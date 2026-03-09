import {
  type ScanOptions,
  SEVERITY_MAP,
  ThreatCategory,
  type ThreatReportWithoutLocation,
} from "./types";

type InjectionType =
  | "override"
  | "exfiltration"
  | "guardrail-bypass"
  | "role-override";

type InjectionRule = {
  /** Stable rule identifier */
  id: string;

  /** Injection subtype */
  type: InjectionType;

  /** Threat severity */
  severity: "HIGH" | "CRITICAL";

  /** Human-readable message */
  message: string;

  /** Direct detection pattern */
  regex: RegExp;

  /** Canonical normalized pattern */
  normalizedPattern: string;
};

/**
 * Deterministic Prompt Injection Rules
 *
 * These rules capture **well-known lexical patterns used in prompt injection attacks**.
 *
 * The detector intentionally focuses on **structural override phrases** rather than
 * semantic interpretation. This keeps the system:
 *
 * - deterministic
 * - explainable
 * - fast
 * - safe to run locally
 *
 * Each rule belongs to one of the following injection subtypes:
 *
 * override
 *   Attempts to replace or ignore prior instructions.
 *
 * exfiltration
 *   Attempts to reveal system prompts or hidden instructions.
 *
 * guardrail-bypass
 *   Attempts to disable safety protections.
 *
 * role-override
 *   Attempts to redefine the assistant's behavior or identity.
 *
 * Rule namespace:
 *
 * PSI — PromptShield Injection
 */
const INJECTION_RULES: InjectionRule[] = [
  {
    id: "PSI001",
    type: "override",
    severity: "CRITICAL",
    message: "Prompt injection attempt: ignore previous instructions",
    regex: /ignore\s+(all\s+)?previous\s+instructions/gi,
    normalizedPattern: "ignorepreviousinstructions",
  },

  {
    id: "PSI002",
    type: "exfiltration",
    severity: "CRITICAL",
    message: "Attempt to reveal system prompt",
    regex: /(reveal|show|display|print)\s+(the\s+)?(system|hidden)\s+prompt/gi,
    normalizedPattern: "revealsystemprompt",
  },

  {
    id: "PSI003",
    type: "guardrail-bypass",
    severity: "HIGH",
    message: "Attempt to disable guardrails or safety protections",
    regex: /disable\s+(the\s+)?(guardrails|safety|safeguards)/gi,
    normalizedPattern: "disableguardrails",
  },

  {
    id: "PSI004",
    type: "override",
    severity: "HIGH",
    message: "System instruction override detected",
    regex: /override\s+(the\s+)?(system\s+)?(instructions|rules)/gi,
    normalizedPattern: "overridesysteminstructions",
  },

  {
    id: "PSI005",
    type: "override",
    severity: "CRITICAL",
    message: "Prompt injection attempt: ignore system prompt",
    regex: /ignore\s+(the\s+)?system\s+prompt/gi,
    normalizedPattern: "ignoresystemprompt",
  },

  {
    id: "PSI006",
    type: "override",
    severity: "CRITICAL",
    message: "Instruction override: follow attacker-provided instructions",
    regex: /follow\s+(my|these)\s+instructions/gi,
    normalizedPattern: "followmyinstructions",
  },

  {
    id: "PSI007",
    type: "role-override",
    severity: "HIGH",
    message: "Role override instruction detected",
    regex: /(you\s+are\s+now|act\s+as)\s+/gi,
    normalizedPattern: "youarenow",
  },

  {
    id: "PSI008",
    type: "exfiltration",
    severity: "CRITICAL",
    message: "Attempt to reveal hidden instructions",
    regex: /(reveal|show|display)\s+(hidden|internal)\s+instructions/gi,
    normalizedPattern: "revealhiddeninstructions",
  },
];

/**
 * Build a canonical representation of the text while preserving
 * a mapping back to the original character indices.
 *
 * Why per-character normalization?
 *
 * Unicode normalization (NFKD/NFKC) can **expand characters**.
 *
 * Example:
 *
 *   é  →  e + ◌́
 *
 * If normalization is applied to the entire string first, character
 * positions drift and cannot be reliably mapped back to the original
 * source text.
 *
 * To prevent this, we normalize **each character individually** and
 * record the originating index for every emitted normalized character.
 *
 * Normalization pipeline:
 *
 * 1. Unicode decomposition (NFKD)
 * 2. Remove combining marks (diacritics)
 * 3. Lowercase
 * 4. Retain only ASCII letters
 *
 * Example:
 *
 * Original:
 *
 *   "I g n o r é   previous instructions"
 *
 * Normalized:
 *
 *   "ignorepreviousinstructions"
 *
 * The returned `map` array stores the original source index
 * corresponding to each normalized character.
 */
const normalizeWithMap = (text: string) => {
  const normalizedChars: string[] = [];
  const map: number[] = [];

  for (let i = 0; i < text.length; i++) {
    const normalized = text[i]
      .normalize("NFKD")
      .replace(/\p{M}+/gu, "")
      .toLowerCase();

    for (const ch of normalized) {
      if (/[a-z]/.test(ch)) {
        normalizedChars.push(ch);
        map.push(i);
      }
    }
  }

  return {
    normalized: normalizedChars.join(""),
    map,
  };
};

/**
 * Scan text for deterministic prompt-injection patterns.
 *
 * Detection strategy:
 *
 * 1. Perform **direct regex matching** against the raw text.
 * 2. Perform **normalized matching** to catch obfuscation such as:
 *
 *    - excessive whitespace
 *    - character splitting
 *    - accent obfuscation
 *
 *    Example:
 *
 *      i g n o r e
 *      previous
 *      instructions
 *
 * To avoid duplicate reporting:
 *
 * - Direct matches are recorded first.
 * - Normalized matches are skipped if they overlap an already
 *   detected span for the same rule.
 *
 * Complexity:
 *
 * - One normalization pass over the text
 * - One regex scan per rule
 * - One incremental normalized search per rule
 *
 * Overall runtime remains **linear in input size**.
 *
 * @param text Raw text to scan
 * @param options Scanner configuration
 */
export const scanInjectionPatterns = (
  text: string,
  options: ScanOptions = {},
): ThreatReportWithoutLocation[] => {
  const threats: ThreatReportWithoutLocation[] = [];

  const { normalized, map } = normalizeWithMap(text);

  for (const rule of INJECTION_RULES) {
    const localThreats: ThreatReportWithoutLocation[] = [];

    /**
     * Create a local RegExp instance to ensure `lastIndex`
     * is isolated per rule execution.
     */
    const regex = new RegExp(rule.regex);

    let match: RegExpExecArray | null;

    /**
     * 1. Direct regex detection
     */
    // biome-ignore lint/suspicious/noAssignInExpressions: required for exec loop
    while ((match = regex.exec(text)) !== null) {
      const start = match.index;
      const end = start + match[0].length;

      localThreats.push({
        ruleId: rule.id,
        category: ThreatCategory.Injection,
        severity: rule.severity,
        message: `\`${rule.type}\`: ${rule.message}`,
        offendingText: match[0],
        range: { start, end },
        readableLabel: `[Injection (${rule.type})]`,
        suggestion:
          "Remove instruction-override language from prompts or user content.",
        referenceUrl: `https://promptshield.js.org/docs/detectors/injection-patterns#${rule.id}`,
      });

      if (
        options.stopOnFirstThreat &&
        SEVERITY_MAP[rule.severity] <=
          SEVERITY_MAP[options.minSeverity ?? "LOW"] &&
        !options.ignoreChecker?.(start, end)
      ) {
        threats.push(...localThreats);
        return threats;
      }

      // Prevent infinite loops for zero-length matches
      if (match[0].length === 0) {
        regex.lastIndex++;
      }
    }

    /**
     * 2. Normalized detection (handles obfuscation)
     *
     * After direct regex matching, we perform detection on a normalized
     * representation of the text. This catches patterns that have been
     * obfuscated using:
     *
     * - excessive spacing
     * - character splitting
     * - accent/diacritic tricks
     *
     * Example:
     *
     *   "i g n o r é   previous instructions"
     *
     * becomes:
     *
     *   "ignorepreviousinstructions"
     *
     * Mapping allows us to reconstruct the correct source span.
     *
     * Deduplication strategy:
     *
     * Direct regex matches are processed first and stored in `localThreats`.
     * Since both direct and normalized matches are discovered in increasing
     * source order, we maintain a moving pointer (`directThreatIdx`) that
     * skips past direct matches that can no longer overlap.
     *
     * This guarantees efficient overlap checks without rescanning earlier
     * threats.
     */

    const patternLength = rule.normalizedPattern.length;

    let idx = normalized.indexOf(rule.normalizedPattern);
    let directThreatIdx = 0;

    while (idx !== -1) {
      const start = map[idx];
      const end = map[idx + patternLength - 1] + 1;

      /**
       * Advance pointer past direct matches that end before this
       * normalized match begins.
       *
       * Since threats are sorted by start index, these earlier
       * spans can never overlap future matches.
       */
      while (
        directThreatIdx < localThreats.length &&
        localThreats[directThreatIdx].range.end < start
      ) {
        directThreatIdx++;
      }

      /**
       * Check overlap against remaining direct matches.
       */
      let overlap = false;

      for (let i = directThreatIdx; i < localThreats.length; i++) {
        const t = localThreats[i];

        if (t.range.start > end) break;

        if (start === t.range.start && end === t.range.end) {
          overlap = true;
          break;
        }
      }

      /**
       * Only report the normalized detection if it does not overlap
       * with a previously detected direct match.
       */
      if (!overlap) {
        const offendingText = text.slice(start, end);

        localThreats.push({
          ruleId: rule.id,
          category: ThreatCategory.Injection,
          severity: rule.severity,
          message: `\`${rule.type}\`: ${rule.message} (obfuscated form detected)`,
          offendingText,
          range: { start, end },
          readableLabel: `[Injection (${rule.type})]`,
          suggestion:
            "Obfuscated instruction detected. Inspect and remove malicious content.",
          referenceUrl: `https://promptshield.js.org/docs/detectors/injection-patterns#${rule.id}`,
        });

        if (
          options.stopOnFirstThreat &&
          SEVERITY_MAP[rule.severity] <=
            SEVERITY_MAP[options.minSeverity ?? "LOW"] &&
          !options.ignoreChecker?.(start, end)
        ) {
          threats.push(...localThreats);
          return threats;
        }
      }

      // Continue searching for the next normalized occurrence
      idx = normalized.indexOf(rule.normalizedPattern, idx + 1);
    }

    threats.push(...localThreats);
  }

  return threats;
};
