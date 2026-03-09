import {
  type ScanOptions,
  ThreatCategory,
  type ThreatReportWithoutLocation,
} from "./types";

/**
 * Registry of invisible or near-invisible characters commonly abused
 * in obfuscation attacks.
 *
 * These characters typically render with zero width or no visible glyph
 * in most editors, terminals, or UI environments.
 *
 * They have historically been used for:
 *
 * • Prompt injection obfuscation
 * • Token boundary manipulation
 * • Content smuggling
 * • Validation bypass
 *
 * Examples observed in real-world attacks:
 *
 * - Zero-width spaces inserted inside keywords
 * - Hangul fillers used as invisible padding
 * - Word joiners used to alter token boundaries
 *
 * NOTE:
 *
 * Some invisible characters are intentionally **excluded here** because
 * they are handled by other detectors:
 *
 * | Character Class | Detector |
 * |-----------------|----------|
 * BIDI overrides   | Trojan Source detector |
 * Invisible steganography runs | Smuggling detector |
 *
 * This detector focuses strictly on **lexical invisibility issues**
 * rather than covert data encoding.
 *
 * References:
 * - Unicode TR36 (Security Considerations)
 * - Trojan Source (CVE-2021-42574)
 * - Multiple LLM prompt injection research reports (2023-2025)
 */
const CHAR_LABELS: Readonly<Record<string, string>> = {
  "\u200B": "ZWSP", // Zero Width Space
  "\u200C": "ZWNJ", // Zero Width Non-Joiner
  "\u200D": "ZWJ", // Zero Width Joiner
  "\u2060": "WJ", // Word Joiner
  "\u180E": "MVS", // Mongolian Vowel Separator (historically abused)
  "\uFEFF": "BOM", // Byte Order Mark
  "\u3164": "HF", // Hangul Filler
  "\uFFA0": "HHF", // Halfwidth Hangul Filler
};

/**
 * Invisible character detection regex.
 *
 * Detects:
 *
 * • Zero-width characters
 * • Word joiner
 * • Mongolian vowel separator
 * • Hangul fillers
 * • Unicode tag characters
 *
 * Unicode tag characters are included because they frequently appear
 * inside invisible sequences and may encode hidden payloads.
 *
 * NOTE:
 *
 * Long runs of invisible characters used for **binary steganography**
 * are handled separately by the **Smuggling detector (PSS001)**.
 *
 * This detector focuses on **structural invisibility anomalies** rather
 * than decoding covert payload channels.
 */
const INVISIBLE_REGEX =
  /([\u200B-\u200D\u2060\u180E\uFEFF\u3164\uFFA0]|\uDB40[\uDC00-\uDC7F])/gu;

/**
 * Threshold used to detect excessive invisible padding.
 *
 * Long runs of invisible characters are rarely legitimate and are
 * commonly used for:
 *
 * • prompt smuggling
 * • context stuffing
 * • LLM token manipulation
 */
const EXCESSIVE_THRESHOLD = 16;

/**
 * Invisible character detector.
 *
 * This detector emits **span-level threats** with the following precedence:
 *
 * PSU004 → Unicode tag payload
 * PSU005 → Excessive invisible padding
 * PSU001 → Invisible characters present
 *
 * Additionally:
 *
 * PSU002 is emitted independently for **token boundary manipulation**
 * where an invisible character appears inside a visible token.
 *
 * Span semantics:
 *
 * • offendingText represents the **entire invisible sequence**
 * • spans are **not merged across newline boundaries**
 */
export const scanInvisibleChars = (
  text: string,
  options: ScanOptions = {},
): ThreatReportWithoutLocation[] => {
  const invisibleRegex = new RegExp(INVISIBLE_REGEX);

  let match: RegExpExecArray | null = invisibleRegex.exec(text);
  if (!match || options?.minSeverity === "CRITICAL") return [];

  const threats: ThreatReportWithoutLocation[] = [];

  let spanStart = -1;
  let spanEnd = -1;

  const resetSpan = () => {
    spanStart = -1;
    spanEnd = -1;
  };

  /**
   * Emit accumulated invisible span.
   */
  const flushSpan = () => {
    if (spanStart === -1) return;

    const offendingText = text.slice(spanStart, spanEnd);
    const decodedPayload = decodeUnicodeTags(offendingText);

    const labels = [...offendingText].map((c) => {
      const cp = c.codePointAt(0);
      return CHAR_LABELS[c] || `U+${cp?.toString(16).toUpperCase()}`;
    });

    let threat: ThreatReportWithoutLocation | undefined;

    /**
     * PSU004 — Unicode tag payload
     */
    if (decodedPayload) {
      threat = {
        ruleId: "PSU004",
        category: ThreatCategory.Invisible,
        severity: "HIGH",
        message:
          "Unicode tag characters encode hidden ASCII content inside invisible text.",
        referenceUrl:
          "https://promptshield.js.org/docs/detectors/invisible-chars#PSU004",
        range: { start: spanStart, end: spanEnd },
        offendingText,
        decodedPayload,
        readableLabel: "[TAG_PAYLOAD]",
        suggestion: "Remove Unicode tag characters containing hidden text.",
      };
    } else if (
      options.minSeverity !== "HIGH" &&
      offendingText.length >= EXCESSIVE_THRESHOLD
    ) {
      /**
       * PSU005 — Excessive invisible padding
       */
      threat = {
        ruleId: "PSU005",
        category: ThreatCategory.Invisible,
        severity: "MEDIUM",
        message:
          "Excessive invisible characters detected. Large invisible sequences are commonly used for padding or obfuscation.",
        referenceUrl:
          "https://promptshield.js.org/docs/detectors/invisible-chars#PSU005",
        range: { start: spanStart, end: spanEnd },
        offendingText,
        readableLabel: `[${labels.join(" ")}]`,
        suggestion: "Remove unnecessary invisible characters.",
      };
    } else if (options.minSeverity !== "MEDIUM") {
      /**
       * PSU001 — Invisible characters present
       */
      threat = {
        ruleId: "PSU001",
        category: ThreatCategory.Invisible,
        severity: "LOW",
        message:
          "Invisible Unicode characters detected. These characters can alter tokenization and prompt interpretation without being visible.",
        referenceUrl:
          "https://promptshield.js.org/docs/detectors/invisible-chars#PSU001",
        range: { start: spanStart, end: spanEnd },
        offendingText,
        readableLabel: `[${labels.join(" ")}]`,
        suggestion:
          "Remove invisible characters to ensure the prompt text is interpreted exactly as written.",
      };
    }

    if (threat) {
      threats.push(threat);

      if (
        options.stopOnFirstThreat &&
        !options.ignoreChecker?.(threat.range.start, threat.range.end)
      ) {
        throw threats;
      }
    }

    resetSpan();
  };

  try {
    while (match !== null) {
      const index = match.index;
      const char = match[0];

      /**
       * PSU002 — Token boundary manipulation
       */
      if (index > 0 && index < text.length - 1) {
        const prev = text[index - 1];
        const next = text[index + char.length];

        if (prev?.trim() && next?.trim()) {
          const start = index;
          const end = index + char.length;

          const threat: ThreatReportWithoutLocation = {
            ruleId: "PSU002",
            category: ThreatCategory.Invisible,
            severity: "HIGH",
            message:
              "Invisible character detected inside a visible token. This can manipulate token boundaries or bypass validation.",
            referenceUrl:
              "https://promptshield.js.org/docs/detectors/invisible-chars#PSU002",
            range: { start, end },
            offendingText: char,
            readableLabel: `[${CHAR_LABELS[char]}]` || "[INVISIBLE]",
            suggestion: "Remove invisible characters embedded within words.",
          };

          threats.push(threat);

          if (
            options.stopOnFirstThreat &&
            !options.ignoreChecker?.(start, end)
          ) {
            return threats;
          }
        }
      }

      if (spanStart === -1) {
        spanStart = index;
        spanEnd = index + char.length;
      } else if (index === spanEnd) {
        spanEnd += char.length;
      } else {
        flushSpan();
        spanStart = index;
        spanEnd = index + char.length;
      }

      match = invisibleRegex.exec(text);
    }

    flushSpan();
  } catch (early) {
    return early as ThreatReportWithoutLocation[];
  }

  return threats;
};

/**
 * Attempts to decode Unicode tag characters into ASCII text.
 *
 * Unicode tag characters live in the range:
 *
 *   U+E0000 – U+E007F
 *
 * Each tag character encodes an ASCII value using:
 *
 *   ASCII = codePoint − 0xE0000
 *
 * This mechanism has been abused in multiple security reports to embed
 * hidden instructions inside invisible character streams.
 *
 * This decoder performs a best-effort extraction.
 */
export const decodeUnicodeTags = (text: string): string | undefined => {
  let result = "";
  let found = false;

  for (const char of text) {
    const cp = char.codePointAt(0) as number;

    if (cp >= 0xe0000 && cp <= 0xe007f) {
      const ascii = cp - 0xe0000;

      if (ascii >= 32 && ascii <= 126) {
        result += String.fromCharCode(ascii);
        found = true;
      }
    }
  }

  return found ? result : undefined;
};
