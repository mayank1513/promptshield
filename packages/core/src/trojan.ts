import {
  type ScanOptions,
  ThreatCategory,
  type ThreatReportWithoutLocation,
} from "./types";

/**
 * Unicode Bidirectional control characters used in Trojan Source attacks.
 *
 * Reference:
 * CVE-2021-42574
 * https://trojansource.codes/
 *
 * PUSH characters start a directional override/isolation context.
 * POP characters terminate that context.
 *
 * LRM / RLM / ALM are included because they influence visual ordering
 * and may be used in obfuscation sequences even though they do not
 * create explicit push/pop scopes.
 */
const BIDI_CHARS: Record<string, "PUSH" | "POP" | "MARK"> = {
  "\u202A": "PUSH", // LRE
  "\u202B": "PUSH", // RLE
  "\u202D": "PUSH", // LRO
  "\u202E": "PUSH", // RLO
  "\u2066": "PUSH", // LRI
  "\u2067": "PUSH", // RLI
  "\u2068": "PUSH", // FSI

  "\u202C": "POP", // PDF
  "\u2069": "POP", // PDI

  "\u200E": "MARK", // LRM
  "\u200F": "MARK", // RLM
  "\u061C": "MARK", // ALM
};

/**
 * Trojan Source detector.
 *
 * Detects unsafe usage of Unicode Bidirectional (BIDI) control characters
 * that can cause the *visual order* of text to differ from its *logical order*.
 *
 * These attacks allow malicious code or instructions to appear benign to
 * reviewers while executing differently when interpreted by compilers,
 * interpreters, or LLMs.
 *
 * Detection rules:
 *
 * PST001 — Matched BIDI override sequence
 * PST002 — Unterminated BIDI override sequence
 */
export const scanTrojanSource = (
  text: string,
  options: ScanOptions = {},
): ThreatReportWithoutLocation[] => {
  const threats: ThreatReportWithoutLocation[] = [];

  /**
   * Stack of active BIDI push contexts.
   *
   * Nested contexts are valid in Unicode and must be handled correctly.
   */
  const stack: number[] = [];

  let index = 0;

  for (let i = 0; i < text.length; ) {
    const code = text.codePointAt(i) as number;
    const char = String.fromCodePoint(code);
    const type = BIDI_CHARS[char];

    /**
     * PUSH — start new BIDI context
     */
    if (type === "PUSH") {
      stack.push(index);
    } else if (type === "POP" && stack.length) {
      /**
       * POP — close most recent context
       */
      const start = stack.pop() as number;
      const end = index + char.length;

      const offendingText = text.slice(start, end);

      /**
       * Inner logical content between control characters.
       */
      const innerText = text.slice(start + 1, end - 1);

      threats.push({
        ruleId: "PST001",
        category: ThreatCategory.Trojan,
        severity: "CRITICAL",
        message:
          "Bidirectional override characters detected (Trojan Source). These characters can visually reorder text and mislead reviewers.",
        referenceUrl:
          "https://promptshield.js.org/docs/detectors/trojan-source#PST001",
        range: { start, end },
        offendingText,
        decodedPayload: innerText,
        readableLabel: "[BIDI_OVERRIDE]",
        suggestion:
          "Remove bidirectional control characters or replace them with visible equivalents.",
      });

      if (options.stopOnFirstThreat && !options.ignoreChecker?.(start, end))
        return threats;
    }

    /**
     * CRITICAL RULE
     *
     * If a newline is reached while a BIDI context remains open,
     * the sequence is suspicious.
     *
     * Trojan Source attacks often rely on unterminated contexts
     * that span code regions.
     */
    if ((char === "\n" || char === "\r") && stack.length) {
      const start = stack.pop() as number;
      const end = index;

      const offendingText = text.slice(start, end);
      const innerText = text.slice(start + 1, end);

      threats.push({
        ruleId: "PST002",
        category: ThreatCategory.Trojan,
        severity: "CRITICAL",
        message:
          "Unterminated bidirectional override sequence detected (Trojan Source). This may cause visual and logical text order to differ.",
        referenceUrl:
          "https://promptshield.js.org/docs/detectors/trojan-source#PST002",
        range: { start, end },
        offendingText,
        decodedPayload: innerText,
        readableLabel: "[BIDI_UNTERMINATED]",
        suggestion:
          "Ensure BIDI control characters are properly terminated within the same logical line or remove them entirely.",
      });

      if (options.stopOnFirstThreat && !options.ignoreChecker?.(start, end))
        return threats;
    }

    index += char.length;
    i += char.length;
  }

  /**
   * Final safety check:
   *
   * Any remaining open contexts at EOF are suspicious.
   */
  while (stack.length) {
    const start = stack.pop() as number;
    const end = text.length;

    const offendingText = text.slice(start, end);
    const innerText = text.slice(start + 1);

    threats.push({
      ruleId: "PST002",
      category: ThreatCategory.Trojan,
      severity: "CRITICAL",
      message:
        "Unterminated bidirectional override sequence detected (Trojan Source).",
      referenceUrl:
        "https://promptshield.js.org/docs/detectors/trojan-source#PST002",
      range: { start, end },
      offendingText,
      decodedPayload: innerText,
      readableLabel: "[BIDI_UNTERMINATED]",
      suggestion:
        "Remove or terminate bidirectional override characters before the end of the document.",
    });

    if (options.stopOnFirstThreat && !options.ignoreChecker?.(start, end))
      return threats;
  }

  return threats;
};
