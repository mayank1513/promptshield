import {
  type ScanOptions,
  ThreatCategory,
  type ThreatReportWithoutLocation,
} from "./types";

/**
 * Unicode normalization detector.
 *
 * Detects characters whose representation changes under **NFKC normalization**.
 *
 * Unicode normalization may transform visually similar or compatibility
 * characters into canonical equivalents. When displayed text differs from
 * its normalized form, this can introduce ambiguity between what users see
 * and what downstream systems interpret.
 *
 * Such situations may indicate:
 *
 * - compatibility glyph usage
 * - spoofing attempts
 * - homoglyph confusion
 * - prompt smuggling techniques
 * - validation bypass in downstream processing pipelines
 *
 * Detection model:
 *
 * 1. Normalize the text using **NFKC**
 * 2. Iterate over characters in the original text
 * 3. Identify characters whose normalized form differs
 * 4. Group adjacent normalization-sensitive characters into spans
 * 5. Emit one threat per span
 *
 * Severity heuristic:
 *
 * - **PSN001 (LOW)**
 *   Compatibility normalization producing simple ASCII text.
 *
 * - **PSN002 (MEDIUM)**
 *   More complex normalization transformations.
 *
 * Span semantics:
 *
 * offendingText = original span
 * decodedPayload = normalized span
 *
 * Normalization can expand characters (example: `ﬀ → ff`), therefore
 * the normalized payload is computed from the entire span.
 */
export const scanNormalization = (
  text: string,
  options: ScanOptions = {},
): ThreatReportWithoutLocation[] => {
  if (options.minSeverity === "CRITICAL") return [];

  const threats: ThreatReportWithoutLocation[] = [];

  const normalized = text.normalize("NFKC");
  if (text === normalized) return [];

  let index = 0;
  let spanStart = -1;
  let spanEnd = -1;

  const flushSpan = () => {
    if (spanStart === -1) return;

    const offendingText = text.slice(spanStart, spanEnd);
    const decodedPayload = offendingText.normalize("NFKC");

    /**
     * Heuristic severity tuning
     */
    const asciiCompat = /^[a-z0-9\s]+$/i.test(decodedPayload);

    const ruleId = asciiCompat ? "PSN001" : "PSN002";
    const severity = asciiCompat ? "LOW" : "MEDIUM";

    threats.push({
      ruleId,
      category: ThreatCategory.Normalization,
      severity,
      message:
        "Text changes under Unicode NFKC normalization. This may cause ambiguity between displayed and interpreted content.",
      referenceUrl: `https://promptshield.js.org/docs/detectors/normalization#${ruleId}`,
      range: { start: spanStart, end: spanEnd },
      offendingText,
      decodedPayload,
      readableLabel: "[NFKC_DIFF]",
      suggestion: "Replace with normalized text to avoid ambiguity.",
    });

    spanStart = -1;
    spanEnd = -1;
  };

  for (const char of text) {
    const normChar = char.normalize("NFKC");

    if (char !== normChar) {
      if (spanStart === -1) {
        spanStart = index;
        spanEnd = index + char.length;
      } else {
        spanEnd += char.length;
      }

      if (
        options.stopOnFirstThreat &&
        !options.ignoreChecker?.(index, index + char.length)
      ) {
        flushSpan();
        return threats;
      }
    } else {
      flushSpan();
    }

    index += char.length;
  }

  flushSpan();

  return threats;
};
