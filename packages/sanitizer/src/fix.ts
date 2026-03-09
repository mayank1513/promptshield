import { ThreatCategory, type ThreatReport } from "@promptshield/core";

/**
 * Result returned by {@link applyFixes}.
 *
 * Describes the outcome after attempting safe automatic fixes
 * for detected threats within a text document.
 *
 * The result includes:
 *
 * - The updated text after modifications
 * - Threats that were successfully fixed
 * - Threats that were intentionally skipped
 *
 * Skipped threats usually require human review or contextual decisions
 * that should not be performed automatically.
 */
export interface FixResult {
  /** Text after safe automatic fixes were applied */
  text: string;

  /** Threats that were successfully fixed */
  fixed: ThreatReport[];

  /** Threats that were intentionally skipped */
  skipped: ThreatReport[];
}

/**
 * Applies safe automatic fixes for detected threats.
 *
 * This utility performs deterministic structural cleanup for
 * threats that can be safely remediated without altering meaning.
 *
 * Design principles:
 *
 * - **Deterministic** – no heuristics or AI involved
 * - **Idempotent** – running multiple times produces the same result
 * - **Index-safe** – fixes are applied from end → start to prevent offset shifts
 * - **Conservative** – only safe structural removals or normalizations are performed
 *
 * Examples of automatic fixes:
 *
 * - Removing invisible characters
 * - Stripping hidden Markdown comments
 * - Removing empty Markdown links
 * - Unwrapping hidden HTML containers
 * - Replacing encoded payloads with decoded content
 * - Normalizing Unicode compatibility characters
 *
 * Some threats (such as prompt injection attempts) are intentionally
 * **not modified automatically**, as doing so may alter the meaning
 * of the original content. These are returned in the `skipped` list.
 *
 * @param text Original scanned text
 * @param threats Detected threats to evaluate for safe fixes
 */
export const applyFixes = (
  text: string,
  threats: ThreatReport[],
): FixResult => {
  if (!threats.length) return { text, fixed: [], skipped: [] };

  // Sort descending to avoid index shifting
  const sorted = [...threats].sort(
    (a, b) => b.range.start.index - a.range.start.index,
  );

  const fixed: ThreatReport[] = [];
  const skipped: ThreatReport[] = [];

  let output = text;

  for (const threat of sorted) {
    const start = threat.range.start.index;
    const end = threat.range.end.index;
    const offending = threat.offendingText;

    if (start < 0 || !offending) continue;

    switch (threat.category) {
      case ThreatCategory.Invisible:
      case ThreatCategory.Trojan:
        output = output.slice(0, start) + output.slice(end);
        fixed.push(threat);
        break;

      case ThreatCategory.Smuggling:
        if (
          threat.readableLabel?.startsWith("[Hidden Comment]") ||
          threat.readableLabel?.startsWith("[Empty Link]")
        ) {
          // Both can be safely stripped
          output = output.slice(0, start) + output.slice(end);
          fixed.push(threat);
        } else if (threat.readableLabel?.startsWith("[Hidden HTML]")) {
          // Strip the wrappers, keep content
          output =
            output.slice(0, start) +
            offending.replace(/<(details|template)[^>]*>(.*?)<\/\1>/gi, "$2") +
            output.slice(end);
          fixed.push(threat);
        } else if (
          threat.readableLabel?.startsWith("[Base64]: ") ||
          threat.readableLabel?.startsWith("[HEX]: ")
        ) {
          // Decode by taking the remainder of the readableLabel and mapping to the offendingText range
          // The label format is usually "[Base64]: <decoded_stuff>"
          const match = threat.readableLabel.match(/^\[(.*?)\]:\s*(.*)$/);
          if (match?.[2] && match[2] !== "...") {
            const decoded = match[2];
            output = output.slice(0, start) + decoded + output.slice(end);
            fixed.push(threat);
          } else {
            // Cannot reliably recover or it's truncated
            skipped.push(threat);
          }
        } else {
          skipped.push(threat);
        }
        break;

      case ThreatCategory.Injection:
        skipped.push(threat);
        break;

      case ThreatCategory.Normalization:
        output =
          output.slice(0, start) +
          offending.normalize("NFKC") +
          output.slice(end);

        fixed.push(threat);
        break;

      default:
        skipped.push(threat);
    }
  }

  return { text: output, fixed, skipped };
};
