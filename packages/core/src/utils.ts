import type { ScanContext, ThreatReport, ThreatReportWithRange } from "./types";

/**
 * Computes line start offsets for a string.
 *
 * Each entry represents the character index where a new line begins.
 * The first entry is always `0`.
 *
 * Example:
 * "a\nb\nc" → [0, 2, 4]
 *
 * This enables fast index → (line, column) mapping without repeatedly
 * scanning the entire string.
 */
export const getLineOffsets = (text: string): number[] => {
  const lineOffsets = [0];

  for (let i = 0; i < text.length; i++) {
    if (text[i] === "\n") {
      lineOffsets.push(i + 1);
    }
  }

  return lineOffsets;
};

/**
 * Resolves a character index into a line/column location.
 *
 * Uses binary search over precomputed line offsets for O(log n) lookup.
 *
 * Context provides:
 * - baseLine
 * - baseCol
 * - lineOffsets
 *
 * `baseLine` and `baseCol` allow this function to operate correctly when
 * scanning substrings that originate from a larger document.
 */
export const getLocForIndex = (
  index: number,
  context: Required<ScanContext>,
): { line: number; column: number; index: number } => {
  const { lineOffsets, baseLine, baseCol } = context;

  let low = 0;
  let high = lineOffsets.length - 1;

  while (low <= high) {
    const mid = (low + high) >> 1;

    if (lineOffsets[mid] <= index) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  const lineIndex = Math.max(high, 0);

  return {
    line: baseLine + lineIndex,
    column: index - lineOffsets[lineIndex] + (lineIndex === 0 ? baseCol : 1),
    index,
  };
};

/**
 * Enriches ThreatReports with human-readable line/column locations.
 *
 * PromptShield detectors operate on absolute character offsets for
 * performance and editor compatibility (e.g., Tiptap, LSP, AST tools).
 *
 * However, human-facing environments such as:
 *
 * - CLI output
 * - CI diagnostics
 * - logs
 * - static analysis reports
 *
 * require line and column information.
 *
 * This helper converts offset-based threat ranges into location-aware
 * structures in a single pass.
 *
 * The function computes line offsets once and resolves both start and
 * end positions using binary search (`getLocForIndex`).
 *
 * This approach is significantly more efficient than resolving locations
 * during detection or performing repeated scans of the input text.
 *
 * @param threats
 * List of ThreatReports produced by `scan()`. These must contain
 * offset-based ranges (`range.start`, `range.end`).
 *
 * @param text
 * The original scanned text used to generate the threats.
 *
 * @param context
 * Optional scan context for offset translation. Supports:
 * - `baseLine`
 * - `baseCol`
 *
 * This is useful when scanning substrings embedded inside a larger
 * document (e.g., editor buffers, LSP fragments).
 *
 * @returns
 * A new array of ThreatReports where each threat includes
 * `loc.start` and `loc.end` describing the resolved line/column
 * positions.
 *
 * @example
 * ```ts
 * const result = scan(text);
 * const threats = enrichWithLoc(result.threats, text);
 *
 * console.log(threats[0].loc);
 * // {
 * //   start: { line: 2, column: 5, index: 17 },
 * //   end:   { line: 2, column: 8, index: 20 }
 * // }
 * ```
 */
export const enrichWithRange = (
  threats: ThreatReport[],
  text: string,
  context: Omit<ScanContext, "lineOffsets"> = {},
): ThreatReportWithRange[] => {
  const lineOffsets = getLineOffsets(text);
  const { baseLine = 1, baseCol = 1 } = context;
  const ctx: Required<ScanContext> = {
    lineOffsets,
    baseLine,
    baseCol,
  };

  return threats.map((threat) => {
    const startLoc = getLocForIndex(threat.range.start, ctx);
    const endLoc = getLocForIndex(threat.range.end, ctx);

    return {
      ...threat,
      range: {
        start: startLoc,
        end: endLoc,
      },
    };
  });
};
