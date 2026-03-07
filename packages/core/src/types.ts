/**
 * Severity levels assigned to detected threats.
 *
 * These levels are ordered by risk:
 *
 * LOW < MEDIUM < HIGH < CRITICAL
 *
 * The scanner may filter results using `ScanOptions.minSeverity`.
 */
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/**
 * Numeric severity ranking map.
 *
 * Lower numbers represent higher severity.
 *
 * Used for:
 * - Severity threshold comparisons
 * - Sorting threats by priority
 * - Efficient numeric filtering
 *
 * Example:
 *   SEVERITY_MAP["CRITICAL"] < SEVERITY_MAP["LOW"] // true
 */
export const SEVERITY_MAP: Record<Severity, number> = {
  CRITICAL: 1,
  HIGH: 2,
  MEDIUM: 3,
  LOW: 4,
};

/**
 * Categories of threats detected by PromptShield.
 *
 * Categories describe the *type of attack vector* rather than
 * the specific implementation detail.
 */
export enum ThreatCategory {
  /**
   * Invisible Unicode characters such as:
   * - Zero Width Space (ZWSP)
   * - Zero Width Joiner (ZWJ)
   * - BIDI markers
   *
   * These are commonly used for prompt injection smuggling.
   */
  Invisible = "INVISIBLE_CHAR",

  /**
   * Mixed-script characters that visually resemble others.
   *
   * Example:
   * Cyrillic "а" vs Latin "a".
   */
  Homoglyph = "HOMOGLYPH",

  /**
   * Encoded or concealed content intended to bypass inspection.
   *
   * Examples:
   * - Base64 payloads
   * - hidden markdown
   * - encoded instructions
   */
  Smuggling = "SMUGGLING",

  /**
   * Prompt injection patterns.
   *
   * Deterministic, rule-based detection only.
   */
  Injection = "PROMPT_INJECTION",

  /**
   * Trojan Source attack vectors (CVE-2021-42574).
   *
   * These use bidirectional override characters to manipulate
   * code or prompt interpretation.
   */
  Trojan = "TROJAN_SOURCE",

  /**
   * Unicode normalization inconsistencies where visually identical
   * characters differ at the code-point level.
   */
  Normalization = "NORMALIZATION",
}

/**
 * Location of a threat within the scanned text.
 *
 * The scanner reports both human-readable and machine-friendly
 * position data.
 */
export interface Location {
  /** 1-based line number */
  line: number;

  /** 1-based column number */
  column: number;

  /** 0-based character index in the scanned text */
  index: number;
}

/**
 * Report describing a detected threat span.
 *
 * NOTE:
 * A ThreatReport represents a **span**, not a single character.
 * Adjacent suspicious characters should be grouped into one report.
 */
export interface ThreatReport {
  /**
   * Stable rule identifier.
   *
   * Example:
   * "PSU001", "PST001", "PSI002"
   */
  ruleId: string;

  /** Threat classification */
  category: ThreatCategory;

  /** Risk severity */
  severity: Severity;

  /**
   * Human-readable diagnostic message.
   *
   * Describes WHAT was detected and WHY it matters.
   * This should not include remediation steps.
   */
  message: string;

  /** Location of the threat start */
  range: {
    /** Offset: 0-based character index */
    start: number;
    /** Offset: 0-based character index */
    end: number;
  };

  /**
   * The substring responsible for the detection.
   *
   * This may contain multiple characters if the threat
   * represents a sequence.
   */
  offendingText: string;

  /**
   * Optional readable label for UI rendering.
   *
   * Example:
   * "[ZWSP × 3]"
   */
  readableLabel?: string;

  /**
   * Suggested remediation guidance.
   *
   * This is optional and may vary by environment (editor, CI, UI).
   */
  suggestion?: string;

  /**
   * Optional decoded payload extracted from concealed content.
   *
   * Example:
   * "ignore previous instructions"
   */
  decodedPayload?: string;

  /**
   * Reference documentation explaining the risk.
   *
   * Example:
   * https://promptshield.js.org/docs/detectors/invisible-chars#PSU001
   */
  referenceUrl: string;

  /**
   * Indicates whether this threat was suppressed
   * by an ignore directive.
   */
  suppressed?: boolean;
}

/**
 * Threat report enriched with human-readable location information.
 *
 * `ThreatReportWithLocation` extends the base `ThreatReport` by replacing the
 * offset-based `range` with resolved line/column locations. This format is
 * intended for environments where diagnostics must be presented to humans,
 * such as:
 *
 * - CLI output
 * - CI reports
 * - logs
 * - editor diagnostics
 *
 * The core scanner operates purely on absolute character offsets for
 * performance and interoperability with editor APIs (e.g., Tiptap, LSP).
 * Location resolution is performed later using utilities such as
 * `enrichWithLoc`.
 *
 * Each range endpoint includes:
 *
 * - `line`   — 1-based line number
 * - `column` — 1-based column number
 * - `index`  — original 0-based character offset
 *
 * Keeping the original `index` ensures deterministic mapping back to the
 * source text while still providing user-friendly diagnostics.
 *
 * @example
 * ```ts
 * {
 *   ruleId: "PSU001",
 *   severity: "LOW",
 *   message: "Invisible Unicode characters detected.",
 *   range: {
 *     start: { line: 2, column: 5, index: 17 },
 *     end:   { line: 2, column: 6, index: 18 }
 *   }
 * }
 * ```
 */
export interface ThreatReportWithRange extends Omit<ThreatReport, "range"> {
  range: {
    /** Start position of the detected threat span. */
    start: Location;

    /** End position of the detected threat span. */
    end: Location;
  };
}

/**
 * Scanner configuration options.
 */
export interface ScanOptions {
  /**
   * Stop scanning after the first detected threat.
   *
   * Useful for CI validation or fast-fail scenarios.
   *
   * @default false
   */
  stopOnFirstThreat?: boolean;

  /**
   * Minimum severity to report.
   *
   * @default "LOW"
   */
  minSeverity?: Severity;

  /** Disable invisible-character detection
   *
   * @default false
   */
  disableInvisible?: boolean;

  /** Disable homoglyph detection
   *
   * @default false
   */
  disableHomoglyphs?: boolean;

  /** Disable smuggling detection
   *
   * @default false
   */
  disableSmuggling?: boolean;

  /** Disable Trojan Source detection
   *
   * @default false
   */
  disableTrojan?: boolean;

  /** Disable normalization detection
   *
   * @default false
   */
  disableNormalization?: boolean;

  /** Disable injection-pattern detection
   *
   * @default false
   */
  disableInjectionPatterns?: boolean;
}

/**
 * Execution context for scanning text fragments.
 *
 * Used when scanning partial content extracted from a larger source.
 */
export interface ScanContext {
  /**
   * Base line offset.
   * @default 1
   */
  baseLine?: number;

  /**
   * Base column offset.
   * @default 1
   */
  baseCol?: number;

  /**
   * Precomputed line offsets for performance.
   */
  lineOffsets: number[];
}

/**
 * Detector function contract.
 *
 * Detectors must be:
 * - deterministic
 * - side-effect free
 * - synchronous
 */
export type Detector = (text: string, options: ScanOptions) => ThreatReport[];

/**
 * Result returned by the scanner.
 */
export interface ScanResult {
  threats: ThreatReport[];
  isClean: boolean;
}
