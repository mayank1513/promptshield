/** biome-ignore-all lint/suspicious/noAssignInExpressions: iterating over regex matches */
import {
  type ScanOptions,
  ThreatCategory,
  type ThreatReportWithoutLocation,
} from "./types";

/**
 * Minimum Base64 payload size worth decoding.
 */
const BASE64_MIN_LENGTH = 24;

/**
 * Upper bound to avoid decoding extremely large blobs.
 */
const BASE64_MAX_LENGTH = 4096;

/**
 * Base64 candidate detection.
 *
 * Supports both:
 *
 * 1. Continuous Base64
 * 2. Whitespace-broken Base64 (common evasion technique)
 *
 * Example evasion:
 *
 * SGVsbG8g
 * d29ybGQ=
 *
 * The detector strips whitespace before decoding.
 *
 * Also supports URL-safe Base64 variants (- and _).
 */
const BASE64_REGEX =
  /(?:[A-Za-z0-9+/_-]{4}[\s\u200B-\u200D\u2060\uFEFF]*){8,}(?:[A-Za-z0-9+/_-]{2}==|[A-Za-z0-9+/_-]{3}=)?/g;

/**
 * Hex-encoded payload detection.
 *
 * Attackers frequently encode instructions using hex representation.
 *
 * Example:
 *
 * 69676e6f72652070726576696f757320696e737472756374696f6e73
 *
 * → "ignore previous instructions"
 */
const HEX_REGEX = /\b(?:[0-9a-fA-F]{2}){12,}\b/g;

/**
 * Detect hidden Markdown comments.
 *
 * Markdown comments are invisible in rendered output but remain
 * present in source text.
 */
const MARKDOWN_COMMENT_REGEX = /<!--[\s\S]*?-->/g;

/**
 * Detect empty Markdown links.
 *
 * Example:
 * [](...)
 *
 * These render invisibly but may carry payload URLs or instructions.
 */
const EMPTY_LINK_REGEX = /\[\s*\]\([^)]+\)/g;

/**
 * Detect hidden HTML containers.
 *
 * Many renderers collapse <details> blocks by default and templates are almost never rendered.
 */
const HIDDEN_CONTAINER_REGEX = /<(details|template)[^>]*>[\s\S]*?<\/\1>/gi;

const SUMMARY_REGEXP = /<summary[^>]*>[\s\S]*?<\/summary>/i;

/**
 * Invisible characters commonly used for steganography.
 */
const STEG_REGEX = /([\u200B-\u200D\u2060\uFEFF\u3164\uFFA0]+)/g;

/**
 * Browser-safe Base64 decoding.
 *
 * Automatically switches between Buffer (Node) and atob (browser).
 */
const decodeBase64 = (value: string): string => {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(value, "base64").toString("utf8");
  }

  const binary = atob(value);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
};

/**
 * Attempts Base64 decoding and verifies printable ASCII ratio.
 *
 * This reduces false positives from hashes, UUIDs, and random tokens.
 *
 * Returns decoded text only when content appears human-readable.
 */
const decodeBase64IfLikely = (value: string): string | null => {
  try {
    const cleaned = value.replace(/\s+/g, "");

    if (
      cleaned.length < BASE64_MIN_LENGTH ||
      cleaned.length > BASE64_MAX_LENGTH
    )
      return null;

    const decoded = decodeBase64(cleaned);
    if (!decoded) return null;

    let printable = 0;

    for (const c of decoded) {
      const code = c.charCodeAt(0);
      if (code >= 32 && code <= 126) printable++;
    }

    const ratio = printable / decoded.length;

    return ratio >= 0.7 ? decoded : null;
  } catch {
    return null;
  }
};

/**
 * Attempts hex decoding and verifies printable ASCII ratio.
 *
 * Uses browser-safe decoding.
 */
const decodeHexIfLikely = (value: string): string | null => {
  try {
    if (value.length < BASE64_MIN_LENGTH) return null;

    const bytes = new Uint8Array(value.length / 2);

    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
    }

    const decoded = new TextDecoder().decode(bytes);

    let printable = 0;

    for (const c of decoded) {
      const code = c.charCodeAt(0);
      if (code >= 32 && code <= 126) printable++;
    }

    const ratio = printable / decoded.length;

    return ratio >= 0.7 ? decoded : null;
  } catch {
    return null;
  }
};

/**
 * Smuggling detector.
 *
 * Detects techniques used to conceal instructions or payloads
 * inside otherwise harmless-looking text.
 *
 * Rules emitted:
 *
 * PSS001 — Invisible-character steganography (HIGH)
 * PSS002 — Base64 payload with readable content (MEDIUM)
 * PSS006 — Hex-encoded payload with readable content (MEDIUM)
 * PSS003 — Hidden Markdown comment (LOW)
 * PSS004 — Invisible Markdown link (LOW)
 * PSS005 — Hidden HTML container (LOW)
 *
 * Span semantics:
 *
 * offendingText = suspicious region
 * decodedPayload = recovered payload when available
 */
export const scanSmuggling = (
  text: string,
  options: ScanOptions = {},
): ThreatReportWithoutLocation[] => {
  if (options.minSeverity === "CRITICAL") return [];

  const threats: ThreatReportWithoutLocation[] = [];
  let match: RegExpExecArray | null;

  /**
   * --------------------------------------------------
   * PSS001 — Invisible-character steganography (HIGH)
   * --------------------------------------------------
   */

  const stegRegex = new RegExp(STEG_REGEX);

  while ((match = stegRegex.exec(text)) !== null) {
    const captured = match[0];

    if (captured.length < 8 || captured.length > BASE64_MAX_LENGTH) continue;

    const distinctChars = Array.from(new Set([...captured]));

    /**
     * Support small alphabets used for binary encoding.
     */
    if (distinctChars.length < 2 || distinctChars.length > 4) continue;

    const permutations = [];

    for (let i = 0; i < distinctChars.length; i++) {
      for (let j = 0; j < distinctChars.length; j++) {
        if (i !== j)
          permutations.push({ zero: distinctChars[i], one: distinctChars[j] });
      }
    }

    for (const { zero, one } of permutations) {
      let binary = "";

      for (const char of captured) {
        if (char === zero) binary += "0";
        else if (char === one) binary += "1";
      }

      let decoded = "";

      for (let i = 0; i < binary.length; i += 8) {
        const byte = binary.slice(i, i + 8);
        if (byte.length !== 8) continue;

        const code = parseInt(byte, 2);

        if (code >= 32 && code <= 126) {
          decoded += String.fromCharCode(code);
        }
      }

      if (decoded.length >= 3) {
        const start = match.index;
        const end = start + captured.length;
        threats.push({
          ruleId: "PSS001",
          category: ThreatCategory.Smuggling,
          severity: "HIGH",
          message:
            "Detected hidden steganography message encoded in invisible characters.",
          range: { start, end },
          offendingText: captured,
          decodedPayload: decoded,
          readableLabel: `[Hidden]: ${decoded.slice(0, 120)}...`,
          suggestion:
            "Invisible-character encoding detected. Inspect hidden content.",
          referenceUrl:
            "https://promptshield.js.org/docs/detectors/smuggling#PSS001",
        });

        if (options.stopOnFirstThreat && !options.ignoreChecker?.(start, end)) {
          return threats;
        }

        break;
      }
    }
  }

  if (options.minSeverity === "HIGH") return threats;

  /**
   * --------------------------------------------------
   * PSS002 — Base64 payload detection (MEDIUM)
   * --------------------------------------------------
   */

  const b64Regex = new RegExp(BASE64_REGEX);

  while ((match = b64Regex.exec(text)) !== null) {
    const candidate = match[0];

    const decoded = decodeBase64IfLikely(candidate);
    if (!decoded) continue;

    const start = match.index;
    const end = start + candidate.length;

    threats.push({
      ruleId: "PSS002",
      category: ThreatCategory.Smuggling,
      severity: "MEDIUM",
      message: "Detected Base64 payload containing readable content.",
      range: { start, end },
      offendingText: candidate,
      decodedPayload: decoded,
      readableLabel: `[Base64]: ${decoded.slice(0, 120)}...`,
      suggestion: "Decoded Base64 contains readable text. Inspect payload.",
      referenceUrl:
        "https://promptshield.js.org/docs/detectors/smuggling#PSS002",
    });

    if (options.stopOnFirstThreat && !options.ignoreChecker?.(start, end)) {
      return threats;
    }
  }

  /**
   * --------------------------------------------------
   * PSS006 — Hex payload detection
   * --------------------------------------------------
   */

  const hexRegex = new RegExp(HEX_REGEX);

  while ((match = hexRegex.exec(text)) !== null) {
    const candidate = match[0];

    const decoded = decodeHexIfLikely(candidate);
    if (!decoded) continue;

    const start = match.index;
    const end = start + candidate.length;

    threats.push({
      ruleId: "PSS006",
      category: ThreatCategory.Smuggling,
      severity: "MEDIUM",
      message: "Detected hex-encoded payload containing readable content.",
      range: { start, end },
      offendingText: candidate,
      decodedPayload: decoded,
      readableLabel: `[HEX]: ${decoded.slice(0, 120)}...`,
      suggestion: "Decoded hex contains readable text. Inspect payload.",
      referenceUrl:
        "https://promptshield.js.org/docs/detectors/smuggling#PSS006",
    });

    if (options.stopOnFirstThreat && !options.ignoreChecker?.(start, end)) {
      return threats;
    }
  }

  if (options.minSeverity === "MEDIUM") return threats;

  /**
   * --------------------------------------------------
   * PSS003 — Hidden Markdown comments
   * --------------------------------------------------
   */

  const commentRegex = new RegExp(MARKDOWN_COMMENT_REGEX);

  while ((match = commentRegex.exec(text)) !== null) {
    const start = match.index;
    const end = start + match[0].length;

    threats.push({
      ruleId: "PSS003",
      category: ThreatCategory.Smuggling,
      severity: "LOW",
      message: "Detected hidden Markdown comment.",
      range: { start, end },
      offendingText: match[0],
      readableLabel: "[Hidden Comment]",
      suggestion:
        "Comments are not visible in rendered Markdown but can carry instructions.",
      referenceUrl:
        "https://promptshield.js.org/docs/detectors/smuggling#PSS003",
    });

    if (options.stopOnFirstThreat && !options.ignoreChecker?.(start, end)) {
      return threats;
    }
  }

  /**
   * --------------------------------------------------
   * PSS004 — Invisible Markdown links (LOW)
   * --------------------------------------------------
   */

  const linkRegex = new RegExp(EMPTY_LINK_REGEX);

  while ((match = linkRegex.exec(text)) !== null) {
    const start = match.index;
    const end = start + match[0].length;

    threats.push({
      ruleId: "PSS004",
      category: ThreatCategory.Smuggling,
      severity: "LOW",
      message: "Detected empty Markdown link (invisible in rendered output).",
      range: { start, end },
      offendingText: match[0],
      readableLabel: "[Empty Link]",
      suggestion: "Empty links can be used to hide URLs or data.",
      referenceUrl:
        "https://promptshield.js.org/docs/detectors/smuggling#PSS004",
    });

    if (options.stopOnFirstThreat && !options.ignoreChecker?.(start, end)) {
      return threats;
    }
  }

  /**
   * --------------------------------------------------
   * PSS005 — Hidden HTML container
   * --------------------------------------------------
   */

  const containerRegex = new RegExp(HIDDEN_CONTAINER_REGEX);

  while ((match = containerRegex.exec(text)) !== null) {
    const offendingText = match[0];

    if (
      offendingText.startsWith("<details") &&
      SUMMARY_REGEXP.test(offendingText)
    )
      continue;

    const start = match.index;
    const end = start + offendingText.length;

    threats.push({
      ruleId: "PSS005",
      category: ThreatCategory.Smuggling,
      severity: "LOW",
      message: "Detected hidden HTML container potentially concealing content.",
      range: { start, end },
      offendingText,
      readableLabel: "[Hidden HTML]",
      suggestion:
        "Hidden containers may conceal instructions from rendered output.",
      referenceUrl:
        "https://promptshield.js.org/docs/detectors/smuggling#PSS005",
    });

    if (options.stopOnFirstThreat && !options.ignoreChecker?.(start, end)) {
      return threats;
    }
  }

  return threats;
};
