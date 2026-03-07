import { scanHomoglyphs } from "./homoglyph";
import { scanInjectionPatterns } from "./injection-patterns";
import { scanInvisibleChars } from "./invisible";
import { scanNormalization } from "./normalization";
import { scanSmuggling } from "./smuggling";
import { scanTrojanSource } from "./trojan";
import type { Detector, ScanOptions, ScanResult, ThreatReport } from "./types";

/**
 * Core scanning entry point.
 *
 * Executes all enabled detectors in priority order:
 *
 * 1. Trojan Source (BIDI logic manipulation)
 * 2. Invisible characters
 * 3. Homoglyph spoofing
 * 4. Unicode normalization anomalies
 * 5. Smuggling techniques
 *
 * @example
 * ```ts
 * import { scan } from '@promptshield/core';
 *
 * const result = scan("Hello\u200BWorld");
 * if (!result.isClean) {
 *   console.log(result.threats);
 * }
 * ```
 */
export const scan = (text: string, options: ScanOptions = {}): ScanResult => {
  const threats: ThreatReport[] = [];

  const detectors: Detector[] = [];

  if (!options.disableTrojan) detectors.push(scanTrojanSource);
  if (!options.disableInvisible) detectors.push(scanInvisibleChars);
  if (!options.disableHomoglyphs) detectors.push(scanHomoglyphs);
  if (!options.disableNormalization) detectors.push(scanNormalization);
  if (!options.disableSmuggling) detectors.push(scanSmuggling);
  if (!options.disableInjectionPatterns) detectors.push(scanInjectionPatterns);

  for (const detector of detectors) {
    const detectorThreats = detector(text, options);
    threats.push(...detectorThreats);

    if (options.stopOnFirstThreat && detectorThreats.length > 0) {
      break;
    }
  }

  return {
    threats,
    isClean: threats.length === 0,
  };
};
