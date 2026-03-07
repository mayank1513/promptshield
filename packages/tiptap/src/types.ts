import type { ScanOptions, ThreatReport } from "@promptshield/core";

export interface PromptShieldOptions extends ScanOptions {
  /**
   * Whether to scan automatically when the document is updated.
   * @default true
   */
  scanOnUpdate?: boolean;

  /**
   * Whether to scan automatically when content is pasted.
   * @default true
   */
  scanOnPaste?: boolean;

  /**
   * Milliseconds to debounce the scanner.
   * @default 300
   */
  debounceMs?: number;

  /**
   * Whether to enable the built-in UI tooltips on hover.
   * @default true
   */
  hoverUi?: boolean;

  /**
   * Whether to disable inline ignore directive parsing (`promptshield-ignore`).
   * @default false
   */
  noInlineIgnore?: boolean;
}

export interface PromptShieldStorage {
  threats: ThreatReport[];
  threatCount: number;
}

export interface PromptShieldEvents {
  "promptShield:updated": { threats: ThreatReport[] };
}
