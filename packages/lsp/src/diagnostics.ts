import { SEVERITY_MAP, type ThreatReport } from "@promptshield/core";
import type { Diagnostic, DiagnosticSeverity } from "vscode-languageserver";
import { SOURCE } from "./constants";

/**
 * Converts ThreatReports into LSP Diagnostics.
 *
 * Design notes:
 * - PromptShield locations are 1-based; LSP is 0-based.
 * - `ruleId` is preferred for the diagnostic code.
 * - The full ThreatReport is attached via `data` so the
 *   VSCode extension can reconstruct decorations and actions.
 */
export const convertReportsToDiagnostics = (
  reports: ThreatReport[],
): Diagnostic[] => {
  const grouped = new Map<number, ThreatReport[]>();
  for (const r of reports) {
    const group = grouped.get(r.range.start.index) ?? [];
    group.push(r);
    grouped.set(r.range.start.index, group);
  }

  const diagnostics: Diagnostic[] = [];
  for (const [_index, group] of grouped) {
    // Highest severity (lowest numerical value in DiagnosticSeverity)
    group.sort((a, b) => {
      return SEVERITY_MAP[a.severity] - SEVERITY_MAP[b.severity];
    });
    const primaryReport = group[0];

    const start = primaryReport.range.start;
    const end = primaryReport.range.end;

    let message = primaryReport.message;
    if (group.length > 1) {
      const categories = Array.from(new Set(group.map((g) => g.category)));
      message = `[Multiple Threats] ${categories.join(", ")}`;
    }

    const range = {
      start: { line: start.line - 1, character: start.column - 1 },
      end: { line: end.line - 1, character: end.column - 1 },
    };
    diagnostics.push({
      severity: SEVERITY_MAP[primaryReport.severity] as DiagnosticSeverity,
      range,
      message,
      source: SOURCE,
      code: Array.from(new Set(group.map((g) => g.ruleId))).join(", "),
      data: group, // Pass the array of threats
    });
  }

  return diagnostics;
};
