import { scan } from "@promptshield/core";
import { filterThreats } from "@promptshield/ignore";
import { type Hover, MarkupKind, type Position } from "vscode-languageserver";
import type { TextDocument } from "vscode-languageserver-textdocument";
import { getIconMarkdown, ICONS } from "./icons";

/**
 * Provide hover information for threats at the given position.
 */
export const getHover = (
  document: TextDocument,
  position: Position,
): Hover | null => {
  const text = document.getText();
  const { threats: rawThreats } = scan(text);

  // Enrich with line/column information

  const { threats } = filterThreats(text, rawThreats);

  // Find threats intersecting the position
  const activeThreats = threats.filter((t) => {
    const { start, end } = t.range;

    // Check if position is within [start, end] range
    const isAfterStart =
      position.line > start.line - 1 ||
      (position.line === start.line - 1 &&
        position.character >= start.column - 1);

    const isBeforeEnd =
      position.line < end.line - 1 ||
      (position.line === end.line - 1 && position.character <= end.column - 1);

    return isAfterStart && isBeforeEnd;
  });

  if (activeThreats.length === 0) return null;

  const contents: string[] = [];

  for (const t of activeThreats) {
    let iconUrl = ICONS.TRIANGLE_ALERT;
    if (t.severity === "CRITICAL" || t.severity === "HIGH") {
      iconUrl = ICONS.SHIELD_ALERT;
    }

    const iconMd = getIconMarkdown(iconUrl, t.severity);

    let md = `### ${iconMd} ${t.category}\n\n`;
    md += `${t.message}\n\n`;

    if (t.suggestion) {
      md += `**Suggestion:** ${t.suggestion}\n`;
    }

    contents.push(md);
  }

  return {
    contents: {
      kind: MarkupKind.Markdown,
      value: contents.join("\n---\n"),
    },
  };
};
