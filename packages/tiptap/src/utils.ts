import type { Node } from "@tiptap/pm/model";

export interface TextMapping {
  textStart: number;
  textEnd: number;
  pmStart: number;
}

export interface DocumentTextAndMapping {
  text: string;
  mapping: TextMapping[];
}

export function extractTextAndMapping(doc: Node): DocumentTextAndMapping {
  let text = "";
  const mapping: TextMapping[] = [];

  doc.descendants((node, pos) => {
    if (node.isText) {
      const nodeText = node.text || "";
      mapping.push({
        textStart: text.length,
        textEnd: text.length + nodeText.length,
        pmStart: pos,
      });
      text += nodeText;
    } else if (node.type.name === "hard_break") {
      mapping.push({
        textStart: text.length,
        textEnd: text.length + 1,
        pmStart: pos,
      });
      text += "\n";
    } else if (node.isBlock && node.content.size > 0) {
      if (text.length > 0 && text[text.length - 1] !== "\n") {
        text += "\n";
      }
    }
  });

  return { text, mapping };
}

export function mapTextIndexToPmPos(
  index: number,
  mapping: TextMapping[],
): number | null {
  for (const map of mapping) {
    if (index >= map.textStart && index < map.textEnd) {
      return map.pmStart + (index - map.textStart);
    }
  }
  return null;
}
