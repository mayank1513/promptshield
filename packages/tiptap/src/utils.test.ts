import { Editor } from "@tiptap/core";
import Document from "@tiptap/extension-document";
import Paragraph from "@tiptap/extension-paragraph";
import Text from "@tiptap/extension-text";
import { describe, expect, test } from "vitest";
import { extractTextAndMapping, mapTextIndexToPmPos } from "./utils";

const createEditor = (content: string) => {
  return new Editor({
    extensions: [Document, Paragraph, Text],
    content,
  });
};

describe("Tiptap Utils", () => {
  describe("extractTextAndMapping", () => {
    test("extracts text from a single paragraph", () => {
      const editor = createEditor("<p>Hello World</p>");
      const { text, mapping } = extractTextAndMapping(editor.state.doc);

      expect(text).toBe("Hello World");
      expect(mapping).toHaveLength(1);
      expect(mapping[0]).toEqual({
        textStart: 0,
        textEnd: 11,
        pmStart: 1,
      });
    });

    test("handles multiple paragraphs", () => {
      const editor = createEditor("<p>Line 1</p><p>Line 2</p>");
      const { text, mapping } = extractTextAndMapping(editor.state.doc);

      expect(text).toBe("Line 1\nLine 2");
      expect(mapping).toHaveLength(2);

      expect(mapping[0]).toEqual({ textStart: 0, textEnd: 6, pmStart: 1 });
      expect(mapping[1]).toEqual({ textStart: 7, textEnd: 13, pmStart: 9 });
    });

    test("handles empty blocks", () => {
      const editor = createEditor("<p></p><p>Content</p>");
      const { text, mapping } = extractTextAndMapping(editor.state.doc);

      expect(text).toBe("Content");
      expect(mapping).toHaveLength(1);
      expect(mapping[0]).toEqual({ textStart: 0, textEnd: 7, pmStart: 3 });
    });
  });

  describe("mapTextIndexToPmPos", () => {
    const mapping = [
      { textStart: 0, textEnd: 5, pmStart: 1 },
      { textStart: 5, textEnd: 6, pmStart: 6 }, // Simulator for a hard break or newline if it was a block
      { textStart: 6, textEnd: 11, pmStart: 7 },
    ];

    test("maps index within a range", () => {
      expect(mapTextIndexToPmPos(0, mapping)).toBe(1);
      expect(mapTextIndexToPmPos(2, mapping)).toBe(3);
      expect(mapTextIndexToPmPos(4, mapping)).toBe(5);
    });

    test("maps index at start of range", () => {
      expect(mapTextIndexToPmPos(6, mapping)).toBe(7);
    });

    test("returns null for index out of range", () => {
      expect(mapTextIndexToPmPos(11, mapping)).toBeNull();
      expect(mapTextIndexToPmPos(-1, mapping)).toBeNull();
    });

    test("handles empty mapping", () => {
      expect(mapTextIndexToPmPos(0, [])).toBeNull();
    });
  });
});
