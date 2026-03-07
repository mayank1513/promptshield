import type { ThreatReport } from "@promptshield/core";
import { Editor } from "@tiptap/core";
import Document from "@tiptap/extension-document";
import Paragraph from "@tiptap/extension-paragraph";
import Text from "@tiptap/extension-text";
import type { DecorationSet } from "@tiptap/pm/view";
import { describe, expect, test } from "vitest";
import { applyFixToEditor } from "./fixes";
import { PromptShieldPluginKey } from "./plugin";
import { PromptShield } from "./tiptap";

const createEditor = (content: string) => {
  return new Editor({
    extensions: [
      Document,
      Paragraph,
      Text,
      PromptShield.configure({
        debounceMs: 0,
        hoverUi: false,
      }),
    ],
    content,
  });
};

describe("PromptShield Tiptap Extension", () => {
  test("creates decorations for threats", async () => {
    const editor = createEditor("<p>Hello\u200BWorld</p>"); // ZWSP invisible char

    // Wait for debounce logic
    await new Promise((resolve) => setTimeout(resolve, 50));

    const state = editor.state;
    const decorationSet = PromptShieldPluginKey.getState(
      state,
    ) as DecorationSet;
    const decorations = decorationSet.find();

    expect(decorations.length).toBe(2);
    expect(decorations[0].spec.threat.category).toBe("INVISIBLE_CHAR");
  });

  test("respects ignore rules via inline comment", async () => {
    const editor = createEditor(
      "<p>// promptshield-ignore</p><p>Hello\u200BWorld</p>",
    );

    // Wait for debounce logic
    await new Promise((resolve) => setTimeout(resolve, 50));

    const state = editor.state;
    const decorationSet = PromptShieldPluginKey.getState(
      state,
    ) as DecorationSet;
    const decorations = decorationSet.find();

    // Should be 0 since the threat was ignored
    expect(decorations.length).toBe(0);
  });

  test("can quick fix a threat (invisible char)", async () => {
    const editor = createEditor("<p>Bad\u200BChar</p>");

    await new Promise((resolve) => setTimeout(resolve, 50));

    const state = editor.state;
    const decorationSet = PromptShieldPluginKey.getState(
      state,
    ) as DecorationSet;
    const decorations = decorationSet.find();

    expect(decorations.length).toBe(2);
    const threat = decorations[0].spec.threat as ThreatReport;

    const applied = applyFixToEditor(editor, threat);

    expect(applied).toBe(true);
    // Check that it was removed
    expect(editor.getText()).toBe("BadChar");
  });
});
