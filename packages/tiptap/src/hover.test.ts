import { Editor } from "@tiptap/core";
import Document from "@tiptap/extension-document";
import Paragraph from "@tiptap/extension-paragraph";
import Text from "@tiptap/extension-text";
import type { DecorationSet } from "@tiptap/pm/view";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { PromptShieldPluginKey } from "./plugin";
import { PromptShield } from "./tiptap";

const createEditor = (content: string, element: HTMLElement) => {
  return new Editor({
    element,
    extensions: [
      Document,
      Paragraph,
      Text,
      PromptShield.configure({
        debounceMs: 0,
        hoverUi: true,
      }),
    ],
    content,
  });
};

describe("Tiptap Hover UI", () => {
  let container: HTMLElement;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
  });

  afterEach(() => {
    document.body.innerHTML = "";
    vi.clearAllMocks();
  });

  const sleep = (ms: number) =>
    new Promise((resolve) => setTimeout(resolve, ms));

  test("shows tooltip on hover", { timeout: 15000 }, async () => {
    const editor = createEditor("<p>Bad\u200BChar</p>", container);

    // Verify decorations exist in state
    const decorationSet = PromptShieldPluginKey.getState(
      editor.state,
    ) as DecorationSet;
    expect(decorationSet.find().length).toBeGreaterThan(0);

    // Wait for DOM to catch up
    await sleep(100);

    const threatEl = container.querySelector(
      ".promptshield-threat",
    ) as HTMLElement;
    expect(threatEl).not.toBeNull();

    // Trigger mouseover
    threatEl.dispatchEvent(new MouseEvent("mouseover", { bubbles: true }));

    // Tooltip is debounced by 200ms in hover.ts
    await sleep(300);

    const tooltip = document.querySelector(".ps-tooltip-container");
    expect(tooltip).not.toBeNull();
    expect(tooltip?.textContent).toContain("PromptShield");
    expect(tooltip?.textContent).toContain("INVISIBLE CHAR");
  });

  test("hides tooltip on mouseout", { timeout: 15000 }, async () => {
    const editor = createEditor("<p>Bad\u200BChar</p>", container);
    await sleep(100);

    const threatEl = container.querySelector(
      ".promptshield-threat",
    ) as HTMLElement;
    threatEl.dispatchEvent(new MouseEvent("mouseover", { bubbles: true }));
    await sleep(300);

    expect(document.querySelector(".ps-tooltip-container")).not.toBeNull();

    // Trigger mouseout
    threatEl.dispatchEvent(
      new MouseEvent("mouseout", {
        bubbles: true,
        relatedTarget: document.body,
      }),
    );

    // Hide is debounced by 200ms
    await sleep(300);

    expect(document.querySelector(".ps-tooltip-container")).toBeNull();
  });

  test("interacts with Quick Fix menu", { timeout: 15000 }, async () => {
    const editor = createEditor("<p>Bad\u200BChar</p>", container);
    await sleep(100);

    const threatEl = container.querySelector(
      ".promptshield-threat",
    ) as HTMLElement;
    threatEl.dispatchEvent(new MouseEvent("mouseover", { bubbles: true }));
    await sleep(300);

    const tooltip = document.querySelector(
      ".ps-tooltip-container",
    ) as HTMLElement;
    const trigger = tooltip.querySelector(
      "#ps-quick-fix-trigger",
    ) as HTMLElement;
    const menu = tooltip.querySelector("#ps-quick-fix-menu") as HTMLElement;

    expect(menu.style.display).toBe("none");

    // Click trigger to open menu
    trigger.click();
    expect(menu.style.display).toBe("block");

    // Click apply fix
    const applyBtn = tooltip.querySelector("#ps-apply-fix") as HTMLElement;
    applyBtn.click();

    // Tooltip should be hidden immediately upon fix applying
    expect(document.querySelector(".ps-tooltip-container")).toBeNull();

    // Content should be fixed
    expect(editor.getText()).toBe("BadChar");
  });

  test("triggers Fix All from tooltip", { timeout: 15000 }, async () => {
    // Use normalization which is more predictable for text length in tests
    const editor = createEditor("<p>\u210B1</p><p>\u210B2</p>", container);
    await sleep(100);

    const threatEl = container.querySelector(
      ".promptshield-threat",
    ) as HTMLElement;
    threatEl.dispatchEvent(new MouseEvent("mouseover", { bubbles: true }));
    await sleep(300);

    const tooltip = document.querySelector(
      ".ps-tooltip-container",
    ) as HTMLElement;
    (tooltip.querySelector("#ps-quick-fix-trigger") as HTMLElement).click();

    const fixAllBtn = tooltip.querySelector("#ps-fix-all") as HTMLElement;
    fixAllBtn.click();

    expect(document.querySelector(".ps-tooltip-container")).toBeNull();

    // Tiptap .getText() adds \n\n between paragraphs by default in happy-dom
    expect(editor.getText().replace(/\n\n/g, "\n")).toBe("H1\nH2");
  });

  test("cleans up on destroy", async () => {
    const editor = createEditor("<p>Bad\u200BChar</p>", container);
    await sleep(100);

    const threatEl = container.querySelector(
      ".promptshield-threat",
    ) as HTMLElement;
    threatEl.dispatchEvent(new MouseEvent("mouseover", { bubbles: true }));
    await sleep(300);

    expect(document.querySelector(".ps-tooltip-container")).not.toBeNull();

    // Destroy the editor
    editor.destroy();

    // Tooltip should be removed
    expect(document.querySelector(".ps-tooltip-container")).toBeNull();
  });
});
