import { Extension } from "@tiptap/core";
import { PromptShieldHoverPlugin } from "./hover";
import { PromptShieldPlugin } from "./plugin";
import type { PromptShieldOptions, PromptShieldStorage } from "./types";

export const PromptShield = Extension.create<
  PromptShieldOptions,
  PromptShieldStorage
>({
  name: "promptshield",

  addOptions() {
    return {
      scanOnUpdate: true,
      scanOnPaste: true,
      debounceMs: 300,
      hoverUi: true,
      noInlineIgnore: false,
    };
  },

  addStorage() {
    return {
      threats: [],
      threatCount: 0,
    };
  },

  addProseMirrorPlugins() {
    const plugins = [PromptShieldPlugin(this.editor, this.options)];

    if (this.options.hoverUi) {
      plugins.push(PromptShieldHoverPlugin(this.editor));
    }

    return plugins;
  },
});
