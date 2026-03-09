import { scan } from "@promptshield/core";
import type { Editor } from "@tiptap/core";
import type { Node as ProseMirrorNode } from "@tiptap/pm/model";
import { Plugin, PluginKey } from "@tiptap/pm/state";
import { Decoration, DecorationSet } from "@tiptap/pm/view";
import type { PromptShieldOptions } from "./types";
import { extractTextAndMapping, mapTextIndexToPmPos } from "./utils";

export const PromptShieldPluginKey = new PluginKey("promptShield");

export const PromptShieldPlugin = (
  editor: Editor,
  options: PromptShieldOptions,
) => {
  let timeout: ReturnType<typeof setTimeout> | null = null;
  const debounceMs = options.debounceMs ?? 300;

  // Function to scan document and return decorations
  const runScan = (doc: ProseMirrorNode) => {
    const { text, mapping } = extractTextAndMapping(doc);

    // 1. Scan text using @promptshield/core
    const scanResult = scan(text, options);
    const threats = scanResult.threats;

    // 3. Update Storage & Emit Events
    const storage = editor.storage.promptshield;
    if (storage) {
      storage.threats = threats;
      storage.threatCount = threats.length;
    }
    // @ts-expect-error
    editor.emit("promptShield:updated", { threats });

    // 4. Create decorations
    const decorations: Decoration[] = [];

    for (const threat of threats) {
      if (threat.range.start.index < 0 || !threat.offendingText) continue;

      const pmStart = mapTextIndexToPmPos(threat.range.start.index, mapping);
      if (pmStart === null) continue;

      const pmEnd = pmStart + threat.offendingText.length;

      const severityClass = `ps-severity-${threat.severity.toLowerCase()}`;

      // Inline decoration for the highlight
      decorations.push(
        Decoration.inline(
          pmStart,
          pmEnd,
          {
            class: `promptshield-threat ${severityClass}`,
            "data-ps-threat": "true",
          },
          { threat },
        ),
      );
    }

    return DecorationSet.create(doc, decorations);
  };

  return new Plugin({
    key: PromptShieldPluginKey,

    state: {
      init(_, { doc }) {
        if (options.scanOnUpdate !== false) {
          return runScan(doc);
        }
        return DecorationSet.empty;
      },
      apply(tr, oldState) {
        // If we dispatched a transaction specifically with new decorations
        const newDecorationsMeta = tr.getMeta(PromptShieldPluginKey);
        if (newDecorationsMeta) {
          return newDecorationsMeta;
        }
        // Map old decorations through document changes
        return oldState.map(tr.mapping, tr.doc);
      },
    },

    props: {
      decorations(state) {
        return this.getState(state);
      },
    },

    view(view) {
      const scheduleScan = () => {
        if (timeout) clearTimeout(timeout);
        timeout = setTimeout(() => {
          const newDecorations = runScan(view.state.doc);
          const tr = view.state.tr.setMeta(
            PromptShieldPluginKey,
            newDecorations,
          );
          view.dispatch(tr);
        }, debounceMs);
      };

      return {
        update(view, prevState) {
          if (options.scanOnUpdate === false) return;

          if (!view.state.doc.eq(prevState.doc)) {
            scheduleScan();
          }
        },
        destroy() {
          if (timeout) clearTimeout(timeout);
        },
      };
    },
  });
};
