import type { ThreatReport } from "@promptshield/core";
import type { Editor } from "@tiptap/core";
import { Plugin } from "@tiptap/pm/state";
import type { EditorView } from "@tiptap/pm/view";
import {
  applyAllFixesToEditor,
  applyFixToEditor,
  ignoreThreatInEditor,
} from "./fixes";
import { PromptShieldPluginKey } from "./plugin";

class HoverTooltipView {
  private view: EditorView;
  private editor: Editor;
  private tooltip: HTMLElement | null = null;
  private hoverTimeout: ReturnType<typeof setTimeout> | null = null;

  constructor(view: EditorView, editor: Editor) {
    this.view = view;
    this.editor = editor;

    this.view.dom.addEventListener("mouseover", this.handleMouseOver);
    this.view.dom.addEventListener("mouseout", this.handleMouseOut);
  }

  private handleMouseOver = (e: MouseEvent) => {
    const target = e.target as HTMLElement;
    if (target.classList.contains("promptshield-threat")) {
      if (this.hoverTimeout) clearTimeout(this.hoverTimeout);

      this.hoverTimeout = setTimeout(() => {
        this.showTooltip(target);
      }, 200);
    }
  };

  private handleMouseOut = (e: MouseEvent) => {
    const relatedTarget = e.relatedTarget as HTMLElement;

    // If we are moving into the tooltip, do not hide
    if (this.tooltip?.contains(relatedTarget)) {
      return;
    }

    if (this.hoverTimeout) clearTimeout(this.hoverTimeout);

    this.hoverTimeout = setTimeout(() => {
      this.hideTooltip();
    }, 200);
  };

  private showTooltip(target: HTMLElement) {
    if (this.tooltip) this.hideTooltip();

    // Get position from the DOM node
    const pos = this.view.posAtDOM(target, 0);
    if (pos < 0) return;

    // Get the plugin state containing our decorations
    const decorationSet = PromptShieldPluginKey.getState(this.view.state);
    if (!decorationSet) return;

    // Find decorations spanning the hovered pos
    const length = target.textContent?.length || 1;
    const found = decorationSet.find(pos, pos + length);
    if (!found.length) return;

    // The threat object is inside the spec
    const threat = found[0].spec.threat as ThreatReport;
    if (!threat) return;

    this.tooltip = document.createElement("div");
    this.tooltip.className = "ps-tooltip-container";

    // Set Tooltip Content
    this.tooltip.innerHTML = `
      <div class="ps-tooltip-header">
        <div class="ps-tooltip-title">
          <span>🛡️ Detect: ${threat.category.replace(/_/g, " ")}</span>
        </div>
        <span class="ps-tooltip-category">${threat.severity}</span>
      </div>
      <div class="ps-tooltip-message">${threat.message}</div>
      <div class="ps-tooltip-actions"></div>
    `;

    // Actions
    const actionsContainer = this.tooltip.querySelector(".ps-tooltip-actions")!;

    // Try to provide a reliable fix if possible
    const canQuickFix = [
      "INVISIBLE_CHAR",
      "TROJAN_SOURCE",
      "NORMALIZATION",
      "SMUGGLING",
    ].includes(threat.category);

    if (canQuickFix && threat.suggestion) {
      const fixBtn = document.createElement("button");
      fixBtn.className = "ps-tooltip-button";
      fixBtn.innerText = "✨ Quick Fix: " + threat.suggestion;
      fixBtn.onclick = () => {
        applyFixToEditor(this.editor, threat);
        this.hideTooltip();
      };
      actionsContainer.appendChild(fixBtn);
    }

    // Ignore button
    const ignoreBtn = document.createElement("button");
    ignoreBtn.className = "ps-tooltip-button ps-tooltip-button-secondary";
    ignoreBtn.innerText = "👀 Ignore on this line";
    ignoreBtn.onclick = () => {
      ignoreThreatInEditor(this.editor, threat);
      this.hideTooltip();
    };
    actionsContainer.appendChild(ignoreBtn);

    // Fix All Button (if there are other threats)
    const storage = this.editor.storage["promptshield"];
    if (storage && storage.threatCount > 1) {
      const fixAllBtn = document.createElement("button");
      fixAllBtn.className = "ps-tooltip-button ps-tooltip-button-accent";
      fixAllBtn.innerText = `🛡️ Fix All (${storage.threatCount}) Issues`;
      fixAllBtn.onclick = () => {
        applyAllFixesToEditor(this.editor);
        this.hideTooltip();
      };
      actionsContainer.appendChild(fixAllBtn);
    }

    // Document styling prevents it from leaving when hovering
    this.tooltip.addEventListener("mouseleave", (ev) => {
      this.handleMouseOut(ev);
    });
    this.tooltip.addEventListener("mouseenter", () => {
      if (this.hoverTimeout) clearTimeout(this.hoverTimeout);
    });

    document.body.appendChild(this.tooltip);

    // Position the tooltip near the text
    const rect = target.getBoundingClientRect();
    this.tooltip.style.position = "absolute";
    this.tooltip.style.left = `${rect.left + window.scrollX}px`;
    this.tooltip.style.top = `${rect.bottom + window.scrollY + 5}px`;
  }

  private hideTooltip() {
    if (this.tooltip) {
      this.tooltip.remove();
      this.tooltip = null;
    }
  }

  update(view: EditorView) {
    this.view = view;
  }

  destroy() {
    this.view.dom.removeEventListener("mouseover", this.handleMouseOver);
    this.view.dom.removeEventListener("mouseout", this.handleMouseOut);
    if (this.tooltip) this.tooltip.remove();
    if (this.hoverTimeout) clearTimeout(this.hoverTimeout);
  }
}

export const PromptShieldHoverPlugin = (editor: Editor) => {
  return new Plugin({
    view(view) {
      return new HoverTooltipView(view, editor);
    },
  });
};
