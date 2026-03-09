import type { ThreatReport } from "@promptshield/core";
import type { Editor } from "@tiptap/core";
import { Plugin } from "@tiptap/pm/state";
import type { EditorView } from "@tiptap/pm/view";
import { applyAllFixesToEditor, applyFixToEditor, canFixThreat } from "./fixes";
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
    this.tooltip.className = "ps-tooltip-container ps-vscode-theme";

    const ruleId = threat.ruleId || "UNKNOWN";
    const categoryLabel = threat.category.replace(/_/g, " ");
    const severity = threat.severity.toUpperCase();

    // Shield Icon SVG
    const shieldIcon = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="ps-icon-shield"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>`;

    // Set Tooltip Content
    this.tooltip.innerHTML = `
      <div class="ps-tooltip-content">
        <div class="ps-tooltip-section ps-tooltip-header">
          <div class="ps-tooltip-title-row">
            ${shieldIcon}
            <span class="ps-tooltip-title">PromptShield: ${categoryLabel} (${ruleId})</span>
          </div>
        </div>

        <div class="ps-tooltip-section">
          <div class="ps-tooltip-severity-row">
            <span class="ps-tooltip-label">Severity:</span>
            <span class="ps-tooltip-value ps-severity-${threat.severity.toLowerCase()}">${severity}</span>
          </div>
          <div class="ps-tooltip-message">${threat.message}</div>
          <a href="https://promptshield.js.org/docs" target="_blank" class="ps-tooltip-link">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path><polyline points="15 3 21 3 21 9"></polyline><line x1="10" y1="14" x2="21" y2="3"></line></svg>
            Learn more
          </a>
        </div>

        ${
          threat.offendingText
            ? `
        <div class="ps-tooltip-section ps-tooltip-context">
          <div class="ps-tooltip-label">Offending Text:</div>
          <code class="ps-tooltip-code">${threat.offendingText}</code>
        </div>
        `
            : ""
        }
      </div>

      <div class="ps-tooltip-footer">
        <div class="ps-dropdown">
          <button class="ps-tooltip-action-btn ps-btn-secondary ps-dropdown-trigger" id="ps-quick-fix-trigger">
            Quick Fix...
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>
          </button>
          <div class="ps-dropdown-menu" id="ps-quick-fix-menu" style="display: none;">
            ${
              canFixThreat(threat)
                ? `
            <button class="ps-dropdown-item" id="ps-apply-fix">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
              Apply fix
            </button>
            `
                : ""
            }
            <button class="ps-dropdown-item" id="ps-fix-all">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
              Fix all issues
            </button>
          </div>
        </div>
      </div>
    `;

    // Event Listeners for Actions
    const trigger = this.tooltip.querySelector("#ps-quick-fix-trigger");
    const menu = this.tooltip.querySelector(
      "#ps-quick-fix-menu",
    ) as HTMLElement;
    const applyFixBtn = this.tooltip.querySelector("#ps-apply-fix");
    const fixAllBtn = this.tooltip.querySelector("#ps-fix-all");

    if (trigger && menu) {
      trigger.addEventListener("click", (e) => {
        e.stopPropagation();
        const isVisible = menu.style.display === "block";
        menu.style.display = isVisible ? "none" : "block";
      });

      // Close menu when clicking outside
      const closeMenu = () => {
        menu.style.display = "none";
      };

      document.addEventListener("click", closeMenu, { once: true });
    }

    if (applyFixBtn) {
      applyFixBtn.addEventListener("click", () => {
        applyFixToEditor(this.editor, threat);
        this.hideTooltip();
      });
    }

    if (fixAllBtn) {
      fixAllBtn.addEventListener("click", () => {
        applyAllFixesToEditor(this.editor);
        this.hideTooltip();
      });
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
