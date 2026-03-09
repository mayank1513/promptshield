import type { ThreatReport } from "@promptshield/core";
import { applyFixes } from "@promptshield/sanitizer";
import {
  type CodeAction,
  CodeActionKind,
  type Diagnostic,
  Range,
  TextEdit,
} from "vscode-languageserver";
import type { TextDocument } from "vscode-languageserver-textdocument";
import { UNUSED_DIRECTIVE_CODE } from "./constants";

/**
 * Create "Fix with AI" code action.
 */
export const getAiFixAction = (
  document: TextDocument,
  threats: ThreatReport[],
): CodeAction => {
  return {
    title: "✨ Fix with AI",
    kind: CodeActionKind.QuickFix,
    command: {
      title: "Fix with AI",
      command: "promptshield.fixWithAI",
      arguments: [document.uri, threats],
    },
  };
};

/**
 * Compute a minimal edit between original and updated text.
 */
const computeMinimalEdit = (
  document: TextDocument,
  original: string,
  updated: string,
): TextEdit | null => {
  if (original === updated) return null;

  let start = 0;

  while (
    start < original.length &&
    start < updated.length &&
    original[start] === updated[start]
  ) {
    start++;
  }

  let endOriginal = original.length - 1;
  let endUpdated = updated.length - 1;

  while (
    endOriginal >= start &&
    endUpdated >= start &&
    original[endOriginal] === updated[endUpdated]
  ) {
    endOriginal--;
    endUpdated--;
  }

  const range = Range.create(
    document.positionAt(start),
    document.positionAt(endOriginal + 1),
  );

  const newText = updated.slice(start, endUpdated + 1);

  return TextEdit.replace(range, newText);
};

/**
 * Create "Fix all issues" code action.
 */
export const getFixAllAction = (
  document: TextDocument,
  threats: ThreatReport[],
): CodeAction | null => {
  if (threats.length === 0) return null;

  const original = document.getText();
  const result = applyFixes(original, threats);

  const edit = computeMinimalEdit(document, original, result.text);
  if (!edit) return null;

  return {
    title: "PromptShield: Fix all issues in file",
    kind: CodeActionKind.QuickFix,
    isPreferred: true,
    edit: { changes: { [document.uri]: [edit] } },
  };
};

/**
 * Map language ID to comment style.
 */
const COMMENT_STYLES: Record<string, string> = {
  javascript: "//",
  typescript: "//",
  javascriptreact: "//",
  typescriptreact: "//",
  java: "//",
  c: "//",
  cpp: "//",
  csharp: "//",
  go: "//",
  rust: "//",
  python: "#",
  ruby: "#",
  shellscript: "#",
  yaml: "#",
  dockerfile: "#",
};

/**
 * Fallback comment wrapping for unknown languages (like markdown)
 */
const getCommentDirective = (languageId: string, directive: string): string => {
  const prefix = COMMENT_STYLES[languageId];
  if (prefix) {
    return `${prefix} ${directive}`;
  }
  return `<!-- ${directive} -->`;
};

/**
 * Create "Ignore this line" code action.
 */
export const getIgnoreAction = (
  document: TextDocument,
  threat: ThreatReport,
): { action: CodeAction; directive: string } | null => {
  const startLine = threat.range.start.line - 1;
  const endLine = threat.range.end.line - 1;
  const lineCount = endLine - startLine + 1;

  const lineStart = document.offsetAt({ line: startLine, character: 0 });

  // Better: Get indentation from the current line to match
  const lineText = document.getText({
    start: { line: startLine, character: 0 },
    end: { line: startLine, character: 100 },
  });
  const match = lineText.match(/^(\s*)/);
  const indentation = match ? match[1] : "";

  const baseDirective =
    lineCount > 1
      ? `promptshield-ignore next ${lineCount}`
      : `promptshield-ignore`;

  const commentDirective = getCommentDirective(
    document.languageId,
    baseDirective,
  );

  const edit = TextEdit.insert(
    document.positionAt(lineStart),
    `${indentation}${commentDirective}\n`,
  );

  return {
    action: {
      title:
        lineCount > 1
          ? `PromptShield: Ignore next ${lineCount} lines`
          : "PromptShield: Ignore this line",
      kind: CodeActionKind.QuickFix,
      edit: { changes: { [document.uri]: [edit] } },
    },
    directive: commentDirective,
  };
};

/**
 * Create per-threat quick fixes.
 */
export const getThreatFixActions = (
  document: TextDocument,
  threats: ThreatReport[],
): CodeAction[] => {
  const original = document.getText();
  const seenActions = new Set<string>();
  const actions: CodeAction[] = [];

  for (const threat of threats) {
    const result = applyFixes(original, [threat]);
    const edit = computeMinimalEdit(document, original, result.text);

    if (edit) {
      const title = `PromptShield: Fix ${threat.category}`;
      if (!seenActions.has(title)) {
        seenActions.add(title);
        actions.push({
          title,
          kind: CodeActionKind.QuickFix,
          edit: { changes: { [document.uri]: [edit] } },
        });
      }
    }
  }

  return actions;
};

/**
 * Create "Remove unused ignore directive" code actions.
 */
export const getRemoveUnusedIgnoreActions = (
  document: TextDocument,
  diagnostics: Diagnostic[],
): CodeAction[] => {
  return diagnostics
    .filter((d) => d.code === UNUSED_DIRECTIVE_CODE)
    .map((diagnostic) => {
      const line = diagnostic.range.start.line;
      const lineText = document.getText({
        start: { line, character: 0 },
        end: { line: line + 1, character: 0 },
      });

      let editRange = diagnostic.range;

      const trimmed = lineText.trim();
      if (
        trimmed.startsWith("//") ||
        trimmed.startsWith("#") ||
        trimmed.startsWith("/*")
      ) {
        // If the line is just a comment, delete the whole line.
        editRange = {
          start: { line, character: 0 },
          end: { line: line + 1, character: 0 },
        };
      }

      const edit = TextEdit.replace(editRange, "");

      return {
        title: "PromptShield: Remove unused ignore directive",
        kind: CodeActionKind.QuickFix,
        edit: { changes: { [document.uri]: [edit] } },
      };
    });
};
