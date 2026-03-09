---
"@promptshield/tiptap": patch
"@promptshield/sanitizer": patch
---

- Upgrade to Tiptap v3 with backward compatibility for v2.
- Move Tiptap core dependencies to peerDependencies.
- Add `canFixThreat` logic to filter actions in the hover UI (homoglyphs and complex smuggling cases are hidden).
- Fix CodeQL warning in `@promptshield/sanitizer` regarding incomplete multi-character sanitization.
- Improve TypeScript ergonomics with module augmentation for storage and events.
