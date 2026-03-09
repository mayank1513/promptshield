# @promptshield/sanitizer

## 1.0.0

### Major Changes

- [`36c59e8`](https://github.com/promptshield-io/promptshield/commit/36c59e8a177ab763050017226c12a317d36fc32d) Thanks [@mayank1513](https://github.com/mayank1513)! - feat(@promptshield/sanitizer): bump to major version to align with @promptshield/core breaking changes

  The core scanning engine has been refactored to use offset-based detection and centralized location resolution. Since sanitizer depends directly on core's scanning logic and report format, this major bump ensures ecosystem consistency.

### Patch Changes

- [`ac51eda`](https://github.com/promptshield-io/promptshield/commit/ac51eda96f796d5b175b17f997a675e0b1ea375e) Thanks [@mayank1513](https://github.com/mayank1513)! - - Upgrade to Tiptap v3 with backward compatibility for v2.
  - Move Tiptap core dependencies to peerDependencies.
  - Add `canFixThreat` logic to filter actions in the hover UI (homoglyphs and complex smuggling cases are hidden).
  - Fix CodeQL warning in `@promptshield/sanitizer` regarding incomplete multi-character sanitization.
  - Improve TypeScript ergonomics with module augmentation for storage and events.

## 0.0.2

### Patch Changes

- Updated dependencies [[`33694ff`](https://github.com/promptshield-io/promptshield/commit/33694ff124629e4f7797e1624b1a3acde8af0c38), [`4c3ddc7`](https://github.com/promptshield-io/promptshield/commit/4c3ddc7a2f3e2a5c0d085ee8f34463bbbeaa7056), [`aac8870`](https://github.com/promptshield-io/promptshield/commit/aac8870183a5b118348e2b0e4bc9323bf86ecb32)]:
  - @promptshield/core@1.0.0

## 0.0.1

### Patch Changes

- Updated dependencies [[`811fad0`](https://github.com/promptshield-io/promptshield/commit/811fad055be08b2bf845aa3daff18fdb90677333)]:
  - @promptshield/core@0.1.0
