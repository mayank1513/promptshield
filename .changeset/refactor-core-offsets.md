---
"@promptshield/core": major
---

Refactored the core scanning engine to use offset-based detection and centralized location resolution.

- Detectors now operate on absolute character offsets instead of line/column coordinates.
- Introduced `enrichWithLocation` utility for post-processing character offsets into human-readable locations.
- Simplified `scan` entry point by removing manual line-splitting logic.
- Updated `ThreatReport` to use a `range` object.
  ```ts
  range: {
    start: { line, column, index }
    end: { line, column, index }
  }
  ```
