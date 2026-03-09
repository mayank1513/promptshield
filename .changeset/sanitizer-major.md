---
"@promptshield/sanitizer": major
---

feat(@promptshield/sanitizer): bump to major version to align with @promptshield/core breaking changes

The core scanning engine has been refactored to use offset-based detection and centralized location resolution. Since sanitizer depends directly on core's scanning logic and report format, this major bump ensures ecosystem consistency.
