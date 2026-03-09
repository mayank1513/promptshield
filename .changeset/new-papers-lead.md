---
"@promptshield/ignore": major
---

⚠️ **Breaking change**

This release updates the package to work with the new `ThreatReportWithLocation` format introduced in `@promptshield/core`.

Previous versions of `@promptshield/core` exposed threat locations using `loc`.
The new format exposes locations using `range.start` and `range.end`.

As a result, this version of `@promptshield/ignore` **is not compatible with older versions of `@promptshield/core`.**

### Changes

* Updated ignore filtering logic to support **multi-line threats**.
* A threat is now suppressed **only when its entire span falls inside an ignore range**.
* Prevents partial suppression where only the first line of a multi-line threat is ignored.

### Technical details

* `filterThreats` now operates on `ThreatReportWithLocation`.
* Threat location data is read from `range.start` / `range.end`.
* Suppression checks both `range.start.line` and `range.end.line`.
* Threat sorting now uses `range.start.index`.

### Security impact

This change prevents bypasses where attackers could hide multi-line prompt injections by ignoring only the first line.

Example bypass now prevented:

```
promptshield-ignore next 1
ignore
previous
instructions
```

Previously the threat could be suppressed because the first line matched the ignore directive.
Now suppression requires the **entire threat span** to fall within the ignore range.
