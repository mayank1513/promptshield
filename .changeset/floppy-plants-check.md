---
"@promptshield/core": major
---

Remove performance metrics from the core scanning API.

The `ScanStats` interface has been removed and the `stats` field has been
removed from `ScanResult`.

Performance measurements such as `durationMs` and `totalChars` are now considered
integration concerns and should be implemented by higher-level tooling such as
the CLI, LSP, or other runtime wrappers.

`@promptshield/core` now focuses purely on deterministic lexical scanning and
threat detection without runtime instrumentation.

### API change summary

Before:

```ts
export interface ScanResult {
  threats: ThreatReport[]
  stats: ScanStats
  isClean: boolean
}
```

After:

```ts
export interface ScanResult {
  threats: ThreatReport[]
  isClean: boolean
}
```

`scan()` no longer returns the stats.
