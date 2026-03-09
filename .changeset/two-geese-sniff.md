---
"@promptshield/core": major
---

Enhance detection coverage and introduce multi-line threat spans.

## Security

* Added **hex-encoded payload detection (PSS006)** to detect hidden instructions encoded in hexadecimal.
* Improved **Base64 payload detection (PSS002)** with support for:

  * whitespace-broken Base64
  * character-spaced Base64 obfuscation.
* Added **hidden HTML container detection (PSS005)** for `<details>` and `<template>` elements used to conceal instructions.
* Improved **Trojan Source detection** with support for nested BIDI contexts.

## Breaking

* Threat ranges may now span **multiple lines**.
* Consumers must not assume threats occur on a single line.
* UI layers should project multi-line threats into per-line diagnostics when needed.

## Added

* **PSS005** — Hidden HTML container detection.
* **PSS006** — Hex-encoded payload detection.
* Support for **chunked / spaced Base64 evasion techniques**.

## Improved

* Trojan Source detector now correctly handles **nested BIDI override contexts**.
* Added coverage for additional directionality marks:

  * LRM (`U+200E`)
  * RLM (`U+200F`)
  * ALM (`U+061C`)
* Unicode iteration updated to **code point–safe traversal**.
* Correct handling of **CRLF and mixed line endings**.

## Docs

* Updated smuggling detector documentation.
* Added real-world Trojan Source examples from the original research paper.
* Improved explanations for multi-line threat handling.
