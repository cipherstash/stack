---
"stash": minor
"@cipherstash/wizard": minor
---

Rename `stash db install` to `stash eql install`. The command scaffolds
`stash.config.ts` and installs the EQL extensions, so it now lives under a
dedicated `eql` command group. `stash db install` keeps working as a
deprecated alias that prints a warning pointing at the new name. All help
text, hints, generated migration headers, and wizard steps now reference
`stash eql install`.
