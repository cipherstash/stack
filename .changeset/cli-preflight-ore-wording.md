---
"stash": patch
---

`stash eql preflight` now describes the ORE operator class check in words that
apply to every SDK and every EQL version. When the role cannot create the
class, the output names types by suffix: OPE-ordered types (`*Ord`) and
ORE types (`*OrdOre`, `*SearchOre`). The output no longer names the
TypeScript `types.*` factories or the EQL v3 domains. `stash eql install`,
`stash eql status`, and `stash eql verify` print the same remedy sentence, so
it changes there too.

Where EQL is already installed, preflight no longer predicts a fallback that
`stash eql install` would not install, and points at `stash eql status`
instead. The row values, exit codes, and `--json` output are unchanged.
