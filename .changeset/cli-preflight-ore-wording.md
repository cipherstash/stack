---
"stash": patch
---

`stash eql preflight` now describes the ORE operator class check in words that
apply to every SDK and every EQL version. When the role cannot create the
class, the output names types by suffix: OPE-ordered types (`*Ord`) and
ORE-ordered types (`*OrdOre`). It no longer names the TypeScript `types.*`
factories or the EQL v3 domains. `stash eql install`, `stash eql status`, and
`stash eql verify` print the same remedy sentence, so it changes there too.
The row values, exit codes, and `--json` output are unchanged.
