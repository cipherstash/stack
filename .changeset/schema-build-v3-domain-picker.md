---
'stash': patch
---

`stash schema build` now picks a concrete EQL v3 domain per column
(`TextSearch`, `IntegerOrd`, `TextEq`, …) instead of the legacy v2
"searchable capabilities" toggle. Boolean and JSON columns are assigned
their single storage-only domain automatically; other columns default to
the widest searchable domain, matching the previous behaviour. The
internal `SearchOp` capability tuple and the `v3DomainFactory` translation
shim are removed, unblocking EQL v2 removal (#707, #751).
