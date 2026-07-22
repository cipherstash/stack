---
'stash': patch
---

`stash schema build` now picks a concrete EQL v3 domain per column
(`TextSearch`, `IntegerOrd`, `TextEq`, …) instead of the legacy v2
"searchable capabilities" toggle. Boolean columns are assigned the
storage-only `types.Boolean` domain automatically, while JSON columns are
assigned the queryable `types.Json` domain, with encrypted containment and
selector queries. Other columns default to the widest searchable domain,
matching the previous behaviour. The internal `SearchOp` capability tuple
and the `v3DomainFactory` translation shim are removed, unblocking EQL v2
removal (#707, #751).
