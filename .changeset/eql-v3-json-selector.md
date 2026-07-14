---
'@cipherstash/stack-drizzle': minor
---

Add EQL v3 JSON **selector-with-constraint** querying to the Drizzle integration
(#623). `ops.selector(col, '$.path')` returns comparison methods bound to a
JSONPath into a `types.Json` column — `eq`/`ne`/`gt`/`gte`/`lt`/`lte` — emitting
`col->'<selector>' <op> <value>` over the encrypted document. Its unique power
over `contains` is **ordering at a path** (`col->'$.age' > 21`), which
containment cannot express.

Complements the existing `contains` (JSONB `@>`) containment operator. Core
`@cipherstash/stack` needs no change — the selector term and comparison entry are
produced by `encryptQuery`/`encrypt` on the existing `types.Json` surface. v1
supports dot-notation object paths; array-index/wildcard paths are rejected with
a clear error. The Supabase adapter is tracked separately.
