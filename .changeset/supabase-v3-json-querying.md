---
'@cipherstash/stack-supabase': minor
'@cipherstash/stack': minor
---

Encrypted-JSON querying on the v3 Supabase surface (#650). A `types.Json`
column now supports exact encrypted containment — `contains(col, subDocument)`
(ste_vec `@>` via PostgREST `cs`, with the sub-document storage-encrypted
against the column) — and JSONPath selector predicates: `selectorEq(col, path,
value)` and `selectorNe(col, path, value)` (dot-notation paths; `ne` includes
rows where the path is absent, mirroring the Drizzle selector's semantics).
Raw `.filter(col, 'cs', subDocument)` and `not(col, 'contains', …)` route
through the same encrypted path. Selector ordering is not expressible over
PostgREST yet (needs an EQL-bundle overload — see
cipherstash/encrypt-query-language#407); the Drizzle integration's
`ops.selector()` covers ordering today.

In core, `QueryTypesForColumn` gains the `searchableJson` arm (a `types.Json`
column no longer resolves to `never`, so typed adapter key sets can include
it), and the JSONPath selector-path helpers the Drizzle adapter introduced in
#651 moved to `@cipherstash/stack/adapter-kit` so both adapters share one
validation surface (`@cipherstash/stack-drizzle` re-exports them unchanged).
