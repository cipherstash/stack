---
'@cipherstash/stack-drizzle': patch
'stash': patch
---

Fix invalid DDL from `drizzle-kit generate`/`push` for EQL v3 encrypted columns.
A v3 column declared its SQL type as the schema-qualified domain
(`public.eql_v3_text_search`), but drizzle-kit wraps a custom type's whole name
in a single pair of double quotes — emitting `"public.eql_v3_text_search"`, which
Postgres reads as one dotted identifier and rejects with `type
"public.eql_v3_text_search" does not exist`. Generated migrations had to be
hand-repaired.

The v3 column now emits the **unqualified** domain (`eql_v3_text_search`), which
drizzle-kit renders as the valid `"eql_v3_text_search"` and which resolves via the
search path (the domains live in `public`). This matches how the v2
`encryptedType` surface already declares its type, and how drizzle-kit reads the
type back during a `push` introspection diff, so the two sides no longer disagree.
Builder recovery still yields the canonical `public.eql_v3_*` identity, so
operators and schema extraction are unchanged.

The bundled `stash-drizzle` skill is updated to describe the unqualified generated
type and the search-path requirement (hence the `stash` bump — the skill ships in
its tarball).
