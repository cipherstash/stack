---
'stash': patch
---

`stash init`'s setup prompt no longer tells agents to declare an EQL v2 cutover
column with a `types.*` domain.

The `types.*` factories are EQL v3 only — a v2 column is an `eql_v2_encrypted`
composite — so an agent following the old step-4 guidance would author a schema
that cannot describe the column it just cut over to. The prompt now says
explicitly not to use `types.*` for a v2 column, and points at the deprecated
`@cipherstash/stack/schema` builders with decryption through
`@cipherstash/stack`, which is the actual read path for legacy v2 rows.
