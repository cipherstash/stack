---
'@cipherstash/stack-supabase': patch
'@cipherstash/stack': minor
'stash': patch
---

Diagnose an EQL v2 table by name instead of crashing with a raw `TypeError`.

A v2 `EncryptedTable` is structurally identical to a v3 one — same `tableName`,
same `columnBuilders` — and only `buildColumnKeyMap()` tells them apart. Passing
one to `encryptedSupabase({ schemas })` therefore sailed past every check that
looked at shape and died deep inside verification as `builder.getEqlType is not
a function`, naming an internal method rather than the version mismatch that
caused it. Constructing the query builder directly failed the same way one layer
down, as `table.buildColumnKeyMap is not a function`.

Both paths now fail closed with the table named and the fix stated. The check
routes through `hasBuildColumnKeyMap`, the canonical v2/v3 discriminator, rather
than a second hand-written spelling of it.

`@cipherstash/stack` re-exports `hasBuildColumnKeyMap` from
`@cipherstash/stack/adapter-kit` so first-party adapters can make that routing
decision without reaching into internals. It is deliberately not on `./types`:
deciding which wire version a table targets is adapter plumbing, not end-user
API.
