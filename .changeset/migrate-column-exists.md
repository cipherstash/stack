---
'@cipherstash/migrate': minor
'stash': patch
---

Add `columnExists(client, tableName, columnName)` — a case-exact "does this
column exist at all?" catalog probe, distinct from `detectColumnEqlVersion`'s
"and is it an EQL column?".

Callers need that difference to tell a STALE column reference (it is gone) from
a live one the domain classifier simply does not recognise — most often a legacy
`eql_v2_encrypted` counterpart.

`stash encrypt cutover` / `drop` had a private copy of this probe built on a bare
`to_regclass($1)`. That form *parses* its argument and case-folds unquoted
identifiers, so on a Prisma-style `"User"` table it resolved `user`, reported the
column missing, and treated a valid recorded pairing as stale — silently skipping
the fail-closed that stops those commands acting on a guessed encrypted column.
The shared implementation quotes with `format('%I')` first, like every other
catalog probe in this package, so the lookup is case-exact while still honouring
`search_path` for unqualified names.
