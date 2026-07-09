---
'@cipherstash/stack': patch
---

Fix the Supabase adapter encrypting `is` and `null` filter operands.

`is` is a SQL predicate — PostgREST accepts only `null`/`true`/`false` after it
— and a `null` operand is SQL NULL, never a value to search for. Only the direct
`.is()` filter skipped encryption; `not()`, `or()`, `match()`, raw `filter()`,
and the `in()` element list all encrypted whatever they were handed. So
`or('age.is.null')` emitted `age.is."("null")"` and `eq('email', null)` emitted
`email=("null")` — operands PostgREST rejects. A null plaintext is stored as a
NULL column rather than ciphertext, so it is found with an unencrypted
`IS NULL`; encrypting the operand could never match.

A single `isEncryptableTerm(operator, value)` predicate now guards every term
collector. Affects both `encryptedSupabase` (v2) and `encryptedSupabaseV3`. On
v3 this additionally removes a spurious `does not support equality queries`
error, which `is` raised because it maps to the `equality` query type and so hit
the column-capability guard — `or('active.is.null')` on a storage-only column
threw rather than querying.

Relatedly, an `or()` string is now rebuilt whenever a condition *references* an
encrypted column, not only when one of its values was encrypted. An `is` on an
encrypted column encrypts nothing, and the old condition sent it down the
verbatim path, forwarding the caller's JS property name to a database that only
knows the column's DB name.
