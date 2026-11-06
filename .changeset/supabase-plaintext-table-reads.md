---
"@cipherstash/stack-supabase": patch
---

Reading a table that has no encrypted columns no longer fails. Such a table is
not registered with the encryption client, and the adapter still asked the
client to decrypt its rows, so every `select()` on it, and every insert, update
or upsert followed by `.select()`, returned "decryptModel received a table this
client was not initialized with" (or threw, with `throwOnError`). On the
`wasm-inline` entry, writes to such a table failed the same way. The adapter now
passes the rows of a table with no encrypted columns straight through, in both
introspection and declared mode, without calling the encryption client.
