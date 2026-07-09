---
'@cipherstash/stack': minor
---

Add `encryptedSupabaseV3` — the EQL v3 dialect of the Supabase adapter. It is
now a connect-time-async factory: `await encryptedSupabaseV3(url, key)` (or
`(client)`) introspects the database over `DATABASE_URL`, detects EQL v3 columns
by their Postgres domain (`information_schema.columns.domain_name`), and derives
each column's encryption config from its domain — callers no longer pass a
schema to `from()`. `select('*')` is supported (expanded from the introspected
column list, and aliased back to each declared column's JS property name so a
property→DB rename round-trips). A column using an EQL v3 domain this SDK version does not model
(e.g. `public.json`, `*_ord_ope`) throws at construction rather than silently
passing through. Supplying `schemas` remains optional and adds compile-time
types plus startup verification of the declared tables against the database.
Requires a Postgres connection for introspection (`pg` is a new optional peer),
so it cannot run in a Worker or the browser. v2 (`encryptedSupabase`) is
unchanged.
