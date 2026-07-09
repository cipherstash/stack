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
so it cannot run in a Worker or the browser.

Every column name a query carries — filters, `match`, `not`, raw `filter`,
`or()`, `order()`, and the `onConflict` option — is now resolved from its JS
property name to its DB column name in a single pass before the query is built,
so a declared rename round-trips everywhere rather than only on the paths that
remembered to translate. `order()` on a column whose domain has no
`orderAndRange` capability (e.g. a storage-only `public.boolean`) is rejected —
at compile time when `schemas` is supplied, and at runtime otherwise — instead
of silently sorting by the raw ciphertext envelope.

v2 (`encryptedSupabase`) is unchanged.
