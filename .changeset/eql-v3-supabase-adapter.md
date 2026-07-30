---
'@cipherstash/stack-supabase': minor
---

`encryptedSupabase` is a connect-time-async, introspecting EQL v3 factory:
`await encryptedSupabase(url, key)` (or `(client)`) introspects the database over
`DATABASE_URL`, detects EQL v3 columns by their Postgres domain
(`information_schema.columns.domain_name`), and derives each column's encryption
config from its domain — callers no longer pass a schema to `from()`.
`select('*')` is supported (expanded from the introspected column list, and
aliased back to each declared column's JS property name so a property→DB rename
round-trips). A column using a `public.eql_v3_*` domain this SDK version does not
model throws when its table is named via `from()` rather than silently passing
through. Supplying `schemas` remains optional and adds compile-time types plus
eager construction-time verification of the declared tables against the
database — including that same unmodelled-column check. Requires a Postgres connection for
introspection (`pg` is an optional peer), so it cannot run in a Worker or the
browser.

Every column name a query carries — filters, `match`, `not`, raw `filter`,
`or()`, `order()`, and the `onConflict` option — is resolved from its JS property
name to its DB column name in a single pass before the query is built, so a
declared rename round-trips everywhere rather than only on the paths that
remembered to translate.

`.or()` understands PostgREST's `column.not.<op>.<value>` negation. It was
previously parsed as `{ op: 'not', value: '<op>.<value>' }`, so on an encrypted
column `or('nickname.not.in.(ada,grace)')` encrypted the literal string
`in.(ada,grace)` as a single plaintext and produced a filter that silently
matched nothing.

Encrypted free-text search is `matches(column, value)`, narrowed at compile time
to columns whose domain carries the `freeTextSearch` capability
(`public.eql_v3_text_match`, `public.eql_v3_text_search`) and guarded at runtime
for the untyped surface. It matches any needle whose trigrams are all present in
the stored value; needles shorter than the tokenizer's window (3 characters)
bloom to nothing and are rejected rather than silently matching every row. A raw
`filter(column, operator, …)` on an encrypted column derives its query type from
the operator instead of always encrypting an equality term, so
`filter('bio', 'cs', …)` on a `public.eql_v3_text_match` column works rather than
being rejected, and an unsupported operator throws instead of silently encrypting
the wrong term.

The v3 match index emits `include_original: false` — the flag is inert in
protect-ffi (the bloom is trigram-only either way), so this moves no ciphertext
and only pins the value a substring-search domain wants.
