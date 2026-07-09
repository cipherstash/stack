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
remembered to translate.

`order()` on ANY encrypted v3 column is now rejected — at compile time when
`schemas` is supplied, and at runtime otherwise. The EQL v3 domains are
`DOMAIN … AS jsonb` and the bundle declares no btree operator class on them, so
`ORDER BY col` resolves through jsonb's default `jsonb_cmp` and sorts by the
envelope's byte structure: a stable, plausible-looking, meaningless row order,
with no error. Correct ordering is `ORDER BY eql_v3.ord_term(col)`, which
PostgREST's `order=` cannot express. Order by a plaintext column, expose
`eql_v3.ord_term()` as a generated column or view, or use the EQL v3 Drizzle
integration, which emits `ord_term` directly. Note `gte`/`lte` filters remain
correct: the comparison operators *are* declared on the ord domains, and only
sorting resolves through the missing operator class.

`.or()` now understands PostgREST's `column.not.<op>.<value>` negation. It was
previously parsed as `{ op: 'not', value: '<op>.<value>' }`, so on an encrypted
column `or('nickname.not.in.(ada,grace)')` encrypted the literal string
`in.(ada,grace)` as a single plaintext and produced a filter that silently
matched nothing.

Free-text search on the v3 builder is `contains(column, value)`. `like`/`ilike`
are not exposed, because EQL v3 free-text search is token containment over a
bloom filter (`@>`, backed by `eql_v3.contains`) rather than SQL wildcard
matching — `%` is tokenized like any other character, so a `like` pattern is a
category error. This matches the v3 Drizzle integration, which omits them for
the same reason. On an encrypted column `like`/`ilike` now throw and name
`contains`; on a plaintext column they remain ordinary PostgREST filters.

`contains` is narrowed at compile time to columns whose domain carries the
`freeTextSearch` capability (`public.text_match`, `public.text_search`), and
guarded at runtime for the untyped surface. A raw `filter(column, operator, …)`
on an encrypted v3 column now derives its query type from the operator instead
of always encrypting an equality term, so `filter('bio', 'cs', …)` on a
`public.text_match` column works rather than being rejected, and an unsupported
operator throws instead of silently encrypting the wrong term.

Substring `contains` still matches only when the needle equals the stored value
or is exactly the tokenizer's window (3 characters): the operand is a storage
envelope whose bloom carries the whole needle as an `include_original` token.
This is shared with v3 Drizzle's `contains` and tracked upstream in EQL.

v2 (`encryptedSupabase`) is unchanged: it keeps `like`/`ilike` (`eql_v2.like`,
`~~`) and its raw-`filter` query-type mapping, so no v2 ciphertext moves.
