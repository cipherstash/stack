---
name: stash-postgres
description: Query EQL v3 encrypted columns from hand-written Postgres SQL over `pg` (node-postgres) or `postgres` (postgres-js) — no ORM. Covers the column-domain-to-query-domain operator matrix (which of `=`, `<>`, `<`, `>=`, `@@`, `@>` each encrypted domain accepts), minting search needles with `encryptQuery`, the per-driver parameter-binding rules for encrypted payloads, and the double-encoding failure that trips the domain CHECK with a message naming neither JSON nor encoding. Use when writing INSERT/SELECT against an encrypted column without an ORM, when a predicate returns zero rows or raises "operator does not exist", or when a domain CHECK constraint rejects an encrypted value on write.
---

# Raw Postgres SQL Against Encrypted Columns (EQL v3)

An EQL v3 encrypted column is a **Postgres domain over `jsonb`** (`public.eql_v3_text_search`,
`public.eql_v3_bigint_ord`, …). Reading and writing it from raw SQL is two rules:

1. **Writing** — bind the `Encrypted` payload your client produced as a
   *JSON object* parameter. How you do that differs per driver, and getting it
   wrong trips a domain CHECK with an unhelpful message.
2. **Querying** — never send a plaintext. Mint a **query term** with
   `encryptQuery` and cast it to the column's matching `eql_v3.query_*`
   domain. That cast is what selects the right operator overload: leave the
   operand as bare `jsonb` and you get a *different* overload, one that
   expects a full storage envelope.

This covers the `pg` and `postgres-js` drivers with no ORM — plain Node
services, Hono, edge functions. If you use Drizzle, Prisma Next, or the
Supabase client, those integrations emit correct operands for you: see
`stash-drizzle`, `stash-prisma-next`, `stash-supabase` instead.

## When to Use This Skill

- Writing `INSERT` / `UPDATE` / `SELECT` against an encrypted column by hand.
- A predicate returns zero rows, or errors with `operator does not exist`.
- A write fails with `value for domain eql_v3_… violates check constraint`.
- Choosing the right operator for a column's domain.
- Ordering, ranging, or searching inside an encrypted JSON document.

## The Two Halves

Assume `users.email` is a `types.TextEq` column — the domain names below
follow the column, so a `types.TextSearch` column would use
`eql_v3.query_text_search` in exactly the same places.

```ts
// 1. Encrypt for storage — the payload includes the ciphertext (`c`).
const enc = await client.encrypt('alice@example.com', { table: users, column: users.email })
if (enc.failure) throw new Error(enc.failure.message)
await sql`INSERT INTO users (email) VALUES (${sql.json(enc.data)})`

// 2. Mint a search needle — CIPHERTEXT-FREE, terms only.
const term = await client.encryptQuery('alice@example.com', {
  table: users, column: users.email, queryType: 'equality',
})
if (term.failure) throw new Error(term.failure.message)
const rows = await sql`
  SELECT * FROM users WHERE email = ${sql.json(term.data)}::jsonb::eql_v3.query_text_eq`
```

Storage payloads and query terms are **different shapes with different
domains**. A storage payload carries `c` (the ciphertext); a query term
deliberately omits it and the `eql_v3.query_*` CHECKs *require* its absence.
Binding a storage payload where a query term belongs fails the CHECK, and vice
versa.

`queryType` is one of `'equality'`, `'freeTextSearch'`, `'orderAndRange'`,
`'searchableJson'`. Omit it only for single-index columns (`types.TextEq`);
be explicit on multi-index domains like `types.TextSearch`.

## Naming: Column Domain → Query Domain

Strip `public.`, insert `query_`, move to the `eql_v3` schema:

```
public.eql_v3_text_eq       →  eql_v3.query_text_eq
public.eql_v3_text_search   →  eql_v3.query_text_search
public.eql_v3_bigint_ord    →  eql_v3.query_bigint_ord
public.eql_v3_timestamp_ord →  eql_v3.query_timestamp_ord
```

**One irregular case:** `types.Json` builds `public.eql_v3_json_search`, but
its query domain is `eql_v3.query_json` — not `query_json_search`.

| Schema factory | Column domain (`public.`) | Query domain (`eql_v3.`) |
|---|---|---|
| `types.TextEq` | `eql_v3_text_eq` | `query_text_eq` |
| `types.TextMatch` | `eql_v3_text_match` | `query_text_match` |
| `types.TextOrd` | `eql_v3_text_ord` | `query_text_ord` |
| `types.TextSearch` | `eql_v3_text_search` | `query_text_search` |
| `types.<N>Eq` | `eql_v3_<n>_eq` | `query_<n>_eq` |
| `types.<N>Ord` | `eql_v3_<n>_ord` | `query_<n>_ord` |
| `types.<N>OrdOre` | `eql_v3_<n>_ord_ore` | `query_<n>_ord_ore` |
| `types.Json` | `eql_v3_json_search` | **`query_json`** |
| `types.Text`, `types.<N>`, `types.Boolean` | `eql_v3_text` / `eql_v3_<n>` / `eql_v3_boolean` | **none — storage only** |

`<N>` ranges over `Integer`, `Smallint`, `Bigint`, `Numeric`, `Real`,
`Double`, `Date`, `Timestamp`. The storage-only domains carry no query terms
by design — there is no query domain and nothing to search server-side.

## The Predicate Matrix

Which operators each column domain accepts against its query domain. Anything
not listed does not exist as an encrypted operator.

| Column domain | Operators | Query domain operand |
|---|---|---|
| `eql_v3_<n>_eq`, `eql_v3_text_eq` | `=` `<>` | `query_<n>_eq` / `query_text_eq` |
| `eql_v3_<n>_ord`, `eql_v3_text_ord` | `=` `<>` `<` `<=` `>` `>=` | `query_<n>_ord` / `query_text_ord` |
| `eql_v3_<n>_ord_ore`, `eql_v3_text_ord_ore` | `=` `<>` `<` `<=` `>` `>=` | `query_<n>_ord_ore` / `query_text_ord_ore` |
| `eql_v3_text_match` | `@@` | `query_text_match` |
| `eql_v3_text_search` | `=` `<>` `<` `<=` `>` `>=` `@@` | `query_text_search` |
| `eql_v3_json_search` | `@>` | `query_json` |
| `eql_v3_json_entry` (from `col -> 'selector'`) | `=` `<>` `<` `<=` `>` `>=` | any `query_<n>_ord` / `query_text_ord` / `query_text_search` |

Note what is **absent**: there is no `<` on an `_eq` domain, and no `@@`
outside the match-capable text domains. Asking for one raises
`operator does not exist` — which is the good failure. The bad failure is
leaving the operand as bare `jsonb` (see [Traps](#traps)).

Every operator has a function twin, useful when an operator is awkward to
emit: `eql_v3.eq(col, term)`, `eql_v3.matches(col, term)`, and the comparison
functions. `col = term` and `eql_v3.eq(col, term)` are equivalent.

## Binding Parameters: The Driver Rules

**This differs between drivers.** Both encrypted payloads and query terms are
plain JS objects, and the two drivers disagree about how to put a JS object
into a `jsonb`-backed domain.

### `postgres` (postgres-js) — always `sql.json(...)`

| Binding form | `INSERT` into a domain column | Query operand with `::jsonb::eql_v3.query_*` |
|---|---|---|
| `${sql.json(payload)}` | ✅ | ✅ |
| `${payload}` (bare object) | ❌ `invalid input syntax for type json` | ✅ |
| `${JSON.stringify(payload)}::jsonb` | ❌ CHECK violation | ❌ CHECK violation |

**Use `sql.json(...)` in both positions** — it is the only form that works in
both, so there is no reason to track which position you are in.

```ts
await sql`INSERT INTO users (email) VALUES (${sql.json(enc.data)})`
await sql`SELECT * FROM users
           WHERE email = ${sql.json(term.data)}::jsonb::eql_v3.query_text_eq`
```

### `pg` (node-postgres) — pass the object

node-postgres serialises a JS object to JSON exactly once, so all three forms
happen to work. Pass the object and let the driver do it:

```ts
await client.query('INSERT INTO users (email) VALUES ($1)', [enc.data])
await client.query(
  'SELECT * FROM users WHERE email = $1::eql_v3.query_text_eq', [term.data])
```

Do not pre-stringify even though `pg` tolerates it — it is the one habit that
silently breaks if the project ever moves to `postgres-js`.

### The double-encoding failure, precisely

`${JSON.stringify(payload)}::jsonb` on postgres-js produces:

```
value for domain eql_v3_text_search violates check constraint "eql_v3_text_search_check"
```

The message names neither JSON nor encoding, which is why this one costs an
afternoon. What happened: the explicit `::jsonb` makes postgres-js infer a
`jsonb` parameter, so it JSON-encodes the value — which was *already* a JSON
string. The result is a jsonb **string scalar**, not an object:

```sql
SELECT jsonb_typeof($1::jsonb)   -- 'string', not 'object'
```

Every EQL domain CHECK opens with `jsonb_typeof(VALUE) = 'object'`, so it
fails on the very first clause. Diagnose any CHECK-violation-on-write by
running `jsonb_typeof` on the parameter; `'string'` means double-encoded.

## Query Recipes

Assume `sql` is a postgres-js tag; for `pg` use numbered placeholders as above.

### Equality

```ts
const term = await client.encryptQuery(email, {
  table: users, column: users.email, queryType: 'equality',
})
await sql`SELECT * FROM users
           WHERE email = ${sql.json(term.data)}::jsonb::eql_v3.query_text_eq`
```

On a `types.TextSearch` column the cast is `::eql_v3.query_text_search` — the
query domain always matches the *column's* domain, not the query type.

### Free-text match

```ts
// `bio` is a types.TextSearch column here; on a types.TextMatch column the
// cast is ::eql_v3.query_text_match.
const term = await client.encryptQuery('needle', {
  table: users, column: users.bio, queryType: 'freeTextSearch',
})
await sql`SELECT * FROM users
           WHERE bio @@ ${sql.json(term.data)}::jsonb::eql_v3.query_text_search`
```

Match is **one-sided**: a hit may be a false positive, a miss never is. Filter
client-side after decryption if exactness matters — and never build a negated
match (`NOT (bio @@ …)`), which would drop true rows. Needles must be at least
3 characters; shorter ones tokenize to nothing and are rejected.

### Range and ordering

```ts
const term = await client.encryptQuery(new Date('2026-01-01'), {
  table: events, column: events.createdAt, queryType: 'orderAndRange',
})
await sql`SELECT * FROM events
           WHERE created_at >= ${sql.json(term.data)}::jsonb::eql_v3.query_timestamp_ord
           ORDER BY eql_v3.ord_term(created_at) DESC
           LIMIT 20`
```

**`ORDER BY` must use the extractor form.** `ORDER BY created_at` sorts the
raw encrypted payload — which is neither meaningful nor index-backed. Sorting
on `eql_v3.ord_term(col)` is both. Ordering is available on `_ord`,
`_ord_ore`, and `text_search` columns; use `ord_term_ore` for `_ord_ore`.

### Encrypted JSON — containment

```ts
const needle = await client.encryptQuery({ role: 'admin' }, {
  table: users, column: users.prefs, queryType: 'searchableJson',
})
await sql`SELECT * FROM users
           WHERE prefs @> ${sql.json(needle.data)}::jsonb::eql_v3.query_json`
```

An **object** value produces a containment needle. Note the containment needle
is a bare `{ sv: [...] }` shape with no version field — unlike the scalar
terms, which are full v3 envelopes. Bind it the same way regardless.

### Encrypted JSON — field selector

A **string** value produces a JSONPath selector, and v3 has no encrypted-selector
envelope: `encryptQuery` returns the **bare selector-hash string**. Bind it as
the plain text argument of `->` / `->>`, with no domain cast:

```ts
const sel = await client.encryptQuery('$.role', {
  table: users, column: users.prefs, queryType: 'searchableJson',
})
await sql`SELECT prefs -> ${sel.data} FROM users`
```

The extracted value is an `eql_v3_json_entry`, which accepts the ordering
operators — so a field inside an encrypted document can be ranged and ordered:

```ts
await sql`SELECT * FROM orders
           WHERE data -> ${sel.data} >= ${sql.json(term.data)}::jsonb::eql_v3.query_integer_ord
           ORDER BY eql_v3.ord_term(data -> ${sel.data})`
```

Field-level `=` between extracted entries is **not** supported (an extracted
entry carries no value selector) — use document containment for exact field
equality.

## Reading Rows Back

`SELECT` returns the stored payload as an object; hand it straight to
`decrypt` — do not `JSON.parse` it, and do not cast it to `::jsonb` in the
query (see the projection trap below).

```ts
const [row] = await sql`SELECT id, email FROM users WHERE id = ${id}`
const dec = await client.decrypt(row.email)
if (dec.failure) throw new Error(dec.failure.message)
```

For whole rows, `decryptModel` / `bulkDecryptModels` walk the schema and
decrypt every declared column in one ZeroKMS round trip. They match by **JS
property name**, so a raw `SELECT` returning snake_case DB column names will
not match a schema keyed by camelCase properties — alias in the query
(`SELECT last_login AS "lastLogin"`) or decrypt the columns individually.

## Traps

**A bare `::jsonb` operand picks a different operator, not a missing one.**
EQL also defines overloads with `jsonb` on the right — and they coerce that
operand to the **storage** domain:

```sql
-- what `col = $1::jsonb` actually resolves to:
eql_v3.eq_term(a) = eql_v3.eq_term(b::public.eql_v3_text_search)
```

The storage domain's CHECK requires the ciphertext key `c`, which query terms
deliberately omit — so binding a query term without the domain cast raises a
CHECK violation rather than doing what you meant. Those overloads exist so you
can compare against a *full storage envelope* (an already-encrypted value).
For a needle from `encryptQuery`, always cast to the `eql_v3.query_*` domain.

**Cast to the `query_*` domain, not the column domain.** `$1::public.eql_v3_text_eq`
fails for the same reason — the column domain's CHECK requires `c`.

**The `value::jsonb` projection trap.** `SELECT email::jsonb … ORDER BY email`
folds the cast into the scan and sorts on `(email)::jsonb`, matching no index.
Project the column raw.

**`GROUP BY` / `DISTINCT` on the raw column** hashes the whole encrypted
payload (1–2 KB per row) and spills. Group on the extractor —
`GROUP BY eql_v3.eq_term(email)` — which is small and deterministic.

**Predicates are not indexes.** Everything here works without an index and
sequential-scans. Adding the functional index over the extractor is a separate
step — see `stash-indexing`.

**Every writer needs the same credentials.** Index terms derive from the
ZeroKMS client key, so rows written by a client with different `CS_*`
credentials decrypt correctly but never match a query — silently. This
includes `stash encrypt backfill` and seed scripts. See `stash-edge` §
The Credential-Identity Rule.

## Troubleshooting

**`operator does not exist: public.eql_v3_… = eql_v3.query_…`** — the domain
pair has no such operator. Check the [matrix](#the-predicate-matrix): the
column's domain may not support that predicate (e.g. `<` on an `_eq` column),
or the query domain does not match the column's domain.

**`value for domain … violates check constraint`** on write — double-encoded
payload; run `SELECT jsonb_typeof($1::jsonb)` and see
[above](#the-double-encoding-failure-precisely). On a *query* operand, the
same error usually means a storage payload (with `c`) was bound where a query
term belongs.

**Zero rows, no error** — in order of likelihood: (1) the rows were written
under different `CS_*` credentials (see the trap above — this is the common
one, and it is completely silent); (2) the column's domain does not carry the
term the predicate needs (a `types.Text` column carries none); (3) a
free-text needle under 3 characters tokenized to nothing. A *missing* domain
cast raises an error rather than returning zero rows, so it is not a candidate
here.

**Slow but correct** — no index. See `stash-indexing`; confirm with
`EXPLAIN (COSTS OFF)` that the plan shows an `Index Cond` on the extractor
rather than a `Seq Scan`.

**Checking what a column actually is**, when the schema and the database may
have drifted:

```sql
SELECT column_name, domain_schema, domain_name
  FROM information_schema.columns
 WHERE table_name = 'users' AND domain_name LIKE 'eql_v3%';
```

## Reference

- `stash-encryption` — schema authoring, the `types.*` catalog, `encryptQuery`
  and the client API, the rollout/cutover lifecycle.
- `stash-indexing` — functional indexes over the term extractors, and the
  `EXPLAIN` checklist.
- `stash-edge` — the WASM entry, `CS_*` credentials, and the
  credential-identity rule.
- `stash-cli` — `stash eql install`, `stash db validate`, `stash encrypt backfill`.
