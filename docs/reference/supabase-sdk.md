# Supabase SDK reference

`@cipherstash/stack-supabase` wraps a supabase-js client so encrypted columns
are transparently encrypted on mutations, `::jsonb`-cast on selects, encrypted
in filter terms, and decrypted in results.

One entry point, EQL v3 only:

| Entry point | Schema DSL | Column storage |
|---|---|---|
| `encryptedSupabase` | `@cipherstash/stack/eql/v3` (EQL v3) | native `public.eql_v3_*` domains |

`encryptedSupabaseV3` remains as a `@deprecated`, type-identical alias. The old
EQL v2 authoring wrapper — `encryptedSupabase({ encryptionClient,
supabaseClient })` — has been removed; the name now binds to the v3 factory
below.

It filters via **direct EQL operators over PostgREST**: the wrapper encrypts
the filter term and emits an ordinary `col <op> term` filter, which resolves
to the custom operator defined on the encrypted type (equality by HMAC, range
by the ordering term — CLLW-OPE on `_ord` domains, block-ORE on `_ord_ore` —
free-text by bloom-filter containment).

## Quick start (EQL v3)

`encryptedSupabase` is an async factory that **introspects the database at
connect time**: it detects EQL v3 columns by their Postgres domain, derives
each column's encryption config from the domain, and builds the encryption
client internally. Introspection needs a direct Postgres connection
(`options.databaseUrl`, defaulting to `DATABASE_URL`), so the factory cannot
run in a Worker or the browser.

```typescript
import { encryptedSupabase } from '@cipherstash/stack-supabase'

// Introspects the database via options.databaseUrl or DATABASE_URL
const es = await encryptedSupabase(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_ANON_KEY!,
)
// or wrap an existing client: await encryptedSupabase(supabaseClient, options)

await es.from('users').insert({ email: 'a@b.com', amount: 30 })

const { data } = await es
  .from('users')
  .select('id, email, amount')
  .eq('email', 'a@b.com')

await es.from('users').select('id, amount').gte('amount', 10).lte('amount', 100)
```

`from(tableName)` takes only the table name — no schema argument; column
capabilities come from the introspected domains.

The builder surface is `.select/.insert/.update/.upsert/.delete`,
`.eq/.neq/.in/.is/.gt/.gte/.lt/.lte/.match/.or/.not/.filter`,
transforms (`.order/.limit/.range/.single/.maybeSingle/.csv/.abortSignal/.throwOnError`),
plus `.withLockContext(lockContext)` and `.audit(config)`. For free-text
search it exposes `.matches()` (fuzzy bloom token search) on encrypted
columns, keeps `.contains()` for native (exact) containment on plaintext
columns, and treats `like`/`ilike` on an encrypted column as an approximate
shim that delegates to `.matches()` (see "v3 encoding details" below).

### Typing (v3)

Declared schemas are optional. Passing `schemas` — a record whose keys must
equal each table's name — adds compile-time types and verifies the declared
tables against the database at construction:

```typescript
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { encryptedSupabase } from '@cipherstash/stack-supabase'

const users = encryptedTable('users', {
  email:  types.TextSearch('email'),   // public.eql_v3_text_search
  amount: types.IntegerOrd('amount'),  // public.eql_v3_integer_ord
})

const es = await encryptedSupabase(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_ANON_KEY!,
  { schemas: { users } },
)
```

`es.from('users')` then infers rows as **exactly** the table's plaintext
shape (schema columns get their domain plaintext types — `types.IntegerOrd` →
`number`, `types.TimestampOrd` → `Date`, …). Storage-only columns (e.g.
`types.Boolean`) are excluded from every filter method — including `.match()` —
at the type level, `matches()` is narrowed to match-indexed columns, and
`order()` to plaintext columns; filtering a storage-only column is always a
clear runtime error. Undeclared tables behave exactly as with no `schemas` at
all: `from<Row>(tableName)` returns the untyped v3 builder, with `Row`
defaulting to `Record<string, unknown>`.

Every v3 column is fully described by its `types.*` factory — there are no
capability or tuning chains on v3 columns.

### Property ↔ DB column names (v3)

A v3 column can map a JS property to a different DB name:

```typescript
const events = encryptedTable('events', {
  createdAt: types.TimestampOrd('created_at'),
})
```

The adapter resolves the mapping everywhere: filters and mutations address
`created_at`, selects alias it back (`createdAt:created_at::jsonb`), and
result rows are keyed by `createdAt`. `date` / `timestamp` columns decrypt
to real `Date` objects (reconstructed from the encrypt-config `cast_as`).

## Database setup

### v3: per-domain columns

```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email public.eql_v3_text_search,
  amount public.eql_v3_integer_ord,
  created_at public.eql_v3_timestamp_ord
);
```

The `types.*` member name maps to the flat domain name: strip the `eql_v3_`
prefix and PascalCase each `_`-separated segment (`types.TextEq` → `public.eql_v3_text_eq`,
`types.IntegerOrd` → `public.eql_v3_integer_ord`, `types.Timestamp` → `public.eql_v3_timestamp`).
The domains use SQL-standard type names (`integer`, `smallint`, `real`,
`double`, `boolean`, `timestamp`).

### Install EQL

```bash
# v2 (default)
stash eql install --supabase

# v3
stash eql install --eql-version 3 --supabase
```

For **v2**, `--supabase` selects the opclass-stripped bundle (operator
classes / families require superuser, which Supabase does not grant) and
applies the schema grants for `anon`, `authenticated`, and `service_role`.
Without the grants, encrypted queries fail with `42501`.

For **v3**, since eql-3.0.0 there is **one** SQL artifact for every target —
no separate Supabase variant. The bundle's only superuser-requiring
statements (the `ore_block_256` operator class/family) self-skip on
`insufficient_privilege`, and the bundle then disables the ORE-opclass-backed
domains it cannot support (CIP-3468) — so the same bundle installs with or
without `--supabase`. The flag changes one thing: it additionally applies the
role grants for `anon` / `authenticated` / `service_role`.

The vendored v3 bundle is the `eql-3.0.0` release artifact. It installs two
schemas: `eql_v3` (index-term extractors and the operator-backing comparison
functions) and `eql_v3_internal` (SEM internals — support functions and types
the domains depend on); the column domains themselves live in `public`. The
installer applies role grants to **both** EQL schemas; `eql_v3_internal`
needs the grants but must never be exposed (see below). Without the grants,
encrypted queries fail loudly with a permission error (e.g. `permission
denied for schema eql_v3_internal`).

### Exposed schemas

**v2 (manual, required):** for a bare `col <op> term` filter to reach the
custom operator, `eql_v2` must be on PostgREST's request-time search_path —
add it to **Dashboard → Settings → API → Exposed schemas**
([Supabase custom-schemas guide](https://supabase.com/docs/guides/api/using-custom-schemas)).

> **Warning — silent fallback (v2).** If the schema is not exposed, the
> operators do not error: comparisons silently fall back to the base jsonb
> operators and return **wrong rows with no error**. After changing the
> setting, verify with a known-value round-trip: insert a row, filter for it
> by an encrypted column, and assert the hit.

**v3 (no change needed):** the column domains and their operators live in
`public`, so bare `col <op> term` filters resolve under Supabase's default
PostgREST configuration. Do not add `eql_v3_internal` (or `eql_v3`) to
Exposed schemas — the role grants are what matter, and grants and exposure
are independent.

## v3 encoding details

These are internal to the adapter but explain observable behaviour. Envelopes
(stored payloads and filter operands alike) are versioned `v: 3`.

- **INTERIM — filter operands are full storage envelopes.** This is a
  workaround, not the design, and the adapter-side fix is tracked
  (Linear **CIP-3402**). The term-only wire shape now exists: the bundle
  defines an `eql_v3.query_<name>` companion domain for each storage domain,
  whose CHECK accepts exactly the no-ciphertext shape, and protect-ffi 0.29's
  `encryptQuery` can mint those narrowed operands. But they are unreachable
  from this adapter: PostgREST has no syntax to cast a filter value, and an
  uncast literal is ambiguous between the query-domain and `jsonb` operator
  overloads (`42725`), so the reachable overload is the `jsonb` one — whose
  body coerces its operand into the STORAGE domain, whose CHECK requires the
  storage keys (`v`/`i`/`c` plus the domain's index terms: `hm` for
  `text_eq`, `op` for `integer_ord`, `hm`+`op`+`bf` for `text_search`). So the
  adapter encrypts each filter value with the full storage path and the
  operators extract the term they need (`eq_term`/`ord_term`/`match_term`).

  **Security caveat:** query terms are supposed to be index-terms-only by
  design, but a full-envelope operand carries a real, decryptable ciphertext
  `c` plus **all** of the column's index terms — and PostgREST filters travel
  in GET query strings, so these envelopes can land in URL logs, intermediate
  proxies, and Supabase request logs. The remaining gap is PostgREST operand
  casting; until the adapter can reach the query domains (CIP-3402), operands
  keep carrying ciphertext.
- **Free-text search is `matches()`; `contains()` on an encrypted column is
  rejected** with an error naming `matches()`. The v3 domains define no LIKE
  operator — encrypted free-text search is fuzzy bloom-filter token matching
  (`matches()` → PostgREST `cs` → `@>`), one-sided (a match may be a false
  positive, a non-match never is) and order-/multiplicity-insensitive, where
  match is tokenized + downcased and `%` is tokenized like any other character.
  `contains()` is reserved for native (exact) jsonb/array containment on
  plaintext columns, which pass through unchanged.
- **`like`/`ilike` on an encrypted column are an approximate compatibility
  shim** that delegates to `matches()`: leading/trailing `%` are stripped and
  the residual term is fuzzy-matched (emitting the same `cs` wire, with a
  one-time warning). Because the match is case-insensitive, one-sided, and
  anchoring is not honored, the result is APPROXIMATE. A pattern with an
  internal `%` or any `_` cannot be approximated and throws; call `matches()`
  directly to make the fuzzy intent explicit. On plaintext columns `like`/`ilike`
  pass through unchanged as real SQL LIKE.
- **`matches()` matches substrings.** The search term blooms to its own
  trigrams, and a row matches when the stored value's bloom contains all of
  them — so any substring of at least 3 characters (the tokenizer's
  `token_length`) matches. Shorter terms bloom to nothing and would match every
  row, so they are rejected with an error rather than answered.
- **`select('*')` (and bare `select()`) works on v3** — it expands to the
  introspected column list, with encrypted columns aliased and `::jsonb`-cast.
- **Mutations send the raw encrypted payload** (the domains are
  `DOMAIN … AS jsonb`), unlike v2's `{ data: … }` composite wrap.
- **Null filter values are rejected** with a pointer to `.is(column, null)` —
  a null cannot be encrypted into an operand, and silently passing it through
  would compare against the jsonb literal `null`.

## Caveats

- **No `ORDER BY` on encrypted columns (v2 and v3).** Range *filtering*
  (`WHERE col >= term`) works in both; sorting does not.
  - v2: operator families need superuser, so the Supabase install ships
    without an orderable opclass.
  - v3: the bundle deliberately declares no btree operator class on any
    domain, so a bare `ORDER BY` would silently sort the raw ciphertext
    envelope. Correct ordering is `ORDER BY eql_v3.ord_term(col)`, which
    PostgREST's `order=` parameter cannot express — the v3 builder therefore
    rejects `order()` on any encrypted column (including range-capable ones)
    with a clear error.
- **`select('*')` is rejected on v2** — list columns explicitly so encrypted
  columns can be cast. (v3 expands `'*'` from the introspected column list.)
- **v2 operator visibility depends on the Exposed-schemas step** (above); v3
  needs only the role grants.
