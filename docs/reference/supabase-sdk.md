# Supabase SDK reference

`@cipherstash/stack/supabase` wraps a supabase-js client so encrypted columns
are transparently encrypted on mutations, `::jsonb`-cast on selects, encrypted
in filter terms, and decrypted in results.

Two entry points, one query mechanism:

| Entry point | Schema DSL | Column storage |
|---|---|---|
| `encryptedSupabase` | `@cipherstash/stack/schema` (EQL v2) | `eql_v2_encrypted` composite |
| `encryptedSupabaseV3` | `@cipherstash/stack/eql/v3` (EQL v3) | native `eql_v3.*` domains |

Both filter via **direct EQL operators over PostgREST**: the wrapper encrypts
the filter term and emits an ordinary `col <op> term` filter, which resolves
to the custom operator defined on the encrypted type (equality by HMAC, range
by ORE, free-text by bloom-filter containment).

## Quick start (EQL v3)

```typescript
import { Encryption } from '@cipherstash/stack'
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { encryptedSupabaseV3 } from '@cipherstash/stack/supabase'
import { createClient } from '@supabase/supabase-js'

const users = encryptedTable('users', {
  email:  types.TextSearch('email'),   // eql_v3.text_search
  amount: types.IntegerOrd('amount'),  // eql_v3.integer_ord
})

const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!)
const client = await Encryption({ schemas: [users] })
const es = encryptedSupabaseV3({ encryptionClient: client, supabaseClient: supabase })

await es.from('users', users).insert({ email: 'a@b.com', amount: 30 })

const { data } = await es
  .from('users', users)
  .select('id, email, amount')
  .eq('email', 'a@b.com')

await es.from('users', users).select('id, amount').gte('amount', 10).lte('amount', 100)
```

The builder surface is identical across v2 and v3:
`.select/.insert/.update/.upsert/.delete`,
`.eq/.neq/.in/.like/.ilike/.is/.gt/.gte/.lt/.lte/.match/.or/.not/.filter`,
transforms (`.order/.limit/.range/.single/.maybeSingle/.csv/.abortSignal/.throwOnError`),
plus `.withLockContext(lockContext)` and `.audit(config)`.

### Typing (v3)

`es.from('users', users)` infers rows as **exactly** the table's plaintext
shape (schema columns get their domain plaintext types — `types.IntegerOrd` →
`number`, `types.BigintOrd` → `bigint`, `types.TimestampOrd` → `Date`, …).
Storage-only columns (e.g. `types.Boolean`) are excluded from every filter
method — including `.match()` — at the type level; filtering one is always a
clear runtime error.

Plaintext passthrough columns (`id`, `created_at`, …) are not part of the
default row type, so filtering or inserting them needs an explicit row type
(deliberate: widening the default with an index signature would silently
disable the storage-only guard):

```typescript
type UserRow = { id: number; email: string; amount: number }
const builder = es.from<typeof users, UserRow>('users', users)
builder.eq('id', 1) // ok — id is in UserRow
```

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
  email eql_v3.text_search,
  amount eql_v3.integer_ord,
  created_at eql_v3.timestamp_ord
);
```

The `types.*` member name maps to the domain name: strip the `eql_v3.` prefix
and PascalCase each `_`-separated segment (`types.TextEq` → `eql_v3.text_eq`,
`types.IntegerOrd` → `eql_v3.integer_ord`, `types.Timestamp` → `eql_v3.timestamp`).
The domains use SQL-standard type names (`integer`, `smallint`, `bigint`,
`real`, `double`, `boolean`, `timestamp`).

#### bigint domains (`types.Bigint` / `BigintEq` / `BigintOrdOre` / `BigintOrd`)

Plaintext is a JS `bigint` — encrypt takes a `bigint` and decrypt always
returns a `bigint` (never a precision-lossy `number`). Bounds are the full
PostgreSQL `bigint`/i64 range (`-2^63 … 2^63 - 1`), enforced at the
protect-ffi boundary: an out-of-range value surfaces as an encryption error
from the FFI, not a silent truncation.

> **Live since `@cipherstash/protect-ffi` 0.28.** The runtime marshals a JS
> `bigint` across the native boundary (i64-bounds-checked, with a `RangeError`
> for out-of-range values), so the bigint domains encrypt and decrypt
> end-to-end with no further SDK changes.

### Install EQL

```bash
# v2 (default)
stash eql install --supabase

# v3
stash eql install --eql-version 3 --supabase
```

The `--supabase` install uses the opclass-stripped bundle (operator classes /
families require superuser, which Supabase does not grant) and applies the
schema grants for `anon`, `authenticated`, and `service_role`. Without the
grants, encrypted queries fail with `42501`.

The vendored v3 bundle is the [`eql-3.0.0-alpha.2`](https://github.com/cipherstash/encrypt-query-language/releases/tag/eql-3.0.0-alpha.2)
release artifact. It installs two schemas: `eql_v3` (the column domains and
operators) and `eql_v3_internal` (SEM internals — support functions and types
the domains depend on). The installer applies role grants to **both** schemas;
`eql_v3_internal` needs the grants but must never be exposed (see below).

### Exposed schemas (manual, required)

For a bare `col <op> term` filter to reach the custom operator, the EQL schema
(`eql_v2` for v2, `eql_v3` for v3) must be on PostgREST's request-time
search_path — add it to **Dashboard → Settings → API → Exposed schemas**
([Supabase custom-schemas guide](https://supabase.com/docs/guides/api/using-custom-schemas)).

For v3, expose `eql_v3` **only**. SEM internals live in a separate
`eql_v3_internal` schema precisely so that exposing `eql_v3` (and Supabase's
Table-Builder type picker) surfaces just the column domains — do not add
`eql_v3_internal` to Exposed schemas. It still receives role grants (the
installer applies them); grants and exposure are independent.

> **Warning — silent fallback.** If the schema is not exposed, the operators
> do not error: comparisons silently fall back to the base jsonb operators and
> return **wrong rows with no error**. After changing the setting, verify with
> a known-value round-trip: insert a row, filter for it by an encrypted
> column, and assert the hit.

## v3 encoding details

These are internal to the adapter but explain observable behaviour. Envelopes
(stored payloads and filter operands alike) are versioned `v: 3`.

- **INTERIM — filter operands are full storage envelopes.** This is a
  workaround, not the design, and it is tracked for replacement
  (Linear **CIP-3402**). Why it is required today: every `eql_v3.*` domain
  CHECK requires the storage keys (`v`/`i`/`c` plus the domain's index terms:
  `hm` for `text_eq`, `ob` for `integer_ord`, all three for `text_search`),
  and the SQL operator functions coerce their jsonb operand into the domain.
  A narrowed query-only term (no ciphertext) fails the CHECK with `23514` for
  every domain, so the adapter encrypts each filter value with the full
  storage path and the operators extract the term they need
  (`eq_term`/`ord_term`/`match_term`).

  **Security caveat:** query terms are supposed to be index-terms-only by
  design, but a full-envelope operand carries a real, decryptable ciphertext
  `c` plus **all** of the column's index terms — and PostgREST filters travel
  in GET query strings, so these envelopes can land in URL logs, intermediate
  proxies, and Supabase request logs. The planned fix is an EQL-side
  **term-only scalar query envelope** (the scalar analog of the existing
  `eql_v3.jsonb_query`) that the domains/operators accept without storage
  keys; once it ships, operands stop carrying ciphertext.
- **`like`/`ilike` are emitted as PostgREST `cs`** (`@>` bloom containment) —
  the v3 domains define no LIKE operator. Match is tokenized + downcased, so
  `like` and `ilike` behave identically; do not include `%` wildcards.
- **INTERIM — free-text search needs `include_original: false`** on the
  column's match index for substring patterns to match:

  ```typescript
  types.TextSearch('email').freeTextSearch({ include_original: false })
  ```

  With the default `include_original: true`, the full-envelope operand's bloom
  carries the whole pattern as an extra token that only matches when the
  pattern equals the stored value. This requirement is a symptom of the same
  full-envelope interim mechanism above — a term-only query envelope encodes
  the pattern as a query (not as a stored value), so the requirement goes away
  with CIP-3402.
- **Mutations send the raw encrypted payload** (the domains are
  `DOMAIN … AS jsonb`), unlike v2's `{ data: … }` composite wrap.
- **Null filter values are rejected** with a pointer to `.is(column, null)` —
  a null cannot be encrypted into an operand, and silently passing it through
  would compare against the jsonb literal `null`.

## Caveats (shared by v2 and v3)

- **No `ORDER BY` on encrypted columns.** Operator families need superuser, so
  the Supabase install ships without index acceleration and without an
  orderable opclass. Range *filtering* (`WHERE col >= term`) works; sorting
  does not. OPE index terms that are natively orderable on Supabase (btree +
  `ORDER BY`, built-in comparison) are in active development.
- **`select('*')` is rejected** — list columns explicitly so encrypted columns
  can be cast.
- **Operator visibility depends on the Exposed-schemas step** (above).
