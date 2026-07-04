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
  amount: types.Int4Ord('amount'),     // eql_v3.int4_ord
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
shape (schema columns get their domain plaintext types — `types.Int4Ord` →
`number`, `types.TimestamptzOrd` → `Date`, …). Storage-only columns (e.g.
`types.Bool`) are excluded from every filter method — including `.match()` —
at the type level; filtering one is always a clear runtime error.

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
  createdAt: types.TimestamptzOrd('created_at'),
})
```

The adapter resolves the mapping everywhere: filters and mutations address
`created_at`, selects alias it back (`createdAt:created_at::jsonb`), and
result rows are keyed by `createdAt`. `date` / `timestamptz` columns decrypt
to real `Date` objects (reconstructed from the encrypt-config `cast_as`).

## Database setup

### v3: per-domain columns

```sql
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  email eql_v3.text_search,
  amount eql_v3.int4_ord,
  created_at eql_v3.timestamptz_ord
);
```

The `types.*` member name maps to the domain name: strip the `eql_v3.` prefix
and PascalCase each `_`-separated segment (`types.TextEq` → `eql_v3.text_eq`,
`types.Int4Ord` → `eql_v3.int4_ord`, `types.Timestamptz` → `eql_v3.timestamptz`).

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

### Exposed schemas (manual, required)

For a bare `col <op> term` filter to reach the custom operator, the EQL schema
(`eql_v2` for v2, `eql_v3` for v3) must be on PostgREST's request-time
search_path — add it to **Dashboard → Settings → API → Exposed schemas**
([Supabase custom-schemas guide](https://supabase.com/docs/guides/api/using-custom-schemas)).

> **Warning — silent fallback.** If the schema is not exposed, the operators
> do not error: comparisons silently fall back to the base jsonb operators and
> return **wrong rows with no error**. After changing the setting, verify with
> a known-value round-trip: insert a row, filter for it by an encrypted
> column, and assert the hit.

## v3 encoding details

These are internal to the adapter but explain observable behaviour:

- **Filter operands are full storage envelopes.** Every `eql_v3.*` domain
  CHECK requires the storage keys (`v`/`i`/`c` plus the domain's index terms:
  `hm` for `text_eq`, `ob` for `int4_ord`, all three for `text_search`), and
  the SQL operator functions coerce their jsonb operand into the domain. A
  narrowed query-only term (no ciphertext) fails the CHECK with `23514` for
  every domain, so the adapter encrypts each filter value with the full
  storage path and the operators extract the term they need
  (`eq_term`/`ord_term`/`match_term`).
- **`like`/`ilike` are emitted as PostgREST `cs`** (`@>` bloom containment) —
  the v3 domains define no LIKE operator. Match is tokenized + downcased, so
  `like` and `ilike` behave identically; do not include `%` wildcards.
- **Free-text search needs `include_original: false`** on the column's match
  index for substring patterns to match:

  ```typescript
  types.TextSearch('email').freeTextSearch({ include_original: false })
  ```

  With the default `include_original: true`, the full-envelope operand's bloom
  carries the whole pattern as an extra token that only matches when the
  pattern equals the stored value.
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
