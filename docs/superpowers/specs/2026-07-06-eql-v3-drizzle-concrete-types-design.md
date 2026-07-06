# EQL v3 Drizzle support — concrete-type authoring — design

Status: proposed
Date: 2026-07-06
Branch: `feat/eql-v3-text-search-schema`

## 1. Goal

Add EQL v3 support to the Drizzle integration inside `@cipherstash/stack`, mirroring
the existing v2 Drizzle integration (`@cipherstash/stack/drizzle`) but re-shaped
around the v3 **concrete-type** model.

The defining change of v3: **the concrete type defines the search capabilities.**
A column declared `eql_v3.int4_eq` supports equality; `eql_v3.int4_ord` supports
order/range (and equality via ORE); `eql_v3.text_search` supports equality, order,
and free-text match. There is no separate `.equality()` / `.orderAndRange()` /
`.freeTextSearch()` index configuration as in v2 — everything the adapter needs
(SQL column domain, `cast_as`, and which operators are legal) is **derived from the
concrete type**, which already carries that metadata in
`@cipherstash/stack/eql/v3`.

Success = a developer can declare a Drizzle `pgTable` with encrypted v3 columns,
feed the same schema to `EncryptionV3`, and run equality / range / free-text /
ordering queries through Drizzle using capability-checked operators that emit the
correct `eql_v3` term-function SQL.

## 2. Background: why v3 is different from v2

Confirmed against this branch's SQL bundle
(`packages/stack/__tests__/fixtures/eql-v3/cipherstash-encrypt-v3.sql`) and the live
pg tests (`packages/stack/__tests__/schema-v3-pg.test.ts`).

**Column type.** v2 uses a single composite type `eql_v2_encrypted` for every
encrypted column. v3 uses **one `CREATE DOMAIN … AS jsonb` per concrete type** —
`eql_v3.int4_ord`, `eql_v3.text_eq`, `eql_v3.text_search`, `eql_v3.bool`, … There is
no single catch-all `eql_v3_encrypted`.

**Wire form.** v2 writes a composite literal `("…")`. v3 domains are plain jsonb, so
the value is inserted as plain JSON cast to the domain (`$1::eql_v3.int4_ord`).

**Query form.** v2 compares encrypted payloads directly (native `=` on
`eql_v2_encrypted`, or `eql_v2.gt/lt/like/order_by(...)` convenience functions). v3
has **no convenience operators**; it compares **extracted index terms** on both
sides:

| Capability | v3 SQL |
| --- | --- |
| equality (HMAC) | `eql_v3.eq_term(col) = eql_v3.hmac_256($::jsonb)` |
| equality (ORE, numeric/date order domains) | `eql_v3.ord_term(col) = eql_v3.ore_block_256($::jsonb)` |
| order/range | `eql_v3.ord_term(col) </<=/>/>= eql_v3.ore_block_256($::jsonb)` |
| free-text match | `eql_v3.match_term(col) @> eql_v3.bloom_filter($::jsonb)` |
| order by | `ORDER BY eql_v3.ord_term(col)` |

The column-side extractor (`eq_term`/`ord_term`/`match_term`) takes the column
domain (its stored value has ciphertext `c`, so it passes the domain CHECK). The
search-side constructor (`hmac_256`/`ore_block_256`/`bloom_filter`) pulls the index
field straight out of the query-term jsonb with no domain coercion — this is why a
query term (which has no ciphertext) must be cast to `::jsonb`, never to the domain.

**Concrete types already exist.** `@cipherstash/stack/eql/v3` ships the full
concrete-type system (`packages/stack/src/eql/v3/{columns,types,table,index}.ts`):
- `types.<Domain>(name)` factories for all 35 shipped domains.
- Each `EncryptedV3Column` carries `getEqlType()` (`eql_v3.int4_ord`), `castAs`
  (`'string' | 'number' | 'boolean' | 'date'`), `getQueryCapabilities()`
  (`{ equality, orderAndRange, freeTextSearch }`), and `build()` →
  `{ cast_as, indexes: { unique?, ore?, match? } }`.
- `encryptedTable(name, columns)` builds the schema `EncryptionV3` consumes.
- `EncryptionV3(...).encryptQuery(value, { table, column, queryType })` produces the
  query term; the FFI's `resolveIndexType` picks the index (including equality-via-ORE
  for numeric/date order domains).

This adapter **reuses** that system verbatim — it never re-declares domain or
capability data.

## 3. Scope

### In scope
- A new Drizzle v3 module in `@cipherstash/stack`, exported at
  `@cipherstash/stack/eql/v3/drizzle` (nested under the existing `eql/v3` namespace).
- A Drizzle-native `types` namespace with the **identical PascalCase factory names**
  as `@cipherstash/stack/eql/v3` (`types.TextSearch`, `types.Int4Ord`, `types.Bool`,
  … all 35 shipped domains), each returning a Drizzle `customType` column.
- Plain-jsonb codec (`toDriver` / `fromDriver`).
- Schema extraction: Drizzle table → v3 `encryptedTable` for `EncryptionV3`.
- `createEncryptionOperatorsV3(client)` — capability-checked async operators:
  `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `between`, `notBetween`, `like`, `ilike`,
  `notIlike`, `inArray`, `notInArray`, `asc`, `desc`, `and`, `or`, plus the
  pass-through non-encrypting operators (`isNull`, `isNotNull`, `not`, `exists`,
  `notExists`).
- Detection: recover the concrete builder from a processed Drizzle column.
- A `.changeset/` entry (minor `@cipherstash/stack`).

### Out of scope (explicit gaps, not silent omissions)
- **JSON / `ste_vec`** operators (`jsonbPathQueryFirst`, `jsonbGet`,
  `jsonbPathExists`). No v3 JSON column builder ships yet (`eql_v3.json` /
  `ste_vec` have no `types.*` factory), so these are simply absent from the v3
  operator surface — there is no v3 column they could target. Deferred until a v3
  JSON builder exists.
- **int8 / bigint** domains — intentionally absent from `eql/v3` pending lossless
  FFI round-tripping. This adapter mirrors that: no int8 factory.
- **`like`/`ilike` pattern semantics.** v3's only text-match SQL is bloom-filter
  containment (`match_term @> bloom_filter`), which is **token/substring matching,
  not SQL `LIKE` patterns**. `like`/`ilike`/`notIlike` all map to containment
  (`notIlike` = `NOT (…)`); wildcards in the argument are not interpreted. Documented
  on each operator.
- **No changes to the v2 Drizzle module** (`@cipherstash/stack/drizzle`) or the
  standalone `@cipherstash/drizzle` package. Zero v2 regression surface.
- **No dialect-seam refactor of the v2 `operators.ts`.** The v3 operators are a
  self-contained module; the SQL-dialect seam (below) lives only inside v3.

## 4. Architecture & location

```
packages/stack/src/eql/v3/drizzle/
  index.ts             // barrel: types, createEncryptionOperatorsV3, extractEncryptionSchemaV3, errors
  types.ts             // Drizzle `types` namespace (PascalCase factories → customType columns)
  column.ts            // customType wrapper + detection + config stash
  codec.ts             // plain-jsonb toDriver / fromDriver
  sql-dialect.ts       // v3 term-function SQL emission (local seam)
  operators.ts         // createEncryptionOperatorsV3
  schema-extraction.ts // Drizzle table → eql/v3 encryptedTable
```

Package wiring: add `"./eql/v3/drizzle"` to `packages/stack/package.json` `exports`
and to the tsup entry list, following the existing `./eql/v3` and `./drizzle`
entries.

The v3 module depends inward on `@/eql/v3` (concrete types + `encryptedTable`) and
the base `EncryptionClient` (`@/encryption`) — the same client the v2 Drizzle
operators use. It does **not** depend on the v2 Drizzle module.

## 5. Components

### 5.1 `types` namespace + column wrapper (`types.ts`, `column.ts`, `codec.ts`)

`types.TextSearch(name)` (and the 34 siblings) returns a Drizzle column built via
`customType`. Each factory:

1. Constructs the corresponding `eql/v3` builder — `v3.types.TextSearch(name)` — the
   **single source of truth** for domain / `cast_as` / capabilities. No metadata is
   re-declared here; this file is a name→delegate map.
2. Builds a `customType<{ data: Plaintext; driverData: string | null }>` whose
   `dataType()` returns `builder.getEqlType()` (e.g. `eql_v3.int4_ord`), and whose
   `toDriver`/`fromDriver` are the plain-jsonb codec.
3. Stashes the `eql/v3` builder on the column (`_eqlv3Column`) **and** in a
   module-global map keyed by column name — mirroring v2's dual registration — so
   detection and schema-extraction can recover it after `pgTable` strips custom
   props.

The decrypted TypeScript type is `PlaintextForColumn<typeof builder>` (string /
number / boolean / Date), so `users.age` decrypts to `number`, `users.createdAt` to
`Date`, etc.

**Codec** (`codec.ts`), proven by the `eql-v3-drizzle-adapter` branch:
- `toDriver`: `null`/`undefined` → SQL `NULL` (JS `null`). The v3 domains
  `CHECK jsonb_typeof(VALUE) = 'object'`, so a JSONB `null` literal would fail the
  domain; SQL NULL is accepted. Otherwise `JSON.stringify(value)`.
- `fromDriver`: pass `null` through; return already-parsed objects as-is (the
  postgres driver may hand back a parsed jsonb object); else `JSON.parse`.

**Detection** (`column.ts`): `isEqlV3Column(column)` / `getEqlV3Column(name, column)`
check `_eqlv3Column`, falling back to the name-keyed map, and validate the
`dataType()` string is one of the known `eql_v3.*` domains (source: iterate the
`eql/v3` `types` factories once at module load to build the domain set — no
hand-maintained string list).

### 5.2 SQL dialect (`sql-dialect.ts`)

A small object that emits the v3 term-function SQL, keyed off which index the column
exposes. Gating and dialect both read `builder.build().indexes` — the authoritative
index set:

- `indexes.unique` present → equality via `eql_v3.eq_term(col) = eql_v3.hmac_256($::jsonb)`.
- `indexes.ore` present → order/range via `eql_v3.ord_term(col) <op> eql_v3.ore_block_256($::jsonb)`;
  order-by via `eql_v3.ord_term(col)`; **and** equality via ORE when `unique` is
  absent (`eql_v3.ord_term(col) = eql_v3.ore_block_256($::jsonb)`).
- `indexes.match` present → free-text via `eql_v3.match_term(col) @> eql_v3.bloom_filter($::jsonb)`.

Query terms are bound params already wrapped with `bindIfParam` by the caller, then
cast `::jsonb` inside the constructor call. Constructor names are pinned to this
branch's bundle: `hmac_256`, `ore_block_256`, `bloom_filter` (note: **not** the
`ore_block_u64_8_256` spelling from the older adapter branch — that predates this
bundle).

### 5.3 Operators (`operators.ts`)

`createEncryptionOperatorsV3(client: EncryptionClient)` returns the async-operator
object, same ergonomics as v2 (`await ops.eq(users.email, 'x')`, `ops.and(...)` /
`ops.or(...)` batch encryption, `ops.asc(...)` / `ops.desc(...)`,
`ops.inArray(...)`). Per operator:

| Operator | Requires index | `queryType` sent to `encryptQuery` | Emitted SQL |
| --- | --- | --- | --- |
| `eq` / `ne` | `unique` or `ore` | `equality` | `unique` → `eq_term = hmac_256`; else `ord_term =/<> ore_block_256` |
| `gt`/`gte`/`lt`/`lte` | `ore` | `orderAndRange` | `ord_term </<=/>/>= ore_block_256` |
| `between` / `notBetween` | `ore` | `orderAndRange` | `ord_term >= ore_block_256($min) AND ord_term <= ore_block_256($max)`, NOT-wrapped for `notBetween` |
| `like`/`ilike`/`notIlike` | `match` | `freeTextSearch` | `match_term @> bloom_filter`, NOT-wrapped for `notIlike` |
| `inArray`/`notInArray` | `unique` or `ore` | `equality` | OR of `eq` terms / AND of `ne` terms |
| `asc` / `desc` | `ore` | — | `ORDER BY eql_v3.ord_term(col)` |
| `isNull`/`isNotNull`/`not`/`exists`/`notExists` | — | — | pass-through Drizzle operators |

Term encryption reuses the column's recovered `eql/v3` builder + its owning
`encryptedTable` (rebuilt via schema-extraction and cached per table, exactly as v2
caches the ProtectTable): `client.encryptQuery(value, { table, column, queryType })`.

**Error handling — no silent fallback.** In v2, an operator on a non-encrypted
column falls through to the plain Drizzle operator. In v3 that is impossible: a v3
domain column has no plaintext form, and using the wrong operator emits SQL the
domain CHECK rejects at runtime. So the operators **throw `EncryptionOperatorError`**
(reusing the v2 error class name) when a column lacks the required index — e.g.
`ops.gt` on a `types.TextEq` column (equality-only, no `ore`), or `ops.ilike` on a
column without `match`. The message names the column, operator, and the missing
capability. A non-v3 column passed to a v3 operator also throws (it can't be a v3
domain), rather than silently degrading.

### 5.4 Schema extraction (`schema-extraction.ts`)

`extractEncryptionSchemaV3(drizzleTable)` iterates the Drizzle columns, recovers each
stashed `eql/v3` builder via detection, and returns
`encryptedTable(tableName, { <property>: builder, … })` — ready for
`EncryptionV3({ schemas: [users] })`. Throws if the table has no v3 columns (mirrors
v2's `extractEncryptionSchema`). Operators call this internally to resolve the
`encryptedTable` for a column's parent table, caching per table name.

## 6. Data flow (per query)

```
types.Int4Ord('age')                      // authoring
  → customType dataType() = 'eql_v3.int4_ord', stash eql/v3 builder
pgTable('users', { age })                  // Drizzle table

extractEncryptionSchemaV3(users)           // → encryptedTable('users', { age: <builder> })
EncryptionV3({ schemas: [users-schema] })  // typed client

await ops.gte(users.age, 30)
  → recover builder (ore index present ✓)
  → client.encryptQuery(30, { table, column, queryType: 'orderAndRange' })  // term
  → sql`eql_v3.ord_term(${users.age}) >= eql_v3.ore_block_256(${term}::jsonb)`
```

## 7. Testing

Mirror `packages/drizzle/__tests__` structure, plus the v3 live-pg pattern from
`packages/stack/__tests__/schema-v3-pg.test.ts`. Location:
`packages/stack/__tests__/drizzle-v3/` (or alongside the existing
`packages/stack/__tests__/drizzle-*.test.ts` files, matching whatever the v2 drizzle
tests in stack already use).

**Unit (no DB):**
- `types.*` produce the correct `dataType()` domain string for a representative set
  across every scalar family and capability tier.
- Codec round-trip (object ⇄ jsonb string; null ⇄ SQL NULL).
- `extractEncryptionSchemaV3` rebuilds the expected `encryptedTable` (`build()`
  output equals the directly-authored `eql/v3` table's).
- Operator SQL emission via a mock client + `PgDialect`: assert exact
  `eql_v3.eq_term/ord_term/match_term` + `hmac_256/ore_block_256/bloom_filter`
  strings and the equality-via-ORE branch on an order-only numeric column.
- Gating errors: `gt` on equality-only, `ilike` on non-match column, and a non-v3
  column passed into a v3 operator.

**Live pg** (gated by `LIVE_EQL_V3_PG_ENABLED`, install via `installEqlV3IfNeeded`):
- One `pgTable` with a representative column per tier: `types.TextSearch('email')`,
  `types.Int4Ord('age')`, `types.TextEq('nickname')`, `types.Bool('active')`.
- Seed with `EncryptionV3(...).bulkEncryptModels` (or raw insert with
  `$::eql_v3.<domain>` casts), then real Drizzle `select().where(await ops.eq(...))`,
  `ops.gte(...)`, `ops.between(...)`, `ops.ilike(...)`, `orderBy(ops.asc(...))`;
  decrypt; assert the selected rows. Use `test_run_id` isolation like the v2 suite.

## 8. Open implementation details (resolved during build, not blocking)

- Exact test directory name / whether to gate live tests behind the same env var the
  stack v3 pg tests use (`LIVE_EQL_V3_PG_ENABLED`) — adopt the existing helper.
- Whether `between` on a text order domain (which has both `unique` and `ore`) needs
  any special handling — it uses `ore`, same as numeric; verify against a live row.
- Confirm the postgres driver path Drizzle uses binds `$::jsonb` correctly for the
  term param (the pg tests use `sql.json(...)`; Drizzle's `bindIfParam` + `::jsonb`
  cast is the equivalent — assert in a live round-trip).

## 9. Non-goals / follow-ups (tracked, not in this milestone)

- v3 JSON / `ste_vec` operators once a v3 JSON column builder ships.
- int8 / bigint once the FFI round-trips losslessly.
- Mirroring into the standalone `@cipherstash/drizzle` package (only if it must ship
  v3 independently of `@cipherstash/stack`).
- drizzle-kit migration generation for v3 domains (the v2 `generate-eql-migration`
  path emits `eql_v2_encrypted`; a v3 equivalent is a separate effort).
