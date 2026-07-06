# EQL v3 Schema DSL — `text_search` (Increment 1)

> **Superseded (2026-07-03):** the authoring surface described below has moved.
> The subpath is now `@cipherstash/stack/eql/v3` (not `schema/v3`) and columns
> are authored via the `types` namespace — `types.TextSearch('email')` replaces
> `encryptedTextSearchColumn('email')`. This document is retained as the original
> design record for the increment; the code examples show the historical API.

**Date:** 2026-06-30
**Status:** Approved (design)
**Package:** `@cipherstash/stack`
**Scope:** Authoring DSL + encrypt-config emission for the `eql_v3.text_search`
concrete type, **plus** a backward-compatible structural widening of the public
client types so v3 builders are first-class with the client API (`Encryption`,
`encrypt`, `decrypt`, `encryptQuery`). DDL and query-dialect work are explicitly
deferred (see Non-goals).

---

## Goal

Begin the EQL v3 version of the encryption SDK. EQL v3 removes the generic
"encrypted" concept in favour of **concrete types that carry their own
capabilities**. The first concrete type is `eql_v3.text_search`.

Today:

```ts
const users = encryptedTable('users', {
  email: encryptedColumn('email').equality().freeTextSearch(),
})
```

v3:

```ts
const users = encryptedTable('users', {
  email: encryptedTextSearchColumn('email'),
})
```

Because the concrete type carries capability, the capability-enabling calls
(`.equality()`, `.orderAndRange()`, `.freeTextSearch()` *as enablers*) disappear.
What remains is **tuning** of the match index:

```ts
const users = encryptedTable('users', {
  email: encryptedTextSearchColumn('email').freeTextSearch({
    tokenizer: { kind: 'ngram', token_length: 4 },
    token_filters: [{ kind: 'downcase' }],
    k: 8,
    m: 4096,
    include_original: false,
  }),
})
```

## Background — what `eql_v3.text_search` is

Source of truth:
`<eql-v3-worktree>/release/cipherstash-encrypt-v3.sql`.

`eql_v3.text_search` is a Postgres `CREATE DOMAIN ... AS jsonb` whose `CHECK`
requires an object containing `v, i, c, hm, ob, bf` (with `v = '2'`). The domain
defines **all three** index extractors as functions:

- `eql_v3.eq_term(text_search)` → equality (`hm` = hmac)
- `eql_v3.ord_term(text_search)` → order/range (`ob` = ore blocks)
- `eql_v3.match_term(text_search)` → free-text match (`bf` = bloom filter)

So `text_search` is the **full-capability** text type: equality + order + match.
EQL v3 also defines narrower text domains (`text`, `text_eq`, `text_match`,
`text_ord(_ore)`) and full families for `int*`/`float*`/`date`/`bool`/`numeric`/
`timestamptz`/`json` — all out of scope for this increment.

### The load-bearing fact: the payload is identical

The encrypted envelope a v2 column produces (`{ v, i, c, hm, ob, bf }`) already
satisfies the `eql_v3.text_search` domain `CHECK`. Therefore:

- A v2 `eql_v2_encrypted` column built with equality + order + match can be
  retyped to `eql_v3.text_search` with **no re-encryption** — a future
  `ALTER COLUMN ... TYPE` is a `jsonb → jsonb` metadata flip.
- The native cipherstash-client (`@cipherstash/protect-ffi` `newClient`) needs
  **no changes**: the `EncryptConfig` it receives is unchanged.
- The SDK's **runtime** encrypt/decrypt/query path needs no changes either — it
  is purely structural (it only reads `column.getName()`, `column.build()`,
  `table.tableName`, `table.build().columns`; there is no `instanceof` on that
  path).

What this increment *does* change is the SDK's **public TYPES**: today they are
typed against the v2 `EncryptedTable<EncryptedTableColumn>` / `EncryptedColumn`
classes, which are nominal (private fields), so the separate v3
`EncryptedTextSearchColumn` class is not assignable to them. To make v3 builders
work with the client (not just emit a config), the public client types are
**widened to a structural contract** in this increment (see "Client integration"
below). The widening is purely additive — existing v2 usage is unaffected.

## Architecture & location

- New module: `packages/stack/src/schema/v3/` (own `index.ts`; split into
  focused files if it grows).
- New export subpath: `@cipherstash/stack/schema/v3` (added to `package.json`
  `exports` + `tsup`/build entry as needed).
- The v2 schema module (`packages/stack/src/schema/index.ts`) keeps its runtime
  behavior and existing exported symbol shapes; the only permitted edit there is
  a backward-compatible **widening** of `buildEncryptConfig`'s parameter type to
  the shared structural table contract (it already only calls `.build()`).
- v3 builders emit the existing `ColumnSchema` / `EncryptConfig` shape, so the
  encryption client, payload, encrypt/decrypt, and query paths work at runtime
  with **zero runtime changes**. Client integration at the **type** level is
  achieved by widening the public types (next section), not by a runtime rewrite.

## Public API

```ts
import { encryptedTable, encryptedTextSearchColumn } from '@cipherstash/stack/schema/v3'

// minimal — capability is carried by the type
const users = encryptedTable('users', {
  email: encryptedTextSearchColumn('email'),
})

// with match-index tuning
const users = encryptedTable('users', {
  email: encryptedTextSearchColumn('email').freeTextSearch({
    tokenizer: { kind: 'ngram', token_length: 4 },
    token_filters: [{ kind: 'downcase' }],
    k: 8,
    m: 4096,
    include_original: false,
  }),
})
```

- `encryptedTextSearchColumn(name)` → `EncryptedTextSearchColumn`. The concrete
  type **inherently enables equality + order + match**. There are no
  capability-enabling methods.
- `.freeTextSearch(opts?)` is **tuning only** — it overrides the match-index
  parameters. It never "enables" a capability (match is always on for this type).
- `encryptedTable(tableName, columns)` (v3) accepts v3 column builders and
  assembles `{ tableName, columns }`.
- `buildEncryptConfig(...tables)` (v3) assembles an `EncryptConfig` (`v: 1`).

> Naming note: v3 `encryptedTable` / `buildEncryptConfig` intentionally shadow the
> v2 names but live on the `/v3` subpath, so an importer picks the model by import
> path, not by symbol name.

## Client integration (in scope)

v3 builders must be **accepted by the client API**, not merely emit a config. The
runtime already works (structural — see "load-bearing fact"); the blocker is the
public TYPES. This increment widens them to a shared **structural contract** so
both v2 and v3 builders satisfy them:

```ts
// minimal structural shapes — exact members verified against the client's
// actual usage (column.getName/build, table.tableName/build):
interface BuildableColumn { getName(): string; build(): ColumnSchema }
interface BuildableTable {
  tableName: string
  build(): { tableName: string; columns: Record<string, ColumnSchema> }
}
// Query path is NARROWER: it must reject non-queryable EncryptedField (no
// indexes). A v2 EncryptedColumn qualifies nominally; a v3 queryable concrete
// type qualifies via getEqlType(); EncryptedField is excluded.
type BuildableQueryColumn =
  | EncryptedColumn
  | (BuildableColumn & { getEqlType(): string })
```

Widened surfaces (in `packages/stack/src/types.ts`) — note the **storage vs query split**:

- `EncryptionClientConfig.schemas` → `AtLeastOneCsTable<BuildableTable>`
- `EncryptOptions.column` / `.table` → `BuildableColumn` / `BuildableTable` —
  the STORAGE path (`encrypt`) accepts columns AND nested fields.
- `SearchTerm` / `QueryTermBase.column` → `BuildableQueryColumn`; `.table` →
  `BuildableTable` — the QUERY path (`encryptQuery`) accepts only queryable
  columns, so a `BuildableQueryColumn` excludes `EncryptedField` (which the
  nominal `EncryptedColumn` type rejected and must keep rejecting).
- Internally, the query-only index-inference helpers
  (`inferIndexType`/`validateIndexType`/`resolveIndexType`) also take
  `BuildableQueryColumn` (verified reached only from the `encryptQuery` path).

Plus `buildEncryptConfig`'s parameter is widened to `BuildableTable` (pure
widening; it only calls `.build()`).

**v3 keeps its own `EncryptedTable` class** (it needs a different column
constraint and a simpler `build()` than v2's nested-field/ste_vec logic). Both
the v2 and v3 table/column classes satisfy the structural contract, which is what
lets a single widened type accept either.

**Backward compatibility:** widening only — existing v2 tables/columns still
satisfy the new types (a regression type-test asserts this). The **generic
schema-aware model methods** (`encryptModel<S extends EncryptedTableColumn>` /
`bulkEncryptModels`) are **left unchanged** so v2's field-level inference
(`InferPlaintext`, `EncryptedFields`, `EncryptedFromSchema`, the
`EncryptedTable<T> & T` accessor) is preserved. v3 support for the model methods
(its columns don't satisfy `EncryptedTableColumn`) is a **future increment**.

**Acceptance (these must type-check with v3 builders):**
`Encryption({ schemas: [v3users] })`, `client.encrypt(v, { table: v3users, column:
v3users.email })`, `client.decrypt(...)` round-trip, and
`client.encryptQuery(v, { table: v3users, column: v3users.email })`. Plus the
storage/query split: a v2 `encryptedField` is `encrypt`-able but a `@ts-expect-error`
proves it is NOT `encryptQuery`-able, and a v2 `EncryptedColumn` stays queryable.

> Discriminator follow-up: `getEqlType()` distinguishes queryable v3 types today
> only because the one v3 type shipping (`text_search`) is queryable. If a future
> v3 *non-queryable* type also carries `getEqlType()`, switch the query-path
> discriminator to a queryability-specific marker. Not blocking for this increment.

## `build()` output — pinned to v2

`encryptedTextSearchColumn('email').build()` emits exactly:

```ts
{
  cast_as: 'string',
  indexes: {
    unique: { token_filters: [] },
    ore: {},
    match: {
      tokenizer: { kind: 'ngram', token_length: 3 },
      token_filters: [{ kind: 'downcase' }],
      k: 6,
      m: 2048,
      include_original: true,
    },
  },
}
```

Notes:

- **`cast_as: 'string'`**, not `'text'`. The native cipherstash-client receives
  the SDK-facing value verbatim; `toEqlCastAs` ('string' → 'text') is applied
  only on the `wasm-inline.ts` SQL-generation path, not the `newClient` path.
- Defaults mirror v2's `freeTextSearch()` **exactly**: ngram-3, downcase filter,
  `k = 6`, `m = 2048`, `include_original = true` (note: `true`, matching the v2
  builder default, not the zod-schema default of `false`).
- `unique.token_filters` defaults to `[]` (case-sensitive equality, matching v2).
- `.freeTextSearch(opts)` overrides on a per-field basis using the same merge
  semantics as v2 (each provided key replaces the default; omitted keys keep the
  default).

**The guarantee:** this output is byte-identical to

```ts
encryptedColumn('email').equality().orderAndRange().freeTextSearch().build()
```

and a test asserts that equality directly (see Testing). This is what makes
"swap the column type and it just works" true at the config level.

## v3 metadata for later increments

`EncryptedTextSearchColumn` records its concrete domain name —
`'eql_v3.text_search'` — exposed via the `getEqlType()` method (method only, no
property getter, matching the v2 builder convention).

- `build()` (the encrypt config) does **not** include `eqlType`; the wire config
  stays identical to v2.
- The name is metadata that the *future* DDL and query-dialect increments read
  (per-column Postgres type, `eql_v3.eq_term(...)` lowering). Recording it now
  gives those increments a hook without changing today's config.

## Type inference

v3 `InferPlaintext` / `InferEncrypted` mirror v2:

- `InferPlaintext<typeof users>` → `{ email: string }`
- `InferEncrypted<typeof users>` → `{ email: Encrypted }`

## Non-goals (deferred to follow-up increments)

> Note: "widen the public client types" was previously implied as out of scope
> ("zero client changes"). It is now **in scope** for this increment (see Client
> integration). The items below remain deferred.

- **v3 support in the generic schema-aware model methods** (`encryptModel` /
  `bulkEncryptModels` field-level inference) — v3 columns don't satisfy the v2
  `EncryptedTableColumn` constraint those generics use. Single-value
  `encrypt`/`decrypt`/`encryptQuery` + `Encryption()` config DO work in this
  increment; model-method inference for v3 is a follow-up.
- **v3 columns through the WASM-inline entry** (`wasm-inline.ts`) — known
  boundary. `getColumnName()` (`src/wasm-inline.ts:314-320`) runtime-checks
  `instanceof EncryptedColumn || instanceof EncryptedField` and throws otherwise,
  so a v3 column passed to the WASM-inline client would throw at runtime. The
  type widening still compiles (the `instanceof` guard narrows the wider union)
  and this path is outside the scoped typecheck, so it is a documented deferred
  boundary, not a regression. The batch-2 "no `instanceof`" / structural-runtime
  claim is scoped to the native `operations/*.ts` path.
- **Per-column DDL type emission** — deriving each column's Postgres type from
  its v3 builder. v2 hard-codes one native type (`eql_v2_encrypted`); v3 needs a
  per-column type (`eql_v3.text_search`, etc.). Net-new, touches every adapter.
- **v2 → v3 transition tooling** — `ALTER TABLE ... ALTER COLUMN ... TYPE
  eql_v3.text_search` and retiring the now-redundant `eql_v2_configuration` /
  `add_search_config` rows for the column.
- **v3 query dialect** — `eql_v3.eq_term(col) = eql_v3.eq_term($1::eql_v3.text_search)`
  in drizzle / supabase operator lowering.
- **Other v3 concrete types** — `int*`, `float*`, `date`, `bool`, `numeric`,
  `timestamptz`, `text_eq`/`text_ord`, `json`, etc. The module is structured so
  these slot in later (a domain → config mapping per type).
- **Nested `encryptedField` / structured columns** for v3 — only top-level
  `text_search` columns ship in increment 1.

## Testing

- **Config-equivalence (load-bearing):**
  `encryptedTextSearchColumn('email').build()` deep-equals
  `encryptedColumn('email').equality().orderAndRange().freeTextSearch().build()`.
- **`.freeTextSearch()` override:** each provided opt replaces its default;
  omitted opts retain defaults; verify the documented "additional config" example
  produces the expected match block.
- **Defaults:** assert the exact default `build()` output above (catches any
  silent default drift).
- **`buildEncryptConfig`:** a v3 table assembles into a valid `EncryptConfig`
  (`v: 1`) that passes `encryptConfigSchema.parse(...)`.
- **`eqlType` metadata:** `getEqlType()` returns `'eql_v3.text_search'` and is
  absent from `build()` output.
- **No shared mutable state:** two columns built independently must not alias —
  mutating one column's `build()` output must not affect another's (defaults are
  produced per-instance, `build()` returns a fresh clone).
- **Type-level:** `InferPlaintext` / `InferEncrypted` produce the expected shapes.
- **Client integration (type-level):** the acceptance snippets above type-check
  with v3 builders, and a regression test asserts v2 tables/columns still satisfy
  the widened public types.

## Open questions

None blocking. Future increments will decide how `eqlType` threads into DDL and
query lowering, and how the narrower text domains (`text_eq`, `text_match`,
`text_ord`) and other scalar families are expressed in the DSL.
