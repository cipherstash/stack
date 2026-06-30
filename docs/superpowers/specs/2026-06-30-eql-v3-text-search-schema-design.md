# EQL v3 Schema DSL — `text_search` (Increment 1)

**Date:** 2026-06-30
**Status:** Approved (design)
**Package:** `@cipherstash/stack`
**Scope:** Authoring DSL + encrypt-config emission for the `eql_v3.text_search`
concrete type. DDL and query-dialect work are explicitly deferred (see Non-goals).

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
`/Users/tobyhede/src/encrypt-query-language/.worktrees/eql_v3/release/cipherstash-encrypt-v3.sql`.

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

This is what makes increment 1 purely additive: the v3 builder emits the
**existing `EncryptConfig` shape**; only the developer-facing authoring surface
is new.

## Architecture & location

- New module: `packages/stack/src/schema/v3/` (own `index.ts`; split into
  focused files if it grows).
- New export subpath: `@cipherstash/stack/schema/v3` (added to `package.json`
  `exports` + `tsup`/build entry as needed).
- v2 (`packages/stack/src/schema/index.ts`) is **untouched**.
- v3 builders emit the existing `ColumnSchema` / `EncryptConfig` shape, so the
  encryption client, payload, encrypt/decrypt, and query paths work with zero
  client changes.

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
`eqlType = 'eql_v3.text_search'` — exposed via a getter (e.g. `getEqlType()`).

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
- **Type-level:** `InferPlaintext` / `InferEncrypted` produce the expected shapes.

## Open questions

None blocking. Future increments will decide how `eqlType` threads into DDL and
query lowering, and how the narrower text domains (`text_eq`, `text_match`,
`text_ord`) and other scalar families are expressed in the DSL.
