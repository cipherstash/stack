# EQL v3 Prisma-next Default Design

Status: proposed
Date: 2026-07-08
Revised: 2026-07-08 (design A — capabilities encoded in the type system; per-domain constructors; boolean-option resolver removed)
Revised: 2026-07-09 (audit vs `feat/eql-v3-supabase-adapter`: domains are `public.*` / operator functions stay `eql_v3.*`; BigInt is now a first-class v3 family; boolean domain is `public.boolean`; catalog derived from `DOMAIN_REGISTRY`)
Revised: 2026-07-09c (Prisma Next 0.14 alignment: `packages/prisma-next` now pins `@prisma-next/*` at 0.14.0 — contract storage/domain shapes, the emit/re-pin loop, and test-harness requirements changed between 0.8 and 0.14; the operational details live in the companion plan's "Prisma Next 0.14 ground truth" section. Source line references in this spec are 0.8-era anchors and may have drifted by a few lines. The plan's live-suite list also replaces the mixed-client test with side-by-side v2/v3 clients per decision 1b.)
Revised: 2026-07-09b (review remediation: **concrete per-domain types are the spine** — see [Type Discipline]; v2/v3 are **separate entry points**, no in-one-client mixing (bare names are v3, `*V2` is legacy — a breaking major, no transition guard); encrypted ORDER BY (`asc`/`desc` → `eql_v3.ord_term`) in scope; `between` parenthesisation + `bigintSafeReplacer` are correctness invariants; framework-neutral primitives (codec, gate index-sets, fn-schema/op-map/paren-rule) lifted to `eql/v3/`; tests require a plaintext oracle, real properties, full-string operator pins, and mandatory `*.test-d.ts`)
Target package: `@cipherstash/prisma-next`
Reference branches:
- `feat/eql-v3-supabase-adapter` (base) for the current FFI 0.28 concrete domain catalog (`public.*` domains, `eql_v3.*` operator functions), the `DOMAIN_REGISTRY` source of truth, and the canonical v3 adapter shape (Supabase is PostgREST, so its operator model does not port; use it for catalog/derivation/wire-format, not for SQL operator lowering).
- `eql-v3-drizzle-concrete-types` for the canonical **SQL** integration shape, operator lowering (two-arg `eql_v3.*(...::jsonb)`), and plain-jsonb v3 wire format — this is the model prisma-next mirrors.
- Operator SQL is proven live in `packages/stack/__tests__/v3-matrix/matrix-live-pg.test.ts` and `schema-v3-pg.test.ts`.

## Goal

Change `@cipherstash/prisma-next` so that EQL v3 columns are authored through **concrete per-domain constructors** that map 1:1 to the `eql_v3.*` Postgres domains. Capability is encoded in the type system: the constructor you choose *is* the capability set. There is no boolean-option surface and no runtime domain-resolution stage.

This is the original intent of the v3 work. EQL v3 makes each capability combination its own Postgres domain (`public.text_eq`, `public.text_search`, …), so capability is a property of the type, not runtime configuration. The authoring surface mirrors that: one constructor per exposed domain, each carrying a static codec id.

> **Schema note (protect-ffi 0.28).** Two different Postgres schemas are in play and must not be conflated:
> - **Domains / native types live in `public`** — `public.text_eq`, `public.integer_ord`, `public.boolean`, `public.bigint_ord`. The stack catalog pins this at the type level: `eqlType: \`public.${string}\``. This is the column's `nativeType`.
> - **Operator functions live in `eql_v3`** — `eql_v3.eq(...)`, `eql_v3.gt(...)`, `eql_v3.contains(...)`, `eql_v3.ord_term(...)`. This is the SQL the operators lower to.
>
> Wherever this spec refers to a *domain* it is `public.*`; wherever it refers to an *operator function* it is `eql_v3.*`. The `cipherstash/eql-v3/...` codec-id namespace is a logical version tag, unrelated to either Postgres schema.

EQL v2 remains available only through explicit legacy `*V2` names where a compatibility path is needed.

### Why not the boolean-option surface

The v2 authoring surface (`EncryptedString({ equality, freeTextSearch, orderAndRange })`) exists because v2 has a **single** native type (`eql_v2_encrypted`) shared by all codecs, with searchability layered on at migration time via `add_search_config` / `remove_search_config`. In v2, capability is runtime configuration applied to an opaque encrypted blob, and the booleans are the front-end for that config.

v3 deletes that model: query behavior is encoded by the concrete domain, and v3 columns must **not** emit `add_search_config` / `remove_search_config` (see [Migrations](#migrations)). Carrying the boolean surface into v3 would require a resolution stage to translate booleans into a domain and to reject the impossible combinations at runtime — reintroducing a v2 configuration model on top of a v3 type model, and degrading compile-time guarantees into runtime throws. Design A drops the booleans so that:

- **Illegal capability combinations are unrepresentable**, not runtime errors. There is no `EncryptedTextEqMatch()` constructor because there is no `public.text_eq_match` domain, so the combination simply cannot be authored.
- **The codec id is static and known at authoring time.** `(codec id) ⟺ (eql_v3.* domain) ⟺ capabilities` is bijective; nothing is resolved.
- **Autocomplete lists the valid domains.** Discoverability comes from the constructor set, not from a checkbox matrix where most combinations throw.

## Type Discipline (the spine)

Concrete per-domain types are the **core** of EQL v3 and MUST be preserved end-to-end — from the imported catalog, through authoring and the contract descriptor, into derivation and the stack client. This is the load-bearing invariant of the whole design, not a convenience mirrored from another adapter. A v3 implementation that widens columns to a single `AnyEncryptedV3Column`, or descriptors to `{ codecId: string; capabilities: unknown }`, has discarded the exact thing v3 exists to encode. Every task must be specified so the types flow; "derive it like Drizzle" is not a specification.

Requirements (each is independently type-tested):

- **Distinct type per domain.** `encryptedBigIntOrd()` and `encryptedText()` have *different* static types. Two factories for two different domains never share a type.
- **Literal codec id.** A descriptor's `codecId` is a member of the generated literal union `CipherstashV3CodecId` (e.g. `'cipherstash/eql-v3/text_eq@1'`), never `string`.
- **Literal native type.** `nativeType` is the concrete `` `public.${Domain}` `` literal (e.g. `'public.text_eq'`), never widened to `string` or bare `` `public.${string}` ``.
- **Concrete capabilities.** `capabilities` is the domain's literal `QueryCapabilities` (e.g. `{ equality: true; orderAndRange: false; freeTextSearch: false }`), never `unknown` or a widened `QueryCapabilities` that loses the boolean literals.
- **Derivation preserves identity.** `deriveStackSchemasV3` maps each column to its concrete stack factory + column class (`types.TextEq` → `EncryptedTextEqColumn`) and threads that concrete type into `encryptedTableV3`. It MUST NOT widen to `AnyEncryptedV3Column` before building the table — that erases the per-column plaintext / capability inference the stack factories exist to provide.
- **Type-level tests are mandatory** (`*.test-d.ts`), not optional. They pin that the factories are mutually non-assignable, that `codecId` / `nativeType` / `capabilities` are the literal types (not their widenings), and that derivation round-trips the concrete column type. A runtime-only suite does not protect this invariant.

The stack already carries these types — each `types.*` factory returns a concrete `EncryptedXColumn` with literal `eqlType` / `castAs` / `capabilities`. prisma-next's job is to *thread them through generically*, never to collapse them to a uniform descriptor.

## Non-Goals

- Do not add a boolean-capability authoring surface or a domain-resolution stage. Capability is chosen by constructor identity.
- Do not expose `*_ord_ore` variants in this release. The catalog defines them (`EncryptedTextOrdOreColumn`, etc.), but prisma-next surfaces only the `_ord` order domains. `_ord_ore` remains unexposed.
- Do not use `encryptQuery` or v3 term-only operands in Prisma-next. The canonical Drizzle branch uses full encrypted operands and public two-arg SQL functions.
- Do not invent domains that the FFI catalog does not expose. Searchable JSON is not in the current v3 catalog, so there is **no** v3 JSON constructor. (BigInt **is** in the catalog as of protect-ffi 0.28 — `public.bigint` / `bigint_eq` / `bigint_ord` / `bigint_ord_ore` — and is exposed as a first-class v3 family; see [Constructor Inventory](#constructor-inventory).)
- Do not hand-maintain a local copy of the v3 domain catalog. Import it and derive the constructor set, codec ids, capabilities, and cast kinds from it (see [Source of Truth](#source-of-truth)).
- Do not cross the v2 and v3 implementations. v3 is a self-contained namespace; do not branch v2 code paths with `if (isV3)` wire-format switches (see [Namespace Separation](#namespace-separation)).

## Namespace Separation

v3 is implemented as a parallel, self-contained namespace, not as v3-aware branches grafted onto the v2 code. This is a hard constraint, not a stylistic preference: the two versions have different wire formats, clients, codecs, migrations, and query lowering, and entangling them is exactly how cross-version leaks (e.g. an `instanceof` dispatch matching the wrong version) and ambiguous contracts arise.

Rules:

- **Separate module subtree.** All v3 implementation lives under a dedicated namespace — `src/v3/` for codecs/middleware/operators/adapter and `extension-metadata/constants-v3.ts` for ids/traits/invariants. v3 modules must not import v2 codec, wire (`encodeEqlV2EncryptedWire` / composite-literal), middleware, or adapter modules.
- **Separate everything on the wire/runtime path.** Distinct v3 codecs, v3 bulk-encrypt middleware, v3 operator lowering, v3 SDK adapter, and the v3 `EncryptionV3` client. No v2 function gains a v3 branch.
- **Separate entry points, not a shared dispatch.** v2 and v3 are distinct extension factories with distinct extension ids, registered one-per-client (the framework `OperationRegistry` is a flat method-keyed map that disallows override, so two descriptors sharing `cipherstash*` method names cannot co-register). There is no runtime codec-id-namespace router inside a single client, and mixed v2+v3 columns in one client are not supported this release (see [Schema Derivation](#schema-derivation-and-stack-adapter)). Each version flows through fully isolated code from authoring to client.
- **Permitted shared primitives.** Only genuinely version-neutral, presentation-layer primitives may be shared: the `EncryptedEnvelopeBase` class and framework-level authoring/trait infrastructure. Where a v3 column reuses a user-facing value type, it is surfaced through the v3 barrel and must not pull in any v2 wire/codec code.

## Source of Truth

The v3 domain catalog comes from `@cipherstash/stack/eql/v3` after the FFI sync. Prisma-next must **import** this catalog and derive the constructor set, domain names, plaintext cast kinds, capabilities, and codec ids from it. Do not duplicate it as a local table.

The catalog exports a `types` namespace of per-domain factories (`packages/stack/src/eql/v3/types.ts`), each backed by a concrete column class, plus a `DOMAIN_REGISTRY` (`packages/stack/src/eql/v3/domain-registry.ts`) mapping the **bare** (unqualified) Postgres domain name to its factory:

```
types.Text, types.TextEq, types.TextMatch, types.TextOrd, types.TextOrdOre, types.TextSearch
types.Integer, types.IntegerEq, types.IntegerOrd, types.IntegerOrdOre
types.Smallint, types.SmallintEq, types.SmallintOrd, types.SmallintOrdOre
types.Bigint, types.BigintEq, types.BigintOrd, types.BigintOrdOre
types.Numeric, types.NumericEq, types.NumericOrd, types.NumericOrdOre
types.Real, types.RealEq, types.RealOrd, types.RealOrdOre
types.Double, types.DoubleEq, types.DoubleOrd, types.DoubleOrdOre
types.Date, types.DateEq, types.DateOrd, types.DateOrdOre
types.Timestamp, types.TimestampEq, types.TimestampOrd, types.TimestampOrdOre
types.Boolean
```

Catalog constraints:

1. There is no searchable v3 JSON domain. BigInt **is** present (`public.bigint` / `bigint_eq` / `bigint_ord` / `bigint_ord_ore`, `cast_as: 'bigint'`, plaintext = JS `bigint`).
2. `public.boolean` (`types.Boolean`) is storage-only. It does not advertise equality; there is only one boolean domain (no `boolean_eq`).
3. The `*OrdOre` factories exist but are **not** exposed by prisma-next this release (this now includes `types.BigintOrdOre`).

Reuse technique: import `DOMAIN_REGISTRY` / `factoryForDomain` / `stripDomainSchema` from `@cipherstash/stack/eql/v3` and iterate the registry. Each registry key is the bare domain name; each value is a factory that builds a concrete column whose `getEqlType()` returns the `public.`-qualified type, `getQueryCapabilities()` returns `{ equality, orderAndRange, freeTextSearch }`, and `build()` returns `{ cast_as, indexes }`. Derive the codec id from the bare name (`cipherstash/eql-v3/${bareName}@1`); derive `nativeType` from `getEqlType()` (already `public.*`); use `stripDomainSchema()` when you need the bare name from a `public.`-qualified type. The derivation *is* the catalog; there is no separate local table to pin. Retain one drift test only for the FFI-catalog invariants that are not structural (no searchable JSON domain; `public.boolean` is storage-only; `*OrdOre` intentionally unexposed).

> Note: `getEqlType()` is metadata only — `build()` emits `cast_as` + `indexes` and never the domain name. `integer_ord` and `integer_ord_ore` build byte-identically; they differ **only** in `getEqlType()` (the `public.*` domain). This is why override/derivation validation must compare exact domain identity, not just `cast_as` + index keys.

## Public Authoring Surface

One constructor per exposed v3 domain, mirroring the catalog `types.*` names with an `Encrypted` prefix. Each constructor has a static codec id; the constructor name is the capability.

### Constructor Inventory

All constructors below are **new** — none of the v3 constructors reuses a v2 name for v3 behavior. Capability is read from the constructor:

| Family | Storage-only | `+ equality` | `+ equality + order/range` | `+ free-text` | full |
| --- | --- | --- | --- | --- | --- |
| Text | `EncryptedText` | `EncryptedTextEq` | `EncryptedTextOrd` | `EncryptedTextMatch` | `EncryptedTextSearch` |
| Integer | `EncryptedInteger` | `EncryptedIntegerEq` | `EncryptedIntegerOrd` | — | — |
| Smallint | `EncryptedSmallint` | `EncryptedSmallintEq` | `EncryptedSmallintOrd` | — | — |
| BigInt | `EncryptedBigInt` | `EncryptedBigIntEq` | `EncryptedBigIntOrd` | — | — |
| Numeric | `EncryptedNumeric` | `EncryptedNumericEq` | `EncryptedNumericOrd` | — | — |
| Real | `EncryptedReal` | `EncryptedRealEq` | `EncryptedRealOrd` | — | — |
| Double | `EncryptedDouble` | `EncryptedDoubleEq` | `EncryptedDoubleOrd` | — | — |
| Date | `EncryptedDate` | `EncryptedDateEq` | `EncryptedDateOrd` | — | — |
| Timestamp | `EncryptedTimestamp` | `EncryptedTimestampEq` | `EncryptedTimestampOrd` | — | — |
| Boolean | `EncryptedBoolean` (storage-only) | — | — | — | — |

Notes:

- `EncryptedTextOrd` maps to `public.text_ord` (equality + order/range). `EncryptedTextSearch` maps to `public.text_search` (equality + free-text + order/range). `public.text_ord_ore` is not exposed.
- Scalar `*Ord` (including `EncryptedBigIntOrd`) maps to the `public.*_ord` domain (equality + order/range); `*_ord_ore` is not exposed.
- `EncryptedBigInt*` maps to `public.bigint` / `bigint_eq` / `bigint_ord` (`cast_as: 'bigint'`, plaintext = JS `bigint`). `EncryptedBigIntOrdOre` is not exposed.
- `EncryptedBoolean` maps to storage-only `public.boolean`. There is no boolean equality constructor until the FFI exposes a boolean equality domain.
- There is **no** `EncryptedJson` v3 constructor. The name does not exist on the v3 surface; use `EncryptedJsonV2` (see [JSON](#json)).

The constructor set is **derived from the catalog**, not hand-listed: iterate the exposed `types.*` factories (excluding `*OrdOre`) and generate one authoring constructor per factory. Adding a domain to the catalog adds a constructor automatically; removing one removes it.

### PSL / TS surface

```prisma
model User {
  email     cipherstash.EncryptedTextSearch()   // eq + free-text + order/range
  name      cipherstash.EncryptedTextEq()        // equality only
  notes     cipherstash.EncryptedText()          // storage only
  age       cipherstash.EncryptedIntegerOrd()    // eq + order/range
  tier      cipherstash.EncryptedInteger()       // storage only
  balance   cipherstash.EncryptedBigIntOrd()     // eq + order/range (JS bigint)
  birthday  cipherstash.EncryptedDateEq()        // equality only
  createdAt cipherstash.EncryptedTimestampOrd()  // eq + order/range
  active    cipherstash.EncryptedBoolean()       // storage only
}
```

The TS factories mirror the PSL constructors 1:1 (camelCase):

```ts
encryptedTextSearch()
encryptedTextEq()
encryptedText()
encryptedIntegerOrd()
encryptedInteger()
encryptedBigIntOrd()
encryptedDateEq()
encryptedTimestampOrd()
encryptedBoolean()
```

Legacy v2 is explicit and unchanged:

```prisma
legacyEmail cipherstash.EncryptedStringV2()
legacyData  cipherstash.EncryptedJsonV2()
```

```ts
encryptedStringV2()
encryptedJsonV2()
```

### Capability semantics per domain

The capability a constructor grants is defined by its domain's `getQueryCapabilities()`, not by any local flag:

- **Storage-only** (`EncryptedText`, `EncryptedInteger`, …, `EncryptedBoolean`): encrypt/store/decrypt only. Every search operator is rejected at operator time.
- **`*Eq`**: equality (`=`, `IN`) only.
- **`*Ord`**: equality plus comparison / range / ordering (`<`, `>`, `BETWEEN`, `ORDER BY`).
- **`EncryptedTextMatch`**: free-text token containment only.
- **`EncryptedTextSearch`**: equality + free-text + order/range.

There is no combination to validate at authoring time: unrepresentable combinations have no constructor. The only capability enforcement at runtime is **operator gating** (see [Operators](#operators)) — rejecting an operator a column's domain does not support — which reads the domain's capabilities directly.

### JSON

`EncryptedJson` has **no** v3 constructor. The v3 barrel does not export it, so `cipherstash.EncryptedJson()` is an unresolved name at authoring time (PSL / TS "unknown constructor"), not a runtime throw. Documentation and the changeset must direct users to the v2 alias:

- searchable JSON → `EncryptedJsonV2` / `encryptedJsonV2`.

BigInt, by contrast, **is** a first-class v3 family as of protect-ffi 0.28: `EncryptedBigInt` / `EncryptedBigIntEq` / `EncryptedBigIntOrd` (`cast_as: 'bigint'`, plaintext = JS `bigint`, backed by `public.bigint` / `bigint_eq` / `bigint_ord`). The legacy `EncryptedBigIntV2` / `encryptedBigIntV2` remain available only for explicit v2 compatibility.

`EncryptedTimestamp*` maps to `cast_as: "timestamp"` and preserves time of day. `EncryptedDate*` maps to `cast_as: "date"` and reconstructs to `Date`.

## Contract Representation

Each v3 column descriptor is **static at authoring** — there is no post-authoring rewrite. The constructor emits its concrete descriptor directly:

- `codecId`: the concrete per-domain v3 codec id, **derived from the domain**, not a reused v2 codec id.
- `nativeType`: the concrete `public.*` domain (from `getEqlType()`).
- `typeParams`:
  - `castAs`
  - `capabilities`

### The codec id is a projection of the domain, not independent data

In v2, one native type (`eql_v2_encrypted`) is shared by all six codecs, so the codec id is the only discriminator and is genuinely independent data. In v3 the relationship inverts: each domain is its own Postgres domain, so `(codec id) ⟺ (public.* domain)` is bijective. The codec id therefore carries no discriminating information the domain does not already have. Its two remaining jobs are:

1. **Serialization handle.** The contract is JSON; the domain *type* exists only at compile time. The codec id is the string key that reconstitutes the runtime codec/envelope/trait bundle from persisted JSON.
2. **Version axis.** The `@N` suffix (which the bare domain name lacks) is exactly how v2 and v3 — same logical type, different wire format — stay distinguishable, and how a future wire-format change to a domain would be versioned.

Consequences for the design:

- **Derive, do not author.** Codec ids are generated from the catalog as `cipherstash/eql-v3/${bareDomain}@1`, not hand-listed, where `bareDomain` is the `DOMAIN_REGISTRY` key (equivalently `stripDomainSchema(getEqlType())` — the domain with the `public.` prefix removed). Iterate `DOMAIN_REGISTRY` rather than re-deriving.
- **Single source for the type.** `nativeType` is the single source; do not also carry a redundant `typeParams.eqlType`.
- **Type the ids as a generated closed union.** Produce `CIPHERSTASH_V3_CODEC_IDS` (const tuple) → `CipherstashV3CodecId` (union) → set + guard, mirroring `CIPHERSTASH_CODEC_IDS` / `CipherstashCodecId` / `isCipherstashCodecId` (`extension-metadata/constants.ts:88-123`) so every codec-id-keyed dispatch table is compile-time-exhaustive.
- **No id reuse.** v3 must not reuse v2 codec ids such as `cipherstash/string@1`. Tests must assert the v3 and v2 id sets are disjoint.

Type the descriptor fields with the imported stack types rather than free strings: `nativeType` as `` `public.${string}` `` / `EqlTypeForColumn`, `capabilities` as the exported `QueryCapabilities` (`{ equality, orderAndRange, freeTextSearch }`), `castAs` restricted to `PlaintextKind` (`'string' | 'number' | 'bigint' | 'boolean' | 'date' | 'timestamp'`) / `DateLikeCast`.

Legacy v2 aliases keep the existing v2 codec ids and `eql_v2_encrypted` native type.

Place v3 ids/traits/invariants in a dedicated `extension-metadata/constants-v3.ts` (or `v3/` subtree) rather than swelling the v2 `constants.ts`.

## Runtime Codecs

V3 columns are PostgreSQL domains over `jsonb`. Runtime encoding and decoding must use plain JSONB, matching `v3ToDriver` / `v3FromDriver` from the Drizzle integration:

```ts
// `bigintSafeReplacer` is load-bearing and MUST be copied with the codec: a
// well-formed envelope never carries a bigint (bigint plaintext is encrypted to
// ciphertext strings first), but a malformed envelope with a stray bigint would
// otherwise throw `TypeError: Do not know how to serialize a BigInt`. A copy
// that drops it is a regression (see `eql/v3/drizzle/codec.ts:18,28`).
function bigintSafeReplacer(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? value.toString() : value
}

function v3ToDriver(value: unknown): string | null {
  if (value === null || value === undefined) return null
  return JSON.stringify(value, bigintSafeReplacer)
}
```

Per [Operators](#operators), this codec (`v3ToDriver` / `v3FromDriver` / `bigintSafeReplacer`) is a **shared** framework-neutral primitive lifted to `eql/v3/codec.ts` and imported by both the Drizzle and prisma-next adapters — not re-implemented here.

v3 codecs live in the v3 subtree and depend only on the neutral `EncryptedEnvelopeBase`; they must not import the v2 composite/wire codec. The v3 codec factory reuses the version-neutral user-facing value classes where the type already matches (surfaced through the v3 barrel) and introduces a number envelope for number-backed v3 domains:

- text -> `EncryptedString`
- integer, smallint, numeric, real, double -> `EncryptedNumber`
- bigint -> `EncryptedBigInt` (bigint-backed, **not** `EncryptedNumber`)
- date, timestamp -> `EncryptedDate`
- boolean -> `EncryptedBoolean`

`EncryptedNumber` and `EncryptedDouble` must be **siblings**, each extending `EncryptedEnvelopeBase<number>` with its own distinct `typeName`. Do **not** alias or subclass one from the other: `typeName` drives the `$encryptedX` placeholder marker that `decryptAll` keys on (`envelope-base.ts:87-99`), so aliasing renders the wrong marker, and subclassing makes `value instanceof EncryptedNumber` true for a v2 `EncryptedDouble` — a cross-version leak in any coercer that dispatches on `instanceof` (`execution/operators.ts:202-233`). Each concrete v3 number domain sets `renderOutputType` to `'EncryptedNumber'`. `EncryptedDouble` (the value class) remains available for legacy v2 compatibility only; v3 integer/numeric constructors must not render as `EncryptedDouble`.

`EncryptedBigInt` is a **separate** value envelope extending `EncryptedEnvelopeBase<bigint>` with its own `typeName` — the `bigint` `cast_as` domains (`public.bigint*`) carry JS `bigint` plaintext, which is not a `number`, so they must not reuse the `EncryptedNumber` envelope. `bigint` values are lossless across the FFI boundary; the runtime wire codec still `JSON.stringify`s the *ciphertext envelope* (never the raw `bigint`), so JSON's lack of native `bigint` support does not arise on the wire path.

The runtime codec descriptor should:

- advertise the concrete domain in `targetTypes`
- use plain JSONB for parameter wire encoding
- never use the v2 composite-literal codec
- emit `[REDACTED]` placeholders through the existing envelope base

## Middleware

Add a **separate** v3 bulk-encrypt middleware under the v3 subtree. Do not generalize the v2 middleware with a wire-format branch (see [Namespace Separation](#namespace-separation)). The v3 middleware may reuse the neutral routing-key stamping *utility*, but must not share the v2 encode path.

Required behavior:

1. Filter parameters by the v3 codec id set.
2. Stamp `(table, column)` routing keys from INSERT/UPDATE ASTs, reusing the neutral `stampRoutingKeysFromAst` / `setHandleRoutingKey` utility (`bulk-encrypt.ts:80-81, 198-231`) — a version-neutral primitive, not the v2 encode path.
3. For search operands produced by operators, rely on operator-time routing-key stamping (`execution/operators.ts:147-158`).
4. Group by routing key.
5. Call `sdk.bulkEncrypt`, not `sdk.bulkEncryptQuery`. (`bulkEncrypt` is already the established prisma-next path — `bulk-encrypt.ts:121`.)
6. Replace parameter values with plain JSONB encoded ciphertext payloads (not the v2 composite from `encodeEqlV2EncryptedWire`).

There is no query/storage split in this design. Search operands are full encrypted payloads because the canonical Drizzle branch lowers to public two-arg functions that accept `$::jsonb` full operands.

## Operators

Keep the existing cipherstash-prefixed methods:

- `cipherstashEq`, `cipherstashNe`
- `cipherstashInArray`, `cipherstashNotInArray`
- `cipherstashGt`, `cipherstashGte`, `cipherstashLt`, `cipherstashLte`
- `cipherstashBetween`, `cipherstashNotBetween`
- `cipherstashIlike`, `cipherstashNotIlike`
- `cipherstashAsc`, `cipherstashDesc` — encrypted ordering, lowering to `eql_v3.ord_term({{self}})`, gated on an `ore` index. In scope this release (Drizzle parity: `operators.ts:497-502`). Storage-only / non-`ore` columns reject ordering with `EncryptionOperatorError`.

For v3 columns, lower to the same SQL shape as the canonical Drizzle branch. The prisma-next lowering mechanism is a template with `{{self}}` / `{{arg0}}` placeholders (`execution/operators.ts:302-326`); the v3 templates must carry the `::jsonb` cast, which the v2 templates do not:

```
eql_v3.eq({{self}}, {{arg0}}::jsonb)
eql_v3.neq({{self}}, {{arg0}}::jsonb)
eql_v3.gt({{self}}, {{arg0}}::jsonb)
eql_v3.gte({{self}}, {{arg0}}::jsonb)
eql_v3.lt({{self}}, {{arg0}}::jsonb)
eql_v3.lte({{self}}, {{arg0}}::jsonb)
eql_v3.contains({{self}}, {{arg0}}::jsonb)
eql_v3.ord_term({{self}})
```

**`cipherstashBetween` / `cipherstashNotBetween` parenthesisation is a correctness invariant, not a style choice.** The range template MUST be a single self-contained, parenthesised conjunction:

```
(eql_v3.gte({{self}}, {{arg0}}::jsonb) AND eql_v3.lte({{self}}, {{arg1}}::jsonb))
```

Postgres binds `NOT` tighter than `AND`. Emitted bare, `NOT (between)` parses as `(NOT gte) AND lte` — selecting rows *below the lower bound* instead of the complement of the range (this is the exact class of bug fixed in `9c82f50e`; the reference documents it at `sql-dialect.ts:26-37`). `cipherstashNotBetween` then emits `NOT <parenthesised-range>`. A test MUST pin the full parenthesised string for both, and assert `not(between)` wraps the whole conjunction. Emitting the two calls unwrapped is a defect even though each half is individually correct.

The operator **functions** live in the `eql_v3` schema (unchanged by 0.28) even though the **domains** they operate on are `public.*`; do not "correct" these to `public.*`. This exact two-arg `::jsonb` shape is proven end-to-end against real domains in `packages/stack/__tests__/v3-matrix/matrix-live-pg.test.ts` and `schema-v3-pg.test.ts` (e.g. `eql_v3.eq("col", $::jsonb)`, `eql_v3.contains("col", $::jsonb)`, range = `eql_v3.gte(...) AND eql_v3.lte(...)`). The `::jsonb` template change and the middleware wire-format branch (plain JSON, not the v2 composite) must be implemented together — the template consumes exactly what the middleware produces.

The operand is the **full encrypted envelope** (every index term), not a narrowed query term: the `encryptQuery` scalar-term path is unsupported in protect-ffi 0.28 (`EQL_V3_QUERY_UNSUPPORTED`), and the SQL function chosen — not a `queryType` — selects which term is compared. On a pure-ORE domain (no `unique`/`hm` index) `eql_v3.eq` resolves via `ord_term` (equality-via-ORE); this is why the equality gate accepts `unique` **or** `ore`. `eql_v3.contained_by` also exists as the dual of `contains`, but prisma-next exposes only `contains` (via `cipherstashIlike`) this release.

`cipherstashIlike` / `cipherstashNotIlike` lower to `eql_v3.contains` (bloom-filter token containment, not SQL `LIKE`). Carry this caveat into user docs so wildcard semantics are not implied. (The Drizzle reference names this operator `contains`; prisma-next keeps its `ilike` method name — an intentional surface divergence.)

Capability gating must read the domain's built `indexes` (from `column.build().indexes`), not any authoring flag. The gate is a disjunction — any listed index grants the capability:

- equality (`eq`, `ne`, `IN`, `NOT IN`) requires `unique` **or** `ore`
- comparison / range / ordering (`gt`/`gte`/`lt`/`lte`, `between`/`notBetween`, `asc`/`desc`) requires `ore`
- free-text search (`ilike`) requires `match`
- storage-only domains (no index) reject every search operator

This gating is the **only** runtime capability enforcement in the design — there is no authoring-time combination validation because impossible combinations have no constructor.

**Shared, framework-neutral primitives — lift to `packages/stack/src/eql/v3/`, do not re-copy.** Three things the Drizzle adapter currently keeps under its own subtree have **no** Drizzle dependency and are a correctness surface that must not diverge between adapters:

1. The **wire codec** `v3ToDriver` / `v3FromDriver` **including `bigintSafeReplacer`** (currently `eql/v3/drizzle/codec.ts`, but it imports only `Encrypted` from `@/types`). Move to `eql/v3/codec.ts`; both adapters import it.
2. The **gate index-sets** `EQUALITY_INDEXES = ['unique','ore']`, `ORE_INDEXES = ['ore']`, `MATCH_INDEXES = ['match']` and the `requireIndex` disjunction rule (currently `eql/v3/drizzle/operators.ts:205-221`). These decide which operators a domain may answer — two divergent copies is a correctness bug, not a DRY nit.
3. The **function-schema + op→function-name map + parenthesisation rule**: `EQL_V3_FN_SCHEMA = 'eql_v3'`, the `eq→eq`/`ne→neq`/`gt→gt`/… name map, and the "range is a parenthesised conjunction" rule (currently `eql/v3/drizzle/sql-dialect.ts`). The *fragment builders* can't be shared verbatim (Drizzle emits `sql` fragments; prisma-next emits `{{self}}`/`{{arg0}}` template strings), but the schema, the name map, and the paren rule can and must be. Had they been shared, the between bug above could not exist in two places.

This expands scope to touch the existing Drizzle adapter (it re-imports from the lifted location). That is intended.

Add a real exported error class `EncryptionOperatorError` carrying a `context: { columnName?, tableName?, operator? }` (mirroring `eql/v3/drizzle/operators.ts:66-78`). The two adapters keep **separate** `EncryptionOperatorError` classes by deliberate fork (they are independently-versioned entry points — see the "INTENTIONAL FORK" note in the reference); this is the one place duplication is correct. Prisma-next operators currently throw plain `TypeError` / `Error`; "structured like" is not enough — the class must exist and be exported.

Per-domain trait derivation: each concrete v3 codec descriptor derives its `cipherstash:*` traits from the domain's `QueryCapabilities` keys (`equality → cipherstash:equality`, etc.), a single mapping reused across domains.

Do not attach built-in framework equality traits that would re-enable plain SQL `=`. CipherStash operators stay in the `cipherstash:*` trait namespace (regression-pinned by `test/equality-trait-removal.test.ts`).

## Schema Derivation and Stack Adapter

**v2 and v3 are separate entry points — they are never co-registered in one Prisma-next client.** The framework's `OperationRegistry` is a flat, method-name-keyed map that disallows override; two descriptors both defining `cipherstashEq` collide at registration regardless of extension id. Rather than overload one gated descriptor, v3 ships as its **own** extension factory with its **own** distinct extension id/version, keeping the **same** `cipherstash*` operator method names. A given client is either v2 or v3.

Consequences:

- **No single-dispatch-boundary / codec-id-namespace routing inside one client.** There is no shared `deriveStackSchemas` that branches v2 vs v3 at runtime, and no per-client registry that holds both versions. Delete that machinery.
- **Mixed v2 + v3 columns in a single client are not supported this release.** A schema is authored for one version. (A codebase can still run a v2 client and a v3 client side by side; they do not share a registry, descriptor, or dispatch.)
- **`deriveStackSchemasV3(contractJson)` is a v3-only derivation.** It reads the v3 codec ids and builds concrete `@cipherstash/stack/eql/v3` schemas, preserving the concrete column type (see [Type Discipline](#type-discipline-the-spine)):

```ts
// nativeType 'public.text_eq' -> concrete factory types.TextEq -> EncryptedTextEqColumn
encryptedTableV3(table, { [column]: types.TextEq(column) })
```

It MUST NOT widen the built column to `AnyEncryptedV3Column` before constructing the table. A v3 contract containing a v2 codec id is a hard error (wrong entry point), not a silently-derived v2 column.

- **v3 client.** `cipherstashFromStackV3` builds a single `EncryptionV3({ schemas })` client from the v3-derived schemas. v3 bulk-encrypt goes through `EncryptionV3(...)`, never the base v2 `bulkEncrypt`. The v3 SDK adapter/registry accepts the v3 concrete columns; the v2 registry (`sdk-adapter.ts:136`) is untouched and unaware of v3.

Override validation for v3 columns lives in the v3 derivation path and must compare **exact v3 domain identity**, not only `cast_as` and index keys (`from-stack.ts:149-176` cannot distinguish `integer_ord` from `integer_ord_ore` — they have identical `cast_as` and built indexes and differ only in `nativeType`). Two columns with the same `cast_as` but different domains are not equivalent. v2 override validation is unchanged.

## Migrations

Add a v3 bundle baseline migration after the existing v2 baseline. Keep the v2 baseline while legacy v2 aliases exist.

V3 columns must not emit v2 `add_search_config` / `remove_search_config` lifecycle operations. Their query behavior is encoded by the concrete PostgreSQL domain.

The migration package must include:

- EQL v3 install SQL sourced from `@cipherstash/eql/sql` (`releaseManifest`, `@cipherstash/eql@3.0.0-alpha.3` — the same source `packages/stack/scripts/install-eql-v3.ts` / `installEqlV3IfNeeded` use), **not** a hand-vendored FFI fixture. This install creates the `public.*` domains and the `eql_v3.*` operator functions.
- new invariant id `cipherstash:install-eql-v3-bundle-v1`
- migration directory `20260601T0100_install_eql_v3_bundle`, which sorts after the v2 install (`20260601T0000_install_eql_bundle` / `cipherstash:install-eql-bundle-v1`)

## Testing

Target three levels — unit, property, and integration.

### Unit / authoring

Add or update tests in `packages/prisma-next/test` (each maps to an existing file that gains v3 cases unless noted):

1. Authoring: each v3 constructor emits its concrete per-domain codec id and concrete `public.*` native type, statically — no resolution pass (`authoring.test.ts`).
2. Constructor↔domain 1:1: the generated constructor set exactly matches the exposed catalog `types.*` factories (excluding `*OrdOre`); every constructor's codec id, `nativeType`, and `capabilities` equal the catalog values for that domain (`authoring.test.ts` / `column-types.test.ts`).
3. Legacy: `*V2` constructors emit current v2 codec ids and `eql_v2_encrypted` (`authoring.test.ts` / `psl-interpretation*.test.ts`).
4. Unexposed / absent surface: no `*OrdOre` constructor is exported (including `EncryptedBigIntOrdOre`); no `EncryptedJson` v3 constructor exists (the name is unresolved on the v3 barrel); `EncryptedBoolean` is storage-only and exposes no equality constructor. Conversely, `EncryptedBigInt` / `EncryptedBigIntEq` / `EncryptedBigIntOrd` **are** exported and emit `public.bigint*` with `cast_as: 'bigint'` (`column-types.test.ts`, `psl-interpretation*.test.ts`).
5. Catalog invariants (new): a drift test asserting no searchable JSON v3 domain is exposed, `public.boolean` is storage-only, `*OrdOre` (incl. `bigint_ord_ore`) is excluded from the generated surface, and the BigInt family IS exposed. Assert native types are `public.*` while operator SQL functions are `eql_v3.*` (the schema split is not accidentally collapsed). Structural derivation from the imported `DOMAIN_REGISTRY` covers the rest — no hand-maintained table to pin.
6. Runtime codec: v3 encodes/decodes plain JSONB and never emits v2 composite literals (`codec-runtime.test.ts`, `cipherstash-codec*.test.ts`).
7. Middleware: v3 parameters are bulk-encrypted with `sdk.bulkEncrypt` and JSONB encoded (`bulk-encrypt-middleware.test.ts`). This suite MUST cover the edge cases the implementation itself handles (the Drizzle reference covers all four — `eql/v3/drizzle/operators.test.ts`): (a) a bulk-encrypt response whose length ≠ the operand count is **rejected**, not truncated (a short response would silently widen `inArray` / narrow `notInArray`); (b) partial-failure is wrapped in the structured error with `{ operator, columnName }`; (c) returned terms are positionally aligned index-for-index with the operands; (d) a `null` in a value list is rejected **before** any crypto crossing.
8. Operator SQL lowering: **pin the full lowered string with `.toBe()` for every operator** (`eq`, `ne`, `inArray`, `notInArray`, `gt`, `gte`, `lt`, `lte`, `between`, `notBetween`, `ilike`, `notIlike`, `asc`, `desc`) — not `.toContain('eql_v3.eq(')`, which would not catch the `between` paren bug. Include an explicit test that `cipherstashNotBetween` (and `not(between)`) emits `NOT (eql_v3.gte(...) AND eql_v3.lte(...))` with the conjunction parenthesised (`operator-lowering*.test.ts`).
9. Operator gating: for each domain, the gate allows exactly the operators the domain's built indexes support and rejects the rest with `EncryptionOperatorError`; storage-only domains reject every search operator **and** `asc`/`desc` (`operator-lowering*.test.ts`).
10. Trait: framework built-in equality traits are not reintroduced (`equality-trait-removal.test.ts`).
11. Derivation: v3 contracts derive exact `@cipherstash/stack/eql/v3` concrete schemas (`derive-schemas.test.ts`).
12. Divergence: override schemas with the specific **same-`cast_as`, different-domain** mismatch fail (`from-stack-divergence.test.ts`).
13. Bundling: v3 codecs and bundle assets do not pull the v2 composite codec path unnecessarily (`bundling-isolation.test.ts`).
14. Codec-id disjointness: the v3 codec-id set and the v2 codec-id set are disjoint.

### Type-level (`*.test-d.ts`) — mandatory

These enforce [Type Discipline](#type-discipline-the-spine); a runtime-only suite does not. Add `*.test-d.ts` files (as the Drizzle side does — `packages/stack/__tests__/drizzle-v3/types.test-d.ts`):

15. **Factories are mutually non-assignable.** `encryptedBigIntOrd()` is *not* assignable to the type of `encryptedText()` (and vice-versa); a representative off-diagonal set is checked so an accidental collapse to one shared descriptor type fails to compile.
16. **Descriptor field types are literal, not widened.** For a sample of domains, `codecId` is the literal union member (e.g. `'cipherstash/eql-v3/text_eq@1'`, not `string`), `nativeType` is the `` `public.text_eq` `` literal (not `string`), and `capabilities` is the concrete literal `QueryCapabilities` (booleans preserved, not `unknown`).
17. **Derivation preserves the concrete column type.** `deriveStackSchemasV3` over a known contract yields the concrete `EncryptedTextEqColumn` / `EncryptedBigintOrdColumn` types into `encryptedTableV3`, not `AnyEncryptedV3Column`.

### Property-based

`fast-check ^4.8.0` is already in the monorepo (`packages/drizzle/package.json`) but is not yet a prisma-next devDependency — add it. Required properties:

These must be genuine properties over generated inputs — not `fc.constantFrom(...EXPOSED_DOMAIN_ENTRIES)` table-tests wearing a fast-check costume. Iterating the closed catalog is a table test; keep those as `it.each`, and reserve `fc` for real input spaces:

- **JSONB round-trip**: over `fc.jsonValue()`, `v3FromDriver(v3ToDriver(x))` deep-equals `x`; `null`/`undefined → null`.
- **BigInt losslessness**: over `fc.bigInt()`, a v3 bigint value survives encode→decode / the codec path and reconstructs to the identical JS `bigint` (this is the property `9c82f50e`'s oracle needed and the current plan lacks).
- **Codec round-trip per `castAs`**: for each `castAs`, an arbitrary plaintext of that kind round-trips through the cell codec to an equal value (the current JSON-only round-trip does not exercise the number/bigint/date/boolean envelopes).
- **`[REDACTED]` invariant**: for arbitrary user values the serialized envelope never contains the plaintext and always renders the placeholder.
- **ORE order-preservation (metamorphic)**: over arbitrary ordered pairs of same-typed plaintexts, the emitted ordering relation agrees with the plaintext comparison — the property that also makes the live oracle rigorous.
- **Operator-gating equivalence**: for arbitrary `(domain, operator)`, the gate allows the operator iff the pure capability predicate holds.
- **Derivation round-trip**: arbitrary v3 contract column → `deriveStackSchemasV3` → derived domain identity equals the original.

### Integration / live-PG

prisma-next has no live-PG tests today; add suites mirroring the Drizzle branch, reusing `describeLivePg` / `LIVE_EQL_V3_PG_ENABLED` / `installEqlV3IfNeeded` (self-skip locally, run in CI with `DATABASE_URL` + `CS_*`):

The live suite MUST assert against a **plaintext-computed oracle**, not hand-picked rows (mirror the Drizzle oracle `eql/v3/drizzle/operators-live-pg.test.ts` — `expectedKeysFor` / `sortedKeysFor` / `comparePlain`, which now includes a `bigint` branch after `9c82f50e`). Asserting "the expected row is selected" over a couple of rows would pass against a `between` that matches everything — the oracle is exactly what caught the paren bug.

- **operators-live-pg**: per capability tier (per constructor), encrypt → INSERT → query via each `cipherstash*` operator → decrypt against real `public.*` domains; assert the selected key set **equals the oracle's `expectedKeysFor`** over a seeded plaintext population.
- **range boundaries (the paren oracle)**: a `cipherstashBetween` with a single-row-wide window selects exactly that row, and a `cipherstashNotBetween` anchored at the **lower** bound excludes it (and selects the rest) — the specific shape that fails when `NOT (gte AND lte)` degrades to `(NOT gte) AND lte`.
- **ordering live**: `cipherstashAsc` / `cipherstashDesc` over a seeded population return rows in the exact plaintext order (`sortedKeysFor`); a non-`ore` column rejects ordering.
- **operators-null-live-pg**: null operands and null columns round-trip.
- **boolean storage-only live**: `public.boolean` survives INSERT/SELECT/decrypt and rejects every search operator (and ordering).
- **bigint round-trip live**: `public.bigint` / `bigint_eq` / `bigint_ord` encrypt → INSERT → query (eq / order-range) → decrypt to a JS `bigint`, ordering asserted via `comparePlain`'s bigint branch.
- **migration application live**: apply `20260601T0100_install_eql_v3_bundle`; assert the concrete domains exist, invariant `cipherstash:install-eql-v3-bundle-v1` is registered, and v3 columns emit no `add_search_config` / `remove_search_config`.
- **real bulkEncrypt**: middleware → real `EncryptionClient.bulkEncrypt` (not the fake) → INSERT, proving routing-key stamping and JSONB payloads end-to-end.

(No "mixed v2 + v3 in one client" live test — that mode is unsupported per [Schema Derivation](#schema-derivation-and-stack-adapter). A v2 client and a v3 client running side by side may be exercised separately.)

### Commands

```bash
pnpm --filter @cipherstash/prisma-next test
pnpm --filter @cipherstash/prisma-next build
```

If implementation touches `@cipherstash/stack` public exports, also run the relevant stack v3 tests.

## Release Notes

This is a breaking public behavior change for `@cipherstash/prisma-next`: v3 columns are authored through new per-domain constructors, and the legacy boolean-option surface is not carried into v3.

Required release metadata:

- Add a changeset for `@cipherstash/prisma-next`.
- Mark the change as major if the package is considered published/stable.
- If the package is still experimental and versioning policy allows a minor, the changeset body must still call out the new authoring surface explicitly.

User-facing migration guidance:

- EQL v3 columns are authored with concrete per-domain constructors — the constructor is the capability. Examples: `EncryptedTextSearch()` (eq + free-text + order/range), `EncryptedTextEq()` (equality), `EncryptedIntegerOrd()` (eq + order/range), `EncryptedText()` / `EncryptedInteger()` (storage-only), `EncryptedBoolean()` (storage-only).
- There is no boolean-option surface (`EncryptedString({ equality, ... })`) in v3. Choose the constructor whose name matches the capability you need.
- Impossible capability combinations have no constructor (e.g. text equality + free-text without order/range) — they are unrepresentable rather than runtime errors.
- Use `*V2` constructors to keep old v2 columns.
- BigInt is a first-class v3 family (`EncryptedBigInt` / `EncryptedBigIntEq` / `EncryptedBigIntOrd`, JS `bigint` plaintext). Searchable JSON has no v3 constructor; use `EncryptedJsonV2`.
- Boolean v3 is storage-only; there is no boolean equality constructor.
- Regenerate contracts and migrations after changing constructors.
