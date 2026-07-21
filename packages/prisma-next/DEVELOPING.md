# Developing `@cipherstash/prisma-next`

Contributor-facing notes for the cipherstash extension. The user-facing
surface lives in [`README.md`](./README.md); this file collects the
internal layout, the substrate architecture, how the v3 domain surface
is derived, and the design choices a contributor needs to know when
extending the package.

**This package is EQL v3 only.** Every encrypted column is a concrete
Postgres domain (`public.eql_v3_text_search`, `public.eql_v3_bigint_ord`,
…); the domain you choose *is* the capability set. There is no EQL v2
surface — no `*V2` constructors, no `eql_v2_encrypted` composite wire, no
per-column search-mode flags.

## Source layout

```text
packages/prisma-next/
├── src/
│   ├── contract.prisma                  PSL contract source (models NO storage — v3
│   │                                     declares none; the bundle creates the domains)
│   ├── contract.{json,d.ts}             emitted contract-space artefacts
│   ├── contract-authoring.ts            v3 PSL constructors (`cipherstash.TextSearch()` …),
│   │                                     derived 1:1 from the catalog
│   ├── execution/                       version-neutral runtime substrate
│   │   ├── envelope-base.ts             EncryptedEnvelopeBase<T> shared superclass
│   │   ├── envelope-{string,bigint,     concrete value envelopes (EncryptedNumber lives
│   │   │   boolean,date,json}.ts         under src/v3/)
│   │   ├── sdk.ts                       CipherstashSdk interface (framework-native)
│   │   ├── routing.ts                   routing-key derivation + stampRoutingKeysFromAst
│   │   ├── middleware-registry.ts       per-SDK "middleware wired?" WeakSet
│   │   ├── decrypt-all.ts               opt-in read-side bulk-decrypt walker
│   │   └── abort.ts                     RUNTIME.ABORTED envelope wrappers
│   ├── v3/                              the EQL v3 plane
│   │   ├── catalog.ts                   per-domain metadata, DERIVED from the stack's
│   │   │                                 DOMAIN_REGISTRY (never hand-maintained)
│   │   ├── envelope-number.ts           EncryptedNumber (the numeric-family envelope)
│   │   ├── codec-runtime-v3.ts          createV3CodecDescriptors + CipherstashV3CellCodec
│   │   ├── wire-v3.ts                   plain-JSONB wire (v3ToDriver / v3FromDriver)
│   │   ├── operators-v3.ts              the eql* query operators + eqlAsc/eqlDesc
│   │   ├── query-term.ts                the query-term seam (mark / collect / route)
│   │   ├── bulk-encrypt-v3.ts           bulkEncryptMiddlewareV3(sdk)
│   │   ├── runtime-v3.ts                createCipherstashV3RuntimeDescriptor({ sdk })
│   │   ├── derive-schemas-v3.ts         contract.json → EncryptedTable[] for EncryptionV3
│   │   ├── sdk-adapter-v3.ts            EncryptionV3 client → CipherstashSdk adapter
│   │   ├── from-stack-v3-validate.ts    assertV3SchemasAgree (override-vs-contract check)
│   │   └── barrel.ts                    user-facing envelope re-exports
│   ├── stack/
│   │   └── from-stack-v3.ts             cipherstashFromStack({ contractJson })
│   ├── migration/
│   │   ├── cipherstash-codec-v3.ts      v3 control-plane hooks (identity expandNativeType)
│   │   └── eql-bundle-v3.ts             runtime EQL v3 install-SQL injection
│   ├── extension-metadata/
│   │   ├── constants.ts                 shared ids: space id, version, cipherstash:* traits
│   │   ├── constants-v3.ts              v3 codec-id tuple, invariants, baseline name, guards
│   │   ├── codec-metadata.ts            SDK-free v3 codec metadata for pack-meta
│   │   └── descriptor-meta.ts           cipherstashPackMeta (authoring + codecInstances + storage)
│   ├── types/
│   │   ├── codec-types.ts               CodecTypes (40 v3 codec-id entries, decode types)
│   │   └── operation-types.ts           QueryOperationTypes (the eql* method surface)
│   └── exports/
│       ├── control.ts                   SqlControlExtensionDescriptor (control-plane entry)
│       ├── runtime.ts                   envelopes + SDK + v3 codec runtime + decryptAll +
│       │                                 bulkEncryptMiddlewareV3 (runtime entry)
│       ├── stack.ts                     cipherstashFromStack + the v3 stack primitives
│       ├── v3.ts                        the complete v3 surface in one import
│       ├── pack.ts                      cipherstashPackMeta default export (TS authoring)
│       ├── column-types.ts              the v3 TS contract factories (text / textSearch / …)
│       ├── codec-types.ts               codec-types augmentation re-export
│       ├── operation-types.ts           operation-types augmentation re-export
│       └── contract-space-typing.ts     helper types for contract-space consumers
└── migrations/
    ├── 20260601T0100_install_eql_v3_bundle/   the SOLE migration — invariant-only genesis
    │                                           edge (from: null) installing the EQL v3 bundle
    └── refs/head.json                          hand-pinned head ref (v3 invariant only)
```

## The v3 domain surface is DERIVED, not hand-wired

The single most important thing to know: v3 does **not** have a
per-codec wiring template. The entire domain surface — codec ids, native
types, query capabilities, authoring constructors, runtime codecs,
pack-meta instances, storage rows — is derived from one source of truth,
the stack's `DOMAIN_REGISTRY`, through `src/v3/catalog.ts`.

`catalog.ts` probes each registry factory and reads `getEqlType()` (the
`public.*` native type), `getQueryCapabilities()`, and `build()`
(`cast_as` + `indexes`) off the instance. The codec id is
`cipherstash/eql-v3/${bareDomain}@1` where `bareDomain` is the registry
key VERBATIM (only the `public.` qualifier is stripped) — a mechanical
bijection, never a prettified transform. It exports:

- `V3_DOMAIN_META_BY_CODEC_ID` — the per-domain metadata map (all 40
  domains, including the authoring-unexposed `*_ord_ore` variants the
  codec layer still decodes);
- `EXPOSED_DOMAIN_ENTRIES` — the catalog minus `*_ord_ore` (the domains
  that get an authoring constructor);
- `V3_FACTORY_BY_NATIVE_TYPE` / `toV3CodecId` — the `(codec id) ⟺
  (public.* domain)` bijection used by schema derivation;
- `envelopeTypeNameForCastAs` — maps a domain's `cast_as` to the envelope
  class name that decodes it (numeric family → `EncryptedNumber`, bigint
  → `EncryptedBigInt`, text → `EncryptedString`, …).

Because everything derives from this, **adding or changing a domain
almost never touches this package** — it flows from a `@cipherstash/stack`
registry change plus a rebuild. Drift is caught by the 1:1 runtime tests
(`test/v3/catalog.test.ts`, `test/column-types.test.ts`,
`test/authoring.test.ts`, `test/v3/constants-v3.test.ts`).

### Authoring: the constructor IS the capability set

Each exposed domain gets exactly one **argument-less** constructor:

- PSL: `cipherstash.TextSearch()` (in `src/contract-authoring.ts`);
- TS: `textSearch()` (in `src/exports/column-types.ts`).

The name is the mechanical PascalCase/camelCase transform of the bare
domain with its `eql_v3_` prefix stripped (`eql_v3_bigint_ord` →
`BigIntOrd` / `bigIntOrd`); the codec id keeps the registry key verbatim.
There are NO options — the constructor you pick *is* the capability set
(`textSearch` vs `text`, `bigIntOrd` vs `bigIntEq`, …). Both forms lower
to an identical `ColumnTypeDescriptor` with a static
`{ castAs, capabilities }` typeParams block, so PSL- and TS-authored
contracts emit byte-identical `contract.json` (pinned by the parity
tests).

## Substrate architecture

### `EncryptedEnvelopeBase<T>` — shared envelope superclass

`src/execution/envelope-base.ts` exports an abstract
`EncryptedEnvelopeBase<T>` that holds the `#`-prefixed
`EncryptedHandle<T>` slot and ships the five redaction overrides
(`toJSON`, `toString`, `valueOf`, `Symbol.toPrimitive`,
`Symbol.for('nodejs.util.inspect.custom')`), `expose()`,
`decrypt({ signal? })`, and the post-decrypt plaintext cache.

The concrete value classes are **version-neutral** — they are the
user-facing input/output types for encrypted columns regardless of the
domain:

- `EncryptedString`, `EncryptedBigInt`, `EncryptedBoolean`,
  `EncryptedDate`, `EncryptedJson` (in `src/execution/envelope-*.ts`);
- `EncryptedNumber` (in `src/v3/envelope-number.ts`) — the numeric
  family: every `number`-castAs v3 domain (integer / smallint / numeric /
  real / double) decodes to `EncryptedNumber`.

Each concrete subclass holds nothing of its own beyond a static
`from(plaintext): Self` and `fromInternal(args): Self`, and may override
`parseDecryptedValue(plaintext: unknown): T` when the SDK round-trips
through a JS type that differs from the envelope's `T` (`EncryptedBigInt`
coerces `number | string → bigint`; `EncryptedDate` coerces ISO strings →
`Date`). The base stamps a per-subclass redacted JSON placeholder
(`{ "$encryptedString": "<opaque>" }` vs `{ "$encryptedNumber": "<opaque>" }`)
so accidental `JSON.stringify` reveals the *type* but not the *value*.

### v3 codec runtime — `createV3CodecDescriptors(sdk)`

`src/v3/codec-runtime-v3.ts` builds one
`RuntimeParameterizedCodecDescriptor` per catalog domain (derived from
`V3_DOMAIN_META_BY_CODEC_ID`, never hand-listed), with three properties
that define the v3 wire:

- **Wire**: plain JSONB (`src/v3/wire-v3.ts` — `v3ToDriver` /
  `v3FromDriver`). v3 columns are Postgres domains over `jsonb`; the
  encoded param slot is the serialised EQL payload, not a composite-text
  literal.
- **Native type**: each descriptor targets its concrete `public.eql_v3_*`
  domain.
- **Traits**: derived per-domain from the catalog's query capabilities
  via `v3TraitsForCapabilities` — intrinsic to the domain, not a
  per-column option.

The params shape matches the static `{ castAs, capabilities }` block v3
authoring emits. `encode` reads the ciphertext off the handle; `decode`
constructs the per-`castAs` envelope via `envelopeTypeNameForCastAs`.

### v3 control-plane hooks — `cipherstashV3CodecControlHooks`

`src/migration/cipherstash-codec-v3.ts` registers an identity
`expandNativeType` hook (which strips the `public.` qualifier so DDL and
introspection agree on the bare domain name) and **no `onFieldEvent`**.
The Postgres planner requires an `expandNativeType` hook to *exist* for
any column carrying `typeParams` (and every v3 column carries the static
`{ castAs, capabilities }` block); the absence of `onFieldEvent` is what
guarantees v3 columns emit **no** `add_search_config` /
`remove_search_config` ops — v3 domains carry their own index metadata.

## The operator surface — the `eql*` vocabulary

The v3 query operators use an EQL-derived vocabulary and live in
`src/v3/operators-v3.ts`, registered through the framework's
`OperationRegistry` via `cipherstashV3QueryOperations()`.

### Predicate operators — column-method surface

Return `Expression<pg/bool@1>` and surface as column methods:
`eqlEq` / `eqlNeq` / `eqlIn` / `eqlNotIn` / `eqlGt` / `eqlGte` / `eqlLt` /
`eqlLte` / `eqlBetween` / `eqlNotBetween`, the fuzzy free-text
`eqlMatch` (`eql_v3.contains` — NOT SQL `ILIKE`; may false-positive, so
there is deliberately no negated form), and the JSONB `eqlJsonContains`
(`@>` containment on `eql_v3_json`).

Type-level visibility is trait-dispatched: each operator's `self`
declares a `cipherstash:v3-*` marker (`src/types/operation-types.ts`),
and each v3 codec entry (`src/types/codec-types.ts`) carries the markers
its capability tier permits. Storage-only domains (e.g. `eql_v3_boolean`,
bare `eql_v3_text`) carry no markers, so they surface no operators —
matching the runtime gate. The markers are TYPE-LEVEL only (no runtime
counterpart).

### Free-standing helpers — non-predicate surface

`eqlAsc` / `eqlDesc` return `OrderByItem` for ORDER BY (via
`eql_v3.ord_term` / `eql_v3.ord_term_ore` by the column's ordering
flavour). They are pure functions with no registry participation.

### The query-term seam (`src/v3/query-term.ts`)

A three-module contract that keeps query-term encryption ciphertext-free
without importing the operator registry into the middleware/SDK:

1. **`operators-v3` MARKS** — each predicate wraps its operand in a
   per-`castAs` envelope, stamps the query flavour it needs
   (`markV3QueryTerm`), and binds the envelope as a `pg/text@1` param (so
   it carries no v3 codec id and stays out of the storage jurisdiction).
2. **`bulk-encrypt-v3` COLLECTS** — the middleware recognises marked
   envelopes among the plan params and forwards the envelope itself
   through `CipherstashSdk.bulkEncrypt` so the mark survives the SDK
   boundary.
3. **`sdk-adapter-v3` ROUTES** — the SDK adapter reads the mark
   (`v3QueryTermTypeOf`) and encrypts marked envelopes via the stack
   client's `encryptQuery({ queryType })` (a ciphertext-free term),
   never the storage `bulkEncrypt` path. The resulting term is written
   back as JSONB and is NOT stamped onto the envelope's ciphertext slot
   (a query term is not the cell's storage ciphertext).

## Write-path lifecycle — two-pass codec encode + middleware rewrite

The SQL family runtime calls `encode` (in `lower`/`encodeParams`)
**before** the `beforeExecute` middleware chain, so the codec cannot read
`handle.ciphertext` during `encode` on the write path — the envelope only
carries plaintext at that point. The package handles this as a deliberate
two-pass design:

1. **First pass — `CipherstashV3CellCodec#encode`.** With
   `handle.ciphertext === undefined` the codec returns the envelope
   itself as the pre-encrypt sentinel (a bare string or `null`/`undefined`
   passes straight through); the second-pass middleware fills in the
   ciphertext. That sentinel is only legitimate if a second pass is
   actually coming, so `encode` first consults the per-SDK
   `middleware-registry` WeakSet that `bulkEncryptMiddlewareV3(sdk)`
   marks its SDK in. An unregistered SDK means the two-pass flow can
   never complete, so the codec raises `RUNTIME.ENCODE_FAILED` with a
   copy-pasteable wiring snippet rather than letting the envelope reach
   the pg driver as an opaque serialise error. The check is memoised per
   codec (the registry is add-only), so it costs one WeakSet lookup, not
   one per cell.
2. **Second pass — `bulkEncryptMiddlewareV3#beforeExecute`.** Walks the
   lowered AST to stamp `(table, column)` routing keys
   (`stampRoutingKeysFromAst`, version-neutral, shared from
   `src/execution/routing.ts`), collects every v3-codec'd envelope and
   every marked query term, groups by `(table, column)`, issues one
   `sdk.bulkEncrypt(...)` per group, and calls `params.replaceValues(...)`
   with the plain-JSONB wire text. Storage envelopes get their ciphertext
   slot stamped (plaintext retained) for follow-on reuse; query terms do
   not.

The read path degenerates to a single pass — when `handle.ciphertext` is
already set (just decoded from a `SELECT`, or carried across queries),
`encode` returns the wire format directly.

Tests pin both halves and the jurisdiction split:
`test/v3/bulk-encrypt-v3.test.ts` covers the wire-format `replaceValues`
payload, the one-call-per-`(table,column)` grouping, and that non-v3
params are invisible to the middleware.

## Wiring it together — the setup entry

`cipherstashFromStack({ contractJson })` (`src/stack/from-stack-v3.ts`) is
the one-call factory: it derives the v3 encryption schemas from the
contract (`deriveStackSchemasV3` — one `public.eql_v3_*` domain per
column, selected by `nativeType` via `V3_FACTORY_BY_NATIVE_TYPE`),
constructs the `@cipherstash/stack` `EncryptionV3` client, adapts it to
`CipherstashSdk` (`src/v3/sdk-adapter-v3.ts`), and returns ready-to-spread
`extensions` / `middleware` for `postgres<Contract>({...})`. It rejects a
contract carrying non-v3 cipherstash codec ids — the package is v3 only.

The runtime extension descriptor
(`createCipherstashV3RuntimeDescriptor({ sdk })`,
`src/v3/runtime-v3.ts`) presents the **pack id** (`CIPHERSTASH_SPACE_ID` =
`'cipherstash'`) so `postgres<Contract>({ extensions })` accepts contracts
emitted by the cipherstash control descriptor, with v3's own version
(`CIPHERSTASH_V3_EXTENSION_VERSION`).

## Runtime-side gotchas

### Physical column-name routing keys

The framework lowers PSL field names through `@map(...)` before
middleware sees `ParamRef`s, so the bulk-encrypt middleware and the SDK
adapter both key on **physical** column names (e.g. `accountid`, not the
PSL `accountId`). The SDK adapter's `(table, column)` registry is keyed by
physical name (`getName()`) to match.

### `bigint` SDK boundary

`@cipherstash/stack`'s SDK and ZeroKMS accept
`JsPlaintext = string | number | boolean | object | array` (no `bigint`).
`EncryptedBigInt` handles this: the encrypt side coerces `bigint → Number`
with a `Number.MAX_SAFE_INTEGER` bounds check; the decrypt side's
`parseDecryptedValue` accepts `number | string` and coerces back via
`BigInt(...)`. Values beyond the safe-integer range cannot be encrypted
today — a known limitation requiring upstream SDK / ZeroKMS work.

## The migration is an invariant-only genesis edge

`migrations/20260601T0100_install_eql_v3_bundle/` is the **sole**
migration and the contract space's root: `describe()` returns
`{ from: null, to: <empty-storage hash> }`. The v3 bundle creates the
`public.eql_v3_*` domains, the `eql_v3.*` operator functions, the
`eql_v3.query_*` operand domains, and the `eql_v3_internal` helper schema
— but **no contract-space storage** (no config table), so the contract
models no tables and the storage hash is the empty-storage hash.

The op is `operationClass: 'data'` (not `additive`): a genesis edge that
moves no contract storage must carry a `data`-class op or the aggregate
integrity checker rejects it. The install SQL is **not baked** into
`ops.json` — the committed op carries `RUNTIME_EQL_SQL_SENTINEL`, and
`control.ts` injects `readInstallSql()` from the installed
`@cipherstash/eql` at descriptor-build time and recomputes the
content-addressed migration hash (`src/migration/eql-bundle-v3.ts`), so
bumping the pinned EQL version needs a dependency bump and rebuild, not a
migration re-emit.

Authoring loop: `migration.ts` is hand-edited; re-emit `ops.json` /
`migration.json` after edits via
`pnpm exec tsx migrations/20260601T0100_install_eql_v3_bundle/migration.ts`.
The contract-space artefacts (`src/contract.{json,d.ts}`) are re-emitted
via `pnpm exec prisma-next contract emit`; `refs/head.json` is hand-pinned
to the head migration's `to` hash and its invariant.

## Other design choices worth knowing

### Handle storage — `#` field with redacting overrides

Every envelope holds its `EncryptedHandle<T>` on a single `#`-prefixed
field. Plaintext/ciphertext are reachable only through an explicit
`envelope.expose()`; every implicit serialization path is redacted. The
encapsulation is deliberately not airtight — the goal is to make plaintext
access **explicit** at the call site, not **impossible**.

### Plaintext is retained post-encrypt

The bulk-encrypt middleware populates the handle's ciphertext slot but
does not zero the plaintext slot (zeroing JS strings is best-effort;
GC-driven lifecycle is sufficient). As a side effect a write-side
envelope's `decrypt()` returns the original plaintext synchronously
without an SDK round-trip.

### `CipherstashSdk` is framework-native

The interface declares three async methods (`decrypt`, `bulkEncrypt`,
`bulkDecrypt`), each accepting an optional `AbortSignal`, with
polymorphic (`unknown`) value types. It is deliberately smaller than the
upstream `EncryptionV3` client, so real usage wraps that client behind a
thin adapter (`src/v3/sdk-adapter-v3.ts`) and the framework-side surface
stays free of upstream-specific types.

### `decryptAll(rows, opts?)` — opt-in read-side amortisation

`decode` returns envelopes that defer their SDK round-trip until
`.decrypt()` is awaited, keeping SELECT plans cheap. `decryptAll(rows)`
(`src/execution/decrypt-all.ts`) is the read-side amortisation: it walks
the result graph (arrays, objects, nested envelopes; cycle-safe; skips
already-decrypted; passes over exotic containers like `Date` / `Map` /
`Set`), partitions discovered envelopes by `(sdk, table, column)`, and
issues one `bulkDecrypt` per partition. Resolved plaintexts pass through
each envelope's `parseDecryptedValue` and cache back onto the handle.
Version-neutral — it works on any `EncryptedEnvelopeBase` subclass.

### Cipherstash-namespaced traits

The extension uses `cipherstash:`-prefixed traits exclusively — the
runtime capability traits (`cipherstash:equality`,
`cipherstash:order-and-range`, `cipherstash:free-text-search`,
`cipherstash:searchable-json`) in `src/extension-metadata/constants.ts`,
and the TYPE-LEVEL `cipherstash:v3-*` dispatch markers in
`src/types/*`. These sit *outside* the framework's closed `CodecTrait`
union deliberately: a cipherstash codec advertising the framework's
`equality` trait would make the built-in `m.col.eq(...)` synthesise on
encrypted columns and lower to SQL `=` against a nondeterministic
ciphertext — the wrong-SQL footgun this namespace closes. The single
cast from the extension namespace into the framework union is localised
and carries a rationale comment; `test/equality-trait-removal.test.ts`
pins that no v3 codec descriptor ever advertises a framework built-in
trait.

### Control vs runtime tree-shaking

The package composes tree-shakably along a control/runtime seam:
`./control` (contract-space authoring + the v3 codec lifecycle hook) must
not drag in the runtime envelopes, the SDK, the codec runtime, or the
bulk-encrypt middleware; `./runtime` / `./v3` must not drag in the EQL
install SQL, the baseline migration, or the codec-control hook. The split
lives in the source-import discipline and is pinned byte-level by
`test/bundling-isolation.test.ts` (entry-body forbidden-substring check +
chunk-graph disjointness, modulo pure constants / catalog metadata
chunks).

## Tracked follow-ups

- **`bigint` beyond `Number.MAX_SAFE_INTEGER`.** The `bigint → Number`
  coercion at the SDK boundary caps encryptable magnitude; lifting it
  requires upstream SDK / ZeroKMS support for a `bigint` plaintext.
- **JSON selector querying.** `eqlJsonContains` covers `@>` containment on
  `eql_v3_json`; comparing the value at a specific JSONPath selector is a
  separate capability (tracked in GitHub issue #677).

## Behavioural invariants pinned by tests

The following user-facing behaviours are pinned by on-disk tests. This
section is the canonical statement of what the package guarantees; if you
find yourself loosening one, that's the signal to add a regression test
alongside.

### Contract space & migration

- The descriptor exposes a contract space that models **no storage**, one
  migration (the v3 baseline), an invariant-only genesis edge
  (`from: null`), and a head ref requiring only
  `cipherstash:install-eql-v3-bundle-v1`. Self-consistency
  (`headRef.hash === contract.storageHash`) holds. Pinned by
  `test/descriptor.test.ts` and `test/v3/migration-v3.test.ts`.
- The v3 baseline op carries the runtime sentinel (not baked SQL); the
  descriptor injects `readInstallSql()` and the injected package survives
  the canonical disk writer + integrity-checking reader round-trip.

### Catalog & authoring

- Every exposed domain has exactly one argument-less constructor (PSL and
  TS) whose descriptor equals the catalog values; the exposed set is
  exactly the derived v3 names (no `*OrdOre`, no unqualified `String`).
  TS and PSL authoring emit byte-identical `contract.json`. Pinned by
  `test/authoring.test.ts`, `test/column-types.test.ts`,
  `test/psl-interpretation.test.ts`, `test/v3/properties.test.ts`.
- The pinned v3 codec-id tuple equals the registry-derived set, and the
  `isCipherstashV3CodecId` guard narrows only `eql_v3_*`-prefixed ids
  (`test/v3/constants-v3.test.ts`, `test/v3/catalog.test.ts`).

### Codec runtime & operators

- One v3 codec descriptor per catalog domain, each targeting its concrete
  `public.eql_v3_*` native type, wired to the plain-JSONB wire — never a
  composite literal. `decode` builds the right envelope via
  `envelopeTypeNameForCastAs`. No v3 descriptor advertises a framework
  built-in trait (`test/equality-trait-removal.test.ts`,
  `test/v3/runtime-v3.test.ts`).
- The `eql*` operators lower to the corresponding `eql_v3.*` functions and
  surface only on the domains whose capability tier permits them; the
  type-level marker dispatch agrees with the runtime gate. Pinned by
  `test/v3/operator-lowering-v3-*.test.ts`,
  `test/v3/operator-gating-v3.test.ts`, and the type tests
  `test/operation-types.types.test-d.ts`.

### Envelopes, bulk-encrypt & decryptAll

- Every envelope ships the redaction overrides + `expose()` +
  `decrypt({ signal? })` + `parseDecryptedValue`; `Object.keys(envelope)`
  is empty and `JSON.stringify` yields the documented `$encrypted<Type>`
  placeholder (`test/envelope-*.test.ts`, `test/v3/envelope-number.test.ts`).
- `bulkEncryptMiddlewareV3` issues one `bulkEncrypt` per `(table, column)`
  group, writes plain-JSONB wire text, retains plaintext, and ignores
  non-v3 params; `ctx.signal` is forwarded by identity
  (`test/v3/bulk-encrypt-v3.test.ts`).
- `decryptAll` walks recursively, decrypts one `bulkDecrypt` per
  `(sdk, table, column)` group, caches back onto each handle, and forwards
  `opts.signal` (`test/decrypt-all.test.ts`).

### Cancellation

- `RUNTIME.ABORTED` envelope wrapping at every cipherstash-internal async
  phase (`bulk-encrypt`, `decrypt`, `decrypt-all`), reusing the framework
  envelope shape with cipherstash-specific `details.phase` strings
  (`test/abort.test.ts`; the bulk-encrypt phase in
  `test/v3/bulk-encrypt-v3.test.ts`).

### Layering & bundling

- `pnpm lint:deps` clean; strict `dbInit` preserved. Tree-shakable
  control vs runtime planes pinned byte-level by
  `test/bundling-isolation.test.ts`.

## References

- [Prisma Next encryption docs](https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next) — user-facing reference for the extension.
- [`@cipherstash/stack`](../stack/README.md) — encryption SDK and schema DSL this package adapts.
- [CipherStash EQL](https://github.com/cipherstash/encrypt-query-language) — the SQL the baseline migration installs.
