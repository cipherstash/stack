# EQL v3 Prisma-next Implementation Plan (design A — per-domain constructors)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `@cipherstash/prisma-next` author EQL v3 columns through **concrete per-domain constructors** that map 1:1 to the `public.*` Postgres domains, each carrying a static codec id + concrete `public.*` native type + `{ castAs, capabilities }` typeParams — no boolean-option surface, no runtime domain-resolution stage — wired end-to-end through a self-contained `src/v3/` namespace, with legacy `*V2` aliases preserved.

**Architecture:** v3 is a **parallel, self-contained namespace** — never v3 branches grafted onto v2 code. Capability is encoded by constructor identity: the constructor you choose *is* the capability set, and it emits its concrete descriptor statically (`(codec id) ⟺ (public.* domain) ⟺ capabilities` is bijective — nothing is resolved). The **domains / native types live in `public`** (`public.text_eq`, `public.integer_ord`, `public.boolean`, `public.bigint_ord`); the **operator functions live in `eql_v3`** (`eql_v3.eq`, `eql_v3.gt`, `eql_v3.contains`, `eql_v3.ord_term`). These two schemas must never be conflated. The constructor set, codec ids, capabilities, cast kinds, and native types are all **derived from the imported `DOMAIN_REGISTRY`** in `@cipherstash/stack/eql/v3` — there is no hand-maintained local table. Concrete per-domain types are threaded end-to-end (literal `codecId` / `nativeType` / `capabilities`; see Task 3's `V3ColumnDescriptor<C>` and the `.test-d.ts`). **v2 and v3 are separate entry points** (decision 1b): v3 is its own extension factory with its own distinct extension id, keeping the same `cipherstash*` method names, and is **never co-registered** with v2 in one client (the flat `OperationRegistry` disallows the duplicate-method override). A client is v2 or v3; mixed v2+v3 columns in one client are unsupported this release.

**Tech Stack:** TypeScript, `@cipherstash/stack` (`/eql/v3` catalog + a v3 `EncryptionV3` client), `@cipherstash/eql@3.0.0-alpha.3` (`/sql` → `readInstallSql` / `releaseManifest`), `@prisma-next/*` framework **pinned at 0.14.0** (see the "Prisma Next 0.14 ground truth" notes below — this plan was originally drafted against 0.8.0 and has been re-aligned), `arktype`, `vitest` (`vitest run`), `fast-check ^4.8.0` (added here), `biome` (lint), `tsup` (build), `postgres` (live tests).

## Global Constraints

- **Schema split (hard — the #1 thing to get right).** Two Postgres schemas are in play and must not be conflated:
  - **Domains / native types → `public`.** `public.text_eq`, `public.integer_ord`, `public.boolean`, `public.bigint_ord`, … A column's `getEqlType()` returns this `public.*` string; it is the column's `nativeType`. The stack type pins it as `` `public.${string}` ``.
  - **Operator functions → `eql_v3`.** `eql_v3.eq(...)`, `eql_v3.gt(...)`, `eql_v3.contains(...)`, `eql_v3.ord_term(...)`. This is the SQL the operators lower to. Do NOT "correct" these to `public.*`.
- **Namespace separation (hard).** All v3 implementation lives under `packages/prisma-next/src/v3/` plus `packages/prisma-next/src/extension-metadata/constants-v3.ts`. v3 modules MUST NOT import v2 codec/wire (`encodeEqlV2EncryptedWire`), the v2 bulk-encrypt middleware, the v2 codec-runtime, or the v2 SDK adapter. The only permitted shared primitives are the version-neutral value-envelope classes (`EncryptedEnvelopeBase`, `EncryptedString`, `EncryptedDate`, `EncryptedBoolean`, `EncryptedBigInt`) + the routing-key stamping utilities and framework authoring/trait infrastructure. No v2 module gains an `if (isV3)` wire-format branch.
- **Source of truth = the imported `DOMAIN_REGISTRY`.** Derive domain names, `castAs`, capabilities, indexes, native types, and codec ids from `@cipherstash/stack/eql/v3` by iterating `DOMAIN_REGISTRY` (keys are bare domain names → factory). Do NOT hand-maintain a local domain table. The stack v3 layer defines NO codec-id strings; `codecId` is purely a prisma-next concept.
- **Codec id scheme.** Concrete per-domain id = `` `cipherstash/eql-v3/${bareDomain}@1` `` where `bareDomain` is the domain with the `public.` prefix stripped (e.g. `public.text_search` → `cipherstash/eql-v3/text_search@1`). Strip `public.` (never `eql_v3.`). The `eql-v3` token is a logical version tag, not a schema.
- **castAs set.** `'string' | 'number' | 'bigint' | 'boolean' | 'date' | 'timestamp'`. `bigint` domains (`public.bigint*`) carry JS `bigint` plaintext.
- **No id reuse.** v3 ids MUST NOT reuse v2 ids (`cipherstash/string@1`, …). The v3 and v2 id sets MUST be disjoint (pinned by a test).
- **Legacy aliases.** `*V2` constructors keep the existing v2 codec ids and `eql_v2_encrypted` native type — unchanged behavior. The v2 constructors that used unqualified names (`EncryptedString`, `EncryptedDouble`, `EncryptedBigInt`, `EncryptedDate`, `EncryptedBoolean`, `EncryptedJson`) are renamed to their `*V2` forms; the unqualified names are taken over by the v3 surface (except `EncryptedString`/`EncryptedJson`, which have no v3 constructor — text v3 uses `EncryptedText*`, and JSON has no v3 domain).
- **Contract representation.** Each v3 column carries `codecId` (concrete per-domain id), `nativeType` (concrete `public.*` domain), `typeParams: { castAs, capabilities }`. There is NO redundant `eqlType` field — `nativeType` is the single source.
- **`*_ord_ore` not exposed.** The registry defines `*_ord_ore` domains; prisma-next surfaces only the `_ord` order domains. `_ord_ore` gets no constructor. (The catalog META/codec-id set may still include them so runtime decode/derivation is robust; only the *authoring constructor set* excludes them.)
- **No searchable JSON v3 domain, no `EncryptedJson` v3 constructor.** BigInt IS a first-class v3 family (`public.bigint` / `bigint_eq` / `bigint_ord`).
- **Wire format.** v3 columns are PG domains over `jsonb`; encode = `JSON.stringify`, decode = `JSON.parse` (object passthrough). Never the v2 composite literal.
- **Operators.** v3 lowers to the two-arg `eql_v3.*(...::jsonb)` functions, byte-for-byte matching the canonical Drizzle branch. No built-in framework equality traits; CipherStash operators stay in the `cipherstash:*` trait namespace.
- **Migrations.** v3 install SQL is sourced from `@cipherstash/eql/sql` (`readInstallSql()` / `releaseManifest.eqlVersion`, `@cipherstash/eql@3.0.0-alpha.3`), NOT a hand-vendored FFI fixture. Invariant `cipherstash:install-eql-v3-bundle-v1`; directory `20260601T0100_install_eql_v3_bundle` (sorts after the v2 `20260601T0000_install_eql_bundle`). v3 columns emit NO `add_search_config` / `remove_search_config`.
- **Commands.** Test: `pnpm --filter @cipherstash/prisma-next test`. Build: `pnpm --filter @cipherstash/prisma-next build`. Lint: `pnpm --filter @cipherstash/prisma-next lint`. If a task touches `@cipherstash/stack` public exports, also run `pnpm --filter @cipherstash/stack test`. Every task ends green on `test`.

## Ground-truth notes (verified against the worktree `.worktrees/feat/eql-v3-supabase-adapter`)

1. **`DOMAIN_REGISTRY` / `factoryForDomain` / `stripDomainSchema` are NOT yet re-exported** from the `@cipherstash/stack/eql/v3` barrel (`packages/stack/src/eql/v3/index.ts`); they live in `domain-registry.ts` as internal. Task 1 Step 1 adds them to the barrel (touches stack public exports → run stack tests).
2. **`EncryptedBigInt`, `EncryptedString`, `EncryptedDate`, `EncryptedBoolean`, `EncryptedDouble` value envelopes already exist** in `packages/prisma-next/src/execution/envelope-*.ts` (each with its own `typeName`). **`EncryptedNumber` does NOT exist and must be created** (a sibling of `EncryptedDouble`). `EncryptedBigInt` is REUSED (not recreated) and surfaced through the v3 barrel.
3. **`stampRoutingKeysFromAst` is module-private** in `src/middleware/bulk-encrypt.ts`. Task 5 exports it (a version-neutral primitive).
4. **`CipherstashSdk`** (`src/execution/sdk.ts`): `decrypt(args) => Promise<string>`, `bulkEncrypt({ routingKey, values, signal? }) => Promise<ReadonlyArray<unknown>>`, `bulkDecrypt({ routingKey, ciphertexts, signal? }) => Promise<ReadonlyArray<unknown>>`; `CipherstashRoutingKey { readonly table: string; readonly column: string }`.
5. **`encryptedTable(name, columns)`** (stack `eql/v3/table.ts`) returns `EncryptedTable<T> & T`; instance members: `tableName`, `columnBuilders`, `build() => { tableName, columns }`, `buildColumnKeyMap()`. `AnyV3Table = EncryptedTable<EncryptedV3TableColumn>`.
6. **`@cipherstash/eql/sql`** exports `readInstallSql(): string` and `releaseManifest` (`.eqlVersion`). `installEqlV3IfNeeded(sql)` lives in `packages/stack/__tests__/helpers/eql-v3.ts` (advisory lock `3_733_003`; staleness via `eql_v3.version()`).
7. **The Drizzle reference operator/gating shapes** live on branch `eql-v3-drizzle-concrete-types` (not the working tree). Their shapes are reproduced inline in the relevant tasks. Operator SQL is proven live in `packages/stack/__tests__/v3-matrix/matrix-live-pg.test.ts` and `schema-v3-pg.test.ts`.
8. **Operator method names + the flat registry (resolved: decision 1b).** The framework `OperationRegistry` is a flat, method-name-keyed map that disallows override, so two descriptors both defining `cipherstashEq` collide at registration regardless of extension id. Resolution: v2 and v3 are **separate entry points** — v3 registers its own extension descriptor (its own distinct `id`/`version`, same `cipherstash*` method names) and is **never co-registered** with the v2 descriptor. There is no single-shared-gated-descriptor and no in-one-client mixing. This is not a fallback; it is the design.

## Prisma Next 0.14 ground truth (re-alignment, 2026-07-09)

This plan was drafted while `packages/prisma-next` pinned `@prisma-next/*` at **0.8.0**. The package has since been upgraded to **0.14.0** (branch `chore/prisma-next-0.14-upgrade`, one commit per minor). Everything below is verified against that branch and **overrides** any 0.8-era shape the original draft assumed. Tasks whose steps this affects carry an inline `> **0.14:**` note.

1. **Contract JSON shape (affects every contract fixture and every contract walker).** `contract.json` is namespace-enveloped at both planes:
   - Storage: `storage.namespaces.<ns>.entries.table.<tableName>` (the `entries.<kind>` envelope landed in 0.13). There is **no** flat `storage.tables` — the structural validator rejects it.
   - Domain: `domain.namespaces.<ns>.models` replaces flat `models`; `roots` entries are `{ model, namespace }` objects.
   - The Postgres default namespace is **`public`** (`kind: 'postgres-schema'`) since 0.12; the emitted extension contract carries the sole namespace `public` (0.14 dropped the spurious empty `__unbound__` slot, TML-2916).
   - Reference implementation: the v2 `deriveStackSchemas` (`src/stack/derive-schemas.ts`) already walks `storage.namespaces.<ns>.tables`-era → 0.14 `entries`-shaped views on the branch; `deriveStackSchemasV3` must walk the same envelope (Task 7 has been updated accordingly).
2. **Handcrafted contract fixtures** (`test/operator-lowering.helpers.ts`, `test/helpers.test.ts`) are validated with `validateSqlContractFully<PostgresContract>(value)` — single argument, imported from `@prisma-next/sql-contract/validators` (`@prisma-next/sql-contract/validate` and the two-arg `validateContract` are gone). Fixtures carry `storage.namespaces.__unbound__ = { id, entries: { table: {...} } }` and `domain: { namespaces: { __unbound__: { models: {} } } }`. Mirror this shape for `contractV3` (Task 6).
3. **Lowered params are structured.** `adapter.lower(...)` emits `LoweredParam` entries (`{ kind: 'literal', value } | { kind: 'bind', name }`), not raw values. The v2 helpers export `literalParamValue(param)` for unwrapping — reuse it in v3 lowering tests that assert on `lowered.params`.
4. **PSL interpreter harness.** `interpretPslDocumentToSqlContract` requires the target ref to carry `defaultNamespaceId` (`'public'`) and requires `composedExtensionContracts: ReadonlyMap<spaceId, Contract>` (the composed cipherstash contract must be in the map or interpretation fails with `PSL_UNKNOWN_CONTRACT_SPACE`). Interpreted tables land under the `public` namespace at `storage.namespaces.public.entries.table`. The `psl-interpretation*.test.ts` harnesses (`interpret()`, `asStorage()`) are already 0.14-shaped on the branch — new v3 cases extend them, don't fork them.
5. **Contract-space emit / re-pin loop (Task 8's backbone).** The self-emit (`pnpm exec tsx migrations/<dir>/migration.ts`) writes **only** `ops.json` + `migration.json`. It does not write `end-contract.json`, does not print a contract hash, and does not touch `migrations/refs/head.json`. The full maintainer loop, exercised four times on the upgrade branch, is:
   1. `pnpm exec prisma-next contract emit` (from `packages/prisma-next/`) → rewrites `src/contract.{json,d.ts}`; the new hash is `src/contract.json` → `storage.storageHash`.
   2. Copy `src/contract.json` → `migrations/<dir>/end-contract.json` and `src/contract.d.ts` → `migrations/<dir>/end-contract.d.ts`.
   3. Hand-edit the migration's `describe()` hash literal(s).
   4. Self-emit: `pnpm exec tsx migrations/<dir>/migration.ts` → regenerates `ops.json` + `migration.json` (0.12+ manifests carry no `labels`/`hints` and no inlined `fromContract`/`toContract`).
   5. Hand-edit `migrations/refs/head.json` (`{ hash, invariants }`).
   - Current head after the 0.14 upgrade: `hash: sha256:1e86a0160ba305fa74516b6d9449218308b258a51a913c1fc907e629f44568a7`, `invariants: ["cipherstash:install-eql-bundle-v1"]`. The v2 baseline's `describe()` is `{ from: null, to: <that hash> }`.
6. **Descriptor self-consistency requires the family canonicalization hooks.** `assertDescriptorSelfConsistency` must be passed `sqlContractCanonicalizationHooks.shouldPreserveEmpty` / `.sortStorage` (from `@prisma-next/sql-contract/canonicalization-hooks`) or the recomputed hash will not match the emitted one. `test/descriptor.test.ts` already does this on the branch; Task 8's "descriptor test passes with the second migration wired" step inherits it.
7. **Codec control hooks carry a namespace coordinate.** `FieldEventContext` has a required `namespaceId` (plus optional `priorTable`/`newTable`), and `planFieldEventOperations` walks `storage.namespaces.<ns>` — relevant only to v2 hooks (v3 registers none), but any new test that invokes a hook directly must pass `namespaceId`.
8. **Plan ops can lower lazily.** `OpFactoryCall.toOp()` may return a `Promise<MigrationPlanOperation>`; tests await `Promise.all(ops.map((c) => c.toOp()))` (see `test/cipherstash-codec.test.ts` on the branch).
9. **Middleware context requires `planExecutionId`.** `SqlMiddlewareContext` (via `RuntimeMiddlewareContext`) has a required `planExecutionId: string`; the v2 test `createCtx()` fixtures already stamp one — the extracted shared helper (Task 5) inherits it.
10. **`createRuntime` is removed** from `@prisma-next/sql-runtime` (construct `new PostgresRuntimeImpl(...)` from `@prisma-next/postgres/runtime`), the bare migration op factories are methods on the `Migration` base class (`this.createTable({...})` etc.) — but **`rawSql` survives as a free function** in 0.14 and the v2 baseline still uses it; Task 8's migration module is unaffected. ORM access is namespace-qualified (`db.orm.public.User`) — relevant to any live-suite example code.

## File Structure

New / modified files, by responsibility:

```
packages/stack/
  src/eql/v3/index.ts               (MODIFY) re-export DOMAIN_REGISTRY, factoryForDomain, stripDomainSchema, V3ColumnFactory
packages/prisma-next/
  src/
    extension-metadata/
      constants-v3.ts               (NEW) v3 codec ids (derived closed union), traits map, invariants, migration name
    v3/
      catalog.ts                    (NEW) derive domain meta + codec ids + native-type→factory map from DOMAIN_REGISTRY
      envelope-number.ts            (NEW) EncryptedNumber envelope (sibling of EncryptedDouble)
      wire-v3.ts                    (NEW) v3ToDriver / v3FromDriver (plain JSONB)
      codec-runtime-v3.ts           (NEW) v3 cell codec (JSONB), per-domain factories, metadata
      bulk-encrypt-v3.ts            (NEW) bulkEncryptMiddlewareV3(sdk): JSONB payloads, neutral routing-key stamp
      operators-v3.ts               (NEW) cipherstashV3QueryOperations(), EncryptionOperatorError, capability gating
      derive-schemas-v3.ts          (NEW) deriveStackSchemasV3(contractJson) -> AnyV3Table[]
      sdk-adapter-v3.ts             (NEW) createCipherstashV3Sdk(EncryptionV3 client, v3 schemas)
      runtime-v3.ts                 (NEW) createCipherstashV3RuntimeDescriptor({ sdk })
      from-stack-v3-validate.ts     (NEW) assertV3SchemasAgree (exact domain identity)
      barrel.ts                     (NEW) v3 user-facing value types (reuse neutral classes + EncryptedNumber)
    contract-authoring.ts           (MODIFY) v3 concrete per-domain constructors (derived) + *V2 aliases
    exports/column-types.ts         (MODIFY) TS factories mirror the PSL constructors + *V2
    middleware/bulk-encrypt.ts      (MODIFY) export stampRoutingKeysFromAst as neutral util
    stack/from-stack.ts             (MODIFY) dispatch v2/v3, build Encryption + EncryptionV3 clients
    migration/
      eql-bundle-v3.ts              (NEW) re-export readInstallSql / releaseManifest from @cipherstash/eql/sql
    migrations/20260601T0100_install_eql_v3_bundle/
      migration.ts                  (NEW) rawSql install op, invariant cipherstash:install-eql-v3-bundle-v1
      migration.json / ops.json      (GENERATED by the migration.ts self-emit)
      end-contract.{json,d.ts}       (COPIED from src/contract.{json,d.ts} after `prisma-next contract emit`)
    exports/control.ts              (MODIFY) add the v3 baseline to the migrations array
    exports/runtime.ts              (MODIFY) export v3 runtime surface
    exports/stack.ts                (MODIFY) export v3 derivation/adapter
  test/
    v3/ (new suites — see tasks)
    live/helpers/live-gate.ts, eql-v3.ts (NEW) mirror stack live helpers
  package.json                      (MODIFY) add fast-check + @cipherstash/eql devDeps; ./v3 subpath exports
.changeset/eql-v3-prisma-next.md    (NEW)
```

---

### Task 1: Export `DOMAIN_REGISTRY` from stack + derive the v3 catalog (meta + codec ids)

Re-export the registry from the stack v3 barrel, then derive every v3 domain's `{ nativeType, bareDomain, castAs, capabilities, indexes }` and its concrete codec id by iterating `DOMAIN_REGISTRY`. This is the single runtime source of truth; every later task reads from it.

**Files:**
- Modify: `packages/stack/src/eql/v3/index.ts`
- Create: `packages/prisma-next/src/v3/catalog.ts`
- Test: `packages/prisma-next/test/v3/catalog.test.ts`

**Interfaces:**
- Consumes: `@cipherstash/stack/eql/v3` — after Step 1: `DOMAIN_REGISTRY` (`Record<bareDomain, (name: string) => AnyEncryptedV3Column>`), `stripDomainSchema(eqlType): string`, `type V3ColumnFactory`; already public: `type QueryCapabilities`, `type AnyEncryptedV3Column`, `type EqlTypeForColumn`. Each column exposes `getEqlType(): \`public.${string}\``, `getQueryCapabilities(): QueryCapabilities`, `build(): { cast_as: string; indexes: Record<string, unknown> }`.
- Produces:
  - `type V3CastAs = 'string' | 'number' | 'bigint' | 'boolean' | 'date' | 'timestamp'`
  - `interface V3DomainMeta { readonly nativeType: \`public.${string}\`; readonly bareDomain: string; readonly castAs: V3CastAs; readonly capabilities: QueryCapabilities; readonly indexes: Readonly<Record<string, unknown>> }`
  - `function toV3CodecId(bareDomain: string): string` → `` `cipherstash/eql-v3/${bareDomain}@1` ``
  - `const V3_DOMAIN_META_BY_CODEC_ID: ReadonlyMap<string, V3DomainMeta>` (all registry domains, keyed by concrete codec id)
  - `const V3_CODEC_IDS: readonly string[]`
  - `const V3_FACTORY_BY_NATIVE_TYPE: ReadonlyMap<string, (name: string) => AnyEncryptedV3Column>` (keyed by `public.*` native type)
  - `function isOrdOreDomain(bareDomain: string): boolean`
  - `const EXPOSED_DOMAIN_ENTRIES: ReadonlyArray<readonly [codecId: string, meta: V3DomainMeta]>` (registry minus `*_ord_ore`)
  - `function envelopeTypeNameForCastAs(castAs: V3CastAs): 'EncryptedString' | 'EncryptedNumber' | 'EncryptedBigInt' | 'EncryptedDate' | 'EncryptedBoolean'`

- [ ] **Step 1: Re-export the registry from the stack v3 barrel**

In `packages/stack/src/eql/v3/index.ts`, add:

```ts
export {
  DOMAIN_REGISTRY,
  factoryForDomain,
  stripDomainSchema,
  type V3ColumnFactory,
} from './domain-registry'
```

Run: `pnpm --filter @cipherstash/stack build && pnpm --filter @cipherstash/stack test`
Expected: PASS (pure additive export; no behavior change).

- [ ] **Step 2: Write the failing test**

Create `packages/prisma-next/test/v3/catalog.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import {
  EXPOSED_DOMAIN_ENTRIES,
  envelopeTypeNameForCastAs,
  isOrdOreDomain,
  toV3CodecId,
  V3_CODEC_IDS,
  V3_DOMAIN_META_BY_CODEC_ID,
  V3_FACTORY_BY_NATIVE_TYPE,
} from '../../src/v3/catalog'

describe('v3 catalog derivation', () => {
  it('derives a concrete codec id per domain by stripping the public. prefix', () => {
    expect(toV3CodecId('text_search')).toBe('cipherstash/eql-v3/text_search@1')
    expect(toV3CodecId('boolean')).toBe('cipherstash/eql-v3/boolean@1')
  })

  it('records the public.* native type (never eql_v3.*) for text_search with full caps', () => {
    const meta = V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/text_search@1')
    expect(meta?.nativeType).toBe('public.text_search')
    expect(meta?.nativeType.startsWith('public.')).toBe(true)
    expect(meta?.castAs).toBe('string')
    expect(meta?.capabilities).toEqual({ equality: true, orderAndRange: true, freeTextSearch: true })
    expect(Object.keys(meta?.indexes ?? {}).sort()).toEqual(['match', 'ore', 'unique'])
  })

  it('marks public.boolean as storage-only (no indexes, all capabilities false)', () => {
    const meta = V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/boolean@1')
    expect(meta?.nativeType).toBe('public.boolean')
    expect(meta?.castAs).toBe('boolean')
    expect(meta?.capabilities).toEqual({ equality: false, orderAndRange: false, freeTextSearch: false })
    expect(Object.keys(meta?.indexes ?? {})).toEqual([])
  })

  it('exposes bigint as a first-class family with bigint castAs', () => {
    expect(V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/bigint@1')?.castAs).toBe('bigint')
    expect(V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/bigint_ord@1')?.nativeType).toBe('public.bigint_ord')
  })

  it('derives timestamp castAs distinctly from date', () => {
    expect(V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/timestamp@1')?.castAs).toBe('timestamp')
    expect(V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/date@1')?.castAs).toBe('date')
  })

  it('maps native type back to its concrete factory', () => {
    const factory = V3_FACTORY_BY_NATIVE_TYPE.get('public.integer_ord')
    expect(factory).toBeDefined()
    expect(factory?.('score').getEqlType()).toBe('public.integer_ord')
  })

  it('maps castAs to the envelope type name (bigint distinct from number)', () => {
    expect(envelopeTypeNameForCastAs('string')).toBe('EncryptedString')
    expect(envelopeTypeNameForCastAs('number')).toBe('EncryptedNumber')
    expect(envelopeTypeNameForCastAs('bigint')).toBe('EncryptedBigInt')
    expect(envelopeTypeNameForCastAs('date')).toBe('EncryptedDate')
    expect(envelopeTypeNameForCastAs('timestamp')).toBe('EncryptedDate')
    expect(envelopeTypeNameForCastAs('boolean')).toBe('EncryptedBoolean')
  })

  it('includes *_ord_ore in the full meta but excludes it from the exposed entries', () => {
    expect(V3_DOMAIN_META_BY_CODEC_ID.has('cipherstash/eql-v3/integer_ord_ore@1')).toBe(true)
    expect(isOrdOreDomain('integer_ord_ore')).toBe(true)
    const exposedBare = new Set(EXPOSED_DOMAIN_ENTRIES.map(([, m]) => m.bareDomain))
    expect([...exposedBare].some((b) => b.endsWith('_ord_ore'))).toBe(false)
    expect(exposedBare.has('integer_ord')).toBe(true)
    expect(exposedBare.has('bigint')).toBe(true)
  })

  it('every codec id is v3-namespaced and unique', () => {
    expect(new Set(V3_CODEC_IDS).size).toBe(V3_CODEC_IDS.length)
    for (const id of V3_CODEC_IDS) expect(id.startsWith('cipherstash/eql-v3/')).toBe(true)
  })
})
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/catalog`
Expected: FAIL — `Cannot find module '../../src/v3/catalog'`.

- [ ] **Step 4: Write minimal implementation**

Create `packages/prisma-next/src/v3/catalog.ts`:

```ts
/**
 * v3 domain catalog — derived (never hand-maintained) from the imported
 * `DOMAIN_REGISTRY`. For each bare domain name we probe its factory and read
 * `getEqlType()` (the `public.*` native type), `getQueryCapabilities()`, and
 * `build()` (`cast_as` + `indexes`) off the instance. Codec id is
 * `cipherstash/eql-v3/${bareDomain}@1` — the `public.` prefix is stripped, and
 * the `eql-v3` token is a logical version tag, NOT the operator schema.
 */
import {
  type AnyEncryptedV3Column,
  DOMAIN_REGISTRY,
  type QueryCapabilities,
  type V3ColumnFactory,
} from '@cipherstash/stack/eql/v3'

export type V3CastAs = 'string' | 'number' | 'bigint' | 'boolean' | 'date' | 'timestamp'

export interface V3DomainMeta {
  readonly nativeType: `public.${string}`
  readonly bareDomain: string
  readonly castAs: V3CastAs
  readonly capabilities: QueryCapabilities
  readonly indexes: Readonly<Record<string, unknown>>
}

export function toV3CodecId(bareDomain: string): string {
  return `cipherstash/eql-v3/${bareDomain}@1`
}

const PROBE = '__probe__'

function metaFor(bareDomain: string, factory: V3ColumnFactory): V3DomainMeta {
  const column = factory(PROBE)
  const built = column.build()
  return {
    nativeType: column.getEqlType(),
    bareDomain,
    castAs: built.cast_as as V3CastAs,
    capabilities: column.getQueryCapabilities(),
    indexes: built.indexes,
  }
}

const registryEntries: ReadonlyArray<readonly [string, V3ColumnFactory]> =
  Object.entries(DOMAIN_REGISTRY)

const metaEntries: Array<readonly [string, V3DomainMeta]> = registryEntries.map(
  ([bareDomain, factory]) => [toV3CodecId(bareDomain), metaFor(bareDomain, factory)] as const,
)

export const V3_DOMAIN_META_BY_CODEC_ID: ReadonlyMap<string, V3DomainMeta> = new Map(metaEntries)

export const V3_CODEC_IDS: readonly string[] = metaEntries.map(([id]) => id)

export const V3_FACTORY_BY_NATIVE_TYPE: ReadonlyMap<
  string,
  (name: string) => AnyEncryptedV3Column
> = new Map(registryEntries.map(([, factory]) => [factory(PROBE).getEqlType(), factory] as const))

export function isOrdOreDomain(bareDomain: string): boolean {
  return bareDomain.endsWith('_ord_ore')
}

export const EXPOSED_DOMAIN_ENTRIES: ReadonlyArray<readonly [string, V3DomainMeta]> =
  metaEntries.filter(([, meta]) => !isOrdOreDomain(meta.bareDomain))

export function envelopeTypeNameForCastAs(
  castAs: V3CastAs,
): 'EncryptedString' | 'EncryptedNumber' | 'EncryptedBigInt' | 'EncryptedDate' | 'EncryptedBoolean' {
  switch (castAs) {
    case 'string':
      return 'EncryptedString'
    case 'number':
      return 'EncryptedNumber'
    case 'bigint':
      return 'EncryptedBigInt'
    case 'date':
    case 'timestamp':
      return 'EncryptedDate'
    case 'boolean':
      return 'EncryptedBoolean'
  }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/catalog`
Expected: PASS (9 tests).

- [ ] **Step 6: Commit**

```bash
git add packages/stack/src/eql/v3/index.ts packages/prisma-next/src/v3/catalog.ts packages/prisma-next/test/v3/catalog.test.ts
git commit -m "feat(prisma-next): derive v3 domain catalog + codec ids from stack DOMAIN_REGISTRY"
```

---

### Task 2: `constants-v3.ts` — codec-id closed union, traits, invariants, drift test

Produce the generated closed union (`CIPHERSTASH_V3_CODEC_IDS` → `CipherstashV3CodecId` → set + guard), the per-capability trait mapping, the FFI-catalog invariant drift test, and the migration name/invariant constants. Mirrors the v2 `constants.ts` shape. There are NO family ids and NO resolver in design A.

**Files:**
- Create: `packages/prisma-next/src/extension-metadata/constants-v3.ts`
- Test: `packages/prisma-next/test/v3/constants-v3.test.ts`, `packages/prisma-next/test/v3/catalog-invariants.test.ts`

**Interfaces:**
- Consumes: Task 1 `V3_CODEC_IDS`, `V3_DOMAIN_META_BY_CODEC_ID`, `EXPOSED_DOMAIN_ENTRIES`; `@cipherstash/stack/eql/v3` types `EqlTypeForColumn`, `AnyEncryptedV3Column`, `QueryCapabilities`; existing v2 `CIPHERSTASH_CODEC_IDS`, `CIPHERSTASH_TRAIT_EQUALITY`, `CIPHERSTASH_TRAIT_ORDER_AND_RANGE`, `CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH` (`./constants`).
- Produces:
  - `type CipherstashV3CodecId` (compile-time closed union, one id per catalog domain)
  - `const CIPHERSTASH_V3_CODEC_IDS: readonly CipherstashV3CodecId[]`
  - `const CIPHERSTASH_V3_CODEC_ID_SET: ReadonlySet<string>`
  - `function isCipherstashV3CodecId(id: string): id is CipherstashV3CodecId`
  - re-exported trait constants; `function v3TraitsForCapabilities(caps: QueryCapabilities): readonly string[]`
  - `const CIPHERSTASH_V3_BASELINE_MIGRATION_NAME = '20260601T0100_install_eql_v3_bundle'`
  - `const CIPHERSTASH_V3_INVARIANTS = { installBundle: 'cipherstash:install-eql-v3-bundle-v1' } as const`
  - `const CIPHERSTASH_V3_SPACE_ID` / `const CIPHERSTASH_V3_EXTENSION_VERSION` — v3's own distinct extension identity (decision 1b), asserted ≠ the v2 id/version.

- [ ] **Step 1: Write the failing test**

Create `packages/prisma-next/test/v3/constants-v3.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { CIPHERSTASH_CODEC_IDS } from '../../src/extension-metadata/constants'
import { V3_CODEC_IDS } from '../../src/v3/catalog'
import {
  CIPHERSTASH_V3_BASELINE_MIGRATION_NAME,
  CIPHERSTASH_V3_CODEC_ID_SET,
  CIPHERSTASH_V3_CODEC_IDS,
  CIPHERSTASH_V3_INVARIANTS,
  isCipherstashV3CodecId,
  v3TraitsForCapabilities,
} from '../../src/extension-metadata/constants-v3'

describe('constants-v3', () => {
  it('the PINNED codec-id tuple equals the registry-derived set (drift guard, runtime side)', () => {
    // The compile-time `satisfies` + `Exclude` guards catch type drift; this
    // catches derivation drift (e.g. the registry iteration silently dropping
    // or reordering a domain). Both directions must hold.
    expect(new Set(CIPHERSTASH_V3_CODEC_IDS)).toEqual(new Set(V3_CODEC_IDS))
    expect(CIPHERSTASH_V3_CODEC_IDS.length).toBe(V3_CODEC_IDS.length)
    expect(new Set(CIPHERSTASH_V3_CODEC_IDS).size).toBe(CIPHERSTASH_V3_CODEC_IDS.length)
  })

  it('v3 and v2 codec-id sets are disjoint', () => {
    const v2 = new Set<string>(CIPHERSTASH_CODEC_IDS)
    for (const id of CIPHERSTASH_V3_CODEC_IDS) expect(v2.has(id)).toBe(false)
  })

  it('guard narrows only v3 ids', () => {
    expect(isCipherstashV3CodecId('cipherstash/eql-v3/text_eq@1')).toBe(true)
    expect(isCipherstashV3CodecId('cipherstash/string@1')).toBe(false)
    expect(CIPHERSTASH_V3_CODEC_ID_SET.has('cipherstash/eql-v3/text_eq@1')).toBe(true)
  })

  it('derives cipherstash-namespaced traits from capabilities', () => {
    expect(
      v3TraitsForCapabilities({ equality: true, orderAndRange: true, freeTextSearch: true }).sort(),
    ).toEqual(['cipherstash:equality', 'cipherstash:free-text-search', 'cipherstash:order-and-range'])
    expect(v3TraitsForCapabilities({ equality: false, orderAndRange: false, freeTextSearch: false })).toEqual([])
  })

  it('pins the migration name + invariant', () => {
    expect(CIPHERSTASH_V3_BASELINE_MIGRATION_NAME).toBe('20260601T0100_install_eql_v3_bundle')
    expect(CIPHERSTASH_V3_INVARIANTS.installBundle).toBe('cipherstash:install-eql-v3-bundle-v1')
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/constants-v3`
Expected: FAIL — module not found.

- [ ] **Step 3: Write minimal implementation**

Create `packages/prisma-next/src/extension-metadata/constants-v3.ts`:

```ts
/**
 * v3 codec ids, traits, and migration invariants. Parallel to the v2
 * `constants.ts`; imports NO v2 codec/wire code. Codec ids are the generated
 * closed union derived from the imported catalog: `(codec id) ⟺ (public.*
 * domain)` is bijective, so the id set IS the catalog.
 */
import type {
  AnyEncryptedV3Column,
  EqlTypeForColumn,
  QueryCapabilities,
} from '@cipherstash/stack/eql/v3'
import { V3_CODEC_IDS } from '../v3/catalog'
import {
  CIPHERSTASH_TRAIT_EQUALITY,
  CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH,
  CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
} from './constants'

export {
  CIPHERSTASH_TRAIT_EQUALITY,
  CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH,
  CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
}

/** Strip the `public.` schema qualifier at the type level. */
type StripSchema<T> = T extends `public.${infer D}` ? D : never

/** Compile-time closed union: one concrete codec id per catalog domain. A
 * catalog change that adds/drops a domain surfaces as a type error at the
 * `satisfies` line below. */
export type CipherstashV3CodecId =
  `cipherstash/eql-v3/${StripSchema<EqlTypeForColumn<AnyEncryptedV3Column>>}@1`

/**
 * PINNED literal tuple — the compile-time source of truth for the v3 codec-id
 * set. Hand-listed, one entry per catalog domain (INCLUDING the `*_ord_ore`
 * variants that authoring does not expose but the codec/derivation layer still
 * decodes). This is deliberately NOT `V3_CODEC_IDS as readonly CipherstashV3CodecId[]`
 * — that is a masking cast that asserts the derived array IS the union and so
 * catches NO drift. Here, catalog drift fails to COMPILE in both directions:
 *   - `satisfies readonly CipherstashV3CodecId[]` fails if a listed id is no
 *     longer a catalog domain (a domain removed / renamed).
 *   - `_NoUnpinnedDomain` (below) fails if the catalog gained a domain not
 *     pinned here.
 * The Step-1 runtime test additionally asserts this equals the registry-derived
 * `V3_CODEC_IDS` (guarding the derivation itself).
 */
export const CIPHERSTASH_V3_CODEC_IDS = [
  'cipherstash/eql-v3/integer@1',
  'cipherstash/eql-v3/integer_eq@1',
  'cipherstash/eql-v3/integer_ord_ore@1',
  'cipherstash/eql-v3/integer_ord@1',
  'cipherstash/eql-v3/smallint@1',
  'cipherstash/eql-v3/smallint_eq@1',
  'cipherstash/eql-v3/smallint_ord_ore@1',
  'cipherstash/eql-v3/smallint_ord@1',
  'cipherstash/eql-v3/bigint@1',
  'cipherstash/eql-v3/bigint_eq@1',
  'cipherstash/eql-v3/bigint_ord_ore@1',
  'cipherstash/eql-v3/bigint_ord@1',
  'cipherstash/eql-v3/date@1',
  'cipherstash/eql-v3/date_eq@1',
  'cipherstash/eql-v3/date_ord_ore@1',
  'cipherstash/eql-v3/date_ord@1',
  'cipherstash/eql-v3/timestamp@1',
  'cipherstash/eql-v3/timestamp_eq@1',
  'cipherstash/eql-v3/timestamp_ord_ore@1',
  'cipherstash/eql-v3/timestamp_ord@1',
  'cipherstash/eql-v3/numeric@1',
  'cipherstash/eql-v3/numeric_eq@1',
  'cipherstash/eql-v3/numeric_ord_ore@1',
  'cipherstash/eql-v3/numeric_ord@1',
  'cipherstash/eql-v3/text@1',
  'cipherstash/eql-v3/text_eq@1',
  'cipherstash/eql-v3/text_match@1',
  'cipherstash/eql-v3/text_ord_ore@1',
  'cipherstash/eql-v3/text_ord@1',
  'cipherstash/eql-v3/text_search@1',
  'cipherstash/eql-v3/boolean@1',
  'cipherstash/eql-v3/real@1',
  'cipherstash/eql-v3/real_eq@1',
  'cipherstash/eql-v3/real_ord_ore@1',
  'cipherstash/eql-v3/real_ord@1',
  'cipherstash/eql-v3/double@1',
  'cipherstash/eql-v3/double_eq@1',
  'cipherstash/eql-v3/double_ord_ore@1',
  'cipherstash/eql-v3/double_ord@1',
] as const satisfies readonly CipherstashV3CodecId[]

// Bidirectional drift guard — the direction `satisfies` cannot catch. If the
// catalog gains a domain that is not pinned above, `Exclude<...>` is non-`never`
// and this assignment fails to compile with the offending id in the error.
type _PinnedId = (typeof CIPHERSTASH_V3_CODEC_IDS)[number]
type _NoUnpinnedDomain = [Exclude<CipherstashV3CodecId, _PinnedId>] extends [never]
  ? true
  : ['catalog gained an unpinned codec id', Exclude<CipherstashV3CodecId, _PinnedId>]
const _driftGuard: _NoUnpinnedDomain = true
void _driftGuard

export const CIPHERSTASH_V3_CODEC_ID_SET: ReadonlySet<string> = new Set(CIPHERSTASH_V3_CODEC_IDS)

export function isCipherstashV3CodecId(id: string): id is CipherstashV3CodecId {
  return CIPHERSTASH_V3_CODEC_ID_SET.has(id)
}

export function v3TraitsForCapabilities(caps: QueryCapabilities): readonly string[] {
  const traits: string[] = []
  if (caps.equality) traits.push(CIPHERSTASH_TRAIT_EQUALITY)
  if (caps.orderAndRange) traits.push(CIPHERSTASH_TRAIT_ORDER_AND_RANGE)
  if (caps.freeTextSearch) traits.push(CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH)
  return traits
}

export const CIPHERSTASH_V3_BASELINE_MIGRATION_NAME = '20260601T0100_install_eql_v3_bundle'

export const CIPHERSTASH_V3_INVARIANTS = {
  installBundle: 'cipherstash:install-eql-v3-bundle-v1',
} as const

// v3's OWN extension identity (decision 1b) — DISTINCT from the v2
// CIPHERSTASH_SPACE_ID / CIPHERSTASH_EXTENSION_VERSION. v3 and v2 are separate
// entry points, never co-registered; the distinct id keeps the two extension
// descriptors cleanly separate. Confirm the exact SPACE_ID shape the framework
// expects against the v2 `constants.ts` (e.g. a namespaced string / UUID) and
// mirror it under the `eql-v3` namespace.
export const CIPHERSTASH_V3_SPACE_ID = 'cipherstash/eql-v3' as const
export const CIPHERSTASH_V3_EXTENSION_VERSION = 1 as const
```

Add a test asserting the v3 extension id/version are **not equal** to the v2 `CIPHERSTASH_SPACE_ID` / `CIPHERSTASH_EXTENSION_VERSION` (imported from `../../src/extension-metadata/constants`), so the separation can never silently regress.

- [ ] **Step 4: Run test to verify it passes**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/constants-v3`
Expected: PASS (4 tests).

- [ ] **Step 5: Add the catalog-invariant drift test**

Create `packages/prisma-next/test/v3/catalog-invariants.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { DOMAIN_REGISTRY } from '@cipherstash/stack/eql/v3'
import { EXPOSED_DOMAIN_ENTRIES, V3_DOMAIN_META_BY_CODEC_ID } from '../../src/v3/catalog'

describe('FFI catalog invariants (non-structural — pinned)', () => {
  const bareDomains = Object.keys(DOMAIN_REGISTRY)

  it('exposes no searchable JSON v3 domain', () => {
    expect(bareDomains.some((d) => d.includes('json'))).toBe(false)
  })

  it('public.boolean is storage-only (advertises no equality, no indexes)', () => {
    const bool = V3_DOMAIN_META_BY_CODEC_ID.get('cipherstash/eql-v3/boolean@1')
    expect(bool?.nativeType).toBe('public.boolean')
    expect(bool?.capabilities.equality).toBe(false)
    expect(Object.keys(bool?.indexes ?? {})).toEqual([])
    // there is only one boolean domain (no boolean_eq)
    expect(bareDomains.filter((d) => d.startsWith('boolean'))).toEqual(['boolean'])
  })

  it('the BigInt family IS exposed (base/_eq/_ord), *OrdOre is not', () => {
    const exposedBare = EXPOSED_DOMAIN_ENTRIES.map(([, m]) => m.bareDomain)
    expect(exposedBare).toEqual(expect.arrayContaining(['bigint', 'bigint_eq', 'bigint_ord']))
    expect(exposedBare).not.toContain('bigint_ord_ore')
    expect(exposedBare.some((b) => b.endsWith('_ord_ore'))).toBe(false)
  })

  it('native types are public.* while operator SQL is eql_v3.* (schema split not collapsed)', () => {
    for (const [, meta] of V3_DOMAIN_META_BY_CODEC_ID) {
      expect(meta.nativeType.startsWith('public.')).toBe(true)
      expect(meta.nativeType.startsWith('eql_v3.')).toBe(false)
    }
  })
})
```

- [ ] **Step 6: Run and commit**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/constants-v3 v3/catalog-invariants`
Expected: PASS.

```bash
git add packages/prisma-next/src/extension-metadata/constants-v3.ts packages/prisma-next/test/v3/constants-v3.test.ts packages/prisma-next/test/v3/catalog-invariants.test.ts
git commit -m "feat(prisma-next): v3 codec-id closed union, traits, invariants, drift test"
```

---

### Task 3: Authoring surface — derived per-domain constructors + `*V2` aliases

Rewrite `contract-authoring.ts` (PSL) and `exports/column-types.ts` (TS factories) so every exposed v3 domain gets one concrete constructor (static codec id + `public.*` native type + `{ castAs, capabilities }` typeParams, NO options), derived from `EXPOSED_DOMAIN_ENTRIES`. Rename the six pre-existing v2 constructors to their `*V2` forms (keeping v2 codec ids + `eql_v2_encrypted`). The PSL constructor name and the TS factory name are the mechanical `Encrypted<Stem><Suffix>` / `encrypted<Stem><Suffix>` transform of the bare domain.

**Files:**
- Modify: `packages/prisma-next/src/contract-authoring.ts`
- Modify: `packages/prisma-next/src/exports/column-types.ts`
- Test: `packages/prisma-next/test/authoring.test.ts` (add/retarget v3 + V2 cases), `packages/prisma-next/test/column-types.test.ts` (add v3 + V2 cases)

**Interfaces:**
- Consumes: Task 1 `EXPOSED_DOMAIN_ENTRIES`, `V3DomainMeta`; existing v2 `CIPHERSTASH_STRING_CODEC_ID`, `CIPHERSTASH_DOUBLE_CODEC_ID`, `CIPHERSTASH_BIGINT_CODEC_ID`, `CIPHERSTASH_DATE_CODEC_ID`, `CIPHERSTASH_BOOLEAN_CODEC_ID`, `CIPHERSTASH_JSON_CODEC_ID`, `EQL_V2_ENCRYPTED_TYPE` (`./extension-metadata/constants`); framework `AuthoringTypeNamespace` (`@prisma-next/framework-components/authoring`).
- Produces:
  - `function v3PascalName(bareDomain: string): string` / `function v3CamelName(bareDomain: string): string` (shared name transform; exported from `contract-authoring.ts` for reuse by `column-types.ts` and tests).
  - PSL: `cipherstashAuthoringTypes.cipherstash` carrying one constructor per exposed domain (`EncryptedText`, `EncryptedTextEq`, `EncryptedTextOrd`, `EncryptedTextMatch`, `EncryptedTextSearch`, `EncryptedInteger`/`Eq`/`Ord`, `EncryptedSmallint`/`Eq`/`Ord`, `EncryptedBigInt`/`Eq`/`Ord`, `EncryptedNumeric`/`Eq`/`Ord`, `EncryptedReal`/`Eq`/`Ord`, `EncryptedDouble`/`Eq`/`Ord`, `EncryptedDate`/`Eq`/`Ord`, `EncryptedTimestamp`/`Eq`/`Ord`, `EncryptedBoolean`) plus v2 aliases `EncryptedStringV2`, `EncryptedDoubleV2`, `EncryptedBigIntV2`, `EncryptedDateV2`, `EncryptedBooleanV2`, `EncryptedJsonV2`.
  - TS: one factory per exposed domain (`encryptedTextSearch`, `encryptedIntegerOrd`, `encryptedBigIntOrd`, `encryptedBoolean`, …) returning `{ codecId, nativeType, typeParams: { castAs, capabilities } }`, plus `encryptedStringV2`, `encryptedDoubleV2`, `encryptedBigIntV2`, `encryptedDateV2`, `encryptedBooleanV2`, `encryptedJsonV2`.

- [ ] **Step 0: Confirm the framework accepts static (non-arg) typeParams**

The v2 constructors use `{ kind: 'arg', ... }` typeParam nodes because they take options. v3 constructors take no options, so their `typeParams` are static literal values (`castAs: 'string'`, `capabilities: { equality: true, ... }`). Confirm the framework serializes static literal typeParam values:

Run: `sed -n '1,80p' packages/prisma-next/node_modules/@prisma-next/framework-components/dist/authoring.d.ts 2>/dev/null || grep -rn "typeParams" packages/prisma-next/src/contract-authoring.ts`
Expected: `typeParams` values are `unknown`/JSON — static literals are allowed. If the framework requires `{ kind: 'arg' | 'literal', ... }` node wrappers, wrap each static value as `{ kind: 'literal', value }` in Step 2 (adjust both the PSL emit and the Step-1 test expectation together). Record the confirmed shape in a comment atop `contract-authoring.ts`.

- [ ] **Step 1: Write the failing test (PSL authoring outputs, derived 1:1)**

Replace the v2 authoring assertions in `packages/prisma-next/test/authoring.test.ts` with the v3 + V2 surface:

```ts
import { EXPOSED_DOMAIN_ENTRIES } from '../src/v3/catalog'
import { cipherstashAuthoringTypes, v3PascalName } from '../src/contract-authoring'

describe('cipherstash v3 authoring (concrete per-domain, static descriptors)', () => {
  const ns = cipherstashAuthoringTypes.cipherstash as Record<string, { output: Record<string, unknown> }>

  it('emits exactly one constructor per exposed domain, matching the catalog values', () => {
    for (const [codecId, meta] of EXPOSED_DOMAIN_ENTRIES) {
      const name = v3PascalName(meta.bareDomain)
      const ctor = ns[name]
      expect(ctor, `missing constructor ${name}`).toBeDefined()
      expect(ctor.output).toMatchObject({
        codecId,
        nativeType: meta.nativeType,
        typeParams: { castAs: meta.castAs, capabilities: meta.capabilities },
      })
    }
  })

  it('EncryptedTextSearch → public.text_search with full capabilities', () => {
    expect(ns.EncryptedTextSearch.output).toMatchObject({
      codecId: 'cipherstash/eql-v3/text_search@1',
      nativeType: 'public.text_search',
      typeParams: {
        castAs: 'string',
        capabilities: { equality: true, orderAndRange: true, freeTextSearch: true },
      },
    })
  })

  it('EncryptedBoolean → storage-only public.boolean (no equality constructor exists)', () => {
    expect(ns.EncryptedBoolean.output).toMatchObject({
      codecId: 'cipherstash/eql-v3/boolean@1',
      nativeType: 'public.boolean',
      typeParams: { castAs: 'boolean', capabilities: { equality: false, orderAndRange: false, freeTextSearch: false } },
    })
    expect(ns.EncryptedBooleanEq).toBeUndefined()
  })

  it('BigInt family is present (public.bigint*, cast_as bigint); no *OrdOre, no v3 Json/String', () => {
    expect(ns.EncryptedBigInt.output).toMatchObject({ nativeType: 'public.bigint', typeParams: { castAs: 'bigint' } })
    expect(ns.EncryptedBigIntEq.output).toMatchObject({ nativeType: 'public.bigint_eq' })
    expect(ns.EncryptedBigIntOrd.output).toMatchObject({ nativeType: 'public.bigint_ord' })
    expect(ns.EncryptedBigIntOrdOre).toBeUndefined()
    expect(ns.EncryptedIntegerOrdOre).toBeUndefined()
    expect(ns.EncryptedTextOrdOre).toBeUndefined()
    expect(ns.EncryptedJson).toBeUndefined() // no v3 searchable JSON
    expect(ns.EncryptedString).toBeUndefined() // v3 text uses EncryptedText*
  })

  it('*V2 aliases keep v2 codec ids + eql_v2_encrypted', () => {
    expect(ns.EncryptedStringV2.output).toMatchObject({ codecId: 'cipherstash/string@1', nativeType: 'eql_v2_encrypted' })
    expect(ns.EncryptedJsonV2.output).toMatchObject({ codecId: 'cipherstash/json@1', nativeType: 'eql_v2_encrypted' })
    expect(ns.EncryptedBigIntV2.output).toMatchObject({ codecId: 'cipherstash/bigint@1', nativeType: 'eql_v2_encrypted' })
  })
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pnpm --filter @cipherstash/prisma-next test -- authoring`
Expected: FAIL — `v3PascalName` / constructors undefined.

- [ ] **Step 3: Write the PSL implementation (derived)**

Replace `packages/prisma-next/src/contract-authoring.ts` with:

```ts
import type { AuthoringTypeNamespace } from '@prisma-next/framework-components/authoring'
import {
  CIPHERSTASH_BIGINT_CODEC_ID,
  CIPHERSTASH_BOOLEAN_CODEC_ID,
  CIPHERSTASH_DATE_CODEC_ID,
  CIPHERSTASH_DOUBLE_CODEC_ID,
  CIPHERSTASH_JSON_CODEC_ID,
  CIPHERSTASH_STRING_CODEC_ID,
  EQL_V2_ENCRYPTED_TYPE,
} from './extension-metadata/constants'
import { EXPOSED_DOMAIN_ENTRIES, type V3DomainMeta } from './v3/catalog'

// The stem of a bare domain maps to a JS-friendly display label; the suffix
// after the first `_` names the capability tier. `bigint` deliberately renders
// as `BigInt` (capital I) while `smallint` stays `Smallint` — this table is the
// single source for both PSL (`Encrypted…`) and TS (`encrypted…`) names.
const STEM_LABEL: Record<string, string> = {
  text: 'Text',
  integer: 'Integer',
  smallint: 'Smallint',
  bigint: 'BigInt',
  numeric: 'Numeric',
  real: 'Real',
  double: 'Double',
  date: 'Date',
  timestamp: 'Timestamp',
  boolean: 'Boolean',
}
const SUFFIX_LABEL: Record<string, string> = {
  '': '',
  eq: 'Eq',
  ord: 'Ord',
  match: 'Match',
  search: 'Search',
}

function coreName(bareDomain: string): string {
  const i = bareDomain.indexOf('_')
  const stem = i === -1 ? bareDomain : bareDomain.slice(0, i)
  const suffix = i === -1 ? '' : bareDomain.slice(i + 1)
  const stemLabel = STEM_LABEL[stem]
  const suffixLabel = SUFFIX_LABEL[suffix]
  if (stemLabel === undefined || suffixLabel === undefined) {
    throw new Error(
      `contract-authoring: cannot name exposed domain "${bareDomain}" — extend STEM_LABEL/SUFFIX_LABEL.`,
    )
  }
  return `${stemLabel}${suffixLabel}`
}

/** `text_search` → `EncryptedTextSearch`, `bigint_ord` → `EncryptedBigIntOrd`. */
export function v3PascalName(bareDomain: string): string {
  return `Encrypted${coreName(bareDomain)}`
}
/** `text_search` → `encryptedTextSearch`, `bigint_ord` → `encryptedBigIntOrd`. */
export function v3CamelName(bareDomain: string): string {
  return `encrypted${coreName(bareDomain)}`
}

function v3Constructor(codecId: string, meta: V3DomainMeta) {
  return {
    kind: 'typeConstructor',
    args: [],
    output: {
      codecId,
      nativeType: meta.nativeType,
      // Static, not `{ kind: 'arg' }`: there are no options — the constructor
      // IS the capability set. (If the framework requires literal-node
      // wrappers, wrap these two values per Step 0.)
      typeParams: { castAs: meta.castAs, capabilities: meta.capabilities },
    },
  } as const
}

// --- v2 legacy aliases (verbatim old v2 outputs, renamed to *V2) ---
const v2StringOptions = {
  kind: 'object',
  name: 'options',
  optional: true,
  properties: {
    equality: { kind: 'boolean', optional: true },
    freeTextSearch: { kind: 'boolean', optional: true },
    orderAndRange: { kind: 'boolean', optional: true },
  },
} as const
const argTrue = (path: string) => ({ kind: 'arg', index: 0, path: [path], default: true }) as const

const v2String = {
  kind: 'typeConstructor',
  args: [v2StringOptions],
  output: {
    codecId: CIPHERSTASH_STRING_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: {
      equality: argTrue('equality'),
      freeTextSearch: argTrue('freeTextSearch'),
      orderAndRange: argTrue('orderAndRange'),
    },
  },
} as const

const v2Scalar = (codecId: string) =>
  ({
    kind: 'typeConstructor',
    args: [
      {
        kind: 'object',
        name: 'options',
        optional: true,
        properties: {
          equality: { kind: 'boolean', optional: true },
          orderAndRange: { kind: 'boolean', optional: true },
        },
      },
    ],
    output: {
      codecId,
      nativeType: EQL_V2_ENCRYPTED_TYPE,
      typeParams: { equality: argTrue('equality'), orderAndRange: argTrue('orderAndRange') },
    },
  }) as const

const v2Boolean = {
  kind: 'typeConstructor',
  args: [
    { kind: 'object', name: 'options', optional: true, properties: { equality: { kind: 'boolean', optional: true } } },
  ],
  output: {
    codecId: CIPHERSTASH_BOOLEAN_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: { equality: argTrue('equality') },
  },
} as const

const v2Json = {
  kind: 'typeConstructor',
  args: [
    {
      kind: 'object',
      name: 'options',
      optional: true,
      properties: { searchableJson: { kind: 'boolean', optional: true } },
    },
  ],
  output: {
    codecId: CIPHERSTASH_JSON_CODEC_ID,
    nativeType: EQL_V2_ENCRYPTED_TYPE,
    typeParams: { searchableJson: argTrue('searchableJson') },
  },
} as const

const v3Constructors: Record<string, unknown> = Object.fromEntries(
  EXPOSED_DOMAIN_ENTRIES.map(([codecId, meta]) => [v3PascalName(meta.bareDomain), v3Constructor(codecId, meta)]),
)

export const cipherstashAuthoringTypes = {
  cipherstash: {
    ...v3Constructors,
    // v2 legacy aliases
    EncryptedStringV2: v2String,
    EncryptedDoubleV2: v2Scalar(CIPHERSTASH_DOUBLE_CODEC_ID),
    EncryptedBigIntV2: v2Scalar(CIPHERSTASH_BIGINT_CODEC_ID),
    EncryptedDateV2: v2Scalar(CIPHERSTASH_DATE_CODEC_ID),
    EncryptedBooleanV2: v2Boolean,
    EncryptedJsonV2: v2Json,
  },
} as unknown as AuthoringTypeNamespace
```

> Dynamic construction loses the literal object type that `as const satisfies AuthoringTypeNamespace` gave the old file; the `as unknown as AuthoringTypeNamespace` cast is deliberate, and the 1:1 test in Step 1 is what enforces the shape at runtime.

- [ ] **Step 4: Run the PSL authoring test**

Run: `pnpm --filter @cipherstash/prisma-next test -- authoring`
Expected: PASS for the v3 + V2 cases.

- [ ] **Step 5: Retarget pre-existing v2 assertions in `psl-interpretation*.test.ts`**

Any assertion expecting the unqualified `EncryptedString`/`EncryptedDouble`/`EncryptedBigInt`/`EncryptedDate`/`EncryptedBoolean`/`EncryptedJson` to lower to `cipherstash/*@1` + `eql_v2_encrypted` must be retargeted to the `*V2` name (or moved to a v3 expectation where the unqualified name is now a v3 domain).

> **0.14:** extend the existing `interpret()` / `asStorage()` harnesses in `psl-interpretation*.test.ts` — they already carry the 0.14 requirements (target ref with `defaultNamespaceId: 'public'`, the `composedExtensionContracts` map keyed by the cipherstash space id, and namespace-envelope reads via `entries.table`). Interpreted tables land under the `public` namespace (ground-truth note 4). Do not fork a pre-0.13 harness shape for the v3 cases.

Run: `pnpm --filter @cipherstash/prisma-next test -- psl-interpretation`
Expected: the failing assertions name the exact lines; update each to `EncryptedStringV2` / `EncryptedDoubleV2` / etc.

- [ ] **Step 6: Write the failing TS-factory test**

Add to `packages/prisma-next/test/column-types.test.ts`:

```ts
import * as columnTypes from '../src/exports/column-types'
import { EXPOSED_DOMAIN_ENTRIES } from '../src/v3/catalog'
import { v3CamelName } from '../src/contract-authoring'

describe('v3 TS factories', () => {
  it('one factory per exposed domain, returning the concrete descriptor', () => {
    for (const [codecId, meta] of EXPOSED_DOMAIN_ENTRIES) {
      const fn = (columnTypes as Record<string, () => unknown>)[v3CamelName(meta.bareDomain)]
      expect(fn, `missing factory ${v3CamelName(meta.bareDomain)}`).toBeTypeOf('function')
      expect(fn()).toEqual({
        codecId,
        nativeType: meta.nativeType,
        typeParams: { castAs: meta.castAs, capabilities: meta.capabilities },
      })
    }
  })

  it('encryptedBigIntOrd() emits public.bigint_ord with bigint castAs', () => {
    expect(columnTypes.encryptedBigIntOrd()).toMatchObject({
      codecId: 'cipherstash/eql-v3/bigint_ord@1',
      nativeType: 'public.bigint_ord',
      typeParams: { castAs: 'bigint' },
    })
  })

  it('encryptedStringV2() keeps the v2 codec id', () => {
    expect(columnTypes.encryptedStringV2()).toEqual({
      codecId: 'cipherstash/string@1',
      nativeType: 'eql_v2_encrypted',
      typeParams: { equality: true, freeTextSearch: true, orderAndRange: true },
    })
  })
})
```

- [ ] **Step 7: Implement the TS factories**

In `packages/prisma-next/src/exports/column-types.ts`, derive a descriptor record and expose one named factory per exposed domain plus the `*V2` aliases. Add the imports and this block; keep the existing option/descriptor interfaces for the `*V2` return shapes.

```ts
import {
  type AnyEncryptedV3Column,
  type PlaintextKind,
  stripDomainSchema,
  types,
} from '@cipherstash/stack/eql/v3'

type StripPublic<T extends string> = T extends `public.${infer D}` ? D : never

/**
 * Literal-preserving authoring descriptor, generic over the concrete stack
 * column `C`. `codecId`, `nativeType`, and `capabilities` are the domain's
 * LITERAL types (not `string` / `unknown`), so two domains' factories are
 * mutually non-assignable — this is the type spine (design "Type Discipline").
 * `castAs` is the one field the stack widens (`build(): ColumnSchema`), which is
 * harmless: `nativeType` already discriminates every domain. Pinned by the
 * `column-types.test-d.ts` type-level tests (Task: type-level).
 */
export interface V3ColumnDescriptor<C extends AnyEncryptedV3Column> {
  readonly codecId: `cipherstash/eql-v3/${StripPublic<ReturnType<C['getEqlType']>>}@1`
  readonly nativeType: ReturnType<C['getEqlType']>
  readonly typeParams: {
    readonly castAs: PlaintextKind
    readonly capabilities: ReturnType<C['getQueryCapabilities']>
  }
}

/**
 * Build one authoring factory from a concrete stack `types.*` factory. VALUES
 * are read from the column (`getEqlType` / `getQueryCapabilities` / `build`) —
 * nothing is hardcoded — while the literal TYPES flow from `C`. The factory set
 * is a typed 1:1 mirror of the exposed catalog domains, which is how "derive
 * from the catalog" and "distinct static type per domain" coexist: TypeScript
 * cannot hand distinct static types to values pulled from a runtime record, so
 * each factory names its stack factory. Drift is caught by the Step-1 1:1 test
 * (exposed factory set === registry minus `*_ord_ore`) and Task 2's drift test.
 */
function v3Authored<C extends AnyEncryptedV3Column>(
  make: (name: string) => C,
): () => V3ColumnDescriptor<C> {
  const probe = make('__probe__')
  const nativeType = probe.getEqlType()
  const descriptor = {
    codecId: `cipherstash/eql-v3/${stripDomainSchema(nativeType)}@1`,
    nativeType,
    typeParams: {
      castAs: probe.build().cast_as as PlaintextKind,
      capabilities: probe.getQueryCapabilities(),
    },
  } as V3ColumnDescriptor<C>
  return () => descriptor
}

// Each factory has a DISTINCT return type (V3ColumnDescriptor<EncryptedXColumn>);
// `encryptedBigIntOrd()` is not assignable to `encryptedText()` and vice-versa.
// Note the stack factory names: bigint is `types.Bigint*` (not `BigInt`).
// text family
export const encryptedText = v3Authored(types.Text)
export const encryptedTextEq = v3Authored(types.TextEq)
export const encryptedTextOrd = v3Authored(types.TextOrd)
export const encryptedTextMatch = v3Authored(types.TextMatch)
export const encryptedTextSearch = v3Authored(types.TextSearch)
// integer
export const encryptedInteger = v3Authored(types.Integer)
export const encryptedIntegerEq = v3Authored(types.IntegerEq)
export const encryptedIntegerOrd = v3Authored(types.IntegerOrd)
// smallint
export const encryptedSmallint = v3Authored(types.Smallint)
export const encryptedSmallintEq = v3Authored(types.SmallintEq)
export const encryptedSmallintOrd = v3Authored(types.SmallintOrd)
// bigint
export const encryptedBigInt = v3Authored(types.Bigint)
export const encryptedBigIntEq = v3Authored(types.BigintEq)
export const encryptedBigIntOrd = v3Authored(types.BigintOrd)
// numeric
export const encryptedNumeric = v3Authored(types.Numeric)
export const encryptedNumericEq = v3Authored(types.NumericEq)
export const encryptedNumericOrd = v3Authored(types.NumericOrd)
// real
export const encryptedReal = v3Authored(types.Real)
export const encryptedRealEq = v3Authored(types.RealEq)
export const encryptedRealOrd = v3Authored(types.RealOrd)
// double
export const encryptedDouble = v3Authored(types.Double)
export const encryptedDoubleEq = v3Authored(types.DoubleEq)
export const encryptedDoubleOrd = v3Authored(types.DoubleOrd)
// date
export const encryptedDate = v3Authored(types.Date)
export const encryptedDateEq = v3Authored(types.DateEq)
export const encryptedDateOrd = v3Authored(types.DateOrd)
// timestamp
export const encryptedTimestamp = v3Authored(types.Timestamp)
export const encryptedTimestampEq = v3Authored(types.TimestampEq)
export const encryptedTimestampOrd = v3Authored(types.TimestampOrd)
// boolean (storage-only)
export const encryptedBoolean = v3Authored(types.Boolean)
```

> Note: `V3ColumnDescriptor<C>` widens to the framework's `ColumnTypeDescriptor` (whose `codecId` is `string`) at the framework authoring boundary — that widening is fine at the edge; prisma-next's own factories and the `.test-d.ts` retain the literals. If `PlaintextKind` is not re-exported from `@cipherstash/stack/eql/v3`, add it to that barrel (it is the `build().cast_as` union) rather than falling back to `string`.

Add the MANDATORY type-level test (design "Type Discipline" — a runtime suite does not protect the spine). Create `packages/prisma-next/test/v3/column-types.test-d.ts`:

```ts
import { expectTypeOf } from 'vitest'
import type { QueryCapabilities } from '@cipherstash/stack/eql/v3'
import {
  encryptedBigIntOrd,
  encryptedText,
  encryptedTextEq,
} from '../../src/exports/column-types'

// 1. Factories are mutually non-assignable — distinct type per domain.
expectTypeOf(encryptedTextEq()).not.toMatchTypeOf(encryptedText())
expectTypeOf(encryptedBigIntOrd()).not.toMatchTypeOf(encryptedText())
expectTypeOf(encryptedText()).not.toMatchTypeOf(encryptedBigIntOrd())

// 2. codecId is the literal union member, not `string`.
expectTypeOf(encryptedTextEq().codecId).toEqualTypeOf<'cipherstash/eql-v3/text_eq@1'>()
expectTypeOf(encryptedBigIntOrd().codecId).toEqualTypeOf<'cipherstash/eql-v3/bigint_ord@1'>()

// 3. nativeType is the `public.*` literal, not `string`.
expectTypeOf(encryptedTextEq().nativeType).toEqualTypeOf<'public.text_eq'>()
expectTypeOf(encryptedBigIntOrd().nativeType).toEqualTypeOf<'public.bigint_ord'>()

// 4. capabilities is (at least) the concrete QueryCapabilities, never `unknown`.
//    (If the stack types each domain's capabilities as literal booleans, this
//    also narrows further — the point is it is NOT `unknown`.)
expectTypeOf(encryptedTextEq().typeParams.capabilities).toMatchTypeOf<QueryCapabilities>()
expectTypeOf(encryptedTextEq().typeParams.capabilities).not.toBeUnknown()
```

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/column-types.test-d` (vitest typecheck) → PASS.

Rename the six existing factories to their `*V2` names, keeping their previous bodies verbatim (they still return `{ codecId: CIPHERSTASH_*_CODEC_ID, nativeType: EQL_V2_ENCRYPTED_TYPE, typeParams: {...} }`):

```ts
export function encryptedStringV2(options: EncryptedStringOptions = {}) { /* previous encryptedString body */ }
export function encryptedDoubleV2(options: EncryptedNumericOptions = {}) { /* previous encryptedDouble body */ }
export function encryptedBigIntV2(options: EncryptedNumericOptions = {}) { /* previous encryptedBigInt body */ }
export function encryptedDateV2(options: EncryptedDateOptions = {}) { /* previous encryptedDate body */ }
export function encryptedBooleanV2(options: EncryptedBooleanOptions = {}) { /* previous encryptedBoolean body */ }
export function encryptedJsonV2(options: EncryptedJsonOptions = {}) { /* previous encryptedJson body */ }
```

If any barrel (`exports/index.ts`) re-exported the old `encryptedString`/`encryptedDouble`/… by name, update those re-exports to the `*V2` names (and add the new v3 names). Run the build to surface any dangling re-export.

- [ ] **Step 8: Run and commit**

Run: `pnpm --filter @cipherstash/prisma-next test -- authoring psl-interpretation column-types && pnpm --filter @cipherstash/prisma-next build`
Expected: PASS + build clean.

```bash
git add packages/prisma-next/src/contract-authoring.ts packages/prisma-next/src/exports/column-types.ts packages/prisma-next/test/authoring.test.ts packages/prisma-next/test/column-types.test.ts packages/prisma-next/test/psl-interpretation*.test.ts
git commit -m "feat(prisma-next): derived v3 per-domain constructors + V2 aliases"
```

---

### Task 4: Runtime codecs — `EncryptedNumber` + plain-JSONB v3 cell codec

Create the `EncryptedNumber` envelope (a **sibling** of `EncryptedDouble`, distinct `typeName`), the plain-JSONB `v3ToDriver`/`v3FromDriver`, the SDK-bound v3 cell codec + per-domain descriptors (native type = the concrete `public.*` domain), and the v3 barrel that surfaces the neutral value classes (`EncryptedString`, `EncryptedDate`, `EncryptedBoolean`, the existing `EncryptedBigInt`) plus `EncryptedNumber`. v3 codecs depend only on the neutral `EncryptedEnvelopeBase`; they never import the v2 composite/wire codec.

**Files:**
- Create: `packages/prisma-next/src/v3/envelope-number.ts`, `packages/prisma-next/src/v3/wire-v3.ts`, `packages/prisma-next/src/v3/codec-runtime-v3.ts`, `packages/prisma-next/src/v3/barrel.ts`
- Test: `packages/prisma-next/test/v3/envelope-number.test.ts`, `packages/prisma-next/test/v3/wire-v3.test.ts`, `packages/prisma-next/test/v3/codec-runtime-v3.test.ts`

**Interfaces:**
- Consumes: `EncryptedEnvelopeBase`, `EncryptedEnvelopeFromInternalArgs`, `EncryptedEnvelopeHandle` (`../execution/envelope-base`); neutral value classes `EncryptedString` (`../execution/envelope-string`), `EncryptedDate` (`../execution/envelope-date`), `EncryptedBoolean` (`../execution/envelope-boolean`), `EncryptedBigInt` (`../execution/envelope-bigint`); Task 1 `V3_DOMAIN_META_BY_CODEC_ID`, `V3DomainMeta`, `V3CastAs`, `envelopeTypeNameForCastAs`; Task 2 `CipherstashV3CodecId`, `v3TraitsForCapabilities`; `CipherstashSdk` (`../execution/sdk`); framework codec infra.
- Produces:
  - `class EncryptedNumber extends EncryptedEnvelopeBase<number>` (`typeName = 'EncryptedNumber'`, `static from`, `static fromInternal`).
  - `function v3ToDriver(value: unknown): string | null`; `function v3FromDriver<T>(value: string | object | null | undefined): T`.
  - `class CipherstashV3CellCodec<E>`; `function createV3CodecDescriptors(sdk): ReadonlyArray<RuntimeParameterizedCodecDescriptor<unknown>>` (one per catalog domain; `nativeType`/`targetTypes` = the concrete `public.*` domain; traits from capabilities).
  - `barrel.ts` re-exporting `EncryptedNumber`, `EncryptedString`, `EncryptedDate`, `EncryptedBoolean`, `EncryptedBigInt`.

- [ ] **Step 1: Write the failing test for `EncryptedNumber`**

Create `packages/prisma-next/test/v3/envelope-number.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { EncryptedDouble } from '../../src/execution/envelope-double'
import { EncryptedNumber } from '../../src/v3/envelope-number'

describe('EncryptedNumber', () => {
  it('is a distinct sibling of EncryptedDouble (no cross-instanceof leak)', () => {
    const n = EncryptedNumber.from(42)
    expect(n).toBeInstanceOf(EncryptedNumber)
    expect(n instanceof EncryptedDouble).toBe(false)
    expect(EncryptedDouble.from(42) instanceof EncryptedNumber).toBe(false)
  })
  it('renders the $encryptedNumber placeholder marker (distinct typeName)', () => {
    expect(JSON.stringify(EncryptedNumber.from(7))).toBe('{"$encryptedNumber":"<opaque>"}')
  })
  it('redacts and round-trips plaintext via decrypt() fast path', async () => {
    const n = EncryptedNumber.from(3.14)
    expect(String(n)).toBe('[REDACTED]')
    expect(await n.decrypt()).toBe(3.14)
  })
})
```

- [ ] **Step 2: Run to verify it fails**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/envelope-number`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `EncryptedNumber`**

Create `packages/prisma-next/src/v3/envelope-number.ts` (mirror `execution/envelope-double.ts` byte-for-byte, changing only the class name + `typeName`):

```ts
import {
  EncryptedEnvelopeBase,
  type EncryptedEnvelopeFromInternalArgs,
  type EncryptedEnvelopeHandle,
} from '../execution/envelope-base'

export type EncryptedNumberHandle = EncryptedEnvelopeHandle<number>
export type EncryptedNumberFromInternalArgs = EncryptedEnvelopeFromInternalArgs

/**
 * v3 number envelope. A SIBLING of `EncryptedDouble` — NOT a subclass or alias.
 * Its distinct `typeName` drives the `$encryptedNumber` marker; keeping the
 * class separate prevents `value instanceof EncryptedNumber` from matching a v2
 * `EncryptedDouble` (a cross-version leak). Integer/smallint/numeric/real/double
 * v3 domains all render as `EncryptedNumber`.
 */
export class EncryptedNumber extends EncryptedEnvelopeBase<number> {
  protected override get typeName(): string {
    return 'EncryptedNumber'
  }

  static from(plaintext: number): EncryptedNumber {
    return new EncryptedNumber({ plaintext, ciphertext: undefined, table: undefined, column: undefined, sdk: undefined })
  }

  static fromInternal(args: EncryptedNumberFromInternalArgs): EncryptedNumber {
    return new EncryptedNumber({
      plaintext: undefined,
      ciphertext: args.ciphertext,
      table: args.table,
      column: args.column,
      sdk: args.sdk,
    })
  }
}
```

> Confirm the `typeName` accessor visibility + the `from`/`fromInternal` argument object against the actual `envelope-double.ts` before finalizing; match it exactly.

- [ ] **Step 4: Run to verify it passes**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/envelope-number`
Expected: PASS (3 tests).

- [ ] **Step 5: Write + implement `wire-v3.ts` (TDD)**

Create `packages/prisma-next/test/v3/wire-v3.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { v3FromDriver, v3ToDriver } from '../../src/v3/wire-v3'

describe('v3 wire (plain JSONB)', () => {
  it('serialises to JSON text, never the v2 composite literal', () => {
    expect(v3ToDriver({ a: 1 })).toBe('{"a":1}')
    expect(v3ToDriver({ a: 1 })).not.toMatch(/^\(/)
  })
  it('null/undefined -> null', () => {
    expect(v3ToDriver(null)).toBeNull()
    expect(v3ToDriver(undefined)).toBeNull()
  })
  it('bigintSafeReplacer: a stray bigint in a malformed envelope serialises to its decimal string, not a throw', () => {
    // A well-formed envelope never carries a bigint; this pins the defensive
    // guard so the codec never throws "Do not know how to serialize a BigInt".
    expect(v3ToDriver({ c: 10n })).toBe('{"c":"10"}')
    expect(() => v3ToDriver({ c: 9007199254740993n })).not.toThrow()
  })
  it('fromDriver parses text, passes objects through, preserves null/undefined', () => {
    expect(v3FromDriver('{"a":1}')).toEqual({ a: 1 })
    expect(v3FromDriver({ a: 1 } as object)).toEqual({ a: 1 })
    expect(v3FromDriver(null)).toBeNull()
    expect(v3FromDriver(undefined)).toBeUndefined()
  })
})
```

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/wire-v3` → FAIL. Then create `packages/prisma-next/src/v3/wire-v3.ts`:

```ts
/**
 * v3 columns are `CREATE DOMAIN ... AS jsonb`, so they serialise as plain jsonb
 * — distinct from v2's composite-literal wire.
 *
 * NOTE: this is a thin re-export of the SHARED, framework-neutral codec lifted
 * to `@cipherstash/stack/eql/v3` (`v3ToDriver` / `v3FromDriver` /
 * `bigintSafeReplacer`) — see the shared-primitive-lift task. It is reproduced
 * here only to show the exact behaviour under test; the implementation must
 * `import { v3ToDriver, v3FromDriver } from '@cipherstash/stack/eql/v3'` rather
 * than fork a second copy.
 */

// `bigintSafeReplacer` is LOAD-BEARING and must not be dropped: a well-formed
// envelope never carries a bigint (bigint plaintext is encrypted to ciphertext
// strings first), but a malformed envelope with a stray bigint would otherwise
// throw `TypeError: Do not know how to serialize a BigInt`. Dropping it is a
// regression (ref `eql/v3/drizzle/codec.ts:18,28`).
function bigintSafeReplacer(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? value.toString() : value
}

export function v3ToDriver(value: unknown): string | null {
  if (value === null || value === undefined) return null
  return JSON.stringify(value, bigintSafeReplacer)
}

export function v3FromDriver<T>(value: string | object | null | undefined): T {
  if (value === null || value === undefined) return value as T
  if (typeof value === 'object') return value as T
  return JSON.parse(value) as T
}
```

Run again → PASS.

- [ ] **Step 6: Write + implement the v3 cell codec + descriptors (TDD)**

Create `packages/prisma-next/test/v3/codec-runtime-v3.test.ts`:

```ts
import { describe, expect, it, vi } from 'vitest'
import type { CipherstashSdk } from '../../src/execution/sdk'
import { createV3CodecDescriptors } from '../../src/v3/codec-runtime-v3'

const emptySdk = (): CipherstashSdk => ({
  decrypt: vi.fn(),
  bulkEncrypt: vi.fn(),
  bulkDecrypt: vi.fn(),
})

describe('createV3CodecDescriptors', () => {
  it('emits one descriptor per catalog domain; native type = the public.* domain', () => {
    const ds = createV3CodecDescriptors(emptySdk())
    const textSearch = ds.find((d) => d.codecId === 'cipherstash/eql-v3/text_search@1')
    expect(textSearch).toBeDefined()
    expect(textSearch?.targetTypes).toEqual(['public.text_search'])
    expect(textSearch?.meta).toEqual({ db: { sql: { postgres: { nativeType: 'public.text_search' } } } })
    expect(textSearch?.renderOutputType?.({} as never)).toBe('EncryptedString')
  })

  it('storage-only public.boolean declares no traits; text_search declares all three', () => {
    const ds = createV3CodecDescriptors(emptySdk())
    expect(ds.find((d) => d.codecId === 'cipherstash/eql-v3/boolean@1')?.traits).toEqual([])
    expect([...(ds.find((d) => d.codecId === 'cipherstash/eql-v3/text_search@1')?.traits ?? [])].sort()).toEqual([
      'cipherstash:equality',
      'cipherstash:free-text-search',
      'cipherstash:order-and-range',
    ])
  })

  it('number domains render EncryptedNumber; bigint domains render EncryptedBigInt', () => {
    const ds = createV3CodecDescriptors(emptySdk())
    expect(ds.find((d) => d.codecId === 'cipherstash/eql-v3/integer_ord@1')?.renderOutputType?.({} as never)).toBe(
      'EncryptedNumber',
    )
    expect(ds.find((d) => d.codecId === 'cipherstash/eql-v3/bigint_ord@1')?.renderOutputType?.({} as never)).toBe(
      'EncryptedBigInt',
    )
  })

  it('encode serialises an envelope\'s ciphertext to plain JSONB text', async () => {
    const ds = createV3CodecDescriptors(emptySdk())
    const desc = ds.find((d) => d.codecId === 'cipherstash/eql-v3/text_eq@1')!
    const codec = desc.factory({} as never)({} as never)
    // `encode` operates on an ENVELOPE (with `.expose()`), not a plain object.
    // A set ciphertext serialises via v3ToDriver to JSONB text.
    const envelope = { expose: () => ({ ciphertext: { c: 'abc' } }) }
    const encoded = await codec.encode(envelope as never, {} as never)
    expect(encoded).toBe('{"c":"abc"}')
  })

  it('encode passes a pre-serialised JSONB string through unchanged (middleware two-pass sentinel)', async () => {
    const ds = createV3CodecDescriptors(emptySdk())
    const codec = ds.find((d) => d.codecId === 'cipherstash/eql-v3/text_eq@1')!.factory({} as never)({} as never)
    expect(await codec.encode('{"c":"enc"}' as never, {} as never)).toBe('{"c":"enc"}')
  })

  it('encode returns the value unchanged when the envelope has no ciphertext yet (pre-encrypt)', async () => {
    const ds = createV3CodecDescriptors(emptySdk())
    const codec = ds.find((d) => d.codecId === 'cipherstash/eql-v3/text_eq@1')!.factory({} as never)({} as never)
    const preEncrypt = { expose: () => ({ ciphertext: undefined }) }
    expect(await codec.encode(preEncrypt as never, {} as never)).toBe(preEncrypt)
  })
})
```

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/codec-runtime-v3` → FAIL. Then create `packages/prisma-next/src/v3/codec-runtime-v3.ts`:

```ts
import type { JsonValue } from '@prisma-next/contract/types'
import {
  type AnyCodecDescriptor,
  CodecImpl,
  type CodecInstanceContext,
  type CodecTrait,
} from '@prisma-next/framework-components/codec'
import { runtimeError } from '@prisma-next/framework-components/runtime'
import type { Codec, SqlCodecCallContext } from '@prisma-next/sql-relational-core/ast'
import type { RuntimeParameterizedCodecDescriptor } from '@prisma-next/sql-runtime'
import { type as arktype } from 'arktype'
import { type CipherstashV3CodecId, v3TraitsForCapabilities } from '../extension-metadata/constants-v3'
import { EncryptedBigInt } from '../execution/envelope-bigint'
import type { EncryptedEnvelopeBase } from '../execution/envelope-base'
import { EncryptedBoolean } from '../execution/envelope-boolean'
import { EncryptedDate } from '../execution/envelope-date'
import { EncryptedString } from '../execution/envelope-string'
import type { CipherstashSdk } from '../execution/sdk'
import {
  envelopeTypeNameForCastAs,
  type V3CastAs,
  type V3DomainMeta,
  V3_DOMAIN_META_BY_CODEC_ID,
} from './catalog'
import { EncryptedNumber } from './envelope-number'
import { v3FromDriver, v3ToDriver } from './wire-v3'

type FromInternal = (args: {
  ciphertext: unknown
  table: string
  column: string
  sdk: CipherstashSdk
}) => EncryptedEnvelopeBase<unknown>

function fromInternalForCastAs(castAs: V3CastAs): FromInternal {
  switch (castAs) {
    case 'string':
      return EncryptedString.fromInternal
    case 'number':
      return EncryptedNumber.fromInternal
    case 'bigint':
      return EncryptedBigInt.fromInternal
    case 'date':
    case 'timestamp':
      return EncryptedDate.fromInternal
    case 'boolean':
      return EncryptedBoolean.fromInternal
  }
}

export class CipherstashV3CellCodec<E extends EncryptedEnvelopeBase<unknown>> extends CodecImpl<
  string,
  readonly CodecTrait[],
  unknown,
  E
> {
  readonly #fromInternal: FromInternal
  readonly #typeName: string
  constructor(descriptor: AnyCodecDescriptor, private readonly sdk: CipherstashSdk, typeName: string, fromInternal: FromInternal) {
    super(descriptor)
    this.#fromInternal = fromInternal
    this.#typeName = typeName
  }

  async encode(value: E | string, _ctx: SqlCodecCallContext): Promise<unknown> {
    // Two-pass: the v3 bulk-encrypt middleware replaces the param with the JSONB
    // text before the driver reads it. If we still hold an envelope, serialise
    // its stamped ciphertext (or return itself as the pre-encrypt sentinel).
    if (typeof value === 'string') return value
    if (value === null || value === undefined) return value
    const handle = (value as E).expose()
    if (handle.ciphertext === undefined) return value
    return v3ToDriver(handle.ciphertext)
  }

  async decode(wire: unknown, ctx: SqlCodecCallContext): Promise<E> {
    const column = ctx.column
    if (!column) {
      throw runtimeError(
        'RUNTIME.DECODE_FAILED',
        `cipherstash ${this.descriptor.codecId}: decode requires the projected-column routing context.`,
        { codecId: this.descriptor.codecId, reason: 'cipherstash-v3-decode-column-context-missing' },
      )
    }
    return this.#fromInternal({
      ciphertext: v3FromDriver(wire as string | object | null | undefined),
      table: column.table,
      column: column.name,
      sdk: this.sdk,
    }) as E
  }

  encodeJson(_v: E): JsonValue {
    const marker = `$${this.#typeName.charAt(0).toLowerCase()}${this.#typeName.slice(1)}`
    return { [marker]: '<opaque>' } as JsonValue
  }
  decodeJson(): E {
    throw new Error('cipherstash v3 codec: decodeJson is not supported')
  }
}

const V3_PARAMS_SCHEMA = arktype({ castAs: 'string', capabilities: 'object' })

function makeV3Descriptor(
  sdk: CipherstashSdk,
  codecId: CipherstashV3CodecId,
  meta: V3DomainMeta,
): RuntimeParameterizedCodecDescriptor<unknown> {
  const typeName = envelopeTypeNameForCastAs(meta.castAs)
  const descriptorMeta: AnyCodecDescriptor = {
    codecId,
    traits: v3TraitsForCapabilities(meta.capabilities) as unknown as readonly CodecTrait[],
    targetTypes: [meta.nativeType],
    meta: { db: { sql: { postgres: { nativeType: meta.nativeType } } } },
    paramsSchema: V3_PARAMS_SCHEMA,
    isParameterized: true,
    renderOutputType: () => typeName,
    factory: () => () => codec,
  }
  const codec = new CipherstashV3CellCodec(descriptorMeta, sdk, typeName, fromInternalForCastAs(meta.castAs)) as CipherstashV3CellCodec<
    EncryptedEnvelopeBase<unknown>
  > &
    Codec<string, readonly CodecTrait[], unknown, EncryptedEnvelopeBase<unknown>>
  return {
    codecId,
    traits: descriptorMeta.traits,
    targetTypes: descriptorMeta.targetTypes,
    meta: descriptorMeta.meta,
    paramsSchema: V3_PARAMS_SCHEMA,
    isParameterized: true as const,
    renderOutputType: () => typeName,
    factory: (_p: unknown) => (_ctx: CodecInstanceContext) => codec,
  }
}

export function createV3CodecDescriptors(
  sdk: CipherstashSdk,
): ReadonlyArray<RuntimeParameterizedCodecDescriptor<unknown>> {
  return [...V3_DOMAIN_META_BY_CODEC_ID.entries()].map(([codecId, meta]) =>
    makeV3Descriptor(sdk, codecId as CipherstashV3CodecId, meta),
  )
}
```

Then create `packages/prisma-next/src/v3/barrel.ts`:

```ts
/**
 * v3 user-facing value types, surfaced through the v3 subtree. Re-exports the
 * version-neutral value classes plus the v3-only `EncryptedNumber`. Pulls in NO
 * v2 wire/codec code.
 */
export { EncryptedBigInt } from '../execution/envelope-bigint'
export { EncryptedBoolean } from '../execution/envelope-boolean'
export { EncryptedDate } from '../execution/envelope-date'
export { EncryptedString } from '../execution/envelope-string'
export { EncryptedNumber } from './envelope-number'
```

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/codec-runtime-v3` → PASS. (If arktype's `paramsSchema` type differs from the framework's `~standard` shape, mirror the exact `paramsSchema` object used in v2 `parameterized.ts`. Confirm `CodecImpl` / `AnyCodecDescriptor` / `runtimeError` import paths against the v2 codec-runtime module before finalizing.)

- [ ] **Step 7: Commit**

```bash
git add packages/prisma-next/src/v3/envelope-number.ts packages/prisma-next/src/v3/wire-v3.ts packages/prisma-next/src/v3/codec-runtime-v3.ts packages/prisma-next/src/v3/barrel.ts packages/prisma-next/test/v3/envelope-number.test.ts packages/prisma-next/test/v3/wire-v3.test.ts packages/prisma-next/test/v3/codec-runtime-v3.test.ts
git commit -m "feat(prisma-next): v3 EncryptedNumber + plain-JSONB cell codec + per-domain descriptors (public.* native types)"
```

---

### Task 5: v3 bulk-encrypt middleware (JSONB payloads)

A separate v3 middleware that filters by the v3 codec-id set, stamps `(table, column)` routing keys via the **neutral** AST utility (reused from the v2 module — not the v2 encode path), groups by routing key, calls `sdk.bulkEncrypt`, and replaces params with **plain JSONB** ciphertext (never the v2 composite).

**Files:**
- Modify: `packages/prisma-next/src/middleware/bulk-encrypt.ts` (export `stampRoutingKeysFromAst`)
- Create: `packages/prisma-next/src/v3/bulk-encrypt-v3.ts`
- Test: `packages/prisma-next/test/v3/bulk-encrypt-v3.test.ts`

**Interfaces:**
- Consumes: neutral `stampRoutingKeysFromAst` (now exported from `../middleware/bulk-encrypt`), `setHandleCiphertext`, `EncryptedEnvelopeBase` (`../execution/envelope-base`); `groupByRoutingKey`, `BulkEncryptTarget` (`../execution/routing`); `CipherstashSdk` (`../execution/sdk`); `markBulkEncryptMiddlewareRegistered` (`../execution/middleware-registry`); Task 2 `CIPHERSTASH_V3_CODEC_ID_SET`; Task 4 `v3ToDriver`; abort helpers (`../execution/abort`).
- Produces: `function bulkEncryptMiddlewareV3(sdk: CipherstashSdk): SqlMiddleware` — `name: 'cipherstash.bulk-encrypt-v3'`, `familyId: 'sql'`.

- [ ] **Step 1: Export the neutral AST-stamping util (refactor, no behavior change)**

In `packages/prisma-next/src/middleware/bulk-encrypt.ts`, change `function stampRoutingKeysFromAst(...)` to `export function stampRoutingKeysFromAst(...)`. No other change.

Run: `pnpm --filter @cipherstash/prisma-next test -- bulk-encrypt-middleware`
Expected: PASS (unchanged v2 behavior).

- [ ] **Step 2: Write the failing test**

Create `packages/prisma-next/test/v3/bulk-encrypt-v3.test.ts` (reuse the v2 harness; if `buildInsertPlan`/`createCtx`/`createSqlParamRefMutator` are not already exported from a shared helper, extract them into `packages/prisma-next/test/bulk-encrypt-middleware.helpers.ts` as a first sub-step and re-import from the v2 test too — pure refactor, run the v2 suite green afterward; `buildInsertPlan` gains a 3rd arg = the codec id stamped on each `ParamRef.of(value, { codec: { codecId } })`):

```ts
import { describe, expect, it, vi } from 'vitest'
import type { CipherstashSdk } from '../../src/execution/sdk'
import { EncryptedString } from '../../src/execution/envelope-string'
import { bulkEncryptMiddlewareV3 } from '../../src/v3/bulk-encrypt-v3'
import { buildInsertPlan, createCtx, createSqlParamRefMutator } from '../bulk-encrypt-middleware.helpers'

const V3_TEXT_SEARCH = 'cipherstash/eql-v3/text_search@1'

function makeSdk(): CipherstashSdk & { calls: unknown[] } {
  const calls: unknown[] = []
  return {
    calls,
    decrypt: vi.fn(),
    bulkDecrypt: vi.fn(),
    bulkEncrypt(args) {
      calls.push(args)
      return Promise.resolve(args.values.map((v) => ({ c: `enc:${String(v)}` })))
    },
  }
}

describe('bulkEncryptMiddlewareV3', () => {
  it('has the v3 identity', () => {
    const m = bulkEncryptMiddlewareV3(makeSdk())
    expect(m.name).toBe('cipherstash.bulk-encrypt-v3')
    expect(m.familyId).toBe('sql')
  })

  it('bulk-encrypts v3 params and writes plain JSONB (not the v2 composite)', async () => {
    const sdk = makeSdk()
    const m = bulkEncryptMiddlewareV3(sdk)
    const env = EncryptedString.from('alice@example.com')
    const plan = buildInsertPlan('user', [{ email: env }], V3_TEXT_SEARCH)
    const params = createSqlParamRefMutator(plan)
    await m.beforeExecute?.(plan, createCtx(), params)
    expect(sdk.calls).toHaveLength(1)
    const only = params.currentParams()[0]
    expect(only).toBe('{"c":"enc:alice@example.com"}')
    expect(only).not.toMatch(/^\(/) // never the composite literal
  })

  it('ignores v2-codec params (jurisdiction is the v3 id set only)', async () => {
    const sdk = makeSdk()
    const m = bulkEncryptMiddlewareV3(sdk)
    const env = EncryptedString.from('x')
    const plan = buildInsertPlan('user', [{ email: env }], 'cipherstash/string@1')
    const params = createSqlParamRefMutator(plan)
    await m.beforeExecute?.(plan, createCtx(), params)
    expect(sdk.calls).toHaveLength(0)
  })
})
```

- [ ] **Step 3: Run to verify it fails**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/bulk-encrypt-v3`
Expected: FAIL — module not found.

- [ ] **Step 4: Implement `bulk-encrypt-v3.ts`**

Create `packages/prisma-next/src/v3/bulk-encrypt-v3.ts` (structure mirrors v2 `bulk-encrypt.ts`, but filters on the v3 set and writes `v3ToDriver`):

```ts
import type { ParamRefHandle, SqlParamRefMutator } from '@prisma-next/sql-relational-core/middleware'
import type { SqlMiddleware } from '@prisma-next/sql-runtime'
import { ifDefined } from '@prisma-next/utils/defined'
import { CIPHERSTASH_V3_CODEC_ID_SET } from '../extension-metadata/constants-v3'
import { checkCipherstashAborted, raceCipherstashAbort } from '../execution/abort'
import { EncryptedEnvelopeBase, setHandleCiphertext } from '../execution/envelope-base'
import { markBulkEncryptMiddlewareRegistered } from '../execution/middleware-registry'
import { type BulkEncryptTarget, groupByRoutingKey } from '../execution/routing'
import type { CipherstashSdk } from '../execution/sdk'
// NEUTRAL util — reused, not the v2 encode path.
import { stampRoutingKeysFromAst } from '../middleware/bulk-encrypt'
import { v3ToDriver } from './wire-v3'

export function bulkEncryptMiddlewareV3(sdk: CipherstashSdk): SqlMiddleware {
  markBulkEncryptMiddlewareRegistered(sdk)
  return {
    name: 'cipherstash.bulk-encrypt-v3',
    familyId: 'sql',
    async beforeExecute(plan, ctx, params) {
      if (!params) return
      stampRoutingKeysFromAst(plan.ast)
      const targets = collectV3Targets(params)
      if (targets.length === 0) return
      for (const [groupKey, group] of groupByRoutingKey(targets)) {
        const first = group[0]
        if (!first) continue
        checkCipherstashAborted(ctx.signal, 'bulk-encrypt')
        const ciphertexts = await raceCipherstashAbort(
          sdk.bulkEncrypt({
            routingKey: first.routingKey,
            values: group.map((t) => t.plaintext),
            ...ifDefined('signal', ctx.signal),
          }),
          ctx.signal,
          'bulk-encrypt',
        )
        if (ciphertexts.length !== group.length) {
          throw new Error(
            `cipherstash v3 bulk-encrypt: SDK returned ${ciphertexts.length} ciphertexts for routing key ${groupKey} but ${group.length} were requested.`,
          )
        }
        params.replaceValues(
          group.map((t, i) => {
            const ciphertext = ciphertexts[i]
            setHandleCiphertext(t.envelope, ciphertext)
            return { ref: t.ref, newValue: v3ToDriver(ciphertext) }
          }),
        )
      }
    },
  }
}

function collectV3Targets(params: SqlParamRefMutator): BulkEncryptTarget<ParamRefHandle<string | undefined>>[] {
  const targets: BulkEncryptTarget<ParamRefHandle<string | undefined>>[] = []
  for (const entry of params.entries()) {
    if (entry.codecId === undefined || !CIPHERSTASH_V3_CODEC_ID_SET.has(entry.codecId)) continue
    const value = entry.value
    if (!(value instanceof EncryptedEnvelopeBase)) continue
    const handle = value.expose()
    if (handle.plaintext === undefined) {
      throw new Error(
        'cipherstash v3 bulk-encrypt: encountered a write-path envelope with no plaintext. Use `Encrypted*.from(plaintext)`.',
      )
    }
    if (handle.table === undefined || handle.column === undefined) {
      throw new Error(
        'cipherstash v3 bulk-encrypt: envelope reached the bulk-encrypt phase without a (table, column) routing context.',
      )
    }
    targets.push({
      ref: entry.ref,
      plaintext: handle.plaintext,
      envelope: value,
      routingKey: { table: handle.table, column: handle.column },
    })
  }
  return targets
}
```

- [ ] **Step 5: Run to verify it passes**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/bulk-encrypt-v3 bulk-encrypt-middleware`
Expected: PASS (v3 suite + unchanged v2 suite).

- [ ] **Step 6: Commit**

```bash
git add packages/prisma-next/src/middleware/bulk-encrypt.ts packages/prisma-next/src/v3/bulk-encrypt-v3.ts packages/prisma-next/test/v3/bulk-encrypt-v3.test.ts packages/prisma-next/test/bulk-encrypt-middleware.helpers.ts packages/prisma-next/test/bulk-encrypt-middleware.test.ts
git commit -m "feat(prisma-next): v3 bulk-encrypt middleware with JSONB payloads"
```

---

### Task 6: v3 operators — `::jsonb` two-arg lowering + capability gating + `EncryptionOperatorError`

Keep the `cipherstash*` method names but lower v3 columns to the two-arg `eql_v3.*(...::jsonb)` **functions** (in the `eql_v3` schema — the domains they operate on are `public.*`; do NOT conflate), gate by the concrete domain's index set, and throw a real exported `EncryptionOperatorError`. `cipherstashIlike`/`cipherstashNotIlike` lower to `eql_v3.contains` (documented bloom-filter caveat). No built-in equality traits are attached.

**Files:**
- Create: `packages/prisma-next/src/v3/operators-v3.ts`
- Test: `packages/prisma-next/test/v3/operator-lowering-v3.test.ts`, `packages/prisma-next/test/v3/operator-gating-v3.test.ts`, `packages/prisma-next/test/v3/operator-lowering-v3.helpers.ts`

**Interfaces:**
- Consumes: framework operator infra (`buildOperation`, `codecOf`, `toExpr`, `ParamRef`, `Expression`, `ScopeField`, `CodecRef`, `SqlOperationDescriptor(s)` — same imports as v2 `execution/operators.ts`); Task 1 `V3_DOMAIN_META_BY_CODEC_ID`, `V3DomainMeta`; Task 2 trait constants; Task 4 `EncryptedNumber` + neutral `EncryptedString`/`EncryptedDate`/`EncryptedBoolean`/`EncryptedBigInt`; `setHandleRoutingKey` (`../execution/envelope-base`).
- Produces:
  - `class EncryptionOperatorError extends Error` (name `'EncryptionOperatorError'`) carrying `{ tableName?, columnName?, operator? }`.
  - `function cipherstashV3QueryOperations(): SqlOperationDescriptors` with `cipherstashEq`, `cipherstashNe`, `cipherstashInArray`, `cipherstashNotInArray`, `cipherstashGt`, `cipherstashGte`, `cipherstashLt`, `cipherstashLte`, `cipherstashBetween`, `cipherstashNotBetween`, `cipherstashIlike`, `cipherstashNotIlike`.
  - Templates: `eql_v3.eq({{self}}, {{arg0}}::jsonb)`, `eql_v3.neq(...)`, `eql_v3.gt/gte/lt/lte(...)`, range = `eql_v3.gte({{self}}, {{arg0}}::jsonb) AND eql_v3.lte({{self}}, {{arg1}}::jsonb)`, `eql_v3.contains({{self}}, {{arg0}}::jsonb)`.

- [ ] **Step 1: Write the failing lowering test + helpers**

Create `packages/prisma-next/test/v3/operator-lowering-v3.helpers.ts` mirroring the v2 `operator-lowering.helpers.ts`, but composing the v3 runtime (`createCipherstashV3RuntimeDescriptor({ sdk: emptySdk() })` from Task 7 — until Task 7 lands, compose a minimal adapter directly from `createV3CodecDescriptors` + `cipherstashV3QueryOperations`) and v3 codec ids in `columnAccessorV3` / `contractV3`. Export `callOperator`, `columnAccessorV3`, `contractV3`, `makeV3Adapter`, `selectWithWhere`, `TABLE`, `emptySdk`.

> **0.14:** the v2 helpers file being mirrored is already 0.14-shaped on the branch — `contractV3` must follow it: `validateSqlContractFully<PostgresContract>(value)` (single arg, from `@prisma-next/sql-contract/validators`), storage as `namespaces.__unbound__ = { id: '__unbound__', entries: { table: {...} } }`, a `domain: { namespaces: { __unbound__: { models: {} } } }` plane, and per-column `nativeType` set to the concrete `public.*` domain. If any v3 lowering assertion reads `lowered.params`, unwrap the structured `LoweredParam` entries with the exported `literalParamValue` helper (ground-truth notes 2–3).

Create `packages/prisma-next/test/v3/operator-lowering-v3.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { cipherstashV3QueryOperations } from '../../src/v3/operators-v3'
import { callOperator, columnAccessorV3, contractV3, makeV3Adapter, selectWithWhere, TABLE } from './operator-lowering-v3.helpers'

// Extract just the operator fragment from the lowered WHERE clause and
// normalise the framework's param placeholders (`$1`/`$2`/…) to `$` so the
// assertion pins the FULL function-call skeleton — parentheses included —
// without coupling to placeholder numbering. A `.toContain('eql_v3.eq(')`
// check (the previous form) does NOT catch the `between` paren bug; these do.
// NOTE TO IMPLEMENTER: once the helper's exact `lowered.sql` format is
// confirmed against the v2 `operator-lowering.helpers.ts`, tighten each
// `whereFragment(...)` assertion to a full-string `.toBe(...)`.
function whereFragment(sql: string): string {
  return sql.slice(sql.toUpperCase().indexOf('WHERE ') + 6).replace(/\$\d+/g, '$').trim()
}

const TEXT = 'cipherstash/eql-v3/text_search@1'
const ORD = 'cipherstash/eql-v3/integer_ord@1'
const lowerOf = (predicate: unknown) =>
  whereFragment(makeV3Adapter().lower(selectWithWhere(predicate), { contract: contractV3 }).sql)

describe('v3 operator lowering (::jsonb two-arg eql_v3.* functions)', () => {
  const ops = cipherstashV3QueryOperations()

  it.each([
    ['cipherstashEq', ORD, ['x'], 'eql_v3.eq($, $::jsonb)'],
    ['cipherstashNe', ORD, ['x'], 'eql_v3.neq($, $::jsonb)'],
    ['cipherstashGt', ORD, ['x'], 'eql_v3.gt($, $::jsonb)'],
    ['cipherstashGte', ORD, ['x'], 'eql_v3.gte($, $::jsonb)'],
    ['cipherstashLt', ORD, ['x'], 'eql_v3.lt($, $::jsonb)'],
    ['cipherstashLte', ORD, ['x'], 'eql_v3.lte($, $::jsonb)'],
    ['cipherstashIlike', TEXT, ['x'], 'eql_v3.contains($, $::jsonb)'],
    ['cipherstashNotIlike', TEXT, ['x'], 'NOT eql_v3.contains($, $::jsonb)'],
  ] as const)('%s lowers to the exact ::jsonb skeleton', (method, codecId, args, expected) => {
    const predicate = callOperator(ops[method], columnAccessorV3(TABLE, 'c', codecId), ...args)
    expect(lowerOf(predicate)).toBe(expected)
  })

  it('cipherstashBetween is a SELF-PARENTHESISED conjunction (composition-safe)', () => {
    const predicate = callOperator(ops.cipherstashBetween, columnAccessorV3(TABLE, 'c', ORD), 1, 9)
    // The leading/trailing parens are the fix: without them a generic NOT/OR
    // over `between` mis-parses. Pin the whole shape.
    expect(lowerOf(predicate)).toBe('(eql_v3.gte($, $::jsonb) AND eql_v3.lte($, $::jsonb))')
  })

  it('cipherstashNotBetween wraps the WHOLE conjunction: NOT (gte AND lte)', () => {
    const predicate = callOperator(ops.cipherstashNotBetween, columnAccessorV3(TABLE, 'c', ORD), 1, 9)
    const frag = lowerOf(predicate)
    expect(frag).toBe('NOT (eql_v3.gte($, $::jsonb) AND eql_v3.lte($, $::jsonb))')
    // Regression guard on the 9c82f50e degradation `NOT gte AND lte`:
    expect(frag).not.toMatch(/NOT eql_v3\.gte/)
  })

  it.each([
    ['cipherstashInArray', '(eql_v3.eq($, $::jsonb) OR eql_v3.eq($, $::jsonb))'],
    ['cipherstashNotInArray', 'NOT (eql_v3.eq($, $::jsonb) OR eql_v3.eq($, $::jsonb))'],
  ] as const)('%s ORs/NOT-ORs one eq term per value, parenthesised', (method, expected) => {
    const predicate = callOperator(ops[method], columnAccessorV3(TABLE, 'c', ORD), ['a', 'b'])
    expect(lowerOf(predicate)).toBe(expected)
  })
})
```

- [ ] **Step 2: Write the failing gating test**

Create `packages/prisma-next/test/v3/operator-gating-v3.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { cipherstashV3QueryOperations, EncryptionOperatorError } from '../../src/v3/operators-v3'
import { callOperator, columnAccessorV3, TABLE } from './operator-lowering-v3.helpers'

describe('v3 operator capability gating', () => {
  it('equality requires unique or ore — storage-only public.text rejects cipherstashEq', () => {
    const op = cipherstashV3QueryOperations().cipherstashEq
    expect(() => callOperator(op, columnAccessorV3(TABLE, 'note', 'cipherstash/eql-v3/text@1'), 'x')).toThrow(
      EncryptionOperatorError,
    )
  })
  it('comparison requires ore — text_eq rejects cipherstashGt', () => {
    const op = cipherstashV3QueryOperations().cipherstashGt
    expect(() => callOperator(op, columnAccessorV3(TABLE, 'email', 'cipherstash/eql-v3/text_eq@1'), 'x')).toThrow(/order\/range/)
  })
  it('free-text requires match — text_eq rejects cipherstashIlike', () => {
    const op = cipherstashV3QueryOperations().cipherstashIlike
    expect(() => callOperator(op, columnAccessorV3(TABLE, 'email', 'cipherstash/eql-v3/text_eq@1'), 'x')).toThrow(/free-text/)
  })
  it('storage-only public.boolean rejects every search operator', () => {
    const op = cipherstashV3QueryOperations().cipherstashEq
    expect(() => callOperator(op, columnAccessorV3(TABLE, 'active', 'cipherstash/eql-v3/boolean@1'), true)).toThrow(
      EncryptionOperatorError,
    )
  })
})
```

- [ ] **Step 3: Run to verify both fail**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/operator`
Expected: FAIL — module not found.

- [ ] **Step 4: Implement `operators-v3.ts`**

Create `packages/prisma-next/src/v3/operators-v3.ts` (structure mirrors v2 `execution/operators.ts`, coercing to v3 envelopes, resolving domain meta from the codec id, gating on `meta.indexes`, using `::jsonb` templates):

```ts
import type { CodecTrait } from '@prisma-next/framework-components/codec'
import type { SqlOperationDescriptor, SqlOperationDescriptors } from '@prisma-next/sql-operations'
import { type AnyExpression, type ColumnRef, type CodecRef, ParamRef } from '@prisma-next/sql-relational-core/ast'
import { buildOperation, codecOf, type Expression, type ScopeField, toExpr } from '@prisma-next/sql-relational-core/expression'
import {
  CIPHERSTASH_TRAIT_EQUALITY,
  CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH,
  CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
} from '../extension-metadata/constants-v3'
import { EncryptedBigInt } from '../execution/envelope-bigint'
import { setHandleRoutingKey } from '../execution/envelope-base'
import { EncryptedBoolean } from '../execution/envelope-boolean'
import { EncryptedDate } from '../execution/envelope-date'
import { EncryptedString } from '../execution/envelope-string'
import { type V3DomainMeta, V3_DOMAIN_META_BY_CODEC_ID } from './catalog'
import { EncryptedNumber } from './envelope-number'

const PG_BOOL_CODEC_ID = 'pg/bool@1' as const
type PgBoolReturn = { readonly codecId: typeof PG_BOOL_CODEC_ID; readonly nullable: false }

export class EncryptionOperatorError extends Error {
  constructor(
    message: string,
    public readonly context?: { columnName?: string; tableName?: string; operator?: string },
  ) {
    super(message)
    this.name = 'EncryptionOperatorError'
  }
}

function coerceV3(meta: V3DomainMeta, value: unknown) {
  switch (meta.castAs) {
    case 'string':
      if (value instanceof EncryptedString) return value
      if (typeof value === 'string') return EncryptedString.from(value)
      break
    case 'number':
      if (value instanceof EncryptedNumber) return value
      if (typeof value === 'number') return EncryptedNumber.from(value)
      break
    case 'bigint':
      if (value instanceof EncryptedBigInt) return value
      if (typeof value === 'bigint') return EncryptedBigInt.from(value)
      break
    case 'date':
    case 'timestamp':
      if (value instanceof EncryptedDate) return value
      if (value instanceof Date) return EncryptedDate.from(value)
      break
    case 'boolean':
      if (value instanceof EncryptedBoolean) return value
      if (typeof value === 'boolean') return EncryptedBoolean.from(value)
      break
  }
  throw new EncryptionOperatorError(`cipherstash v3 operator: value not assignable to castAs "${meta.castAs}".`)
}

function requireSelfCodec(self: Expression<ScopeField>, method: string): CodecRef {
  const codec = codecOf(self)
  if (codec === undefined) {
    throw new EncryptionOperatorError(
      `cipherstash ${method}: self expression is missing a CodecRef. Reach the operator through the ORM model accessor.`,
      { operator: method },
    )
  }
  return codec
}

function metaFor(codecId: string, method: string): V3DomainMeta {
  const meta = V3_DOMAIN_META_BY_CODEC_ID.get(codecId)
  if (!meta) {
    throw new EncryptionOperatorError(`cipherstash ${method}: column codec id "${codecId}" is not a public.* v3 domain.`, {
      operator: method,
    })
  }
  return meta
}

function extractColumnRef(selfAst: AnyExpression): ColumnRef | undefined {
  if (selfAst.kind === 'column-ref') return selfAst
  try {
    return selfAst.baseColumnRef()
  } catch {
    return undefined
  }
}

function asEncryptedParam(selfAst: AnyExpression, selfCodec: CodecRef, meta: V3DomainMeta, value: unknown): ParamRef {
  const envelope = coerceV3(meta, value)
  const columnRef = extractColumnRef(selfAst)
  if (columnRef) setHandleRoutingKey(envelope, columnRef.table, columnRef.column)
  return ParamRef.of(envelope, { codec: selfCodec })
}

type Gate = (meta: V3DomainMeta) => boolean
// equality is answered via `unique` (HMAC) OR `ore` (equality-via-ORE on a
// pure-order domain); comparison/range/order require `ore`; free-text `match`.
const hasEquality: Gate = (m) => !!(m.indexes.unique || m.indexes.ore)
const hasOre: Gate = (m) => !!m.indexes.ore
const hasMatch: Gate = (m) => !!m.indexes.match

function gate(meta: V3DomainMeta, ok: Gate, method: string, capability: string): void {
  if (!ok(meta)) {
    throw new EncryptionOperatorError(
      `Operator "${method}" requires ${capability} on this column (domain ${meta.nativeType} does not support it).`,
      { operator: method },
    )
  }
}

function fixedArity(method: string, trait: string, arity: number, template: string, gateFn: Gate, capability: string): SqlOperationDescriptor {
  return {
    self: { traits: [trait] as unknown as readonly CodecTrait[] },
    impl: (self: Expression<ScopeField>, ...userArgs: unknown[]): Expression<PgBoolReturn> => {
      if (userArgs.length !== arity) {
        throw new EncryptionOperatorError(`cipherstash ${method}: expected ${arity} argument(s), got ${userArgs.length}.`, {
          operator: method,
        })
      }
      const selfCodec = requireSelfCodec(self, method)
      const meta = metaFor(selfCodec.codecId, method)
      gate(meta, gateFn, method, capability)
      const selfAst = toExpr(self, selfCodec)
      const argRefs = userArgs.map((v) => asEncryptedParam(selfAst, selfCodec, meta, v))
      return buildOperation({
        method,
        args: [selfAst, ...argRefs],
        returns: { codecId: PG_BOOL_CODEC_ID, nullable: false },
        lowering: { targetFamily: 'sql', strategy: 'function', template },
      })
    },
  }
}

function variableArity(method: string, trait: string, build: (n: number) => string): SqlOperationDescriptor {
  return {
    self: { traits: [trait] as unknown as readonly CodecTrait[] },
    impl: (self: Expression<ScopeField>, values: unknown): Expression<PgBoolReturn> => {
      if (!Array.isArray(values)) throw new EncryptionOperatorError(`cipherstash ${method}: expected an array.`, { operator: method })
      if (values.length === 0) throw new EncryptionOperatorError(`cipherstash ${method}: empty array is not supported.`, { operator: method })
      const selfCodec = requireSelfCodec(self, method)
      const meta = metaFor(selfCodec.codecId, method)
      gate(meta, hasEquality, method, 'equality')
      const selfAst = toExpr(self, selfCodec)
      const argRefs = values.map((v) => asEncryptedParam(selfAst, selfCodec, meta, v))
      return buildOperation({
        method,
        args: [selfAst, ...argRefs],
        returns: { codecId: PG_BOOL_CODEC_ID, nullable: false },
        lowering: { targetFamily: 'sql', strategy: 'function', template: build(values.length) },
      })
    },
  }
}

const inArrayTemplate = (n: number) =>
  `(${Array.from({ length: n }, (_, i) => `eql_v3.eq({{self}}, {{arg${i}}}::jsonb)`).join(' OR ')})`
const notInArrayTemplate = (n: number) => `NOT ${inArrayTemplate(n)}`

export function cipherstashV3QueryOperations(): SqlOperationDescriptors {
  return {
    cipherstashEq: fixedArity('cipherstashEq', CIPHERSTASH_TRAIT_EQUALITY, 1, 'eql_v3.eq({{self}}, {{arg0}}::jsonb)', hasEquality, 'equality'),
    cipherstashNe: fixedArity('cipherstashNe', CIPHERSTASH_TRAIT_EQUALITY, 1, 'eql_v3.neq({{self}}, {{arg0}}::jsonb)', hasEquality, 'equality'),
    cipherstashInArray: variableArity('cipherstashInArray', CIPHERSTASH_TRAIT_EQUALITY, inArrayTemplate),
    cipherstashNotInArray: variableArity('cipherstashNotInArray', CIPHERSTASH_TRAIT_EQUALITY, notInArrayTemplate),
    cipherstashGt: fixedArity('cipherstashGt', CIPHERSTASH_TRAIT_ORDER_AND_RANGE, 1, 'eql_v3.gt({{self}}, {{arg0}}::jsonb)', hasOre, 'order/range'),
    cipherstashGte: fixedArity('cipherstashGte', CIPHERSTASH_TRAIT_ORDER_AND_RANGE, 1, 'eql_v3.gte({{self}}, {{arg0}}::jsonb)', hasOre, 'order/range'),
    cipherstashLt: fixedArity('cipherstashLt', CIPHERSTASH_TRAIT_ORDER_AND_RANGE, 1, 'eql_v3.lt({{self}}, {{arg0}}::jsonb)', hasOre, 'order/range'),
    cipherstashLte: fixedArity('cipherstashLte', CIPHERSTASH_TRAIT_ORDER_AND_RANGE, 1, 'eql_v3.lte({{self}}, {{arg0}}::jsonb)', hasOre, 'order/range'),
    // between's template is a SELF-CONTAINED PARENTHESISED conjunction. The
    // parens are load-bearing, not cosmetic: Postgres binds NOT tighter than
    // AND, so an unparenthesised `gte AND lte` under any generic negation (a
    // framework `not(between(...))`, an OR composition, etc.) parses as
    // `(NOT gte) AND lte` — rows BELOW the lower bound instead of the range
    // complement (the 9c82f50e bug class). Parenthesising here makes every
    // composition safe instead of relying on each caller to remember.
    cipherstashBetween: fixedArity('cipherstashBetween', CIPHERSTASH_TRAIT_ORDER_AND_RANGE, 2, '(eql_v3.gte({{self}}, {{arg0}}::jsonb) AND eql_v3.lte({{self}}, {{arg1}}::jsonb))', hasOre, 'order/range'),
    cipherstashNotBetween: fixedArity('cipherstashNotBetween', CIPHERSTASH_TRAIT_ORDER_AND_RANGE, 2, 'NOT (eql_v3.gte({{self}}, {{arg0}}::jsonb) AND eql_v3.lte({{self}}, {{arg1}}::jsonb))', hasOre, 'order/range'),
    // ilike/notIlike lower to eql_v3.contains (bloom-filter token containment, NOT SQL LIKE — carry this caveat into user docs).
    cipherstashIlike: fixedArity('cipherstashIlike', CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH, 1, 'eql_v3.contains({{self}}, {{arg0}}::jsonb)', hasMatch, 'free-text search'),
    cipherstashNotIlike: fixedArity('cipherstashNotIlike', CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH, 1, 'NOT eql_v3.contains({{self}}, {{arg0}}::jsonb)', hasMatch, 'free-text search'),
  }
}
```

- [ ] **Step 5: Run to verify both suites pass**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/operator`
Expected: PASS.

- [ ] **Step 6: Pin the trait-removal regression for v3**

Add to `packages/prisma-next/test/equality-trait-removal.test.ts` (or a v3 sibling): every descriptor from `createV3CodecDescriptors(emptySdk())` has traits ⊆ `cipherstash:*` and never contains the framework built-in `'equality'`.

```ts
import { createV3CodecDescriptors } from '../src/v3/codec-runtime-v3'
it('v3 codec descriptors never advertise the framework built-in equality trait', () => {
  for (const d of createV3CodecDescriptors({ decrypt: vi.fn(), bulkEncrypt: vi.fn(), bulkDecrypt: vi.fn() })) {
    for (const t of d.traits) expect(String(t).startsWith('cipherstash:')).toBe(true)
    expect(d.traits).not.toContain('equality')
  }
})
```

- [ ] **Step 7: Verify no method-name collision across v2+v3 descriptors**

Confirm the **v3 descriptor stands alone**: `createCipherstashV3RuntimeDescriptor({ sdk })` (Task 7) registers its `cipherstash*` operations under v3's own distinct extension id and builds cleanly. Do NOT co-register it with the v2 descriptor — decision 1b makes v2 and v3 separate entry points precisely because the flat `OperationRegistry` rejects two descriptors sharing the `cipherstashEq` method name. Add a test asserting a v3-only adapter builds, and (optionally) that attempting to register v2 and v3 descriptors together throws — documenting why they must not be combined.

- [ ] **Step 8: Commit**

```bash
git add packages/prisma-next/src/v3/operators-v3.ts packages/prisma-next/test/v3/operator-lowering-v3.test.ts packages/prisma-next/test/v3/operator-lowering-v3.helpers.ts packages/prisma-next/test/v3/operator-gating-v3.test.ts packages/prisma-next/test/equality-trait-removal.test.ts
git commit -m "feat(prisma-next): v3 operators with eql_v3.* ::jsonb lowering, capability gating, EncryptionOperatorError"
```

---

### Task 7: v3 schema derivation, SDK adapter, runtime descriptor, and the v3 entry point (`cipherstashFromStackV3`)

Derive `@cipherstash/stack/eql/v3` schemas from v3 contract columns (mapping `nativeType` (`public.*`) → the matching concrete factory, preserving the concrete column type — no widening to `AnyEncryptedV3Column`), adapt the `EncryptionV3` client to the `CipherstashSdk` shape, compose the v3 runtime descriptor (under v3's **own distinct extension id/version**), and add a **v3-only** entry point `cipherstashFromStackV3` that builds a single `EncryptionV3` client. Decision **1b**: v2 and v3 are separate entry points — the v2 `cipherstashFromStack` is left unchanged, there is no two-client dispatch, and a v3 contract carrying a v2 codec id is a hard error. v3 override validation compares exact domain identity (`integer_ord` ≠ `integer_ord_ore`).

**Files:**
- Create: `packages/prisma-next/src/v3/derive-schemas-v3.ts`, `packages/prisma-next/src/v3/sdk-adapter-v3.ts`, `packages/prisma-next/src/v3/runtime-v3.ts`, `packages/prisma-next/src/v3/from-stack-v3-validate.ts`
- Modify: `packages/prisma-next/src/stack/from-stack.ts`, `packages/prisma-next/src/exports/stack.ts`, `packages/prisma-next/src/exports/runtime.ts`
- Test: `packages/prisma-next/test/v3/derive-schemas-v3.test.ts`, `packages/prisma-next/test/v3/sdk-adapter-v3.test.ts`, `packages/prisma-next/test/v3/from-stack-divergence-v3.test.ts`

**Interfaces:**
- Consumes: `@cipherstash/stack/eql/v3` — `types`, `encryptedTable`, `AnyV3Table`, `AnyEncryptedV3Column`; Task 1 `V3_FACTORY_BY_NATIVE_TYPE`; Task 2 `isCipherstashV3CodecId`; `EncryptionV3` (from the stack v3 client entry — see Step 4 note); `CipherstashSdk`, `CipherstashRoutingKey` (`../execution/sdk`); Task 4 `createV3CodecDescriptors`; Task 6 `cipherstashV3QueryOperations`; Task 5 `bulkEncryptMiddlewareV3`; existing v2 `deriveStackSchemas`, `createCipherstashSdk`, `createCipherstashRuntimeDescriptor`, `bulkEncryptMiddleware`, `Encryption`.
- Produces:
  - `function deriveStackSchemasV3(contractJson): ReadonlyArray<AnyV3Table>`
  - `function createCipherstashV3Sdk(client, schemas): CipherstashSdk`
  - `function createCipherstashV3RuntimeDescriptor(opts: { sdk: CipherstashSdk }): SqlRuntimeExtensionDescriptor<'postgres'>`
  - `function assertV3SchemasAgree(derived: AnyV3Table, override: AnyV3Table): void`
  - `function cipherstashFromStackV3(opts: CipherstashFromStackV3Options): Promise<CipherstashFromStackResult>` — the v3-only entry point (decision 1b). The v2 `cipherstashFromStack` is **unchanged** and not touched by this task.
  - `interface V3ContractShape` (structural view of the contract storage — the 0.14 namespace envelope, mirroring the v2 `ContractStorageView` in `src/stack/derive-schemas.ts`): `{ storage?: { namespaces?: Record<string, { entries?: { table?: Record<string, { columns?: Record<string, { codecId?: string; nativeType?: string; typeParams?: unknown }> }> } }> } }` (exported for reuse by tests/properties).

- [ ] **Step 1: Write the failing derivation test**

Create `packages/prisma-next/test/v3/derive-schemas-v3.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { deriveStackSchemasV3 } from '../../src/v3/derive-schemas-v3'

// 0.14 contract shape: tables live under storage.namespaces.<ns>.entries.table
// (Postgres default namespace is `public`).
function contract(columns: Record<string, { codecId: string; nativeType: string; typeParams?: unknown }>) {
  return {
    storage: {
      namespaces: { public: { entries: { table: { user: { columns } } } } },
    },
  }
}

describe('deriveStackSchemasV3', () => {
  it('derives one v3 EncryptedTable, mapping public.* nativeType -> the concrete factory', () => {
    const [table] = deriveStackSchemasV3(
      contract({
        email: { codecId: 'cipherstash/eql-v3/text_search@1', nativeType: 'public.text_search' },
        score: { codecId: 'cipherstash/eql-v3/integer_ord@1', nativeType: 'public.integer_ord' },
        balance: { codecId: 'cipherstash/eql-v3/bigint_ord@1', nativeType: 'public.bigint_ord' },
      }),
    )
    const built = table!.build()
    expect(built.tableName).toBe('user')
    expect(Object.keys(built.columns.email!.indexes).sort()).toEqual(['match', 'ore', 'unique'])
    expect(Object.keys(built.columns.score!.indexes)).toEqual(['ore'])
    expect(built.columns.email!.cast_as).toBe('string')
    expect(built.columns.score!.cast_as).toBe('number')
    expect(built.columns.balance!.cast_as).toBe('bigint')
  })

  it('skips tables with no v3 columns', () => {
    expect(
      deriveStackSchemasV3(contract({ x: { codecId: 'cipherstash/string@1', nativeType: 'eql_v2_encrypted' } })),
    ).toHaveLength(0)
  })
})
```

- [ ] **Step 2: Run to verify it fails, then implement**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/derive-schemas-v3` → FAIL. Create `packages/prisma-next/src/v3/derive-schemas-v3.ts`:

```ts
import { type AnyEncryptedV3Column, type AnyV3Table, encryptedTable } from '@cipherstash/stack/eql/v3'
import { isCipherstashV3CodecId } from '../extension-metadata/constants-v3'
import { V3_FACTORY_BY_NATIVE_TYPE } from './catalog'

interface V3TableView {
  readonly columns?: Record<
    string,
    { codecId?: string; nativeType?: string; typeParams?: unknown }
  >
}

// 0.14 storage envelope: namespaces.<ns>.entries.table.<name> (see the
// "Prisma Next 0.14 ground truth" notes; mirrors the v2 ContractStorageView).
export interface V3ContractShape {
  storage?: {
    namespaces?: Record<string, { entries?: { table?: Record<string, V3TableView> } }>
  }
}

export function deriveStackSchemasV3(contractJson: V3ContractShape): ReadonlyArray<AnyV3Table> {
  const namespaces = contractJson.storage?.namespaces
  if (!namespaces) return []
  const tables: Record<string, V3TableView> = {}
  for (const namespace of Object.values(namespaces)) {
    Object.assign(tables, namespace.entries?.table)
  }
  const result: AnyV3Table[] = []
  for (const [tableName, table] of Object.entries(tables)) {
    const columns: Record<string, AnyEncryptedV3Column> = {}
    for (const [columnName, column] of Object.entries(table.columns ?? {})) {
      const codecId = column.codecId
      if (codecId == null || !isCipherstashV3CodecId(codecId)) continue
      const nativeType = column.nativeType
      const factory = nativeType ? V3_FACTORY_BY_NATIVE_TYPE.get(nativeType) : undefined
      if (!factory) {
        throw new Error(
          `deriveStackSchemasV3: column "${tableName}"."${columnName}" has v3 codec id "${codecId}" but nativeType "${nativeType}" maps to no eql/v3 factory. Re-emit the contract with a current @cipherstash/stack.`,
        )
      }
      columns[columnName] = factory(columnName)
    }
    if (Object.keys(columns).length === 0) continue
    result.push(encryptedTable(tableName, columns))
  }
  return result
}
```

Run again → PASS.

- [ ] **Step 3: Implement the exact-domain override validator (TDD)**

Create `packages/prisma-next/test/v3/from-stack-divergence-v3.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { assertV3SchemasAgree } from '../../src/v3/from-stack-v3-validate'

describe('v3 override divergence — same cast_as, different domain', () => {
  it('rejects integer_ord vs integer_ord_ore (both cast_as number)', () => {
    const derived = encryptedTable('user', { score: types.IntegerOrd('score') })
    const override = encryptedTable('user', { score: types.IntegerOrdOre('score') })
    expect(() => assertV3SchemasAgree(derived, override)).toThrow(/domain/)
  })
  it('accepts an exact domain match', () => {
    const derived = encryptedTable('user', { score: types.IntegerOrd('score') })
    const override = encryptedTable('user', { score: types.IntegerOrd('score') })
    expect(() => assertV3SchemasAgree(derived, override)).not.toThrow()
  })
})
```

Create `packages/prisma-next/src/v3/from-stack-v3-validate.ts`:

```ts
import type { AnyV3Table } from '@cipherstash/stack/eql/v3'

/** v3 override validation compares EXACT domain identity (getEqlType() →
 * public.*), not just cast_as + index keys — integer_ord and integer_ord_ore
 * share cast_as and index families but are different domains. */
export function assertV3SchemasAgree(derived: AnyV3Table, override: AnyV3Table): void {
  const d = Object.fromEntries(Object.values(derived.columnBuilders).map((c) => [c.getName(), c.getEqlType()]))
  const o = Object.fromEntries(Object.values(override.columnBuilders).map((c) => [c.getName(), c.getEqlType()]))
  for (const col of new Set([...Object.keys(d), ...Object.keys(o)])) {
    if (d[col] !== o[col]) {
      throw new Error(
        `cipherstashFromStack (v3): schema divergence on column "${derived.tableName}"."${col}". Contract domain "${d[col] ?? '(missing)'}" but override domain "${o[col] ?? '(missing)'}". Fix prisma/schema.prisma and re-emit rather than overriding.`,
      )
    }
  }
}
```

> Confirm the `columnBuilders` property name against `packages/stack/src/eql/v3/table.ts` (`EncryptedTable`); if the concrete-column map is exposed under another name, adjust here and in the SDK adapter (Step 4).

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/from-stack-divergence-v3` → PASS.

- [ ] **Step 4: Implement the v3 SDK adapter (TDD)**

Create `packages/prisma-next/test/v3/sdk-adapter-v3.test.ts` asserting `createCipherstashV3Sdk` routes `(table, column)` to the v3 typed objects and calls the client's `bulkEncrypt`, returning a bare array (matching `CipherstashSdk.bulkEncrypt: Promise<ReadonlyArray<unknown>>`). Then create `packages/prisma-next/src/v3/sdk-adapter-v3.ts`:

```ts
import type { AnyEncryptedV3Column, AnyV3Table } from '@cipherstash/stack/eql/v3'
import type { CipherstashRoutingKey, CipherstashSdk } from '../execution/sdk'

/** Minimal structural view of the stack `EncryptionV3` client. Confirm the real
 * result shapes against `packages/stack/src/encryption/v3.ts` at implementation
 * time; if a method returns a chainable operation, `await` it directly (it is a
 * PromiseLike) and keep this adapter's `CipherstashSdk` output shape unchanged. */
interface V3Client {
  bulkEncrypt(
    payload: ReadonlyArray<{ plaintext: unknown }>,
    opts: { table: AnyV3Table; column: AnyEncryptedV3Column },
  ): PromiseLike<{ data?: Array<{ data: unknown }>; failure?: { message: string } }>
  decrypt(encrypted: unknown): PromiseLike<{ data?: unknown; failure?: { message: string } }>
  bulkDecrypt(
    payloads: ReadonlyArray<{ data: unknown }>,
  ): PromiseLike<{ data?: Array<{ data?: unknown; error?: unknown }>; failure?: { message: string } }>
}

interface V3RegistryEntry {
  readonly table: AnyV3Table
  readonly columns: ReadonlyMap<string, AnyEncryptedV3Column>
}

export function createCipherstashV3Sdk(client: V3Client, schemas: ReadonlyArray<AnyV3Table>): CipherstashSdk {
  const registry = new Map<string, V3RegistryEntry>()
  for (const table of schemas) {
    const columns = new Map<string, AnyEncryptedV3Column>()
    for (const value of Object.values(table.columnBuilders)) {
      columns.set((value as AnyEncryptedV3Column).getName(), value as AnyEncryptedV3Column)
    }
    registry.set(table.tableName, { table, columns })
  }

  function lookup(rk: CipherstashRoutingKey) {
    const entry = registry.get(rk.table)
    if (!entry) throw new Error(`cipherstash v3 SDK adapter: routing-key table "${rk.table}" is not in the v3 schemas.`)
    const column = entry.columns.get(rk.column)
    if (!column) throw new Error(`cipherstash v3 SDK adapter: routing-key column "${rk.column}" is not on v3 table "${rk.table}".`)
    return { table: entry.table, column }
  }

  return {
    async bulkEncrypt({ values, routingKey }) {
      const { table, column } = lookup(routingKey)
      const result = await client.bulkEncrypt(values.map((plaintext) => ({ plaintext })), { table, column })
      if (result.failure) throw new Error(`cipherstash v3 bulkEncrypt failed: ${result.failure.message}`)
      return (result.data ?? []).map((e) => e.data)
    },
    async decrypt({ ciphertext }) {
      const result = await client.decrypt(ciphertext)
      if (result.failure) throw new Error(`cipherstash v3 decrypt failed: ${result.failure.message}`)
      return result.data as string
    },
    async bulkDecrypt({ ciphertexts }) {
      const result = await client.bulkDecrypt(ciphertexts.map((data) => ({ data })))
      if (result.failure) throw new Error(`cipherstash v3 bulkDecrypt failed: ${result.failure.message}`)
      return (result.data ?? []).map((entry) => {
        if (entry.error !== undefined) throw new Error(`cipherstash v3 bulkDecrypt entry failed: ${String(entry.error)}`)
        return entry.data as string
      })
    },
  }
}
```

- [ ] **Step 5: Implement the v3 runtime descriptor**

Create `packages/prisma-next/src/v3/runtime-v3.ts`:

```ts
import type { SqlRuntimeExtensionDescriptor } from '@prisma-next/sql-runtime'
// v3 uses its OWN extension id/version (decision 1b) — NOT the v2
// CIPHERSTASH_SPACE_ID / CIPHERSTASH_EXTENSION_VERSION. Sharing the v2 id while
// registering the same `cipherstash*` method names is the collision that makes
// v2+v3 co-registration throw; distinct ids keep the two entry points cleanly
// separate. (Method names stay identical — they are never co-registered.)
import {
  CIPHERSTASH_V3_EXTENSION_VERSION,
  CIPHERSTASH_V3_SPACE_ID,
} from '../extension-metadata/constants-v3'
import type { CipherstashSdk } from '../execution/sdk'
import { createV3CodecDescriptors } from './codec-runtime-v3'
import { cipherstashV3QueryOperations } from './operators-v3'

export function createCipherstashV3RuntimeDescriptor(opts: { sdk: CipherstashSdk }): SqlRuntimeExtensionDescriptor<'postgres'> {
  const descriptors = createV3CodecDescriptors(opts.sdk)
  return {
    kind: 'extension' as const,
    id: CIPHERSTASH_V3_SPACE_ID,
    version: CIPHERSTASH_V3_EXTENSION_VERSION,
    familyId: 'sql' as const,
    targetId: 'postgres' as const,
    types: { codecTypes: { codecDescriptors: descriptors } },
    codecs: () => descriptors,
    queryOperations: () => cipherstashV3QueryOperations(),
    create() {
      return { familyId: 'sql' as const, targetId: 'postgres' as const }
    },
  }
}
```

> Match the exact `SqlRuntimeExtensionDescriptor` field set against the v2 `createCipherstashRuntimeDescriptor` in `runtime.ts`; copy any additional required fields verbatim.

- [ ] **Step 6: v3 entry point — `cipherstashFromStackV3` (separate from v2, never co-registered)**

Decision **1b**: v2 and v3 are **separate entry points** and are **never co-registered** in one client. The framework `OperationRegistry` is a flat, method-name-keyed map that disallows override, so pushing both the v2 and v3 runtime descriptors (both defining `cipherstashEq`) into one `extensions[]` collides at registration. Do **NOT** extend `cipherstashFromStack` to build both. Leave the v2 `cipherstashFromStack` **unchanged**, and add a v3-only entry point. A given client is v2 or v3; mixed v2+v3 columns in one client are unsupported this release.

Create `packages/prisma-next/src/stack/from-stack-v3.ts`:

```ts
import type { ClientConfig } from '@cipherstash/stack'
import { EncryptionV3 } from '@cipherstash/stack/v3' // confirm the v3 client entry path (Step 8 note)
import { isCipherstashV3CodecId } from '../extension-metadata/constants-v3'
import { bulkEncryptMiddlewareV3 } from '../v3/bulk-encrypt-v3'
import { assertV3SchemasAgree } from '../v3/from-stack-v3-validate'
import { deriveStackSchemasV3 } from '../v3/derive-schemas-v3'
import { createCipherstashV3RuntimeDescriptor } from '../v3/runtime-v3'
import { createCipherstashV3Sdk } from '../v3/sdk-adapter-v3'

export interface CipherstashFromStackV3Options {
  readonly contractJson: unknown
  readonly schemasV3?: ReadonlyArray<import('@cipherstash/stack/eql/v3').AnyV3Table>
  readonly encryptionConfig?: ClientConfig
}

/**
 * v3-only stack entry point. A v3 client is v3-only: a contract carrying a v2
 * codec id is the WRONG entry point (mixed v2+v3 in one client is unsupported —
 * decision 1b), and is a hard error rather than a silently-derived v2 column.
 */
export async function cipherstashFromStackV3(
  opts: CipherstashFromStackV3Options,
): Promise<CipherstashFromStackResult> {
  const foreignV2 = collectV2CodecIds(opts.contractJson) // any codecId that is NOT isCipherstashV3CodecId
  if (foreignV2.length > 0) {
    throw new Error(
      `cipherstashFromStackV3: contract.json contains v2 codec ids [${foreignV2.join(', ')}]. ` +
        'A v3 client is v3-only; use cipherstashFromStack for a v2 contract. Mixed v2+v3 in one client is unsupported.',
    )
  }

  const derivedV3 = deriveStackSchemasV3(opts.contractJson)
  if (derivedV3.length === 0) {
    throw new Error(
      'cipherstashFromStackV3: no v3 cipherstash columns in contract.json. Declare at least one v3 cipherstash.Encrypted*() column and re-emit.',
    )
  }

  if (opts.schemasV3) {
    const overrideByName = new Map(opts.schemasV3.map((t) => [t.tableName, t]))
    for (const dt of derivedV3) {
      const ot = overrideByName.get(dt.tableName)
      if (ot) assertV3SchemasAgree(dt, ot) // exact domain identity: integer_ord ≠ integer_ord_ore
    }
  }

  const [f, ...r] = derivedV3
  const clientV3 = await EncryptionV3({
    schemas: [f!, ...r] as never,
    ...(opts.encryptionConfig ? { config: opts.encryptionConfig } : {}),
  })
  const sdkV3 = createCipherstashV3Sdk(clientV3 as never, derivedV3)
  return {
    extensions: [createCipherstashV3RuntimeDescriptor({ sdk: sdkV3 })],
    middleware: [bulkEncryptMiddlewareV3(sdkV3)],
    encryptionClient: clientV3 as never,
  }
}

/** Walk the contract columns and collect every codecId that is not a v3 id. */
function collectV2CodecIds(contractJson: unknown): string[] {
  const ids = new Set<string>()
  for (const col of iterateContractColumns(contractJson)) {
    if (typeof col.codecId === 'string' && col.codecId.startsWith('cipherstash/') && !isCipherstashV3CodecId(col.codecId)) {
      ids.add(col.codecId)
    }
  }
  return [...ids]
}
```

(`iterateContractColumns` is the same contract walker `deriveStackSchemasV3` uses.) The v2 `cipherstashFromStack` keeps its signature and body untouched.

- [ ] **Step 7: Export the v3 surface**

In `packages/prisma-next/src/exports/runtime.ts` add:

```ts
export { EncryptedNumber } from '../v3/envelope-number'
export { createCipherstashV3RuntimeDescriptor } from '../v3/runtime-v3'
export { createV3CodecDescriptors } from '../v3/codec-runtime-v3'
export { cipherstashV3QueryOperations, EncryptionOperatorError } from '../v3/operators-v3'
export { bulkEncryptMiddlewareV3 } from '../v3/bulk-encrypt-v3'
export { v3FromDriver, v3ToDriver } from '../v3/wire-v3'
```

In `packages/prisma-next/src/exports/stack.ts` add:

```ts
export { deriveStackSchemasV3 } from '../v3/derive-schemas-v3'
export { createCipherstashV3Sdk } from '../v3/sdk-adapter-v3'
export { assertV3SchemasAgree } from '../v3/from-stack-v3-validate'
```

- [ ] **Step 8: Run and commit**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/derive-schemas-v3 v3/sdk-adapter-v3 v3/from-stack-divergence-v3 && pnpm --filter @cipherstash/prisma-next build`
Expected: PASS + build clean. (If the stack v3 client is exported from a subpath other than `@cipherstash/stack/v3`, grep `packages/stack/package.json` `exports` for the `EncryptionV3` entry and adjust the import in Step 6.)

```bash
git add packages/prisma-next/src/v3/derive-schemas-v3.ts packages/prisma-next/src/v3/sdk-adapter-v3.ts packages/prisma-next/src/v3/runtime-v3.ts packages/prisma-next/src/v3/from-stack-v3-validate.ts packages/prisma-next/src/stack/from-stack.ts packages/prisma-next/src/exports/stack.ts packages/prisma-next/src/exports/runtime.ts packages/prisma-next/test/v3/derive-schemas-v3.test.ts packages/prisma-next/test/v3/sdk-adapter-v3.test.ts packages/prisma-next/test/v3/from-stack-divergence-v3.test.ts
git commit -m "feat(prisma-next): v3 derivation, SDK adapter, runtime descriptor, two-client from-stack dispatch"
```

---

### Task 8: v3 bundle baseline migration (SQL from `@cipherstash/eql/sql`)

Add a v3 baseline migration `20260601T0100_install_eql_v3_bundle` with invariant `cipherstash:install-eql-v3-bundle-v1`, whose install SQL is sourced at emit time from `@cipherstash/eql/sql` (`readInstallSql()` / `releaseManifest.eqlVersion`, `@cipherstash/eql@3.0.0-alpha.3` — the same source `packages/stack/scripts/install-eql-v3.ts` / `installEqlV3IfNeeded` use), NOT a hand-vendored FFI fixture. Wire it into the control descriptor after the v2 baseline. v3 columns emit **no** `add_search_config`/`remove_search_config`.

**Files:**
- Modify: `packages/prisma-next/package.json` (add `@cipherstash/eql` devDependency)
- Create: `packages/prisma-next/src/migration/eql-bundle-v3.ts`, `packages/prisma-next/migrations/20260601T0100_install_eql_v3_bundle/migration.ts`
- Generated by running `migration.ts`: `migration.json`, `ops.json`, `end-contract.json`, updated `migrations/refs/head.json`
- Modify: `packages/prisma-next/src/exports/control.ts`
- Test: `packages/prisma-next/test/v3/migration-v3.test.ts`

**Interfaces:**
- Consumes: `@cipherstash/eql/sql` `readInstallSql()`, `releaseManifest`; Task 2 `CIPHERSTASH_V3_INVARIANTS`, `CIPHERSTASH_V3_BASELINE_MIGRATION_NAME`; framework `Migration`, `MigrationCLI`, `rawSql` (`@prisma-next/target-postgres/migration`); `contractSpaceFromJson`.
- Produces: `eql-bundle-v3.ts` (re-export of `readInstallSql` / `releaseManifest`); the migration module + emitted artifacts.

- [ ] **Step 1: Add the `@cipherstash/eql` devDependency**

Edit `packages/prisma-next/package.json` — add to `devDependencies`:

```json
"@cipherstash/eql": "3.0.0-alpha.3",
```

Run: `pnpm install` (repo root). Expected: resolves to the version already in the monorepo (stack's devDep). The SQL is baked into `ops.json` at emit time, so `@cipherstash/eql` stays a devDependency (not a runtime dependency of the published package).

- [ ] **Step 2: Create the bundle re-export**

Create `packages/prisma-next/src/migration/eql-bundle-v3.ts`:

```ts
/**
 * CipherStash EQL v3 install SQL, sourced from `@cipherstash/eql/sql` — the same
 * source the stack install script uses. `readInstallSql()` returns the full
 * bundle that creates the `public.*` domains and the `eql_v3.*` operator
 * functions; `releaseManifest.eqlVersion` identifies the pinned release. The SQL
 * is read at migration EMIT time and baked into `ops.json`.
 */
export { readInstallSql, releaseManifest } from '@cipherstash/eql/sql'
```

- [ ] **Step 3: Create the migration module**

Create `packages/prisma-next/migrations/20260601T0100_install_eql_v3_bundle/migration.ts` (mirror the v2 `20260601T0000_install_eql_bundle/migration.ts`, but v3 invariant, v3 SQL, and a v3 postcheck — a concrete `public.*` domain + the `eql_v3` operator schema exist, and NO `add_search_config`):

```ts
#!/usr/bin/env -S node
import { Migration, MigrationCLI, rawSql } from '@prisma-next/target-postgres/migration'
import { CIPHERSTASH_V3_INVARIANTS } from '../../src/extension-metadata/constants-v3'
import { readInstallSql, releaseManifest } from '../../src/migration/eql-bundle-v3'

const INSTALL_LABEL = `Install EQL v3 bundle (${releaseManifest.eqlVersion}: public.* domains + eql_v3.* functions)`

export default class M extends Migration {
  override describe() {
    // The v3 baseline is the SECOND migration in the cipherstash contract
    // space: `from` is the v2 baseline's `to` (the current head hash — see
    // "Prisma Next 0.14 ground truth" note 5; after the 0.14 upgrade it is
    // sha256:1e86a0160ba305fa74516b6d9449218308b258a51a913c1fc907e629f44568a7).
    // `to` is the storage hash after this migration (see Step 4).
    return {
      from: 'sha256:1e86a0160ba305fa74516b6d9449218308b258a51a913c1fc907e629f44568a7',
      to: 'sha256:REPLACE_WITH_EMITTED_HASH',
    }
  }
  override get operations() {
    return [
      rawSql({
        id: 'cipherstash.install-eql-v3-bundle',
        label: INSTALL_LABEL,
        operationClass: 'additive',
        invariantId: CIPHERSTASH_V3_INVARIANTS.installBundle,
        target: { id: 'postgres' },
        precheck: [],
        execute: [{ description: INSTALL_LABEL, sql: readInstallSql() }],
        postcheck: [
          {
            description: 'verify the eql_v3 operator schema exists',
            sql: "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'eql_v3')",
          },
          {
            description: 'verify the concrete domain public.text_search exists',
            sql: "SELECT to_regtype('public.text_search') IS NOT NULL",
          },
          {
            description: 'verify the eql_v3.eq operator function exists',
            sql: "SELECT to_regprocedure('eql_v3.eq(public.eql_encrypted, jsonb)') IS NOT NULL OR to_regproc('eql_v3.eq') IS NOT NULL",
          },
        ],
      }),
    ]
  }
}

MigrationCLI.run(import.meta.url, M)
```

> Match the exact `rawSql` field names + the `Migration` subclass shape against the v2 `migration.ts`. In particular confirm whether it uses `get operations()` or `override operations()` and the postcheck object keys; copy the v2 shape verbatim, changing only id/label/invariant/sql/postcheck.
>
> **0.14:** the bare structural op factories (`createTable`, `setNotNull`, …) became protected methods on the `Migration` base class in Prisma Next 0.14, but **`rawSql` survives as a free function** and the v2 baseline still imports it — the import above is correct as written (ground-truth note 10).

- [ ] **Step 4: Emit the migration artifacts (0.14 loop — self-emit writes `ops.json` + `migration.json` ONLY)**

> **0.14:** the self-emit does **not** write `end-contract.json`, does **not** print a contract hash, and does **not** touch `migrations/refs/head.json` — all three are manual (ground-truth note 5). The loop below was exercised four times on the upgrade branch.

First decide the `to` hash — it depends on whether this migration changes the extension's declared contract storage:

- **If `src/contract.prisma` is unchanged** (the v3 bundle only creates `public.*` domains + `eql_v3.*` functions, and no config table is added to the contract space), the storage hash does not move: `to` equals `from` (the current head hash) and the edge is **invariant-only**. VERIFY the migration graph (`reconstructGraph` / `readMigrationsDir` in `@prisma-next/migration-tools`) accepts a `from === to` edge before committing to this shape; if it rejects self-loop edges, declare the v3 configuration state in `src/contract.prisma` (mirroring how the v2 space declares `eql_v2_configuration`) so the hash genuinely moves.
- **If the contract space gains v3-visible storage** (e.g. a v3 config table), run the full re-pin loop and use the new hash.

The loop (all from `packages/prisma-next/`):

1. If the contract changed: `pnpm exec prisma-next contract emit` → rewrites `src/contract.{json,d.ts}`; read the new hash from `src/contract.json` → `storage.storageHash`.
2. Copy `src/contract.json` → `migrations/20260601T0100_install_eql_v3_bundle/end-contract.json` and `src/contract.d.ts` → `.../end-contract.d.ts` (for an invariant-only edge these equal the v2 baseline's end-contract — copy them anyway; every on-disk migration package carries its destination snapshot).
3. Replace `REPLACE_WITH_EMITTED_HASH` in `describe().to` with the hash from (1) (or the `from` hash for an invariant-only edge).
4. Self-emit: `pnpm exec tsx migrations/20260601T0100_install_eql_v3_bundle/migration.ts` → writes `ops.json` + `migration.json`.
5. Hand-edit `migrations/refs/head.json`: set `hash` to the v3 `to` hash and append `cipherstash:install-eql-v3-bundle-v1` to `invariants` (keeping `cipherstash:install-eql-bundle-v1`).

- [ ] **Step 5: Wire the v3 baseline into control.ts**

In `packages/prisma-next/src/exports/control.ts`:

```ts
import v3BaselineMetadata from '../../migrations/20260601T0100_install_eql_v3_bundle/migration.json' with { type: 'json' }
import v3BaselineOps from '../../migrations/20260601T0100_install_eql_v3_bundle/ops.json' with { type: 'json' }
import { CIPHERSTASH_V3_BASELINE_MIGRATION_NAME } from '../extension-metadata/constants-v3'
// ...
  migrations: [
    { dirName: CIPHERSTASH_BASELINE_MIGRATION_NAME, metadata: baselineMetadata, ops: baselineOps },
    { dirName: CIPHERSTASH_V3_BASELINE_MIGRATION_NAME, metadata: v3BaselineMetadata, ops: v3BaselineOps },
  ],
```

Do **not** register any v3 codec ids in `controlPlaneHooks` — that omission is what guarantees v3 columns emit no `add_search_config`/`remove_search_config`.

- [ ] **Step 6: Write the migration assertion test**

Create `packages/prisma-next/test/v3/migration-v3.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import v3Ops from '../../migrations/20260601T0100_install_eql_v3_bundle/ops.json'

describe('v3 baseline migration', () => {
  it('installs under the v3 invariant with an additive rawSql op', () => {
    const op = (v3Ops as Array<Record<string, unknown>>)[0]!
    expect(op.invariantId).toBe('cipherstash:install-eql-v3-bundle-v1')
    expect(op.operationClass).toBe('additive')
  })
  it('emits no add_search_config / remove_search_config ops', () => {
    const json = JSON.stringify(v3Ops)
    expect(json).not.toContain('add_search_config')
    expect(json).not.toContain('remove_search_config')
  })
  it('sorts after the v2 baseline', () => {
    expect('20260601T0100_install_eql_v3_bundle' > '20260601T0000_install_eql_bundle').toBe(true)
  })
})
```

- [ ] **Step 7: Run and commit**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/migration-v3 descriptor && pnpm --filter @cipherstash/prisma-next build`
Expected: PASS (including the existing `descriptor.test.ts` self-consistency check with the second migration wired — note it already passes `sqlContractCanonicalizationHooks` to `assertDescriptorSelfConsistency`, required since 0.12, and its "head ref tracks the latest migration's `to`" assertion will now point at the v3 baseline; ground-truth notes 5–6).

```bash
git add packages/prisma-next/package.json packages/prisma-next/src/migration/eql-bundle-v3.ts packages/prisma-next/migrations/20260601T0100_install_eql_v3_bundle packages/prisma-next/migrations/refs/head.json packages/prisma-next/src/exports/control.ts packages/prisma-next/test/v3/migration-v3.test.ts ../../pnpm-lock.yaml
git commit -m "feat(prisma-next): v3 bundle baseline migration from @cipherstash/eql/sql (install-eql-v3-bundle-v1)"
```

---

### Task 9: Property-based tests (`fast-check`)

Add `fast-check ^4.8.0` as a prisma-next devDependency and cover the five required properties. (There is no resolver, so there is no resolver-totality property — the constructor↔domain totality property replaces it.)

**Files:**
- Modify: `packages/prisma-next/package.json` (devDependencies)
- Create: `packages/prisma-next/test/v3/properties.test.ts`

**Interfaces:**
- Consumes: `fast-check`; Task 4 `v3ToDriver`/`v3FromDriver`, `EncryptedNumber`; Task 1 `V3_DOMAIN_META_BY_CODEC_ID`, `EXPOSED_DOMAIN_ENTRIES`; Task 3 `v3PascalName`; Task 6 `EncryptionOperatorError`; Task 7 `deriveStackSchemasV3`; `cipherstashAuthoringTypes`.

- [ ] **Step 1: Add the devDependency**

Edit `packages/prisma-next/package.json` — add to `devDependencies`:

```json
"fast-check": "^4.8.0",
```

Run: `pnpm install` (repo root). Expected: resolves to the monorepo catalog version already present in `packages/drizzle`.

- [ ] **Step 2: Write the five properties**

Create `packages/prisma-next/test/v3/properties.test.ts`:

```ts
import fc from 'fast-check'
import { describe, expect, it } from 'vitest'
import { cipherstashAuthoringTypes, v3PascalName } from '../../src/contract-authoring'
import { EncryptedNumber } from '../../src/v3/envelope-number'
import { v3FromDriver, v3ToDriver } from '../../src/v3/wire-v3'
import { EXPOSED_DOMAIN_ENTRIES, V3_DOMAIN_META_BY_CODEC_ID } from '../../src/v3/catalog'
import { deriveStackSchemasV3 } from '../../src/v3/derive-schemas-v3'

describe('property: JSONB round-trip', () => {
  it('v3FromDriver(v3ToDriver(x)) deep-equals x; null/undefined -> null', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (x) => {
        expect(v3FromDriver(v3ToDriver(x))).toEqual(x)
      }),
    )
    expect(v3ToDriver(null)).toBeNull()
    expect(v3ToDriver(undefined)).toBeNull()
  })
})

describe('property: [REDACTED] invariant', () => {
  it('serialized envelope never contains the plaintext and always renders the placeholder', () => {
    fc.assert(
      fc.property(fc.double({ noNaN: true }), (n) => {
        const env = EncryptedNumber.from(n)
        expect(JSON.stringify(env)).toBe('{"$encryptedNumber":"<opaque>"}')
        expect(String(env)).toBe('[REDACTED]')
        expect(`${env}`).not.toContain(String(n))
      }),
    )
  })
})

describe('property: constructor↔domain totality (public.*)', () => {
  const ns = cipherstashAuthoringTypes.cipherstash as Record<string, { output: Record<string, unknown> }>
  it('every exposed domain has exactly one constructor whose descriptor equals the catalog values', () => {
    fc.assert(
      fc.property(fc.constantFrom(...EXPOSED_DOMAIN_ENTRIES), ([codecId, meta]) => {
        const ctor = ns[v3PascalName(meta.bareDomain)]
        expect(ctor).toBeDefined()
        expect(ctor.output.codecId).toBe(codecId)
        expect(ctor.output.nativeType).toBe(meta.nativeType)
        expect(meta.nativeType.startsWith('public.')).toBe(true)
        expect((ctor.output.typeParams as { capabilities: unknown }).capabilities).toEqual(meta.capabilities)
      }),
    )
  })
  it('no constructor maps off-catalog', () => {
    const validNames = new Set(EXPOSED_DOMAIN_ENTRIES.map(([, m]) => v3PascalName(m.bareDomain)))
    for (const name of Object.keys(ns)) {
      if (name.endsWith('V2')) continue
      expect(validNames.has(name), `constructor ${name} is not in the exposed catalog`).toBe(true)
    }
  })
})

describe('property: operator-gating equivalence', () => {
  it('the equality gate allows a domain iff it has a unique or ore index', () => {
    fc.assert(
      fc.property(fc.constantFrom(...V3_DOMAIN_META_BY_CODEC_ID.keys()), (codecId) => {
        const meta = V3_DOMAIN_META_BY_CODEC_ID.get(codecId)!
        const gateAllows = !!(meta.indexes.unique || meta.indexes.ore)
        const predicate = meta.capabilities.equality || meta.capabilities.orderAndRange
        expect(gateAllows).toBe(predicate)
      }),
    )
  })
})

describe('property: derivation round-trip', () => {
  it('arbitrary v3 contract column -> deriveStackSchemasV3 -> derived domain identity == original', () => {
    fc.assert(
      fc.property(fc.constantFrom(...V3_DOMAIN_META_BY_CODEC_ID.entries()), ([codecId, meta]) => {
        const [table] = deriveStackSchemasV3({
          storage: {
            namespaces: {
              public: {
                entries: {
                  table: { user: { columns: { c: { codecId, nativeType: meta.nativeType } } } },
                },
              },
            },
          },
        })
        const col = Object.values(table!.columnBuilders)[0]!
        expect((col as { getEqlType(): string }).getEqlType()).toBe(meta.nativeType)
      }),
    )
  })
})
```

- [ ] **Step 3: Run and commit**

Run: `pnpm --filter @cipherstash/prisma-next test -- v3/properties`
Expected: PASS (5 property blocks).

```bash
git add packages/prisma-next/package.json packages/prisma-next/test/v3/properties.test.ts ../../pnpm-lock.yaml
git commit -m "test(prisma-next): property-based coverage for v3 wire, constructor totality, gating, derivation"
```

---

### Task 10: Bundling isolation + live-PG integration suites

Pin the namespace-separation invariant at the bundle level (v3 entry never pulls the v2 composite codec), and add the seven live-PG suites mirroring the Drizzle branch, installing v3 via `@cipherstash/eql/sql` `readInstallSql()` behind an advisory lock.

**Files:**
- Modify: `packages/prisma-next/test/bundling-isolation.test.ts` (add v3 assertions)
- Create: `packages/prisma-next/test/live/helpers/live-gate.ts`, `packages/prisma-next/test/live/helpers/eql-v3.ts`, and seven suites under `packages/prisma-next/test/live/`
- Modify: `packages/prisma-next/package.json` (optional `test:live` script)

**Interfaces:**
- Consumes: `@cipherstash/eql/sql` `readInstallSql` / `releaseManifest`; `postgres`; the v3 runtime/middleware from Tasks 4–7; the stack `EncryptionV3` client.
- Produces: `LIVE_EQL_V3_PG_ENABLED`, `describeLivePg`, `installEqlV3IfNeeded(sql)` local helpers.

- [ ] **Step 1: Bundling isolation — add v3 forbidden-substring assertions**

In `packages/prisma-next/test/bundling-isolation.test.ts`, assert that no v3-only chunk reachable from the v3 barrel/runtime re-exports includes the v2 composite encoder (`encodeEqlV2EncryptedWire`), reusing the file's existing `collectGraph`/`readChunk` helpers:

```ts
it('v3 codec runtime does not pull the v2 composite-literal codec', () => {
  const v3Chunks = [...collectGraph('runtime.js').entries()].filter(
    ([name]) => name.includes('v3') || name.includes('codec-runtime-v3'),
  )
  for (const [, chunk] of v3Chunks) {
    expect(chunk.body.includes('encodeEqlV2EncryptedWire')).toBe(false)
  }
})
```

> The chunk-name predicate depends on tsup's output; adjust the `.filter` after inspecting `dist/` names.

Run: `pnpm --filter @cipherstash/prisma-next build && pnpm --filter @cipherstash/prisma-next test -- bundling-isolation`
Expected: PASS.

- [ ] **Step 2: Create the local live-PG helpers**

Create `packages/prisma-next/test/live/helpers/live-gate.ts`:

```ts
import { describe } from 'vitest'

export const LIVE_CIPHERSTASH_ENABLED = Boolean(
  process.env.CS_WORKSPACE_CRN && process.env.CS_CLIENT_ID && process.env.CS_CLIENT_KEY && process.env.CS_CLIENT_ACCESS_KEY,
)
export const LIVE_EQL_V3_PG_ENABLED = Boolean(process.env.DATABASE_URL && LIVE_CIPHERSTASH_ENABLED)
export const describeLivePg = LIVE_EQL_V3_PG_ENABLED ? describe : describe.skip
```

Create `packages/prisma-next/test/live/helpers/eql-v3.ts` (mirror `packages/stack/__tests__/helpers/eql-v3.ts` — advisory lock + `eql_v3.version()` staleness probe + `readInstallSql()`):

```ts
import { readInstallSql, releaseManifest } from '@cipherstash/eql/sql'
import type postgres from 'postgres'

const EQL_V3_ADVISORY_LOCK_ID = 3_733_003

async function readEqlV3Version(sql: postgres.Sql): Promise<string | null> {
  const [probe] = await sql<{ present: boolean }[]>`SELECT to_regprocedure('eql_v3.version()') IS NOT NULL AS present`
  if (!probe?.present) return null
  const [row] = await sql<{ version: string }[]>`SELECT eql_v3.version() AS version`
  return row?.version ?? null
}

export async function installEqlV3IfNeeded(sql: postgres.Sql): Promise<void> {
  const reserved = await sql.reserve()
  try {
    await reserved`SELECT pg_advisory_lock(${EQL_V3_ADVISORY_LOCK_ID})`
    try {
      if ((await readEqlV3Version(reserved)) === releaseManifest.eqlVersion) return
      await reserved.unsafe(readInstallSql())
      const installed = await readEqlV3Version(reserved)
      if (installed !== releaseManifest.eqlVersion) {
        throw new Error(`EQL v3 installation did not yield ${releaseManifest.eqlVersion}, got ${installed ?? 'none'}`)
      }
    } finally {
      await reserved`SELECT pg_advisory_unlock(${EQL_V3_ADVISORY_LOCK_ID})`
    }
  } finally {
    reserved.release()
  }
}
```

- [ ] **Step 3: Write the seven live suites (self-skipping)**

Create the following under `packages/prisma-next/test/live/`, each guarded by `describeLivePg`, installing v3 in `beforeAll`, and driving real INSERT/SELECT/decrypt against the `public.*` domains + `eql_v3.*` operators via `cipherstashFromStackV3` (the v3-only entry point — decision 1b) + a real `EncryptionV3` client. Shared skeleton:

```ts
import { afterAll, beforeAll, expect, it } from 'vitest'
import postgres from 'postgres'
import { describeLivePg, LIVE_EQL_V3_PG_ENABLED } from './helpers/live-gate'
import { installEqlV3IfNeeded } from './helpers/eql-v3'

const sql = LIVE_EQL_V3_PG_ENABLED ? postgres(process.env.DATABASE_URL!, { prepare: false }) : undefined
beforeAll(async () => { if (LIVE_EQL_V3_PG_ENABLED && sql) await installEqlV3IfNeeded(sql) })
afterAll(async () => { if (sql) await sql.end() })
```

1. `operators-live-pg.test.ts` — per capability tier (`text_search`, `text_eq`, `integer_ord`, `date_ord`, `timestamp_ord`): encrypt → INSERT → query via each `cipherstash*` operator → decrypt; assert the **expected row is selected** (not just an SQL string).
2. `operators-null-live-pg.test.ts` — null operands and null columns round-trip (insert NULL, select, decrypt to null).
3. `boolean-storage-live-pg.test.ts` — `public.boolean` survives INSERT/SELECT/decrypt and every `cipherstash*` search operator throws `EncryptionOperatorError` (storage-only).
4. `bigint-live-pg.test.ts` — `public.bigint` / `bigint_eq` / `bigint_ord` encrypt → INSERT → query (eq / order-range) → decrypt to a JS `bigint`; assert `typeof decrypted === 'bigint'`, lossless value, and ORE ordering over real domains.
5. `migration-apply-live-pg.test.ts` — apply the v3 bundle (`installEqlV3IfNeeded`); assert `to_regtype('public.text_search')`/`public.integer_ord` are non-null, the `eql_v3` schema exists, the invariant `cipherstash:install-eql-v3-bundle-v1` is recorded (via the migration ops fixture or the runner's marker table), and no `add_search_config` was executed.
6. `bulk-encrypt-live-pg.test.ts` — drive the v3 middleware against a **real** `EncryptionV3(...)` client (not a fake) → INSERT; assert the stored cell parses as JSON and decrypts to the original, proving routing-key stamping + JSONB payloads end-to-end.
7. `side-by-side-clients-live-pg.test.ts` — a v2 client (`cipherstashFromStack`, v2-only contract/table) and a v3 client (`cipherstashFromStackV3`, v3-only contract/table) running in the same process against the same database; insert/query/decrypt through each, proving the two entry points coexist without sharing a registry, descriptor, or dispatch. (Mixed v2+v3 columns in ONE client are unsupported per decision 1b — the spec explicitly excludes a mixed-client live test; this replaces the earlier `mixed-v2-v3-live-pg.test.ts` item, which contradicted it.)

- [ ] **Step 4: Verify self-skip locally, then commit**

Run (no live env): `pnpm --filter @cipherstash/prisma-next test`
Expected: the seven live suites report `skipped`; every non-live suite passes.

```bash
git add packages/prisma-next/test/bundling-isolation.test.ts packages/prisma-next/test/live packages/prisma-next/package.json
git commit -m "test(prisma-next): v3 bundling-isolation + live-PG integration suites"
```

---

### Task 11: Release notes / changeset

**Files:**
- Create: `.changeset/eql-v3-prisma-next.md`

- [ ] **Step 1: Write the changeset**

Create `.changeset/eql-v3-prisma-next.md` (major if the package is treated as stable; the body must call out the new authoring surface regardless — see repo `.changeset/config.json` for the bump policy):

```md
---
"@cipherstash/prisma-next": major
---

**Breaking:** EQL v3 columns are now authored through **concrete per-domain constructors** — the constructor you choose *is* the capability set. The legacy boolean-option surface (`EncryptedString({ equality, freeTextSearch, orderAndRange })`) is not carried into v3.

- New per-domain constructors, one per exposed `public.*` domain:
  - Text: `EncryptedText` (storage), `EncryptedTextEq`, `EncryptedTextOrd` (eq + order/range), `EncryptedTextMatch` (free-text), `EncryptedTextSearch` (eq + free-text + order/range).
  - Scalars (Integer, Smallint, BigInt, Numeric, Real, Double, Date, Timestamp): `Encrypted<Fam>` (storage), `Encrypted<Fam>Eq`, `Encrypted<Fam>Ord`.
  - `EncryptedBoolean` — storage-only (`public.boolean`); there is no boolean equality constructor.
- **Impossible capability combinations have no constructor** (e.g. text equality + free-text without order/range) — they are unrepresentable, not runtime errors.
- **BigInt is a first-class v3 family** (`EncryptedBigInt` / `EncryptedBigIntEq` / `EncryptedBigIntOrd`, JS `bigint` plaintext, backed by `public.bigint*`).
- **Searchable JSON has no v3 constructor.** Use `EncryptedJsonV2`.
- Use the `*V2` constructors (`EncryptedStringV2`, `EncryptedDoubleV2`, `EncryptedBigIntV2`, `EncryptedDateV2`, `EncryptedBooleanV2`, `EncryptedJsonV2`) to keep EQL v2 columns.
- Query operators (`cipherstashEq`, `cipherstashGt`, …) lower to the two-arg `eql_v3.*(...::jsonb)` functions for v3 columns; `cipherstashIlike` maps to `eql_v3.contains` (bloom-filter token containment, not SQL `LIKE`). The domains are `public.*`; the operator functions live in `eql_v3`.
- A new baseline migration `20260601T0100_install_eql_v3_bundle` (invariant `cipherstash:install-eql-v3-bundle-v1`) installs the `public.*` domains and `eql_v3.*` functions. Regenerate contracts and run migrations after changing constructors.
```

- [ ] **Step 2: Full green + commit**

Run: `pnpm --filter @cipherstash/prisma-next test && pnpm --filter @cipherstash/prisma-next build && pnpm --filter @cipherstash/prisma-next lint`
Expected: all PASS. Because Task 1 touched `@cipherstash/stack` public exports, also run: `pnpm --filter @cipherstash/stack test`.

```bash
git add .changeset/eql-v3-prisma-next.md
git commit -m "docs(prisma-next): changeset for EQL v3 per-domain authoring surface"
```

---

## Self-Review

**1. Spec coverage** — each spec section maps to a task:

| Spec section | Task(s) |
| --- | --- |
| Goal / Public Authoring Surface (per-domain constructors + `*V2`) | 3 |
| Namespace Separation (dedicated `src/v3/`, separate v2/v3 entry points — decision 1b) | 1–10 (structural); v3 entry point in 7 |
| Source of Truth (import `DOMAIN_REGISTRY`, derive; codec id strips `public.`) | 1, 2 |
| Schema split (native types `public.*`; operator functions `eql_v3.*`) | 1 (meta), 4 (codec native type), 6 (operator templates); pinned by 2 drift test |
| Constructor Inventory (Encrypted prefix, exclude `*OrdOre`, BigInt first-class, no v3 JSON, boolean storage-only) | 3 |
| Capability semantics per domain | 3 (typeParams), 6 (gating) |
| Contract Representation (concrete codec id, `public.*` nativeType, typeParams castAs/capabilities; drop redundant eqlType; generated closed union; disjoint ids) | 2 (union/disjoint), 3 (representation) |
| Runtime Codecs (plain JSONB; EncryptedNumber sibling; EncryptedBigInt distinct envelope; `[REDACTED]`) | 4 |
| Middleware (separate v3, `sdk.bulkEncrypt`, JSONB, neutral routing-key stamp) | 5 |
| Operators (`eql_v3.* ::jsonb` templates; capability gating; `EncryptionOperatorError`; ilike→contains; no built-in equality traits; per-domain traits) | 6 |
| Schema Derivation + Stack Adapter (v3-only `cipherstashFromStackV3`; single `EncryptionV3` client; distinct extension id; v2 contract = hard error; exact-domain override validation) | 7 |
| Migrations (v3 baseline from `@cipherstash/eql/sql`; invariant; no add_search_config) | 8 |
| Testing → Unit/authoring (14 items) | 1,2,3,4,5,6,7,8 (mapping below) |
| Testing → Property-based (5) | 9 |
| Testing → Integration/live-PG (7) | 10 |
| Release Notes / changeset | 11 |

**14 unit tests → tasks:** (1) authoring static per-domain codec id + `public.*` native type = 3; (2) constructor↔domain 1:1 = 3; (3) `*V2` legacy = 3; (4) unexposed/absent surface (`*OrdOre`, no v3 JSON, boolean storage-only, BigInt present) = 3 + 2 (drift); (5) catalog invariants + `public.*` vs `eql_v3.*` = 2; (6) runtime codec plain JSONB / no composite = 4; (7) middleware `sdk.bulkEncrypt` + JSONB = 5; (8) operator SQL lowering = 6; (9) operator gating = 6; (10) trait removal = 6; (11) derivation exact schemas = 7; (12) same-cast_as different-domain divergence = 7; (13) bundling isolation = 10; (14) codec-id disjointness = 2. **All 14 present.** **5 properties** all in Task 9. **7 live suites** all in Task 10.

**Removed vs. the old (stale) plan:**
- **Old Task 4** (`resolveV3Domain` pure resolver) and **old Task 5** (`cipherstashV3ContractSource` / `source.load` wrapper) are **deleted** — design A has no resolution stage. The "family codec id / Stage 1 / Stage 2 / boolean-option" model and the pinned boolean/bigint/json error strings are gone.
- Old family constructors + boolean-option authoring replaced by derived per-domain constructors (Task 3).
- Old `eql_v3.*` **native types** corrected to `public.*` throughout (catalog, codec descriptors, derivation, override validation); operator **functions** stay `eql_v3.*`.
- Old hand-vendored FFI install fixture replaced by `@cipherstash/eql/sql` `readInstallSql()` (Task 8).
- Boolean domain corrected from `bool` → `boolean` (`public.boolean`, codec id `cipherstash/eql-v3/boolean@1`).
- BigInt promoted from "throws / unavailable" to a first-class family; `EncryptedBigInt` envelope reused (not recreated).

**2. Placeholder scan** — no `TBD`/`TODO`/"add error handling"/"similar to Task N" left. Every code step shows real code. The remaining "confirm at implementation time" notes (framework static-typeParams shape in Task 3 Step 0; `envelope-double` shape in Task 4 Step 3; codec import paths in Task 4 Step 6; `columnBuilders` name in Task 7 Step 3; `EncryptionV3` entry path in Task 7 Step 6/8; `rawSql` field names in Task 8 Step 3; tsup chunk names in Task 10 Step 1) are each a concrete verification against a named file with a stated fallback, not a deferred design decision.

**3. Type consistency** — names verified stable across tasks:
- Task 1 → `V3CastAs`, `V3DomainMeta`, `toV3CodecId`, `V3_DOMAIN_META_BY_CODEC_ID`, `V3_CODEC_IDS`, `V3_FACTORY_BY_NATIVE_TYPE`, `EXPOSED_DOMAIN_ENTRIES`, `isOrdOreDomain`, `envelopeTypeNameForCastAs` — consumed unchanged in 2,3,4,6,7,9.
- Task 2 → `CipherstashV3CodecId`, `CIPHERSTASH_V3_CODEC_IDS`, `CIPHERSTASH_V3_CODEC_ID_SET`, `isCipherstashV3CodecId`, `v3TraitsForCapabilities`, trait constants, `CIPHERSTASH_V3_INVARIANTS`, `CIPHERSTASH_V3_BASELINE_MIGRATION_NAME` — consumed in 3,4,5,6,7,8.
- Task 3 → `v3PascalName` / `v3CamelName` — consumed in 3 tests, 9.
- Task 4 → `EncryptedNumber` (`typeName='EncryptedNumber'`, distinct from `EncryptedDouble`), `v3ToDriver`/`v3FromDriver`, `createV3CodecDescriptors`, `CipherstashV3CellCodec` — consumed in 5,6,7,9,10.
- Task 5 → `bulkEncryptMiddlewareV3`; exported `stampRoutingKeysFromAst` — consumed in 7.
- Task 6 → `cipherstashV3QueryOperations`, `EncryptionOperatorError` — consumed in 7,9,10.
- Task 7 → `deriveStackSchemasV3`, `V3ContractShape`, `createCipherstashV3Sdk`, `createCipherstashV3RuntimeDescriptor`, `assertV3SchemasAgree` — consumed in 9 (derivation), 10 (live).
- `EncryptedBigInt` is REUSED from `../execution/envelope-bigint` in 4 and 6 (never recreated); `EncryptedString`/`EncryptedDate`/`EncryptedBoolean` reused identically.

No signature drift found. Plan is internally consistent.

---

**Plan complete and saved to `docs/superpowers/plans/2026-07-08-eql-v3-prisma-next.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — a fresh subagent per task, review between tasks, fast iteration.

**2. Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints.

**Which approach?**
