# EQL v3 `text_search` Schema DSL Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an EQL v3 authoring DSL (`encryptedTextSearchColumn`, plus v3 `encryptedTable` / `buildEncryptConfig`) on a new `@cipherstash/stack/schema/v3` subpath that emits the existing `EncryptConfig` shape with zero native-client changes.

**Architecture:** A new, self-contained module at `packages/stack/src/schema/v3/index.ts` mirrors the v2 builder structure but exposes one concrete type — `EncryptedTextSearchColumn` — whose capabilities (equality + order/range + free-text match) are baked in. Its `build()` returns the **same** `ColumnSchema` a fully-configured v2 column produces, so the encryption client, payload, and query paths are untouched. The v2 module (`src/schema/index.ts`) is not modified.

**Tech Stack:** TypeScript (ES2022, bundler module resolution), Zod 3.25.76, Vitest 3, tsup (dual ESM+CJS build), Biome (formatting/lint).

## Review dispositions

Code-review feedback verified against the actual files before incorporation. Verdicts and what changed:

- **[VALID] `token_filters: []` nullish-merge edge is untested.** Confirmed `[] ?? x` evaluates to `[]` (an empty array is not nullish), so an explicit `token_filters: []` DOES override the downcase default through the `?? ` merge. v2 tests this (`schema-builders.test.ts:87-103` passes `token_filters: []` and asserts `[]` survives). The v3 plan's override test (Task 1, Step 1) deliberately omitted `token_filters` and never exercised the explicit-empty-array path. **Change:** added a dedicated `.freeTextSearch({ token_filters: [] })` override test asserting `match.token_filters === []`.
- **[VALID] Repeated `.freeTextSearch()` calls are untested.** Confirmed the sketched v3 `freeTextSearch()` (like v2 `src/schema/index.ts:353-367`) re-merges each call against a fresh defaults object (`defaultMatchOpts()` after the batch-2 factory change), NOT against current state — so `.freeTextSearch({ k: 8 }).freeTextSearch({ m: 4096 })` resets `k` back to `6` (last-call-wins-fully). This matches v2 exactly, so per the "mirror v2 exactly" global constraint we KEEP this behavior rather than switching to merge-against-current (which would diverge from v2). **Change:** added a repeated-call test that pins the v2-consistent last-call-wins-fully semantics.
- **[VALID] Type-level tests don't run in CI (pre-existing repo issue).** Confirmed `vitest.config.ts` has no `typecheck` block, `package.json` `test` script is `vitest run` (no `--typecheck`), and `.github/workflows/tests.yml` runs `pnpm run test`. Vitest only collects `*.test-d.ts` under typecheck mode, so the existing `__tests__/types.test-d.ts` is ALSO unenforced in CI today. **Change:** added Task 4, Step 4 — add a `test:types` package script. (Batch 2 finalizes the CI decision: scope typecheck + wire into CI — see below.)
- **[VALID] Dead-code remap in `InferPlaintext`/`InferEncrypted`.** In v3's flat single-type model `EncryptedV3TableColumn = { [key: string]: EncryptedTextSearchColumn }`, the `as C[K] extends EncryptedTextSearchColumn ? K : never` key-remap filters nothing (every value is already that type). v2 needs the filter because its column map also admits nested-object branches (`src/schema/index.ts:526`, `548`). **Change:** simplified both helpers to `{ [K in keyof C]: string }` / `{ [K in keyof C]: Encrypted }` with a comment marking the filter as a future extension point for when more v3 concrete types land.
- **[VALID] API surface bloat: three ways to read one literal.** v2 exposes column metadata via methods only (`getName()`, `build()` — no getters: `src/schema/index.ts:240-407`). The plan exposed the eql type via a `get eqlType` getter AND `getEqlType()` AND an exported const. **Change (partial):** dropped the `get eqlType` property getter; kept `getEqlType()` (method, matching v2 convention) and the exported `TEXT_SEARCH_EQL_TYPE` const (the single source-of-truth literal, useful for external comparison without instantiation). Updated the constraint, the interface list, and the test that asserted `col.eqlType`.
- **[VALID] Assertions.** **Changes:** switched the load-bearing/default `build()` assertions to `toStrictEqual` (catches stray `undefined` keys); switched the two column-instance type checks from the looser `toMatchTypeOf` to `toEqualTypeOf`; added a negative `@ts-expect-error` type test proving a v2 `EncryptedColumn` is rejected by the v3 `EncryptedV3TableColumn` constraint (v2/v3 column classes carry different private fields, so they are nominally non-assignable — the rejection is real).
- **[VALID] Type tightening.** **Changes:** tightened `InferPlaintext`/`InferEncrypted` constraints from `EncryptedTable<any>` to `EncryptedTable<EncryptedV3TableColumn>`; inlined the pointless `const castAs: CastAs = 'string'` local into `cast_as: 'string'` (the `ColumnSchema` return type already checks the literal against `CastAs`), and dropped the now-unused `CastAs` import.

### Batch 2 — scope decision + further review

**SCOPE DECISION (Option A): v3 must WORK with the client.** This increment now includes widening the public client types so the v3 builders are accepted by `Encryption` / `encrypt` / `decrypt` / `encryptQuery`. Verified the runtime path is purely structural — no `instanceof` anywhere in `src/encryption/operations/*.ts`; the client only reads `column.getName()` (`encrypt.ts:53` etc.), `column.build()` (`encryption/helpers/infer-index-type.ts:11,58`), `table.tableName` (`encrypt.ts:52` etc.), `table.build().columns` (`encryption/helpers/model-helpers.ts:268,566`; dynamodb ops), and `buildEncryptConfig(...schemas)` which calls `tb.build()` (`encryption/index.ts:674`). The blocking types are in `src/types.ts`: `EncryptionClientConfig.schemas` (:98), `EncryptOptions.column`/`table` (:113-114), `SearchTerm` (:123-128) / `QueryTermBase` (:275-280) `.column`/`.table` — all typed against nominal v2 classes (private fields → v3 class not assignable). **Added Task 5** to widen these to a structural contract; runtime is untouched.

- **[VALID — real latent bug] Shared mutable defaults.** Confirmed in the plan's sketch: `this.matchOpts = { ...DEFAULT_MATCH_OPTS }` is a SHALLOW copy, so the module-level `DEFAULT_MATCH_OPTS.tokenizer` and `.token_filters` (and the `{ kind: 'downcase' }` object inside) are shared by reference across every column built from defaults; `.freeTextSearch()` re-uses those same refs on the `?? ` fallback; and `build()` returns `this.matchOpts` directly. So a caller mutating one built config can mutate the shared defaults used by later columns (cross-column aliasing). **v2 comparison:** v2 (`src/schema/index.ts:353-367`) constructs FRESH inline object literals each `freeTextSearch()` call (no shared module-level const), so it has no cross-column aliasing — but its `build()` still returns `this.indexesValue` by reference, a milder self-aliasing latent issue. Not fixing v2 here. **Change (Task 1):** replaced the `DEFAULT_MATCH_OPTS` const with a `defaultMatchOpts()` factory (fresh nested objects per call) and made `build()` return a deep-cloned `match` block; added a two-column independent-mutation test.
- **[VALID] Missing changeset.** Confirmed the repo uses Changesets (`.changeset/config.json`, sample `.changeset/native-binary-guards.md`). Frontmatter key is the package `name`; `packages/stack/package.json` name is `@cipherstash/stack`. **Change: added Task 6** to create a `.changeset/*.md` with a **minor** bump (additive `./schema/v3` subpath + exports, plus backward-compatible type widening).
- **[VALID] Task 4 TDD label.** "Write the failing type test" contradicted "run to verify it passes" — these type tests are expected green on first run. **Change:** renamed Task 4 Step 1 to "Write type-level regression tests" and adjusted the surrounding wording so the sequencing is honest.
- **[CI — scoped path chosen, with finding] Enforce v3 type tests in CI.** Ran `pnpm exec vitest --run --typecheck __tests__/types.test-d.ts`: the `types.test-d.ts` assertions PASS (18 passed, "Type Errors: no errors"), but the package-wide typecheck surfaces **124 pre-existing "Unhandled Source Error"s** — `src/wasm-inline.ts` can't resolve `@cipherstash/auth/wasm-inline` / `@cipherstash/protect-ffi/wasm-inline` type decls, plus a type mismatch in `__tests__/wasm-inline-normalize.test.ts:69`. Root cause: `tsconfig.json` has NO `include`, so typecheck checks every file. Verified `@/encryption` does NOT import `wasm-inline.ts`, so a typecheck program rooted only at the `*.test-d.ts` files (which import `@/schema`, `@/schema/v3`, `@/types`, `@/encryption`) will not reach the broken modules. **Decision (per coordinator's "scope safely"):** SCOPE Vitest typecheck to the stack package's type-test files via a dedicated narrow `tsconfig.typecheck.json`, add a `test:types` script, and wire THAT into CI — so v3 (and the existing) type tests are enforced without forcing a repo-wide cleanup. The 124 latent wasm-inline typecheck errors are recorded as a flagged follow-up, NOT fixed here. (See Task 4 — scoped config/script in Steps 2-3, CI wiring in Step 5; flag refined in Batch 3 below.)

### Batch 3 — widen internal consumers + tighten typecheck scoping

- **[VALID — real gap] Task 5 widened only the public aliases, not the internal consumers.** Verified that widening `EncryptOptions` / `SearchTerm` / `QueryTermBase` to `BuildableColumn` / `BuildableTable` breaks internal code that stores those values into narrow v2-typed fields. Concretely: `operations/encrypt.ts` declares `private column: EncryptedColumn | EncryptedField` (:27) / `private table: EncryptedTable<EncryptedTableColumn>` (:28), assigns `opts.column`/`opts.table` into them (:38-39), and re-exposes them via `getOperation()` (:112-113); `operations/bulk-encrypt.ts` has the same fields (:66-67) plus the module-level `createEncryptPayloads(column: EncryptedColumn | EncryptedField, table: EncryptedTable<EncryptedTableColumn>)` (:28-29); `helpers/infer-index-type.ts` types `inferIndexType` (:10), `validateIndexType` (:55), `resolveIndexType` (:87) as `column: EncryptedColumn` and they are called with the now-widened `term.column` / `opts.column`. **Verified the contract is sufficient (no over-widening / no richer contract needed):** every one of these consumers only ever calls `.getName()`, `.tableName`, and `column.build().indexes` — all present on `BuildableColumn` / `BuildableTable` (`build(): ColumnSchema` exposes `.indexes`). **Verified NOT affected (so we don't over-reach):** `EncryptionClient` stores only `client` + `encryptConfig` (no narrow `schemas` field; methods pass `opts` straight to the operation constructors at `index.ts:203,575,298`), so no client-field change; `operations/encrypt-query.ts` / `batch-encrypt-query.ts` store the *public* widened types (`EncryptQueryOptions` / `ScalarQueryTerm[]`) with no narrow re-declaration, so they need no edit; and the MODEL path (`encrypt-model.ts`, `bulk-encrypt-models.ts`, `model-helpers.ts`) stays narrow (`EncryptedTable<EncryptedTableColumn>` / `EncryptedTable<S>`) because the generic model methods are intentionally NOT widened — so those files are untouched. **Change:** expanded Task 5's file list + steps to also widen `operations/encrypt.ts`, `operations/bulk-encrypt.ts`, and `helpers/infer-index-type.ts` (each with the exact fields/signatures + line refs), with an explicit "do NOT widen the model path" guard.
- **[VALID] `test:types` could run runtime suites.** `vitest --run --typecheck` enables typecheck but still runs the runtime suites too (including credential/network-sensitive ones). Verified the repo's Vitest is **3.2.4** (`package.json` `"vitest": "catalog:repo"` → `3.2.4`), which supports `--typecheck.only`. **Change:** `test:types` is now `vitest --run --typecheck.only` (typecheck enabled, runtime suites skipped), with `tsconfig`/`include` set in `vitest.config.ts`; CI calls the same script.
- **[VALID] First typecheck run was unscoped.** Task 4's old Step 2 ran `vitest --run --typecheck __tests__/schema-v3.test-d.ts` BEFORE the scoped `tsconfig.typecheck.json` existed (created in the old Step 4), so the very first run would hit the 124 unrelated errors. **Change:** reordered Task 4 so the scoped `tsconfig.typecheck.json` + `vitest.config.ts` `typecheck` block + `test:types` script are created FIRST (new Step 2); every typecheck invocation (Task 4 and Task 5's failing-first run) goes through `pnpm run test:types`, which is scoped from the very first run.
- **[VALID] Duplicate `Encrypted` import.** Task 4 Step 1 already adds `import type { Encrypted } from '@/types'`; Task 5 Step 1 repeated it. **Change:** Task 5 now adds ONLY the genuinely new imports (`Encryption, EncryptionClient` from `@/encryption`; `encryptedTable as v2EncryptedTable` extending the existing `@/schema` import) and reuses the already-imported `Encrypted`.

### Batch 4 — split the query column contract (encryptQuery must reject non-queryable fields)

- **[VALID — type-safety regression in batch-2/3 widening] `encryptQuery` was widened too far.** Batch 2 widened `SearchTerm.column` / `QueryTermBase.column` from the nominal `EncryptedColumn` to the structural `BuildableColumn`. Verified the problem: `BuildableColumn` (`{ getName(): string; build(): ColumnSchema }`) is INTENTIONALLY also satisfied by v2 `EncryptedField` (confirmed `EncryptedField` at `src/schema/index.ts:197` has `getName()` (:235) and `build()` returning `{ cast_as, indexes: {} }` (:228)) — that structural match is REQUIRED so `encrypt()` can still target nested fields. Side effect: widening the query path to `BuildableColumn` would make `encryptQuery()` type-callable with an `encryptedField(...)`, which has no indexes and which the original nominal `EncryptedColumn` correctly rejected; it would only blow up at runtime ("no indexes configured"). **Fix:** keep `encrypt`'s storage path at `BuildableColumn` (columns AND fields), but give the query path its own narrower contract `BuildableQueryColumn = EncryptedColumn | (BuildableColumn & { getEqlType(): string })`. Verified `getEqlType()` is a sound discriminator: a `grep` for `getEqlType` across `src/` returns nothing today (v3 not implemented), v2 `EncryptedColumn`/`EncryptedField` do NOT declare it, and only v3 `EncryptedTextSearchColumn` will — so the nominal arm admits v2 queryable columns, the structural arm admits v3 queryable columns, and `EncryptedField` (no `getEqlType`, not an `EncryptedColumn`) is excluded. Verified the narrowing is safe for the storage path: the `infer-index-type.ts` functions batch-3 widened (`inferIndexType`/`validateIndexType`/`resolveIndexType`) are reached ONLY via `resolveIndexType`, imported solely by `operations/encrypt-query.ts` (:72,:165) and `operations/batch-encrypt-query.ts` (:51) — NOT by `encrypt.ts`/`bulk-encrypt.ts` — so narrowing them to `BuildableQueryColumn` cannot break field encryption. **Change:** `SearchTerm.column` + `QueryTermBase.column` → `BuildableQueryColumn`; `EncryptOptions.column` stays `BuildableColumn`; the three `infer-index-type.ts` signatures take `BuildableQueryColumn` (not `BuildableColumn`); added negative (`encryptQuery` rejects a field) + positive (`encrypt` accepts a field; `encryptQuery` accepts v2 column and v3 column) type tests.
  - **Follow-up flagged (not blocking):** `getEqlType()` works as the queryability discriminator only because the sole v3 type shipping is `text_search`, which is queryable. If a future v3 *non-queryable* concrete type also carries `getEqlType()`, the structural arm would wrongly admit it. When such a type lands, switch the discriminator to a queryability-specific marker (e.g. a `readonly __queryable` brand or an explicit capability method) rather than the generic `getEqlType()`. Kept `getEqlType()` for now.

### Batch 5 — pin the bulk-encrypt widen-site + note the WASM v3 boundary

- **[VALID — should-fix] `bulk-encrypt.ts` widen-site was vague + mislabeled.** The batch-3 step covered the `column`/`table` re-exposure only via a conditional ("if the `*WithLockContext` variant re-exposes … widen those too") with no line ref and the wrong owning class. Verified the real site: it is `BulkEncryptOperation.getOperation()`'s RETURN TYPE at `src/encryption/operations/bulk-encrypt.ts:141-142` (`column: EncryptedColumn | EncryptedField` (:141), `table: EncryptedTable<EncryptedTableColumn>` (:142)) — destructured and consumed by `BulkEncryptOperationWithLockContext.execute()` at :168 (uses only `.getName()` / `.tableName`). It is NOT a member of the `*WithLockContext` class. **Change:** rewrote the `bulk-encrypt.ts` step to pin `:141-142` as a REQUIRED widen-site on `BulkEncryptOperation.getOperation()`, with the corrected class label, so an implementer can't leave `bulk-encrypt.ts` red.
- **[VALID — flag, not blocking] WASM-inline path does not accept v3 columns.** Verified `src/wasm-inline.ts:314-320`: `getColumnName(col: EncryptOptions['column'])` does `if (col instanceof EncryptedColumn || col instanceof EncryptedField) return col.getName(); throw …`. Confirmed (a) it STILL type-checks after the `EncryptOptions['column']` widening — an `instanceof` guard narrowing a wider union is valid TS; and (b) it is OUTSIDE the scoped typecheck graph (`@/encryption` doesn't import `wasm-inline.ts`; the `test:types` tsconfig roots only the `*.test-d.ts` files), so it does NOT make the package red. But a v3 column routed through the WASM-inline entry would hit the `else throw` at RUNTIME. This is consistent with the batch-2 "no `instanceof`" finding being explicitly scoped to `operations/*.ts`. **Change:** added a note to Task 5 (Step 3b) and the spec's known-boundaries that the WASM-inline entry does not yet accept v3 columns — a deferred, documented boundary, not a latent surprise.

### Batch 6 — `Required<MatchIndexOpts>` vs an explicit built type

- **[REFUTED as a bug → applied as robustness] `Required<MatchIndexOpts>` could fail typecheck.** The finding claimed that because `matchIndexOptsSchema` fields are `.default(...).optional()` (`src/schema/index.ts:99-105`), `Required<>` might not strip `undefined` and the plan's `defaultMatchOpts()` / `matchOpts` spread-clone could fail declaration/build typecheck. **Verified and refuted under this repo's actual config:**
  - `tsconfig.json` sets `strict: true`, has **no `extends`** (no base tsconfig), and does **NOT** set `exactOptionalPropertyTypes`.
  - TS's `-?` mapped modifier (`Required<T> = { [K]-?: T[K] }`) DOES strip `undefined` when `exactOptionalPropertyTypes` is off. Reproduced empirically with the repo's TypeScript **5.9.3**: a faithful replica of the plan's exact pattern (`Required<MatchIndexOpts>` factory + private field + the `build()` spread/clone of `tokenizer`/`token_filters` + `.map()` + non-`undefined` assignments) compiles with **ZERO errors** under `--strict` (no EOPT). It only errors (TS2532 / TS2322) when `--exactOptionalPropertyTypes` is forced on — which the repo does not use.
  - **v2 precedent confirms it:** v2 already declares `match?: Required<MatchIndexOpts>` (`src/schema/index.ts:246`, not `:247` — `:247` is `ste_vec`) and the package builds/ships under this tsconfig. So `Required<MatchIndexOpts>` works in-repo today; the "can fail typecheck" premise is false here.
  - **Decision (robustness, NOT a fix):** still adopted `BuiltMatchIndexOpts` (`{ tokenizer: NonNullable<MatchIndexOpts['tokenizer']>; … }`) for `defaultMatchOpts()`'s return type and the private `matchOpts` field, because it states non-null intent explicitly and is decoupled from `Required<>`'s `exactOptionalPropertyTypes`-dependent subtlety. Verified empirically that this explicit type compiles clean BOTH without AND with `exactOptionalPropertyTypes` (so it also future-proofs the new module against a later strictness bump, which `Required<MatchIndexOpts>` would not survive). The public tuning input stays `MatchIndexOpts` (all-optional); only the internal resolved shape uses `BuiltMatchIndexOpts`. The emitted `build()` shape is unchanged (a fully-required object is assignable to the optional `ColumnSchema.indexes.match`).

### Batch 7 — `@ts-expect-error` placement in the Batch-4 negative test

- **[VALID — real defect] Batch-4 negative test placed `@ts-expect-error` on the wrong line.** The Batch-4 test put `// @ts-expect-error` directly above the `client.encryptQuery('…', {` call line, but the `EncryptedField`-not-assignable-to-`BuildableQueryColumn` error is a DEEP object-literal property mismatch that tsc reports on the inner `column:` argument line, not the call's first line. Since `@ts-expect-error` only suppresses the immediately-following line, the directive would be unused → **TS2578 "Unused '@ts-expect-error' directive"** AND the real error would leak from the `column:` line → `schema-v3.test-d.ts` goes red. (Hazard compounded: an implementer "fixing" the TS2578 by deleting the directive would silently delete the negative guarantee.) **Reproduced empirically** with the repo's TypeScript **5.9.3**: directive-above-the-call → TS2578 (at the directive line) + TS2741 (at the `column:` line); directive-directly-above-`column:` (multi-line) or a collapsed one-line call → both clean (no TS2578, no leak). **Fix (Variant B):** moved the `@ts-expect-error` to sit directly above the `column: v2usersWithField.profile.email,` line (kept the call multi-line), matching the placement style of Task 4's negative test, and added an inline comment explaining the deep-property-line requirement.
- **Audit of all other `@ts-expect-error` directives in the plan:** the only other one is Task 4's "rejects a v2 `EncryptedColumn` in a v3 table" test — verified it ALREADY sits directly above the offending `email: encryptedColumn('email'),` property line (the generic-constraint mismatch lands there), so it is correctly placed and needs no change. No other mis-placed directives found.

## Global Constraints

- **Do NOT change** the v2 module's (`packages/stack/src/schema/index.ts`) runtime behavior or the shape of its existing exported symbols. The DSL additions are purely additive. The ONLY permitted edit to this file is a backward-compatible **widening** of `buildEncryptConfig`'s parameter type to the shared structural `BuildableTable` contract (Task 5) — a pure widening (existing callers still type-check) required so the client accepts both v2 and v3 tables. (If the team prefers zero v2 edits, the documented fallback in Task 5 is to assemble the config inline in `Encryption()` instead.)
- **Runtime is structural and unchanged.** The encrypt/decrypt/query path reads only `column.getName()`, `column.build()`, `table.tableName`, `table.build().columns` — no `instanceof`. Client integration is achieved by widening the public TYPES (Task 5), not by a runtime rewrite.
- v3 builders MUST emit the existing `ColumnSchema` / `EncryptConfig` shape imported from `@/schema` — reuse the v2 types, do not redefine them.
- `cast_as` MUST be the SDK-facing literal `'string'` (NOT `'text'`). `toEqlCastAs` is a v2/wasm-inline concern and is out of scope here.
- Match-index defaults MUST mirror the v2 `freeTextSearch()` builder **exactly**: `tokenizer: { kind: 'ngram', token_length: 3 }`, `token_filters: [{ kind: 'downcase' }]`, `k: 6`, `m: 2048`, `include_original: true`. (Note: `include_original` is `true` — the v2 builder default, not the zod-schema default of `false`.)
- `unique.token_filters` defaults to `[]` (case-sensitive equality, matching v2).
- `.freeTextSearch(opts?)` is **tuning only** — it overrides match-index params and NEVER enables a capability. Merge semantics are per-top-level-key replace against the defaults (mirror v2's `opts?.x ?? default`).
- `EncryptedTextSearchColumn` records the eql type `'eql_v3.text_search'`, exposed via the `getEqlType()` method ONLY (no property getter — methods-not-getters matches the v2 builder convention). The single source-of-truth literal is the exported `TEXT_SEARCH_EQL_TYPE` const. This value is metadata for future increments and MUST be absent from `build()` output.
- v3 `encryptedTable` and `buildEncryptConfig` intentionally shadow the v2 symbol names; they live only on the `/v3` subpath. `buildEncryptConfig` emits `{ v: 1, tables }`.
- Tests live in `packages/stack/__tests__/`, named `*.test.ts` (runtime) and `*.test-d.ts` (type-level, run via the scoped `test:types` script with `--typecheck.only` — Task 4). Source imports use the `@/` alias (`@/schema`, `@/schema/v3`, `@/types`).
- Run all commands from `packages/stack/` unless noted. The test runner is `pnpm exec vitest`.
- Keep changes Biome-clean (2-space indent, single quotes, no semicolons — match the surrounding files).

## File Structure

- **Create:** `packages/stack/src/schema/v3/index.ts` — the entire v3 DSL: `EncryptedTextSearchColumn`, v3 `EncryptedTable`, `encryptedTextSearchColumn`, `encryptedTable`, `buildEncryptConfig`, `InferPlaintext`, `InferEncrypted`, and the `EncryptedV3TableColumn` shape type. Single focused file (the spec allows splitting later if it grows).
- **Create:** `packages/stack/__tests__/schema-v3.test.ts` — runtime behavior tests.
- **Create:** `packages/stack/__tests__/schema-v3.test-d.ts` — type-level inference tests.
- **Modify:** `packages/stack/tsup.config.ts` — add `src/schema/v3/index.ts` to the main config's `entry` array.
- **Modify:** `packages/stack/package.json` — add the `./schema/v3` export, `typesVersions` entry, and a `test:types` script.
- **Modify:** `packages/stack/src/types.ts` — define the structural `BuildableColumn` / `BuildableTable` contract and widen `EncryptionClientConfig.schemas`, `EncryptOptions`, `SearchTerm` / `QueryTermBase` to it (Task 5).
- **Modify:** `packages/stack/src/schema/index.ts` — backward-compatible widening of `buildEncryptConfig`'s parameter type ONLY (Task 5; see Global Constraints for the fallback).
- **Modify:** `packages/stack/src/encryption/operations/encrypt.ts`, `.../operations/bulk-encrypt.ts` (storage path → `BuildableColumn` / `BuildableTable`) and `.../helpers/infer-index-type.ts` (query path → `BuildableQueryColumn`) — widen the internal consumers of the widened public types (Task 5, Step 3b).
- **Create:** `packages/stack/tsconfig.typecheck.json` — narrow tsconfig (roots = `__tests__/**/*.test-d.ts`) so Vitest typecheck enforces the type tests without dragging in the 124 pre-existing wasm-inline errors (Task 4).
- **Modify:** `packages/stack/vitest.config.ts` — add a `typecheck` block (include `__tests__/**/*.test-d.ts`, `tsconfig: './tsconfig.typecheck.json'`) (Task 4).
- **Modify:** `.github/workflows/tests.yml` — run the scoped type tests in CI (Task 4).
- **Create:** `.changeset/<name>.md` — minor bump for `@cipherstash/stack` (Task 6).

---

### Task 1: `EncryptedTextSearchColumn` builder

**Files:**
- Create: `packages/stack/src/schema/v3/index.ts`
- Test: `packages/stack/__tests__/schema-v3.test.ts`

**Interfaces:**
- Consumes (from v2, `@/schema`): `type ColumnSchema`, `type MatchIndexOpts`, the runtime builder `encryptedColumn` (test only, for the equivalence assertion). (`CastAs` is NOT consumed — `build()` emits the bare `'string'` literal, checked by the `ColumnSchema` return type.)
- Produces:
  - `class EncryptedTextSearchColumn` with:
    - `constructor(columnName: string)`
    - `freeTextSearch(opts?: MatchIndexOpts): this`
    - `build(): ColumnSchema`
    - `getName(): string`
    - `getEqlType(): 'eql_v3.text_search'` (method only — no `get eqlType` property getter)
  - `function encryptedTextSearchColumn(columnName: string): EncryptedTextSearchColumn`
  - `const TEXT_SEARCH_EQL_TYPE = 'eql_v3.text_search'` (exported const literal)

- [ ] **Step 1: Write the failing tests**

Create `packages/stack/__tests__/schema-v3.test.ts`:

```ts
import { describe, expect, it } from 'vitest'
import { encryptedColumn } from '@/schema'
import {
  EncryptedTextSearchColumn,
  encryptedTextSearchColumn,
} from '@/schema/v3'

describe('eql_v3 text_search column', () => {
  it('returns an EncryptedTextSearchColumn with the correct name', () => {
    const col = encryptedTextSearchColumn('email')
    expect(col).toBeInstanceOf(EncryptedTextSearchColumn)
    expect(col.getName()).toBe('email')
  })

  it('.build() emits the pinned default config (cast_as: string + all three indexes)', () => {
    const built = encryptedTextSearchColumn('email').build()
    // toStrictEqual (not toEqual) so a stray `undefined` key would fail.
    expect(built).toStrictEqual({
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
    })
  })

  it('LOAD-BEARING: default build() deep-equals the v2 equality+order+match column', () => {
    const v3 = encryptedTextSearchColumn('email').build()
    const v2 = encryptedColumn('email')
      .equality()
      .orderAndRange()
      .freeTextSearch()
      .build()
    // toStrictEqual: byte-identical, no extra/undefined keys on either side.
    expect(v3).toStrictEqual(v2)
  })

  it('.freeTextSearch(opts) overrides each provided key and keeps the rest as defaults', () => {
    const built = encryptedTextSearchColumn('email')
      .freeTextSearch({
        tokenizer: { kind: 'ngram', token_length: 4 },
        k: 8,
        m: 4096,
        include_original: false,
      })
      .build()
    expect(built.indexes.match).toEqual({
      tokenizer: { kind: 'ngram', token_length: 4 },
      // omitted -> default downcase filter retained
      token_filters: [{ kind: 'downcase' }],
      k: 8,
      m: 4096,
      include_original: false,
    })
  })

  it('.freeTextSearch({ token_filters: [] }) overrides the downcase default with an empty array', () => {
    // LOAD-BEARING: `[] ?? default` evaluates to `[]` (an empty array is not
    // nullish), so an explicit empty array must OVERRIDE the downcase default,
    // not fall back to it. Mirrors v2 (schema-builders.test.ts).
    const built = encryptedTextSearchColumn('email')
      .freeTextSearch({ token_filters: [] })
      .build()
    expect(built.indexes.match.token_filters).toEqual([])
  })

  it('repeated .freeTextSearch() calls are last-call-wins-fully (each re-merges against defaults, not prior state)', () => {
    // Each call re-merges against a fresh defaultMatchOpts(), not the
    // accumulated matchOpts — so the second call resets k back to its default
    // of 6. This is intentional: it mirrors v2 exactly. Pinned here so a future
    // "merge against current state" change can't silently slip in.
    const built = encryptedTextSearchColumn('email')
      .freeTextSearch({ k: 8 })
      .freeTextSearch({ m: 4096 })
      .build()
    expect(built.indexes.match.k).toBe(6)
    expect(built.indexes.match.m).toBe(4096)
  })

  it('.freeTextSearch() is tuning-only: unique and ore indexes stay present', () => {
    const built = encryptedTextSearchColumn('email')
      .freeTextSearch({ k: 8 })
      .build()
    expect(built.indexes.unique).toEqual({ token_filters: [] })
    expect(built.indexes.ore).toEqual({})
  })

  it('getEqlType() returns the concrete domain name', () => {
    const col = encryptedTextSearchColumn('email')
    expect(col.getEqlType()).toBe('eql_v3.text_search')
  })

  it('eqlType metadata is absent from build() output', () => {
    const built = encryptedTextSearchColumn('email').build()
    expect(built).not.toHaveProperty('eqlType')
    expect(Object.keys(built).sort()).toEqual(['cast_as', 'indexes'])
  })

  it('built columns share no mutable state: mutating one build() output does not affect another', () => {
    // Guards against the shared-defaults aliasing bug: defaults come from a
    // per-instance factory and build() deep-clones the match block.
    const a = encryptedTextSearchColumn('a').build()
    const b = encryptedTextSearchColumn('b').build()

    // Mutate every nested level of a's match block.
    a.indexes.match.k = 999
    a.indexes.match.token_filters.push({ kind: 'downcase' })
    a.indexes.match.tokenizer = { kind: 'standard' }

    expect(b.indexes.match.k).toBe(6)
    expect(b.indexes.match.token_filters).toEqual([{ kind: 'downcase' }])
    expect(b.indexes.match.tokenizer).toEqual({ kind: 'ngram', token_length: 3 })

    // A second build() of an independent column is also pristine.
    const c = encryptedTextSearchColumn('c').build()
    expect(c.indexes.match.k).toBe(6)
    expect(c.indexes.match.token_filters).toEqual([{ kind: 'downcase' }])
  })
})
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm exec vitest run __tests__/schema-v3.test.ts`
Expected: FAIL — module resolution error `Failed to resolve import "@/schema/v3"` (the file does not exist yet).

- [ ] **Step 3: Create the v3 module with the column builder**

Create `packages/stack/src/schema/v3/index.ts`:

```ts
import type { ColumnSchema, MatchIndexOpts } from '@/schema'

/**
 * The concrete EQL v3 domain name for a full-capability text column.
 * Recorded as metadata for future DDL / query-dialect increments; it is
 * intentionally absent from the emitted encrypt config.
 */
export const TEXT_SEARCH_EQL_TYPE = 'eql_v3.text_search'

/**
 * Fully-resolved match-index options: every field present and non-`undefined`.
 *
 * `MatchIndexOpts` (the user-facing tuning input) has all fields optional —
 * each is `.default(...).optional()` in the zod schema, so its inferred type is
 * `T | undefined`. This type pins the BUILT/resolved shape explicitly via
 * `NonNullable<...>`, which states the non-null intent directly and is robust
 * regardless of `Required<>`'s subtle, `exactOptionalPropertyTypes`-dependent
 * stripping semantics. (v2 uses `Required<MatchIndexOpts>` and that compiles
 * fine under this repo's tsconfig — `strict: true`, NO `exactOptionalPropertyTypes`
 * — so this is a clarity/robustness choice, not a fix for a present break.)
 */
type BuiltMatchIndexOpts = {
  tokenizer: NonNullable<MatchIndexOpts['tokenizer']>
  token_filters: NonNullable<MatchIndexOpts['token_filters']>
  k: NonNullable<MatchIndexOpts['k']>
  m: NonNullable<MatchIndexOpts['m']>
  include_original: NonNullable<MatchIndexOpts['include_original']>
}

/**
 * Default match-index parameters. These mirror the v2 `freeTextSearch()`
 * builder defaults EXACTLY (note `include_original: true`, which is the v2
 * builder default rather than the zod-schema default of `false`).
 *
 * This is a FACTORY (not a shared `const`) so every caller gets fresh, unaliased
 * nested objects (`tokenizer`, `token_filters` and the `{ kind: 'downcase' }`
 * inside it). A shared const would be shallow-copied by `{ ...DEFAULT }`, leaving
 * those nested objects aliased across every column — a caller mutating one built
 * config could then corrupt the defaults used by later columns.
 */
function defaultMatchOpts(): BuiltMatchIndexOpts {
  return {
    tokenizer: { kind: 'ngram', token_length: 3 },
    token_filters: [{ kind: 'downcase' }],
    k: 6,
    m: 2048,
    include_original: true,
  }
}

/**
 * Builder for an `eql_v3.text_search` column.
 *
 * The concrete type inherently enables equality + order/range + free-text
 * match — there are no capability-enabling methods. `.freeTextSearch(opts?)`
 * tunes the match index only.
 */
export class EncryptedTextSearchColumn {
  private readonly columnName: string
  private matchOpts: BuiltMatchIndexOpts

  constructor(columnName: string) {
    this.columnName = columnName
    this.matchOpts = defaultMatchOpts()
  }

  /**
   * The concrete EQL v3 domain name. Metadata only; not emitted by `build()`.
   * Method (not a property getter) to match the v2 builder convention.
   */
  getEqlType(): typeof TEXT_SEARCH_EQL_TYPE {
    return TEXT_SEARCH_EQL_TYPE
  }

  /**
   * Tune the match index. Each provided key replaces its default; omitted
   * keys keep the default. This NEVER enables a capability — match is always
   * on for this type. Merge semantics mirror v2's `opts?.x ?? default`.
   */
  freeTextSearch(opts?: MatchIndexOpts): this {
    // A fresh defaults object per call supplies the `?? ` fallbacks, so no
    // nested default object is ever shared into `this.matchOpts` by reference.
    const defaults = defaultMatchOpts()
    this.matchOpts = {
      tokenizer: opts?.tokenizer ?? defaults.tokenizer,
      token_filters: opts?.token_filters ?? defaults.token_filters,
      k: opts?.k ?? defaults.k,
      m: opts?.m ?? defaults.m,
      include_original: opts?.include_original ?? defaults.include_original,
    }
    return this
  }

  /** Emit the encrypt-config column. Byte-identical to a v2 equality+order+match column. */
  build(): ColumnSchema {
    // `cast_as` is typed `CastAs` by the `ColumnSchema` return type, so the
    // literal is checked here without a redundant local annotation.
    //
    // Deep-clone the match block so the returned config NEVER aliases this
    // builder's internal `matchOpts` (or any caller-supplied opts merged into
    // it). A caller mutating the returned object cannot corrupt this builder's
    // state or another column's defaults.
    return {
      cast_as: 'string',
      indexes: {
        unique: { token_filters: [] },
        ore: {},
        match: {
          ...this.matchOpts,
          tokenizer: { ...this.matchOpts.tokenizer },
          token_filters: this.matchOpts.token_filters.map((f) => ({ ...f })),
        },
      },
    }
  }

  getName(): string {
    return this.columnName
  }
}

/**
 * Define an `eql_v3.text_search` column. The concrete type carries all three
 * capabilities (equality + order/range + free-text match). Chain
 * `.freeTextSearch(opts)` to tune the match index.
 */
export function encryptedTextSearchColumn(
  columnName: string,
): EncryptedTextSearchColumn {
  return new EncryptedTextSearchColumn(columnName)
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pnpm exec vitest run __tests__/schema-v3.test.ts`
Expected: PASS (all 10 tests in this describe block green).

- [ ] **Step 5: Commit**

```bash
git add packages/stack/src/schema/v3/index.ts packages/stack/__tests__/schema-v3.test.ts
git commit -m "feat(stack): add eql_v3 text_search column builder"
```

---

### Task 2: v3 `encryptedTable`, `buildEncryptConfig`, and inference helpers

**Files:**
- Modify: `packages/stack/src/schema/v3/index.ts` (append table + config + inference)
- Test: `packages/stack/__tests__/schema-v3.test.ts` (append `describe` blocks)

**Interfaces:**
- Consumes (from v2, `@/schema`): `type ColumnSchema`, `type EncryptConfig`, `encryptConfigSchema` (test only). From `@/types`: `type Encrypted`.
- Consumes (from Task 1): `EncryptedTextSearchColumn`, `encryptedTextSearchColumn`.
- Produces:
  - `type EncryptedV3TableColumn = { [key: string]: EncryptedTextSearchColumn }`
  - `class EncryptedTable<T extends EncryptedV3TableColumn>` with `tableName: string`, `columnBuilders: T`, and `build(): { tableName: string; columns: Record<string, ColumnSchema> }`
  - `function encryptedTable<T extends EncryptedV3TableColumn>(tableName: string, columns: T): EncryptedTable<T> & T`
  - `function buildEncryptConfig(...tables: Array<EncryptedTable<EncryptedV3TableColumn>>): EncryptConfig`
  - `type InferPlaintext<T extends EncryptedTable<EncryptedV3TableColumn>>` → `{ [col]: string }`
  - `type InferEncrypted<T extends EncryptedTable<EncryptedV3TableColumn>>` → `{ [col]: Encrypted }`

- [ ] **Step 1: Write the failing tests**

Append to `packages/stack/__tests__/schema-v3.test.ts`. First add `encryptConfigSchema` to the existing `@/schema` import and the table symbols to the `@/schema/v3` import, so the file header becomes:

```ts
import { describe, expect, it } from 'vitest'
import { encryptConfigSchema, encryptedColumn } from '@/schema'
import {
  buildEncryptConfig,
  EncryptedTable,
  EncryptedTextSearchColumn,
  encryptedTable,
  encryptedTextSearchColumn,
} from '@/schema/v3'
```

Then append these `describe` blocks at the end of the file:

```ts
describe('eql_v3 encryptedTable', () => {
  it('creates a table exposing column builders as properties', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    expect(users).toBeInstanceOf(EncryptedTable)
    expect(users.tableName).toBe('users')
    expect(users.email).toBeInstanceOf(EncryptedTextSearchColumn)
  })

  it('table.email returns the same builder instance passed in', () => {
    const emailCol = encryptedTextSearchColumn('email')
    const users = encryptedTable('users', { email: emailCol })
    expect(users.email).toBe(emailCol)
  })

  it('build() assembles { tableName, columns } with built column configs', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    const built = users.build()
    expect(built.tableName).toBe('users')
    expect(built.columns).toStrictEqual({
      email: {
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
      },
    })
  })
})

describe('eql_v3 buildEncryptConfig', () => {
  it('produces a { v: 1, tables } config', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    const config = buildEncryptConfig(users)
    expect(config.v).toBe(1)
    expect(config.tables).toHaveProperty('users')
    expect(config.tables.users).toHaveProperty('email')
  })

  it('emits a config that passes encryptConfigSchema.parse()', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    const config = buildEncryptConfig(users)
    expect(() => encryptConfigSchema.parse(config)).not.toThrow()
  })

  it('supports multiple tables', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    const posts = encryptedTable('posts', {
      body: encryptedTextSearchColumn('body'),
    })
    const config = buildEncryptConfig(users, posts)
    expect(Object.keys(config.tables).sort()).toEqual(['posts', 'users'])
  })
})
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm exec vitest run __tests__/schema-v3.test.ts`
Expected: FAIL — `buildEncryptConfig`, `EncryptedTable`, and `encryptedTable` are not exported from `@/schema/v3` (import errors / `is not a function`).

- [ ] **Step 3: Append the table, config builder, and inference helpers**

Append to `packages/stack/src/schema/v3/index.ts`. First extend the import at the top of the file so it reads:

```ts
import type {
  ColumnSchema,
  EncryptConfig,
  MatchIndexOpts,
} from '@/schema'
import type { Encrypted } from '@/types'
```

Then append after `encryptedTextSearchColumn`:

```ts
/**
 * Shape of v3 table columns: every value is a top-level
 * {@link EncryptedTextSearchColumn}. (Nested fields and other v3 concrete
 * types are deferred to later increments.)
 */
export type EncryptedV3TableColumn = {
  [key: string]: EncryptedTextSearchColumn
}

interface TableDefinition {
  tableName: string
  columns: Record<string, ColumnSchema>
}

/**
 * A v3 encrypted table. Mirrors the v2 `EncryptedTable` but only accepts v3
 * column builders. Emits the same `{ tableName, columns }` definition shape.
 */
export class EncryptedTable<T extends EncryptedV3TableColumn> {
  /** @internal Type-level brand so TypeScript can infer `T` from `EncryptedTable<T>`. */
  declare readonly _columnType: T

  constructor(
    public readonly tableName: string,
    public readonly columnBuilders: T,
  ) {}

  build(): TableDefinition {
    const builtColumns: Record<string, ColumnSchema> = {}
    for (const [colName, builder] of Object.entries(this.columnBuilders)) {
      builtColumns[colName] = builder.build()
    }
    return {
      tableName: this.tableName,
      columns: builtColumns,
    }
  }
}

/**
 * Define a v3 encrypted table. Intentionally shadows the v2 `encryptedTable`
 * name but lives on the `/v3` subpath — the importer picks the model by import
 * path. The returned object is also a column accessor (`users.email`).
 */
export function encryptedTable<T extends EncryptedV3TableColumn>(
  tableName: string,
  columns: T,
): EncryptedTable<T> & T {
  const tableBuilder = new EncryptedTable(
    tableName,
    columns,
  ) as EncryptedTable<T> & T

  for (const [colName, colBuilder] of Object.entries(columns)) {
    ;(tableBuilder as EncryptedV3TableColumn)[colName] = colBuilder
  }

  return tableBuilder
}

/**
 * Build an `EncryptConfig` (`v: 1`) from one or more v3 tables. Emits the same
 * shape as v2's `buildEncryptConfig`.
 */
export function buildEncryptConfig(
  ...tables: Array<EncryptedTable<EncryptedV3TableColumn>>
): EncryptConfig {
  const config: EncryptConfig = {
    v: 1,
    tables: {},
  }

  for (const tb of tables) {
    const tableDef = tb.build()
    config.tables[tableDef.tableName] = tableDef.columns
  }

  return config
}

/**
 * Infer the plaintext (decrypted) shape from a v3 table schema.
 *
 * In v3's flat single-type column model every value is an
 * {@link EncryptedTextSearchColumn}, so no key-remap filter is needed — every
 * column maps to `string`. When future v3 increments add other concrete column
 * types (or nested fields), reintroduce a `[K in keyof C as C[K] extends ... ]`
 * filter here.
 */
export type InferPlaintext<T extends EncryptedTable<EncryptedV3TableColumn>> =
  T extends EncryptedTable<infer C> ? { [K in keyof C]: string } : never

/**
 * Infer the encrypted shape from a v3 table schema. See {@link InferPlaintext}
 * for why no key-remap filter is needed in the flat single-type model.
 */
export type InferEncrypted<T extends EncryptedTable<EncryptedV3TableColumn>> =
  T extends EncryptedTable<infer C> ? { [K in keyof C]: Encrypted } : never
```

Note: `CastAs` is intentionally NOT imported — Task 1's `build()` emits the bare `'string'` literal (checked by the `ColumnSchema` return type), so no `CastAs` annotation is needed anywhere in this module.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pnpm exec vitest run __tests__/schema-v3.test.ts`
Expected: PASS (all runtime tests across both describe groups green).

- [ ] **Step 5: Commit**

```bash
git add packages/stack/src/schema/v3/index.ts packages/stack/__tests__/schema-v3.test.ts
git commit -m "feat(stack): add eql_v3 encryptedTable and buildEncryptConfig"
```

---

### Task 3: Wire the `./schema/v3` export subpath

**Files:**
- Modify: `packages/stack/tsup.config.ts` (add the v3 entry)
- Modify: `packages/stack/package.json` (`exports` + `typesVersions`)

**Interfaces:**
- Consumes: the module from Tasks 1-2 at `src/schema/v3/index.ts`.
- Produces: external import path `@cipherstash/stack/schema/v3` resolving to `dist/schema/v3/index.{js,cjs,d.ts,d.cts}`.

- [ ] **Step 1: Add the v3 build entry to tsup**

In `packages/stack/tsup.config.ts`, find the `entry` array of the FIRST (main) config object and add the v3 path. Change:

```ts
      'src/schema/index.ts',
      'src/drizzle/index.ts',
```

to:

```ts
      'src/schema/index.ts',
      'src/schema/v3/index.ts',
      'src/drizzle/index.ts',
```

- [ ] **Step 2: Add the `./schema/v3` export to package.json**

In `packages/stack/package.json`, in the `exports` object, add a `./schema/v3` entry immediately after the existing `./schema` block:

```json
		"./schema/v3": {
			"import": {
				"types": "./dist/schema/v3/index.d.ts",
				"default": "./dist/schema/v3/index.js"
			},
			"require": {
				"types": "./dist/schema/v3/index.d.cts",
				"default": "./dist/schema/v3/index.cjs"
			}
		},
```

(Place it between the `./schema` block and the `./types` block. Keep the existing tab indentation used in this file.)

- [ ] **Step 3: Add the `schema/v3` typesVersions entry**

In `packages/stack/package.json`, in the `typesVersions["*"]` object, add immediately after the existing `"schema"` entry:

```json
				"schema/v3": [
					"./dist/schema/v3/index.d.ts"
				],
```

- [ ] **Step 4: Build and verify the export resolves**

Run: `pnpm run build`
Expected: build succeeds and emits `dist/schema/v3/index.js`, `dist/schema/v3/index.cjs`, `dist/schema/v3/index.d.ts`, `dist/schema/v3/index.d.cts`.

Then verify the published export name resolves in both module systems (run from `packages/stack/`):

```bash
node -e "const m = require('@cipherstash/stack/schema/v3'); if (typeof m.encryptedTextSearchColumn !== 'function') { throw new Error('CJS export missing'); } console.log('cjs ok')"
node --input-type=module -e "import('@cipherstash/stack/schema/v3').then(m => { if (typeof m.encryptedTextSearchColumn !== 'function') throw new Error('ESM export missing'); console.log('esm ok'); })"
```

Expected: prints `cjs ok` then `esm ok`.

- [ ] **Step 5: Run the CJS-consumer regression test**

The existing `__tests__/cjs-require.test.ts` auto-discovers every `dist/**/*.cjs` entry, so it now also exercises `dist/schema/v3/index.cjs` (no edit needed).

Run: `pnpm exec vitest run __tests__/cjs-require.test.ts`
Expected: PASS — including the discovered `dist/schema/v3/index.cjs` entry (loads in a real Node CJS process, no externalized ESM-only `require`).

- [ ] **Step 6: Commit**

```bash
git add packages/stack/tsup.config.ts packages/stack/package.json
git commit -m "feat(stack): wire @cipherstash/stack/schema/v3 export subpath"
```

---

### Task 4: Type-level inference tests + CI enforcement

**Files:**
- Create: `packages/stack/__tests__/schema-v3.test-d.ts`
- Create: `packages/stack/tsconfig.typecheck.json` (Step 4)
- Modify: `packages/stack/vitest.config.ts` (add a scoped `typecheck` block — Step 4)
- Modify: `packages/stack/package.json` (add a `test:types` script — Step 4)
- Modify: `.github/workflows/tests.yml` (run the scoped type tests in CI — Step 4)

> Note: the v3 client-integration acceptance type-tests (`Encryption({ schemas: [v3users] })`, `client.encrypt`/`decrypt`/`encryptQuery` with v3 builders) are added in **Task 5**, which also appends to this same `schema-v3.test-d.ts`. They are enforced by the same CI wiring set up here.

**Interfaces:**
- Consumes: `encryptedTable`, `encryptedTextSearchColumn`, `type EncryptedTextSearchColumn`, `type InferEncrypted`, `type InferPlaintext` from `@/schema/v3`; `type Encrypted` from `@/types`; `encryptedColumn` from `@/schema` (v2, for the negative `@ts-expect-error` rejection test).

- [ ] **Step 1: Write type-level regression tests**

These are regression/guard tests, expected to type-check green on first run (Tasks 1-2 already define the types they assert). Create `packages/stack/__tests__/schema-v3.test-d.ts`:

```ts
import { describe, expectTypeOf, it } from 'vitest'
// v2 column builder — used only to prove the v3 table type rejects it.
import { encryptedColumn } from '@/schema'
import type {
  EncryptedTextSearchColumn,
  InferEncrypted,
  InferPlaintext,
} from '@/schema/v3'
import { encryptedTable, encryptedTextSearchColumn } from '@/schema/v3'
import type { Encrypted } from '@/types'

describe('eql_v3 schema type inference', () => {
  it('encryptedTextSearchColumn returns an EncryptedTextSearchColumn', () => {
    const col = encryptedTextSearchColumn('email')
    expectTypeOf(col).toEqualTypeOf<EncryptedTextSearchColumn>()
  })

  it('encryptedTable exposes column builders as typed properties', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    expectTypeOf(users.email).toEqualTypeOf<EncryptedTextSearchColumn>()
    expectTypeOf(users.tableName).toBeString()
  })

  it('rejects a v2 EncryptedColumn in a v3 table (nominal private-field mismatch)', () => {
    encryptedTable('users', {
      // @ts-expect-error - a v2 EncryptedColumn is not an EncryptedTextSearchColumn
      email: encryptedColumn('email'),
    })
  })

  it('InferPlaintext maps each column to string', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
      name: encryptedTextSearchColumn('name'),
    })
    type Plaintext = InferPlaintext<typeof users>
    expectTypeOf<Plaintext>().toEqualTypeOf<{ email: string; name: string }>()
  })

  it('InferEncrypted maps each column to Encrypted', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    type Enc = InferEncrypted<typeof users>
    expectTypeOf<Enc>().toEqualTypeOf<{ email: Encrypted }>()
  })
})
```

- [ ] **Step 2: Create the SCOPED typecheck config + `test:types` script (BEFORE any typecheck run)**

`.test-d.ts` files run ONLY in Vitest typecheck mode, and today nothing runs typecheck in CI (`package.json` `test` = `vitest run`; `tests.yml` runs `pnpm run test`). So neither this `schema-v3.test-d.ts` nor the pre-existing `types.test-d.ts` is enforced — a wrong inferred shape would NOT fail the build.

**Verified finding (do not skip):** `tsconfig.json` has NO `include`, so a naive package-wide `vitest --typecheck` checks every file and surfaces **124 pre-existing "Unhandled Source Error"s** unrelated to v3 — `src/wasm-inline.ts` cannot resolve `@cipherstash/auth/wasm-inline` / `@cipherstash/protect-ffi/wasm-inline` type decls, plus a type mismatch at `__tests__/wasm-inline-normalize.test.ts:69`. (The `*.test-d.ts` assertions themselves pass.) So we set up the SCOPED config FIRST, so the very first typecheck a worker runs is already narrowed and green. Verified `@/encryption` does not import `wasm-inline.ts`, so a program rooted at the `*.test-d.ts` files does not reach the broken modules.

a) Create `packages/stack/tsconfig.typecheck.json` — narrow roots so tsc only pulls the type-test files and what they actually import:

```json
{
  "extends": "./tsconfig.json",
  "include": ["__tests__/**/*.test-d.ts"]
}
```

b) Add a scoped `typecheck` block to `packages/stack/vitest.config.ts`:

```ts
import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: {
    alias: {
      '@/': resolve(__dirname, './src') + '/',
    },
  },
  test: {
    typecheck: {
      // Scoped tsconfig keeps the 124 pre-existing wasm-inline typecheck errors
      // out of scope (tracked as a follow-up). Run via the `test:types` script
      // with `--typecheck.only` so the runtime suites do NOT also execute.
      tsconfig: './tsconfig.typecheck.json',
      include: ['__tests__/**/*.test-d.ts'],
    },
  },
})
```

c) Add a `test:types` script to `packages/stack/package.json`. Use `--typecheck.only` (Vitest **3.2.4**, confirmed in the repo, supports it) so ONLY the type tests run — `--typecheck` alone would ALSO run the runtime suites (including the credential/network-sensitive ones):

```json
    "test:types": "vitest --run --typecheck.only",
```

- [ ] **Step 3: Run the scoped type tests to verify they pass**

Run: `pnpm run test:types`
Expected: PASS — `schema-v3.test-d.ts` type-checks (and the existing `types.test-d.ts` does too); ZERO errors; no runtime suites executed. (If `@/schema/v3` types were missing or `InferPlaintext`/`InferEncrypted` produced the wrong shape, `toEqualTypeOf` would surface a type error here. Tasks 1-2 already define these, so it type-checks green on first run.)

> **STOP-gate:** if this scoped run still reports the `wasm-inline` errors (e.g. a type-test transitively imports a broken module), narrow `tsconfig.typecheck.json` further (add an `exclude` for `src/wasm-inline.ts` / `__tests__/wasm-inline-normalize.test.ts`) until the run is clean BEFORE wiring CI. Do not wire a red command into CI.

- [ ] **Step 4: Run the full v3 runtime suite as a guard**

Run: `pnpm exec vitest run __tests__/schema-v3.test.ts`
Expected: PASS (all runtime tests still green — no regression from the type-test file).

- [ ] **Step 5: Wire the scoped type tests into CI**

In `.github/workflows/tests.yml`, add a step in the `run-tests` job (after `Install dependencies`):

```yaml
      - name: Type tests (stack)
        run: pnpm --filter @cipherstash/stack run test:types
```

> **Flagged follow-up (NOT fixed here):** the 124 pre-existing package-wide typecheck errors (missing `@cipherstash/{auth,protect-ffi}/wasm-inline` type declarations + `wasm-inline-normalize.test.ts:69`) are a separate cleanup. Enabling typecheck repo-wide / unscoped should be a dedicated follow-up after those are resolved.

- [ ] **Step 6: Commit**

```bash
git add packages/stack/__tests__/schema-v3.test-d.ts packages/stack/tsconfig.typecheck.json packages/stack/vitest.config.ts packages/stack/package.json .github/workflows/tests.yml
git commit -m "test(stack): type-level tests for eql_v3 schema DSL + scoped CI typecheck"
```

---

### Task 5: Widen the public client types to a structural contract (Option A — v3 works with the client)

**Goal:** make the v3 builders first-class with the client API (`Encryption`, `encrypt`, `decrypt`, `encryptQuery`) by widening the blocking public types to a structural contract that BOTH v2 and v3 builders satisfy. Runtime is untouched (verified structural — no `instanceof` on the encrypt/decrypt/query path).

**Decision — v3 keeps its OWN `EncryptedTable` class** (not reuse v2's): v3 needs a different column constraint (`EncryptedV3TableColumn`) and a simpler `build()` (no nested-field / ste_vec rewriting). v2 and v3 classes are nominally distinct (private fields) but BOTH structurally satisfy `BuildableColumn` / `BuildableTable`, which is exactly what a single widened type can accept. Reusing v2's class would not help anyway — v3 columns don't satisfy v2's `EncryptedTableColumn` generic constraint.

**Verified structural members the client actually touches** (so the contract is minimal and correct):
- Column: `getName(): string` (`operations/encrypt.ts:53` etc.), `build(): ColumnSchema` (`helpers/infer-index-type.ts:11,58`).
- Table: `tableName: string` (`operations/encrypt.ts:52` etc.), `build(): { tableName; columns }` (`helpers/model-helpers.ts:268,566`; dynamodb ops; and `buildEncryptConfig(...schemas)` → `tb.build()` at `encryption/index.ts:674`).

**Files:**
- Modify: `packages/stack/src/types.ts` — define `BuildableColumn` / `BuildableTable`; widen `EncryptionClientConfig.schemas`, `EncryptOptions`, `SearchTerm`, `QueryTermBase`.
- Modify: `packages/stack/src/schema/index.ts` — widen `buildEncryptConfig`'s parameter type ONLY (backward-compatible; the file already does `import type { Encrypted } from '@/types'`, so referencing `BuildableTable` from `@/types` adds no new module cycle).
- Modify: `packages/stack/src/encryption/operations/encrypt.ts` — internal consumer of the widened `EncryptOptions` (Step 3b).
- Modify: `packages/stack/src/encryption/operations/bulk-encrypt.ts` — internal consumer of the widened `EncryptOptions` (Step 3b).
- Modify: `packages/stack/src/encryption/helpers/infer-index-type.ts` — internal consumer of the widened query-term `column` (Step 3b).
- Test: append a `describe` block to `packages/stack/__tests__/schema-v3.test-d.ts`.

> **Internal-consumer note (verified):** widening the public aliases is NOT enough on its own — three internal files store/accept those values in narrow v2 types and would fail typecheck. They are widened in Step 3b. Verified NOT needing changes (do not over-widen): the `EncryptionClient` class (stores only `client` + `encryptConfig`, passes `opts` straight through); `operations/encrypt-query.ts` / `batch-encrypt-query.ts` (store the public widened types directly, no narrow re-declaration); and the entire MODEL path (`encrypt-model.ts`, `bulk-encrypt-models.ts`, `model-helpers.ts`), which intentionally stays narrow because the generic model methods are NOT widened in this increment.

**Interfaces (define in `src/types.ts`, alongside the other public client types):**

```ts
import type {
  ColumnSchema,
  EncryptedColumn,
  // ...existing imports (EncryptedColumn already imported; EncryptedField, EncryptedTable, EncryptedTableColumn)
} from '@/schema'

/** Structural contract for a column builder the client can consume for STORAGE
 *  (`encrypt`). Satisfied by v2 `EncryptedColumn` / `EncryptedField` AND v3
 *  `EncryptedTextSearchColumn` — fields ARE encryptable, so this stays wide. */
export interface BuildableColumn {
  getName(): string
  build(): ColumnSchema
}

/** Structural contract for a column the client can consume for QUERIES
 *  (`encryptQuery` / search terms). Narrower than `BuildableColumn`: it must
 *  EXCLUDE non-queryable `EncryptedField` (a field has no indexes). A v2
 *  `EncryptedColumn` qualifies via the nominal arm; a v3 queryable concrete
 *  type qualifies via the `getEqlType()` structural arm; `EncryptedField` (no
 *  `getEqlType`, not an `EncryptedColumn`) is rejected. */
export type BuildableQueryColumn =
  | EncryptedColumn
  | (BuildableColumn & { getEqlType(): string })

/** Structural contract for a table builder the client can consume. Satisfied by
 *  v2 and v3 `EncryptedTable` alike. */
export interface BuildableTable {
  tableName: string
  build(): { tableName: string; columns: Record<string, ColumnSchema> }
}
```

- [ ] **Step 1: Write the failing client-integration acceptance tests**

Append to `packages/stack/__tests__/schema-v3.test-d.ts`. First extend its imports — `import type { Encrypted } from '@/types'` and `encryptedColumn` from `@/schema` are ALREADY present from Task 4, so add ONLY the genuinely new symbols:

```ts
// NEW imports for Task 5 (Encrypted + encryptedColumn already imported in Task 4):
import { Encryption, EncryptionClient } from '@/encryption'
// extend the existing `import { encryptedColumn } from '@/schema'` to also bring in:
import {
  encryptedColumn,
  encryptedField,
  encryptedTable as v2EncryptedTable,
} from '@/schema'
```

Then append:

```ts
describe('eql_v3 client integration (type-level acceptance)', () => {
  const v3users = encryptedTable('users', {
    email: encryptedTextSearchColumn('email'),
  })

  it('Encryption accepts a v3 schema', () => {
    expectTypeOf(Encryption).toBeCallableWith({ schemas: [v3users] })
  })

  it('encrypt accepts a v3 table + column', () => {
    const client = {} as EncryptionClient
    expectTypeOf(client.encrypt).toBeCallableWith('alice@example.com', {
      table: v3users,
      column: v3users.email,
    })
  })

  it('encryptQuery accepts a v3 table + column', () => {
    const client = {} as EncryptionClient
    expectTypeOf(client.encryptQuery).toBeCallableWith('alice@example.com', {
      table: v3users,
      column: v3users.email,
    })
  })

  it('decrypt accepts an Encrypted value (round-trip target type; schema-independent)', () => {
    const client = {} as EncryptionClient
    expectTypeOf(client.decrypt).toBeCallableWith({} as Encrypted)
  })

  it('BACKWARD COMPAT: v2 tables/columns still satisfy the widened types', () => {
    const v2users = v2EncryptedTable('users', {
      email: encryptedColumn('email').equality(),
    })
    expectTypeOf(Encryption).toBeCallableWith({ schemas: [v2users] })
    const client = {} as EncryptionClient
    expectTypeOf(client.encrypt).toBeCallableWith('alice@example.com', {
      table: v2users,
      column: v2users.email,
    })
    // a v2 EncryptedColumn is STILL queryable (nominal arm of BuildableQueryColumn)
    expectTypeOf(client.encryptQuery).toBeCallableWith('alice@example.com', {
      table: v2users,
      column: v2users.email,
    })
  })

  it('a non-queryable v2 EncryptedField is encryptable but NOT queryable', () => {
    const v2usersWithField = v2EncryptedTable('users', {
      profile: { email: encryptedField('email') },
    })
    const client = {} as EncryptionClient

    // POSITIVE: a field IS encryptable (storage path = BuildableColumn)
    expectTypeOf(client.encrypt).toBeCallableWith('alice@example.com', {
      table: v2usersWithField,
      column: v2usersWithField.profile.email,
    })

    // NEGATIVE: a field is NOT queryable. The query path uses
    // BuildableQueryColumn, which excludes EncryptedField (no indexes). If the
    // query path were instead widened to BuildableColumn (the rejected
    // Batch-2/3 design), this call would compile and only fail at runtime with
    // "no indexes configured" — so this test guards against that re-widening.
    //
    // The mismatch is a DEEP object-literal property error, so tsc reports it on
    // the `column:` line — the `@ts-expect-error` MUST sit directly above that
    // line (not above the call), or you get TS2578 "unused directive" + the real
    // error leaking. (Mirror of Task 4's v2-column-rejected test placement.)
    client.encryptQuery('alice@example.com', {
      table: v2usersWithField,
      // @ts-expect-error - EncryptedField is not assignable to BuildableQueryColumn
      column: v2usersWithField.profile.email,
    })
  })
})
```

- [ ] **Step 2: Run the type tests to verify they fail**

Run: `pnpm run test:types` (script added in Task 4)
Expected: FAIL — the v3 `Encryption` / `encrypt` / `encryptQuery` assertions error because `EncryptedTextSearchColumn` / v3 `EncryptedTable` are not assignable to the still-nominal pre-Task-5 v2 types. These clear after Step 3.

(The v2 backward-compat `encrypt`/`encryptQuery` assertions and `decrypt` already pass. The field tests also already pass: pre-Task-5 `QueryTermBase.column` is the original nominal `EncryptedColumn`, so the `@ts-expect-error` on querying a field is already a valid suppression — those tests stay green through Step 3, guarding against any future re-widening of the query path to `BuildableColumn`.)

- [ ] **Step 3a: Define the structural contract and widen the public types**

In `packages/stack/src/types.ts`:
1. Add `ColumnSchema` to the existing `@/schema` type import (`EncryptedColumn` is already imported there).
2. Add the `BuildableColumn` / `BuildableQueryColumn` / `BuildableTable` definitions (above).
3. Widen the blocking surfaces. Note the **storage vs query split**: `EncryptOptions` (encrypt) accepts `BuildableColumn` (columns AND fields), while `SearchTerm` / `QueryTermBase` (encryptQuery) accept the narrower `BuildableQueryColumn` so a non-queryable field is rejected at the type layer:

```ts
export type EncryptionClientConfig = {
  schemas: AtLeastOneCsTable<BuildableTable>
  config?: ClientConfig
}

export type EncryptOptions = {
  column: BuildableColumn // storage: fields are encryptable, so stays wide
  table: BuildableTable
}

export type SearchTerm = {
  value: JsPlaintext
  column: BuildableQueryColumn // query: excludes non-queryable EncryptedField
  table: BuildableTable
  returnType?: EncryptedReturnType
}

export type QueryTermBase = {
  column: BuildableQueryColumn // query: excludes non-queryable EncryptedField
  table: BuildableTable
  queryType?: QueryTypeName
  returnType?: EncryptedReturnType
}
```

In `packages/stack/src/schema/index.ts`, widen `buildEncryptConfig`'s parameter (the ONLY permitted edit to the v2 module — pure widening, no behavior change):

```ts
import type { BuildableTable, Encrypted } from '@/types'

export function buildEncryptConfig(
  ...protectTables: Array<BuildableTable>
): EncryptConfig {
  // body unchanged — already only calls tb.build()
}
```

> **Do NOT touch** the generic schema-aware model methods `encryptModel<S extends EncryptedTableColumn>` / `bulkEncryptModels` (`encryption/index.ts:394,489`) or `EncryptedFromSchema` / `InferPlaintext` / `EncryptedFields`. They must keep inferring `S` from `EncryptedTable<S>` so v2 field-level inference is preserved. v3 support for the model methods is a future increment (v3 columns don't satisfy `EncryptedTableColumn`). The `EncryptedTable<T> & T` accessor and v2 inference must be re-verified green (Step 4).
>
> **Fallback (if the team forbids ANY v2-module edit):** instead of widening `buildEncryptConfig`, leave it as-is and change `Encryption()` (`encryption/index.ts`) to assemble the config inline from the structural `schemas` (`for (const tb of schemas) { const d = tb.build(); config.tables[d.tableName] = d.columns }`). This keeps `src/schema/index.ts` pristine at the cost of ~6 duplicated lines in the client.

- [ ] **Step 3b: Widen the internal consumers the public change forces**

After Step 3a, the package will NOT typecheck until the internal consumers that store/accept the widened values are widened too. All three only call `.getName()`, `.tableName`, and `column.build().indexes` — so `BuildableColumn` / `BuildableTable` are sufficient (no richer contract). Widen exactly these, and nothing in the model path:

1. **`src/encryption/operations/encrypt.ts`** — `EncryptOperation`:
   - field `private column: EncryptedColumn | EncryptedField` (:27) → `private column: BuildableColumn`
   - field `private table: EncryptedTable<EncryptedTableColumn>` (:28) → `private table: BuildableTable`
   - `getOperation()` return type's `column` / `table` (:112-113) → `BuildableColumn` / `BuildableTable`
   - imports: add `BuildableColumn, BuildableTable` to the `@/types` import; drop the now-unused `EncryptedColumn, EncryptedField, EncryptedTable, EncryptedTableColumn` from the `@/schema` import (if nothing else uses them).
   - The constructor already takes `opts: EncryptOptions` (widened) — no signature change; only the field/return types.

2. **`src/encryption/operations/bulk-encrypt.ts`** — `BulkEncryptOperation`:
   - module fn `createEncryptPayloads(column: EncryptedColumn | EncryptedField, table: EncryptedTable<EncryptedTableColumn>, ...)` (:28-29) → `column: BuildableColumn, table: BuildableTable`
   - fields `private column` (:66) / `private table` (:67) → `BuildableColumn` / `BuildableTable`
   - **`BulkEncryptOperation.getOperation()` return type (:141-142)** — REQUIRED widen-site: it re-exposes `column: EncryptedColumn | EncryptedField` (:141) and `table: EncryptedTable<EncryptedTableColumn>` (:142) → `BuildableColumn` / `BuildableTable`. (This return value is destructured and consumed by `BulkEncryptOperationWithLockContext.execute()` at :168, which only uses `.getName()` / `.tableName`.) Do NOT miss this — leaving it narrow keeps `bulk-encrypt.ts` red. (Note: this is `getOperation()`'s return type on `BulkEncryptOperation`, NOT a member of the `*WithLockContext` class.)
   - same import swap (`@/types` gains `BuildableColumn, BuildableTable`; drop unused `@/schema` narrow types).

3. **`src/encryption/helpers/infer-index-type.ts`** — index inference (QUERY path only — verified reached solely via `resolveIndexType` from `encrypt-query.ts:72,165` and `batch-encrypt-query.ts:51`, NOT from the storage path):
   - `inferIndexType(column: EncryptedColumn)` (:10), `validateIndexType(column: EncryptedColumn, ...)` (:55), `resolveIndexType(column: EncryptedColumn, ...)` (:87) → `column: BuildableQueryColumn` in all three (NOT `BuildableColumn` — these run only for queries, so they should reject non-queryable fields too).
   - import: replace `import type { EncryptedColumn } from '@/schema'` with `import type { BuildableQueryColumn } from '@/types'`.
   - Bodies are unchanged: they read `column.build().indexes` and `column.getName()`, both available on `BuildableQueryColumn` (its `EncryptedColumn` arm and its `BuildableColumn & …` arm each provide `getName()` + `build()`).

> **Do NOT widen the model path.** `encrypt-model.ts`, `bulk-encrypt-models.ts`, and `model-helpers.ts` keep `EncryptedTable<EncryptedTableColumn>` / `EncryptedTable<S>` — they are fed by the generic `encryptModel<S extends EncryptedTableColumn>` methods which are intentionally left narrow (preserves v2 inference; v3 model support is a later increment). Widening them would over-reach and could disturb inference.
>
> **WASM-inline boundary (documented, not fixed here).** `src/wasm-inline.ts:314-320` has `getColumnName(col)` doing `if (col instanceof EncryptedColumn || col instanceof EncryptedField) … else throw`. After widening `EncryptOptions['column']` to `BuildableColumn` this still type-checks (an `instanceof` guard narrows a wider type fine) and `wasm-inline.ts` is outside the scoped typecheck graph (`@/encryption` does not import it; the `test:types` tsconfig roots only the `*.test-d.ts` files), so it does NOT turn the package red — but a v3 column routed through the WASM-inline entry would hit the `else throw` at RUNTIME. The batch-2 "no `instanceof`" finding was explicitly scoped to `operations/*.ts`; the WASM-inline entry does not yet accept v3 columns, which is a deferred, documented boundary (not a latent surprise).

- [ ] **Step 4: Run the full suite to verify pass + no regression**

```bash
pnpm run test:types         # v3 acceptance + v2 backward-compat + existing types.test-d.ts all green
pnpm exec vitest run        # all runtime tests still pass (encryptModel inference unaffected)
```

Expected: all green. In particular `__tests__/types.test-d.ts` (v2 inference, `EncryptedFromSchema`, `encryptModel` schema-aware return types) must still pass — proving the widening did not narrow or break v2.

- [ ] **Step 5: Commit**

```bash
git add packages/stack/src/types.ts packages/stack/src/schema/index.ts \
  packages/stack/src/encryption/operations/encrypt.ts \
  packages/stack/src/encryption/operations/bulk-encrypt.ts \
  packages/stack/src/encryption/helpers/infer-index-type.ts \
  packages/stack/__tests__/schema-v3.test-d.ts
git commit -m "feat(stack): widen public client types so v3 builders work with the client"
```

---

### Task 6: Changeset

**Files:**
- Create: `.changeset/eql-v3-text-search.md`

**Interfaces:** none (release metadata only). The repo uses Changesets (`.changeset/config.json`); frontmatter keys are package `name`s. `packages/stack/package.json` name is `@cipherstash/stack`.

- [ ] **Step 1: Create the changeset**

Create `.changeset/eql-v3-text-search.md` (minor — additive `./schema/v3` subpath + exports, plus backward-compatible public-type widening; no breaking changes):

```md
---
"@cipherstash/stack": minor
---

Add the EQL v3 `text_search` authoring DSL on a new `@cipherstash/stack/schema/v3`
subpath (`encryptedTextSearchColumn`, v3 `encryptedTable` / `buildEncryptConfig`).
The v3 builders emit the existing `EncryptConfig` shape, so encryption, payloads,
and query paths are unchanged at runtime.

Also widens the public client types (`EncryptionClientConfig.schemas`,
`EncryptOptions`, `SearchTerm`/`EncryptQueryOptions`) to a structural contract so
both v2 and v3 builders are accepted by `Encryption` / `encrypt` / `decrypt` /
`encryptQuery`. This is a backward-compatible widening — existing v2 usage is
unaffected.
```

- [ ] **Step 2: Verify the changeset is valid**

Run: `pnpm exec changeset status` (from the repo root)
Expected: lists a pending `minor` bump for `@cipherstash/stack`, no errors. (If `changeset status` is unavailable in this environment, confirm the frontmatter key exactly matches the package `name` and the bump keyword is one of `major`/`minor`/`patch`.)

- [ ] **Step 3: Commit**

```bash
git add .changeset/eql-v3-text-search.md
git commit -m "chore(stack): changeset for eql_v3 text_search DSL (minor)"
```

---

## Self-Review

**Spec coverage:**
- Public API (`encryptedTextSearchColumn`, v3 `encryptedTable`, v3 `buildEncryptConfig`) → Tasks 1-2.
- `.freeTextSearch(opts?)` as tuning-only with per-key replace merge → Task 1, Steps 1 & 3 (override + tuning-only tests).
- Pinned `build()` output (`cast_as: 'string'` + three indexes, defaults) → Task 1, default-config test.
- Load-bearing v2/v3 equivalence assertion → Task 1, "LOAD-BEARING" test (imports v2 `encryptedColumn`).
- `'eql_v3.text_search'` via `getEqlType()` method (no property getter), absent from `build()` → Task 1, getEqlType + absence tests.
- `buildEncryptConfig` → valid `EncryptConfig` (`v: 1`) passing `encryptConfigSchema.parse` → Task 2.
- `InferPlaintext` / `InferEncrypted` → Task 4 (type) + Task 2 (definition).
- New `@cipherstash/stack/schema/v3` subpath (exports + tsup) → Task 3.
- No shared mutable state (per-instance defaults + cloned `build()`) → Task 1 (`defaultMatchOpts()` factory + independent-mutation test).
- **Client integration (Option A):** widen public types AND the internal consumers they force so v3 builders work with `Encryption` / `encrypt` / `decrypt` / `encryptQuery`; storage path (`encrypt`, `operations/encrypt.ts`, `operations/bulk-encrypt.ts`) uses `BuildableColumn` (accepts fields), query path (`encryptQuery`, `helpers/infer-index-type.ts`) uses the narrower `BuildableQueryColumn` (rejects non-queryable fields); model path left narrow; v2 backward-compat preserved → Task 5 (Steps 3a + 3b).
- Type tests enforced in CI (scoped typecheck, `--typecheck.only`) → Task 4, Steps 2-3 (scoped config + script) and Step 5 (CI wiring).
- Changeset (minor) for the public-surface change → Task 6.
- v2 module: runtime + existing exported shapes untouched; ONLY a backward-compatible `buildEncryptConfig` param widening (Task 5) — see Global Constraints.
- Non-goals (v3 in the generic model methods, DDL, transition tooling, query dialect, other concrete types, nested fields) → not implemented (correctly out of scope).

**Placeholder scan:** No TBD/TODO/"handle edge cases" present; every code step contains complete, runnable code.

**Type consistency:** `EncryptedTextSearchColumn`, `encryptedTextSearchColumn`, `EncryptedTable`, `encryptedTable`, `buildEncryptConfig`, `EncryptedV3TableColumn`, `InferPlaintext`, `InferEncrypted`, `TEXT_SEARCH_EQL_TYPE`, the `defaultMatchOpts()` factory, `getEqlType()` (method only — no property getter; also the query-path discriminator in `BuildableQueryColumn`), and the structural `BuildableColumn` / `BuildableQueryColumn` / `BuildableTable` contract (Task 5) are used identically across tasks and tests. `build()` returns `ColumnSchema`; `EncryptedTable.build()` returns `{ tableName, columns: Record<string, ColumnSchema> }`, matching both `buildEncryptConfig`'s consumption and the `BuildableTable` contract.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-30-eql-v3-text-search-schema-plan.md`. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
</content>
</invoke>
