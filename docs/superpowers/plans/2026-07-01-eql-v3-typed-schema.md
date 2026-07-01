# EQL v3 Typed Schema Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand `@cipherstash/stack/schema/v3` from the current `text_search` slice to all generated EQL v3 SQL domains with domain-precise builders, explicit query capability metadata, and structurally widened client/model support while preserving v2 behavior.

**Architecture:** Keep v3 isolated under `packages/stack/src/schema/v3/index.ts` and the `@cipherstash/stack/schema/v3` export. Implement one v3 column class/builder per EQL v3 domain using a shared internal column base parameterized by the full literal domain definition (`eqlType`, `castAs`, capabilities), not by capabilities alone. Client query typing should accept v3 columns only when they expose capability metadata and `isQueryable(): true`; storage-only v3 columns remain encryptable but not queryable.

**Tech Stack:** TypeScript, Vitest runtime tests, Vitest type tests, tsup package build, `@cipherstash/protect-ffi`, existing `ColumnSchema`/`EncryptConfig` v1 config shape.

---

## File Structure Map

**Modify:**
- `packages/stack/src/schema/v3/index.ts`
  - Owns all v3 builders, domain metadata, table builder, `buildEncryptConfig`, and v3 `InferPlaintext` / `InferEncrypted`.
- `packages/stack/src/types.ts`
  - Tightens `BuildableQueryColumn`; widens model schema typing from v2-only columns to structural buildable table columns while preserving literal schema keys through each table's `_columnType` brand.
- `packages/stack/src/encryption/index.ts`
  - Updates `encryptModel` and `bulkEncryptModels` generics and table parameter types to accept v3 tables.
- `packages/stack/src/encryption/helpers/model-helpers.ts`
  - Replaces v2 `EncryptedTable<EncryptedTableColumn>` annotations with structural `BuildableTable`.
- `packages/stack/src/encryption/operations/encrypt-model.ts`
  - Replaces v2 table annotations with `BuildableTable`.
- `packages/stack/src/encryption/operations/bulk-encrypt-models.ts`
  - Replaces v2 table annotations with `BuildableTable`.
- `packages/stack/src/wasm-inline.ts`
  - Widens WASM schema config type to structural buildable tables if needed; keeps structural `getColumnName`.
- `packages/stack/vitest.config.ts`
  - Fixes or isolates `@cipherstash/protect-ffi/wasm-inline` import resolution for `wasm-inline-column-name.test.ts`.
- `packages/stack/package.json`
  - Keep existing `./schema/v3` export and `db:eql-v3:install`; add no new subpath unless tests prove required.

**Modify tests:**
- `packages/stack/__tests__/schema-v3.test.ts`
  - Runtime builder/config/capability tests for all v3 domains.
- `packages/stack/__tests__/schema-v3.test-d.ts`
  - Type-level tests for all builders, queryability, inferred plaintext/encrypted model shapes, and v2 compatibility.
- `packages/stack/__tests__/schema-v3-client.test.ts`
  - Live env-gated client tests expanded to representative storage-only/equality/order/match/search columns.
- `packages/stack/__tests__/schema-v3-pg.test.ts`
  - Keep guarded Postgres `text_search` coverage; add representative non-text EQL v3 domains when the SQL fixture supports them.
- `packages/stack/__tests__/wasm-inline-column-name.test.ts`
  - Keep focused column-name test; update import style only if needed after Vitest resolution fix.

**Create:**
- `.changeset/eql-v3-typed-schema.md`
  - Public API addition for `@cipherstash/stack`.

**Do not modify:**
- `packages/stack/src/schema/index.ts`
  - v2 schema API remains stable.
- Payload contracts and Result shapes.
- Any code that logs plaintext.

---

### Task 1: Baseline And Source-Of-Truth Snapshot

**Files:**
- Read only: `packages/stack/src/schema/v3/index.ts`
- Read only: `/Users/tobyhede/src/encrypt-query-language/.worktrees/eql_v3/crates/eql-bindings/src/v3/inventory.rs`
- Read only: `/Users/tobyhede/src/encrypt-query-language/.worktrees/eql_v3/crates/eql-bindings/schema/v3/*.json`

- [ ] **Step 1: Confirm branch and dirty state**

Run:

```bash
git status --short --branch
```

Expected:

```text
## feat/eql-v3-text-search-schema...origin/feat/eql-v3-text-search-schema
```

Also expect currently untracked v3 live-test/helper files and the `packages/stack/package.json` script change. Do not revert them.

- [ ] **Step 2: Confirm complete v3 domain inventory**

Run:

```bash
sed -n '1,140p' /Users/tobyhede/src/encrypt-query-language/.worktrees/eql_v3/crates/eql-bindings/src/v3/inventory.rs
```

Expected: inventory includes exactly these domain identifiers:

```text
int4 int4_eq int4_ord_ore int4_ord
int2 int2_eq int2_ord_ore int2_ord
int8 int8_eq int8_ord_ore int8_ord
date date_eq date_ord_ore date_ord
timestamptz timestamptz_eq timestamptz_ord_ore timestamptz_ord
numeric numeric_eq numeric_ord_ore numeric_ord
text text_eq text_match text_ord_ore text_ord text_search
bool
float4 float4_eq float4_ord_ore float4_ord
float8 float8_eq float8_ord_ore float8_ord
```

- [ ] **Step 3: Confirm capability rule from JSON schemas**

Run:

```bash
rg '"required"' /Users/tobyhede/src/encrypt-query-language/.worktrees/eql_v3/crates/eql-bindings/schema/v3 -n
```

Expected:
- Schemas with required `hm` support equality.
- Schemas with required `ob` support order/range.
- Schemas with required `bf` support free-text search.
- Schemas with only `v`, `i`, `c` are storage-only.

---

### Task 2: Write Failing Runtime Tests For All v3 Builders

**Files:**
- Modify: `packages/stack/__tests__/schema-v3.test.ts`

- [ ] **Step 1: Add import coverage for every new builder and class**

Replace the v3 import block with this full import list:

```ts
import {
  buildEncryptConfig,
  EncryptedBoolColumn,
  EncryptedDateColumn,
  EncryptedDateEqColumn,
  EncryptedDateOrdColumn,
  EncryptedDateOrdOreColumn,
  EncryptedFloat4Column,
  EncryptedFloat4EqColumn,
  EncryptedFloat4OrdColumn,
  EncryptedFloat4OrdOreColumn,
  EncryptedFloat8Column,
  EncryptedFloat8EqColumn,
  EncryptedFloat8OrdColumn,
  EncryptedFloat8OrdOreColumn,
  EncryptedInt2Column,
  EncryptedInt2EqColumn,
  EncryptedInt2OrdColumn,
  EncryptedInt2OrdOreColumn,
  EncryptedInt4Column,
  EncryptedInt4EqColumn,
  EncryptedInt4OrdColumn,
  EncryptedInt4OrdOreColumn,
  EncryptedInt8Column,
  EncryptedInt8EqColumn,
  EncryptedInt8OrdColumn,
  EncryptedInt8OrdOreColumn,
  EncryptedNumericColumn,
  EncryptedNumericEqColumn,
  EncryptedNumericOrdColumn,
  EncryptedNumericOrdOreColumn,
  EncryptedTable,
  EncryptedTextColumn,
  EncryptedTextEqColumn,
  EncryptedTextMatchColumn,
  EncryptedTextOrdColumn,
  EncryptedTextOrdOreColumn,
  EncryptedTextSearchColumn,
  EncryptedTimestamptzColumn,
  EncryptedTimestamptzEqColumn,
  EncryptedTimestamptzOrdColumn,
  EncryptedTimestamptzOrdOreColumn,
  encryptedBoolColumn,
  encryptedDateColumn,
  encryptedDateEqColumn,
  encryptedDateOrdColumn,
  encryptedDateOrdOreColumn,
  encryptedFloat4Column,
  encryptedFloat4EqColumn,
  encryptedFloat4OrdColumn,
  encryptedFloat4OrdOreColumn,
  encryptedFloat8Column,
  encryptedFloat8EqColumn,
  encryptedFloat8OrdColumn,
  encryptedFloat8OrdOreColumn,
  encryptedInt2Column,
  encryptedInt2EqColumn,
  encryptedInt2OrdColumn,
  encryptedInt2OrdOreColumn,
  encryptedInt4Column,
  encryptedInt4EqColumn,
  encryptedInt4OrdColumn,
  encryptedInt4OrdOreColumn,
  encryptedInt8Column,
  encryptedInt8EqColumn,
  encryptedInt8OrdColumn,
  encryptedInt8OrdOreColumn,
  encryptedNumericColumn,
  encryptedNumericEqColumn,
  encryptedNumericOrdColumn,
  encryptedNumericOrdOreColumn,
  encryptedTable,
  encryptedTextColumn,
  encryptedTextEqColumn,
  encryptedTextMatchColumn,
  encryptedTextOrdColumn,
  encryptedTextOrdOreColumn,
  encryptedTextSearchColumn,
  encryptedTimestamptzColumn,
  encryptedTimestamptzEqColumn,
  encryptedTimestamptzOrdColumn,
  encryptedTimestamptzOrdOreColumn,
} from '@/schema/v3'
```

- [ ] **Step 2: Add a complete table-driven domain test**

Add this test near the top of `schema-v3.test.ts`:

```ts
const domainCases = [
  ['eql_v3.int4', encryptedInt4Column, EncryptedInt4Column, 'number', {}, { equality: false, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.int4_eq', encryptedInt4EqColumn, EncryptedInt4EqColumn, 'number', { unique: { token_filters: [] } }, { equality: true, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.int4_ord_ore', encryptedInt4OrdOreColumn, EncryptedInt4OrdOreColumn, 'number', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.int4_ord', encryptedInt4OrdColumn, EncryptedInt4OrdColumn, 'number', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.int2', encryptedInt2Column, EncryptedInt2Column, 'number', {}, { equality: false, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.int2_eq', encryptedInt2EqColumn, EncryptedInt2EqColumn, 'number', { unique: { token_filters: [] } }, { equality: true, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.int2_ord_ore', encryptedInt2OrdOreColumn, EncryptedInt2OrdOreColumn, 'number', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.int2_ord', encryptedInt2OrdColumn, EncryptedInt2OrdColumn, 'number', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.int8', encryptedInt8Column, EncryptedInt8Column, 'bigint', {}, { equality: false, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.int8_eq', encryptedInt8EqColumn, EncryptedInt8EqColumn, 'bigint', { unique: { token_filters: [] } }, { equality: true, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.int8_ord_ore', encryptedInt8OrdOreColumn, EncryptedInt8OrdOreColumn, 'bigint', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.int8_ord', encryptedInt8OrdColumn, EncryptedInt8OrdColumn, 'bigint', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.date', encryptedDateColumn, EncryptedDateColumn, 'date', {}, { equality: false, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.date_eq', encryptedDateEqColumn, EncryptedDateEqColumn, 'date', { unique: { token_filters: [] } }, { equality: true, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.date_ord_ore', encryptedDateOrdOreColumn, EncryptedDateOrdOreColumn, 'date', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.date_ord', encryptedDateOrdColumn, EncryptedDateOrdColumn, 'date', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.timestamptz', encryptedTimestamptzColumn, EncryptedTimestamptzColumn, 'date', {}, { equality: false, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.timestamptz_eq', encryptedTimestamptzEqColumn, EncryptedTimestamptzEqColumn, 'date', { unique: { token_filters: [] } }, { equality: true, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.timestamptz_ord_ore', encryptedTimestamptzOrdOreColumn, EncryptedTimestamptzOrdOreColumn, 'date', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.timestamptz_ord', encryptedTimestamptzOrdColumn, EncryptedTimestamptzOrdColumn, 'date', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.numeric', encryptedNumericColumn, EncryptedNumericColumn, 'number', {}, { equality: false, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.numeric_eq', encryptedNumericEqColumn, EncryptedNumericEqColumn, 'number', { unique: { token_filters: [] } }, { equality: true, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.numeric_ord_ore', encryptedNumericOrdOreColumn, EncryptedNumericOrdOreColumn, 'number', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.numeric_ord', encryptedNumericOrdColumn, EncryptedNumericOrdColumn, 'number', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.text', encryptedTextColumn, EncryptedTextColumn, 'string', {}, { equality: false, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.text_eq', encryptedTextEqColumn, EncryptedTextEqColumn, 'string', { unique: { token_filters: [] } }, { equality: true, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.text_match', encryptedTextMatchColumn, EncryptedTextMatchColumn, 'string', { match: { tokenizer: { kind: 'ngram', token_length: 3 }, token_filters: [{ kind: 'downcase' }], k: 6, m: 2048, include_original: true } }, { equality: false, orderAndRange: false, freeTextSearch: true }],
  ['eql_v3.text_ord_ore', encryptedTextOrdOreColumn, EncryptedTextOrdOreColumn, 'string', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.text_ord', encryptedTextOrdColumn, EncryptedTextOrdColumn, 'string', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.bool', encryptedBoolColumn, EncryptedBoolColumn, 'boolean', {}, { equality: false, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.float4', encryptedFloat4Column, EncryptedFloat4Column, 'number', {}, { equality: false, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.float4_eq', encryptedFloat4EqColumn, EncryptedFloat4EqColumn, 'number', { unique: { token_filters: [] } }, { equality: true, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.float4_ord_ore', encryptedFloat4OrdOreColumn, EncryptedFloat4OrdOreColumn, 'number', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.float4_ord', encryptedFloat4OrdColumn, EncryptedFloat4OrdColumn, 'number', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.float8', encryptedFloat8Column, EncryptedFloat8Column, 'number', {}, { equality: false, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.float8_eq', encryptedFloat8EqColumn, EncryptedFloat8EqColumn, 'number', { unique: { token_filters: [] } }, { equality: true, orderAndRange: false, freeTextSearch: false }],
  ['eql_v3.float8_ord_ore', encryptedFloat8OrdOreColumn, EncryptedFloat8OrdOreColumn, 'number', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
  ['eql_v3.float8_ord', encryptedFloat8OrdColumn, EncryptedFloat8OrdColumn, 'number', { ore: {} }, { equality: true, orderAndRange: true, freeTextSearch: false }],
] as const

describe('eql_v3 concrete domain columns', () => {
  it.each(domainCases)('%s builder exposes name, config, type, and capabilities', (eqlType, factory, Klass, castAs, indexes, capabilities) => {
    const col = factory('value')
    expect(col).toBeInstanceOf(Klass)
    expect(col.getName()).toBe('value')
    expect(col.getEqlType()).toBe(eqlType)
    expect(col.getQueryCapabilities()).toStrictEqual(capabilities)
    expect(col.isQueryable()).toBe(Object.values(capabilities).some(Boolean))
    expect(col.build()).toStrictEqual({ cast_as: castAs, indexes })
    expect(col.build()).not.toHaveProperty('eqlType')
    expect(col.build()).not.toHaveProperty('queryCapabilities')
  })
})
```

- [ ] **Step 3: Keep and adapt existing `text_search` tests**

Keep existing `text_search` tests, but add:

```ts
expect(encryptedTextSearchColumn('email').getQueryCapabilities()).toStrictEqual({
  equality: true,
  orderAndRange: true,
  freeTextSearch: true,
})
expect(encryptedTextSearchColumn('email').isQueryable()).toBe(true)
```

- [ ] **Step 4: Run runtime test and confirm failure**

Run:

```bash
pnpm --filter @cipherstash/stack vitest run __tests__/schema-v3.test.ts
```

Expected: FAIL with missing exports such as `encryptedInt4Column` and missing methods `getQueryCapabilities` / `isQueryable`.

---

### Task 3: Implement v3 Domain Column Base And Builders

**Files:**
- Modify: `packages/stack/src/schema/v3/index.ts`

- [ ] **Step 1: Add shared capability and full domain-definition types**

Add near the top of `schema/v3/index.ts`:

```ts
export type QueryCapabilities = Readonly<{
  equality: boolean
  orderAndRange: boolean
  freeTextSearch: boolean
}>

type PlaintextKind = 'string' | 'number' | 'bigint' | 'boolean' | 'date'

type V3DomainDefinition = Readonly<{
  eqlType: `eql_v3.${string}`
  castAs: PlaintextKind
  capabilities: QueryCapabilities
}>

type QueryableFlag<D extends V3DomainDefinition> =
  D['capabilities'] extends { equality: false; orderAndRange: false; freeTextSearch: false }
    ? false
    : true

const STORAGE_ONLY = {
  equality: false,
  orderAndRange: false,
  freeTextSearch: false,
} as const

const EQUALITY_ONLY = {
  equality: true,
  orderAndRange: false,
  freeTextSearch: false,
} as const

const ORDER_AND_RANGE = {
  equality: true,
  orderAndRange: true,
  freeTextSearch: false,
} as const

const MATCH_ONLY = {
  equality: false,
  orderAndRange: false,
  freeTextSearch: true,
} as const

const TEXT_SEARCH = {
  equality: true,
  orderAndRange: true,
  freeTextSearch: true,
} as const

const INT4 = { eqlType: 'eql_v3.int4', castAs: 'number', capabilities: STORAGE_ONLY } as const
const INT4_EQ = { eqlType: 'eql_v3.int4_eq', castAs: 'number', capabilities: EQUALITY_ONLY } as const
const INT4_ORD_ORE = { eqlType: 'eql_v3.int4_ord_ore', castAs: 'number', capabilities: ORDER_AND_RANGE } as const
const INT4_ORD = { eqlType: 'eql_v3.int4_ord', castAs: 'number', capabilities: ORDER_AND_RANGE } as const
```

Every concrete domain must get its own `as const` domain definition object. This is load-bearing: empty subclasses are not nominal in TypeScript, so the base class must carry literal `eqlType`/`castAs` data in its private definition field. Do not type columns as `EncryptedV3Column<typeof STORAGE_ONLY>`; that makes all storage-only domains mutually assignable and breaks plaintext inference.

- [ ] **Step 2: Add config helpers**

Add these helpers before column classes:

```ts
function indexesForCapabilities(capabilities: QueryCapabilities): ColumnSchema['indexes'] {
  const indexes: ColumnSchema['indexes'] = {}

  if (capabilities.equality && !capabilities.orderAndRange) {
    indexes.unique = { token_filters: [] }
  }

  if (capabilities.orderAndRange) {
    indexes.ore = {}
  }

  if (capabilities.freeTextSearch) {
    const match = defaultMatchOpts()
    indexes.match = {
      ...match,
      tokenizer: { ...match.tokenizer },
      token_filters: match.token_filters.map((f) => ({ ...f })),
    }
  }

  return indexes
}

function isQueryableCapabilities(capabilities: QueryCapabilities): boolean {
  return capabilities.equality || capabilities.orderAndRange || capabilities.freeTextSearch
}
```

Important: `orderAndRange` domains use `{ ore: {} }` only. Do not also emit `unique`; the EQL v3 `ob` key supports equality and range.

- [ ] **Step 3: Add generic base class**

Add:

```ts
class EncryptedV3Column<D extends V3DomainDefinition> {
  constructor(
    private readonly columnName: string,
    private readonly definition: D,
  ) {}

  getName(): string {
    return this.columnName
  }

  getEqlType(): D['eqlType'] {
    return this.definition.eqlType
  }

  getQueryCapabilities(): D['capabilities'] {
    return this.definition.capabilities
  }

  isQueryable(): QueryableFlag<D> {
    return isQueryableCapabilities(this.definition.capabilities) as QueryableFlag<D>
  }

  build(): ColumnSchema {
    return {
      cast_as: this.definition.castAs,
      indexes: indexesForCapabilities(this.definition.capabilities),
    }
  }
}
```

Because `definition` is a private base field whose type includes literal `eqlType` and `castAs`, `EncryptedBoolColumn` is no longer assignable to `EncryptedInt8Column` even if both are storage-only.

- [ ] **Step 4: Keep text-search override semantics**

Change `EncryptedTextSearchColumn` to extend the base but keep its existing `matchOpts`, `freeTextSearch(opts?)`, and deep-clone behavior.

Expected final shape:

```ts
const TEXT_SEARCH_DOMAIN = {
  eqlType: TEXT_SEARCH_EQL_TYPE,
  castAs: 'string',
  capabilities: TEXT_SEARCH,
} as const

export class EncryptedTextSearchColumn extends EncryptedV3Column<typeof TEXT_SEARCH_DOMAIN> {
  private matchOpts: BuiltMatchIndexOpts

  constructor(columnName: string) {
    super(columnName, TEXT_SEARCH_DOMAIN)
    this.matchOpts = defaultMatchOpts()
  }

  freeTextSearch(opts?: MatchIndexOpts): this {
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

  override build(): ColumnSchema {
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
}
```

- [ ] **Step 5: Add all concrete classes and builder functions**

Add these class/function pairs exactly, using the domain constants from Step 1:

```ts
export class EncryptedInt4Column extends EncryptedV3Column<typeof INT4> {}
export const encryptedInt4Column = (columnName: string) => new EncryptedInt4Column(columnName, INT4)

export class EncryptedInt4EqColumn extends EncryptedV3Column<typeof INT4_EQ> {}
export const encryptedInt4EqColumn = (columnName: string) => new EncryptedInt4EqColumn(columnName, INT4_EQ)

export class EncryptedInt4OrdOreColumn extends EncryptedV3Column<typeof INT4_ORD_ORE> {}
export const encryptedInt4OrdOreColumn = (columnName: string) => new EncryptedInt4OrdOreColumn(columnName, INT4_ORD_ORE)

export class EncryptedInt4OrdColumn extends EncryptedV3Column<typeof INT4_ORD> {}
export const encryptedInt4OrdColumn = (columnName: string) => new EncryptedInt4OrdColumn(columnName, INT4_ORD)
```

Repeat the same exact pattern for:

```text
Int2: int2, int2_eq, int2_ord_ore, int2_ord -> castAs number
Int8: int8, int8_eq, int8_ord_ore, int8_ord -> castAs bigint
Date: date, date_eq, date_ord_ore, date_ord -> castAs date
Timestamptz: timestamptz, timestamptz_eq, timestamptz_ord_ore, timestamptz_ord -> castAs date
Numeric: numeric, numeric_eq, numeric_ord_ore, numeric_ord -> castAs number
Text: text, text_eq, text_match, text_ord_ore, text_ord -> castAs string
Bool: bool -> castAs boolean
Float4: float4, float4_eq, float4_ord_ore, float4_ord -> castAs number
Float8: float8, float8_eq, float8_ord_ore, float8_ord -> castAs number
```

For `text_match`, use `MATCH_ONLY`.

After adding all classes, add a compile-time guard test in `schema-v3.test-d.ts`:

```ts
it('v3 domain classes remain nominal by literal domain definition', () => {
  const int8 = encryptedInt8Column('id64')
  const bool = encryptedBoolColumn('active')

  expectTypeOf(int8).not.toEqualTypeOf<typeof bool>()

  // @ts-expect-error - storage-only bool is not assignable to storage-only int8
  const invalid: typeof int8 = bool
  void invalid
})
```

- [ ] **Step 6: Run runtime schema tests**

Run:

```bash
pnpm --filter @cipherstash/stack vitest run __tests__/schema-v3.test.ts
```

Expected: PASS for schema-v3 runtime tests. If class constructor visibility fails, make the base class constructor `public`.

---

### Task 4: Generalize v3 Table Column Types And Inference

**Files:**
- Modify: `packages/stack/src/schema/v3/index.ts`
- Modify: `packages/stack/__tests__/schema-v3.test-d.ts`

- [ ] **Step 1: Replace single-column v3 table type**

In `schema/v3/index.ts`, replace:

```ts
export type EncryptedV3TableColumn = {
  [key: string]: EncryptedTextSearchColumn
}
```

with:

```ts
export type AnyEncryptedV3Column =
  | EncryptedInt4Column
  | EncryptedInt4EqColumn
  | EncryptedInt4OrdOreColumn
  | EncryptedInt4OrdColumn
  | EncryptedInt2Column
  | EncryptedInt2EqColumn
  | EncryptedInt2OrdOreColumn
  | EncryptedInt2OrdColumn
  | EncryptedInt8Column
  | EncryptedInt8EqColumn
  | EncryptedInt8OrdOreColumn
  | EncryptedInt8OrdColumn
  | EncryptedDateColumn
  | EncryptedDateEqColumn
  | EncryptedDateOrdOreColumn
  | EncryptedDateOrdColumn
  | EncryptedTimestamptzColumn
  | EncryptedTimestamptzEqColumn
  | EncryptedTimestamptzOrdOreColumn
  | EncryptedTimestamptzOrdColumn
  | EncryptedNumericColumn
  | EncryptedNumericEqColumn
  | EncryptedNumericOrdOreColumn
  | EncryptedNumericOrdColumn
  | EncryptedTextColumn
  | EncryptedTextEqColumn
  | EncryptedTextMatchColumn
  | EncryptedTextOrdOreColumn
  | EncryptedTextOrdColumn
  | EncryptedTextSearchColumn
  | EncryptedBoolColumn
  | EncryptedFloat4Column
  | EncryptedFloat4EqColumn
  | EncryptedFloat4OrdOreColumn
  | EncryptedFloat4OrdColumn
  | EncryptedFloat8Column
  | EncryptedFloat8EqColumn
  | EncryptedFloat8OrdOreColumn
  | EncryptedFloat8OrdColumn

export type EncryptedV3TableColumn = {
  [key: string]: AnyEncryptedV3Column
}
```

- [ ] **Step 2: Add plaintext inference by literal domain definition**

Add:

```ts
type PlaintextFromKind<K extends PlaintextKind> =
  K extends 'string'
    ? string
    : K extends 'number'
      ? number
      : K extends 'bigint'
        ? bigint
        : K extends 'boolean'
          ? boolean
          : K extends 'date'
            ? Date
            : never

type PlaintextForColumn<C> =
  C extends EncryptedV3Column<infer D>
    ? PlaintextFromKind<D['castAs']>
    : never
```

Do not infer plaintext from a long subclass conditional. Empty subclasses that share the same base generic are structurally assignable; the private base field carrying the full literal domain definition is the stable type discriminator.

Then replace `InferPlaintext` with:

```ts
export type InferPlaintext<T extends EncryptedTable<EncryptedV3TableColumn>> =
  T extends EncryptedTable<infer C>
    ? { [K in keyof C]: PlaintextForColumn<C[K]> }
    : never
```

Keep `InferEncrypted` as `{ [K in keyof C]: Encrypted }`.

- [ ] **Step 3: Add type tests for mixed v3 table inference**

In `schema-v3.test-d.ts`, add:

```ts
it('InferPlaintext maps v3 concrete domains to plaintext TypeScript types', () => {
  const metrics = encryptedTable('metrics', {
    name: encryptedTextColumn('name'),
    age: encryptedInt4Column('age'),
    id64: encryptedInt8Column('id64'),
    active: encryptedBoolColumn('active'),
    createdAt: encryptedTimestamptzColumn('created_at'),
    score: encryptedFloat8Column('score'),
  })

  type Plaintext = InferPlaintext<typeof metrics>

  expectTypeOf<Plaintext>().toEqualTypeOf<{
    name: string
    age: number
    id64: bigint
    active: boolean
    createdAt: Date
    score: number
  }>()
})
```

- [ ] **Step 4: Run type tests and confirm expected failure before query type fixes**

Run:

```bash
pnpm --filter @cipherstash/stack test:types
```

Expected at this point: may FAIL because `BuildableQueryColumn` still accepts storage-only v3 columns. Continue to Task 5 before requiring a full pass.

---

### Task 5: Require v3 Query Capability Metadata For `encryptQuery`

**Files:**
- Modify: `packages/stack/src/types.ts`
- Modify: `packages/stack/__tests__/schema-v3.test-d.ts`

- [ ] **Step 1: Tighten `BuildableQueryColumn`**

In `types.ts`, replace:

```ts
export type BuildableQueryColumn =
  | EncryptedColumn
  | (BuildableColumn & { getEqlType(): string })
```

with:

```ts
export interface BuildableV3QueryableColumn extends BuildableColumn {
  getEqlType(): string
  getQueryCapabilities(): {
    equality: boolean
    orderAndRange: boolean
    freeTextSearch: boolean
  }
  isQueryable(): true
}

export type BuildableQueryColumn = EncryptedColumn | BuildableV3QueryableColumn
```

- [ ] **Step 2: Add positive and negative queryability type tests**

In `schema-v3.test-d.ts`, add:

```ts
it('encryptQuery accepts queryable v3 columns with explicit capability metadata', () => {
  const users = encryptedTable('users', {
    emailEq: encryptedTextEqColumn('email_eq'),
    emailMatch: encryptedTextMatchColumn('email_match'),
    emailSearch: encryptedTextSearchColumn('email_search'),
    createdAt: encryptedTimestamptzOrdColumn('created_at'),
  })
  const client = {} as EncryptionClient

  expectTypeOf(client.encryptQuery).toBeCallableWith('alice@example.com', {
    table: users,
    column: users.emailEq,
  })
  expectTypeOf(client.encryptQuery).toBeCallableWith('ali', {
    table: users,
    column: users.emailMatch,
    queryType: 'freeTextSearch',
  })
  expectTypeOf(client.encryptQuery).toBeCallableWith(new Date(), {
    table: users,
    column: users.createdAt,
    queryType: 'orderAndRange',
  })
  expectTypeOf(client.encryptQuery).toBeCallableWith('alice@example.com', {
    table: users,
    column: users.emailSearch,
    queryType: 'equality',
  })
})

it('encryptQuery rejects storage-only v3 columns at compile time', () => {
  const users = encryptedTable('users', {
    email: encryptedTextColumn('email'),
    active: encryptedBoolColumn('active'),
  })
  const client = {} as EncryptionClient

  client.encryptQuery('alice@example.com', {
    table: users,
    // @ts-expect-error - storage-only v3 text column is not queryable
    column: users.email,
  })

  client.encryptQuery(true, {
    table: users,
    // @ts-expect-error - storage-only v3 bool column is not queryable
    column: users.active,
  })
})
```

- [ ] **Step 3: Preserve literal `isQueryable()` inference in the base class**

In `schema/v3/index.ts`, storage-only class instances must have `isQueryable(): false` inferred through `QueryableFlag<D>`, and queryable class instances must have `isQueryable(): true`. Do not add per-class overrides unless TypeScript proves the base method fails; 40 overrides add noise and are not needed when domain constants remain `as const`.

- [ ] **Step 4: Add runtime capability-misuse tests**

In `schema-v3.test.ts`, import `resolveIndexType` from `@/encryption/helpers/infer-index-type` and add tests that call the query helper path with unsupported query types:

```ts
it('throws when querying a storage-only v3 column at runtime', () => {
  const raw = encryptedTextColumn('raw')
  expect(() => resolveIndexType(raw as never)).toThrow(/no indexes configured/)
})

it('throws when a query type is not configured on a queryable v3 column', () => {
  const matchOnly = encryptedTextMatchColumn('body')
  expect(() => resolveIndexType(matchOnly, 'equality')).toThrow(
    /Index type "unique" is not configured/,
  )
  expect(() => resolveIndexType(matchOnly, 'orderAndRange')).toThrow(
    /Index type "ore" is not configured/,
  )
})
```

- [ ] **Step 5: Run type tests**

Run:

```bash
pnpm --filter @cipherstash/stack test:types
```

Expected: PASS for `schema-v3.test-d.ts` and existing v2 compatibility type tests.

Do not make these tests green by weakening `toEqualTypeOf` assertions to `toMatchTypeOf`. The failure mode being guarded here is over-broad inference, so exact type equality is required.

---

### Task 6: Structurally Widen Model Encryption For v3 Tables

**Files:**
- Modify: `packages/stack/src/types.ts`
- Modify: `packages/stack/src/encryption/index.ts`
- Modify: `packages/stack/src/encryption/helpers/model-helpers.ts`
- Modify: `packages/stack/src/encryption/operations/encrypt-model.ts`
- Modify: `packages/stack/src/encryption/operations/bulk-encrypt-models.ts`
- Modify: `packages/stack/__tests__/schema-v3.test-d.ts`

- [ ] **Step 1: Add structural model schema types**

In `types.ts`, add after `BuildableTable`:

```ts
export type BuildableTableColumns<T extends BuildableTable> =
  T extends { readonly _columnType: infer C }
    ? C extends Record<string, unknown>
      ? C
      : never
    : never

export type EncryptedFromBuildableTable<T, Table extends BuildableTable> = {
  [K in keyof T]: [K] extends [keyof BuildableTableColumns<Table>]
    ? null extends T[K]
      ? Encrypted | null
      : Encrypted
    : T[K]
}
```

This must use the table's existing `_columnType` brand, not `build().columns`. `build()` intentionally returns `Record<string, ColumnSchema>`, which erases literal keys and would mark every model field as encrypted. Keep existing `EncryptedFromSchema` for v2 backward compatibility.

- [ ] **Step 2: Update client model method signatures**

In `encryption/index.ts`, change:

```ts
encryptModel<
  T extends Record<string, unknown>,
  S extends EncryptedTableColumn = EncryptedTableColumn,
>(
  input: T,
  table: EncryptedTable<S>,
): EncryptModelOperation<EncryptedFromSchema<T, S>>
```

to:

```ts
encryptModel<
  T extends Record<string, unknown>,
  Table extends BuildableTable,
>(
  input: T,
  table: Table,
): EncryptModelOperation<EncryptedFromBuildableTable<T, Table>>
```

Change `bulkEncryptModels` similarly:

```ts
bulkEncryptModels<
  T extends Record<string, unknown>,
  Table extends BuildableTable,
>(
  input: Array<T>,
  table: Table,
): BulkEncryptModelsOperation<EncryptedFromBuildableTable<T, Table>>
```

Add imports for `BuildableTable` and `EncryptedFromBuildableTable`.

- [ ] **Step 3: Update helper and operation table types**

In all listed files, replace:

```ts
EncryptedTable<EncryptedTableColumn>
```

with:

```ts
BuildableTable
```

For imports, remove v2 schema table imports and import `BuildableTable` from `@/types`.

Affected functions/properties:

```ts
prepareFieldsForEncryption(..., table: BuildableTable)
encryptModelFields(..., table: BuildableTable)
encryptModelFieldsWithLockContext(..., table: BuildableTable)
prepareBulkModelsForOperation(..., table?: BuildableTable)
bulkEncryptModels(..., table: BuildableTable)
bulkEncryptModelsWithLockContext(..., table: BuildableTable)
EncryptModelOperation.table
EncryptModelOperation.constructor table
EncryptModelOperation.getOperation().table
BulkEncryptModelsOperation.table
BulkEncryptModelsOperation.constructor table
BulkEncryptModelsOperation.getOperation().table
```

- [ ] **Step 4: Add model type tests for v3 tables**

In `schema-v3.test-d.ts`, add:

```ts
it('encryptModel and bulkEncryptModels infer encrypted fields from v3 tables', () => {
  const users = encryptedTable('users', {
    email: encryptedTextSearchColumn('email'),
    active: encryptedBoolColumn('active'),
  })
  const client = {} as EncryptionClient

  const encryptedOne = client.encryptModel(
    { id: 'u1', email: 'alice@example.com', active: true, untouched: 42 },
    users,
  )
  expectTypeOf(encryptedOne).toEqualTypeOf<
    import('@/encryption').EncryptModelOperation<{
      id: string
      email: Encrypted
      active: Encrypted
      untouched: number
    }>
  >()

  const encryptedMany = client.bulkEncryptModels(
    [{ id: 'u1', email: 'alice@example.com', active: true }],
    users,
  )
  expectTypeOf(encryptedMany).toEqualTypeOf<
    import('@/encryption').BulkEncryptModelsOperation<
      {
        id: string
        email: Encrypted
        active: Encrypted
      }
    >
  >()
})
```

Add nullable and v2 re-pinning cases:

```ts
it('v3 encryptModel preserves unrelated and nullable fields', () => {
  const users = encryptedTable('users', {
    email: encryptedTextSearchColumn('email'),
  })
  const client = {} as EncryptionClient

  const encrypted = client.encryptModel(
    { id: 'u1', email: null as string | null, untouched: 42 },
    users,
  )

  expectTypeOf(encrypted).toEqualTypeOf<
    import('@/encryption').EncryptModelOperation<{
      id: string
      email: Encrypted | null
      untouched: number
    }>
  >()
})

it('v2 encryptModel inference still preserves non-schema fields after widening', () => {
  const users = v2EncryptedTable('users', {
    email: encryptedColumn('email').equality(),
  })
  const client = {} as EncryptionClient

  const encrypted = client.encryptModel(
    { id: 'u1', email: 'alice@example.com', age: 30 },
    users,
  )

  expectTypeOf(encrypted).toEqualTypeOf<
    import('@/encryption').EncryptModelOperation<{
      id: string
      email: Encrypted
      age: number
    }>
  >()
})
```

- [ ] **Step 5: Run targeted type tests**

Run:

```bash
pnpm --filter @cipherstash/stack test:types
```

Expected: PASS. Existing v2 model typing should remain accepted.

---

### Task 7: Add Runtime Client Tests For Representative v3 Domains

**Files:**
- Modify: `packages/stack/__tests__/schema-v3-client.test.ts`

- [ ] **Step 1: Expand schema with representative domains**

Replace the current `users` schema with:

```ts
const users = encryptedTable('schema_v3_client_users', {
  email: encryptedTextSearchColumn('email'),
  age: encryptedInt4OrdColumn('age'),
  nickname: encryptedTextEqColumn('nickname'),
  body: encryptedTextMatchColumn('body'),
  notes: encryptedTextColumn('notes'),
  active: encryptedBoolColumn('active'),
  externalId: encryptedInt8Column('external_id'),
  createdOn: encryptedDateColumn('created_on'),
  occurredAt: encryptedTimestamptzColumn('occurred_at'),
})
```

- [ ] **Step 2: Add env-gated storage-only encryption tests**

Add:

```ts
it('encrypts and decrypts storage-only v3 columns', async () => {
  const encryptedText = unwrapResult(
    await protectClient.encrypt('private note', {
      table: users,
      column: users.notes,
    }),
  )
  expect(encryptedText).toMatchObject({
    i: { t: 'schema_v3_client_users', c: 'notes' },
    v: 2,
  })
  expect(encryptedText).toHaveProperty('c')
  expect(encryptedText).not.toHaveProperty('hm')
  expect(encryptedText).not.toHaveProperty('bf')
  expect(encryptedText).not.toHaveProperty('ob')
  expect(unwrapResult(await protectClient.decrypt(encryptedText))).toBe('private note')

  const encryptedBool = unwrapResult(
    await protectClient.encrypt(true, {
      table: users,
      column: users.active,
    }),
  )
  expect(encryptedBool).toHaveProperty('c')
  expect(unwrapResult(await protectClient.decrypt(encryptedBool))).toBe(true)
}, 30000)
```

- [ ] **Step 3: Add representative query tests**

Add:

```ts
it('encrypts equality and order query terms for typed v3 columns', async () => {
  const equalityTerm = unwrapResult(
    await protectClient.encryptQuery('ada', {
      table: users,
      column: users.nickname,
    }),
  )
  expect(equalityTerm).toHaveProperty('hm')
  expect(equalityTerm).not.toHaveProperty('c')

  const orderTerm = unwrapResult(
    await protectClient.encryptQuery(37, {
      table: users,
      column: users.age,
      queryType: 'orderAndRange',
    }),
  )
  expect(orderTerm).toHaveProperty('ob')
  expect(orderTerm).not.toHaveProperty('c')
}, 30000)
```

- [ ] **Step 4: Add `text_match`, bigint, and Date live checks**

Add:

```ts
it('encrypts free-text terms for text_match columns', async () => {
  const encrypted = unwrapResult(
    await protectClient.encrypt('Ada Lovelace wrote notes', {
      table: users,
      column: users.body,
    }),
  )
  expect(encrypted).toHaveProperty('c')
  expect(encrypted).toHaveProperty('bf')
  expect(encrypted).not.toHaveProperty('hm')
  expect(encrypted).not.toHaveProperty('ob')

  const matchTerm = unwrapResult(
    await protectClient.encryptQuery('Lovelace', {
      table: users,
      column: users.body,
      queryType: 'freeTextSearch',
    }),
  )
  expect(matchTerm).toHaveProperty('bf')
  expect(matchTerm).not.toHaveProperty('c')
}, 30000)

it('round-trips representative bigint and date-like v3 storage domains', async () => {
  const int8Encrypted = unwrapResult(
    await protectClient.encrypt(1234567890123456789n, {
      table: users,
      column: users.externalId,
    }),
  )
  expect(unwrapResult(await protectClient.decrypt(int8Encrypted))).toBe(1234567890123456789n)

  const day = new Date('2026-07-01T00:00:00.000Z')
  const dateEncrypted = unwrapResult(
    await protectClient.encrypt(day, {
      table: users,
      column: users.createdOn,
    }),
  )
  expect(unwrapResult(await protectClient.decrypt(dateEncrypted))).toEqual(day)
}, 30000)
```

- [ ] **Step 5: Run without credentials to verify skip behavior**

Run:

```bash
env -u CS_WORKSPACE_CRN -u CS_CLIENT_ID -u CS_CLIENT_KEY -u CS_CLIENT_ACCESS_KEY pnpm --filter @cipherstash/stack vitest run __tests__/schema-v3-client.test.ts
```

Expected: PASS with suite skipped; no module-load throw.

- [ ] **Step 6: Run with credentials when available**

Run:

```bash
pnpm --filter @cipherstash/stack vitest run __tests__/schema-v3-client.test.ts
```

Expected:
- If `CS_*` env vars are missing: PASS skipped.
- If `CS_*` env vars are present: PASS all live tests.

---

### Task 8: Preserve And Broaden Postgres v3 Tests Safely

**Files:**
- Modify: `packages/stack/__tests__/schema-v3-pg.test.ts`

- [ ] **Step 1: Keep `text_search` Postgres tests unchanged unless they fail**

Preserve:

```ts
const LIVE_EQL_V3_PG_ENABLED = Boolean(
  process.env.DATABASE_URL &&
    process.env.CS_WORKSPACE_CRN &&
    process.env.CS_CLIENT_ID &&
    process.env.CS_CLIENT_KEY &&
    process.env.CS_CLIENT_ACCESS_KEY,
)
const describeLivePg = LIVE_EQL_V3_PG_ENABLED ? describe : describe.skip
```

- [ ] **Step 2: Add one representative typed-column table when fixture supports it**

Before adding tests, run:

```bash
rg "CREATE DOMAIN|CREATE TYPE" packages/stack/__tests__/fixtures/eql-v3/cipherstash-encrypt-v3.sql | rg "int4_ord|text_eq|bool"
```

Expected: output includes `eql_v3.int4_ord`, `eql_v3.text_eq`, and `eql_v3.bool`.

If those exact domains are present, add a second schema:

```ts
const typedTable = encryptedTable('protect_ci_v3_typed_domains', {
  age: encryptedInt4OrdColumn('age'),
  nickname: encryptedTextEqColumn('nickname'),
  active: encryptedBoolColumn('active'),
})
```

and create:

```sql
CREATE TABLE IF NOT EXISTS protect_ci_v3_typed_domains (
  id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  age eql_v3.int4_ord NOT NULL,
  nickname eql_v3.text_eq NOT NULL,
  active eql_v3.bool NOT NULL,
  test_run_id TEXT NOT NULL
)
```

- [ ] **Step 3: Add representative PG roundtrip/query test if fixture supports domains**

Add:

```ts
it('round-trips and queries representative typed v3 domains', async () => {
  const age = unwrapResult(await protectClient.encrypt(37, { table: typedTable, column: typedTable.age }))
  const nickname = unwrapResult(await protectClient.encrypt('ada', { table: typedTable, column: typedTable.nickname }))
  const active = unwrapResult(await protectClient.encrypt(true, { table: typedTable, column: typedTable.active }))

  const [inserted] = await sql<{ id: number }[]>`
    INSERT INTO protect_ci_v3_typed_domains (age, nickname, active, test_run_id)
    VALUES (
      ${sql.json(age as postgres.JSONValue)}::eql_v3.int4_ord,
      ${sql.json(nickname as postgres.JSONValue)}::eql_v3.text_eq,
      ${sql.json(active as postgres.JSONValue)}::eql_v3.bool,
      ${TEST_RUN_ID}
    )
    RETURNING id
  `

  const ageTerm = unwrapResult(await protectClient.encryptQuery(30, {
    table: typedTable,
    column: typedTable.age,
    queryType: 'orderAndRange',
  })) as postgres.JSONValue

  const rows = await sql<{ id: number }[]>`
    SELECT id
    FROM protect_ci_v3_typed_domains
    WHERE test_run_id = ${TEST_RUN_ID}
      AND eql_v3.ord_term(age) >= eql_v3.ore_block_256(${sql.json(ageTerm)}::jsonb)
  `

  expect(rows.map((row) => row.id)).toContain(inserted.id)
}, 30000)
```

If the fixture does not expose these exact domains, do not add this test. Keep existing `text_search` PG coverage as the live SQL proof for this pass.

- [ ] **Step 4: Verify skip and live behavior**

Run:

```bash
env -u DATABASE_URL pnpm --filter @cipherstash/stack vitest run __tests__/schema-v3-pg.test.ts
```

Expected: PASS skipped; no module-load throw.

Run with DB/env only when available:

```bash
pnpm --filter @cipherstash/stack vitest run __tests__/schema-v3-pg.test.ts
```

Expected:
- Missing env: PASS skipped.
- Present env and fixture installed: PASS.

---

### Task 9: Fix Or Isolate `wasm-inline-column-name.test.ts` Import Resolution

**Files:**
- Modify: `packages/stack/vitest.config.ts`
- Modify only if needed: `packages/stack/__tests__/wasm-inline-column-name.test.ts`

- [ ] **Step 1: Reproduce current failure**

Run:

```bash
pnpm --filter @cipherstash/stack vitest run __tests__/wasm-inline-column-name.test.ts
```

Expected current failure: Vitest cannot resolve or load `@cipherstash/protect-ffi/wasm-inline`.

- [ ] **Step 2: Prefer local mocks for this unit test**

At the top of `wasm-inline-column-name.test.ts`, before importing `../src/wasm-inline`, add:

```ts
import { vi } from 'vitest'

vi.mock('@cipherstash/auth/wasm-inline', () => ({
  AccessKeyStrategy: {
    create: vi.fn(),
  },
}))

vi.mock('@cipherstash/protect-ffi/wasm-inline', () => ({
  decrypt: vi.fn(),
  encrypt: vi.fn(),
  isEncrypted: vi.fn(),
  newClient: vi.fn(),
}))
```

This test only covers `getColumnName`; it does not need real WASM.

- [ ] **Step 3: Add Vitest alias only if mocking does not resolve import evaluation**

Inspect package path:

```bash
node -p "require.resolve('@cipherstash/protect-ffi/package.json')"
```

Inspect exports:

```bash
node -p "JSON.stringify(require('@cipherstash/protect-ffi/package.json').exports, null, 2)"
```

If the export points to a concrete JS file and mocks are insufficient, add an alias in `vitest.config.ts` using the actual export path.

- [ ] **Step 4: Run the focused test**

Run:

```bash
pnpm --filter @cipherstash/stack vitest run __tests__/wasm-inline-column-name.test.ts
```

Expected: PASS.

---

### Task 10: Validate Package Export And Build Compatibility

**Files:**
- Modify only if failing: `packages/stack/package.json`
- Modify only if failing: `packages/stack/tsup.config.ts`

- [ ] **Step 1: Confirm `schema/v3` remains exported for ESM and CJS**

Run:

```bash
node -p "const p=require('./packages/stack/package.json'); p.exports['./schema/v3']"
```

Expected includes both:

```text
import.types ./dist/schema/v3/index.d.ts
import.default ./dist/schema/v3/index.js
require.types ./dist/schema/v3/index.d.cts
require.default ./dist/schema/v3/index.cjs
```

- [ ] **Step 2: Confirm tsup includes v3 entry**

Run:

```bash
rg "src/schema/v3/index.ts" packages/stack/tsup.config.ts
```

Expected: one match in the main dual-format entry list.

- [ ] **Step 3: Build stack package**

Run:

```bash
pnpm --filter @cipherstash/stack build
```

Expected: PASS. `dist/schema/v3/index.d.ts`, `.d.cts`, `.js`, and `.cjs` are generated.

- [ ] **Step 4: Verify CJS require remains supported**

Run:

```bash
pnpm --filter @cipherstash/stack vitest run __tests__/cjs-require.test.ts
```

Expected: PASS. If no v3 CJS assertion exists, add:

```ts
const schemaV3 = require('@cipherstash/stack/schema/v3')
expect(typeof schemaV3.encryptedTextSearchColumn).toBe('function')
expect(typeof schemaV3.encryptedInt4Column).toBe('function')
```

---

### Task 11: Add Changeset

**Files:**
- Create: `.changeset/eql-v3-typed-schema.md`

- [ ] **Step 1: Add changeset file**

Create:

```md
---
'@cipherstash/stack': minor
---

Add EQL v3 schema builders for all generated SQL domains under `@cipherstash/stack/schema/v3`, including explicit query capability metadata and v3 table support in model encryption helpers.
```

- [ ] **Step 2: Verify changeset format**

Run:

```bash
pnpm changeset status
```

Expected: command reports a pending minor changeset for `@cipherstash/stack`.

---

### Task 12: Full Verification Pass

**Files:**
- All changed files above.

- [ ] **Step 1: Run formatter/fixer**

Run:

```bash
pnpm run code:fix
```

Expected: PASS; files may be formatted.

- [ ] **Step 2: Run focused stack tests**

Run:

```bash
pnpm --filter @cipherstash/stack vitest run __tests__/schema-v3.test.ts __tests__/schema-v3-client.test.ts __tests__/schema-v3-pg.test.ts __tests__/wasm-inline-column-name.test.ts
```

Expected:
- Unit tests PASS.
- Live tests PASS skipped when env vars are missing.
- No module-load failures when env vars are missing.

- [ ] **Step 3: Run type tests**

Run:

```bash
pnpm --filter @cipherstash/stack test:types
```

Expected: PASS.

- [ ] **Step 4: Run package build**

Run:

```bash
pnpm --filter @cipherstash/stack build
```

Expected: PASS.

- [ ] **Step 5: Run package test suite if credentials are available**

Run:

```bash
pnpm --filter @cipherstash/stack test
```

Expected:
- With credentials: PASS, including live tests.
- Without credentials: PASS for unit tests and env-gated live suites skipped. If unrelated existing live tests fail due to missing `CS_*`, record that explicitly in the final implementation notes.

---

## Commit Plan

- [ ] Commit 1: `test: cover eql v3 typed schema domains`
  - Include `schema-v3.test.ts` and `schema-v3.test-d.ts` failing tests.
- [ ] Commit 2: `feat: add eql v3 domain builders`
  - Include `schema/v3/index.ts`.
- [ ] Commit 3: `feat: support v3 tables in model encryption`
  - Include `types.ts`, encryption client/helper/operation files, and model type tests.
- [ ] Commit 4: `test: stabilize v3 client and wasm-inline coverage`
  - Include live test updates and Vitest/WASM test fix.
- [ ] Commit 5: `changeset: document eql v3 typed schema`
  - Include `.changeset/eql-v3-typed-schema.md`.

---

## Self-Review

**Spec coverage:** This plan keeps v3 isolated under `@cipherstash/stack/schema/v3`, exports one builder per EQL v3 domain, preserves v2 schema, adds explicit `getQueryCapabilities()` and `isQueryable()`, tightens `BuildableQueryColumn`, widens model helpers structurally, preserves `text_search` byte-equivalent config, keeps `EncryptConfig` free of v3 metadata, env-gates live tests, and addresses `wasm-inline` Vitest resolution.

**Review-driven corrections:** The design intentionally uses a full literal domain definition generic (`eqlType`, `castAs`, and capabilities), not a capability-only generic, because empty TypeScript subclasses are not nominal. Model encryption inference intentionally reads table keys from the existing `_columnType` brand, not `build().columns`, because the structural `BuildableTable.build()` contract erases literal keys to `Record<string, ColumnSchema>`.

**Placeholder scan:** No task uses unresolved placeholders. Conditional Postgres expansion is tied to a concrete `rg` command and an explicit keep-existing-tests outcome.

**Type consistency:** Public capability names are consistently `equality`, `orderAndRange`, and `freeTextSearch`. Queryable v3 columns require `isQueryable(): true`; storage-only columns return `false` and remain accepted by `encrypt` through `BuildableColumn`.
