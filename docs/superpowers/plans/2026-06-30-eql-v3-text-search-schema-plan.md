# EQL v3 `text_search` Schema DSL Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an EQL v3 authoring DSL (`encryptedTextSearchColumn`, plus v3 `encryptedTable` / `buildEncryptConfig`) on a new `@cipherstash/stack/schema/v3` subpath that emits the existing `EncryptConfig` shape with zero native-client changes.

**Architecture:** A new, self-contained module at `packages/stack/src/schema/v3/index.ts` mirrors the v2 builder structure but exposes one concrete type — `EncryptedTextSearchColumn` — whose capabilities (equality + order/range + free-text match) are baked in. Its `build()` returns the **same** `ColumnSchema` a fully-configured v2 column produces, so the encryption client, payload, and query paths are untouched. The v2 module (`src/schema/index.ts`) is not modified.

**Tech Stack:** TypeScript (ES2022, bundler module resolution), Zod 3.25.76, Vitest 3, tsup (dual ESM+CJS build), Biome (formatting/lint).

## Global Constraints

- **Do NOT modify** `packages/stack/src/schema/index.ts` (the v2 module). v3 is purely additive.
- v3 builders MUST emit the existing `ColumnSchema` / `EncryptConfig` shape imported from `@/schema` — reuse the v2 types, do not redefine them.
- `cast_as` MUST be the SDK-facing literal `'string'` (NOT `'text'`). `toEqlCastAs` is a v2/wasm-inline concern and is out of scope here.
- Match-index defaults MUST mirror the v2 `freeTextSearch()` builder **exactly**: `tokenizer: { kind: 'ngram', token_length: 3 }`, `token_filters: [{ kind: 'downcase' }]`, `k: 6`, `m: 2048`, `include_original: true`. (Note: `include_original` is `true` — the v2 builder default, not the zod-schema default of `false`.)
- `unique.token_filters` defaults to `[]` (case-sensitive equality, matching v2).
- `.freeTextSearch(opts?)` is **tuning only** — it overrides match-index params and NEVER enables a capability. Merge semantics are per-top-level-key replace against the defaults (mirror v2's `opts?.x ?? default`).
- `EncryptedTextSearchColumn` records `eqlType = 'eql_v3.text_search'`, exposed via a getter / `getEqlType()`. This value is metadata for future increments and MUST be absent from `build()` output.
- v3 `encryptedTable` and `buildEncryptConfig` intentionally shadow the v2 symbol names; they live only on the `/v3` subpath. `buildEncryptConfig` emits `{ v: 1, tables }`.
- Tests live in `packages/stack/__tests__/`, named `*.test.ts` (runtime) and `*.test-d.ts` (type-level, run with `--typecheck`). Source imports use the `@/` alias (`@/schema`, `@/schema/v3`, `@/types`).
- Run all commands from `packages/stack/` unless noted. The test runner is `pnpm exec vitest`.
- Keep changes Biome-clean (2-space indent, single quotes, no semicolons — match the surrounding files).

## File Structure

- **Create:** `packages/stack/src/schema/v3/index.ts` — the entire v3 DSL: `EncryptedTextSearchColumn`, v3 `EncryptedTable`, `encryptedTextSearchColumn`, `encryptedTable`, `buildEncryptConfig`, `InferPlaintext`, `InferEncrypted`, and the `EncryptedV3TableColumn` shape type. Single focused file (the spec allows splitting later if it grows).
- **Create:** `packages/stack/__tests__/schema-v3.test.ts` — runtime behavior tests.
- **Create:** `packages/stack/__tests__/schema-v3.test-d.ts` — type-level inference tests.
- **Modify:** `packages/stack/tsup.config.ts` — add `src/schema/v3/index.ts` to the main config's `entry` array.
- **Modify:** `packages/stack/package.json` — add the `./schema/v3` export and `typesVersions` entry.

---

### Task 1: `EncryptedTextSearchColumn` builder

**Files:**
- Create: `packages/stack/src/schema/v3/index.ts`
- Test: `packages/stack/__tests__/schema-v3.test.ts`

**Interfaces:**
- Consumes (from v2, `@/schema`): `type CastAs`, `type ColumnSchema`, `type MatchIndexOpts`, the runtime builder `encryptedColumn` (test only, for the equivalence assertion).
- Produces:
  - `class EncryptedTextSearchColumn` with:
    - `constructor(columnName: string)`
    - `freeTextSearch(opts?: MatchIndexOpts): this`
    - `build(): ColumnSchema`
    - `getName(): string`
    - `getEqlType(): 'eql_v3.text_search'` and a `get eqlType(): 'eql_v3.text_search'` getter
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
    expect(built).toEqual({
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
    expect(v3).toEqual(v2)
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

  it('.freeTextSearch() is tuning-only: unique and ore indexes stay present', () => {
    const built = encryptedTextSearchColumn('email')
      .freeTextSearch({ k: 8 })
      .build()
    expect(built.indexes.unique).toEqual({ token_filters: [] })
    expect(built.indexes.ore).toEqual({})
  })

  it('getEqlType() / eqlType getter return the concrete domain name', () => {
    const col = encryptedTextSearchColumn('email')
    expect(col.getEqlType()).toBe('eql_v3.text_search')
    expect(col.eqlType).toBe('eql_v3.text_search')
  })

  it('eqlType metadata is absent from build() output', () => {
    const built = encryptedTextSearchColumn('email').build()
    expect(built).not.toHaveProperty('eqlType')
    expect(Object.keys(built).sort()).toEqual(['cast_as', 'indexes'])
  })
})
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pnpm exec vitest run __tests__/schema-v3.test.ts`
Expected: FAIL — module resolution error `Failed to resolve import "@/schema/v3"` (the file does not exist yet).

- [ ] **Step 3: Create the v3 module with the column builder**

Create `packages/stack/src/schema/v3/index.ts`:

```ts
import type { CastAs, ColumnSchema, MatchIndexOpts } from '@/schema'

/**
 * The concrete EQL v3 domain name for a full-capability text column.
 * Recorded as metadata for future DDL / query-dialect increments; it is
 * intentionally absent from the emitted encrypt config.
 */
export const TEXT_SEARCH_EQL_TYPE = 'eql_v3.text_search'

/**
 * Default match-index parameters. These mirror the v2 `freeTextSearch()`
 * builder defaults EXACTLY (note `include_original: true`, which is the v2
 * builder default rather than the zod-schema default of `false`).
 */
const DEFAULT_MATCH_OPTS: Required<MatchIndexOpts> = {
  tokenizer: { kind: 'ngram', token_length: 3 },
  token_filters: [{ kind: 'downcase' }],
  k: 6,
  m: 2048,
  include_original: true,
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
  private matchOpts: Required<MatchIndexOpts>

  constructor(columnName: string) {
    this.columnName = columnName
    this.matchOpts = { ...DEFAULT_MATCH_OPTS }
  }

  /** The concrete EQL v3 domain name. Metadata only; not emitted by `build()`. */
  get eqlType(): typeof TEXT_SEARCH_EQL_TYPE {
    return TEXT_SEARCH_EQL_TYPE
  }

  /** The concrete EQL v3 domain name. Metadata only; not emitted by `build()`. */
  getEqlType(): typeof TEXT_SEARCH_EQL_TYPE {
    return TEXT_SEARCH_EQL_TYPE
  }

  /**
   * Tune the match index. Each provided key replaces its default; omitted
   * keys keep the default. This NEVER enables a capability — match is always
   * on for this type. Merge semantics mirror v2's `opts?.x ?? default`.
   */
  freeTextSearch(opts?: MatchIndexOpts): this {
    this.matchOpts = {
      tokenizer: opts?.tokenizer ?? DEFAULT_MATCH_OPTS.tokenizer,
      token_filters: opts?.token_filters ?? DEFAULT_MATCH_OPTS.token_filters,
      k: opts?.k ?? DEFAULT_MATCH_OPTS.k,
      m: opts?.m ?? DEFAULT_MATCH_OPTS.m,
      include_original:
        opts?.include_original ?? DEFAULT_MATCH_OPTS.include_original,
    }
    return this
  }

  /** Emit the encrypt-config column. Byte-identical to a v2 equality+order+match column. */
  build(): ColumnSchema {
    const castAs: CastAs = 'string'
    return {
      cast_as: castAs,
      indexes: {
        unique: { token_filters: [] },
        ore: {},
        match: this.matchOpts,
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
Expected: PASS (all 7 tests in this file green).

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
  - `type InferPlaintext<T extends EncryptedTable<any>>` → `{ [col]: string }`
  - `type InferEncrypted<T extends EncryptedTable<any>>` → `{ [col]: Encrypted }`

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
    expect(built.columns).toEqual({
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
  CastAs,
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

/** Infer the plaintext (decrypted) shape from a v3 table schema. */
export type InferPlaintext<T extends EncryptedTable<any>> =
  T extends EncryptedTable<infer C>
    ? {
        [K in keyof C as C[K] extends EncryptedTextSearchColumn
          ? K
          : never]: string
      }
    : never

/** Infer the encrypted shape from a v3 table schema. */
export type InferEncrypted<T extends EncryptedTable<any>> =
  T extends EncryptedTable<infer C>
    ? {
        [K in keyof C as C[K] extends EncryptedTextSearchColumn
          ? K
          : never]: Encrypted
      }
    : never
```

Note: the `CastAs` import is still used by Task 1's `build()`; keep it in the import list.

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

### Task 4: Type-level inference tests

**Files:**
- Create: `packages/stack/__tests__/schema-v3.test-d.ts`

**Interfaces:**
- Consumes: `encryptedTable`, `encryptedTextSearchColumn`, `type EncryptedTextSearchColumn`, `type InferEncrypted`, `type InferPlaintext` from `@/schema/v3`; `type Encrypted` from `@/types`.

- [ ] **Step 1: Write the failing type test**

Create `packages/stack/__tests__/schema-v3.test-d.ts`:

```ts
import { describe, expectTypeOf, it } from 'vitest'
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
    expectTypeOf(col).toMatchTypeOf<EncryptedTextSearchColumn>()
  })

  it('encryptedTable exposes column builders as typed properties', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    expectTypeOf(users.email).toMatchTypeOf<EncryptedTextSearchColumn>()
    expectTypeOf(users.tableName).toBeString()
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

- [ ] **Step 2: Run the type test to verify it passes**

Type-level (`.test-d.ts`) files only execute under Vitest's typecheck mode.

Run: `pnpm exec vitest --run --typecheck __tests__/schema-v3.test-d.ts`
Expected: PASS — no type errors reported. (If `@/schema/v3` types were missing or `InferPlaintext`/`InferEncrypted` produced the wrong shape, `toEqualTypeOf` would surface a type error here. Because Tasks 1-2 already define these, this file type-checks green on first run; if it fails, fix the inference helpers in `src/schema/v3/index.ts` before continuing.)

- [ ] **Step 3: Run the full v3 runtime suite as a final guard**

Run: `pnpm exec vitest run __tests__/schema-v3.test.ts`
Expected: PASS (all runtime tests still green — no regression from the type-test file).

- [ ] **Step 4: Commit**

```bash
git add packages/stack/__tests__/schema-v3.test-d.ts
git commit -m "test(stack): type-level inference tests for eql_v3 schema DSL"
```

---

## Self-Review

**Spec coverage:**
- Public API (`encryptedTextSearchColumn`, v3 `encryptedTable`, v3 `buildEncryptConfig`) → Tasks 1-2.
- `.freeTextSearch(opts?)` as tuning-only with per-key replace merge → Task 1, Steps 1 & 3 (override + tuning-only tests).
- Pinned `build()` output (`cast_as: 'string'` + three indexes, defaults) → Task 1, default-config test.
- Load-bearing v2/v3 equivalence assertion → Task 1, "LOAD-BEARING" test (imports v2 `encryptedColumn`).
- `eqlType = 'eql_v3.text_search'` via getter, absent from `build()` → Task 1, getEqlType + absence tests.
- `buildEncryptConfig` → valid `EncryptConfig` (`v: 1`) passing `encryptConfigSchema.parse` → Task 2.
- `InferPlaintext` / `InferEncrypted` → Task 4 (type) + Task 2 (definition).
- New `@cipherstash/stack/schema/v3` subpath (exports + tsup) → Task 3.
- v2 module untouched → enforced by Global Constraints; no task edits `src/schema/index.ts`.
- Non-goals (DDL, transition tooling, query dialect, other concrete types, nested fields) → not implemented (correctly out of scope).

**Placeholder scan:** No TBD/TODO/"handle edge cases" present; every code step contains complete, runnable code.

**Type consistency:** `EncryptedTextSearchColumn`, `encryptedTextSearchColumn`, `EncryptedTable`, `encryptedTable`, `buildEncryptConfig`, `EncryptedV3TableColumn`, `InferPlaintext`, `InferEncrypted`, `TEXT_SEARCH_EQL_TYPE`, `DEFAULT_MATCH_OPTS`, and `getEqlType()`/`eqlType` are used identically across tasks and tests. `build()` returns `ColumnSchema`; `EncryptedTable.build()` returns the local `TableDefinition` (`{ tableName, columns: Record<string, ColumnSchema> }`), matching `buildEncryptConfig`'s consumption.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-06-30-eql-v3-text-search-schema-plan.md`. Two execution options:

1. **Subagent-Driven (recommended)** — dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
</content>
</invoke>
