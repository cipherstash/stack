import type { ColumnSchema, EncryptConfig, MatchIndexOpts } from '@/schema'
import type { Encrypted } from '@/types'

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
