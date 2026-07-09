import { z } from 'zod'
import type { BuildableTable, Encrypted } from '@/types'
import { resolveMatchOpts } from './match-defaults'

// ------------------------
// Zod schemas
// ------------------------

/**
 * Allowed cast types for CipherStash schema fields.
 *
 * **Possible values:**
 * - `"bigint"`
 * - `"boolean"`
 * - `"date"`
 * - `"timestamp"`
 * - `"number"`
 * - `"string"`
 * - `"json"`
 * - `"text"`
 *
 * @remarks
 * This is a Zod enum used at runtime to validate schema definitions.
 * Use {@link CastAs} when typing your own code.
 *
 * @internal
 */
/**
 * EQL cast types — the PostgreSQL-aligned types that EQL actually accepts.
 * These are stored in the `cast_as` field of the EncryptConfig.
 */
export const eqlCastAsEnum = z
  .enum([
    'text',
    'int',
    'small_int',
    'big_int',
    'real',
    'double',
    'boolean',
    'date',
    'timestamp',
    'jsonb',
  ])
  .default('text')

/**
 * SDK-facing data types — developer-friendly aliases accepted by `dataType()`.
 *
 * `timestamp` is distinct from `date`: `date` is calendar-date only (time-of-day
 * truncated to midnight), while `timestamp` preserves the full date+time. v3
 * `timestamp` domains set `cast_as: 'timestamp'` so the FFI keeps the instant.
 */
export const castAsEnum = z
  .enum([
    'bigint',
    'boolean',
    'date',
    'timestamp',
    'number',
    'string',
    'json',
    'text',
  ])
  .default('text')

/**
 * Map SDK-facing data types to EQL `cast_as` values.
 *
 * The SDK accepts developer-friendly types like `'string'` and `'number'`,
 * but EQL expects PostgreSQL-aligned types like `'text'` and `'double'`.
 */
export function toEqlCastAs(value: CastAs): EqlCastAs {
  switch (value) {
    case 'string':
      return 'text'
    case 'text':
      return 'text'
    case 'number':
      return 'double'
    case 'bigint':
      return 'big_int'
    case 'boolean':
      return 'boolean'
    case 'date':
      return 'date'
    case 'timestamp':
      return 'timestamp'
    case 'json':
      return 'jsonb'
  }
}

const tokenFilterSchema = z.object({
  kind: z.literal('downcase'),
})

const tokenizerSchema = z
  .union([
    z.object({
      kind: z.literal('standard'),
    }),
    z.object({
      kind: z.literal('ngram'),
      token_length: z.number(),
    }),
  ])
  .default({ kind: 'ngram', token_length: 3 })
  .optional()

const oreIndexOptsSchema = z.object({})

const uniqueIndexOptsSchema = z.object({
  token_filters: z.array(tokenFilterSchema).default([]).optional(),
})

const matchIndexOptsSchema = z.object({
  tokenizer: tokenizerSchema,
  token_filters: z.array(tokenFilterSchema).default([]).optional(),
  k: z.number().default(6).optional(),
  m: z.number().default(2048).optional(),
  include_original: z.boolean().default(false).optional(),
})

const arrayIndexModeSchema = z.union([
  z.literal('all'),
  z.literal('none'),
  z.object({
    item: z.boolean().optional(),
    wildcard: z.boolean().optional(),
    position: z.boolean().optional(),
  }),
])

const steVecIndexOptsSchema = z.object({
  prefix: z.string(),
  array_index_mode: arrayIndexModeSchema.optional(),
})

const indexesSchema = z
  .object({
    ore: oreIndexOptsSchema.optional(),
    unique: uniqueIndexOptsSchema.optional(),
    match: matchIndexOptsSchema.optional(),
    ste_vec: steVecIndexOptsSchema.optional(),
  })
  .default({})

const columnSchema = z
  .object({
    cast_as: castAsEnum,
    indexes: indexesSchema,
  })
  .default({})

const tableSchema = z.record(columnSchema).default({})

const tablesSchema = z.record(tableSchema).default({})

/** @internal */
export const encryptConfigSchema = z.object({
  v: z.number(),
  tables: tablesSchema,
})

// ------------------------
// Type definitions
// ------------------------

/**
 * Type-safe alias for {@link castAsEnum} used to specify the *unencrypted* data type of a column or value.
 * This is important because once encrypted, all data is stored as binary blobs.
 *
 * @see {@link castAsEnum} for possible values.
 */
export type CastAs = z.infer<typeof castAsEnum>
export type EqlCastAs = z.infer<typeof eqlCastAsEnum>
export type TokenFilter = z.infer<typeof tokenFilterSchema>
export type MatchIndexOpts = z.infer<typeof matchIndexOptsSchema>
export type SteVecIndexOpts = z.infer<typeof steVecIndexOptsSchema>
export type UniqueIndexOpts = z.infer<typeof uniqueIndexOptsSchema>
export type OreIndexOpts = z.infer<typeof oreIndexOptsSchema>
export type ColumnSchema = z.infer<typeof columnSchema>

/**
 * Shape of table columns: either top-level {@link EncryptedColumn} or nested
 * objects whose leaves are {@link EncryptedField}. Used with {@link encryptedTable}.
 */
export type EncryptedTableColumn = {
  [key: string]:
    | EncryptedColumn
    | {
        [key: string]:
          | EncryptedField
          | {
              [key: string]:
                | EncryptedField
                | {
                    [key: string]: EncryptedField
                  }
            }
      }
}
export type EncryptConfig = z.infer<typeof encryptConfigSchema>

// ------------------------
// Interface definitions
// ------------------------

/**
 * Builder for a nested encrypted field (encrypted but not searchable).
 * Create with {@link encryptedField}. Use inside nested objects in {@link encryptedTable};
 * supports `.dataType()` for plaintext type. No index methods (equality, orderAndRange, etc.).
 */
export class EncryptedField {
  private valueName: string
  private castAsValue: CastAs

  constructor(valueName: string) {
    this.valueName = valueName
    this.castAsValue = 'string'
  }

  /**
   * Set or override the plaintext data type for this field.
   *
   * By default all values are treated as `'string'`. Use this method to specify
   * a different type so the encryption layer knows how to encode the plaintext
   * before encrypting.
   *
   * @param castAs - The plaintext data type: `'string'`, `'number'`, `'boolean'`, `'date'`, `'timestamp'`, `'text'`, `'bigint'`, or `'json'`. Use `'timestamp'` (not `'date'`) to preserve time-of-day — `'date'` truncates to midnight.
   * @returns This `EncryptedField` instance for method chaining.
   *
   * @example
   * ```typescript
   * import { encryptedField } from "@cipherstash/stack/schema"
   *
   * const age = encryptedField("age").dataType("number")
   * ```
   */
  dataType(castAs: CastAs) {
    this.castAsValue = castAs
    return this
  }

  build() {
    return {
      cast_as: this.castAsValue,
      indexes: {},
    }
  }

  getName() {
    return this.valueName
  }
}

export class EncryptedColumn {
  private columnName: string
  private castAsValue: CastAs
  private indexesValue: {
    ore?: OreIndexOpts
    unique?: UniqueIndexOpts
    match?: Required<MatchIndexOpts>
    ste_vec?: SteVecIndexOpts
  } = {}

  constructor(columnName: string) {
    this.columnName = columnName
    this.castAsValue = 'string'
  }

  /**
   * Set or override the plaintext data type for this column.
   *
   * By default all columns are treated as `'string'`. Use this method to specify
   * a different type so the encryption layer knows how to encode the plaintext
   * before encrypting.
   *
   * @param castAs - The plaintext data type: `'string'`, `'number'`, `'boolean'`, `'date'`, `'timestamp'`, `'text'`, `'bigint'`, or `'json'`. Use `'timestamp'` (not `'date'`) to preserve time-of-day — `'date'` truncates to midnight.
   * @returns This `EncryptedColumn` instance for method chaining.
   *
   * @example
   * ```typescript
   * import { encryptedColumn } from "@cipherstash/stack/schema"
   *
   * const dateOfBirth = encryptedColumn("date_of_birth").dataType("date")
   * ```
   */
  dataType(castAs: CastAs) {
    this.castAsValue = castAs
    return this
  }

  /**
   * Enable Order-Revealing Encryption (ORE) indexing on this column.
   *
   * ORE allows sorting, comparison, and range queries on encrypted data.
   * Use with `encryptQuery` and `queryType: 'orderAndRange'`.
   *
   * @returns This `EncryptedColumn` instance for method chaining.
   *
   * @example
   * ```typescript
   * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
   *
   * const users = encryptedTable("users", {
   *   email: encryptedColumn("email").orderAndRange(),
   * })
   * ```
   */
  orderAndRange() {
    this.indexesValue.ore = {}
    return this
  }

  /**
   * Enable an exact-match (unique) index on this column.
   *
   * Allows equality queries on encrypted data. Use with `encryptQuery`
   * and `queryType: 'equality'`.
   *
   * @param tokenFilters - Optional array of token filters (e.g. `[{ kind: 'downcase' }]`).
   *   When omitted, no token filters are applied.
   * @returns This `EncryptedColumn` instance for method chaining.
   *
   * @example
   * ```typescript
   * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
   *
   * const users = encryptedTable("users", {
   *   email: encryptedColumn("email").equality(),
   * })
   * ```
   */
  equality(tokenFilters?: TokenFilter[]) {
    this.indexesValue.unique = {
      token_filters: tokenFilters ?? [],
    }
    return this
  }

  /**
   * Enable a full-text / fuzzy search (match) index on this column.
   *
   * Uses n-gram tokenization by default for substring and fuzzy matching.
   * Use with `encryptQuery` and `queryType: 'freeTextSearch'`.
   *
   * @param opts - Optional match index configuration. Defaults to 3-character ngram
   *   tokenization with a downcase filter, `k=6`, `m=2048`, and `include_original=true`.
   * @returns This `EncryptedColumn` instance for method chaining.
   *
   * @example
   * ```typescript
   * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
   *
   * const users = encryptedTable("users", {
   *   email: encryptedColumn("email").freeTextSearch(),
   * })
   *
   * // With custom options
   * const posts = encryptedTable("posts", {
   *   body: encryptedColumn("body").freeTextSearch({
   *     tokenizer: { kind: "ngram", token_length: 4 },
   *     k: 8,
   *     m: 4096,
   *   }),
   * })
   * ```
   */
  freeTextSearch(opts?: MatchIndexOpts) {
    // Shared merge+clone (schema/match-defaults) — one source of truth with the
    // EQL v3 domain builders. `resolveMatchOpts` deep-clones, so a caller
    // mutating their own `opts` (or its nested tokenizer/token_filters) after
    // this call cannot leak into the stored schema.
    this.indexesValue.match = resolveMatchOpts(opts)
    return this
  }

  /**
   * Configure this column for searchable encrypted JSON (STE-Vec).
   *
   * Enables encrypted JSONPath selector queries (e.g. `'$.user.email'`) and
   * containment queries (e.g. `{ role: 'admin' }`). Automatically sets the
   * data type to `'json'`.
   *
   * When used with `encryptQuery`, the query operation is auto-inferred from
   * the plaintext type: strings become selector queries, objects/arrays become
   * containment queries.
   *
   * @returns This `EncryptedColumn` instance for method chaining.
   *
   * @example
   * ```typescript
   * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
   *
   * const documents = encryptedTable("documents", {
   *   metadata: encryptedColumn("metadata").searchableJson(),
   * })
   * ```
   */
  searchableJson() {
    this.castAsValue = 'json'
    this.indexesValue.ste_vec = { prefix: 'enabled', array_index_mode: 'all' }
    return this
  }

  build() {
    return {
      cast_as: this.castAsValue,
      indexes: this.indexesValue,
    }
  }

  getName() {
    return this.columnName
  }
}

interface TableDefinition {
  tableName: string
  columns: Record<string, ColumnSchema>
}

export class EncryptedTable<T extends EncryptedTableColumn> {
  /** @internal Type-level brand so TypeScript can infer `T` from `EncryptedTable<T>`. */
  declare readonly _columnType: T

  constructor(
    public readonly tableName: string,
    public readonly columnBuilders: T,
  ) {}

  /**
   * Compile this table schema into a `TableDefinition` used internally by the encryption client.
   *
   * Iterates over all column builders, calls `.build()` on each, and assembles
   * the final `{ tableName, columns }` structure. For `searchableJson()` columns,
   * the STE-Vec prefix is automatically set to `"<tableName>/<columnName>"`.
   *
   * @returns A `TableDefinition` containing the table name and built column configs.
   *
   * @example
   * ```typescript
   * const users = encryptedTable("users", {
   *   email: encryptedColumn("email").equality(),
   * })
   *
   * const definition = users.build()
   * // { tableName: "users", columns: { email: { cast_as: "string", indexes: { unique: ... } } } }
   * ```
   */
  build(): TableDefinition {
    const builtColumns: Record<string, ColumnSchema> = {}

    const processColumn = (
      builder:
        | EncryptedColumn
        | Record<
            string,
            | EncryptedField
            | Record<
                string,
                | EncryptedField
                | Record<
                    string,
                    EncryptedField | Record<string, EncryptedField>
                  >
              >
          >,
      colName: string,
    ) => {
      if (builder instanceof EncryptedColumn) {
        const builtColumn = builder.build()

        // Hanlde building the ste_vec index for JSON columns so users don't have to pass the prefix.
        if (
          builtColumn.cast_as === 'json' &&
          builtColumn.indexes.ste_vec?.prefix === 'enabled'
        ) {
          builtColumns[colName] = {
            ...builtColumn,
            indexes: {
              ...builtColumn.indexes,
              ste_vec: {
                ...builtColumn.indexes.ste_vec,
                prefix: `${this.tableName}/${colName}`,
              },
            },
          }
        } else {
          builtColumns[colName] = builtColumn
        }
      } else {
        for (const [key, value] of Object.entries(builder)) {
          if (value instanceof EncryptedField) {
            builtColumns[value.getName()] = value.build()
          } else {
            processColumn(value, key)
          }
        }
      }
    }

    for (const [colName, builder] of Object.entries(this.columnBuilders)) {
      processColumn(builder, colName)
    }

    return {
      tableName: this.tableName,
      columns: builtColumns,
    }
  }
}

// ------------------------
// Schema type inference helpers
// ------------------------

/**
 * Infer the plaintext (decrypted) type from a EncryptedTable schema.
 *
 * @example
 * ```typescript
 * const users = encryptedTable("users", {
 *   email: encryptedColumn("email").equality(),
 *   name: encryptedColumn("name"),
 * })
 *
 * type UserPlaintext = InferPlaintext<typeof users>
 * // => { email: string; name: string }
 * ```
 */
export type InferPlaintext<T extends EncryptedTable<any>> =
  T extends EncryptedTable<infer C>
    ? {
        [K in keyof C as C[K] extends EncryptedColumn | EncryptedField
          ? K
          : never]: string
      }
    : never

/**
 * Infer the encrypted type from a EncryptedTable schema.
 *
 * @example
 * ```typescript
 * const users = encryptedTable("users", {
 *   email: encryptedColumn("email").equality(),
 * })
 *
 * type UserEncrypted = InferEncrypted<typeof users>
 * // => { email: Encrypted }
 * ```
 */
export type InferEncrypted<T extends EncryptedTable<any>> =
  T extends EncryptedTable<infer C>
    ? {
        [K in keyof C as C[K] extends EncryptedColumn | EncryptedField
          ? K
          : never]: Encrypted
      }
    : never

// ------------------------
// User facing functions
// ------------------------

/**
 * Define an encrypted table schema.
 *
 * Creates a `EncryptedTable` that maps a database table name to a set of encrypted
 * column definitions. Pass the resulting object to `Encryption({ schemas: [...] })`
 * when initializing the client.
 *
 * The returned object is also a proxy that exposes each column builder directly,
 * so you can reference columns as `users.email` when calling `encrypt`, `decrypt`,
 * and `encryptQuery`.
 *
 * @param tableName - The name of the database table this schema represents.
 * @param columns - An object whose keys are logical column names and values are
 *   {@link EncryptedColumn} from {@link encryptedColumn}, or nested objects whose
 *   leaves are {@link EncryptedField} from {@link encryptedField}.
 * @returns A `EncryptedTable<T> & T` that can be used as both a schema definition
 *   and a column accessor.
 *
 * @example
 * ```typescript
 * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
 *
 * const users = encryptedTable("users", {
 *   email: encryptedColumn("email").equality().freeTextSearch(),
 *   address: encryptedColumn("address"),
 * })
 *
 * // Use as schema
 * const client = await Encryption({ schemas: [users] })
 *
 * // Use as column accessor
 * await client.encrypt("hello@example.com", { column: users.email, table: users })
 * ```
 */
export function encryptedTable<T extends EncryptedTableColumn>(
  tableName: string,
  columns: T,
): EncryptedTable<T> & T {
  const tableBuilder = new EncryptedTable(
    tableName,
    columns,
  ) as EncryptedTable<T> & T

  for (const [colName, colBuilder] of Object.entries(columns)) {
    ;(tableBuilder as EncryptedTableColumn)[colName] = colBuilder
  }

  return tableBuilder
}

/**
 * Define an encrypted column within a table schema.
 *
 * Creates a `EncryptedColumn` builder for the given column name. Chain index
 * methods (`.equality()`, `.freeTextSearch()`, `.orderAndRange()`,
 * `.searchableJson()`) and/or `.dataType()` to configure searchable encryption
 * and the plaintext data type.
 *
 * @param columnName - The name of the database column to encrypt.
 * @returns A new `EncryptedColumn` builder.
 *
 * @example
 * ```typescript
 * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
 *
 * const users = encryptedTable("users", {
 *   email: encryptedColumn("email").equality().freeTextSearch().orderAndRange(),
 * })
 * ```
 */
export function encryptedColumn(columnName: string) {
  return new EncryptedColumn(columnName)
}

/**
 * Define an encrypted field for use in nested or structured schemas.
 *
 * `encryptedField` is similar to {@link encryptedColumn} but creates an {@link EncryptedField}
 * for nested fields that are encrypted but not searchable (no indexes). Use `.dataType()`
 * to specify the plaintext type.
 *
 * @param valueName - The name of the value field.
 * @returns A new `EncryptedField` builder.
 *
 * @example
 * ```typescript
 * import { encryptedTable, encryptedField } from "@cipherstash/stack/schema"
 *
 * const orders = encryptedTable("orders", {
 *   details: {
 *     amount: encryptedField("amount").dataType("number"),
 *     currency: encryptedField("currency"),
 *   },
 * })
 * ```
 */
export function encryptedField(valueName: string) {
  return new EncryptedField(valueName)
}

/**
 * Build an encrypt config from a list of encrypted tables.
 *
 * @param protectTables - The list of encrypted tables to build the config from.
 * @returns An encrypt config object.
 *
 * @example
 * ```typescript
 * import { buildEncryptConfig } from "@cipherstash/stack/schema"
 *
 * const users = encryptedTable("users", {
 *   email: encryptedColumn("email").equality(),
 * })
 *
 * const orders = encryptedTable("orders", {
 *   amount: encryptedColumn("amount").dataType("number"),
 * })
 *
 * const config = buildEncryptConfig(users, orders)
 * console.log(config)
 * ```
 */
export function buildEncryptConfig(
  ...protectTables: Array<BuildableTable>
): EncryptConfig {
  const config: EncryptConfig = {
    v: 1,
    tables: {},
  }

  for (const tb of protectTables) {
    const tableDef = tb.build()
    config.tables[tableDef.tableName] = tableDef.columns
  }

  return config
}
