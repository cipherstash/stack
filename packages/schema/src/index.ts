import { z } from 'zod'

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
 * - `"number"`
 * - `"string"`
 * - `"json"`
 *
 * @remarks
 * This is a Zod enum used at runtime to validate schema definitions.
 * Use {@link CastAs} when typing your own code.
 */
export const castAsEnum = z
  .enum(['bigint', 'boolean', 'date', 'number', 'string', 'json'])
  .default('string')

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
  mode: z.enum(['compat', 'standard']).optional(),
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

// `v` is locked to `1` because protect-ffi `0.22.0+` rejects any other value at
// `newClient` with `UNSUPPORTED_CONFIG_VERSION`. Enforcing it here means a bad
// hand-rolled config fails at zod-validation time instead of crossing into the
// native module first.
export const encryptConfigSchema = z.object({
  v: z.literal(1),
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
export type TokenFilter = z.infer<typeof tokenFilterSchema>
export type MatchIndexOpts = z.infer<typeof matchIndexOptsSchema>
export type SteVecIndexOpts = z.infer<typeof steVecIndexOptsSchema>
export type UniqueIndexOpts = z.infer<typeof uniqueIndexOptsSchema>
export type OreIndexOpts = z.infer<typeof oreIndexOptsSchema>
export type ColumnSchema = z.infer<typeof columnSchema>

export type ProtectTableColumn = {
  [key: string]:
    | ProtectColumn
    | {
        [key: string]:
          | ProtectValue
          | {
              [key: string]:
                | ProtectValue
                | {
                    [key: string]: ProtectValue
                  }
            }
      }
}
export type EncryptConfig = z.infer<typeof encryptConfigSchema>

// ------------------------
// Interface definitions
// ------------------------
export class ProtectValue {
  private valueName: string
  private castAsValue: CastAs

  constructor(valueName: string) {
    this.valueName = valueName
    this.castAsValue = 'string'
  }

  /**
   * Set or override the cast_as value.
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

export class ProtectColumn {
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
   * Set or override the cast_as value.
   */
  dataType(castAs: CastAs) {
    this.castAsValue = castAs
    return this
  }

  /**
   * Enable ORE indexing (Order-Revealing Encryption).
   */
  orderAndRange() {
    this.indexesValue.ore = {}
    return this
  }

  /**
   * Enable an Exact index. Optionally pass tokenFilters.
   */
  equality(tokenFilters?: TokenFilter[]) {
    this.indexesValue.unique = {
      token_filters: tokenFilters ?? [],
    }
    return this
  }

  /**
   * Enable a Match index. Allows passing of custom match options.
   */
  freeTextSearch(opts?: MatchIndexOpts) {
    // Provide defaults
    this.indexesValue.match = {
      tokenizer: opts?.tokenizer ?? { kind: 'ngram', token_length: 3 },
      token_filters: opts?.token_filters ?? [
        {
          kind: 'downcase',
        },
      ],
      k: opts?.k ?? 6,
      m: opts?.m ?? 2048,
      include_original: opts?.include_original ?? true,
    }
    return this
  }

  /**
   * Configure this column for searchable encrypted JSON.
   * Enables path queries ($.user.email) and containment queries ({ role: 'admin' }).
   * Automatically sets cast_as to 'json'.
   */
  searchableJson() {
    this.castAsValue = 'json'
    // `mode: 'standard'` pins the per-entry ordering term to CLLW-ORE (`oc`),
    // the only encoding the eql_v2 SQL compares. protect-ffi 0.29 flipped the
    // library default to `compat` (CLLW-OPE, `op`) for EQL v3; without the pin
    // every v2 containment query silently matches nothing — and existing v2
    // rows encrypted under `standard` are not cross-comparable with `compat`
    // anyway, so this also keeps the v2 wire format byte-stable.
    this.indexesValue.ste_vec = {
      prefix: 'enabled',
      array_index_mode: 'all',
      mode: 'standard',
    }
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

export class ProtectTable<T extends ProtectTableColumn> {
  constructor(
    public readonly tableName: string,
    private readonly columnBuilders: T,
  ) {}

  /**
   * Build a TableDefinition object: tableName + built column configs.
   */
  build(): TableDefinition {
    const builtColumns: Record<string, ColumnSchema> = {}

    const processColumn = (
      builder:
        | ProtectColumn
        | Record<
            string,
            | ProtectValue
            | Record<
                string,
                | ProtectValue
                | Record<string, ProtectValue | Record<string, ProtectValue>>
              >
          >,
      colName: string,
    ) => {
      if (builder instanceof ProtectColumn) {
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
          if (value instanceof ProtectValue) {
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
// User facing functions
// ------------------------
export function csTable<T extends ProtectTableColumn>(
  tableName: string,
  columns: T,
): ProtectTable<T> & T {
  const tableBuilder = new ProtectTable(tableName, columns) as ProtectTable<T> &
    T

  for (const [colName, colBuilder] of Object.entries(columns)) {
    ;(tableBuilder as ProtectTableColumn)[colName] = colBuilder
  }

  return tableBuilder
}

export function csColumn(columnName: string) {
  return new ProtectColumn(columnName)
}

export function csValue(valueName: string) {
  return new ProtectValue(valueName)
}

// ------------------------
// Internal functions
// ------------------------
export function buildEncryptConfig(
  ...protectTables: Array<ProtectTable<ProtectTableColumn>>
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
