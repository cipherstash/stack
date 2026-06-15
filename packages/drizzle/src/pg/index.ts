import type { CastAs, MatchIndexOpts, TokenFilter } from '@cipherstash/schema'
import { customType } from 'drizzle-orm/pg-core'
import { ALL_V3_DOMAINS } from './v3/domain-map.js'

export type { CastAs, MatchIndexOpts, TokenFilter }

/**
 * Configuration for encrypted column indexes and data types
 */
export type EncryptedColumnConfig = {
  /**
   * Data type for the column (default: 'string')
   */
  dataType?: CastAs
  /**
   * Enable free text search. Can be a boolean for default options, or an object for custom configuration.
   */
  freeTextSearch?: boolean | MatchIndexOpts
  /**
   * Enable equality index. Can be a boolean for default options, or an array of token filters.
   */
  equality?: boolean | TokenFilter[]
  /**
   * Enable order and range index for sorting and range queries.
   */
  orderAndRange?: boolean
  /**
   * Enable searchable JSON index for JSONB path queries.
   * Requires dataType: 'json'.
   */
  searchableJson?: boolean
}

/**
 * Map to store configuration for encrypted columns, keyed by column name (the
 * name passed to encryptedType / eqlV3Type).
 *
 * Anchored on a global-registry Symbol so every copy of this module shares ONE
 * map. The CJS build emits separate bundles for ./pg and ./pg/v3 (no code
 * splitting), so a CJS consumer importing eqlV3Type from ./pg/v3 but
 * extractProtectSchema/operators from ./pg would otherwise register into one
 * bundle's private map and read the other's — schema extraction would then find
 * no encrypted columns and operators could emit unencrypted SQL.
 */
const COLUMN_CONFIG_MAP_KEY = Symbol.for(
  '@cipherstash/drizzle/pg:columnConfigMap',
)
type ColumnConfigMap = Map<string, EncryptedColumnConfig & { name: string }>
const globalStore = globalThis as unknown as {
  [COLUMN_CONFIG_MAP_KEY]?: ColumnConfigMap
}
const columnConfigMap: ColumnConfigMap =
  globalStore[COLUMN_CONFIG_MAP_KEY] ?? new Map()
// Idempotent write-back: stores the new map on first load, no-ops thereafter.
globalStore[COLUMN_CONFIG_MAP_KEY] = columnConfigMap

/**
 * Returns true if a Drizzle column's sql-name is an encrypted type we manage —
 * either the v2 composite or a v3 domain. Shared by the builder and extraction.
 * The v3 domain set is owned by domain-map.ts (no second hand-maintained list).
 */
export function isEncryptedSqlName(name: unknown): boolean {
  if (typeof name !== 'string') return false
  return name === 'eql_v2_encrypted' || ALL_V3_DOMAINS.has(name)
}

/** @internal Register a column config for later extraction lookup. */
export function registerColumnConfig(
  config: EncryptedColumnConfig & { name: string },
): void {
  columnConfigMap.set(config.name, config)
}

/**
 * Creates an encrypted column type for Drizzle ORM with configurable searchable encryption options.
 *
 * When data is encrypted, the actual stored value is an [EQL v2](/docs/reference/eql) encrypted composite type which includes any searchable encryption indexes defined for the column.
 * Importantly, the original data type is not known until it is decrypted. Therefore, this function allows specifying
 * the original data type via the `dataType` option in the configuration.
 * This ensures that when data is decrypted, it can be correctly interpreted as the intended TypeScript type.
 *
 * @typeParam TData - The TypeScript type of the data stored in the column
 * @param name - The column name in the database
 * @param config - Optional configuration for data type and searchable encryption indexes
 * @returns A Drizzle column type that can be used in pgTable definitions
 *
 * ## Searchable Encryption Options
 *
 * - `dataType`: Specifies the original data type of the column (e.g., 'string', 'number', 'json'). Default is 'string'.
 * - `freeTextSearch`: Enables free text search index. Can be a boolean for default options, or an object for custom configuration.
 * - `equality`: Enables equality index. Can be a boolean for default options, or an array of token filters.
 * - `orderAndRange`: Enables order and range index for sorting and range queries.
 * - `searchableJson`: Enables searchable JSON index for JSONB path queries on encrypted JSON columns.
 *
 * See {@link EncryptedColumnConfig}.
 *
 * @example
 * Defining a drizzle table schema for postgres table with encrypted columns.
 *
 * ```typescript
 * import { pgTable, integer, timestamp } from 'drizzle-orm/pg-core'
 * import { encryptedType } from '@cipherstash/drizzle/pg'
 *
 * const users = pgTable('users', {
 *   email: encryptedType('email', {
 *     freeTextSearch: true,
 *     equality: true,
 *     orderAndRange: true,
 *   }),
 *   age: encryptedType('age', {
 *     dataType: 'number',
 *     equality: true,
 *     orderAndRange: true,
 *   }),
 *   profile: encryptedType('profile', {
 *     dataType: 'json',
 *   }),
 * })
 * ```
 */
export const encryptedType = <TData>(
  name: string,
  config?: EncryptedColumnConfig,
) => {
  // Create the Drizzle custom type
  const customColumnType = customType<{ data: TData; driverData: string }>({
    dataType() {
      return 'eql_v2_encrypted'
    },
    toDriver(value: TData): string {
      const jsonStr = JSON.stringify(value)
      const escaped = jsonStr.replace(/"/g, '""')
      return `("${escaped}")`
    },
    fromDriver(value: string): TData {
      const parseComposite = (str: string) => {
        if (!str || str === '') return null

        const trimmed = str.trim()

        if (trimmed.startsWith('(') && trimmed.endsWith(')')) {
          let inner = trimmed.slice(1, -1)
          inner = inner.replace(/""/g, '"')

          if (inner.startsWith('"') && inner.endsWith('"')) {
            const stripped = inner.slice(1, -1)
            return JSON.parse(stripped)
          }

          if (inner.startsWith('{') || inner.startsWith('[')) {
            return JSON.parse(inner)
          }

          return inner
        }

        return JSON.parse(str)
      }

      return parseComposite(value) as TData
    },
  })

  // Create the column instance
  const column = customColumnType(name)

  // Store configuration keyed by column name
  // This allows us to look it up during schema extraction
  const fullConfig: EncryptedColumnConfig & { name: string } = {
    name,
    ...config,
  }

  // Store in Map keyed by column name (will be looked up during extraction)
  columnConfigMap.set(name, fullConfig)

  // Also store on property for immediate access (before pgTable processes it)
  // We need to use any here because Drizzle columns don't have a type for custom properties
  // biome-ignore lint/suspicious/noExplicitAny: Drizzle columns don't expose custom property types
  ;(column as any)._protectConfig = fullConfig

  return column
}

/**
 * Get configuration for an encrypted column by checking if it's an encrypted type
 * and looking up the config by column name
 * @internal
 */
export function getEncryptedColumnConfig(
  columnName: string,
  column: unknown,
): (EncryptedColumnConfig & { name: string }) | undefined {
  // Check if this is an encrypted column
  if (column && typeof column === 'object') {
    // We need to use any here to access Drizzle column properties
    // biome-ignore lint/suspicious/noExplicitAny: Drizzle column types don't expose all properties
    const columnAny = column as any

    // Check if it's an encrypted column by checking sqlName or dataType
    // After pgTable processes it, sqlName will be 'eql_v2_encrypted'
    const isEncrypted =
      isEncryptedSqlName(columnAny.sqlName) ||
      isEncryptedSqlName(columnAny.dataType) ||
      (typeof columnAny.dataType === 'function' &&
        isEncryptedSqlName(columnAny.dataType()))

    if (isEncrypted) {
      // Try to get config from property (if still there)
      if (columnAny._protectConfig) {
        return columnAny._protectConfig
      }

      // Look up config by column name (the name passed to encryptedType)
      // The column.name should match what was passed to encryptedType
      const lookupName = columnAny.name || columnName
      return columnConfigMap.get(lookupName)
    }
  }
  return undefined
}

// Re-export schema extraction utility
export { extractProtectSchema } from './schema-extraction.js'

// Re-export operators
export {
  createProtectOperators,
  ProtectOperatorError,
  ProtectConfigError,
} from './operators.js'
