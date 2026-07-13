import type {
  CastAs,
  MatchIndexOpts,
  TokenFilter,
} from '@cipherstash/stack/schema'
import { customType } from 'drizzle-orm/pg-core'

export type { CastAs, MatchIndexOpts, TokenFilter }

// The encrypted column type is created by the EQL install script in the
// `public` schema (see packages/cli/src/installer/index.ts). We return the
// bare identifier here — drizzle-kit's CREATE TABLE path emits it correctly
// (it only prepends a schema when `typeSchema` is set, which is only true
// for pgEnum columns). The ALTER COLUMN path is a different story: it
// unconditionally wraps the dataType() return in double-quotes and prepends
// `"{typeSchema}".`, and since custom types have no typeSchema, the output
// becomes `"undefined"."eql_v2_encrypted"`. Returning a pre-quoted
// `"public"."eql_v2_encrypted"` here does NOT fix that — drizzle-kit just
// double-escapes the quotes, producing `"undefined".""public"."eql_v2_encrypted""`.
// Instead, the CLI's `rewriteEncryptedAlterColumns` rewrites every broken
// ALTER COLUMN form into an ADD + DROP + RENAME sequence that does work.
const EQL_ENCRYPTED_DATA_TYPE = 'eql_v2_encrypted'

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
 * Map to store configuration for encrypted columns
 * Keyed by column name (the name passed to encryptedType)
 */
const columnConfigMap = new Map<
  string,
  EncryptedColumnConfig & { name: string }
>()

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
 * import { encryptedType } from '@cipherstash/stack-drizzle'
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
      return EQL_ENCRYPTED_DATA_TYPE
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
  ;(column as any)._encryptionConfig = fullConfig

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

    // Check if it's an encrypted column by checking sqlName or dataType.
    // We accept both the bare `eql_v2_encrypted` form (current) and the
    // fully-qualified `"public"."eql_v2_encrypted"` form that @cipherstash/stack
    // 0.15.0 briefly emitted, for back-compat with tables built against that
    // release.
    const isEncryptedTypeString = (value: unknown): boolean =>
      value === EQL_ENCRYPTED_DATA_TYPE ||
      value === '"public"."eql_v2_encrypted"'

    const isEncrypted =
      isEncryptedTypeString(columnAny.sqlName) ||
      isEncryptedTypeString(columnAny.dataType) ||
      (columnAny.dataType &&
        typeof columnAny.dataType === 'function' &&
        isEncryptedTypeString(columnAny.dataType()))

    if (isEncrypted) {
      // Try to get config from property (if still there)
      if (columnAny._encryptionConfig) {
        return columnAny._encryptionConfig
      }

      // Look up config by column name (the name passed to encryptedType)
      // The column.name should match what was passed to encryptedType
      const lookupName = columnAny.name || columnName
      return columnConfigMap.get(lookupName)
    }
  }
  return undefined
}

/**
 * Create Drizzle query operators (`eq`, `lt`, `gt`, etc.) that work with
 * encrypted columns. The returned operators encrypt query values before
 * passing them to Drizzle, enabling searchable encryption in standard
 * Drizzle queries.
 */
export {
  createEncryptionOperators,
  EncryptionConfigError,
  EncryptionOperatorError,
} from './operators.js'
/**
 * Extract a CipherStash encryption schema from a Drizzle table definition.
 *
 * Inspects columns created with {@link encryptedType} and builds the equivalent
 * `encryptedTable` / `encryptedColumn` schema automatically.
 */
export { extractEncryptionSchema } from './schema-extraction.js'
