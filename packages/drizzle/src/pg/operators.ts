import type { QueryTypeName } from '@cipherstash/protect'
import type {
  ProtectClient,
  ProtectColumn,
  ProtectTable,
  ProtectTableColumn,
} from '@cipherstash/protect/client'
import {
  type SQL,
  type SQLWrapper,
  and,
  arrayContained,
  arrayContains,
  arrayOverlaps,
  asc,
  between,
  desc,
  eq,
  exists,
  gt,
  gte,
  ilike,
  inArray,
  isNotNull,
  isNull,
  like,
  lt,
  lte,
  ne,
  not,
  notBetween,
  notExists,
  notIlike,
  notInArray,
  or,
} from 'drizzle-orm'
import { bindIfParam, sql } from 'drizzle-orm'
import type { PgTable } from 'drizzle-orm/pg-core'
import type { EncryptedColumnConfig } from './index.js'
import { getEncryptedColumnConfig } from './index.js'
import { extractProtectSchema } from './schema-extraction.js'
import {
  type ComparisonOp,
  type EqualityOp,
  type MatchOp,
  type SqlDialect,
  v2Dialect,
} from './sql-dialect.js'

// ============================================================================
// Type Definitions and Type Guards
// ============================================================================

/**
 * Branded type for Drizzle table with encrypted columns
 */
// biome-ignore lint/suspicious/noExplicitAny: Drizzle table types don't expose Symbol properties
type EncryptedDrizzleTable = PgTable<any> & {
  readonly __isEncryptedTable?: true
}

/**
 * Type guard to check if a value is a Drizzle SQLWrapper
 */
function isSQLWrapper(value: unknown): value is SQLWrapper {
  return (
    typeof value === 'object' &&
    value !== null &&
    'sql' in value &&
    typeof (value as { sql: unknown }).sql !== 'undefined'
  )
}

/**
 * Type guard to check if a value is a Drizzle table
 */
function isPgTable(value: unknown): value is EncryptedDrizzleTable {
  return (
    typeof value === 'object' &&
    value !== null &&
    Symbol.for('drizzle:Name') in value
  )
}

/**
 * Custom error types for better debugging
 */
export class ProtectOperatorError extends Error {
  constructor(
    message: string,
    public readonly context?: {
      tableName?: string
      columnName?: string
      operator?: string
    },
  ) {
    super(message)
    this.name = 'ProtectOperatorError'
  }
}

export class ProtectConfigError extends ProtectOperatorError {
  constructor(message: string, context?: ProtectOperatorError['context']) {
    super(message, context)
    this.name = 'ProtectConfigError'
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Helper to extract table name from a Drizzle table
 */
function getDrizzleTableName(drizzleTable: unknown): string | undefined {
  if (!isPgTable(drizzleTable)) {
    return undefined
  }
  // Access Symbol property using Record type to avoid indexing errors
  const tableWithSymbol = drizzleTable as unknown as Record<
    symbol,
    string | undefined
  >
  return tableWithSymbol[Symbol.for('drizzle:Name')]
}

/**
 * Helper to get the drizzle table from a drizzle column
 */
function getDrizzleTableFromColumn(drizzleColumn: SQLWrapper): unknown {
  const column = drizzleColumn as unknown as Record<string, unknown>
  return column.table as unknown
}

/**
 * Helper to extract protect table from a drizzle column by deriving it from the column's parent table
 */
function getProtectTableFromColumn(
  drizzleColumn: SQLWrapper,
  protectTableCache: Map<string, ProtectTable<ProtectTableColumn>>,
): ProtectTable<ProtectTableColumn> | undefined {
  const drizzleTable = getDrizzleTableFromColumn(drizzleColumn)
  if (!drizzleTable) {
    return undefined
  }

  const tableName = getDrizzleTableName(drizzleTable)
  if (!tableName) {
    return undefined
  }

  // Check cache first
  let protectTable = protectTableCache.get(tableName)
  if (protectTable) {
    return protectTable
  }

  // Extract protect schema from drizzle table and cache it
  try {
    // biome-ignore lint/suspicious/noExplicitAny: PgTable type doesn't expose all needed properties
    protectTable = extractProtectSchema(drizzleTable as PgTable<any>)
    protectTableCache.set(tableName, protectTable)
    return protectTable
  } catch {
    // Table doesn't have encrypted columns or extraction failed
    return undefined
  }
}

/**
 * Helper to get the ProtectColumn for a Drizzle column from the ProtectTable
 */
function getProtectColumn(
  drizzleColumn: SQLWrapper,
  protectTable: ProtectTable<ProtectTableColumn>,
): ProtectColumn | undefined {
  const column = drizzleColumn as unknown as Record<string, unknown>
  const columnName = column.name as string | undefined
  if (!columnName) {
    return undefined
  }

  const protectTableAny = protectTable as unknown as Record<string, unknown>
  return protectTableAny[columnName] as ProtectColumn | undefined
}

/**
 * Column metadata extracted from a Drizzle column
 */
interface ColumnInfo {
  readonly protectColumn: ProtectColumn | undefined
  readonly config: (EncryptedColumnConfig & { name: string }) | undefined
  readonly protectTable: ProtectTable<ProtectTableColumn> | undefined
  readonly columnName: string
  readonly tableName: string | undefined
}

/**
 * Helper to get the ProtectColumn and column config for a Drizzle column
 * If protectTable is not provided, it will be derived from the column
 */
function getColumnInfo(
  drizzleColumn: SQLWrapper,
  protectTable: ProtectTable<ProtectTableColumn> | undefined,
  protectTableCache: Map<string, ProtectTable<ProtectTableColumn>>,
): ColumnInfo {
  const column = drizzleColumn as unknown as Record<string, unknown>
  const columnName = (column.name as string | undefined) || 'unknown'

  // If protectTable not provided, try to derive it from the column
  let resolvedProtectTable = protectTable
  if (!resolvedProtectTable) {
    resolvedProtectTable = getProtectTableFromColumn(
      drizzleColumn,
      protectTableCache,
    )
  }

  const drizzleTable = getDrizzleTableFromColumn(drizzleColumn)
  const tableName = getDrizzleTableName(drizzleTable)

  if (!resolvedProtectTable) {
    // Column is not from an encrypted table
    const config = getEncryptedColumnConfig(columnName, drizzleColumn)
    return {
      protectColumn: undefined,
      config,
      protectTable: undefined,
      columnName,
      tableName,
    }
  }

  const protectColumn = getProtectColumn(drizzleColumn, resolvedProtectTable)
  const config = getEncryptedColumnConfig(columnName, drizzleColumn)

  return {
    protectColumn,
    config,
    protectTable: resolvedProtectTable,
    columnName,
    tableName,
  }
}

/**
 * Helper to convert a value to plaintext format
 */
function toPlaintext(value: unknown): string | number {
  if (typeof value === 'boolean') {
    return value ? 1 : 0
  }
  if (typeof value === 'string' || typeof value === 'number') {
    return value
  }
  if (value instanceof Date) {
    return value.toISOString()
  }
  return String(value)
}

/**
 * Value to encrypt with its associated column
 */
interface ValueToEncrypt {
  readonly value: string | number
  readonly column: SQLWrapper
  readonly columnInfo: ColumnInfo
  readonly queryType?: QueryTypeName
  readonly originalIndex: number
}

/**
 * Helper to encrypt multiple values for use in a query
 * Returns an array of encrypted search terms or original values if not encrypted
 */
async function encryptValues(
  protectClient: ProtectClient,
  values: Array<{
    value: unknown
    column: SQLWrapper
    queryType?: QueryTypeName
  }>,
  protectTable: ProtectTable<ProtectTableColumn> | undefined,
  protectTableCache: Map<string, ProtectTable<ProtectTableColumn>>,
): Promise<unknown[]> {
  if (values.length === 0) {
    return []
  }

  // Single pass: collect values to encrypt with their metadata
  const valuesToEncrypt: ValueToEncrypt[] = []
  const results: unknown[] = new Array(values.length)

  for (let i = 0; i < values.length; i++) {
    const { value, column, queryType } = values[i]
    const columnInfo = getColumnInfo(column, protectTable, protectTableCache)

    if (
      !columnInfo.protectColumn ||
      !columnInfo.config ||
      !columnInfo.protectTable
    ) {
      // Column is not encrypted, return value as-is
      results[i] = value
      continue
    }

    const plaintextValue = toPlaintext(value)
    valuesToEncrypt.push({
      value: plaintextValue,
      column,
      columnInfo,
      queryType,
      originalIndex: i,
    })
  }

  if (valuesToEncrypt.length === 0) {
    return results
  }

  // Group values by column to batch encrypt with same column/table
  const columnGroups = new Map<
    string,
    {
      column: ProtectColumn
      table: ProtectTable<ProtectTableColumn>
      columnName: string
      values: Array<{
        value: string | number
        index: number
        queryType?: QueryTypeName
      }>
      resultIndices: number[]
    }
  >()

  let valueIndex = 0
  for (const {
    value,
    columnInfo,
    queryType,
    originalIndex,
  } of valuesToEncrypt) {
    // Safe access with validation - we know these exist from earlier checks
    if (
      !columnInfo.config ||
      !columnInfo.protectColumn ||
      !columnInfo.protectTable
    ) {
      continue
    }

    const columnName = columnInfo.config.name
    const groupKey = `${columnInfo.tableName ?? 'unknown'}/${columnName}`
    let group = columnGroups.get(groupKey)
    if (!group) {
      group = {
        column: columnInfo.protectColumn,
        table: columnInfo.protectTable,
        columnName,
        values: [],
        resultIndices: [],
      }
      columnGroups.set(groupKey, group)
    }
    group.values.push({ value, index: valueIndex++, queryType })
    group.resultIndices.push(originalIndex)
  }

  // Encrypt all values for each column in batches
  for (const [, group] of columnGroups) {
    const { columnName } = group
    try {
      const terms = group.values.map((v) => ({
        value: v.value,
        column: group.column,
        table: group.table,
        queryType: v.queryType,
      }))

      const encryptedTerms = await protectClient.encryptQuery(terms)

      if (encryptedTerms.failure) {
        throw new ProtectOperatorError(
          `Failed to encrypt query terms for column "${columnName}": ${encryptedTerms.failure.message}`,
          { columnName },
        )
      }

      // Map results back to original indices
      for (let i = 0; i < group.values.length; i++) {
        const resultIndex = group.resultIndices[i] ?? -1
        if (resultIndex >= 0 && resultIndex < results.length) {
          results[resultIndex] = encryptedTerms.data[i]
        }
      }
    } catch (error) {
      if (error instanceof ProtectOperatorError) {
        throw error
      }
      const errorMessage =
        error instanceof Error ? error.message : String(error)
      throw new ProtectOperatorError(
        `Unexpected error encrypting values for column "${columnName}": ${errorMessage}`,
        { columnName },
      )
    }
  }

  return results
}

/**
 * Helper to encrypt a single value for use in a query
 * Returns the encrypted search term or the original value if not encrypted
 */
async function encryptValue(
  protectClient: ProtectClient,
  value: unknown,
  drizzleColumn: SQLWrapper,
  protectTable: ProtectTable<ProtectTableColumn> | undefined,
  protectTableCache: Map<string, ProtectTable<ProtectTableColumn>>,
  queryType?: QueryTypeName,
): Promise<unknown> {
  const results = await encryptValues(
    protectClient,
    [{ value, column: drizzleColumn, queryType }],
    protectTable,
    protectTableCache,
  )
  return results[0]
}

// ============================================================================
// Lazy Operator Pattern
// ============================================================================

/**
 * Simplified lazy operator that defers encryption until awaited or batched
 */
interface LazyOperator {
  readonly __isLazyOperator: true
  readonly operator: string
  readonly queryType?: QueryTypeName
  readonly left: SQLWrapper
  readonly right: unknown
  readonly min?: unknown
  readonly max?: unknown
  readonly needsEncryption: boolean
  readonly columnInfo: ColumnInfo
  execute(
    encrypted: unknown,
    encryptedMin?: unknown,
    encryptedMax?: unknown,
  ): SQL
}

/**
 * Type guard for lazy operators
 */
function isLazyOperator(value: unknown): value is LazyOperator {
  return (
    typeof value === 'object' &&
    value !== null &&
    '__isLazyOperator' in value &&
    (value as LazyOperator).__isLazyOperator === true
  )
}

/**
 * Creates a lazy operator that defers execution
 */
function createLazyOperator(
  operator: string,
  left: SQLWrapper,
  right: unknown,
  execute: (
    encrypted: unknown,
    encryptedMin?: unknown,
    encryptedMax?: unknown,
  ) => SQL,
  needsEncryption: boolean,
  columnInfo: ColumnInfo,
  protectClient: ProtectClient,
  defaultProtectTable: ProtectTable<ProtectTableColumn> | undefined,
  protectTableCache: Map<string, ProtectTable<ProtectTableColumn>>,
  min?: unknown,
  max?: unknown,
  queryType?: QueryTypeName,
): LazyOperator & Promise<SQL> {
  let resolvedSQL: SQL | undefined
  let encryptionPromise: Promise<SQL> | undefined

  const lazyOp: LazyOperator = {
    __isLazyOperator: true,
    operator,
    queryType,
    left,
    right,
    min,
    max,
    needsEncryption,
    columnInfo,
    execute,
  }

  // Create a promise that will be resolved when encryption completes
  const promise = new Promise<SQL>((resolve, reject) => {
    // Auto-execute when awaited directly
    queueMicrotask(async () => {
      if (resolvedSQL !== undefined) {
        resolve(resolvedSQL)
        return
      }

      try {
        if (!encryptionPromise) {
          encryptionPromise = executeLazyOperatorDirect(
            lazyOp,
            protectClient,
            defaultProtectTable,
            protectTableCache,
          )
        }
        const sql = await encryptionPromise
        resolvedSQL = sql
        resolve(sql)
      } catch (error) {
        reject(error)
      }
    })
  })

  // Attach lazy operator properties to the promise
  return Object.assign(promise, lazyOp)
}

/**
 * Executes a lazy operator with pre-encrypted values (used in batched mode)
 */
async function executeLazyOperator(
  lazyOp: LazyOperator,
  encryptedValues?: { value: unknown; encrypted: unknown }[],
): Promise<SQL> {
  if (!lazyOp.needsEncryption) {
    return lazyOp.execute(lazyOp.right)
  }

  if (lazyOp.min !== undefined && lazyOp.max !== undefined) {
    // Between operator - use provided encrypted values
    let encryptedMin: unknown
    let encryptedMax: unknown

    if (encryptedValues && encryptedValues.length >= 2) {
      encryptedMin = encryptedValues[0]?.encrypted
      encryptedMax = encryptedValues[1]?.encrypted
    } else {
      throw new ProtectOperatorError(
        'Between operator requires both min and max encrypted values',
        {
          columnName: lazyOp.columnInfo.columnName,
          tableName: lazyOp.columnInfo.tableName,
          operator: lazyOp.operator,
        },
      )
    }

    if (encryptedMin === undefined || encryptedMax === undefined) {
      throw new ProtectOperatorError(
        'Between operator requires both min and max values to be encrypted',
        {
          columnName: lazyOp.columnInfo.columnName,
          tableName: lazyOp.columnInfo.tableName,
          operator: lazyOp.operator,
        },
      )
    }

    return lazyOp.execute(undefined, encryptedMin, encryptedMax)
  }

  // Single value operator
  let encrypted: unknown

  if (encryptedValues && encryptedValues.length > 0) {
    encrypted = encryptedValues[0]?.encrypted
  } else {
    throw new ProtectOperatorError(
      'Operator requires encrypted value but none provided',
      {
        columnName: lazyOp.columnInfo.columnName,
        tableName: lazyOp.columnInfo.tableName,
        operator: lazyOp.operator,
      },
    )
  }

  if (encrypted === undefined) {
    throw new ProtectOperatorError(
      'Encryption failed or value was not encrypted',
      {
        columnName: lazyOp.columnInfo.columnName,
        tableName: lazyOp.columnInfo.tableName,
        operator: lazyOp.operator,
      },
    )
  }

  return lazyOp.execute(encrypted)
}

/**
 * Executes a lazy operator directly by encrypting values on demand
 * Used when operator is awaited directly (not batched)
 */
async function executeLazyOperatorDirect(
  lazyOp: LazyOperator,
  protectClient: ProtectClient,
  defaultProtectTable: ProtectTable<ProtectTableColumn> | undefined,
  protectTableCache: Map<string, ProtectTable<ProtectTableColumn>>,
): Promise<SQL> {
  if (!lazyOp.needsEncryption) {
    return lazyOp.execute(lazyOp.right)
  }

  if (lazyOp.min !== undefined && lazyOp.max !== undefined) {
    // Between operator - encrypt min and max
    const [encryptedMin, encryptedMax] = await encryptValues(
      protectClient,
      [
        { value: lazyOp.min, column: lazyOp.left, queryType: lazyOp.queryType },
        { value: lazyOp.max, column: lazyOp.left, queryType: lazyOp.queryType },
      ],
      defaultProtectTable,
      protectTableCache,
    )
    return lazyOp.execute(undefined, encryptedMin, encryptedMax)
  }

  // Single value operator
  const encrypted = await encryptValue(
    protectClient,
    lazyOp.right,
    lazyOp.left,
    defaultProtectTable,
    protectTableCache,
    lazyOp.queryType,
  )

  return lazyOp.execute(encrypted)
}

// ============================================================================
// Operator Factory Functions
// ============================================================================

/**
 * Creates a comparison operator (eq, ne, gt, gte, lt, lte)
 */
function createComparisonOperator(
  operator: 'eq' | 'ne' | 'gt' | 'gte' | 'lt' | 'lte',
  left: SQLWrapper,
  right: unknown,
  columnInfo: ColumnInfo,
  protectClient: ProtectClient,
  defaultProtectTable: ProtectTable<ProtectTableColumn> | undefined,
  protectTableCache: Map<string, ProtectTable<ProtectTableColumn>>,
  dialect: SqlDialect,
): Promise<SQL> | SQL {
  const { config } = columnInfo

  // Operators requiring orderAndRange index
  const requiresOrderAndRange = ['gt', 'gte', 'lt', 'lte'].includes(operator)

  if (requiresOrderAndRange) {
    if (!config?.orderAndRange) {
      // Return regular Drizzle operator for non-encrypted columns
      switch (operator) {
        case 'gt':
          return gt(left, right)
        case 'gte':
          return gte(left, right)
        case 'lt':
          return lt(left, right)
        case 'lte':
          return lte(left, right)
      }
    }

    // This will be replaced with encrypted value in executeLazyOperator
    const executeFn = (encrypted: unknown) => {
      if (encrypted === undefined) {
        throw new ProtectOperatorError(
          `Encryption failed for ${operator} operator`,
          {
            columnName: columnInfo.columnName,
            tableName: columnInfo.tableName,
            operator,
          },
        )
      }
      return dialect.comparison(
        operator as ComparisonOp,
        sql`${left}`,
        sql`${bindIfParam(encrypted, left)}`,
      )
    }

    return createLazyOperator(
      operator,
      left,
      right,
      executeFn,
      true,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
      undefined, // min
      undefined, // max
      'orderAndRange',
    ) as Promise<SQL>
  }

  // Equality operators (eq, ne)
  const requiresEquality = ['eq', 'ne'].includes(operator)

  if (requiresEquality && config?.equality) {
    const executeFn = (encrypted: unknown) => {
      if (encrypted === undefined) {
        throw new ProtectOperatorError(
          `Encryption failed for ${operator} operator`,
          {
            columnName: columnInfo.columnName,
            tableName: columnInfo.tableName,
            operator,
          },
        )
      }
      return dialect.equality(
        operator as EqualityOp,
        sql`${left}`,
        sql`${bindIfParam(encrypted, left)}`,
      )
    }

    return createLazyOperator(
      operator,
      left,
      right,
      executeFn,
      true,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
      undefined, // min
      undefined, // max
      'equality',
    ) as Promise<SQL>
  }

  // Fallback to regular Drizzle operators
  return operator === 'eq' ? eq(left, right) : ne(left, right)
}

/**
 * Creates a range operator (between, notBetween)
 */
function createRangeOperator(
  operator: 'between' | 'notBetween',
  left: SQLWrapper,
  min: unknown,
  max: unknown,
  columnInfo: ColumnInfo,
  protectClient: ProtectClient,
  defaultProtectTable: ProtectTable<ProtectTableColumn> | undefined,
  protectTableCache: Map<string, ProtectTable<ProtectTableColumn>>,
  dialect: SqlDialect,
): Promise<SQL> | SQL {
  const { config } = columnInfo

  if (!config?.orderAndRange) {
    return operator === 'between'
      ? between(left, min, max)
      : notBetween(left, min, max)
  }

  const executeFn = (
    _encrypted: unknown,
    encryptedMin?: unknown,
    encryptedMax?: unknown,
  ) => {
    if (encryptedMin === undefined || encryptedMax === undefined) {
      throw new ProtectOperatorError(
        `${operator} operator requires both min and max values`,
        {
          columnName: columnInfo.columnName,
          tableName: columnInfo.tableName,
          operator,
        },
      )
    }

    const rangeCondition = dialect.range(
      sql`${left}`,
      sql`${bindIfParam(encryptedMin, left)}`,
      sql`${bindIfParam(encryptedMax, left)}`,
    )

    return operator === 'between'
      ? rangeCondition
      : sql`NOT (${rangeCondition})`
  }

  return createLazyOperator(
    operator,
    left,
    undefined,
    executeFn,
    true,
    columnInfo,
    protectClient,
    defaultProtectTable,
    protectTableCache,
    min,
    max,
    'orderAndRange',
  ) as Promise<SQL>
}

/**
 * Creates a text search operator (like, ilike, notIlike)
 */
function createTextSearchOperator(
  operator: 'like' | 'ilike' | 'notIlike',
  left: SQLWrapper,
  right: unknown,
  columnInfo: ColumnInfo,
  protectClient: ProtectClient,
  defaultProtectTable: ProtectTable<ProtectTableColumn> | undefined,
  protectTableCache: Map<string, ProtectTable<ProtectTableColumn>>,
  dialect: SqlDialect,
): Promise<SQL> | SQL {
  const { config } = columnInfo

  if (!config?.freeTextSearch) {
    // Cast to satisfy TypeScript
    const rightValue = right as string | SQLWrapper
    switch (operator) {
      case 'like':
        return like(left as Parameters<typeof like>[0], rightValue)
      case 'ilike':
        return ilike(left as Parameters<typeof ilike>[0], rightValue)
      case 'notIlike':
        return notIlike(left as Parameters<typeof notIlike>[0], rightValue)
    }
  }

  const executeFn = (encrypted: unknown) => {
    if (encrypted === undefined) {
      throw new ProtectOperatorError(
        `Encryption failed for ${operator} operator`,
        {
          columnName: columnInfo.columnName,
          tableName: columnInfo.tableName,
          operator,
        },
      )
    }

    const sqlFn = dialect.match(
      (operator === 'notIlike' ? 'ilike' : operator) as MatchOp,
      sql`${left}`,
      sql`${bindIfParam(encrypted, left)}`,
    )
    return operator === 'notIlike' ? sql`NOT (${sqlFn})` : sqlFn
  }

  return createLazyOperator(
    operator,
    left,
    right,
    executeFn,
    true,
    columnInfo,
    protectClient,
    defaultProtectTable,
    protectTableCache,
    undefined, // min
    undefined, // max
    'freeTextSearch',
  ) as Promise<SQL>
}

/**
 * Creates a JSONB operator that encrypts a JSON path selector and wraps it
 * in the appropriate `eql_v2` function call.
 *
 * Supports `jsonbPathQueryFirst`, `jsonbGet`, and `jsonbPathExists`.
 * The column must have `searchableJson` enabled in its {@link EncryptedColumnConfig}.
 *
 * @param operator - Which JSONB operation to perform.
 * @param left - The encrypted column reference.
 * @param right - The JSON path selector value to encrypt.
 * @param columnInfo - Resolved column metadata including config and table name.
 * @param protectClient - The Protect client used for encryption.
 * @param defaultProtectTable - The default protect table for schema resolution.
 * @param protectTableCache - Cache of resolved protect tables.
 * @returns A promise resolving to the SQL condition with an encrypted, cast parameter.
 * @throws {ProtectOperatorError} If `searchableJson` is not enabled on the column, or if encryption fails.
 */
function createJsonbOperator(
  operator: 'jsonbPathQueryFirst' | 'jsonbGet' | 'jsonbPathExists',
  left: SQLWrapper,
  right: unknown,
  columnInfo: ColumnInfo,
  protectClient: ProtectClient,
  defaultProtectTable: ProtectTable<ProtectTableColumn> | undefined,
  protectTableCache: Map<string, ProtectTable<ProtectTableColumn>>,
): Promise<SQL> {
  const { config } = columnInfo
  const encryptedSelector = (value: unknown) =>
    sql`${bindIfParam(value, left)}::eql_v2_encrypted`

  if (!config?.searchableJson) {
    throw new ProtectOperatorError(
      `The ${operator} operator requires searchableJson to be enabled on the column configuration.`,
      {
        columnName: columnInfo.columnName,
        tableName: columnInfo.tableName,
        operator,
      },
    )
  }

  const executeFn = (encrypted: unknown) => {
    if (encrypted === undefined) {
      throw new ProtectOperatorError(
        `Encryption failed for ${operator} operator`,
        {
          columnName: columnInfo.columnName,
          tableName: columnInfo.tableName,
          operator,
        },
      )
    }
    switch (operator) {
      case 'jsonbPathQueryFirst':
        return sql`eql_v2.jsonb_path_query_first(${left}, ${encryptedSelector(encrypted)})`
      case 'jsonbGet':
        return sql`${left} -> ${encryptedSelector(encrypted)}`
      case 'jsonbPathExists':
        return sql`eql_v2.jsonb_path_exists(${left}, ${encryptedSelector(encrypted)})`
    }
  }

  return createLazyOperator(
    operator,
    left,
    right,
    executeFn,
    true,
    columnInfo,
    protectClient,
    defaultProtectTable,
    protectTableCache,
    undefined,
    undefined,
    'steVecSelector',
  ) as Promise<SQL>
}

// ============================================================================
// Public API: createProtectOperators
// ============================================================================

/**
 * Creates a set of Protect.js-aware operators that automatically encrypt values
 * for encrypted columns before using them with Drizzle operators.
 *
 * For equality and text search operators (eq, ne, like, ilike, inArray, etc.):
 * Values are encrypted and then passed to regular Drizzle operators, which use
 * PostgreSQL's built-in operators for eql_v2_encrypted types.
 *
 * For order and range operators (gt, gte, lt, lte, between, notBetween):
 * Values are encrypted and then use eql_v2.* functions (eql_v2.gt(), eql_v2.gte(), etc.)
 * which are required for ORE (Order-Revealing Encryption) comparisons.
 *
 * @param protectClient - The Protect.js client instance
 * @returns An object with all Drizzle operators wrapped for encrypted columns
 *
 * @example
 * ```ts
 * // Initialize operators
 * const protectOps = createProtectOperators(protectClient)
 *
 * // Equality search - automatically encrypts and uses PostgreSQL operators
 * const results = await db
 *   .select()
 *   .from(usersTable)
 *   .where(await protectOps.eq(usersTable.email, 'user@example.com'))
 *
 * // Range query - automatically encrypts and uses eql_v2.gte()
 * const olderUsers = await db
 *   .select()
 *   .from(usersTable)
 *   .where(await protectOps.gte(usersTable.age, 25))
 * ```
 */
export function createProtectOperators(
  protectClient: ProtectClient,
  dialect: SqlDialect = v2Dialect,
): {
  // Comparison operators
  /**
   * Equality operator - encrypts value for encrypted columns.
   * Requires either `equality` or `orderAndRange` to be set on {@link EncryptedColumnConfig}.
   *
   * @example
   * Select users with a specific email address.
   * ```ts
   * const condition = await protectOps.eq(usersTable.email, 'user@example.com')
   * const results = await db.select().from(usersTable).where(condition)
   * ```
   */
  eq: (left: SQLWrapper, right: unknown) => Promise<SQL> | SQL

  /**
   * Not equal operator - encrypts value for encrypted columns.
   * Requires either `equality` or `orderAndRange` to be set on {@link EncryptedColumnConfig}.
   *
   * @example
   * Select users whose email address is not a specific value.
   * ```ts
   * const condition = await protectOps.ne(usersTable.email, 'user@example.com')
   * const results = await db.select().from(usersTable).where(condition)
   * ```
   */
  ne: (left: SQLWrapper, right: unknown) => Promise<SQL> | SQL

  /**
   * Greater than operator for encrypted columns with ORE index.
   * Requires `orderAndRange` to be set on {@link EncryptedColumnConfig}.
   *
   * @example
   * Select users older than a specific age.
   * ```ts
   * const condition = await protectOps.gt(usersTable.age, 30)
   * const results = await db.select().from(usersTable).where(condition)
   * ```
   */
  gt: (left: SQLWrapper, right: unknown) => Promise<SQL> | SQL

  /**
   * Greater than or equal operator for encrypted columns with ORE index.
   * Requires `orderAndRange` to be set on {@link EncryptedColumnConfig}.
   *
   * @example
   * Select users older than or equal to a specific age.
   * ```ts
   * const condition = await protectOps.gte(usersTable.age, 30)
   * const results = await db.select().from(usersTable).where(condition)
   * ```
   */
  gte: (left: SQLWrapper, right: unknown) => Promise<SQL> | SQL

  /**
   * Less than operator for encrypted columns with ORE index.
   * Requires `orderAndRange` to be set on {@link EncryptedColumnConfig}.
   *
   * @example
   * Select users younger than a specific age.
   * ```ts
   * const condition = await protectOps.lt(usersTable.age, 30)
   * const results = await db.select().from(usersTable).where(condition)
   * ```
   */
  lt: (left: SQLWrapper, right: unknown) => Promise<SQL> | SQL

  /**
   * Less than or equal operator for encrypted columns with ORE index.
   * Requires `orderAndRange` to be set on {@link EncryptedColumnConfig}.
   *
   * @example
   * Select users younger than or equal to a specific age.
   * ```ts
   * const condition = await protectOps.lte(usersTable.age, 30)
   * const results = await db.select().from(usersTable).where(condition)
   * ```
   */
  lte: (left: SQLWrapper, right: unknown) => Promise<SQL> | SQL

  /**
   * Between operator for encrypted columns with ORE index.
   * Requires `orderAndRange` to be set on {@link EncryptedColumnConfig}.
   *
   * @example
   * Select users within a specific age range.
   * ```ts
   * const condition = await protectOps.between(usersTable.age, 20, 30)
   * const results = await db.select().from(usersTable).where(condition)
   * ```
   */
  between: (left: SQLWrapper, min: unknown, max: unknown) => Promise<SQL> | SQL

  /**
   * Not between operator for encrypted columns with ORE index.
   * Requires `orderAndRange` to be set on {@link EncryptedColumnConfig}.
   *
   * @example
   * Select users outside a specific age range.
   * ```ts
   * const condition = await protectOps.notBetween(usersTable.age, 20, 30)
   * const results = await db.select().from(usersTable).where(condition)
   * ```
   */
  notBetween: (
    left: SQLWrapper,
    min: unknown,
    max: unknown,
  ) => Promise<SQL> | SQL

  /**
   * Like operator for encrypted columns with free text search.
   * Requires `freeTextSearch` to be set on {@link EncryptedColumnConfig}.
   *
   * > [!IMPORTANT]
   * > Case sensitivity on encrypted columns depends on the {@link EncryptedColumnConfig}.
   * > Ensure that the column is configured for case-insensitive search if needed.
   *
   * @example
   * Select users with email addresses matching a pattern.
   * ```ts
   * const condition = await protectOps.like(usersTable.email, '%@example.com')
   * const results = await db.select().from(usersTable).where(condition)
   * ```
   */
  like: (left: SQLWrapper, right: unknown) => Promise<SQL> | SQL

  /**
   * ILike operator for encrypted columns with free text search.
   * Requires `freeTextSearch` to be set on {@link EncryptedColumnConfig}.
   *
   * > [!IMPORTANT]
   * > Case sensitivity on encrypted columns depends on the {@link EncryptedColumnConfig}.
   * > Ensure that the column is configured for case-insensitive search if needed.
   *
   * @example
   * Select users with email addresses matching a pattern (case-insensitive).
   * ```ts
   * const condition = await protectOps.ilike(usersTable.email, '%@example.com')
   * const results = await db.select().from(usersTable).where(condition)
   * ```
   */
  ilike: (left: SQLWrapper, right: unknown) => Promise<SQL> | SQL
  notIlike: (left: SQLWrapper, right: unknown) => Promise<SQL> | SQL

  /**
   * JSONB path query first operator for encrypted columns with searchable JSON.
   * Requires `searchableJson` to be set on {@link EncryptedColumnConfig}.
   *
   * Encrypts the JSON path selector and calls `eql_v2.jsonb_path_query_first()`,
   * casting the parameter to `eql_v2_encrypted`.
   *
   * @example
   * Query the first matching value at a JSON path inside an encrypted column.
   * ```ts
   * const condition = await protectOps.jsonbPathQueryFirst(docsTable.metadata, '$.profile.email')
   * const results = await db.select().from(docsTable).where(condition)
   * ```
   *
   * @throws {ProtectOperatorError} If the column does not have `searchableJson` enabled.
   */
  jsonbPathQueryFirst: (left: SQLWrapper, right: unknown) => Promise<SQL>

  /**
   * JSONB get operator for encrypted columns with searchable JSON.
   * Requires `searchableJson` to be set on {@link EncryptedColumnConfig}.
   *
   * Encrypts the JSON path selector and uses the `->` operator,
   * casting the parameter to `eql_v2_encrypted`.
   *
   * @example
   * Get a value at a JSON path inside an encrypted column.
   * ```ts
   * const condition = await protectOps.jsonbGet(docsTable.metadata, '$.profile.name')
   * const results = await db.select().from(docsTable).where(condition)
   * ```
   *
   * @throws {ProtectOperatorError} If the column does not have `searchableJson` enabled.
   */
  jsonbGet: (left: SQLWrapper, right: unknown) => Promise<SQL>

  /**
   * JSONB path exists operator for encrypted columns with searchable JSON.
   * Requires `searchableJson` to be set on {@link EncryptedColumnConfig}.
   *
   * Encrypts the JSON path selector and calls `eql_v2.jsonb_path_exists()`,
   * casting the parameter to `eql_v2_encrypted`.
   *
   * @example
   * Check whether a JSON path exists inside an encrypted column.
   * ```ts
   * const condition = await protectOps.jsonbPathExists(docsTable.metadata, '$.profile.email')
   * const results = await db.select().from(docsTable).where(condition)
   * ```
   *
   * @throws {ProtectOperatorError} If the column does not have `searchableJson` enabled.
   */
  jsonbPathExists: (left: SQLWrapper, right: unknown) => Promise<SQL>
  // Array operators
  inArray: (left: SQLWrapper, right: unknown[] | SQLWrapper) => Promise<SQL>
  notInArray: (left: SQLWrapper, right: unknown[] | SQLWrapper) => Promise<SQL>
  // Sorting operators
  asc: (column: SQLWrapper) => SQL
  desc: (column: SQLWrapper) => SQL
  and: (
    ...conditions: (SQL | SQLWrapper | Promise<SQL> | undefined)[]
  ) => Promise<SQL>
  or: (
    ...conditions: (SQL | SQLWrapper | Promise<SQL> | undefined)[]
  ) => Promise<SQL>
  // Operators that don't need encryption (pass through to Drizzle)
  exists: typeof exists
  notExists: typeof notExists
  isNull: typeof isNull
  isNotNull: typeof isNotNull
  not: typeof not
  // Array operators that work with arrays directly (not encrypted values)
  arrayContains: typeof arrayContains
  arrayContained: typeof arrayContained
  arrayOverlaps: typeof arrayOverlaps
} {
  // Create a cache for protect tables keyed by table name
  const protectTableCache = new Map<string, ProtectTable<ProtectTableColumn>>()
  const defaultProtectTable: ProtectTable<ProtectTableColumn> | undefined =
    undefined

  /**
   * Equality operator - encrypts value and uses regular Drizzle operator
   */
  const protectEq = (left: SQLWrapper, right: unknown): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )
    return createComparisonOperator(
      'eq',
      left,
      right,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
      dialect,
    )
  }

  /**
   * Not equal operator - encrypts value and uses regular Drizzle operator
   */
  const protectNe = (left: SQLWrapper, right: unknown): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )
    return createComparisonOperator(
      'ne',
      left,
      right,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
      dialect,
    )
  }

  /**
   * Greater than operator - uses eql_v2.gt() for encrypted columns with ORE index
   */
  const protectGt = (left: SQLWrapper, right: unknown): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )
    return createComparisonOperator(
      'gt',
      left,
      right,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
      dialect,
    )
  }

  /**
   * Greater than or equal operator - uses eql_v2.gte() for encrypted columns with ORE index
   */
  const protectGte = (left: SQLWrapper, right: unknown): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )
    return createComparisonOperator(
      'gte',
      left,
      right,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
      dialect,
    )
  }

  /**
   * Less than operator - uses eql_v2.lt() for encrypted columns with ORE index
   */
  const protectLt = (left: SQLWrapper, right: unknown): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )
    return createComparisonOperator(
      'lt',
      left,
      right,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
      dialect,
    )
  }

  /**
   * Less than or equal operator - uses eql_v2.lte() for encrypted columns with ORE index
   */
  const protectLte = (left: SQLWrapper, right: unknown): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )
    return createComparisonOperator(
      'lte',
      left,
      right,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
      dialect,
    )
  }

  /**
   * Between operator - uses eql_v2.gte() and eql_v2.lte() for encrypted columns with ORE index
   */
  const protectBetween = (
    left: SQLWrapper,
    min: unknown,
    max: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )
    return createRangeOperator(
      'between',
      left,
      min,
      max,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
      dialect,
    )
  }

  /**
   * Not between operator - uses eql_v2.gte() and eql_v2.lte() for encrypted columns with ORE index
   */
  const protectNotBetween = (
    left: SQLWrapper,
    min: unknown,
    max: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )
    return createRangeOperator(
      'notBetween',
      left,
      min,
      max,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
      dialect,
    )
  }

  /**
   * Like operator - encrypts value and uses eql_v2.like() for encrypted columns with match index
   */
  const protectLike = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )
    return createTextSearchOperator(
      'like',
      left,
      right,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
      dialect,
    )
  }

  /**
   * Case-insensitive like operator - encrypts value and uses eql_v2.ilike() for encrypted columns with match index
   */
  const protectIlike = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )
    return createTextSearchOperator(
      'ilike',
      left,
      right,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
      dialect,
    )
  }

  /**
   * Not like operator (case insensitive) - encrypts value and uses eql_v2.ilike() for encrypted columns with match index
   */
  const protectNotIlike = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )
    return createTextSearchOperator(
      'notIlike',
      left,
      right,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
      dialect,
    )
  }

  /**
   * JSONB path query first operator - encrypts the selector and calls
   * `eql_v2.jsonb_path_query_first()` for encrypted columns with searchable JSON.
   *
   * @throws {ProtectOperatorError} If the column lacks `searchableJson` config.
   */
  const protectJsonbPathQueryFirst = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> => {
    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )
    return createJsonbOperator(
      'jsonbPathQueryFirst',
      left,
      right,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
    )
  }

  /**
   * JSONB get operator - encrypts the selector and uses the `->` operator
   * for encrypted columns with searchable JSON.
   *
   * @throws {ProtectOperatorError} If the column lacks `searchableJson` config.
   */
  const protectJsonbGet = (left: SQLWrapper, right: unknown): Promise<SQL> => {
    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )
    return createJsonbOperator(
      'jsonbGet',
      left,
      right,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
    )
  }

  /**
   * JSONB path exists operator - encrypts the selector and calls
   * `eql_v2.jsonb_path_exists()` for encrypted columns with searchable JSON.
   *
   * @throws {ProtectOperatorError} If the column lacks `searchableJson` config.
   */
  const protectJsonbPathExists = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> => {
    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )
    return createJsonbOperator(
      'jsonbPathExists',
      left,
      right,
      columnInfo,
      protectClient,
      defaultProtectTable,
      protectTableCache,
    )
  }

  /**
   * In array operator - encrypts all values in the array
   */
  const protectInArray = async (
    left: SQLWrapper,
    right: unknown[] | SQLWrapper,
  ): Promise<SQL> => {
    // If right is a SQLWrapper (subquery), pass through to Drizzle
    if (isSQLWrapper(right)) {
      return inArray(left, right as unknown as Parameters<typeof inArray>[1])
    }

    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )

    if (!columnInfo.config?.equality || !Array.isArray(right)) {
      return inArray(left, right as unknown[])
    }

    // Encrypt all values in the array in a single batch
    const encryptedValues = await encryptValues(
      protectClient,
      right.map((value) => ({
        value,
        column: left,
        queryType: 'equality' as const,
      })),
      defaultProtectTable,
      protectTableCache,
    )

    // Route each value through the dialect seam (not Drizzle's bare `eq`): under v3
    // equality compares eql_v3.eq_term(col) to eql_v3.hmac_256(term), since a native
    // `=` would coerce the term into text_eq and fail the domain CHECK (SQLSTATE
    // 23514). v2Dialect emits the identical native `=`, so v2 is unaffected.
    const conditions = encryptedValues
      .filter((encrypted) => encrypted !== undefined)
      .map((encrypted) =>
        dialect.equality(
          'eq',
          sql`${left}`,
          sql`${bindIfParam(encrypted, left)}`,
        ),
      )

    if (conditions.length === 0) {
      return sql`false`
    }

    const combined = or(...conditions)
    return combined ?? sql`false`
  }

  /**
   * Not in array operator
   */
  const protectNotInArray = async (
    left: SQLWrapper,
    right: unknown[] | SQLWrapper,
  ): Promise<SQL> => {
    // If right is a SQLWrapper (subquery), pass through to Drizzle
    if (isSQLWrapper(right)) {
      return notInArray(
        left,
        right as unknown as Parameters<typeof notInArray>[1],
      )
    }

    const columnInfo = getColumnInfo(
      left,
      defaultProtectTable,
      protectTableCache,
    )

    if (!columnInfo.config?.equality || !Array.isArray(right)) {
      return notInArray(left, right as unknown[])
    }

    // Encrypt all values in the array in a single batch
    const encryptedValues = await encryptValues(
      protectClient,
      right.map((value) => ({
        value,
        column: left,
        queryType: 'equality' as const,
      })),
      defaultProtectTable,
      protectTableCache,
    )

    // Route each value through the dialect seam (not Drizzle's bare `ne`) — same
    // reason as protectInArray: v3 inequality is eql_v3.eq_term(col) <> hmac_256(term).
    const conditions = encryptedValues
      .filter((encrypted) => encrypted !== undefined)
      .map((encrypted) =>
        dialect.equality(
          'ne',
          sql`${left}`,
          sql`${bindIfParam(encrypted, left)}`,
        ),
      )

    if (conditions.length === 0) {
      return sql`true`
    }

    const combined = and(...conditions)
    return combined ?? sql`true`
  }

  /**
   * Ascending order helper - uses eql_v2.order_by() for encrypted columns with ORE index
   */
  const protectAsc = (column: SQLWrapper): SQL => {
    const columnInfo = getColumnInfo(
      column,
      defaultProtectTable,
      protectTableCache,
    )

    if (columnInfo.config?.orderAndRange) {
      return asc(dialect.orderBy(sql`${column}`))
    }

    return asc(column)
  }

  /**
   * Descending order helper - uses eql_v2.order_by() for encrypted columns with ORE index
   */
  const protectDesc = (column: SQLWrapper): SQL => {
    const columnInfo = getColumnInfo(
      column,
      defaultProtectTable,
      protectTableCache,
    )

    if (columnInfo.config?.orderAndRange) {
      return desc(dialect.orderBy(sql`${column}`))
    }

    return desc(column)
  }

  /**
   * Batched AND operator - collects lazy operators, batches encryption, and combines conditions
   */
  const protectAnd = async (
    ...conditions: (SQL | SQLWrapper | Promise<SQL> | undefined)[]
  ): Promise<SQL> => {
    // Single pass: separate lazy operators from regular conditions
    const lazyOperators: LazyOperator[] = []
    const regularConditions: (SQL | SQLWrapper | undefined)[] = []
    const regularPromises: Promise<SQL>[] = []

    for (const condition of conditions) {
      if (condition === undefined) {
        continue
      }

      if (isLazyOperator(condition)) {
        lazyOperators.push(condition)
      } else if (condition instanceof Promise) {
        // Check if promise is also a lazy operator
        if (isLazyOperator(condition)) {
          lazyOperators.push(condition)
        } else {
          regularPromises.push(condition)
        }
      } else {
        regularConditions.push(condition)
      }
    }

    // If there are no lazy operators, just use Drizzle's and()
    if (lazyOperators.length === 0) {
      const allConditions: (SQL | SQLWrapper | undefined)[] = [
        ...regularConditions,
        ...(await Promise.all(regularPromises)),
      ]
      return and(...allConditions) ?? sql`true`
    }

    // Single pass: collect all values to encrypt with metadata
    const valuesToEncrypt: Array<{
      value: unknown
      column: SQLWrapper
      columnInfo: ColumnInfo
      queryType?: QueryTypeName
      lazyOpIndex: number
      isMin?: boolean
      isMax?: boolean
    }> = []

    for (let i = 0; i < lazyOperators.length; i++) {
      const lazyOp = lazyOperators[i]
      if (!lazyOp.needsEncryption) {
        continue
      }

      if (lazyOp.min !== undefined && lazyOp.max !== undefined) {
        valuesToEncrypt.push({
          value: lazyOp.min,
          column: lazyOp.left,
          columnInfo: lazyOp.columnInfo,
          queryType: lazyOp.queryType,
          lazyOpIndex: i,
          isMin: true,
        })
        valuesToEncrypt.push({
          value: lazyOp.max,
          column: lazyOp.left,
          columnInfo: lazyOp.columnInfo,
          queryType: lazyOp.queryType,
          lazyOpIndex: i,
          isMax: true,
        })
      } else if (lazyOp.right !== undefined) {
        valuesToEncrypt.push({
          value: lazyOp.right,
          column: lazyOp.left,
          columnInfo: lazyOp.columnInfo,
          queryType: lazyOp.queryType,
          lazyOpIndex: i,
        })
      }
    }

    // Batch encrypt all values
    const encryptedResults = await encryptValues(
      protectClient,
      valuesToEncrypt.map((v) => ({
        value: v.value,
        column: v.column,
        queryType: v.queryType,
      })),
      defaultProtectTable,
      protectTableCache,
    )

    // Group encrypted values by lazy operator index
    const encryptedByLazyOp = new Map<
      number,
      { value?: unknown; min?: unknown; max?: unknown }
    >()

    for (let i = 0; i < valuesToEncrypt.length; i++) {
      const { lazyOpIndex, isMin, isMax } = valuesToEncrypt[i]
      const encrypted = encryptedResults[i]

      let group = encryptedByLazyOp.get(lazyOpIndex)
      if (!group) {
        group = {}
        encryptedByLazyOp.set(lazyOpIndex, group)
      }

      if (isMin) {
        group.min = encrypted
      } else if (isMax) {
        group.max = encrypted
      } else {
        group.value = encrypted
      }
    }

    // Execute all lazy operators with their encrypted values
    const sqlConditions: SQL[] = []
    for (let i = 0; i < lazyOperators.length; i++) {
      const lazyOp = lazyOperators[i]
      const encrypted = encryptedByLazyOp.get(i)

      let sqlCondition: SQL
      if (lazyOp.needsEncryption && encrypted) {
        const encryptedValues: Array<{ value: unknown; encrypted: unknown }> =
          []
        if (encrypted.value !== undefined) {
          encryptedValues.push({
            value: lazyOp.right,
            encrypted: encrypted.value,
          })
        }
        if (encrypted.min !== undefined) {
          encryptedValues.push({ value: lazyOp.min, encrypted: encrypted.min })
        }
        if (encrypted.max !== undefined) {
          encryptedValues.push({ value: lazyOp.max, encrypted: encrypted.max })
        }
        sqlCondition = await executeLazyOperator(lazyOp, encryptedValues)
      } else {
        sqlCondition = lazyOp.execute(lazyOp.right)
      }

      sqlConditions.push(sqlCondition)
    }

    // Await any regular promises
    const regularPromisesResults = await Promise.all(regularPromises)

    // Combine all conditions
    const allConditions: (SQL | SQLWrapper | undefined)[] = [
      ...regularConditions,
      ...sqlConditions,
      ...regularPromisesResults,
    ]

    return and(...allConditions) ?? sql`true`
  }

  /**
   * Batched OR operator - collects lazy operators, batches encryption, and combines conditions
   */
  const protectOr = async (
    ...conditions: (SQL | SQLWrapper | Promise<SQL> | undefined)[]
  ): Promise<SQL> => {
    const lazyOperators: LazyOperator[] = []
    const regularConditions: (SQL | SQLWrapper | undefined)[] = []
    const regularPromises: Promise<SQL>[] = []

    for (const condition of conditions) {
      if (condition === undefined) {
        continue
      }

      if (isLazyOperator(condition)) {
        lazyOperators.push(condition)
      } else if (condition instanceof Promise) {
        if (isLazyOperator(condition)) {
          lazyOperators.push(condition)
        } else {
          regularPromises.push(condition)
        }
      } else {
        regularConditions.push(condition)
      }
    }

    if (lazyOperators.length === 0) {
      const allConditions: (SQL | SQLWrapper | undefined)[] = [
        ...regularConditions,
        ...(await Promise.all(regularPromises)),
      ]
      return or(...allConditions) ?? sql`false`
    }

    const valuesToEncrypt: Array<{
      value: unknown
      column: SQLWrapper
      columnInfo: ColumnInfo
      queryType?: QueryTypeName
      lazyOpIndex: number
      isMin?: boolean
      isMax?: boolean
    }> = []

    for (let i = 0; i < lazyOperators.length; i++) {
      const lazyOp = lazyOperators[i]
      if (!lazyOp.needsEncryption) {
        continue
      }

      if (lazyOp.min !== undefined && lazyOp.max !== undefined) {
        valuesToEncrypt.push({
          value: lazyOp.min,
          column: lazyOp.left,
          columnInfo: lazyOp.columnInfo,
          queryType: lazyOp.queryType,
          lazyOpIndex: i,
          isMin: true,
        })
        valuesToEncrypt.push({
          value: lazyOp.max,
          column: lazyOp.left,
          columnInfo: lazyOp.columnInfo,
          queryType: lazyOp.queryType,
          lazyOpIndex: i,
          isMax: true,
        })
      } else if (lazyOp.right !== undefined) {
        valuesToEncrypt.push({
          value: lazyOp.right,
          column: lazyOp.left,
          columnInfo: lazyOp.columnInfo,
          queryType: lazyOp.queryType,
          lazyOpIndex: i,
        })
      }
    }

    const encryptedResults = await encryptValues(
      protectClient,
      valuesToEncrypt.map((v) => ({
        value: v.value,
        column: v.column,
        queryType: v.queryType,
      })),
      defaultProtectTable,
      protectTableCache,
    )

    const encryptedByLazyOp = new Map<
      number,
      { value?: unknown; min?: unknown; max?: unknown }
    >()

    for (let i = 0; i < valuesToEncrypt.length; i++) {
      const { lazyOpIndex, isMin, isMax } = valuesToEncrypt[i]
      const encrypted = encryptedResults[i]

      let group = encryptedByLazyOp.get(lazyOpIndex)
      if (!group) {
        group = {}
        encryptedByLazyOp.set(lazyOpIndex, group)
      }

      if (isMin) {
        group.min = encrypted
      } else if (isMax) {
        group.max = encrypted
      } else {
        group.value = encrypted
      }
    }

    const sqlConditions: SQL[] = []
    for (let i = 0; i < lazyOperators.length; i++) {
      const lazyOp = lazyOperators[i]
      const encrypted = encryptedByLazyOp.get(i)

      let sqlCondition: SQL
      if (lazyOp.needsEncryption && encrypted) {
        const encryptedValues: Array<{ value: unknown; encrypted: unknown }> =
          []
        if (encrypted.value !== undefined) {
          encryptedValues.push({
            value: lazyOp.right,
            encrypted: encrypted.value,
          })
        }
        if (encrypted.min !== undefined) {
          encryptedValues.push({ value: lazyOp.min, encrypted: encrypted.min })
        }
        if (encrypted.max !== undefined) {
          encryptedValues.push({ value: lazyOp.max, encrypted: encrypted.max })
        }
        sqlCondition = await executeLazyOperator(lazyOp, encryptedValues)
      } else {
        sqlCondition = lazyOp.execute(lazyOp.right)
      }

      sqlConditions.push(sqlCondition)
    }

    const regularPromisesResults = await Promise.all(regularPromises)

    const allConditions: (SQL | SQLWrapper | undefined)[] = [
      ...regularConditions,
      ...sqlConditions,
      ...regularPromisesResults,
    ]

    return or(...allConditions) ?? sql`false`
  }

  return {
    // Comparison operators
    eq: protectEq,
    ne: protectNe,
    gt: protectGt,
    gte: protectGte,
    lt: protectLt,
    lte: protectLte,

    // Range operators
    between: protectBetween,
    notBetween: protectNotBetween,

    // Text search operators
    like: protectLike,
    ilike: protectIlike,
    notIlike: protectNotIlike,

    // Searchable JSON operators
    jsonbPathQueryFirst: protectJsonbPathQueryFirst,
    jsonbGet: protectJsonbGet,
    jsonbPathExists: protectJsonbPathExists,

    // Array operators
    inArray: protectInArray,
    notInArray: protectNotInArray,

    // Sorting operators
    asc: protectAsc,
    desc: protectDesc,

    // AND operator - batches encryption operations
    and: protectAnd,

    // OR operator - batches encryption operations
    or: protectOr,

    // Operators that don't need encryption (pass through to Drizzle)
    exists,
    notExists,
    isNull,
    isNotNull,
    not,
    // Array operators that work with arrays directly (not encrypted values)
    arrayContains,
    arrayContained,
    arrayOverlaps,
  }
}
