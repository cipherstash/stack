import {
  and,
  arrayContained,
  arrayContains,
  arrayOverlaps,
  asc,
  between,
  bindIfParam,
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
  type SQL,
  type SQLWrapper,
  sql,
} from 'drizzle-orm'
import type { PgTable } from 'drizzle-orm/pg-core'
import type { EncryptionClient } from '@/encryption/index.js'
import type {
  EncryptedColumn,
  EncryptedTable,
  EncryptedTableColumn,
} from '@/schema'
import { type QueryTypeName, queryTypes } from '@/types'
import type { EncryptedColumnConfig } from './index.js'
import { getEncryptedColumnConfig } from './index.js'
import { extractEncryptionSchema } from './schema-extraction.js'

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
export class EncryptionOperatorError extends Error {
  constructor(
    message: string,
    public readonly context?: {
      tableName?: string
      columnName?: string
      operator?: string
    },
  ) {
    super(message)
    this.name = 'EncryptionOperatorError'
  }
}

export class EncryptionConfigError extends EncryptionOperatorError {
  constructor(message: string, context?: EncryptionOperatorError['context']) {
    super(message, context)
    this.name = 'EncryptionConfigError'
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
 * Helper to extract encrypted table from a drizzle column by deriving it from the column's parent table
 */
function getEncryptedTableFromColumn(
  drizzleColumn: SQLWrapper,
  tableCache: Map<string, EncryptedTable<EncryptedTableColumn>>,
): EncryptedTable<EncryptedTableColumn> | undefined {
  const drizzleTable = getDrizzleTableFromColumn(drizzleColumn)
  if (!drizzleTable) {
    return undefined
  }

  const tableName = getDrizzleTableName(drizzleTable)
  if (!tableName) {
    return undefined
  }

  // Check cache first
  let encryptedTable = tableCache.get(tableName)
  if (encryptedTable) {
    return encryptedTable
  }

  // Extract encryption schema from drizzle table and cache it
  try {
    // biome-ignore lint/suspicious/noExplicitAny: PgTable type doesn't expose all needed properties
    encryptedTable = extractEncryptionSchema(drizzleTable as PgTable<any>)
    tableCache.set(tableName, encryptedTable)
    return encryptedTable
  } catch {
    // Table doesn't have encrypted columns or extraction failed
    return undefined
  }
}

/**
 * Helper to get the encrypted column definition for a Drizzle column from the encrypted table
 */
function getEncryptedColumn(
  drizzleColumn: SQLWrapper,
  encryptedTable: EncryptedTable<EncryptedTableColumn>,
): EncryptedColumn | undefined {
  const column = drizzleColumn as unknown as Record<string, unknown>
  const columnName = column.name as string | undefined
  if (!columnName) {
    return undefined
  }

  const tableRecord = encryptedTable as unknown as Record<string, unknown>
  return tableRecord[columnName] as EncryptedColumn | undefined
}

/**
 * Column metadata extracted from a Drizzle column
 */
interface ColumnInfo {
  readonly encryptedColumn: EncryptedColumn | undefined
  readonly config: (EncryptedColumnConfig & { name: string }) | undefined
  readonly encryptedTable: EncryptedTable<EncryptedTableColumn> | undefined
  readonly columnName: string
  readonly tableName: string | undefined
}

/**
 * Helper to get the encrypted column and column config for a Drizzle column
 * If encryptedTable is not provided, it will be derived from the column
 */
function getColumnInfo(
  drizzleColumn: SQLWrapper,
  encryptedTable: EncryptedTable<EncryptedTableColumn> | undefined,
  tableCache: Map<string, EncryptedTable<EncryptedTableColumn>>,
): ColumnInfo {
  const column = drizzleColumn as unknown as Record<string, unknown>
  const columnName = (column.name as string | undefined) || 'unknown'

  // If encryptedTable not provided, try to derive it from the column
  let resolvedTable = encryptedTable
  if (!resolvedTable) {
    resolvedTable = getEncryptedTableFromColumn(drizzleColumn, tableCache)
  }

  const drizzleTable = getDrizzleTableFromColumn(drizzleColumn)
  const tableName = getDrizzleTableName(drizzleTable)

  if (!resolvedTable) {
    // Column is not from an encrypted table
    const config = getEncryptedColumnConfig(columnName, drizzleColumn)
    return {
      encryptedColumn: undefined,
      config,
      encryptedTable: undefined,
      columnName,
      tableName,
    }
  }

  const encryptedColumn = getEncryptedColumn(drizzleColumn, resolvedTable)
  const config = getEncryptedColumnConfig(columnName, drizzleColumn)

  return {
    encryptedColumn,
    config,
    encryptedTable: resolvedTable,
    columnName,
    tableName,
  }
}

/**
 * Helper to convert a value to plaintext format
 */
function toPlaintext(value: unknown): string | number | bigint {
  if (typeof value === 'boolean') {
    return value ? 1 : 0
  }
  if (
    typeof value === 'string' ||
    typeof value === 'number' ||
    // `bigint` (int8 columns) must pass through as a native bigint, NOT via the
    // `String(value)` fallthrough below — a stringified bigint would be
    // encrypted as text and silently mismatch the column's bigint domain. The
    // downstream `encryptQuery` term type is `Plaintext`, which carries bigint,
    // and protect-ffi 0.28 i64-bounds-checks it at the boundary.
    typeof value === 'bigint'
  ) {
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
  readonly value: string | number | bigint
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
  encryptionClient: EncryptionClient,
  values: Array<{
    value: unknown
    column: SQLWrapper
    queryType?: QueryTypeName
  }>,
  encryptedTable: EncryptedTable<EncryptedTableColumn> | undefined,
  tableCache: Map<string, EncryptedTable<EncryptedTableColumn>>,
): Promise<unknown[]> {
  if (values.length === 0) {
    return []
  }

  // Single pass: collect values to encrypt with their metadata
  const valuesToEncrypt: ValueToEncrypt[] = []
  const results: unknown[] = new Array(values.length)

  for (let i = 0; i < values.length; i++) {
    const { value, column, queryType } = values[i]
    const columnInfo = getColumnInfo(column, encryptedTable, tableCache)

    if (
      !columnInfo.encryptedColumn ||
      !columnInfo.config ||
      !columnInfo.encryptedTable
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
      column: EncryptedColumn
      table: EncryptedTable<EncryptedTableColumn>
      columnName: string
      values: Array<{
        value: string | number | bigint
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
      !columnInfo.encryptedColumn ||
      !columnInfo.encryptedTable
    ) {
      continue
    }

    const columnName = columnInfo.config.name
    const groupKey = `${columnInfo.tableName ?? 'unknown'}/${columnName}`
    let group = columnGroups.get(groupKey)
    if (!group) {
      group = {
        column: columnInfo.encryptedColumn,
        table: columnInfo.encryptedTable,
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

      const encryptedTerms = await encryptionClient.encryptQuery(terms)

      if (encryptedTerms.failure) {
        throw new EncryptionOperatorError(
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
      if (error instanceof EncryptionOperatorError) {
        throw error
      }
      const errorMessage =
        error instanceof Error ? error.message : String(error)
      throw new EncryptionOperatorError(
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
  encryptionClient: EncryptionClient,
  value: unknown,
  drizzleColumn: SQLWrapper,
  encryptedTable: EncryptedTable<EncryptedTableColumn> | undefined,
  tableCache: Map<string, EncryptedTable<EncryptedTableColumn>>,
  queryType?: QueryTypeName,
): Promise<unknown> {
  const results = await encryptValues(
    encryptionClient,
    [{ value, column: drizzleColumn, queryType }],
    encryptedTable,
    tableCache,
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
  encryptionClient: EncryptionClient,
  defaultTable: EncryptedTable<EncryptedTableColumn> | undefined,
  tableCache: Map<string, EncryptedTable<EncryptedTableColumn>>,
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
            encryptionClient,
            defaultTable,
            tableCache,
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
      throw new EncryptionOperatorError(
        'Between operator requires both min and max encrypted values',
        {
          columnName: lazyOp.columnInfo.columnName,
          tableName: lazyOp.columnInfo.tableName,
          operator: lazyOp.operator,
        },
      )
    }

    if (encryptedMin === undefined || encryptedMax === undefined) {
      throw new EncryptionOperatorError(
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
    throw new EncryptionOperatorError(
      'Operator requires encrypted value but none provided',
      {
        columnName: lazyOp.columnInfo.columnName,
        tableName: lazyOp.columnInfo.tableName,
        operator: lazyOp.operator,
      },
    )
  }

  if (encrypted === undefined) {
    throw new EncryptionOperatorError(
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
  encryptionClient: EncryptionClient,
  defaultTable: EncryptedTable<EncryptedTableColumn> | undefined,
  tableCache: Map<string, EncryptedTable<EncryptedTableColumn>>,
): Promise<SQL> {
  if (!lazyOp.needsEncryption) {
    return lazyOp.execute(lazyOp.right)
  }

  if (lazyOp.min !== undefined && lazyOp.max !== undefined) {
    // Between operator - encrypt min and max
    const [encryptedMin, encryptedMax] = await encryptValues(
      encryptionClient,
      [
        { value: lazyOp.min, column: lazyOp.left, queryType: lazyOp.queryType },
        { value: lazyOp.max, column: lazyOp.left, queryType: lazyOp.queryType },
      ],
      defaultTable,
      tableCache,
    )
    return lazyOp.execute(undefined, encryptedMin, encryptedMax)
  }

  // Single value operator
  const encrypted = await encryptValue(
    encryptionClient,
    lazyOp.right,
    lazyOp.left,
    defaultTable,
    tableCache,
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
  encryptionClient: EncryptionClient,
  defaultTable: EncryptedTable<EncryptedTableColumn> | undefined,
  tableCache: Map<string, EncryptedTable<EncryptedTableColumn>>,
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
        throw new EncryptionOperatorError(
          `Encryption failed for ${operator} operator`,
          {
            columnName: columnInfo.columnName,
            tableName: columnInfo.tableName,
            operator,
          },
        )
      }
      return sql`eql_v2.${sql.raw(operator)}(${left}, ${bindIfParam(encrypted, left)})`
    }

    return createLazyOperator(
      operator,
      left,
      right,
      executeFn,
      true,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
      undefined, // min
      undefined, // max
      queryTypes.orderAndRange,
    ) as Promise<SQL>
  }

  // Equality operators (eq, ne)
  const requiresEquality = ['eq', 'ne'].includes(operator)

  if (requiresEquality && config?.equality) {
    const executeFn = (encrypted: unknown) => {
      if (encrypted === undefined) {
        throw new EncryptionOperatorError(
          `Encryption failed for ${operator} operator`,
          {
            columnName: columnInfo.columnName,
            tableName: columnInfo.tableName,
            operator,
          },
        )
      }
      return operator === 'eq' ? eq(left, encrypted) : ne(left, encrypted)
    }

    return createLazyOperator(
      operator,
      left,
      right,
      executeFn,
      true,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
      undefined, // min
      undefined, // max
      queryTypes.equality,
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
  encryptionClient: EncryptionClient,
  defaultTable: EncryptedTable<EncryptedTableColumn> | undefined,
  tableCache: Map<string, EncryptedTable<EncryptedTableColumn>>,
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
      throw new EncryptionOperatorError(
        `${operator} operator requires both min and max values`,
        {
          columnName: columnInfo.columnName,
          tableName: columnInfo.tableName,
          operator,
        },
      )
    }

    const rangeCondition = sql`eql_v2.gte(${left}, ${bindIfParam(encryptedMin, left)}) AND eql_v2.lte(${left}, ${bindIfParam(encryptedMax, left)})`

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
    encryptionClient,
    defaultTable,
    tableCache,
    min,
    max,
    queryTypes.orderAndRange,
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
  encryptionClient: EncryptionClient,
  defaultTable: EncryptedTable<EncryptedTableColumn> | undefined,
  tableCache: Map<string, EncryptedTable<EncryptedTableColumn>>,
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
      throw new EncryptionOperatorError(
        `Encryption failed for ${operator} operator`,
        {
          columnName: columnInfo.columnName,
          tableName: columnInfo.tableName,
          operator,
        },
      )
    }

    const sqlFn = sql`eql_v2.${sql.raw(operator === 'notIlike' ? 'ilike' : operator)}(${left}, ${bindIfParam(encrypted, left)})`
    return operator === 'notIlike' ? sql`NOT (${sqlFn})` : sqlFn
  }

  return createLazyOperator(
    operator,
    left,
    right,
    executeFn,
    true,
    columnInfo,
    encryptionClient,
    defaultTable,
    tableCache,
    undefined, // min
    undefined, // max
    queryTypes.freeTextSearch,
  ) as Promise<SQL>
}

/**
 * Creates a JSONB operator that encrypts a JSON path selector and wraps it
 * in the appropriate `eql_v2` function call.
 *
 * Supports `jsonbPathQueryFirst`, `jsonbGet`, and `jsonbPathExists`.
 * The column must have `searchableJson` enabled in its {@link EncryptedColumnConfig}.
 */
function createJsonbOperator(
  operator: 'jsonbPathQueryFirst' | 'jsonbGet' | 'jsonbPathExists',
  left: SQLWrapper,
  right: unknown,
  columnInfo: ColumnInfo,
  encryptionClient: EncryptionClient,
  defaultTable: EncryptedTable<EncryptedTableColumn> | undefined,
  tableCache: Map<string, EncryptedTable<EncryptedTableColumn>>,
): Promise<SQL> {
  const { config } = columnInfo
  const encryptedSelector = (value: unknown) =>
    sql`${bindIfParam(value, left)}::eql_v2_encrypted`

  if (!config?.searchableJson) {
    throw new EncryptionOperatorError(
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
      throw new EncryptionOperatorError(
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
    encryptionClient,
    defaultTable,
    tableCache,
    undefined,
    undefined,
    queryTypes.steVecSelector,
  ) as Promise<SQL>
}

// ============================================================================
// Public API: createEncryptionOperators
// ============================================================================

/**
 * Creates a set of encryption-aware operators that automatically encrypt values
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
 * @param encryptionClient - The EncryptionClient instance
 * @returns An object with all Drizzle operators wrapped for encrypted columns
 *
 * @example
 * ```ts
 * // Initialize operators
 * const ops = createEncryptionOperators(encryptionClient)
 *
 * // Equality search - automatically encrypts and uses PostgreSQL operators
 * const results = await db
 *   .select()
 *   .from(usersTable)
 *   .where(await ops.eq(usersTable.email, 'user@example.com'))
 *
 * // Range query - automatically encrypts and uses eql_v2.gte()
 * const olderUsers = await db
 *   .select()
 *   .from(usersTable)
 *   .where(await ops.gte(usersTable.age, 25))
 * ```
 */
export function createEncryptionOperators(encryptionClient: EncryptionClient): {
  // Comparison operators
  /**
   * Equality operator - encrypts value for encrypted columns.
   * Requires either `equality` or `orderAndRange` to be set on {@link EncryptedColumnConfig}.
   *
   * @example
   * Select users with a specific email address.
   * ```ts
   * const condition = await ops.eq(usersTable.email, 'user@example.com')
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
   * const condition = await ops.ne(usersTable.email, 'user@example.com')
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
   * const condition = await ops.gt(usersTable.age, 30)
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
   * const condition = await ops.gte(usersTable.age, 30)
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
   * const condition = await ops.lt(usersTable.age, 30)
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
   * const condition = await ops.lte(usersTable.age, 30)
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
   * const condition = await ops.between(usersTable.age, 20, 30)
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
   * const condition = await ops.notBetween(usersTable.age, 20, 30)
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
   * const condition = await ops.like(usersTable.email, '%@example.com')
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
   * const condition = await ops.ilike(usersTable.email, '%@example.com')
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
   * @throws {EncryptionOperatorError} If the column does not have `searchableJson` enabled.
   */
  jsonbPathQueryFirst: (left: SQLWrapper, right: unknown) => Promise<SQL>

  /**
   * JSONB get operator for encrypted columns with searchable JSON.
   * Requires `searchableJson` to be set on {@link EncryptedColumnConfig}.
   *
   * Encrypts the JSON path selector and uses the `->` operator,
   * casting the parameter to `eql_v2_encrypted`.
   *
   * @throws {EncryptionOperatorError} If the column does not have `searchableJson` enabled.
   */
  jsonbGet: (left: SQLWrapper, right: unknown) => Promise<SQL>

  /**
   * JSONB path exists operator for encrypted columns with searchable JSON.
   * Requires `searchableJson` to be set on {@link EncryptedColumnConfig}.
   *
   * Encrypts the JSON path selector and calls `eql_v2.jsonb_path_exists()`,
   * casting the parameter to `eql_v2_encrypted`.
   *
   * @throws {EncryptionOperatorError} If the column does not have `searchableJson` enabled.
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
  // Create a cache for encrypted tables keyed by table name
  const tableCache = new Map<string, EncryptedTable<EncryptedTableColumn>>()
  const defaultTable: EncryptedTable<EncryptedTableColumn> | undefined =
    undefined

  /**
   * Equality operator - encrypts value and uses regular Drizzle operator
   */
  const encryptedEq = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(left, defaultTable, tableCache)
    return createComparisonOperator(
      'eq',
      left,
      right,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
    )
  }

  /**
   * Not equal operator - encrypts value and uses regular Drizzle operator
   */
  const encryptedNe = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(left, defaultTable, tableCache)
    return createComparisonOperator(
      'ne',
      left,
      right,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
    )
  }

  /**
   * Greater than operator - uses eql_v2.gt() for encrypted columns with ORE index
   */
  const encryptedGt = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(left, defaultTable, tableCache)
    return createComparisonOperator(
      'gt',
      left,
      right,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
    )
  }

  /**
   * Greater than or equal operator - uses eql_v2.gte() for encrypted columns with ORE index
   */
  const encryptedGte = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(left, defaultTable, tableCache)
    return createComparisonOperator(
      'gte',
      left,
      right,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
    )
  }

  /**
   * Less than operator - uses eql_v2.lt() for encrypted columns with ORE index
   */
  const encryptedLt = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(left, defaultTable, tableCache)
    return createComparisonOperator(
      'lt',
      left,
      right,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
    )
  }

  /**
   * Less than or equal operator - uses eql_v2.lte() for encrypted columns with ORE index
   */
  const encryptedLte = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(left, defaultTable, tableCache)
    return createComparisonOperator(
      'lte',
      left,
      right,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
    )
  }

  /**
   * Between operator - uses eql_v2.gte() and eql_v2.lte() for encrypted columns with ORE index
   */
  const encryptedBetween = (
    left: SQLWrapper,
    min: unknown,
    max: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(left, defaultTable, tableCache)
    return createRangeOperator(
      'between',
      left,
      min,
      max,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
    )
  }

  /**
   * Not between operator - uses eql_v2.gte() and eql_v2.lte() for encrypted columns with ORE index
   */
  const encryptedNotBetween = (
    left: SQLWrapper,
    min: unknown,
    max: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(left, defaultTable, tableCache)
    return createRangeOperator(
      'notBetween',
      left,
      min,
      max,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
    )
  }

  /**
   * Like operator - encrypts value and uses eql_v2.like() for encrypted columns with match index
   */
  const encryptedLike = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(left, defaultTable, tableCache)
    return createTextSearchOperator(
      'like',
      left,
      right,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
    )
  }

  /**
   * Case-insensitive like operator - encrypts value and uses eql_v2.ilike() for encrypted columns with match index
   */
  const encryptedIlike = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(left, defaultTable, tableCache)
    return createTextSearchOperator(
      'ilike',
      left,
      right,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
    )
  }

  /**
   * Not like operator (case insensitive) - encrypts value and uses eql_v2.ilike() for encrypted columns with match index
   */
  const encryptedNotIlike = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> | SQL => {
    const columnInfo = getColumnInfo(left, defaultTable, tableCache)
    return createTextSearchOperator(
      'notIlike',
      left,
      right,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
    )
  }

  /**
   * JSONB path query first operator - encrypts the selector and calls
   * `eql_v2.jsonb_path_query_first()` for encrypted columns with searchable JSON.
   */
  const encryptedJsonbPathQueryFirst = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> => {
    const columnInfo = getColumnInfo(left, defaultTable, tableCache)
    return createJsonbOperator(
      'jsonbPathQueryFirst',
      left,
      right,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
    )
  }

  /**
   * JSONB get operator - encrypts the selector and uses the `->` operator
   * for encrypted columns with searchable JSON.
   */
  const encryptedJsonbGet = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> => {
    const columnInfo = getColumnInfo(left, defaultTable, tableCache)
    return createJsonbOperator(
      'jsonbGet',
      left,
      right,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
    )
  }

  /**
   * JSONB path exists operator - encrypts the selector and calls
   * `eql_v2.jsonb_path_exists()` for encrypted columns with searchable JSON.
   */
  const encryptedJsonbPathExists = (
    left: SQLWrapper,
    right: unknown,
  ): Promise<SQL> => {
    const columnInfo = getColumnInfo(left, defaultTable, tableCache)
    return createJsonbOperator(
      'jsonbPathExists',
      left,
      right,
      columnInfo,
      encryptionClient,
      defaultTable,
      tableCache,
    )
  }

  /**
   * In array operator - encrypts all values in the array
   */
  const encryptedInArray = async (
    left: SQLWrapper,
    right: unknown[] | SQLWrapper,
  ): Promise<SQL> => {
    // If right is a SQLWrapper (subquery), pass through to Drizzle
    if (isSQLWrapper(right)) {
      return inArray(left, right as unknown as Parameters<typeof inArray>[1])
    }

    const columnInfo = getColumnInfo(left, defaultTable, tableCache)

    if (!columnInfo.config?.equality || !Array.isArray(right)) {
      return inArray(left, right as unknown[])
    }

    // Encrypt all values in the array in a single batch
    const encryptedValues = await encryptValues(
      encryptionClient,
      right.map((value) => ({
        value,
        column: left,
        queryType: queryTypes.equality,
      })),
      defaultTable,
      tableCache,
    )

    // Use regular eq for each encrypted value - PostgreSQL operators handle it
    const conditions = encryptedValues
      .filter((encrypted) => encrypted !== undefined)
      .map((encrypted) => eq(left, encrypted))

    if (conditions.length === 0) {
      return sql`false`
    }

    const combined = or(...conditions)
    return combined ?? sql`false`
  }

  /**
   * Not in array operator
   */
  const encryptedNotInArray = async (
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

    const columnInfo = getColumnInfo(left, defaultTable, tableCache)

    if (!columnInfo.config?.equality || !Array.isArray(right)) {
      return notInArray(left, right as unknown[])
    }

    // Encrypt all values in the array in a single batch
    const encryptedValues = await encryptValues(
      encryptionClient,
      right.map((value) => ({
        value,
        column: left,
        queryType: queryTypes.equality,
      })),
      defaultTable,
      tableCache,
    )

    // Use regular ne for each encrypted value - PostgreSQL operators handle it
    const conditions = encryptedValues
      .filter((encrypted) => encrypted !== undefined)
      .map((encrypted) => ne(left, encrypted))

    if (conditions.length === 0) {
      return sql`true`
    }

    const combined = and(...conditions)
    return combined ?? sql`true`
  }

  /**
   * Ascending order helper - uses eql_v2.order_by() for encrypted columns with ORE index
   */
  const encryptedAsc = (column: SQLWrapper): SQL => {
    const columnInfo = getColumnInfo(column, defaultTable, tableCache)

    if (columnInfo.config?.orderAndRange) {
      return asc(sql`eql_v2.order_by(${column})`)
    }

    return asc(column)
  }

  /**
   * Descending order helper - uses eql_v2.order_by() for encrypted columns with ORE index
   */
  const encryptedDesc = (column: SQLWrapper): SQL => {
    const columnInfo = getColumnInfo(column, defaultTable, tableCache)

    if (columnInfo.config?.orderAndRange) {
      return desc(sql`eql_v2.order_by(${column})`)
    }

    return desc(column)
  }

  /**
   * Batched AND operator - collects lazy operators, batches encryption, and combines conditions
   */
  const encryptedAnd = async (
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
      encryptionClient,
      valuesToEncrypt.map((v) => ({
        value: v.value,
        column: v.column,
        queryType: v.queryType,
      })),
      defaultTable,
      tableCache,
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
  const encryptedOr = async (
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
      encryptionClient,
      valuesToEncrypt.map((v) => ({
        value: v.value,
        column: v.column,
        queryType: v.queryType,
      })),
      defaultTable,
      tableCache,
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
    eq: encryptedEq,
    ne: encryptedNe,
    gt: encryptedGt,
    gte: encryptedGte,
    lt: encryptedLt,
    lte: encryptedLte,

    // Range operators
    between: encryptedBetween,
    notBetween: encryptedNotBetween,

    // Text search operators
    like: encryptedLike,
    ilike: encryptedIlike,
    notIlike: encryptedNotIlike,

    // Searchable JSON operators
    jsonbPathQueryFirst: encryptedJsonbPathQueryFirst,
    jsonbGet: encryptedJsonbGet,
    jsonbPathExists: encryptedJsonbPathExists,

    // Array operators
    inArray: encryptedInArray,
    notInArray: encryptedNotInArray,

    // Sorting operators
    asc: encryptedAsc,
    desc: encryptedDesc,

    // AND operator - batches encryption operations
    and: encryptedAnd,

    // OR operator - batches encryption operations
    or: encryptedOr,

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
