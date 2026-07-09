import {
  and,
  asc,
  Column,
  desc,
  exists,
  is,
  isNotNull,
  isNull,
  not,
  notExists,
  or,
  type SQL,
  type SQLWrapper,
  sql,
} from 'drizzle-orm'
import type { PgTable } from 'drizzle-orm/pg-core'
import type { EncryptionClient } from '@/encryption'
import type { AuditConfig } from '@/encryption/operations/base-operation'
import type { AnyEncryptedV3Column, AnyV3Table } from '@/eql/v3'
import type { LockContext } from '@/identity'
import type { ColumnSchema } from '@/schema'
import { getEqlV3Column } from './column.js'
import { extractEncryptionSchemaV3 } from './schema-extraction.js'
import { type ComparisonOp, type EqualityOp, v3Dialect } from './sql-dialect.js'

const MAX_IN_ARRAY_CONCURRENCY = 4

export class EncryptionOperatorError extends Error {
  constructor(
    message: string,
    public readonly context?: {
      columnName?: string
      tableName?: string
      operator?: string
    },
  ) {
    super(message)
    this.name = 'EncryptionOperatorError'
  }
}

interface ColumnContext {
  builder: AnyEncryptedV3Column
  table: AnyV3Table
  indexes: ColumnSchema['indexes']
  columnName: string
  tableName: string
}

export type EncryptionOperatorCallOpts = {
  lockContext?: LockContext
  audit?: AuditConfig
}

type ChainableOperation = {
  withLockContext(lockContext: LockContext): ChainableOperation
  audit(config: AuditConfig): ChainableOperation
  then: PromiseLike<{
    data?: unknown
    failure?: { message: string }
  }>['then']
}

async function mapWithConcurrency<T, R>(
  values: T[],
  limit: number,
  mapper: (value: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(values.length)
  let next = 0

  async function worker(): Promise<void> {
    while (true) {
      const index = next
      next += 1
      if (index >= values.length) return
      results[index] = await mapper(values[index])
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(limit, values.length) }, () => worker()),
  )
  return results
}

export function createEncryptionOperatorsV3(
  client: EncryptionClient,
  defaults: EncryptionOperatorCallOpts = {},
) {
  const tableCache = new WeakMap<PgTable, AnyV3Table>()

  function drizzleTableOf(column: SQLWrapper): PgTable | undefined {
    return is(column, Column)
      ? (column.table as PgTable | undefined)
      : undefined
  }

  function resolveContext(column: SQLWrapper, operator: string): ColumnContext {
    const columnName = is(column, Column) ? column.name : 'unknown'
    const builder = getEqlV3Column(columnName, column)
    if (!builder) {
      throw new EncryptionOperatorError(
        `Operator "${operator}" requires an encrypted v3 column, but "${columnName}" is not one.`,
        { columnName, operator },
      )
    }

    const drizzleTable = drizzleTableOf(column)
    const drizzleTableSymbols = drizzleTable as
      | Record<symbol, string | undefined>
      | undefined
    const tableName =
      drizzleTableSymbols?.[Symbol.for('drizzle:Name')] ?? 'unknown'

    let table = drizzleTable ? tableCache.get(drizzleTable) : undefined
    if (!table && drizzleTable) {
      table = extractEncryptionSchemaV3(drizzleTable)
      tableCache.set(drizzleTable, table)
    }
    if (!table) {
      throw new EncryptionOperatorError(
        `Unable to resolve the encrypted table for column "${columnName}".`,
        { columnName, operator },
      )
    }

    return {
      builder,
      table,
      indexes: builder.build().indexes,
      columnName,
      tableName,
    }
  }

  function requireIndex(
    ctx: ColumnContext,
    index: 'unique' | 'ore' | 'match',
    operator: string,
    capability: string,
  ): void {
    if (!ctx.indexes[index]) {
      throw new EncryptionOperatorError(
        `Operator "${operator}" requires ${capability} on column "${ctx.columnName}" (eql_v3 domain ${ctx.builder.getEqlType()} does not support it).`,
        { columnName: ctx.columnName, tableName: ctx.tableName, operator },
      )
    }
  }

  function applyOperationOptions(
    op: ChainableOperation,
    opts?: EncryptionOperatorCallOpts,
  ): ChainableOperation {
    const lockContext = opts?.lockContext ?? defaults.lockContext
    const audit = opts?.audit ?? defaults.audit
    const withLock = lockContext ? op.withLockContext(lockContext) : op
    if (audit) withLock.audit(audit)
    return withLock
  }

  async function encryptOperand(
    ctx: ColumnContext,
    value: unknown,
    operator: string,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    if (value == null) {
      throw new EncryptionOperatorError(
        `Operator "${operator}" cannot encrypt a null operand for column "${ctx.columnName}". Use isNull() or isNotNull() for NULL checks.`,
        {
          columnName: ctx.columnName,
          tableName: ctx.tableName,
          operator,
        },
      )
    }

    const result = await applyOperationOptions(
      client.encrypt(value as never, {
        table: ctx.table,
        column: ctx.builder as never,
      }) as unknown as ChainableOperation,
      opts,
    )
    if (result.failure) {
      throw new EncryptionOperatorError(
        `Failed to encrypt query operand for "${ctx.columnName}": ${result.failure.message}`,
        { columnName: ctx.columnName, tableName: ctx.tableName, operator },
      )
    }
    return sql`${JSON.stringify(result.data)}`
  }

  const colSql = (column: SQLWrapper): SQL => sql`${column}`

  async function equality(
    op: EqualityOp,
    left: SQLWrapper,
    right: unknown,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    const ctx = resolveContext(left, op)
    if (!ctx.indexes.unique && !ctx.indexes.ore) {
      throw new EncryptionOperatorError(
        `Operator "${op}" requires equality on column "${ctx.columnName}".`,
        { columnName: ctx.columnName, tableName: ctx.tableName, operator: op },
      )
    }
    const enc = await encryptOperand(ctx, right, op, opts)
    return v3Dialect.equality(op, colSql(left), enc)
  }

  async function comparison(
    op: ComparisonOp,
    left: SQLWrapper,
    right: unknown,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    const ctx = resolveContext(left, op)
    requireIndex(ctx, 'ore', op, 'order/range')
    const enc = await encryptOperand(ctx, right, op, opts)
    return v3Dialect.comparison(op, colSql(left), enc)
  }

  async function range(
    left: SQLWrapper,
    min: unknown,
    max: unknown,
    negate: boolean,
    operator: string,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    const ctx = resolveContext(left, operator)
    requireIndex(ctx, 'ore', operator, 'order/range')
    const encMin = await encryptOperand(ctx, min, operator, opts)
    const encMax = await encryptOperand(ctx, max, operator, opts)
    const condition = v3Dialect.range(colSql(left), encMin, encMax)
    return negate ? sql`NOT (${condition})` : condition
  }

  async function contains(
    left: SQLWrapper,
    right: unknown,
    operator: string,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    const ctx = resolveContext(left, operator)
    requireIndex(ctx, 'match', operator, 'free-text search')
    const enc = await encryptOperand(ctx, right, operator, opts)
    return v3Dialect.contains(colSql(left), enc)
  }

  async function inArrayOp(
    left: SQLWrapper,
    values: unknown[],
    negate: boolean,
    operator: string,
    opts?: EncryptionOperatorCallOpts,
  ): Promise<SQL> {
    if (values.length === 0) {
      const ctx = resolveContext(left, operator)
      throw new EncryptionOperatorError(
        `Operator "${operator}" requires a non-empty list of values for column "${ctx.columnName}".`,
        { columnName: ctx.columnName, tableName: ctx.tableName, operator },
      )
    }
    const conditions = await mapWithConcurrency(
      values,
      MAX_IN_ARRAY_CONCURRENCY,
      (v) => equality(negate ? 'ne' : 'eq', left, v, opts),
    )
    const combined = negate ? and(...conditions) : or(...conditions)
    return combined ?? (negate ? sql`true` : sql`false`)
  }

  function orderTerm(column: SQLWrapper, operator: string): SQL {
    const ctx = resolveContext(column, operator)
    requireIndex(ctx, 'ore', operator, 'order/range')
    return v3Dialect.orderBy(colSql(column))
  }

  async function combine(
    joiner: typeof and,
    empty: SQL,
    conditions: (SQL | SQLWrapper | Promise<SQL> | undefined)[],
  ): Promise<SQL> {
    const present = conditions.filter(
      (c): c is SQL | SQLWrapper | Promise<SQL> => c !== undefined,
    )
    const resolved = await Promise.all(present)
    return joiner(...resolved) ?? empty
  }

  return {
    eq: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      equality('eq', l, r, opts),
    ne: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      equality('ne', l, r, opts),
    gt: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      comparison('gt', l, r, opts),
    gte: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      comparison('gte', l, r, opts),
    lt: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      comparison('lt', l, r, opts),
    lte: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      comparison('lte', l, r, opts),
    between: (
      l: SQLWrapper,
      min: unknown,
      max: unknown,
      opts?: EncryptionOperatorCallOpts,
    ) => range(l, min, max, false, 'between', opts),
    notBetween: (
      l: SQLWrapper,
      min: unknown,
      max: unknown,
      opts?: EncryptionOperatorCallOpts,
    ) => range(l, min, max, true, 'notBetween', opts),
    contains: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      contains(l, r, 'contains', opts),
    inArray: (
      l: SQLWrapper,
      values: unknown[],
      opts?: EncryptionOperatorCallOpts,
    ) => inArrayOp(l, values, false, 'inArray', opts),
    notInArray: (
      l: SQLWrapper,
      values: unknown[],
      opts?: EncryptionOperatorCallOpts,
    ) => inArrayOp(l, values, true, 'notInArray', opts),
    asc: (c: SQLWrapper) => asc(orderTerm(c, 'asc')),
    desc: (c: SQLWrapper) => desc(orderTerm(c, 'desc')),
    and: (...conds: (SQL | SQLWrapper | Promise<SQL> | undefined)[]) =>
      combine(and, sql`true`, conds),
    or: (...conds: (SQL | SQLWrapper | Promise<SQL> | undefined)[]) =>
      combine(or, sql`false`, conds),
    isNull,
    isNotNull,
    not,
    exists,
    notExists,
  }
}
