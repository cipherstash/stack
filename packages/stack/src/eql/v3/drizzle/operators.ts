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
import type { AuditConfig } from '@/encryption/operations/base-operation'
import type { AnyEncryptedV3Column, AnyV3Table } from '@/eql/v3'
import type { LockContext } from '@/identity'
import type { ColumnSchema } from '@/schema'
import { getEqlV3Column } from './column.js'
import {
  extractEncryptionSchemaV3,
  getDrizzleTableName,
} from './schema-extraction.js'
import { type ComparisonOp, type EqualityOp, v3Dialect } from './sql-dialect.js'

const MAX_IN_ARRAY_CONCURRENCY = 4

/**
 * The single client capability this factory consumes: `encrypt`. Declared
 * structurally — with maximally-permissive operands — so it is satisfied by the
 * nominal `EncryptionClient`, by the `TypedEncryptionClient` that `EncryptionV3`
 * returns (whatever its schema tuple), AND by a hand-rolled test double, none
 * needing a cast. Typing the parameter to the nominal `TypedEncryptionClient<S>`
 * would reject a client built for a narrower schema tuple (it accepts fewer
 * tables than `readonly AnyV3Table[]`); the structural surface sidesteps that
 * variance. The factory resolves the column/table at runtime and encrypts
 * through its own casts, so it relies on none of the client's per-column
 * `encrypt` overloads.
 */
type OperandEncryptionClient = {
  encrypt(
    plaintext: never,
    opts: { table: AnyV3Table; column: AnyEncryptedV3Column },
  ): unknown
}

/**
 * A dedicated error for v3 operator gating and operand-encryption failures,
 * carrying the offending column/table/operator for diagnostics.
 *
 * INTENTIONAL FORK: this mirrors the v2 adapter's `EncryptionOperatorError`
 * rather than sharing it. Unifying the two would couple `./drizzle` and
 * `./eql/v3/drizzle` — two independently-versioned public entry points — so the
 * duplication is deliberate, not an oversight.
 */
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

/**
 * Build v3-aware query operators (`eq`, `gte`, `contains`, `asc`, …) bound to an
 * encryption `client`. Each comparison/containment operator AUTO-ENCRYPTS its
 * plaintext operand into an EQL v3 query term before handing it to Drizzle, so
 * callers pass plaintext and the emitted SQL compares encrypted values. Every
 * operator also gates on the target column's capabilities and throws
 * {@link EncryptionOperatorError} when the column can't answer the operator
 * (e.g. ordering a non-`ore` column).
 *
 * @param client - anything that can `encrypt` — the nominal `EncryptionClient`
 *   or the `TypedEncryptionClient` from `EncryptionV3` (no cast needed).
 * @param defaults - lock context / audit applied to every operand encryption
 *   unless a per-call override is supplied.
 *
 * @example
 * ```typescript
 * const ops = createEncryptionOperatorsV3(await EncryptionV3({ schemas: [users] }))
 * await db.select().from(users).where(await ops.eq(users.email, 'a@b.com'))
 * ```
 */
export function createEncryptionOperatorsV3(
  client: OperandEncryptionClient,
  defaults: EncryptionOperatorCallOpts = {},
) {
  const tableCache = new WeakMap<PgTable, AnyV3Table>()
  // Per-column context memo. `resolveContext` is value-independent, so caching
  // by column identity makes `inArray`/`notInArray` build the context (and its
  // deep-cloned match block) once for the whole list instead of once per value.
  const contextCache = new WeakMap<SQLWrapper, ColumnContext>()

  function drizzleTableOf(column: SQLWrapper): PgTable | undefined {
    return is(column, Column)
      ? (column.table as PgTable | undefined)
      : undefined
  }

  function resolveContext(column: SQLWrapper, operator: string): ColumnContext {
    const cached = contextCache.get(column)
    if (cached) return cached

    const columnName = is(column, Column) ? column.name : 'unknown'
    const builder = getEqlV3Column(columnName, column)
    if (!builder) {
      throw new EncryptionOperatorError(
        `Operator "${operator}" requires an encrypted v3 column, but "${columnName}" is not one.`,
        { columnName, operator },
      )
    }

    const drizzleTable = drizzleTableOf(column)
    const tableName = getDrizzleTableName(drizzleTable) ?? 'unknown'

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

    const context: ColumnContext = {
      builder,
      table,
      indexes: builder.build().indexes,
      columnName,
      tableName,
    }
    contextCache.set(column, context)
    return context
  }

  function requireIndex(
    ctx: ColumnContext,
    index: 'unique' | 'ore' | 'match',
    operator: string,
    capability: string,
  ): void {
    if (!ctx.indexes[index]) {
      throw new EncryptionOperatorError(
        `Operator "${operator}" requires ${capability} on column "${ctx.columnName}" (domain ${ctx.builder.getEqlType()} does not support it).`,
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
        column: ctx.builder,
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
    // Independent operands — encrypt concurrently rather than paying two
    // sequential round-trips to the crypto backend.
    const [encMin, encMax] = await Promise.all([
      encryptOperand(ctx, min, operator, opts),
      encryptOperand(ctx, max, operator, opts),
    ])
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
    /** Equality: `column = value`. Encrypts `r` and emits `eql_v3.eq`.
     * Requires a `unique` or `ore` index on the column. */
    eq: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      equality('eq', l, r, opts),
    /** Inequality: `column <> value`. Encrypts `r` and emits `eql_v3.neq`.
     * Requires a `unique` or `ore` index on the column. */
    ne: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      equality('ne', l, r, opts),
    /** Greater-than: `column > value`. Encrypts `r` and emits `eql_v3.gt`.
     * Requires an `ore` (order/range) index. */
    gt: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      comparison('gt', l, r, opts),
    /** Greater-than-or-equal: `column >= value`. Encrypts `r` and emits
     * `eql_v3.gte`. Requires an `ore` (order/range) index. */
    gte: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      comparison('gte', l, r, opts),
    /** Less-than: `column < value`. Encrypts `r` and emits `eql_v3.lt`.
     * Requires an `ore` (order/range) index. */
    lt: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      comparison('lt', l, r, opts),
    /** Less-than-or-equal: `column <= value`. Encrypts `r` and emits
     * `eql_v3.lte`. Requires an `ore` (order/range) index. */
    lte: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      comparison('lte', l, r, opts),
    /** Inclusive range `min <= column <= max`. Encrypts both bounds
     * concurrently. Requires an `ore` (order/range) index. */
    between: (
      l: SQLWrapper,
      min: unknown,
      max: unknown,
      opts?: EncryptionOperatorCallOpts,
    ) => range(l, min, max, false, 'between', opts),
    /** Negated inclusive range `NOT (min <= column <= max)`. Encrypts both
     * bounds concurrently. Requires an `ore` (order/range) index. */
    notBetween: (
      l: SQLWrapper,
      min: unknown,
      max: unknown,
      opts?: EncryptionOperatorCallOpts,
    ) => range(l, min, max, true, 'notBetween', opts),
    /** Free-text containment: emits `eql_v3.contains` over the encrypted match
     * term. Encrypts `r`. Requires a `match` (free-text search) index. */
    contains: (l: SQLWrapper, r: unknown, opts?: EncryptionOperatorCallOpts) =>
      contains(l, r, 'contains', opts),
    /** Membership: ORs one encrypted `eq` term per value. Each value is
     * encrypted (concurrency-bounded). Rejects an empty list; requires a
     * `unique` or `ore` index. */
    inArray: (
      l: SQLWrapper,
      values: unknown[],
      opts?: EncryptionOperatorCallOpts,
    ) => inArrayOp(l, values, false, 'inArray', opts),
    /** Non-membership: ANDs one encrypted `ne` term per value. Each value is
     * encrypted (concurrency-bounded). Rejects an empty list; requires a
     * `unique` or `ore` index. */
    notInArray: (
      l: SQLWrapper,
      values: unknown[],
      opts?: EncryptionOperatorCallOpts,
    ) => inArrayOp(l, values, true, 'notInArray', opts),
    /** Ascending order by the encrypted order term (`eql_v3.ord_term`).
     * Synchronous (no operand to encrypt). Requires an `ore` index. */
    asc: (c: SQLWrapper) => asc(orderTerm(c, 'asc')),
    /** Descending order by the encrypted order term (`eql_v3.ord_term`).
     * Synchronous (no operand to encrypt). Requires an `ore` index. */
    desc: (c: SQLWrapper) => desc(orderTerm(c, 'desc')),
    /** Conjunction of the given conditions, awaiting any async operands and
     * dropping `undefined`. Empty input resolves to `true`. */
    and: (...conds: (SQL | SQLWrapper | Promise<SQL> | undefined)[]) =>
      combine(and, sql`true`, conds),
    /** Disjunction of the given conditions, awaiting any async operands and
     * dropping `undefined`. Empty input resolves to `false`. */
    or: (...conds: (SQL | SQLWrapper | Promise<SQL> | undefined)[]) =>
      combine(or, sql`false`, conds),
    /** Drizzle's `isNull`, re-exported unchanged — `column IS NULL` needs no
     * encryption and works on any (nullable) encrypted column. */
    isNull,
    /** Drizzle's `isNotNull`, re-exported unchanged — `column IS NOT NULL`
     * needs no encryption. */
    isNotNull,
    /** Drizzle's `not`, re-exported unchanged — negates an already-built
     * (encrypted) predicate. */
    not,
    /** Drizzle's `exists`, re-exported unchanged — for correlated subqueries. */
    exists,
    /** Drizzle's `notExists`, re-exported unchanged — for correlated
     * subqueries. */
    notExists,
  }
}
