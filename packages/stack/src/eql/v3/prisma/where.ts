import type { EncryptionClient } from '@/encryption'
import type { AnyEncryptedV3Column, PlaintextForColumn } from '@/eql/v3'
import { EncryptionOperatorError, PrismaEncryptionError } from './errors'
import type { ColumnContext } from './model-map'
import { type BinaryFn, quoteIdent, v3PrismaDialect } from './sql-dialect'
import type {
  EncryptedCallOpts,
  PrismaNamespaceLike,
  SqlFragment,
} from './types'

/** Operand-encryption concurrency cap for list operators. */
const MAX_LIST_CONCURRENCY = 4

/**
 * Capability-checked `Prisma.sql` fragment builders for encrypted columns.
 * Compose the fragments into `$queryRaw` (or `$queryRawEncrypted`):
 *
 * ```ts
 * const rows = await $queryRawEncrypted(
 *   users,
 *   Prisma.sql`SELECT * FROM users WHERE ${await where.eq(users.email, 'a@b.com')} AND plan = ${plan}`,
 * )
 * ```
 */
export interface EncryptedWhere {
  eq<Col extends AnyEncryptedV3Column>(
    column: Col,
    value: PlaintextForColumn<Col>,
    opts?: EncryptedCallOpts,
  ): Promise<SqlFragment>
  ne<Col extends AnyEncryptedV3Column>(
    column: Col,
    value: PlaintextForColumn<Col>,
    opts?: EncryptedCallOpts,
  ): Promise<SqlFragment>
  gt<Col extends AnyEncryptedV3Column>(
    column: Col,
    value: PlaintextForColumn<Col>,
    opts?: EncryptedCallOpts,
  ): Promise<SqlFragment>
  gte<Col extends AnyEncryptedV3Column>(
    column: Col,
    value: PlaintextForColumn<Col>,
    opts?: EncryptedCallOpts,
  ): Promise<SqlFragment>
  lt<Col extends AnyEncryptedV3Column>(
    column: Col,
    value: PlaintextForColumn<Col>,
    opts?: EncryptedCallOpts,
  ): Promise<SqlFragment>
  lte<Col extends AnyEncryptedV3Column>(
    column: Col,
    value: PlaintextForColumn<Col>,
    opts?: EncryptedCallOpts,
  ): Promise<SqlFragment>
  between<Col extends AnyEncryptedV3Column>(
    column: Col,
    min: PlaintextForColumn<Col>,
    max: PlaintextForColumn<Col>,
    opts?: EncryptedCallOpts,
  ): Promise<SqlFragment>
  notBetween<Col extends AnyEncryptedV3Column>(
    column: Col,
    min: PlaintextForColumn<Col>,
    max: PlaintextForColumn<Col>,
    opts?: EncryptedCallOpts,
  ): Promise<SqlFragment>
  /**
   * Free-text (bloom-filter) containment — TOKEN matching, not SQL `LIKE`:
   * the value is tokenized/downcased the same way the stored value was;
   * wildcards are not interpreted.
   */
  contains<Col extends AnyEncryptedV3Column>(
    column: Col,
    value: PlaintextForColumn<Col>,
    opts?: EncryptedCallOpts,
  ): Promise<SqlFragment>
  in<Col extends AnyEncryptedV3Column>(
    column: Col,
    values: ReadonlyArray<PlaintextForColumn<Col>>,
    opts?: EncryptedCallOpts,
  ): Promise<SqlFragment>
  notIn<Col extends AnyEncryptedV3Column>(
    column: Col,
    values: ReadonlyArray<PlaintextForColumn<Col>>,
    opts?: EncryptedCallOpts,
  ): Promise<SqlFragment>
  /** `eql_v3.ord_term(col) ASC|DESC` — interpolate after `ORDER BY`. */
  orderBy(column: AnyEncryptedV3Column, direction?: 'asc' | 'desc'): SqlFragment
  isNull(column: AnyEncryptedV3Column): SqlFragment
  isNotNull(column: AnyEncryptedV3Column): SqlFragment
}

type Gate = 'equality' | 'orderAndRange' | 'freeTextSearch'

async function mapWithConcurrency<T, R>(
  values: ReadonlyArray<T>,
  limit: number,
  mapper: (value: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(values.length)
  let next = 0
  async function worker(): Promise<void> {
    while (next < values.length) {
      const index = next
      next += 1
      results[index] = await mapper(values[index])
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(limit, values.length) }, () => worker()),
  )
  return results
}

export function createEncryptedWhere(deps: {
  encryptionClient: EncryptionClient
  prisma: PrismaNamespaceLike
  byColumn: Map<object, ColumnContext>
}): EncryptedWhere {
  const { encryptionClient, prisma, byColumn } = deps
  const sql = prisma.sql

  function resolve(column: AnyEncryptedV3Column, operator: string) {
    const ctx = byColumn.get(column)
    if (!ctx) {
      throw new EncryptionOperatorError(
        `[prisma v3]: column "${column?.getName?.() ?? 'unknown'}" is not registered — pass its table in the \`tables\` map of encryptedPrisma()`,
        { columnName: column?.getName?.(), operator },
      )
    }
    return { ctx, ident: quoteIdent(ctx.dbName) }
  }

  /**
   * Gate an operator against the column's built index set — the same
   * authoritative source the encrypt config is built from. Client-side
   * gating is load-bearing: the bundle defines "unsupported" stub functions
   * for missing capabilities, so without this the failure would surface as
   * an opaque SQL error (or worse, an empty result).
   */
  function gate(ctx: ColumnContext, operator: string, need: Gate): void {
    const { indexes } = ctx
    const ok =
      need === 'equality'
        ? Boolean(indexes.unique || indexes.ore)
        : need === 'orderAndRange'
          ? Boolean(indexes.ore)
          : Boolean(indexes.match)
    if (!ok) {
      throw new EncryptionOperatorError(
        `[prisma v3]: operator "${operator}" requires ${need} on column "${ctx.dbName}" (${ctx.builder.getEqlType()} does not support it) — declare the column with a domain that carries that capability`,
        {
          columnName: ctx.dbName,
          tableName: ctx.tableName,
          operator,
        },
      )
    }
  }

  /**
   * Encrypt one filter operand as a FULL storage envelope, serialized to
   * jsonb text.
   *
   * INTERIM + the single swap point (CIP-3402 / CIP-3423): the two-arg
   * `eql_v3.*` functions coerce their jsonb operand into the column's domain,
   * whose CHECK requires the storage keys — so a term-only operand is
   * impossible until protect-ffi ships v3 scalar query terms AND the bundle
   * gives them a public SQL entry point. When that lands, swap the encryption
   * call here and move the dialect off the domain-coercing forms in the SAME
   * change. Every consumer treats the returned operand as an opaque,
   * already-encoded string.
   */
  async function encryptOperand(
    ctx: ColumnContext,
    value: unknown,
    operator: string,
    opts?: EncryptedCallOpts,
  ): Promise<string> {
    if (value == null) {
      throw new EncryptionOperatorError(
        `[prisma v3]: cannot encrypt a null operand for column "${ctx.dbName}" — use isNull('${ctx.dbName}') for NULL checks`,
        { columnName: ctx.dbName, tableName: ctx.tableName, operator },
      )
    }

    const baseOp = encryptionClient.encrypt(value as never, {
      column: ctx.builder as never,
      table: ctx.table as never,
    })
    const op = opts?.lockContext
      ? baseOp.withLockContext(opts.lockContext)
      : baseOp
    if (opts?.audit) op.audit(opts.audit)

    const result = await op
    if (result.failure) {
      throw new PrismaEncryptionError(
        `[prisma v3]: failed to encrypt operand for column "${ctx.dbName}": ${result.failure.message}`,
        result.failure,
      )
    }
    return JSON.stringify(result.data)
  }

  async function binary(
    fn: BinaryFn,
    need: Gate,
    column: AnyEncryptedV3Column,
    value: unknown,
    opts?: EncryptedCallOpts,
  ): Promise<SqlFragment> {
    const { ctx, ident } = resolve(column, fn)
    gate(ctx, fn, need)
    const operand = await encryptOperand(ctx, value, fn, opts)
    return v3PrismaDialect.binary(sql, fn, ident, operand)
  }

  async function range(
    negate: boolean,
    column: AnyEncryptedV3Column,
    min: unknown,
    max: unknown,
    opts?: EncryptedCallOpts,
  ): Promise<SqlFragment> {
    const operator = negate ? 'notBetween' : 'between'
    const { ctx, ident } = resolve(column, operator)
    gate(ctx, operator, 'orderAndRange')
    const [encMin, encMax] = await Promise.all([
      encryptOperand(ctx, min, operator, opts),
      encryptOperand(ctx, max, operator, opts),
    ])
    return v3PrismaDialect.between(sql, ident, encMin, encMax, negate)
  }

  async function list(
    negate: boolean,
    column: AnyEncryptedV3Column,
    values: ReadonlyArray<unknown>,
    opts?: EncryptedCallOpts,
  ): Promise<SqlFragment> {
    const operator = negate ? 'notIn' : 'in'
    const { ctx, ident } = resolve(column, operator)
    gate(ctx, operator, 'equality')
    if (values.length === 0) {
      throw new EncryptionOperatorError(
        `[prisma v3]: "${operator}" requires a non-empty list of values for column "${ctx.dbName}"`,
        { columnName: ctx.dbName, tableName: ctx.tableName, operator },
      )
    }
    const operands = await mapWithConcurrency(
      values,
      MAX_LIST_CONCURRENCY,
      (value) => encryptOperand(ctx, value, operator, opts),
    )
    return negate
      ? v3PrismaDialect.list(sql, 'neq', 'AND', ident, operands)
      : v3PrismaDialect.list(sql, 'eq', 'OR', ident, operands)
  }

  return {
    eq: (column, value, opts) => binary('eq', 'equality', column, value, opts),
    ne: (column, value, opts) => binary('neq', 'equality', column, value, opts),
    gt: (column, value, opts) =>
      binary('gt', 'orderAndRange', column, value, opts),
    gte: (column, value, opts) =>
      binary('gte', 'orderAndRange', column, value, opts),
    lt: (column, value, opts) =>
      binary('lt', 'orderAndRange', column, value, opts),
    lte: (column, value, opts) =>
      binary('lte', 'orderAndRange', column, value, opts),
    between: (column, min, max, opts) => range(false, column, min, max, opts),
    notBetween: (column, min, max, opts) => range(true, column, min, max, opts),
    contains: (column, value, opts) =>
      binary('contains', 'freeTextSearch', column, value, opts),
    in: (column, values, opts) => list(false, column, values, opts),
    notIn: (column, values, opts) => list(true, column, values, opts),
    orderBy: (column, direction = 'asc') => {
      const { ctx, ident } = resolve(column, 'orderBy')
      gate(ctx, 'orderBy', 'orderAndRange')
      return v3PrismaDialect.ordTerm(
        sql,
        ident,
        direction === 'desc' ? 'DESC' : 'ASC',
      )
    },
    isNull: (column) => {
      const { ident } = resolve(column, 'isNull')
      return v3PrismaDialect.nullCheck(sql, ident, false)
    },
    isNotNull: (column) => {
      const { ident } = resolve(column, 'isNotNull')
      return v3PrismaDialect.nullCheck(sql, ident, true)
    },
  }
}
