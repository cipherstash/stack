import { stripDomainSchema } from '@cipherstash/stack/adapter-kit'
import {
  databaseUrl,
  type IntegrationAdapter,
  type PlainRow,
  type QueryOp,
  type QueryOpKind,
  type TableSpec,
} from '@cipherstash/test-kit'
import type { AnyExpression } from '@prisma-next/sql-relational-core/ast'
import { ColumnRef, OrderByItem } from '@prisma-next/sql-relational-core/ast'
import postgres from 'postgres'
import { EncryptedBigInt } from '../src/execution/envelope-bigint'
import { EncryptedBoolean } from '../src/execution/envelope-boolean'
import { EncryptedDate } from '../src/execution/envelope-date'
import { EncryptedJson } from '../src/execution/envelope-json'
import { EncryptedString } from '../src/execution/envelope-string'
import { toV3CodecId } from '../src/v3/catalog'
import { EncryptedNumber } from '../src/v3/envelope-number'
import { eqlAsc, eqlDesc } from '../src/v3/operators-v3'
import {
  createLiveTable,
  insertEncryptedRows,
  type LiveRowSpec,
  type LiveV3Client,
  liveV3Contract,
  runLoweredSelect,
  selectIdsOrderBy,
  selectIdsWhere,
  setupLiveV3,
} from '../test/live/helpers/harness'
import {
  callOperator,
  columnAccessorV3,
  getOperator,
} from '../test/v3/operator-lowering-v3.helpers'

/**
 * The prisma-next v3 adapter under real ZeroKMS ciphertext — the third
 * first-party adapter behind the shared test-kit family driver, pinned
 * against the same catalog, plaintext oracle, and single-vs-bulk insert
 * crossover as the Drizzle and Supabase suites (PR #655 review ask #4).
 *
 * prisma-next has no `encryptModel`/`bulkEncryptModels` pair: its ONE
 * encrypt path is the v3 bulk-encrypt middleware, which batches every
 * envelope param of a statement. `insertSingle` therefore runs a
 * one-row INSERT (one middleware crossing per row) and `insertBulk` a
 * single multi-row INSERT (one crossing for the whole batch) — the two
 * genuinely different batching shapes this integration exposes.
 *
 * Queries go through the REAL surface: operator lowering via the
 * registered `eql*` operations, the postgres adapter's `lower`, and the
 * middleware minting ciphertext-free `encryptQuery` terms — the same
 * seam the ORM's `where((u) => u.col.eqlEq(...))` callback drives.
 */

const SUPPORTED_OPS: ReadonlySet<QueryOpKind> = new Set([
  'eq',
  'ne',
  'in',
  'notIn',
  'gt',
  'gte',
  'lt',
  'lte',
  'between',
  'notBetween',
  'matches',
  'order',
  'isNull',
  'isNotNull',
])

/** prisma-next talks straight to Postgres; nothing is refused adapter-wide. */
const ALWAYS_REJECTED: ReadonlySet<QueryOpKind> = new Set()

/** test-kit op kind → registered v3 operation method name. */
const OP_METHOD = {
  eq: 'eqlEq',
  ne: 'eqlNeq',
  in: 'eqlIn',
  notIn: 'eqlNotIn',
  gt: 'eqlGt',
  gte: 'eqlGte',
  lt: 'eqlLt',
  lte: 'eqlLte',
  between: 'eqlBetween',
  notBetween: 'eqlNotBetween',
  matches: 'eqlMatch',
} as const

/**
 * Wrap a plaintext in the envelope class matching the domain's castAs —
 * the shape the bulk-encrypt middleware expects for INSERT params.
 */
function envelopeFor(castAs: string, value: unknown): unknown {
  if (value === null || value === undefined) return null
  switch (castAs) {
    case 'string':
      return EncryptedString.from(value as string)
    case 'number':
      return EncryptedNumber.from(value as number)
    case 'bigint':
      return EncryptedBigInt.from(value as bigint)
    case 'date':
    case 'timestamp':
      return EncryptedDate.from(value as Date)
    case 'boolean':
      return EncryptedBoolean.from(value as boolean)
    case 'json':
      return EncryptedJson.from(value)
    default:
      throw new Error(
        `prisma-next integration adapter: unknown castAs "${castAs}"`,
      )
  }
}

export function makePrismaNextAdapter(): IntegrationAdapter {
  let sql: postgres.Sql
  let live: LiveV3Client
  let contract: ReturnType<typeof liveV3Contract>
  let tableName: string
  /** column slug → v3 codec id, derived from the family's domains. */
  let codecIds: Record<string, string>
  /** column slug → the domain's castAs, for envelope construction. */
  let castAsBySlug: Record<string, string>

  const accessor = (slug: string) =>
    columnAccessorV3(tableName, slug, codecIds[slug] as string)

  /** Every op except `order`/`isNull`/`isNotNull` lowers through the v3 registry. */
  const predicateFor = (op: QueryOp): AnyExpression => {
    // `callOperator` (the shared lowering helper) already returns the
    // built AST node — no further `buildAst()` step.
    switch (op.kind) {
      case 'eq':
      case 'ne':
      case 'gt':
      case 'gte':
      case 'lt':
      case 'lte':
        return callOperator(
          getOperator(OP_METHOD[op.kind]),
          accessor(op.column),
          op.value,
        )
      case 'in':
      case 'notIn':
        return callOperator(
          getOperator(OP_METHOD[op.kind]),
          accessor(op.column),
          [...op.values],
        )
      case 'between':
      case 'notBetween':
        return callOperator(
          getOperator(OP_METHOD[op.kind]),
          accessor(op.column),
          op.lo,
          op.hi,
        )
      case 'matches':
        return callOperator(
          getOperator(OP_METHOD.matches),
          accessor(op.column),
          op.needle,
        )
      default:
        throw new Error(`predicateFor: ${op.kind} is not a lowered predicate`)
    }
  }

  const toLiveRow = (spec: TableSpec, row: PlainRow): LiveRowSpec => ({
    id: row.rowKey,
    cells: Object.fromEntries(
      spec.columns.map((c) => [
        c.slug,
        {
          codecId: codecIds[c.slug] as string,
          value: envelopeFor(
            castAsBySlug[c.slug] as string,
            row.values[c.slug] ?? null,
          ),
        },
      ]),
    ),
  })

  /** Structural NULL checks never carry encrypted operands — plain SQL. */
  const runNullCheck = async (column: string, negated: boolean) => {
    const rows = (await sql.unsafe(
      `SELECT id FROM "${tableName}" WHERE "${column}" IS ${negated ? 'NOT ' : ''}NULL ORDER BY id ASC`,
    )) as unknown as Array<{ id: string }>
    return rows.map((row) => row.id)
  }

  return {
    name: 'prisma-next',
    supportedOps: SUPPORTED_OPS,
    alwaysRejectedOps: ALWAYS_REJECTED,

    async setup() {
      sql = postgres(databaseUrl(), { prepare: false, onnotice: () => {} })
      // Contract + client are built in `createTable`: they are derived from
      // the family's column set, which does not exist yet.
    },

    async teardown() {
      if (tableName) await sql.unsafe(`DROP TABLE IF EXISTS "${tableName}"`)
      await sql.end()
    },

    async createTable(spec: TableSpec) {
      tableName = spec.name
      codecIds = Object.fromEntries(
        spec.columns.map((c) => [
          c.slug,
          toV3CodecId(stripDomainSchema(c.eqlType)),
        ]),
      )
      castAsBySlug = Object.fromEntries(
        spec.columns.map((c) => [c.slug, c.spec.castAs]),
      )
      await createLiveTable(sql, spec.name, codecIds)
      contract = liveV3Contract(spec.name, codecIds)
      live = await setupLiveV3(contract)
    },

    async insertSingle(spec: TableSpec, row: PlainRow) {
      await insertEncryptedRows(sql, live.middleware, tableName, [
        toLiveRow(spec, row),
      ])
    },

    async insertBulk(spec: TableSpec, rows: readonly PlainRow[]) {
      await insertEncryptedRows(
        sql,
        live.middleware,
        tableName,
        rows.map((row) => toLiveRow(spec, row)),
      )
    },

    async run(_spec: TableSpec, op: QueryOp): Promise<string[]> {
      if (op.kind === 'isNull') return runNullCheck(op.column, false)
      if (op.kind === 'isNotNull') return runNullCheck(op.column, true)

      if (op.kind === 'order') {
        const term =
          op.direction === 'asc'
            ? eqlAsc(accessor(op.column))
            : eqlDesc(accessor(op.column))
        // Break plaintext ties on `id`, mirroring the oracle's rowKey
        // tie-break (domains with fewer distinct samples than rows seed
        // duplicate plaintexts).
        const ast = selectIdsOrderBy(tableName, [
          term,
          OrderByItem.asc(ColumnRef.of(tableName, 'id')),
        ])
        const { ids } = await runLoweredSelect(
          sql,
          live.middleware,
          contract,
          ast,
        )
        // The driver's contract excludes the all-NULL row from `order`
        // results (NULL placement is a SQL-dialect property, not an
        // encrypted-term property). Dropping it client-side preserves
        // the database-produced order of the value rows.
        const nullIds = new Set(await runNullCheck(op.column, false))
        return ids.filter((id) => !nullIds.has(id))
      }

      const ast = selectIdsWhere(tableName, predicateFor(op))
      const { ids } = await runLoweredSelect(
        sql,
        live.middleware,
        contract,
        ast,
      )
      return ids
    },

    async expectRejected(_spec: TableSpec, op: QueryOp) {
      try {
        if (op.kind === 'order') {
          // `eqlAsc`/`eqlDesc` throw synchronously on a column with no
          // ordering capability.
          void (op.direction === 'asc'
            ? eqlAsc(accessor(op.column))
            : eqlDesc(accessor(op.column)))
        } else if (op.kind === 'isNull' || op.kind === 'isNotNull') {
          throw new Error(
            `expectRejected(${op.kind}) is structural and never rejected for prisma-next`,
          )
        } else {
          // Operator lowering gates on the domain's capabilities and
          // throws `EncryptionOperatorError` before any encryption.
          predicateFor(op)
        }
      } catch {
        return // an `EncryptionOperatorError` is the rejection
      }
      throw new Error(
        `Expected ${op.kind}("${op.column}") to be rejected, but it succeeded`,
      )
    },
  }
}
