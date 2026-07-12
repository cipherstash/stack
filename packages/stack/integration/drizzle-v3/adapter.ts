import {
  databaseUrl,
  type IntegrationAdapter,
  type PlainRow,
  type QueryOp,
  type QueryOpKind,
  type TableSpec,
} from '@cipherstash/test-kit'
import { asc, type SQL } from 'drizzle-orm'
import { type PgTable, pgTable, text } from 'drizzle-orm/pg-core'
import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import { EncryptionV3 } from '@/encryption/v3'
import {
  createEncryptionOperatorsV3,
  extractEncryptionSchemaV3,
} from '@/eql/v3/drizzle'
import { makeEqlV3Column } from '@/eql/v3/drizzle/column'

/**
 * The Drizzle v3 adapter under real ZeroKMS ciphertext.
 *
 * The counterpart to the Supabase adapter, driven by the same catalog, the same
 * plaintext oracle and the same driver — so the two cannot quietly cover
 * different operations while both read as "comprehensive". Where they legitimately
 * differ, they differ in `supportedOps`, not in what a shared test asserts.
 *
 * Ordering is the interesting case. Drizzle emits the canonical EQL form,
 * `ORDER BY eql_v3.ord_term(col)`, straight from `sql-dialect.ts`. Supabase
 * cannot call a function through PostgREST and orders the same term through the
 * jsonb path `col->op`. Both must satisfy the identical oracle.
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
  'contains',
  'order',
  'isNull',
  'isNotNull',
])

/** Drizzle talks straight to Postgres; nothing is refused adapter-wide. */
const ALWAYS_REJECTED: ReadonlySet<QueryOpKind> = new Set()

// biome-ignore lint/suspicious/noExplicitAny: the table shape is built per family at runtime
type AnyTable = any

export function makeDrizzleAdapter(): IntegrationAdapter {
  let sqlClient: postgres.Sql
  let db: ReturnType<typeof drizzle>
  let client: Awaited<ReturnType<typeof EncryptionV3>>
  let ops: ReturnType<typeof createEncryptionOperatorsV3>
  let table: AnyTable
  let schema: ReturnType<typeof extractEncryptionSchemaV3>
  let tableName: string

  const column = (slug: string) => table[slug]

  /** Every op except `order` resolves to a WHERE condition. */
  const conditionFor = async (op: QueryOp): Promise<SQL | undefined> => {
    const col = column(op.column)
    switch (op.kind) {
      case 'eq':
        return ops.eq(col, op.value as never)
      case 'ne':
        return ops.ne(col, op.value as never)
      case 'gt':
        return ops.gt(col, op.value as never)
      case 'gte':
        return ops.gte(col, op.value as never)
      case 'lt':
        return ops.lt(col, op.value as never)
      case 'lte':
        return ops.lte(col, op.value as never)
      case 'in':
        // Drizzle has no raw-filter path; `asRawFilter` is a Supabase concern.
        return ops.inArray(col, [...op.values] as never)
      case 'notIn':
        return ops.notInArray(col, [...op.values] as never)
      case 'between':
        return ops.between(col, op.lo as never, op.hi as never)
      case 'notBetween':
        return ops.notBetween(col, op.lo as never, op.hi as never)
      case 'contains':
        return ops.contains(col, op.needle as never)
      case 'isNull':
        return ops.isNull(col)
      case 'isNotNull':
        return ops.isNotNull(col)
      case 'order':
        throw new Error('order is a transform, not a condition')
    }
  }

  const selectRowKeys = async (where: SQL | undefined, orderBy: SQL[]) => {
    const rows = (await db
      .select({ rowKey: table.rowKey })
      .from(table as PgTable)
      .where(where)
      .orderBy(...orderBy)) as Array<{ rowKey: string }>
    return rows.map((row) => row.rowKey)
  }

  return {
    name: 'drizzle',
    supportedOps: SUPPORTED_OPS,
    alwaysRejectedOps: ALWAYS_REJECTED,

    async setup() {
      sqlClient = postgres(databaseUrl(), { prepare: false })
      db = drizzle({ client: sqlClient })
      // `client` and `ops` are built in `createTable`: the encryption client is
      // constructed from the table's schema, which does not exist yet.
    },

    async teardown() {
      if (tableName) await sqlClient.unsafe(`DROP TABLE IF EXISTS ${tableName}`)
      await sqlClient.end()
    },

    async createTable(spec: TableSpec) {
      tableName = spec.name

      const columns = Object.fromEntries(
        spec.columns.map((c) => [
          c.slug,
          makeEqlV3Column(c.spec.builder(c.slug)),
        ]),
      )
      table = pgTable(spec.name, {
        rowKey: text('row_key').primaryKey(),
        ...columns,
      })
      schema = extractEncryptionSchemaV3(table)

      // The DDL comes from the column builders, not from a hand-written list, so
      // a domain rename cannot silently desync the table from the schema.
      const ddl = spec.columns
        .map((c) => `"${c.slug}" ${c.eqlType}`)
        .join(',\n          ')
      await sqlClient.unsafe(`DROP TABLE IF EXISTS ${spec.name}`)
      await sqlClient.unsafe(`
        CREATE TABLE ${spec.name} (
          row_key TEXT PRIMARY KEY,
          ${ddl}
        )
      `)

      // The client must know this table's schema to encrypt for it. Rebuilt per
      // family, since each family has its own columns.
      client = await EncryptionV3({ schemas: [schema as never] })
      ops = createEncryptionOperatorsV3(client)
    },

    async insertSingle(_spec: TableSpec, row: PlainRow) {
      const result = await client.encryptModel(
        { rowKey: row.rowKey, ...row.values } as never,
        schema as never,
      )
      if (result.failure) {
        throw new Error(
          `insertSingle(${row.rowKey}): ${result.failure.message}`,
        )
      }
      await db.insert(table as PgTable).values(result.data as never)
    },

    async insertBulk(_spec: TableSpec, rows: readonly PlainRow[]) {
      const models = rows.map((row) => ({ rowKey: row.rowKey, ...row.values }))
      const result = await client.bulkEncryptModels(
        models as never,
        schema as never,
      )
      if (result.failure)
        throw new Error(`insertBulk: ${result.failure.message}`)
      await db.insert(table as PgTable).values(result.data as never)
    },

    async run(_spec: TableSpec, op: QueryOp): Promise<string[]> {
      if (op.kind === 'order') {
        const col = column(op.column)
        const term = op.direction === 'asc' ? ops.asc(col) : ops.desc(col)
        // Exclude the all-NULL row, and break ties on `row_key` — the oracle
        // does both. Domains with fewer distinct samples than rows give two rows
        // the same plaintext, so the term alone does not determine their order.
        return selectRowKeys(await ops.isNotNull(col), [
          term as SQL,
          asc(table.rowKey),
        ])
      }

      return selectRowKeys(await conditionFor(op), [asc(table.rowKey)])
    },

    async expectRejected(_spec: TableSpec, op: QueryOp) {
      try {
        if (op.kind === 'order') {
          const col = column(op.column)
          // `asc`/`desc` throw synchronously on a column with no ordering term.
          void (op.direction === 'asc' ? ops.asc(col) : ops.desc(col))
        } else {
          await conditionFor(op)
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
