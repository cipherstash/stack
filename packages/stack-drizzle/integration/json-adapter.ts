import { EncryptionV3 } from '@cipherstash/stack/v3'
import {
  databaseUrl,
  type JsonIntegrationAdapter,
  type JsonQueryOp,
  type JsonTableSpec,
  unwrapResult,
} from '@cipherstash/test-kit'
import { asc, type SQL } from 'drizzle-orm'
import { type PgTable, pgTable, text } from 'drizzle-orm/pg-core'
import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import {
  createEncryptionOperatorsV3,
  extractEncryptionSchemaV3,
  types,
} from '../src/v3/index.js'

// biome-ignore lint/suspicious/noExplicitAny: the table name is supplied by the shared suite at runtime
type AnyTable = any

/** Drizzle implementation of the shared live encrypted-JSON contract. */
export function makeDrizzleJsonAdapter(): JsonIntegrationAdapter {
  let sqlClient: postgres.Sql
  let db: ReturnType<typeof drizzle>
  let tableName: string
  let table: AnyTable
  let client: Awaited<ReturnType<typeof EncryptionV3>>
  let ops: ReturnType<typeof createEncryptionOperatorsV3>

  const rowsFor = async (
    where: SQL | undefined,
    orderBy: readonly SQL[] = [asc(table.rowKey)],
  ): Promise<string[]> => {
    const rows = (await db
      .select({ rowKey: table.rowKey })
      .from(table as PgTable)
      .where(where)
      .orderBy(...orderBy)) as Array<{ rowKey: string }>
    return rows.map((row) => row.rowKey)
  }

  const selectorCondition = async (
    op: Extract<JsonQueryOp, { kind: 'selector' }>,
  ): Promise<SQL> => {
    const selector = ops.selector(table.document, op.path)
    switch (op.comparison) {
      case 'eq':
        return selector.eq(op.value)
      case 'ne':
        return selector.ne(op.value)
      case 'gt':
        return selector.gt(op.value)
      case 'gte':
        return selector.gte(op.value)
      case 'lt':
        return selector.lt(op.value)
      case 'lte':
        return selector.lte(op.value)
    }
  }

  return {
    name: 'drizzle',

    async setup(spec: JsonTableSpec) {
      tableName = spec.name
      sqlClient = postgres(databaseUrl(), { prepare: false })
      db = drizzle({ client: sqlClient })
      table = pgTable(spec.name, {
        rowKey: text('row_key').primaryKey(),
        document: types.Json('document'),
      })
      const schema = extractEncryptionSchemaV3(table)
      client = await EncryptionV3({ schemas: [schema] })
      ops = createEncryptionOperatorsV3(client)

      await sqlClient.unsafe(`DROP TABLE IF EXISTS ${tableName}`)
      await sqlClient.unsafe(`
        CREATE TABLE ${tableName} (
          row_key TEXT PRIMARY KEY,
          document public.eql_v3_json_search NOT NULL
        )
      `)

      const encrypted = unwrapResult(
        await client.bulkEncryptModels(
          spec.rows.map((row) => ({
            rowKey: row.rowKey,
            document: row.document,
          })),
          schema,
        ),
      )
      await db.insert(table as PgTable).values(encrypted as never)
    },

    async teardown() {
      if (tableName) await sqlClient.unsafe(`DROP TABLE IF EXISTS ${tableName}`)
      await sqlClient.end()
    },

    async run(op: JsonQueryOp): Promise<string[]> {
      if (op.kind === 'contains') {
        return rowsFor(await ops.contains(table.document, op.value))
      }
      if (op.kind === 'selector') {
        return rowsFor(await selectorCondition(op))
      }

      const selector = ops.selector(table.document, op.path)
      const term =
        op.direction === 'asc' ? await selector.asc() : await selector.desc()
      return rowsFor(undefined, [term as SQL, asc(table.rowKey)])
    },
  }
}
