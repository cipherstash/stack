/**
 * Live JSON containment for the v3 `types.Json()` column through the Drizzle
 * operators. Seeds encrypted JSONB documents and queries them with
 * `ops.contains(col, subObject)` — the same operator text search uses, dispatched
 * to `eql_v3.contains` over the ste_vec document — asserting it returns exactly
 * the rows whose document contains the sub-object (jsonb `@>` semantics), and
 * excludes the rest.
 */
import { databaseUrl, unwrapResult } from '@cipherstash/test-kit'
import { and, asc as drizzleAsc, eq as drizzleEq, type SQL } from 'drizzle-orm'
import { integer, pgTable, text } from 'drizzle-orm/pg-core'
import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { EncryptionV3, types } from '@/encryption/v3'
import {
  createEncryptionOperatorsV3,
  extractEncryptionSchemaV3,
} from '@/eql/v3/drizzle'
import { makeEqlV3Column } from '@/eql/v3/drizzle/column'

const sqlClient = postgres(databaseUrl(), { prepare: false })

const TABLE_NAME = 'protect_ci_v3_json_contains'
const RUN = `run-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

const docTable = pgTable(TABLE_NAME, {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  rowKey: text('row_key').notNull(),
  testRunId: text('test_run_id').notNull(),
  doc: makeEqlV3Column(types.Json('doc')),
} as never)

const schema = extractEncryptionSchemaV3(docTable)

// Distinct documents so each containment query has a definite expected set.
const DOCS: Record<string, Record<string, unknown>> = {
  ada: { user: 'ada@example.com', roles: ['admin', 'eng'], active: true },
  grace: { user: 'grace@example.com', roles: ['eng'] },
  zoe: { user: 'zoe@example.com', roles: ['ops'], active: false },
}

type SelectRow = { rowKey: string }
let client: Awaited<ReturnType<typeof EncryptionV3>>
let ops: ReturnType<typeof createEncryptionOperatorsV3>
let db: ReturnType<typeof drizzle>

async function matching(condition: SQL): Promise<string[]> {
  const rows = (await db
    .select({ rowKey: docTable.rowKey })
    .from(docTable)
    .where(and(drizzleEq(docTable.testRunId, RUN), condition))
    .orderBy(drizzleAsc(docTable.rowKey))) as SelectRow[]
  return rows.map((row) => row.rowKey)
}

beforeAll(async () => {
  // EQL v3 is installed once per run by `global-setup.ts`.
  client = await EncryptionV3({ schemas: [schema] })
  ops = createEncryptionOperatorsV3(client)
  db = drizzle({ client: sqlClient })

  await sqlClient.unsafe(`DROP TABLE IF EXISTS ${TABLE_NAME}`)
  await sqlClient.unsafe(`
    CREATE TABLE ${TABLE_NAME} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      row_key TEXT NOT NULL,
      test_run_id TEXT NOT NULL,
      doc public.eql_v3_json NOT NULL
    )
  `)

  const rows = Object.entries(DOCS).map(([rowKey, doc]) => ({
    rowKey,
    testRunId: RUN,
    doc,
  }))
  const encrypted = unwrapResult(
    await client.bulkEncryptModels(rows as never, schema),
  ) as Array<Record<string, unknown>>
  await db.insert(docTable).values(encrypted as never)
}, 120000)

afterAll(async () => {
  await sqlClient`DELETE FROM ${sqlClient(TABLE_NAME)} WHERE test_run_id = ${RUN}`
  await sqlClient.end()
}, 30000)

describe('v3 drizzle JSON containment (live pg)', () => {
  it('matches every document containing a sub-object (array element containment)', async () => {
    // `{ roles: ['eng'] }` ⊆ ada (admin,eng) and grace (eng), not zoe (ops).
    const condition = await ops.contains(docTable.doc, { roles: ['eng'] })
    expect(await matching(condition)).toEqual(['ada', 'grace'])
  }, 30000)

  it('matches on a scalar field', async () => {
    const condition = await ops.contains(docTable.doc, {
      user: 'zoe@example.com',
    })
    expect(await matching(condition)).toEqual(['zoe'])
  }, 30000)

  it('matches on a nested boolean', async () => {
    const condition = await ops.contains(docTable.doc, { active: true })
    expect(await matching(condition)).toEqual(['ada'])
  }, 30000)

  it('returns nothing for a sub-object no document contains', async () => {
    const condition = await ops.contains(docTable.doc, { roles: ['nope'] })
    expect(await matching(condition)).toEqual([])
  }, 30000)
})
