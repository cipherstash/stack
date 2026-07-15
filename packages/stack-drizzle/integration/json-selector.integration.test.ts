/**
 * Live JSONPath selector-with-constraint for the v3 `types.Json()` column (#623).
 * Distinct from containment (`ops.contains`, `@>`): this extracts the encrypted
 * leaf entry at a JSONPath and compares it, so it can express ORDERING at a path
 * (`col->'$.age' > 25`) that containment cannot. Emits
 * `eql_v3.<op>(eql_v3.jsonb_path_query_first(col, '<sel>'), eql_v3.jsonb_path_query_first('<needle>'::eql_v3_json, '<sel>'))`.
 *
 * INTERIM (cipherstash/protectjs-ffi#137): the RHS needle is a STORAGE encryption
 * of `{path: value}` — its ste_vec entry carries `c` + `op`/`hm`, which the
 * comparison extracts. Once protect-ffi can mint a ciphertext-free ordering query
 * needle for a ste_vec column, the RHS drops the ciphertext.
 */

import type { JsonDocument } from '@cipherstash/stack/eql/v3'
import { EncryptionV3 } from '@cipherstash/stack/v3'
import { databaseUrl, unwrapResult } from '@cipherstash/test-kit'
import { and, asc, eq, type SQL } from 'drizzle-orm'
import { integer, pgTable, text } from 'drizzle-orm/pg-core'
import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  createEncryptionOperatorsV3,
  extractEncryptionSchemaV3,
  types,
} from '../src/v3/index.js'

const sqlClient = postgres(databaseUrl(), { prepare: false })

const TABLE_NAME = 'protect_ci_v3_json_selector'
const RUN = `run-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

const docTable = pgTable(TABLE_NAME, {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  rowKey: text('row_key').notNull(),
  testRunId: text('test_run_id').notNull(),
  doc: types.Json('doc'),
})

const schema = extractEncryptionSchemaV3(docTable)

// Distinct ages so ordering-at-a-selector has a definite expected set.
const DOCS: Record<string, JsonDocument> = {
  ada: { user: 'ada@example.com', age: 30 },
  grace: { user: 'grace@example.com', age: 20 },
  zoe: { user: 'zoe@example.com', age: 40 },
}

type SelectRow = { rowKey: string }
let client: Awaited<ReturnType<typeof EncryptionV3>>
let ops: ReturnType<typeof createEncryptionOperatorsV3>
let db: ReturnType<typeof drizzle>

async function matching(condition: SQL): Promise<string[]> {
  const rows = (await db
    .select({ rowKey: docTable.rowKey })
    .from(docTable)
    .where(and(eq(docTable.testRunId, RUN), condition))
    .orderBy(asc(docTable.rowKey))) as SelectRow[]
  return rows.map((row) => row.rowKey)
}

beforeAll(async () => {
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
    await client.bulkEncryptModels(rows, schema),
  ) as Array<Record<string, unknown>>
  await db.insert(docTable).values(encrypted as never)
}, 120000)

afterAll(async () => {
  await sqlClient`DELETE FROM ${sqlClient(TABLE_NAME)} WHERE test_run_id = ${RUN}`
  await sqlClient.end()
}, 30000)

describe('v3 drizzle JSON selector-with-constraint (live pg)', () => {
  it('equality at a scalar selector', async () => {
    expect(
      await matching(await ops.selector(docTable.doc, '$.age').eq(30)),
    ).toEqual(['ada'])
  }, 30000)

  it('equality at a string selector', async () => {
    const condition = await ops
      .selector(docTable.doc, '$.user')
      .eq('zoe@example.com')
    expect(await matching(condition)).toEqual(['zoe'])
  }, 30000)

  it('ordering at a selector: greater-than (the form containment cannot express)', async () => {
    // ages: ada 30, grace 20, zoe 40 → > 25 selects ada, zoe.
    expect(
      await matching(await ops.selector(docTable.doc, '$.age').gt(25)),
    ).toEqual(['ada', 'zoe'])
  }, 30000)

  it('ordering at a selector: less-than', async () => {
    expect(
      await matching(await ops.selector(docTable.doc, '$.age').lt(35)),
    ).toEqual(['ada', 'grace'])
  }, 30000)

  it('ordering at a selector: gte inclusive boundary', async () => {
    expect(
      await matching(await ops.selector(docTable.doc, '$.age').gte(30)),
    ).toEqual(['ada', 'zoe'])
  }, 30000)

  it('returns nothing when no leaf satisfies the constraint', async () => {
    expect(
      await matching(await ops.selector(docTable.doc, '$.age').gt(100)),
    ).toEqual([])
  }, 30000)

  it('rejects array/wildcard selector paths (v1 supports object keys only)', async () => {
    await expect(
      ops.selector(docTable.doc, '$.items[0].name').eq('x'),
    ).rejects.toThrow(/not yet supported/)
  }, 30000)
})
