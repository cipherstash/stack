/**
 * Live NULL persistence for encrypted columns across every capability tier.
 *
 * `operators-live-pg.test.ts` proves `isNull`/`isNotNull` — but only for a
 * single `text_eq` column (`nullableTextEq`). NULL storage and retrieval for
 * the other tiers (storage-only, order/ORE, free-text match) is untested live:
 * a bug that mangled a NULL cell, or a domain that rejected NULL, would only
 * show up on those column kinds.
 *
 * This file seeds two rows — row A all-NULL, row B all-present — across one
 * representative column per tier, then asserts, per column: `isNull` selects
 * the NULL row, `isNotNull` selects the present row, the NULL cell reads back
 * as SQL NULL, and the present cell still decrypts to its plaintext.
 */

import { EncryptionV3 } from '@cipherstash/stack/v3'
import { databaseUrl, V3_MATRIX } from '@cipherstash/test-kit'
import { and, asc as drizzleAsc, eq as drizzleEq, type SQL } from 'drizzle-orm'
import { integer, pgTable, text } from 'drizzle-orm/pg-core'
import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { makeEqlV3Column } from '../src/column'
import {
  createEncryptionOperators,
  extractEncryptionSchema,
} from '../src/index.js'

const sqlClient = postgres(databaseUrl(), { prepare: false })

const TABLE_NAME = 'protect_ci_v3_drizzle_nullable'
const RUN = `run-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
const ROW_A = 'row-a' // all NULL
const ROW_B = 'row-b' // all present

// One representative column per capability tier, each NULLABLE.
const nullableTable = pgTable(TABLE_NAME, {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  rowKey: text('row_key').notNull(),
  testRunId: text('test_run_id').notNull(),
  storageText: makeEqlV3Column(
    V3_MATRIX['public.eql_v3_text'].builder('storage_text'),
  ),
  eqText: makeEqlV3Column(
    V3_MATRIX['public.eql_v3_text_eq'].builder('eq_text'),
  ),
  ordInt: makeEqlV3Column(
    V3_MATRIX['public.eql_v3_integer_ord'].builder('ord_int'),
  ),
  matchText: makeEqlV3Column(
    V3_MATRIX['public.eql_v3_text_match'].builder('match_text'),
  ),
} as never)

// Tier metadata: property (drizzle) + DB column + a present-row plaintext.
const TIERS = [
  {
    key: 'storageText',
    db: 'storage_text',
    domain: 'public.eql_v3_text',
    sample: 'stored-secret',
  },
  {
    key: 'eqText',
    db: 'eq_text',
    domain: 'public.eql_v3_text_eq',
    sample: 'ada@example.com',
  },
  {
    key: 'ordInt',
    db: 'ord_int',
    domain: 'public.eql_v3_integer_ord',
    sample: 42,
  },
  {
    key: 'matchText',
    db: 'match_text',
    domain: 'public.eql_v3_text_match',
    sample: 'ada lovelace',
  },
] as const

const schema = extractEncryptionSchema(nullableTable)

type SelectRow = { rowKey: string }

let client: Awaited<ReturnType<typeof EncryptionV3>>
let ops: ReturnType<typeof createEncryptionOperators>
let db: ReturnType<typeof drizzle>

function unwrap<T>(result: { data?: T; failure?: { message: string } }): T {
  if (result.failure) throw new Error(result.failure.message)
  return result.data as T
}

const columnFor = (key: string): SQL =>
  (nullableTable as unknown as Record<string, SQL>)[key]

async function selectRowKeys(condition: SQL): Promise<string[]> {
  const rows = (await db
    .select({ rowKey: nullableTable.rowKey })
    .from(nullableTable)
    .where(and(drizzleEq(nullableTable.testRunId, RUN), condition))
    .orderBy(drizzleAsc(nullableTable.rowKey))) as SelectRow[]
  return rows.map((row) => row.rowKey)
}

beforeAll(async () => {
  // EQL v3 is installed once per run by `global-setup.ts`.
  client = await EncryptionV3({ schemas: [schema] })
  ops = createEncryptionOperators(client)
  db = drizzle({ client: sqlClient })

  const columnDefs = TIERS.map((t) => `"${t.db}" ${t.domain}`).join(',\n      ')
  await sqlClient.unsafe(`
    CREATE TABLE IF NOT EXISTS ${TABLE_NAME} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      row_key TEXT NOT NULL,
      test_run_id TEXT NOT NULL,
      ${columnDefs}
    )
  `)

  // Row A: every encrypted column NULL. Row B: every column present.
  const rowA: Record<string, unknown> = { rowKey: ROW_A, testRunId: RUN }
  const rowB: Record<string, unknown> = { rowKey: ROW_B, testRunId: RUN }
  for (const t of TIERS) {
    rowA[t.key] = null
    rowB[t.key] = t.sample
  }

  const encryptedRows = unwrap<Array<Record<string, unknown>>>(
    await client.bulkEncryptModels([rowA, rowB] as never, schema),
  )
  await db.insert(nullableTable).values(encryptedRows as never)
}, 120000)

afterAll(async () => {
  await sqlClient`DELETE FROM ${sqlClient(TABLE_NAME)} WHERE test_run_id = ${RUN}`
  await sqlClient.end()
}, 30000)

describe('v3 drizzle NULL persistence across tiers (live pg)', () => {
  it.each(TIERS)('$domain isNull selects the NULL row', async (tier) => {
    expect(await selectRowKeys(ops.isNull(columnFor(tier.key)))).toEqual([
      ROW_A,
    ])
  }, 30000)

  it.each(TIERS)('$domain isNotNull selects the present row', async (tier) => {
    expect(await selectRowKeys(ops.isNotNull(columnFor(tier.key)))).toEqual([
      ROW_B,
    ])
  }, 30000)

  it.each(
    TIERS,
  )('$domain stores a real NULL for the null row', async (tier) => {
    const [row] = await sqlClient.unsafe<Array<{ value: unknown }>>(
      `SELECT "${tier.db}"::jsonb AS value FROM ${TABLE_NAME}
         WHERE test_run_id = $1 AND row_key = $2`,
      [RUN, ROW_A],
    )
    // Without this, a missing fixture makes `row.value` raise a TypeError and
    // the failure reads as a null-handling bug rather than an absent row.
    expect(row).toBeDefined()
    expect(row.value).toBeNull()
  }, 30000)

  it.each(
    TIERS,
  )('$domain present cell decrypts to its plaintext', async (tier) => {
    const [row] = await sqlClient.unsafe<Array<{ value: unknown }>>(
      `SELECT "${tier.db}"::jsonb AS value FROM ${TABLE_NAME}
         WHERE test_run_id = $1 AND row_key = $2`,
      [RUN, ROW_B],
    )
    expect(row.value).toHaveProperty('c')
    const decrypted = unwrap(await client.decrypt(row.value as never))
    expect(decrypted).toBe(tier.sample)
  }, 30000)
})
