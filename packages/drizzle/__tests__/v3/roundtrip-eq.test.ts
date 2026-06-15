import 'dotenv/config'
import { protect } from '@cipherstash/protect'
import { pgTable } from 'drizzle-orm/pg-core'
import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  createProtectOperators,
  eqlV3Type,
  extractProtectSchema,
} from '../../src/pg/v3/index'
import { installEqlV3 } from './helpers/install-v3'

// DB-gated suite: skipped (not failed) without DATABASE_URL — see provisioning.test.ts.
const HAS_DB = !!process.env.DATABASE_URL

const TABLE = `v3_eq_${Date.now()}`
const table = pgTable(TABLE, {
  t_eq: eqlV3Type<string>('t_eq', { dataType: 'text', index: 'equality' }),
})
const schema = extractProtectSchema(table)

let sql: ReturnType<typeof postgres>
let db: ReturnType<typeof drizzle>
let protectClient: Awaited<ReturnType<typeof protect>>
let ops: ReturnType<typeof createProtectOperators>

beforeAll(async () => {
  if (!HAS_DB) return
  // { prepare: false } is required for the pooled CI DB (PgBouncer transaction
  // mode) — mirrors packages/protect/__tests__/searchable-json-pg.test.ts:12.
  sql = postgres(process.env.DATABASE_URL as string, { prepare: false })
  await installEqlV3(sql)
  await sql.unsafe(
    `CREATE TABLE IF NOT EXISTS "${TABLE}" (t_eq eql_v3.text_eq)`,
  )
  db = drizzle({ client: sql })
  protectClient = await protect({ schemas: [schema] })
  ops = createProtectOperators(protectClient)
}, 120000)

afterAll(async () => {
  await sql?.unsafe(`DROP TABLE IF EXISTS "${TABLE}"`)
  await sql?.end()
})

describe.skipIf(!HAS_DB)('v3 text_eq round-trip', () => {
  it('encrypts, inserts, queries with =, and decrypts back to plaintext', async () => {
    const enc = unwrap(
      await protectClient.bulkEncryptModels([{ t_eq: 'alice' }], schema),
    )
    await db.insert(table).values(enc[0] as never)

    const rows = await db
      .select()
      .from(table)
      .where(await ops.eq(table.t_eq, 'alice'))
    expect(rows).toHaveLength(1)

    const dec = unwrap(await protectClient.bulkDecryptModels(rows as never[]))
    expect(dec[0].t_eq).toBe('alice')
  })
})

// biome-ignore lint/suspicious/noExplicitAny: test unwrap
function unwrap(r: any) {
  if (r.failure) {
    throw new Error(
      `[protect] ${r.failure.message ?? JSON.stringify(r.failure)}`,
    )
  }
  return r.data
}
