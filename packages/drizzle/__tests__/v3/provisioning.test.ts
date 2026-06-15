import 'dotenv/config'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { installEqlV3 } from './helpers/install-v3'

// DB-gated suite: without DATABASE_URL the whole describe is skipped (not failed),
// so a bare `pnpm test` reports skips rather than a hard import-time throw.
const HAS_DB = !!process.env.DATABASE_URL

let sql: ReturnType<typeof postgres>

beforeAll(async () => {
  if (!HAS_DB) return
  // { prepare: false } is required for the pooled CI DB (PgBouncer transaction
  // mode) — mirrors packages/protect/__tests__/searchable-json-pg.test.ts:12.
  sql = postgres(process.env.DATABASE_URL as string, { prepare: false })
  await installEqlV3(sql)
}, 120000)

afterAll(async () => {
  await sql?.end()
})

describe.skipIf(!HAS_DB)('v3 DB provisioning', () => {
  it('installs the eql_v3 schema and its text_eq domain', async () => {
    const rows = await sql`
      SELECT 1 FROM pg_type t
      JOIN pg_namespace n ON n.oid = t.typnamespace
      WHERE n.nspname = 'eql_v3' AND t.typname = 'text_eq'
    `
    expect(rows.length).toBe(1)
  })

  it('the v3 extractor functions were installed (eq_term, ord_term, match_term)', async () => {
    const fns = await sql`
      SELECT proname FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'eql_v3' AND p.proname IN ('eq_term','ord_term','match_term')
    `
    // >= 3, not == 3: each extractor is overloaded per scalar (text/int2/int4/int8/
    // date/timestamptz/…), so there are many rows. At least one per name proves the
    // DDL executed rather than silently no-op'ing.
    expect(fns.length).toBeGreaterThanOrEqual(3)
  })
})
