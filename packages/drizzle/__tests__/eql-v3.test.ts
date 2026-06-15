import 'dotenv/config'
import { protect } from '@cipherstash/protect'
import { sql as dsql } from 'drizzle-orm'
import { pgTable } from 'drizzle-orm/pg-core'
import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  createProtectOperators,
  eqlV3Type,
  extractProtectSchema,
} from '../src/pg/v3/index'
import {
  oracleAscLabels,
  oracleContains,
  oracleEq,
  oracleLt,
  oracleNe,
  v3SeedData,
} from './fixtures/eql-v3-seed-data'
import { installEqlV3 } from './v3/helpers/install-v3'

// DB-gated suite: skipped (not failed) without DATABASE_URL — see provisioning.test.ts.
const HAS_DB = !!process.env.DATABASE_URL

const SKIP_ORDER_BY = true // shared CI DB, mirrors drizzle.test.ts:61
const TABLE = `v3_matrix_${Date.now()}`

const table = pgTable(TABLE, {
  t_storage: eqlV3Type<string>('t_storage', { dataType: 'text' }),
  t_eq: eqlV3Type<string>('t_eq', { dataType: 'text', index: 'equality' }),
  t_match: eqlV3Type<string>('t_match', {
    dataType: 'text',
    index: 'freeTextSearch',
  }),
  t_ord: eqlV3Type<string>('t_ord', {
    dataType: 'text',
    index: 'orderAndRange',
  }),
})
const schema = extractProtectSchema(table)

let sql: ReturnType<typeof postgres>
let db: ReturnType<typeof drizzle>
let pc: Awaited<ReturnType<typeof protect>>
let ops: ReturnType<typeof createProtectOperators>

// biome-ignore lint/suspicious/noExplicitAny: test unwrap
function unwrap(r: any) {
  if (r.failure) {
    throw new Error(
      `[protect] ${r.failure.message ?? JSON.stringify(r.failure)}`,
    )
  }
  return r.data
}

beforeAll(async () => {
  if (!HAS_DB) return
  // { prepare: false } is required for the pooled CI DB (PgBouncer transaction
  // mode) — mirrors packages/protect/__tests__/searchable-json-pg.test.ts:12.
  sql = postgres(process.env.DATABASE_URL as string, { prepare: false })
  await installEqlV3(sql)
  await sql.unsafe(`CREATE TABLE IF NOT EXISTS "${TABLE}" (
    t_storage eql_v3.text,
    t_eq eql_v3.text_eq,
    t_match eql_v3.text_match,
    t_ord eql_v3.text_ord
  )`)
  await sql.unsafe(
    `CREATE INDEX IF NOT EXISTS "${TABLE}_eq_idx" ON "${TABLE}" (eql_v3.eq_term(t_eq))`,
  )
  await sql.unsafe(
    `CREATE INDEX IF NOT EXISTS "${TABLE}_match_idx" ON "${TABLE}" USING gin (eql_v3.match_term(t_match))`,
  )
  await sql.unsafe(
    `CREATE INDEX IF NOT EXISTS "${TABLE}_ord_idx" ON "${TABLE}" (eql_v3.ord_term(t_ord))`,
  )

  db = drizzle({ client: sql })
  pc = await protect({ schemas: [schema] })
  ops = createProtectOperators(pc)

  const models = v3SeedData.map((r) => ({
    t_storage: r.label,
    t_eq: r.label,
    t_match: r.label,
    t_ord: r.label,
  }))
  const enc = unwrap(await pc.bulkEncryptModels(models, schema))
  await db.insert(table).values(enc as never[])
}, 180000)

afterAll(async () => {
  await sql?.unsafe(`DROP TABLE IF EXISTS "${TABLE}"`)
  await sql?.end()
})

async function decryptLabels(
  rows: unknown[],
  col: 't_storage' | 't_eq' | 't_match' | 't_ord',
) {
  const dec = unwrap(await pc.bulkDecryptModels(rows as never[]))
  // biome-ignore lint/suspicious/noExplicitAny: dynamic col access
  return dec.map((d: any) => d[col]).sort()
}

describe.skipIf(!HAS_DB)('EQL v3 text domain matrix', () => {
  it('t_storage: insert + decrypt round-trip', async () => {
    const rows = await db.select().from(table)
    expect(rows.length).toBe(v3SeedData.length)
    const labels = await decryptLabels(rows, 't_storage')
    expect(labels).toEqual(v3SeedData.map((r) => r.label).sort())
  })

  it('t_storage: NULL round-trips through the adapter codec (not just raw IS NULL)', async () => {
    await sql.unsafe(`INSERT INTO "${TABLE}" (t_storage) VALUES (NULL)`)
    // Read the NULL row back THROUGH the Drizzle typed column so v3FromDriver's
    // null branch is exercised, then decrypt through the codec — proving the
    // adapter maps a DB NULL to a JS null end-to-end, not just that a NULL exists.
    const nullRows = await db
      .select()
      .from(table)
      .where(dsql`${table.t_storage} IS NULL`)
    expect(nullRows.length).toBeGreaterThanOrEqual(1)
    // biome-ignore lint/suspicious/noExplicitAny: reading the typed column value
    expect((nullRows[0] as any).t_storage).toBeNull()
    const dec = unwrap(await pc.bulkDecryptModels(nullRows as never[]))
    expect(dec[0].t_storage).toBeNull()
  })

  it('t_eq: = returns exactly the matching row(s)', async () => {
    const rows = await db
      .select()
      .from(table)
      .where(await ops.eq(table.t_eq, 'banana'))
    expect(await decryptLabels(rows, 't_eq')).toEqual(
      oracleEq('banana').map((r) => r.label),
    )
  })

  it('t_eq: <> returns the exact complement', async () => {
    const rows = await db
      .select()
      .from(table)
      .where(await ops.ne(table.t_eq, 'banana'))
    expect(await decryptLabels(rows, 't_eq')).toEqual(
      oracleNe('banana')
        .map((r) => r.label)
        .sort(),
    )
  })

  it('t_eq: HMAC determinism — duplicate plaintext, = returns both', async () => {
    const enc = unwrap(await pc.bulkEncryptModels([{ t_eq: 'banana' }], schema))
    await db.insert(table).values(enc[0] as never)
    const rows = await db
      .select()
      .from(table)
      .where(await ops.eq(table.t_eq, 'banana'))
    expect(rows.length).toBe(2)
  })

  it('t_match: containment returns matches and excludes non-matching', async () => {
    const rows = await db
      .select()
      .from(table)
      .where(await ops.ilike(table.t_match, 'aard'))
    const got = await decryptLabels(rows, 't_match')
    expect(got).toEqual(
      oracleContains('aard')
        .map((r) => r.label)
        .sort(),
    )
    expect(got).not.toContain('banana')
  })

  it('t_ord: < returns the lexicographic prefix set', async () => {
    const rows = await db
      .select()
      .from(table)
      .where(await ops.lt(table.t_ord, 'cherry'))
    expect(await decryptLabels(rows, 't_ord')).toEqual(
      oracleLt('cherry')
        .map((r) => r.label)
        .sort(),
    )
  })

  const ordByIt = SKIP_ORDER_BY ? it.skip : it
  ordByIt('t_ord: ORDER BY returns the exact decrypted sequence', async () => {
    const rows = await db.select().from(table).orderBy(ops.asc(table.t_ord))
    const dec = unwrap(await pc.bulkDecryptModels(rows as never[]))
    // biome-ignore lint/suspicious/noExplicitAny: dynamic col
    expect(dec.map((d: any) => d.t_ord)).toEqual(oracleAscLabels())
  })

  // §7 min/max coverage. Skipped under the same shared-CI ORDER BY constraint
  // (MIN/MAX over an encrypted ord domain relies on the same ORE ordering the
  // CI DB declines). Present as a stub so the gap is visible, not omitted.
  ordByIt('t_ord: MIN()/MAX() return the lexicographic extremes', async () => {
    const rows = await sql.unsafe(
      `SELECT eql_v3.min(t_ord) AS lo, eql_v3.max(t_ord) AS hi FROM "${TABLE}"`,
    )
    expect(rows.length).toBe(1)
  })
})

describe.skipIf(!HAS_DB)('v3 negative assertions', () => {
  it('CHECK rejects a match payload (bf, no hm) inserted into text_eq', async () => {
    // A match payload carries {c,i,v,bf} but no hm; text_eq_check requires hm, so
    // coercing it into text_eq fails with the domain CHECK (SQLSTATE 23514).
    const matchEnc = unwrap(
      await pc.bulkEncryptModels([{ t_match: 'banana' }], schema),
    )
    const badPayload = JSON.stringify(
      (matchEnc[0] as Record<string, unknown>).t_match,
    )
    await expect(
      sql.unsafe(
        `INSERT INTO "${TABLE}" (t_eq) VALUES ('${badPayload}'::jsonb::eql_v3.text_eq)`,
      ),
    ).rejects.toThrow(/text_eq_check|23514/i)
  })

  it('blocker RAISEs for an unsupported ordering operator on text_eq', async () => {
    // text_eq is equality-only: eql_v3.lt(text_eq, …) is a blocker that RAISEs
    // 'operator < is not supported for eql_v3.text_eq' — NOT a bare Postgres 42883
    // "operator does not exist". The operator EXISTS and binds the blocker fn.
    await expect(
      sql.unsafe(`SELECT * FROM "${TABLE}" WHERE t_eq < t_eq`),
    ).rejects.toThrow(/not supported for .*eql_v3\.text_eq/i)
  })

  it('wrong-domain: an eq-shaped term used as text_ord is rejected, not silently coerced', async () => {
    // An eq value has {c,i,v,hm} but no ob. The text_ord `=` operator extracts the
    // ord term via eql_v3.ord_term → eql_v3.ore_block_u64_8_256(jsonb), which RAISEs
    // 'Expected an ore index (ob) value in json' for the missing ob. (text_ord_check
    // would also reject it; either is an intentional v3 guard, never silent coercion.)
    const eqEnc = unwrap(
      await pc.bulkEncryptModels([{ t_eq: 'banana' }], schema),
    )
    const eqTerm = JSON.stringify((eqEnc[0] as Record<string, unknown>).t_eq)
    await expect(
      sql.unsafe(
        `SELECT * FROM "${TABLE}" WHERE t_ord = '${eqTerm}'::jsonb::eql_v3.text_ord`,
      ),
    ).rejects.toThrow(/ore index \(ob\)|text_ord_check|23514/i)
  })

  it('mapping gaps are loud (pure function rejects out-of-scope tuples)', async () => {
    const { eqlV3Domain } = await import('../src/pg/v3/domain-map')
    // @ts-expect-error number has no v3 domain in this milestone
    expect(() => eqlV3Domain('number', 'equality')).toThrow(/unsupported/i)
  })
})

describe.skipIf(!HAS_DB)('v3 functional index definitions', () => {
  it('eq_term / match_term / ord_term functional indexes exist on the table', async () => {
    const rows = await sql`
      SELECT indexname, indexdef FROM pg_indexes
      WHERE tablename = ${TABLE}
    `
    const defs = rows.map((r) => r.indexdef as string).join('\n')
    expect(defs).toContain('eq_term')
    expect(defs).toContain('match_term')
    expect(defs).toContain('ord_term')
  })
})
