/**
 * DB-only smoke tests — exercise the schema/mode/EXPLAIN path against the
 * existing local-postgres container without requiring CipherStash credentials.
 * The seed/encryption path is covered separately by `harness.test.ts`, which
 * does require credentials.
 */

import type pg from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { applySchema, connect, countBenchRows } from '../src/harness/db.js'
import { explain, hasNodeType, summarize } from '../src/harness/explain.js'

let client: pg.Client

beforeAll(async () => {
  client = await connect()
  await applySchema(client)
})

afterAll(async () => {
  if (client) await client.end()
})

describe('db-only harness', () => {
  it('schema applied (bench table exists, count is 0)', async () => {
    const rows = await countBenchRows(client)
    expect(rows).toBe(0)
  })

  it('EXPLAIN parses a trivial plan', async () => {
    const plan = await explain(client, 'SELECT id FROM bench LIMIT 1', [], {
      analyze: false,
    })
    expect(plan['Node Type']).toBeTruthy()
    expect(typeof summarize(plan)).toBe('string')
  })

  it('functional indexes exist after schema apply', async () => {
    const res = await client.query<{ indexname: string }>(
      `SELECT indexname FROM pg_indexes WHERE tablename = 'bench' ORDER BY indexname`,
    )
    const names = res.rows.map((r) => r.indexname)
    expect(names).toContain('bench_text_hmac_idx')
    expect(names).toContain('bench_text_bloom_idx')
    expect(names).toContain('bench_jsonb_stevec_idx')
  })

  it('plan walker traverses nested Plans nodes', async () => {
    const plan = await explain(
      client,
      'SELECT b1.id FROM bench b1 JOIN bench b2 ON b1.id = b2.id LIMIT 1',
      [],
      { analyze: false },
    )
    expect(hasNodeType(plan, 'Limit')).toBe(true)
  })
})
