import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { BenchHandle } from '../src/drizzle/setup.js'
import { buildBench, teardownBench } from '../src/drizzle/setup.js'
import { applySchema, countBenchRows } from '../src/harness/db.js'
import { explain, summarize } from '../src/harness/explain.js'
import { getTargetRows, seed } from '../src/harness/seed.js'

let handle: BenchHandle

beforeAll(async () => {
  handle = await buildBench()
  await applySchema(handle.pgClient)
  await seed(handle)
})

afterAll(async () => {
  if (handle) await teardownBench(handle)
})

describe('bench harness smoke', () => {
  it('applied schema and seeded the target row count', async () => {
    const rows = await countBenchRows(handle.pgClient)
    expect(rows).toBeGreaterThanOrEqual(getTargetRows())
  })

  it('EXPLAIN parses a trivial plan', async () => {
    const plan = await explain(
      handle.pgClient,
      'SELECT id FROM bench LIMIT 1',
      [],
      { analyze: false },
    )
    expect(plan['Node Type']).toBeTruthy()
    expect(typeof summarize(plan)).toBe('string')
  })
})
