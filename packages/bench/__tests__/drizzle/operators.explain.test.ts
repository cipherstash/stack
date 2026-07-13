import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createEncryptionOperators } from '@cipherstash/stack-drizzle'
import type { SQL } from 'drizzle-orm'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  type BenchHandle,
  benchTable,
  buildBench,
  teardownBench,
} from '../../src/drizzle/setup.js'
import { applySchema } from '../../src/harness/db.js'
import {
  explain,
  hasSeqScan,
  type PlanNode,
  summarize,
  topScan,
} from '../../src/harness/explain.js'
import { seed } from '../../src/harness/seed.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const resultsDir = resolve(__dirname, '..', '..', 'results')

let handle: BenchHandle
let ops: ReturnType<typeof createEncryptionOperators>
const investigationLog: Record<string, unknown> = { observations: {} }

beforeAll(async () => {
  handle = await buildBench()
  await applySchema(handle.pgClient)
  await seed(handle)
  ops = createEncryptionOperators(handle.encryptionClient)
})

afterAll(async () => {
  if (handle) await teardownBench(handle)

  // Persist #422 investigation outputs as a JSON artifact regardless of pass/fail.
  try {
    mkdirSync(resultsDir, { recursive: true })
    writeFileSync(
      resolve(resultsDir, 'explain-shape.json'),
      `${JSON.stringify(investigationLog, null, 2)}\n`,
    )
  } catch (err) {
    console.warn('[bench] failed to persist investigation log:', err)
  }
})

/**
 * Compile a Drizzle WHERE expression to SQL+params and run EXPLAIN against it.
 * Wraps in a SELECT that touches the bench table so the planner has to make
 * a decision on the encrypted column.
 */
async function explainWhere(where: SQL): Promise<PlanNode> {
  const query = handle.db.select().from(benchTable).where(where)
  const compiled = query.toSQL()
  return explain(handle.pgClient, compiled.sql, compiled.params as unknown[])
}

async function explainOrderBy(orderBy: SQL): Promise<PlanNode> {
  const query = handle.db.select().from(benchTable).orderBy(orderBy).limit(10)
  const compiled = query.toSQL()
  return explain(handle.pgClient, compiled.sql, compiled.params as unknown[])
}

function recordObservation(name: string, plan: PlanNode): void {
  const scan = topScan(plan)
  investigationLog.observations = {
    ...(investigationLog.observations as Record<string, unknown>),
    [name]: {
      summary: summarize(plan),
      nodeType: scan?.['Node Type'],
      indexName: scan?.['Index Name'] ?? null,
    },
  }
}

function recordError(name: string, err: unknown): void {
  investigationLog.observations = {
    ...(investigationLog.observations as Record<string, unknown>),
    [name]: {
      error: err instanceof Error ? err.message : String(err),
    },
  }
}

/**
 * Run a Drizzle WHERE-shaped expression through EXPLAIN, but if compiling or
 * planning the query fails (e.g. the operator returns a non-boolean type), log
 * the error to the investigation artifact instead of bubbling it. #422 tests
 * must never block CI — they're observational.
 */
async function tryExplainWhere(name: string, where: SQL): Promise<void> {
  try {
    const plan = await explainWhere(where)
    recordObservation(name, plan)
  } catch (err) {
    recordError(name, err)
  }
}

// --- #421: equality + array operators -------------------------------------
//
// `bench_text_hmac_idx` (functional hash on eql_v2.hmac_256) is the expected
// fast path. Pre-fix Drizzle emits bare `=` / `<>` / `IN (...)` which falls
// back to seq scan. Post-fix it emits `eql_v2.hmac_256(col) =
// eql_v2.hmac_256(value)` and the index scan kicks in.
//
// `eq` and `inArray` are naturally high-selectivity (only a few rows match),
// so the planner should pick the hmac index — assertion enforces it.
//
// `ne` and `notInArray` are naturally low-selectivity (almost all rows match);
// even with the hmac index available the planner correctly chooses a seq
// scan because it would re-touch nearly every row. We record their plans for
// the investigation log but don't assert — the SQL shape is what matters,
// and that's covered by the unit tests under packages/stack.
describe('#421: equality and array operators', () => {
  it('eq engages the hmac functional index', async () => {
    const plan = await explainWhere(
      (await ops.eq(benchTable.encText, 'value-0000042')) as SQL,
    )
    recordObservation('eq', plan)
    expect(hasSeqScan(plan), summarize(plan)).toBe(false)
  })

  it('inArray engages the hmac functional index', async () => {
    const plan = await explainWhere(
      await ops.inArray(benchTable.encText, [
        'value-0000042',
        'value-0000123',
        'value-0000999',
      ]),
    )
    recordObservation('inArray', plan)
    expect(hasSeqScan(plan), summarize(plan)).toBe(false)
  })

  it('records ne plan shape (low-selectivity, not asserted)', async () => {
    const plan = await explainWhere(
      (await ops.ne(benchTable.encText, 'value-0000042')) as SQL,
    )
    recordObservation('ne', plan)
  })

  it('records notInArray plan shape (low-selectivity, not asserted)', async () => {
    const plan = await explainWhere(
      await ops.notInArray(benchTable.encText, [
        'value-0000042',
        'value-0000123',
      ]),
    )
    recordObservation('notInArray', plan)
  })
})

// --- #422: investigation operators ----------------------------------------
//
// We don't yet know which call-shaped forms the planner inlines. Record plan
// shape; assertions land in a follow-up once #422 closes.
describe('#422: call-shaped operators (recorded, not asserted)', () => {
  it('records like / ilike plan shapes', async () => {
    await tryExplainWhere(
      'like',
      (await ops.like(benchTable.encText, '%value-00000%')) as SQL,
    )
    await tryExplainWhere(
      'ilike',
      (await ops.ilike(benchTable.encText, '%VALUE-00000%')) as SQL,
    )
  })

  it('records gt / gte / lt / lte plan shapes', async () => {
    for (const [name, build] of [
      ['gt', () => ops.gt(benchTable.encInt, 5000)],
      ['gte', () => ops.gte(benchTable.encInt, 5000)],
      ['lt', () => ops.lt(benchTable.encInt, 5000)],
      ['lte', () => ops.lte(benchTable.encInt, 5000)],
    ] as const) {
      await tryExplainWhere(name, (await build()) as SQL)
    }
  })

  it('records between plan shape', async () => {
    await tryExplainWhere(
      'between',
      (await ops.between(benchTable.encInt, 2500, 7500)) as SQL,
    )
  })

  it('records jsonb operator plan shapes', async () => {
    for (const [name, build] of [
      [
        'jsonbPathQueryFirst',
        () => ops.jsonbPathQueryFirst(benchTable.encJsonb, '$.idx'),
      ],
      ['jsonbGet', () => ops.jsonbGet(benchTable.encJsonb, '$.idx')],
      [
        'jsonbPathExists',
        () => ops.jsonbPathExists(benchTable.encJsonb, '$.idx'),
      ],
    ] as const) {
      await tryExplainWhere(name, await build())
    }
  })

  it('records ORDER BY plan shape (asc / desc)', async () => {
    for (const [name, build] of [
      ['asc', () => ops.asc(benchTable.encInt)],
      ['desc', () => ops.desc(benchTable.encInt)],
    ] as const) {
      try {
        const plan = await explainOrderBy(build())
        recordObservation(`orderBy_${name}`, plan)
      } catch (err) {
        recordError(`orderBy_${name}`, err)
      }
    }
  })
})
