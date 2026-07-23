import { createEncryptionOperators } from '@cipherstash/stack-drizzle'
import type { SQL } from 'drizzle-orm'
import { afterAll, beforeAll, bench, describe } from 'vitest'
import {
  type BenchHandle,
  benchTable,
  buildBench,
  teardownBench,
} from '../../src/drizzle/setup.js'
import { applySchema } from '../../src/harness/db.js'
import { seed } from '../../src/harness/seed.js'

let handle: BenchHandle
let ops: ReturnType<typeof createEncryptionOperators>

beforeAll(async () => {
  handle = await buildBench()
  await applySchema(handle.pgClient)
  await seed(handle)
  ops = createEncryptionOperators(handle.encryptionClient)
})

afterAll(async () => {
  if (handle) await teardownBench(handle)
})

/**
 * Encryption cost is paid inside each iteration too — folding it into the
 * timed loop reflects what customer code actually does, and the index
 * engagement signal still dominates the differential between operators.
 */
describe('drizzle', () => {
  bench('eq (string match)', async () => {
    const where = (await ops.eq(benchTable.encText, 'value-0000042')) as SQL
    await handle.db.select().from(benchTable).where(where)
  })

  bench('inArray (3 string matches)', async () => {
    const where = await ops.inArray(benchTable.encText, [
      'value-0000042',
      'value-0000123',
      'value-0000999',
    ])
    await handle.db.select().from(benchTable).where(where)
  })

  bench('matches (free-text)', async () => {
    // A FULL seeded value, not the shared `value` prefix: every row is
    // `value-<7 digits>`, so a bare `value` needle matches all 10k rows and the
    // bloom index has nothing to narrow — the number would measure a full scan
    // rather than the index path this bench exists to measure.
    const where = (await ops.matches(
      benchTable.encText,
      'value-0000042',
    )) as SQL
    await handle.db.select().from(benchTable).where(where)
  })

  bench('gt (int)', async () => {
    const where = (await ops.gt(benchTable.encInt, 9990)) as SQL
    await handle.db.select().from(benchTable).where(where)
  })

  bench('between (int)', async () => {
    const where = (await ops.between(benchTable.encInt, 4000, 4100)) as SQL
    await handle.db.select().from(benchTable).where(where)
  })

  bench('orderBy desc + limit 10', async () => {
    await handle.db
      .select()
      .from(benchTable)
      .orderBy(ops.desc(benchTable.encInt))
      .limit(10)
  })
})
