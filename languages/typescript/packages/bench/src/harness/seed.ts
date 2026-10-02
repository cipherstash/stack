import {
  type BenchHandle,
  type BenchPlaintextRow,
  benchTable,
  encryptionBenchTable,
} from '../drizzle/setup.js'
import { countBenchRows } from './db.js'

export const DEFAULT_TARGET_ROWS = 10_000
const INSERT_BATCH = 250

export type SeedResult = {
  rowsBefore: number
  rowsAfter: number
  inserted: number
  skipped: boolean
}

export function getTargetRows(): number {
  const raw = process.env.BENCH_ROWS
  if (!raw) return DEFAULT_TARGET_ROWS
  const n = Number.parseInt(raw, 10)
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_TARGET_ROWS
  return n
}

/** Exported so `__unit__/seed-keys.test.ts` can check the row keys. */
export function makePlaintextRow(idx: number): BenchPlaintextRow {
  return {
    encText: `value-${String(idx).padStart(7, '0')}`,
    encInt: idx,
    encJsonb: { idx, group: idx % 100 },
  }
}

/**
 * Idempotent seed. If `bench` already has >= target rows, returns without
 * doing any work. Otherwise generates the deficit, encrypts in bulk via
 * `protectClient.bulkEncryptModels`, and inserts in chunks.
 */
export async function seed(
  h: BenchHandle,
  targetRows: number = getTargetRows(),
): Promise<SeedResult> {
  const rowsBefore = await countBenchRows(h.pgClient)

  if (rowsBefore >= targetRows) {
    return { rowsBefore, rowsAfter: rowsBefore, inserted: 0, skipped: true }
  }

  const toInsert = targetRows - rowsBefore
  const plaintexts: BenchPlaintextRow[] = []
  for (let i = 0; i < toInsert; i++) {
    plaintexts.push(makePlaintextRow(rowsBefore + i))
  }

  const encResult = await h.encryptionClient.bulkEncryptModels(
    plaintexts,
    encryptionBenchTable,
  )
  if (encResult.failure) {
    throw new Error(
      `[bench:seed] bulkEncryptModels failed: ${encResult.failure.message}`,
    )
  }

  // bulkEncryptModels returns rows under the SAME keys it matched on — the
  // Drizzle table's JS property names — with EQL v3 envelopes as values. Those
  // are the keys `db.insert()` wants, so there is nothing to remap. (The
  // remap that used to sit here rewrote enc_text -> encText, which only
  // appeared to work: nothing was ever encrypted, so it was moving plaintext.)
  const encRows = encResult.data

  for (let i = 0; i < encRows.length; i += INSERT_BATCH) {
    const batch = encRows.slice(i, i + INSERT_BATCH)
    await h.db.insert(benchTable).values(batch)
  }

  await h.pgClient.query('ANALYZE bench')

  const rowsAfter = await countBenchRows(h.pgClient)
  return { rowsBefore, rowsAfter, inserted: toInsert, skipped: false }
}
