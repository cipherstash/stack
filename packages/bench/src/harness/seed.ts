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

function makePlaintextRow(idx: number): BenchPlaintextRow {
  return {
    enc_text: `value-${String(idx).padStart(7, '0')}`,
    enc_int: idx,
    enc_jsonb: { idx, group: idx % 100 },
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

  // bulkEncryptModels returns rows keyed by the encryptedTable column names
  // (snake_case here) with encrypted EQL v3 envelopes as values. Drizzle's
  // `benchTable` uses camelCase TS field names — remap before insert.
  const encRows = encResult.data.map((r) => ({
    encText: r.enc_text,
    encInt: r.enc_int,
    encJsonb: r.enc_jsonb,
  }))

  for (let i = 0; i < encRows.length; i += INSERT_BATCH) {
    const batch = encRows.slice(i, i + INSERT_BATCH)
    await h.db.insert(benchTable).values(batch)
  }

  await h.pgClient.query('ANALYZE bench')

  const rowsAfter = await countBenchRows(h.pgClient)
  return { rowsBefore, rowsAfter, inserted: toInsert, skipped: false }
}
