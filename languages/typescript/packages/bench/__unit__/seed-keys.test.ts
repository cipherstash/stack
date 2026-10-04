/**
 * The seed's row keys must be the keys model encryption MATCHES on.
 *
 * `extractEncryptionSchema` keys the encrypted-table column map by the Drizzle
 * table's **JS property** (`encText`), while the column's DB name (`enc_text`)
 * is what the builder carries. So `resolveEncryptColumnMap().columnPaths` — the
 * list every model operation matches a row's fields against — is the property
 * names. A row keyed by DB name matches nothing: `bulkEncryptModels` returns it
 * untouched, with no failure, and the insert then puts PLAINTEXT into columns
 * typed `eql_v3_*`.
 *
 * That is exactly what the v2 -> v3 port left behind, and nothing caught it:
 * `tsc --noEmit` passes because `BenchPlaintextRow` was hand-written and agreed
 * with itself, and CI only runs the `db-only` filter, which never seeds
 * (#772 review, finding 12).
 *
 * Credential-free by construction — this compares two key sets and never
 * reaches ZeroKMS.
 */
import { describe, expect, it } from 'vitest'
import { encryptionBenchTable } from '../src/drizzle/setup.js'
import { makePlaintextRow } from '../src/harness/seed.js'

describe('bench seed rows are keyed for model encryption', () => {
  // `resolveEncryptColumnMap` is internal, but it derives `columnPaths` as
  // exactly `Object.keys(table.buildColumnKeyMap())` — read the same source.
  const columnPaths = Object.keys(encryptionBenchTable.buildColumnKeyMap())

  it('finds the encrypted columns (guards against an empty comparison)', () => {
    expect(columnPaths.length).toBeGreaterThan(0)
  })

  it('emits a field for every encrypted column, under the matched key', () => {
    const rowKeys = Object.keys(makePlaintextRow(0))

    // Every encrypted column must be present in the row, or that column is
    // silently never encrypted.
    expect(rowKeys).toEqual(expect.arrayContaining([...columnPaths]))
  })

  it('emits no field the matcher would pass through as plaintext', () => {
    const rowKeys = Object.keys(makePlaintextRow(0))
    const unmatched = rowKeys.filter((key) => !columnPaths.includes(key))

    expect(
      unmatched,
      `these seed fields match no encrypted column, so they would be inserted as plaintext into an eql_v3_* column: ${unmatched.join(', ')}`,
    ).toEqual([])
  })
})
