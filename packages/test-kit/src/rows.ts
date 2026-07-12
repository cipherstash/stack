import type { FamilyDomain, FamilyName } from './families.ts'
import type { Plain } from './ops.ts'
import { plainValue } from './oracle.ts'

/** The table one family file creates: one column per covered domain in the family. */
export type TableSpec = Readonly<{
  /** Unique per run so concurrent suites and reruns never collide. */
  name: string
  runId: string
  columns: readonly FamilyDomain[]
}>

export type PlainRow = Readonly<{
  rowKey: string
  runId: string
  /** Plaintext per column slug. Empty on the NULL row. */
  values: Readonly<Record<string, Plain>>
}>

export type RowPlan = Readonly<{
  /** Row keys carrying values, in ascending order — the oracle's domain. */
  rowKeys: readonly string[]
  byKey: Readonly<Record<string, PlainRow>>
  /** Inserted one at a time, through the adapter's `encryptModel` path. */
  singleKeys: readonly string[]
  /** Inserted as one array, through the adapter's `bulkEncryptModels` path. */
  bulkKeys: readonly string[]
  /** Every encrypted column NULL. Exercises `isNull`/`isNotNull` on every domain. */
  nullRow: PlainRow
}>

/**
 * Three value rows minimum, so a predicate that over-matches by one row is
 * detectable; four when any domain in the family has that many distinct samples,
 * so the extra sample (usually a type bound) reaches the database. More rows buy
 * nothing: the oracle already covers ties via the `samples[min(i, len-1)]` reuse.
 */
const MIN_VALUE_ROWS = 3
const MAX_VALUE_ROWS = 4

const ROW_KEYS = ['a', 'b', 'c', 'd'] as const
const NULL_ROW_KEY = 'null'

function valueRowCount(domains: readonly FamilyDomain[]): number {
  const widest = Math.max(...domains.map((d) => d.spec.samples.length))
  return Math.min(Math.max(widest, MIN_VALUE_ROWS), MAX_VALUE_ROWS)
}

/**
 * A table name unique to this family and run. Postgres identifiers cap at 63
 * bytes and the run id is a caller-supplied short hex string, so this stays well
 * inside the limit for every family name.
 */
export function planTable(
  family: FamilyName,
  domains: readonly FamilyDomain[],
  runId: string,
): TableSpec {
  if (domains.length === 0) {
    throw new Error(
      `Family "${family}" has no covered domains — check FAMILY_PREFIXES and the catalog's deferred rows`,
    )
  }
  return {
    name: `v3_it_${family.replace(/-/g, '_')}_${runId}`,
    runId,
    columns: domains,
  }
}

/**
 * Seed rows plus the single/bulk split.
 *
 * The halves are DISJOINT and interleaved (`a`,`c` single; `b`,`d` bulk) so that
 * any per-domain predicate matching more than one row necessarily spans both
 * encryption paths. That is what turns "the bulk path mangled a row" into a red
 * test rather than a coincidence — before this, the Supabase adapter's array
 * insert (`bulkEncryptModels`) and the Drizzle single insert (`encryptModel`)
 * were each untested on their respective sides.
 */
export function planRows(
  domains: readonly FamilyDomain[],
  runId: string,
): RowPlan {
  const count = valueRowCount(domains)
  const rowKeys = ROW_KEYS.slice(0, count)

  const byKey: Record<string, PlainRow> = {}
  for (const rowKey of rowKeys) {
    const values: Record<string, Plain> = {}
    for (const domain of domains) {
      values[domain.slug] = plainValue(domain.spec, rowKeys, rowKey)
    }
    byKey[rowKey] = { rowKey, runId, values }
  }

  return {
    rowKeys,
    byKey,
    singleKeys: rowKeys.filter((_, i) => i % 2 === 0),
    bulkKeys: rowKeys.filter((_, i) => i % 2 === 1),
    nullRow: { rowKey: NULL_ROW_KEY, runId, values: {} },
  }
}

export { NULL_ROW_KEY }
