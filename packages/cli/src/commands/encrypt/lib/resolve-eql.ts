import {
  type EncryptedColumnInfo,
  listEncryptedColumns,
  readManifest,
  resolveEncryptedColumn,
} from '@cipherstash/migrate'
import type pg from 'pg'

/**
 * The resolved encryption lifecycle for one plaintext column: which column
 * carries the ciphertext, and which EQL generation its domain type declares.
 */
export interface ResolvedLifecycle {
  /** The encrypted counterpart, or `null` when none could be identified. */
  info: EncryptedColumnInfo | null
  /**
   * Every EQL-domain column on the table — non-empty when resolution failed
   * because several candidates exist and none is identifiable. Lets the
   * caller name them instead of erroring blind.
   */
  candidates: EncryptedColumnInfo[]
}

/**
 * Resolve a plaintext column's encrypted counterpart, trusting the DOMAIN
 * TYPES in the database — the EQL v3 types are self-describing, so the
 * `<column>_encrypted` naming is a convention only, never enforced and never
 * relied upon. Resolution order:
 *
 * 1. The manifest's recorded `encryptedColumn` (written by `encrypt
 *    backfill`, including any `--encrypted-column` override) — used as a
 *    HINT and still validated against the actual domain type.
 * 2. The `<column>_encrypted` convention, validated the same way.
 * 3. The table's sole EQL-domain column, if there is exactly one.
 *
 * The VERSION always comes from the domain type — the manifest's cached
 * `eqlVersion` is for display paths that have no DB connection.
 */
export async function resolveColumnLifecycle(
  client: pg.ClientBase,
  table: string,
  column: string,
): Promise<ResolvedLifecycle> {
  const manifest = await readManifest().catch(() => null)
  const hint = manifest?.tables[table]?.find(
    (entry) => entry.column === column,
  )?.encryptedColumn

  let info = hint
    ? await resolveEncryptedColumn(client, table, column, hint)
    : null
  // A stale hint (column since renamed/retyped) must not mask a resolvable
  // counterpart — fall back to convention + sole-EQL-column resolution.
  if (!info) info = await resolveEncryptedColumn(client, table, column)
  if (info) return { info, candidates: [] }

  return { info: null, candidates: await listEncryptedColumns(client, table) }
}
