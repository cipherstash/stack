import {
  type EncryptedColumnInfo,
  listEncryptedColumns,
  pickEncryptedColumn,
  type ResolvedEncryptedColumn,
  readManifest,
} from '@cipherstash/migrate'
import type pg from 'pg'

/**
 * The resolved encryption lifecycle for one plaintext column: which column
 * carries the ciphertext, which EQL generation its domain type declares,
 * and which rule identified it (`info.via` — destructive commands must not
 * act on a `'sole'` match; see {@link pickEncryptedColumn}).
 */
export interface ResolvedLifecycle {
  /** The encrypted counterpart, or `null` when none could be identified. */
  info: ResolvedEncryptedColumn | null
  /**
   * Every EQL-domain column on the table, always populated (it's the same
   * catalog read resolution picks from). When `info` is `null` and this is
   * non-empty, resolution failed because none of these candidates is
   * identifiable — callers name them instead of erroring blind.
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
 * 3. The table's sole EQL-domain column, if there is exactly one — flagged
 *    `via: 'sole'` because uniqueness cannot prove the pairing.
 *
 * The VERSION always comes from the domain type. This deliberately diverges
 * from `encrypt status`, which falls back to the manifest's cached
 * `eqlVersion`: status may run without DB access, whereas the lifecycle
 * commands always hold a connection, so live truth wins here.
 *
 * A missing manifest is fine (`readManifest` returns `null` on ENOENT) but
 * any other manifest failure — malformed JSON, schema mismatch, permissions
 * — propagates: the callers are destructive commands, and silently losing
 * the recorded column hint must not let them fall through to a guess.
 */
export async function resolveColumnLifecycle(
  client: pg.ClientBase,
  table: string,
  column: string,
): Promise<ResolvedLifecycle> {
  const manifest = await readManifest()
  const hint = manifest?.tables[table]?.find(
    (entry) => entry.column === column,
  )?.encryptedColumn

  const candidates = await listEncryptedColumns(client, table)
  let info = hint ? pickEncryptedColumn(candidates, column, hint) : null
  // A stale hint (column since renamed/retyped) must not mask a resolvable
  // counterpart — fall back to convention + sole-EQL-column resolution.
  if (!info) info = pickEncryptedColumn(candidates, column)
  return { info, candidates }
}

/**
 * Explain a failed resolution (`info === null`) to the user, or return
 * `null` when the failure is fine to fall through to the v2 lifecycle.
 *
 * The one fall-through case is "no EQL columns at all", which the v2
 * phase/config preconditions turn into an accurate error ("not backfilled",
 * "no pending config", …). Since `classifyEqlDomain` recognises `eql_v3_*`
 * only, that case now also covers the post-cutover v2 state — `<col>` was
 * renamed onto the ciphertext, and its `eql_v2_encrypted` domain is no longer
 * classified, so the column never appears as a candidate. (It used to arrive
 * here as a `version: 2` candidate and needed its own exemption.)
 *
 * A non-empty candidate list therefore means EQL v3 columns exist but none is
 * identifiable — the caller must fail closed with this message rather than
 * guess a lifecycle, including when one candidate happens to share the
 * plaintext column's name (v3 has no cut-over rename, so that is not the
 * post-cutover state).
 */
export function explainUnresolved(
  table: string,
  column: string,
  candidates: readonly EncryptedColumnInfo[],
): string | null {
  if (candidates.length === 0) return null
  const listed = candidates
    .map((c) => `  - ${c.column} (${c.domain})`)
    .join('\n')
  return `Cannot identify which encrypted column corresponds to ${table}.${column}. EQL columns on ${table}:\n${listed}\nRecord the pairing and retry: re-run \`stash encrypt backfill --table ${table} --column ${column} --encrypted-column <name>\` (which writes it to the manifest), or set "encryptedColumn" for this column in .cipherstash/migrations.json.`
}
