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
  /**
   * The manifest's recorded `encryptedColumn` when it named a real column that
   * is NOT among `candidates`, AND `candidates` is non-empty — i.e. the pairing
   * is on record, the column it names is not an EQL v3 column (typically legacy
   * `eql_v2_encrypted`, which `classifyEqlDomain` no longer recognises), and
   * there are v3 columns here that a guess could wrongly claim.
   *
   * Distinct from a stale hint. It means the answer IS known and disagrees
   * with anything resolution could otherwise guess, so callers must fail closed
   * naming it rather than fall through to `via: 'sole'` (#772 review, finding 7).
   *
   * Deliberately NOT set when `candidates` is empty. That is the pure-v2 table
   * — a `<col>` / `<col>_encrypted` pair and nothing else — where there is no
   * v3 column to mis-claim and so nothing to protect against. The v2 lifecycle
   * is still implemented in `cutover.ts` / `drop.ts`, and those commands must
   * keep reaching it; failing closed here would refuse a lifecycle this same
   * build still performs, and tell the user to downgrade to reach it (#787
   * review).
   */
  unresolvedHint?: string
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
  const hinted = hint ? pickEncryptedColumn(candidates, column, hint) : null
  if (hinted) return { info: hinted, candidates }

  // The hint named a column that is not a candidate. Three very different
  // reasons, and they must not share an outcome:
  //
  // - the column no longer exists (renamed, dropped) — a genuinely STALE hint,
  //   which must not mask a resolvable counterpart, so fall through;
  // - the column exists, is not an EQL v3 column, and the table HAS v3 columns
  //   — the mixed table. The usual shape is a legacy `eql_v2_encrypted`
  //   counterpart, which `classifyEqlDomain` stopped recognising. Here the
  //   pairing IS known and falling through would discard it in favour of a
  //   guess: the sole-EQL-column rule claims an unrelated v3 column, `cutover`
  //   reports success for a rename it never performed, and `drop`'s remedy
  //   tells the user to record the guess (#772 review, finding 7). Fail closed;
  // - the column exists, is not an EQL v3 column, and there are NO v3 columns
  //   on the table — the pure-v2 table. Nothing here can be mis-claimed, and
  //   `cutover` / `drop` still implement the v2 ladder, so fall through to it
  //   exactly as before. Gating on `candidates.length` is what keeps the
  //   protection above scoped to the mixed table it was written for (#787
  //   review).
  if (
    hint &&
    candidates.length > 0 &&
    (await columnExists(client, table, hint))
  ) {
    return { info: null, candidates, unresolvedHint: hint }
  }

  return { info: pickEncryptedColumn(candidates, column), candidates }
}

/** Whether `column` exists on `table` at all, whatever its type. */
async function columnExists(
  client: pg.ClientBase,
  table: string,
  column: string,
): Promise<boolean> {
  const { rows } = await client.query<{ exists: boolean }>(
    `SELECT EXISTS (
       SELECT 1 FROM pg_attribute
       WHERE attrelid = to_regclass($1)
         AND attname = $2
         AND attnum > 0
         AND NOT attisdropped
     ) AS exists`,
    [table, column],
  )
  return rows[0]?.exists === true
}

/**
 * Explain a failed resolution (`info === null`) to the user, or return
 * `null` when the failure is fine to fall through to the v2 lifecycle.
 *
 * The one fall-through case is "no EQL v3 columns at all", which the v2
 * phase/config preconditions turn into an accurate error ("not backfilled",
 * "no pending config", …). Since `classifyEqlDomain` recognises `eql_v3_*`
 * only, that case covers every pure-v2 table — both the pre-cutover pair
 * (`<col>` / `<col>_encrypted`) and the post-cutover state where `<col>` was
 * renamed onto the ciphertext. Neither column is ever a candidate, so a pure-v2
 * table reaches the v2 ladder here regardless of what the manifest recorded;
 * a recorded `encryptedColumn` must NOT turn that into a refusal, because
 * `cutover.ts` / `drop.ts` in this same build still implement that ladder
 * (#787 review).
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
  unresolvedHint?: string,
): string | null {
  // "No EQL v3 columns at all" always falls through, even with a recorded hint.
  // That is the pure-v2 table, and the v2 ladder in `cutover.ts` / `drop.ts`
  // still handles it — the caller's own preconditions produce the accurate
  // error. Ordered ahead of the hint branch deliberately: `resolveColumnLifecycle`
  // already declines to set `unresolvedHint` on an empty candidate list, and this
  // keeps the two agreeing for direct callers of this function (#787 review).
  if (candidates.length === 0) return null

  // The recorded pairing points at a real column that is not an EQL v3 column,
  // on a table that does have v3 columns — almost always a legacy
  // `eql_v2_encrypted` counterpart alongside an unrelated v3 one. Say exactly
  // that: listing the v3 candidates here would invite the user to record one of
  // them, which is how the guess used to get laundered into a `via: 'hint'` match.
  if (unresolvedHint !== undefined) {
    return `${table}.${column} is recorded as pairing with "${unresolvedHint}", but ${unresolvedHint} is not an EQL v3 column — it is most likely a legacy eql_v2_encrypted column. ${table} also holds EQL v3 columns, and none of them is a confirmed counterpart for ${column}, so this command cannot tell which lifecycle applies and will not guess.\n\nIf that pairing is wrong, correct or remove "encryptedColumn" for ${column} in .cipherstash/migrations.json and re-run. If it is right, ${column} is on the EQL v2 lifecycle: drive it against ${unresolvedHint} directly rather than through this command, which resolves EQL v3 counterparts only.`
  }

  const listed = candidates
    .map((c) => `  - ${c.column} (${c.domain})`)
    .join('\n')
  return `Cannot identify which encrypted column corresponds to ${table}.${column}. EQL columns on ${table}:\n${listed}\nRecord the pairing and retry: re-run \`stash encrypt backfill --table ${table} --column ${column} --encrypted-column <name>\` (which writes it to the manifest), or set "encryptedColumn" for this column in .cipherstash/migrations.json.`
}
