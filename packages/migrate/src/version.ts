import type { ClientBase } from 'pg'

/**
 * Which EQL generation an encrypted column belongs to. The migration lifecycle
 * differs between them: v2 is driven by the `eql_v2_configuration` state machine
 * (see {@link import('./eql.js')}), while v3 is domain-native — configuration
 * lives in the column's own type and there is no configuration table, so its
 * lifecycle is backfill-then-drop with no cut-over rename.
 *
 * Numeric (`2 | 3`) to match the manifest's `eqlVersion` field and the CLI
 * installer's `--eql-version` — one representation everywhere, no
 * string↔number translation at boundaries.
 */
export type EqlVersion = 2 | 3

/** An encrypted column found on a table, classified by its domain type. */
export interface EncryptedColumnInfo {
  /** The column's name, exactly as Postgres reports it. */
  column: string
  /** The EQL domain name, e.g. `eql_v2_encrypted` or `eql_v3_text_search`. */
  domain: string
  version: EqlVersion
}

/**
 * Classify a Postgres domain-type name as an EQL generation.
 *
 * EQL v3 types are deliberately self-describing — the domain name alone
 * carries the generation — which is why this predicate is the ONE place the
 * rule lives, and why detection never relies on column NAMES: the
 * `<column>_encrypted` naming is a convention, neither enforced nor required.
 *
 * - `eql_v2_encrypted` → 2
 * - `eql_v3_*` (e.g. `eql_v3_text_search`, `eql_v3_integer_ord`) → 3
 * - anything else → `null` (not an EQL column)
 */
export function classifyEqlDomain(domain: string): EqlVersion | null {
  if (domain === 'eql_v2_encrypted') return 2
  // Underscore included: a bare `startsWith('eql_v3')` would also claim
  // hypothetical future generations like `eql_v30_*`.
  if (domain.startsWith('eql_v3_')) return 3
  return null
}

/**
 * Resolve `tableName` (optionally `schema.table`) to a regclass expression
 * that preserves the identifier's case.
 *
 * A bare `to_regclass($1)` PARSES its argument, case-folding unquoted names —
 * so `to_regclass('User')` looks up `user` and misses a Prisma-style `"User"`
 * table that the rest of the pipeline (which quotes identifiers verbatim, see
 * `qualifyTable`/`quoteIdent` in cursor.ts) handles fine. `format('%I', …)`
 * quotes the name first, making the lookup case-exact while still honouring
 * `search_path` for unqualified names.
 */
const REGCLASS_SQL = `to_regclass(
  CASE WHEN $2::text IS NULL THEN format('%I', $1::text)
       ELSE format('%I.%I', $2::text, $1::text) END
)`

/** Split `schema.table` the same way `qualifyTable` does (first dot wins). */
function splitTableName(tableName: string): {
  schema: string | null
  table: string
} {
  const dot = tableName.indexOf('.')
  return dot >= 0
    ? { schema: tableName.slice(0, dot), table: tableName.slice(dot + 1) }
    : { schema: null, table: tableName }
}

/**
 * Detect the EQL version of one named column by inspecting its Postgres
 * domain type. Returns `null` for a plaintext column, a non-EQL domain, or a
 * table/column that doesn't exist.
 *
 * `tableName` may be schema-qualified (`schema.table`); resolution is
 * case-exact and honours `search_path` for unqualified names.
 */
export async function detectColumnEqlVersion(
  client: ClientBase,
  tableName: string,
  columnName: string,
): Promise<EqlVersion | null> {
  const { schema, table } = splitTableName(tableName)
  // `a.atttypid` on a domain-typed column is the DOMAIN's oid, so `t.typname`
  // is the domain name (e.g. `eql_v2_encrypted`), not the underlying `jsonb`.
  const result = await client.query<{ domain_name: string }>(
    `SELECT t.typname AS domain_name
       FROM pg_attribute a
       JOIN pg_type t ON t.oid = a.atttypid
      WHERE a.attrelid = ${REGCLASS_SQL}
        AND a.attname = $3
        AND NOT a.attisdropped`,
    [table, schema, columnName],
  )
  const domain = result.rows[0]?.domain_name
  return domain === undefined ? null : classifyEqlDomain(domain)
}

/**
 * Every EQL-domain column on a table, classified. The EQL types are
 * self-describing, so this is the ground truth for "which columns on this
 * table are encrypted, and under which generation" — no naming convention
 * involved.
 */
export async function listEncryptedColumns(
  client: ClientBase,
  tableName: string,
): Promise<EncryptedColumnInfo[]> {
  const { schema, table } = splitTableName(tableName)
  const result = await client.query<{ column: string; domain_name: string }>(
    `SELECT a.attname AS column, t.typname AS domain_name
       FROM pg_attribute a
       JOIN pg_type t ON t.oid = a.atttypid
      WHERE a.attrelid = ${REGCLASS_SQL}
        AND a.attnum > 0
        AND NOT a.attisdropped
      ORDER BY a.attnum`,
    [table, schema],
  )
  const out: EncryptedColumnInfo[] = []
  for (const row of result.rows) {
    const version = classifyEqlDomain(row.domain_name)
    if (version !== null) {
      out.push({ column: row.column, domain: row.domain_name, version })
    }
  }
  return out
}

/**
 * Which rule identified the encrypted counterpart. Callers gate on this:
 * `hint` and `convention` positively assert the plaintext↔ciphertext
 * pairing; `sole` only proves the column is the table's ONE EQL column —
 * it may encrypt a *different* field, so irreversible operations (dropping
 * the plaintext) must not act on it without explicit confirmation.
 */
export type EncryptedColumnResolution = 'hint' | 'convention' | 'sole'

/** An {@link EncryptedColumnInfo} plus how it was identified. */
export interface ResolvedEncryptedColumn extends EncryptedColumnInfo {
  via: EncryptedColumnResolution
}

/**
 * Pick the encrypted counterpart of a plaintext column from an already
 * fetched candidate list (see {@link listEncryptedColumns}), trusting the
 * domain types over any naming convention:
 *
 * 1. An explicit `hint` (from `--encrypted-column` or the manifest's recorded
 *    `encryptedColumn`) wins — but only if that column really carries an EQL
 *    domain (`via: 'hint'`).
 * 2. Otherwise the `<column>_encrypted` CONVENTION is tried — again validated
 *    against the domain type, never assumed (`via: 'convention'`).
 * 3. Otherwise, if the table has exactly ONE EQL-domain column, that's the
 *    best guess (`via: 'sole'`) — the self-describing types make the
 *    convention unnecessary, but uniqueness alone cannot prove the pairing;
 *    check `via` before doing anything destructive.
 *
 * Pure — callers with several lookups against the same table fetch the
 * candidates once and pick repeatedly. Returns `null` when nothing matches
 * or when several EQL columns exist and none is identifiable (ambiguous —
 * the caller should ask the user, listing the candidates).
 */
export function pickEncryptedColumn(
  candidates: readonly EncryptedColumnInfo[],
  plaintextColumn: string,
  hint?: string,
): ResolvedEncryptedColumn | null {
  if (candidates.length === 0) return null

  if (hint) {
    const hinted = candidates.find((c) => c.column === hint)
    return hinted ? { ...hinted, via: 'hint' } : null
  }

  const conventional = candidates.find(
    (c) => c.column === `${plaintextColumn}_encrypted`,
  )
  if (conventional) return { ...conventional, via: 'convention' }

  // The plaintext column itself can't be its own encrypted counterpart.
  const others = candidates.filter((c) => c.column !== plaintextColumn)
  return others.length === 1 && others[0] ? { ...others[0], via: 'sole' } : null
}

/**
 * {@link pickEncryptedColumn} over a live catalog read — fetches the
 * table's EQL-domain columns and picks from them.
 */
export async function resolveEncryptedColumn(
  client: ClientBase,
  tableName: string,
  plaintextColumn: string,
  hint?: string,
): Promise<ResolvedEncryptedColumn | null> {
  const candidates = await listEncryptedColumns(client, tableName)
  return pickEncryptedColumn(candidates, plaintextColumn, hint)
}
