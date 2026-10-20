import type { ClientBase } from 'pg'

/**
 * Which EQL generation an encrypted column belongs to. EQL v3 is domain-native:
 * configuration lives in the column's own type and its lifecycle is
 * backfill-then-drop with no cut-over rename. The `2` member remains solely for
 * reading legacy manifest and status records.
 *
 * Numeric (`2 | 3`) to match the manifest's `eqlVersion` field.
 */
export type EqlVersion = 2 | 3

/** An encrypted column found on a table, classified by its domain type. */
export interface EncryptedColumnInfo {
  /** The column's name, exactly as Postgres reports it. */
  column: string
  /** The EQL domain name, e.g. `eql_v3_text_search` or `eql_v3_integer_ord`. */
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
 * - `eql_v3_*` (e.g. `eql_v3_text_search`, `eql_v3_integer_ord`) → 3
 * - anything else → `null` (not an EQL v3 column)
 *
 * v3 is the sole generation this workspace authors and backfills, so the
 * classifier only recognises `eql_v3_*` domains. A legacy `eql_v2_encrypted`
 * column is therefore no longer classified here — its version is carried by
 * the manifest's recorded `eqlVersion` instead (see the `?? eqlVersion`
 * fallbacks in the CLI's `encrypt status` / `status` renderers). Existing v2
 * ciphertext stays decryptable; only its *classification as an authorable
 * generation* is dropped. `EqlVersion` keeps the `2` member for those
 * manifest-sourced legacy values.
 */
export function classifyEqlDomain(domain: string): EqlVersion | null {
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
 * Whether `columnName` exists on `tableName` at all, whatever its type.
 *
 * Distinct from {@link detectColumnEqlVersion}, which answers "and is it an EQL
 * column?". Callers need the difference to tell a STALE reference (the column
 * is gone) from a live one the classifier simply does not recognise — most
 * often a legacy `eql_v2_encrypted` counterpart.
 *
 * Lives here rather than in the CLI so it shares {@link REGCLASS_SQL} with the
 * other catalog probes: a hand-rolled `to_regclass($1)` case-folds unquoted
 * identifiers and silently reports "missing" for a Prisma-style `"User"` table
 * (#787 review).
 */
export async function columnExists(
  client: ClientBase,
  tableName: string,
  columnName: string,
): Promise<boolean> {
  const { schema, table } = splitTableName(tableName)
  const { rows } = await client.query<{ exists: boolean }>(
    `SELECT EXISTS (
       SELECT 1 FROM pg_attribute
       WHERE attrelid = ${REGCLASS_SQL}
         AND attname = $3
         AND attnum > 0
         AND NOT attisdropped
     ) AS exists`,
    [table, schema, columnName],
  )
  return rows[0]?.exists === true
}

/**
 * The columns of `tableName`'s primary key, in attribute order. Empty when
 * the table has no primary key or does not exist.
 *
 * Resolves through {@link REGCLASS_SQL}, so an unqualified name follows
 * `search_path` and stays case-exact. Matching `relname` in every schema
 * instead would merge same-named tables (Supabase's `public.users` and
 * `auth.users`) into one apparent composite key.
 */
export async function primaryKeyColumns(
  client: ClientBase,
  tableName: string,
): Promise<string[]> {
  const { schema, table } = splitTableName(tableName)
  const { rows } = await client.query<{ column_name: string }>(
    `SELECT a.attname AS column_name
       FROM pg_index i
       JOIN pg_attribute a
         ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
      WHERE i.indisprimary
        AND i.indrelid = ${REGCLASS_SQL}
      ORDER BY a.attnum ASC`,
    [table, schema],
  )
  return rows.map((row) => row.column_name)
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

/**
 * The column's declared type as Postgres itself renders it
 * (`format_type(atttypid, atttypmod)`, e.g. `character varying(255)`,
 * `timestamp with time zone`, `jsonb`), or `null` when the column does not
 * exist.
 *
 * The reverse backfill casts every decrypted value to this exact string, so it
 * honours whatever type the user actually gave the plaintext twin — a
 * `varchar(255)` instead of the suggested `text`, say — rather than the type
 * the CLI would have proposed. `format_type` output is designed to be valid
 * type syntax, quoting included, which is why it is safe to splice.
 */
export async function columnSqlType(
  client: ClientBase,
  tableName: string,
  columnName: string,
): Promise<string | null> {
  const { schema, table } = splitTableName(tableName)
  const { rows } = await client.query<{ sql_type: string }>(
    `SELECT format_type(a.atttypid, a.atttypmod) AS sql_type
       FROM pg_attribute a
      WHERE a.attrelid = ${REGCLASS_SQL}
        AND a.attname = $3
        AND a.attnum > 0
        AND NOT a.attisdropped`,
    [table, schema, columnName],
  )
  return rows[0]?.sql_type ?? null
}

/** An index that depends on a column, as {@link listColumnIndexes} reports it. */
export interface ColumnIndexInfo {
  /** Schema the index lives in. */
  schema: string
  /** The index's own name. */
  name: string
  /** `pg_get_indexdef` output, for display. */
  definition: string
}

/**
 * Every index that depends on `columnName` — plain column indexes AND
 * expression indexes over it (an EQL functional index such as
 * `eql_v3.ord_term(email_encrypted)` references the column only through its
 * expression, so `indkey` alone would miss it; `pg_depend` records both).
 *
 * Used by `stash decrypt drop` to drop the EQL-term indexes explicitly and
 * name them, rather than leaving them to `DROP COLUMN`'s implicit cascade.
 */
export async function listColumnIndexes(
  client: ClientBase,
  tableName: string,
  columnName: string,
): Promise<ColumnIndexInfo[]> {
  const { schema, table } = splitTableName(tableName)
  const { rows } = await client.query<{
    schema: string
    name: string
    definition: string
  }>(
    `SELECT DISTINCT n.nspname AS schema,
            ic.relname AS name,
            pg_get_indexdef(i.indexrelid) AS definition
       FROM pg_index i
       JOIN pg_class ic ON ic.oid = i.indexrelid
       JOIN pg_namespace n ON n.oid = ic.relnamespace
       JOIN pg_attribute a
         ON a.attrelid = i.indrelid
        AND a.attname = $3
        AND a.attnum > 0
        AND NOT a.attisdropped
       JOIN pg_depend d
         ON d.classid = 'pg_class'::regclass
        AND d.objid = i.indexrelid
        AND d.refclassid = 'pg_class'::regclass
        AND d.refobjid = i.indrelid
        AND d.refobjsubid = a.attnum
      WHERE i.indrelid = ${REGCLASS_SQL}
      ORDER BY ic.relname`,
    [table, schema, columnName],
  )
  return rows
}

/**
 * SQL predicate (over `pg_attribute a`, `pg_type t`, `pg_class c`) matching a
 * user-visible relation column whose type is an EQL v3 domain, or an array of
 * one. Shared by {@link countEqlColumnsInDatabase} and the apply-time recheck
 * `stash decrypt drop --uninstall-eql` embeds in its migration, so the CLI's
 * check and the migration's check cannot disagree.
 */
export const EQL_COLUMN_PREDICATE_SQL = `a.attnum > 0
         AND NOT a.attisdropped
         AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
         AND (t.typname LIKE 'eql\\_v3\\_%' OR t.typname LIKE '\\_eql\\_v3\\_%')`

/**
 * How many columns in the WHOLE database (every schema) are typed with an EQL
 * v3 domain. Uninstalling EQL v3 drops its schemas with `CASCADE`, which
 * removes every such column along with the domains — so `stash decrypt drop
 * --uninstall-eql` refuses unless the column it is dropping is the last one.
 * Legacy `eql_v2_encrypted` columns are not counted: the v3 uninstall does not
 * touch the v2 schema they depend on.
 */
export async function countEqlColumnsInDatabase(
  client: ClientBase,
): Promise<number> {
  const { rows } = await client.query<{ count: string }>(
    `SELECT count(*)::text AS count
       FROM pg_attribute a
       JOIN pg_type t ON t.oid = a.atttypid
       JOIN pg_class c ON c.oid = a.attrelid
      WHERE ${EQL_COLUMN_PREDICATE_SQL}`,
  )
  return Number(rows[0]?.count ?? 0)
}
