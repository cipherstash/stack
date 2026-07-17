import type { ClientBase } from 'pg'
import { quoteIdent } from './sql.js'

/**
 * Inputs to {@link fetchUnencryptedPage}.
 */
export interface KeysetPageOptions {
  /** Physical table name. Supports `schema.table`. */
  tableName: string
  /**
   * Primary-key column used for keyset pagination. Must be comparable with
   * `>`. Cast to text by the query so any PK type works.
   */
  pkColumn: string
  /** Column to read the plaintext from, e.g. `email`. */
  plaintextColumn: string
  /**
   * Target encrypted column, e.g. `email_encrypted`. Rows where this is
   * already non-null are skipped (idempotency guard).
   */
  encryptedColumn: string
  /**
   * Exclusive lower bound on `pkColumn`. Set to `null` to start from the
   * beginning; pass the `lastPk` of the previous page to continue.
   */
  after: string | null
  /** Maximum rows returned per call. */
  limit: number
  /**
   * When true, drop the `<encrypted_col> IS NULL` guard so rows that
   * already have ciphertext are re-emitted. Used by `stash encrypt
   * backfill --force` to recover from drift (e.g. dual-writes weren't
   * actually deployed when an earlier backfill ran). Off by default — the
   * guard makes normal re-runs idempotent.
   */
  force?: boolean
}

/**
 * One page of rows from {@link fetchUnencryptedPage}. `lastPk` is `null`
 * only when the page is empty — the caller's completion signal.
 */
export interface KeysetPage<Row = Record<string, unknown>> {
  rows: Row[]
  lastPk: string | null
}

/**
 * Fetch the next page of rows that still need encryption for a given column.
 *
 * Guards with `plaintext_col IS NOT NULL AND encrypted_col IS NULL` so a
 * concurrent backfill or a re-run never re-processes the same row, even if
 * the pagination cursor is lost. The ORDER BY + LIMIT form gives keyset
 * (seek) pagination rather than OFFSET, which keeps the scan bounded as
 * the cursor advances.
 */
export async function fetchUnencryptedPage(
  client: ClientBase,
  opts: KeysetPageOptions,
): Promise<KeysetPage<{ pk: string; plaintext: unknown }>> {
  const pk = quoteIdent(opts.pkColumn)
  const plain = quoteIdent(opts.plaintextColumn)
  const enc = quoteIdent(opts.encryptedColumn)
  const table = qualifyTable(opts.tableName)

  const params: unknown[] = []
  let where = opts.force
    ? `${plain} IS NOT NULL`
    : `${plain} IS NOT NULL AND ${enc} IS NULL`
  if (opts.after !== null) {
    params.push(opts.after)
    where += ` AND ${pk} > $${params.length}`
  }
  params.push(opts.limit)
  const limitParam = `$${params.length}`

  const sql = `
    SELECT ${pk}::text AS pk, ${plain} AS plaintext
    FROM ${table}
    WHERE ${where}
    ORDER BY ${pk} ASC
    LIMIT ${limitParam}
  `
  const result = await client.query<{ pk: string; plaintext: unknown }>(
    sql,
    params,
  )
  const rows = result.rows
  const lastPk = rows.length > 0 ? rows[rows.length - 1]?.pk : null
  return { rows, lastPk }
}

/**
 * Count rows that still need encryption: `plaintext IS NOT NULL AND
 * encrypted IS NULL`. Called once at the start of a backfill to compute
 * `rowsTotal` for progress reporting; does not hold a snapshot, so new
 * rows inserted during the backfill are simply picked up on the next
 * chunk's SELECT.
 *
 * When `force` is true, drops the `encrypted IS NULL` guard — used by
 * `--force` to count every plaintext row, including ones that already
 * have a (potentially stale) ciphertext.
 */
export async function countUnencrypted(
  client: ClientBase,
  tableName: string,
  plaintextColumn: string,
  encryptedColumn: string,
  force = false,
): Promise<number> {
  const plain = quoteIdent(plaintextColumn)
  const enc = quoteIdent(encryptedColumn)
  const table = qualifyTable(tableName)
  const where = force
    ? `${plain} IS NOT NULL`
    : `${plain} IS NOT NULL AND ${enc} IS NULL`
  const result = await client.query<{ count: string }>(
    `SELECT count(*)::text AS count FROM ${table} WHERE ${where}`,
  )
  return Number(result.rows[0]?.count ?? 0)
}

/**
 * Count rows whose encrypted column is populated: `encrypted IS NOT NULL`.
 *
 * The v3 backfill-verification primitive. EQL v2 verified via
 * `eql_v2.count_encrypted_with_active_config(...)`, which reads the
 * `eql_v2_configuration` table — v3 has no configuration table, so the
 * equivalent check is a plain count of the target column (the concrete
 * `eql_v3_*` domain's CHECK constraint already guarantees every non-null
 * value is a valid v3 envelope).
 */
export async function countEncrypted(
  client: ClientBase,
  tableName: string,
  encryptedColumn: string,
): Promise<number> {
  const enc = quoteIdent(encryptedColumn)
  const table = qualifyTable(tableName)
  const result = await client.query<{ count: string }>(
    `SELECT count(*)::text AS count FROM ${table} WHERE ${enc} IS NOT NULL`,
  )
  return Number(result.rows[0]?.count ?? 0)
}

/**
 * Quote a possibly schema-qualified table name for use in a SQL statement.
 * `"foo"` → `"foo"`; `"public.foo"` → `"public"."foo"`. Use for identifiers
 * that cannot be parameterised.
 */
export function qualifyTable(tableName: string): string {
  if (tableName.includes('.')) {
    const parts = tableName.split('.')
    return parts.map(quoteIdent).join('.')
  }
  return quoteIdent(tableName)
}
