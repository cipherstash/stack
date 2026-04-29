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
  let where = `${plain} IS NOT NULL AND ${enc} IS NULL`
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
 */
export async function countUnencrypted(
  client: ClientBase,
  tableName: string,
  plaintextColumn: string,
  encryptedColumn: string,
): Promise<number> {
  const plain = quoteIdent(plaintextColumn)
  const enc = quoteIdent(encryptedColumn)
  const table = qualifyTable(tableName)
  const result = await client.query<{ count: string }>(
    `SELECT count(*)::text AS count FROM ${table} WHERE ${plain} IS NOT NULL AND ${enc} IS NULL`,
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
