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
  const page = await fetchPendingPage(client, {
    tableName: opts.tableName,
    pkColumn: opts.pkColumn,
    sourceColumn: opts.plaintextColumn,
    targetColumn: opts.encryptedColumn,
    after: opts.after,
    limit: opts.limit,
    force: opts.force,
  })
  return {
    rows: page.rows.map((row) => ({ pk: row.pk, plaintext: row.value })),
    lastPk: page.lastPk,
  }
}

/**
 * Inputs to {@link fetchUndecryptedPage} — the reverse (decrypt) twin of
 * {@link KeysetPageOptions}. The roles swap: the ENCRYPTED column is the
 * source being read and the plaintext column is the target being filled.
 */
export interface DecryptKeysetPageOptions {
  /** Physical table name. Supports `schema.table`. */
  tableName: string
  /** Primary-key column used for keyset pagination. */
  pkColumn: string
  /** EQL v3 column to read the ciphertext from, e.g. `email_encrypted`. */
  encryptedColumn: string
  /**
   * Plaintext column to fill, e.g. `email`. Rows where this is already
   * non-null are skipped (idempotency guard) unless `force` is set.
   */
  plaintextColumn: string
  /** Exclusive lower bound on `pkColumn`; `null` starts from the beginning. */
  after: string | null
  /** Maximum rows returned per call. */
  limit: number
  /**
   * When true, drop the `<plaintext_col> IS NULL` guard so rows that already
   * have plaintext are re-emitted — the reverse twin of the forward `force`.
   */
  force?: boolean
}

/**
 * Fetch the next page of rows that still need DECRYPTING: ciphertext set,
 * plaintext twin NULL. The exact mirror of {@link fetchUnencryptedPage} —
 * same keyset pagination and the same idempotency guard, with source and
 * target swapped — because it is the same query.
 *
 * The ciphertext is read as `::jsonb` so the driver hands back the parsed EQL
 * envelope regardless of how it reports the domain's type OID.
 */
export async function fetchUndecryptedPage(
  client: ClientBase,
  opts: DecryptKeysetPageOptions,
): Promise<KeysetPage<{ pk: string; ciphertext: unknown }>> {
  const page = await fetchPendingPage(client, {
    tableName: opts.tableName,
    pkColumn: opts.pkColumn,
    sourceColumn: opts.encryptedColumn,
    targetColumn: opts.plaintextColumn,
    after: opts.after,
    limit: opts.limit,
    force: opts.force,
    sourceCast: 'jsonb',
  })
  return {
    rows: page.rows.map((row) => ({ pk: row.pk, ciphertext: row.value })),
    lastPk: page.lastPk,
  }
}

/**
 * The one keyset query both directions share: rows whose `source` is set and
 * whose `target` is still NULL, after the cursor, in PK order. Forward reads
 * plaintext into an empty encrypted column; reverse reads ciphertext into an
 * empty plaintext column.
 */
async function fetchPendingPage(
  client: ClientBase,
  opts: {
    tableName: string
    pkColumn: string
    sourceColumn: string
    targetColumn: string
    after: string | null
    limit: number
    force?: boolean
    /** Only ever a fixed literal from this module — never caller input. */
    sourceCast?: 'jsonb'
  },
): Promise<KeysetPage<{ pk: string; value: unknown }>> {
  const pk = quoteIdent(opts.pkColumn)
  const source = quoteIdent(opts.sourceColumn)
  const target = quoteIdent(opts.targetColumn)
  const table = qualifyTable(opts.tableName)

  const params: unknown[] = []
  let where = pendingPredicate(source, target, opts.force ?? false)
  if (opts.after !== null) {
    params.push(opts.after)
    where += ` AND ${pk} > $${params.length}`
  }
  params.push(opts.limit)
  const limitParam = `$${params.length}`
  const selected = opts.sourceCast ? `${source}::${opts.sourceCast}` : source

  const sql = `
    SELECT ${pk}::text AS pk, ${selected} AS value
    FROM ${table}
    WHERE ${where}
    ORDER BY ${pk} ASC
    LIMIT ${limitParam}
  `
  const result = await client.query<{ pk: string; value: unknown }>(sql, params)
  const rows = result.rows
  const lastPk = rows.length > 0 ? rows[rows.length - 1]?.pk : null
  return { rows, lastPk }
}

/** `source IS NOT NULL [AND target IS NULL]` over already-quoted identifiers. */
function pendingPredicate(
  quotedSource: string,
  quotedTarget: string,
  force: boolean,
): string {
  return force
    ? `${quotedSource} IS NOT NULL`
    : `${quotedSource} IS NOT NULL AND ${quotedTarget} IS NULL`
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
 * have a (potentially stale) ciphertext. `after` counts only rows past a
 * resume cursor.
 */
export async function countUnencrypted(
  client: ClientBase,
  tableName: string,
  plaintextColumn: string,
  encryptedColumn: string,
  force = false,
  after: KeysetBound | null = null,
): Promise<number> {
  return countPending(
    client,
    tableName,
    plaintextColumn,
    encryptedColumn,
    force,
    after,
  )
}

/**
 * Count rows that still need DECRYPTING: `encrypted IS NOT NULL AND
 * plaintext IS NULL`. The reverse twin of {@link countUnencrypted}, used for
 * the reverse backfill's `rowsTotal` and as the coverage gate before
 * `stash decrypt drop` removes the encrypted column — any row it counts would
 * lose its only copy of the data.
 *
 * Rows that cannot be decrypted (for example, values bound to an end-user
 * lock context) stay counted here after a backfill, by design: they still
 * have no plaintext.
 */
export async function countUndecrypted(
  client: ClientBase,
  tableName: string,
  encryptedColumn: string,
  plaintextColumn: string,
  force = false,
  after: KeysetBound | null = null,
): Promise<number> {
  return countPending(
    client,
    tableName,
    encryptedColumn,
    plaintextColumn,
    force,
    after,
  )
}

/**
 * An exclusive lower bound on the primary key, in the same form the keyset
 * page query takes: count only rows the pass has not reached yet.
 */
export interface KeysetBound {
  pkColumn: string
  /** The cursor value (`pk::text`) to count strictly after. */
  pk: string
}

async function countPending(
  client: ClientBase,
  tableName: string,
  sourceColumn: string,
  targetColumn: string,
  force: boolean,
  after: KeysetBound | null = null,
): Promise<number> {
  const table = qualifyTable(tableName)
  let where = pendingPredicate(
    quoteIdent(sourceColumn),
    quoteIdent(targetColumn),
    force,
  )
  const params: unknown[] = []
  if (after !== null) {
    params.push(after.pk)
    where += ` AND ${quoteIdent(after.pkColumn)} > $${params.length}`
  }
  const result = await client.query<{ count: string }>(
    `SELECT count(*)::text AS count FROM ${table} WHERE ${where}`,
    params,
  )
  return Number(result.rows[0]?.count ?? 0)
}

/**
 * Whether any row has `column` set. A plaintext twin that already holds
 * values before the reverse lifecycle starts is the case `stash decrypt`
 * refuses by default: the reverse backfill only fills NULLs, so whatever is
 * there would be kept, current or not. `EXISTS` stops at the first match.
 */
export async function columnHasValues(
  client: ClientBase,
  tableName: string,
  column: string,
): Promise<boolean> {
  const result = await client.query<{ populated: boolean }>(
    `SELECT EXISTS (SELECT 1 FROM ${qualifyTable(tableName)} WHERE ${quoteIdent(column)} IS NOT NULL) AS populated`,
  )
  return result.rows[0]?.populated === true
}

/**
 * Count rows whose encrypted column is populated: `encrypted IS NOT NULL`.
 *
 * Backfill verification for EQL v3 is a plain count of the target column (the concrete
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
