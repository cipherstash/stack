import type { ClientBase } from 'pg'

/**
 * Thin, typed wrappers around the EQL (Encrypt Query Language) functions
 * installed by `stash db install`. These mirror the canonical SQL API that
 * CipherStash Proxy also drives, so every action we take here stays
 * visible to Proxy using the same column-level config.
 *
 * Defined by the EQL project at
 * https://github.com/cipherstash/encrypt-query-language — see
 * `src/config/functions.sql` and `src/encryptindex/functions.sql` for the
 * source of truth.
 */

/**
 * A column that has been registered in the `pending` EQL configuration but
 * is not yet part of the `active` config. Returned by
 * {@link selectPendingColumns}.
 */
export interface PendingColumn {
  tableName: string
  columnName: string
}

/**
 * Return columns present in the `pending` EQL config but absent (or
 * different) in the `active` one. Wraps `eql_v2.select_pending_columns()`.
 * Useful for showing "what's about to change" before calling
 * {@link readyForEncryption} + activating the pending config.
 */
export async function selectPendingColumns(
  client: ClientBase,
): Promise<PendingColumn[]> {
  const result = await client.query<{
    table_name: string
    column_name: string
  }>('SELECT table_name, column_name FROM eql_v2.select_pending_columns()')
  return result.rows.map((row) => ({
    tableName: row.table_name,
    columnName: row.column_name,
  }))
}

/**
 * Check EQL's precondition for activating a pending configuration: every
 * pending column must have a matching `eql_v2_encrypted`-typed target
 * column in the schema. Returns `true` if activation is safe.
 * Wraps `eql_v2.ready_for_encryption()`.
 */
export async function readyForEncryption(client: ClientBase): Promise<boolean> {
  const result = await client.query<{ ready: boolean }>(
    'SELECT eql_v2.ready_for_encryption() AS ready',
  )
  return result.rows[0]?.ready === true
}

/**
 * Atomically rename every `<col>` → `<col>_plaintext` and
 * `<col>_encrypted` → `<col>` across tables in the active EQL config.
 * Wraps `eql_v2.rename_encrypted_columns()`.
 *
 * This is the **cut-over primitive**: after this returns, any SQL that
 * reads `<col>` transparently receives the encrypted column (decrypted on
 * read by Proxy or Protect). Call inside a transaction.
 *
 * Idempotency: the underlying EQL function is safe to call when no renames
 * are pending; it simply returns without changes.
 */
export async function renameEncryptedColumns(
  client: ClientBase,
): Promise<void> {
  await client.query('SELECT eql_v2.rename_encrypted_columns()')
}

/**
 * Nudge Proxy to re-read its config immediately instead of waiting for its
 * next 60-second refresh tick. Wraps `eql_v2.reload_config()`.
 *
 * **Must be executed through a CipherStash Proxy connection** — when
 * connected directly to Postgres, `reload_config()` is a no-op (by design,
 * per the EQL documentation). The CLI's `cutover` command accepts a
 * `--proxy-url` flag and will connect to that separately to issue this.
 */
export async function reloadConfig(client: ClientBase): Promise<void> {
  await client.query('SELECT eql_v2.reload_config()')
}

/**
 * Return EQL's count of rows in `<tableName>.<columnName>` whose encrypted
 * payload's config version matches the currently active config. Useful as
 * a cheap sanity check — 0 after a backfill generally means something's
 * wrong (wrong config active, or the backfill wrote with a stale version).
 *
 * Wraps `eql_v2.count_encrypted_with_active_config(table, column)`.
 */
export async function countEncryptedWithActiveConfig(
  client: ClientBase,
  tableName: string,
  columnName: string,
): Promise<number> {
  const result = await client.query<{ count: string }>(
    'SELECT eql_v2.count_encrypted_with_active_config($1, $2) AS count',
    [tableName, columnName],
  )
  return Number(result.rows[0]?.count ?? 0)
}
