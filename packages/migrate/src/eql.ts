import type { ClientBase } from 'pg'

/**
 * Thin, typed wrappers around the EQL (Encrypt Query Language) functions
 * installed by `stash eql install`. These mirror the canonical SQL API that
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
 * `<col>_encrypted` → `<col>` across tables in the **pending** EQL config.
 * Wraps `eql_v2.rename_encrypted_columns()`.
 *
 * This is the **cut-over primitive**: after this returns, any SQL that
 * reads `<col>` transparently receives the encrypted column (decrypted on
 * read by Proxy or Protect). Call inside a transaction.
 *
 * **Requires a pending configuration.** The underlying EQL function calls
 * `select_pending_columns()` and raises `'No pending configuration exists
 * to encrypt'` if none is registered. Call `db push` to register a pending
 * config first; if no rename targets are present in the diff, the loop
 * inside `rename_encrypted_columns()` does nothing — but the function
 * still requires pending to exist.
 *
 * Renames physical columns only — does not advance the EQL state machine.
 * Pair with {@link migrateConfig} + {@link activateConfig} to finish the
 * pending → encrypting → active transition.
 */
export async function renameEncryptedColumns(
  client: ClientBase,
): Promise<void> {
  await client.query('SELECT eql_v2.rename_encrypted_columns()')
}

/**
 * Advance the EQL state machine: `pending → encrypting`. Wraps
 * `eql_v2.migrate_config()`.
 *
 * Throws when:
 * - There is no pending configuration to migrate.
 * - There is already an encrypting configuration in flight.
 * - Some pending column lacks its encrypted target column (`<col>_encrypted`
 *   doesn't exist in the schema with `eql_v2_encrypted` UDT).
 */
export async function migrateConfig(client: ClientBase): Promise<void> {
  await client.query('SELECT eql_v2.migrate_config()')
}

/**
 * Advance the EQL state machine: `encrypting → active`. Wraps
 * `eql_v2.activate_config()`. Marks any prior `active` row as `inactive`
 * in the same call.
 *
 * Throws when there is no encrypting configuration to activate. Always
 * call after {@link migrateConfig} has flipped the pending row to
 * encrypting (typically inside the same transaction as
 * {@link renameEncryptedColumns} for cutover; or alone for non-rename
 * activations like adding a new column to an existing config).
 */
export async function activateConfig(client: ClientBase): Promise<void> {
  await client.query('SELECT eql_v2.activate_config()')
}

/**
 * Discard the pending configuration without applying it. Wraps
 * `eql_v2.discard()`. Used by `db push` to clean up any stale pending
 * before writing a new one — the state machine only allows one pending
 * row at a time, and a stale pending blocks new pushes.
 *
 * No-op when no pending exists.
 */
export async function discardPendingConfig(client: ClientBase): Promise<void> {
  // The EQL `discard()` function raises when there's no pending row —
  // we want a no-op in that case, so DELETE directly. Safer than
  // wrapping eql_v2.discard() in a try/catch that swallows shape errors.
  await client.query(
    "DELETE FROM public.eql_v2_configuration WHERE state = 'pending'",
  )
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
 *
 * Returns `bigint` because the underlying Postgres function returns
 * `BIGINT` and naively coercing to JS `number` loses precision past
 * `Number.MAX_SAFE_INTEGER` — exactly the row counts large-table users
 * are running this against. Callers that need a JS number can do their
 * own range check.
 */
export async function countEncryptedWithActiveConfig(
  client: ClientBase,
  tableName: string,
  columnName: string,
): Promise<bigint> {
  const result = await client.query<{ count: string }>(
    'SELECT eql_v2.count_encrypted_with_active_config($1, $2) AS count',
    [tableName, columnName],
  )
  return BigInt(result.rows[0]?.count ?? '0')
}
