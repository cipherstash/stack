import { loadStashConfig } from '@/config/index.js'
import {
  appendEvent,
  progress,
  reloadConfig,
  renameEncryptedColumns,
} from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import pg from 'pg'

/**
 * Options accepted by `stash encrypt cutover`. Swaps the plaintext and
 * encrypted columns via `eql_v2.rename_encrypted_columns()` so that apps
 * reading `<column>` transparently receive the encrypted column
 * (decrypted on read by Proxy or client-side by Stack).
 */
export interface CutoverCommandOptions {
  /** Physical table name, e.g. `users`. Supports `schema.table`. */
  table: string
  /**
   * Physical plaintext column that is being cut over, e.g. `email`. Used
   * only for the state-transition check and event log; the actual rename
   * affects every column in the active EQL config in a single call.
   */
  column: string
  /**
   * Optional Postgres URL of a CipherStash Proxy. When set, the command
   * connects to the Proxy after the rename and runs `eql_v2.reload_config()`
   * so Proxy picks up the renamed columns immediately rather than waiting
   * for its 60-second refresh. When unset, prints a warning to that effect
   * and returns — the Proxy will refresh on its own.
   *
   * Also readable from `CIPHERSTASH_PROXY_URL` in the environment.
   */
  proxyUrl?: string
}

/**
 * CLI handler for `stash encrypt cutover`. Verifies the target column is
 * in phase `backfilled`, runs `eql_v2.rename_encrypted_columns()` inside
 * a transaction, appends a `cut_over` event, and optionally triggers a
 * Proxy config reload. Exits with code `1` if preconditions are not met.
 */
export async function cutoverCommand(options: CutoverCommandOptions) {
  p.intro('npx @cipherstash/cli encrypt cutover')

  const config = await loadStashConfig()
  const client = new pg.Client({ connectionString: config.databaseUrl })

  try {
    await client.connect()

    const state = await progress(client, options.table, options.column)
    if (state?.phase !== 'backfilled') {
      p.log.error(
        `Cannot cut over: ${options.table}.${options.column} is in phase '${state?.phase ?? '—'}'. Must be 'backfilled'.`,
      )
      process.exit(1)
    }

    await client.query('BEGIN')
    try {
      await renameEncryptedColumns(client)
      await appendEvent(client, {
        tableName: options.table,
        columnName: options.column,
        event: 'cut_over',
        phase: 'cut-over',
        details: { renamed: true },
      })
      await client.query('COMMIT')
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {})
      throw err
    }

    p.log.success(
      `Renamed ${options.column} → ${options.column}_plaintext and ${options.column}_encrypted → ${options.column}.`,
    )

    const proxyUrl = options.proxyUrl ?? process.env.CIPHERSTASH_PROXY_URL
    if (proxyUrl) {
      const proxy = new pg.Client({ connectionString: proxyUrl })
      try {
        await proxy.connect()
        await reloadConfig(proxy)
        p.log.success('Proxy config reloaded.')
      } finally {
        await proxy.end()
      }
    } else {
      p.log.warn(
        'CIPHERSTASH_PROXY_URL not set; Proxy users must wait up to 60s for config refresh.',
      )
    }

    p.outro(
      'Cut-over complete. Your app reads the encrypted column transparently.',
    )
  } catch (error) {
    p.log.error(error instanceof Error ? error.message : 'Cut-over failed.')
    process.exit(1)
  } finally {
    await client.end()
  }
}
