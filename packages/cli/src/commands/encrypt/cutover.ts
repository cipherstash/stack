import {
  activateConfig,
  appendEvent,
  migrateConfig,
  progress,
  reloadConfig,
  renameEncryptedColumns,
} from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import pg from 'pg'
import { detectDrizzle } from '@/commands/db/detect.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadStashConfig } from '@/config/index.js'
import { scaffoldDrizzleMigration } from './drizzle-helper.js'

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
  /**
   * Drizzle migrations directory (passed to `drizzle-kit generate
   * --custom`). Defaults to `./drizzle`. Only used when the project is
   * Drizzle — non-Drizzle projects skip the snapshot-resync step.
   */
  migrationsDir?: string
}

/**
 * CLI handler for `stash encrypt cutover`. Verifies the target column is
 * in phase `backfilled`, runs `eql_v2.rename_encrypted_columns()` inside
 * a transaction, appends a `cut_over` event, and optionally triggers a
 * Proxy config reload. Exits with code `1` if preconditions are not met.
 */
export async function cutoverCommand(options: CutoverCommandOptions) {
  p.intro(runnerCommand(detectPackageManager(), 'stash encrypt cutover'))

  const config = await loadStashConfig()
  const client = new pg.Client({ connectionString: config.databaseUrl })
  let exitCode = 0

  try {
    await client.connect()

    const state = await progress(client, options.table, options.column)
    if (state?.phase !== 'backfilled') {
      p.log.error(
        `Cannot cut over: ${options.table}.${options.column} is in phase '${state?.phase ?? '—'}'. Must be 'backfilled'.`,
      )
      exitCode = 1
      return
    }

    // Verify a pending EQL config exists. cutover assumes the user has
    // already run `stash db push` against a schema that switches the
    // column from `<col>_encrypted` (or whatever twin name) to `<col>` —
    // db push writes that as pending, and cutover transitions
    // pending → encrypting → active alongside the physical rename.
    const pending = await client.query<{ exists: boolean }>(
      "SELECT EXISTS(SELECT 1 FROM public.eql_v2_configuration WHERE state = 'pending') AS exists",
    )
    if (pending.rows[0]?.exists !== true) {
      p.log.error(
        'No pending EQL configuration to cut over. Cutover operates on the EQL v2 + CipherStash Proxy config lifecycle — update your schema to point at the encrypted column (drop the `_encrypted` suffix) and register the pending change before cutting over.',
      )
      exitCode = 1
      return
    }

    // Full lifecycle in one transaction:
    //   1. rename_encrypted_columns — physical column rename
    //   2. migrate_config            — pending → encrypting
    //   3. activate_config           — encrypting → active (and prior active → inactive)
    // Each step is a side-effect-free function from the user's POV
    // (everything happens inside the txn). Rollback on any error leaves
    // the system in its pre-cutover state.
    await client.query('BEGIN')
    try {
      await renameEncryptedColumns(client)
      await migrateConfig(client)
      await activateConfig(client)
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
      `Renamed ${options.column} → ${options.column}_plaintext and ${options.column}_encrypted → ${options.column}; pending config promoted to active.`,
    )

    // Drizzle snapshot resync. The rename above ran outside drizzle-kit's
    // authority — the snapshot at `<out>/meta/<idx>_snapshot.json` still
    // describes the pre-rename column shape. If we don't acknowledge the
    // change in Drizzle's metadata, the next `drizzle-kit generate` will
    // produce a confused diff trying to re-create the old layout.
    //
    // Scaffolding a custom migration with idempotent rename SQL solves
    // both problems: it adds the journal entry + snapshot diff that
    // Drizzle expects, and the SQL itself is a no-op on the source DB
    // (the pre-rename column doesn't exist any more) but applies
    // correctly when migrating a fresh database.
    if (detectDrizzle(process.cwd())) {
      try {
        const renameSql = buildRenameMigrationSql(options.table, options.column)
        const result = await scaffoldDrizzleMigration({
          name: `cutover_${options.table}_${options.column}`,
          outDir: options.migrationsDir ?? 'drizzle',
          sql: renameSql,
        })
        p.log.success(
          `Drizzle snapshot updated: ${result.path} (idempotent — no-op on this DB, applies on a fresh restore).`,
        )
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err)
        p.log.warn(
          `Could not scaffold the Drizzle rename migration: ${reason}\nDrizzle's snapshot may be out of sync with the live schema. Run \`drizzle-kit pull\` to resync, or scaffold the rename migration manually.`,
        )
      }
    }

    // Proxy reload runs *after* the cutover transaction has committed.
    // Any error from here on is post-commit cosmetic — the rename and
    // config promotion are durable. Catch the proxy reload separately so
    // a transient Proxy connectivity blip doesn't make the outer catch
    // exit(1), which would falsely tell automation the cutover failed
    // and encourage unsafe retries.
    const proxyUrl = options.proxyUrl ?? process.env.CIPHERSTASH_PROXY_URL
    if (proxyUrl) {
      const proxy = new pg.Client({ connectionString: proxyUrl })
      try {
        await proxy.connect()
        try {
          await reloadConfig(proxy)
          p.log.success('Proxy config reloaded.')
        } catch (err) {
          const reason = err instanceof Error ? err.message : String(err)
          p.log.warn(
            `Proxy config reload failed (${reason}). The cutover itself is committed and durable; Proxy will pick up the new config on its next 60s refresh.`,
          )
        }
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
    exitCode = 1
  } finally {
    await client.end()
  }
  if (exitCode) process.exit(exitCode)
}

/**
 * Build the SQL body for the post-cutover Drizzle migration. Wrapped in a
 * `DO` block that checks whether `<col>_encrypted` still exists — on the
 * source database the rename already ran (so the column is gone and the
 * block does nothing), but on a fresh restore the rename hasn't run yet
 * (so the block performs the swap). Same migration file, both behaviours,
 * idempotent.
 *
 * Splits `schema.table` into separate identifiers so the generated SQL is
 * correct regardless of whether the user passed `users` or `public.users`.
 */
function buildRenameMigrationSql(table: string, column: string): string {
  const dot = table.indexOf('.')
  const [schema, tableName] =
    dot >= 0 ? [table.slice(0, dot), table.slice(dot + 1)] : [null, table]

  const qualified = schema ? `"${schema}"."${tableName}"` : `"${tableName}"`
  const schemaPredicate = schema
    ? `table_schema = '${schema.replace(/'/g, "''")}' AND `
    : ''

  return `-- Generated by stash encrypt cutover.
-- Records the rename that eql_v2.rename_encrypted_columns() performed
-- so Drizzle's snapshot stays in sync. Idempotent: a no-op on the DB
-- where cutover already ran; applies on a fresh restore.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE ${schemaPredicate}table_name = '${tableName.replace(/'/g, "''")}'
      AND column_name = '${column}_encrypted'
  ) THEN
    ALTER TABLE ${qualified} RENAME COLUMN "${column}" TO "${column}_plaintext";
    ALTER TABLE ${qualified} RENAME COLUMN "${column}_encrypted" TO "${column}";
  END IF;
END $$;
`
}
