import { discardPendingConfig } from '@cipherstash/migrate'
import type { CastAs, EncryptConfig } from '@cipherstash/stack/schema'
import { toEqlCastAs } from '@cipherstash/stack/schema'
import * as p from '@clack/prompts'
import pg from 'pg'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadEncryptConfig, loadStashConfig } from '@/config/index.js'
import { EQLInstaller } from '@/installer/index.js'
import { validateEncryptConfig } from './validate.js'

/**
 * Transform an EncryptConfig so that all `cast_as` values use EQL-compatible
 * types (e.g. `'number'` → `'double'`, `'string'` → `'text'`, `'json'` → `'jsonb'`).
 */
function toEqlConfig(config: EncryptConfig): Record<string, unknown> {
  const tables: Record<string, Record<string, unknown>> = {}

  for (const [tableName, columns] of Object.entries(config.tables)) {
    const eqlColumns: Record<string, unknown> = {}
    for (const [columnName, column] of Object.entries(columns)) {
      eqlColumns[columnName] = {
        ...column,
        cast_as: toEqlCastAs(column.cast_as as CastAs),
      }
    }
    tables[tableName] = eqlColumns
  }

  return { v: config.v, tables }
}

export async function pushCommand(options: {
  dryRun?: boolean
  databaseUrl?: string
}) {
  p.intro(runnerCommand(detectPackageManager(), 'stash db push'))
  p.log.info(
    'This command pushes the encryption schema to the database for use with CipherStash Proxy.\nIf you are using the SDK directly (Drizzle, Supabase, or plain PostgreSQL), this step is not required.',
  )

  const s = p.spinner()

  s.start('Loading stash.config.ts...')
  const config = await loadStashConfig({ databaseUrlFlag: options.databaseUrl })
  s.stop('Configuration loaded.')

  // `db push` writes the encrypt config into `public.eql_v2_configuration` —
  // a v2 + CipherStash Proxy artifact. EQL v3 has no configuration table
  // (config lives in each column's `eql_v3.*` domain type) and nothing reads
  // it, so on a v3-only database push has nothing to do and the table doesn't
  // even exist. Detect that and exit cleanly instead of failing with a raw
  // `relation "public.eql_v2_configuration" does not exist`.
  const installer = new EQLInstaller({ databaseUrl: config.databaseUrl })
  const [v2Installed, v3Installed] = await Promise.all([
    installer.isInstalled({ eqlVersion: 2 }).catch(() => false),
    installer.isInstalled({ eqlVersion: 3 }).catch(() => false),
  ])
  if (v3Installed && !v2Installed) {
    p.log.info(
      "`stash db push` isn't needed under EQL v3 — encryption config lives in each column's `eql_v3.*` type, not a central config table. This command only applies to EQL v2 with CipherStash Proxy.",
    )
    p.outro('Nothing to do.')
    return
  }

  s.start(`Loading encrypt client from ${config.client}...`)
  const encryptConfig = await loadEncryptConfig(config.client)
  s.stop('Encrypt client loaded and validated.')

  // Run validation as a pre-push check (warn but don't block)
  if (encryptConfig) {
    const issues = validateEncryptConfig(encryptConfig, {})
    if (issues.length > 0) {
      p.log.warn('Schema validation found issues:')
      for (const issue of issues) {
        const logFn =
          issue.severity === 'error'
            ? p.log.error
            : issue.severity === 'warning'
              ? p.log.warn
              : p.log.info
        logFn(`${issue.table}.${issue.column}: ${issue.message}`)
      }
      console.log()
    }
  }

  // Transform SDK types to EQL types for the database
  const eqlConfig = toEqlConfig(encryptConfig)

  if (options.dryRun) {
    p.log.info('Dry run — no changes will be pushed.')
    p.note(JSON.stringify(eqlConfig, null, 2), 'Encryption Schema')
    p.outro('Dry run complete.')
    return
  }

  const client = new pg.Client({ connectionString: config.databaseUrl })
  let exitCode = 0

  try {
    s.start('Connecting to Postgres...')
    await client.connect()
    s.stop('Connected to Postgres.')

    s.start('Checking public.eql_v2_configuration state...')
    const activeResult = await client.query<{ exists: boolean }>(
      "SELECT EXISTS(SELECT 1 FROM public.eql_v2_configuration WHERE state = 'active') AS exists",
    )
    const hasActive = activeResult.rows[0]?.exists === true
    s.stop(
      hasActive
        ? 'Active configuration found.'
        : 'No active configuration yet (first push).',
    )

    if (!hasActive) {
      // First push: nothing to rename, no risk of contention with a live
      // Proxy reading the active config. Insert directly as `active`.
      s.start('Writing initial active configuration...')
      await client.query(
        "INSERT INTO public.eql_v2_configuration (state, data) VALUES ('active', $1)",
        [eqlConfig],
      )
      s.stop('Active configuration written.')
      p.outro('Push complete. Encryption is live.')
      return
    }

    // Active config already exists. Write the new config as `pending` so
    // the EQL state machine (pending → encrypting → active) can mediate
    // the change — the same flow Proxy uses for hot-reloads. The user
    // promotes pending → active by running either `stash encrypt cutover`
    // (when columns need renaming, e.g. `<col>_encrypted` → `<col>`) or
    // `stash db activate` (when the change is purely additive).
    s.start('Replacing pending configuration...')
    await client.query('BEGIN')
    try {
      await discardPendingConfig(client)
      await client.query(
        "INSERT INTO public.eql_v2_configuration (state, data) VALUES ('pending', $1)",
        [eqlConfig],
      )
      await client.query('COMMIT')
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {})
      throw err
    }
    s.stop('Pending configuration written.')

    p.note(
      [
        'A pending configuration is registered but not yet active. The current',
        'active configuration continues to serve reads until you finalise it:',
        '',
        '  stash encrypt cutover --table T --column C',
        '    Renames `<col>_encrypted` → `<col>` (and `<col>` → `<col>_plaintext`),',
        '    then promotes pending → active. Use this when the new config replaces',
        '    a column you migrated via `stash encrypt backfill`.',
        '',
        '  stash db activate',
        '    Promotes pending → active without renaming. Use this when the new',
        '    config purely adds columns or changes index ops on already-active',
        '    columns (no `<col>_encrypted` twin to swap in).',
      ].join('\n'),
      'Next step',
    )
    p.outro('Push complete (pending).')
  } catch (error) {
    s.stop('Failed.')
    p.log.error(
      error instanceof Error ? error.message : 'Failed to push configuration.',
    )
    exitCode = 1
  } finally {
    await client.end()
  }
  if (exitCode) process.exit(exitCode)
}
