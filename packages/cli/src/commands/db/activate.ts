import { activateConfig, migrateConfig } from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import pg from 'pg'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadStashConfig } from '@/config/index.js'

/**
 * `stash db activate` — promote the pending EQL configuration to active
 * **without** renaming any columns.
 *
 * Used after `stash db push` when the new config is purely additive
 * (e.g. registering a brand-new encrypted column on a project that
 * already has an active config) — there are no `<col>_encrypted` twins
 * to rename, so the cut-over rename step is unnecessary.
 *
 * For path 3 (existing populated column → encrypted via lifecycle), use
 * `stash encrypt cutover` instead. Cutover does the same activation but
 * also runs the physical rename.
 *
 * Mechanics: chains `eql_v2.migrate_config()` (pending → encrypting) and
 * `eql_v2.activate_config()` (encrypting → active) inside a single
 * transaction. Errors out clearly when there is no pending config to
 * activate.
 */
export interface ActivateCommandOptions {
  databaseUrl?: string
}

export async function activateCommand(
  options: ActivateCommandOptions,
): Promise<void> {
  p.intro(runnerCommand(detectPackageManager(), 'stash db activate'))

  const stashConfig = await loadStashConfig({
    databaseUrlFlag: options.databaseUrl,
  })
  const client = new pg.Client({ connectionString: stashConfig.databaseUrl })
  let exitCode = 0

  try {
    await client.connect()

    const pending = await client.query<{ exists: boolean }>(
      "SELECT EXISTS(SELECT 1 FROM public.eql_v2_configuration WHERE state = 'pending') AS exists",
    )
    if (pending.rows[0]?.exists !== true) {
      p.log.error(
        'No pending EQL configuration to activate. Run `stash db push` first to register a change.',
      )
      exitCode = 1
      return
    }

    await client.query('BEGIN')
    try {
      await migrateConfig(client)
      await activateConfig(client)
      await client.query('COMMIT')
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {})
      throw err
    }

    p.log.success('Pending configuration promoted to active.')
    p.outro('Done.')
  } catch (error) {
    p.log.error(error instanceof Error ? error.message : 'Activation failed.')
    exitCode = 1
  } finally {
    await client.end()
  }
  if (exitCode) process.exit(exitCode)
}
