import * as p from '@clack/prompts'
import { CliExit } from '@/cli/exit.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadStashConfig } from '@/config/index.js'
import { EqlReinstallRefusalError } from '@/installer/derived-search-index-restoration.js'
import { EQLInstaller } from '@/installer/index.js'
import { assessEqlInstallation } from '@/installer/installation-state.js'
import { reportSupabaseGrantsOutcome } from './grants-report.js'

export async function upgradeCommand(options: {
  dryRun?: boolean
  supabase?: boolean
  databaseUrl?: string
}) {
  const pm = detectPackageManager()
  p.intro(runnerCommand(pm, 'stash eql upgrade'))
  const s = p.spinner()

  s.start('Loading stash.config.ts...')
  const config = await loadStashConfig({
    databaseUrlFlag: options.databaseUrl,
    supabase: options.supabase,
  })
  s.stop('Configuration loaded.')

  const installer = new EQLInstaller({ databaseUrl: config.databaseUrl })
  s.start('Checking current EQL v3 installation...')
  const before = await assessEqlInstallation({
    databaseUrl: config.databaseUrl,
  })
  if (before.v3.status === 'absent') {
    s.stop('EQL v3 is not installed.')
    p.log.warn(
      `EQL v3 is not currently installed. Run "${runnerCommand(pm, 'stash eql install')}" first.`,
    )
    p.outro('Upgrade aborted.')
    process.exit(1)
  }

  const previousVersion =
    before.v3.version === 'unknown' ? null : before.v3.version
  s.stop(`Current version: ${previousVersion ?? 'unknown'}`)
  if (options.dryRun) {
    p.log.info('Dry run — no changes will be made.')
    p.note(
      `Current version: ${previousVersion ?? 'unknown'}\nWould re-run the pinned EQL v3 install SQL against the database`,
      'Dry Run',
    )
    p.outro('Dry run complete.')
    return
  }

  s.start('Upgrading EQL v3 extensions (pinned bundle)...')
  let result: Awaited<ReturnType<EQLInstaller['install']>>
  try {
    result = await installer.install({ supabase: options.supabase })
  } catch (error) {
    s.stop('EQL upgrade failed.')
    if (error instanceof EqlReinstallRefusalError) {
      p.log.error(error.message)
      p.outro('Upgrade aborted.')
      throw new CliExit(1)
    }
    throw error
  }
  s.stop('EQL extensions upgraded.')
  if (options.supabase) reportSupabaseGrantsOutcome(result)

  s.start('Verifying new version...')
  const after = await assessEqlInstallation({ databaseUrl: config.databaseUrl })
  const newVersion =
    after.v3.status === 'installed' && after.v3.version !== 'unknown'
      ? after.v3.version
      : null
  s.stop(`New version: ${newVersion ?? 'unknown'}`)
  if (previousVersion && newVersion && previousVersion === newVersion) {
    p.log.info('Version unchanged — EQL was already up to date.')
  }
  p.outro('Done!')
}
