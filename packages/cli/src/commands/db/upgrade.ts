import { resolveDatabaseUrl } from '@/config/database-url.js'
import { loadStashConfig } from '@/config/index.js'
import { EQLInstaller } from '@/installer/index.js'
import * as p from '@clack/prompts'

export async function upgradeCommand(options: {
  dryRun?: boolean
  supabase?: boolean
  excludeOperatorFamily?: boolean
  latest?: boolean
  databaseUrl?: string
}) {
  p.intro('npx @cipherstash/cli db upgrade')

  await resolveDatabaseUrl({
    databaseUrlFlag: options.databaseUrl,
    supabase: options.supabase,
  })

  const s = p.spinner()

  s.start('Loading stash.config.ts...')
  const config = await loadStashConfig()
  s.stop('Configuration loaded.')

  const installer = new EQLInstaller({
    databaseUrl: config.databaseUrl,
  })

  s.start('Checking current EQL installation...')
  const installed = await installer.isInstalled()

  if (!installed) {
    s.stop('EQL is not installed.')
    p.log.warn(
      'EQL is not currently installed. Run "npx @cipherstash/cli db install" first.',
    )
    p.outro('Upgrade aborted.')
    process.exit(1)
  }

  const previousVersion = await installer.getInstalledVersion()
  s.stop(`Current version: ${previousVersion ?? 'unknown'}`)

  if (options.dryRun) {
    p.log.info('Dry run — no changes will be made.')
    const source = options.latest
      ? 'Would download EQL install script from GitHub (latest)'
      : 'Would re-run bundled EQL install script'
    p.note(
      `Current version: ${previousVersion ?? 'unknown'}\n${source}\nWould execute the SQL against the database`,
      'Dry Run',
    )
    p.outro('Dry run complete.')
    return
  }

  const source = options.latest ? 'from GitHub (latest)' : 'bundled'
  s.start(`Upgrading EQL extensions (${source})...`)
  await installer.install({
    excludeOperatorFamily: options.excludeOperatorFamily,
    supabase: options.supabase,
    latest: options.latest,
  })
  s.stop('EQL extensions upgraded.')

  if (options.supabase) {
    p.log.success('Supabase role permissions granted.')
  }

  s.start('Verifying new version...')
  const newVersion = await installer.getInstalledVersion()
  s.stop(`New version: ${newVersion ?? 'unknown'}`)

  if (previousVersion && newVersion && previousVersion === newVersion) {
    p.log.info('Version unchanged — EQL was already up to date.')
  }

  p.outro('Done!')
}
