import * as p from '@clack/prompts'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadStashConfig } from '@/config/index.js'
import { EQLInstaller, resolveEqlVersion } from '@/installer/index.js'

export async function upgradeCommand(options: {
  dryRun?: boolean
  supabase?: boolean
  excludeOperatorFamily?: boolean
  latest?: boolean
  databaseUrl?: string
  /** EQL generation to upgrade: `'3'` (default) or `'2'`. */
  eqlVersion?: string
}) {
  const pm = detectPackageManager()
  p.intro(runnerCommand(pm, 'stash eql upgrade'))

  if (
    options.eqlVersion !== undefined &&
    options.eqlVersion !== '2' &&
    options.eqlVersion !== '3'
  ) {
    p.log.error(
      `Unknown \`--eql-version ${options.eqlVersion}\`. Supported values: 2, 3.`,
    )
    p.outro('Upgrade aborted.')
    process.exit(1)
  }
  const eqlVersion: 2 | 3 = resolveEqlVersion(options.eqlVersion)

  if (eqlVersion === 3 && options.latest) {
    // `--latest` is v2-only (no public v3 release artifacts exist yet). Since
    // v3 is the default, tell the user how to reach the v2 latest upgrade.
    p.log.error(
      options.eqlVersion === '3'
        ? '`--eql-version 3` does not support `--latest` — no public v3 release artifacts exist yet. Use the bundled upgrade.'
        : '`--latest` requires EQL v2 — no public v3 release artifacts exist yet. Re-run with `--eql-version 2 --latest`, or drop `--latest` for the bundled v3 upgrade.',
    )
    p.outro('Upgrade aborted.')
    process.exit(1)
  }

  const s = p.spinner()

  s.start('Loading stash.config.ts...')
  const config = await loadStashConfig({
    databaseUrlFlag: options.databaseUrl,
    supabase: options.supabase,
  })
  s.stop('Configuration loaded.')

  const installer = new EQLInstaller({
    databaseUrl: config.databaseUrl,
  })

  s.start('Checking current EQL installation...')
  const installed = await installer.isInstalled({ eqlVersion })

  if (!installed) {
    s.stop(`EQL v${eqlVersion} is not installed.`)
    // A version mismatch is the likely cause — point at the generation that
    // IS installed rather than a bare "run install".
    const otherVersion: 2 | 3 = eqlVersion === 3 ? 2 : 3
    const otherInstalled = await installer
      .isInstalled({ eqlVersion: otherVersion })
      .catch(() => false)
    if (otherInstalled) {
      p.log.warn(
        `EQL v${eqlVersion} is not installed, but EQL v${otherVersion} is. Re-run with \`--eql-version ${otherVersion}\`, or install v${eqlVersion} with "${runnerCommand(pm, `stash eql install --eql-version ${eqlVersion}`)}".`,
      )
    } else {
      p.log.warn(
        `EQL is not currently installed. Run "${runnerCommand(pm, 'stash eql install')}" first.`,
      )
    }
    p.outro('Upgrade aborted.')
    process.exit(1)
  }

  const previousVersion = await installer.getInstalledVersion({ eqlVersion })
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
  s.start(
    `Upgrading EQL ${eqlVersion === 3 ? 'v3 ' : ''}extensions (${source})...`,
  )
  await installer.install({
    excludeOperatorFamily: options.excludeOperatorFamily,
    supabase: options.supabase,
    latest: options.latest,
    eqlVersion,
  })
  s.stop('EQL extensions upgraded.')

  if (options.supabase) {
    p.log.success('Supabase role permissions granted.')
  }

  s.start('Verifying new version...')
  const newVersion = await installer.getInstalledVersion({ eqlVersion })
  s.stop(`New version: ${newVersion ?? 'unknown'}`)

  if (previousVersion && newVersion && previousVersion === newVersion) {
    p.log.info('Version unchanged — EQL was already up to date.')
  }

  p.outro('Done!')
}
