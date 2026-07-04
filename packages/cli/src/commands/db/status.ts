import * as p from '@clack/prompts'
import pg from 'pg'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadStashConfig } from '@/config/index.js'
import { EQLInstaller } from '@/installer/index.js'

export async function statusCommand(options: { databaseUrl?: string } = {}) {
  const pm = detectPackageManager()
  p.intro(runnerCommand(pm, 'stash eql status'))

  const s = p.spinner()

  s.start('Loading stash.config.ts...')
  const config = await loadStashConfig({ databaseUrlFlag: options.databaseUrl })
  s.stop('Configuration loaded.')

  const installer = new EQLInstaller({
    databaseUrl: config.databaseUrl,
  })

  // 1. Check EQL installation status and version — both generations, so a
  // v3-only database is not misreported as "not installed" (the v2 check
  // only looks for the eql_v2 schema).
  s.start('Checking EQL installation...')

  let installedV2: boolean
  let installedV3: boolean
  let versionV2: string | null
  let versionV3: string | null

  try {
    installedV2 = await installer.isInstalled()
    installedV3 = await installer.isInstalled({ eqlVersion: 3 })
    versionV2 = installedV2 ? await installer.getInstalledVersion() : null
    versionV3 = installedV3
      ? await installer.getInstalledVersion({ eqlVersion: 3 })
      : null
  } catch (error) {
    s.stop('Failed.')
    p.log.error(
      error instanceof Error
        ? error.message
        : 'Failed to check EQL installation status.',
    )
    p.outro('Status check failed.')
    process.exit(1)
  }

  if (installedV2 || installedV3) {
    s.stop('EQL is installed.')
    if (installedV2) {
      p.log.success(
        `EQL v2 installed: yes (version: ${versionV2 ?? 'unknown'})`,
      )
    }
    if (installedV3) {
      p.log.success(
        `EQL v3 installed: yes (version: ${versionV3 ?? 'unknown'})`,
      )
    }
  } else {
    s.stop('EQL is not installed.')
    p.log.warn(
      `EQL is not installed. Run \`${runnerCommand(pm, 'stash eql install')}\` to install it.`,
    )
    p.outro('Status check complete.')
    return
  }

  // 2. Check database permissions
  s.start('Checking database permissions...')

  try {
    const permissions = await installer.checkPermissions()
    s.stop('Permissions checked.')

    if (permissions.ok) {
      p.log.success('Database permissions: OK')
    } else {
      p.log.warn('Database permissions: insufficient')
      for (const missing of permissions.missing) {
        p.log.warn(`  - ${missing}`)
      }
    }
  } catch (error) {
    s.stop('Failed.')
    p.log.error(
      error instanceof Error
        ? error.message
        : 'Failed to check database permissions.',
    )
  }

  // 3. Check for active encrypt config (proxy mode)
  s.start('Checking encrypt configuration...')

  const client = new pg.Client({ connectionString: config.databaseUrl })

  try {
    await client.connect()

    const result = await client.query<{ id: number; state: string }>(
      "SELECT id, state FROM eql_v2_configuration WHERE state = 'active'",
    )

    s.stop('Configuration checked.')

    if (result.rowCount !== null && result.rowCount > 0) {
      p.log.success(
        `Active encrypt config: yes (${result.rowCount} active ${result.rowCount === 1 ? 'row' : 'rows'})`,
      )
    } else {
      p.log.info(
        'Active encrypt config: none (only needed for CipherStash Proxy)',
      )
    }
  } catch (error) {
    s.stop('Configuration check failed.')

    // The table may not exist if push has never been run — that's fine
    const message = error instanceof Error ? error.message : String(error)
    if (message.includes('does not exist')) {
      p.log.info(
        `Active encrypt config: table not found (run \`${runnerCommand(pm, 'stash db push')}\` to create it)`,
      )
    } else {
      p.log.error(`Failed to check encrypt configuration: ${message}`)
    }
  } finally {
    await client.end()
  }

  p.outro('Status check complete.')
}
