import { resolveDatabaseUrl } from '@/config/database-url.js'
import { loadStashConfig } from '@/config/index.js'
import { EQLInstaller } from '@/installer/index.js'
import * as p from '@clack/prompts'
import pg from 'pg'

export async function statusCommand(options: { databaseUrl?: string } = {}) {
  p.intro('npx @cipherstash/cli db status')

  await resolveDatabaseUrl({ databaseUrlFlag: options.databaseUrl })

  const s = p.spinner()

  s.start('Loading stash.config.ts...')
  const config = await loadStashConfig()
  s.stop('Configuration loaded.')

  const installer = new EQLInstaller({
    databaseUrl: config.databaseUrl,
  })

  // 1. Check EQL installation status and version
  s.start('Checking EQL installation...')

  let installed: boolean
  let version: string | null

  try {
    installed = await installer.isInstalled()
    version = installed ? await installer.getInstalledVersion() : null
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

  if (installed) {
    s.stop('EQL is installed.')
    p.log.success(`EQL installed: yes (version: ${version ?? 'unknown'})`)
  } else {
    s.stop('EQL is not installed.')
    p.log.warn(
      'EQL is not installed. Run `npx @cipherstash/cli db install` to install it.',
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
        'Active encrypt config: table not found (run `npx @cipherstash/cli db push` to create it)',
      )
    } else {
      p.log.error(`Failed to check encrypt configuration: ${message}`)
    }
  } finally {
    await client.end()
  }

  p.outro('Status check complete.')
}
