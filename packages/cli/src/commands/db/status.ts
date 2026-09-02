import * as p from '@clack/prompts'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { loadStashConfig } from '@/config/index.js'
import { createPgClient } from '@/db/client.js'
import { assessEqlInstallation } from '@/installer/installation-state.js'
import { describeOreState } from '@/installer/ore.js'

export async function statusCommand(options: { databaseUrl?: string } = {}) {
  const pm = detectPackageManager()
  p.intro(runnerCommand(pm, 'stash eql status'))

  const s = p.spinner()

  s.start('Loading stash.config.ts...')
  const config = await loadStashConfig({ databaseUrlFlag: options.databaseUrl })
  s.stop('Configuration loaded.')

  // 1. Check EQL installation status and version — both generations, so a
  // v3-only database is not misreported as "not installed" (the v2 check
  // only looks for the eql_v2 schema).
  s.start('Checking EQL installation...')

  let installation: Awaited<ReturnType<typeof assessEqlInstallation>>

  try {
    installation = await assessEqlInstallation({
      databaseUrl: config.databaseUrl,
      includeOre: true,
    })
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

  const installedV2 = installation.v2.status === 'installed'
  const installedV3 = installation.v3.status === 'installed'
  if (installedV2 || installedV3) {
    s.stop('EQL is installed.')
    if (installedV2) {
      p.log.success(
        `EQL v2 installed: yes (version: ${installation.v2.status === 'installed' ? installation.v2.version : 'unknown'})`,
      )
    }
    if (installedV3) {
      p.log.success(
        `EQL v3 installed: yes (version: ${installation.v3.status === 'installed' ? installation.v3.version : 'unknown'})`,
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
    const capabilityAssessment = await assessEqlInstallation({
      databaseUrl: config.databaseUrl,
      includeCapabilities: true,
    })
    if (capabilityAssessment.capabilities.status !== 'assessed') {
      throw new Error('Database capabilities were not assessed')
    }
    const permissions = capabilityAssessment.capabilities.preflight
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

  // 3. The ORE half of the install.
  //
  // Reported here so the trade an operator was told about at install time is
  // recoverable afterwards, without re-reading scrollback (#891). Only when
  // v3 is installed: the state is a property of the v3 bundle's conditional
  // half, and reads as 'fallback' on a database that has no EQL at all.
  if (installedV3) {
    s.start('Checking ORE operator class...')
    const ore = installation.ore
    s.stop('ORE state checked.')
    if (ore.status === 'observed') {
      const described = describeOreState(ore.state)
      if (described.severity === 'damage') {
        p.log.error(described.message)
      } else {
        p.log.info(described.message)
      }
    } else if (ore.status === 'not-comparable') {
      // Version skew is not damage, and must not be rendered as any ORE
      // answer at all: the domain list the poison CHECKs are counted over is
      // the PINNED bundle's, so a perfectly healthy fallback install of an
      // older EQL classifies as incoherent and would send this operator to
      // `install --force` over nothing. Say the true thing instead.
      p.log.info(
        `ORE operator class: not compared — EQL ${
          ore.installedVersion ?? 'unknown'
        } is installed and this CLI pins EQL ${ore.bundleVersion}, so the ORE state cannot be read against the pinned bundle. Run \`${runnerCommand(pm, 'stash eql upgrade')}\`, then check status again.`,
      )
    } else if (ore.status === 'unavailable') {
      p.log.warn(`Could not read the ORE operator class state: ${ore.message}`)
    }
  }

  // 4. Encrypt configuration.
  //
  // `public.eql_v2_configuration` is a v2 + CipherStash Proxy artifact: the v2
  // install creates it and Proxy reads it. EQL v3 has no configuration table —
  // encryption config lives in each column's `eql_v3.*` domain type — so on a
  // v3-only install there's nothing to probe. Gate the check on v2 being
  // installed; this also avoids probing a table that does not apply to v3.
  if (!installedV2) {
    p.log.info(
      "Encrypt config: carried in each column's `eql_v3.*` type (EQL v3 has no Proxy config table).",
    )
    p.outro('Status check complete.')
    return
  }

  s.start('Checking encrypt configuration...')

  const client = createPgClient(config.databaseUrl)

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
      p.log.info('Active encrypt config: none (only used by CipherStash Proxy)')
    }
  } catch (error) {
    s.stop('Configuration check failed.')
    const message = error instanceof Error ? error.message : String(error)
    p.log.error(`Failed to check encrypt configuration: ${message}`)
  } finally {
    await client.end()
  }

  p.outro('Status check complete.')
}
