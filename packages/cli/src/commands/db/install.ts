import { installMigrationsSchema } from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import { resolveDatabaseUrl } from '@/config/database-url.js'
import { findConfigFile, loadStashConfig } from '@/config/index.js'
import { createPgClient } from '@/db/client.js'
import { EQLInstaller } from '@/installer/index.js'
import { assessEqlInstallation } from '@/installer/installation-state.js'
import { describeOreState } from '@/installer/ore.js'
import type { VerifyReport } from '@/installer/verify.js'
import { messages } from '@/messages.js'
import { detectPackageManager, runnerCommand } from '../init/utils.js'
import { ensureEncryptionClient } from './client-scaffold.js'
import { offerStashConfig } from './config-scaffold.js'
import { detectPrismaNext, detectSupabase } from './detect.js'
import { reportSupabaseGrantsOutcome } from './grants-report.js'

export const SAFE_MIGRATION_NAME = /^[\w-]+$/

export const EQL_V2_RELEASE_URL =
  'https://github.com/cipherstash/encrypt-query-language/releases/tag/eql-2.3.1'

export interface InstallOptions {
  force?: boolean
  dryRun?: boolean
  supabase?: boolean
  databaseUrl?: string
  scaffoldConfig?: 'ensure' | 'offer' | 'skip'
}

/** Recognise removed argv before any I/O instead of silently ignoring it. */
export function validateInstallFlags(
  options: Record<string, unknown>,
): string | null {
  if (options.eqlVersion === '2' || options.latest === true) {
    return `EQL v2 installation has been removed from stash. To recover or restore an existing EQL v2 database dump, download the EQL 2.3.1 SQL from ${EQL_V2_RELEASE_URL}. New installs use EQL v3.`
  }
  if (options.eqlVersion !== undefined) {
    return '`--eql-version` has been removed. EQL v3 is now the only installable generation; remove the flag.'
  }
  if (
    options.drizzle === true ||
    options.name !== undefined ||
    options.out !== undefined
  ) {
    return '`eql install --drizzle` has been removed. Generate an EQL v3 Drizzle migration with `stash eql migration --drizzle` (and pass --name/--out there).'
  }
  if (options.migration === true || options.migrationsDir !== undefined) {
    return '`eql install --migration` has been removed. Use `stash eql migration` to keep the EQL v3 install in migration history: `--supabase` writes into supabase/migrations/, `--drizzle` emits a Drizzle migration (add `--supabase` there for the role grants). Pass the target directory as `--out`.'
  }
  if (options.direct === true) {
    return '`--direct` has been removed because `stash eql install` is now always a direct EQL v3 install.'
  }
  if (options.excludeOperatorFamily === true) {
    return '`--exclude-operator-family` has been removed. The pinned EQL v3 bundle self-adapts when the database role cannot create its optional operator family.'
  }
  return null
}

async function resolveInstallContext(
  options: InstallOptions,
  s: ReturnType<typeof p.spinner>,
): Promise<{ databaseUrl: string; clientPath: string | null }> {
  const mode = options.scaffoldConfig ?? 'offer'
  const configPath = mode === 'skip' ? null : findConfigFile(process.cwd())
  if (configPath) {
    s.start('Loading stash.config.ts...')
    const config = await loadStashConfig(
      {
        databaseUrlFlag: options.databaseUrl,
        supabase: options.supabase,
      },
      configPath,
    )
    s.stop('Configuration loaded.')
    if (
      options.databaseUrl !== undefined &&
      config.databaseUrl !== options.databaseUrl.trim()
    ) {
      p.log.warn(
        `Ignoring --database-url: ${configPath} sets an explicit databaseUrl that takes precedence. Installing against the config's database.`,
      )
    }
    return { databaseUrl: config.databaseUrl, clientPath: config.client }
  }

  const databaseUrl = await resolveDatabaseUrl({
    databaseUrlFlag: options.databaseUrl,
    supabase: options.supabase,
  })
  if (mode === 'skip' || options.dryRun) {
    return { databaseUrl, clientPath: null }
  }
  const clientPath = await offerStashConfig({ ensure: mode === 'ensure' })
  return { databaseUrl, clientPath }
}

export type InstallOutcome = 'installed' | 'already-installed' | 'dry-run'

export async function installCommand(
  options: InstallOptions,
): Promise<InstallOutcome> {
  p.intro(runnerCommand(detectPackageManager(), 'stash eql install'))
  const flagError = validateInstallFlags(options)
  if (flagError) {
    p.log.error(flagError)
    p.outro('Installation aborted.')
    process.exit(1)
  }

  const prismaNextBlock = prismaNextInstallGuard(process.cwd(), options)
  if (prismaNextBlock) {
    p.log.error(prismaNextBlock)
    p.outro('Installation aborted.')
    process.exit(1)
  }

  const s = p.spinner()
  const { databaseUrl, clientPath } = await resolveInstallContext(options, s)
  if (clientPath && !options.dryRun) {
    ensureEncryptionClient(clientPath, process.cwd(), databaseUrl)
  }

  const supabase =
    options.supabase === undefined
      ? detectSupabase(databaseUrl)
      : options.supabase
  if (options.supabase === undefined && supabase) {
    p.log.info(
      'Detected Supabase database from DATABASE_URL — enabling --supabase.',
    )
  }

  if (options.dryRun) {
    p.log.info('Dry run — no changes will be made.')
    p.note(
      'Would use the pinned EQL v3 install SQL\nWould execute the SQL against the database',
      'Dry Run',
    )
    p.outro('Dry run complete.')
    return 'dry-run'
  }

  const installer = new EQLInstaller({ databaseUrl })
  s.start('Checking database permissions...')
  const installation = await assessEqlInstallation({
    databaseUrl,
    includeCapabilities: true,
  })
  if (installation.capabilities.status !== 'assessed') {
    throw new Error('Database capabilities were not assessed')
  }
  const permissions = installation.capabilities.preflight
  if (!permissions.ok) {
    s.stop('Insufficient database permissions.')
    p.log.error('The connected database role is missing required permissions:')
    for (const missing of permissions.missing) p.log.warn(`  - ${missing}`)
    p.outro('Installation aborted.')
    process.exit(1)
  } else if (!permissions.isSuperuser && !supabase) {
    s.stop(
      'Database permissions verified. The EQL v3 bundle will self-skip optional operator classes this role cannot create.',
    )
  } else {
    s.stop('Database permissions verified.')
  }
  if (supabase && permissions.memberOfPostgres !== true) {
    p.log.info(
      `The connected role (${permissions.currentUser}) is not a member of \`postgres\`, so the optional \`ALTER DEFAULT PRIVILEGES FOR ROLE postgres\` statements will be skipped. The install proceeds and is complete without them — stash re-grants every object on each install/upgrade.`,
    )
  }

  if (!options.force) {
    s.start('Checking if EQL is already installed...')
    const installed = installation.v3.status === 'installed'
    s.stop(installed ? 'EQL is already installed.' : 'EQL is not installed.')
    if (installed) {
      // Re-apply the grants even when the bundle is present: since the bundle
      // commits before the grants run, a grants failure leaves an installed-
      // but-ungranted database, and a plain re-run must heal it rather than
      // early-exit past it. Idempotent, a handful of statements.
      if (supabase) {
        s.start('Re-applying Supabase role grants...')
        const grantsResult = await installer.applySupabaseGrants()
        s.stop('Supabase role grants applied.')
        reportSupabaseGrantsOutcome(grantsResult)
      }
      // isInstalled() is a schemas-exist presence test, so this path is
      // exactly where a partial install would otherwise slip through: install
      // commits, verify fails, and the natural retry — a plain re-run without
      // --force — used to print "Nothing to do." and exit 0 on the very
      // database it just called damaged. Verify here too.
      await verifySurfaceOrExit(databaseUrl, s, {
        remedy:
          'The existing install is incomplete — queries against the missing objects will fail. Re-run with `stash eql install --force` to reinstall the bundle.',
      })
      p.log.info('Use --force to re-run the install script.')
      p.outro('Nothing to do.')
      return 'already-installed'
    }
  }

  s.start('Installing EQL v3 extensions (pinned bundle)...')
  const installResult = await installer.install({ supabase })
  s.stop('EQL extensions installed.')
  if (supabase) reportSupabaseGrantsOutcome(installResult)

  // #890: an install can commit and still be incomplete at query time (the
  // bundle's own conditional paths, platform quirks, concurrent DDL). Verify
  // the surface against the pinned bundle before declaring success — the
  // check is a handful of read-only catalog queries.
  await verifySurfaceOrExit(databaseUrl, s, {
    remedy:
      'Queries against the missing objects will fail. Re-run `stash eql install --force`, and if this persists, please report it: https://github.com/cipherstash/stack/issues',
  })

  s.start('Installing cs_migrations tracking schema...')
  const migrationsDb = createPgClient(databaseUrl)
  try {
    await migrationsDb.connect()
    await installMigrationsSchema(migrationsDb)
    s.stop('cs_migrations schema installed.')
  } catch (err) {
    s.stop('Failed to install cs_migrations schema.')
    p.log.warn(
      err instanceof Error
        ? err.message
        : 'Encryption migration tracking is unavailable; `stash encrypt` commands will fail until this is resolved.',
    )
  } finally {
    await migrationsDb.end()
  }

  printNextSteps()
  p.outro('Done!')
  return 'installed'
}

/**
 * The #890 surface check, shared by the fresh-install tail and the
 * already-installed path. Exits 1 on damage; a verification ERROR (the
 * database dropped the connection, a timeout) is a warning, not a failure —
 * the install itself is committed, and `stash eql verify` can re-check later.
 *
 * Exported for the unit suite only — the command surface is `installCommand`.
 */
export async function verifySurfaceOrExit(
  databaseUrl: string,
  s: ReturnType<typeof p.spinner>,
  options: { remedy: string },
): Promise<void> {
  s.start('Verifying the installed EQL surface...')
  let report: VerifyReport
  try {
    const installation = await assessEqlInstallation({
      databaseUrl,
      depth: 'exhaustive',
    })
    if (installation.surface.status === 'not-requested') {
      throw new Error('Exhaustive EQL assessment returned no surface result')
    }
    report = installation.surface.report
  } catch (err) {
    s.stop('Could not verify the installed EQL surface.')
    p.log.warn(
      `${err instanceof Error ? err.message : String(err)} — run \`stash eql verify\` to check the install later.`,
    )
    return
  }
  if (report.status === 'version-mismatch') {
    // `ok: false`, but NOT damage: the pinned bundle is the wrong manifest to
    // diff against, so nothing was actually checked. `stash eql verify` stays
    // strict about that (exit 1 — could-not-verify must never gate as
    // verified), but a no-op `eql install` re-run over an older EQL was exit 0
    // before verification existed, and idempotent provisioning scripts depend
    // on that. Warn with the skew and the remedy, and carry on.
    s.stop(
      'Installed EQL version differs from the pinned bundle — surface not verified.',
    )
    const mismatch = report.findings[0]?.message
    if (mismatch) p.log.warn(mismatch)
    return
  }
  if (report.ok) {
    s.stop('EQL surface verified — install is complete.')
    // Reported once, here, rather than left to surface as a failing predicate
    // the first time someone casts a column (#891). `eql status` and
    // `eql verify` say the same thing later, so the answer is recoverable.
    if (report.ore?.state === 'fallback') {
      p.log.info(describeOreState('fallback').message)
    }
    return
  }
  s.stop('The installed EQL surface is incomplete.')
  const { reportVerifyFindings } = await import('../eql/verify.js')
  reportVerifyFindings(report)
  p.log.error(options.remedy)
  p.outro('Installation incomplete.')
  process.exit(1)
}

export function prismaNextInstallGuard(
  cwd: string,
  options: Pick<InstallOptions, 'force'>,
): string | null {
  if (options.force || !detectPrismaNext(cwd)) return null
  return (
    `${messages.eql.prismaNextDetected} (found prisma-next.config.* or @cipherstash/stack-prisma). ` +
    'Prisma Next installs the EQL bundle through its own migration system — run ' +
    '`prisma-next migrate` instead of `stash eql install`. ' +
    'Pass --force to run the standalone installer against this database anyway.'
  )
}

export function printNextSteps(): void {
  p.note(
    [
      'Your project is set up. To encrypt your first column, pick the path',
      'that fits and ask your agent (the one `stash init` handed off to,',
      'or whichever agent you use):',
      '',
      '  Migrate an existing populated column (preserves live data):',
      '    Ask: "Use the stash lifecycle to encrypt <table>.<column>."',
      '',
      '  Add a new encrypted column from scratch (no plaintext predecessor):',
      '    Ask: "Add an encrypted <column> to <table>."',
      '',
      'The agent will edit your schema, generate the migration, wire the',
      'application code, and run the relevant `stash encrypt` commands.',
      'Reference: the stash-encryption / stash-cli skills (loaded in your',
      "agent's workspace) and https://cipherstash.com/docs.",
    ].join('\n'),
    'What next',
  )
}
