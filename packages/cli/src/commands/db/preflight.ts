import * as p from '@clack/prompts'
import { emitJsonError, emitJsonEvent } from '@/commands/auth/events.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { EQLInstaller, type PreflightResult } from '@/installer/index.js'
import { resolveDiagnosticDatabaseUrl } from './resolve-diagnostic-url.js'

/** See {@link resolveDiagnosticDatabaseUrl} — preflight keeps config-wins. */
function resolvePreflightDatabaseUrl(
  databaseUrlFlag: string | undefined,
  json: boolean,
): Promise<string> {
  return resolveDiagnosticDatabaseUrl({
    databaseUrlFlag,
    json,
    flagWins: false,
    verb: 'Probing',
  })
}

/**
 * `stash eql preflight` — read-only "will `eql install` work here, and if not,
 * why" report. Runs the same catalogue query the installer runs at the head of
 * `eql install`, but as a standalone command an operator (or agent, via
 * `--json`) can run before attempting anything.
 *
 * Exit code: 1 when a blocking gap is present (`result.ok === false`), else 0.
 * Membership of `postgres` is reported but never blocks — the installer
 * skips the optional owner-scoped Supabase grants for non-member roles.
 */
export async function preflightCommand(
  options: { databaseUrl?: string; json?: boolean } = {},
): Promise<void> {
  if (options.json) {
    const databaseUrl = await resolvePreflightDatabaseUrl(
      options.databaseUrl,
      true,
    )
    const installer = new EQLInstaller({ databaseUrl })
    let result: PreflightResult
    try {
      result = await installer.preflight()
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      emitJsonError('preflight_failed', message)
      process.exit(1)
    }
    // `status` is the discriminator agents gate on, so blockers must not
    // masquerade as 'ok' — 'blocked' means the probe worked and found gaps.
    emitJsonEvent({ status: result.ok ? 'ok' : 'blocked', ...result })
    if (!result.ok) process.exit(1)
    return
  }

  p.intro(runnerCommand(detectPackageManager(), 'stash eql preflight'))

  // Resolve the URL before any spinner exists: tier 4 of the resolver is an
  // interactive prompt, and a live spinner would redraw over it.
  const databaseUrl = await resolvePreflightDatabaseUrl(
    options.databaseUrl,
    false,
  )

  const s = p.spinner()
  s.start('Probing database role capability...')
  const installer = new EQLInstaller({ databaseUrl })
  let result: PreflightResult
  try {
    result = await installer.preflight()
  } catch (error) {
    s.stop('Preflight failed.')
    p.log.error(error instanceof Error ? error.message : String(error))
    p.outro('Preflight failed.')
    process.exit(1)
  }
  s.stop('Probe complete.')

  p.note(renderPreflightReport(result), 'Database preflight')

  if (!result.ok) {
    p.log.error(
      'The connected role cannot run `stash eql install` on this database:',
    )
    for (const missing of result.missing) p.log.warn(`  - ${missing}`)
    p.outro('Preflight found blockers.')
    process.exit(1)
  }

  if (result.memberOfPostgres !== true) {
    p.log.info(
      'Not a member of `postgres`: in Supabase mode the optional `ALTER DEFAULT PRIVILEGES FOR ROLE postgres` statements are skipped. The install is complete without them — they only cover EQL objects created outside stash tooling, and stash re-grants every object on each install/upgrade.',
    )
  }
  p.outro('This role can install EQL.')
}

/** The human-readable rows, aligned. Exported for unit tests. */
export function renderPreflightReport(result: PreflightResult): string {
  const yesNo = (value: boolean) => (value ? 'yes' : 'no')
  const pgcryptoValue = result.pgcryptoInstalled
    ? `present${result.pgcryptoSchema ? ` (in ${result.pgcryptoSchema})` : ''}`
    : 'absent'
  const pgcryptoUnsupported =
    result.pgcryptoInstalled &&
    result.pgcryptoSchema !== null &&
    !['extensions', 'public'].includes(result.pgcryptoSchema)
  const rows: Array<[string, string, string?]> = [
    ['current_user', result.currentUser],
    ['superuser', yesNo(result.isSuperuser)],
    [
      'member of postgres',
      result.memberOfPostgres === null
        ? 'n/a (no postgres role)'
        : yesNo(result.memberOfPostgres),
      result.memberOfPostgres === false
        ? '<- skips optional: ALTER DEFAULT PRIVILEGES FOR ROLE postgres'
        : undefined,
    ],
    [
      'CREATE on database',
      yesNo(result.hasDatabaseCreate),
      result.hasDatabaseCreate || result.isSuperuser
        ? undefined
        : '<- blocks: CREATE SCHEMA / CREATE EXTENSION',
    ],
    [
      'CREATE on public',
      yesNo(result.hasPublicCreate),
      result.hasPublicCreate || result.isSuperuser
        ? undefined
        : '<- blocks: CREATE DOMAIN public.eql_v3_*',
    ],
    [
      'pgcrypto',
      pgcryptoValue,
      pgcryptoUnsupported
        ? '<- blocks: not on the EQL search_path (ALTER EXTENSION pgcrypto SET SCHEMA extensions)'
        : !result.pgcryptoInstalled &&
            !result.hasDatabaseCreate &&
            !result.isSuperuser
          ? '<- blocks: CREATE EXTENSION pgcrypto'
          : undefined,
    ],
    ['eql_v3 schema', result.eqlV3SchemaPresent ? 'present' : 'absent'],
    [
      'eql_v3_internal',
      result.eqlV3InternalSchemaPresent ? 'present' : 'absent',
    ],
  ]
  // Ownership only matters (and is only known) when a schema already exists:
  // a reinstall opens with DROP SCHEMA ... CASCADE.
  if (
    result.canDropEqlV3Schema !== null ||
    result.canDropEqlV3InternalSchema !== null
  ) {
    const canDrop =
      result.canDropEqlV3Schema !== false &&
      result.canDropEqlV3InternalSchema !== false
    rows.push([
      'can drop EQL schemas',
      yesNo(canDrop),
      canDrop
        ? undefined
        : '<- blocks: reinstall (DROP SCHEMA ... CASCADE needs the owner or a superuser)',
    ])
  }
  const labelWidth = Math.max(...rows.map(([label]) => label.length))
  return rows
    .map(([label, value, annotation]) =>
      [label.padEnd(labelWidth), value, annotation]
        .filter((part): part is string => part !== undefined)
        .join('  '),
    )
    .join('\n')
}
