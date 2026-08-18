import * as p from '@clack/prompts'
import { emitJsonError, emitJsonEvent } from '@/commands/auth/events.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import { resolveDatabaseUrl } from '@/config/database-url.js'
import { findConfigFile, loadStashConfig } from '@/config/index.js'
import type { SurfaceFinding, VerifyReport } from '@/installer/verify.js'
import { verifyEqlSurface } from '@/installer/verify.js'

/**
 * `stash eql verify` — assert the installed EQL surface is complete and
 * coherent, independent of any application schema (#890). A partial install —
 * domains present, some supporting functions or operators absent — reports
 * success at install time and fails at query time on a specific predicate;
 * this is the check that catches it early.
 *
 * Exit code: 1 when the install is damaged or absent (`status` of
 * `incomplete` or `not-installed`), else 0. The ORE operator class being
 * absent WITH its loud-failure fallback in place is a supported
 * managed-Postgres configuration and reads as such, not as damage.
 */
export async function verifyCommand(
  options: { databaseUrl?: string; json?: boolean } = {},
): Promise<void> {
  if (options.json) {
    const databaseUrl = await resolveVerifyDatabaseUrl(
      options.databaseUrl,
      true,
    )
    let report: VerifyReport
    try {
      report = await verifyEqlSurface(databaseUrl)
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      emitJsonError('verify_failed', message)
      process.exit(1)
    }
    emitJsonEvent({ ...report })
    if (!report.ok) process.exit(1)
    return
  }

  p.intro(runnerCommand(detectPackageManager(), 'stash eql verify'))

  // Resolve the URL before any spinner exists: tier 4 of the resolver is an
  // interactive prompt, and a live spinner would redraw over it.
  const databaseUrl = await resolveVerifyDatabaseUrl(options.databaseUrl, false)

  const s = p.spinner()
  s.start('Comparing the installed EQL surface with the pinned bundle...')
  let report: VerifyReport
  try {
    report = await verifyEqlSurface(databaseUrl)
  } catch (error) {
    s.stop('Verification failed.')
    p.log.error(error instanceof Error ? error.message : String(error))
    p.outro('Verification failed.')
    process.exit(1)
  }
  s.stop('Surface compared.')

  reportVerifyFindings(report)

  switch (report.status) {
    case 'complete':
      p.outro(`EQL ${report.bundleVersion} install is complete.`)
      return
    case 'version-mismatch':
      p.outro('Surface not verified — version mismatch.')
      return
    case 'not-installed':
      p.outro('EQL is not installed.')
      process.exit(1)
      break
    case 'incomplete':
      p.outro('The EQL install is incomplete — see the damage above.')
      process.exit(1)
  }
}

/**
 * Like preflight, verify must work without a stash.config.ts — fall back to
 * the plain DATABASE_URL resolution chain. In json mode the resolver keeps
 * stdout parseable (quiet chrome, shared error envelope).
 */
async function resolveVerifyDatabaseUrl(
  databaseUrlFlag: string | undefined,
  json: boolean,
): Promise<string> {
  const configPath = findConfigFile(process.cwd())
  if (configPath) {
    const config = await loadStashConfig(
      { databaseUrlFlag, quiet: json, jsonErrors: json },
      configPath,
    )
    if (
      databaseUrlFlag !== undefined &&
      config.databaseUrl !== databaseUrlFlag.trim()
    ) {
      const warning = `Ignoring --database-url: ${configPath} sets an explicit databaseUrl that takes precedence. Verifying the config's database.`
      if (json) {
        process.stderr.write(`${warning}\n`)
      } else {
        p.log.warn(warning)
      }
    }
    return config.databaseUrl
  }
  return resolveDatabaseUrl({
    databaseUrlFlag,
    quiet: json,
    jsonErrors: json,
  })
}

/**
 * Render a report: the counts note, then damage grouped per-domain — the
 * shape the failure arrives in ("`weight >= x` errored") is per-domain, so
 * the diagnosis should be too. Exported for reuse by `eql install`'s
 * post-install verification.
 */
export function reportVerifyFindings(report: VerifyReport): void {
  if (report.counts) {
    p.note(renderSurfaceCounts(report), 'EQL surface')
  }

  const damage = report.findings.filter(
    (finding) => finding.severity === 'damage',
  )
  for (const finding of report.findings) {
    if (finding.severity === 'warning') p.log.warn(finding.message)
    if (finding.severity === 'expected') p.log.info(finding.message)
  }
  if (damage.length === 0) return

  for (const [domain, messages] of groupByDomain(damage)) {
    const capped = messages.slice(0, 10)
    const more =
      messages.length > capped.length
        ? [`… and ${messages.length - capped.length} more`]
        : []
    p.log.error(
      [domain === undefined ? 'install-wide:' : `${domain}:`]
        .concat([...capped, ...more].map((message) => `  - ${message}`))
        .join('\n'),
    )
  }
}

function groupByDomain(
  damage: SurfaceFinding[],
): Map<string | undefined, string[]> {
  const groups = new Map<string | undefined, string[]>()
  for (const finding of damage) {
    const existing = groups.get(finding.domain) ?? []
    existing.push(finding.message)
    groups.set(finding.domain, existing)
  }
  return groups
}

/** The aligned counts rows. Exported for unit tests. */
export function renderSurfaceCounts(report: VerifyReport): string {
  const { counts, ore } = report
  if (!counts || !ore) return ''
  const rows: Array<[string, string]> = [
    ['installed version', report.installedVersion ?? 'missing'],
    ['pinned bundle', report.bundleVersion],
    ...(['domains', 'types', 'functions', 'operators', 'casts'] as const).map(
      (kind): [string, string] => {
        const { expected, present } = counts[kind]
        return [
          kind,
          `${present}/${expected}${present === expected ? '' : '  <- incomplete'}`,
        ]
      },
    ),
    [
      'ORE operator class',
      ore.state === 'indexable'
        ? 'present'
        : ore.state === 'fallback'
          ? 'skipped (expected on managed Postgres)'
          : 'INCOHERENT',
    ],
  ]
  const labelWidth = Math.max(...rows.map(([label]) => label.length))
  return rows
    .map(([label, value]) => `${label.padEnd(labelWidth)}  ${value}`)
    .join('\n')
}
