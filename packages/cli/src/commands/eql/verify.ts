import * as p from '@clack/prompts'
import { emitJsonError, emitJsonEvent } from '@/commands/auth/events.js'
import { resolveDiagnosticDatabaseUrl } from '@/commands/db/resolve-diagnostic-url.js'
import { detectPackageManager, runnerCommand } from '@/commands/init/utils.js'
import type { SurfaceFinding, VerifyReport } from '@/installer/verify.js'
import { verifyEqlSurface } from '@/installer/verify.js'

/**
 * `stash eql verify` — assert the installed EQL surface is complete and
 * coherent, independent of any application schema (#890). A partial install —
 * domains present, some supporting functions or operators absent — reports
 * success at install time and fails at query time on a specific predicate;
 * this is the check that catches it early.
 *
 * ONE exit predicate for both output modes: `report.ok`, true only when the
 * surface was checked and found complete. `not-installed`, `incomplete`, and
 * `version-mismatch` (checked nothing — "could not verify" must never read as
 * "verified") all exit 1. The ORE operator class being absent WITH its
 * loud-failure fallback in place is a supported managed-Postgres
 * configuration and reads as such, not as damage.
 *
 * `--database-url` is a one-shot, like `eql install`'s: it bypasses config
 * loading, so the database the user named is the database that gets judged
 * (see {@link resolveDiagnosticDatabaseUrl}).
 */
export async function verifyCommand(
  options: { databaseUrl?: string; json?: boolean } = {},
): Promise<void> {
  const json = options.json === true

  if (!json) {
    p.intro(runnerCommand(detectPackageManager(), 'stash eql verify'))
  }

  // Resolve the URL before any spinner exists: tier 4 of the resolver is an
  // interactive prompt, and a live spinner would redraw over it.
  const databaseUrl = await resolveDiagnosticDatabaseUrl({
    databaseUrlFlag: options.databaseUrl,
    json,
    flagWins: true,
    verb: 'Verifying',
  })

  const s = json ? null : p.spinner()
  s?.start('Comparing the installed EQL surface with the pinned bundle...')
  let report: VerifyReport
  try {
    report = await verifyEqlSurface(databaseUrl)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    if (json) {
      emitJsonError('verify_failed', message)
    } else {
      s?.stop('Verification failed.')
      p.log.error(message)
      p.outro('Verification failed.')
    }
    process.exit(1)
  }
  s?.stop('Surface compared.')

  if (json) {
    emitJsonEvent({ ...report })
  } else {
    reportVerifyFindings(report)
    switch (report.status) {
      case 'complete':
        p.outro(`EQL ${report.bundleVersion} install is complete.`)
        break
      case 'version-mismatch':
        p.outro('Surface not verified — version mismatch.')
        break
      case 'not-installed':
        p.outro('EQL is not installed.')
        break
      case 'incomplete':
        p.outro('The EQL install is incomplete — see the damage above.')
        break
    }
  }

  if (!report.ok) process.exit(1)
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
