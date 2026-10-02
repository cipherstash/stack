import { existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import * as p from '@clack/prompts'
import { CliExit } from '@/cli/exit.js'
import {
  type RewriteResult,
  rewriteEncryptedAlterColumns,
} from '@/commands/db/rewrite-migrations.js'
import {
  DEFAULT_MIGRATIONS_RELATION,
  isValidRelation,
  LEDGER_ABSENT,
  latestAppliedMillis,
  NOTHING_APPLIED,
} from '@/commands/eql/applied.js'
import {
  type JournalEntry,
  JournalError,
  readJournal,
} from '@/commands/eql/journal.js'
import {
  reportSkipped,
  reportSweepFailure,
  reportSweepResult,
} from '@/commands/eql/sweep-report.js'
import { resolveDatabaseUrl } from '@/config/database-url.js'
import { messages } from '@/messages.js'

/** Same default as `eql migration --drizzle`, and as drizzle-kit's own `out`. */
const DEFAULT_DRIZZLE_OUT = 'drizzle'

export interface EqlRepairOptions {
  /** Repair a Drizzle output directory. Required — mirrors `eql migration`. */
  drizzle?: boolean
  /** Directory holding the migrations. Defaults to `drizzle`. */
  out?: string
  /** Report what would be rewritten without writing anything. */
  dryRun?: boolean
  /**
   * Database to check applied state against. Without it (and without
   * `DATABASE_URL`) the repair proceeds, warning that it could not verify.
   */
  databaseUrl?: string
  /**
   * The drizzle migration ledger to read applied state from, as
   * `[schema.]table`. Defaults to drizzle-kit's own
   * `drizzle.__drizzle_migrations`; set it to match `migrations.table` /
   * `migrations.schema` in drizzle.config.ts when the project overrides them.
   */
  migrationsTable?: string
}

/**
 * `stash eql repair` — sweep an existing migration directory for the un-runnable
 * in-place `ALTER COLUMN ... SET DATA TYPE <encrypted domain>` statements
 * drizzle-kit emits, and rewrite them into a staged encrypted-column addition.
 */
export async function eqlRepairCommand(
  options: EqlRepairOptions,
): Promise<void> {
  if (!options.drizzle) {
    p.log.error(messages.eql.repairNeedsTarget)
    throw new CliExit(1)
  }

  // Before anything else: a malformed ledger name must not reach the probe,
  // where its "relation does not exist" would masquerade as an absent ledger.
  const relation = options.migrationsTable ?? DEFAULT_MIGRATIONS_RELATION
  if (!isValidRelation(relation)) {
    p.log.error(messages.eql.repairMigrationsTableInvalid(relation))
    throw new CliExit(1)
  }

  const outDir = resolve(options.out ?? DEFAULT_DRIZZLE_OUT)

  // Fail closed on a directory that isn't there. `rewriteEncryptedAlterColumns`
  // treats ENOENT as an empty sweep, which is right for a generate-time sweep
  // but wrong here: a repair that reports "nothing to repair" for a mistyped
  // --out sends the user to `drizzle-kit migrate` with the broken SQL intact.
  if (!existsSync(outDir)) {
    p.log.error(messages.eql.repairOutMissing(outDir))
    throw new CliExit(1)
  }

  let journal: JournalEntry[]
  try {
    journal = await readJournal(outDir)
  } catch (error) {
    if (error instanceof JournalError) {
      p.log.error(messages.eql.repairJournalUnreadable(error.message))
      throw new CliExit(1)
    }
    throw error
  }

  p.intro('CipherStash EQL repair')

  const dryRun = options.dryRun ?? false
  const applied = await appliedFiles(
    outDir,
    journal,
    options.databaseUrl,
    relation,
  )

  let appliedFindings: AppliedFindings
  let result: RewriteResult
  let sweepIncomplete: boolean
  try {
    appliedFindings = await refusedAppliedFiles(outDir, applied)
    result = await rewriteEncryptedAlterColumns(outDir, {
      dryRun,
      skip: [...applied],
    })
    sweepIncomplete = reportSweepResult(result, { dryRun })
  } catch (error) {
    // Unlike `eql migration`, where the sweep is advisory work after a
    // migration was already written, here it IS the command — so report the
    // partial work (#786) and fail, rather than surfacing a raw stack trace.
    reportSweepFailure(outDir, error)
    p.log.error(messages.eql.repairSweepIncomplete(outDir))
    p.outro('Repair incomplete.')
    throw new CliExit(1)
  }

  const { refused, nearMisses } = appliedFindings
  if (refused.length > 0) {
    p.log.warn(messages.eql.repairAppliedRefused(refused.length))
    for (const file of refused) p.log.step(`  - ${file}`)
    p.log.step(`      ${messages.eql.repairAppliedHazard}`)
  }
  // Held back with the rest of their file, so the real sweep never saw them —
  // report them here with the same guidance an unapplied near-miss gets.
  reportSkipped(nearMisses)

  if (sweepIncomplete || refused.length > 0 || nearMisses.length > 0) {
    p.log.error(messages.eql.repairSweepIncomplete(outDir))
    p.outro('Repair incomplete.')
    throw new CliExit(1)
  }
  if (result.rewritten.length === 0) {
    p.log.success(messages.eql.repairNothingToDo)
  }
  p.outro(dryRun ? 'Dry run complete.' : 'Done!')
}

/**
 * What an applied migration carries, split by what the rewriter would have done
 * with it — because the two need different words from us.
 *
 * `refused` are files the sweep WOULD have rewritten. Holding them back is the
 * applied-migration hazard, and {@link messages.eql.repairAppliedHazard}
 * explains it.
 *
 * `nearMisses` are statements the sweep would have left alone anyway — an
 * undeclared source column, an already-encrypted one, an existing twin. Their
 * applied-ness is beside the point: the actionable thing is the skip reason, so
 * they get the same guidance an unapplied near-miss gets. Reporting them under
 * the hazard banner would swap advice the user can act on for an explanation
 * that does not apply to them.
 */
interface AppliedFindings {
  refused: string[]
  nearMisses: RewriteResult['skipped']
}

/**
 * The applied migrations that carry an ALTER-to-encrypted statement, split into
 * {@link AppliedFindings}.
 *
 * Answered with a second, WRITE-FREE sweep over the whole directory rather than
 * a private matcher: "does this file carry a statement the repair would act on"
 * is exactly the question the rewriter answers, and a hand-rolled regex here
 * would be a second definition of it, free to drift. The real sweep that follows
 * holds these files back, so it cannot answer this itself.
 */
async function refusedAppliedFiles(
  outDir: string,
  applied: ReadonlySet<string>,
): Promise<AppliedFindings> {
  // The intersection is empty by construction when nothing is applied — which
  // is every offline run — so don't pay for the extra pass.
  if (applied.size === 0) return { refused: [], nearMisses: [] }
  const preview = await rewriteEncryptedAlterColumns(outDir, { dryRun: true })
  return {
    refused: preview.rewritten.filter((file) => applied.has(file)).sort(),
    nearMisses: preview.skipped.filter(({ file }) => applied.has(file)),
  }
}

/**
 * The migration files this database has already run, as absolute paths.
 *
 * Offline (no database URL resolvable) the answer is "none": see
 * {@link resolveRepairDatabaseUrl} for why that is the default rather than a
 * refusal.
 */
async function appliedFiles(
  outDir: string,
  journal: readonly JournalEntry[],
  databaseUrlFlag: string | undefined,
  relation: string = DEFAULT_MIGRATIONS_RELATION,
): Promise<Set<string>> {
  const databaseUrl = await resolveRepairDatabaseUrl(databaseUrlFlag)
  if (databaseUrl === undefined) {
    p.log.warn(messages.eql.repairAppliedUnverified)
    return new Set()
  }

  let watermark: number | typeof NOTHING_APPLIED | typeof LEDGER_ABSENT
  try {
    watermark = await latestAppliedMillis(databaseUrl, relation)
  } catch (error) {
    // Asking for the check and not getting it is a hard failure. Proceeding
    // here would rewrite applied migrations while having told the user the
    // check was on — the precise drift they passed --database-url to avoid.
    p.log.error(
      messages.eql.repairAppliedCheckFailed(
        error instanceof Error ? error.message : String(error),
      ),
    )
    p.outro('Repair incomplete.')
    throw new CliExit(1)
  }
  // Absent relation: ambiguous, so warn rather than claim a clean check. See
  // LEDGER_ABSENT. Still proceeds, for the same reason the offline path does.
  if (watermark === LEDGER_ABSENT) {
    p.log.warn(messages.eql.repairLedgerMissing(relation))
    return new Set()
  }
  if (watermark === NOTHING_APPLIED) {
    p.log.info(messages.eql.repairNothingApplied)
    return new Set()
  }

  // `folderMillis <= max(created_at)` — drizzle's own applied-check, mirrored.
  const applied = new Set(
    journal
      .filter((entry) => entry.when <= watermark)
      .map((entry) => join(outDir, `${entry.tag}.sql`)),
  )
  p.log.info(messages.eql.repairAppliedCount(applied.size))
  return applied
}

/**
 * The database URL to check applied state against, or `undefined` to skip the
 * check.
 *
 * Deliberately only the first two tiers of `resolveDatabaseUrl` — the explicit
 * flag and `DATABASE_URL` — never the interactive prompt or the hard failure
 * below them. The applied-state check is an enhancement, not the command's
 * purpose: prompting for a connection string in the middle of an offline repair
 * would be surprising, and failing without one would make the command useless
 * in the flow it exists for (a broken, never-applied migration in a project
 * whose database may not even be reachable).
 */
async function resolveRepairDatabaseUrl(
  flag: string | undefined,
): Promise<string | undefined> {
  if (flag === undefined && !process.env.DATABASE_URL?.trim()) return undefined
  // Routed through the shared resolver so a malformed --database-url is
  // rejected the same way every other command rejects it.
  return await resolveDatabaseUrl({ databaseUrlFlag: flag })
}
