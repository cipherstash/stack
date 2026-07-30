import * as p from '@clack/prompts'
import {
  describeSkipReason,
  describeStagedReconciliation,
  isPartialRewriteResult,
  type PartialRewriteResult,
  type RewriteResult,
} from '@/commands/db/rewrite-migrations.js'
import { messages } from '@/messages.js'

/**
 * Shared rendering for a {@link RewriteResult}.
 *
 * `stash eql migration --drizzle` and `stash eql repair --drizzle` run the same
 * sweep over the same directory, so they must say the same things about it —
 * a divergence between the two surfaces is a defect, not a style difference.
 * Both call these helpers rather than each formatting the result themselves.
 */

/** Render the rewritten-file list under `lead`. */
function reportRewritten(files: readonly string[], lead: string): void {
  if (files.length === 0) return
  p.log.info(lead)
  for (const file of files) p.log.step(`  - ${file}`)
}

/**
 * Render the near-misses the sweep left alone, each with the guidance its
 * {@link describeSkipReason} carries — the reasons need different action from
 * the user, so a single generic line would hide that.
 */
function reportSkipped(skipped: PartialRewriteResult['skipped']): void {
  if (!skipped || skipped.length === 0) return
  p.log.warn(
    `Found ${skipped.length} ALTER-to-encrypted statement(s) the sweep left alone. Review and fix them before running your migrations:`,
  )
  for (const { file, statement, reason } of skipped) {
    p.log.step(`  - ${file}: ${statement}`)
    p.log.step(`      ${describeSkipReason(reason)}`)
  }
}

/** Render the schema/snapshot reconciliation a staged twin leaves behind. */
function reportStaged(staged: PartialRewriteResult['staged']): void {
  if (!staged || staged.length === 0) return
  p.log.warn(describeStagedReconciliation(staged).join('\n'))
}

/**
 * Report a completed sweep. Returns `true` when it left statements behind,
 * which every caller turns into a non-zero exit: the remaining SQL still fails
 * at migrate time, and a zero exit would tell CI the sweep had succeeded.
 */
export function reportSweepResult(
  result: RewriteResult,
  options: { dryRun?: boolean } = {},
): boolean {
  reportRewritten(
    result.rewritten,
    options.dryRun
      ? `Would rewrite ${result.rewritten.length} migration file(s) to add staged encrypted columns while preserving the source columns:`
      : `Rewrote ${result.rewritten.length} migration file(s) to add staged encrypted columns while preserving the source columns:`,
  )
  // The rewrite repaired SQL only, so schema.ts and the drizzle-kit snapshot now
  // disagree with the database — and `drizzle-kit generate` cannot see it (#836,
  // item 2). A warning rather than a failure: the swept SQL is valid and
  // additive, and the reconciliation is the user's editorial call.
  //
  // Under --dry-run none of that has happened yet. `describeStagedReconciliation`
  // is written in the past tense ("the database now has"), so printing it here
  // would send the user reconciling against a column no migration adds. Count
  // the twins instead, and let the real run print the reconciliation.
  if (options.dryRun) {
    if (result.staged.length > 0) {
      p.log.info(messages.eql.repairDryRunStaged(result.staged.length))
    }
  } else {
    reportStaged(result.staged)
  }
  reportSkipped(result.skipped)
  return result.skipped.length > 0
}

/**
 * Report a sweep that threw partway through: the work it had already done
 * (#786), then the failure itself. Callers always treat this as incomplete.
 */
export function reportSweepFailure(outDir: string, error: unknown): void {
  const partial: PartialRewriteResult = isPartialRewriteResult(error)
    ? error
    : {}
  reportRewritten(
    partial.rewritten ?? [],
    `Rewrote ${partial.rewritten?.length ?? 0} migration file(s) before the sweep stopped:`,
  )
  // A partial sweep still staged real twins, so the same three-way divergence
  // already exists for them.
  reportStaged(partial.staged)
  reportSkipped(partial.skipped)
  p.log.warn(
    `Could not sweep ${outDir} for unsafe ALTER COLUMN statements: ${
      error instanceof Error ? error.message : String(error)
    }`,
  )
}
