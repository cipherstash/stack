/**
 * Post-agent CLI steps.
 *
 * Runs deterministic commands after the agent finishes editing code.
 * These don't need AI — they're fixed commands we can run directly.
 */

import { execSync } from 'node:child_process'
import * as p from '@clack/prompts'
import type { GatheredContext } from './gather.js'
import { describeSkipReason, sweepMigrationDirs } from './rewrite-migrations.js'
import type { DetectedPackageManager, Integration } from './types.js'

interface PostAgentOptions {
  cwd: string
  integration: Integration
  gathered: GatheredContext
  packageManager: DetectedPackageManager | undefined
}

/**
 * Candidate directories drizzle-kit may write migrations to. `drizzle` is the
 * default, but a project's configured `out` is not discoverable from here, so
 * every candidate that exists is swept — see {@link sweepMigrationDirs} for why
 * stopping at the first one loses migrations.
 */
const DRIZZLE_OUT_DIRS = ['drizzle', 'migrations', 'src/db/migrations']

/**
 * Run all post-agent steps: install packages, install EQL, run migrations.
 */
export async function runPostAgentSteps(opts: PostAgentOptions): Promise<void> {
  const { cwd, integration, gathered, packageManager } = opts
  const runner = packageManager?.execCommand ?? 'npx'

  // Step 1: Install @cipherstash/stack
  await runStep(
    'Installing @cipherstash/stack...',
    'Package installed',
    gathered.installCommand,
    cwd,
  )

  // Step 2: Run runner stash eql install if the project doesn't yet
  // have a stash.config.ts. `eql install` scaffolds the config and installs
  // EQL in a single step (CIP-2986).
  if (!gathered.hasStashConfig) {
    await runStep(
      `Running ${runner} stash eql install...`,
      `${runner} stash eql install complete`,
      `${runner} stash eql install`,
      cwd,
    )
  }

  // Step 3: Integration-specific migrations. Older gathered context may still
  // carry `usesProxy`; it is compatibility data only. EQL v3 has no Proxy
  // configuration to push, and the retired `stash db push` must never run.
  if (integration === 'drizzle') {
    await runStep(
      'Generating Drizzle migration...',
      'Migration generated',
      `${runner} drizzle-kit generate`,
      cwd,
    )

    // Rewrite any `ALTER COLUMN ... SET DATA TYPE <eql domain>` that
    // drizzle-kit just produced — those fail in Postgres (no cast from
    // text/numeric to an EQL domain). Covers the EQL v3 family the wizard now
    // scaffolds, and legacy eql_v2_encrypted. CIP-2991 + CIP-2994 + #693.
    const sweep = await rewriteEncryptedMigrations(cwd)
    const staged = sweep.rewritten > 0
    const skipped = sweep.skipped > 0
    const unverified = sweep.failedDirs.length > 0

    if (staged) {
      p.log.info(
        `Rewrote ${sweep.rewritten} migration file(s) in the drizzle output to add staged encrypted columns while preserving the source columns.`,
      )
    }
    if (skipped || unverified) {
      throw new Error(
        `The ALTER COLUMN sweep found unsafe or unverified SQL. The generated migration remains in ${cwd}, but review the sibling migrations before running drizzle-kit migrate.`,
      )
    }

    const shouldMigrate = await p.confirm({
      message: staged
        ? `Run the migration now? (${runner} drizzle-kit migrate) — the generated migration adds staged encrypted columns and preserves the source column for the later backfill and application switch`
        : `Run the migration now? (${runner} drizzle-kit migrate)`,
      initialValue: true,
    })

    if (!p.isCancel(shouldMigrate) && shouldMigrate) {
      await runStep(
        'Running migration...',
        'Migration complete',
        `${runner} drizzle-kit migrate`,
        cwd,
      )
    }
  }

  if (integration === 'prisma') {
    const shouldMigrate = await p.confirm({
      message: `Run Prisma migration now? (${runner} prisma migrate dev --name add-encryption)`,
      initialValue: true,
    })

    if (!p.isCancel(shouldMigrate) && shouldMigrate) {
      await runStep(
        'Running Prisma migration...',
        'Migration complete',
        `${runner} prisma migrate dev --name add-encryption`,
        cwd,
      )
    }
  }
}

/**
 * Sweep the candidate migration directories, reporting what happened, and
 * return the totals so the caller can decide how dangerous "run it now" is.
 *
 * `failedDirs` names the directories that exist but whose sweep threw. It is a
 * third state, not a variant of "nothing to do": those migrations may still
 * contain unrepaired `SET DATA TYPE` statements and went unchecked, which the
 * `rewritten`/`skipped` counts cannot express — both stay 0 for such a
 * directory, exactly as they do for a clean one.
 */
async function rewriteEncryptedMigrations(cwd: string): Promise<{
  rewritten: number
  skipped: number
  failedDirs: string[]
}> {
  const results = await sweepMigrationDirs(cwd, DRIZZLE_OUT_DIRS)
  const totals = { rewritten: 0, skipped: 0, failedDirs: [] as string[] }

  for (const { dir, rewritten, skipped, error, notDrizzleOutput } of results) {
    totals.rewritten += rewritten.length
    totals.skipped += skipped.length

    // Not a failure and not a risk — the directory belongs to some other tool,
    // so `drizzle-kit migrate` will not run it and the prompt below is
    // unaffected. Said out loud anyway, so a user whose drizzle output really
    // does live here (meta/ deleted, or a hand-assembled directory) can see why
    // nothing was repaired instead of assuming it was clean.
    if (notDrizzleOutput) {
      p.log.info(
        `Left ${dir}/ alone — it holds .sql files but no drizzle-kit journal (meta/_journal.json), so it is not a drizzle output directory. If it IS your drizzle \`out\`, run \`drizzle-kit generate\` once to create the journal, then re-run the wizard.`,
      )
      continue
    }

    // Presence, not truthiness: `error` is `err.message` for a thrown `Error`,
    // and `new Error()` has an empty message. Testing `if (error)` would put a
    // blank-message failure back on the fail-open path this whole branch exists
    // to close.
    if (error !== undefined) {
      totals.failedDirs.push(dir)
      p.log.warn(
        `Could not rewrite migrations in ${dir}: ${error || 'unknown error'}`,
      )
      continue
    }

    if (rewritten.length > 0) {
      p.log.info(
        `Rewrote ${rewritten.length} migration file(s) in ${dir}/ to add staged encrypted columns while preserving the source columns.`,
      )
      for (const file of rewritten) p.log.step(`  - ${file}`)
    }

    if (skipped.length > 0) {
      p.log.warn(
        `${skipped.length} statement(s) look like an ALTER-to-encrypted that the rewrite left alone. Review them before migrating:`,
      )
      for (const s of skipped) {
        p.log.step(`  - ${s.file}: ${s.statement}`)
        p.log.step(`      ${describeSkipReason(s.reason)}`)
      }
    }
  }

  return totals
}

async function runStep(
  startMsg: string,
  doneMsg: string,
  command: string,
  cwd: string,
): Promise<void> {
  const s = p.spinner()
  s.start(startMsg)
  try {
    execSync(command, {
      cwd,
      stdio: 'pipe',
      timeout: 120_000,
    })
    s.stop(doneMsg)
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error'
    s.stop(`Failed: ${command}`)
    p.log.warn(`Command failed: ${message}`)
    p.log.info(`You can run this manually: ${command}`)
  }
}
