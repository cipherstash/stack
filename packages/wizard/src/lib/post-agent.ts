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

    // A rewritten file is a DROP+ADD in disguise — the next migrate destroys
    // data on any table that already holds rows. A flagged statement never got
    // that treatment: it is left on disk untouched, so nothing is destroyed by
    // migrating, but a raw ALTER to an encrypted domain has no cast in
    // Postgres and fails at migrate time until a human resolves it. Both
    // default the prompt to NO — an `initialValue: true` immediately under
    // either warning invites exactly the mistake the warning is about — but
    // they need different words: claiming "DESTROYS data" for a migration
    // that destroyed nothing is its own kind of wrong guidance.
    const destructive = sweep.rewritten > 0
    const flaggedOnly = !destructive && sweep.skipped > 0

    // A directory whose sweep threw contributes 0 to both totals, so on its own
    // it is indistinguishable from a clean sweep — except that it means the
    // opposite: those migrations may still hold unrepaired `SET DATA TYPE`
    // statements and nobody has looked. `stash eql migration` / `db install`
    // treat "sweep failed outright" and "sweep left near-misses" as the same
    // state for the same reason; unknown is not safe, so the default is NO here
    // too. The wording differs from the destructive case on purpose: nothing is
    // known about that directory, so claiming it destroys data would be a guess.
    const unverifiedDirs = sweep.failedDirs
    const unverified = unverifiedDirs.length > 0
    const unverifiedList = unverifiedDirs.map((dir) => `${dir}/`).join(', ')
    const unverifiedCount = `${unverifiedDirs.length} director${
      unverifiedDirs.length === 1 ? 'y' : 'ies'
    }`
    if (unverified) {
      p.log.warn(
        `The ALTER COLUMN sweep did not fully complete — review the sibling migrations in ${unverifiedList} before running drizzle-kit migrate, or you may apply broken/unsafe SQL.`,
      )
    }

    const shouldMigrate = await p.confirm({
      message: destructive
        ? `Run the migration now? (${runner} drizzle-kit migrate) — see the warnings above: this migration DESTROYS data on any table that already holds rows`
        : flaggedOnly
          ? `Run the migration now? (${runner} drizzle-kit migrate) — statement(s) were flagged for review above rather than rewritten; nothing was destroyed, but the raw ALTER will fail at migrate time until they're resolved`
          : unverified
            ? `Run the migration now? (${runner} drizzle-kit migrate) — the sweep could not check ${unverifiedCount} (${unverifiedList}); review those migrations before migrating, or you may apply broken/unsafe SQL`
            : `Run the migration now? (${runner} drizzle-kit migrate)`,
      initialValue: !destructive && !flaggedOnly && !unverified,
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
        `Rewrote ${rewritten.length} migration file(s) in ${dir}/ to use ADD+DROP+RENAME for encrypted columns.`,
      )
      for (const file of rewritten) p.log.step(`  - ${file}`)
      p.log.warn(
        'This rewrite is data-destroying — safe only on an EMPTY table. If any of these tables already have rows, do NOT run the migration; use the staged `stash encrypt` flow (add -> backfill via @cipherstash/stack -> cutover -> drop) instead. See the comments in the rewritten SQL.',
      )
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
