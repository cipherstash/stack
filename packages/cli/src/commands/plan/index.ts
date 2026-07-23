import { type Stats, statSync } from 'node:fs'
import { resolve } from 'node:path'
import { readManifest } from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import { CliExit } from '../../cli/exit.js'
import { isInteractive as isInteractiveTty } from '../../config/tty.js'
import { messages } from '../../messages.js'
import {
  HANDOFF_CHOICES,
  howToProceedStep,
  resolveTarget,
} from '../impl/steps/how-to-proceed.js'
import { type AgentEnvironment, detectAgents } from '../init/detect-agents.js'
import type { PlanStep } from '../init/lib/parse-plan.js'
import { readContextFile } from '../init/lib/read-context.js'
import {
  detectColumnStates,
  rollupPlanStep,
} from '../init/lib/rollout-state.js'
import { PLAN_REL_PATH } from '../init/lib/setup-prompt.js'
import {
  CONTEXT_REL_PATH,
  type ContextFile,
} from '../init/lib/write-context.js'
import { CancelledError, type InitState } from '../init/types.js'
import { detectPackageManager, runnerCommand } from '../init/utils.js'

/**
 * Stat the plan file, returning its `Stats` only when it's a regular FILE and
 * treating "absent or not a usable plan" as `undefined`.
 *
 * `throwIfNoEntry: false` turns the common ENOENT into `undefined`. A non-file
 * — most realistically a DIRECTORY at `.cipherstash/plan.md` — also maps to
 * `undefined`: `statSync` succeeds for a directory, but the agent cannot have
 * written a plan there, so without the `isFile()` gate it would read as a
 * pre-existing/unchanged plan and let the command exit 0 against something no
 * agent can consume. Any OTHER fs error — ENOTDIR if `.cipherstash` is somehow
 * a file, EACCES on a locked path, an ELOOP symlink — is converted into a
 * controlled `CliExit(1)` with an actionable message instead of unwinding as a
 * generic "Fatal error". This command exists to give automation a reliable
 * signal about the plan's state (#738), so a filesystem hiccup must not become
 * an opaque crash, and a non-file must not read as success.
 */
function statPlan(planAbs: string): Stats | undefined {
  try {
    const stats = statSync(planAbs, { throwIfNoEntry: false })
    return stats?.isFile() ? stats : undefined
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    p.log.error(`Could not read \`${PLAN_REL_PATH}\`: ${message}`)
    throw new CliExit(1)
  }
}

function buildStateFromContext(
  ctx: ContextFile,
  agents: AgentEnvironment,
  planStep: PlanStep,
): InitState {
  return {
    integration: ctx.integration,
    clientFilePath: ctx.encryptionClientPath,
    schemas: ctx.schemas,
    envKeys: ctx.envKeys,
    stackInstalled: true,
    cliInstalled: true,
    eqlInstalled: true,
    agents,
    mode: 'plan',
    planStep,
    usesProxy: ctx.usesProxy ?? false,
  }
}

/**
 * Confirm the user wants to skip the production-deploy gate.
 *
 * The gate-skip is a deliberate act, so it needs explicit consent:
 *  - interactive TTY → a default-no `p.confirm` (a stray Enter is "no").
 *  - `--yes` → the non-interactive consent flag; proceed, after logging the
 *    warnings so the record shows what was skipped.
 *  - non-interactive without `--yes` → REFUSE with a non-zero exit. We must
 *    not silently cancel-with-0: automation that asked for a complete-rollout
 *    plan and got exit 0 would assume a plan exists when none was drafted.
 */
async function confirmCompleteRollout(opts: {
  assumeYes: boolean
  isInteractive: boolean
}): Promise<void> {
  p.log.warn(
    '`--complete-rollout` plans the full encryption lifecycle (schema-add through drop) in one document. It SKIPS the production-deploy gate that protects backfill from running before dual-writes are live.',
  )
  p.log.warn(
    'Only safe when this database is not backing a deployed application — local development, ephemeral test environments, or freshly seeded sandboxes. If a deployed app writes to this database, rows inserted during the planned backfill will land in plaintext only and you will need a recovery pass.',
  )

  if (opts.assumeYes) {
    p.log.info(
      `${messages.plan.completeRolloutConfirmed} by your explicit confirmation.`,
    )
    return
  }

  if (!opts.isInteractive) {
    p.log.error(
      `${messages.plan.completeRolloutNeedsYes}. Re-run with \`--yes\` to confirm non-interactively — only safe when no deployed application writes to this database (see the warnings above).`,
    )
    // Non-zero: the requested plan was NOT drafted. Distinct from a user's
    // interactive decline (a deliberate "no" → exit 0 via CancelledError).
    throw new CliExit(1)
  }

  const ok = await p.confirm({
    message: 'Proceed with a complete-rollout plan?',
    initialValue: false,
  })
  if (p.isCancel(ok) || !ok) throw new CancelledError()
}

/**
 * Detect what step the encryption rollout is at, by reading
 * `cs_migrations` for every column declared in `.cipherstash/migrations.json`.
 *
 * Falls back to `'rollout'` when:
 *  - the manifest is missing or empty (fresh project, nothing tracked yet),
 *  - `stash.config.ts` can't be loaded (no DATABASE_URL),
 *  - the database isn't reachable.
 *
 * The fallback is intentional: a rollout-shaped plan is always a safe
 * starting point, and the agent will ask the user about path=new vs
 * path=migrate per column anyway.
 */
async function detectPlanStep(cwd: string): Promise<PlanStep> {
  const manifest = await readManifest(cwd).catch(() => null)
  if (!manifest) return 'rollout'

  const columns: { table: string; column: string }[] = []
  for (const [table, cols] of Object.entries(manifest.tables)) {
    for (const col of cols) {
      columns.push({ table, column: col.column })
    }
  }
  if (columns.length === 0) return 'rollout'

  let databaseUrl: string
  try {
    const { loadStashConfig } = await import('../../config/index.js')
    const config = await loadStashConfig()
    databaseUrl = config.databaseUrl
  } catch {
    return 'rollout'
  }

  const states = await detectColumnStates(databaseUrl, columns)
  // DB unreachable — fall back to a rollout-shaped plan rather than
  // refusing. The plan command is read-only and the agent will surface
  // the missing observation in the prose.
  if (states === null) return 'rollout'
  const step = rollupPlanStep(states)
  // `unknown` and `completed` both map to rollout for plan-step selection:
  //   unknown   — no events; treat as fresh.
  //   completed — every tracked column is `dropped`; the user must want to
  //               plan something new, so a rollout-shaped plan is the right
  //               canvas. (If they really have nothing to do, the agent
  //               will figure that out and tell them.)
  if (step === 'cutover' || step === 'rollout') return step
  return 'rollout'
}

/**
 * `stash plan` — draft a reviewable encryption plan.
 *
 * State-driven: reads `.cipherstash/migrations.json` and `cs_migrations`
 * to decide whether to produce an encryption-rollout plan (the default
 * starting point) or an encryption-cutover plan (when at least one column
 * has crossed the deploy gate). The selection is invisible to the user —
 * they just run `stash plan` and get a plan for whatever step is next.
 *
 * Flags:
 *   `--complete-rollout` — escape hatch for databases without a deployed
 *                          application. Plans schema-add through drop in
 *                          one document with no deploy gate. Needs explicit
 *                          confirmation: an interactive default-no prompt, or
 *                          `--yes` non-interactively (else it refuses with a
 *                          non-zero exit rather than silently doing nothing).
 *   `--yes`              — confirm `--complete-rollout`'s gate-skip without a
 *                          prompt, for automation. No effect without it.
 */
export async function planCommand(
  flags: Record<string, boolean> = {},
  values: Record<string, string> = {},
) {
  const cwd = process.cwd()
  const pm = detectPackageManager()
  const cli = runnerCommand(pm, 'stash')

  const ctx = readContextFile(cwd)
  if (!ctx) {
    p.log.error(
      `No CipherStash context found at \`${CONTEXT_REL_PATH}\`. Run \`${cli} init\` first.`,
    )
    process.exit(1)
  }

  const targetFlag = values.target
  const target = resolveTarget(targetFlag)
  if (targetFlag && !target) {
    p.log.error(
      `Unknown --target \`${targetFlag}\`. Valid values: ${HANDOFF_CHOICES.join(', ')}.`,
    )
    process.exit(1)
  }

  p.intro('CipherStash Plan')

  // Interactive only when stdin is a real TTY and we're not in CI — via the
  // shared `isInteractive()` (config/tty.ts) so this gate stays identical to
  // every other prompt gate (its `isCiEnv()` treats `CI=1`/`CI=TRUE` as CI too,
  // which a bare `CI !== 'true'` inline would miss). Keying off
  // `process.stdout.isTTY` alone is wrong: a redirected stdin still hangs the
  // agent-target picker (clack `select` reads from /dev/tty). Computed up here
  // because the complete-rollout confirmation needs it too.
  const isInteractive = isInteractiveTty()

  const planAbs = resolve(cwd, PLAN_REL_PATH)

  try {
    // Stat (not just existence) so the post-handoff check can tell a revised
    // plan from a pre-existing one the run never touched (#738). Inside the
    // try so a filesystem error routes through the same controlled exit as the
    // rest of the command rather than bypassing it.
    const planBefore = statPlan(planAbs)

    if (planBefore) {
      p.log.warn(
        `Plan already exists at \`${PLAN_REL_PATH}\`. The agent will be told to revise it; delete the file first if you want to start fresh.`,
      )
    }

    let planStep: PlanStep
    if (flags['complete-rollout']) {
      await confirmCompleteRollout({
        assumeYes: flags.yes ?? false,
        isInteractive,
      })
      planStep = 'complete'
    } else {
      planStep = await detectPlanStep(cwd)
      if (planStep === 'rollout') {
        p.log.info(
          'Drafting an encryption-rollout plan (schema-add + dual-write code). After it ships to production, run `stash plan` again to draft the cutover.',
        )
      } else {
        p.log.info(
          'Detected dual-writes recorded in cs_migrations. Drafting an encryption-cutover plan (backfill, switch reads, drop plaintext).',
        )
      }
    }

    const agents = detectAgents(cwd, process.env)
    const state = buildStateFromContext(ctx, agents, planStep)

    // Non-interactive without --target would hang on the agent-target
    // picker. Exit cleanly with a hint so automation users discover the flag.
    if (!target && !isInteractive) {
      p.log.info(
        `No agent selected. Pass --target <${HANDOFF_CHOICES.join('|')}> to run the handoff non-interactively.`,
      )
      p.outro('No handoff performed.')
      return
    }

    const handedOff = await howToProceedStep.run(
      target ? { ...state, handoff: target } : state,
    )

    // The plan file is written by the handed-off agent, not by this command,
    // so the outcome is only knowable from the disk. Verify before claiming
    // anything — the unconditional "Plan drafted" this replaces let a failed
    // handoff exit 0 and send `stash impl` after a file that never existed
    // (#738).
    const planAfter = statPlan(planAbs)

    if (!planAfter) {
      if (handedOff.agentLaunched) {
        // An agent ran and was told to write the plan, but didn't — the
        // deliverable is missing. Non-zero, so automation never reads this
        // as "a plan exists".
        p.log.error(
          `${messages.plan.notWritten} to \`${PLAN_REL_PATH}\`. The agent may have been interrupted before saving it — re-run \`${cli} plan\` to try again.`,
        )
        p.outro('No plan was drafted.')
        throw new CliExit(1)
      }
      // Deferred handoff (AGENTS.md target, or a CLI target that isn't
      // installed): the files-and-instructions contract was delivered and
      // the plan is written later, when the user drives their agent. That's
      // a success for what was runnable — but never claim the plan exists.
      p.outro(
        `${messages.plan.noPlanYet} — complete the handoff above, then review \`${PLAN_REL_PATH}\` and run \`${cli} impl\` to implement.`,
      )
      return
    }

    // A pre-existing plan the run didn't modify is still usable (the agent
    // may have judged it current), but "drafted" would be a false claim —
    // report which of the two happened.
    //
    // Heuristic, deliberately not a content hash: an in-place revision that
    // preserves BOTH byte size and the mtime tick would misreport as
    // "unchanged". Blast radius is a cosmetic wording error — the plan is
    // usable either way, and a real agent write bumps mtime (and usually
    // size) — so it isn't worth hashing a large file on every run.
    const wrote =
      !planBefore ||
      planAfter.mtimeMs !== planBefore.mtimeMs ||
      planAfter.size !== planBefore.size
    const planLine = wrote
      ? `${messages.plan.drafted} \`${PLAN_REL_PATH}\``
      : `Plan at \`${PLAN_REL_PATH}\` ${messages.plan.unchanged}`

    if (isInteractive) {
      const proceed = await p.confirm({
        message: `${planLine}. Continue to \`${cli} impl\` now?`,
        initialValue: true,
      })
      if (!p.isCancel(proceed) && proceed) {
        p.outro('Plan complete — handing off to `stash impl`.')
        const { implCommand } = await import('../impl/index.js')
        await implCommand({}, {})
        return
      }
      p.outro(`${planLine}. Review it, then run \`${cli} impl\` to implement.`)
    } else {
      // Mirror init's non-TTY hint: the next command will also hit the
      // agent-target picker, so name `--target` here rather than letting
      // the user re-discover the flag on the next exit-cleanly hint.
      p.outro(
        `${planLine}. Review it, then run \`${cli} impl --target <claude-code|codex|agents-md|wizard>\` to implement. The \`--target\` flag is required when running non-interactively.`,
      )
    }
  } catch (err) {
    if (err instanceof CancelledError) {
      p.cancel('Cancelled.')
      // Cooperative exit: unwinds to run() so the cancel is tracked and the
      // telemetry flush completes before the process exits 0 (see cli/exit.ts).
      throw new CliExit(0)
    }
    throw err
  }
}
