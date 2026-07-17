import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { readManifest } from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import { CliExit } from '../../cli/exit.js'
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
  cli: string
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

  // Interactive only when stdin is a real TTY and we're not in CI — the same
  // gate `stash impl` and the encrypt commands use. Keying off
  // `process.stdout.isTTY` alone is wrong: a redirected stdin still hangs the
  // agent-target picker (clack `select` reads from /dev/tty). Computed up here
  // because the complete-rollout confirmation needs it too.
  const isInteractive =
    Boolean(process.stdin.isTTY) && process.env.CI !== 'true'

  try {
    if (existsSync(resolve(cwd, PLAN_REL_PATH))) {
      p.log.warn(
        `Plan already exists at \`${PLAN_REL_PATH}\`. The agent will be told to revise it; delete the file first if you want to start fresh.`,
      )
    }

    let planStep: PlanStep
    if (flags['complete-rollout']) {
      await confirmCompleteRollout({
        assumeYes: flags.yes ?? false,
        isInteractive,
        cli,
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

    await howToProceedStep.run(target ? { ...state, handoff: target } : state)

    if (isInteractive) {
      const proceed = await p.confirm({
        message: `Plan drafted at \`${PLAN_REL_PATH}\`. Continue to \`${cli} impl\` now?`,
        initialValue: true,
      })
      if (!p.isCancel(proceed) && proceed) {
        p.outro('Plan complete — handing off to `stash impl`.')
        const { implCommand } = await import('../impl/index.js')
        await implCommand({}, {})
        return
      }
      p.outro(
        `Plan drafted at \`${PLAN_REL_PATH}\`. Review it, then run \`${cli} impl\` to implement.`,
      )
    } else {
      // Mirror init's non-TTY hint: the next command will also hit the
      // agent-target picker, so name `--target` here rather than letting
      // the user re-discover the flag on the next exit-cleanly hint.
      p.outro(
        `Plan drafted at \`${PLAN_REL_PATH}\`. Review it, then run \`${cli} impl --target <claude-code|codex|agents-md|wizard>\` to implement. The \`--target\` flag is required when running non-interactively.`,
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
