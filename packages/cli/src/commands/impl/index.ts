import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import * as p from '@clack/prompts'
import { type AgentEnvironment, detectAgents } from '../init/detect-agents.js'
import {
  type PlanStep,
  type PlanSummary,
  effectiveStep,
  parsePlanSummary,
  renderPlanSummary,
} from '../init/lib/parse-plan.js'
import { readContextFile } from '../init/lib/read-context.js'
import {
  classifyPhase,
  detectColumnStates,
} from '../init/lib/rollout-state.js'
import { PLAN_REL_PATH } from '../init/lib/setup-prompt.js'
import {
  CONTEXT_REL_PATH,
  type ContextFile,
} from '../init/lib/write-context.js'
import { CancelledError, type InitState } from '../init/types.js'
import { detectPackageManager, runnerCommand } from '../init/utils.js'
import {
  HANDOFF_CHOICES,
  howToProceedStep,
  resolveTarget,
} from './steps/how-to-proceed.js'

function buildStateFromContext(
  ctx: ContextFile,
  agents: AgentEnvironment,
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
    mode: 'implement',
    usesProxy: ctx.usesProxy ?? false,
  }
}

/**
 * Confirm before launching implementation when the user has chosen to
 * skip the planning checkpoint. Default-no is the security stance —
 * passing through this prompt by accident is the failure mode we're
 * guarding against.
 */
async function confirmContinueWithoutPlan(): Promise<void> {
  const confirmed = await p.confirm({
    message: 'Implementation can take some time. Continue?',
    initialValue: false,
  })
  if (p.isCancel(confirmed) || !confirmed) {
    throw new CancelledError()
  }
}

/**
 * Verify the plan-summary's targeted columns have crossed the deploy gate
 * (a `dual_writing` event recorded in `cs_migrations`). Used only for
 * `cutover`-step plans. Returns the list of columns that are still in the
 * rollout step (no `dual_writing` event yet) — empty when the plan is
 * safe to proceed.
 *
 * On any DB error, returns `null` to signal "could not verify". The caller
 * still proceeds — refusing to run when the DB is just temporarily
 * unreachable would be too brittle, and the encrypt commands themselves
 * also gate on the same event before doing anything destructive.
 */
async function verifyCutoverPreconditions(
  cwd: string,
  summary: PlanSummary,
): Promise<{ table: string; column: string }[] | null> {
  const migrate = summary.columns.filter((c) => c.path === 'migrate')
  if (migrate.length === 0) return []

  let databaseUrl: string
  try {
    const { loadStashConfig } = await import('../../config/index.js')
    const config = await loadStashConfig()
    databaseUrl = config.databaseUrl
  } catch {
    return null
  }

  const states = await detectColumnStates(databaseUrl, migrate)
  if (states === null) return null
  return states
    .filter((s) => classifyPhase(s.phase) !== 'cutover')
    .map((s) => ({ table: s.table, column: s.column }))
}

/**
 * Print the deploy-gate banner shown at the end of a successful
 * rollout-step impl run. The banner is the explicit handover from the
 * CLI back to the user — the encrypted twin column and dual-write code
 * are now in the repo, but they only become safe once that code is
 * running in production. The CLI deliberately does not chain into
 * anything destructive here; the next destructive step (`stash encrypt
 * backfill`) requires the user to come back and run `stash plan` after
 * deploy.
 */
function printDeployGateBanner(cli: string): void {
  p.note(
    [
      'Encryption rollout is in your repo.',
      '',
      'Encrypted values are not yet flowing through your application because the',
      'dual-write code is not deployed. Until your production environment is running',
      'this code, backfilling historical rows would corrupt new writes (any row',
      'inserted during the backfill window would land in plaintext only and create',
      'silent migration drift).',
      '',
      'Next:',
      `  1. Deploy this branch to production.`,
      `  2. Run \`${cli} status\` to verify dual-writes are live.`,
      `  3. Run \`${cli} plan\` again — the CLI will detect dual-writes and draft`,
      `     the encryption cutover (backfill → switch reads → drop plaintext).`,
    ].join('\n'),
    '⛔ Deploy gate',
  )
}

/**
 * `stash impl` — execute an encryption plan via agent handoff.
 *
 * Cutover-step plans are gated on a `dual_writing` event being recorded
 * in `cs_migrations` for every migrate column (the safety net that
 * stops destructive work running ahead of a production deploy of the
 * dual-write code). After a rollout-step handoff, the outro is the
 * deploy-gate banner instead of a generic "verify state" pointer.
 */
export async function implCommand(
  flags: Record<string, boolean>,
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

  // Validate `--target` before printing the intro so the error sits at
  // the top of the output instead of after a half-rendered prompt frame.
  const targetFlag = values.target
  const target = resolveTarget(targetFlag)
  if (targetFlag && !target) {
    p.log.error(
      `Unknown --target \`${targetFlag}\`. Valid values: ${HANDOFF_CHOICES.join(', ')}.`,
    )
    process.exit(1)
  }

  p.intro('CipherStash Implementation')

  const planPath = resolve(cwd, PLAN_REL_PATH)
  const planExists = existsSync(planPath)
  const continueWithoutPlan = flags['continue-without-plan'] === true
  // Interactive only when stdin is a real TTY and we're not in CI — the
  // same gate the encrypt commands use. `process.stdout.isTTY` alone is
  // wrong: a redirected stdin still hangs the agent-target picker (clack
  // `select` reads from /dev/tty).
  const isTTY = Boolean(process.stdin.isTTY) && process.env.CI !== 'true'

  let planStep: PlanStep | undefined

  try {
    if (planExists) {
      const summary = parsePlanSummary(readFileSync(planPath, 'utf-8'))
      planStep = summary ? effectiveStep(summary) : undefined

      // Deploy-gate enforcement for cutover-step plans. Block before any
      // confirm prompt or handoff so the user never gets the chance to
      // press Enter through a misshapen flow. The check itself is
      // defensive: a DB outage doesn't fail the run (returns null), the
      // encrypt commands have their own gate.
      if (summary && planStep === 'cutover') {
        const missing = await verifyCutoverPreconditions(cwd, summary)
        if (missing && missing.length > 0) {
          p.log.error(
            'This plan is a cutover-step plan, but `cs_migrations` has no `dual_writing` event for the following column(s):',
          )
          for (const col of missing) {
            p.log.error(`  · ${col.table}.${col.column}`)
          }
          p.log.info(
            `Backfill, cutover, and drop are unsafe until the dual-write code is live in production. Deploy your encryption-rollout PR first, then re-run \`${cli} status\` to verify and \`${cli} plan\` to redraft.`,
          )
          p.outro('Cutover blocked.')
          process.exit(1)
        }
      }

      // Plan-summary checkpoint: the last save point before launching the
      // (potentially hour-long) implementation phase.
      if (isTTY) {
        if (summary) {
          p.note(renderPlanSummary(summary, cli), 'Plan summary')
        } else {
          p.note(
            `Plan at \`${PLAN_REL_PATH}\` doesn't include a machine-readable summary. Open it in your editor before proceeding.`,
            'Plan ready',
          )
        }
        const proceed = await p.confirm({
          message: 'Proceed with implementation against this plan?',
          initialValue: true,
        })
        if (p.isCancel(proceed) || !proceed) {
          throw new CancelledError()
        }
      } else {
        p.log.info(
          `Plan at \`${PLAN_REL_PATH}\` — agent will execute it as the source of truth.`,
        )
      }
    } else {
      // No plan on disk. Branch on flag / TTY / interactive.
      if (continueWithoutPlan) {
        await confirmContinueWithoutPlan()
      } else if (!isTTY) {
        p.log.error(
          `No plan at \`${PLAN_REL_PATH}\`. Run \`${cli} plan\` first, or pass --continue-without-plan to skip planning.`,
        )
        process.exit(1)
      } else {
        const choice = await p.select<'plan' | 'continue'>({
          message: 'No plan found. What would you like to do?',
          options: [
            {
              value: 'plan',
              label: 'Draft a plan first (recommended)',
              hint: `runs \`${cli} plan\` — usually 1–3 min`,
            },
            {
              value: 'continue',
              label: 'Continue without a plan',
              hint: 'skip the planning checkpoint',
            },
          ],
          initialValue: 'plan',
        })
        if (p.isCancel(choice)) throw new CancelledError()

        if (choice === 'plan') {
          // Lazy import avoids a circular module load between plan ↔ impl.
          const { planCommand } = await import('../plan/index.js')
          // Close the current intro frame before plan opens its own.
          p.outro('Handing off to `stash plan`.')
          await planCommand()
          return
        }

        await confirmContinueWithoutPlan()
      }
    }

    const agents = detectAgents(cwd, process.env)
    const state = buildStateFromContext(ctx, agents)

    // Non-TTY without an explicit target would block forever on the
    // agent-target picker (it reads from /dev/tty). Make the command
    // safe to call from automation by short-circuiting with a hint.
    if (!target && !isTTY) {
      p.log.info(
        `No agent selected. Plan is at \`${PLAN_REL_PATH}\`. Pass --target <${HANDOFF_CHOICES.join('|')}> to run the handoff non-interactively.`,
      )
      p.outro('No handoff performed.')
      return
    }

    await howToProceedStep.run(target ? { ...state, handoff: target } : state)

    if (planStep === 'rollout') {
      printDeployGateBanner(cli)
      p.outro('Encryption rollout handed off — deploy when ready.')
    } else {
      p.outro(
        `Implementation handoff complete. Run \`${cli} status\` to verify state.`,
      )
    }
  } catch (err) {
    if (err instanceof CancelledError) {
      p.cancel('Cancelled.')
      process.exit(0)
    }
    throw err
  }
}
