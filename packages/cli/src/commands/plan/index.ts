import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { readManifest } from '@cipherstash/migrate'
import * as p from '@clack/prompts'
import { howToProceedStep } from '../impl/steps/how-to-proceed.js'
import { type AgentEnvironment, detectAgents } from '../init/detect-agents.js'
import { readContextFile } from '../init/lib/read-context.js'
import { detectColumnStates, rollupPlanStep } from '../init/lib/rollout-state.js'
import type { PlanStep } from '../init/lib/parse-plan.js'
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
  }
}

/**
 * Confirm the user wants to skip the production-deploy gate. Default-no is
 * the security stance — the warning has to be a deliberate `y` press, not
 * a stray Enter.
 */
async function confirmCompleteRollout(): Promise<void> {
  p.log.warn(
    '`--complete-rollout` plans the full encryption lifecycle (schema-add through drop) in one document. It SKIPS the production-deploy gate that protects backfill from running before dual-writes are live.',
  )
  p.log.warn(
    'Only safe when this database is not backing a deployed application — local development, ephemeral test environments, or freshly seeded sandboxes. If a deployed app writes to this database, rows inserted during the planned backfill will land in plaintext only and you will need a recovery pass.',
  )
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
 *                          one document with no deploy gate. Confirms
 *                          (default-no) before generating.
 */
export async function planCommand(flags: Record<string, boolean> = {}) {
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

  p.intro('CipherStash Plan')

  try {
    if (existsSync(resolve(cwd, PLAN_REL_PATH))) {
      p.log.warn(
        `Plan already exists at \`${PLAN_REL_PATH}\`. The agent will be told to revise it; delete the file first if you want to start fresh.`,
      )
    }

    let planStep: PlanStep
    if (flags['complete-rollout']) {
      await confirmCompleteRollout()
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

    await howToProceedStep.run(state)

    if (process.stdout.isTTY) {
      const proceed = await p.confirm({
        message: `Plan drafted at \`${PLAN_REL_PATH}\`. Continue to \`${cli} impl\` now?`,
        initialValue: true,
      })
      if (!p.isCancel(proceed) && proceed) {
        p.outro('Plan complete — handing off to `stash impl`.')
        const { implCommand } = await import('../impl/index.js')
        await implCommand({})
        return
      }
    }

    p.outro(
      `Plan drafted at \`${PLAN_REL_PATH}\`. Review it, then run \`${cli} impl\` to implement.`,
    )
  } catch (err) {
    if (err instanceof CancelledError) {
      p.cancel('Cancelled.')
      process.exit(0)
    }
    throw err
  }
}
