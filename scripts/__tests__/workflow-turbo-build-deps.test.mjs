import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import { readJsonc } from './lib/read-jsonc.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * A turbo task declaring `dependsOn: ["^build"]` gets its workspace
 * dependencies built before it runs — but ONLY when turbo is the one invoking
 * it. Run the same task as a bare package script (`pnpm --filter <pkg> run
 * <task>`) and the dependency graph is skipped silently.
 *
 * That failure mode is invisible in CI, because a bare step usually still
 * passes: some earlier step in the same job built the workspace via its own
 * `^build`. The step is then load-bearing on an ordering nobody declared.
 * Reorder or delete that earlier step — and they read as independent guards
 * for other packages, so they look freely removable — and the bare step fails
 * with a module-resolution error (`TS2307`, `Failed to resolve entry for
 * package`) that reads as "the code is broken" rather than "you skipped the
 * build".
 *
 * This is not hypothetical: #787 added `typecheck:scaffold` as a bare
 * `pnpm --filter stash run typecheck:scaffold` and it went green for exactly
 * that reason. The fixtures it typechecks import `@cipherstash/stack/v3`, so
 * the step needs that package built; it was routed through turbo in review.
 * This test pins that routing so it cannot be quietly "simplified" back.
 */

/**
 * The workflow that must carry the `typecheck:scaffold` step specifically.
 * Scoped, because "that step exists" is a claim about this file, not about
 * workflows in general.
 */
const SCAFFOLD_WORKFLOW = '.github/workflows/tests.yml'

/**
 * Every workflow, not just `tests.yml`. A bare build-dependent step is the same
 * latent trap wherever it runs, and the integration workflows are where it is
 * least visible: they build only `stash` (via the shared `integration-setup`
 * action) and reach every other package through that one task's `^build`.
 * Narrowing the guard to one file left five real bare invocations unchecked
 * (#787 review follow-up).
 */
const WORKFLOWS = workflowFiles()

/**
 * Bare invocations that predate this guard. Each is the same latent trap: it
 * passes today only because an earlier step in its job builds the workspace.
 * They are recorded rather than ignored so the list can be worked down — do
 * not add to it. Route new steps through `turbo run` instead.
 */
const KNOWN_BARE = new Set([
  'pnpm --filter @cipherstash/stack-prisma run typecheck',
  'pnpm --filter @cipherstash/wizard run typecheck',
])

const turboJson = readJsonc(resolve(REPO_ROOT, 'turbo.json'))
const rootScripts =
  JSON.parse(readFileSync(resolve(REPO_ROOT, 'package.json'), 'utf8'))
    .scripts ?? {}

/** Turbo tasks that build their workspace dependencies first. */
const buildDependentTasks = new Set(
  Object.entries(turboJson.tasks ?? {})
    .filter(([, task]) => (task?.dependsOn ?? []).includes('^build'))
    .map(([name]) => name),
)

/** pnpm's own verbs — never package scripts. */
const PNPM_VERBS = new Set([
  'install',
  'exec',
  'dlx',
  'add',
  'why',
  'store',
  'run',
])

/**
 * The task a command line runs, and whether turbo is the thing running it.
 * Returns null when the line runs no recognisable task.
 *
 * Two shapes matter:
 *   `pnpm exec turbo run <task> --filter <pkg>` / `pnpm turbo <task>` → routed
 *   `pnpm [--filter <pkg>] [run] <task>`                             → bare
 */
function invokedTask(line) {
  const turbo = line.match(/\bturbo\b\s+(?:run\s+)?([\w:.-]+)/)
  if (turbo) return { task: turbo[1], routed: true, filtered: false }

  const pnpm = line.match(
    /\bpnpm\b(?:\s+(?:--filter|-F)\s+\S+|\s+--if-present)*\s+(?:run\s+)?([\w:.-]+)/,
  )
  if (!pnpm) return null
  const task = pnpm[1]
  if (PNPM_VERBS.has(task)) return null
  return { task, routed: false, filtered: /\s(?:--filter|-F)\s/.test(line) }
}

/**
 * Root scripts may delegate to turbo themselves (`"test": "turbo test ..."`).
 *
 * Only ever consult this for an UNFILTERED invocation. `pnpm --filter <pkg>
 * <task>` runs that package's script, so the root script's delegation says
 * nothing about it — reading it either way exempted a genuinely bare
 * `pnpm --filter @cipherstash/prisma-example test:e2e` purely because the
 * root happens to define `"test:e2e": "turbo run test:e2e"` (#787 review
 * follow-up).
 */
const rootScriptDelegatesToTurbo = (task) =>
  typeof rootScripts[task] === 'string' && /\bturbo\b/.test(rootScripts[task])

function workflowRunLines(path) {
  const doc = readWorkflow(path)
  const lines = []
  for (const [jobName, job] of Object.entries(doc?.jobs ?? {})) {
    for (const step of job?.steps ?? []) {
      if (typeof step?.run !== 'string') continue
      for (const raw of step.run.split('\n')) {
        const line = raw.trim()
        if (line) lines.push({ jobName, stepName: step.name, line })
      }
    }
  }
  return lines
}

describe('workflows route build-dependent turbo tasks through turbo', () => {
  it('turbo.json declares the tasks this guard protects', () => {
    // If `^build` is dropped from these, the guard below silently stops
    // checking anything — assert the premise rather than trusting it.
    expect(buildDependentTasks).toContain('typecheck:scaffold')
    expect(buildDependentTasks).toContain('typecheck')
    expect(buildDependentTasks).toContain('build')
  })

  it('typecheck:scaffold is invoked via turbo, never bare', () => {
    const invocations = workflowRunLines(SCAFFOLD_WORKFLOW).filter(
      ({ line }) => invokedTask(line)?.task === 'typecheck:scaffold',
    )

    // A bare `pnpm --filter stash run typecheck:scaffold` matches
    // `invokedTask` but not `routedThroughTurbo`, so it would fail here.
    // Deleting the step entirely is caught by this length assertion.
    expect(
      invocations.length,
      `${SCAFFOLD_WORKFLOW} must run typecheck:scaffold — the scaffold fixtures are only typechecked there`,
    ).toBeGreaterThan(0)

    for (const { jobName, stepName, line } of invocations) {
      expect(
        invokedTask(line).routed,
        `${SCAFFOLD_WORKFLOW} job "${jobName}" step "${stepName}" runs typecheck:scaffold without turbo:\n  ${line}\nThe scaffold fixtures import @cipherstash/stack/v3, so this needs that package BUILT. Use \`pnpm exec turbo run typecheck:scaffold --filter stash\`.`,
      ).toBe(true)
    }
  })

  it('no new bare invocation of a build-dependent turbo task in any workflow', () => {
    const offenders = WORKFLOWS.flatMap((file) =>
      workflowRunLines(file)
        .filter(({ line }) => {
          const invoked = invokedTask(line)
          if (!invoked || invoked.routed) return false
          if (!buildDependentTasks.has(invoked.task)) return false
          // A filtered invocation runs the package's own script, so the root
          // script's turbo delegation is irrelevant to it.
          if (!invoked.filtered && rootScriptDelegatesToTurbo(invoked.task))
            return false
          return !KNOWN_BARE.has(line)
        })
        .map(
          ({ jobName, stepName, line }) =>
            `${file} / ${jobName} / ${stepName}: ${line}`,
        ),
    )

    expect(
      offenders,
      `These steps run a turbo task declaring \`dependsOn: ["^build"]\` without turbo, so nothing guarantees their workspace dependencies are built. They pass only while an earlier step in the same job happens to build them. Route them through \`pnpm exec turbo run <task> --filter <pkg>\`.`,
    ).toEqual([])
  })

  it('the grandfathered bare invocations still exist as written', () => {
    // KNOWN_BARE entries are matched by exact string. If a step is reworded or
    // fixed, its entry goes stale and silently exempts nothing — or worse,
    // masks a different line later. Fail so the list gets pruned.
    // Searched across every workflow, not just tests.yml: the allowlist now
    // exempts lines found anywhere, so a narrower staleness check would let an
    // entry keep exempting a step it no longer describes.
    const lines = new Set(
      WORKFLOWS.flatMap((file) => workflowRunLines(file)).map(
        ({ line }) => line,
      ),
    )
    for (const bare of KNOWN_BARE) {
      expect(
        lines.has(bare),
        `KNOWN_BARE entry is stale — no workflow step runs:\n  ${bare}\nRemove it from the allowlist.`,
      ).toBe(true)
    }
  })
})
