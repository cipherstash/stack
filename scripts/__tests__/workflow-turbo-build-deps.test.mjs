import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { readJsonc } from './lib/read-jsonc.mjs'

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

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../..')
const WORKFLOW = '.github/workflows/tests.yml'

/**
 * Bare invocations that predate this guard. Each is the same latent trap: it
 * passes today only because an earlier step in its job builds the workspace.
 * They are recorded rather than ignored so the list can be worked down — do
 * not add to it. Route new steps through `turbo run` instead.
 */
const KNOWN_BARE = new Set([
  'pnpm --filter @cipherstash/prisma-next run typecheck',
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
  if (turbo) return { task: turbo[1], routed: true }

  const pnpm = line.match(
    /\bpnpm\b(?:\s+(?:--filter|-F)\s+\S+|\s+--if-present)*\s+(?:run\s+)?([\w:.-]+)/,
  )
  if (!pnpm) return null
  const task = pnpm[1]
  if (PNPM_VERBS.has(task)) return null
  return { task, routed: false }
}

/** Root scripts may delegate to turbo themselves (`"test": "turbo test ..."`). */
const rootScriptDelegatesToTurbo = (task) =>
  typeof rootScripts[task] === 'string' && /\bturbo\b/.test(rootScripts[task])

function workflowRunLines(path) {
  const doc = yaml.load(readFileSync(resolve(REPO_ROOT, path), 'utf8'))
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

describe('tests.yml routes build-dependent turbo tasks through turbo', () => {
  it('turbo.json declares the tasks this guard protects', () => {
    // If `^build` is dropped from these, the guard below silently stops
    // checking anything — assert the premise rather than trusting it.
    expect(buildDependentTasks).toContain('typecheck:scaffold')
    expect(buildDependentTasks).toContain('typecheck')
    expect(buildDependentTasks).toContain('build')
  })

  it('typecheck:scaffold is invoked via turbo, never bare', () => {
    const invocations = workflowRunLines(WORKFLOW).filter(
      ({ line }) => invokedTask(line)?.task === 'typecheck:scaffold',
    )

    // A bare `pnpm --filter stash run typecheck:scaffold` matches
    // `invokedTask` but not `routedThroughTurbo`, so it would fail here.
    // Deleting the step entirely is caught by this length assertion.
    expect(
      invocations.length,
      `${WORKFLOW} must run typecheck:scaffold — the scaffold fixtures are only typechecked there`,
    ).toBeGreaterThan(0)

    for (const { jobName, stepName, line } of invocations) {
      expect(
        invokedTask(line).routed,
        `${WORKFLOW} job "${jobName}" step "${stepName}" runs typecheck:scaffold without turbo:\n  ${line}\nThe scaffold fixtures import @cipherstash/stack/v3, so this needs that package BUILT. Use \`pnpm exec turbo run typecheck:scaffold --filter stash\`.`,
      ).toBe(true)
    }
  })

  it('no new bare invocation of a build-dependent turbo task', () => {
    const offenders = workflowRunLines(WORKFLOW)
      .filter(({ line }) => {
        const invoked = invokedTask(line)
        if (!invoked || invoked.routed) return false
        if (!buildDependentTasks.has(invoked.task)) return false
        if (rootScriptDelegatesToTurbo(invoked.task)) return false
        return !KNOWN_BARE.has(line)
      })
      .map(({ jobName, stepName, line }) => `${jobName} / ${stepName}: ${line}`)

    expect(
      offenders,
      `These steps run a turbo task declaring \`dependsOn: ["^build"]\` without turbo, so nothing guarantees their workspace dependencies are built. They pass only while an earlier step in the same job happens to build them. Route them through \`pnpm exec turbo run <task> --filter <pkg>\`.`,
    ).toEqual([])
  })

  it('the grandfathered bare invocations still exist as written', () => {
    // KNOWN_BARE entries are matched by exact string. If a step is reworded or
    // fixed, its entry goes stale and silently exempts nothing — or worse,
    // masks a different line later. Fail so the list gets pruned.
    const lines = new Set(workflowRunLines(WORKFLOW).map(({ line }) => line))
    for (const bare of KNOWN_BARE) {
      expect(
        lines.has(bare),
        `KNOWN_BARE entry is stale — no step in ${WORKFLOW} runs:\n  ${bare}\nRemove it from the allowlist.`,
      ).toBe(true)
    }
  })
})
