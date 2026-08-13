import { existsSync, globSync, readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'
import { workspacePackagePatterns } from '../release-gate.mjs'
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
 * Bare invocations that predate this guard, allowed to stay. Empty, and kept
 * rather than deleted.
 *
 * It held two entries. `pnpm --filter @cipherstash/stack-prisma run typecheck`
 * is why: the EQL subtree import turned `@cipherstash/eql` from a registry
 * tarball with `dist/` inside into a workspace package whose `dist/` is a build
 * output, and that step was the first in its job to need one. It failed
 * `TS2307` on three files in CI. The other entry,
 * `pnpm --filter @cipherstash/wizard run typecheck`, was routed through turbo
 * at the same time — not because it was at risk (wizard has no workspace
 * dependencies at all) but because an empty list is a rule and a one-entry list
 * is a habit.
 *
 * Every entry here is a bet that no future change makes an undeclared ordering
 * false. One of the two lost, to a change made deliberately and reviewed
 * carefully, eight commits earlier. Do not add to it.
 */
const KNOWN_BARE = new Set([])

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

/**
 * The blind spot the check above cannot see, and how it was found.
 *
 * That check asks "is this script a task `turbo.json` declares with
 * `dependsOn: ["^build"]`?". It is a question about turbo's configuration, and
 * the risk is not in turbo's configuration — it is in the package graph. Five
 * bare steps invoked `test:types` and `test:typecheck:wasm`, which are package
 * scripts and not turbo tasks at all, so the check skipped them in silence.
 * Their packages import build output from workspace dependencies exactly like
 * `stack-prisma` does; they simply had not broken yet.
 *
 * So this asks the question the risk is actually made of: **does the package
 * whose script is being run depend on a workspace package that emits a build?**
 * If it does, running its script bare means resolving `dist/` that nothing in
 * the command guarantees exists. The two checks are kept side by side because
 * neither implies the other — a package with no buildable dependencies can
 * still run a `^build` task bare (harmlessly), and a package full of them can
 * run a script turbo has never heard of (which is the case that bit).
 *
 * Composite actions are scanned too. An action under `.github/actions` runs its
 * steps on the same runner as the job that calls it, and nothing about the trap
 * changes when the step is one file further away — but `workflowFiles()` never
 * looks there.
 */

/** Workspace members, by package name, resolved from pnpm's own globs. */
const WORKSPACE = (() => {
  const patterns = workspacePackagePatterns(
    readFileSync(resolve(REPO_ROOT, 'pnpm-workspace.yaml'), 'utf8'),
  ).map((pattern) => pattern + '/package.json')
  const byName = new Map()
  for (const rel of globSync(patterns, { cwd: REPO_ROOT }).sort()) {
    const manifest = JSON.parse(readFileSync(resolve(REPO_ROOT, rel), 'utf8'))
    if (manifest.name) byName.set(manifest.name, manifest)
  }
  return byName
})()

/** A package emits build output when it declares a `build` script. */
const emitsBuildOutput = (name) =>
  typeof WORKSPACE.get(name)?.scripts?.build === 'string'

/**
 * Package names whose DIRECT workspace dependencies include at least one that
 * emits build output.
 *
 * Direct, not transitive, and that is the right depth: a bare script resolves
 * the specifiers this package declares. A transitive dependency is reached
 * through one of them, so the direct one already implicates it.
 */
const NEEDS_BUILT_DEPS = new Set(
  [...WORKSPACE]
    .filter(([, manifest]) =>
      Object.entries({
        ...manifest.dependencies,
        ...manifest.devDependencies,
      }).some(
        ([dep, spec]) =>
          String(spec).startsWith('workspace:') && emitsBuildOutput(dep),
      ),
    )
    .map(([name]) => name),
)

/** Each composite action's manifest, which `workflowFiles()` does not return. */
function actionFiles() {
  const dir = resolve(REPO_ROOT, '.github/actions')
  return readdirSync(dir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => '.github/actions/' + entry.name + '/action.yml')
    .filter((rel) => existsSync(resolve(REPO_ROOT, rel)))
}

/** Run lines from a composite action, shaped like `workflowRunLines`. */
function actionRunLines(relPath) {
  const doc = yaml.load(readFileSync(resolve(REPO_ROOT, relPath), 'utf8'))
  const lines = []
  for (const step of doc?.runs?.steps ?? []) {
    if (typeof step?.run !== 'string') continue
    for (const raw of step.run.split('\n')) {
      const line = raw.trim()
      if (line) lines.push({ jobName: 'runs', stepName: step.name, line })
    }
  }
  return lines
}

/** The package a `--filter`ed pnpm line targets, or null. */
function filteredPackage(line) {
  return line.match(/\bpnpm\b.*?\s(?:--filter|-F)\s+(\S+)/)?.[1] ?? null
}

/** Every bare, package-filtered pnpm invocation across workflows and actions. */
const BARE_FILTERED = [
  ...WORKFLOWS.map((file) => [file, workflowRunLines(file)]),
  ...actionFiles().map((file) => [file, actionRunLines(file)]),
].flatMap(([file, lines]) =>
  lines
    .map((entry) => ({ ...entry, file, pkg: filteredPackage(entry.line) }))
    .filter(({ line, pkg }) => {
      if (!pkg) return false
      const invoked = invokedTask(line)
      return Boolean(invoked) && !invoked.routed
    }),
)

describe('a bare pnpm --filter never resolves an unbuilt workspace dependency', () => {
  it('the workspace graph resolved, and knows which packages build', () => {
    // Every claim below is read off this graph. Resolved from pnpm's own globs
    // rather than a list, so it covers a package added tomorrow — and asserted
    // here, because a graph that came back empty would make the real check pass
    // over nothing at all.
    expect(WORKSPACE.size).toBeGreaterThan(10)
    expect(emitsBuildOutput('@cipherstash/eql')).toBe(true)
    expect(NEEDS_BUILT_DEPS.has('@cipherstash/stack-prisma')).toBe(true)
    // The two that are safe on the merits rather than by exemption. If either
    // ever gains a buildable workspace dependency, this flips and the check
    // below starts covering its steps — which is the intended behaviour, and
    // the reason neither is on an allowlist.
    expect(NEEDS_BUILT_DEPS.has('@cipherstash/protect-ffi')).toBe(false)
    expect(NEEDS_BUILT_DEPS.has('@cipherstash/wizard')).toBe(false)
  })

  it('still finds the bare filtered invocations it is meant to judge', () => {
    // The scan's floor. Five bare `pnpm --filter @cipherstash/protect-ffi …`
    // steps exist and are legitimate; if the extraction breaks, they vanish
    // from the scan and the check below passes over an empty set.
    expect(BARE_FILTERED.length).toBeGreaterThanOrEqual(5)
    expect(
      BARE_FILTERED.some((entry) => entry.file.startsWith('.github/actions/')),
      'No composite action step was scanned — actionFiles() or actionRunLines() has stopped matching, and the actions are back to being invisible.',
    ).toBe(true)
  })

  it('no bare filtered invocation targets a package that needs built deps', () => {
    const offenders = BARE_FILTERED.filter(({ pkg }) =>
      NEEDS_BUILT_DEPS.has(pkg),
    ).map(
      ({ file, jobName, stepName, line }) =>
        `${file} / ${jobName} / ${stepName}: ${line}`,
    )

    expect(
      offenders,
      'These steps run a package script with a bare `pnpm --filter`, and the package imports build output from a workspace dependency. Nothing in the command builds it — they pass only while an earlier step in the same job happens to, which is an ordering nobody declared and reviewers cannot see. Route them through `pnpm exec turbo run <script> --filter <pkg>`, declaring the script in turbo.json if it is not a task yet.',
    ).toEqual([])
  })
})
