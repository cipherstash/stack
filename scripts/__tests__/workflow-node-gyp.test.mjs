import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * Every job that runs `pnpm install` on a Linux runner must install `node-gyp`
 * first.
 *
 * WHY THIS IS A RULE AND NOT A COINCIDENCE. `node-pty` is a dev-dependency of
 * the `stash` CLI (its pty-driven E2E suite) and the repo's ONE entry in
 * `pnpm.onlyBuiltDependencies`, so it is the one package permitted to run a
 * lifecycle script — and its script is
 *
 *     "install": "node scripts/prebuild.js || node-gyp rebuild"
 *
 * `prebuild.js` is a bare `existsSync` on `prebuilds/<platform>-<arch>`, with no
 * network fetch and no ABI check. The 1.1.0 tarball ships four of those
 * directories — `darwin-arm64`, `darwin-x64`, `win32-arm64`, `win32-x64` — and
 * no `linux-*` at all. So on a Linux runner the fallback is not an edge case,
 * it is the only path: every workspace install in this repo compiles node-pty
 * from source. npm bundles `node-gyp`; pnpm does not, and
 * `pnpm/action-setup@v6` no longer puts it on PATH. Hence the three-line
 * `npm install -g node-gyp` step repeated across the workflows.
 *
 * WHAT HAPPENED. Two workflows added during the protect-ffi absorption —
 * `tests-rust.yml` and `integration-protect-ffi.yml` — copied the pnpm + Node
 * preamble without that step. Both died in `Install dependencies` with
 * `sh: 1: node-gyp: not found`, on every run, from the day they landed: 11 and
 * 8 runs respectively, none of which reached cargo or vitest. Neither job uses
 * a pty, which is exactly why the omission looked harmless — the dependency is
 * on the workspace install, not on anything the job does.
 *
 * The step is also invisible locally: macOS has a matching prebuild, so
 * `pnpm install` on a contributor's machine never touches node-gyp. This
 * failure mode is only reachable from CI, which is precisely the kind that
 * needs a check rather than a reviewer.
 *
 * WHAT THIS CHECKS, AND WHY IT FOLLOWS COMPOSITES. Four of the sixteen
 * installing jobs never mention `pnpm install` in their own workflow file —
 * they reach it through `uses: ./.github/actions/integration-setup`, which
 * carries both the node-gyp step and the install. A scan that stopped at the
 * workflow's own step list would report those four as violations and, worse,
 * would let a future composite that installs without node-gyp through. So the
 * traversal opens every local `uses:` and flattens it in place, and a local
 * `uses:` it cannot open is a FAILURE rather than a skip — "could not look" and
 * "looked and found nothing" must not produce the same green.
 */

/**
 * The JOBS that run a workspace install today. This is NOT the list the checks
 * iterate — those scan the directory — it is the guard on the scan.
 *
 * Jobs, not files, and for the reason spelled out in
 * `ffi-binding-step-order.test.mjs`: the per-job check is GENERATED from the
 * scan, so removing a job's install step does not fail its check, it deletes
 * it. A file-granular list cannot see that — `tests.yml` alone accounts for
 * five of these, so four could vanish with the file still "found".
 *
 * A minimum, not an equality: a new job that installs must be subjected to the
 * check below, not rejected by this list. If a job legitimately stops
 * installing, remove it here deliberately.
 */
const EXPECTED_INSTALLING_JOBS = [
  '.github/workflows/fta-v3.yml / fta',
  '.github/workflows/integration-drizzle.yml / integration',
  '.github/workflows/integration-prisma-next.yml / integration',
  '.github/workflows/integration-protect-ffi.yml / integration',
  '.github/workflows/integration-supabase.yml / integration',
  '.github/workflows/prisma-example-readme-e2e.yml / walkthrough',
  '.github/workflows/prisma-next-e2e.yml / e2e',
  '.github/workflows/release.yml / release',
  '.github/workflows/tests-bench.yml / tests-bench',
  '.github/workflows/tests-rust.yml / rust',
  '.github/workflows/tests-supply-chain.yml / verify-no-caching-in-release-workflows',
  '.github/workflows/tests.yml / e2e-tests',
  '.github/workflows/tests.yml / lint',
  '.github/workflows/tests.yml / run-tests',
  '.github/workflows/tests.yml / run-tests-bun',
  '.github/workflows/tests.yml / wasm-e2e-tests',
]

/**
 * The jobs whose install is reached through a local composite action. Held
 * separately because it is the traversal itself that is being asserted: drop
 * the composite following and these four stop being seen as installing jobs at
 * all, `EXPECTED_INSTALLING_JOBS` above goes red — but this says which capability
 * broke rather than leaving four names to puzzle over.
 */
const EXPECTED_COMPOSITE_INSTALLS = [
  '.github/workflows/integration-drizzle.yml / integration',
  '.github/workflows/integration-prisma-next.yml / integration',
  '.github/workflows/integration-supabase.yml / integration',
  '.github/workflows/tests-bench.yml / tests-bench',
]

// ---------------------------------------------------------------------------
// Step predicates
// ---------------------------------------------------------------------------

/**
 * `pnpm … install` / `pnpm … i` as a whole token. The trailing `(\s|$)` is what
 * keeps `pnpm run install:deps` and `pnpm run lint:installed` out: both contain
 * the word but neither is an install.
 *
 * Deliberately loose about what sits between `pnpm` and the verb, so
 * `pnpm --filter x install` and `pnpm install --frozen-lockfile` both match. An
 * over-broad match here costs a spurious `npm install -g node-gyp`; a narrow
 * one costs a job that never starts.
 */
const PNPM_INSTALL = /(?:^|[\s;&|(])pnpm\s+(?:[^\n]*\s)?(?:install|i)(?:\s|$)/m

/** `pnpm/action-setup` performs the install itself when told to. */
const PNPM_ACTION_SETUP = /^pnpm\/action-setup(?:@|$)/

/**
 * A global `node-gyp` install. Stricter than "mentions node-gyp" on purpose: a
 * comment or an env var naming it must not satisfy the rule, because neither
 * puts a binary on PATH.
 */
const INSTALLS_NODE_GYP =
  /\bnpm\s+(?:install|i|add)\s+(?:-g|--global)\s+[^\n]*\bnode-gyp\b/

/**
 * The exemption. `--ignore-scripts` means no lifecycle script runs, so
 * node-pty's hook never fires and node-gyp is genuinely not needed.
 */
const IGNORE_SCRIPTS = /--ignore-scripts\b/

/**
 * Runner labels that ship a node-pty prebuild, i.e. where the gyp fallback is
 * not reached. Everything else — including a `${{ matrix.os }}` expression this
 * file cannot resolve — is treated as needing node-gyp. That is the fail-closed
 * direction: a redundant 3-second step on a macOS runner is free, a missing one
 * on Linux is a job that never starts.
 */
const PREBUILT_RUNNER = /(?:^|[\s-])(?:macos|windows|win32|darwin)(?:[\s-]|$)/i

function usesOf(step) {
  return typeof step?.uses === 'string' ? step.uses.trim() || null : null
}

function runOf(step) {
  return typeof step?.run === 'string' ? step.run : null
}

export function isInstallStep(step) {
  const run = runOf(step)
  if (run !== null && PNPM_INSTALL.test(run)) return true
  const uses = usesOf(step)
  // `run_install:` accepts `true` or a recipe list; both install.
  return (
    uses !== null &&
    PNPM_ACTION_SETUP.test(uses) &&
    Boolean(step?.with?.run_install)
  )
}

export function exemptFromNodeGyp(step) {
  const run = runOf(step)
  return run !== null && IGNORE_SCRIPTS.test(run)
}

export function providesNodeGyp(step) {
  const run = runOf(step)
  return run !== null && INSTALLS_NODE_GYP.test(run)
}

export function needsNodeGyp(runsOn) {
  if (typeof runsOn !== 'string') return true
  return !PREBUILT_RUNNER.test(runsOn)
}

// ---------------------------------------------------------------------------
// Traversal
// ---------------------------------------------------------------------------

const LOCAL_USES = /^\.{1,2}\//

function stepLabel(step, index) {
  return step?.name || usesOf(step) || `step #${index + 1}`
}

/**
 * Flattens a step list, splicing a local composite action's own steps in at the
 * position of the `uses:` that reaches it. The result is the sequence GitHub
 * actually executes, which is the only sequence in which "before" means
 * anything.
 *
 * `resolveComposite` is injected so the checker can be exercised against
 * synthetic composites below without writing fixture files — an in-repo scan is
 * not a test of the traversal, it is a test of the repo.
 *
 * `visited` breaks the `A uses B uses A` cycle. Scoped per job, matching
 * `lint-no-workflow-caching.mjs`: a composite shared by two jobs is flattened
 * into each.
 */
export function flattenSteps(
  steps,
  resolveComposite,
  trail = '',
  visited = new Set(),
) {
  const flat = []
  const unresolved = []

  ;(Array.isArray(steps) ? steps : []).forEach((step, index) => {
    const label = `${trail}${stepLabel(step, index)}`
    const uses = usesOf(step)

    if (uses === null || !LOCAL_USES.test(uses)) {
      flat.push({ step, label })
      return
    }

    const composite = resolveComposite(uses)
    if (composite === null) {
      // Fail closed. A local `uses:` pointing at nothing fails the job on
      // GitHub anyway; passing it here would make "rename the action" a way to
      // leave this check with nothing to read.
      unresolved.push(`${label}: \`uses: ${uses}\` — no action manifest there`)
      flat.push({ step, label })
      return
    }
    if (visited.has(composite.id)) return
    visited.add(composite.id)

    const nested = flattenSteps(
      composite.steps,
      resolveComposite,
      `${label} -> ${composite.id} step "`,
      visited,
    )
    for (const entry of nested.flat) {
      flat.push({ step: entry.step, label: `${entry.label}"` })
    }
    unresolved.push(...nested.unresolved)
  })

  return { flat, unresolved }
}

/**
 * The rule itself, over an already-flattened sequence: for each install step,
 * some EARLIER step must have put node-gyp on PATH.
 *
 * Position, not mere presence. A node-gyp step written after the install is the
 * same failure as no node-gyp step at all, and it is the more likely edit —
 * steps get appended.
 */
export function auditFlattened(flat) {
  const installs = []
  const violations = []

  flat.forEach((entry, index) => {
    if (!isInstallStep(entry.step)) return
    installs.push(entry.label)
    if (exemptFromNodeGyp(entry.step)) return
    const satisfied = flat
      .slice(0, index)
      .some((earlier) => providesNodeGyp(earlier.step))
    if (!satisfied) violations.push(entry.label)
  })

  return { installs, violations }
}

// ---------------------------------------------------------------------------
// The repo scan
// ---------------------------------------------------------------------------

/**
 * GitHub resolves `uses: ./x` against the checkout root, not the calling file.
 * Both manifest spellings are valid, so probing only `action.yml` would stop
 * the traversal dead at a composite that used the other one.
 */
function resolveRepoComposite(usesPath) {
  const dir = usesPath.replace(LOCAL_USES, '')
  for (const name of ['action.yml', 'action.yaml']) {
    const rel = `${dir}/${name}`
    if (existsSync(join(REPO_ROOT, rel))) {
      const doc = readWorkflow(rel)
      return { id: rel, steps: doc?.runs?.steps ?? [] }
    }
  }
  return null
}

function scan() {
  const jobs = []
  for (const relPath of workflowFiles()) {
    const wf = readWorkflow(relPath)
    for (const [jobName, job] of Object.entries(wf?.jobs ?? {})) {
      const { flat, unresolved } = flattenSteps(
        job?.steps,
        resolveRepoComposite,
      )
      const { installs, violations } = auditFlattened(flat)
      if (installs.length === 0 && unresolved.length === 0) continue
      jobs.push({
        id: `${relPath} / ${jobName}`,
        runsOn: job?.['runs-on'],
        ownSteps: Array.isArray(job?.steps) ? job.steps : [],
        flat,
        installs,
        violations,
        unresolved,
      })
    }
  }
  return jobs
}

const SCANNED = scan()
const INSTALLING = SCANNED.filter((job) => job.installs.length > 0)

describe('every pnpm install has node-gyp on PATH first', () => {
  it('finds the jobs that run a workspace install', () => {
    const missing = EXPECTED_INSTALLING_JOBS.filter(
      (id) => !INSTALLING.some((job) => job.id === id),
    )
    expect(
      missing,
      'These jobs ran `pnpm install` and the scan no longer sees them. Either the install step was removed (update EXPECTED_INSTALLING_JOBS deliberately) or it is now spelled in a way PNPM_INSTALL does not match — in which case the check for that job did not fail, it stopped existing.',
    ).toEqual([])
  })

  it('follows local composite actions to find their install', () => {
    const missing = EXPECTED_COMPOSITE_INSTALLS.filter((id) => {
      const job = INSTALLING.find((entry) => entry.id === id)
      if (!job) return true
      // The job's own step list must NOT contain the install — that is what
      // makes it a test of the traversal rather than of the workflow.
      return job.ownSteps.some((step) => isInstallStep(step))
    })
    expect(
      missing,
      'These jobs reach `pnpm install` only through a local composite action, so seeing them proves the traversal opens composites. If one now installs in its own step list, move it out of EXPECTED_COMPOSITE_INSTALLS; if it is missing entirely, the composite following is broken and the checks below are reading half the repo.',
    ).toEqual([])
  })

  it('resolves every local action reference it walks through', () => {
    const unresolved = SCANNED.flatMap((job) =>
      job.unresolved.map((entry) => `${job.id}: ${entry}`),
    )
    expect(
      unresolved,
      'A `uses: ./…` pointed at no action.yml or action.yaml. This check cannot read the steps behind it, so it cannot prove they install node-gyp before installing dependencies — and GitHub fails the job on this anyway.',
    ).toEqual([])
  })

  for (const job of INSTALLING) {
    it(`${job.id} installs node-gyp before its dependencies`, () => {
      if (!needsNodeGyp(job.runsOn)) return
      const order = job.flat
        .map((entry, index) => `  ${index}: ${entry.label}`)
        .join('\n')
      expect(
        job.violations,
        `This job runs a workspace install with no \`node-gyp\` on PATH ahead of it, so it fails in that step with \`sh: 1: node-gyp: not found\` before running anything of its own.\n\nnode-pty is the repo's one entry in \`pnpm.onlyBuiltDependencies\` and its install hook is \`node scripts/prebuild.js || node-gyp rebuild\`. The 1.1.0 tarball ships no linux prebuild, so on a Linux runner that fallback always fires; pnpm does not bundle node-gyp and \`pnpm/action-setup@v6\` does not put it on PATH.\n\nAdd, before the install:\n\n      - name: Install node-gyp\n        run: npm install -g node-gyp\n\nSteps as ordered:\n${order}`,
      ).toEqual([])
    })
  }
})

describe('the checker this guard depends on', () => {
  // A checker that answers "fine" to everything is a check that cannot fail.
  // These pin both verdicts, including the exact shape of the bug that
  // motivated the file.
  const install = {
    name: 'Install dependencies',
    run: 'pnpm install --frozen-lockfile',
  }
  const gyp = { name: 'Install node-gyp', run: 'npm install -g node-gyp' }
  const noComposites = () => null

  const audit = (steps, resolveComposite = noComposites) =>
    auditFlattened(flattenSteps(steps, resolveComposite).flat)

  it('reproduces the defect: an install with no node-gyp step', () => {
    const { installs, violations } = audit([
      { uses: 'actions/setup-node@v6.5.0' },
      install,
    ])
    expect(installs).toHaveLength(1)
    expect(violations).toEqual(['Install dependencies'])
  })

  it('clears the fixed shape', () => {
    expect(audit([gyp, install]).violations).toEqual([])
  })

  it('rejects a node-gyp step that runs after the install', () => {
    // Presence is not the property; order is. This is the likelier regression,
    // because steps get appended.
    expect(audit([install, gyp]).violations).toEqual(['Install dependencies'])
  })

  it('accepts an install that runs no lifecycle scripts', () => {
    const ignored = {
      name: 'Install',
      run: 'pnpm install --frozen-lockfile --ignore-scripts',
    }
    expect(audit([ignored]).violations).toEqual([])
  })

  it('finds node-gyp inside a composite action that runs before the install', () => {
    const resolveComposite = (uses) =>
      uses === './.github/actions/setup'
        ? { id: 'setup/action.yml', steps: [gyp] }
        : null
    const { installs, violations } = audit(
      [{ uses: './.github/actions/setup' }, install],
      resolveComposite,
    )
    expect(installs).toHaveLength(1)
    expect(violations).toEqual([])
  })

  it('finds an install inside a composite action', () => {
    const resolveComposite = (uses) =>
      uses === './.github/actions/setup'
        ? { id: 'setup/action.yml', steps: [install] }
        : null
    const { installs, violations } = audit(
      [{ uses: './.github/actions/setup' }],
      resolveComposite,
    )
    expect(installs).toHaveLength(1)
    expect(violations).toHaveLength(1)
  })

  it('reports a local action it cannot open rather than skipping it', () => {
    const { unresolved } = flattenSteps(
      [{ uses: './.github/actions/gone' }],
      noComposites,
    )
    expect(unresolved).toHaveLength(1)
  })

  it('terminates on a composite cycle', () => {
    const resolveComposite = (uses) =>
      uses === './a'
        ? { id: 'a', steps: [{ uses: './b' }] }
        : { id: 'b', steps: [{ uses: './a' }, install] }
    expect(() => audit([{ uses: './a' }], resolveComposite)).not.toThrow()
  })

  it('treats `pnpm/action-setup` with run_install as an install', () => {
    const runInstall = {
      uses: 'pnpm/action-setup@v6.0.9',
      with: { run_install: true },
    }
    expect(audit([runInstall]).violations).toHaveLength(1)
    expect(
      audit([
        { uses: 'pnpm/action-setup@v6.0.9', with: { run_install: false } },
      ]).installs,
    ).toEqual([])
  })

  it('does not mistake a script name for an install', () => {
    // `pnpm run install:deps` and friends contain the word and install nothing.
    for (const run of [
      'pnpm run install:deps',
      'pnpm run lint:installed',
      'pnpm test',
    ]) {
      expect(audit([{ name: run, run }]).installs, run).toEqual([])
    }
  })

  it('matches the install spellings actually used here', () => {
    for (const run of [
      'pnpm install',
      'pnpm install --frozen-lockfile',
      'pnpm --filter stash install',
      'pnpm i --frozen-lockfile',
    ]) {
      expect(audit([{ name: run, run }]).installs, run).toHaveLength(1)
    }
  })

  it('requires node-gyp on an unrecognised runner and not on a prebuilt one', () => {
    // Fail closed: an expression this file cannot resolve must not read as
    // "exempt".
    expect(needsNodeGyp('blacksmith-4vcpu-ubuntu-2404')).toBe(true)
    expect(needsNodeGyp('ubuntu-latest')).toBe(true)
    // biome-ignore lint/suspicious/noTemplateCurlyInString: a GitHub Actions expression, which is the literal `runs-on` value this must not exempt.
    expect(needsNodeGyp('${{ matrix.os }}')).toBe(true)
    // A matrix `runs-on` can also be a list, which is not a string at all.
    expect(needsNodeGyp(['ubuntu-latest'])).toBe(true)
    expect(needsNodeGyp('macos-latest')).toBe(false)
    expect(needsNodeGyp('windows-latest')).toBe(false)
  })
})
