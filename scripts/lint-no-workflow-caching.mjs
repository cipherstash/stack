import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'
import yaml from 'js-yaml'

const REPO_ROOT = resolve(import.meta.dirname, '..')

// Default targets — the workflows the supply-chain gate covers. Override with
// argv[2..] for tests / ad-hoc multi-file checks.
const TARGETS = process.argv.slice(2).length
  ? process.argv.slice(2)
  : [
      '.github/workflows/release.yml',
      '.github/workflows/tests-supply-chain.yml',
    ]

// `uses:` values that pull in the GitHub Actions cache directly.
const CACHE_ACTION = /^actions\/cache(\/(restore|save))?@/

// Steps that must disable their built-in caching *explicitly* — leaving the
// key off and relying on the default is not enough: the gate asserts intent.
const PNPM_ACTION_SETUP = /^pnpm\/action-setup(@|$)/
const SETUP_NODE = /^actions\/setup-node(@|$)/

// A `uses:` naming a directory in this checkout rather than a published action.
// GitHub requires the `./` prefix for those, so anything without it is an
// `owner/repo@ref` or `docker://` reference with nothing here to open.
const LOCAL_USES = /^\.{1,2}\//

function stepLabel(step, idx) {
  return step?.name || step?.uses || `step #${idx + 1}`
}

// Returns a reason string if `inputName` is not explicitly set to boolean
// `false` on the step's `with:`, otherwise null.
function explicitFalseReason(step, inputName) {
  const w = step?.with
  if (!w || !Object.hasOwn(w, inputName)) {
    return `must set \`${inputName}: false\` explicitly (key missing)`
  }
  if (w[inputName] !== false) {
    return `\`${inputName}\` must be \`false\`, found ${JSON.stringify(w[inputName])}`
  }
  return null
}

const offenders = []
const unresolved = []

// Every rule that applies to a single step. Factored out of the job loop
// because the same rules have to hold for a step written inside a composite
// action: it runs in the same job, holding the same credentials, and caches by
// the same defaults. Exempting composites would make "move the step into a
// composite" a supported way out of the rule — which is the bug this file's
// traversal exists to close, one level up.
function checkStep(step, at) {
  // `cache:` under a step's `with:` — covers actions/setup-node,
  // actions/setup-python, etc. An explicit falsy value does not count.
  if (step?.with && Object.hasOwn(step.with, 'cache') && step.with.cache) {
    offenders.push(
      `${at}: \`with.cache: ${JSON.stringify(step.with.cache)}\` restores the GitHub Actions cache`,
    )
  }

  // `uses: actions/cache...`
  if (typeof step?.uses === 'string' && CACHE_ACTION.test(step.uses)) {
    offenders.push(`${at}: uses \`${step.uses}\` (GitHub Actions cache)`)
  }

  // Explicit-disable assertions for the package-manager setup actions.
  if (typeof step?.uses === 'string') {
    if (PNPM_ACTION_SETUP.test(step.uses)) {
      const reason = explicitFalseReason(step, 'cache')
      if (reason) offenders.push(`${at}: pnpm/action-setup ${reason}`)
    }
    if (SETUP_NODE.test(step.uses)) {
      const reason = explicitFalseReason(step, 'package-manager-cache')
      if (reason) offenders.push(`${at}: actions/setup-node ${reason}`)
    }
  }
}

// GitHub resolves `uses: ./x` against the root of the CHECKOUT, not against the
// workflow file's own directory, so the traversal has to know where that root
// is. Any workflow GitHub will actually run sits in `<root>/.github/workflows/`,
// which names the root exactly. The fallback covers a file handed to this
// script from somewhere else — a fixture, or an ad-hoc check — where the repo
// root is the only sensible reading of `./`.
function workspaceRootFor(workflowFile) {
  const dir = dirname(workflowFile)
  return dir.endsWith(`${sep}.github${sep}workflows`)
    ? resolve(dir, '../..')
    : REPO_ROOT
}

// Both spellings are valid to GitHub, and a repo that mixes them is not doing
// anything wrong — so accepting only `action.yml` would silently stop
// traversing half the composites it was pointed at.
function resolveActionFile(workspaceRoot, usesPath) {
  const dir = resolve(workspaceRoot, usesPath)
  for (const name of ['action.yml', 'action.yaml']) {
    const file = join(dir, name)
    if (existsSync(file)) return file
  }
  return null
}

// Walks a step list, following any step that hands off to a local composite
// action.
//
// WHY: a composite is one `uses:` of indirection and the checks above used to
// stop dead at it. `uses: ./.github/actions/build-ffi-binding` in release.yml
// restored two GitHub Actions caches into the credential-bearing publishing job
// while this script printed `OK` — confirmed against a copy of release.yml with
// that step spliced in, exit 0, no output. Neither target workflow uses a local
// composite today; this is the gate that keeps that true.
//
// `visited` is scoped per job, not per run: a job is the unit of credential
// exposure this rule protects, so one report per job is enough, while a
// composite shared between two jobs still gets named in each. It also breaks
// the `A uses B uses A` cycle, which otherwise recurses until the stack blows.
//
// `if:` is deliberately not evaluated. A conditional cache restore is still a
// cache restore, and its condition is only known at run time anyway.
function walkSteps(steps, prefix, workspaceRoot, visited) {
  steps.forEach((step, idx) => {
    const at = `${prefix} step "${stepLabel(step, idx)}"`
    checkStep(step, at)

    if (typeof step?.uses !== 'string' || !LOCAL_USES.test(step.uses)) return

    const file = resolveActionFile(workspaceRoot, step.uses)
    if (file === null) {
      unresolved.push(
        `${at}: \`uses: ${step.uses}\` — no action.yml or action.yaml there`,
      )
      return
    }
    if (visited.has(file)) return
    visited.add(file)

    // An action manifest puts its steps under `runs:`, not `jobs:` — and only
    // when `runs.using` is `composite`. A JavaScript or Docker action has a
    // `runs.main`/`runs.image` and no step list, which lands on the `[]` below.
    const doc = yaml.load(readFileSync(file, 'utf8'))
    const nested = Array.isArray(doc?.runs?.steps) ? doc.runs.steps : []

    // The trail is the whole chain, not just its ends. A message naming only
    // the workflow step sends the reader to a file with no `actions/cache`
    // anywhere in it.
    walkSteps(
      nested,
      `${at} -> ${relative(workspaceRoot, file)}`,
      workspaceRoot,
      visited,
    )
  })
}

for (const target of TARGETS) {
  const abs = resolve(REPO_ROOT, target)
  const rel = relative(REPO_ROOT, abs)
  const workspaceRoot = workspaceRootFor(abs)
  const doc = yaml.load(readFileSync(abs, 'utf8'))
  const jobs = doc?.jobs ?? {}
  for (const [jobName, job] of Object.entries(jobs)) {
    const steps = Array.isArray(job?.steps) ? job.steps : []
    walkSteps(steps, `${rel}: job "${jobName}"`, workspaceRoot, new Set())
  }
}

if (unresolved.length > 0) {
  console.error(
    `Found ${unresolved.length} unresolvable local action reference(s):\n`,
  )
  for (const u of unresolved) console.error(`  ${u}`)
  console.error(
    '\nA `uses:` pointing at nothing fails the job on GitHub anyway, and until\n' +
      'it is fixed this gate cannot prove the steps behind it are cache-free.\n' +
      'Skipping it silently would turn a typo into a permanent exemption.',
  )
  // Exit 2, not 1: nothing was found caching — the linter could not look. Same
  // contract as lint-no-hardcoded-runners.mjs uses for a missing scan target.
  process.exit(2)
}

if (offenders.length > 0) {
  console.error(`Found ${offenders.length} caching issue(s) in workflow(s):\n`)
  for (const o of offenders) console.error(`  ${o}`)
  console.error(
    '\nThese workflows must not restore the GitHub Actions cache — it is a\n' +
      'cache-poisoning / supply-chain vector for credential-bearing jobs.\n' +
      'Caching must be disabled explicitly (`cache: false`,\n' +
      '`package-manager-cache: false`), including inside any local composite\n' +
      'action they use. See the "CI/CD Supply-Chain Hardening" section of\n' +
      'SECURITY.md.',
  )
  process.exit(1)
}

console.log('OK — GitHub Actions caching is explicitly disabled in:\n')
for (const target of TARGETS) console.log(target)
