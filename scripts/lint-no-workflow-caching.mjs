import { existsSync, readFileSync, statSync } from 'node:fs'
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

// Unlike an action, a reusable workflow is named by its file, extension and
// all (`./.github/workflows/x.yml`), so there is no `.yml`/`.yaml` probing to
// do here — the path is exact. `isFile` is the guard that matters instead: a
// path that exists as a directory would otherwise reach `readFileSync` and
// abort the run with an unhandled EISDIR, which is a worse outcome than the
// report below.
function resolveWorkflowFile(workspaceRoot, usesPath) {
  const file = resolve(workspaceRoot, usesPath)
  return existsSync(file) && statSync(file).isFile() ? file : null
}

// Follows `jobs.<id>.uses:` — a job that delegates its whole body to another
// workflow.
//
// WHY: such a job has no `steps:` at all, so the loop below used to hand
// `walkSteps` an empty list and skip the job entire. Confirmed before this
// existed against a caller whose only job was
// `uses: ./.github/workflows/reusable.yml` with `secrets: inherit`, the called
// workflow holding an `actions/cache@v4` step: exit 0, `OK`, nothing scanned.
// Same failure the composite traversal closed, one shape over.
//
// The verdict deliberately ignores `secrets:`. It is not the only credential
// channel — `permissions:` is inherited independently, and that is what mints
// the OIDC token npm trusted publishing signs with, so a call passing no
// secrets can still publish. Nor does a restore need credentials in its own job
// to be the attack: poisoned bytes landing in a build job that hands an
// artifact to a publish job is the canonical shape. Conditioning on `secrets:`
// would prevent no failure and would hand an attacker a phrasing that evades
// the gate.
function followReusableWorkflow(uses, prefix, workspaceRoot, visited) {
  // A remote reusable workflow is reported, where `walkSteps` skips a remote
  // *step* action, and the difference is coverage rather than depth. A
  // marketplace step sits inside a job whose step list this gate has read end
  // to end; flagging every `actions/checkout@v6` would make it exit 2 forever
  // and mean nothing. A remote job-level `uses:` is the whole job — no steps
  // read, no verdict reached, `OK` printed anyway, which is precisely the
  // "a check that never ran reads like a check that passed" failure this file
  // exists to stop. It is rare (zero in this repo today) and actionable —
  // inline the job, or point it at a workflow in this checkout — so the report
  // is signal rather than noise.
  if (!LOCAL_USES.test(uses)) {
    unresolved.push(
      `${prefix}: \`uses: ${uses}\` — a remote reusable workflow; its jobs are not in this checkout`,
    )
    return
  }

  const file = resolveWorkflowFile(workspaceRoot, uses)
  if (file === null) {
    unresolved.push(`${prefix}: \`uses: ${uses}\` — no workflow file there`)
    return
  }
  if (visited.has(file)) return
  visited.add(file)

  // One `visited` spans both node types, so `a.yml -> b.yml -> a.yml`
  // terminates the same way `a -> b -> a` does between composites.
  const doc = yaml.load(readFileSync(file, 'utf8'))
  for (const [jobName, job] of Object.entries(doc?.jobs ?? {})) {
    walkJob(
      job,
      `${prefix} -> ${relative(workspaceRoot, file)} job "${jobName}"`,
      workspaceRoot,
      visited,
    )
  }
}

// A job is one of two shapes, and the recursion has to know both: `steps:` (a
// normal job, and the shape a composite's `runs.steps` also has) or `uses:` (a
// call into another workflow, whose own jobs are either shape again).
//
// Both are checked rather than one being chosen. Carrying both keys is invalid
// to GitHub's schema, which rejects the file outright — but this gate runs on
// files GitHub has not validated yet, and treating either key as authoritative
// would let such a file hide a cache behind the key the gate ignored and still
// report a pass.
//
// The job object itself is never passed to `checkStep`: at job level `with:` is
// inputs to the called workflow, not `with:` on an action step, so the step
// rules would flag a caller for passing `cache: true` to an input that
// switches something else on entirely.
function walkJob(job, prefix, workspaceRoot, visited) {
  walkSteps(
    Array.isArray(job?.steps) ? job.steps : [],
    prefix,
    workspaceRoot,
    visited,
  )

  if (typeof job?.uses === 'string') {
    followReusableWorkflow(job.uses, prefix, workspaceRoot, visited)
  }
}

for (const target of TARGETS) {
  const abs = resolve(REPO_ROOT, target)
  const rel = relative(REPO_ROOT, abs)
  const workspaceRoot = workspaceRootFor(abs)
  const doc = yaml.load(readFileSync(abs, 'utf8'))
  const jobs = doc?.jobs ?? {}
  for (const [jobName, job] of Object.entries(jobs)) {
    walkJob(job, `${rel}: job "${jobName}"`, workspaceRoot, new Set())
  }
}

if (unresolved.length > 0) {
  console.error(`Found ${unresolved.length} un-auditable reference(s):\n`)
  for (const u of unresolved) console.error(`  ${u}`)
  console.error(
    '\nEach of these hands this gate a step list it cannot open, so it cannot\n' +
      'prove those steps are cache-free. A local `uses:` pointing at nothing\n' +
      'fails the job on GitHub anyway; a remote reusable workflow runs fine and\n' +
      'audits nothing at all. Passing either silently would turn it into a\n' +
      'permanent exemption — fix the path, inline the job, or point it at a\n' +
      'workflow in this checkout.',
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
      'action or reusable workflow they reach. See the "CI/CD Supply-Chain\n' +
      'Hardening" section of SECURITY.md.',
  )
  process.exit(1)
}

console.log('OK — GitHub Actions caching is explicitly disabled in:\n')
for (const target of TARGETS) console.log(target)
