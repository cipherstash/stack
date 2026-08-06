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

// ALLOWLIST RATIONALE — why this is a list of what is permitted, and not a
// longer list of cache actions.
//
// The rules above only see two things: an action literally named
// `actions/cache*`, and an action that takes a `cache:` input. A third-party
// cache action has neither, so it was invisible to the whole file. Reproduced
// against a composite reached from a targeted workflow holding
// `useblacksmith/cache@v5` and `Swatinem/rust-cache@v2`: `OK`, exit 0. Both are
// live-relevant here — eleven jobs in this repo run on `blacksmith-*` runners,
// where `useblacksmith/cache` is the documented drop-in for `actions/cache`,
// and an in-tree Cargo workspace is exactly where someone reaches for
// `Swatinem/rust-cache`.
//
// The obvious repair is to enumerate the cache actions — by name
// (`useblacksmith/cache`, `buildjet/cache`, `runs-on/cache`, `tespkg/actions-
// cache`, …) or by name shape (does the path contain "cache"?). Both were
// rejected, for the same reason:
//
//   A denylist fails OPEN on the action nobody has met yet. It is silently
//   correct until the day it is silently wrong, and it is wrong in the
//   direction that prints `OK`. That is this repo's own stated criticism of
//   its own checks — "a check that never ran reads exactly like a check that
//   passed" — and it applies with full force to a list of vendor names that
//   grows without this repo hearing about it.
//
// Worse, neither denylist form covers the class most likely to be added here by
// accident: a `setup-<tool>` action that caches BY DEFAULT, with no `cache:`
// input to inspect and no "cache" anywhere in its name.
// `gradle/actions/setup-gradle` is one; a runner vendor's drop-in `setup-node`
// is another. This file already carries two hand-maintained members of that
// class — `pnpm/action-setup` and `actions/setup-node` above — and they are
// here only because somebody happened to notice. Nothing would have caught the
// third.
//
// So the rule is inverted. Every REMOTE `uses:` reachable from a targeted
// workflow must appear below, or it is reported. This fails CLOSED: an action
// this gate has never seen is a finding by default, whatever it is called and
// whatever inputs it takes.
//
// This does not go stale silently, which is the whole point of choosing it. An
// allowlist's staleness is a build failure naming the exact action and the file
// it was added to — the person adding it is the person told to audit it, in the
// same PR. A denylist's staleness is an `OK`.
//
// The cost is bounded and was measured before choosing it, not assumed. The two
// targeted workflows are deliberately minimal and reach exactly four actions
// between them (all four are below); traversal is target-scoped, so nothing
// outside what release.yml and tests-supply-chain.yml reach is constrained; and
// they reach no local composite and no reusable workflow today. Adding an
// action to the npm-publishing workflow costs one line here plus a sentence
// saying why — which is the review that workflow warrants regardless.
//
// LOCAL `uses:` IS EXEMPT, and deliberately so: this gate opens a `./` action
// and reads every one of its steps, so it is audited by construction rather
// than trusted. Listing it here would report the composite and bury the
// `actions/cache` inside it — the finding that actually matters.
const AUDITED_ACTIONS = new Set([
  // First-party checkout. No cache of its own.
  'actions/checkout',
  // Both cache on request only, and the explicit-`false` rules above assert
  // that these two are told not to — they are on this list *and* separately
  // constrained.
  'actions/setup-node',
  'pnpm/action-setup',
  // release.yml's publish step. Runs `pnpm run release` and talks to npm over
  // OIDC; no cache, no cache input.
  'changesets/action',
])

// A secondary, deliberately over-broad read of the action's name. It is NOT the
// defence — the allowlist above is, and it already rejects everything this
// matches. This exists for two narrower jobs:
//
//  1. Message quality. `useblacksmith/cache@v5` should read as "this restores a
//     cache", not "this is not on a list" — the second invites adding it to the
//     list.
//  2. Guarding the allowlist against itself. The one careless edit that could
//     re-open this hole is someone appending a cache action to AUDITED_ACTIONS,
//     so the assertion below makes that impossible: no entry may be
//     cache-shaped, checked on every single invocation.
//
// Substring, not segment-equality, and that was verified rather than assumed:
// `Swatinem/rust-cache` has no path segment equal to `cache`, so
// `/(^|\/)cache(\/|$)/` misses it while a substring catches it — along with
// `tespkg/actions-cache` and any `*-cache` / `cache-*` naming a vendor picks.
// False positives (a hypothetical `foo/cache-warmer-status`) cost one line of
// review and cannot let anything through, because the allowlist has already
// done the fail-closed work.
const CACHE_SHAPED_ACTION = /cache/i

for (const audited of AUDITED_ACTIONS) {
  if (CACHE_SHAPED_ACTION.test(audited)) {
    throw new Error(
      `AUDITED_ACTIONS must not contain a cache action, found "${audited}". ` +
        'Allowlisting one would re-open the hole this list exists to close.',
    )
  }
}

// GitHub trims a `uses:` value before resolving it, and a quoted one can carry
// leading whitespace (`uses: " ./.github/actions/x"`). Untrimmed, that fails
// LOCAL_USES, so the composite is never opened — and before the allowlist above
// nothing was reported either, making it the one unfollowable local reference
// shape that exited 0 rather than 2. Normalising once here means every rule
// below reads the same string GitHub does.
function usesOf(step) {
  if (typeof step?.uses !== 'string') return null
  const trimmed = step.uses.trim()
  return trimmed === '' ? null : trimmed
}

// The `owner/repo[/subpath]` half of a `uses:`, without the `@ref`. Compared
// case-insensitively because GitHub repository names are: a `uses: Actions/
// Checkout@v6` is the same action, and case-sensitivity would only ever make
// the allowlist reject something legitimate (fail-closed, so harmless) while
// letting `Actions/Cache@v4` past a case-sensitive denylist (fail-open, not).
function actionPath(uses) {
  return uses.split('@')[0].toLowerCase()
}

function stepLabel(step, idx) {
  return step?.name || usesOf(step) || `step #${idx + 1}`
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
//
// `bodyAudited` says this step hands off to a local composite whose steps this
// gate reads for itself. It suppresses exactly one rule — see below.
function checkStep(step, at, bodyAudited = false) {
  // `cache:` under a step's `with:` — covers actions/setup-node,
  // actions/setup-python, etc. An explicit falsy value does not count.
  //
  // Skipped when the step's body is audited, and only then. `with:` on a step
  // that hands off to a local composite is that composite's declared inputs,
  // and a composite is free to declare one called `cache` that switches
  // something else on entirely — the same false positive `walkJob` refuses to
  // make by never running these rules over a job-level `with:`. The
  // justification for skipping is "the body is read instead", so it may only
  // apply where the body is actually read: a composite that forwards `cache`
  // into a caching step is still reported, on the step doing the caching.
  //
  // A local `uses:` that resolves to nothing, or to a JS/Docker action, keeps
  // the rule. There the gate opens no step list and reaches no verdict, and a
  // local `uses:` is already exempt from AUDITED_ACTIONS — so this heuristic is
  // the only thing standing.
  if (
    !bodyAudited &&
    step?.with &&
    Object.hasOwn(step.with, 'cache') &&
    step.with.cache
  ) {
    offenders.push(
      `${at}: \`with.cache: ${JSON.stringify(step.with.cache)}\` restores the GitHub Actions cache`,
    )
  }

  const uses = usesOf(step)
  if (uses === null) return

  // Explicit-disable assertions for the package-manager setup actions. Both are
  // allowlisted, so these are the additional constraint on them, not a
  // substitute for one.
  if (PNPM_ACTION_SETUP.test(uses)) {
    const reason = explicitFalseReason(step, 'cache')
    if (reason) offenders.push(`${at}: pnpm/action-setup ${reason}`)
  }
  if (SETUP_NODE.test(uses)) {
    const reason = explicitFalseReason(step, 'package-manager-cache')
    if (reason) offenders.push(`${at}: actions/setup-node ${reason}`)
  }

  // One verdict per `uses:`, most specific first — a step reported twice reads
  // as two problems and gets fixed once.
  if (CACHE_ACTION.test(uses)) {
    // `uses: actions/cache...`
    offenders.push(`${at}: uses \`${uses}\` (GitHub Actions cache)`)
  } else if (LOCAL_USES.test(uses)) {
    // Audited by construction: `walkSteps` opens it and checks every step.
  } else if (CACHE_SHAPED_ACTION.test(actionPath(uses))) {
    offenders.push(
      `${at}: uses \`${uses}\` — a third-party cache action (GitHub Actions cache)`,
    )
  } else if (!AUDITED_ACTIONS.has(actionPath(uses))) {
    offenders.push(
      `${at}: uses \`${uses}\` — not in AUDITED_ACTIONS. This gate cannot read ` +
        'a published action’s steps, so it cannot prove this one does not cache',
    )
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

    // The action is resolved BEFORE the step is checked, not after, because
    // `checkStep` needs to know whether this step's body is about to be
    // audited. Resolving it twice — once for that answer, once to recurse —
    // would let the two readings drift apart, which is the one way the
    // suppression could outlive the audit that justifies it.
    const uses = usesOf(step)
    if (uses === null || !LOCAL_USES.test(uses)) {
      checkStep(step, at)
      return
    }

    const file = resolveActionFile(workspaceRoot, uses)
    if (file === null) {
      // No manifest to open: nothing here is audited, so every step rule
      // applies, and the offender it finds prints alongside the report below.
      checkStep(step, at)
      unresolved.push(
        `${at}: \`uses: ${uses}\` — no action.yml or action.yaml there`,
      )
      return
    }

    // An action manifest puts its steps under `runs:`, not `jobs:` — and only
    // when `runs.using` is `composite`. A JavaScript or Docker action has a
    // `runs.main`/`runs.image` and no step list, which lands on the `[]` below.
    //
    // Read before the `visited` check rather than after: a second reference to
    // an already-walked composite still needs the same verdict on its own
    // `with:`, and its body has been audited by the first reference. Re-parsing
    // a handful of small manifests is cheaper than the alternatives, and
    // `visited` still guards the recursion, so nothing is reported twice.
    const doc = yaml.load(readFileSync(file, 'utf8'))

    // Keyed on `runs.using`, not on "did we find a step list", so that a
    // manifest declaring a JS runtime yet carrying steps — invalid to GitHub,
    // but this gate runs on files GitHub has not validated — is audited AND
    // still judged on its caller's `with:`. Both readings, fail-closed.
    checkStep(step, at, doc?.runs?.using === 'composite')

    if (visited.has(file)) return
    visited.add(file)

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
// switches something else on entirely. `walkSteps` makes the same distinction
// one level down, for a step whose `uses:` is a local composite — see
// `bodyAudited`.
function walkJob(job, prefix, workspaceRoot, visited) {
  walkSteps(
    Array.isArray(job?.steps) ? job.steps : [],
    prefix,
    workspaceRoot,
    visited,
  )

  const uses = usesOf(job)
  if (uses !== null) {
    followReusableWorkflow(uses, prefix, workspaceRoot, visited)
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
}

if (offenders.length > 0) {
  // Separated from the block above only when there is a block above, so the
  // two epilogues do not run together on a mixed run and the common
  // single-finding output does not open on a blank line.
  if (unresolved.length > 0) console.error('')
  console.error(`Found ${offenders.length} caching issue(s) in workflow(s):\n`)
  for (const o of offenders) console.error(`  ${o}`)
  console.error(
    '\nThese workflows must not restore the GitHub Actions cache — it is a\n' +
      'cache-poisoning / supply-chain vector for credential-bearing jobs.\n' +
      'Caching must be disabled explicitly (`cache: false`,\n' +
      '`package-manager-cache: false`), including inside any local composite\n' +
      'action or reusable workflow they reach.\n' +
      '\nA published `uses:` that is not in AUDITED_ACTIONS is reported for the\n' +
      'same reason rather than a different one: this gate cannot open a\n' +
      'published action, so it cannot prove that action does not cache — and\n' +
      'the ones that do are not all called "cache" (a `setup-<tool>` action\n' +
      'that caches by default has no `cache:` input and no telling name).\n' +
      'The list is what is permitted, not what is forbidden, so an action it\n' +
      'has never met fails by default. Review the action and add it there with\n' +
      'the reason, or drop the step.\n' +
      '\nSee the "CI/CD Supply-Chain Hardening" section of SECURITY.md.',
  )
}

// Both lists print before either exit, because a run can collect both and each
// is acted on separately. Exiting inside the first block hid the cache finding
// — the one with a step to delete — until the broken path was fixed, at which
// point it arrived on the next run looking new.
//
// Exit 2 outranks 1 on a mixed run, and not because nothing was found caching:
// on a mixed run something was. An incomplete scan is simply the more severe
// verdict, since the exit 1 reports what this gate could see and the exit 2
// says that list may be short. Same contract lint-no-hardcoded-runners.mjs uses
// for a missing scan target.
if (unresolved.length > 0) process.exit(2)
if (offenders.length > 0) process.exit(1)

console.log('OK — GitHub Actions caching is explicitly disabled in:\n')
for (const target of TARGETS) console.log(target)
