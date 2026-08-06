import { describe, expect, it } from 'vitest'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * `./.github/actions/require-cs-secrets` must run BEFORE
 * `./.github/actions/build-ffi-binding` in any job that uses both.
 *
 * The secrets action is a pre-flight, and its whole value is being cheap: it
 * reads four inputs and fails in seconds when a CS_* secret was rotated,
 * cleared, or is absent because the PR came from a fork. Every workflow that
 * carries it says so in a comment ("Fast pre-flight: fail in seconds if a
 * secret was rotated or cleared, before the docker pull").
 *
 * `build-ffi-binding` is the opposite kind of step. On a cache miss it compiles
 * the Rust core from cold — minutes of runner time, and more again with
 * `wasm: 'true'`. Put it first and a job with no usable credentials pays the
 * full compile before it learns it was never going to be able to encrypt
 * anything. The pre-flight still fails, just several minutes later and after
 * the expensive half of the job has already been billed — which is the same as
 * not having a pre-flight at all.
 *
 * So the order is load-bearing, and it does not look load-bearing: both steps
 * are self-contained `uses:` blocks, and swapping them changes nothing about
 * whether the job passes. That is exactly the shape of edit that gets made
 * while "grouping the build steps together". Hence this test — the two steps
 * are checked by position, across every workflow, discovered rather than
 * listed, so a new workflow that adds the binding build is covered the day it
 * lands.
 *
 * NOTE the direction of the fix when this fails. Moving the binding build down
 * is only correct when nothing between the two steps needs the binding. In
 * `tests.yml`'s `wasm-e2e-tests` job a `Build stack` step sits between them and
 * consumes `dist/wasm/**`, so there the pre-flight moves UP instead. Same
 * resulting order; the other edit would have broken the job.
 */

const BUILD_FFI = './.github/actions/build-ffi-binding'
const REQUIRE_SECRETS = './.github/actions/require-cs-secrets'

/**
 * The JOBS that pair the two actions today. This is NOT the list the checks
 * iterate — those scan the directory — it is the guard on the scan itself. A
 * discovery test that matches nothing passes and proves nothing, and this repo
 * has been bitten by that shape before (see the exit-2 "the linter could not
 * run" contract in `scripts/lint-no-hardcoded-runners.mjs`, and
 * `lintWiring.test.ts`'s "a check nothing invokes reads exactly like a check
 * that passes").
 *
 * Jobs, not files, and that distinction is the whole guard. The ordering check
 * below is generated per paired job, so deleting a job's pre-flight does not
 * fail it — it deletes it. A file-granular list cannot see that: drop the
 * `Require CipherStash secrets` step from `tests.yml`'s `wasm-e2e-tests` job
 * and `tests.yml` is still paired via `run-tests`, so the file is still found,
 * the count still clears its floor, and the suite goes green having stopped
 * checking the single most expensive job in the repo — the one that builds the
 * binding with `wasm: 'true'`, i.e. the cold compile this pre-flight exists to
 * stay ahead of. Mutation-tested: against a file-granular list that deletion
 * took the suite from 9 tests to 8 passing, with nothing red.
 *
 * It is no longer the only thing standing there — `every credentialed job runs
 * the secrets pre-flight first` (below) goes red on that same deletion, because
 * `wasm-e2e-tests` carries CS_* and so cannot drop out of ITS scan. This list
 * still earns its place: it names WHICH job stopped being checked, and it
 * covers a paired job that carries no credential expression, which the other
 * scan cannot see.
 *
 * Held as a minimum, not an equality: adding a job that builds the binding
 * must not fail this. If one is renamed or genuinely stops needing the
 * binding, update the list deliberately — the failure prints the ids the scan
 * DID find (see `scanGuard`), so a rename is a copy from the message into the
 * list rather than a re-derivation from the workflows.
 */
const EXPECTED_PAIRED_JOBS = [
  '.github/workflows/integration-drizzle.yml / integration',
  '.github/workflows/integration-prisma-next.yml / integration',
  '.github/workflows/integration-protect-ffi.yml / integration',
  '.github/workflows/integration-supabase.yml / integration',
  '.github/workflows/prisma-example-readme-e2e.yml / walkthrough',
  '.github/workflows/prisma-next-e2e.yml / e2e',
  '.github/workflows/tests.yml / e2e-tests',
  '.github/workflows/tests.yml / run-tests',
  '.github/workflows/tests.yml / run-tests-bun',
  '.github/workflows/tests.yml / wasm-e2e-tests',
]

/** The `uses:` of a step, normalised — `uses` may carry trailing whitespace. */
function stepUses(step) {
  return typeof step?.uses === 'string' ? step.uses.trim() : null
}

/**
 * Every job that uses BOTH actions, with the EARLIEST step index of each.
 * Indexed by position in the job's own `steps` list, which is the order GitHub
 * runs them.
 *
 * First occurrence, not all of them, and that is the property rather than a
 * simplification: the claim is "no credentialed work starts before the
 * pre-flight", so what matters is whether the earliest pre-flight precedes the
 * earliest build. A job that repeats either step still has to clear that, and
 * comparing later pairs would let an early unguarded build through on the
 * strength of a later guarded one.
 */
function pairedJobs(relPath) {
  const wf = readWorkflow(relPath)
  const found = []
  for (const [jobName, job] of Object.entries(wf?.jobs ?? {})) {
    const steps = Array.isArray(job?.steps) ? job.steps : []
    const firstBuild = steps.findIndex((step) => stepUses(step) === BUILD_FFI)
    const firstSecrets = steps.findIndex(
      (step) => stepUses(step) === REQUIRE_SECRETS,
    )
    if (firstBuild === -1 || firstSecrets === -1) continue
    found.push({ relPath, jobName, steps, firstBuild, firstSecrets })
  }
  return found
}

const PAIRED = workflowFiles().flatMap(pairedJobs)
const PAIRED_JOB_IDS = PAIRED.map(
  (entry) => `${entry.relPath} / ${entry.jobName}`,
)

/**
 * The four CipherStash credentials, as they appear in a workflow: `${{ vars.X }}`
 * for the two public ones, `${{ secrets.X }}` for the two that aren't. A job
 * carrying any of them is a job that intends to talk to the live service.
 *
 * Matched against the whole job — `env:` at job level, `env:` on a step, a
 * `with:` input to the pre-flight action, or a `run:` body that writes a `.env`
 * file. `run-tests-bun` is the last of those and the reason a job-level-`env`
 * scan would not have been enough.
 */
const CREDENTIAL_EXPRESSION =
  /\$\{\{\s*(?:vars|secrets)\.CS_(?:WORKSPACE_CRN|CLIENT_ID|CLIENT_KEY|CLIENT_ACCESS_KEY)\s*\}\}/

/**
 * Every job in a workflow that receives at least one CS_* credential, with the
 * EARLIEST step index of each action — `-1` when the job does not run it.
 *
 * Both indices, not just `buildsBinding`, because this scan is the only one
 * that can see a job which builds the binding with no pre-flight at all:
 * `pairedJobs` skips exactly that job. Earliest occurrence for the reason
 * `pairedJobs` gives — the claim is "no credentialed work starts before the
 * pre-flight", so a later guarded build cannot vouch for an earlier unguarded
 * one.
 */
function credentialedJobs(relPath) {
  const wf = readWorkflow(relPath)
  const found = []
  for (const [jobName, job] of Object.entries(wf?.jobs ?? {})) {
    if (!CREDENTIAL_EXPRESSION.test(JSON.stringify(job))) continue
    const steps = Array.isArray(job?.steps) ? job.steps : []
    const firstBuild = steps.findIndex((step) => stepUses(step) === BUILD_FFI)
    const firstSecrets = steps.findIndex(
      (step) => stepUses(step) === REQUIRE_SECRETS,
    )
    found.push({
      relPath,
      jobName,
      firstBuild,
      firstSecrets,
      buildsBinding: firstBuild !== -1,
      runsPreflight: firstSecrets !== -1,
    })
  }
  return found
}

const CREDENTIALED = workflowFiles().flatMap(credentialedJobs)
const CREDENTIALED_JOB_IDS = CREDENTIALED.map(
  (entry) => `${entry.relPath} / ${entry.jobName}`,
)

/**
 * The credentialed JOBS, as the guard on the coverage scan below — same role
 * as `EXPECTED_PAIRED_JOBS` plays for the ordering scan, and held as a minimum
 * for the same reason. If the credential names or expression syntax ever
 * change, this empties the scan, and a coverage check that iterates nothing
 * passes while proving nothing.
 */
const EXPECTED_CREDENTIALED_JOBS = [
  '.github/workflows/integration-drizzle.yml / integration',
  '.github/workflows/integration-prisma-next.yml / integration',
  '.github/workflows/integration-protect-ffi.yml / integration',
  '.github/workflows/integration-supabase.yml / integration',
  '.github/workflows/prisma-example-readme-e2e.yml / walkthrough',
  '.github/workflows/prisma-next-e2e.yml / e2e',
  '.github/workflows/tests.yml / e2e-tests',
  '.github/workflows/tests.yml / run-tests',
  '.github/workflows/tests.yml / run-tests-bun',
  '.github/workflows/tests.yml / wasm-e2e-tests',
]

/**
 * Credentialed jobs that legitimately do NOT build the binding, each with the
 * reason it doesn't need one. Empty today, and that is the intended steady
 * state: every job we hand CS_* to currently runs code that encrypts.
 *
 * It exists because a job can hold credentials without touching the binding —
 * one that only validates that the secrets are present, or one that passes them
 * to a service container and never runs a suite. When that job arrives, name it
 * here WITH its reason rather than loosening the scan; the second test below
 * fails on an entry that no longer matches a credentialed job, so a stale
 * exemption cannot outlive the job it was written for.
 */
const BINDING_EXEMPT_JOBS = new Map([
  // ['<workflow> / <job>', 'why this job never loads index.node or dist/wasm'],
])

/**
 * Credentialed jobs that legitimately do NOT run the secrets pre-flight, each
 * with the reason. Empty today, and — like `BINDING_EXEMPT_JOBS` — intended to
 * stay that way: a job holding CS_* is a job that can be broken by a rotated
 * secret, and the pre-flight is how it says so in seconds.
 *
 * Separate from `BINDING_EXEMPT_JOBS` because the two exemptions are not the
 * same claim. "This job never loads the binding" says nothing about whether a
 * missing credential should fail it early, and a job could plausibly want one
 * without the other. Name a job here WITH its reason rather than narrowing the
 * scan to jobs that happen to already carry the step — that narrowing is the
 * exact defect this check exists to close (see the note above the describe).
 */
const PREFLIGHT_EXEMPT_JOBS = new Map([
  // ['<workflow> / <job>', 'why a rotated CS_* secret need not fail this job fast'],
])

/**
 * The four hand-maintained lists in this file are checked the same way: every
 * id in the list must still match something the scan found. Same shape, and —
 * more to the point — the same failure. A job gets renamed, the list still
 * names the old id, and the fix is to swap in the new one.
 *
 * That fix costs two seconds if the message says what the scan DID find, and a
 * source dive if it only says what went missing: the developer has the old id
 * (it is in the diff) and needs the new one, which appears nowhere in the
 * output. Mutation-tested — renaming `integration-drizzle.yml`'s `integration`
 * job to `integration-suite` failed both guards, and only the credentialed one
 * printed the new name.
 *
 * So the listing is built HERE rather than at each call site: it is part of
 * what makes a guard fixable, and a guard that grew its own terser message
 * would quietly lose that.
 *
 * `message` is returned as a value, not passed straight into `expect`, because
 * vitest only evaluates an assertion message when the assertion FAILS. A
 * diagnostic that is only read on failure is a diagnostic nothing tests — which
 * is how it gets stripped back out. `names every job its scan found` below
 * asserts on these strings directly.
 */
function scanGuard({ entries, found, hint }) {
  return {
    found,
    unmatched: entries.filter((id) => !found.includes(id)),
    message: `${hint}\nThe scan currently sees:\n${
      found.length === 0
        ? '  (nothing — the scan matched no jobs)'
        : found.map((id) => `  ${id}`).join('\n')
    }`,
  }
}

const SCAN_GUARDS = {
  paired: scanGuard({
    entries: EXPECTED_PAIRED_JOBS,
    found: PAIRED_JOB_IDS,
    hint: `These jobs used both ${BUILD_FFI} and ${REQUIRE_SECRETS}, and the scan no longer sees them. Either an action path changed (update the constants in this file), or a job's pre-flight was dropped — in which case the ordering check for it did not fail, it stopped existing. Restore the step, or update EXPECTED_PAIRED_JOBS deliberately.`,
  }),
  credentialed: scanGuard({
    entries: EXPECTED_CREDENTIALED_JOBS,
    found: CREDENTIALED_JOB_IDS,
    hint: `These jobs pass a CS_* credential and the scan no longer sees them. Either the credential names or the \`\${{ }}\` syntax changed (update CREDENTIAL_EXPRESSION), or the job was renamed or deleted — update EXPECTED_CREDENTIALED_JOBS deliberately.`,
  }),
  exemptions: scanGuard({
    entries: [...BINDING_EXEMPT_JOBS.keys()],
    found: CREDENTIALED_JOB_IDS,
    hint: 'These BINDING_EXEMPT_JOBS entries do not match any credentialed job. Remove them, or fix the id — an exemption for a job that no longer exists exempts nothing and hides the next one.',
  }),
  preflightExemptions: scanGuard({
    entries: [...PREFLIGHT_EXEMPT_JOBS.keys()],
    found: CREDENTIALED_JOB_IDS,
    hint: 'These PREFLIGHT_EXEMPT_JOBS entries do not match any credentialed job. Remove them, or fix the id — an exemption for a job that no longer exists exempts nothing and hides the next one.',
  }),
}

describe('protect-ffi binding builds after the secrets pre-flight', () => {
  it('finds the jobs that pair the two actions', () => {
    // The guard on the scan. Without it, a rename of either action path (or a
    // js-yaml parse that quietly returned undefined) would empty `PAIRED` and
    // every check below would pass by vacuum.
    //
    // No separate count assertion: job ids are unique, so an empty `unmatched`
    // already means every expected job was found. A `PAIRED.length >= N`
    // floor is what let the `wasm-e2e-tests` deletion through — it had slack
    // in it, and slack in a scan guard is where the un-run check hides.
    const guard = SCAN_GUARDS.paired
    expect(guard.unmatched, guard.message).toEqual([])
  })

  for (const file of workflowFiles()) {
    const jobs = pairedJobs(file)
    if (jobs.length === 0) continue

    for (const { jobName, steps, firstBuild, firstSecrets } of jobs) {
      it(`${file} / ${jobName} requires secrets before building the binding`, () => {
        const order = steps
          .map(
            (step, index) =>
              `  ${index}: ${step?.name ?? stepUses(step) ?? '(unnamed)'}`,
          )
          .join('\n')

        expect(
          firstSecrets,
          `"Require CipherStash secrets" must run before "Build the protect-ffi binding" in ${file} job "${jobName}".\nThe secrets check costs seconds; a cold Rust build costs minutes. Running the build first means a job with a rotated or missing credential pays the whole compile before failing — which is the same as having no pre-flight.\nSteps as ordered:\n${order}`,
        ).toBeLessThan(firstBuild)
      })
    }
  }
})

/**
 * COVERAGE, where the checks above are ORDER. Those only look at jobs that
 * already pair the two actions, so a job that never builds the binding at all
 * is invisible to them — it is not failing them, it is not in them.
 *
 * That gap is not theoretical. `packages/protect-ffi` is a workspace package
 * now, so `lib/`, `index.node` and `dist/wasm/**` are BUILD OUTPUTS rather than
 * tarball contents, and every job that encrypts has to produce them itself. Two
 * credentialed jobs in `tests.yml` were missed when the `workspace:*` links
 * landed: `e2e-tests` (its unfiltered `test:e2e` run picks up
 * `tests/prisma-example-readme.e2e.test.ts`, whose `describe.skipIf` un-skips
 * the moment CS_CLIENT_ID and CS_CLIENT_KEY are set, and whose `pnpm start`
 * step encrypts for real) and `run-tests-bun` (writes the four CS_* into
 * `packages/stack/.env`, then runs 120 `packages/stack` suites of which only 8
 * mock protect-ffi).
 *
 * The failure mode is `Cannot find module '.../index.node'`, reported once per
 * test rather than once per job — and in `run-tests-bun` not reported at all,
 * since it carries `continue-on-error: true` AND a `|| true` around the vitest
 * invocation. So the omission is silent in exactly the job least likely to be
 * looked at.
 *
 * Discovered, not listed: a new credentialed job is covered the day it lands,
 * which is the only way this stays true. Exemptions are explicit and carry
 * their reason (see BINDING_EXEMPT_JOBS).
 */
describe('every credentialed job builds the protect-ffi binding', () => {
  it('finds the jobs that receive CipherStash credentials', () => {
    const guard = SCAN_GUARDS.credentialed
    expect(guard.unmatched, guard.message).toEqual([])
  })

  it('exempts only jobs that are still credentialed', () => {
    // A stale exemption is the silent-skip failure this whole file exists to
    // avoid: the named job gets renamed or gains a real need for the binding,
    // and the entry sits there exempting nothing while reading as deliberate.
    const guard = SCAN_GUARDS.exemptions
    expect(guard.unmatched, guard.message).toEqual([])
  })

  it('builds the binding in every credentialed job', () => {
    const offenders = CREDENTIALED.filter(
      (entry) =>
        !entry.buildsBinding &&
        !BINDING_EXEMPT_JOBS.has(`${entry.relPath} / ${entry.jobName}`),
    ).map((entry) => `${entry.relPath} / ${entry.jobName}`)

    expect(
      offenders,
      `These jobs receive CipherStash credentials but never run ${BUILD_FFI}.\n\`packages/protect-ffi\` is a workspace package: \`lib/\`, \`index.node\` and \`dist/wasm/**\` are build outputs, not tarball contents, so a job that encrypts or decrypts must build them itself. Without the step the suite fails with \`Cannot find module '.../protect-ffi-linux-x64-gnu/index.node'\`, once per test.\nAdd the step AFTER any \`${REQUIRE_SECRETS}\` pre-flight and BEFORE anything that consumes the binding. Pass \`wasm: 'true'\` only if the job loads the real WASM build.\nIf a job genuinely does not need it, add it to BINDING_EXEMPT_JOBS with the reason.`,
    ).toEqual([])
  })
})

/**
 * ORDER again — but scanned from the CREDENTIALED side, which is the half the
 * per-job checks at the top of this file structurally cannot reach.
 *
 * Those are generated per PAIRED job, and `pairedJobs` skips any job missing
 * EITHER action. So a credentialed job that builds the binding with no
 * pre-flight at all is not failing them; it is absent from them — the same
 * silent-skip shape as the deleted-step case that motivated
 * `EXPECTED_PAIRED_JOBS`, except no hand-maintained list catches it either,
 * because the job is a legitimate new entry rather than a missing old one.
 *
 * `tests.yml`'s `run-tests-bun` was the live instance: it writes all four CS_*
 * into `packages/stack/.env` and runs `./.github/actions/build-ffi-binding`
 * with no pre-flight before it. It appeared in `EXPECTED_CREDENTIALED_JOBS`,
 * satisfied the coverage check, and generated zero ordering assertions.
 *
 * The fix is to derive the check from the credential expression rather than
 * from the presence of the very step being checked for. A job that skipped the
 * pre-flight then FAILS this instead of disappearing from it.
 */
describe('every credentialed job runs the secrets pre-flight first', () => {
  it('exempts only jobs that are still credentialed', () => {
    const guard = SCAN_GUARDS.preflightExemptions
    expect(guard.unmatched, guard.message).toEqual([])
  })

  it('runs the pre-flight before the binding build in every credentialed job', () => {
    const offenders = CREDENTIALED.filter(
      (entry) =>
        !PREFLIGHT_EXEMPT_JOBS.has(`${entry.relPath} / ${entry.jobName}`) &&
        (!entry.runsPreflight ||
          (entry.buildsBinding && entry.firstSecrets > entry.firstBuild)),
    ).map((entry) =>
      entry.runsPreflight
        ? `${entry.relPath} / ${entry.jobName} — pre-flight at step ${entry.firstSecrets}, binding build at step ${entry.firstBuild}`
        : `${entry.relPath} / ${entry.jobName} — no ${REQUIRE_SECRETS} step at all`,
    )

    expect(
      offenders,
      `These jobs receive CipherStash credentials without running ${REQUIRE_SECRETS} ahead of ${BUILD_FFI}.\nThe pre-flight costs seconds; a cold Rust build costs minutes. A job that learns its credential was rotated only after the compile has the same cost profile as a job with no pre-flight at all.\nWhen the step is MISSING, add it immediately before the binding build, wiring the four inputs from \`vars.CS_WORKSPACE_CRN\`, \`vars.CS_CLIENT_ID\`, \`secrets.CS_CLIENT_KEY\` and \`secrets.CS_CLIENT_ACCESS_KEY\` — copy the \`Require CipherStash secrets\` step in \`tests.yml\`'s \`run-tests\`.\nWhen it is merely LATE, move the PRE-FLIGHT UP rather than the build down: in \`tests.yml\`'s \`wasm-e2e-tests\` a \`Build stack\` step sits between them and consumes \`dist/wasm/**\`, so the other edit would break the job.\nIf a job genuinely does not need one, add it to PREFLIGHT_EXEMPT_JOBS with the reason.`,
    ).toEqual([])
  })
})

/**
 * The guards above are only ever read when they FAIL, which is the one moment
 * their text has to be right and the one moment nothing is watching it. So the
 * text itself is asserted here, on the real strings the guards carry.
 *
 * The property is "the message names every job the scan found", and it is the
 * difference between a two-second fix and a source dive on the most likely
 * failure these guards will ever see: a job rename. The developer has the OLD
 * id — it is in the list, and in the diff — and needs the NEW one. Without the
 * listing the new id appears nowhere in the output, and the only way to get it
 * is to open the workflow and re-derive what the scan would have matched.
 */
describe('the scan guards name what they found', () => {
  for (const [label, guard] of Object.entries(SCAN_GUARDS)) {
    it(`${label}: the failure message lists every job its scan found`, () => {
      // Not vacuous: an empty scan would satisfy a bare forEach over `found`.
      // These guards exist precisely because a scan can silently empty out.
      expect(
        guard.found.length,
        `The ${label} scan matched no jobs at all, so this test would pass without checking anything.`,
      ).toBeGreaterThan(0)

      const unlisted = guard.found.filter((id) => !guard.message.includes(id))
      expect(
        unlisted,
        `The ${label} guard's failure message does not name these jobs, and they are exactly what a reader needs.\nWhen a job is renamed the guard reports the OLD id as missing; the NEW id is only visible if the message lists what the scan found. Keep the listing (see \`scanGuard\`).\nMessage as it stands:\n${guard.message}`,
      ).toEqual([])
    })
  }

  it('says so explicitly when the scan matched nothing', () => {
    // The empty scan is the catastrophic case, not a corner case: rename either
    // action path and `pairedJobs` matches nothing at all (mutation-tested —
    // pointing BUILD_FFI at a path no workflow uses took the file from 21 tests
    // to 11, with the ten ordering checks not failing but ceasing to exist).
    // Rendered as a bare empty list the message
    // ends on a dangling "The scan currently sees:" with vitest's own
    // `expected [...] to deeply equal []` running on from the same line, which
    // reads as a broken template rather than as the finding.
    const guard = scanGuard({
      entries: ['workflow.yml / job'],
      found: [],
      hint: 'hint',
    })
    expect(guard.message).toContain('(nothing — the scan matched no jobs)')
  })
})
