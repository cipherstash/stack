import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import yaml from 'js-yaml'
import { afterAll, describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * The EQL suite's full Postgres matrix must be reachable by a trigger that
 * actually fires in THIS repository.
 *
 * WHAT HAPPENED. The workflow arrived from `cipherstash/encrypt-query-language`
 * with the subtree, and its `setup` job derives the fan-out from the event:
 * `merge_group` gets PG 14-17, everything else gets PG17 alone. The port also
 * dropped the `push:` trigger, justified in the file header by "Under a
 * required merge queue, push-to-main validation is redundant: the queue already
 * validated the exact merge commit, and branch protection blocks direct
 * pushes."
 *
 * Every clause of that premise is false here. Checked against the live repo:
 *
 *   gh api graphql '{repository(owner:"cipherstash",name:"stack"){
 *     mergeQueue(branch:"main"){id}}}'   ->  {"mergeQueue": null}
 *   gh api repos/cipherstash/stack/branches/main/protection
 *                                        ->  404 "Branch not protected"
 *   the active ruleset (id 4478501) carries only `deletion`, `pull_request`
 *   (1 approval), `non_fast_forward` and `required_signatures` — there is NO
 *   `required_status_checks` rule, so `ci-required` is required by nothing.
 *
 * `merge_group` is therefore an event this repository never emits. `test-eql.yml`
 * is the only workflow in the tree that declares it, and it was the sole gate on
 * the full matrix — so PG 14, 15 and 16 were tested NEVER, and with `push:`
 * gone nothing EQL-related ran post-merge at all. Both failures are invisible:
 * an event that is never delivered produces no runs to notice the absence of.
 *
 * WHY THE PROPERTY IS SPELLED THIS WAY. A test in the tree cannot query repo
 * settings, and one that could would be asserting about a mutable dashboard
 * rather than about this file. So the invariant is encoded structurally: the
 * full matrix must be reachable from `push`, `schedule` or `pull_request` —
 * events GitHub delivers on its own. `merge_group` and `workflow_dispatch` are
 * deliberately excluded: the first requires a merge queue that does not exist,
 * the second requires a human to press a button, and "someone could run it by
 * hand" is not coverage. If a merge queue is turned on later, `merge_group` may
 * be ADDED to the full-matrix path — it may not become the only one again
 * without deleting this test on purpose.
 *
 * The fan-out is not re-derived here, it is EXECUTED: the `setup` job's script
 * is run once per candidate event and its real `$GITHUB_OUTPUT` is read back.
 * A guard that reimplemented the if/else would agree with a rewritten script
 * exactly as often as it disagreed.
 */

const WORKFLOW = '.github/workflows/test-eql.yml'
const COMPOSE = 'packages/eql/tests/docker-compose.yml'

/**
 * The events GitHub delivers without a merge queue and without a human. The
 * whole point of the file — see the header.
 */
const SELF_FIRING_EVENTS = ['push', 'schedule', 'pull_request']

/** Every event the check evaluates the matrix under. */
const CANDIDATE_EVENTS = [
  ...SELF_FIRING_EVENTS,
  'merge_group',
  'workflow_dispatch',
]

const wf = readWorkflow(WORKFLOW)

/** `on:` parses as the boolean `true` under YAML 1.1 — the "Norway problem". */
const TRIGGERS = (() => {
  const on = wf?.on ?? wf?.[true]
  return on && typeof on === 'object' ? on : {}
})()

const DECLARED = CANDIDATE_EVENTS.filter((event) => event in TRIGGERS)

/**
 * The Postgres versions this suite ships a container for, read from the compose
 * file the `postgres:up` task drives rather than listed here.
 *
 * Derived because the two lists are one claim: a `postgres-18` service that no
 * matrix ever selects is a version nobody tests, which is the same defect as
 * the one above wearing different clothes.
 */
function supportedPostgresVersions() {
  const compose = yaml.load(readFileSync(join(REPO_ROOT, COMPOSE), 'utf8'))
  return Object.keys(compose?.services ?? {})
    .map((name) => /^postgres-(\d+)$/.exec(name))
    .filter(Boolean)
    .map((match) => Number(match[1]))
    .sort((a, b) => a - b)
}

const SUPPORTED_PG = supportedPostgresVersions()

// ---------------------------------------------------------------------------
// Following the workflow's own data flow to the script that computes the matrix
// ---------------------------------------------------------------------------

/** `${{ needs.<job>.outputs.<name> }}` -> `{ job, output }`, else null. */
function needsOutputRef(expression) {
  const match = /needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)/.exec(
    String(expression ?? ''),
  )
  return match ? { job: match[1], output: match[2] } : null
}

/**
 * The step that produces `jobs.<job>.outputs.<name>`, found by resolving the
 * output expression to a step `id`.
 *
 * Discovery rather than a named constant: the coupling being checked is
 * matrix -> job output -> step, and following it means a renamed job or step
 * fails this file loudly instead of leaving it checking a script nothing runs.
 */
function stepProducing({ job, output }) {
  const definition = wf?.jobs?.[job]
  const ref = /steps\.([A-Za-z0-9_-]+)\.outputs\./.exec(
    String(definition?.outputs?.[output] ?? ''),
  )
  if (!ref) return null
  const step = (definition?.steps ?? []).find((entry) => entry?.id === ref[1])
  return step ? { job, stepId: ref[1], step } : null
}

/** The job output the matrix's `postgres-version` axis is computed from. */
const MATRIX_SOURCE = (() => {
  for (const job of Object.values(wf?.jobs ?? {})) {
    const axis = job?.strategy?.matrix?.['postgres-version']
    const ref = needsOutputRef(axis)
    if (ref) return ref
  }
  return null
})()

/** The relevance flag every gated job's `if:` reads. */
const RELEVANCE_SOURCE = (() => {
  for (const job of Object.values(wf?.jobs ?? {})) {
    const ref = needsOutputRef(job?.if)
    if (ref) return ref
  }
  return null
})()

const MATRIX_STEP = MATRIX_SOURCE ? stepProducing(MATRIX_SOURCE) : null
const RELEVANCE_STEP = RELEVANCE_SOURCE ? stepProducing(RELEVANCE_SOURCE) : null

/**
 * The step `env:` key wired to `${{ github.event_name }}`.
 *
 * The script has to read the event from the environment rather than from an
 * inlined `${{ }}`, precisely so it can be executed here against each event in
 * turn. That is not a concession to the test: an expression interpolated into a
 * shell body is unrunnable, unquotable and — for anything less fixed than an
 * event name — an injection site.
 */
function eventEnvKey(step) {
  return (
    Object.entries(step?.env ?? {}).find(([, value]) =>
      /^\$\{\{\s*github\.event_name\s*\}\}$/.test(String(value)),
    )?.[0] ?? null
  )
}

const SCRATCH = mkdtempSync(join(tmpdir(), 'eql-matrix-triggers-'))
afterAll(() => rmSync(SCRATCH, { recursive: true, force: true }))

let runCounter = 0

/**
 * Run a step's `run:` body under a synthetic event and return the key/value
 * pairs it wrote to `$GITHUB_OUTPUT`.
 *
 * Every OTHER `env:` entry is set to the empty string, which is what GitHub
 * actually substitutes for an expression that resolves to nothing — the
 * relevance step reads `steps.f.outputs.relevant`, and step `f` is skipped on
 * every event but `pull_request`.
 */
function runStep({ step }, eventName) {
  const envKey = eventEnvKey(step)
  runCounter += 1
  const outputFile = join(SCRATCH, `outputs-${runCounter}.txt`)
  writeEmpty(outputFile)

  const env = { PATH: process.env.PATH, GITHUB_OUTPUT: outputFile }
  for (const key of Object.keys(step?.env ?? {})) env[key] = ''
  env[envKey] = eventName

  execFileSync('bash', ['-c', String(step.run)], {
    cwd: SCRATCH,
    env,
    encoding: 'utf8',
  })

  return Object.fromEntries(
    readFileSync(outputFile, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((line) => {
        const at = line.indexOf('=')
        return [line.slice(0, at), line.slice(at + 1)]
      }),
  )
}

function writeEmpty(path) {
  execFileSync('bash', ['-c', ': > "$1"', 'bash', path])
}

/** The Postgres versions the matrix fans out to under one event. */
function pgVersionsFor(eventName) {
  const outputs = runStep(MATRIX_STEP, eventName)
  const raw = outputs[MATRIX_SOURCE.output.replace(/-/g, '_')] ?? outputs.pg
  return JSON.parse(raw)
    .map(Number)
    .sort((a, b) => a - b)
}

const isFullMatrix = (versions) =>
  SUPPORTED_PG.every((version) => versions.includes(version))

describe('the EQL matrix is reachable by a trigger that fires', () => {
  it('follows the workflow to the script that computes the fan-out', () => {
    // Every assertion below runs that script. If the trail from the matrix axis
    // to it breaks, this file would otherwise report success having executed
    // nothing — the failure mode the whole directory guards against.
    expect(
      MATRIX_SOURCE,
      `No job in ${WORKFLOW} derives \`strategy.matrix.postgres-version\` from a \`needs.<job>.outputs.<name>\` expression, so there is no fan-out to evaluate.`,
    ).toBeTruthy()
    expect(
      MATRIX_STEP,
      `\`jobs.${MATRIX_SOURCE?.job}.outputs.${MATRIX_SOURCE?.output}\` does not resolve to a step \`id:\` in that job.`,
    ).toBeTruthy()
    expect(
      eventEnvKey(MATRIX_STEP?.step),
      `The "${MATRIX_SOURCE?.job}" job's \`${MATRIX_STEP?.stepId}\` step must read the event from its \`env:\` (a key set to \`\${{ github.event_name }}\`) rather than interpolating the expression into the shell body. An inlined expression cannot be executed here, so this guard would silently stop evaluating the real fan-out.`,
    ).toBeTruthy()

    expect(
      SUPPORTED_PG.length,
      `${COMPOSE} declares fewer than two \`postgres-<version>\` services, so "the full matrix" is not a meaningful claim. Either the compose file was restructured or the service naming changed.`,
    ).toBeGreaterThanOrEqual(2)
  })

  it('runs the full matrix under at least one event', () => {
    // Separated from the check below so the two failures read differently: this
    // one means the workflow no longer HAS a full-matrix path, which is a much
    // larger finding than it having one behind the wrong trigger.
    const full = CANDIDATE_EVENTS.filter((event) =>
      isFullMatrix(pgVersionsFor(event)),
    )
    expect(
      full,
      `No event makes ${WORKFLOW} fan out across every Postgres version in ${COMPOSE} (${SUPPORTED_PG.join(', ')}). Per event:\n${CANDIDATE_EVENTS.map((event) => `  ${event}: PG ${pgVersionsFor(event).join(', ')}`).join('\n')}`,
    ).not.toEqual([])
  })

  it('reaches the full matrix from a trigger this repo actually emits', () => {
    const reaching = SELF_FIRING_EVENTS.filter(
      (event) => DECLARED.includes(event) && isFullMatrix(pgVersionsFor(event)),
    )
    expect(
      reaching,
      `${WORKFLOW} gates its full Postgres matrix behind events this repository never delivers on its own.\nDeclared triggers: ${DECLARED.join(', ') || '(none)'}\nPer event:\n${CANDIDATE_EVENTS.map((event) => `  ${event}: ${DECLARED.includes(event) ? '' : '(not declared) '}PG ${pgVersionsFor(event).join(', ')}`).join('\n')}\nThere is no merge queue on \`main\` and no \`required_status_checks\` rule (see this file's header for the API responses), so \`merge_group\` never fires and \`workflow_dispatch\` needs a human. Give the full matrix a \`push\`, \`schedule\` or \`pull_request\` path.`,
    ).not.toEqual([])
  })

  it('keeps a post-merge run of some shape', () => {
    // Weaker than the check above and not implied by it: a nightly `schedule`
    // satisfies the full-matrix property while leaving every merge to `main`
    // unvalidated until 02:00. Both halves were lost in the same edit.
    expect(
      DECLARED.filter((event) => event === 'push' || event === 'schedule'),
      `${WORKFLOW} declares neither \`push\` nor \`schedule\`, so nothing EQL-related runs after a pull request merges. With no branch protection and no merge queue on \`main\`, the pre-merge run is the ONLY run — and it validated the head commit, not the merge result.`,
    ).not.toEqual([])
  })
})

describe('the relevance flag opens on every non-PR event', () => {
  it('follows the workflow to the step that computes it', () => {
    expect(
      RELEVANCE_SOURCE,
      `No job \`if:\` in ${WORKFLOW} reads a \`needs.<job>.outputs.<name>\` relevance flag, so this suite has nothing to evaluate.`,
    ).toBeTruthy()
    expect(RELEVANCE_STEP).toBeTruthy()
    expect(
      eventEnvKey(RELEVANCE_STEP?.step),
      `The "${RELEVANCE_SOURCE?.job}" job's \`${RELEVANCE_STEP?.stepId}\` step must read the event from its \`env:\` rather than inlining \`\${{ github.event_name }}\`, for the reason given on the matrix step.`,
    ).toBeTruthy()
  })

  for (const event of CANDIDATE_EVENTS.filter((e) => e !== 'pull_request')) {
    it(`defaults to relevant on ${event}`, () => {
      // The path filter only runs on `pull_request` — it needs a base ref — so
      // on every other event the flag is a hardcoded default. Get that default
      // wrong and every gated job skips on the new trigger while the run still
      // reports success, which is the same silent-skip class as the trigger bug
      // this file exists for.
      const outputs = runStep(RELEVANCE_STEP, event)
      expect(
        outputs[RELEVANCE_SOURCE.output],
        `The relevance step wrote ${JSON.stringify(outputs)} on a ${event} event. Every heavy job is gated on this being 'true', and the filter that would compute it does not run outside \`pull_request\`.`,
      ).toBe('true')
    })
  }
})

/**
 * The structural half, and the one that outlives the specific trigger added
 * today.
 *
 * Every gated job here was written as an ALLOWLIST of events —
 * `merge_group || workflow_dispatch || (pull_request && relevant)` — which is
 * the exact defect `workflow-dispatch-job-conditions.test.mjs` was written for
 * one workflow over: a condition that enumerates the events known at writing
 * time fails SHUT on the one nobody enumerated. Add a trigger and every job
 * skips, the run reports success, and nothing says the suite did not execute.
 *
 * The corrected form is the same inversion that file prescribes: name the case
 * that must NOT run — a pull request whose diff is irrelevant, or one from a
 * fork that has no secrets — and let every other event through. So the rule is
 * mechanical: no job condition in this workflow may test `github.event_name`
 * for EQUALITY.
 */
describe('no job condition enumerates the events it will run on', () => {
  const CONDITIONS = Object.entries(wf?.jobs ?? {})
    .filter(([, job]) => job?.if !== undefined)
    .map(([jobName, job]) => ({ jobName, condition: String(job.if) }))

  it('finds the job conditions it means to check', () => {
    expect(
      CONDITIONS.map((entry) => entry.jobName),
      `No job in ${WORKFLOW} carries an \`if:\`, so this check iterates nothing. Either the gating moved or the file was restructured.`,
    ).not.toEqual([])
  })

  for (const { jobName, condition } of CONDITIONS) {
    it(`${jobName} gates on what must not run, not on what may`, () => {
      const allowlisted = [
        ...condition.matchAll(/github\.event_name\s*==\s*'([^']*)'/g),
      ].map((match) => match[1])
      expect(
        allowlisted,
        `The \`if:\` on "${jobName}" enumerates the events it runs on:\n  if: ${condition}\nA trigger added later matches none of these clauses, so every job skips, the run reports success, and nothing indicates the suite did not execute — which is the failure this workflow already shipped once. Invert it: \`github.event_name != 'pull_request' || <the pull-request-only gate>\`.`,
      ).toEqual([])
    })
  }
})
