import { describe, expect, it } from 'vitest'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * The failsafe: the test that fails when the selector job does not decide
 * whether a job runs.
 *
 * ADR 0003 and `.github/CONTEXT.md` describe the design. A selector job starts
 * each workflow that runs on a pull request or in a merge queue. It compares
 * the files a change touches with each check's trigger paths. Each job's `if:`
 * reads its answer. A job that does not read it runs on every change. That
 * costs money, and nobody notices. This test makes it visible.
 *
 * It reads every workflow that runs on `pull_request` or `merge_group`. In
 * each one, a job passes when one of these is true:
 *
 * - It is the selector job, or the summary job that ends the workflow.
 * - Its `needs:` includes the selector job and its `if:` reads the selector
 *   job's outputs. Each output it reads must be one the selector job declares:
 *   an output that does not exist is empty, and the job would never run.
 * - It needs a job that passes by the rule above, and its `if:` calls no
 *   `always()`, `failure()` or `cancelled()`. GitHub then skips it whenever
 *   that job is skipped, so the selector decides it too.
 * - It has a written reason in `RUNS_ON_EVERY_CHANGE`.
 *
 * A whole workflow can be exempt, with a written reason, in `NOT_CHECKS` or
 * `NOT_YET_CONVERTED`. An exemption that matches nothing, or is no longer
 * needed, fails the test. So the lists only hold what is true today.
 *
 * The failsafe reads workflow files. It does not act while a workflow runs.
 */

const SELECTOR = 'selector'

/**
 * Workflows that will never have a selector job. They are not checks, and no
 * branch rule requires them.
 */
const NOT_CHECKS = {
  '.github/workflows/claude-review.yml':
    'Review bot, not a check. No branch rule requires it.',
  '.github/workflows/code-review.yml':
    'Review bot, not a check. No branch rule requires it.',
  '.github/workflows/impact.yml':
    'Advisory report, not a check. No branch rule requires it.',
}

/**
 * Workflows that do not have a selector job yet. Each conversion removes its
 * entry, and this list shrinks to empty.
 */
const NOT_YET_CONVERTED = Object.fromEntries(
  [
    'codeql.yml',
    'crap-crates.yml',
    'fta-v3.yml',
    'fuzz.yml',
    'integration-drizzle.yml',
    'integration-prisma-next.yml',
    'integration-protect-ffi.yml',
    'integration-supabase.yml',
    'lint-release.yml',
    'miri.yml',
    'musl-build-image.yml',
    'mutants.yml',
    'osv-scanner.yml',
    'prisma-example-readme-e2e.yml',
    'prisma-next-e2e.yml',
    'require-auth-npm-changeset.yml',
    'tests-auth-refresh.yml',
    'tests-bench.yml',
    'tests-crates.yml',
    'tests-golang.yml',
    'tests-rust.yml',
    'tests-supply-chain.yml',
    'tests.yml',
    'udeps.yml',
  ].map((name) => [
    `.github/workflows/${name}`,
    'Not yet converted to a selector job.',
  ]),
)

/**
 * Jobs in a workflow with a selector job that run on every change, on
 * purpose. Keyed `<workflow>#<job id>`.
 */
const RUNS_ON_EVERY_CHANGE = {
  '.github/workflows/test-eql.yml#setup':
    'Sets the Postgres versions and shard count that the gated jobs read. It is a bash step with no checkout.',
  '.github/workflows/test-eql.yml#docs-static':
    'Checks the SQL documentation on every pull request, including the docs-only ones the selector skips. It needs no database or credentials.',
  '.github/workflows/test-eql.yml#known-failures':
    'Checks that each suppressed test names an open issue, on every pull request. It needs no database or credentials.',
  '.github/workflows/test-eql.yml#doc-anchors':
    'Checks Markdown anchor links. Its inputs are the docs themselves, which the selector does not select for.',
}

const IN_SCOPE_EVENTS = ['pull_request', 'merge_group']

function events(workflow) {
  // `on:` parses as the boolean `true` under YAML 1.1.
  const on = workflow?.on ?? workflow?.[true]
  if (typeof on === 'string') return [on]
  if (Array.isArray(on)) return on
  return Object.keys(on ?? {})
}

const needsOf = (job) => [job?.needs ?? []].flat()

const ifText = (job) => String(job?.if ?? '')

/** The selector outputs a job's `if:` reads. */
const outputsRead = (job) =>
  [
    ...ifText(job).matchAll(
      new RegExp(`needs\\.${SELECTOR}\\.outputs\\.([A-Za-z0-9_-]+)`, 'g'),
    ),
  ].map((match) => match[1])

/** A status function stops GitHub skipping a job when a job it needs skipped. */
const keepsRunningAfterSkip = (job) =>
  /\b(always|failure|cancelled)\s*\(/.test(ifText(job))

/**
 * The job that ends the workflow: its `if:` is `always()` and it needs every
 * other job.
 */
function summaryJobId(jobs) {
  const ids = Object.keys(jobs)
  const last = ids.at(-1)
  const others = ids.filter((id) => id !== last).sort()
  const needs = [...needsOf(jobs[last])].sort()
  const isSummary =
    ifText(jobs[last]).trim() === 'always()' &&
    JSON.stringify(needs) === JSON.stringify(others)
  return isSummary ? last : undefined
}

/** The ids of the jobs the selector job decides, directly or through `needs:`. */
function decidedJobIds(jobs) {
  const declared = Object.keys(jobs[SELECTOR]?.outputs ?? {})
  const readsSelector = (job) => {
    const read = outputsRead(job)
    return read.length > 0 && read.every((name) => declared.includes(name))
  }
  const decided = new Set(
    Object.entries(jobs)
      .filter(
        ([, job]) => needsOf(job).includes(SELECTOR) && readsSelector(job),
      )
      .map(([id]) => id),
  )
  let grew = true
  while (grew) {
    grew = false
    for (const [id, job] of Object.entries(jobs)) {
      if (decided.has(id) || keepsRunningAfterSkip(job)) continue
      if (needsOf(job).some((need) => decided.has(need))) {
        decided.add(id)
        grew = true
      }
    }
  }
  return decided
}

const WORKFLOWS = workflowFiles()
  .map((file) => ({ file, workflow: readWorkflow(file) }))
  .filter(({ workflow }) =>
    events(workflow).some((event) => IN_SCOPE_EVENTS.includes(event)),
  )

const hasSelector = ({ workflow }) => Boolean(workflow?.jobs?.[SELECTOR])

const isExemptWorkflow = ({ file }) =>
  file in NOT_CHECKS || file in NOT_YET_CONVERTED

/** The workflows checked job by job. */
const CHECKED = WORKFLOWS.filter(
  (entry) => hasSelector(entry) && !isExemptWorkflow(entry),
).map(({ file, workflow }) => {
  const jobs = workflow.jobs
  return {
    file,
    jobs,
    summary: summaryJobId(jobs),
    decided: decidedJobIds(jobs),
  }
})

const reasonMissing = (map) =>
  Object.entries(map)
    .filter(([, reason]) => typeof reason !== 'string' || !reason.trim())
    .map(([key]) => key)

describe('the failsafe', () => {
  it('finds the workflows it checks', () => {
    // An empty scan would pass every check below.
    expect(WORKFLOWS.length).toBeGreaterThan(0)
    expect(CHECKED.map(({ file }) => file)).toContain(
      '.github/workflows/test-eql.yml',
    )
  })

  it('fails when the selector job does not decide whether a job runs', () => {
    const undecided = CHECKED.flatMap(({ file, jobs, summary, decided }) =>
      Object.keys(jobs)
        .filter((id) => id !== SELECTOR && id !== summary)
        .filter((id) => !decided.has(id))
        .map((id) => `${file}#${id}`)
        .filter((ref) => !(ref in RUNS_ON_EVERY_CHANGE)),
    )
    expect(
      undecided,
      `The selector job does not decide whether these jobs run, so they run on every change. Give each one \`needs: [${SELECTOR}]\` and an \`if:\` that reads an output the selector job declares. If a job must run on every change, add it to RUNS_ON_EVERY_CHANGE with the reason. If the summary job is listed, make it the last job, with \`if: always()\` and every other job in its \`needs:\`.`,
    ).toEqual([])
  })

  it('fails when a workflow on pull requests or in a merge queue has no selector job', () => {
    const missing = WORKFLOWS.filter(
      (entry) => !hasSelector(entry) && !isExemptWorkflow(entry),
    ).map(({ file }) => file)
    expect(
      missing,
      `These workflows run on pull requests or in a merge queue and have no \`${SELECTOR}\` job. Add one (ADR 0003), or exempt the workflow with a reason.`,
    ).toEqual([])
  })

  it('fails when an exemption has no written reason', () => {
    expect([
      ...reasonMissing(NOT_CHECKS),
      ...reasonMissing(NOT_YET_CONVERTED),
      ...reasonMissing(RUNS_ON_EVERY_CHANGE),
    ]).toEqual([])
  })

  it('fails when a workflow exemption matches no workflow it would exempt', () => {
    const inScope = new Map(WORKFLOWS.map((entry) => [entry.file, entry]))
    const stale = [
      ...Object.keys(NOT_CHECKS)
        .filter((file) => !inScope.has(file))
        .map(
          (file) =>
            `${file}: in NOT_CHECKS, but it runs on no pull request or merge queue`,
        ),
      ...Object.keys(NOT_YET_CONVERTED)
        .filter((file) => !inScope.has(file))
        .map(
          (file) =>
            `${file}: in NOT_YET_CONVERTED, but it runs on no pull request or merge queue`,
        ),
      ...Object.keys(NOT_YET_CONVERTED)
        .filter((file) => inScope.has(file) && hasSelector(inScope.get(file)))
        .map(
          (file) =>
            `${file}: in NOT_YET_CONVERTED, but it has a selector job. Remove the entry.`,
        ),
      ...Object.keys(NOT_CHECKS)
        .filter((file) => file in NOT_YET_CONVERTED)
        .map((file) => `${file}: in both NOT_CHECKS and NOT_YET_CONVERTED`),
    ]
    expect(stale).toEqual([])
  })

  it('fails when a job exemption matches no job the selector leaves undecided', () => {
    const undecidedRefs = new Set(
      CHECKED.flatMap(({ file, jobs, summary, decided }) =>
        Object.keys(jobs)
          .filter((id) => id !== SELECTOR && id !== summary)
          .filter((id) => !decided.has(id))
          .map((id) => `${file}#${id}`),
      ),
    )
    const stale = Object.keys(RUNS_ON_EVERY_CHANGE).filter(
      (ref) => !undecidedRefs.has(ref),
    )
    expect(
      stale,
      'These exemptions match no job that the selector job leaves undecided. The job is gone, its workflow is exempt as a whole, or the selector now decides it. Remove each entry.',
    ).toEqual([])
  })
})
