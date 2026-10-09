import { describe, expect, it } from 'vitest'
import { expr } from './lib/expressions.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * A scheduled workflow that fails must tell someone.
 *
 * WHAT HAPPENED. The nightly fuzz campaign uploaded each crash reproducer as an
 * artifact and stopped there. A scheduled run has no pull request to turn red,
 * and GitHub mails its failure to one person — whoever last edited the cron
 * line — so a crash would have sat in the Actions tab until someone happened to
 * look. test-eql.yml, macro-expand-eql.yml and bench-eql.yml had the same gap,
 * as did the push-to-main runs of the first and last; only
 * musl-build-image.yml opened an issue.
 *
 * THE FIX is `_report-unattended-failure.yml`, called as the last job of each
 * of those workflows. This file pins the ways that call can quietly stop
 * working:
 *
 * 1. A new scheduled workflow lands without it. So scheduled workflows are
 *    DISCOVERED by scanning the directory, and each must either call the
 *    reporter or be listed in `REPORTS_ELSEWHERE` with its reason.
 * 2. A job is added to a workflow but not to the report job's `needs`. The
 *    report job's `failure()` only sees the jobs it needs, so a failure in the
 *    new job would go unreported, silently. So `needs` must be every other job.
 * 3. The condition is narrowed back to `github.event_name == 'schedule'`,
 *    which drops push-to-main failures and fails shut on any trigger added
 *    later (eql-matrix-triggers.test.mjs forbids that shape in test-eql.yml
 *    for the same reason). So the condition is held to one spelling.
 */

const REPORTER = './.github/workflows/_report-unattended-failure.yml'

/** The report job's condition, as the parsed workflow holds it. */
const CONDITION =
  "failure() && github.event_name != 'pull_request' && github.event_name != 'workflow_dispatch'"

/**
 * Scheduled workflows that do not call the reporter, with the reason. An
 * equality, not a floor: an entry for a workflow that has since started
 * calling the reporter, or stopped being scheduled, fails too.
 */
const REPORTS_ELSEWHERE = {
  // CodeQL uploads its findings to code scanning, where they raise alerts on
  // their own.
  '.github/workflows/codeql.yml': 'findings go to code scanning',
  // Same: `fail-on-vuln: false`, and the scan's SARIF goes to code scanning.
  '.github/workflows/osv-scanner.yml': 'findings go to code scanning',
  // Opens its own issue from a step inside its single job, pinned by
  // musl-build-image.test.mjs.
  '.github/workflows/musl-build-image.yml': 'opens its own issue',
}

/**
 * The workflows known to call the reporter today. A minimum, so the discovery
 * below cannot pass by finding nothing.
 */
const EXPECTED_REPORTERS = [
  '.github/workflows/bench-eql.yml',
  '.github/workflows/fuzz.yml',
  '.github/workflows/macro-expand-eql.yml',
  '.github/workflows/test-eql.yml',
]

function triggers(wf) {
  return wf?.on ?? wf?.[true] ?? {}
}

const workflows = workflowFiles().map((path) => ({
  path,
  wf: readWorkflow(path),
}))

function reportJobs(wf) {
  return Object.entries(wf?.jobs ?? {}).filter(
    ([, job]) => job?.uses === REPORTER,
  )
}

const reporters = workflows.filter(({ wf }) => reportJobs(wf).length > 0)

describe('unattended workflow failures are reported', () => {
  it('discovers the known reporters', () => {
    expect(reporters.map(({ path }) => path)).toEqual(
      expect.arrayContaining(EXPECTED_REPORTERS),
    )
  })

  it('every scheduled workflow calls the reporter or says why not', () => {
    const silent = workflows
      .filter(({ wf }) => triggers(wf).schedule)
      .filter(({ wf }) => reportJobs(wf).length === 0)
      .map(({ path }) => path)
      .sort()
    expect(silent).toEqual(Object.keys(REPORTS_ELSEWHERE).sort())
  })

  for (const { path, wf } of reporters) {
    it(`${path} reports a failure in any of its jobs`, () => {
      const jobs = reportJobs(wf)
      expect(jobs).toHaveLength(1)
      const [[name, job]] = jobs
      const others = Object.keys(wf.jobs)
        .filter((other) => other !== name)
        .sort()
      expect([job.needs].flat().sort()).toEqual(others)
      expect(job.if).toBe(CONDITION)
      expect(job.permissions).toEqual({ issues: 'write' })
      expect(String(job.with?.guidance ?? '').trim()).not.toBe('')
    })
  }

  it('the reporter keeps one open issue per workflow and branch', () => {
    const wf = readWorkflow(REPORTER.slice(2))
    expect(triggers(wf).workflow_call?.inputs?.guidance?.required).toBe(true)
    const steps = Object.values(wf.jobs).flatMap((job) => job?.steps ?? [])
    const run = steps.map((step) => String(step?.run ?? '')).join('\n')
    expect(run).toContain('gh issue create')
    expect(run).toContain('gh issue comment')
    // The issue is found by its title, so the title must name the caller.
    const env = Object.assign({}, ...steps.map((step) => step?.env ?? {}))
    expect(env.TITLE).toContain(expr('github.workflow'))
    expect(env.TITLE).toContain(expr('github.ref_name'))
  })
})
