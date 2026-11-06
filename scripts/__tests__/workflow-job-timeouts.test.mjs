import { describe, expect, it } from 'vitest'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * Every job sets `timeout-minutes`.
 *
 * Without it, GitHub stops a job after 360 minutes. A job that hangs holds
 * its runner, and costs money, for all of that time. In a trial of new
 * runners, one job without a limit ran for over 2 hours.
 *
 * A job that calls a reusable workflow (a job-level `uses:`) cannot set
 * `timeout-minutes`, because GitHub rejects the key there. A call to a
 * workflow in this repository needs nothing more: this test reads the called
 * workflow too, so its own jobs must set the limit. A call to a workflow in
 * another repository is different. Its jobs are defined there, so nothing
 * here can limit them. Each such call needs a written reason below.
 */
const EXTERNAL_CALLS = {
  '.github/workflows/osv-scanner.yml#osv-scan':
    'Calls the OSV-Scanner reusable workflow from google/osv-scanner-action. Its jobs, and their timeouts, are defined in that repository.',
}

const jobs = workflowFiles().flatMap((file) =>
  Object.entries(readWorkflow(file)?.jobs ?? {}).map(([id, job]) => ({
    ref: `${file}#${id}`,
    job,
  })),
)

const callsWorkflow = ({ job }) => typeof job?.uses === 'string'
const callsExternalWorkflow = (entry) =>
  callsWorkflow(entry) && !entry.job.uses.startsWith('./')

/** A positive number, or an expression GitHub resolves when the job starts. */
const isTimeout = (value) =>
  (typeof value === 'number' && value > 0) ||
  (typeof value === 'string' && /^\$\{\{.+\}\}$/.test(value.trim()))

describe('every workflow job sets timeout-minutes', () => {
  it('finds the jobs it checks', () => {
    // An empty scan would pass every check below.
    expect(jobs.length).toBeGreaterThan(50)
  })

  it('sets timeout-minutes on every job that runs on a runner', () => {
    const missing = jobs
      .filter((entry) => !callsWorkflow(entry))
      .filter(({ job }) => !isTimeout(job?.['timeout-minutes']))
      .map(({ ref }) => ref)
    expect(missing).toEqual([])
  })

  it('gives a written reason for each call to another repository’s workflow', () => {
    const unexplained = jobs
      .filter(callsExternalWorkflow)
      .map(({ ref }) => ref)
      .filter((ref) => !EXTERNAL_CALLS[ref]?.trim())
    expect(unexplained).toEqual([])
  })

  it('has no reason left for a call that no longer exists', () => {
    const external = new Set(
      jobs.filter(callsExternalWorkflow).map(({ ref }) => ref),
    )
    const stale = Object.keys(EXTERNAL_CALLS).filter(
      (ref) => !external.has(ref),
    )
    expect(stale).toEqual([])
  })
})
