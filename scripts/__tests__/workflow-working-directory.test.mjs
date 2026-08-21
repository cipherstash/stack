import { describe, expect, it } from 'vitest'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * A `run:` step cannot enter a directory the runner does not have.
 *
 * `test-eql.yml` sets `defaults.run.working-directory: packages/eql` at
 * WORKFLOW level, which is the right call — every `run:` in it is written
 * against the EQL root, and the alternative is ~30 per-step lines that can each
 * be forgotten independently. But workflow-level defaults reach every job,
 * including the ones that deliberately never check out: a pure-bash matrix
 * computation, and an aggregator that only reads `needs.*.result`.
 *
 * Those jobs fail before their first line, with `chdir: packages/eql: No such
 * file or directory`. Two things make it worth a guard rather than a fix and a
 * shrug:
 *
 *  1. **It is invisible in review.** The job is correct, the default is
 *     correct, and the interaction is somewhere else in the file. Both jobs
 *     here were ported faithfully and both were broken by a line neither of
 *     them contains.
 *  2. **The expensive one is the aggregator.** `ci-required` is the required
 *     check. It fails for a reason that has nothing to do with the suite it
 *     reports on, which is a red gate carrying no information — and the natural
 *     reading of a red `ci-required` is that a test failed.
 *
 * The fix is a job-level `defaults.run.working-directory: .`, which is what
 * this asserts the absence of. Discovered over the workflow directory rather
 * than listed, so a new workflow adopting a working-directory default is
 * covered the day it lands.
 */

const CHECKOUT = 'actions/checkout'

/** The `working-directory` in force for a job's `run:` steps, if any. */
function effectiveWorkingDirectory(workflow, job) {
  return (
    job?.defaults?.run?.['working-directory'] ??
    workflow?.defaults?.run?.['working-directory'] ??
    null
  )
}

/**
 * Jobs whose `run:` steps would execute in a directory that does not exist.
 *
 * A step carrying its own `working-directory:` is excluded — it has overridden
 * the default and answers for itself. `.` is treated as no default at all,
 * since that is the opt-out spelling.
 */
function offendingJobs(relPath) {
  const workflow = readWorkflow(relPath)
  const found = []
  for (const [jobName, job] of Object.entries(workflow?.jobs ?? {})) {
    const workingDirectory = effectiveWorkingDirectory(workflow, job)
    if (!workingDirectory || workingDirectory === '.') continue
    const steps = Array.isArray(job?.steps) ? job.steps : []
    if (steps.some((step) => String(step?.uses ?? '').includes(CHECKOUT))) {
      continue
    }
    const stranded = steps.filter(
      (step) => typeof step?.run === 'string' && !step['working-directory'],
    )
    if (stranded.length === 0) continue
    found.push({ relPath, jobName, workingDirectory, count: stranded.length })
  }
  return found
}

const OFFENDERS = workflowFiles().flatMap(offendingJobs)

/**
 * The jobs that opt out today, as the guard on the scan.
 *
 * A check that iterates nothing passes and proves nothing — and the ways this
 * one empties out are all silent: `readWorkflow` changing shape, the
 * `defaults.run` key being spelled differently, or the last working-directory
 * default leaving the tree. Held as a minimum: adding a job that opts out must
 * not fail this.
 */
const EXPECTED_OPT_OUTS = [
  '.github/workflows/test-eql.yml / setup',
  '.github/workflows/test-eql.yml / ci-required',
]

/** Jobs that set a job-level `working-directory: .` over a workflow default. */
const OPT_OUTS = workflowFiles().flatMap((relPath) => {
  const workflow = readWorkflow(relPath)
  if (!workflow?.defaults?.run?.['working-directory']) return []
  return Object.entries(workflow.jobs ?? {})
    .filter(([, job]) => job?.defaults?.run?.['working-directory'] === '.')
    .map(([jobName]) => `${relPath} / ${jobName}`)
})

describe('a run: step never chdirs into a directory the job did not check out', () => {
  it('finds no job whose run: steps would fail before their first line', () => {
    expect(
      OFFENDERS.map(
        (o) =>
          `${o.relPath} / ${o.jobName}: ${o.count} run step(s) under \`working-directory: ${o.workingDirectory}\`, but the job never checks out`,
      ),
      'Give the job its own `defaults: { run: { working-directory: . } }`, or add a checkout if it genuinely needs the tree.',
    ).toEqual([])
  })

  it('still sees the jobs that opt out', () => {
    // The scan's floor. Without it, a `readWorkflow` that started returning
    // `{}` would make the check above pass on an empty set forever.
    const missing = EXPECTED_OPT_OUTS.filter((id) => !OPT_OUTS.includes(id))
    expect(
      missing,
      `The scan currently sees these opt-outs:\n${
        OPT_OUTS.length === 0
          ? '  (nothing — the scan matched no job)'
          : OPT_OUTS.map((id) => `  ${id}`).join('\n')
      }`,
    ).toEqual([])
  })

  it('does not count a step that sets its own working-directory', () => {
    // The exclusion that keeps this from being noise: a step carrying its own
    // `working-directory:` has overridden the default and answers for itself.
    const workflow = {
      defaults: { run: { 'working-directory': 'packages/eql' } },
      jobs: {
        a: { steps: [{ run: 'echo hi', 'working-directory': '.' }] },
        b: { steps: [{ run: 'echo hi' }] },
      },
    }
    const stranded = Object.entries(workflow.jobs).filter(([, job]) =>
      job.steps.some((step) => step.run && !step['working-directory']),
    )
    expect(stranded.map(([name]) => name)).toEqual(['b'])
  })
})
