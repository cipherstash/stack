import { describe, expect, it } from 'vitest'
import { runsWhen } from './lib/expressions.mjs'
import {
  NON_PULL_REQUEST_EVENTS,
  readSelectorJob,
  runSelectorDecision,
  runSummaryCheck,
  SELECTOR_JOB,
  selectorOutputsRead,
} from './lib/selector.mjs'
import { workflowFiles } from './lib/workflows.mjs'

/**
 * Every workflow with a selector job follows the same design (ADR 0003): the
 * selector job decides which checks a pull request runs, each gated job reads
 * the selector's answer in its `if:`, and a summary job ends the workflow.
 * `.github/CONTEXT.md` defines the terms.
 *
 * The workflows are discovered, not listed, so a workflow that gains a
 * selector job is held to this the day it lands. What each selector decides
 * for particular changes is pinned per workflow, in the `*-selector*.test.mjs`
 * files.
 *
 * Whether every job is decided by the selector, or has a written reason to run
 * on every change, is the failsafe's question, not this file's.
 */

const SELECTOR_WORKFLOWS = workflowFiles().filter(
  (relPath) => readSelectorJob(relPath) !== null,
)

/**
 * The guard on the scan. A minimum: a workflow that gains a selector job must
 * not fail this. Each workflow's own `*-selector*.test.mjs` file checks that
 * its selector job exists.
 */
const EXPECTED_SELECTOR_WORKFLOWS = ['.github/workflows/test-eql.yml']

const triggersOf = (workflow) => workflow?.on ?? workflow?.[true]

const needsOf = (job) => [job?.needs ?? []].flat()

/** The jobs whose `if:` reads a selector output. */
function gatedJobs(workflow) {
  return Object.entries(workflow?.jobs ?? {})
    .map(([id, job]) => ({ id, job, reads: selectorOutputsRead(job) }))
    .filter((entry) => entry.reads.length > 0)
}

describe('the workflows with a selector job', () => {
  it('include the converted workflows', () => {
    expect(SELECTOR_WORKFLOWS).toEqual(
      expect.arrayContaining(EXPECTED_SELECTOR_WORKFLOWS),
    )
  })
})

for (const relPath of SELECTOR_WORKFLOWS) {
  const selector = readSelectorJob(relPath)
  const { workflow } = selector
  const jobIds = Object.keys(workflow.jobs)
  const summaryId = jobIds.at(-1)
  const filterNames = Object.keys(selector.filters)
  const outputNames = Object.keys(selector.outputs)

  describe(relPath, () => {
    it('has no path filter on pull_request', () => {
      // A workflow that a path filter skips leaves its required checks
      // pending, and GitHub's documentation on required status checks says
      // that blocks a merge. The selector job decides instead.
      const pullRequest = triggersOf(workflow)?.pull_request ?? {}
      expect(Object.keys(pullRequest)).not.toContain('paths')
      expect(Object.keys(pullRequest)).not.toContain('paths-ignore')
    })

    it('starts with the selector job, on a GitHub-hosted runner', () => {
      // ADR 0003: every gated job waits for it, and a self-provisioned
      // machine takes longer to start.
      expect(jobIds[0]).toBe(SELECTOR_JOB)
      expect(String(selector.job['runs-on'])).toMatch(/^ubuntu-/)
      expect(selector.job.needs).toBeUndefined()
      expect(selector.job.if).toBeUndefined()
    })

    it('has one path filter step, run only on a pull request', () => {
      expect(selector.filterSteps).toHaveLength(1)
      expect(String(selector.filterStep?.if)).toBe(
        "github.event_name == 'pull_request'",
      )
      expect(filterNames).not.toEqual([])
    })

    it('writes no `!` rule that dorny would read as matching everything', () => {
      // Under dorny's default quantifier, `some`, a file counts when ANY rule
      // matches, so `!**/*.md` matches every file that is not Markdown. A `!`
      // rule only excludes under `every`, where a file must match every rule,
      // and there a second positive rule would select nothing at all.
      expect(['some', 'every']).toContain(selector.quantifier)
      for (const [name, rules] of Object.entries(selector.filters)) {
        const positive = rules.filter((rule) => !rule.startsWith('!'))
        const negative = rules.filter((rule) => rule.startsWith('!'))
        if (selector.quantifier === 'every') {
          expect(positive, `filter "${name}"`).toHaveLength(1)
        } else {
          expect(negative, `filter "${name}"`).toEqual([])
        }
      }
    })

    it('names each output after the filter that decides it', () => {
      // The guards follow a job's `if:` to its filter by this name.
      expect(outputNames.sort()).toEqual([...filterNames].sort())
      for (const [name, stepOutput] of Object.entries(selector.outputs)) {
        expect(stepOutput, `output "${name}"`).toBe(name)
      }
      expect(
        selector.decideStep,
        'No single step writes the selector outputs.',
      ).toBeTruthy()
    })

    it('selects every job on events other than pull_request', () => {
      for (const event of NON_PULL_REQUEST_EVENTS) {
        const { status, log, outputs } = runSelectorDecision(relPath, event, {})
        expect(status, log).toBe(0)
        for (const name of outputNames) {
          expect(outputs[name], `${name} on ${event}`).toBe('true')
        }
      }
    })

    it('passes the filter answers through on a pull request', () => {
      for (const answer of ['true', 'false']) {
        const answers = Object.fromEntries(
          filterNames.map((name) => [name, answer]),
        )
        const { status, log, outputs } = runSelectorDecision(
          relPath,
          'pull_request',
          answers,
        )
        expect(status, log).toBe(0)
        expect(outputs).toEqual(answers)
      }
    })

    it('fails when a pull request filter gives no answer', () => {
      // A missing answer would skip every gated job, and the summary job
      // counts skipped as passed: a green run that ran nothing.
      for (const name of filterNames) {
        for (const bad of ['', 'maybe']) {
          const answers = Object.fromEntries(
            filterNames.map((other) => [other, other === name ? bad : 'true']),
          )
          const { status } = runSelectorDecision(
            relPath,
            'pull_request',
            answers,
          )
          expect(status, `filter "${name}" answering '${bad}'`).not.toBe(0)
        }
      }
    })

    it('gates jobs only on outputs the selector writes, and needs it', () => {
      const gated = gatedJobs(workflow)
      expect(gated).not.toEqual([])
      for (const { id, job, reads } of gated) {
        expect(needsOf(job), `job "${id}"`).toContain(SELECTOR_JOB)
        for (const name of reads) {
          expect(outputNames, `job "${id}" reads "${name}"`).toContain(name)
        }
      }
    })

    it("writes each gated job's `if:` as an exclusion of pull_request", () => {
      // Outside a pull request the selector's answers must not matter: a job
      // written as a list of allowed events skips on the event nobody listed.
      for (const { id, job } of gatedJobs(workflow)) {
        for (const event of NON_PULL_REQUEST_EVENTS) {
          const verdict = (answer) =>
            runsWhen(job.if, {
              github: {
                event_name: event,
                repository: 'cipherstash/stack',
                event: {},
              },
              needs: {
                [SELECTOR_JOB]: {
                  result: 'success',
                  outputs: Object.fromEntries(
                    outputNames.map((name) => [name, answer]),
                  ),
                },
              },
              vars: {},
            })
          expect(verdict('false'), `job "${id}" on ${event}`).toBe(
            verdict('true'),
          )
        }
      }
    })

    it('ends with a summary job that needs every other job', () => {
      const summary = workflow.jobs[summaryId]
      expect(String(summary.if)).toBe('always()')
      expect([...needsOf(summary)].sort()).toEqual(
        jobIds.filter((id) => id !== summaryId).sort(),
      )
    })

    it('passes the summary only when every needed job passed or skipped', () => {
      const status = (results) => runSummaryCheck(relPath, summaryId, results)
      expect(status(['success', 'skipped', 'success'])).toBe(0)
      expect(status(['success', 'failure'])).not.toBe(0)
      expect(status(['skipped', 'cancelled'])).not.toBe(0)
    })
  })
}
