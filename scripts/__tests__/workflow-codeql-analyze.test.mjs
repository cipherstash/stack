import { describe, expect, it } from 'vitest'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * A job that starts CodeQL must also run the analysis.
 *
 * `codeql-action/init` only prepares the database. `codeql-action/analyze`
 * runs the queries and uploads the results. From 12 May to November 2026 the
 * analysis step in `codeql.yml` named `init` by mistake. The job still
 * passed, with only a warning about the unexpected `category` input, so
 * nothing showed that no code on `main` was analysed.
 */
const CODEQL_STEP = /^github\/codeql-action\/(init|analyze)@/

const codeqlJobs = workflowFiles().flatMap((file) =>
  Object.entries(readWorkflow(file)?.jobs ?? {})
    .map(([id, job]) => ({
      ref: `${file}#${id}`,
      actions: (job?.steps ?? [])
        .map((step) => step?.uses)
        .filter((uses) => typeof uses === 'string' && CODEQL_STEP.test(uses))
        .map((uses) => uses.match(CODEQL_STEP)[1]),
    }))
    .filter(({ actions }) => actions.length > 0),
)

describe('CodeQL jobs run the analysis', () => {
  it('finds the CodeQL job', () => {
    // An empty scan would pass the check below.
    expect(codeqlJobs.map(({ ref }) => ref)).toContain(
      '.github/workflows/codeql.yml#analyze',
    )
  })

  it('runs init once, then analyze, in every CodeQL job', () => {
    const wrong = codeqlJobs
      .filter(({ actions }) => actions.join(',') !== 'init,analyze')
      .map(({ ref, actions }) => `${ref}: ${actions.join(', ')}`)
    expect(wrong).toEqual([])
  })
})
