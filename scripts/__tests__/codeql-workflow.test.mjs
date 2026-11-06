import { describe, expect, it } from 'vitest'
import { readWorkflow } from './lib/workflows.mjs'

/**
 * CodeQL must run `init` and then `analyze`.
 *
 * `init` starts the CodeQL tracer and `analyze` builds the database, runs the
 * queries and uploads the SARIF. A job with `init` twice and no `analyze` went
 * green on every run while producing no code-scanning results at all: `init`
 * accepts no `category` input, so the second step silently ignored it. A
 * Dependabot bump carried the wrong action forward rather than catching it.
 */

const WORKFLOW = '.github/workflows/codeql.yml'
const steps = readWorkflow(WORKFLOW).jobs.analyze.steps
const codeql = steps
  .map((step) => String(step.uses ?? ''))
  .filter((uses) => uses.startsWith('github/codeql-action/'))
const actionOf = (uses) =>
  uses.split('@')[0].replace('github/codeql-action/', '')
const refOf = (uses) => uses.split('@')[1]

describe('CodeQL workflow', () => {
  it('initialises CodeQL and then analyses, in that order', () => {
    expect(codeql.map(actionOf)).toEqual(['init', 'analyze'])
  })

  it('pins init and analyze to the same codeql-action release', () => {
    expect(new Set(codeql.map(refOf)).size).toBe(1)
  })
})
