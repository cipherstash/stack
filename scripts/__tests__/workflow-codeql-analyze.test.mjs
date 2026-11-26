import { describe, expect, it } from 'vitest'
import {
  flattenSteps,
  readWorkflow,
  resolveRepoComposite,
  workflowFiles,
} from './lib/workflows.mjs'

/**
 * A job that starts CodeQL must also run the analysis.
 *
 * `codeql-action/init` only prepares the database. `codeql-action/analyze`
 * runs the queries and uploads the results. Commit `ed08dce88`, on 12 May
 * 2026, changed the analysis step in `codeql.yml` to name `init` by mistake.
 * Until November 2026 the job still passed, with only a warning about the
 * unexpected `category` input, so nothing showed that no code on `main` was
 * analysed.
 */
const CODEQL_STEP = /^github\/codeql-action\/(init|analyze)@/

// A local action that cannot be opened is reported, because a CodeQL step
// could be inside it.
function codeqlSteps(steps, resolveComposite) {
  const { flat, unresolved } = flattenSteps(steps, resolveComposite)
  const actions = flat.flatMap(({ step }) => {
    const match =
      typeof step?.uses === 'string' ? step.uses.match(CODEQL_STEP) : null
    return match ? [match[1]] : []
  })
  return { actions, unresolved }
}

const scanned = workflowFiles().flatMap((file) =>
  Object.entries(readWorkflow(file)?.jobs ?? {}).map(([id, job]) => ({
    ref: `${file}#${id}`,
    ...codeqlSteps(job?.steps, resolveRepoComposite),
  })),
)
const codeqlJobs = scanned.filter(({ actions }) => actions.length > 0)

describe('CodeQL jobs run the analysis', () => {
  it('finds the CodeQL job', () => {
    // An empty scan would pass the check below.
    expect(codeqlJobs.map(({ ref }) => ref)).toContain(
      '.github/workflows/codeql.yml#analyze',
    )
  })

  it('opens every local action that a job uses', () => {
    const unresolved = scanned.flatMap(({ ref, unresolved }) =>
      unresolved.map((entry) => `${ref}: ${entry}`),
    )
    expect(unresolved).toEqual([])
  })

  it('runs init once, then analyze, in every CodeQL job', () => {
    const wrong = codeqlJobs
      .filter(({ actions }) => actions.join(', ') !== 'init, analyze')
      .map(({ ref, actions }) => `${ref}: ${actions.join(', ')}`)
    expect(wrong).toEqual([])
  })
})

describe('the checker this guard depends on', () => {
  const init = { uses: 'github/codeql-action/init@v4.38.0' }
  const analyze = { uses: 'github/codeql-action/analyze@v4.38.0' }
  const callComposite = { uses: './.github/actions/codeql' }
  const noComposites = () => null
  const composite = (steps) => (uses) =>
    uses === callComposite.uses ? { id: 'codeql/action.yml', steps } : null

  it('reproduces the defect: init named twice', () => {
    expect(codeqlSteps([init, init], noComposites).actions).toEqual([
      'init',
      'init',
    ])
  })

  it('finds init inside a composite action', () => {
    expect(
      codeqlSteps([callComposite, analyze], composite([init])).actions,
    ).toEqual(['init', 'analyze'])
  })

  it('finds a composite action that runs init with no analysis', () => {
    expect(codeqlSteps([callComposite], composite([init])).actions).toEqual([
      'init',
    ])
  })

  it('reports a local action it cannot open', () => {
    expect(codeqlSteps([callComposite], noComposites).unresolved).toHaveLength(
      1,
    )
  })
})
