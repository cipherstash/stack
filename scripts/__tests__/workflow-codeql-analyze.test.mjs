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
  const found = flat.flatMap(({ step, label, conditions }) => {
    const match =
      typeof step?.uses === 'string' ? step.uses.match(CODEQL_STEP) : null
    return match ? [{ action: match[1], step, label, conditions }] : []
  })
  return {
    actions: found.map(({ action }) => action),
    analyses: found.filter(({ action }) => action === 'analyze'),
    unresolved,
  }
}

// `if: false`, `if: 'false'` and `if: ${{ false }}` all skip the step.
const ALWAYS_FALSE = /^\s*(?:\$\{\{\s*false\s*\}\}|false)\s*$/
const alwaysFalse = (condition) =>
  condition === false ||
  (typeof condition === 'string' && ALWAYS_FALSE.test(condition))

// `enclosing` is the `if:` of each composite call around the step, from
// `flattenSteps`. The analyze action uploads to code scanning only when
// `upload` is `always`, which is its default.
function analysisProblem(step, enclosing = []) {
  if (alwaysFalse(step?.if)) {
    return '`if:` is always false, so the analysis never runs'
  }
  if (enclosing.some(alwaysFalse)) {
    return 'the composite action around it is called with an `if:` that is always false, so the analysis never runs'
  }
  const upload = step?.with?.upload
  if (upload !== undefined && upload !== 'always') {
    return `\`upload: ${upload}\` keeps the results out of code scanning. Remove \`upload\`, or set it to \`always\`.`
  }
  return null
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

  it('runs every CodeQL analysis and uploads its results', () => {
    const wrong = codeqlJobs.flatMap(({ ref, analyses }) =>
      analyses.flatMap(({ step, label, conditions }) => {
        const problem = analysisProblem(step, conditions)
        return problem ? [`${ref}: ${label}: ${problem}`] : []
      }),
    )
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

  it('counts each call to the same composite action', () => {
    expect(
      codeqlSteps([callComposite, callComposite, analyze], composite([init]))
        .actions,
    ).toEqual(['init', 'init', 'analyze'])
  })

  it('reports a local action it cannot open', () => {
    expect(codeqlSteps([callComposite], noComposites).unresolved).toHaveLength(
      1,
    )
  })

  it('finds an analysis inside a composite action, to check its settings', () => {
    const skipped = { ...analyze, if: false }
    const { analyses } = codeqlSteps(
      [init, callComposite],
      composite([skipped]),
    )
    expect(analyses.map(({ step }) => step)).toEqual([skipped])
  })

  // biome-ignore lint/suspicious/noTemplateCurlyInString: a literal Actions expression, as written in a workflow.
  it.each([false, 'false', '${{ false }}'])(
    'refuses an analysis with `if: %j`',
    (condition) => {
      expect(analysisProblem({ ...analyze, if: condition })).toMatch(/`if:`/)
    },
  )

  it('refuses an analysis inside a composite action called with `if: false`', () => {
    const [analysis] = codeqlSteps(
      [init, { ...callComposite, if: false }],
      composite([analyze]),
    ).analyses
    expect(analysisProblem(analysis.step, analysis.conditions)).toMatch(/`if:`/)
  })

  it('accepts an analysis inside a composite action called with no `if:`', () => {
    const [analysis] = codeqlSteps(
      [init, callComposite],
      composite([analyze]),
    ).analyses
    expect(analysisProblem(analysis.step, analysis.conditions)).toBeNull()
  })

  it('accepts an analysis whose `if:` can be true', () => {
    expect(
      analysisProblem({ ...analyze, if: "github.event_name == 'push'" }),
    ).toBeNull()
  })

  it.each(['never', 'failure-only', false])(
    'refuses an analysis with `upload: %j`',
    (upload) => {
      expect(analysisProblem({ ...analyze, with: { upload } })).toMatch(
        /`upload: /,
      )
    },
  )

  it('accepts an analysis that leaves `upload` unset, or sets it to always', () => {
    expect(analysisProblem(analyze)).toBeNull()
    expect(
      analysisProblem({ ...analyze, with: { upload: 'always' } }),
    ).toBeNull()
  })
})
