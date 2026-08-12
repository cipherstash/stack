import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, WORKFLOW_DIR, workflowFiles } from './lib/workflows.mjs'

/**
 * `lint-release.yml` states its scope TWICE — once as the `pull_request` paths
 * filter that decides when the job runs, once as the argument list actionlint
 * is actually pointed at. Nothing bound the two.
 *
 * Both directions are silent. Add a release workflow, name it only in `paths:`,
 * and the gate runs without ever linting it; name it only in the argument list
 * and it is linted except on the pull requests that change it — which is every
 * pull request that could break it. Neither shows up as a failure; both show up
 * as green.
 *
 * `lint-no-workflow-caching.test.mjs` carries the same guard for the same
 * reason, and says so: its `TARGET_WORKFLOWS` "used to be an unchecked second
 * copy".
 */

const LINT_RELEASE = `${WORKFLOW_DIR}/lint-release.yml`

const workflow = readWorkflow(LINT_RELEASE)
// `on:` parses as the boolean `true` under YAML 1.1 — the Norway problem.
const triggers = workflow.on ?? workflow[true]

const filtered = triggers.pull_request.paths.filter((path) =>
  path.startsWith(`${WORKFLOW_DIR}/`),
)

const source = readFileSync(join(REPO_ROOT, LINT_RELEASE), 'utf8')
const linted = [
  ...source.matchAll(/^\s+(\.github\/workflows\/[\w.-]+\.ya?ml)\s*\\?$/gm),
].map((match) => match[1])

describe('lint-release.yml lints exactly what it triggers on', () => {
  it('points actionlint at every workflow in its own paths filter', () => {
    // The direction that loses coverage without looking like it: a workflow
    // added to `paths:` alone runs the gate and is never linted by it.
    expect([...linted].sort()).toEqual([...filtered].sort())
  })

  it('found both lists, rather than passing on two empty ones', () => {
    // A discovery test that discovers nothing passes, having checked nothing —
    // the failure mode `lib/workflows.mjs` was extracted to stop. The floor is
    // the four release workflows this gate was introduced for.
    expect(filtered.length).toBeGreaterThanOrEqual(4)
    expect(linted.length).toBeGreaterThanOrEqual(4)
  })

  it('names only workflows that exist', () => {
    // A renamed or deleted workflow leaves actionlint pointed at a path that no
    // longer resolves, which fails the gate mid-review rather than here.
    const present = workflowFiles()
    for (const relPath of new Set([...linted, ...filtered])) {
      expect(present, `${relPath} is named by lint-release.yml`).toContain(
        relPath,
      )
    }
  })

  it('lints itself', () => {
    // The gate has to be inside its own scope: a shell or syntax error
    // introduced HERE is otherwise checked by nothing.
    expect(linted).toContain(LINT_RELEASE)
  })
})
