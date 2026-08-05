import { readdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import yaml from 'js-yaml'
import { describe, expect, it } from 'vitest'

/**
 * `./.github/actions/require-cs-secrets` must run BEFORE
 * `./.github/actions/build-ffi-binding` in any job that uses both.
 *
 * The secrets action is a pre-flight, and its whole value is being cheap: it
 * reads four inputs and fails in seconds when a CS_* secret was rotated,
 * cleared, or is absent because the PR came from a fork. Every workflow that
 * carries it says so in a comment ("Fast pre-flight: fail in seconds if a
 * secret was rotated or cleared, before the docker pull").
 *
 * `build-ffi-binding` is the opposite kind of step. On a cache miss it compiles
 * the Rust core from cold — minutes of runner time, and more again with
 * `wasm: 'true'`. Put it first and a job with no usable credentials pays the
 * full compile before it learns it was never going to be able to encrypt
 * anything. The pre-flight still fails, just several minutes later and after
 * the expensive half of the job has already been billed — which is the same as
 * not having a pre-flight at all.
 *
 * So the order is load-bearing, and it does not look load-bearing: both steps
 * are self-contained `uses:` blocks, and swapping them changes nothing about
 * whether the job passes. That is exactly the shape of edit that gets made
 * while "grouping the build steps together". Hence this test — the two steps
 * are checked by position, across every workflow, discovered rather than
 * listed, so a new workflow that adds the binding build is covered the day it
 * lands.
 *
 * NOTE the direction of the fix when this fails. Moving the binding build down
 * is only correct when nothing between the two steps needs the binding. In
 * `tests.yml`'s `wasm-e2e-tests` job a `Build stack` step sits between them and
 * consumes `dist/wasm/**`, so there the pre-flight moves UP instead. Same
 * resulting order; the other edit would have broken the job.
 */

const REPO_ROOT = resolve(fileURLToPath(import.meta.url), '../../..')
const WORKFLOW_DIR = '.github/workflows'

const BUILD_FFI = './.github/actions/build-ffi-binding'
const REQUIRE_SECRETS = './.github/actions/require-cs-secrets'

/**
 * The workflows that pair the two actions today. This is NOT the list the
 * checks iterate — those scan the directory — it is the guard on the scan
 * itself. A discovery test that matches zero files passes and proves nothing,
 * and this repo has been bitten by that shape before (see the exit-2 "the
 * linter could not run" contract in `scripts/lint-no-hardcoded-runners.mjs`,
 * and `lintWiring.test.ts`'s "a check nothing invokes reads exactly like a
 * check that passes").
 *
 * Held as a minimum, not an equality: adding a workflow that builds the
 * binding must not fail this. If one of these is renamed or genuinely stops
 * needing the binding, update the list deliberately.
 */
const EXPECTED_PAIRED_WORKFLOWS = [
  '.github/workflows/integration-drizzle.yml',
  '.github/workflows/integration-prisma-next.yml',
  '.github/workflows/integration-supabase.yml',
  '.github/workflows/prisma-example-readme-e2e.yml',
  '.github/workflows/prisma-next-e2e.yml',
  '.github/workflows/tests.yml',
]

function workflowFiles() {
  return readdirSync(join(REPO_ROOT, WORKFLOW_DIR))
    .filter((name) => /\.ya?ml$/.test(name))
    .map((name) => `${WORKFLOW_DIR}/${name}`)
    .sort()
}

function readWorkflow(relPath) {
  return yaml.load(readFileSync(join(REPO_ROOT, relPath), 'utf8'))
}

/** The `uses:` of a step, normalised — `uses` may carry trailing whitespace. */
function stepUses(step) {
  return typeof step?.uses === 'string' ? step.uses.trim() : null
}

/**
 * Every job that uses BOTH actions, with the step index of each. Indexed by
 * position in the job's own `steps` list, which is the order GitHub runs them.
 */
function pairedJobs(relPath) {
  const wf = readWorkflow(relPath)
  const found = []
  for (const [jobName, job] of Object.entries(wf?.jobs ?? {})) {
    const steps = Array.isArray(job?.steps) ? job.steps : []
    const buildAt = []
    const secretsAt = []
    steps.forEach((step, index) => {
      const uses = stepUses(step)
      if (uses === BUILD_FFI) buildAt.push(index)
      if (uses === REQUIRE_SECRETS) secretsAt.push(index)
    })
    if (buildAt.length === 0 || secretsAt.length === 0) continue
    found.push({ relPath, jobName, steps, buildAt, secretsAt })
  }
  return found
}

const PAIRED = workflowFiles().flatMap(pairedJobs)
const PAIRED_FILES = [...new Set(PAIRED.map((entry) => entry.relPath))].sort()

describe('protect-ffi binding builds after the secrets pre-flight', () => {
  it('finds the workflows that pair the two actions', () => {
    // The guard on the scan. Without it, a rename of either action path (or a
    // js-yaml parse that quietly returned undefined) would empty `PAIRED` and
    // every check below would pass by vacuum.
    const missing = EXPECTED_PAIRED_WORKFLOWS.filter(
      (file) => !PAIRED_FILES.includes(file),
    )
    expect(
      missing,
      `These workflows used both ${BUILD_FFI} and ${REQUIRE_SECRETS}, and the scan no longer sees them. Either an action path changed (update the constants in this file) or the pairing was removed deliberately (update EXPECTED_PAIRED_WORKFLOWS).`,
    ).toEqual([])
    expect(PAIRED.length).toBeGreaterThanOrEqual(
      EXPECTED_PAIRED_WORKFLOWS.length,
    )
  })

  for (const file of workflowFiles()) {
    const jobs = pairedJobs(file)
    if (jobs.length === 0) continue

    for (const { jobName, steps, buildAt, secretsAt } of jobs) {
      it(`${file} / ${jobName} requires secrets before building the binding`, () => {
        const firstSecrets = Math.min(...secretsAt)
        const firstBuild = Math.min(...buildAt)
        const order = steps
          .map(
            (step, index) =>
              `  ${index}: ${step?.name ?? stepUses(step) ?? '(unnamed)'}`,
          )
          .join('\n')

        expect(
          firstSecrets,
          `"Require CipherStash secrets" must run before "Build the protect-ffi binding" in ${file} job "${jobName}".\nThe secrets check costs seconds; a cold Rust build costs minutes. Running the build first means a job with a rotated or missing credential pays the whole compile before failing — which is the same as having no pre-flight.\nSteps as ordered:\n${order}`,
        ).toBeLessThan(firstBuild)
      })
    }
  }
})
