import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import stackVitestConfig from '../../packages/stack/vitest.config.ts'
import wasmCoreVitestConfig, {
  WASM_CORE_SUITE,
} from '../../packages/stack/vitest.wasm-core.config.ts'
import { readJsonc } from './lib/read-jsonc.mjs'
import { REPO_ROOT } from './lib/repo-root.mjs'
import { readWorkflow, workflowFiles } from './lib/workflows.mjs'

/**
 * `packages/stack/__tests__/wasm-inline-core-credential-contract.test.ts` loads
 * the REAL protect-ffi WASM core. It is NOT the only suite that does —
 * `packages/stack/integration/wasm/**`, protect-ffi's own `wasm-round-trip` /
 * `wasm-error-codes`, and the Deno smoke tests in `e2e/wasm/` all do, and three
 * CI jobs build `dist/wasm/**` for them. It is the only one that needs the core
 * and NOTHING ELSE — no credentials, no database — which is what put it in its
 * own config rather than into the integration suites, whose `globalSetup`
 * requires both unconditionally. This docblock claimed the stronger thing until
 * review caught it; the arrangement below never depended on it.
 *
 * What the arrangement does depend on is FOUR pieces, and losing any one leaves
 * the contract unchecked:
 *
 *   1. the exclusion in `packages/stack/vitest.config.ts`
 *   2. the `test:wasm-core` script in `packages/stack/package.json`
 *   3. the step in the CI job that builds `dist/wasm/**`
 *   4. the `test:wasm-core` task in `turbo.json`
 *
 * Piece 3 is the quiet one: delete the step and the suite runs nowhere while
 * the exclusion keeps `pnpm test` green, so nothing says the contract stopped
 * being checked. Same shape as
 * `packages/protect-ffi/src/integrationSuiteCi.test.ts` (a suite whose workflow
 * was deposited where GitHub never reads it) and `lintWiring.test.ts`'s "a
 * check nothing invokes reads exactly like a check that passes".
 *
 * Piece 4 is quiet in a narrower way, and the assertions below say exactly
 * which way. DELETING the task is loud — turbo 2.x refuses to run a task the
 * project does not declare, so the step exits 1 — but EDITING it is not.
 * Dry-run measured: strip `dependsOn` and flip `cache` to true and the build
 * graph collapses from nine tasks to one (`@cipherstash/eql#build` and
 * `@cipherstash/protect-ffi#build` stop running) while the suite becomes
 * cacheable against a hash that cannot see the core it tests. Every other turbo
 * guard in this directory stayed green through that mutation, which is why the
 * check lives here.
 *
 * The opposite direction is already loud, which is why it is not asserted here:
 * put the file back in the default config and `run-tests` fails to COLLECT it
 * with `Cannot find module '.../dist/wasm/protect_ffi_inline.js'` — that is the
 * failure (#953) that produced this arrangement.
 *
 * The job is discovered by the `wasm: 'true'` input rather than named, so a
 * future job that also builds the WASM output can host the step without
 * editing this file — and naming the wrong job cannot pass, since a job that
 * does not build wasm cannot run the suite at all.
 */

const BUILD_FFI = './.github/actions/build-ffi-binding'
const SCRIPT = 'test:wasm-core'
const PACKAGE = '@cipherstash/stack'

const stackPackageJson = JSON.parse(
  readFileSync(join(REPO_ROOT, 'packages/stack/package.json'), 'utf8'),
)

/** `turbo.json` carries comments, so it needs the jsonc reader. */
const turboJson = readJsonc(join(REPO_ROOT, 'turbo.json'))

/** Every `run:` line in the workflow graph, tagged with its job. */
function runStepsByJob() {
  const rows = []
  for (const file of workflowFiles()) {
    const workflow = readWorkflow(file)
    for (const [jobId, job] of Object.entries(workflow?.jobs ?? {})) {
      for (const step of job?.steps ?? []) {
        rows.push({ file, jobId, job, step })
      }
    }
  }
  return rows
}

/** Does this job build protect-ffi's `dist/wasm/**`? */
function buildsWasm(job) {
  return (job?.steps ?? []).some(
    (step) => step?.uses === BUILD_FFI && String(step?.with?.wasm) === 'true',
  )
}

describe('the WASM core credential contract runs somewhere (#804)', () => {
  it('the suite the whole arrangement is about still exists', () => {
    expect(existsSync(join(REPO_ROOT, 'packages/stack', WASM_CORE_SUITE))).toBe(
      true,
    )
  })

  it('is the only file its own config collects', () => {
    expect(wasmCoreVitestConfig.test.include).toEqual([WASM_CORE_SUITE])
    // An empty run must be red: with a single-file `include`, a rename is
    // otherwise indistinguishable from a pass.
    expect(wasmCoreVitestConfig.test.passWithNoTests).toBe(false)
  })

  it('is excluded from the default suite, which has no WASM build', () => {
    expect(stackVitestConfig.test.exclude).toContain(WASM_CORE_SUITE)
  })

  it(`is invoked by \`${SCRIPT}\`, pointed at that config`, () => {
    const command = stackPackageJson.scripts?.[SCRIPT]
    expect(command, `packages/stack has no \`${SCRIPT}\` script`).toBeDefined()
    expect(command).toContain('vitest.wasm-core.config.ts')
  })

  it('is a turbo task that builds its deps and never caches', () => {
    const task = turboJson.tasks?.[SCRIPT]
    expect(
      task,
      `turbo.json declares no \`${SCRIPT}\` task. The workflow step runs it through turbo, and turbo 2.x refuses a task the project does not declare — so this one fails loudly rather than silently. Re-add it.`,
    ).toBeDefined()

    // The two fields, and the two different damages. Without `^build` the
    // graph collapses to this task alone and the workspace packages it
    // resolves are never built; with caching on, the suite's real input —
    // protect-ffi's gitignored `dist/wasm/**`, in another package — is
    // invisible to the hash, so a rebuilt core over unchanged stack sources
    // is a cache hit reporting a pass over the previous core.
    // `?? []` so an ABSENT `dependsOn` — the likelier edit of the two — fails
    // on the message below rather than on `toContain(undefined)`, which
    // reports an argument-type complaint and buries the reason.
    expect(
      task.dependsOn ?? [],
      `${SCRIPT} must depend on \`^build\`: without it turbo runs the task alone and stack's workspace dependencies go unbuilt.`,
    ).toContain('^build')
    expect(
      task.cache,
      `${SCRIPT} must set \`cache: false\`. Its real input is protect-ffi's dist/wasm, which turbo cannot hash — a cached run would report a pass over a core it never loaded.`,
    ).toBe(false)
  })

  it('is run by a CI job that builds the WASM output', () => {
    const invocations = runStepsByJob().filter(
      ({ step }) =>
        typeof step?.run === 'string' &&
        step.run.includes(SCRIPT) &&
        step.run.includes(PACKAGE),
    )

    expect(
      invocations.map(({ file, jobId }) => `${file} / ${jobId}`),
      `No workflow job runs \`turbo run ${SCRIPT} --filter ${PACKAGE}\`.\n` +
        `${WASM_CORE_SUITE} is excluded from stack's default vitest config, so with no job invoking it the contract is checked NOWHERE — and \`pnpm test\` stays green.\n` +
        `Add the step back to a job that passes \`wasm: 'true'\` to ${BUILD_FFI} (today: tests.yml / wasm-e2e-tests), or delete the suite and its config through #804 rather than letting it go quiet.`,
    ).not.toHaveLength(0)

    for (const { file, jobId, job } of invocations) {
      expect(
        buildsWasm(job),
        `${file} / ${jobId} runs ${SCRIPT} but does not build protect-ffi's dist/wasm.\n` +
          `The suite resolves \`@cipherstash/protect-ffi/wasm-inline\` for real; without \`wasm: 'true'\` on ${BUILD_FFI} it fails to collect.`,
      ).toBe(true)
    }
  })
})
