import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import stackVitestConfig from '../../packages/stack/vitest.config.ts'
import wasmCoreVitestConfig, {
  WASM_CORE_SUITE,
} from '../../packages/stack/vitest.wasm-core.config.ts'
import supabaseVitestConfig from '../../packages/stack-supabase/vitest.config.ts'
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
 *
 * Two further checks live here, both about what the arrangement COSTS rather
 * than about where the suite runs:
 *
 *   5. the WASM-core config raises Vitest's 5000ms default timeout. That
 *      default was already intermittently too short for this package — the
 *      sibling `vitest.config.ts` says so and raises it — and every case in
 *      the WASM-core suite instantiates the real inlined core.
 *   6. the `browser` export-condition guard sits in a file the DEFAULT stack
 *      suite collects. It reads a manifest and needs no WASM build, so it has
 *      no business paying this arrangement's price: hosted in the WASM-core
 *      file it ran in exactly one CI job and in nobody's local `pnpm test`.
 */

const BUILD_FFI = './.github/actions/build-ffi-binding'
const SCRIPT = 'test:wasm-core'
const PACKAGE = '@cipherstash/stack'

/** Vitest's own default, which both stack configs deliberately exceed. */
const VITEST_DEFAULT_TIMEOUT_MS = 5000

/**
 * Where the `browser` export-condition guards live, one per package that
 * ships a `wasm-inline` entry (#804). Relative to each package root, because
 * that is what a vitest `exclude` pattern is relative to.
 */
const BROWSER_GUARD_SUITE = '__tests__/browser-export-condition.test.ts'

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

/**
 * Which of a vitest config's `exclude` patterns select `relPath`.
 *
 * Deliberately not a glob engine. The patterns in play are literal paths, a
 * literal directory prefix (`integration/**`) and vitest's own
 * anywhere-under-a-directory defaults (node_modules, dist, cypress), and
 * those three shapes are what this handles. A real matcher would be a
 * dependency for no extra coverage, and a pattern shape it does not
 * understand is reported as "not excluded" — the safe direction here only
 * because the exclusion this guards against is written by hand, in one of
 * those shapes, by someone moving the file back.
 */
function excludedBy(patterns, relPath) {
  const segments = relPath.split('/')
  return (patterns ?? []).filter((pattern) => {
    if (pattern === relPath) return true
    const literal = pattern.split('*')[0].replace(/\/$/, '')
    if (literal && relPath.startsWith(`${literal}/`)) return true
    const anywhere = /^\*\*\/([^*/]+)\/\*\*$/.exec(pattern)
    return anywhere ? segments.includes(anywhere[1]) : false
  })
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

  it("gives each case more than vitest's 5s default to run in", () => {
    // A separate config inherits none of the sibling's settings, and the one
    // most easily lost is the one nothing references: `vitest.config.ts`
    // raises this exact default for this exact package, because 5000ms was
    // intermittently short there. Every case in the WASM-core suite
    // instantiates the real inlined core — the last one gets through key
    // loading into `getToken` — so the same risk applies, and it would
    // present as a flake in the one job that runs it rather than as a
    // failure anyone can reproduce.
    expect(
      wasmCoreVitestConfig.test.testTimeout,
      `vitest.wasm-core.config.ts must set an explicit \`testTimeout\` above vitest's ${VITEST_DEFAULT_TIMEOUT_MS}ms default.\n` +
        `Every case there instantiates the REAL inlined WASM core, and the sibling vitest.config.ts already raises this default for this package because ${VITEST_DEFAULT_TIMEOUT_MS}ms was intermittently flaky.`,
    ).toBeGreaterThan(VITEST_DEFAULT_TIMEOUT_MS)
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

describe('the `browser` export-condition guard runs everywhere (#804)', () => {
  // The guard asserts that neither package declares a `browser` export
  // condition, because `wasm-inline` needs a `clientKey` — a workspace secret
  // — on every auth path. It is a manifest read: no WASM build, no
  // credentials, no database.
  //
  // It lived in the WASM-core contract file, which the default stack config
  // excludes, so it ran ONLY in `tests.yml`'s `wasm-e2e-tests` job — the one
  // job that builds WASM output this assertion does not need. It ran in no
  // local `pnpm test`, and on a fork PR in nothing at all (`wasm-e2e-tests`
  // and `run-tests` both hard-fail at `require-cs-secrets` there, and `lint`
  // runs only Biome). Moving it into each package's default suite is what
  // these two cases hold in place.
  const guards = [
    { pkg: 'packages/stack', config: stackVitestConfig },
    { pkg: 'packages/stack-supabase', config: supabaseVitestConfig },
  ]

  for (const { pkg, config } of guards) {
    it(`${pkg} keeps its guard in the default suite`, () => {
      const relative = BROWSER_GUARD_SUITE
      expect(
        existsSync(join(REPO_ROOT, pkg, relative)),
        `${pkg}/${relative} is missing.\n` +
          `That file is the only thing stopping a \`browser\` export condition being added to quiet a bundler, which would ship a workspace secret to the browser. If it moved, move this expectation with it — and keep it somewhere \`pnpm --filter ${pkg.replace('packages/', '@cipherstash/')} test\` collects.`,
      ).toBe(true)

      expect(
        excludedBy(config.test.exclude, relative),
        `${pkg}/${relative} is excluded from that package's default vitest config.\n` +
          `Excluded, it runs only where something invokes a second config — which is exactly the arrangement that kept it out of every local test run and every fork PR before #804.`,
      ).toEqual([])
    })
  }
})
