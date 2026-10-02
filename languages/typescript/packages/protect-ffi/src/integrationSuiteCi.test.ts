/**
 * Guards that the `integration-tests/` suite is RUN, not merely present.
 *
 * Upstream (`cipherstash/protectjs-ffi`) ran these 19 files on every pull
 * request — `mise setup` then `mise run test:integration:all`, in
 * `.github/workflows/test.yml`. The absorption copied the suite into this
 * package intact and left that workflow behind under
 * `packages/protect-ffi/.github/`, where GitHub never looks: it reads workflows
 * from the repository root alone. So the day protect-ffi landed in the
 * monorepo, every live encrypt / decrypt / lock-context / keyset /
 * JSON-SteVec / Postgres / WASM-round-trip assertion in it stopped executing —
 * and a suite that never starts reads exactly like a suite that passes.
 *
 * The property under test is therefore the same one `lintWiring.test.ts`
 * defends for the cargo checks, one level up: a suite nothing invokes is the
 * failure, and it is invisible by construction. This file reads the ROOT
 * workflow directory, so the deposited upstream copy cannot satisfy it.
 */
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

// Vitest resolves cwd to the directory holding vitest.config.ts, i.e. this
// package. `import.meta` is unavailable: tsconfig emits CommonJS and tsc
// rejects it (TS1470). Same reasoning as lintWiring.test.ts.
const packageRoot = process.cwd()
const workflowDir = join(packageRoot, '../../.github/workflows')

/**
 * `//` line comments removed, so `JSON.parse` accepts `turbo.json`.
 *
 * String-aware, and that is not defensive coding: `turbo.json`'s second line is
 * `"$schema": "https://turbo.build/schema.json"`, so a regex for `//` truncates
 * the file at its first key and every task lookup below goes quietly empty.
 * Same reasoning, and the same character scan, as `readJsonc` in
 * `scripts/lint-typecheck-scope.mjs` — reproduced rather than imported because
 * that is an untyped `.mjs` outside this package's tsconfig.
 */
function stripJsonComments(raw: string): string {
  let out = ''
  let inString = false
  let escaped = false

  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]
    if (inString) {
      out += ch
      if (escaped) escaped = false
      else if (ch === '\\') escaped = true
      else if (ch === '"') inString = false
      continue
    }
    if (ch === '"') {
      inString = true
      out += ch
      continue
    }
    if (ch === '/' && raw[i + 1] === '/') {
      while (i < raw.length && raw[i] !== '\n') i++
      out += '\n'
      continue
    }
    out += ch
  }
  return out
}

/**
 * The part of a workflow that actually does something: `jobs:` and everything
 * under it, with comment lines stripped.
 *
 * Every assertion in this file is a substring search, and this file's subject
 * is that a claim can be satisfied by prose rather than by a step. It was:
 * deleting the `Build the protect-ffi binding` STEP from
 * integration-protect-ffi.yml left `build-ffi-binding` in six comments and two
 * `paths:` entries, and the check stayed green. Deleting the
 * `Require CipherStash secrets` step left it in a comment and a `paths:` entry.
 * Dropping `mise run setup` left `mise setup` in the header comment quoting
 * what upstream ran. Three guards, all green, none of them guarding anything.
 *
 * Cutting at `jobs:` is what removes the `on:` / `paths:` block, and that is
 * also what makes the discovery filter below mean what its comment says: a
 * `paths:` filter naming the suite is a trigger, not a run.
 *
 * `nativeLoading.test.ts` strips comments from the emitted entry for the same
 * reason — a comment describing a thing is indistinguishable from the thing.
 */
function executablePart(body: string): string {
  const jobsAt = body.search(/^jobs:/m)
  // No `jobs:` key means nothing runs, so nothing can match. Returning the
  // whole body here would hand every assertion the header comments instead.
  return jobsAt === -1 ? '' : body.slice(jobsAt).replace(/^[ \t]*#.*$/gm, '')
}

/** Every workflow GitHub actually executes, read from the repository root. */
const rootWorkflows = readdirSync(workflowDir)
  .filter((name) => /\.ya?ml$/.test(name))
  .map((name) => ({
    name,
    body: executablePart(readFileSync(join(workflowDir, name), 'utf8')),
  }))

/**
 * The suite's path as a workflow has to spell it — `working-directory`, a
 * `paths:` filter, or a `--prefix`. Matched as a substring rather than as a
 * parsed YAML field so reindenting, renaming the step, or moving the
 * invocation between `run:` and a composite action does not break the check.
 */
const SUITE_DIR = 'packages/protect-ffi/integration-tests'

/**
 * Something that actually STARTS the tests. Either shape counts:
 *
 *  - `npx vitest` / `pnpm vitest` — the runner invoked directly, which is what
 *    CI does so it can sit on the cached release binding from
 *    `.github/actions/build-ffi-binding` instead of recompiling in debug.
 *  - `mise run test:integration:all` — the task upstream CI used, and still
 *    the local entry point (`integration-tests/tasks.toml`).
 *
 * Referencing the directory alone is deliberately not enough: a `paths:` filter
 * naming it is the exact false positive this test exists to reject — which is
 * why both halves are matched against `executablePart`, where no `paths:` block
 * survives. Matched against the raw body, a workflow that merely path-filtered
 * on the suite and happened to run vitest for something else satisfied this.
 */
const INVOKES_SUITE = /\bvitest\b|mise run test:integration/

const suiteRunners = rootWorkflows.filter(
  ({ body }) => body.includes(SUITE_DIR) && INVOKES_SUITE.test(body),
)

describe('integration-tests suite runs in CI', () => {
  it('reads the root workflow directory', () => {
    // The guard on the scan. A discovery test that matches zero files passes
    // and proves nothing, so pin two workflows that live at the root and
    // nowhere else: if this resolved to `packages/protect-ffi/.github/` (the
    // dead upstream deposit) or to a directory that no longer exists, every
    // assertion below would go vacuous instead of red.
    const names = rootWorkflows.map((workflow) => workflow.name)
    expect(names).toContain('tests.yml')
    expect(names).toContain('tests-rust.yml')
  })

  it('still has the suite this file is about', () => {
    // If the suite is ever deleted, the failure should say so here rather than
    // arriving as an unexplained "no workflow runs it" below.
    const testFiles = readdirSync(
      join(packageRoot, 'integration-tests/tests'),
    ).filter((name) => name.endsWith('.test.ts'))

    expect(testFiles).toContain('lock-context.test.ts')
    expect(testFiles).toContain('wasm-round-trip.test.ts')
    expect(testFiles.length).toBeGreaterThanOrEqual(15)
  })

  it('names no script after a turbo task, so `pnpm test` stays credential-free', () => {
    // The cost of workspace membership, and it is not hypothetical. Root
    // `pnpm test` is `turbo test --filter './packages/**'`, which now REACHES
    // this package — turbo already lists `#test` in the graph and skips it only
    // because no script answers to that name. Give one that name and the repo's
    // ordinary unit-test command starts demanding Docker, a Postgres on 5436
    // with both EQL versions installed, and live CipherStash credentials. The
    // suites throw rather than skip when unconfigured, so the failure is loud,
    // universal, and nowhere near the change that caused it.
    //
    // Derived from `turbo.json` rather than a list of names to avoid, because
    // the list was wrong the first time it was written: this guard originally
    // forbade `test` alone, while the suite's own live script was called
    // `test:integration` — which is ALSO a turbo task, invoked by four
    // integration workflows. Every one of them passes `--filter`, so nothing
    // reached the suite in practice; an unfiltered `turbo run test:integration`
    // (the shape of the root `"test:e2e": "turbo run test:e2e"` script) would
    // have. Reading the task keys means a task added to `turbo.json` tomorrow is
    // covered without anyone remembering this file.
    //
    // `typecheck` is the deliberate exception, and the reason the rule is
    // "no LIVE script named after a task" rather than "no script named after a
    // task": the suite's `tsc` gate is *meant* to run under
    // `turbo run typecheck`, from tests.yml, on every PR. It needs no
    // credentials and no database. The live entry points are `vitest:live` /
    // `vitest:live:coverage`, which turbo knows nothing about.
    const turboTasks = new Set(
      Object.keys(
        (
          JSON.parse(
            stripJsonComments(
              readFileSync(join(packageRoot, '../../turbo.json'), 'utf8'),
            ),
          ) as { tasks?: Record<string, unknown> }
        ).tasks ?? {},
      ),
    )
    const suiteManifest = JSON.parse(
      readFileSync(join(packageRoot, 'integration-tests/package.json'), 'utf8'),
    ) as { scripts?: Record<string, string> }

    // The floor on the derivation. An empty or mis-parsed `turbo.json` makes
    // every assertion below vacuous, and it is read through a hand-rolled
    // comment stripper, so it is exactly the kind of thing that fails silently.
    expect(turboTasks).toContain('test')
    expect(turboTasks).toContain('test:integration')

    const live = Object.keys(suiteManifest.scripts ?? {}).filter(
      (name) => name !== 'typecheck',
    )
    expect(live.length).toBeGreaterThan(0)
    expect(live.filter((name) => turboTasks.has(name))).toEqual([])
  })

  it('installs the suite from the workspace, not a second npm tree', () => {
    // `integration-tests` became a pnpm workspace member in CIP-3744: its
    // dependencies come from the repo lockfile, `@cipherstash/eql` resolves
    // `workspace:^` and `@cipherstash/protect-ffi` `workspace:*`. The failure
    // mode worth guarding is a half-revert that reinstates the npm install
    // alongside the workspace one and re-resolves `@cipherstash/eql` from the
    // registry — the emit/store skew the absorption existed to make
    // unrepresentable, and one that would run GREEN in the credentialed job.
    //
    // Asserted against `tasks.toml`, which is where the `npm ci` actually was —
    // step 1 of `[setup]`. An earlier draft of this test scanned the workflow
    // body instead, which never contained the string: the workflow says
    // `run: mise run setup` and delegates, so the guard would have stayed green
    // through exactly the revert it names. That is the same defect
    // `executablePart` exists to prevent one file over — a check pointed at
    // prose rather than at the thing.
    //
    // And COMMENTS ARE STRIPPED, for the other half of that same lesson: this
    // assertion failed on its first run against the file's own comments
    // explaining why `npm ci` is gone. A substring search cannot tell a
    // reinstated command from a sentence about one. Whole-line `#` only, which
    // is how every comment in this file is written; a shell comment inside a
    // `"""` block would be stripped too, and none of these tasks has one.
    const tasks = readFileSync(
      join(packageRoot, 'integration-tests/tasks.toml'),
      'utf8',
    ).replace(/^[ \t]*#.*$/gm, '')

    // Floor on the read: a renamed or moved file, or a strip that ate the whole
    // file, would make the assertions below vacuous. `[setup]` is the table the
    // install lives in.
    expect(tasks).toContain('[setup]')
    expect(tasks).not.toMatch(/npm ci/)
    expect(tasks).toMatch(/pnpm install --frozen-lockfile/)
  })

  it('is invoked by at least one root workflow', () => {
    expect(
      suiteRunners.map((workflow) => workflow.name),
      'No workflow in .github/workflows/ both names packages/protect-ffi/integration-tests and starts vitest. That was silently true from the absorption until integration-protect-ffi.yml landed: the suite is 19 files of live coverage that nothing ran.',
    ).not.toEqual([])
  })

  for (const { name, body } of suiteRunners) {
    it(`${name} builds the binding before running the suite`, () => {
      // Every test in the suite imports `@cipherstash/protect-ffi`, which
      // resolves to `lib/index.cjs` and loads `index.node`. As a workspace
      // package neither is in the checkout, so without a build step the job
      // fails with `Cannot find module '.../index.node'` once per test file
      // rather than once — and the two wasm suites additionally need
      // `dist/wasm/protect_ffi_inline.js`, which they throw over rather than
      // skip.
      expect(body).toMatch(
        /build-ffi-binding|mise run test:integration|run build:(native|debug|wasm)/,
      )
    })

    it(`${name} provisions the database and both EQL versions`, () => {
      // `mise setup` is the whole preamble: the workspace install, docker
      // compose up, the EQL **v2** bundle from a GitHub release, and EQL **v3**
      // built from the in-tree `@cipherstash/eql`. Both versions matter —
      // `tests/postgres.test.ts` needs `eql_v2_encrypted`, and
      // `tests/postgres-v3.test.ts` needs the `eql_v3_*` domains. Nothing
      // else in this repo installs v2, so dropping this step fails half the
      // suite on missing SQL functions.
      expect(body).toMatch(/mise (run )?setup/)
    })

    it(`${name} passes live CipherStash credentials`, () => {
      // The suites THROW rather than skip when a credential is absent, so a
      // missing env block is loud — but `require-cs-secrets` makes it loud in
      // seconds instead of after a cold Rust build, and rejects a base64
      // `CS_CLIENT_KEY` that protect-ffi 0.31+ no longer accepts.
      expect(body).toContain('CS_CLIENT_KEY')
      expect(body).toContain('require-cs-secrets')
    })

    it(`${name} runs the lock-context tests too`, () => {
      // `tasks.toml` has two tasks and only one of them is complete:
      // `test:integration` excludes `tests/lock-context.test.ts`,
      // `test:integration:all` includes it. Upstream CI ran `:all`. An
      // invocation that inherits the exclusion drops the identity-aware
      // coverage while still reporting a green integration job.
      expect(body).not.toMatch(/--exclude[^\n]*lock-context/)
      expect(body).not.toMatch(/mise run test:integration(?!:all)/)
    })
  }
})
