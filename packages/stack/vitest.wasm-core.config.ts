import { defineConfig } from 'vitest/config'

/**
 * The one suite in stack's DEFAULT test run that loads the REAL protect-ffi
 * WASM core — NOT the only one in the repo that loads it. `integration/wasm/**`
 * does (its config restores the genuine module over the stub alias), as do
 * protect-ffi's own `wasm-round-trip` / `wasm-error-codes` suites and the Deno
 * smoke tests in `e2e/wasm/`. Three CI jobs build `dist/wasm/**` for them.
 *
 * What is unusual here is the COMBINATION: this file needs the real core and
 * nothing else — no credentials, no database, no PostgREST — because every
 * assertion lands before the first network call. That is what puts it in an
 * awkward middle. It cannot stay with the unit suites, and joining the
 * integration suites would give it dependencies it does not have:
 * `packages/test-kit/src/integration/global-setup.ts` requires credentials AND
 * a database unconditionally (it throws rather than skips, then runs a real
 * `stash eql install`), and `integration-drizzle.yml`, the workflow that runs
 * them, is path-filtered, fork-skipped and matrixed over two databases. A
 * contract about the core would then go unchecked on any diff those paths do
 * not select.
 *
 * So: a SEPARATE config from `packages/stack/vitest.config.ts`, for the same
 * reason `integration/vitest.config.ts` is one — the default suite has to run
 * with nothing but a checkout and `pnpm install`, and this file needs a build
 * that neither of those produces.
 *
 * `@cipherstash/protect-ffi` is a workspace package now, so its `./wasm-inline`
 * entry resolves to `dist/wasm/protect_ffi_inline.js` — wasm-pack output, and
 * only the three `.d.ts` beside it are tracked in git. Left in the default
 * config the file does not skip, it fails to COLLECT
 * (`Cannot find module '.../dist/wasm/protect_ffi_inline.js'`), which is what
 * turned `run-tests` red: that job builds the binding without `wasm: 'true'`,
 * as does the Bun job, and both say so in a comment. A local
 * `pnpm --filter @cipherstash/stack test` would have needed cargo and wasm-pack
 * too.
 *
 * So it runs from `tests.yml`'s `wasm-e2e-tests` job — the one job that builds
 * `dist/wasm/**` — via the `test:wasm-core` script.
 * `scripts/__tests__/wasm-core-contract-ci.test.mjs` holds that wiring
 * together: a suite excluded from the default config and invoked by no job
 * reads exactly like a suite that passes.
 *
 * NO ALIASES, and that is the point rather than an omission.
 * `stackSourceAlias` maps `@cipherstash/protect-ffi/wasm-inline` to a stub
 * whose `newClient` throws, which is right for the unit suites and would make
 * this one assert against nothing. The test resolves the module through Node
 * rather than the bare specifier, so it dodges that alias wherever it runs;
 * leaving the map out here means it does not have to.
 */
export const WASM_CORE_SUITE =
  '__tests__/wasm-inline-core-credential-contract.test.ts'

export default defineConfig({
  test: {
    root: __dirname,
    include: [WASM_CORE_SUITE],
    // The default, set explicitly: a rename that leaves the glob behind must
    // fail rather than report a green run of zero files — the one failure mode
    // a single-file `include` invites.
    passWithNoTests: false,
  },
})
