import { defineConfig } from 'vitest/config'

/**
 * The one suite that loads the REAL protect-ffi WASM core.
 *
 * Deliberately a SEPARATE config from `packages/stack/vitest.config.ts`, for
 * the same reason `integration/vitest.config.ts` is one: the default suite has
 * to run with nothing but a checkout and `pnpm install`, and this file needs a
 * build that neither of those produces.
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
