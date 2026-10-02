import { resolve } from 'node:path'

/**
 * Shared integration-suite vitest wiring, so the adapter packages' near-identical
 * `integration/vitest.config.ts` files don't drift. The harness (`global-setup`,
 * the no-skips reporter) lives beside this file in `@cipherstash/test-kit`.
 *
 * Each package still owns its own `defineConfig`, `resolve.alias`
 * (`...sharedAlias, ...stackSourceAlias`), and `test.root` — only the harness
 * paths and the shared `test.*` knobs come from here.
 */
const HERE = __dirname

// Not `as const`: vitest's `test` config wants mutable `string[]` for
// globalSetup/reporters and the `'passed-only'` literal for `silent`; a blanket
// `as const` makes the arrays `readonly` and fails `defineConfig`'s overload.

/** `globalSetup` (installs EQL v3) + the fail-on-skip reporter. */
export const integrationHarness = {
  globalSetup: [resolve(HERE, 'global-setup.ts')],
  reporters: ['default', resolve(HERE, 'no-skips-reporter.ts')],
}

/**
 * The `test.*` knobs every integration suite shares: `@cipherstash/test-kit` must
 * be inlined (it imports `vitest` and is externalized as out-of-root source);
 * real crypto over the network needs generous timeouts; suites share one DB so no
 * file parallelism; suppress passing-rejection ERROR noise; a fully-empty run is a
 * failure, not a pass.
 */
export const integrationTestDefaults = {
  server: { deps: { inline: [/packages\/test-kit/] } },
  testTimeout: 60_000,
  hookTimeout: 180_000,
  fileParallelism: false,
  silent: 'passed-only' as const,
  passWithNoTests: false,
}
