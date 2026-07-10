import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'
import { sharedAlias } from '../../../vitest.shared'

/**
 * Integration suites: real ZeroKMS, real Postgres, real PostgREST.
 *
 * Deliberately a SEPARATE config from `packages/stack/vitest.config.ts`, which
 * excludes `integration/**`. `pnpm test` must stay runnable with no credentials
 * and no database; these run only under `test:integration:*`, from their own CI
 * jobs. That separation is what lets the integration suites throw on missing
 * configuration instead of skipping.
 *
 * `CS_IT_SUITE` selects which suites run, so one config serves every adapter
 * without a second near-identical file. Comma-separated globs; each CI job scopes
 * itself to the adapter it provisioned a database for. Locally it defaults to
 * everything.
 *
 * Scoping matters: the Drizzle suites talk straight to Postgres and the Supabase
 * suites need PostgREST, so a job running both would have to provision both.
 */
const SUITE_GLOBS = (
  process.env['CS_IT_SUITE'] ?? 'integration/**/*.integration.test.ts'
)
  .split(',')
  .map((glob) => glob.trim())
  .filter(Boolean)

export default defineConfig({
  resolve: {
    alias: {
      ...sharedAlias,
      '@/': resolve(__dirname, '../src') + '/',
      '@cipherstash/protect-ffi/wasm-inline': resolve(
        __dirname,
        '../__tests__/helpers/stub-protect-ffi-wasm-inline.ts',
      ),
      '@cipherstash/auth/wasm-inline': resolve(
        __dirname,
        '../__tests__/helpers/stub-auth-wasm-inline.ts',
      ),
    },
  },
  test: {
    root: resolve(__dirname, '..'),
    include: SUITE_GLOBS,
    globalSetup: [resolve(__dirname, 'global-setup.ts')],
    server: {
      deps: {
        // `@cipherstash/test-kit` resolves to source in ANOTHER package, i.e.
        // outside this config's root, so Vitest externalizes it and loads it
        // through Node rather than the transform pipeline. Its driver imports
        // `vitest`, and a `vitest` imported outside a worker cannot reach the
        // runner's state: "Vitest failed to access its internal state".
        inline: [/packages\/test-kit/],
      },
    },
    // Real crypto round-trips over the network. The unit config uses 30s for the
    // same reason; seeding a family table encrypts every sample, so hooks need
    // more headroom than tests do.
    testTimeout: 60_000,
    hookTimeout: 180_000,
    // One database, shared tables. File-level parallelism would have two family
    // suites installing EQL and reloading the PostgREST schema cache at once.
    fileParallelism: false,

    /**
     * Show console output only for tests that FAIL.
     *
     * The capability-rejection tests are the bulk of the suite, and each one
     * makes the adapter refuse an operation. `EncryptedQueryBuilderImpl.execute`
     * logs `logger.error(...)` before returning its `Result` error, so every
     * passing rejection emits an ERROR block with a stack trace. A CI run
     * printed 213 of them — all from passing tests — which is enough noise to
     * bury a real failure and enough to make a green job look broken.
     *
     * `'passed-only'` suppresses those and keeps the logs of any test that
     * actually fails, which is when they are worth reading. The stack logger has
     * no silent level (`STASH_STACK_LOG` bottoms out at `error`), so this is the
     * only place to do it without changing product logging behaviour.
     */
    silent: 'passed-only',
  },
})
