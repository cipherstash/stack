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
 * `SUITE_GLOB` selects the adapter, so one config serves both without a second
 * near-identical file. CI passes it per job; locally it defaults to everything.
 */
const SUITE_GLOB =
  process.env['CS_IT_SUITE'] ?? 'integration/**/*.integration.test.ts'

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
    include: [SUITE_GLOB],
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
  },
})
