import { defineConfig } from 'vitest/config'

/**
 * Bench checks that need neither a database nor credentials.
 *
 * The main config's `globalSetup` installs EQL v3 through the built CLI, so
 * every suite under it requires `turbo run build --filter stash` and a live
 * Postgres. That is right for the benchmarks, and wrong for a check that only
 * compares two key sets — and "it was too expensive to run in CI" is exactly
 * how the seed came to insert plaintext into `eql_v3_*` columns unnoticed
 * (#772 review, finding 12).
 */
export default defineConfig({
  test: {
    include: ['__unit__/**/*.test.ts'],
  },
})
