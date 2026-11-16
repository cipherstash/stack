import { defineConfig } from 'vitest/config'

// E2E tests spawn child processes (built binaries) and may hit the network.
// Use the forks pool so each test gets a clean process; longer timeouts to
// accommodate subprocess startup + I/O.
export default defineConfig({
  test: {
    globals: true,
    include: ['tests/**/*.e2e.test.ts'],
    // Fail without CS_* credentials (and, for the cross-store suite,
    // DATABASE_URL), which turbo's strict env mode hides from `test:e2e`; they
    // run from `vitest.protect-compat.config.ts` and
    // `vitest.protect-crossover.config.ts` instead.
    exclude: [
      '**/node_modules/**',
      'tests/protect-dynamodb-compat.e2e.test.ts',
      'tests/protect-crossover.e2e.test.ts',
      'tests/protect-postgres-upgrade.e2e.test.ts',
      'tests/protect-guide-example.e2e.test.ts',
    ],
    pool: 'forks',
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
})
