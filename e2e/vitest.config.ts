import { defineConfig } from 'vitest/config'

// E2E tests spawn child processes (built binaries) and may hit the network.
// Use the forks pool so each test gets a clean process; longer timeouts to
// accommodate subprocess startup + I/O.
export default defineConfig({
  test: {
    globals: true,
    include: ['tests/**/*.e2e.test.ts'],
    // Fails without CS_* credentials, which turbo's strict env mode hides from
    // `test:e2e`; it runs from `vitest.protect-compat.config.ts` instead.
    exclude: [
      '**/node_modules/**',
      'tests/protect-dynamodb-compat.e2e.test.ts',
    ],
    pool: 'forks',
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
})
