import { defineConfig } from 'vitest/config'

// The suites that load the native build. `test:addon` runs them after
// `build:debug`; root `pnpm test` does not, because it runs no cargo. The
// setup file fails the run when the addon is missing, so a missing build is
// a failure here, never a skip.
export default defineConfig({
  test: {
    include: ['__tests__/addon/**/*.test.ts'],
    setupFiles: ['__tests__/addon/require-addon.ts'],
    testTimeout: 30_000,
  },
})
