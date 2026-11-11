import { defineConfig } from 'vitest/config'
import base from './vitest.config'

// The DynamoDB <-> Postgres cross-store suite, which the default config leaves
// out. It needs the four CS_* credential variables and DATABASE_URL, and fails
// without them. (Not `mergeConfig`: it concatenates arrays, so the base
// `exclude` would win.)
export default defineConfig({
  test: {
    ...base.test,
    include: [
      'tests/protect-crossover.e2e.test.ts',
      'tests/protect-postgres-upgrade.e2e.test.ts',
      'tests/protect-guide-example.e2e.test.ts',
    ],
    fileParallelism: false,
    exclude: ['**/node_modules/**'],
  },
})
