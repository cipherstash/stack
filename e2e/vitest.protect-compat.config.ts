import { defineConfig } from 'vitest/config'
import base from './vitest.config'

// The protect-dynamodb compatibility suite, which the default config leaves
// out. It needs the four CS_* credential variables and fails without them.
// (Not `mergeConfig`: it concatenates arrays, so the base `exclude` would win.)
export default defineConfig({
  test: {
    ...base.test,
    include: ['tests/protect-dynamodb-compat.e2e.test.ts'],
    exclude: ['**/node_modules/**'],
  },
})
