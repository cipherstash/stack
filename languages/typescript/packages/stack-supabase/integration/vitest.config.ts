import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'
import { sharedAlias, stackSourceAlias } from '../../../vitest.shared'
import {
  integrationHarness,
  integrationTestDefaults,
} from '../../test-kit/src/integration/config'

/**
 * Integration suites for the supabase adapter: real ZeroKMS + real Postgres
 * (+ PostgREST for supabase). Runs only under `test:integration` (its own CI
 * job). Harness + shared `test.*` knobs come from `@cipherstash/test-kit`.
 */
export default defineConfig({
  resolve: { alias: { ...sharedAlias, ...stackSourceAlias } },
  test: {
    root: resolve(__dirname, '..'),
    include: ['integration/**/*.integration.test.ts'],
    ...integrationHarness,
    ...integrationTestDefaults,
  },
})
