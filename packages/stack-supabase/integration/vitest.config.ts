import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'
import { sharedAlias } from '../../../vitest.shared'

/**
 * Integration suites for the Supabase adapter: real ZeroKMS, real Postgres, real
 * PostgREST. Runs only under `test:integration` (its own CI job). The shared
 * harness — `global-setup` (installs EQL v3) and the no-skips reporter — lives in
 * `@cipherstash/test-kit/src/integration` so both adapter packages share one copy.
 */
const TEST_KIT_INT = resolve(__dirname, '../../test-kit/src/integration')

export default defineConfig({
  resolve: {
    alias: {
      ...sharedAlias,
      '@cipherstash/stack/adapter-kit': resolve(
        __dirname,
        '../../stack/src/adapter-kit.ts',
      ),
      '@/': resolve(__dirname, '../../stack/src') + '/',
      '@cipherstash/protect-ffi/wasm-inline': resolve(
        __dirname,
        '../../stack/__tests__/helpers/stub-protect-ffi-wasm-inline.ts',
      ),
      '@cipherstash/auth/wasm-inline': resolve(
        __dirname,
        '../../stack/__tests__/helpers/stub-auth-wasm-inline.ts',
      ),
    },
  },
  test: {
    root: resolve(__dirname, '..'),
    include: ['integration/**/*.integration.test.ts'],
    globalSetup: [resolve(TEST_KIT_INT, 'global-setup.ts')],
    server: {
      deps: {
        inline: [/packages\/test-kit/],
      },
    },
    testTimeout: 60_000,
    hookTimeout: 180_000,
    fileParallelism: false,
    silent: 'passed-only',
    passWithNoTests: false,
    reporters: ['default', resolve(TEST_KIT_INT, 'no-skips-reporter.ts')],
  },
})
