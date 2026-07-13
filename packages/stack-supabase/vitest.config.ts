import { resolve } from 'node:path'
import { configDefaults, defineConfig } from 'vitest/config'
import { sharedAlias } from '../../vitest.shared'

export default defineConfig({
  resolve: {
    alias: {
      // Resolve `@cipherstash/stack` + its subpaths (and `@cipherstash/test-kit`)
      // to SOURCE, so `pnpm test` here is not coupled to a prior stack build.
      ...sharedAlias,
      // adapter-kit is the core↔adapter seam; not in the shared block because
      // only the adapter packages consume it.
      '@cipherstash/stack/adapter-kit': resolve(
        __dirname,
        '../stack/src/adapter-kit.ts',
      ),
    },
  },
  test: {
    // Integration suites require credentials + a database + PostgREST and THROW
    // when unconfigured, so `pnpm test` must never collect them.
    exclude: [...configDefaults.exclude, 'integration/**'],
    testTimeout: 30000,
    hookTimeout: 30000,
    typecheck: {
      tsconfig: './tsconfig.json',
      include: ['__tests__/**/*.test-d.ts'],
    },
  },
})
