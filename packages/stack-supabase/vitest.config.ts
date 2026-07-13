import { configDefaults, defineConfig } from 'vitest/config'
import { sharedAlias, stackSourceAlias } from '../../vitest.shared'

export default defineConfig({
  resolve: {
    // `sharedAlias` resolves `@cipherstash/stack` + its subpaths (incl.
    // adapter-kit) and `@cipherstash/test-kit` to SOURCE; `stackSourceAlias` adds
    // stack's internal `@/` alias + the wasm-inline stubs that source needs.
    alias: { ...sharedAlias, ...stackSourceAlias },
  },
  test: {
    // Integration suites require credentials + a database + PostgREST and THROW
    // when unconfigured, so `pnpm test` must never collect them.
    exclude: [...configDefaults.exclude, 'integration/**'],
    testTimeout: 30000,
    hookTimeout: 30000,
    typecheck: {
      tsconfig: './tsconfig.typecheck.json',
      include: ['__tests__/**/*.test-d.ts'],
    },
  },
})
