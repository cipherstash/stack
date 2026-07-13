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
      // We resolve `@cipherstash/stack` to its SOURCE (via sharedAlias), and that
      // source uses stack's internal `@/` alias — so it must resolve here too.
      // This package's own code never uses `@/`, so there is no collision.
      '@/': resolve(__dirname, '../stack/src') + '/',
      // stack's `src/wasm-inline.ts` imports the `/wasm-inline` subpaths of
      // protect-ffi/auth, which aren't resolvable by Vitest; alias to stack's
      // stubs so loading stack source in tests doesn't fail on them.
      '@cipherstash/protect-ffi/wasm-inline': resolve(
        __dirname,
        '../stack/__tests__/helpers/stub-protect-ffi-wasm-inline.ts',
      ),
      '@cipherstash/auth/wasm-inline': resolve(
        __dirname,
        '../stack/__tests__/helpers/stub-auth-wasm-inline.ts',
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
