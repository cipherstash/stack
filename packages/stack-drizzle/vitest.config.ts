import { resolve } from 'node:path'
import { configDefaults, defineConfig } from 'vitest/config'
import { sharedAlias } from '../../vitest.shared'

export default defineConfig({
  resolve: {
    alias: {
      ...sharedAlias,
      '@cipherstash/stack/adapter-kit': resolve(
        __dirname,
        '../stack/src/adapter-kit.ts',
      ),
      // stack source uses its internal `@/`; this package's code never does.
      '@/': resolve(__dirname, '../stack/src') + '/',
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
    exclude: [...configDefaults.exclude, 'integration/**'],
    testTimeout: 30000,
    hookTimeout: 30000,
    typecheck: {
      tsconfig: './tsconfig.typecheck.json',
      include: ['__tests__/**/*.test-d.ts'],
    },
  },
})
