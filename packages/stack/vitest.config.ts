import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: {
    alias: {
      '@/': resolve(__dirname, './src') + '/',
      // The installed `@cipherstash/{protect-ffi,auth}` only export `.`; their
      // `/wasm-inline` subpaths (imported by `src/wasm-inline.ts`) are not
      // resolvable by Vitest. Alias them to local stubs so unit tests that only
      // exercise pure helpers can load the module. Tests needing real WASM
      // behaviour mock these specifiers explicitly.
      '@cipherstash/protect-ffi/wasm-inline': resolve(
        __dirname,
        './__tests__/helpers/stub-protect-ffi-wasm-inline.ts',
      ),
      '@cipherstash/auth/wasm-inline': resolve(
        __dirname,
        './__tests__/helpers/stub-auth-wasm-inline.ts',
      ),
    },
  },
  test: {
    typecheck: {
      // Scoped tsconfig keeps the 124 pre-existing wasm-inline typecheck errors
      // out of scope (tracked as a follow-up). Run via the `test:types` script
      // with `--typecheck.only` so the runtime suites do NOT also execute.
      tsconfig: './tsconfig.typecheck.json',
      include: ['__tests__/**/*.test-d.ts'],
    },
  },
})
