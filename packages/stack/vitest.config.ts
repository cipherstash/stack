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
    // Live suites make real ZeroKMS / CTS network round-trips. The vast
    // majority of these tests already pass an explicit `, 30000)` per-test
    // timeout (300+ call sites); a handful were written without one and so
    // fell back to Vitest's 5000ms default. Under the default forks pool with
    // file parallelism, many live suites hit ZeroKMS concurrently and those
    // 5000ms-default tests intermittently time out (they pass in isolation).
    // Align the global default with the dominant explicit value so the intent
    // is uniform. 30s is comfortably above real network latency but still low
    // enough to surface a genuine hang.
    testTimeout: 30000,
    hookTimeout: 30000,
    typecheck: {
      // Scoped tsconfig keeps the 124 pre-existing wasm-inline typecheck errors
      // out of scope (tracked as a follow-up). Run via the `test:types` script
      // with `--typecheck.only` so the runtime suites do NOT also execute.
      tsconfig: './tsconfig.typecheck.json',
      include: ['__tests__/**/*.test-d.ts'],
    },
  },
})
