import { defineConfig } from 'vitest/config'

// The suites that need no native build: `test`, which root `pnpm test`
// runs on machines with no Rust toolchain. The suites that load the addon
// are in `__tests__/addon` and run from `test:addon` (vitest.addon.config.ts).
export default defineConfig({
  test: {
    include: ['__tests__/unit/**/*.test.ts'],
  },
})
