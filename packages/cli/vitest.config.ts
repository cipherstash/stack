import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    exclude: ['**/node_modules/**', '**/dist/**', 'tests/e2e/**'],
  },
  resolve: {
    alias: {
      '@/': `${resolve(__dirname, './src')}/`,
      // `@cipherstash/migrate` publishes `./dist` only, so importing it — or
      // spreading `importOriginal()` inside a partial `vi.mock` — makes the
      // UNIT suite require a prior workspace build. CI only hides that because
      // turbo runs `^build` first; on a clean checkout `pnpm --filter stash
      // test` would fail to resolve it. Resolving to source keeps the unit
      // config self-contained, as `AGENTS.md` says it is (#787 review).
      '@cipherstash/migrate': resolve(__dirname, '../migrate/src/index.ts'),
    },
  },
})
