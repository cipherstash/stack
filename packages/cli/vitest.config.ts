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
      // turbo runs `^build` first; without this alias and without a build, 10
      // files / 177 tests fail to collect with `Failed to resolve entry for
      // package "@cipherstash/migrate"` — the transitive `src` importers
      // (`status/index.ts`, `db/install.ts`, `encrypt/lib/db-readers.ts`), not
      // just the one mocked test. A full-factory `vi.mock` does not help:
      // Vite's import analysis fails on the source module's import statement
      // before mocking runs.
      //
      // This removes the `@cipherstash/migrate` build coupling ONLY. The suite
      // is still not self-contained: removing `packages/stack/dist` still
      // fails 10 files, via TWO independent routes —
      //   1. `packages/migrate/src/backfill.ts` imports `@cipherstash/stack`,
      //      so this alias reaches it transitively; and
      //   2. `init/lib/__tests__/introspect.test.ts` imports
      //      `@cipherstash/stack/eql/v3` directly, never touching migrate.
      // Route 2 means decoupling `backfill.ts` would NOT make the suite
      // standalone. Closing both needs `stackSourceAlias`, which cannot be
      // spread here — its `'@/'` entry (pointing at `packages/stack/src`)
      // would clobber this package's own `'@/'`. That is why
      // `vitest.shared.ts` is not imported by this config (#787 review).
      '@cipherstash/migrate': resolve(__dirname, '../migrate/src/index.ts'),
    },
  },
})
