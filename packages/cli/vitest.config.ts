import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    exclude: ['**/node_modules/**', '**/dist/**', 'tests/e2e/**'],
    // Two projects so ONLY the live suites are serialised. Four of them gate
    // on STASH_TEST_DATABASE_URL and share one database and one
    // eql_v3/eql_v3_internal pair — and verify.live's beforeAll installs the
    // full bundle, which opens with `DROP SCHEMA … CASCADE`, destroying the
    // schemas (and their ACLs/OIDs) under a concurrently running
    // guarded-grants.live. Run in parallel forks they race; run serially each
    // suite sees the database state its comments already assume. The unit
    // project keeps default file parallelism — serialising all ~1300 tests
    // for the sake of four files is the `packages/migrate` fix at the wrong
    // scale.
    projects: [
      {
        extends: true,
        test: {
          name: 'unit',
          exclude: [
            '**/node_modules/**',
            '**/dist/**',
            'tests/e2e/**',
            '**/*.live.test.ts',
          ],
        },
      },
      {
        extends: true,
        test: {
          name: 'live',
          include: ['src/**/*.live.test.ts'],
          fileParallelism: false,
        },
      },
    ],
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
