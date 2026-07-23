import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['__tests__/**/*.test.ts'],
    // Installs EQL v3 before any suite applies `sql/schema.sql`, which declares
    // its columns as `eql_v3_*` domains. See the file for why this is not a
    // CI-only step.
    globalSetup: ['./src/harness/global-setup.ts'],
    // `@cipherstash/test-kit` is consumed as unbuilt TypeScript source, so it
    // must not be externalized — same reason the integration suites carry this
    // (`packages/test-kit/src/integration/config.ts`).
    server: { deps: { inline: [/packages\/test-kit/] } },
    testTimeout: 300_000,
    hookTimeout: 300_000,
    pool: 'forks',
    poolOptions: {
      forks: { singleFork: true },
    },
    fileParallelism: false,
  },
  benchmark: {
    include: ['__benches__/**/*.bench.ts'],
    outputJson: 'results/bench-results.json',
  },
})
