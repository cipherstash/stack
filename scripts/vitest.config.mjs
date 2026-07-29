import { defineConfig } from 'vitest/config'

// `fileParallelism: false` is load-bearing, not a performance knob.
//
// Several of these suites mutate the real repo tree while they run:
// `lint-no-dead-package-paths.test.mjs` creates and deletes probe package
// directories inside the packages tree (`lint-untracked-probe`,
// `lint-dead-shell-probe`), and `lint-no-hardcoded-runners.test.mjs` walks that
// same tree and writes an `allowlist-probe.mjs` into `scripts/`. Run in
// parallel, one suite's scratch state lands inside another's scan — which is
// how a clean tree produced an `ENOENT: scandir` on a probe directory and a CI
// failure that pointed at nothing.
//
// Note the probe names are deliberately written WITHOUT their directory prefix:
// the sibling `lint-no-dead-package-paths` linter flags that shape when the
// directory does not exist, and these only exist mid-test.
//
// These are eleven small files; serialising them costs a second and removes
// the whole class of cross-suite filesystem race.
export default defineConfig({
  test: {
    include: ['scripts/__tests__/**/*.test.mjs'],
    pool: 'forks',
    fileParallelism: false,
  },
})
