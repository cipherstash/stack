import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    // The two backfill integration suites (v2 + v3) share one real database
    // and the singleton `cipherstash.cs_migrations` schema — run in parallel
    // they race on schema DROP/CREATE and truncate each other's state rows.
    // Everything here is fast enough that whole-package serialization is
    // cheaper than a locking scheme.
    fileParallelism: false,
  },
})
