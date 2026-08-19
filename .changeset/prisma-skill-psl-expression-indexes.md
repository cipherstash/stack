---
'stash': patch
---

Correct the bundled `stash-prisma` and `stash-indexing` skills for Prisma Next 0.17's functional-index support: `@@index` now takes an `expression` argument, so the `eql_v3.*` functional indexes are declared directly in `schema.prisma` (expression indexes require a `name` or `map`) instead of hand-written raw-SQL migration operations. Also documents the physical-name rule (`name:` gains a content-hash suffix, `map:` pins the exact name), the TS contract form (`type` requires `options`), and that `CREATE INDEX CONCURRENTLY` cannot run through the migration runner's transaction — via `rawSql` or otherwise.
