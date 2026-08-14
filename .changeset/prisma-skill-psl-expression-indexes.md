---
'stash': patch
---

Correct the bundled `stash-prisma` and `stash-indexing` skills for Prisma Next 0.17's functional-index support: `@@index` now takes an `expression` argument, so the `eql_v3.*` functional indexes are declared directly in `schema.prisma` (expression indexes require a `name` or `map`; `options` requires `type`) instead of hand-written raw-SQL migration operations. `rawSql` remains the home of the post-build `ANALYZE` and the fallback for DDL that PSL cannot carry.
