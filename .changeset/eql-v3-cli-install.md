---
"stash": minor
---

Add an EQL v3 install path to `stash eql install` via a new `--eql-version <2|3>`
flag (default `2`). v3 installs the native concrete-domain schema (`public.*`
type domains, `eql_v3` operators, `eql_v3_internal` constructors) from bundles
vendored into `packages/cli/src/sql` by `scripts/build-eql-v3-sql.mjs` (full
bundle + a Supabase variant with the two superuser-only operator-class chunks
stripped). v3 currently supports the direct install path only —
`--drizzle`/`--migration`/`--migrations-dir`/`--latest` are rejected — and the
installer keys `isInstalled`/version checks and Supabase grants to the `eql_v3`
schema.
