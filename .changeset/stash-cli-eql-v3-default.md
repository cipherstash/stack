---
"stash": minor
---

Default EQL to v3 and stop the CLI recommending `stash db push` (#585).

- **EQL v3 is now the default.** `stash eql install` and `stash eql upgrade` target v3 (the native `eql_v3.*` domain schema) without `--eql-version 3`. The v2-only paths — `--drizzle`, `--migration`, `--migrations-dir`, and `--latest` — now require an explicit `--eql-version 2` and error with clear guidance otherwise (v3 installs via the direct path only). `stash init` pins v2 automatically when it drives the Drizzle migration flow.
- **`stash db push` is no longer recommended in CLI output.** `db push` writes the `public.eql_v2_configuration` table, which is a v2 + CipherStash Proxy artifact — EQL v3 has no configuration table (config lives in each column's `eql_v3.*` type) and nothing in the v3 stack reads it. The push recommendations are removed from `eql status`, the help banner, and the init/plan/cutover guidance. `db push` (and `db activate`) remain available for EQL v2 + Proxy users; they're now labelled as such.
- **`eql status` is v3-aware.** On a v3-only database it reports that encrypt config lives in the column types instead of hitting a "table not found" dead-end that told users to run `db push` (which neither creates that table nor applies to v3).
- **`stash db push` guards a v3-only database** with a clear "not needed under EQL v3" message instead of a raw `relation "public.eql_v2_configuration" does not exist` error.
