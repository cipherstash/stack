# @cipherstash/bench

Performance / index-engagement benchmarks for stack integrations.

This package validates that each integration emits SQL that engages the canonical
EQL functional indexes (`eql_v3.eq_term`, `eql_v3.match_term`,
`eql_v3.to_ste_vec_query`) on a Supabase-shaped install (no operator classes).
It runs in two layers:

1. **EXPLAIN-shape tests** (`__tests__/`) — vitest tests that assert on
   `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` output. Pass/fail. Cheap.
2. **Wall-clock benches** (`__benches__/`) — vitest `--bench` (tinybench)
   measuring median / p95 latency. On-demand; emits JSON to `results/`.

## Prerequisites

- Local Postgres + EQL via the repo-root `local/docker-compose.yml`:
  ```bash
  cd ../../local && docker compose up -d
  ```
- A CipherStash profile signed in (`stash login`). Auth is read from the
  CipherStash profile; no environment variables required.
- `DATABASE_URL` only needs to be set if you want to override the default
  (`postgres://cipherstash:password@localhost:5432/cipherstash`).

## Run

The bench package's tests are **developer-run only** — they're not invoked by
the repo's CI `test` step (the scripts are deliberately named `test:local` /
`bench:local` so turbo's default `test` task skips this package).

```bash
# Credential-free smoke (verifies schema + EXPLAIN harness):
pnpm test:local -- db-only

# Full suite (requires CipherStash auth via `stash login`, seeds 10k rows on first run):
pnpm db:setup                   # apply schema + seed BENCH_ROWS rows (default 10k)
pnpm test:local                 # EXPLAIN-shape assertions for #421 / #422
pnpm bench:local                # timing benches (slow)
pnpm db:reset                   # drop schema (keeps EQL install)
```

`__tests__/db-only.test.ts` only touches Postgres + the EQL install and is the
recommended starter — it's enough to verify the harness locally before wiring
auth. The other tests under `__tests__/` and the benches under `__benches__/`
use `@cipherstash/stack`'s `Encryption` client for real encryption.

## Why this exists

See cipherstash/stack issues #420, #421, #422.
