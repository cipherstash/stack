# Encryption Migrations — Implementation Plan

## Context

CipherStash today can encrypt a column at rest via EQL + either Stack/Protect.js (client-side) or the CipherStash Proxy (transparent). What it *doesn't* have is a first-class way to migrate an **existing plaintext column** into an encrypted one safely in production. EQL ships the schema/config primitives (`add_column`, `migrate_config`, `rename_encrypted_columns`) but no backfill orchestrator, no per-column phase tracking, and no resumable data mover. Today users have to wire this up themselves, which is both the biggest onboarding friction and the biggest correctness risk (partial backfills, reads on the wrong column, silent plaintext leaks).

This plan adds a shared migration substrate — CLI + library — that walks each column through the full lifecycle:

```
schema-added → dual-writing → backfilling → backfilled → cut-over → dropped
```

The same mechanism serves Stack and Proxy users. Phase 1 ships the status inspector and the backfill engine (the two pieces with no good existing workaround). The other phases get lightweight commands that mostly orchestrate existing EQL functions and delegate code changes to the rulebook/agent flow.

## Scope (Phase 1)

1. `stash encrypt status` — per-column view of current phase, EQL registration, backfill progress, drift between intent and state.
2. `stash encrypt backfill` — resumable, idempotent, chunked plaintext → encrypted migration using the user's encryption client (Protect/Stack mode). Progress reporting, checkpoint on every chunk, `--resume` / `--table` / `--column` / `--chunk-size` flags.
3. A new `cs_migrations` table + small library (`@cipherstash/migrate` or co-located in `@cipherstash/stack`) that the CLI commands drive. Library is exported so users can embed backfill in their own workers/cron later without new infra.
4. `.cipherstash/migrations.json` repo manifest = intent (desired columns + index set + target phase). `stash encrypt plan` diffs intent vs. observed state.
5. Thin wrappers for the other phases so users can drive end-to-end from the CLI today, even if those phases are mostly pass-throughs:
   - `stash encrypt advance --to dual-writing` — records user-declared transition into `cs_migrations` and reminds them what code change is needed. Delegates code changes to the agent-handoff rulebook (see `init-agent-handoff.md`).
   - `stash encrypt cutover` — wraps `eql_v2.rename_encrypted_columns()` + `eql_v2.reload_config()` (via Proxy if present).
   - `stash encrypt drop` — emits a migration file that drops `<col>_plaintext`.

**Out of Phase 1:** Proxy-mode backfill (Phase 2), CS-hosted backfill runner (Phase 3), upstreaming `cs_migrations` into EQL as `eql_v2_migrations` (Phase 3).

## Architecture

### 1. Three-layer state model

| Layer | Home | Role | Frequency |
|---|---|---|---|
| **Intent** | `.cipherstash/migrations.json` (repo) | Desired columns, index set, target phase. Code-reviewable. | Changes with commits. |
| **EQL intent** | `eql_v2_configuration` (DB, existing) | Authoritative "is this column encrypted, with which indexes" — drives Proxy. Unchanged by this plan. | Changes per schema cycle. |
| **Runtime state** | `cs_migrations` (DB, new) | Per-column phase, backfill cursor, rows processed, timestamps. Append-only event log. | High-frequency during backfill. |

Why separate `cs_migrations` from `eql_v2_configuration`: the EQL config's `data` JSONB has a strict CHECK constraint (`{v, tables}` with enumerated `cast_as` + index kinds) that rejects custom metadata; its `state` enum is global (only one `{active, pending, encrypting}` at a time) so it can't represent multiple columns in different phases simultaneously; and backfill-cadence writes would collide with Proxy's 60s config refresh. Detailed reasoning in the conversation transcript linked from commit.

`cs_migrations` schema (append-only; one row per transition or checkpoint):

```sql
CREATE SCHEMA IF NOT EXISTS cipherstash;

CREATE TABLE cipherstash.cs_migrations (
  id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  table_name     text NOT NULL,
  column_name    text NOT NULL,
  event          text NOT NULL,       -- 'schema_added' | 'dual_writing' | 'backfill_started' | 'backfill_checkpoint' | 'backfilled' | 'cut_over' | 'dropped' | 'error'
  phase          text NOT NULL,       -- current phase AFTER this event
  cursor_value   text,                -- keyset pagination cursor (usually the last processed PK)
  rows_processed bigint,
  rows_total     bigint,
  details        jsonb,               -- per-event extra data: error message, chunk size, duration, etc.
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ON cipherstash.cs_migrations (table_name, column_name, id DESC);
```

Current state per column = latest row for `(table_name, column_name)`. History is preserved.

### 2. `stash encrypt status`

Reads from three sources in parallel and renders a unified table:

- **Intent** — `.cipherstash/migrations.json`
- **EQL state** — `SELECT state, data FROM eql_v2_configuration WHERE state IN ('active','pending','encrypting')`; extract per-column registration + index set.
- **Runtime state** — latest `cs_migrations` row per `(table, column)`.

Also fires `information_schema.columns` to detect physical column presence (`<col>`, `<col>_encrypted`, `<col>_plaintext`).

Output (example):

```
TABLE       COLUMN   PHASE            EQL     INDEXES        PROGRESS
users       email    backfilling      active  unique, match  421,018 / 2,104,552 (20%)  ETA 12m
users       ssn      dual-writing     active  unique         —
users       phone    schema-added ⚠   pending match          registered, awaiting migrate_config
orders      notes    cut-over         active  match, ste_vec 1,204,091 / 1,204,091 (100%)
```

Drift flags:

- ⚠ intent says `backfilling` but EQL has no active entry
- ⚠ EQL has index intent says doesn't
- ⚠ `<col>_encrypted` column doesn't exist
- ⚠ backfill says complete but `COUNT(*) WHERE col_encrypted IS NULL` > 0

### 3. `stash encrypt backfill` — the meat

**Flow per column:**

1. Validate preconditions: column registered in active EQL config; `<col>_encrypted` physically exists; phase in `cs_migrations` is `dual_writing` or `backfilling` (not already complete).
2. Load user's encryption client via the same dynamic-import pattern the wizard uses (`loadStashConfig` → dynamic import of `src/encryption/index.ts` → `.init()` with env-sourced credentials).
3. Determine `rows_total` (`SELECT count(*) FROM t WHERE col IS NOT NULL AND col_encrypted IS NULL`).
4. Determine resume cursor: last `backfill_checkpoint` event's `cursor_value`, or NULL.
5. Emit `backfill_started` event.
6. Loop: keyset-paginate on primary key (or user-specified `--order-by`):
   ```sql
   SELECT id, <col> FROM <table>
   WHERE <col> IS NOT NULL AND <col>_encrypted IS NULL AND id > $cursor
   ORDER BY id ASC LIMIT $chunk_size
   ```
   - Default `chunk_size` = 1000 (configurable).
   - Call `bulkEncryptModels(rows, table, client)` from `@cipherstash/stack`.
   - Write back with a single `UPDATE ... FROM (VALUES ...)` per chunk.
   - Wrap the UPDATE in a transaction; insert `backfill_checkpoint` event in the same txn. (Atomicity: either the chunk is persisted and checkpointed, or neither.)
   - Stream progress to stdout (tty-aware — simple log lines in CI).
7. When the chunk returns zero rows, emit `backfilled` event, transition phase.
8. Error handling:
   - Per-chunk try/catch → `error` event row with `details: { message, stack, cursor }`, halt (fail-fast default) or continue (`--continue-on-error` flag for lower-value columns).
   - SIGINT / SIGTERM: finish current chunk, checkpoint, exit cleanly.

**Resumability guarantees:**

- **Idempotent** — the `col_encrypted IS NULL` filter ensures re-running never re-encrypts a row, even without the checkpoint cursor.
- **Resumable** — checkpoint cursor skips already-processed rows for speed.
- **Multi-machine safe** — even without locking, concurrent runners converge (they'll race on the same rows but the UPDATE is idempotent; the `IS NULL` guard prevents double-writes). A `SELECT ... FOR UPDATE SKIP LOCKED` variant will be added in Phase 2 if needed.

**Batch sizing guidance in docs:** start at 1000, lower if you see locking contention, raise for wide columns with small values. Include a `--dry-run` that samples one chunk and prints timings.

### 4. `stash encrypt advance --to <phase>`

Records a user-declared transition. This is the honest path for phases where the tool can't safely detect the state (dual-writing is an app-code property, not a DB property):

- `--to dual-writing`: insert `dual_writing` event; print a reminder + the relevant rulebook snippet for editing persistence code. Offer to invoke the agent handoff if configured.
- `--to backfilling`: insert event; effectively equivalent to starting `stash encrypt backfill` (and does so unless `--no-run`).

### 5. `stash encrypt cutover`

For each column in `backfilled` phase, in a single transaction:

```sql
BEGIN;
-- Renames <col> -> <col>_plaintext, <col>_encrypted -> <col>
SELECT eql_v2.rename_encrypted_columns();
COMMIT;

-- If Proxy URL is configured, force refresh
\c <proxy_url>
SELECT eql_v2.reload_config();
```

Record `cut_over` event. App's existing `SELECT email FROM users` now returns the encrypted column (decrypted transparently by Proxy or client-side by Stack). No app code change required for reads — this is the big payoff of the rename approach.

### 6. `stash encrypt drop`

For columns in `cut_over` phase:

1. Read Drizzle / Prisma / other migration tooling from repo (we already detect this in init).
2. Emit a standard migration file (drizzle format by default): `ALTER TABLE <table> DROP COLUMN <col>_plaintext;`.
3. Print next-step instructions ("review and run `drizzle-kit generate && drizzle-kit migrate`" or equivalent).
4. Only record the `dropped` event *after* a follow-up `stash encrypt reconcile` verifies the column is gone from `information_schema.columns`.

## Critical files to modify or create

- `stack/packages/cli/src/commands/encrypt/` — **new command group** (parallel to `db/`)
  - `index.ts` — subcommand registration
  - `status.ts` — new
  - `backfill.ts` — new
  - `advance.ts` — new
  - `cutover.ts` — new
  - `drop.ts` — new
  - `plan.ts` — new (diffs intent vs. observed)
- `stack/packages/cli/src/bin/stash.ts` — register `encrypt` subcommand (analogous to existing `db` registration at ~line 237)
- `stack/packages/migrate/` — **new package** (library the CLI drives)
  - `src/state.ts` — `cs_migrations` DAO (append event, get latest, get progress)
  - `src/backfill.ts` — the chunked loop, exported as `runBackfill({ table, column, client, db, chunkSize, signal })`
  - `src/cursor.ts` — keyset pagination primitive
  - `src/eql.ts` — thin wrappers over `eql_v2.*` functions (rename, reload, config read)
  - `src/manifest.ts` — read/write `.cipherstash/migrations.json`
  - `src/schema.sql` — `cs_migrations` DDL, installed by `db install` or an explicit `encrypt install` step
- `stack/packages/cli/src/commands/db/install.ts` — extend to install `cs_migrations` schema alongside EQL
- `stack/packages/cli/src/commands/wizard/lib/gather.ts` — reuse introspection for `status` (no changes needed, just an import)
- `stack/packages/cli/src/config/` — extend `stash.config.ts` loader so backfill subprocess can dynamically import user's encryption client
- `stack/packages/cli/package.json` — add `@cipherstash/migrate` dep
- Rulebook partials (see `init-agent-handoff.md`) — **add** per-integration sections for "how to wire dual-write in your persistence layer" so the agent handoff can apply Phase 2 code changes consistently

## Existing primitives to reuse (do not reinvent)

- `@cipherstash/stack` `bulkEncryptModels`, `bulkDecryptModels`, `encryptModel`, `decryptModel` (at `packages/stack/src/encryption/operations/`). Bulk APIs do not chunk internally — our code chunks.
- `introspectDatabase` in `packages/cli/src/commands/wizard/tools/wizard-tools.ts:150-191`.
- `loadStashConfig` + dynamic encryption-client import (currently in `packages/cli/src/commands/wizard/lib/`) — lift into `@cipherstash/migrate` so both CLI and library users get it.
- `rewriteEncryptedAlterColumns` in `packages/cli/src/commands/db/rewrite-migrations.ts` — the phase-1 schema-add is already solved by drizzle-kit + this rewriter. The new commands **will not** re-solve it.
- EQL functions (Postgres): `eql_v2.add_column`, `eql_v2.add_search_config`, `eql_v2.migrate_config`, `eql_v2.activate_config`, `eql_v2.rename_encrypted_columns`, `eql_v2.reload_config`, `eql_v2.count_encrypted_with_active_config`, `eql_v2.select_pending_columns`, `eql_v2.ready_for_encryption`.
- `db push` in `packages/cli/src/commands/db/push.ts` — already handles writing to `eql_v2_configuration`; reuse the DAO.

## Verification

1. **Unit**
   - `cs_migrations` DAO: append event, latest-by-column, progress query.
   - Cursor pagination: exhausts all rows, handles gaps, stable under concurrent inserts (snapshot-based row count held at start).
   - Manifest reader: schema validation, drift detection.
2. **Integration (Drizzle, local Postgres)**
   - Seed 100k-row `users` table with plaintext `email`.
   - `stash db install` → EQL + `cs_migrations` installed.
   - `stash encrypt advance --to dual-writing --table users --column email` → records event.
   - Manually wire dual-write in the test app's insert code (simulates user + agent handoff).
   - `stash encrypt backfill --table users --column email` → completes; progress output sane; `COUNT(*) WHERE email_encrypted IS NULL` = 0.
   - Kill mid-backfill (SIGINT) → re-run with `--resume` → completes without duplicate encryption; `cs_migrations` shows continuous cursor progression.
   - `stash encrypt status` → shows `backfilled`.
   - `stash encrypt cutover` → rename executes; app (still running, reads `email`) now gets decrypted ciphertext transparently.
   - `stash encrypt drop` → migration file emitted; apply; `email_plaintext` gone.
3. **Idempotency**
   - Run `backfill` twice with no kill — second run does 0 writes.
   - Concurrent runners on two shells — both converge, no duplicate writes, no missed rows.
4. **Proxy interop**
   - After cutover, connect via Proxy and `SELECT email FROM users` → returns plaintext (Proxy decrypted).
   - Connect directly to Postgres and `SELECT email FROM users` → returns encrypted JSON payload.
5. **Failure paths**
   - Inject a row with invalid UTF-8 → `error` event recorded with cursor; `--continue-on-error` skips; default halts.
   - Kill DB mid-chunk → transaction rollback; retry succeeds.
6. **Status accuracy**
   - Manually drop a `<col>_encrypted` column → `status` flags drift (EQL says registered, physical column absent).
   - Manually set `eql_v2_configuration` to `pending` with an unready column → `status` surfaces `ready_for_encryption = false`.
7. **Large-data smoke**
   - 10M-row table backfill on a dev DB; measure wall-clock, memory, DB load. Confirm no OOM, no unbounded RAM (chunk buffer drains each loop).

## Phase 2+ (not in this plan)

- **Proxy-mode backfill** — `UPDATE ... FROM (SELECT id, col FROM t WHERE ...)` routed through a Proxy connection; Proxy encrypts on the fly. Same `cs_migrations` state, same cursor model.
- **Upstream `cs_migrations` into EQL** as `eql_v2_migrations` so Proxy can read/write it directly. Requires EQL release + coordinated CLI bump.
- **`FOR UPDATE SKIP LOCKED`** variant for true multi-worker parallelism.
- **CipherStash-hosted backfill runner** (push a backfill job; we run it).
- **`stash encrypt reverse`** — emergency rollback: rename-swap back, re-enable plaintext reads. Controversial; needs separate design.
- **Drizzle/Prisma/Generic dual-write helpers** in `@cipherstash/stack` — e.g. `dualWrite(email, email_encrypted)` wrapper that agents can drop in with minimal surface area.
- **Non-PK ordering** for tables without a sortable primary key (hash-partitioned CTIDs, etc.).

## Open items flagged (decisions already made)

- Phase 1 runtime mode = Protect/Stack client-side only.
- Phase 4 default cutover mechanism = `eql_v2.rename_encrypted_columns()` (transparent to app code).
- State store = repo manifest + `eql_v2_configuration` (EQL intent) + new `cs_migrations` table (runtime state).
- Phase 1 shipping scope = status + backfill first-class; other phases as thin wrappers.
- `cs_migrations` is CLI-owned for now, explicitly designed to be upstreamed into EQL as `eql_v2_migrations` in a later release so both Stack and Proxy own it jointly.
