# Encryption Migrations — Implementation Plan

> **Status (2026-07-29): historical. Parts of the surface below no longer exist.**
>
> This document is kept as the design record for `cs_migrations`, the manifest,
> and the backfill engine — all of which shipped and are current. What was
> retired with the EQL v2 removal:
>
> - **`stash encrypt cutover` and the whole `cut-over` phase.** EQL v3 has no
>   rename swap. The lifecycle is `schema-added → dual-writing → backfilling →
>   backfilled → dropped`: backfill, switch the application to the encrypted
>   column *by name*, then drop the plaintext column (which is the original
>   `<col>`, not a `<col>_plaintext` left behind by a rename).
> - **`stash db push`, `db install`, `db upgrade`, `db status`.** `db push` and
>   its `eql_v2_configuration` DAO are gone entirely; the installer is now
>   `stash eql install`.
> - **Every `eql_v2.*` function call.** `stash` no longer installs or drives EQL
>   v2. Existing v2 ciphertext stays readable; it is not an authoring or rollout
>   target.
>
> Read the sections below as "what we planned in Phase 1", not as a description
> of the current CLI. `skills/stash-cli/SKILL.md` and
> `skills/stash-encryption/SKILL.md` are the current lifecycle reference.

## Context

CipherStash today can encrypt a column at rest via EQL + either Stack/Protect.js (client-side) or the CipherStash Proxy (transparent). What it *doesn't* have is a first-class way to migrate an **existing plaintext column** into an encrypted one safely in production. EQL ships the schema/config primitives (`add_column`, `migrate_config`, `rename_encrypted_columns`) but no backfill orchestrator, no per-column phase tracking, and no resumable data mover. Today users have to wire this up themselves, which is both the biggest onboarding friction and the biggest correctness risk (partial backfills, reads on the wrong column, silent plaintext leaks).

This plan adds a shared migration substrate — CLI + library — that walks each column through the full lifecycle:

```
schema-added → dual-writing → backfilling → backfilled → cut-over → dropped
```

*The shipped lifecycle drops `cut-over`: `schema-added → dual-writing →
backfilling → backfilled → dropped`. Status readers still display legacy
`cut_over` rows so old history remains printable.*

The same mechanism serves Stack and Proxy users. Phase 1 ships the status inspector and the backfill engine (the two pieces with no good existing workaround). The other phases get lightweight commands that mostly orchestrate existing EQL functions and delegate the code changes (e.g. wiring dual-writes into the persistence layer) to the agent handoff that `stash init` set up — Claude / Codex / AGENTS.md, with the relevant skills already installed.

## Scope (Phase 1)

1. `stash encrypt status` — per-column view of current phase, EQL registration, backfill progress, drift between intent and state.
2. `stash encrypt backfill` — resumable, idempotent, chunked plaintext → encrypted migration using the user's encryption client (Protect/Stack mode). Progress reporting, checkpoint on every chunk, `--resume` / `--table` / `--column` / `--chunk-size` / `--force` / `--confirm-dual-writes-deployed` flags. The first run on a column prompts the user (or accepts `--confirm-dual-writes-deployed` for non-interactive contexts) to confirm the application is dual-writing, and records that as the `dual_writing` transition in `cs_migrations` — there is no separate "advance" command.
3. A new `cs_migrations` table + small library (`@cipherstash/migrate` or co-located in `@cipherstash/stack`) that the CLI commands drive. Library is exported so users can embed backfill in their own workers/cron later without new infra.
4. `.cipherstash/migrations.json` repo manifest = intent (desired columns + index set + target phase). `stash encrypt plan` diffs intent vs. observed state.
5. Thin wrappers for the post-backfill phases so users can drive end-to-end from the CLI today, even if those phases are mostly pass-throughs:
   - `stash encrypt cutover` — wraps `eql_v2.rename_encrypted_columns()` + `eql_v2.reload_config()` (via Proxy if present). *(Removed — see Status. There is no cut-over rename.)*
   - `stash encrypt drop` — emits a migration file that drops `<col>_plaintext`. *(Shipped, but it drops the original `<col>`: with no rename, there is no `<col>_plaintext`.)*

**Out of Phase 1:** Proxy-mode backfill (Phase 2), CS-hosted backfill runner (Phase 3), upstreaming `cs_migrations` into EQL as `eql_v2_migrations` (Phase 3), `stash encrypt update` for re-encrypting an already-cut-over column with new EQL config (next change).

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

### 4. Dual-write confirmation, folded into `backfill`

`dual-writing` is an application-code property — the CLI cannot detect it from the database. Earlier drafts of this plan exposed a separate `stash encrypt advance --to dual-writing` command to record the transition; that turned out to be over-modelling, since it only ever did meaningful work for one transition and the user had to know to invoke it.

Backfill now owns the bookmark. The first time backfill runs against a column, it requires explicit confirmation that the application is dual-writing:

- **Interactive (TTY)** — `p.confirm({ message: 'Has the dual-write code been deployed for users.email?' })`. On yes, the CLI appends a `dual_writing` event and proceeds.
- **Non-interactive** — the user must pass `--confirm-dual-writes-deployed`. The CLI prints a loud warning that the user is asserting the precondition, then proceeds.
- **Subsequent runs** — once `cs_migrations` has the `dual_writing` event for the column, the prompt and flag are skipped. Resume / re-run is friction-free.

If the user lies (says yes but dual-writes aren't actually live), rows inserted during the backfill land in plaintext only and the recovery is `stash encrypt backfill --force`, which drops the `<col>_encrypted IS NULL` guard and re-encrypts every row regardless of current state. Audit trail: the `force` run is recorded with `details.force = true` in `cs_migrations` so it shows up in `encrypt status` history as a distinct event.

### 5. `stash encrypt cutover` *(never shipped in this form; removed)*

> Nothing in this section exists. The command, the `cut-over` phase transition,
> and every `eql_v2.*` call below were removed with EQL v2. In EQL v3 the
> application moves to the encrypted column by name after backfill — no rename,
> no config promotion, no Proxy reload.

For each column in `backfilled` phase, in a single transaction:

```sql
BEGIN;
-- Renames <col> -> <col>_plaintext, <col>_encrypted -> <col>
SELECT eql_v2.rename_encrypted_columns();
-- Promote the pending config that was registered by the most recent
-- `stash db push` (which the user ran after switching the schema to
-- declare the encrypted column under its final name).
SELECT eql_v2.migrate_config();   -- pending → encrypting
SELECT eql_v2.activate_config();  -- encrypting → active (prior active → inactive)
COMMIT;

-- If Proxy URL is configured, force refresh
\c <proxy_url>
SELECT eql_v2.reload_config();
```

Record `cut_over` event. App's existing `SELECT email FROM users` returns the encrypted column post-cutover; reading code paths must decrypt via the encryption client (e.g. `decryptModel(rows[0], usersTable)` in Drizzle, or the equivalent `encryptedSupabase` wrapper in Supabase) so the call site receives plaintext. No write-path code change beyond removing the dual-write logic — that comes after cutover.

### 6. `stash encrypt drop`

> Shipped, but gated on `backfilled` (not `cut_over`, which no longer exists)
> and it drops the original `<col>`. It also re-verifies coverage under an
> `ACCESS EXCLUSIVE` lock inside the generated migration.

For columns in `cut_over` phase:

1. Read Drizzle / Prisma / other migration tooling from repo (we already detect this in init).
2. Emit a standard migration file (drizzle format by default): `ALTER TABLE <table> DROP COLUMN <col>_plaintext;`.
3. Print next-step instructions ("review and run `drizzle-kit generate && drizzle-kit migrate`" or equivalent).
4. Only record the `dropped` event *after* a follow-up `stash encrypt reconcile` verifies the column is gone from `information_schema.columns`.

## Critical files to modify or create

- `stack/packages/cli/src/commands/encrypt/` — **new command group** (parallel to `db/`)
  - `status.ts` — new
  - `plan.ts` — new (diffs intent vs. observed)
  - `backfill.ts` — new (also handles the dual-write confirmation + `--force` recovery path)
  - `cutover.ts` — new *(never shipped / removed)*
  - `drop.ts` — new
- `stack/packages/cli/src/bin/stash.ts` — register `encrypt` subcommand (analogous to existing `db` registration at ~line 237)
- `stack/packages/migrate/` — **new package** (library the CLI drives)
  - `src/state.ts` — `cs_migrations` DAO (append event, get latest, get progress)
  - `src/backfill.ts` — the chunked loop, exported as `runBackfill({ table, column, client, db, chunkSize, signal })`
  - `src/cursor.ts` — keyset pagination primitive
  - `src/eql.ts` — thin wrappers over `eql_v2.*` functions (rename, reload, config read) *(never shipped; `@cipherstash/migrate` has no `eql_v2` wrappers — see `src/version.ts` for the v3 domain classifier that replaced this idea)*
  - `src/manifest.ts` — read/write `.cipherstash/migrations.json`
  - `src/schema.sql` — `cs_migrations` DDL, installed by `db install` or an explicit `encrypt install` step *(`db install` is now `stash eql install`)*
- `stack/packages/cli/src/commands/db/install.ts` — extend to install `cs_migrations` schema alongside EQL *(moved: the installer is `commands/eql/install.ts`)*
- `stack/packages/cli/src/commands/init/lib/introspect.ts` — `introspectDatabase` lives here post-#395; `status.ts` reuses it via direct import
- `stack/packages/cli/src/config/` — extend `stash.config.ts` loader so backfill subprocess can dynamically import user's encryption client
- `stack/packages/cli/package.json` — add `@cipherstash/migrate` dep
- Top-level skills (`/skills/stash-encryption/SKILL.md`, `/skills/stash-{drizzle,supabase}/SKILL.md`) — **add** sections on the migration lifecycle and per-integration dual-write patterns so the agent handoff that `stash init` set up can apply Phase 2 code changes consistently. The skills are the canonical guidance source for agents post-#395.

## Existing primitives to reuse (do not reinvent)

- `@cipherstash/stack` `bulkEncryptModels`, `bulkDecryptModels`, `encryptModel`, `decryptModel` (at `packages/stack/src/encryption/operations/`). Bulk APIs do not chunk internally — our code chunks.
- `introspectDatabase` in `packages/cli/src/commands/init/lib/introspect.ts` (moved here from the old wizard package as part of the #395 init handoff work).
- `loadStashConfig` + dynamic encryption-client import lives at `packages/cli/src/config/`. Re-export from `@cipherstash/migrate` so library consumers don't need a hidden cross-package import.
- `rewriteEncryptedAlterColumns` in `packages/cli/src/commands/db/rewrite-migrations.ts` — the phase-1 schema-add is already solved by drizzle-kit + this rewriter. The new commands **will not** re-solve it.
- EQL functions (Postgres): `eql_v2.add_column`, `eql_v2.add_search_config`, `eql_v2.migrate_config`, `eql_v2.activate_config`, `eql_v2.rename_encrypted_columns`, `eql_v2.reload_config`, `eql_v2.count_encrypted_with_active_config`, `eql_v2.select_pending_columns`, `eql_v2.ready_for_encryption`. *(None of these are called any more — `stash` installs and drives EQL v3 only. EQL v3 needs no configuration table: the domain types carry the config.)*
- `db push` in `packages/cli/src/commands/db/push.ts` — already handles writing to `eql_v2_configuration`; reuse the DAO. *(Both the command and that file were deleted; there is no `packages/cli/src/commands/db/push.ts` to read.)*

## Verification

1. **Unit**
   - `cs_migrations` DAO: append event, latest-by-column, progress query.
   - Cursor pagination: exhausts all rows, handles gaps, stable under concurrent inserts (snapshot-based row count held at start).
   - Manifest reader: schema validation, drift detection.
2. **Integration (Drizzle, local Postgres)**
   - Seed 100k-row `users` table with plaintext `email`.
   - `stash db install` → EQL + `cs_migrations` installed. *(now `stash eql install`)*
   - Manually wire dual-write in the test app's insert code (simulates user + agent handoff).
   - `stash encrypt backfill --table users --column email` → interactive prompt confirms dual-writes are deployed, appends `dual_writing` event, runs to completion; progress output sane; `COUNT(*) WHERE email_encrypted IS NULL` = 0.
   - Same flow non-interactively: `--confirm-dual-writes-deployed` accepted, loud warning printed.
   - Kill mid-backfill (SIGINT) → re-run with `--resume` → completes without duplicate encryption; `cs_migrations` shows continuous cursor progression; no second `dual_writing` event.
   - `stash encrypt backfill --force` after manually corrupting an encrypted row → re-encrypts every row; `details.force = true` recorded in `cs_migrations`.
   - `stash encrypt status` → shows `backfilled`.
   - `stash encrypt cutover` → rename executes; app (still running, reads `email`) now gets decrypted ciphertext transparently. *(Removed. The v3 equivalent is a deploy: point the app at `email_encrypted` and decrypt through the encryption client.)*
   - `stash encrypt drop` → migration file emitted; apply; `email_plaintext` gone. *(Drops `email`, the original plaintext column.)*
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

> Two of these were later reversed by the move to EQL v3 — marked inline.

- Phase 1 runtime mode = Protect/Stack client-side only.
- Phase 4 default cutover mechanism = `eql_v2.rename_encrypted_columns()` (transparent to app code). *(Reversed: no cut-over mechanism at all.)*
- State store = repo manifest + `eql_v2_configuration` (EQL intent) + new `cs_migrations` table (runtime state). *(Reversed: EQL v3 carries intent in the column's domain type, so there is no configuration table.)*
- Phase 1 shipping scope = status + backfill first-class; other phases as thin wrappers.
- `cs_migrations` is CLI-owned for now, explicitly designed to be upstreamed into EQL as `eql_v2_migrations` in a later release so both Stack and Proxy own it jointly.
