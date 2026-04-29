---
'@cipherstash/cli': minor
'@cipherstash/migrate': minor
---

Add `stash encrypt` command group and `@cipherstash/migrate` library for plaintext → encrypted column migrations.

New CLI commands:

- `stash encrypt status` — per-column migration status (phase, backfill progress, drift between intent and state, EQL registration).
- `stash encrypt plan` — diff `.cipherstash/migrations.json` (intent) vs observed state.
- `stash encrypt advance --to <phase> --table <t> --column <c>` — record a phase transition (`schema-added` / `dual-writing` / `backfilling` / `backfilled` / `cut-over` / `dropped`).
- `stash encrypt backfill --table <t> --column <c>` — resumable, idempotent, chunked encryption of plaintext into `<col>_encrypted`. Uses the user's encryption client (Protect/Stack). SIGINT-safe; re-run to resume.
- `stash encrypt cutover --table <t> --column <c>` — runs `eql_v2.rename_encrypted_columns()` inside a transaction; optionally forces Proxy config refresh via `CIPHERSTASH_PROXY_URL`. After cutover, apps reading `<col>` transparently receive the encrypted column.
- `stash encrypt drop --table <t> --column <c>` — generates a migration file that drops the old plaintext column.

`stash db install` now also installs a `cipherstash.cs_migrations` table used to track per-column migration runtime state (current phase, backfill cursor, rows processed). The table is append-only (event-log shape) and kept separate from `eql_v2_configuration` which remains the authoritative EQL intent store used by Proxy.

The new `@cipherstash/migrate` package exposes the same primitives as a library for users who want to embed backfill in their own workers or cron jobs — all commands are thin wrappers around its exports (`runBackfill`, `appendEvent`, `latestByColumn`, `progress`, `renameEncryptedColumns`, `reloadConfig`, `readManifest`, `writeManifest`).
