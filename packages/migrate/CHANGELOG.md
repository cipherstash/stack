# @cipherstash/migrate

## 1.0.0-rc.1

### Minor Changes

- 3a86939: EQL v3 support for the encryption rollout lifecycle (#648). The `stash
encrypt *` commands (and `@cipherstash/migrate` underneath) now resolve a
  column's EQL version and its encrypted counterpart from the **Postgres domain
  types** — the EQL v3 types are self-describing, so the `<col>_encrypted`
  naming is a convention only, never enforced or relied upon — and follow the
  right lifecycle, no new flags:

  - **`encrypt backfill`** works on v3 columns unchanged (the engine was always
    version-agnostic; pass an `EncryptionV3` client and real v3 envelopes land
    in the concrete `eql_v3_*` domain column — verified live against a real
    database, including the domain CHECK and a decrypt round-trip). The
    manifest records the detected version, the encrypted column's name, and the
    v3 target phase, and the command prints v3-appropriate next steps.
  - **`encrypt cutover`** on a backfilled v3 column reports "not applicable"
    (exit 0) with guidance: v3 has no rename cut-over — the application
    switches to the encrypted column by name. Before backfill completes it
    exits 1 and says to finish the backfill instead of instructing the switch.
    On a database with no `eql_v2_configuration` table (a v3-only install) the
    v2 path now explains that instead of surfacing a raw Postgres error.
  - **`encrypt drop`** is version-aware: v3 runs from the `backfilled` phase,
    **verifies live coverage** (refuses to generate the migration while any row
    still has the plaintext set and the encrypted column NULL — the
    `countUnencrypted` check), and drops the ORIGINAL plaintext column (there
    is no `<col>_plaintext` under v3); v2 behaviour is unchanged. The generated
    v3 migration **re-verifies coverage at apply time** — it locks the table,
    re-counts, and aborts without dropping if plaintext-only rows appeared
    after generation. And because dropping is the one irreversible step, it
    requires a positively asserted plaintext↔ciphertext pairing (the
    manifest's recorded `encryptedColumn` or the naming convention): a match
    found only by being the table's sole EQL column is refused with
    instructions, and an ambiguous table (several EQL columns, none
    identifiable) fails closed listing the candidates — as does `cutover`.
  - **`encrypt status`** classifies each column from the observed domain type
    (manifest as fallback), shows `v3` in the EQL column, and no longer raises
    the v2-only `not-registered` / `plaintext-col-missing` drift flags for v3
    columns. `stash status`'s quest ladder and the `stash init` agent handoff
    prompt teach the version-appropriate next step (no more "run cutover" on
    v3 columns).
  - New `@cipherstash/migrate` exports: `classifyEqlDomain`,
    `resolveEncryptedColumn`, `pickEncryptedColumn`, `listEncryptedColumns`
    (domain-type resolution — case-exact for quoted/mixed-case table names),
    `countEncrypted` / `countUnencrypted` (coverage counts), and manifest
    `eqlVersion` + `encryptedColumn` fields. `EqlVersion` is numeric (`2 | 3`),
    matching the manifest and the installer. Resolved columns carry `via:
'hint' | 'convention' | 'sole'` so callers can tell a positively asserted
    pairing from a by-elimination guess.
  - Fixed: `encrypt cutover`/`encrypt drop` precondition failures now actually
    exit 1 — the early-return guards previously skipped the exit-code path
    entirely, so failed preconditions exited 0. (This also applies to v2
    preconditions: scripted pipelines that relied on the erroneous exit 0 will
    now see the documented exit 1.)

  The `stash-cli` and `stash-encryption` skills and the `@cipherstash/migrate`
  README document the two lifecycles (v2: backfill → cutover → drop;
  v3: backfill → switch-by-name → drop).

## 1.0.0-rc.0

### Patch Changes

- Updated dependencies [31ca318]
- Updated dependencies [c4787c0]
- Updated dependencies [66a0e02]
- Updated dependencies [cfd46ee]
- Updated dependencies [7eba32d]
- Updated dependencies [0ebf57e]
- Updated dependencies [d73a03c]
- Updated dependencies [89b903f]
- Updated dependencies [229ce59]
- Updated dependencies [50c0a9c]
- Updated dependencies [63ca540]
- Updated dependencies [5d23e80]
- Updated dependencies [1aa9a11]
- Updated dependencies [af2d04e]
- Updated dependencies [b8a3d20]
- Updated dependencies [a0f3b2c]
- Updated dependencies [f23f952]
- Updated dependencies [7c7dbca]
- Updated dependencies [5411a13]
- Updated dependencies [99f8b0a]
- Updated dependencies [fd33aad]
- Updated dependencies [8cd485d]
- Updated dependencies [9b65ae8]
  - @cipherstash/stack@1.0.0-rc.0

## 0.2.0

### Minor Changes

- add4357: Add `stash encrypt` command group and `@cipherstash/migrate` library for plaintext → encrypted column migrations.

  New CLI commands:

  - `stash encrypt status` — per-column migration status (phase, backfill progress, drift between intent and state, EQL registration).
  - `stash encrypt plan` — diff `.cipherstash/migrations.json` (intent) vs observed state.
  - `stash encrypt backfill --table <t> --column <c>` — resumable, idempotent, chunked encryption of plaintext into `<col>_encrypted`. Uses the user's encryption client (Protect/Stack). SIGINT-safe; re-run to resume. The first run on a column prompts to confirm dual-writes are deployed (or accept `--confirm-dual-writes-deployed` for non-interactive contexts), records the `dual_writing` transition in `cs_migrations`, then runs the chunked encryption loop. `--force` re-encrypts every plaintext row regardless of current state — recovery path for drift caused by an earlier backfill running before dual-writes were actually live.
  - `stash encrypt cutover --table <t> --column <c>` — runs `eql_v2.rename_encrypted_columns()` inside a transaction; optionally forces Proxy config refresh via `CIPHERSTASH_PROXY_URL`. After cutover, apps reading `<col>` transparently receive the encrypted column.
  - `stash encrypt drop --table <t> --column <c>` — generates a migration file that drops the old plaintext column.

  `stash db install` now also installs a `cipherstash.cs_migrations` table used to track per-column migration runtime state (current phase, backfill cursor, rows processed). The table is append-only (event-log shape) and kept separate from `eql_v2_configuration` which remains the authoritative EQL intent store used by Proxy.

  The new `@cipherstash/migrate` package exposes the same primitives as a library for users who want to embed backfill in their own workers or cron jobs — all commands are thin wrappers around its exports (`runBackfill`, `appendEvent`, `latestByColumn`, `progress`, `renameEncryptedColumns`, `reloadConfig`, `readManifest`, `writeManifest`).
