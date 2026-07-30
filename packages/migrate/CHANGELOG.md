# @cipherstash/migrate

## 1.0.0

### Major Changes

- 19cff11: Remove the remaining EQL v2 installation and rollout surface. CLI installs,
  upgrades, backfills, and drops now mutate EQL v3 state only, while legacy v2
  status diagnostics and migration-manifest compatibility remain read-only.

### Minor Changes

- 1b8cac2: Add `columnExists(client, tableName, columnName)` — a case-exact "does this
  column exist at all?" catalog probe, distinct from `detectColumnEqlVersion`'s
  "and is it an EQL column?".

  Callers need that difference to tell a STALE column reference (it is gone) from
  a live one the domain classifier simply does not recognise — most often a legacy
  `eql_v2_encrypted` counterpart.

  `stash encrypt drop` had a private copy of this probe built on a bare
  `to_regclass($1)`. That form _parses_ its argument and case-folds unquoted
  identifiers, so on a Prisma-style `"User"` table it resolved `user`, reported the
  column missing, and treated a valid recorded pairing as stale — silently skipping
  the fail-closed that stops the command acting on a guessed encrypted column.
  The shared implementation quotes with `format('%I')` first, like every other
  catalog probe in this package, so the lookup is case-exact while still honouring
  `search_path` for unqualified names.

- 3a86939: EQL v3 support for the encryption rollout lifecycle (#648). The `stash
encrypt *` commands (and `@cipherstash/migrate` underneath) now resolve a
  column's EQL version and its encrypted counterpart from the **Postgres domain
  types** — the EQL v3 types are self-describing, so the `<col>_encrypted`
  naming is a convention only, never enforced or relied upon — and follow the
  right lifecycle, no new flags:

  - **`encrypt backfill`** works on v3 columns unchanged (the engine was always
    version-agnostic; pass an `Encryption` client and real v3 envelopes land
    in the concrete `eql_v3_*` domain column — verified live against a real
    database, including the domain CHECK and a decrypt round-trip). The
    manifest records the detected version, the encrypted column's name, and the
    v3 target phase, and the command prints v3-appropriate next steps.
  - **`encrypt drop`** is version-aware: v3 runs from the `backfilled` phase,
    **verifies live coverage** (refuses to generate the migration while any row
    still has the plaintext set and the encrypted column NULL — the
    `countUnencrypted` check), and drops the ORIGINAL plaintext column (there
    is no `<col>_plaintext` under v3). The generated
    v3 migration **re-verifies coverage at apply time** — it locks the table,
    re-counts, and aborts without dropping if plaintext-only rows appeared
    after generation. And because dropping is the one irreversible step, it
    requires a positively asserted plaintext↔ciphertext pairing (the
    manifest's recorded `encryptedColumn` or the naming convention): a match
    found only by being the table's sole EQL column is refused with
    instructions, and an ambiguous table (several EQL columns, none
    identifiable) fails closed listing the candidates.
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
  - Fixed: `encrypt drop` precondition failures now actually exit 1 — the
    early-return guards previously skipped the exit-code path entirely, so failed
    preconditions exited 0. Scripted pipelines that relied on the erroneous exit 0
    will now see the documented exit 1.

  The `stash-cli` and `stash-encryption` skills and the `@cipherstash/migrate`
  README document the v3 lifecycle: backfill → switch the application to the
  encrypted column by name → drop the plaintext column.

- 4471471: Drop EQL v2 from the domain-type classifier. `classifyEqlDomain` (and the
  `detectColumnEqlVersion` / `listEncryptedColumns` / `resolveEncryptedColumn`
  resolution built on it) no longer recognise the legacy `eql_v2_encrypted`
  domain — v3 is the sole generation this workspace authors and backfills, so a
  column's version is now determined solely from its self-describing `eql_v3_*`
  domain type. A legacy v2 column's version is carried by the manifest's recorded
  `eqlVersion` instead (the CLI's `encrypt status` / `status` renderers already
  fall back to it), so status output is unchanged for v2 columns already recorded
  in `.cipherstash/migrations.json`. A v2 column backfilled from here on records
  no `eqlVersion` and so reports no version in `stash encrypt status` — the v2
  lifecycle itself (cut-over, then dropping `<column>_plaintext`) is unaffected.

  This removes v2 _classification_, not the v2 read path: existing v2 ciphertext
  remains decryptable through `@cipherstash/stack`. `EqlVersion` keeps its `2`
  member for manifest-sourced legacy values; the exported function signatures are
  unchanged.

### Patch Changes

- a5fab3c: Correct shipped documentation that claimed the tooling detects a column's EQL
  **v2** generation. It does not, and has not since `classifyEqlDomain` dropped v2:
  detection is one-sided — a `public.eql_v3_*` Postgres domain classifies as **v3**,
  and anything else (a plaintext column, or a legacy `eql_v2_encrypted` one)
  classifies as _unknown_ and falls through to the **v2** lifecycle. The v2 path is
  reached by fallback, not by detection, and a v2 column records no `eqlVersion` in
  `.cipherstash/migrations.json`, so `stash encrypt status` reports no version for
  it.

  - `skills/stash-supabase/SKILL.md` said the CLI "still auto-detects a v2 column"
    (twice, once inside the "Stay on v2 for now" bullet — exactly the case it got
    wrong) and that `stash encrypt drop` picks its target from a version the CLI
    "auto-detects". All three now describe the one-sided rule, matching the correct
    wording already in the same file's EQL version note. This skill is copied into
    customer repos by `stash init`, so the wrong version of it was being installed
    as guidance.
  - `packages/migrate/README.md` documented `detectColumnEqlVersion(client, table,
column)` as returning `2`, `3`, or `null`. It cannot return `2` — the return
    type is now stated as `3` or `null`, with what a `null` means for the caller.
    The lifecycle intro no longer presents the v2 ladder as a detection result.
  - `packages/stack/README.md`'s Supabase example imported and called
    `encryptedSupabaseV3`, the `@deprecated` alias, contradicting the same file's
    package table and v3-only note. It now uses `encryptedSupabase`.

  Documentation only — no behaviour change.

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
