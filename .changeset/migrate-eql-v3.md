---
'@cipherstash/migrate': minor
'stash': minor
---

EQL v3 support for the encryption rollout lifecycle (#648). The `stash
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
