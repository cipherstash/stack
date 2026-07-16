---
'@cipherstash/migrate': minor
'stash': minor
---

EQL v3 support for the encryption rollout lifecycle (#648). The `stash
encrypt *` commands (and `@cipherstash/migrate` underneath) now auto-detect a
column's EQL version from its Postgres domain type and follow the right
lifecycle — no new flags:

- **`encrypt backfill`** works on v3 columns unchanged (the engine was always
  version-agnostic; pass an `EncryptionV3` client and real v3 envelopes land
  in the concrete `eql_v3_*` domain column — verified live against a real
  database, including the domain CHECK and a decrypt round-trip). The
  manifest records the detected version and the v3 target phase, and the
  command prints v3-appropriate next steps.
- **`encrypt cutover`** on a v3 column reports "not applicable" (exit 0) with
  guidance: v3 has no rename cut-over — the application switches to
  `<col>_encrypted` by name.
- **`encrypt drop`** is version-aware: v3 runs from the `backfilled` phase
  and drops the ORIGINAL plaintext column (there is no `<col>_plaintext`
  under v3); v2 behaviour is unchanged.
- **`encrypt status`** no longer raises the v2-only `not-registered` /
  `plaintext-col-missing` drift flags for v3 columns (v3 has no
  `eql_v2_configuration` and no rename) and shows `v3` in the EQL column.
- New `@cipherstash/migrate` exports: `countEncrypted` (the v3
  backfill-verification primitive) and a manifest `eqlVersion` field.
- Fixed: `encrypt cutover`/`encrypt drop` precondition failures now actually
  exit 1 — the early-return guards previously skipped the exit-code path
  entirely, so failed preconditions exited 0.

The `stash-cli` and `stash-encryption` skills and the `@cipherstash/migrate`
README document the two lifecycles (v2: backfill → cutover → drop;
v3: backfill → switch-by-name → drop).
