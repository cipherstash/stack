---
'@cipherstash/prisma-next': minor
---

Source the EQL v3 install SQL from `@cipherstash/eql` at runtime instead of
baking it into the baseline migration.

`@cipherstash/eql` is now a runtime dependency (`^3.0.0`). The v3 baseline
migration no longer embeds the ~1.7 MB install bundle in its `ops.json`; the
committed op carries a placeholder, and the extension descriptor injects
`readInstallSql()` from the installed `@cipherstash/eql` when it is built. As a
result, a `@cipherstash/eql` patch or minor release flows through to
`prisma-next migration apply` via normal dependency resolution — it no longer
requires re-emitting the migration and cutting a new `@cipherstash/prisma-next`
release. This mirrors how the `stash` CLI already sources the v3 SQL.

No change to user-facing behaviour: EQL still installs as part of
`prisma-next migration apply`. Safe because the v3 baseline is an
invariant-only self-edge — the install SQL never contributes to the
contract-space hash.
