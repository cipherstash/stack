---
'@cipherstash/prisma-next': minor
---

Source the EQL v3 install SQL from `@cipherstash/eql` at runtime instead of
baking it into the baseline migration.

`@cipherstash/eql` is now a runtime dependency, pinned exact (`3.0.0`) to match
the release `@cipherstash/stack` encodes its v3 domain **types** against — the
two must move together, so an EQL upgrade is a coordinated version bump, not a
float. The v3 baseline migration no longer embeds the ~1.7 MB install bundle in
its `ops.json`: the committed op carries a placeholder, and the extension
descriptor injects `readInstallSql()` from the installed `@cipherstash/eql` when
it is built.

The win over baking: bumping the pinned `@cipherstash/eql` no longer requires
re-running the maintainer emit loop to regenerate a 1.7 MB `ops.json` — it is a
one-line version bump plus a rebuild. This mirrors how the `stash` CLI already
sources the v3 SQL.

No change to user-facing behaviour: EQL still installs as part of
`prisma-next migration apply`. Safe because the v3 baseline is an
invariant-only self-edge — the install SQL never contributes to the
contract-space hash. Injection matches the placeholder by value and fails loudly
if it is absent, so a drift between the emit source and the injector can never
silently ship an empty install.
