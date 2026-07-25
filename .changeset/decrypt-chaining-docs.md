---
'stash': patch
'@cipherstash/stack': patch
---

Correct the shipped documentation for `decryptModel` / `bulkDecryptModels`.

Three places in `skills/stash-encryption` and four in `packages/stack/README.md`
said these return "a plain `Promise<Result<...>>` (not a chainable operation)"
and that there is therefore "no `.withLockContext()` to chain". They return an
`AuditableDecryptModelOperation`, which is thenable and carries both
`.withLockContext()` and `.audit()` — the same `.audit()` chain the
audit-on-decrypt work advertises. The skill contradicted itself: its own
reference table already listed the correct return type.

The skill ships inside the `stash` tarball and `installSkills()` copies it into
customer repos, so this was steering agents away from an API that exists. The
README ships in the `@cipherstash/stack` tarball.

The equivalent statement about the **WASM entry** is correct and unchanged —
`@cipherstash/stack/wasm-inline` really does return a plain promise from decrypt,
with no lock-context argument.

Also fixes the setup prompt `stash init` writes for coding agents, which
referenced `protectOps.eq` — an API that does not exist anywhere in the repo.
The operators come from `createEncryptionOperators(client)`, conventionally
bound to `ops`.
