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
Every step naming an integration-specific API now branches on the project's
actual integration, instead of naming Drizzle's and Supabase's and leaving the
other two to guess:

- **Query paths.** `createEncryptionOperators(client)` (conventionally `ops`)
  for Drizzle, the `encryptedSupabase` wrapper's own filters for Supabase, the
  `eql*` column operators for Prisma Next, and `client.encryptQuery(...)` for a
  plain Postgres project.
- **Schema authoring.** The `types.*` column factories for Drizzle, the
  `eql_v3_encrypted` domain in migration SQL for Supabase, the `cipherstash.*`
  field constructors in `schema.prisma` for Prisma Next, and `encryptedTable`
  for plain Postgres. Prisma Next was previously sent at `types.*` /
  `encryptedTable` — the client `stash schema build` explicitly refuses to
  scaffold for that integration.
- **Read paths.** `decryptModel(row, usersSchema)` where that applies, and the
  wrapper's transparent decryption where it does not.
- **Skill pointers.** A plain Postgres project installs no integration-specific
  skill, so each "see the integration skill" was a pointer at a file that was
  never written. Those now point at `stash-encryption`, which it does get.

`client.encryptQuery` is also shown taking the schema objects themselves
(`{ table: usersSchema, column: usersSchema.email }`) rather than an
object-shorthand that read as three required strings — `queryType` is inferred
from the column's configured indexes.

The cutover and complete-rollout **plan templates** now split EQL v3 from v2.
Both described the v2 rename swap (`<col>` → `<col>_plaintext`, twin → `<col>`)
as the only cutover path, so on the default v3 install `stash plan` drafted a
plan built around `stash encrypt cutover` — a command that refuses v3 columns
outright ("there is no rename step") and refuses entirely on a v3-only
database, where `eql_v2_configuration` does not exist. The implement prompt
already carried this split; the plan templates did not. The version is
per-column, so the templates tell the agent to establish it per column rather
than deciding once for the whole plan.

The "already encrypted" stop-and-ask now recognises `eql_v3_*` domains
alongside the legacy `eql_v2_encrypted` udt, so it can fire on the default
path at all.

**`stash init` now detects already-encrypted columns on EQL v3.** Database
introspection marked a column as CipherStash-managed only when its udt was
exactly `eql_v2_encrypted`. v3 columns carry per-domain types
(`eql_v3_text_search`, `eql_v3_integer_ord`, …), so on the default path every
encrypted column was reported as plaintext — shown with its `dataType` and left
unticked in the column picker, inviting a re-run to encrypt it a second time.
The picker also labelled any encrypted column with the literal string
`eql_v2_encrypted`; it now shows the column's real domain.
