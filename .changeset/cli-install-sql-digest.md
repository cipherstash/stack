---
'stash': patch
---

Verify the EQL install SQL against its release digest before running it.

`stash eql install` reads the EQL v3 bundle from the resolved
`@cipherstash/eql` in your `node_modules` and executes it against your
database. That read was a bare `readFileSync` — nothing checked that the bytes
on disk were the bundle the resolved release actually ships. A corrupt,
partially-updated, or tampered package installed silently: the database ended
up carrying SQL the version it reports does not define, and the CLI printed
"EQL extensions installed."

The CLI now hashes the bundle and compares it to `installSqlSha256` from the
release manifest that ships alongside it, and **refuses** on a mismatch. The
error names the expected digest, the actual digest, the resolved file path and
the EQL version, so the remedy is visible rather than inferred. Verification
happens before any database connection is opened, so a refusal means nothing
was attempted — not that something was rolled back.

The check covers all three paths that read the bundle: `stash eql install`,
the SQL embedded by `stash eql migration --drizzle` / `--supabase`, and the
expected-surface baseline `stash eql verify` compares your database against.
`@cipherstash/stack-prisma` has verified against this same digest since its v3
migrations landed; this brings the CLI in line.

No healthy install is affected — the SQL and its manifest are produced by the
same build of `@cipherstash/eql`, so a mismatch only ever means a broken
dependency tree.

`skills/stash-cli` documents the new pre-flight alongside the existing
post-install surface check, so an agent reading it does not report a digest
refusal as a failed install.
