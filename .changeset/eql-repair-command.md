---
'stash': minor
'@cipherstash/wizard': patch
---

Add `stash eql repair --drizzle` — repair a migration directory that `drizzle-kit
generate` filled with an un-runnable in-place `ALTER COLUMN … SET DATA TYPE
<eql_v3_*>`, without generating anything (cipherstash/stack#710).

```bash
stash eql repair --drizzle                        # sweep drizzle/
stash eql repair --drizzle --dry-run              # preview; writes nothing
stash eql repair --drizzle --database-url …       # leave applied migrations alone
```

Until now the only way to run that sweep was `stash eql migration --drizzle`,
which generates a redundant EQL install migration as a side effect purely to
trigger it — the sweep runs before `drizzle-kit generate` has emitted the broken
statement, so recovery meant creating a migration you did not want. `eql repair`
runs the same rewriter and prints the same report (both commands now share one
reporting path, so the two surfaces cannot drift).

**New: applied-migration awareness.** The sweep has always been unfiltered. That
is harmless for almost every match, because an ALTER to an EQL domain cannot run
— so the migration failed and was never applied. The exception is a `jsonb`
column changed to an EQL domain on an empty table, which applies successfully;
rewriting it afterwards leaves the `.sql` describing a shape the database never
got from it, and a fresh CI or staging database replaying the rewritten file
diverges from the original, silently.

`eql repair` therefore reads `meta/_journal.json` offline and, given
`--database-url` (or `DATABASE_URL`), the latest `created_at` in
`drizzle.__drizzle_migrations`. A migration is applied when its journal `when` is
at or below that watermark — the same timestamp comparison `drizzle-kit migrate`
makes, hashes being written but never compared. Applied migrations are reported
as their own outcome, left untouched, and the command exits non-zero. Without a
database URL the repair proceeds and warns that applied state could not be
verified; if the check is requested but cannot run, nothing is rewritten.

`rewriteEncryptedAlterColumns` gained `dryRun`, and its `skip` option now accepts
several paths as well as one. The wizard's copy of the rewriter carries the same
change so the two stay in sync; its own sweep is unaffected.
