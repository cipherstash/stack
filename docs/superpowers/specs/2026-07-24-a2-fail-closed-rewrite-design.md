# A-2 — fail-closed inversion for the encrypted ALTER COLUMN rewrite

**Date:** 2026-07-24
**Addresses:** A-2 in `.work/2026-07-24-eql-v2-removal-verification.md`
**Base:** `05b7bf07` (A-1/A-3 tokenizer fix)
**Affects:** `packages/cli/src/commands/db/rewrite-migrations.ts`, `packages/wizard/src/lib/rewrite-migrations.ts` (the same file twice)

## Problem

`rewriteEncryptedAlterColumns` rewrites an in-place `ALTER COLUMN … SET DATA TYPE
<encrypted domain>` into an ADD + DROP + RENAME sequence. That sequence is
equivalent to DROP + ADD: it fixes the column's type but destroys its contents.

The sweep decides whether to rewrite by consulting a corpus-wide index of columns
the migrations give an *encrypted* type (`indexEncryptedColumns`). A column found
there is skipped as `already-encrypted`, because dropping it would destroy
ciphertext with no plaintext left to backfill from. **Everything else is
rewritten** — including a column the corpus never mentions at all.

That default is fail-open. A column absent from the index is not known to be
plaintext; it is simply unknown. Two reproduced triggers, both from the
verification doc:

- **(a) Lone ALTER, no source declaration.** The corpus contains the ALTER and
  nothing that declares the column. Rewritten today: 1 live `DROP COLUMN`.
- **(b) Cross-directory split.** The declaration lives in `drizzle/` and the
  ALTER in `migrations/`. The index is built per directory, so the sweep of
  `migrations/` never sees the declaration. Rewritten today: 1 live `DROP
  COLUMN` — and the dropped column is already typed `eql_v3_text_eq`, i.e.
  ciphertext.

Trigger (b) is not contrived. `post-agent.ts:163` ships with
`DRIZZLE_OUT_DIRS = ['drizzle', 'migrations', 'src/db/migrations']`, so scanning
multiple directories with a per-directory index *is* the default configuration.

## Decision

Invert the default. Rewrite only a column the corpus positively declares and does
not give an encrypted type. Anything unknown is skipped and reported.

Two alternatives were considered and rejected:

- **Widen the index across directories** (build one corpus index in
  `sweepMigrationDirs` and pass it into each per-directory rewrite). Fixes (b)
  with a sharper `already-encrypted` message, but unioning unrelated migration
  histories can over-detect *plaintext*, which is itself fail-open. Rejected:
  fail-closed already makes (b) safe, and this trades a better message for a new
  fail-open surface.
- **Require the declaration in the same file.** A column created in
  `0001_init.sql` and altered in `0007_encrypt.sql` is the normal case, so this
  would stop rewriting anything.

## Mechanism

The encrypted side is already precise: it matches against the known domain list
in `ENCRYPTED_DOMAIN`. So "plaintext" needs no type classification — it is the
residue. A column the corpus **declares** but that is not in the encrypted set is
plaintext.

That turns "what type is this column?" (a SQL parse) into "does a declaration for
this column exist?" (a name match in a position the code already isolates). No
comma splitting, no paren-depth tracking, no quote state machine.

`indexEncryptedColumns` becomes `indexColumnDeclarations`, one traversal
returning `{ encrypted, declared }`. `encrypted` is populated exactly as today —
the existing broad scan is deliberately over-detecting and must not regress.
`declared` is populated from two positions:

1. **Inside a `CREATE TABLE` body**, already captured as group 3 of
   `CREATE_TABLE_RE`: scan `"([^"]+)"\s+["a-z]` for declared names.
2. **`ALTER TABLE … ADD COLUMN "col" <type>`**: generalise
   `ADD_ENCRYPTED_COLUMN_RE` to accept any type with the same tail.

`RENAME COLUMN "a" TO "b"` propagates `declared` the way it already propagates
`encrypted`.

The `\s+["a-z]` tail is what makes the name match a declaration rather than a
mention. A type token always begins with a letter or a double quote, so
`"email" text` and `"email" "public"."eql_v3_text_search"` match, while these do
not — the name is followed by `)`, `,` or an operator:

```sql
PRIMARY KEY ("id", "name")
FOREIGN KEY ("org_id") REFERENCES "orgs"("id")
CHECK ("age" > 0)
UNIQUE("email")
```

**The scan must stay anchored to those two positions.** A whole-file scan would
let `ALTER COLUMN "email" SET DATA TYPE …` match its own `"email" SET` and
declare the very column it is asking about — a self-fulfilling fail-open.

**Known false positive, accepted.** In
`CONSTRAINT "users_email_unique" UNIQUE("email")` the constraint *name* is
followed by whitespace and a letter, so it registers as a declared column. It is
inert unless a constraint name exactly equals the name of a column that is also
encrypted and undeclared; drizzle's `<table>_<col>_unique` convention makes that
contrived. Documented in the docstring rather than engineered around.

**Corpus-wide, not migration-ordered.** As with the existing encrypted index, a
declaration in a *later* migration than the ALTER still counts. This is a
pre-existing property, not introduced here.

### Decision order in the rewrite callback

Unchanged first step, two steps after it:

1. `isInsideCommentOrString(original, offset)` → return the match untouched.
2. In `encrypted` → `skip(…, 'already-encrypted')`.
3. Not in `declared` → `skip(…, 'source-unknown')`.
4. Otherwise rewrite.

Step 2 must precede step 3 so a column that is both declared and encrypted — the
output of a previous sweep, which emits `ADD COLUMN <tmp> <encrypted>` plus
`RENAME <tmp> TO <col>` — still reports `already-encrypted`, the more specific
and more actionable reason.

`isInsideCommentOrString` is not touched: it is the subject of A-1/A-3, already
landed in the base commit.

## Skip reason

`SkipReason` gains `'source-unknown'`. `describeSkipReason` has no `default` arm,
so the compiler forces the new arm to be written. All three consumers
(`install.ts:660`, `eql/migration.ts:248`, `post-agent.ts:192`) render
`describeSkipReason(reason)` verbatim and need no edit.

The text names both causes, because the user's remedy differs:

> the sweep could not find where this column was declared in this migration
> directory, so it cannot tell a plaintext column (safe to rewrite) from one that
> already holds ciphertext (where the rewrite would DROP it). Usually the
> column's `CREATE TABLE` / `ADD COLUMN` lives in a different directory, or the
> migration history was squashed. Check the column's current type in the
> database: if it is plaintext and the table is empty, apply the
> ADD/DROP/RENAME by hand; if it already holds ciphertext, use the staged
> `stash encrypt` lifecycle instead

## Blast radius

This is a behaviour change for correct corpora, not only for the bug. Any project
whose swept directory does not contain the column's declaration — squashed
migrations, a baseline pulled with `drizzle-kit pull`, a schema bootstrapped from
a hand-written SQL file — stops being rewritten and starts being flagged for
review. That is the trade being bought, and it is the correct direction: the cost
of a false skip is a statement the user fixes by hand, and the cost of a false
rewrite is irrecoverable data.

## Testing

Most existing tests in both files use a bare ALTER with no `CREATE` anywhere and
assert a rewrite; under the inversion they would all become `source-unknown`.
Rather than rewrite each fixture, add a helper that writes a `0000_init.sql`
declaring the plaintext source column. It sorts first and is never rewritten, so
`rewritten`/`skipped` assertions stay as they are and the diff is one line per
test.

New cases, in **both** test files:

- Lone ALTER, no declaration anywhere → `skipped` with `source-unknown`, file
  unchanged on disk, zero `DROP COLUMN`.
- Declaration in a sibling file in the same directory → rewritten (the
  non-regression case).
- Declaration living in the `options.skip` file → still counts as declared.
- `RENAME COLUMN` propagates declared-ness from the original name.
- A column named only inside `PRIMARY KEY (…)` / `REFERENCES "t"("col")` →
  **not** declared, so `source-unknown`.
- A column that is both declared and encrypted → still `already-encrypted`, not
  `source-unknown` (pins the ordering of steps 2 and 3).

Wizard file only:

- The cross-directory split from the verification doc, driven through
  `sweepMigrationDirs`: encrypted declaration in `drizzle/`, ALTER in
  `migrations/` → `source-unknown`, zero `DROP COLUMN` in the output.

## Dual-copy sync

The two files are the same file twice, differing only in the wizard's
`sweepMigrationDirs` / `DirRewriteResult`, its attribution string
(`@cipherstash/wizard` vs `stash`), and a few comment blocks. Apply one fix
twice, then diff the two whitespace-normalised files to confirm nothing new
diverged.

## Docs and changeset

- `skills/stash-cli/SKILL.md:393` and `skills/stash-drizzle/SKILL.md:64` both
  state that each such statement is rewritten. Both need the qualifier that the
  rewrite now requires the column's declaration to be present in the swept
  directory, and otherwise flags the statement for review.
- Extend `.changeset/rewriter-never-drops-ciphertext.md` rather than adding a
  second changeset: it already ships the sibling `already-encrypted` behaviour
  for the same component in the same release, and two changesets would describe
  overlapping behaviour. Both `stash` and `@cipherstash/wizard` are already
  listed.

## Out of scope

- Any change to `isInsideCommentOrString` (A-1/A-3, landed in the base commit).
- Sharing a corpus index across directories in `sweepMigrationDirs` (rejected
  above).
- The near-miss scan (`NEAR_MISS_RE`) and its `unrecognised-form` reason, which
  are unaffected.
