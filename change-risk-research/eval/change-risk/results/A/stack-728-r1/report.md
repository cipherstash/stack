## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `48889952ec..8dcbf05390`

The stash CLI's Drizzle migration rewriter now matches the whole eql_v3_* domain family (plus schema-qualified tables) as well as eql_v2_encrypted, and `stash eql migration --drizzle` (the v3 path) now runs the sweep that `eql install --drizzle` already ran. Any sibling migration with an in-place `ALTER COLUMN ... SET DATA TYPE <eql domain>` is rewritten on disk, without prompting, into ADD + DROP COLUMN + RENAME. That sequence runs successfully and destroys the column's data on a populated table. Before this change the same v3 statement failed loudly in Postgres. The only safeguards are SQL comments and a CLI log line. The strict matcher also ignores the source type, so an encrypted-to-encrypted change (v2 to v3, or one v3 domain to another) is rewritten to drop the ciphertext column. No test covers that case. Unit tests for the regex and sweep were extended but not run here, because there are no node_modules and no CI results. Impact is high. A material data-loss scenario has no in-SQL guard, so changes or verification are required.

### Failure scenarios

**FS-1 · v3 plaintext→encrypted migration that used to fail loudly now runs and drops populated column data** (high impact, plausible)

- Trigger: A v3 user changes an existing plaintext column on a table that has rows to an eql_v3_* type, runs drizzle-kit generate and then `stash eql migration --drizzle`, then runs drizzle-kit migrate against staging or production.
- Mechanism: At base, migration.ts has no sweep (E-2), and the base regex does not match eql_v3_* (E-5), so Postgres rejects the generated ALTER at migrate time and no data is lost. At head, the sweep runs automatically without confirmation (E-1). It rewrites the file into ADD tmp; DROP COLUMN original; RENAME (E-6), which runs successfully. The only safeguards are SQL comments and an info log line, which flows straight into the 'Run drizzle-kit migrate' note (E-10). The emitted SQL has no guard that would abort on a non-empty table.
- Consequence: The plaintext column is dropped and replaced with an all-NULL encrypted column, along with any NOT NULL, DEFAULT or index definitions. The data is recoverable only from a backup. A loud migration failure becomes silent, irreversible data loss.
- Affects: `stash eql migration --drizzle` (packages/cli/src/commands/eql/migration.ts), packages/cli rewrite-migrations (rewriteEncryptedAlterColumns), Customer Drizzle migration files and the databases they are applied to
- Evidence: `packages/cli/src/commands/eql/migration.ts:227-232`; `packages/cli/src/commands/eql/migration.ts:214` (base); `packages/cli/src/commands/db/rewrite-migrations.ts:21-22` (base); `packages/cli/src/commands/db/rewrite-migrations.ts:217-244`; `packages/cli/src/commands/eql/migration.ts:257-264`
- Existing verification: migration.test.ts asserts that the sweep rewrites a v3 sibling into ADD COLUMN and removes SET DATA TYPE. This tests that the rewrite happens, not that a populated table is protected. [exists_not_run]
- Missing verification: No test or integration check that the rewritten SQL refuses to run on a non-empty table.; No user confirmation or opt-in before the CLI edits sibling migration files on disk.
- Mitigation: Emit a guard before the DROP in the rewritten SQL so a populated table fails loudly, for example `DO $$ BEGIN IF EXISTS (SELECT 1 FROM <table>) THEN RAISE EXCEPTION '...use stash encrypt...'; END IF; END $$;`. Alternatively, make the v3 sweep opt-in or ask for confirmation before writing files.

**FS-2 · Encrypted→encrypted type change (v2→v3 or v3 domain swap) rewritten into a DROP of the ciphertext column** (high impact, plausible)

- Trigger: A user migrates a column from eql_v2_encrypted to an eql_v3_* domain, or switches between v3 domains (for example eql_v3_text_search to eql_v3_text_search_ore), and drizzle-kit emits an in-place SET DATA TYPE for the new type.
- Mechanism: ALTER_COLUMN_TO_ENCRYPTED_RE only inspects the target type and assumes the source is plaintext (E-4). Every target that matches eql_v3_[a-z0-9_]+ is rewritten to ADD/DROP/RENAME (E-6). At base, a v3 target did not match (E-5), so the statement went to Postgres unchanged. A v3→v3 change, where both domains are over jsonb (E-13), could then convert in place or fail its CHECK loudly. A v2→v3 change failed loudly. At head, either case silently drops the existing ciphertext column.
- Consequence: Encrypted data in the column is destroyed by a migration that reports success. Re-encrypting needs the original plaintext, which may no longer exist anywhere.
- Affects: packages/cli rewrite-migrations (rewriteEncryptedAlterColumns), `stash eql migration --drizzle` (packages/cli/src/commands/eql/migration.ts), `stash eql install --drizzle` (packages/cli/src/commands/db/install.ts), Customer Drizzle migration files and the databases they are applied to
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:11-79`; `packages/cli/src/commands/db/rewrite-migrations.ts:21-22` (base); `packages/cli/src/commands/db/rewrite-migrations.ts:217-244`; `examples/prisma/migrations/cipherstash/20260601T0100_install_eql_v3_bundle/ops.json:14`
- Existing verification: rewrite-migrations.test.ts covers plaintext targets left untouched and v3 targets rewritten. No case has an encrypted source type. [exists_not_run]
- Missing verification: A test and a decision for a domain-to-domain ALTER (v2→v3 and v3→v3), to establish what drizzle-kit emits and what the rewriter should do.; Whether drizzle-kit produces SET DATA TYPE for an existing eql_v3 column whose domain changes (not verifiable offline).
- Mitigation: Rewrite only when the source can be shown to be plaintext, for example by consulting the drizzle snapshot JSON for the previous column type. Otherwise report the statement as skipped. Add the same non-empty-table guard as in FS-1.

### Recommended controls

- Add a non-empty-table guard (DO block that raises an exception) ahead of the DROP COLUMN in renderSafeAlter, so the failure stays loud on populated data. (other; FS-1, FS-2, VG-1)
- Add rewriter tests for v2→v3 and v3→v3 domain changes, and decide whether those statements should be skipped or rewritten. (test; FS-2, VG-2)
- Review whether `eql migration --drizzle` should edit sibling migration files without confirmation, and whether a --no-sweep or dry-run listing is needed. (review_focus; FS-1)
- Run the packages/cli vitest suite (rewrite-migrations.test.ts, eql/__tests__/migration.test.ts) in CI before release, plus one integration run of a rewritten migration against Postgres with the v3 bundle. (test; VG-3)

### What this assessment could not see

- Tests could not be run: the checkout has no node_modules and network access was not allowed. Test results are exists_not_run; regex behaviour was assessed by reading only.
- The drizzle-kit behaviour (which forms it emits, whether it emits SET DATA TYPE for domain-to-domain changes, how migrate treats edited files) could not be checked offline. The author's version table is an unverified claim. FS-2 stays plausible_failure rather than observed.
- No PR description, CODEOWNERS, CI or deployment context was available. The commit messages were read only as untrusted claims. Rollout controls and reviewer expectations are unknown.
- The v2 install path already rewrote v2 ALTERs into a data-dropping sequence before this change. That behaviour is pre-existing and was not scored. Only its extension to v3 and to the v3 command is assessed. The co-change signal (stash-encryption and stash-supabase skills not updated) was checked by grep, which found no SET DATA TYPE guidance there. The impact attributed to this change is limited to newly exposed paths.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
