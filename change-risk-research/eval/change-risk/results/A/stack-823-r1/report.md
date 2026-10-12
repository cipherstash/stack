## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `bf7be09998..143a99d178`

The Drizzle EQL migration rewriter (duplicated in the stash CLI and @cipherstash/wizard) no longer turns drizzle-kit's in-place `ALTER COLUMN ... SET DATA TYPE <eql domain>` into a destructive ADD+DROP+RENAME. It now emits only `ADD COLUMN "<col>_encrypted"` and keeps the source column. It also adds a `target-exists` skip, stops `$` inside identifiers from opening a dollar-quote, and attaches partial results to sweep errors. Any skipped or unverified statement now makes `stash eql migration --drizzle` exit 1 and makes the wizard throw. Before, these were only warnings. Removing the data-destroying path lowers the worst-case data-loss risk. The main new release risk is a split between the schema and the database. drizzle-kit only emits the ALTER when the user's TypeScript schema already declares the ORIGINAL column as encrypted. After the rewrite, that column is still plaintext in the database and the new twin is not in the schema. The wizard defaults to running the migration and then reports that encryption is set up. Secondary risks: `stash init` swallows the new fail-closed exit and reports it as a drizzle-kit problem, and the command can fail permanently on corpora with flagged history, with no override. The shipped stash-drizzle skill still describes the old destructive rewrite. Tests were updated substantially but were not run (no dependencies installed, no CI results).

### Failure scenarios

**FS-1 · Add-only rewrite leaves the TS schema pointing an encrypted type at a still-plaintext column, and the wizard migrates and reports success** (high impact, plausible)

- Trigger: A user or wizard agent changes an existing populated plaintext column (e.g. `email`) to a `types.*` encrypted column in the Drizzle schema. drizzle-kit emits `ALTER COLUMN "email" SET DATA TYPE eql_v3_*`, the sweep rewrites it, and the user accepts the wizard's default-Yes migrate prompt (or runs drizzle-kit migrate).
- Mechanism: renderSafeAlter now emits only `ADD COLUMN "email_encrypted"` and leaves `email` as text (E-1, E-2). The TS schema and the drizzle snapshot still say `email` is the encrypted domain, and nothing in the schema references `email_encrypted`. The stack-drizzle custom type serialises the envelope to a string (E-7), which a text column accepts. The wizard's prompt defaults to Yes after a rewrite (E-4), and run.ts then prints that encryption is set up and data is protected (E-5).
- Consequence: After migrate, the app's encrypted reads and queries on `email` hit a text column. Existing rows hold plaintext that decryptModel cannot decode, and EQL operators against text fail at runtime. New writes store envelopes in the plaintext column, so plaintext and ciphertext are mixed. Existing plaintext stays at rest while the wizard says the data is protected. A later `drizzle-kit generate` that adds `email_encrypted` to the schema emits an ADD that fails as 'already exists'. Recovery means hand-editing the schema and snapshot. No data is lost, unlike the base behaviour.
- Affects: @cipherstash/wizard post-agent steps and rewriter copy, Customer Drizzle applications / migration directories, wizard run.ts outer flow
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:786-797`; `packages/cli/src/commands/db/rewrite-migrations.ts:851-872`; `packages/wizard/src/lib/post-agent.ts:71-101`; `packages/wizard/src/run.ts:235-289`; `packages/stack-drizzle/src/column.ts:163-176`
- Existing verification: Wizard post-agent test asserts the rewritten file contains ADD COLUMN "email_encrypted", contains no DROP/RENAME, and that the prompt defaults to Yes. It does not check that the schema and database agree. [exists_not_run]
- Missing verification: An end-to-end check (drizzle-kit generate -> sweep -> migrate -> stack-drizzle insert/select) showing the application works against the rewritten schema.; A test or documented decision for what the TS schema should declare after an add-only rewrite (keep `email` as text and add `emailEncrypted`?).
- Mitigation: When a rewrite happens, have the wizard or CLI tell the user (or the agent) to revert the original column to its plaintext type in the TS schema, add the `<col>_encrypted` column, and regenerate so the snapshot matches. Or default the migrate prompt to No and replace the 'data is now protected' outro with next steps for the staged lifecycle.

**FS-2 · stash init swallows the new fail-closed CliExit and misreports it as a drizzle-kit problem** (medium impact, plausible)

- Trigger: `stash init` on a Drizzle project whose migration directory contains a statement the sweep skips (source-unknown, already-encrypted, target-exists or unrecognised-form).
- Mechanism: generateDrizzleEqlMigration writes the install migration and then throws CliExit(1) when sweepIncomplete (E-3). install-eql.ts catches every error on the Drizzle path, logs 'Could not generate the EQL migration — check that drizzle-kit is installed and configured', and returns eqlMigrationPending false (E-6). Unlike the installCommand branch, it does not re-throw CliExit.
- Consequence: The user is told the migration was not generated when it was, and is pointed at the wrong cause. Following the 'Re-run with: stash eql migration --drizzle' advice generates another install migration file. Init continues as if EQL were not pending.
- Affects: stash CLI: rewrite-migrations + eql migration --drizzle, stash init install-eql step (Drizzle path)
- Evidence: `packages/cli/src/commands/eql/migration.ts:289-345`; `packages/cli/src/commands/init/steps/install-eql.ts:125-147`
- Existing verification: install-eql.test.ts covers the case where eqlMigrationCommand rejects with a generic Error, not the sweep-fail CliExit. [exists_not_run]
- Missing verification: An init-level test where the sweep flags a statement, checking the message and the eqlMigrationPending state.
- Mitigation: Return a distinct result or error type for 'migration written, sweep needs review' and have init report it accurately, keeping eqlMigrationPending true.

**FS-3 · Command and wizard fail permanently on corpora with flagged statements, with no override** (medium impact, plausible)

- Trigger: A migration directory with squashed history or a declaration in another directory (source-unknown, which the code itself calls likely the most common skip), or with an already-applied hand-written `SET DATA TYPE ... USING` to an EQL domain.
- Mechanism: Every skip now sets sweepIncomplete, which leads to CliExit(1) (E-3), or makes the wizard throw (E-4). The sweep re-scans the whole directory on every run, and there is no flag to acknowledge a reviewed statement (E-14).
- Consequence: `stash eql migration --drizzle` exits 1 on every run and the wizard aborts before its migrate step and outro, even after the user reviewed the statement. Scripted or CI use of the command breaks. Each run also leaves another generated install migration on disk.
- Affects: stash CLI: rewrite-migrations + eql migration --drizzle, @cipherstash/wizard post-agent steps and rewriter copy
- Evidence: `packages/cli/src/commands/eql/migration.ts:289-345`; `packages/wizard/src/lib/post-agent.ts:71-101`; `packages/cli/src/commands/db/rewrite-migrations.ts:694-702`
- Existing verification: migration.test.ts asserts CliExit and the 'unsafe or unverified SQL' message when statements are skipped. [exists_not_run]
- Missing verification: Behaviour for a reviewed and already-applied flagged statement on a re-run.
- Mitigation: Provide an acknowledgement mechanism (an allowlist or `--accept-reviewed` flag), or skip statements in migrations already recorded in the drizzle journal or applied, and document it in the changeset.

**FS-4 · Shipped stash-drizzle skill still describes the destructive, warn-only rewrite** (low impact, observed in the code)

- Trigger: A customer's coding agent reads the bundled stash-drizzle SKILL.md after upgrading.
- Mechanism: skills/stash-drizzle/SKILL.md (head, line 64) still says the repair is data-destroying, safe only on an empty table, and that unplaceable statements are only flagged. The history signal shows it usually changes together with migration.ts, but it is not updated here.
- Consequence: Agents give contradictory guidance (e.g. 'do not apply the swept migration') and do not expect the non-zero exit or the `<col>_encrypted` twin. This also makes FS-1 more likely, because nothing tells the agent to adjust the TS schema.
- Affects: Shipped agent skills (stash-cli, stash-drizzle)
- Evidence: `skills/stash-drizzle/SKILL.md:64`; signal `co_change.omitted_co_changes[1]`
- Missing verification: Skill/behaviour consistency check for stash-drizzle.
- Mitigation: Update skills/stash-drizzle/SKILL.md in the same release to match stash-cli.

### Recommended controls

- Add an integration test (real drizzle-kit and Postgres): plaintext column -> types.* change -> sweep -> migrate -> insert/select via stack-drizzle. Assert the intended post-migration schema and the user-facing guidance. (test; FS-1, VG-1)
- Review packages/wizard/src/lib/post-agent.ts:87-101 and run.ts outro: whether migrate should default to Yes, and whether 'Your data is now protected' is accurate after an add-only rewrite. (review_focus; FS-1)
- Review install-eql.ts:125-147 handling of the new CliExit from the sweep, and add a test. (review_focus; FS-2, VG-2)
- Decide on an acknowledgement or override path for reviewed flagged statements before shipping the hard exit. (other; FS-3)
- Update skills/stash-drizzle/SKILL.md and state the exit-code change in the changeset. (documentation; FS-4)
- Run the stash, wizard and scripts unit suites (including rewriter-copies-in-sync) in CI before release. (test; VG-3)

### What this assessment could not see

- Tests were not run and no CI results were supplied. Every existing verification is exists_not_run, which caps confidence at medium.
- The wizard agent's prompt and how it edits Drizzle schemas (in place or as twin columns) were not located or read. How often FS-1 triggers depends on agent behaviour that was not seen. If the agent already adds twin columns, drizzle-kit would not emit the ALTER at all.
- The regex and lexer changes (dollar-quote handling, the target-exists index) were read from the diff but not exercised. The wizard copy was assumed to match the CLI copy, based on the in-sync test and the identical diff shape. Subtle mis-parsing regressions would not be caught by this assessment.
- Runtime behaviour of stack-drizzle against a text column (driver serialisation, decrypt errors) is inferred from code, not executed. The exact failure mode in FS-1 (error vs silently mixed data) is not confirmed.

_Inputs unavailable: pr_description, ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
