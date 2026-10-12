## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `bf7be09998..143a99d178`

The change replaces the Drizzle migration rewriter's destructive ADD+DROP+RENAME (which destroyed column data on populated tables) with a single `ADD COLUMN "<col>_encrypted"` that keeps the source column, adds a 'target-exists' skip, tightens dollar-quote detection, and makes both callers fail closed: `stash eql migration --drizzle` now exits 1 and the wizard throws (process.exit 1) whenever any statement is skipped or a directory could not be swept. Both rewriter copies stay byte-identical outside the wizard-only region. Against the base this removes a critical data-loss path. The new risk is semantic: the rewriter only fires when the Drizzle schema changed a column's type in place, and it now produces a database whose shape (plaintext `email` + undeclared `email_encrypted`) no longer matches the schema.ts or the drizzle-kit snapshot, while the wizard defaults to 'Yes, migrate'. Nothing tests or explains that divergence, and the application/ORM side was not visible. Secondary: the new hard exit is mis-reported by `stash init` as a drizzle-kit problem, and the wizard now aborts before finalising on any skip. CI reports all 9 checks passing on the head commit.

### Failure scenarios

**FS-1 · Rewritten migration leaves the database out of step with the Drizzle schema that declared the column encrypted** (high impact, plausible)

- Trigger: A user (or the wizard's agent) changes an existing column's type in schema.ts in place to an encrypted type — the only way drizzle-kit emits the `SET DATA TYPE <eql domain>` this rewriter matches — then applies the rewritten migration (the wizard now defaults that prompt to Yes).
- Mechanism: renderSafeAlter now emits only `ADD COLUMN "email_encrypted"` and keeps `email` with its plaintext type (rewrite-migrations.ts:845-873). The rewriter edits only the .sql file: schema.ts still declares `email` as the encrypted domain, `email_encrypted` is declared nowhere in the application schema, and the drizzle-kit snapshot still records `email` as encrypted. The staged lifecycle in stash-drizzle SKILL.md:450-462 requires the opposite schema shape (`email: text`, `email_encrypted: types.*`). Neither the SQL header, the CLI log line nor the wizard prompt tells the user to reshape schema.ts. At base the ADD+DROP+RENAME made the database match the schema (at the cost of data).
- Consequence: The application's ORM model writes encrypted values to `email`, which is still a plaintext column, and reads try to decrypt existing plaintext rows (inferred: the Drizzle custom-type driver mapping was not in the inputs). The column ends up holding a mix of plaintext and ciphertext envelopes, encrypted query operators fail against a text column, and `email_encrypted` stays empty. A later `stash encrypt backfill` reads `email` as plaintext and can encrypt the envelope strings a second time. Data is recoverable but integrity is damaged, and the wizard's closing message says the data is protected.
- Affects: packages/cli/src/commands/db/rewrite-migrations.ts and packages/wizard/src/lib/rewrite-migrations.ts, @cipherstash/wizard post-agent step and run loop, Customer Drizzle schema.ts, drizzle-kit snapshots and databases, stash encrypt backfill / status (<col>_encrypted convention)
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:845-873`; `skills/stash-drizzle/SKILL.md:450-462`; `packages/wizard/src/lib/post-agent.ts:59-71`; `packages/wizard/src/lib/post-agent.ts:71-101`; `packages/cli/src/commands/encrypt/backfill.ts:139`; `git -C repo grep -n -i snapshot <head> -- packages/cli/src/commands/db/rewrite-migrations.ts packages/wizard/src/lib/rewrite-migrations.ts`
- Existing verification: Rewriter unit tests assert the emitted SQL is one ADD with no cutover statements (rewrite-migrations.test.ts:377) and post-agent tests assert the Yes default after a rewrite; run as part of 'Run Tests' (pnpm run test), which passed. [ran_passed]
- Missing verification: An end-to-end check (drizzle-kit generate → rewrite → migrate → ORM insert/select) showing that the schema.ts, snapshot and database agree after the rewrite, or that the user is stopped until they do; A test that the user-facing output tells them to revert the source column's type in schema.ts and declare `<col>_encrypted`
- Mitigation: Either fail closed on in-place type changes too (flag them with guidance to reshape schema.ts into the `<col>` + `<col>_encrypted` twin and regenerate), or print explicit schema.ts instructions in the SQL header and CLI/wizard output and keep the wizard migrate prompt defaulting to No after a rewrite. Add an integration test across the generate/rewrite/migrate flow.

**FS-2 · drizzle-kit snapshot drift makes the next generated migration fail on a duplicate `<col>_encrypted`** (medium impact, plausible)

- Trigger: After applying a rewritten migration, the user follows the staged lifecycle and changes schema.ts to `email: text` plus `email_encrypted: types.*`, then runs `drizzle-kit generate` and `migrate`.
- Mechanism: The drizzle-kit snapshot from the original generate records `email` as the encrypted type and has no `email_encrypted`, because the rewriter changes only .sql files (no snapshot handling in either copy). drizzle-kit diffs snapshots, not the database, so the next generate emits `ADD COLUMN "email_encrypted"` again (plus a type change of `email` back to text), and the database already has that column.
- Consequence: The next migration fails with 'column already exists' and has to be hand-edited. It fails loudly, but the user is stuck partway through the rollout. Whether the earlier statements in that migration are rolled back depends on drizzle-kit's transaction handling, which was not visible.
- Affects: packages/cli/src/commands/db/rewrite-migrations.ts and packages/wizard/src/lib/rewrite-migrations.ts, Customer Drizzle schema.ts, drizzle-kit snapshots and databases
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:845-873`; `git -C repo grep -n -i snapshot <head> -- packages/cli/src/commands/db/rewrite-migrations.ts packages/wizard/src/lib/rewrite-migrations.ts`; `skills/stash-drizzle/SKILL.md:450-462`
- Missing verification: A test or documented procedure for reconciling the drizzle-kit snapshot after a staged rewrite
- Mitigation: Document (in the SQL header and stash-drizzle skill) how to reconcile the snapshot, e.g. regenerate after reshaping schema.ts and delete the redundant ADD, or have the rewriter also update the snapshot JSON for the added twin.

**FS-3 · `stash init` reports the new fail-closed sweep as a drizzle-kit problem and records no pending migration** (medium impact, observed in the code)

- Trigger: `stash init` on a Drizzle project whose migration directory holds an in-place ALTER the sweep skips (source-unknown after a squashed history, target-exists, unrecognised form).
- Mechanism: generateDrizzleEqlMigration now throws CliExit(1) on any skip (migration.ts:336-344). install-eql.ts:125-143 catches every throw from eqlMigrationCommand, logs 'Could not generate the EQL migration — check that drizzle-kit is installed and configured', and returns eqlMigrationPending false even though the EQL install migration file was written. init/index.ts:149-160 then prints 'EQL extension NOT installed … Run `stash eql install`' and exits 1.
- Consequence: The user gets two contradictory diagnoses and a recovery path (`stash eql install` straight to the database) that bypasses the migration that was written and leaves the skipped sibling SQL untouched. No data effect, but the setup command fails for this configuration with misleading guidance.
- Affects: stash eql migration --drizzle, stash init install-eql step (Drizzle path)
- Evidence: `packages/cli/src/commands/eql/migration.ts:336-345`; `packages/cli/src/commands/init/steps/install-eql.ts:125-147`; `packages/cli/src/commands/init/index.ts:149-160`
- Existing verification: install-eql.test.ts covers a generic thrown Error mapping to not-installed, but not a sweep-originated CliExit [exists_not_run]
- Missing verification: A test of init's Drizzle path when the sweep fails closed
- Mitigation: Let init distinguish the sweep failure (for example a typed error or a returned status), keep eqlMigrationPending true and point the user at the flagged sibling migrations instead of at drizzle-kit/`eql install`.

**FS-4 · Wizard aborts after the agent has edited code whenever any statement is skipped** (medium impact, plausible)

- Trigger: Wizard run on a project whose drizzle output holds any skipped statement — including source-unknown, which the code comments call likely the most common skip on a real (squashed) corpus — or a directory that failed to sweep.
- Mechanism: post-agent.ts:81-85 throws; run.ts:276-290 catches it, logs the message and calls process.exit(1), skipping finalize (skills install offer, completion log/outro) and the call-site report. The agent's code and schema edits are already on disk.
- Consequence: The wizard ends with a failure after making code changes, never offers the skills install, and leaves the user to finish the migration by hand. It fails loudly and unsafe SQL is not applied, so the release risk is limited to the user experience and this configuration.
- Affects: @cipherstash/wizard post-agent step and run loop
- Evidence: `packages/wizard/src/lib/post-agent.ts:71-101`; `packages/wizard/src/run.ts:235-290`
- Existing verification: post-agent tests assert the throw before prompting for flagged and unswept cases (post-agent.test.ts:243, 264); ran in 'Run Tests', which passed [ran_passed]
- Missing verification: A test of run.ts behaviour (finalize/skills install and messaging) after the post-agent step fails closed
- Mitigation: Return a 'needs review' status from runPostAgentSteps and still run finalize with an outro that names the files to review, instead of exiting through the generic error handler.

### Recommended controls

- Decide and document what schema.ts and the snapshot should look like after a staged rewrite. Make the SQL header, the CLI log and the wizard prompt say so, or fail closed on in-place type changes. (review_focus; FS-1, FS-2)
- Add an integration test (Postgres + EQL is already available in the 'Run Tests' job): generate an in-place type change, run the rewriter, migrate, then perform an ORM insert/select and a second generate. (test; VG-1, FS-1, FS-2)
- Keep the wizard's migrate prompt defaulting to No after a rewrite until RC-1 is resolved. (other; FS-1)
- Make init and the wizard distinguish the sweep's fail-closed exit from other failures, and add tests for both callers. (test; FS-3, FS-4, VG-2)
- Release note: the rewrite no longer replaces the column, existing scripts that relied on exit 0 from `stash eql migration --drizzle` may now fail, and the schema must be reshaped to the twin form. (documentation; FS-1, FS-3)

### What this assessment could not see

- The Drizzle custom-type driver mapping (@cipherstash/stack-drizzle toDriver/fromDriver) was not found in the checked paths, so what the ORM does when writing an encrypted type to a text column is inferred. FS-1's runtime consequence (mixed plaintext/ciphertext rather than an immediate error) is inferred; the schema divergence itself is verified.
- The wizard's agent prompt is fetched over the network (fetchIntegrationPrompt) and was unavailable, so whether the agent changes column types in place or writes the twin shape is unknown. How often FS-1 is triggered through the wizard cannot be judged.
- Tests were not run locally (no node_modules, no network). ci.json reports job-level success only; individual tests were mapped to jobs by reading tests.yml (pnpm run test → turbo test over packages/*). ran_passed is attributed at job granularity.
- The test diffs (~1,000 changed lines) were skimmed by test name and assertion; the dollar-quote and the target-exists logic were read in the source, not traced through every fixture. Edge cases in the regex changes may be missed.
- The history signal says migration.ts usually changes together with db/install.ts and skills/stash-drizzle/SKILL.md, and neither changed here. db/install.ts was not read. stash-drizzle SKILL.md was read only at lines 420-580. Any drift between those files and the new behaviour is unassessed, beyond what FS-1 and FS-2 cover.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
