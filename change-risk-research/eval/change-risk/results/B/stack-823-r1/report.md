## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `bf7be09998..143a99d178`

The Drizzle EQL migration rewriter (two byte-mirrored copies, used by `stash eql migration --drizzle` and the wizard) no longer emits ADD+DROP+RENAME; it emits only `ADD COLUMN "<col>_encrypted"` and leaves the source column. Any skipped/unverified statement now aborts the CLI with exit 1 and makes the wizard throw. This removes the data-destroying path on populated tables, but introduces new release risk: the rewritten SQL no longer matches the Drizzle schema and snapshot that produced it (the TS schema still declares the source column as encrypted), so applications can silently write EQL ciphertext into the plaintext `text` column while the twin stays NULL, and the documented staged flow later collides with the already-added twin. The wizard now defaults the migrate prompt to Yes after such a rewrite. Separately, the new hard exit is swallowed by `stash init`, which then misdiagnoses it as a drizzle-kit problem and reports EQL as not installed; and the shipped stash-drizzle skill still says the swept repair is data-destroying. Rewriter-level behaviour is extensively unit-tested (not run here); the schema/DB-alignment and init paths have no tests.

### Failure scenarios

**FS-1 · Add-only rewrite leaves the DB out of step with the Drizzle schema; app writes ciphertext into the plaintext column** (high impact, plausible)

- Trigger: A user (or the wizard agent) changes `email: text()` to `email: types.TextSearch('email')` in the Drizzle schema, runs drizzle-kit generate, the sweep rewrites the ALTER, and the user runs drizzle-kit migrate (wizard now defaults this prompt to Yes).
- Mechanism: renderSafeAlter now emits only `ADD COLUMN "email_encrypted"` (rewrite-migrations.ts:845-873) and the sweep only edits *.sql files (line 735), so the drizzle meta snapshot and the TS schema still say `email` is an EQL domain. At base the ADD/DROP/RENAME left `email` with the encrypted type the schema expects. The stack-drizzle codec serialises envelopes with JSON.stringify (codec.ts:67-72), which a `text` column accepts.
- Consequence: Writes through the Drizzle model store EQL envelopes as text in `email` alongside existing plaintext rows, `email_encrypted` stays NULL, and encrypted query operators against `email` fail. Following the stash-drizzle staged flow afterwards (declare `email_encrypted` in TS, generate) produces a second ADD COLUMN that fails because the twin already exists; a backfill keyed on `email` would read a column that now mixes plaintext and ciphertext. Mixed-content columns need manual data repair.
- Affects: packages/cli rewriter (src/commands/db/rewrite-migrations.ts), packages/wizard rewriter + post-agent step, Customer Drizzle migration directories, snapshots and databases, `stash encrypt` backfill (`<column>_encrypted` convention)
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:845-873`; `packages/cli/src/commands/db/rewrite-migrations.ts:872-874` (base); `packages/cli/src/commands/db/rewrite-migrations.ts:735`; `packages/stack-drizzle/src/codec.ts:67-72`; `packages/wizard/src/lib/post-agent.ts:72-92`; `packages/wizard/src/lib/post-agent.ts:113` (base); `packages/cli/src/commands/encrypt/backfill.ts:139`; `skills/stash-drizzle/SKILL.md:64`
- Existing verification: Rewriter unit tests assert the output contains ADD COLUMN "email_encrypted" and no DROP/RENAME (cli and wizard rewrite-migrations.test.ts) [exists_not_run]; post-agent.test.ts asserts the migrate prompt defaults to Yes after a staged rewrite [exists_not_run]
- Missing verification: No test or check that the rewritten migration plus drizzle snapshot plus TS schema describe the same database (e.g. drizzle-kit generate after the rewrite yields no diff, or a schema that references `<col>_encrypted`).; No end-to-end test of drizzle-kit migrate followed by an insert through the Drizzle model against the rewritten schema.
- Mitigation: Either keep the source schema consistent (rewrite only when the TS schema already declares the twin, otherwise fail closed with instructions to declare `<col>_encrypted` and revert the source column type), or have the CLI/wizard stop before migrate and tell the user to edit the schema so the snapshot matches. Do not default the wizard migrate prompt to Yes after a rewrite until this is resolved.

**FS-2 · `stash init` (Drizzle) misreports a fail-closed sweep as a drizzle-kit failure and says EQL is not installed** (medium impact, observed in the code)

- Trigger: `stash init` with Drizzle in a project whose migration directory has any ALTER-to-EQL statement the sweep skips (source declared elsewhere, hand-written USING, existing twin).
- Mechanism: generateDrizzleEqlMigration now throws CliExit(1) after writing the install migration (migration.ts:338-343). install-eql.ts:126-143 catches every error, logs 'Could not generate the EQL migration — check that drizzle-kit is installed and configured', and returns eqlMigrationPending unset; init/index.ts:149-160 then prints 'EQL extension NOT installed', tells the user to run `stash eql install`, and exits 1. Co-change history shows migration.ts usually changes with install paths, and this caller was not updated.
- Consequence: Onboarding fails with the wrong diagnosis and a remedy that points away from the real problem (sibling migrations needing review); an install migration file is left on disk while init reports nothing was generated, so a retry can add a second install migration.
- Affects: `stash eql migration --drizzle` command, `stash init` Drizzle step (init/steps/install-eql.ts, init/index.ts)
- Evidence: `packages/cli/src/commands/eql/migration.ts:338-343`; `packages/cli/src/commands/init/steps/install-eql.ts:125-147`; `packages/cli/src/commands/init/index.ts:149-160`; signal `co_change.omitted_co_changes`
- Existing verification: migration.test.ts asserts embedded mode still exits 1 (suppresses outro) [exists_not_run]
- Missing verification: No init test for the case where eqlMigrationCommand fails because of sweep findings.
- Mitigation: In install-eql.ts, distinguish a sweep-failure exit (e.g. a typed error or result) from a drizzle-kit failure; set eqlMigrationPending and surface the review message, or rethrow CliExit as installCommand's branch already does.

**FS-3 · Shipped stash-drizzle skill still describes the swept repair as data-destroying and sends users to a staged flow that collides with it** (medium impact, observed in the code)

- Trigger: A customer's coding agent reads the installed stash-drizzle skill after this release.
- Mechanism: skills/stash-drizzle/SKILL.md:64 (head) says the sweep's repair is data-destroying and safe only on empty tables and directs live tables to the staged flow at :450-461, which tells the agent to add `email_encrypted` in the TS schema and generate an ADD COLUMN. The rewriter now already adds that column. The history signal shows migration.ts usually co-changes with this skill.
- Consequence: Agents give wrong guidance in customer repos: they avoid or hand-edit a migration that is now non-destructive, or apply it and then generate a duplicate ADD COLUMN that fails at migrate time.
- Affects: Shipped skills: stash-cli (updated), stash-drizzle (not updated), Customer Drizzle migration directories, snapshots and databases
- Evidence: `skills/stash-cli/SKILL.md:379-381`; `skills/stash-drizzle/SKILL.md:64`; signal `co_change.omitted_co_changes`
- Missing verification: No check that shipped skills agree with rewriter behaviour.
- Mitigation: Update skills/stash-drizzle/SKILL.md in this PR to describe the add-only twin and how it fits the staged flow (declare the twin in the TS schema without regenerating it).

**FS-4 · Projects with historical unplaceable ALTERs can no longer complete `stash eql migration --drizzle` or the wizard** (medium impact, plausible)

- Trigger: A migration directory containing an already-applied hand-written `SET DATA TYPE ... USING` or an ALTER whose column is declared in a squashed/other directory.
- Mechanism: The sweep scans every .sql file in the directory and flags these on every run; the CLI now exits 1 (migration.ts:338-343) and the wizard throws (post-agent.ts:81-85). There is no flag to acknowledge a reviewed statement.
- Consequence: Loud but persistent: CI scripts or onboarding flows that call the command fail every time; users must edit already-applied migration files to proceed.
- Affects: packages/wizard rewriter + post-agent step, `stash eql migration --drizzle` command
- Evidence: `packages/cli/src/commands/eql/migration.ts:338-343`; `packages/wizard/src/lib/post-agent.ts:72-92`
- Existing verification: migration.test.ts 'warns at the closing note when the sweep leaves skipped statements' asserts CliExit and the error message [exists_not_run]
- Missing verification: No test or escape hatch for statements that were already reviewed or applied.
- Mitigation: Provide an explicit acknowledgement (flag or comment marker) for reviewed statements, or limit the hard failure to files not yet recorded in the drizzle journal/applied set.

### Recommended controls

- Decide how the add-only rewrite reconciles with the Drizzle schema/snapshot: require the TS schema to declare `<col>_encrypted` (and keep the source plaintext) before rewriting, or stop before migrate with explicit schema-edit instructions. (review_focus; FS-1, VG-1)
- Add an integration test: schema change -> drizzle-kit generate -> sweep -> drizzle-kit generate again (expect no diff or a clear failure) -> migrate -> insert via Drizzle model; assert ciphertext lands in the encrypted column. (test; FS-1, VG-1)
- Keep the wizard migrate prompt defaulting to No after a rewrite until RC-1 is resolved. (other; FS-1)
- Fix install-eql.ts to distinguish sweep failures (set eqlMigrationPending, show review message) and add an init test for it. (test; FS-2, VG-2)
- Update skills/stash-drizzle/SKILL.md (line 64 and the staged-flow section) in this PR. (documentation; FS-3, VG-3)
- Add a way to acknowledge reviewed/applied statements so the fail-closed exit is not permanent for existing projects. (other; FS-4)
- Run the cli and wizard unit suites and scripts/__tests__/rewriter-copies-in-sync.test.mjs in CI before release. (test; VG-4)

### What this assessment could not see

- No tests were run (no node_modules in the checkout, no network) and no CI results were provided. All verification statuses are exists_not_run; test correctness is unconfirmed.
- drizzle-kit behaviour (snapshot contents, what a subsequent generate emits, migrate hash handling) is from general knowledge, not observed here. The duplicate ADD COLUMN and schema-drift consequences in FS-1 are inferred; their mechanism in this repo's code is verified.
- Test-file diffs (~970 lines) were skimmed by test name and key assertions; the wizard rewriter copy was compared to the CLI copy by diff at head, not read in full. A weakened assertion in the test diff could be missed.
- No PR description or deployment context; whether the wizard agent edits the source column in place or declares a twin was not confirmed from wizard prompts. FS-1's likelihood in the wizard path is uncertain.

_Inputs unavailable: ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
