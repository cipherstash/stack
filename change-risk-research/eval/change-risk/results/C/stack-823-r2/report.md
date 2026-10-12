## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `bf7be09998..143a99d178`

The Drizzle EQL migration rewriter (duplicated in the `stash` CLI and `@cipherstash/wizard`) no longer turns `ALTER COLUMN "c" SET DATA TYPE <eql domain>` into ADD tmp + DROP c + RENAME. It now emits only `ADD COLUMN "c_encrypted" <domain>` and keeps the plaintext source. It also adds a `target-exists` skip, and `stash eql migration --drizzle` and the wizard now fail with a non-zero exit when any statement is skipped or a sweep fails. This removes the old data-destroying output, which is a real reduction in risk. The new risk comes from a gap between the migration and the schema that triggered it. The ALTER only appears because the user's Drizzle schema changed `c` itself to an encrypted type. After the rewrite, the database keeps `c` as plaintext and adds `c_encrypted`, while the schema, the drizzle-kit snapshot and the application still treat `c` as encrypted. The application then writes EQL envelopes into the plaintext column, and nothing in the change detects this or tells the user. The shipped `stash-drizzle` skill still describes the old destructive rewrite, even though its usual co-change partner was edited in this PR. The new fail-closed exits also interrupt `stash init` (with a misleading drizzle-kit error) and stop the wizard before skills are installed. Unit coverage of the rewriter is extensive and CI is green, but no test runs a rewritten migration against Postgres or checks it against the Drizzle schema.

### Failure scenarios

**FS-1 · Rewritten migration leaves the database out of step with the Drizzle schema; ciphertext is written into the plaintext column** (high impact, plausible)

- Trigger: A user (or the wizard's agent) changes an existing Drizzle column `c` in place to an EQL v3 type. drizzle-kit emits `ALTER COLUMN "c" SET DATA TYPE eql_v3_*`, the sweep rewrites it, and the user runs `drizzle-kit migrate` (the wizard prompt now defaults to Yes).
- Mechanism: renderSafeAlter now emits only `ADD COLUMN "c_encrypted"` (rewrite-migrations.ts:872 in the CLI copy, :994 in the wizard copy) and leaves `c` as plaintext. The Drizzle schema and the drizzle-kit snapshot that produced the ALTER still declare `c` as the EQL domain and know nothing about `c_encrypted`. The schema column's toDriver returns a string (stack-drizzle column.ts:167-169), so inserts and updates through Drizzle succeed against the text column. The base rewrite produced a `c` of the encrypted type, which matched the schema (at the cost of data on populated tables).
- Consequence: New rows write EQL envelopes into the plaintext column `c` next to existing plaintext rows. `c_encrypted` stays NULL. Encrypted query operators against `c` fail, decrypting legacy rows fails, and the snapshot drift means a later schema fix that declares `c_encrypted` produces an ADD that fails because the column already exists. The wizard then prints 'Your data is now protected by CipherStash' (run.ts:261) while the plaintext is still in place. The data can be recovered, but the column needs manual repair, and the false assurance is security-relevant.
- Affects: packages/cli/src/commands/db/rewrite-migrations.ts and packages/wizard/src/lib/rewrite-migrations.ts (duplicated rewriter), @cipherstash/wizard post-agent flow (post-agent.ts, run.ts), Customer Drizzle migration directories, drizzle-kit snapshots and live databases, @cipherstash/stack-drizzle EQL v3 column type
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:865-873`; `packages/cli/src/commands/db/rewrite-migrations.ts:872-874` (base); `packages/wizard/src/lib/post-agent.ts:71-92`; `packages/wizard/src/run.ts:235-290`; `packages/stack-drizzle/src/column.ts:164-169`
- Existing verification: Rewriter unit tests assert the emitted ADD COLUMN `<c>_encrypted` SQL text and the absence of DROP/RENAME. [exists_not_run]; CI 'Run Tests (Node 22/24/Bun)' and 'Run E2E Tests' succeeded on head; that they include the rewriter suites is inferred from job names. [ran_passed]
- Missing verification: No test applies a rewritten migration with drizzle-kit migrate to a Postgres database and then runs Drizzle inserts and selects through the unchanged schema.; No check that the rewritten migration agrees with the drizzle-kit snapshot and schema, and nothing tells the user that the schema must now declare `c_encrypted` and keep `c` as plaintext.
- Mitigation: Make the rewrite tell the user that the Drizzle schema must be changed to the twin form (`c` plaintext, `c_encrypted` encrypted) and regenerated. Alternatively, fail closed on in-place schema changes instead of rewriting, and point to the stash-drizzle 'Schema-add: declare the encrypted twin' flow. Default the wizard migrate prompt to No and stop printing 'data is now protected' when a rewrite happened.

**FS-2 · Shipped stash-drizzle skill still describes the old destructive rewrite and the non-fatal flagging** (medium impact, observed in the code)

- Trigger: A customer's coding agent or developer reads the bundled `stash-drizzle` SKILL.md (installed into .claude/skills or inlined into AGENTS.md) after upgrading.
- Mechanism: skills/stash-drizzle/SKILL.md:64 at head still says the sweep 'repairs the invalid statement', that 'the repair is data-destroying, so it is safe only on an empty table', and that unplaceable statements are merely 'flagged for review'. The head behaviour is an add-only twin that preserves data, plus a non-zero exit. The PR updated stash-cli only. The co-change signal shows migration.ts usually changes together with this skill.
- Consequence: Agents in customer repos get contradictory guidance between two skills. They may keep making in-place type changes and expect the column to become encrypted on empty tables, which leads into FS-1. They are also not told that the command now exits 1, or that a `c_encrypted` twin appears and the schema must declare it.
- Affects: Shipped agent skills skills/stash-cli and skills/stash-drizzle
- Evidence: `skills/stash-cli/SKILL.md:379-381`; `skills/stash-drizzle/SKILL.md:64`; signal `co_change.omitted_co_changes[1]`
- Missing verification: No check keeps the skill text in sync with rewriter behaviour (AGENTS.md notes that skills are not type-checked).
- Mitigation: Update skills/stash-drizzle/SKILL.md in this PR so it matches stash-cli: add-only `<c>_encrypted`, the source is preserved, the schema must declare the twin, and the command fails closed with a non-zero exit.

**FS-3 · New fail-closed exits break `stash init` and the wizard mid-flow with misleading or incomplete handling** (medium impact, plausible)

- Trigger: During `stash init` (Drizzle) or the wizard, the sweep skips any statement (source-unknown, already-encrypted, target-exists, unrecognised form) or fails on a directory.
- Mechanism: migration.ts:338-344 throws CliExit(1) after the install migration is already written. install-eql.ts:125-143 catches every error and logs 'Could not generate the EQL migration — check that drizzle-kit is installed and configured', then returns eqlInstalled:false and init continues. In the wizard, post-agent.ts:81-85 throws, run.ts:276-289 exits 1, and finalize (skills install, call-site report) is skipped after the agent has already edited the project. Scripted `stash eql migration --drizzle` runs that used to exit 0 with warnings now exit 1.
- Consequence: Users get a wrong diagnosis (a drizzle-kit problem) for an unsafe-SQL review request. Re-running as advised creates another install migration (drizzle-kit generate --custom), while the original is still on disk. Wizard users are left with agent-edited code but no installed skills or guidance. CI or automation that calls the command starts failing. No data is harmed.
- Affects: `stash eql migration --drizzle` (packages/cli/src/commands/eql/migration.ts), `stash init` Drizzle EQL step (packages/cli/src/commands/init/steps/install-eql.ts), @cipherstash/wizard post-agent flow (post-agent.ts, run.ts)
- Evidence: `packages/cli/src/commands/eql/migration.ts:338-344`; `packages/cli/src/commands/init/steps/install-eql.ts:125-143`; `packages/wizard/src/lib/post-agent.ts:71-92`; `packages/wizard/src/run.ts:235-290`
- Existing verification: migration.test.ts asserts CliExit on skipped statements, including when embedded. post-agent.test.ts asserts the 'unsafe or unverified SQL' throw for flagged, failed and empty-error sweeps. [exists_not_run]
- Missing verification: No test of `stash init`'s install-eql step when the embedded migration exits for a sweep reason, or of the message it prints.; No test that the wizard still installs skills or prints guidance when post-agent throws.
- Mitigation: Rethrow or explicitly handle a sweep CliExit in install-eql.ts with a review-the-migrations message, the same way the installCommand branch rethrows CliExit. In the wizard, run skills install and guidance before exiting, or route the throw through finalize. Note the exit-code change in the changeset.

### Recommended controls

- Decide whether the add-only rewrite of an in-place schema change is the intended contract. If it is, the CLI and wizard output must tell the user to change the Drizzle schema to the twin form and regenerate, and the wizard should not default to migrating or claim the data is protected. (review_focus; FS-1)
- Add an integration test (Postgres plus drizzle-kit) that applies a rewritten migration and asserts what the application sees for the column. (test; FS-1, VG-1)
- Update skills/stash-drizzle/SKILL.md (line 64 and the related section) in this PR. (documentation; FS-2, VG-2)
- Handle the sweep CliExit in install-eql.ts with an accurate message, and make the wizard install skills and guidance before exiting on a flagged sweep. Add tests for both. (other; FS-3, VG-3)
- State the exit-code change of `stash eql migration --drizzle` in the changeset/CHANGELOG so automation users expect it. (documentation; FS-3)

### What this assessment could not see

- The wizard agent's prompt and instructions (which decide whether it changes a column in place or adds a twin) were not located in the checkout. How often FS-1 is triggered through the wizard is unknown.
- Test files were skimmed for case names and assertions only. Tests were not run locally. CI shows job conclusions without logs. Which suites passed in CI is inferred from job names. Coverage of edge cases (BC-2, BC-4, BC-5) was taken from test names and the PR description, not confirmed by running them.
- drizzle-kit snapshot and migrate behaviour (hash checking of edited applied files, diffing after a twin is added) was reasoned from general knowledge, not exercised. The later-migration failure in FS-1's consequence is plausible but not demonstrated.
- Whether the EQL v3 install SQL is idempotent when a re-run creates a second install migration (FS-3) was not checked. The consequence of re-running after a fail-closed exit may be understated or overstated.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
