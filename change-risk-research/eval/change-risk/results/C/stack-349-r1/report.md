## Change risk: Changes or verification required

**Impact if something goes wrong:** critical · **Verification confidence:** low · `530625f59c..a47a63e40b`

Onboarding batch for @cipherstash/cli plus one change to @cipherstash/stack's Drizzle column type. The release risk is concentrated in a new migration rewriter: any drizzle-kit `ALTER COLUMN ... SET DATA TYPE eql_v2_encrypted` is replaced by ADD tmp column, a *commented-out* UPDATE, DROP original column, RENAME. Because the backfill is a comment and the temp column only exists once the migration runs, applying the rewritten migration to a populated table irreversibly deletes the original column's data and leaves the encrypted column NULL. Previously such migrations failed loudly with a cast error. The wizard (which encrypts columns it introspects from an existing database) now runs this rewrite and then offers `drizzle-kit migrate` with default 'yes'; `db install` auto-detects Drizzle and sweeps every .sql file in the migrations folder without prompting. The Drizzle `dataType()` string also changed for all existing @cipherstash/stack users, which may make drizzle-kit regenerate ALTERs for already-encrypted columns that the sweep would then turn into DROPs. Lesser risks: `db setup` was removed while bundled skills (now copied into customer repos) and the stack README still instruct it; Drizzle auto-detection silently changes `db install` from a direct install to migration generation. The new rewriter tests pass in CI but assert the destructive output rather than guard against it. Advisory verdict: changes or verification required.

### Failure scenarios

**FS-1 · Rewritten migration drops the original column's data on populated tables** (critical impact, observed in the code)

- Trigger: A user runs the wizard (or `db install` in a Drizzle project) against an existing app whose tables already have rows, choosing columns to encrypt; drizzle-kit generates `ALTER COLUMN ... SET DATA TYPE eql_v2_encrypted`, and the migration is applied (wizard default answer is yes).
- Mechanism: renderSafeAlter emits ADD COLUMN tmp, the UPDATE only as a SQL comment, then DROP COLUMN original and RENAME (rewrite-migrations.ts:67-78). Nothing copies or encrypts existing values; the guidance to 'backfill the new column BEFORE running this migration' cannot be followed because the tmp column is created by this same migration. The wizard rewrites then prompts `drizzle-kit migrate` with initialValue true (post-agent.ts:71-87), and finishes with 'Your data is now protected' (run.ts:226). Previously the same migration failed with a cast error, leaving data intact.
- Consequence: Irreversible loss of the original column contents (only recoverable from backup); the encrypted column is NULL for every existing row, so the app reads nulls. A loud, safe failure becomes a silent destructive success.
- Affects: packages/cli db/rewrite-migrations.ts, packages/cli wizard post-agent steps, packages/cli `db install` command, Customer PostgreSQL databases and committed Drizzle migration files
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:14-65`; `packages/cli/src/commands/db/rewrite-migrations.ts:67-78`; `packages/cli/src/commands/wizard/lib/post-agent.ts:108-133`; `packages/cli/src/commands/wizard/lib/post-agent.ts:62-87`; `packages/cli/src/commands/wizard/run.ts:181-227`; `packages/cli/src/commands/wizard/lib/gather.ts:59-63`
- Existing verification: rewrite-migrations.test.ts asserts the rewritten text contains ADD/DROP/RENAME; it encodes the destructive output and does not check data preservation. [exists_not_run]; CI 'Run Tests' (pnpm run test via turbo) reported success; whether CLI unit tests were included is inferred, not shown. [ran_passed]
- Missing verification: An integration test applying the rewritten migration to a table with rows and checking values are preserved or the migration refuses to run.; The PR's own manual smoke tests are unchecked.
- Mitigation: Do not emit DROP COLUMN in the same migration as the ADD. Split into (1) ADD tmp column, (2) app-side backfill with encryptModel, (3) a separate DROP/RENAME migration; or emit a guard (e.g. DO block raising if the original column has non-null rows) before DROP. Default the wizard's migrate prompt to 'no' when rewrites occurred.

**FS-2 · Sweep rewrites every existing migration file, including hand-fixed or not-yet-deployed ones** (high impact, plausible)

- Trigger: A Drizzle project (auto-detected, no flag) runs `db install` or the wizard while its migrations folder contains earlier ALTERs to eql_v2_encrypted, including ones a user hand-edited with a USING conversion, or ones committed but not yet applied in staging/production.
- Mechanism: The regex ends in `[^;]*;`, so any trailing clause such as `USING ...` is matched and discarded (rewrite-migrations.ts:14-15). The loop overwrites every .sql file in outDir (rewrite-migrations.ts:42-62); install.ts skips only the install-eql file (install.ts:337-340) and Drizzle detection needs no flag (install.ts:172-178). Rewritten files are not reported for confirmation, just logged.
- Consequence: Committed migration history is silently altered; environments that have not yet applied the file run the DROP version instead of the author's data-preserving conversion, with the FS-1 data loss in those environments.
- Affects: packages/cli db/rewrite-migrations.ts, packages/cli `db install` command, Customer PostgreSQL databases and committed Drizzle migration files
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:14-65`; `packages/cli/src/commands/db/install.ts:332-351`; `packages/cli/src/commands/db/install.ts:51-65`
- Existing verification: No test covers a USING clause or an already-applied migration; tests only cover bare statements. [exists_not_run]
- Missing verification: Test that statements with USING clauses are left alone.; Test that only newly generated migration files are rewritten.
- Mitigation: Restrict the rewrite to files generated in the current run (compare against the drizzle journal before/after), refuse to touch statements with USING, and ask before overwriting.

**FS-3 · Changed Drizzle dataType string causes regenerated ALTERs on already-encrypted columns, which the sweep turns into DROPs** (critical impact, plausible)

- Trigger: An existing @cipherstash/stack + Drizzle user upgrades, runs `drizzle-kit generate`, then runs the wizard or `db install`.
- Mechanism: dataType() changes from 'eql_v2_encrypted' (base drizzle/index.ts:96) to '"public"."eql_v2_encrypted"' (head :12,:104). drizzle-kit snapshots store the column type string; a different string is likely diffed as a type change, producing `ALTER COLUMN ... SET DATA TYPE "public"."eql_v2_encrypted"` for columns that already hold ciphertext. Alone that statement is a same-type no-op, but the rewriter matches it and emits DROP of the existing encrypted column.
- Consequence: Loss of stored ciphertext for existing encrypted columns (data unrecoverable without backup).
- Affects: @cipherstash/stack drizzle integration (encryptedType, getEncryptedColumnConfig), drizzle-kit schema snapshots of existing @cipherstash/stack users, packages/cli db/rewrite-migrations.ts, Customer PostgreSQL databases and committed Drizzle migration files
- Evidence: `packages/stack/src/drizzle/index.ts:12`; `packages/stack/src/drizzle/index.ts:96` (base); `packages/stack/src/drizzle/index.ts:97-105` (inferred); `packages/cli/src/commands/db/rewrite-migrations.ts:14-65`
- Existing verification: No test in packages/stack covers the dataType string or drizzle-kit snapshot behaviour after the change. [unknown]
- Missing verification: Run drizzle-kit generate against a snapshot created with the previous release and confirm no ALTER is emitted.; Verify what SQL drizzle-kit writes for a quoted, schema-qualified custom type name in CREATE TABLE.
- Mitigation: Verify drizzle-kit diff behaviour before release; if it emits ALTERs, document the upgrade or make the rewriter skip ALTERs whose source column is already eql_v2_encrypted (e.g. compare against the previous snapshot).

**FS-4 · Drizzle auto-detection changes `db install` from installing EQL to only writing a migration** (medium impact, plausible)

- Trigger: A project with drizzle-orm in package.json (but applying EQL directly, e.g. in CI or scripts) runs `db install` without flags; or a non-superuser Neon/RDS Drizzle user.
- Mechanism: resolveProviderOptions enables drizzle when detectDrizzle() is true (install.ts:172-178), and installCommand then returns after generateDrizzleMigration (install.ts:55-65) without touching the database; the exit is 'Done!'. On that path excludeOperatorFamily stays false unless passed (install.ts:180, 287-290), so the non-superuser OPE fallback (install.ts:89-98) does not apply and the full-variant migration may fail at migrate time.
- Consequence: EQL silently not installed (subsequent `db push` or app queries fail), or a migration that fails on managed Postgres. Loud downstream, recoverable with `--drizzle=false`/flags.
- Affects: packages/cli `db install` command
- Evidence: `packages/cli/src/commands/db/install.ts:51-65`; `packages/cli/src/commands/db/install.ts:89-113`; `packages/cli/src/__tests__/detect.test.ts:1-30`
- Existing verification: detect.test.ts covers detectDrizzle/detectSupabase inputs, not installCommand behaviour. [exists_not_run]
- Missing verification: Test of installCommand branch selection with and without explicit flags.
- Mitigation: Prompt before switching to the Drizzle path when auto-detected, and apply the superuser check/OPE fallback on the Drizzle path too.

**FS-5 · Removed `db setup` still documented in shipped skills and stack README** (low impact, observed in the code)

- Trigger: A user or a coding agent follows skills/stash-cli/SKILL.md (now copied into customer repos by the wizard) or packages/stack/README.md and runs `db setup`.
- Mechanism: The `setup` case was removed from runDbCommand (base stash.ts:158) so it hits 'Unknown db subcommand' (head stash.ts:193-194); skills/stash-cli/SKILL.md:62-72 and packages/stack/README.md:469 still instruct it, and tsup now ships skills into dist (tsup.config.ts:26).
- Consequence: Onboarding instructions fail; agent guidance in customer repos is wrong. Loud and easily recovered.
- Affects: Bundled agent skills (skills/stash-cli) and packages/stack README, packages/cli `db install` command
- Evidence: `packages/cli/src/bin/stash.ts:158-169` (base); `packages/cli/src/bin/stash.ts:193-194`; `skills/stash-cli/SKILL.md:62-72`; `packages/cli/tsup.config.ts:26`; `packages/stack/README.md:469`
- Missing verification: Grep check that shipped docs/skills do not reference removed commands.
- Mitigation: Update skills/stash-cli and packages/stack README to `db install` in this PR, or keep `db setup` as a deprecated alias.

### Recommended controls

- Change the rewrite so no single migration both adds the encrypted column and drops the original; or guard DROP with a check that the original column is empty. (other; FS-1, FS-2, FS-3)
- Add an integration test against Postgres with EQL installed: populated table, rewritten migration, assert no data loss (or a refusal). Add regex tests for USING clauses and already-encrypted columns. (test; VG-1, FS-2)
- Run drizzle-kit generate on a project whose snapshot was produced with the previous @cipherstash/stack release and confirm no ALTER is generated for existing encrypted columns. (compatibility_check; FS-3, VG-2)
- Review rewrite-migrations.ts:14-78, post-agent.ts:62-133 (default-yes migrate after rewrite) and install.ts:51-65,172-180,332-351. (review_focus; FS-1, FS-2, FS-4)
- Update skills/stash-cli/SKILL.md and packages/stack/README.md for the removal of `db setup` before publishing the CLI. (documentation; FS-5)

### What this assessment could not see

- drizzle-kit internals (snapshot type comparison, how it renders a quoted schema-qualified custom type) were not available offline and were not verified. FS-3 is plausible_failure, not confirmed; its impact holds if the mechanism occurs.
- Tests were not run locally (no installed dependencies). CI shows only check-run conclusions; which CLI tests ran is not visible. Verification statuses are exists_not_run except the aggregate CI pass.
- wire-call-sites.ts, changelog.ts, env/index.ts, install-forge.ts and README changes were skimmed at diff level only. Risks in those report-only/experimental paths may be missed; they do not alter databases.
- No deployment or release context (changesets, publish order of @cipherstash/cli vs @cipherstash/stack). Cannot assess whether CLI and stack versions ship together; the stack dataType change and the CLI rewriter may reach users independently.
- Whether drizzle migrators accept multi-statement chunks for every driver (e.g. HTTP drivers) when the rewrite emits several statements without `--> statement-breakpoint` was not checked. Possible loud migration failure for some drivers is not assessed.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
