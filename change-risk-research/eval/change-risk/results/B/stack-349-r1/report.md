## Change risk: Changes or verification required

**Impact if something goes wrong:** critical · **Verification confidence:** low · `530625f59c..a47a63e40b`

A batch of CLI onboarding changes plus one change to the published @cipherstash/stack Drizzle integration. The material risk is new automatic rewriting of Drizzle migrations: any `ALTER COLUMN ... SET DATA TYPE eql_v2_encrypted` is replaced with ADD tmp column / DROP original / RENAME, with the data-copying UPDATE emitted only as a comment. Before this change such a migration failed loudly with a cast error. Now it succeeds and permanently drops the column's data. The wizard does this on columns the user picked from their live database, then offers to run `drizzle-kit migrate` with yes as the default. Separately, @cipherstash/stack now reports the Drizzle column type as `"public"."eql_v2_encrypted"`. That plausibly makes drizzle-kit see a type change on columns that are already encrypted, and the rewrite would then drop ciphertext. Other changes alter defaults: `db install` auto-detects Drizzle and Supabase with no way to opt out, the CLI loads `.env.local` before `.env`, a non-superuser role silently falls back to the no-operator-family install, and `db setup` is removed while bundled skills and the stack README still tell users to run it. The new tests cover only detection and the rewrite's text output; nothing covers the data effect. Advisory: changes or verification are needed before release.

### Failure scenarios

**FS-1 · Wizard rewrites encryption migration into DROP COLUMN and runs it, destroying existing plaintext data** (critical impact, observed in the code)

- Trigger: A Drizzle user runs the wizard and selects existing, populated columns from their database to encrypt (the normal wizard flow), then accepts the default 'Run the migration now?' prompt. The same applies to anyone who later applies a migration rewritten by `db install` to a populated database.
- Mechanism: gather.ts introspects the live DB and the user picks columns from those tables. The agent changes them to encryptedType and drizzle-kit generate emits ALTER COLUMN ... SET DATA TYPE eql_v2_encrypted. rewriteEncryptedAlterColumns replaces that with ADD tmp / `-- UPDATE ...` (commented out) / DROP COLUMN original / RENAME (rewrite-migrations.ts:66-78). post-agent.ts then prompts to run drizzle-kit migrate with initialValue true. The emitted guidance says to backfill the new column BEFORE running the migration, but the new column is created by that same migration, so the instruction cannot be followed.
- Consequence: The original column and all its values are dropped and replaced by an all-NULL encrypted column. The migration succeeds with no error, so the loss is silent and irreversible without a backup. At base the same migration failed loudly with a cast error and no data was lost.
- Affects: @cipherstash/cli wizard post-agent steps, @cipherstash/cli db install (Drizzle path), Customer databases and Drizzle migration files
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:14-78`; `packages/cli/src/commands/wizard/lib/post-agent.ts:42-133`; `packages/cli/src/commands/wizard/lib/gather.ts:55-63`; `packages/cli/src/__tests__/rewrite-migrations.test.ts:18-37`
- Existing verification: rewrite-migrations.test.ts asserts that the DROP COLUMN text is emitted. It checks the SQL text only and does not cover populated tables. [exists_not_run]
- Missing verification: An integration test applying the rewritten migration to a populated table, asserting that no rows are lost.; A test of the wizard flow showing it does not migrate populated columns without an explicit backfill step.
- Mitigation: Do not emit DROP COLUMN automatically. Either stop and fail with guidance, or emit only ADD COLUMN and leave DROP/RENAME to a separate migration that runs after the app has backfilled via encryptModel. In the wizard, default the migrate prompt to no (or block it) when the rewrite touched any table that has rows.

**FS-2 · Changed Drizzle type string turns existing encrypted columns into ALTERs that the rewrite converts to DROP of ciphertext** (critical impact, plausible)

- Trigger: An existing user whose schema already uses encryptedType upgrades @cipherstash/stack, runs drizzle-kit generate, and then runs `db install` (Drizzle is now auto-detected) or the wizard, both of which sweep the migrations directory.
- Mechanism: encryptedType's dataType changes from 'eql_v2_encrypted' to '"public"."eql_v2_encrypted"' (drizzle/index.ts:12,104). drizzle-kit compares the type string with the previous snapshot and plausibly emits ALTER COLUMN ... SET DATA TYPE "public"."eql_v2_encrypted" for every existing encrypted column. The rewrite regex matches exactly this qualified form (rewrite-migrations.ts:14) and turns it into DROP of the existing encrypted column.
- Consequence: Already-encrypted ciphertext columns are dropped and replaced with NULL columns, an irreversible loss of encrypted data. Even without the rewrite, users see an unexpected type-change migration on upgrade.
- Affects: @cipherstash/stack drizzle integration (encryptedType), drizzle-kit snapshots and generated migrations in customer repos, @cipherstash/cli db install (Drizzle path), Customer databases and Drizzle migration files
- Evidence: `packages/stack/src/drizzle/index.ts:12`; `packages/cli/src/commands/db/rewrite-migrations.ts:14-78`; `packages/cli/src/commands/db/install.ts:332-352`; `packages/stack/src/drizzle/index.ts:6-12` (inferred)
- Missing verification: Run drizzle-kit generate on a project with a snapshot from the base version and confirm whether it emits an ALTER for encrypted columns.; A test that the rewrite ignores ALTERs whose source column is already eql_v2_encrypted.
- Mitigation: Confirm drizzle-kit's diff behaviour before release. If it diffs, keep the bare type name or document a no-op snapshot update, and make the rewrite apply only to newly generated migration files rather than the whole directory.

**FS-3 · `db install` in Drizzle projects silently stops installing EQL and edits migration files instead** (medium impact, plausible)

- Trigger: A project that lists drizzle-orm or drizzle-kit runs `npx @cipherstash/cli db install` without --drizzle, for example from CI, a script or the wizard's post-agent step.
- Mechanism: resolveProviderOptions enables drizzle from detectDrizzle(process.cwd()) (install.ts:154-182). parseArgs only sets flags to true (stash.ts:122-136), so there is no opt-out. The command then generates a migration file, rewrites sibling migrations and exits 0, but does not execute SQL against the DB. In the wizard, `db push` runs next, before any migration is applied.
- Consequence: Callers that expected EQL in the database get exit 0 with EQL not installed, and later commands fail or behave inconsistently. Migration files are modified in the working tree without being asked for.
- Affects: @cipherstash/cli db install (Drizzle path), @cipherstash/cli wizard post-agent steps
- Evidence: `packages/cli/src/commands/db/install.ts:154-182`; `packages/cli/src/bin/stash.ts:122-136`; `packages/cli/src/commands/wizard/lib/post-agent.ts:42-133`
- Existing verification: detect.test.ts covers detectDrizzle/detectSupabase only, not installCommand's branching. [exists_not_run]
- Missing verification: A test of installCommand with no flags in a Drizzle project.; An opt-out path such as --no-drizzle or --direct.
- Mitigation: Add an explicit opt-out flag, print a prominent note that no SQL was executed, and make the wizard apply the migration before `db push`.

**FS-4 · New .env.local precedence points db commands at a different database** (medium impact, plausible)

- Trigger: A project has different DATABASE_URL values in .env.local (or .env.development*) and .env.
- Mechanism: stash.ts:7-10 now loads .env.local first. dotenv does not override keys already set, so .env.local's DATABASE_URL wins, where at base only .env was read (base stash.ts:2).
- Consequence: `db install`, `db push`, `db upgrade` and the wizard's migrate step connect to a different database than they did with the previous version. EQL could be installed, config pushed, or migrations run against an unintended environment.
- Affects: CLI environment resolution (dotenv), Customer databases and Drizzle migration files
- Evidence: `packages/cli/src/bin/stash.ts:7-10`
- Missing verification: A test, or a printed message, showing which env file supplied DATABASE_URL.
- Mitigation: Log the resolved env file and database host before any DB-mutating command, and call out the precedence change in release notes.

**FS-5 · Shipped skills and the stack README still instruct the removed `db setup`** (low impact, observed in the code)

- Trigger: A user or an AI agent follows skills/stash-cli/SKILL.md (now bundled and copied into customer repos by the wizard) or packages/stack/README.md.
- Mechanism: `db setup` was removed (setup.ts deleted; unknown db subcommands exit 1), but SKILL.md:69-72 and the stack README:469 still reference it, and tsup now ships skills/ into dist.
- Consequence: Onboarding commands fail with 'Unknown db subcommand'. It is a loud failure but a launch-path regression and wrong agent guidance in customer repos.
- Affects: Bundled skills (skills/stash-cli) and packages/stack/README.md
- Evidence: `packages/cli/src/bin/stash.ts:193-197`; `skills/stash-cli/SKILL.md:69-72`; `packages/cli/tsup.config.ts:24-26`
- Missing verification: A check that bundled docs and skills reference only existing commands.
- Mitigation: Update skills/stash-cli/SKILL.md and packages/stack/README.md to `db install`, or keep `db setup` as a deprecated alias for one release.

### Recommended controls

- Block release until the rewrite no longer emits an automatic DROP COLUMN (or is gated behind an explicit confirmation stating that data will be deleted), and the wizard no longer defaults to migrating. (review_focus; FS-1, VG-1)
- Run drizzle-kit generate on a fixture project with a snapshot made by the previous @cipherstash/stack and confirm no ALTER is produced for existing encrypted columns. Limit the rewrite to the newly generated migration file. (compatibility_check; FS-2, VG-2)
- Add an integration test (Postgres plus EQL) applying the rewritten migration to a table that has rows and asserting that the data is preserved or the migration refuses to run. (test; FS-1, VG-1)
- Add opt-outs for auto-detection, print the resolved env file and DB host before mutating commands, and restore the permission check in the non-superuser fallback branch. (other; FS-3, FS-4)
- Update the bundled skills and the stack README from `db setup` to `db install`. Add release notes covering the removed command and the .env precedence change. (documentation; FS-5, FS-4)

### What this assessment could not see

- drizzle-kit's diff and snapshot behaviour for custom type strings was not verified (no network, no drizzle-kit source in the checkout). FS-2 remains plausible_failure rather than observed.
- Tests were not run (no node_modules) and no CI results were provided. All existing verification is exists_not_run. Verification confidence is low.
- Wizard additions (changelog, call-site scanner, skills installer), the env command and init streaming were read but only skimmed for risk. Whether EQLInstaller.install is transactional was not checked. Partial-install effects of the BC-4 permission bypass are unassessed.
- There is no PR body, CODEOWNERS file or deployment and release context (for example changesets or version pairing between @cipherstash/cli and @cipherstash/stack). Could not tell whether the stack and CLI changes ship together or what release notes say.

_Inputs unavailable: ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
