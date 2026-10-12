## Change risk: Changes or verification required

**Impact if something goes wrong:** critical · **Verification confidence:** low · `530625f59c..a47a63e40b`

A 25-file onboarding batch for @cipherstash/cli plus one change to the published @cipherstash/stack Drizzle integration. The material risk is a new migration rewriter. It now runs automatically from both `db install` (whenever Drizzle is auto-detected) and the wizard. It rewrites every `ALTER COLUMN ... SET DATA TYPE eql_v2_encrypted` in the project's migration directory into ADD tmp column / commented-out UPDATE / DROP original column / RENAME. Before this change, such a migration failed loudly with a cast error. Now it runs and irreversibly discards the original column's data on any populated table, and the wizard offers to run it straight away (default yes). The stack change also switches the Drizzle column type string to `"public"."eql_v2_encrypted"`. For existing Drizzle users this plausibly makes drizzle-kit emit exactly such ALTER statements for columns that are already encrypted, which the rewriter would then turn into DROPs of ciphertext. Other changes have lower impact. `db setup` is removed, but the bundled stash-cli skill (which the wizard now copies into customer repos) and the stack README still tell users to run it. Provider auto-detection replaces the old interactive provider prompt and has no opt-out. The CLI now loads .env.local/.env.development* ahead of .env, which can change which DATABASE_URL commands target. Unit tests cover the rewriter's text transform and the detectors, but nothing tests the data-preservation behaviour or the drizzle-kit interaction, and no test results were available.

### Failure scenarios

**FS-1 · Rewritten migration drops the original column on a populated table, losing its data** (critical impact, observed in the code)

- Trigger: A Drizzle user converts an existing populated text/numeric column to encryptedType (the wizard's core use case), drizzle-kit emits ALTER COLUMN ... SET DATA TYPE eql_v2_encrypted, and the user accepts the wizard's default-yes 'Run the migration now?' prompt or later runs drizzle-kit migrate.
- Mechanism: renderSafeAlter emits ADD tmp column, then the UPDATE only as an SQL comment, then DROP COLUMN of the original and RENAME (rewrite-migrations.ts:67-79). Nothing copies or encrypts the existing values. The guidance comment says to backfill 'BEFORE running this migration', but the tmp column does not exist until the migration runs, so that instruction cannot be followed. The wizard runs the rewriter and then offers migrate with initialValue true (post-agent.ts:73-85).
- Consequence: Every value in the converted column is permanently deleted and replaced by NULL. Before this change, the same migration failed loudly with a cast error and left the data intact. If DATABASE_URL points at a shared or production database, the loss cannot be undone without a backup.
- Affects: packages/cli db install / migration rewriter, packages/cli wizard post-agent steps, Customer PostgreSQL databases and their Drizzle migration directories
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:14-62`; `packages/cli/src/commands/db/rewrite-migrations.ts:67-79`; `packages/cli/src/commands/wizard/lib/post-agent.ts:64-87`; `packages/cli/src/commands/wizard/lib/post-agent.ts:108-133`
- Existing verification: rewrite-migrations.test.ts asserts that the DROP COLUMN/RENAME text is produced. It does not check data preservation. [exists_not_run]
- Missing verification: An integration test that applies a rewritten migration to a populated table and checks whether data survives; Confirmation that rewriting already-applied migration files is safe for drizzle's migration journal
- Mitigation: Do not emit DROP COLUMN automatically. Leave the original column in place (ADD the encrypted column only) and require an explicit backfill step before a separate drop migration. At minimum, abort or require explicit confirmation when the target table has rows, and change the wizard's migrate prompt default to no when anything was rewritten.

**FS-2 · Type-string change makes drizzle-kit regenerate ALTERs for already-encrypted columns, which the rewriter turns into DROPs of ciphertext** (critical impact, plausible)

- Trigger: An existing Drizzle user with encrypted columns upgrades @cipherstash/stack, runs drizzle-kit generate, and then runs the wizard or `db install` (auto-detected Drizzle path), or applies the regenerated migration.
- Mechanism: encryptedType's dataType() changes from 'eql_v2_encrypted' (base drizzle/index.ts:96) to '"public"."eql_v2_encrypted"' (head :12, :104). drizzle-kit snapshots store the column type string, so a changed string plausibly diffs as a type change and emits ALTER COLUMN ... SET DATA TYPE "public"."eql_v2_encrypted". The rewriter's regex matches the qualified form explicitly (rewrite-migrations.ts:14-15) and sweeps the whole directory.
- Consequence: Columns that already hold ciphertext are dropped and recreated empty: permanent loss of encrypted data. Without the rewriter the ALTER would be a same-type no-op.
- Affects: @cipherstash/stack/drizzle (published entry), packages/cli db install / migration rewriter, Customer PostgreSQL databases and their Drizzle migration directories
- Evidence: `packages/stack/src/drizzle/index.ts:12`; `packages/stack/src/drizzle/index.ts:96` (base); `packages/cli/src/commands/db/rewrite-migrations.ts:14-62`; `packages/cli/src/commands/db/install.ts:332-351`
- Missing verification: Run drizzle-kit generate on a project whose snapshot was produced with the previous stack version and inspect the output; A test that the rewriter ignores columns that are already eql_v2_encrypted
- Mitigation: Verify drizzle-kit's snapshot diff across the type-string change before release. Make the rewriter skip columns whose previous type is already eql_v2_encrypted (e.g. by consulting the drizzle snapshot) and only touch migrations generated in the current run. Add a changeset and upgrade note for @cipherstash/stack.

**FS-3 · Shipped stash-cli skill and stack README still instruct the removed `db setup` command** (medium impact, observed in the code)

- Trigger: A user, or a coding agent reading the skill the wizard just installed into .claude/skills, follows the documented `npx @cipherstash/cli db setup` command.
- Mechanism: db setup is removed from the CLI dispatch (setup.ts deleted). skills/stash-cli/SKILL.md:69-72 and packages/stack/README.md:469 at head still document it, and the wizard now copies stash-cli into customer repos for every integration.
- Consequence: The command fails with the unknown-command or unknown-db-subcommand path. Agents in customer repos receive wrong guidance, and the copied skill persists there after later CLI fixes. Existing scripts or CI that call `db setup` break.
- Affects: skills/stash-cli (bundled into the CLI dist and copied into customer repos), packages/stack README (published to npm)
- Evidence: `packages/cli/src/commands/db/setup.ts:1-224` (base); `skills/stash-cli/SKILL.md:69-72`; `packages/stack/README.md:469`; `packages/cli/src/commands/wizard/lib/install-skills.ts:14-19`
- Missing verification: A check that bundled skills and READMEs only reference commands the CLI dispatches
- Mitigation: Update skills/stash-cli/SKILL.md and the stack README to `db install` in this change, or keep `db setup` as a deprecated alias of `db install` for one release.

**FS-4 · Auto-detection without opt-out picks the wrong install mode** (medium impact, plausible)

- Trigger: A project has drizzle-orm installed but the user wants a direct EQL install, or a Supabase database is reached through a host that is not *.supabase.co/.com (local Supabase on 127.0.0.1, a custom domain, or a proxy).
- Mechanism: resolveProviderOptions only treats undefined as 'detect'. parseArgs only sets flags to true, so --drizzle/--supabase cannot be negated (install.ts:154-180, stash.ts parseArgs). detectSupabase matches host suffixes only (detect.ts:23-25). The removed db setup asked the user to pick a provider explicitly (base setup.ts:184-216).
- Consequence: Drizzle projects get a migration file plus a migration-directory sweep (FS-1) instead of a direct install. Undetected Supabase installs skip the anon/authenticated/service_role grants, so EQL functions fail at query time through PostgREST. Both failures are loud but confusing, and the first feeds FS-1.
- Affects: packages/cli db install / migration rewriter, Customer PostgreSQL databases and their Drizzle migration directories
- Evidence: `packages/cli/src/commands/db/install.ts:154-183`; `packages/cli/src/bin/stash.ts:112-138`; `packages/cli/src/commands/db/detect.ts:18-26`; `packages/cli/src/commands/db/setup.ts:184-223` (base)
- Existing verification: detect.test.ts covers detectSupabase/detectDrizzle unit behaviour [exists_not_run]
- Missing verification: A test of resolveProviderOptions and the install-command path selection
- Mitigation: Support --no-drizzle/--no-supabase (or prompt to confirm detected values in interactive runs), and print the detected mode before any file is written.

**FS-5 · New .env precedence silently retargets DATABASE_URL for db install/push and migrations** (medium impact, plausible)

- Trigger: A project whose .env.local or .env.development* sets a different DATABASE_URL than .env (common in Next.js setups) runs any stash CLI command.
- Mechanism: stash.ts:7-10 loads .env.local first, and dotenv does not overwrite keys that are already set, so its DATABASE_URL now wins. At base only .env was loaded (base stash.ts:2).
- Consequence: EQL install, `db push` and the wizard's migrate step run against a different database than before the upgrade, with no message saying which file supplied the URL. Combined with FS-1, a destructive migration could land on an unexpected database.
- Affects: packages/cli db install / migration rewriter, Customer PostgreSQL databases and their Drizzle migration directories
- Evidence: `packages/cli/src/bin/stash.ts:7-10`; `packages/cli/src/bin/stash.ts:2` (base)
- Missing verification: Any test of env-file precedence
- Mitigation: Log which env file supplied DATABASE_URL and the target host before any mutating command. Document the precedence change in the changelog.

### Recommended controls

- Block release until the rewriter no longer emits an automatic DROP COLUMN for populated tables, and the wizard does not default to running a rewritten migration. (review_focus; FS-1, VG-1)
- Run drizzle-kit generate against a project snapshot produced by @cipherstash/stack 0.15.0's previous type string and confirm no ALTER is emitted for existing encrypted columns. Restrict the rewriter to migrations generated in the current run. (compatibility_check; FS-2, VG-2)
- Add an integration test (Postgres with EQL) that applies a rewritten migration to a table with rows and asserts the outcome the team intends. (test; FS-1, VG-1)
- Update skills/stash-cli/SKILL.md and packages/stack/README.md to `db install`, or keep `db setup` as a deprecated alias. Add changesets for cli and stack noting the removed command, auto-detection and env precedence. (documentation; FS-3, FS-5, VG-3)
- Add negatable --no-drizzle/--no-supabase flags and print the resolved DATABASE_URL source/host and install mode before mutating anything. (other; FS-4, FS-5, VG-4)
- npm publishes cannot be undone, and dropped columns in customer databases cannot be restored by a CLI rollback. Plan a fast follow-up release and advise users to back up before running wizard migrations. (rollback_plan; FS-1, FS-2)

### What this assessment could not see

- drizzle-kit's snapshot-diff behaviour for a changed custom-type string, and how it quotes a dataType that already contains quotes, could not be checked: there is no node_modules and no network. FS-2 stays plausible_failure. Its critical impact rests on the rewriter mechanism, which was verified.
- No tests were run (no installed dependencies) and no CI results were provided. All existing verification is exists_not_run. Verification confidence is low.
- The wizard's runStep executes `db install` with stdio 'pipe' while db install can prompt interactively. That was already true for `db setup` at base. How clack prompts behave without a TTY was not established. Unknown whether the wizard's db install step completes or times out. This could hide or change the FS-4 path in wizard runs.
- Wizard changelog, call-site scanner, env command and install-forge streaming were skimmed only. They appear additive or read-only. Minor issues in those modules may be missed. They do not change the overall rating.
- AGENTS.md and other architecture docs were not consulted, there is no CODEOWNERS file, and there was no PR description beyond the title. Intent behind the rewriter design (e.g. whether data loss is an accepted onboarding trade-off) is unknown.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
