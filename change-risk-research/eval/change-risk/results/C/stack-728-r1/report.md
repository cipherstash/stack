## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `48889952ec..8dcbf05390`

The `stash` CLI's migration rewriter now also matches every `eql_v3_*` domain (by name shape) plus more drizzle-kit type spellings, and handles schema-qualified tables. It now runs on `stash eql migration --drizzle` too, and reports near-miss statements it will not rewrite. The rewrite turns `ALTER COLUMN … SET DATA TYPE <eql domain>` into ADD + DROP + RENAME, which drops the original column's data. For v2 that statement always failed in Postgres, so the rewrite only replaced a guaranteed failure. v3 domains are jsonb domains, so the same ALTER can be valid and keep its data when the column was already jsonb or another `eql_v3_*` domain. The rewriter never checks the source type, so in those cases it turns a working, data-preserving migration into one that destroys data, and it does this to every .sql file in the folder, including migrations already applied. For plaintext→v3 on a populated table, the loud migrate failure now becomes a migration that runs and drops the plaintext column. A header comment, a CLI log line and the skill docs warn about this, but nothing enforces it. CI is green and the unit tests are thorough for the regex. No test runs the rewritten SQL against Postgres, and none covers a v3 ALTER whose source is jsonb or another v3 domain.

### Failure scenarios

**FS-1 · A valid, data-preserving v3 domain change is rewritten into DROP COLUMN, destroying encrypted data** (high impact, plausible)

- Trigger: A v3 Drizzle user changes an existing encrypted column from one domain to another (e.g. `types.Text` → `types.TextSearch`) or from jsonb to a v3 domain. drizzle-kit emits `ALTER COLUMN … SET DATA TYPE "undefined"."eql_v3_text_search"`, and then `stash eql migration --drizzle` (or `eql install --drizzle`) runs over that directory.
- Mechanism: v3 columns are `CREATE DOMAIN public.eql_v3_* AS jsonb`, so changing a column from jsonb or one v3 domain to another needs no cast that Postgres lacks. The rewriter's case for rewriting ("no cast from text/numeric") does not hold here. ALTER_COLUMN_TO_ENCRYPTED_RE matches on the target type alone (rewrite-migrations.ts:78), and renderSafeAlter always emits ADD tmp + DROP original + RENAME (rewrite-migrations.ts:237-242). The negative tests cover a jsonb *target* but not a jsonb or v3 *source* (rewrite-migrations.test.ts:376-390).
- Consequence: drizzle-kit migrate applies the rewritten file. The column that held ciphertext is dropped and replaced by an all-NULL column, and NOT NULL, defaults and indexes are lost. If the plaintext was already retired through the staged encrypt lifecycle, the only copy of the data is gone and can only be restored from a database backup. Nothing fails at migrate time, so the data loss is silent.
- Affects: packages/cli rewrite-migrations (rewriteEncryptedAlterColumns), `stash eql migration --drizzle` command, Customer Drizzle migration files and the databases they are applied to
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:72-96`; `packages/cli/src/commands/db/rewrite-migrations.ts:217-243`; `packages/prisma-next/src/v3/wire-v3.ts:4`; `packages/cli/src/__tests__/rewrite-migrations.test.ts:170-390`
- Existing verification: Unit tests check that every v3 domain target is rewritten and that text/jsonb/eql_v4/not_eql_v3 targets are left alone. CI test jobs passed on head. [ran_passed]
- Missing verification: No test or decision on whether a v3→v3 or jsonb→v3 ALTER should be rewritten at all; No Postgres-backed test showing which source types actually fail the in-place ALTER (domain CHECK constraints may also cause failures)
- Mitigation: Rewrite only when the source type is known not to be jsonb or an eql_v3_* domain. That can come from the drizzle snapshot/journal (the PR defers this to #710), or failing that from reporting v3 matches as near-misses for the user to review rather than rewriting them automatically. At least document domain-to-domain changes as unsupported by the sweep.

**FS-2 · Plaintext→v3 migration on a populated table now runs and drops the plaintext instead of failing** (high impact, plausible)

- Trigger: A v3 user changes a populated plaintext column to an encrypted v3 type in their Drizzle schema, generates the migration, then runs `stash eql migration --drizzle` (e.g. as the recovery step the PR describes) and `drizzle-kit migrate` against production.
- Mechanism: Before this change no v3 statement matched, so `drizzle-kit migrate` failed loudly with `cannot cast type`. Now the sweep rewrites the statement into ADD+DROP+RENAME (rewrite-migrations.ts:237-242). The empty-table-only rule is stated only in a SQL comment, a CLI info line and the skills; nothing checks for rows before dropping the column.
- Consequence: The plaintext column is dropped in the same migration that adds an empty encrypted column, and the data cannot be recovered except from a backup. This mechanism already existed for v2 at base. This change extends it to every v3 user and to the v3 migration-first command.
- Affects: `stash eql migration --drizzle` command, Customer Drizzle migration files and the databases they are applied to, skills/stash-cli and skills/stash-drizzle (shipped in stash tarball)
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:217-243`; `packages/cli/src/commands/eql/migration.ts:215-262`; `skills/stash-cli/SKILL.md:391`
- Existing verification: Tests assert the guidance comment names the domain and warns about constraints. The migration.test.ts sweep test checks the rewrite happens. CI passed. [ran_passed]
- Missing verification: No guard (e.g. a `SELECT 1 FROM t LIMIT 1` precondition, or a statement that fails when the table has rows) that turns the populated-table case back into a loud failure
- Mitigation: Emit a guard in the rewritten SQL that aborts when the table has rows (e.g. a DO block that raises if rows exist), so the empty-table assumption is enforced rather than documented. Alternatively, ask for confirmation before rewriting interactively.

**FS-3 · Already-applied v3 migrations are rewritten on disk, so fresh environments get a different schema from production** (medium impact, plausible)

- Trigger: A project has an applied migration with a successful `SET DATA TYPE eql_v3_*` (jsonb or v3 source), and someone later runs `stash eql migration --drizzle` (e.g. for an EQL upgrade or a new environment).
- Mechanism: The sweep visits every .sql file except the one it just generated (rewrite-migrations.ts:153-154). It does not consult the drizzle journal, which the PR acknowledges and defers to #710.
- Consequence: Committed migration history no longer matches what production ran. Fresh databases (CI, staging, new regions) built from the rewritten history drop and re-add the column without constraints, defaults or indexes. drizzle-kit does not re-run applied migrations, so production itself is unaffected.
- Affects: `stash eql migration --drizzle` command, Customer Drizzle migration files and the databases they are applied to
- Evidence: `packages/cli/src/commands/eql/migration.ts:215-262`; pr_description; `packages/prisma-next/src/v3/wire-v3.ts:4`
- Existing verification: Test verifies that the just-generated install migration is skipped. [ran_passed]
- Missing verification: No test or guard for migrations listed in the drizzle journal as already applied
- Mitigation: Skip files listed in `meta/_journal.json` older than the newest entry, or list rewrites as a diff for the user to approve instead of writing silently. Tracked as #710.

### Recommended controls

- Reviewer should decide whether the sweep should rewrite a v3 target without knowing the source type, given that v3 domains are jsonb and the in-place ALTER can succeed and keep data. (review_focus; FS-1)
- Add a Postgres integration test (EQL v3 installed) covering text→v3 (fails in place), jsonb→v3 and v3→v3 (in-place behaviour), and the rewritten output on an empty and a populated table. (test; VG-1, VG-2, FS-1)
- Make the rewritten SQL abort when the table is non-empty (e.g. a DO block that raises if rows exist), so the empty-table-only rule is enforced rather than left to a comment. (other; FS-2, FS-1)
- Prioritise #710: consult the drizzle journal/snapshots before rewriting, so applied migrations and jsonb/v3-source ALTERs are not touched. (other; FS-3, FS-1)
- Release note / skill text: tell v3 users to review any file the sweep lists, and say explicitly that changing between v3 domains on a populated column is not something the sweep handles safely. (documentation; FS-1, FS-2)

### What this assessment could not see

- I did not run Postgres. I inferred that jsonb→v3 and v3→v3 in-place ALTERs succeed from v3 domains being `AS jsonb`, but domain CHECK constraints could make some of them fail anyway. FS-1 is plausible_failure, not observed. If those ALTERs always fail anyway, FS-1 reduces to FS-2.
- I did not run the tests myself. Test status comes from ci.json job-level conclusions, which do not list individual tests. ran_passed is attributed to the CI jobs that run the unit suite. I cannot tell from the inputs whether the new tests ran in a particular job.
- No deployment or usage data on how often v3 users run the sweep (the PR says the intended flow runs it before the broken migration exists). Likelihood of FS-1/FS-3 is unknown; only impact is assessed.
- I did not check the drizzle-kit versioned output table or the mangled forms myself. The test file and PR description claim them. Matcher completeness for other drizzle-kit versions is unverified, but a miss would fail loudly or show up as a near-miss.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
