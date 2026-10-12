## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `48889952ec..8dcbf05390`

The CLI's Drizzle migration sweep now matches the whole eql_v3_* domain family, schema-qualified tables and extra mangled forms; it is now also run by `stash eql migration --drizzle`, not only by `eql install --drizzle`. Matched sibling migrations are rewritten on disk into ADD+DROP+RENAME, which is DROP+ADD and loses the column's data. Before this change a v3 user's in-place ALTER failed at migrate time. Now the file is turned into runnable SQL that drops the column, with a header comment and a log line as the only guard. The sweep only sees the target type, not the source type. So an encrypted-to-encrypted v3 domain change (for example eql_v3_text_eq to eql_v3_text_search) is rewritten the same way and would drop already-encrypted data. Whether Postgres would have accepted the original jsonb-domain-to-jsonb-domain ALTER is unverified. Regex coverage in the unit tests is extensive, but nothing tests against a real Postgres. No tests were run and no CI results were available. The wizard's copy of the rewriter stays v2-only by design (documented).

### Failure scenarios

**FS-1 · Encrypted-to-encrypted v3 domain change is rewritten into DROP+ADD, losing ciphertext** (high impact, plausible)

- Trigger: A user changes an already-encrypted Drizzle column from one v3 domain to another (e.g. adds ordering/search: eql_v3_text_eq → eql_v3_text_search). drizzle-kit emits ALTER … SET DATA TYPE "undefined"."eql_v3_text_search";. The user then runs `stash eql migration --drizzle` or `eql install --drizzle` with that file in the out directory.
- Mechanism: ALTER_COLUMN_TO_ENCRYPTED_RE only captures table, column and target type; the source type is not in the statement, so a domain-to-domain change is indistinguishable from plaintext-to-encrypted. Every match is rewritten into ADD tmp / DROP original / RENAME. v3 domains are CREATE DOMAIN … AS jsonb, so a jsonb-domain to jsonb-domain ALTER may have been runnable as-is if the target domain's CHECK accepts the existing payloads. That would turn a working migration into a destructive one. Unverified: the v3 domain DDL is not in the checkout.
- Consequence: When the migration is applied, the encrypted column on a populated table is dropped and replaced by an all-NULL column. Its ciphertext is unrecoverable without a backup, and the CLI output frames the rewrite as a fix for an unrunnable migration. Tables that never held plaintext are hit, so the header comment, which is written about plaintext columns, is easy to dismiss.
- Affects: packages/cli db/rewrite-migrations.ts (migration sweep), `stash eql migration --drizzle` command, `stash eql install --drizzle` / `db install` command, Customer Drizzle migration directories and the databases they are applied to
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:72-80`; `packages/cli/src/commands/db/rewrite-migrations.ts:147-193`; `packages/cli/src/commands/db/rewrite-migrations.ts:217-244`; `packages/stack-drizzle/src/v3/codec.ts:1-6` (inferred); `packages/cli/src/commands/eql/migration.ts:227-265`
- Existing verification: Unit tests assert that every v3 domain target is rewritten. None distinguish source type or cover encrypted→encrypted changes. [exists_not_run]
- Missing verification: Run drizzle-kit generate for an eql_v3_text_eq → eql_v3_text_search change and apply the unrewritten ALTER against a Postgres with the EQL v3 bundle and encrypted rows, to establish whether it was runnable before the rewrite.; A test or guard that skips or flags (rather than rewrites) ALTERs whose source column is already an EQL type, e.g. by consulting the drizzle snapshot JSON.
- Mitigation: Use the drizzle snapshot (or a sibling meta/_journal) to tell whether the source column was already an EQL type, and report those statements as `skipped` instead of rewriting them. Otherwise make the rewrite opt-in or interactive whenever a matched statement exists, and document domain-to-domain changes explicitly.

**FS-2 · Loud migrate failure on populated v3 tables becomes silent plaintext loss** (high impact, plausible)

- Trigger: A v3 user changes a populated plaintext column to an eql_v3_* domain, runs `stash eql migration --drizzle`, and then runs `drizzle-kit migrate` (as the CLI's Next Steps note instructs) without reading the rewritten file's header. CI/CD pipelines that run migrate automatically are included.
- Mechanism: At base the v3 path left the in-place ALTER untouched, so migrate failed with a cast error and no data changed. At head the sweep rewrites it into ADD+DROP+RENAME, which Postgres accepts. The only guards are SQL comments and an info-level log line. The closing note still says to run drizzle-kit migrate, and the sweep is non-fatal.
- Consequence: The original plaintext column is dropped and the new encrypted column is NULL for every row. Data is lost on the first migrate, in whatever environment runs it, possibly production.
- Affects: `stash eql migration --drizzle` command, Customer Drizzle migration directories and the databases they are applied to, packages/cli db/rewrite-migrations.ts (migration sweep)
- Evidence: `packages/cli/src/commands/eql/migration.ts:227-265`; `packages/cli/src/commands/db/rewrite-migrations.ts:147-193`; `packages/cli/src/commands/db/rewrite-migrations.ts:217-244`; `packages/cli/src/commands/eql/migration.ts:211-216` (base) (inferred)
- Existing verification: migration.test.ts asserts that the sibling is rewritten and that the generated migration is skipped. rewrite-migrations.test.ts asserts the header text. Nothing checks that the user is stopped or asked to confirm. [exists_not_run]
- Missing verification: A decision, recorded in the PR, that auto-rewriting to destructive SQL is preferable to failing loudly for v3 users.; A test that the Next Steps note warns about data loss when files were rewritten (currently it only warns when the sweep is incomplete).
- Mitigation: When `rewritten` is non-empty, raise the log to warn level and change the Next Steps note to say that rewritten files drop data on non-empty tables. Alternatively, require a --rewrite-alters flag or a confirmation prompt before writing.

**FS-3 · Sweep rewrites historical, already-applied migrations in the out directory** (medium impact, plausible)

- Trigger: The out directory contains an older migration with a v3 SET DATA TYPE statement that was already applied, e.g. against an empty table or a domain-to-domain change. `stash eql migration --drizzle` is then run, for example on an EQL upgrade.
- Mechanism: The sweep iterates every *.sql entry in outDir except the newly generated file and writes changes back unconditionally (rewrite-migrations.ts:147-183). It does not consult the drizzle journal to skip applied migrations, so the history of applied migrations is edited.
- Consequence: Committed migration history diverges from what production ran. Fresh environments replay different DDL (DROP+ADD instead of ALTER), which can lose constraints or indexes, and the diff appears as an unexpected change to old migrations in review.
- Affects: packages/cli db/rewrite-migrations.ts (migration sweep), `stash eql migration --drizzle` command, Customer Drizzle migration directories and the databases they are applied to
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:147-193`; `packages/cli/src/commands/eql/migration.ts:227-265`
- Missing verification: A test that applied migrations (per meta/_journal.json) are not rewritten.
- Mitigation: Limit the sweep to migrations not yet in the journal, or to files newer than the last applied entry; otherwise list rewritten historical files prominently.

### Recommended controls

- Add an integration test against Postgres with the EQL v3 bundle. It should cover (a) a domain-to-domain ALTER generated by drizzle-kit, showing whether it was runnable unrewritten, and (b) that the rewritten SQL executes. (test; FS-1, VG-1)
- Reviewer should decide whether rewriting into data-destroying SQL by default is acceptable for the v3 migration-first path. The alternatives are a flag/prompt, or flagging instead of rewriting. The reviewer should also decide whether encrypted→encrypted changes must be excluded. (review_focus; FS-1, FS-2)
- Escalate the 'Rewrote N files' message to warn and mention data loss in the closing Next Steps note whenever files were rewritten. (other; FS-2)
- Skip migrations already listed in meta/_journal.json, or at least report historical files separately. (other; FS-3, VG-3)
- Run packages/cli unit tests (rewrite-migrations.test.ts, eql/__tests__/migration.test.ts) in CI before release. (test; VG-2)

### What this assessment could not see

- The EQL v3 domain DDL (CHECK constraints on eql_v3_* domains) is not in the checkout; only a code comment states the domains are CREATE DOMAIN … AS jsonb. It could not be established whether a domain-to-domain ALTER would succeed unrewritten. FS-1 stays plausible_failure.
- Tests could not be run (no installed dependencies, no network), and a scratch node script to exercise the regex required approval and was not run. All verification is exists_not_run. Regex behaviour is taken from reading the source.
- No PR description, deployment context or customer usage data was available. How often users run these commands against directories with populated-table or historical migrations is unknown.
- The wizard copy (packages/wizard/src/lib/rewrite-migrations.ts) remains v2-only and still uses the old `[^;]*;` tail. This is pre-existing and documented by the change; it was not assessed as a scenario. Wizard-scaffolded v3 projects, if any appear, would not get the repair. That is a loud migrate failure, not data loss.

_Inputs unavailable: pr_description, ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
