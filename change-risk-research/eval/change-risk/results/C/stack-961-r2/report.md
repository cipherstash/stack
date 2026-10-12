## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `ec590a08cd..386792876d`

Before this change, `stash eql install` and `stash eql upgrade` ran the bundle as BEGIN/bundle/COMMIT. Its DROP SCHEMA ... CASCADE silently deleted anything that depended on EQL, including indexes, views, policies and columns. The new protocol takes a time-limited advisory lock and walks pg_depend from the EQL schemas. If any customer object other than an index depends on EQL, it refuses before changing anything. Otherwise it runs the bundle, rebuilds the captured functional indexes, runs ANALYZE and checks the result, all in one transaction. This is a large safety improvement, and new live-Postgres tests cover it; they passed in CI on PG16 and PG17. The remaining release risks are operational. (1) Dropping the indexes takes ACCESS EXCLUSIVE locks on customer tables, and those locks are now held through every rebuild and ANALYZE. Upgrading large encrypted tables therefore blocks reads and writes until the rebuild finishes. This is documented as maintenance-window only but not tested at realistic sizes. (2) Databases with views, policies, constraints or triggers that use EQL functions can no longer upgrade through the CLI, and there is no override. (3) Any operator in `public`, and any cast, whose function is in an EQL schema is treated as part of the bundle, so a customer-created one is still dropped without warning. Impact is high (availability), but the high-impact scenario is a documented, accepted trade-off, so I rate this as needing focused review rather than as blocking.

### Failure scenarios

**FS-1 · Upgrade blocks all reads and writes on large encrypted tables for the whole index rebuild** (high impact, plausible)

- Trigger: `stash eql upgrade` (or `install --force`) on a database with EQL functional indexes on large, live tables.
- Mechanism: The bundle's DROP SCHEMA ... CASCADE drops every dependent index. In PostgreSQL that takes ACCESS EXCLUSIVE on each indexed table. The change keeps the transaction open through a non-concurrent CREATE INDEX for every captured index, the ALTER/COMMENT/statistics statements, and ANALYZE of every affected table, and only then commits (derived-search-index-restoration.ts:571-598, 679-686). At base the transaction committed right after the bundle, so the locks were held only while the bundle ran.
- Consequence: Application queries on encrypted tables wait for the full rebuild and ANALYZE, which can take minutes to hours on large tables. In effect the encrypted data path is down. If a statement_timeout or connection limit on a managed Postgres kills the transaction, everything rolls back, and the upgrade cannot finish without the operator changing settings.
- Affects: packages/cli installer (derived-search-index-restoration.ts, index.ts), Customer PostgreSQL databases with EQL v3 installed
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:84-429`; `packages/cli/src/installer/derived-search-index-restoration.ts:571-651`; `packages/cli/src/installer/index.ts:194-214`; `packages/cli/README.md:213-222`
- Existing verification: reinstall.live and upgrade-encrypted-indexes.live rebuild indexes on small tables; the CI Run Tests jobs that run them passed. [ran_passed]
- Missing verification: No measurement of lock duration or rebuild time on a realistically sized table.; No test with a statement_timeout typical of managed Postgres.
- Mitigation: The README (lines 220-222) and the ADR consequences say to run it in a maintenance window. Also consider a pre-flight warning or `--dry-run` that lists the indexes and table sizes to be rebuilt, and statement_timeout/lock_timeout guidance in the release notes.

**FS-2 · Databases with EQL-dependent views, policies or constraints can no longer upgrade via the CLI** (medium impact, plausible)

- Trigger: A customer has a view, RLS policy (common on Supabase), CHECK constraint, generated column or trigger condition that calls an eql_v3 function, upgrades the CLI, then runs `stash eql upgrade`.
- Mechanism: inspectReinstallDependencies throws EqlReinstallRefusalError for any dependent object that is not an index (derived-search-index-restoration.ts:552-556). install and upgrade report it as exit 1 (install.ts:210, upgrade.ts:59). `--force` goes through the same install() call (index.ts:196), so there is no way around the refusal.
- Consequence: The upgrade is blocked loudly, and nothing is changed. The customer must drop and recreate the dependent objects by hand around the upgrade. Otherwise they stay on the old SQL bundle while the CLI and client expect a newer EQL, leaving the two out of step. This is not data loss: at base the same command silently destroyed those objects.
- Affects: packages/cli installer (derived-search-index-restoration.ts, index.ts), `stash eql install` / `stash eql upgrade` commands, Published `stash` npm package (changeset minor)
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:84-429`; `packages/cli/src/installer/__tests__/reinstall.live.test.ts:249-606`; `packages/cli/src/commands/db/install.ts:204-216`; `packages/cli/src/commands/db/upgrade.ts:53-65`; `packages/cli/src/installer/index.ts:194-214`; `.changeset/safe-eql-reinstall.md:1-20`
- Existing verification: reinstall.live it.each covers refusal before any change for an RLS policy, view, check constraint, generated column, trigger and customer operators; the CI Run Tests jobs passed. [ran_passed]
- Missing verification: No documented procedure for recreating refused objects. The refusal message lists them but gives no remedy.
- Mitigation: Add a release note that describes the new refusal and gives a manual drop/upgrade/recreate procedure. Consider printing the definitions of refused objects so they can be recreated.

**FS-3 · Customer operator in `public` or customer cast backed by an EQL function is classed as bundle-owned and silently dropped** (medium impact, plausible)

- Trigger: A customer created an operator in schema `public`, or a cast, whose function lives in eql_v3/eql_v3_internal, then reinstalls or upgrades.
- Mechanism: The exemption filter excludes every pg_operator in `public` whose oprcode is in an EQL schema (derived-search-index-restoration.ts:242-257), and every pg_cast whose castfunc is in an EQL schema (261-273), regardless of who created it. CASCADE then drops the object without reporting it. The tests cover customer operators only in a schema other than public, and the cast test expects the exemption.
- Consequence: The customer's object disappears after an upgrade that appears to succeed, and queries that use it then fail. This is the kind of silent loss the change says it prevents. It is not a regression, because base dropped these objects too.
- Affects: packages/cli installer (derived-search-index-restoration.ts, index.ts), Customer PostgreSQL databases with EQL v3 installed
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:84-429`; `packages/cli/src/installer/__tests__/reinstall.live.test.ts:249-606`
- Existing verification: Live tests: a customer operator in schema stash_reinstall_test is refused, and a cast whose function is in an EQL schema is exempted. [ran_passed]
- Missing verification: No test for a customer-created operator in `public` implemented by an EQL function.
- Mitigation: Decide whether an object belongs to the bundle by checking it against the installed bundle's expected surface (or an ownership marker), not by schema alone. Otherwise, document the limitation.

**FS-4 · Objects created by non-stash sessions between inspection and DROP are silently dropped** (medium impact, speculative)

- Trigger: Application migrations or other DDL create an object that depends on EQL while an upgrade is running.
- Mechanism: The advisory lock only serialises stash lifecycle commands (derived-search-index-restoration.ts:467-492). The dependency check takes no catalog locks before `client.query(bundledSql)` (683-684), so an object committed between the check and the bundle is dropped by CASCADE without being captured.
- Consequence: Silent loss of that index, view or policy. The docs already require a maintenance window to avoid this.
- Affects: packages/cli installer (derived-search-index-restoration.ts, index.ts), Customer PostgreSQL databases with EQL v3 installed
- Evidence: `packages/cli/src/installer/derived-search-index-restoration.ts:84-429`; `packages/cli/README.md:213-222`
- Missing verification: No test; this is a timing race.
- Mitigation: Already documented in the README maintenance-window note and the changeset. Optionally re-run the dependency check after the bundle and compare, or lock the dependent tables first.

### Recommended controls

- Review the exemption rules in LIFECYCLE_DEPENDENCIES_SQL (derived-search-index-restoration.ts:170-291), especially those for operators in `public` and for casts. (review_focus; FS-3, VG-2)
- Add live tests for a customer operator in `public` and a customer cast implemented by an EQL function, and expect both to be refused. (test; FS-3, VG-2)
- Release notes: say that an upgrade holds exclusive locks on tables with EQL indexes for the whole rebuild, and give a manual procedure for refused objects. (documentation; FS-1, FS-2)
- Time an upgrade on PG16/17 against a table with a realistic row count (for example 1-10M rows) and record how long the locks are held. Also check behaviour with a statement_timeout set. (test; FS-1, VG-1)
- Confirm from CI logs that upgrade-encrypted-indexes.live.test.ts ran, not skipped, on both PG legs. (other; VG-3)

### What this assessment could not see

- I read derived-search-index-restoration.ts, installation-state.ts, installer/index.ts, install.ts, upgrade.ts and the CI/turbo/vitest changes closely. I skimmed verify.ts, status.ts, validate.ts and the EQL sqlx uninstall tests, and did not read the unit tests in detail. Regressions from the status/verify/validate refactors (BC-4) were assessed only by skimming.
- No access to CI logs, customer deployment data or managed-Postgres settings. How bad FS-1 is depends on table sizes and timeouts I cannot see. I assume the individual live tests ran inside the passing jobs.
- That dropping an index through CASCADE holds ACCESS EXCLUSIVE on the parent table until commit comes from general PostgreSQL knowledge. I did not confirm it by running anything. That step of the FS-1 mechanism is inferred.
- I ran no tests and did not use the network or GitHub. Test results come only from the job conclusions in ci.json.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
