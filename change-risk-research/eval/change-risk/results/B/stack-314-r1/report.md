## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `d3bc40e182..bcfeeb8ed1`

Adds a new public npm package @cipherstash/stack-forge (CLI 'stash-forge') that installs the EQL SQL bundle into a customer's Postgres and pushes the client's encryption schema into public.eql_v2_configuration, plus a new public EncryptionClient.getEncryptConfig() in @cipherstash/stack and an experimental changesets option. Library behaviour of @cipherstash/stack is unchanged apart from the additive getter. The material risk is in what the new CLI does to customer databases: 'push' deactivates every configuration row in an autocommitted statement and then inserts the new one outside a transaction, and the config it inserts uses stack's cast_as vocabulary ('number', 'bigint', 'json') which the EQL CHECK constraint rejects, so for schemas with those types push fails after having already deactivated the existing active (and any pending/encrypting) configuration. 'install' executes whatever SQL is at the EQL 'releases/latest' URL, unpinned and unverified. No test covers push or the installed SQL version; nothing was run. Verdict: changes or verification required before the first release of this package.

### Failure scenarios

**FS-1 · push leaves the database with no active (and a discarded pending/encrypting) EQL configuration when the INSERT fails** (high impact, observed in the code)

- Trigger: Any failure of the INSERT after the UPDATE succeeds: the CHECK constraint rejecting the config (see FS-2), a connection drop, or a permission error; or simply running push while an EQL encryption migration is in the 'pending'/'encrypting' state.
- Mechanism: push.ts runs UPDATE eql_v2_configuration SET state='inactive' with no WHERE clause and then a separate INSERT on a plain pg.Client with no BEGIN/COMMIT, so the UPDATE is autocommitted before the INSERT runs (packages/stack-forge/src/commands/push.ts:33-42). The UPDATE also flips 'pending' and 'encrypting' rows that EQL's migrate_config/activate_config lifecycle depends on.
- Consequence: Customer database is left with every configuration row inactive; anything that reads the active config (EQL helper functions, and per the README the runtime) sees none. An in-flight EQL column migration is silently abandoned. The CLI reports 'Failed.' but does not say the previous configuration was deactivated, and there is no rollback command.
- Affects: @cipherstash/stack-forge (new package and stash-forge CLI), Customer Postgres public.eql_v2_configuration table, EQL SQL functions that read the active/pending configuration (select_pending_columns, migrate_config, activate_config), CipherStash Proxy or other runtimes reading the active EQL configuration
- Evidence: `packages/stack-forge/src/commands/push.ts:25-54`; `packages/stack-forge/src/commands/push.ts:33-42`; `packages/schema/cipherstash-encrypt-2-1-8.sql:3598-3650`; `packages/schema/cipherstash-encrypt-2-1-8.sql:3364-3395`
- Existing verification: No test exercises pushCommand; stack-forge tests cover only loadStashConfig and EQLInstaller. [unknown]
- Missing verification: Test that a failing INSERT leaves the previous active configuration in place; Test against a real EQL-installed Postgres that push of a valid config succeeds and leaves exactly one active row; Decision on whether push should touch pending/encrypting rows at all
- Mitigation: Wrap UPDATE and INSERT in a single transaction (BEGIN/COMMIT with ROLLBACK on error), restrict the UPDATE to state='active', and refuse or warn when a pending/encrypting configuration exists; or go through EQL's own config functions.

**FS-2 · push always fails for schemas with number, bigint or json columns because stack's cast_as values are rejected by the EQL CHECK constraint** (high impact, observed in the code)

- Trigger: Running stash-forge push with an encryption client that has any column using dataType('number'), dataType('bigint'), dataType('json') or searchableJson().
- Mechanism: stack emits cast_as from castAsEnum ['bigint','boolean','date','number','string','json','text'], mapping only 'string' to 'text' (packages/stack/src/schema/index.ts:26-28, 170-175). push inserts this object unchanged. EQL's eql_v2_configuration_data_check calls config_check_cast, which only accepts {text, int, small_int, big_int, real, double, boolean, date, jsonb} and raises otherwise (packages/schema/cipherstash-encrypt-2-1-8.sql:3598-3614, 3642-3650).
- Consequence: push fails with a constraint error for many real schemas, and, combined with FS-1, does so after deactivating the existing configuration. If the CHECK is later relaxed or a different EQL version accepts these names, the stored config would carry type names that EQL-side code does not recognise.
- Affects: @cipherstash/stack-forge (new package and stash-forge CLI), @cipherstash/stack EncryptionClient, Customer Postgres public.eql_v2_configuration table
- Evidence: `packages/stack-forge/src/commands/push.ts:33-42`; `packages/stack/src/schema/index.ts:26-28`; `packages/schema/cipherstash-encrypt-2-1-8.sql:3598-3650`
- Existing verification: No test or example pushes a config containing non-text columns; examples/basic uses a text column only. [unknown]
- Missing verification: Integration test pushing configs with each castAs value into an EQL-installed database; A mapping test between stack castAs values and EQL cast_as values
- Mitigation: Translate stack cast_as values to EQL names (number -> double/int, bigint -> big_int, json -> jsonb) before inserting, or validate against the EQL vocabulary before touching the table; confirm with the EQL owners which vocabulary the DB-side config should use.

**FS-3 · install executes an unpinned, unverified 'latest' EQL SQL bundle against customer databases** (high impact, plausible)

- Trigger: A new EQL release (including a major/breaking one) is published, or the asset is replaced, after a given stack/stack-forge version ships; a customer then runs stash-forge install (or install --force / --drizzle).
- Mechanism: EQLInstaller and the drizzle path fetch https://github.com/cipherstash/encrypt-query-language/releases/latest/download/... at run time and execute or write the body with no version pin, checksum or signature (packages/stack-forge/src/installer/index.ts:3-6, 254; packages/stack-forge/src/commands/install.ts:243-244). The repo itself bundles a specific version (cipherstash-encrypt-2-1-8.sql). isInstalled() only checks for the eql_v2 schema, so version mismatch is not detected.
- Consequence: The installed SQL functions can differ from what the customer's @cipherstash/stack client version produces or expects (client/SQL-bundle pairing), breaking queries or payload checks; the same CLI version installs different SQL on different days, so failures are not reproducible. Executing remote SQL as a superuser makes the release asset a trust anchor with no integrity check.
- Affects: @cipherstash/stack-forge (new package and stash-forge CLI), Customer Postgres public.eql_v2_configuration table, EQL GitHub release asset (encrypt-query-language releases/latest)
- Evidence: `packages/stack-forge/src/installer/index.ts:3-6`; `packages/stack-forge/src/commands/install.ts:122-130`; signal `dependencies` (inferred)
- Existing verification: installer.test.ts mocks fetch and pg to check BEGIN/SQL/COMMIT and ROLLBACK on error; it does not check which version is fetched. [exists_not_run]
- Missing verification: A pinned EQL version (or compatibility range) tied to the stack-forge/stack release; Integrity check (checksum) of the downloaded SQL; Detection of an already-installed but different EQL version
- Mitigation: Pin the EQL release URL to a version compatible with the matching @cipherstash/stack release (or ship the SQL in the package as packages/schema already does) and verify a checksum; report installed vs expected version.

**FS-4 · --supabase grants ALL on the eql_v2 schema and future objects to the anon role** (medium impact, plausible)

- Trigger: A Supabase customer runs stash-forge install --supabase.
- Mechanism: grantSupabasePermissions grants USAGE, ALL ON ALL TABLES/ROUTINES/SEQUENCES and ALTER DEFAULT PRIVILEGES ... GRANT ALL to 'anon, authenticated, service_role' (packages/stack-forge/src/installer/index.ts:232-238).
- Consequence: Unauthenticated (anon) clients gain execute/write rights over every current and future eql_v2 object, including configuration-management routines, to the extent the schema is reachable through Supabase's API. Whether this exceeds EQL's documented Supabase guidance could not be checked.
- Affects: @cipherstash/stack-forge (new package and stash-forge CLI), Customer Postgres public.eql_v2_configuration table
- Evidence: `packages/stack-forge/src/installer/index.ts:229-239`
- Existing verification: No test covers the Supabase grant path. [unknown]
- Missing verification: Security review of the minimum grants needed by anon vs authenticated vs service_role
- Mitigation: Grant only USAGE and EXECUTE on the routines needed for queries, omit anon unless required, and avoid ALTER DEFAULT PRIVILEGES ... GRANT ALL.

**FS-5 · Experimental changesets option can stop peer-dependent packages from being re-released alongside their peers** (medium impact, speculative)

- Trigger: A future release bumps @cipherstash/protect (or another package with workspace peer dependents) within the declared peer range.
- Mechanism: onlyUpdatePeerDependentsWhenOutOfRange (.changeset/config.json:11-13) makes changesets skip bumping peer dependents whose range still matches. protect-dynamodb declares peerDependency '@cipherstash/protect': 'workspace:*', which pnpm rewrites to the exact current version at publish time, so a skipped re-release could leave the published peer range pinned to an older protect version.
- Consequence: Customers upgrading protect could get peer-dependency conflicts for protect-dynamodb; recovery needs a new release. How changesets evaluates 'workspace:*' under this option was not verified.
- Affects: Release pipeline (changesets publish via release.yml) and peer-dependent packages (protect-dynamodb, drizzle)
- Evidence: `.changeset/config.json:10-14`; `packages/protect-dynamodb/package.json:44-46`
- Missing verification: A changeset version dry run with a protect-only changeset to see which packages are bumped
- Mitigation: Run 'changeset version' on a throwaway branch with a protect patch/minor changeset and check protect-dynamodb's bump and published peer range; or drop the option from this PR, which it is not needed for.

### Recommended controls

- Make push transactional and limited to state='active', then add an integration test against an EQL-installed Postgres that (a) pushes configs using every castAs value and (b) forces an INSERT failure and asserts the previous active row survives. (test; FS-1, FS-2, VG-1)
- Map stack cast_as values to EQL names before insert (or validate up front) and get EQL owners to confirm the target vocabulary. (compatibility_check; FS-2)
- Pin the EQL SQL to a specific release compatible with the shipped @cipherstash/stack (or bundle it), verify a checksum, and surface installed-vs-expected version. (other; FS-3, VG-3)
- Security reviewer to look at the Supabase grant set in installer/index.ts:232-238, especially grants to anon and default privileges. (review_focus; FS-4)
- Run changeset version with a protect-only changeset before merging to confirm peer dependents still bump as intended, or split the changesets option into its own PR. (compatibility_check; FS-5, VG-4)
- Until push is fixed, document in README/SKILL.md that push deactivates existing configurations (including pending/encrypting) and is not safe on production databases; consider publishing stack-forge as a pre-release tag first. (documentation; FS-1, FS-2)

### What this assessment could not see

- No CI results and tests not run (no node_modules, no network). All test statuses are exists_not_run or unknown; build success of the new package (tsup path aliases, bin bundle, dts with type-only imports from a devDependency) is not confirmed.
- EQL behaviour was read from the SQL bundled in this repo (2.1.8); the version 'releases/latest' resolves to, and any other runtime reader of eql_v2_configuration (e.g. CipherStash Proxy), were not available. FS-2 is confirmed only against EQL 2.1.8; the downstream consequence of having no active configuration (AC-6) is hypothetical.
- README.md and skills/stash-forge/SKILL.md were skimmed for push/install semantics, not reviewed line by line; parseArgs edge cases, --drizzle file overwrite and the hard-coded '0.1.0' version string were noted but not developed as scenarios. Lower-impact CLI usability defects may be missing from the scenario list.
- PR description is only a title; no CODEOWNERS; no deployment context. Intended scope (e.g. whether push is meant for production use) is unknown.
- History signals flag usually co-changed CHANGELOG/package.json files as absent; these are produced by the changesets 'Version Packages' flow and were judged not material. None expected.

_Inputs unavailable: ci_results, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
