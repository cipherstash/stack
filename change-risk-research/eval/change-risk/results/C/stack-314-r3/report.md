## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `d3bc40e182..bcfeeb8ed1`

Adds a new published package and CLI, @cipherstash/stack-forge (stash-forge install / push), and a small additive getEncryptConfig() method on the @cipherstash/stack EncryptionClient. The runtime SDK's behaviour is otherwise untouched. The risk sits in what the new CLI does to customer databases. `push` deactivates every active row in eql_v2_configuration and then inserts a new one, as two autocommitted statements with no transaction. The SDK's schema builder emits cast_as values ('number', 'bigint', 'json') that the EQL 2.1.8 CHECK constraint in this repo rejects, so for those schemas the insert fails after the deactivation has already committed, which leaves the database with no active configuration. `install` downloads and executes the unpinned releases/latest EQL SQL without an integrity check, so the installed SQL version is not tied to the SDK version. `install --drizzle` silently ignores --supabase and --exclude-operator-family. The unit tests mock pg and fetch and cover only the config loader and the installer. Nothing tests push or the Drizzle path. CI 'Run Tests' passed. A repository-wide experimental changesets option also changes how peer dependents are bumped at release.

### Failure scenarios

**FS-1 · push deactivates the active EQL configuration and then fails to insert the new one, leaving no active config** (high impact, observed in the code)

- Trigger: `stash-forge push` against a database where EQL 2.1.8 (or any version with the same CHECK) is installed, with a schema that uses .dataType('number'|'bigint') or .searchableJson()/'json'. Alternatively, any other insert failure such as a connection drop or a constraint violation.
- Mechanism: push.ts:33-42 runs `UPDATE eql_v2_configuration SET state = 'inactive'` and then the INSERT as separate statements on a pg.Client with no BEGIN, so each autocommits. The schema builder emits cast_as 'number', 'bigint' or 'json' and maps only 'string' to 'text' (schema/index.ts:26-27, 341). EQL's eql_v2_configuration_data_check calls config_check_cast, which RAISEs unless cast_as is in {text, int, small_int, big_int, real, double, boolean, date, jsonb} (cipherstash-encrypt-2-1-8.sql:3598-3604, 3644-3650). The INSERT therefore raises after the deactivation has committed.
- Consequence: The customer database has no active encryption configuration. Anything that reads the active row (EQL config functions, and possibly Proxy) sees no config until someone fixes it by hand. The CLI reports 'Failed' with the raw CHECK error, but the earlier state is already lost. Separately, push cannot succeed at all for schemas with number, bigint or json columns, and writing 'active' directly skips EQL's pending/encrypting migration lifecycle.
- Affects: @cipherstash/stack-forge (new package and stash-forge CLI), Customer PostgreSQL: public.eql_v2_configuration, @cipherstash/stack schema builder (buildEncryptConfig / column build), Readers of the active EQL configuration (EQL config functions; possibly CipherStash Proxy)
- Evidence: `packages/stack-forge/src/commands/push.ts:25-54`; `packages/stack/src/schema/index.ts:26-27`; `local/cipherstash-encrypt-2-1-8.sql:3598-3650`; `local/cipherstash-encrypt-2-1-8.sql:1689-1695`
- Missing verification: A test for push showing that the update and insert are atomic (rollback on insert failure).; An integration test pushing a schema with number, bigint and json columns into a real EQL install.; Confirmation of which cast_as vocabulary the current releases/latest EQL accepts.
- Mitigation: Wrap the deactivate and insert in BEGIN/COMMIT with ROLLBACK on error, or use EQL's config functions. Map SDK cast_as values to EQL's vocabulary (or validate before writing) and add a push test against real EQL.

**FS-2 · install applies an unpinned, unverified releases/latest EQL SQL bundle that may not match the SDK version** (high impact, plausible)

- Trigger: A new EQL release is published (or the release asset is replaced) after this stack-forge version ships, and a user runs `stash-forge install` or `install --drizzle`.
- Mechanism: installer/index.ts:3-6 and install.ts:242-262 fetch `.../releases/latest/download/cipherstash-encrypt*.sql` and execute it (installer:200-208) or write it into a migration (install.ts:188). There is no version pin, checksum, or check against the SDK's expected EQL version. The repo's own checked-in bundle is versioned (local/cipherstash-encrypt-2-1-8.sql).
- Consequence: Different users, or the same Drizzle migration regenerated on another day, get different EQL versions. If latest changes function signatures, payload expectations or config validation, SDK-generated search terms or configs stop matching the installed SQL. Arbitrary downloaded SQL runs with superuser or admin privileges in the customer database, and the installed version cannot be reproduced.
- Affects: @cipherstash/stack-forge (new package and stash-forge CLI), EQL SQL install bundle (GitHub releases/latest), Customer PostgreSQL: public.eql_v2_configuration
- Evidence: `packages/stack-forge/src/installer/index.ts:3-6`; `packages/stack-forge/src/commands/install.ts:242-262`; `packages/stack-forge/src/installer/index.ts:180-239`
- Existing verification: installer.test.ts asserts fetch is called with the latest URL and that SQL runs in a transaction with rollback, using mocked pg and fetch. CI 'Run Tests' passed; that it covered stack-forge is inferred from the turbo filter. [ran_passed]
- Missing verification: No check that the installed EQL version is compatible with the @cipherstash/stack version.; No integrity verification of the downloaded SQL.
- Mitigation: Pin the EQL release URL to a version tied to the stack-forge/stack release (or bundle the SQL in the package) and verify a checksum. Optionally check eql_v2.version() after install.

**FS-3 · install --drizzle silently drops --supabase and --exclude-operator-family** (medium impact, observed in the code)

- Trigger: A Supabase or non-superuser user runs `stash-forge install --drizzle --supabase` (or with --exclude-operator-family).
- Mechanism: installCommand passes only name, out and dryRun to generateDrizzleMigration (install.ts:29-35). downloadEqlSql always fetches the full cipherstash-encrypt.sql (install.ts:242-244) and never adds the Supabase role grants.
- Consequence: The generated migration contains operator-family DDL that a non-superuser cannot run, so `drizzle-kit migrate` fails. Or, if it applies, Supabase roles get no grants and API-role queries using eql_v2 fail. The migration may already be committed to the user's history, and the CLI gives no warning.
- Affects: @cipherstash/stack-forge (new package and stash-forge CLI), EQL SQL install bundle (GitHub releases/latest), skills/stash-forge/SKILL.md and stack-forge README
- Evidence: `packages/stack-forge/src/commands/install.ts:29-35`; `packages/stack-forge/src/commands/install.ts:242-262`
- Missing verification: No test of the --drizzle path or of flag combinations.
- Mitigation: Pass excludeOperatorFamily and supabase through to the Drizzle path (choose the Supabase URL and append the grants), or reject the combination with an error.

**FS-4 · Experimental changesets option changes peer-dependent version bumps for every package** (low impact, plausible)

- Trigger: Next `changeset version` run in which a package that others list as a peer dependency (e.g. @cipherstash/protect for drizzle) is bumped within the declared range, or a changesets patch release renames the experimental key.
- Mechanism: .changeset/config.json:11-13 adds `___experimentalUnsafeOptions_WILL_CHANGE_IN_PATCH.onlyUpdatePeerDependentsWhenOutOfRange`. Dependents are no longer bumped when the peer stays in range, and the key is explicitly unstable.
- Consequence: Release versions differ from previous practice (dependents not republished), or the release tooling fails or ignores the option after a changesets patch upgrade. Both are visible at release time and recoverable with a new release.
- Affects: Release tooling (.changeset/config.json, release workflow)
- Evidence: `.changeset/config.json:11-13`; `packages/drizzle/package.json:45-47`
- Missing verification: A `changeset status`/version dry-run showing the resulting bumps.
- Mitigation: Run a changeset version dry-run before publishing and pin @changesets/cli.

### Recommended controls

- Make push transactional (or use EQL's config functions) and add a test that a failing insert leaves the previous active row intact. (test; FS-1, VG-1)
- Push a schema with number, bigint and json columns into the EQL version stack-forge installs, and reconcile cast_as vocabularies before release. (compatibility_check; FS-1, VG-1)
- Pin the EQL install bundle to a specific release (or ship it in the package) with a checksum, and record the version installed. (review_focus; FS-2, VG-3)
- Fix flag passthrough on the --drizzle path and add tests for --drizzle with --supabase / --exclude-operator-family. (test; FS-3, VG-2)
- Run a changesets version dry-run to confirm the resulting bumps before the first release with the experimental option. (other; FS-4)
- Correct the README claim that @cipherstash/stack reads eql_v2_configuration, since the shipped SKILL.md will propagate it. (documentation; FS-1)

### What this assessment could not see

- The content and cast_as vocabulary of the current GitHub releases/latest EQL bundle could not be checked (no network). The CHECK constraint analysis uses the checked-in EQL 2.1.8 bundle. If a newer EQL accepts 'number', 'bigint' and 'json', the cast_as trigger in FS-1 would not fire, but the non-atomic deactivate-then-insert still stands for any other insert failure.
- What reads the active eql_v2_configuration row in customer deployments (e.g. CipherStash Proxy) is outside this repository. The consequence of FS-1 beyond EQL's own functions is unverified. The impact could be lower if nothing at runtime reads it.
- ci.json gives check names and conclusions only, with no logs. That stack-forge's unit tests ran in 'Run Tests' is inferred from `turbo test --filter './packages/*'`. The build of the bin bundle (tsup banner, path aliases) was not observed or run.
- README.md and SKILL.md were skimmed for claims about the config key, push and flags, not read in full. pnpm-lock.yaml changes were not reviewed beyond the collector's dependency summary. Further documentation drift may exist.
- No tests or builds were run locally. All test statuses come from CI or are exists_not_run.

_Inputs unavailable: dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
