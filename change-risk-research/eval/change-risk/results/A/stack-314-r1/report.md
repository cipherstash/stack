## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `d3bc40e182..bcfeeb8ed1`

Adds a new published CLI/library package @cipherstash/stack-forge (stash-forge install/push) plus an additive EncryptionClient.getEncryptConfig() accessor in @cipherstash/stack. The material risk is in what the CLI does to customer databases. `stash-forge push` deactivates every eql_v2_configuration row and then inserts the new config as two separate autocommitted statements with no transaction; the config it inserts is the client's own schema, whose cast_as values ('number', 'bigint', 'json') are not in the vocabulary the EQL check constraint accepts (bundled EQL 2.1.8), so for those schemas the INSERT fails after the UPDATE has committed, leaving the database with no active EQL configuration. The same UPDATE also silently discards pending/encrypting configurations. `install` executes whatever SQL is at GitHub 'releases/latest' with no version pin or integrity check. The library change to @cipherstash/stack is additive and low risk. Tests for the new package are mocked unit tests of config loading and the installer only; push and the drizzle path are untested, and no test results were seen.

### Failure scenarios

**FS-1 · push leaves the database with no active EQL configuration when the INSERT is rejected** (high impact, observed in the code)

- Trigger: Running `stash-forge push` with any schema that uses .dataType('number'|'bigint') or .searchableJson() (cast_as 'number', 'bigint' or 'json'), or any other INSERT failure (constraint, connection drop, missing table).
- Mechanism: push.ts runs `UPDATE eql_v2_configuration SET state = 'inactive'` and then `INSERT ... ('active', $1)` as separate autocommitted queries (push.ts:33-41, no BEGIN). The inserted data is the client's encrypt config, whose cast_as values come straight from the schema builder ('number', 'bigint', 'json'; schema/index.ts:27, 341). The EQL check constraint (bundled 2.1.8, cipherstash-encrypt-2-1-8.sql:3598-3650) only accepts {text, int, small_int, big_int, real, double, boolean, date, jsonb} and RAISEs otherwise. The UPDATE has already committed when the INSERT fails.
- Consequence: Previously active configuration is deactivated and no replacement is active. Anything that reads the active EQL config (EQL migration functions; Proxy-style consumers) loses its column configuration; depending on the consumer this breaks encrypted queries or stops encryption being applied to configured columns. The CLI exits 1 with the constraint error but does not restore state; manual SQL is needed to reactivate the old row.
- Affects: packages/stack-forge (stash-forge CLI and library), Customer PostgreSQL databases: public.eql_v2_configuration and eql_v2 schema, Consumers of the active EQL configuration (e.g. CipherStash Proxy, EQL migration functions)
- Evidence: `packages/stack-forge/src/commands/push.ts:25-55`; `local/cipherstash-encrypt-2-1-8.sql:3598-3650`; `local/cipherstash-encrypt-2-1-8.sql:3368-3394`; `packages/stack/src/schema/index.ts:26-28`
- Missing verification: Any test of pushCommand; An integration test pushing a schema with number/bigint/json columns into a database with EQL installed; A test that a failed INSERT leaves the previous active configuration intact
- Mitigation: Wrap UPDATE+INSERT in a single transaction (BEGIN/COMMIT/ROLLBACK); map client cast_as values to EQL's vocabulary (or reuse the mapping the client already uses for EQL) before inserting; validate against the constraint in --dry-run.

**FS-2 · push silently discards pending/encrypting EQL configurations and overrides EQL's config lifecycle** (high impact, plausible)

- Trigger: `stash-forge push` against a database where an EQL encryption migration is in progress (a 'pending' or 'encrypting' row exists), or where the active config was managed by EQL functions/another tool.
- Mechanism: The UPDATE has no WHERE clause (push.ts:33-35), so it moves 'pending' and 'encrypting' rows to 'inactive' as well as 'active'. EQL's own functions manage state transitions pending -> encrypting -> active (cipherstash-encrypt-2-1-8.sql:3368-3394). The pushed config fully replaces the active one with whatever the first EncryptionClient export in the client file contains (config/index.ts:170-186), with no diff or confirmation.
- Consequence: An in-flight encryption migration is abandoned without notice; columns configured outside this client file (other services sharing the database) drop out of the active configuration.
- Affects: packages/stack-forge (stash-forge CLI and library), Customer PostgreSQL databases: public.eql_v2_configuration and eql_v2 schema, Consumers of the active EQL configuration (e.g. CipherStash Proxy, EQL migration functions)
- Evidence: `packages/stack-forge/src/commands/push.ts:25-55`; `local/cipherstash-encrypt-2-1-8.sql:3368-3394`; `packages/stack-forge/src/config/index.ts:142-194`
- Missing verification: Test of push against a database with pending/encrypting rows; Review of intended interaction with EQL config lifecycle functions
- Mitigation: Restrict the UPDATE to state = 'active' (or refuse when pending/encrypting rows exist), use EQL's configuration functions where possible, and show a diff of the current vs new config before writing.

**FS-3 · install applies an unpinned 'latest' EQL bundle that may not match the installed client library** (high impact, plausible)

- Trigger: A new EQL release is published on GitHub that is incompatible with the @cipherstash/stack version in the user's project, or the release asset changes/is unavailable.
- Mechanism: Both the installer and the drizzle path fetch releases/latest/download/cipherstash-encrypt*.sql (installer/index.ts:4-6, install.ts:244) and execute or persist it with no version pin, checksum or compatibility check against the client. The profile notes client/SQL pairing as a contract.
- Consequence: Search terms produced by the client may not match the installed SQL functions, breaking encrypted queries; the same stash-forge version installs different SQL on different days, and generated Drizzle migrations are not reproducible across environments.
- Affects: packages/stack-forge (stash-forge CLI and library), Customer PostgreSQL databases: public.eql_v2_configuration and eql_v2 schema
- Evidence: `packages/stack-forge/src/installer/index.ts:1-8`; `packages/stack-forge/src/commands/install.ts:120-262`; `AGENTS.md` (inferred)
- Existing verification: installer.test.ts asserts fetch is called with a URL and SQL runs inside BEGIN, with fetch and pg mocked [exists_not_run]
- Missing verification: Compatibility check between installed EQL version and client version; Integrity verification of downloaded SQL
- Mitigation: Pin the EQL release to a version tied to the stack-forge/stack release (or bundle the SQL in the package), and verify a checksum before executing.

**FS-4 · --supabase grants broad privileges on the eql_v2 schema to anon and authenticated roles** (medium impact, speculative)

- Trigger: `stash-forge install --supabase` on a Supabase project.
- Mechanism: grantSupabasePermissions grants ALL on all tables, routines and sequences in eql_v2 to anon, authenticated and service_role and sets default privileges for role postgres (installer/index.ts:232-238).
- Consequence: Unauthenticated (anon) API clients gain write/execute rights on any present or future eql_v2 objects. What is exposed depends on the objects in the installed bundle, which was not enumerated; the configuration table itself is in public and is not covered by these grants.
- Affects: packages/stack-forge (stash-forge CLI and library), Customer PostgreSQL databases: public.eql_v2_configuration and eql_v2 schema
- Evidence: `packages/stack-forge/src/installer/index.ts:229-239`
- Missing verification: Review of which eql_v2 objects anon actually needs (likely EXECUTE/USAGE only)
- Mitigation: Grant USAGE and EXECUTE only, and limit anon where possible; document the grants.

### Recommended controls

- Add an integration test for push against Postgres with EQL installed, using number/bigint/json columns and a forced INSERT failure; assert the previous active row survives. (test; FS-1, VG-1)
- Make push transactional, scope the UPDATE to 'active', and translate cast_as to EQL's vocabulary before release. (review_focus; FS-1, FS-2)
- Pin the EQL bundle version (or ship it in the package) and check it against the client version before install. (compatibility_check; FS-3, VG-2)
- Review the Supabase grant set with a security owner. (review_focus; FS-4)
- Document the SQL to reactivate the previous eql_v2_configuration row; npm publishing is irreversible, so a fix needs a follow-up release. (rollback_plan; FS-1, FS-2)

### What this assessment could not see

- The cast_as constraint was checked against the EQL 2.1.8 bundle in local/; push targets whatever EQL version the user installed (install uses 'latest'), which was not available offline. If a newer EQL accepts 'number'/'bigint'/'json', FS-1's trigger narrows to other INSERT failures; the non-atomic sequence remains.
- Out-of-repo consumers of eql_v2_configuration (CipherStash Proxy, other services) could not be inspected. Exact consequence of having no active config is inferred, not verified.
- No node_modules and no network; tests and build (tsup bin bundling, path aliases, jiti loading of the native protect-ffi module) were not run. Packaging failures of the new bin cannot be ruled out; verification confidence is capped at low.
- README.md and skills/stash-forge/SKILL.md were only skimmed; pnpm-lock.yaml changes not read in detail. The effect of the experimental changesets option on peer-dependent bumps (e.g. protect-dynamodb's workspace peer) was not analysed. Documentation drift (e.g. SKILL.md documents loadEncryptConfig, which is not exported) and release-versioning effects may be under-reported.
- No PR description, CI results, CODEOWNERS or deployment context. Author intent (e.g. whether push is meant to replace EQL lifecycle) is unknown.

_Inputs unavailable: pr_description, ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
