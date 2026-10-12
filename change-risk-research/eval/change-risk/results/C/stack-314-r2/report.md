## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `d3bc40e182..bcfeeb8ed1`

Adds a new published package, @cipherstash/stack-forge (CLI `stash-forge` plus a small library), that executes DDL against customer PostgreSQL databases: `install` downloads the EQL SQL from GitHub `releases/latest` and runs it (optionally with Supabase role grants), `install --drizzle` writes that SQL into a Drizzle migration, and `push` rewrites `eql_v2_configuration`. It also adds an additive `EncryptionClient.getEncryptConfig()` to @cipherstash/stack, a shipped agent skill, and an experimental changesets option. The SDK change is low risk. The risk sits in the new CLI acting on customer databases: `install --force` re-runs a script whose first statement is `DROP SCHEMA eql_v2 CASCADE`, which can silently drop customer indexes and constraints that depend on EQL objects, while the code and docs describe re-running as safe; the SQL is unpinned (`latest`), so what gets installed is decoupled from the SDK version and not integrity-checked; `push` deactivates every configuration row (including pending/encrypting) outside a transaction; and `--drizzle` silently ignores `--supabase`/`--exclude-operator-family`. Unit tests mock pg and fetch and cover only happy paths and rollback; CI 'Run Tests' passed but nothing exercises a real database. As a new 0.x devDependency nothing existing depends on it, so the blast radius is customers who adopt it.

### Failure scenarios

**FS-1 · `install --force` drops customer EQL indexes and constraints via DROP SCHEMA eql_v2 CASCADE** (high impact, plausible)

- Trigger: A user with EQL already in use (encrypted columns with eql_v2 check constraints and/or EQL-backed indexes) runs `stash-forge install --force`, e.g. to upgrade, as the README/skill suggest.
- Mechanism: --force skips the isInstalled guard (install.ts:70-80) and executes the downloaded SQL. The EQL install SQL (vendored 2.1.8 copy) begins with `DROP SCHEMA IF EXISTS eql_v2 CASCADE` and recreates the schema; CASCADE removes every object depending on eql_v2, including check constraints created by eql_v2.add_encrypted_constraint (which call eql_v2.check_encrypted) and indexes using eql_v2 functions/operator classes. The script only recreates EQL's own objects, not the customer's. The installer docstring states the script 'is idempotent and safe to re-run'.
- Consequence: The transaction commits successfully, so the CLI reports 'Done!'. Customer constraints validating encrypted payloads and EQL indexes on encrypted columns are silently gone: invalid payloads can be written, and encrypted queries degrade to sequential scans or lose ordering support. The public.eql_v2_encrypted column data itself survives (type lives in public).
- Affects: @cipherstash/stack-forge (new package, CLI and library), Customer PostgreSQL databases (eql_v2 schema, dependent indexes/constraints, public.eql_v2_configuration)
- Evidence: `packages/stack-forge/src/installer/index.ts:170-221`; `packages/stack-forge/src/commands/install.ts:70-87`; `packages/schema/cipherstash-encrypt-2-1-8.sql:1-2`; `packages/schema/cipherstash-encrypt-2-1-8.sql:180-187`; `skills/stash-forge/SKILL.md:67-91`
- Existing verification: installer.test.ts mocks pg/fetch with 'CREATE SCHEMA eql_v2;' and only asserts BEGIN/SQL/COMMIT ordering; no reinstall-over-existing-objects test. [ran_passed]
- Missing verification: Integration test against Postgres: install, create a table with an EQL constraint and index, run install --force, assert dependent objects survive or the CLI refuses/warns.; Confirmation of what the current releases/latest SQL does on re-run (vendored 2.1.8 used as a proxy).
- Mitigation: Before re-running, detect dependent objects (pg_depend on eql_v2) and refuse or require explicit confirmation listing what will be dropped; correct the 'safe to re-run' docstring and README/skill wording; document an upgrade path that recreates constraints/indexes.

**FS-2 · Unpinned `releases/latest` EQL SQL breaks the client/SQL pairing and is executed without integrity check** (high impact, plausible)

- Trigger: A new EQL release (e.g. a major/incompatible version) is tagged latest, or the release asset is replaced, while the user's @cipherstash/stack version expects the earlier EQL version.
- Mechanism: Both installer and the Drizzle path fetch a fixed `releases/latest/download/...sql` URL (installer/index.ts:3-6, install.ts:242-245) and execute or persist it as-is; no version pin tied to the stack/stack-forge version and no checksum. With --force (FS-1) this also re-installs over an existing working version.
- Consequence: The database gets EQL functions whose payload/search-term expectations may not match what the installed SDK produces; encrypted queries return wrong results or error, and installs are not reproducible across environments (dev vs CI vs prod installed on different days). The SQL runs with the elevated role the tool asks for.
- Affects: @cipherstash/stack-forge (new package, CLI and library), Customer PostgreSQL databases (eql_v2 schema, dependent indexes/constraints, public.eql_v2_configuration), EQL release artefacts (github.com/cipherstash/encrypt-query-language releases/latest)
- Evidence: `packages/stack-forge/src/installer/index.ts:3-6`; `packages/stack-forge/src/commands/install.ts:29-35`
- Existing verification: Unit test only asserts the URL contains 'cipherstash-encrypt.sql'. [ran_passed]
- Missing verification: A check that the installed EQL version (eql_v2.version()) is compatible with the SDK version.; A test pinning the expected EQL release URL/version.
- Mitigation: Pin the EQL release to a version shipped with stack-forge (or bundle the SQL as the repo already vendors 2.1.8), verify a checksum, and report installed vs expected version.

**FS-3 · `push` deactivates all configs outside a transaction, can leave no active config and discards pending/encrypting state** (medium impact, plausible)

- Trigger: The INSERT fails (e.g. the config is rejected by eql_v2_configuration_data_check for an index/cast the installed EQL version does not accept, or the connection drops) after the UPDATE succeeded; or `push` is run while an EQL config migration is pending/encrypting.
- Mechanism: push.ts:33-42 runs `UPDATE eql_v2_configuration SET state = 'inactive'` (no WHERE, all states) and then the INSERT as separate auto-committed queries with no BEGIN/COMMIT. EQL enforces a CHECK constraint on config data (cipherstash-encrypt-2-1-8.sql:3642-3650).
- Consequence: On INSERT failure the database is left with no active encrypt config; components that read the active config (EQL config functions, CipherStash Proxy) lose the encryption schema. Running during a migration silently flips 'pending'/'encrypting' rows to inactive, abandoning an in-progress re-encryption.
- Affects: @cipherstash/stack-forge (new package, CLI and library), Customer PostgreSQL databases (eql_v2 schema, dependent indexes/constraints, public.eql_v2_configuration)
- Evidence: `packages/stack-forge/src/commands/push.ts:33-42`; `packages/schema/cipherstash-encrypt-2-1-8.sql:3642-3650`
- Missing verification: No test for pushCommand at all.; No test that a rejected config leaves the previous active config intact.
- Mitigation: Wrap UPDATE+INSERT in a transaction; limit UPDATE to state = 'active'; refuse when pending/encrypting rows exist; or use EQL's own config functions.

**FS-4 · `install --drizzle` silently ignores --supabase and --exclude-operator-family** (medium impact, observed in the code)

- Trigger: A Supabase or non-superuser user runs `stash-forge install --drizzle --supabase` (or with --exclude-operator-family), as the skill's examples imply flags combine.
- Mechanism: installCommand passes only name/out/dryRun to generateDrizzleMigration (install.ts:29-35), and downloadEqlSql always fetches the full cipherstash-encrypt.sql (install.ts:242-245); no Supabase grants are added.
- Consequence: The generated migration contains CREATE OPERATOR FAMILY statements and no role grants; `drizzle-kit migrate` fails on Supabase/non-superuser roles, or if it succeeds the anon/authenticated roles lack EQL access and app queries fail. Loud but surfaces in the user's migration pipeline.
- Affects: @cipherstash/stack-forge (new package, CLI and library), Supabase projects (anon, authenticated, service_role roles)
- Evidence: `packages/stack-forge/src/commands/install.ts:29-35`; `packages/stack-forge/src/bin/stash-forge.ts:74-83`
- Missing verification: No test of the --drizzle path or of flag combinations.
- Mitigation: Thread supabase/excludeOperatorFamily into the Drizzle path (choose the Supabase SQL and append grants), or reject the combination with an error.

### Recommended controls

- Review install --force semantics against DROP SCHEMA eql_v2 CASCADE and the 'safe to re-run' claims in installer docstring, README and skills/stash-forge/SKILL.md. (review_focus; FS-1)
- Pin the EQL SQL version (or bundle it) and verify checksum; report installed vs expected eql_v2.version(). (compatibility_check; FS-2, VG-3)
- Add a Postgres-backed integration test (docker/service container) for install, install --force with dependent objects, and push with a rejected config. (test; FS-1, FS-3, VG-1)
- Make push transactional and limit the UPDATE to active rows; add unit tests for push and for --drizzle flag handling. (test; FS-3, FS-4, VG-2)
- Mark the CLI as experimental in the first release and document that --force drops and recreates the eql_v2 schema. (documentation; FS-1)

### What this assessment could not see

- No network: the EQL SQL served from GitHub releases/latest (and its Supabase variant) was not read; behaviour inferred from packages/schema/cipherstash-encrypt-2-1-8.sql. FS-1/FS-2 mechanisms rest on the vendored copy; the live script may differ.
- CI results give only check-run conclusions; no logs. That stack-forge tests ran under 'Run Tests' is inferred from `turbo test --filter './packages/*'`. The stack-forge build (tsup dts, bin bundle) is not shown to run in CI. Packaging/build problems of the new package (e.g. dts resolution of @cipherstash/stack types, bin path) are not covered.
- README.md (289 lines), pnpm-lock.yaml and examples were skimmed, not read in full. The checkPermissions logic (rolcreatedb as proxy for CREATE EXTENSION) was noted but not assessed further: it fails loudly. Minor doc drift or loud permission false-negatives could be missed.
- The changesets experimental option `onlyUpdatePeerDependentsWhenOutOfRange` was not simulated against the workspace graph. Effect on version bumps of other packages at the next release is unknown.

_Inputs unavailable: dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
