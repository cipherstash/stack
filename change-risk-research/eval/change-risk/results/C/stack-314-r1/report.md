## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `d3bc40e182..bcfeeb8ed1`

Adds a new published CLI/library, @cipherstash/stack-forge (`stash-forge install` / `push`), plus an additive `getEncryptConfig()` on the @cipherstash/stack EncryptionClient and a changesets option. The SDK change is low risk. The risk is in what the new CLI does to customer databases. `push` deactivates every eql_v2_configuration row and then inserts the new one as two autocommit statements with no transaction; the config it inserts can hold cast_as values ('number', 'bigint', 'json') that the EQL 2.1.8 CHECK constraint rejects. In that case the database is left with no active encryption configuration, and any in-flight pending/encrypting migration has also been clobbered. `install` downloads and executes the unpinned `releases/latest` EQL SQL, with no integrity check and usually as a superuser, while the repo itself pins EQL 2.1.8. Its `--force` path re-runs a script that begins with `DROP SCHEMA eql_v2 CASCADE`, which can silently drop indexes and constraints on encrypted columns. Tests mock pg and fetch, and push has no tests at all. Verification needed before release: a transactional push tested against a real EQL database, and a pinned install source.

### Failure scenarios

**FS-1 · push leaves the database with no active EQL configuration when the insert fails** (high impact, observed in the code)

- Trigger: A user runs `stash-forge push` with a schema containing a column whose cast_as is not in EQL's allowed set. Examples are `.dataType('number')`, `.dataType('bigint')`, `.dataType('json')` and any `.searchableJson()` column (cast_as 'json'). Any other INSERT error (constraint, permission, dropped connection) also triggers it.
- Mechanism: push.ts:32-43 runs `UPDATE eql_v2_configuration SET state = 'inactive'` and then the INSERT as two separate autocommit queries, with no BEGIN. The stack schema builder emits cast_as values 'number', 'bigint' and 'json' unchanged (schema/index.ts:26-28, 339-344). The EQL 2.1.8 CHECK constraint (config_check_cast) only accepts text, int, small_int, big_int, real, double, boolean, date and jsonb, and RAISEs on anything else (sql:3598-3613, 3642-3650). The INSERT fails after the UPDATE has already committed. Because the UPDATE has no WHERE clause, it also flips any 'pending' or 'encrypting' row to inactive, bypassing EQL's migrate/activate lifecycle.
- Consequence: The previously active configuration is deactivated and nothing replaces it. Anything that reads the active config, such as EQL config functions and likely CipherStash Proxy, loses its encryption configuration. In-progress encryption migrations are silently abandoned. The CLI reports the INSERT error, but the destructive half has already been applied, and recovery means manually reactivating a row.
- Affects: @cipherstash/stack-forge (new package, push/install commands), Customer PostgreSQL databases: public.eql_v2_configuration and the eql_v2 schema, Consumers of the active EQL configuration (e.g. CipherStash Proxy, EQL config functions)
- Evidence: `packages/stack-forge/src/commands/push.ts:28-43`; `packages/stack/src/schema/index.ts:26-28`; `packages/stack/src/schema/index.ts:333-344`; `packages/schema/cipherstash-encrypt-2-1-8.sql:3598-3613`; `packages/schema/cipherstash-encrypt-2-1-8.sql:3642-3650`; `packages/schema/cipherstash-encrypt-2-1-8.sql:3217-3219`
- Existing verification: No test exercises push.ts. The collector lists it among source files with no related test. [unknown]
- Missing verification: Integration test of push against a real EQL-installed Postgres, including a schema with number/json/bigint columns; Test that a failed INSERT leaves the previous active row intact; Check of the cast_as mapping between @cipherstash/stack config and the EQL CHECK constraint
- Mitigation: Wrap the UPDATE and INSERT in a single transaction (BEGIN/COMMIT, ROLLBACK on error). Restrict the UPDATE to state = 'active', or use EQL's own config functions. Map stack cast_as values to EQL names before inserting, or validate the config against EQL's rules before touching the table.

**FS-2 · install --force drops EQL-dependent indexes and constraints on encrypted columns** (high impact, plausible)

- Trigger: A user with EQL already installed and tables using eql_v2_encrypted columns with EQL indexes or constraints runs `stash-forge install --force`, as the CLI itself suggests when EQL is already installed.
- Mechanism: install.ts:70-80 skips the installed-check only under --force and prints 'Use --force to re-run the install script.' The executed script (vendored 2.1.8, sql:1-2) begins `DROP SCHEMA IF EXISTS eql_v2 CASCADE`. That CASCADE removes every object depending on eql_v2 functions, operators and operator classes, for example check constraints added by eql_v2.add_encrypted_constraint (sql:183-189) and indexes using eql_v2.encrypted_operator_class (sql:2239-2247). The script recreates the schema but not the user's dependent objects. The installer comment calls the script 'idempotent and safe to re-run' (installer/index.ts:174).
- Consequence: Encrypted columns lose their indexes and check constraints without an error. Queries keep working but slow down, and invalid payloads are no longer rejected. Nothing tells the user; the install reports 'Done!'.
- Affects: @cipherstash/stack-forge (new package, push/install commands), Customer PostgreSQL databases: public.eql_v2_configuration and the eql_v2 schema
- Evidence: `packages/schema/cipherstash-encrypt-2-1-8.sql:1-2`; `packages/schema/cipherstash-encrypt-2-1-8.sql:183-189`; `packages/stack-forge/src/commands/install.ts:70-80`; `packages/stack-forge/src/installer/index.ts:180-221`
- Existing verification: installer.test.ts mocks pg and only asserts BEGIN/SQL/COMMIT and ROLLBACK; it cannot observe CASCADE effects. [ran_passed]
- Missing verification: Integration test of re-install on a database with encrypted columns, indexes and add_encrypted_constraint constraints; Confirmation that the current 'latest' EQL release still starts with DROP SCHEMA ... CASCADE (not checked; no network)
- Mitigation: Make --force warn about CASCADE effects and require confirmation, or list dependent objects (pg_depend) first and refuse if any exist. Offer an upgrade path that does not drop the schema. Correct the 'safe to re-run' comment and the CLI hint.

**FS-3 · install executes an unpinned, unverified 'latest' EQL SQL bundle as a privileged role** (high impact, plausible)

- Trigger: A user runs `stash-forge install` (or `--drizzle`) after a new EQL release that is incompatible with the installed @cipherstash/stack version, or while the release asset has been tampered with or replaced.
- Mechanism: Both installer/index.ts:3-6 and install.ts:242-262 fetch `releases/latest/download/...sql` with no version pin and no checksum or signature check. The SQL is executed directly (installer/index.ts:201-202), usually by a superuser, since checkPermissions steers users there, or it is written into a committed Drizzle migration. The repo itself pins EQL 2.1.8 (packages/schema/cipherstash-encrypt-2-1-8.sql), so the client/SQL pairing that stack was tested against is not what forge installs.
- Consequence: Installs can't be reproduced, and the version is chosen by the release date rather than by the user. A future EQL major or minor change to payload/search-term handling can install SQL functions that do not match the client's search terms, so queries return wrong or empty results. A compromised release asset becomes arbitrary SQL run as superuser on customer databases.
- Affects: @cipherstash/stack-forge (new package, push/install commands), Customer PostgreSQL databases: public.eql_v2_configuration and the eql_v2 schema, @cipherstash/stack EncryptionClient / schema builder
- Evidence: `packages/stack-forge/src/installer/index.ts:3-6`; `packages/stack-forge/src/commands/install.ts:242-262`; `packages/stack-forge/src/installer/index.ts:180-221`; `packages/schema/cipherstash-encrypt-2-1-8.sql:1-2`
- Existing verification: installer.test.ts asserts only that the fetched URL contains 'cipherstash-encrypt.sql' (fetch mocked). [ran_passed]
- Missing verification: Compatibility test pairing the stack client version with the installed EQL version; Any integrity check of the downloaded SQL
- Mitigation: Pin the EQL version per stack-forge release (or bundle the SQL in the package, as packages/schema already vendors 2.1.8). Verify a checksum. Record the installed EQL version and compare it on later runs.

**FS-4 · A positional argument after --dry-run silently disables the dry run** (medium impact, plausible)

- Trigger: The user runs e.g. `stash-forge install --dry-run foo` or `stash-forge push --dry-run x`, or a script appends an argument after a boolean flag.
- Mechanism: parseArgs (bin/stash-forge.ts:39-55) treats any non-`--` token after a flag as that flag's value. `--dry-run foo` sets values['dry-run'] = 'foo' and leaves flags['dry-run'] undefined, so installCommand/pushCommand run for real.
- Consequence: A command the user meant as a preview modifies the database: it runs the EQL install or the push from FS-1.
- Affects: @cipherstash/stack-forge (new package, push/install commands), Customer PostgreSQL databases: public.eql_v2_configuration and the eql_v2 schema
- Evidence: `packages/stack-forge/src/bin/stash-forge.ts:39-55`
- Existing verification: No CLI argument parsing tests. [unknown]
- Missing verification: Unit tests for parseArgs with boolean flags followed by positional tokens
- Mitigation: Declare which options take values (name, out). Treat all others as boolean, or use node:util parseArgs with an explicit option schema.

### Recommended controls

- Make push transactional, scope the UPDATE to the active row, and add an integration test (local/docker-compose Postgres with EQL 2.1.8). It should push a schema containing number/json/bigint columns and assert the previous active row survives a failed insert. (test; FS-1, VG-1)
- Map or validate stack cast_as values ('number', 'bigint', 'json', 'string') against EQL's allowed set before writing the config. Compare with how CipherStash Proxy expects cast_as. (compatibility_check; FS-1)
- Before release, review install --force: the CASCADE behaviour, the 'Use --force' hint and the 'idempotent and safe to re-run' claim. Add a confirmation prompt or a pg_depend check. (review_focus; FS-2, VG-2)
- Pin the EQL SQL version (or bundle it) and verify a checksum, rather than downloading releases/latest. (other; FS-3)
- Replace the ad-hoc parseArgs with an explicit option schema and add tests for flag/value handling. (test; FS-4, VG-4)
- Correct the README claim that @cipherstash/stack reads the active configuration from the database. Update the shipped stash-forge skill once push semantics change. (documentation; FS-1)

### What this assessment could not see

- The current 'latest' EQL release could not be fetched. The vendored EQL 2.1.8 SQL in the repo stands in for the CHECK constraint and the DROP SCHEMA CASCADE prelude. FS-1 and FS-2 assume 'latest' keeps these behaviours; a newer release could relax config_check_cast or change the prelude.
- No CipherStash Proxy code or deployment context was available, so who reads the active eql_v2_configuration row in practice is not confirmed. FS-1's impact depends on consumers of the active row; it is rated high on the strength of EQL's own config functions and the likely Proxy dependency.
- The tsup build output, the dts generation, and loading the user's client via jiti (including top-level await in examples/basic/encrypt.ts, which needs live CS credentials) were not built or run. Packaging or loading failures in the published CLI would be loud but were not assessed.
- README.md (289 lines), skills/stash-forge/SKILL.md (235 lines) and pnpm-lock.yaml were skimmed rather than read in full. The --supabase grants (ALTER DEFAULT PRIVILEGES FOR ROLE postgres) were read but not tested against Supabase. Guidance drift and Supabase-specific failures may be under-covered.
- The effect of the experimental changesets option on the next release's version bumps was not simulated. Unexpected version bumps (or the absence of expected ones) for peer dependents were not assessed.

_Inputs unavailable: dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
