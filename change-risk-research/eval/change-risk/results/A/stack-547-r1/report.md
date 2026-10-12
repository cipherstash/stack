## Change risk: Changes or verification required

**Impact if something goes wrong:** critical · **Verification confidence:** low · `b405a54850..e027b7492a`

Adds an EQL v3 surface to @cipherstash/stack (v3 schema DSL, typed client, encryptedSupabaseV3 adapter, eqlVersion selection on the FFI client), bumps @cipherstash/protect-ffi 0.26.0 -> 0.27.0 for every consumer, and adds a v3 install/upgrade path to the stash CLI that vendors the eql-3.0.0-alpha.2 SQL bundle. The v2 paths are refactored behind protected seams that default to the old behaviour. The most material risk is in the CLI: the v3 bundle begins with DROP SCHEMA eql_v3 CASCADE, and unlike the v2 bundle (which keeps the customer column type in public), the v3 column domains live inside eql_v3. So `stash eql upgrade --eql-version 3`, `install --force`, or an install over a stale pre-alpha.2 v3 schema would drop every customer column that uses an eql_v3 domain, along with its encrypted data. Secondary risks: Supabase v3 filter operands are full decryptable envelopes sent in PostgREST GET URLs (documented interim); default-configured like/ilike silently returns no matches; the wasm-inline entry accepts v3 columns but never passes eqlVersion. No tests were run and no CI results were available. Live Postgres/ZeroKMS suites are gated on credentials.

### Failure scenarios

**FS-1 · v3 upgrade/reinstall drops customer columns that use eql_v3 domains** (critical impact, plausible)

- Trigger: A user with live tables typed as eql_v3.* domains runs `stash eql upgrade --eql-version 3` (the documented upgrade path), runs `stash eql install --eql-version 3 --force`, or runs install against a pre-alpha.2 v3 database that isInstalled() now reports as not installed.
- Mechanism: upgradeCommand confirms v3 is installed and then calls installer.install({eqlVersion:3}) (upgrade.ts:96-101), which runs the vendored bundle in one transaction. The bundle opens with DROP SCHEMA IF EXISTS eql_v3 CASCADE and eql_v3_internal CASCADE (cipherstash-encrypt-v3.sql:38,46). The column domains are created inside eql_v3 (e.g. CREATE DOMAIN eql_v3.timestamp at :545). PostgreSQL's CASCADE on a schema drops its domains, and dropping a domain with CASCADE drops the table columns that use it. The v2 bundle avoids this on purpose by creating the customer type public.eql_v2_encrypted only if absent ('DO NOT DROP this type unless absolutely certain no encrypted data uses it', cipherstash-encrypt.sql:30-45). Nothing in the v3 CLI path warns, confirms, or checks for dependent columns.
- Consequence: Every encrypted column of every v3 table is silently removed, with its ciphertext, at COMMIT. The CLI then reports 'EQL extensions upgraded.' Recovery needs a database backup. This is irreversible data loss for any early adopter of the published v3 path.
- Affects: stash CLI (packages/cli) eql install/upgrade/status, Customer PostgreSQL / Supabase databases with eql_v3 columns
- Evidence: `packages/cli/src/sql/cipherstash-encrypt-v3.sql:36-46`; `packages/cli/src/sql/cipherstash-encrypt-v3.sql:545`; `packages/cli/src/sql/cipherstash-encrypt.sql:30-45`; `packages/cli/src/commands/db/upgrade.ts:92-101`; `packages/cli/src/installer/index.ts:212-227`
- Existing verification: installer.test.ts v3 cases mock pg and only assert which SQL text and grants are sent. They never run the bundle against a database holding data. [exists_not_run]
- Missing verification: An integration test that installs v3, creates a table with an eql_v3 column and a row, runs `stash eql upgrade --eql-version 3` (and install --force), and asserts the column and row survive.; Running the same against PostgreSQL to confirm the CASCADE drops columns (not run here: no database available).
- Mitigation: Before release, block upgrade/--force for v3 when any column depends on an eql_v3 domain (query pg_attribute/pg_type), or require an explicit destructive-confirmation flag. Ask upstream EQL for a non-destructive v3 upgrade script (CREATE OR REPLACE for functions, domains preserved). Document clearly that v3 alpha reinstall is destructive.

**FS-2 · Supabase v3 filters put decryptable ciphertext and all index terms into request URLs** (medium impact, plausible)

- Trigger: Any encryptedSupabaseV3 select with .eq/.gt/.like/.in/.or/.not on an encrypted column (PostgREST sends filters as GET query parameters).
- Mechanism: encryptCollectedTerms calls encryptionClient.encrypt() (not encryptQuery) for each operand and returns JSON.stringify(result.data) as the filter value (query-builder-v3.ts:194-250). The full envelope holds the ciphertext `c` plus every index term (hm, ob, bf) for the column. v2 sends query-only terms with no ciphertext.
- Consequence: Real ciphertext of searched values, plus order-revealing and equality terms, persist in Supabase/API-gateway/proxy URL logs outside the customer database's access controls and retention. This is not plaintext, but it widens where decryptable material lives, and anyone who can read the logs can correlate by equality and range. The change documents this as an interim limitation (CIP-3402), so it ships as a known gap.
- Affects: @cipherstash/stack/supabase (encryptedSupabaseV3 and refactored v2 EncryptedQueryBuilderImpl), Supabase/PostgREST request logs, proxies, URL logging
- Evidence: `packages/stack/src/supabase/query-builder-v3.ts:194-250`
- Existing verification: supabase-v3-builder.test.ts covers operand encoding and the like->cs remap against a fake Supabase client. [exists_not_run]
- Missing verification: No check or opt-in gate stops users enabling the v3 adapter where request URLs are logged.
- Mitigation: Mark encryptedSupabaseV3 experimental in the changeset and README with the log-exposure caveat. Consider sending filters via POST/RPC until the term-only envelope (CIP-3402) ships.

**FS-3 · Encrypted like/ilike on default-configured v3 text columns silently returns no rows** (medium impact, plausible)

- Trigger: A user declares types.TextSearch('email') with default match options (include_original: true) and calls .like/.ilike with a substring or a %-wildcard pattern.
- Mechanism: like/ilike on encrypted columns become PostgREST `cs` (bloom containment) using a full-envelope operand (query-builder-v3.ts:260-283). With include_original: true, the default from defaultMatchOpts (match-defaults.ts:39), the operand's bloom filter also carries the whole pattern as a token, so containment matches only when the pattern equals the stored value. The pattern string is encrypted as given, so any % characters are tokenized too. The docs describe this as an interim limitation (supabase-sdk.md:172-179).
- Consequence: The query returns an empty or incomplete result instead of an error, and application search silently degrades. Fixing it needs include_original: false, which changes the stored bloom filter, so data written under the default must be re-encrypted.
- Affects: @cipherstash/stack/supabase (encryptedSupabaseV3 and refactored v2 EncryptedQueryBuilderImpl), skills/stash-supabase/SKILL.md and docs/reference/supabase-sdk.md
- Evidence: `packages/stack/__tests__/supabase-v3-builder.test.ts:308-323`; `docs/reference/supabase-sdk.md:172-179`
- Existing verification: Builder unit test asserts the `cs` operator is emitted for a pattern without wildcards. It does not check that matching works. [exists_not_run]
- Missing verification: A live PG test of substring .like on a default TextSearch column (matrix-live-pg suites are gated on DATABASE_URL and CipherStash credentials).
- Mitigation: Default include_original to false for v3 TextSearch, or make the adapter reject like/ilike on columns where include_original is true. Strip or reject % wildcards before encrypting.

**FS-4 · wasm-inline client accepts v3 schemas but emits v2-wire envelopes** (medium impact, plausible)

- Trigger: A Deno/Edge/Worker user passes v3 tables (from @cipherstash/stack/eql/v3) to the wasm-inline Encryption() and encrypts. The change deliberately makes v3 columns accepted there.
- Mechanism: The Node Encryption() resolves eqlVersion from the schema set (index.ts:758), but the wasm-inline Encryption() calls wasmNewClient without eqlVersion (wasm-inline.ts:282-312), so the FFI default (v2) applies. It also skips the mixed-v2/v3 guard. getColumnName was widened so v3 columns no longer throw (wasm-inline.ts:370), and the regression test says a v3 column 'genuinely round-trips'.
- Consequence: Payloads go out in the v2 envelope shape for columns meant for eql_v3 domains. This is either rejected at insert by v3 domain CHECKs (loud), or stored somewhere without CHECKs and later unreadable by v3 SQL and readers. Cross-runtime (Node vs Edge) output differs for the same schema.
- Affects: @cipherstash/stack/wasm-inline (Deno/Edge/Workers)
- Evidence: `packages/stack/src/wasm-inline.ts:282-312`; `packages/stack/__tests__/wasm-inline-column-name.test.ts:34-41`; `packages/stack/src/encryption/index.ts:87-106`
- Existing verification: wasm-inline-column-name.test.ts checks only name resolution with WASM mocked. No test covers the envelope version. [exists_not_run]
- Missing verification: A wasm-inline test asserting eqlVersion is forwarded for v3 schemas (or that v3 schemas are rejected).
- Mitigation: Call resolveEqlVersion in the wasm-inline factory and forward eqlVersion, or reject v3 tables there until supported.

**FS-5 · protect-ffi 0.27 bump changes v2 behaviour for existing users** (high impact, speculative)

- Trigger: Any existing v2 user upgrades @cipherstash/stack. protect-ffi 0.27 (native and WASM) is pulled in even if they never touch v3.
- Mechanism: The FFI is bumped across all platforms (package.json:247). The only v2 guarantee in the diff is that eqlVersion is left undefined, which init-strategy.test.ts checks against a mocked newClient. Nothing seen shows that 0.27 produces byte-compatible v2 payloads or that it accepts 0.26-written data.
- Consequence: If the FFI changed v2 output or parsing, new writes or reads of data already at rest could become incompatible with deployed EQL v2 SQL or other clients. That would be a data-integrity issue across every customer.
- Affects: @cipherstash/stack core client (Encryption, encrypt/encryptQuery/encryptModel), In-repo consumers of @cipherstash/stack (e2e, examples/supabase-worker, packages/migrate, packages/prisma-next, packages/bench)
- Evidence: `packages/stack/package.json:247`; `packages/stack/__tests__/init-strategy.test.ts:116-171`
- Existing verification: init-strategy.test.ts asserts eqlVersion is undefined for v2 schema sets (mocked FFI). [exists_not_run]; Existing live v2 suites (supabase.test.ts etc.) would exercise 0.27 if CI ran them with credentials. No results were available. [unknown]
- Missing verification: A CI run of the live v2 suites on protect-ffi 0.27.; A round-trip check: decrypt 0.26-written v2 payloads with 0.27, and query them with the installed eql-2.3.1 SQL.
- Mitigation: Confirm green live v2 CI on this head. Review the protect-ffi 0.27 changelog for v2 wire changes before publishing.

### Recommended controls

- Add a Postgres integration test: install v3, create a table with eql_v3 columns and rows, run upgrade and install --force, and assert the data survives (or the CLI refuses). (test; FS-1, VG-1)
- Make `stash eql upgrade/install --eql-version 3` refuse to proceed when user columns depend on eql_v3 domains, unless an explicit destructive flag is passed, and print the affected columns. (other; FS-1)
- Label encryptedSupabaseV3 and the v3 CLI path experimental/alpha in changesets and READMEs. Spell out the URL-log exposure and the include_original requirement prominently. (documentation; FS-2, FS-3)
- Forward resolveEqlVersion in the wasm-inline factory, or reject v3 tables there. (other; FS-4, VG-3)
- Before publishing, require a green live CI run of the v2 and v3 suites on this head with protect-ffi 0.27. Include a cross-version decrypt of 0.26-written v2 payloads. (compatibility_check; FS-5, VG-2)
- Reviewer focus: v3 Supabase grants that extend EXECUTE and default privileges on eql_v3_internal to anon. Check they are no broader than the operators need. (review_focus; )

### What this assessment could not see

- The vendored SQL bundles (~109k lines) were only searched for DROP/CREATE statements. Their functions, CHECK constraints and operators were not reviewed. SQL-side defects (e.g. operand coercion, CHECK strictness on v:3) are not assessed. FS-4's consequence assumes the CHECKs pin v:3, based on comments.
- PostgreSQL CASCADE semantics for FS-1 come from PostgreSQL's documented behaviour, not from running the bundle. No database was available. FS-1 is rated plausible_failure rather than observed_defect.
- No CI results and no test execution. protect-ffi 0.27's changes are not visible offline. Verification confidence is low, and FS-5 stays speculative.
- v3 column DSL (columns.ts, table.ts, types.ts), type-level tests and plan/spec docs were skimmed, not read in full. In-repo consumers (examples, migrate, prisma-next) were identified by package.json only. Type-level contract regressions for v2 consumers of the widened types may be missed.

_Inputs unavailable: ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
