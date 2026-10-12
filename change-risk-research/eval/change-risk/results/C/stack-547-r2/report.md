## Change risk: Changes or verification required

**Impact if something goes wrong:** critical · **Verification confidence:** low · `b405a54850..e027b7492a`

Adds an EQL v3 Supabase adapter (encryptedSupabaseV3), a v3 install/upgrade/status path in the stash CLI with vendored eql-3.0.0-alpha.2 SQL bundles, and shared refactors across the v2 encryption client (protect-ffi 0.26.0 -> 0.27.0, BuildableTable widening, eqlVersion auto-detection, Supabase builder dialect seams). The most material risk is in the CLI: `stash eql upgrade --eql-version 3` and `stash eql install --eql-version 3 --force` re-run a bundle that begins with `DROP SCHEMA eql_v3 CASCADE`. The customer's encrypted columns are typed with domains in that schema, so a re-run would drop those columns and their data. v2 avoids this by defining its column type in `public`. The installer also treats a pre-alpha.2 eql_v3 install as not installed, so a plain install would run the same drop. Other silent risks: if `eql_v3` is not in Supabase's Exposed schemas, filters fall back to jsonb comparison and return wrong rows, including for update and delete; filter operands are full ciphertext envelopes sent in GET URLs; and with the default `include_original: true`, free-text search returns nothing. All 9 CI checks pass, but the CLI installer tests mock pg, and CI has no Supabase env (by grep), so the live v3 Supabase suite does not run. Advisory: changes or verification required before release.

### Failure scenarios

**FS-1 · v3 upgrade or forced reinstall drops eql_v3 schema with CASCADE, deleting customers' encrypted columns** (critical impact, observed in the code)

- Trigger: A customer with tables whose columns are eql_v3.* domains runs `stash eql upgrade --eql-version 3` or `stash eql install --eql-version 3 --force`. A plain install also triggers it on a database that has eql_v3 from an earlier alpha but no eql_v3_internal.
- Mechanism: upgradeCommand confirms v3 is installed, then calls installer.install({ eqlVersion: 3 }) (upgrade.ts:52-101). install() runs the bundled SQL in one transaction and commits (installer/index.ts:297-341). That bundle starts with `DROP SCHEMA IF EXISTS eql_v3 CASCADE` and `DROP SCHEMA IF EXISTS eql_v3_internal CASCADE` (cipherstash-encrypt-v3.sql:36-46), and every column domain is created inside eql_v3 (e.g. cipherstash-encrypt-v3.sql:545). In PostgreSQL, CASCADE on a schema drops its domains and any table columns typed with them. The v2 bundle avoids this by defining eql_v2_encrypted in `public` 'to persist independently of eql_v2 schema lifecycle' (cipherstash-encrypt.sql:28-43); v3 has no equivalent. isInstalled({eqlVersion: 3}) returns false when eql_v3_internal is missing (installer/index.ts:205-227), so install skips the already-installed guard (install.ts:223-239).
- Consequence: The encrypted columns, and the ciphertext in them, are dropped in a committed transaction with no error. The data loss is irreversible unless restored from backup. The CLI reports 'EQL extensions upgraded.'
- Affects: stash CLI: eql install / upgrade / status, Vendored EQL v3 SQL bundles (packages/cli/src/sql/cipherstash-encrypt-v3*.sql), Customer databases with eql_v3.* domain columns
- Evidence: `packages/cli/src/installer/index.ts:205-227`; `packages/cli/src/installer/index.ts:297-341`; `packages/cli/src/sql/cipherstash-encrypt-v3.sql:36-46`; `packages/cli/src/sql/cipherstash-encrypt-v3.sql:545-560`; `packages/cli/src/sql/cipherstash-encrypt.sql:28-43`; `packages/cli/src/commands/db/upgrade.ts:52-101`; `packages/cli/src/commands/db/install.ts:223-245`; `skills/stash-supabase/SKILL.md:453-473`; `packages/cli/src/__tests__/installer.test.ts:4-10`
- Existing verification: installer.test.ts checks which v3 bundle and grants are chosen and the two-schema isInstalled rule, with pg mocked; no database is touched. [exists_not_run]
- Missing verification: An integration test that installs v3, creates a table with an eql_v3 domain column and data, runs `stash eql upgrade --eql-version 3`, and asserts the column and rows survive.; The same check for `install --eql-version 3` on a database holding a pre-alpha.2 eql_v3 schema.
- Mitigation: Before running the v3 bundle when eql_v3 already exists, have the CLI refuse or require explicit confirmation if any user column depends on an eql_v3 type (pg_depend / information_schema.columns domain_schema = 'eql_v3'). Longer term, make the v3 bundle upgrade in place without dropping the domain schema. Until then, document that upgrade destroys v3 columns, or disable `upgrade --eql-version 3`.

**FS-2 · eql_v3 missing from Exposed schemas makes encrypted range filters match wrong rows, including in update/delete** (high impact, plausible)

- Trigger: A Supabase project installs v3 but does not add `eql_v3` to Exposed schemas. Only a manual dashboard step does this, and the CLI does not check it.
- Mechanism: The v3 builder sends bare PostgREST filters (gte/lte/eq/cs) with a jsonb envelope operand (query-builder-v3.ts:145-251). If the eql_v3 operators are not on PostgREST's search_path, the shipped skill says they 'silently fall back to base jsonb comparison and return wrong rows' (SKILL.md:482-489). Filters also apply to update and delete mutations (query-builder.ts:679-685).
- Consequence: Selects return wrong or empty result sets with no error. `.update(...).gte(col, x)` or `.delete().lt(col, x)` can change or delete the wrong rows.
- Affects: @cipherstash/stack/supabase (encryptedSupabase v2 and encryptedSupabaseV3), Customer databases with eql_v3.* domain columns, skills/stash-supabase/SKILL.md (shipped agent guidance)
- Evidence: `skills/stash-supabase/SKILL.md:482-489`; `packages/stack/src/supabase/query-builder-v3.ts:194-251`; `packages/stack/src/supabase/query-builder.ts:679-685`
- Existing verification: Live supabase-v3 suite covers range and equality only on a correctly configured project. It is skipped unless SUPABASE_URL/SUPABASE_ANON_KEY/DATABASE_URL are set, and CI does not set the Supabase variables. [exists_not_run]
- Missing verification: Any automated check (install-time or first-query) that the eql_v3 operators resolve through PostgREST.; A live run of the v3 range filters on a Supabase project; the PR states these were not verified.
- Mitigation: Implement the install-time exposed-schema probe the PR names as a follow-up before calling v3 Supabase supported. Alternatively, have the adapter call the public eql_v3 wrapper functions by name, or run a one-time self-check on first query.

**FS-3 · Full ciphertext envelopes for filter values are written to URL logs and proxies** (medium impact, plausible)

- Trigger: Any encryptedSupabaseV3 select, update or delete with a filter on an encrypted column.
- Mechanism: encryptCollectedTerms encrypts every operand with encrypt(), the storage path, and JSON-stringifies it into the PostgREST filter value (query-builder-v3.ts:194-251). The operand therefore includes `c` (decryptable ciphertext) and all index terms, and travels in GET query strings (SKILL.md:500-513).
- Consequence: Ciphertext of searched values, plus their HMAC/ORE/bloom terms, persists in Supabase request logs, CDN or proxy logs and APM traces. Plaintext is not exposed without ZeroKMS keys, but it widens the attack surface beyond the 'query terms only' design and makes log contents correlatable with stored rows.
- Affects: @cipherstash/stack/supabase (encryptedSupabase v2 and encryptedSupabaseV3), Supabase PostgREST request logs / proxies
- Evidence: `packages/stack/src/supabase/query-builder-v3.ts:194-251`; `skills/stash-supabase/SKILL.md:500-525`
- Existing verification: supabase-v3-builder.test.ts checks the wire encoding of operands with mocks; it asserts the full-envelope shape, not its absence. [exists_not_run]
- Missing verification: A security sign-off that logging full envelopes is acceptable for an interim release.
- Mitigation: Ship behind an explicit opt-in or a prominent 'alpha' label until CIP-3402's term-only envelope lands, and tell customers to scrub query strings from request logs.

**FS-4 · Default free-text config makes v3 like/ilike silently return no matches** (medium impact, plausible)

- Trigger: A customer declares `types.TextSearch(col)` without `.freeTextSearch({ include_original: false })` and filters with like/ilike on a substring.
- Mechanism: v3 column builders default the match index to defaultMatchOpts(), which sets include_original: true (columns.ts:323, 419-439; match-defaults.ts:98-106). The operand is a full storage envelope, so its bloom filter includes the whole pattern as a token, and `@>` only matches when the pattern equals the stored value (SKILL.md:518-525).
- Consequence: Substring search returns empty results with no error. Application features such as search boxes appear to work but find nothing.
- Affects: @cipherstash/stack/supabase (encryptedSupabase v2 and encryptedSupabaseV3), skills/stash-supabase/SKILL.md (shipped agent guidance)
- Evidence: `packages/stack/src/eql/v3/columns.ts:419-439`; `packages/stack/__tests__/supabase-v3.test.ts:23-40`; `skills/stash-supabase/SKILL.md:500-525`
- Existing verification: The live v3 test sets include_original: false explicitly, so the default configuration is not exercised; the suite is gated on Supabase env. [exists_not_run]
- Missing verification: A test of like/ilike with the default TextSearch config, or a runtime warning or error when a pattern filter targets a column with include_original: true.
- Mitigation: Default include_original to false for v3 match domains used through the Supabase adapter, or reject or warn in encryptCollectedTerms when queryType is freeTextSearch and include_original is true.

**FS-5 · protect-ffi 0.27 bump and shared refactors change behaviour for existing v2 users** (high impact, speculative)

- Trigger: An existing v2 customer upgrades @cipherstash/stack to the minor release carrying this change.
- Mechanism: Every consumer moves to protect-ffi 0.27.0 (package.json dependency). For v2, newClient receives eqlVersion undefined (encryption/index.ts:87-106, 758-763); the claim that 0.27 produces byte-identical v2 output comes from code comments and the PR. Shared paths also change: `encryptQuery(array, opts)` routing, the resolveLockContext structural check (identity/index.ts:41-48), and the v2 Supabase builder seams (query-builder.ts:929-990).
- Consequence: If 0.27's v2 default differs (payload keys, query-term shape), new writes or queries become incompatible with data at rest or with the installed eql_v2 SQL. For v2 Supabase, a drifted seam would mis-encode filters.
- Affects: @cipherstash/stack encryption client (all v2 consumers), @cipherstash/stack/supabase (encryptedSupabase v2 and encryptedSupabaseV3)
- Evidence: `packages/stack/package.json`; `packages/stack/src/encryption/index.ts:87-106`; `packages/stack/src/identity/index.ts:41-48`; `packages/stack/src/supabase/query-builder.ts:929-990`; ci_result
- Existing verification: CI Run Tests (Node 22/24/Bun), Run E2E Tests and WASM E2E Tests concluded success on the head commit; CI injects CS_* credentials, so live v2 encryption suites likely ran. The v2 Supabase live suite is not configured in CI. [ran_passed]
- Missing verification: A cross-version check that payloads written by 0.26 decrypt and query under 0.27, and the reverse.; A v2 Supabase live run after the seam refactor.
- Mitigation: Add a fixture-based compatibility test: decrypt and query stored v2 payloads produced by 0.26.0 using 0.27.0. Call out the native-module bump in the release notes.

### Recommended controls

- Block or gate `stash eql upgrade --eql-version 3` and `install --eql-version 3 --force` when user columns depend on eql_v3 types; require explicit confirmation naming the columns that will be dropped. (other; FS-1)
- Add a Postgres integration test: install v3, create a table with an eql_v3 domain column and rows, run upgrade, and assert the rows remain. (test; FS-1, VG-1)
- Ask an EQL maintainer whether the v3 bundle is meant to be re-runnable over live data, and whether domains should live outside the dropped schema, as v2's type does in public. (review_focus; FS-1)
- Implement the install-time or first-query probe that confirms eql_v3 operators resolve through PostgREST before v3 Supabase is called supported. (compatibility_check; FS-2, VG-3)
- Run the live supabase-v3 suite against a configured Supabase project before release and record the result; add a case using the default TextSearch config. (test; FS-2, FS-4, VG-2)
- Mark encryptedSupabaseV3 as alpha in the changeset and release notes, stating the ciphertext-in-URL and include_original caveats; consider an opt-in flag. (documentation; FS-3, FS-4)
- Decrypt and query fixtures written with protect-ffi 0.26.0 using 0.27.0 for v2 schemas. (compatibility_check; FS-5, VG-4)

### What this assessment could not see

- The ~36k-line vendored SQL bundles were not reviewed beyond the schema drop/create preamble and domain placement. The Supabase strip script was read but not run. Other bundle-level defects (CHECK constraints, operator semantics) are unassessed.
- The large stacked-branch content (eql/v3 types module, typed v3 client, v3-matrix tests, wasm-inline changes, docs/plans) was skimmed, not read in depth; the Supabase adapter, CLI and shared encryption paths were read closely. Risks inside the v3 types module and the typed client may be missed.
- No tests were run locally (no network, no credentials, dependencies not installed). CI evidence is check-run conclusions only. Which suites ran or were skipped in CI is inferred from workflow configuration.
- The PostgreSQL behaviour of DROP SCHEMA ... CASCADE on domain-typed columns, and PostgREST operator fallback, were taken from PostgreSQL semantics and the shipped docs, not executed. FS-1's data loss and FS-2's wrong-row behaviour were not reproduced.
- CODEOWNERS, deployment context and the design spec (#546) were unavailable. Review ownership and release sequencing are not assessed.

_Inputs unavailable: dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
