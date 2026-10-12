## Change risk: Changes or verification required

**Impact if something goes wrong:** critical · **Verification confidence:** low · `b405a54850..e027b7492a`

Large (92 files, +120k lines, mostly two vendored 36k-line SQL bundles plus a test fixture) change that stacks the EQL v3 typed schema/client work (#541) with a new EQL v3 Supabase adapter (encryptedSupabaseV3) and a CLI v3 install/upgrade path, and bumps @cipherstash/protect-ffi 0.26 -> 0.27 for every user. The most material risk is in the CLI: the vendored eql-3.0.0-alpha.2 bundle begins with DROP SCHEMA eql_v3 CASCADE, and unlike v2 (whose column type lives in public) the v3 column domains live inside eql_v3, so `stash eql upgrade --eql-version 3` (or install --force, or install over a pre-alpha.2 v3 schema) on a database that already has eql_v3.* columns would drop those columns and commit, with no confirmation and no test covering it. The adapter itself deliberately sends full storage envelopes (real ciphertext plus all index terms) as PostgREST GET filter operands, a documented interim weakening of the query-term boundary. Silent wrong-result modes (unexposed eql_v3 schema, default include_original:true on free-text) are documented but not guarded. v2 paths are changed only through identity-default seams and the protect-ffi bump; CI check runs passed, but the live Supabase suites (v2 and v3) are env-gated on SUPABASE_URL, which CI does not set. Advisory verdict: changes or verification required before release.

### Failure scenarios

**FS-1 · `stash eql upgrade --eql-version 3` (or install --force) drops every eql_v3.* user column** (critical impact, observed in the code)

- Trigger: A user who installed EQL v3 and created tables with eql_v3.* domain columns runs `stash eql upgrade --eql-version 3`, or `stash eql install --eql-version 3 --force`, or `stash eql install --eql-version 3` against a database holding a pre-alpha.2 v3 install (eql_v3 present, eql_v3_internal absent, so isInstalled returns false).
- Mechanism: upgradeCommand proceeds whenever v3 is installed and calls installer.install({eqlVersion:3}) with no confirmation (upgrade.ts:96-101). install() runs the vendored bundle in BEGIN/COMMIT (installer/index.ts:334-341). The bundle opens with `DROP SCHEMA IF EXISTS eql_v3 CASCADE` (cipherstash-encrypt-v3.sql:38) and the column domains are created inside that schema (e.g. `CREATE DOMAIN eql_v3.timestamp`, line 545). In PostgreSQL, dropping a schema CASCADE drops its domains and, with them, every table column of those domain types. The v2 bundle avoided this by creating its column type as `public.eql_v2_encrypted` outside the dropped eql_v2 schema (base cipherstash-encrypt.sql:38); v3 does not.
- Consequence: All encrypted v3 columns in the database are silently removed and the transaction commits, reported as 'EQL extensions upgraded.' Encrypted data is lost and recoverable only from backup. Running upgrade after a CLI update is the routine action, so this is the expected upgrade path.
- Affects: packages/cli EQL installer and install/upgrade/status commands, Vendored EQL v3 SQL bundles (packages/cli/src/sql/cipherstash-encrypt-v3*.sql), Customer PostgreSQL/Supabase databases with eql_v3.* columns
- Evidence: `packages/cli/src/sql/cipherstash-encrypt-v3.sql:36-46`; `packages/cli/src/sql/cipherstash-encrypt-v3.sql:545-560`; `packages/cli/src/sql/cipherstash-encrypt.sql:38` (base); `packages/cli/src/commands/db/upgrade.ts:53-101`; `packages/cli/src/installer/index.ts:297-345`; `packages/cli/src/installer/index.ts:205-227`; `packages/cli/src/__tests__/installer.test.ts:208-335`
- Existing verification: installer.test.ts v3 cases mock pg and assert the SQL text contains eql_v3, grants are issued, and isInstalled requires both schemas; nothing runs the bundle against a database with dependent columns. [exists_not_run]; CI 'Run Tests (Node 22/24)' check runs passed; they include the CLI unit tests but no upgrade-on-populated-database test exists to run. [ran_passed]
- Missing verification: Integration test: install v3, create a table with an eql_v3.* column and a row, run upgrade (and install --force), and assert the column and row survive or the command refuses.; Not executed here: no PostgreSQL server was available to run the bundle; the column-drop consequence rests on documented PostgreSQL DROP ... CASCADE semantics.
- Mitigation: Before running the v3 bundle, query pg_attribute/pg_type for user columns whose type is in eql_v3 and refuse (or require an explicit destructive flag and confirmation) when any exist; disable `upgrade --eql-version 3` until EQL ships a non-destructive v3 upgrade script or moves the column domains out of the dropped schema; document that re-running the v3 bundle is destructive.

**FS-2 · v3 filter operands put real ciphertext and all index terms into URL logs** (high impact, plausible)

- Trigger: Any encryptedSupabaseV3 select/update/delete with a filter on an encrypted column, in a deployment where Supabase request logs, CDN/proxy or APM logs record request URLs.
- Mechanism: encryptCollectedTerms in the v3 builder calls encryptionClient.encrypt (storage path) for each operand and returns JSON.stringify(result.data) (query-builder-v3.ts:194-251); the full envelope includes the decryptable ciphertext `c` and every index term (hm, ob, bf) of the column. PostgREST filters are sent as GET query parameters. v2 sends index-term-only encryptQuery output.
- Consequence: Ciphertexts of queried values (often the most sensitive lookups, e.g. emails) and all their index terms are persisted in third-party and operator logs outside the database's access controls. Anyone with log access plus decrypt-capable credentials (or a later key compromise) can recover plaintext; extra index terms (e.g. ORE on an equality lookup) leak more than the query needs. Identity-bound (lock context) operands are less exposed.
- Affects: @cipherstash/stack/supabase (v3 adapter), Supabase / PostgREST request logs and intermediate proxies
- Evidence: `packages/stack/src/supabase/query-builder-v3.ts:194-251`; `docs/reference/supabase-sdk.md:159-170`; pr_description
- Existing verification: supabase-v3-builder.test.ts asserts operands are full-envelope jsonb text (i.e. pins the behaviour rather than guarding against it). [exists_not_run]
- Missing verification: No check of operand size / URL length limits with full envelopes on multi-term `in`/`or` filters.; No decision record on whether shipping this interim behaviour in a minor release is acceptable for production use.
- Mitigation: Ship v3 Supabase as explicitly experimental (or behind an opt-in flag) until the term-only scalar query envelope (CIP-3402) lands; recommend lock contexts; advise disabling URL logging; consider POST-based RPC filters.

**FS-3 · Unexposed eql_v3 schema makes encrypted filters silently return wrong rows** (high impact, plausible)

- Trigger: A Supabase project where `eql_v3` has not been added to Exposed schemas (a manual dashboard step), or where it is later removed.
- Mechanism: eql_v3 domains are `DOMAIN ... AS jsonb`; when the eql_v3 operators are not on PostgREST's search_path, `col >= operand` resolves to the base jsonb operators. The author's docs state comparisons then silently fall back and return wrong rows with no error. The installer applies grants but does not probe exposure; the PR lists the probe as out of scope.
- Consequence: Range filters return rows decided by jsonb ordering of random ciphertext; equality returns nothing. Applications that use encrypted filters to scope data (e.g. by customer email) receive wrong rows without any error.
- Affects: @cipherstash/stack/supabase (v3 adapter), packages/cli EQL installer and install/upgrade/status commands, skills/stash-supabase/SKILL.md (shipped agent skill)
- Evidence: `docs/reference/supabase-sdk.md:139-183`; pr_description
- Existing verification: Live suite supabase-v3.test.ts would catch it but is skipped unless SUPABASE_URL/SUPABASE_ANON_KEY are set; CI does not set them. [exists_not_run]
- Missing verification: Install-time or first-query probe that the eql_v3 operator resolves over PostgREST.; Any CI run of the live Supabase suites.
- Mitigation: Add the exposure probe (insert/filter round-trip or `to_regoperator` check through PostgREST) to `stash eql install --supabase` and/or the adapter's first query; fail loudly.

**FS-4 · Default free-text config makes v3 like/ilike silently miss matches** (medium impact, plausible)

- Trigger: A user declares `types.TextSearch(...)` (or `.freeTextSearch()` without options) and filters with `.like`/`.ilike` through encryptedSupabaseV3.
- Mechanism: The shared match defaults set include_original: true (match-defaults.ts:39), which the v3 column builders use (columns.ts:439). With a full-envelope operand, the operand bloom carries the whole pattern as a token, so a substring pattern only matches when it equals the stored value. The live test sets include_original:false explicitly with a 'load-bearing' comment.
- Consequence: Searches return empty or incomplete results with no error; users get wrong search behaviour under the default configuration.
- Affects: @cipherstash/stack/supabase (v3 adapter), skills/stash-supabase/SKILL.md (shipped agent skill)
- Evidence: `docs/reference/supabase-sdk.md:139-183`; `packages/stack/src/schema/match-defaults.ts:39`; `packages/stack/__tests__/supabase-v3.test.ts:23-40`
- Existing verification: Live supabase-v3.test.ts covers like->cs only with include_original:false and is env-skipped in CI. [exists_not_run]
- Missing verification: A test (or runtime warning) for a free-text filter on a column built with default match options.
- Mitigation: Default include_original to false for v3 match-capable domains used with this adapter, or reject/warn in the v3 builder when a like/ilike targets a column with include_original:true.

**FS-5 · protect-ffi 0.27 changes bulkDecrypt failure shape for existing v2 callers** (medium impact, plausible)

- Trigger: An existing application calls `bulkDecrypt` with a malformed or corrupted ciphertext after upgrading to this minor release.
- Mechanism: Under 0.27 malformed ciphertext parsing moved into the fallible API, so the operation now returns success with per-item `{error}` entries instead of a top-level DecryptionError (commit f3e4c3e updated the test to the new shape). The stack's bulk-decrypt forwards per-item errors (bulk-decrypt.ts:49-50). The changeset describes 0.27 only as enabling eqlVersion and does not mention this.
- Consequence: Callers that only checked `result.failure` and then read `item.data` will treat the batch as successful and get undefined values for corrupt items. Other changes inside protect-ffi 0.27 that affect v2 output are unknown.
- Affects: @cipherstash/stack encryption core (all v2 and v3 users)
- Evidence: `packages/stack/package.json:247`; `packages/stack/__tests__/error-codes.test.ts:247-275`; `.changeset/eql-v3-supabase.md:19-21`; `packages/stack/src/encryption/operations/bulk-decrypt.ts:49-50`
- Existing verification: error-codes.test.ts asserts the new per-item shape; the Node 22/24 test check runs passed (whether live-credential suites ran is not visible from ci.json). [ran_passed]
- Missing verification: protect-ffi 0.27 changelog review for other v2-visible changes (unavailable here).
- Mitigation: Call out the bulkDecrypt behaviour change in the changeset/release notes; confirm v2 payloads are byte-identical under 0.27 with eqlVersion undefined.

### Recommended controls

- Make v3 install/upgrade refuse to run the bundle when any user column depends on an eql_v3 type (or require an explicit destructive flag plus confirmation); consider disabling `upgrade --eql-version 3` until a non-destructive upgrade exists. (other; FS-1)
- Add a CLI integration test against the CI Postgres service: install v3, create a table with an eql_v3 column and a row, run upgrade and install --force, assert the data survives or the command aborts. (test; FS-1, VG-1)
- Label encryptedSupabaseV3 experimental (or gate it behind an explicit opt-in) until CIP-3402 removes ciphertext from operands; state the log-exposure caveat in release notes. (feature_flag; FS-2, VG-3)
- Run the live Supabase v2 and v3 suites at least once against a project with eql_v3 exposed before release (or add a Supabase container job to CI). (test; FS-3, FS-4, VG-2)
- Add an Exposed-schemas probe to `stash eql install --supabase --eql-version 3` and fail loudly when operators do not resolve. (other; FS-3)
- Document the protect-ffi 0.27 bulkDecrypt per-item error change in the changeset; review the 0.27 changelog for other v2-visible changes. (documentation; FS-5, VG-4)
- Reviewers: packages/cli/src/commands/db/upgrade.ts, installer/index.ts install(), and the head of cipherstash-encrypt-v3*.sql; query-builder-v3.ts encryptCollectedTerms; match-defaults include_original for v3 domains. (review_focus; FS-1, FS-2, FS-4)

### What this assessment could not see

- The two 36k-line vendored SQL bundles and the 36k-line test fixture were not reviewed beyond their headers, schema/domain creation and DROP statements. Defects inside the EQL v3 SQL (domain CHECKs, operator semantics) are not assessed; they are upstream EQL alpha.2 content.
- The stacked #541 work (eql/v3 columns.ts, table.ts, types.ts, typed client, v3 matrix tests, planning docs) was skimmed, not read line by line; focus was on the Supabase adapter, shared encryption paths, and the CLI. Typing or config-emission defects in the v3 DSL may be missed.
- No tests were run locally (no node_modules, no network, no PostgreSQL server). FS-1's consequence relies on PostgreSQL DROP SCHEMA/DOMAIN CASCADE semantics, not an executed reproduction. Verification status relies on ci.json conclusions only; ci.json has no logs, so it is unknown which env-gated suites ran.
- supabase-js quoting of JSON operands inside `in.(...)` and `or=(...)` strings was not traced through the real client; the v3 builder tests use a mock Supabase client. A wire-format failure for multi-value v3 filters cannot be ruled out; likely loud rather than silent.
- protect-ffi 0.27 release notes and the EQL alpha.2 upstream changelog were unavailable. Other behaviour changes for v2 users from the native dependency bump are unknown.
- No deployment/release context (npm tags, whether stash CLI and stack release together, customer adoption of v3). Cannot judge how many databases would hit FS-1 on release; impact is rated on consequence, not likelihood.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
