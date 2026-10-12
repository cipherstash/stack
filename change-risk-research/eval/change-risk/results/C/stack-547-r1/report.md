## Change risk: Changes or verification required

**Impact if something goes wrong:** critical · **Verification confidence:** low · `b405a54850..e027b7492a`

Adds an EQL v3 Supabase adapter (encryptedSupabaseV3), a v3 typed client and schema module, bumps @cipherstash/protect-ffi 0.26.0→0.27.0, and adds a `--eql-version 3` path to `stash eql install/upgrade/status` that applies a vendored ~36k-line eql-3.0.0-alpha.2 SQL bundle. The most material risk is in the CLI: `stash eql upgrade --eql-version 3` unconditionally re-runs the v3 bundle, which begins with `DROP SCHEMA IF EXISTS eql_v3 CASCADE`. Unlike v2 (whose column type lives in `public`), v3 user columns are typed with domains inside `eql_v3`, so the CASCADE drops every customer column of those types — irreversible loss of encrypted data. The change's own test helper warns the bundle must never be run unconditionally. Secondary risks: v3 filter operands are full storage envelopes (real ciphertext + all index terms) sent in PostgREST GET query strings, and free-text `like` silently returns no rows on columns using the default `include_original: true`. v2 behaviour is protected by dialect seams with v2 regression unit tests, and all CI check runs passed, but the live Supabase suites (v2 and v3) are not configured in CI. Advisory verdict: changes or verification required before release.

### Failure scenarios

**FS-1 · `stash eql upgrade --eql-version 3` drops every customer column typed with an eql_v3 domain** (critical impact, observed in the code)

- Trigger: A user with tables containing eql_v3.* columns (as the shipped skill instructs) runs `stash eql upgrade --eql-version 3`, or `stash eql install --eql-version 3 --force`, or `install --eql-version 3` against a pre-alpha.2 eql_v3 install (eql_v3 present, eql_v3_internal absent).
- Mechanism: upgradeCommand checks only that v3 is installed and then calls installer.install({ eqlVersion: 3 }) (upgrade.ts:96-101), which executes the bundled SQL (installer/index.ts:335). The bundle begins with `DROP SCHEMA IF EXISTS eql_v3 CASCADE` and `DROP SCHEMA IF EXISTS eql_v3_internal CASCADE` (cipherstash-encrypt-v3-supabase.sql:38,46). The column types themselves are domains inside eql_v3 (e.g. `CREATE DOMAIN eql_v3.timestamp`, line 545), so PostgreSQL's CASCADE drops every dependent table column. In v2 the column type is `public.eql_v2_encrypted` (cipherstash-encrypt-supabase.sql:201), outside the dropped schema, which is why the same re-run pattern was survivable for v2. isInstalled deliberately reports a pre-alpha.2 install as not installed so that install re-runs the bundle (installer/index.ts:205-225). The change's own test helper states the bundle must never be run unconditionally because of this DROP (__tests__/helpers/eql-v3.ts:80-82); the CLI path has no such guard, no confirmation and no dependent-column check.
- Consequence: All encrypted data in eql_v3-typed columns is permanently deleted inside a committed transaction; the command reports 'EQL extensions upgraded.' Recovery requires a database backup restore.
- Affects: stash CLI: eql install / upgrade / status (packages/cli), Vendored EQL v3 SQL bundles (packages/cli/src/sql/cipherstash-encrypt-v3*.sql), Customer PostgreSQL / Supabase databases with eql_v3-typed columns, stash-supabase agent skill (skills/stash-supabase/SKILL.md)
- Evidence: `packages/cli/src/commands/db/upgrade.ts:96-101`; `packages/cli/src/sql/cipherstash-encrypt-v3-supabase.sql:36-46`; `packages/cli/src/sql/cipherstash-encrypt-v3-supabase.sql:545`; `packages/cli/src/installer/index.ts:205-335`; `skills/stash-supabase/SKILL.md:423-472`; `packages/cli/src/sql/cipherstash-encrypt-supabase.sql:201`; `packages/stack/__tests__/helpers/eql-v3.ts:80-82`
- Existing verification: CLI installer unit tests cover flag validation and bundle selection for v3; none exercise upgrade or a reinstall over existing eql_v3-typed columns. [exists_not_run]
- Missing verification: An integration test that creates a table with an eql_v3.* column, runs `stash eql upgrade --eql-version 3` (and `install --force`), and asserts the column and its data survive or the command refuses.; A pre-flight check in the CLI for columns depending on eql_v3 types before running the bundle.
- Mitigation: Before release: make `upgrade --eql-version 3` and `install --eql-version 3 --force` refuse (or require an explicit destructive-confirmation flag) when any pg_attribute column depends on an eql_v3 type; or ship a non-destructive upgrade script. Add a prominent warning to the stash-supabase skill and CLI help.

**FS-2 · v3 Supabase filters send a decryptable ciphertext plus all index terms in PostgREST GET URLs** (medium impact, plausible)

- Trigger: Any encrypted filter (.eq/.gte/.like/.in/.or/.not/.match) issued through encryptedSupabaseV3.
- Mechanism: encryptCollectedTerms in query-builder-v3.ts:194-251 calls encryptionClient.encrypt() for every filter value and returns JSON.stringify(result.data) as the operand. The storage envelope carries `c` (the ciphertext of the searched value) and every index term configured on the column (e.g. ORE terms on an equality-only filter). The class doc (lines 58-71) acknowledges that operands land in URL logs, proxies and Supabase request logs; it is tracked as interim (CIP-3402).
- Consequence: Search values persist as ciphertext plus ORE/HMAC/bloom terms in third-party request logs outside the database's access controls. Not plaintext, but the ciphertext is decryptable by anyone who later gains key access, and the extra index terms widen leakage beyond what a query needs.
- Affects: @cipherstash/stack/supabase encryptedSupabaseV3 (query-builder-v3.ts), Supabase PostgREST request logs / proxies
- Evidence: `packages/stack/src/supabase/query-builder-v3.ts:58-251`
- Existing verification: supabase-v3-builder unit test pins that equality operands are full-envelope jsonb text (asserts the behaviour, not its safety). [exists_not_run]
- Missing verification: A decision record or security sign-off that ciphertext-bearing operands in request URLs are acceptable for a release, not only an alpha.
- Mitigation: Document the exposure prominently in the v3 Supabase docs and skill; mark encryptedSupabaseV3 experimental until the term-only scalar envelope ships; consider routing filters through POST/RPC to keep operands out of URLs.

**FS-3 · v3 `like`/`ilike` silently return no rows for default-configured text_search columns** (medium impact, plausible)

- Trigger: A user declares `types.TextSearch('email')` without `.freeTextSearch({ include_original: false })` (as in the skill's own example) and filters with a substring pattern.
- Mechanism: The v3 text_search column defaults include_original to true (columns.ts:419, match-defaults.ts:39). The operand is a full storage envelope whose bloom filter therefore also contains the whole pattern as a token; `cs` containment (query-builder-v3.ts:260-262) then matches only when the pattern equals the stored value. The live test has to opt out explicitly (supabase-v3.test.ts:33-39).
- Consequence: Search features return empty results with no error; applications appear to work but miss matches.
- Affects: @cipherstash/stack/supabase encryptedSupabaseV3 (query-builder-v3.ts), stash-supabase agent skill (skills/stash-supabase/SKILL.md)
- Evidence: `packages/stack/src/schema/match-defaults.ts:35-41`; `packages/stack/src/eql/v3/columns.ts:417-440`; `packages/stack/__tests__/supabase-v3.test.ts:33-40`; `skills/stash-supabase/SKILL.md:423-472`
- Existing verification: Live supabase-v3 like test uses include_original: false; skipped in CI (no SUPABASE_URL configured). [exists_not_run]
- Missing verification: A test or runtime warning for like/ilike on a v3 column built with include_original: true.
- Mitigation: Default include_original to false for v3 text_search, or throw/warn in the v3 builder when an encrypted pattern filter targets a column with include_original: true; make the skill example set it.

**FS-4 · protect-ffi 0.27.0 bump or eqlVersion plumbing changes v2 output for existing users** (high impact, plausible)

- Trigger: Existing v2 users upgrade @cipherstash/stack; the native binding and newClient options change underneath every encrypt/encryptQuery call.
- Mechanism: package.json:247 bumps protect-ffi; Encryption() passes `eqlVersion: undefined` for v2 schema sets (encryption/index.ts:87-110, 758). The change claims byte-identical v2 output, which depends on 0.27.0 defaulting to v2 wire. v2 Supabase builder now routes through new seam methods (query-builder.ts).
- Consequence: If the FFI default or payload shape shifted, v2 payloads written after upgrade could differ from what installed eql_v2 SQL expects, breaking queries on stored data.
- Affects: @cipherstash/stack core EncryptionClient and protect-ffi native binding, @cipherstash/stack/supabase encryptedSupabase (v2 builder)
- Evidence: `packages/stack/package.json:247`; `packages/stack/src/encryption/index.ts:87-106`; `packages/stack/src/supabase/query-builder.ts`; ci_result
- Existing verification: CI 'Run Tests' (Node 22, Node 24, Bun), 'Run E2E Tests' and WASM Deno E2E check runs passed on head; CI writes CS_* credentials and a local DATABASE_URL, so v2 live encryption suites likely ran. [ran_passed]; v2 regression pins for each dialect seam in supabase-v3-builder.test.ts. [exists_not_run]
- Missing verification: Live v2 Supabase suite is not configured in CI (no SUPABASE_URL), so the v2 builder over a real PostgREST is unverified.
- Mitigation: Run the v2 Supabase live suite once against a real project before release; confirm protect-ffi 0.27.0 changelog states v2 default is unchanged.

### Recommended controls

- Guard the v3 reinstall/upgrade path: detect dependent columns on eql_v3 types and refuse (or require an explicit --destroy-data style flag), or ship a non-destructive v3 upgrade script. (other; FS-1)
- Add a CLI integration test against the CI Postgres: create a table with an eql_v3 column, run upgrade --eql-version 3, assert data survives or the command aborts. (test; FS-1, VG-1)
- Warn in the stash-supabase skill, CLI help and changeset that the v3 bundle drops eql_v3 with CASCADE, and that filter operands carry ciphertext in request URLs. (documentation; FS-1, FS-2)
- Run the v2 and v3 Supabase live suites against a real project before publishing; consider adding Supabase secrets to CI. (test; FS-3, FS-4, VG-2)
- Security review of the full-envelope operand design (query-builder-v3.ts encryptCollectedTerms) and of the include_original default for v3 text_search. (review_focus; FS-2, FS-3)

### What this assessment could not see

- The ~108k lines of vendored SQL (two v3 bundles and a test fixture) were not reviewed beyond the schema drop/create preamble and domain declarations. Defects inside EQL v3 SQL functions, operators or CHECK constraints are not assessed.
- The stacked base work (src/eql/v3 columns/table/types, typed client, wasm-inline changes, identity resolveLockContext change) was skimmed, not traced in depth. Lock-context and wasm-inline regressions in those areas may be missed.
- PostgreSQL CASCADE semantics for dropping domains (dependent columns are dropped) are applied from knowledge; no command was run against a database. FS-1 is supported by code reading, not by a reproduced run.
- protect-ffi 0.27.0 release notes and binary were not available. Whether v2 wire output is truly unchanged rests on CI results only.
- No deployment context: unknown how many users already run eql_v3 alpha installs with data. Likelihood of FS-1 cannot be estimated; impact is assessed regardless.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
