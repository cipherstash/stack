## Change risk: Changes or verification required

**Impact if something goes wrong:** critical · **Verification confidence:** low · `b405a54850..e027b7492a`

Adds EQL v3 support: a new typed schema (`@cipherstash/stack/eql/v3`, `/v3`), an `encryptedSupabaseV3` adapter, `eqlVersion` wire selection on the client (protect-ffi 0.26 -> 0.27 for everyone), and a CLI v3 install/upgrade path with two vendored ~36k-line SQL bundles. The v2 code is refactored into overridable seams that are meant to keep v2 behaviour unchanged. The most material risk is in the CLI: unlike the v2 bundle, which keeps the customer column type `public.eql_v2_encrypted` outside the dropped schema, the v3 bundle defines every customer column domain inside `eql_v3` and opens with `DROP SCHEMA IF EXISTS eql_v3 CASCADE`. The new `stash eql upgrade --eql-version 3` and `install --eql-version 3 --force` both run that bundle, so on a database that already has v3-typed columns they would drop those columns and their encrypted data. Nothing guards against this and no test covers it. Secondary risks: the v3 Supabase filters send full ciphertext envelopes in GET query strings (documented as interim), the free-text `like`/`ilike` defaults silently miss matches, and the FFI bump for v2 users could not be verified here. No tests were run; CI results were not provided.

### Failure scenarios

**FS-1 · `stash eql upgrade --eql-version 3` (or install --force) drops customer columns typed with eql_v3 domains** (critical impact, plausible)

- Trigger: A user with tables already using eql_v3.* columns (as the docs instruct) runs `stash eql upgrade --eql-version 3`, runs `stash eql install --eql-version 3 --force`, or runs a plain v3 install against an older-generation v3 install (eql_v3 present, eql_v3_internal absent).
- Mechanism: upgradeCommand checks isInstalled({eqlVersion:3}) and then calls installer.install({eqlVersion:3}) (upgrade.ts:53,96). install() runs the bundled SQL and then COMMITs (installer/index.ts:335,341). The v3 bundle opens with `DROP SCHEMA IF EXISTS eql_v3 CASCADE` (cipherstash-encrypt-v3.sql:38), and the column domains are defined in that schema (e.g. CREATE DOMAIN eql_v3.timestamp, :545). In PostgreSQL, dropping a domain with CASCADE drops the table columns of that type. The v2 bundle avoids exactly this: it creates the customer column type in `public` and only if absent, with the note 'Customer data columns use this type, so it must not be dropped' (cipherstash-encrypt.sql:28-41). The test helper for this change even notes the bundle 'must never run unconditionally' against a shared database (helpers/eql-v3.ts:80-82), but the CLI upgrade path runs it unconditionally once v3 is detected. BC-2 makes this reachable without --force for older-generation installs.
- Consequence: Every eql_v3-typed column in the database is silently removed in a committed transaction. The encrypted data in those columns is lost and can only come back from a backup. The CLI reports success ('EQL extensions upgraded').
- Affects: stash CLI: eql install / eql upgrade / db status (packages/cli), Customer PostgreSQL / Supabase databases with eql_v3.* columns, Vendored EQL v3 SQL bundles (packages/cli/src/sql/cipherstash-encrypt-v3*.sql)
- Evidence: `packages/cli/src/commands/db/upgrade.ts:50-101`; `packages/cli/src/sql/cipherstash-encrypt-v3.sql:36-47`; `packages/cli/src/sql/cipherstash-encrypt-v3.sql:545-560`; `packages/cli/src/installer/index.ts:297-341`; `packages/cli/src/installer/index.ts:211-227`; `docs/reference/supabase-sdk.md:91-96`; `packages/cli/src/sql/cipherstash-encrypt.sql:28-43`
- Existing verification: installer.test.ts checks that the v3 bundle and grants are issued and that isInstalled requires both schemas (mocked pg). It does not check behaviour against existing v3 columns. [exists_not_run]
- Missing verification: Integration test: create a table with eql_v3.text_search columns and data, run `stash eql upgrade --eql-version 3`, and assert the columns and rows survive (or that the CLI refuses).; Confirmation from the EQL maintainers of whether the v3 bundle is meant to be re-runnable over live data.
- Mitigation: Until the bundle is non-destructive, make v3 upgrade, --force and stale-generation reinstall refuse (or require an explicit destructive confirmation) when any column in pg_attribute depends on a type in eql_v3. Alternatively, move the column domains out of the dropped schema, as v2 does with public.eql_v2_encrypted. Document clearly that v3 alpha upgrades are destructive.

**FS-2 · v3 Supabase filters put full ciphertext envelopes and all index terms in GET URLs** (medium impact, plausible)

- Trigger: Any v3 Supabase filter (`eq`, `gt`, `like`, `in`, `or`, ...) on an encrypted column issued through PostgREST.
- Mechanism: encryptCollectedTerms calls `encryptionClient.encrypt()` per operand and returns JSON.stringify of the full storage payload (query-builder-v3.ts:194-249). The code and docs say this carries a decryptable `c` plus every index term (hm, ob/ORE, bloom) and lands in URL logs (supabase-sdk.md:158-168).
- Consequence: Ciphertexts and searchable index terms (including order-revealing terms) are kept in proxy, CDN and Supabase request logs outside the database's access controls. This widens what an attacker with log access can analyse; plaintext is still not exposed without keys. Large envelopes, or `.in()` with many values, can also exceed URL length limits (a loud failure).
- Affects: @cipherstash/stack encryptedSupabaseV3 (src/supabase/query-builder-v3.ts), PostgREST / proxy / Supabase request logs
- Evidence: `packages/stack/src/supabase/query-builder-v3.ts:194-249`; `docs/reference/supabase-sdk.md:158-168`
- Existing verification: supabase-v3-builder.test.ts checks operator mapping and encoding with a mocked Supabase client. It does not check log or URL exposure. [exists_not_run]
- Missing verification: A security sign-off that the interim full-envelope operand (tracked as CIP-3402 in comments) is acceptable to release, and a measurement of operand URL size per domain.
- Mitigation: Gate encryptedSupabaseV3 as experimental/alpha in release notes. Send filters via POST/RPC where possible. Ship the term-only query envelope before GA.

**FS-3 · v3 `like`/`ilike` silently return no or partial rows with default match options or `%` patterns** (medium impact, plausible)

- Trigger: A user declares `types.TextSearch(...)` without `freeTextSearch({ include_original: false })`, or passes a v2-style `%alice%` pattern (as the v2 sections of the same skill show), and queries with `.like`/`.ilike` through encryptedSupabaseV3.
- Mechanism: Encrypted like/ilike become `cs` on the bloom filter (query-builder-v3.ts:260-277). The operand is a full envelope whose bloom includes the original whole value when include_original is true, the default in defaultMatchOpts (match-defaults.ts:33-41). The code comment says such patterns then only match exact values (query-builder-v3.ts:72-78).
- Consequence: Search features return empty or incomplete results without an error. This is functional degradation, not data loss.
- Affects: @cipherstash/stack encryptedSupabaseV3 (src/supabase/query-builder-v3.ts), stash-supabase agent skill copied into customer repos
- Evidence: `packages/stack/src/supabase/query-builder-v3.ts:72-78`; `packages/stack/src/schema/match-defaults.ts:33-41`
- Existing verification: Builder unit test only checks that like/ilike become `cs`. Whether the result is correct depends on the live-gated pg/Supabase tests, which were not run. [exists_not_run]
- Missing verification: Live test that substring `.ilike` finds rows with the default TextSearch configuration (expected to fail today) and with include_original:false.
- Mitigation: Default include_original to false for v3 domains used through Supabase, or reject/warn on `%` and on include_original:true at query time.

**FS-4 · protect-ffi 0.27 bump changes v2 behaviour for existing users** (high impact, speculative)

- Trigger: Any existing v2 user upgrades @cipherstash/stack and gets protect-ffi 0.27.0 (native or WASM).
- Mechanism: The dependency moves to 0.27.0 (package.json:247), and newClient now receives an `eqlVersion` key (undefined for v2) (encryption/index.ts:153-167). The comments claim v2 output stays byte-identical, but that is a property of the FFI release and cannot be checked in this checkout (no node_modules, no network).
- Consequence: If 0.27 changes v2 payload shape, query-term encoding or error codes, v2 users could write payloads that older readers or the installed eql_v2 SQL handle differently. That is a cross-version data-compatibility problem.
- Affects: @cipherstash/stack v2 encryptedSupabase and EncryptionClient, @cipherstash/protect-ffi native/WASM binding
- Evidence: `packages/stack/package.json:247`; `packages/stack/src/encryption/index.ts:87-106`
- Existing verification: Existing v2 suites (encrypt-query*.test.ts, supabase.test.ts) exercise the FFI, but most are gated on live credentials. [exists_not_run]
- Missing verification: A CI run of the live v2 suites against 0.27.0, and a golden-payload comparison of v2 encrypt/encryptQuery output between 0.26 and 0.27.
- Mitigation: Confirm that the protect-ffi 0.27 changelog states v2 wire output is unchanged, and run the credentialed v2 suites before release.

### Recommended controls

- Add a pre-flight guard to `eql upgrade --eql-version 3`, `install --eql-version 3 --force` and the stale-generation reinstall: query for user columns whose type lives in eql_v3 and abort (or require an explicit destructive flag) if any exist. (other; FS-1)
- Add a Postgres integration test that seeds an eql_v3.text_search column with rows, runs the v3 upgrade, and asserts the data survives or the command refuses. (test; FS-1, VG-1)
- State in the changeset, CLI help and the stash-supabase skill that v3 is alpha and that rerunning the v3 bundle is destructive. Mark encryptedSupabaseV3 as experimental and flag the URL-logged operands. (documentation; FS-1, FS-2)
- Have the EQL/security owners sign off on the interim full-envelope filter operand and the include_original default for v3 free-text search. (review_focus; FS-2, FS-3)
- Run the credentialed v2 suites and a 0.26 vs 0.27 golden-payload comparison before publishing. (compatibility_check; FS-4, VG-3)

### What this assessment could not see

- The ~36k-line vendored SQL bundles were checked only for schema drops, domain locations and the v2 contrast. Their operator semantics were not reviewed. Defects inside the EQL v3 SQL (operator correctness, CHECK constraints) are not assessed.
- No tests were run: there is no node_modules, no Postgres server and no credentials, and no CI results were provided. Every verification status is exists_not_run. The PostgreSQL CASCADE behaviour in FS-1 rests on documented PostgreSQL semantics, not a reproduction.
- src/eql/v3/* (columns/table/types), src/encryption/v3.ts and src/types.ts were skimmed, not read line by line. Test, plan and spec documents were not reviewed. Type-level or schema-builder defects specific to v3 may be missed.
- The wasm-inline `Encryption` factory is still typed to v2 tables and never passes eqlVersion. v3 tables forced through it would get v2 wire format. Not raised as a scenario because the types prevent this without a cast. The interaction between v3 and wasm-inline is not assessed.
- The protect-ffi 0.27 release contents could not be inspected (no network, no installed package). FS-4 stays speculative.

_Inputs unavailable: pr_description, ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
