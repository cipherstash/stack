## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `bab1307fb2..804fe3b331`

Adds encryptQuery / encryptQueryBulk to WasmEncryptionClient in the published @cipherstash/stack/wasm-inline entry (minor changeset). The new methods reuse the native client's resolveIndexType and pre-FFI validators and call two new named imports from @cipherstash/protect-ffi/wasm-inline (pinned 0.29.0, unchanged). The change is additive: existing encrypt/decrypt code paths are untouched, and it does not change storage payloads or SQL. The main release risks are: (1) the new static named imports. If the pinned WASM build did not export them, the whole edge entry would fail to load, including existing encrypt/decrypt. Live Deno e2e tests would catch this, but no CI result was supplied. (2) The declared return type `EncryptedQuery | null` omits the bare string that JSON selector queries return. (3) JSON containment and selector terms are only shape-checked, never row-matched against Postgres. The scalar query types get live row-matching coverage from a new WASM integration suite wired into the Drizzle integration workflow. No test results were seen and none could be run offline (no node_modules, no credentials).

### Failure scenarios

**FS-1 · Missing WASM export breaks the whole wasm-inline entry, including existing encrypt/decrypt** (high impact, plausible)

- Trigger: The resolved @cipherstash/protect-ffi/wasm-inline build does not export encryptQuery or encryptQueryBulk. This could happen with the pinned 0.29.0 build, or with a consumer import map or override that resolves a different version.
- Mechanism: wasm-inline.ts:78-85 statically imports encryptQuery and encryptQueryBulk alongside the existing encrypt/decrypt imports. In ESM, a missing named export is a link-time SyntaxError for the whole module, not a failure only when the new methods are called. protect-ffi is external to the bundle, so the exports come from whatever the consumer resolves. The dependency version did not change in this diff, and the package contents could not be inspected.
- Consequence: Any edge consumer upgrading @cipherstash/stack fails to import @cipherstash/stack/wasm-inline at all, which breaks existing encrypt/decrypt. The failure is loud. The npm release cannot be reversed, so it would need a new release.
- Affects: @cipherstash/stack/wasm-inline (published ESM entry), @cipherstash/protect-ffi/wasm-inline 0.29.0
- Evidence: `packages/stack/src/wasm-inline.ts:78-85`; `packages/stack/package.json:231`; `packages/stack/tsup.config.ts`; `.github/workflows/tests.yml:292-311`
- Existing verification: Deno e2e (roundtrip.test.ts, query-types.test.ts) imports the built dist/wasm-inline.js with the real protect-ffi WASM entry and calls both new methods against live ZeroKMS [exists_not_run]; WASM integration family suite imports src/wasm-inline.ts with the real protect-ffi WASM module under Node [exists_not_run]
- Missing verification: A seen green run of the wasm-e2e-tests job on the head commit (no CI results supplied); A check that protect-ffi's declared minimum version for the stack package includes the WASM query exports, if the pin is ever relaxed
- Mitigation: Before release, confirm the wasm-e2e-tests job is green on the head commit. Optionally smoke-import the packed tarball under Deno, outside the monorepo import map.

**FS-2 · JSON containment/selector terms never row-matched in SQL; a wire mismatch would silently return no rows** (medium impact, plausible)

- Trigger: An edge consumer uses queryType 'searchableJson' (or inference on a Json column) and binds the term into eql_v3 containment (`@>` with ::eql_v3.query_jsonb) or `->`/`->>` selector SQL
- Mechanism: The WASM integration adapter's SUPPORTED_OPS covers only scalar ops (eq/ne/in/notIn/range/matches/order/null). JSON containment and selector are never executed against Postgres. The Deno query-types test only asserts the shape: `{sv:[...]}` with no `v` or `c` for containment, and a non-empty string for the selector. If the WASM build's ste_vec term did not match what the installed EQL v3 SQL expects (for example, selector hashing that differs from the stored sv entries), the query would succeed and match nothing.
- Consequence: Encrypted JSON searches on the edge silently return empty or incomplete result sets. Callers may treat this as "no match" (for example, authorization lookups or dedup checks). Only adopters of the new API are affected, and stored data is not.
- Affects: @cipherstash/stack/wasm-inline (published ESM entry), Edge consumers (Deno, Workers, Supabase Edge) writing raw SQL with EQL v3 query casts
- Evidence: `packages/stack/integration/wasm/adapter.ts:39-54`; `e2e/wasm/query-types.test.ts:96-235`
- Existing verification: Deno query-types.test.ts asserts the containment and selector wire shapes for single and bulk calls [exists_not_run]; Unit test asserts that the ste_vec queryOp is inferred from the value's shape [exists_not_run]
- Missing verification: A live row-matching test that inserts JSON rows via WASM encrypt and queries them with WASM-minted containment and selector terms; A cross-check that WASM-minted and native-minted ste_vec terms for the same input match the same rows
- Mitigation: Add searchableJson containment and selector ops to the WASM integration adapter, or mark JSON query support on the edge as experimental in the changeset until it is row-matched.

**FS-3 · Declared return type omits the bare-string selector result, so typed consumer code mis-handles it** (medium impact, plausible)

- Trigger: A consumer calls encryptQuery or encryptQueryBulk with a string value on a Json column (searchableJson selector) and handles the result according to its declared type
- Mechanism: encryptQuery is declared to return Promise<EncryptedQuery | null> (wasm-inline.ts:443), and encryptQueryBulk to return Array<EncryptedQuery | null> (wasm-inline.ts:479). EncryptedQuery is CipherStashEncryptedQuery | CipherStashEncryptedV3Query (types.ts:72-74). However, the head's own JSDoc (wasm-inline.ts:418) and Deno test say the selector path returns a bare string, and the test has to cast `as unknown as string`. The native API's result type includes `| string` (types.ts:333); the WASM one does not. The wasm-inline sources are excluded from the package's typecheck, and the Deno test runs with --no-check, so nothing type-tests the published .d.ts.
- Consequence: Consumer code narrows the result with `'v' in term` or `'k' in term`, as types.ts:59 recommends, and gets a runtime TypeError, because the `in` operator throws on a string primitive. Alternatively, it binds the result as `$n::jsonb::eql_v3.query_jsonb` and gets a Postgres error. The failure is loud and confined to new adopters, but it is a published type contract that has to change later.
- Affects: @cipherstash/stack/wasm-inline (published ESM entry), Edge consumers (Deno, Workers, Supabase Edge) writing raw SQL with EQL v3 query casts
- Evidence: `packages/stack/src/wasm-inline.ts:440-504`; `packages/stack/src/wasm-inline.ts:368-439`; `e2e/wasm/query-types.test.ts:96-235`; `packages/stack/vitest.config.ts:31-46`; `packages/stack/src/types.ts:72-74`
- Missing verification: A type test (*.test-d.ts) for the wasm-inline encryptQuery return type; Confirmation, from protect-ffi 0.29.0 types, that CipherStashEncryptedV3Query does not already include string
- Mitigation: Widen the return types to EncryptedQuery | string | null, as the native EncryptedQueryResult does, before the minor release fixes the public signature.

**FS-4 · Shipped guidance encourages laxer logging of deterministic query terms** (low impact, plausible)

- Trigger: Edge consumers follow the encryptQuery JSDoc and log query terms more freely than storage payloads
- Mechanism: wasm-inline.ts:371-374 says terms are "safe to log-scrub less aggressively than storage payloads". Equality (unique/HMAC) and ORE/OPE terms are derived from the plaintext and, for equality, are deterministic per column. Logged terms can therefore be correlated with stored index terms to link log lines to rows or to infer frequencies.
- Consequence: Encrypted-search metadata leaks into application logs or third-party log sinks, which weakens the encryption guarantees customers rely on. This is not plaintext exposure. The cause is the documentation, not code behaviour.
- Affects: @cipherstash/stack/wasm-inline (published ESM entry), Edge consumers (Deno, Workers, Supabase Edge) writing raw SQL with EQL v3 query casts
- Evidence: `packages/stack/src/wasm-inline.ts:368-439`
- Missing verification: Security or docs review of the shipped wording
- Mitigation: Reword the JSDoc to say that query terms should be treated as sensitive: they are ciphertext-free but plaintext-derived and linkable.

### Recommended controls

- Require a green wasm-e2e-tests (Deno) run and a green integration-drizzle run (both db legs) on the head sha before publishing. (test; FS-1, VG-1)
- Add searchableJson containment and selector ops to the WASM integration adapter so JSON terms are row-matched against real EQL v3 SQL. (test; FS-2, VG-2)
- Review the encryptQuery/encryptQueryBulk return types against the selector string result. Add a wasm-inline *.test-d.ts that pins them. (review_focus; FS-3, VG-3)
- Reword the logging guidance in the encryptQuery JSDoc. (documentation; FS-4)
- Smoke-import the packed @cipherstash/stack tarball's wasm-inline entry under Deno with npm-resolved protect-ffi, not the monorepo import map, to confirm the new named exports resolve for real consumers. (compatibility_check; FS-1)

### What this assessment could not see

- No node_modules in the checkout, so the protect-ffi 0.29.0 WASM build's exports, its serde shapes and its TypeScript types could not be read. FS-1 and FS-3 remain plausible rather than confirmed or ruled out.
- No CI results, and no tests were run (they need network, credentials and a database). Verification confidence is capped at medium, and no test is reported as passing.
- The test files (unit, Deno e2e, integration adapter) were read in full. The EQL v3 SQL functions and the test-kit family suite were not read. It is unknown which scalar families or negative ops the family suite actually exercises through the WASM adapter.
- AGENTS.md, CODEOWNERS and the PR description were not available under the CASE.md input rules. Ownership and intended rollout are unknown.

_Inputs unavailable: ci_results, architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
