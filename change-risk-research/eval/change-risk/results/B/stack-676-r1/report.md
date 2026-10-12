## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `bab1307fb2..804fe3b331`

Additive minor-release change: the WASM entry (@cipherstash/stack/wasm-inline) gains WasmEncryptionClient.encryptQuery and encryptQueryBulk. They reuse the native client's index resolver and pre-FFI validation, and call protect-ffi's WASM encryptQuery/encryptQueryBulk. Existing encrypt/decrypt behaviour and the stored payload format do not change. The new runtime imports into the WASM bundle (infer-index-type, validation, errors, types) import protect-ffi only as types, so the edge bundle should not pick up the native binding; the Deno e2e job (no FFI permission) would catch it if it did. The material risks are in the new contract. (1) The declared return type, EncryptedQuery | null, leaves out the bare selector-hash string that the method returns for searchableJson string values. The JSDoc and the e2e test both confirm the string return. (2) JSON containment and selector terms on the WASM path are only checked for shape. They are never matched against stored rows, so a term that silently matches nothing would not be caught. (3) The JSDoc tells consumers query terms are safe to log-scrub less aggressively, although they are deterministic derivatives of the plaintext. CI wiring adds a live WASM family suite to the Drizzle integration job and makes the Deno e2e suites fail rather than skip when secrets are missing. No test results were available.

### Failure scenarios

**FS-1 · encryptQuery's declared return type omits the bare selector string it returns for searchableJson** (medium impact, observed in the code)

- Trigger: A TypeScript consumer calls encryptQuery with queryType 'searchableJson' (or an inferred ste_vec column) and a string JSONPath value.
- Mechanism: encryptQuery and encryptQueryBulk are typed Promise<EncryptedQuery | null> and cast the FFI result 'as EncryptedQuery' (wasm-inline.ts:440-449, 477-504). EncryptedQuery is the union of the v2 and v3 query envelope objects (types.ts:72-74). The JSDoc (wasm-inline.ts:416-419) and the e2e test (query-types.test.ts:150-167, which needs 'as unknown as string') show that a selector query returns a bare string. The native surface types the same result as EncryptedQueryResult, which includes string (types.ts:333).
- Consequence: The published .d.ts mis-describes the runtime value. Consumer code that type-narrows on the envelope (term.v, term.sv) or serialises it as a jsonb object type-checks but misbehaves at runtime. Correcting the type later, by widening the union, is a type-level break for consumers who compiled against the narrower one.
- Affects: packages/stack/src/wasm-inline.ts (@cipherstash/stack/wasm-inline public API), Published npm artefact dist/wasm-inline.js / .d.ts, Edge/Deno consumers writing raw SQL against EQL v3 query domains
- Evidence: `packages/stack/src/wasm-inline.ts:440-450`; `packages/stack/src/types.ts:72-74`; `e2e/wasm/query-types.test.ts:82-175`; `packages/stack/src/wasm-inline.ts:368-438`
- Existing verification: e2e/wasm/query-types.test.ts asserts typeof selector === 'string' at runtime but has to cast around the declared type; it runs with --no-check, so the type is not exercised. [exists_not_run]
- Missing verification: A type-level test (expectTypeOf / tsd) pinning the return type of encryptQuery for searchableJson selectors.
- Mitigation: Type the return as EncryptedQueryResult (or EncryptedQuery | string | null), or add overloads keyed on queryType, before the minor release fixes the public type.

**FS-2 · WASM searchable-JSON terms are never matched against stored rows, so a silent no-match would ship** (medium impact, plausible)

- Trigger: A WASM-minted ste_vec containment needle or selector hash differs from what the installed EQL v3 SQL functions expect, for example a serialisation difference across the wasm-bindgen boundary.
- Mechanism: The WASM integration adapter covers only scalar ops (eq/ne/in/range/matches/order, adapter.ts:38-53). The json family is deferred from the op-matrix and covered only by native suites (families.ts:50-56). For JSON, the WASM path is checked only for shape: {sv:[...]} with no c or v, or a non-empty string (query-types.test.ts:82-94, 150-175). Nothing asserts that the term finds the expected row in Postgres.
- Consequence: Edge consumers' encrypted JSON queries return no rows, or the wrong rows, with no error: a silent false negative in application search or filtering logic. Stored data is unaffected.
- Affects: packages/stack/src/wasm-inline.ts (@cipherstash/stack/wasm-inline public API), Edge/Deno consumers writing raw SQL against EQL v3 query domains
- Evidence: `packages/stack/integration/wasm/adapter.ts:38-53`; `packages/test-kit/src/families.ts:50-56`; `e2e/wasm/query-types.test.ts:82-175`
- Existing verification: Deno query-types suite checks containment and selector wire shapes against live ZeroKMS. [exists_not_run]; WASM family integration suite matches real rows for scalar families (eq, range, match, order, in/notIn via bulk). [exists_not_run]
- Missing verification: A live WASM test that inserts a JSON row and finds it with @> on a WASM containment needle and with -> on a WASM selector.
- Mitigation: Add a WASM JSON containment and selector row-matching test, for example by extending the wasm adapter or porting the json-contains suite, or document JSON querying on the edge as unverified.

**FS-3 · Shipped JSDoc invites logging query terms that are deterministic plaintext derivatives** (low impact, plausible)

- Trigger: A consumer follows the encryptQuery JSDoc and logs query terms, or scrubs them less than storage payloads.
- Mechanism: wasm-inline.ts:371-374 says terms are 'safe to log-scrub less aggressively than storage payloads (though it still derives from the plaintext)'. Equality (HMAC) and ORE/OPE terms are deterministic for a given key and value, so logged terms let anyone with log access link equal values and recover order.
- Consequence: Equality and order information about sensitive values leaks into application logs on edge platforms. No plaintext is disclosed directly.
- Affects: Published npm artefact dist/wasm-inline.js / .d.ts, Edge/Deno consumers writing raw SQL against EQL v3 query domains
- Evidence: `packages/stack/src/wasm-inline.ts:368-438`
- Missing verification: Review of the guidance by whoever owns the security documentation.
- Mitigation: Reword the JSDoc to say query terms should be treated as sensitive (they reveal equality and order) and not logged.

### Recommended controls

- Reviewer to check the encryptQuery/encryptQueryBulk return type against the native EncryptedQueryResult and the string selector result, and fix it before release. (review_focus; FS-1, VG-1)
- Add a live WASM JSON test (insert, then @> containment and -> selector) against EQL v3 Postgres. (test; FS-2, VG-2)
- Replace the 'log-scrub less aggressively' wording with guidance that query terms reveal equality and order and must not be logged. (documentation; FS-3)
- Before release, confirm the Deno WASM e2e job and the Drizzle integration job (both db variants) ran green on this head, including the new wasm family suite. (other; VG-3)

### What this assessment could not see

- Could not inspect protect-ffi 0.29.0 (not installed), so it is not verified that its wasm-inline build exports encryptQuery/encryptQueryBulk with the {queries} batch field, or how it serialises results (plain objects vs Map). A missing export or a shape mismatch would surface only in the live tests, whose results were not seen.
- WASM encryptQuery passes no lockContext. Identity binding on the edge comes from the auth strategy (OidcFederationStrategy), which matches the existing WASM encrypt. Whether index terms depend on the lock context for identity-bound columns was not established. If they do, identity-bound queries minted on the edge could fail to match rows written with a lock context. Not assessed.
- encryptQueryBulk writes the FFI results back by position and leaves a slot null if the FFI returns fewer results than were requested. This was not treated as a scenario because no mechanism for a short result was found. Relies on protect-ffi returning one result per query, which was not verified.
- The integration WASM suite runs src/wasm-inline.ts through vitest aliases, not the built dist bundle. Only the Deno e2e job exercises dist/wasm-inline.js. Bundle safety of the new imports was judged by reading their import statements. A tsup bundling regression would be caught only by the Deno job.
- Co-change signals show integration-supabase.yml and examples/supabase-worker usually change with these files; they are not in this change. The Supabase workflow triggers on packages/stack/integration/** but was not checked to see whether it runs the stack wasm suite. Possible gaps in path triggers or example drift were not assessed.
- AGENTS.md asks that public API changes to packages/stack be checked against the shipped skills/stash-encryption. The shipped skills/*/SKILL.md files do not mention WASM at all, so none of them contradicts the new surface, but edge users get no skill guidance on encryptQuery. Skill drift was ruled out; the missing documentation was not treated as a risk scenario.

_Inputs unavailable: ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
