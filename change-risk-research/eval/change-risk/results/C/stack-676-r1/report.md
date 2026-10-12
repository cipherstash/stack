## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `bab1307fb2..804fe3b331`

Additive feature: @cipherstash/stack/wasm-inline's WasmEncryptionClient gains encryptQuery and encryptQueryBulk, minting EQL v3 query terms on Deno/edge. Both reuse the native client's shared index resolver and pre-FFI validators (contrary to the PR description, which says a local port was written), so inference and validation cannot drift from the native path. Existing encrypt/decrypt behaviour is unchanged. Scalar query types are verified end to end: CI ran the shared v3 family matrix through the WASM entry against real ZeroKMS and real Postgres/Supabase (Drizzle v3 integration jobs, both passed), and the Deno smoke suite against the built dist passed. The main residual risks are contract-level on a newly published, effectively irreversible API surface: the declared return type (EncryptedQuery | null) does not admit the bare selector string the searchableJson selector path returns, JSON containment/selector terms are only shape-checked, never matched against a database, and the docblock advises that query terms are safe to log-scrub less aggressively. Impact if these bite is medium; no plaintext or key-handling path is changed.

### Failure scenarios

**FS-1 · Declared return type omits the bare selector string returned for searchableJson selectors** (medium impact, observed in the code)

- Trigger: A TypeScript consumer calls encryptQuery('$.path', { queryType: 'searchableJson' }) (or a bulk term with a string value on an ste_vec column) and handles the result as the declared EncryptedQuery object.
- Mechanism: encryptQuery is typed Promise<EncryptedQuery | null> (wasm-inline.ts:443) and EncryptedQuery is only the two envelope object types (types.ts:72-74), but the docblock (wasm-inline.ts:416-421) and the e2e test (query-types.test.ts:159-165, which needs `as unknown as string`) confirm the selector path returns a plain string. The native client types the same result as EncryptedQueryResult, which includes string (types.ts:333).
- Consequence: Type-guided code (e.g. reading term.v, or JSON-serialising it before binding as jsonb, giving a quoted string) compiles but builds a wrong selector argument; JSON path queries return no or wrong rows silently. Fixing the type later narrows/widens a published signature.
- Affects: packages/stack/src/wasm-inline.ts (@cipherstash/stack/wasm-inline), Published dist/wasm-inline.js / wasm-inline.d.ts in the @cipherstash/stack npm package, Edge/Deno consumers writing raw SQL with WASM-minted terms
- Evidence: `packages/stack/src/types.ts:72-74`; `packages/stack/src/wasm-inline.ts:408-422`; `e2e/wasm/query-types.test.ts:153-166`
- Existing verification: Deno e2e query-types asserts the selector is a non-empty string at runtime (shape only, via a type-erasing cast). [ran_passed]
- Missing verification: A type-level test (test:types) pinning encryptQuery's return type for searchableJson string values; A live SQL test binding the selector to -> / ->> against an eql_v3_json column
- Mitigation: Widen the return types to EncryptedQuery | string | null (mirroring EncryptedQueryResult) before release, or add overloads keyed on queryType/value type.

**FS-2 · JSON containment/selector terms never matched against a real EQL database** (medium impact, plausible)

- Trigger: An edge consumer uses the documented searchableJson recipes (prefs @> term::jsonb::eql_v3.query_jsonb, prefs -> selector).
- Mechanism: The WASM integration adapter's SUPPORTED_OPS (adapter.ts:39-54) covers only scalar ops; the e2e query-types suite only checks term shape (v3, no ciphertext). Nothing executes the JSON SQL shapes from the docblock against Postgres, unlike every scalar query type.
- Consequence: If the WASM-minted ste_vec needle or selector, or the documented cast/operator, does not match what the installed EQL v3 SQL expects, JSON queries silently return no rows (or error) on the edge.
- Affects: packages/stack/src/wasm-inline.ts (@cipherstash/stack/wasm-inline), Edge/Deno consumers writing raw SQL with WASM-minted terms
- Evidence: `packages/stack/integration/wasm/adapter.ts:39-54`; `e2e/wasm/query-types.test.ts:153-166`; `packages/stack/src/wasm-inline.ts:408-422`
- Existing verification: Unit test infers ste_vec queryOp from plaintext shape with a mocked FFI. [ran_passed]; Deno e2e asserts containment needle and selector shapes from live ZeroKMS. [ran_passed]
- Missing verification: Live row-matching test for searchableJson containment and selector via the WASM entry
- Mitigation: Add JSON ops to the WASM adapter (or a dedicated integration test) before advertising JSON search on the edge; otherwise mark it experimental in the changeset.

**FS-3 · Public guidance invites logging query terms that leak equality/order relationships** (low impact, plausible)

- Trigger: A consumer follows the docblock note that query terms are 'safe to log-scrub less aggressively than storage payloads' and logs them.
- Mechanism: wasm-inline.ts:371-375 states terms are safe to log-scrub less aggressively. Terms carry HMAC, bloom and ORE/OPE material derived from plaintext; logged terms correlated across requests or against stored rows reveal equality and ordering of searched values.
- Consequence: Search-term metadata (who searched for what, and order/equality relationships) leaks into log stores outside the encryption boundary. Not plaintext, and no key is exposed.
- Affects: packages/stack/src/wasm-inline.ts (@cipherstash/stack/wasm-inline), Edge/Deno consumers writing raw SQL with WASM-minted terms
- Evidence: `packages/stack/src/wasm-inline.ts:371-375`
- Missing verification: Security review of the documented logging guidance
- Mitigation: Reword the docblock: treat query terms as sensitive (do not log), consistent with the repo's 'do not log plaintext' rule.

### Recommended controls

- Before publishing, fix the declared return type of encryptQuery/encryptQueryBulk to include string (as EncryptedQueryResult does) and add a test:types assertion. (review_focus; FS-1, VG-1)
- Add a live integration case running the documented @> and -> SQL with WASM-minted searchableJson terms against an eql_v3_json column. (test; FS-2, VG-2)
- Replace the 'safe to log-scrub less aggressively' wording with guidance not to log query terms; correct the PR description, which says a local resolver port was written when the shared resolver is imported. (documentation; FS-3)

### What this assessment could not see

- Lock-context / identity binding: the WASM entry (before and after this change) has no withLockContext, while the native query path forwards lockContext. Whether WASM-minted terms match rows written by a native client under a lock context depends on ZeroKMS/EQL index-key derivation, which could not be checked offline. Mixed native/edge deployments using lock contexts are not assessed; this limitation predates the change, so it is not raised as a scenario.
- Docblock SQL shapes using bare operators (email = term::eql_v3.query_text_eq, @>) were not checked against the EQL v3 SQL bundle; the integration adapter uses eql_v3.eq/contains functions instead. Possible doc inaccuracies for operator forms are unassessed.
- Tests were not run locally; all pass/fail statements rely on ci.json conclusions, which do not list individual test cases. That the wasm family suite actually ran inside the Drizzle v3 jobs is inferred from the workflow glob and the CS_* env present. A skipped or empty wasm suite inside a green job cannot be excluded.
- Test files (unit suite, e2e, adapter) were skimmed for coverage, not read line by line; bundle contents of dist/wasm-inline.js were not inspected (only import chains and the passing Deno job). Minor test-quality issues may be missed.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
