## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** high · `e4a814b026..6ad6c76e7d`

Mostly a type-level refactor of the @cipherstash/stack encryption client: twelve `as never` forwarding casts are removed, the native client's `encryptQuery` takes a tuple-union argument list, and the encrypt operations accept the v3 Json document type. The one intentional public-contract change is that `EncryptionClient.encrypt` on a `types.Json` column now types `data` as `Encrypted | null`, which matches the existing runtime behaviour (a null document already resolved to `{ data: null }`). It ships as a minor bump. The runtime changes are small. `NativeEncryptionClient.encryptQuery` now branches on `args[1]` instead of `opts`, which is equivalent. The stack-supabase per-term fallback now throws on a null envelope instead of sending the string "null". That path runs only when a client has no `bulkEncrypt`, and null operands are filtered out before encryption. Head CI is green, including the stack/supabase/drizzle type tests, the Node and Bun unit tests and the Drizzle v3 integration jobs, which run the new live json-crypto null-element round trips. The residual risk is compile-time breakage for downstream TypeScript consumers, which is loud and documented.

### Failure scenarios

**FS-1 · Minor release breaks downstream TypeScript builds that dereference Json encrypt results** (low impact, plausible)

- Trigger: A consumer upgrades @cipherstash/stack across the minor version and has code like `const r = await client.encrypt(doc, { table, column: t.jsonCol }); r.data.c` where `doc` is typed `JsonDocument`, or names `ReturnType<EncryptionClient['encrypt']>`.
- Mechanism: `encrypt` now returns `EncryptOperation<EncryptResult<P>>` with `EncryptResult<P> = Encrypted | (null & P)`; `JsonDocument` admits null, so `data` becomes `Encrypted | null` and strict-null code fails with TS18047. The default `P` keeps explicit `<Table, Col>` calls compiling but types them `Encrypted | null` for Json columns.
- Consequence: Compile errors in consumer builds after a minor bump (loud, caught before deploy). Runtime behaviour is unchanged, and the code these errors flag already threw at runtime when the document was null.
- Affects: @cipherstash/stack encryption client (encryption/client-v3.ts, encryption/index.ts, operations/*), Downstream TypeScript applications using `encrypt` on `types.Json` columns
- Evidence: `languages/typescript/packages/stack/src/encryption/operations/encrypt.ts:41`; `languages/typescript/packages/stack/src/encryption/client-v3.ts:189-197`; `languages/typescript/packages/stack/src/encryption/client-v3.ts:161` (base); pr_description
- Existing verification: Type tests pinning encrypt's result type (literal null, JsonDocument, non-null, scalar, lock context, audit, explicit type args) run in the stack `test:types` step of Run Tests (Node 22/24), which passed on head. [ran_passed]
- Missing verification: No check against external consumer code; the semver classification (minor for a type narrowing that can break compilation) is a judgement call.
- Mitigation: Keep the changeset text that tells users to null-check `result.data` for Json columns, and make sure the release notes put it first.

**FS-2 · Supabase per-term fallback now fails queries it previously sent** (low impact, plausible)

- Trigger: A Supabase builder is given an encryption client without `bulkEncrypt` (older or custom client) and some query operand encrypts to a null envelope.
- Mechanism: `encryptGroupPerTerm` throws `EncryptionFailedError` on `result.data === null` (query-encrypt.ts:417-421). Null and `is` operands are skipped before encryption (query-terms.ts:180), so this fires only on a contract violation by the client.
- Consequence: A query that previously sent the string "null" as the filter operand, and so silently matched the wrong rows, now returns an error. This moves from silent wrong results to a loud failure.
- Affects: @cipherstash/stack-supabase query encryption (query-encrypt.ts)
- Evidence: `languages/typescript/packages/stack-supabase/src/query-encrypt.ts:417-421`; `languages/typescript/packages/stack-supabase/__tests__/supabase-v3-builder.test.ts:1917-1939`; `languages/typescript/packages/stack-supabase/src/query-terms.ts:180`
- Existing verification: New unit test 'rejects a null envelope on the per-term fallback rather than sending "null"' in supabase-v3-builder.test.ts. Unit test jobs passed on head, but the logs are not available to confirm that this file ran in them. [exists_not_run]
- Mitigation: None needed beyond the changeset note; behaviour now matches the bulk path.

### Recommended controls

- Lead the @cipherstash/stack minor release notes with the `encrypt` Json-column result type change and the required null check. (documentation; FS-1)
- Reviewer to confirm the two model-encrypt assertions in client-v3.ts (lines 642, 652) are the only remaining unchecked narrowings, and that `NativeEncryptionClient.encryptQuery` branching on `args[1]` is equivalent to the base `opts` check. (review_focus; FS-1)

### What this assessment could not see

- Test-file diffs (typed-client-v3.test-d.ts, +251 lines) were skimmed, not read line by line; source diffs were read in full. Confidence in which exact type cases are pinned rests partly on the PR description.
- No access to downstream consumer code or published-package type tests outside the repo. The breadth of FS-1 cannot be estimated.
- Pre-existing: `toJsPlaintext` asserts JsonDocument/Date to protect-ffi's `JsPlaintext` without runtime checking, as the base casts did. Not introduced by this change; live tests cover null array elements. Values the FFI rejects still fail at runtime rather than compile time; unchanged risk.

_Inputs unavailable: architecture_docs, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
