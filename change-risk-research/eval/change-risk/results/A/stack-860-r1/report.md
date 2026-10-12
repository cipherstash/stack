## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `970e759801..49325032a8`

Bumps the exact @cipherstash/protect-ffi pin from 0.30.0 to 0.31.0 (a breaking upstream release) in @cipherstash/stack and adapts stack to it: error-code detection moves from `instanceof ProtectError` to a value check (`isProtectErrorCode`), which also changes DynamoDB `handleError` to stop passing foreign codes through; the wasm-inline `newClient` call moves credentials into `clientOpts`, renames `strategy` to `authStrategy` and stops pre-normalising `cast_as`; bulk/model payloads stop forwarding the correlation `id` across the FFI. A CI step now fails fast on a non-hex CS_CLIENT_KEY and a major changeset documents that an explicit clientKey must now be hex. I checked every native and wasm FFI call site at head and none still forwards an `id` or other undeclared key. The main residual risks sit in the dependency boundary, which could not be inspected: the native `newClient` call still passes the auth strategy under the old top-level `strategy` name (only a mocked test covers it), customers with base64 client keys will fail at construction on upgrade (loud, documented, major bump), and the wasm entry now relies on the FFI's own cast_as normalisation. No CI results were supplied and no tests could be run, so the verdict is advisory pending the credentialed suites.

### Failure scenarios

**FS-1 · Native client auth strategy passed under pre-0.31 `strategy` key** (high impact, plausible)

- Trigger: A customer constructs the native Encryption client with config.authStrategy (e.g. an OidcFederationStrategy for user-scoped access) on 0.31.0.
- Mechanism: The wasm call was moved to `authStrategy` because 0.31 renamed the field (E-5), but the native call at encryption/index.ts still passes `strategy: config.authStrategy` at the top level (E-2). The only test is mocked and asserts `opts.strategy` (E-3), so it cannot show what the real 0.31 Neon entry does with it. A test comment says `strategy` survives as a deprecated alias on the wasm side (E-4); that is an unverified author claim, and the native side is not covered by it.
- Consequence: If 0.31 ignores the old key, the client silently falls back to the default `auto` strategy and authenticates with ambient credentials instead of the end-user's federated identity, so operations stop being bound to that identity. If 0.31 rejects it, every native client using authStrategy fails at construction.
- Affects: @cipherstash/stack native entry (Encryption client init and operations)
- Evidence: `packages/stack/src/encryption/index.ts:134-145`; `packages/stack/__tests__/init-strategy.test.ts:47-115`; `packages/stack/__tests__/wasm-inline-new-client.test.ts:133-137` (inferred); `packages/stack/src/wasm-inline.ts:1553-1561`
- Existing verification: init-strategy.test.ts asserts the strategy reaches newClient as opts.strategy, against a mocked protect-ffi. [exists_not_run]; TypeScript excess-property checking of the object literal against 0.31's newClient type would reject `strategy` if 0.31 dropped it from the type; no typecheck result was seen. [unknown]
- Missing verification: A typecheck/build of packages/stack against the installed 0.31.0 declarations.; A credentialed test that builds a native client with authStrategy on 0.31.0 and confirms that strategy is the one used (not the auto fallback).
- Mitigation: Confirm the 0.31 native NewClientOptions field name. If it is `authStrategy`, pass it under that name on the native path too, as the wasm path does, and update init-strategy.test.ts.

**FS-2 · Customers with base64 clientKey fail at construction after upgrade** (high impact, plausible)

- Trigger: A customer upgrades @cipherstash/stack while config.clientKey / CS_CLIENT_KEY holds the base64 spelling (e.g. copied from ~/.cipherstash/secretkey.json).
- Mechanism: The exact pin forces protect-ffi 0.31.0 (E-1), which per the changeset decodes an explicit clientKey as hex only (E-9). On wasm-inline the clientKey is required config and there is no profile-store fallback (E-12).
- Consequence: Every encryption operation in that deployment fails at client construction with a deliberately terse message. The failure is loud and recoverable by re-encoding the key, but it is a full outage of encryption for that app until fixed.
- Affects: @cipherstash/stack native entry (Encryption client init and operations), @cipherstash/stack/wasm-inline entry, Customer applications supplying clientKey explicitly
- Evidence: `packages/stack/package.json:219`; `.changeset/olive-pugs-invite.md:1-44`; `packages/cli/src/commands/env/index.ts:425`; `skills/stash-auth/SKILL.md:209-227`
- Existing verification: require-cs-secrets now rejects a non-hex CS_CLIENT_KEY in this repo's CI (guards this repo's pipelines only, not customers). [exists_not_run]
- Missing verification: No in-repo test of the hex-only rejection on the native or wasm entry (the behaviour lives in protect-ffi and was not inspectable).
- Mitigation: Already mitigated by the major version bump, the changeset upgrade note, the stash-auth skill guidance and `stash env` emitting hex. Release notes should lead with this. Optionally, have stack detect a base64-looking key and return a ClientInitError naming the encoding, without echoing the key.

**FS-3 · wasm encryptConfig now relies on FFI cast_as normalisation** (high impact, speculative)

- Trigger: A wasm-inline client encrypts or queries a column whose SDK cast_as the 0.31 Rust normaliser maps differently from stack's toEqlCastAs (e.g. 'number' -> 'double', 'json' -> 'jsonb').
- Mechanism: Base ran normalizeCastAs(encryptConfig) before newClient (E-6), so wasm used stack's mapping (E-7). Head forwards the SDK spelling unnormalised (E-5, E-8) and depends on 0.31's Rust-side mapping, which could not be inspected.
- Consequence: If a mapping diverged, wasm-written ciphertexts or query terms for that type would be encoded under a different cast than existing data and native-written terms. Range/equality queries could then silently miss rows, or decryption could return a differently typed plaintext.
- Affects: @cipherstash/stack/wasm-inline entry
- Evidence: `packages/stack/src/wasm-inline.ts:1553-1561`; `packages/stack/src/wasm-inline.ts:1530-1536` (base); `packages/stack/src/schema/internal.ts:73-92`; `packages/stack/__tests__/wasm-inline-new-client.test.ts:116`
- Existing verification: wasm-inline-new-client.test.ts / wasm-inline-v3.test.ts assert cast_as 'string' is forwarded unchanged, against a mocked binding. [exists_not_run]; The native entry already passed un-normalised config to the FFI at base, so the FFI mapping is already in production use for native clients. [unknown]
- Missing verification: A wasm round-trip/cross-binding test per cast_as variant on 0.31 (wasm encrypt -> native decrypt/query and the reverse).
- Mitigation: Run the credentialed wasm integration suites (v2-decrypt-compat, v3 matrix) on 0.31 before release, or add a unit test that pins the FFI's canonical cast for each SDK variant to toEqlCastAs.

**FS-4 · DynamoDB callers branching on error.code see a different code** (medium impact, plausible)

- Trigger: An application using the DynamoDB helpers branches on EncryptedDynamoDBError.code for an error whose code is not in protect-ffi's set.
- Mechanism: handleError now keeps a code only if isProtectErrorCode accepts it, otherwise it returns DYNAMODB_ENCRYPTION_ERROR (E-13). Before, any string code passed through.
- Consequence: Retry-vs-fail logic keyed on transport codes such as ECONNRESET stops matching, so the caller may stop retrying transient errors. The impact is limited to error routing and recoverable.
- Affects: @cipherstash/stack DynamoDB helpers
- Evidence: `packages/stack/src/dynamodb/helpers.ts:54-58`; `packages/stack/__tests__/dynamodb/resolve-decrypt.test.ts:384-470`; `.changeset/olive-pugs-invite.md:1-44`
- Existing verification: resolve-decrypt.test.ts adds credential-free handleError tests covering FFI codes, foreign codes and the throwPreservingCode round trip. [exists_not_run]
- Mitigation: This is intentional and documented in the major changeset; make sure it appears in the release notes.

### Recommended controls

- Reviewer to confirm the 0.31.0 native newClient option name for the auth strategy and reconcile encryption/index.ts:134-145 with the wasm call. (review_focus; FS-1, VG-2)
- Run typecheck plus the credentialed native and wasm integration suites on 0.31.0, including an authStrategy/OIDC native client and per-cast_as wasm<->native round trips, and attach the results. (test; FS-1, FS-3, VG-1)
- Lead the 2.0.0 release notes with the hex-only clientKey change and the DynamoDB error-code change. (documentation; FS-2, FS-4)
- Publishing is irreversible. Customers can stay on the previous major. Plan a fast follow-up release if the native strategy or wasm cast mapping proves wrong. (rollback_plan; FS-1, FS-3)

### What this assessment could not see

- The protect-ffi 0.31.0 package was not available (no node_modules, no network), so its types, its JS wrappers and its behaviour (unknown-key rejection, hex-only keys, deprecated aliases, cast_as normalisation) are known only from author comments and the changeset. FS-1 and FS-3 cannot be confirmed or ruled out. Upstream claims are treated as claims.
- No CI results, and no tests or typecheck were run. All existing verification is exists_not_run, which caps verification confidence at low for the boundary scenarios.
- Test-file changes were read for the new and changed assertions. The 137-line resolve-decrypt.test.ts addition was skimmed, not traced line by line. Minor. It only affects FS-4, which is medium impact.
- Whether unverifiedContext, lockContext and the batch query payload fields are all declared in 0.31's types could not be checked. They are unchanged by this diff. If 0.31 also rejects one of them, the failure would be loud at runtime. That is not assessed here.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
