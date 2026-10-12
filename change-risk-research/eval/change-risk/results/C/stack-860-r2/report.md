## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `970e759801..49325032a8`

Bumps the exact pin on @cipherstash/protect-ffi from 0.30.0 to 0.31.0 in @cipherstash/stack (runtime dependency, so it reaches every consumer) and adapts to its breaking changes: the ProtectError class is replaced by a value-based isProtectErrorCode guard, the WASM newClient takes credentials under clientOpts and the strategy under authStrategy, WASM encryptConfig is no longer pre-normalised, and the undeclared correlation `id` is stripped from every bulk payload because 0.31 rejects unknown keys. The most material release risk is intended and loud: an explicitly supplied base64 clientKey now fails at client construction, which the change handles with a major changeset, skill documentation and a CI pre-flight. The item a reviewer should resolve is that the native entry still passes the strategy under the deprecated `strategy` name while the WASM entry was moved to `authStrategy`; if that alias is not honoured by the native binding, a caller's authStrategy would be dropped. All 16 CI checks passed, including credentialed integration and WASM Deno E2E jobs, which supports the bulk-payload and cast_as changes against the real 0.31 binary. I searched every native and WASM FFI call site at head and found no remaining undeclared payload keys.

### Failure scenarios

**FS-1 · Deployments with a base64 clientKey fail at client construction after upgrading** (high impact, plausible)

- Trigger: A customer upgrades @cipherstash/stack with CS_CLIENT_KEY or config.clientKey holding the base64 form (e.g. copied from ~/.cipherstash/secretkey.json).
- Mechanism: stack pins protect-ffi exactly, so the upgrade forces 0.31.0, whose clientKey decoder is reported to be hex-only. The error message deliberately omits detail. On wasm-inline there is no profile-store fallback; clientId/clientKey are required config.
- Consequence: Every encryption and decryption operation in the affected service fails from startup until the key is re-encoded. The failure is loud and recoverable without data loss, but it is a full outage of the encryption path for that service.
- Affects: @cipherstash/stack native entry (Encryption / newClient), @cipherstash/stack/wasm-inline entry, Customer deployments supplying an explicit clientKey
- Evidence: pr_description; `.changeset/olive-pugs-invite.md:1-44`; `skills/stash-auth/SKILL.md:209-228`
- Existing verification: Credentialed CI jobs passed on head, behind the new hex pre-flight, showing a hex key constructs and operates on 0.31.0. [ran_passed]
- Missing verification: No test asserts the base64 rejection or its error message (the behaviour lives in protect-ffi, whose source was unavailable).; Number of customers supplying base64 keys is unknown.
- Mitigation: Already mitigated by a major version bump, changeset upgrade notes and the stash-auth skill. Make sure the release notes put the hex requirement first. Consider a stack-side pre-construction check that names encoding as the likely cause without echoing the key.

**FS-2 · Native entry still passes `strategy`; a supplied authStrategy could be dropped by 0.31** (high impact, plausible)

- Trigger: A caller passes config.authStrategy (e.g. OidcFederationStrategy) to the native Encryption client, and the 0.31 native binding does not honour the deprecated `strategy` name.
- Mechanism: The same change renames strategy to authStrategy on the WASM entry because 0.31 renamed the field. Its own test comments say `strategy` 'still works there as a deprecated alias' and is 'slated for removal'. The native call at encryption/index.ts:143 still sends `strategy: config.authStrategy`. The PR states that both entries now deserialize the same NewClientOptions. If the alias is not honoured now, or is removed in a later protect-ffi bump, the client falls back to the default auto strategy using env credentials.
- Consequence: Without lock context, operations could run under the service's ambient credentials instead of the caller's federated identity. With lock context, operations would fail. This is an identity-binding change on the auth path.
- Affects: @cipherstash/stack native entry (Encryption / newClient)
- Evidence: `packages/stack/src/encryption/index.ts:134-145`; `packages/stack/src/wasm-inline.ts:1523-1563`; `packages/stack/__tests__/wasm-inline-new-client.test.ts:119-138`; `packages/stack/__tests__/init-strategy.test.ts:22-107`
- Existing verification: init-strategy.test.ts asserts that the strategy reaches a MOCKED newClient as opts.strategy. It cannot show that the real 0.31 binding honours the name. [exists_not_run]; matrix-identity.integration.test.ts passes authStrategy to the native client live. The Drizzle integration job that globs it passed, but the suite skips without CLERK_MACHINE_TOKEN, and job-level results cannot show whether it ran. [unknown]
- Missing verification: Confirmation, from 0.31.0's native NewClientOptions declaration or a live run, that `strategy` is honoured on the native binding.; A non-mocked test that a native client built with authStrategy actually calls the strategy's getToken().
- Mitigation: Pass `authStrategy: config.authStrategy` on the native entry as well, matching the WASM change, and update init-strategy.test.ts. Alternatively, confirm the alias against the 0.31.0 typings and Rust deserializer before release.

**FS-3 · WASM encryptConfig no longer pre-normalised; a cast mapped differently by 0.31 would change column semantics** (medium impact, speculative)

- Trigger: A WASM-entry schema uses an SDK cast_as variant that 0.31's Rust-side normalisation maps differently from stack's toEqlCastAs, or does not accept.
- Mechanism: normalizeCastAs was removed from the newClient path (it is kept only as deprecated). The SDK spelling now reaches protect-ffi, which is reported to normalise on both bindings. The native entry already relied on FFI normalisation before this change, so the WASM entry now converges on native behaviour.
- Consequence: The likely failure is loud: client construction fails for that column type. If the mapping differed silently, values could be encrypted with a different plaintext cast than native clients use for the same column. Query terms could then fail to match or values could decode as the wrong type across entries.
- Affects: @cipherstash/stack/wasm-inline entry
- Evidence: `packages/stack/src/wasm-inline.ts:1523-1563`; `packages/stack/__tests__/wasm-inline-new-client.test.ts:98-117`
- Existing verification: Run WASM E2E Tests (Deno) passed on head against the real 0.31 WASM build. [ran_passed]; wasm-inline-new-client / wasm-inline-v3 tests assert the 'string' spelling is forwarded (mocked FFI). [exists_not_run]
- Missing verification: No test runs every CastAs variant through the real 0.31 WASM newClient and compares the result with native output.
- Mitigation: Add a cross-entry round-trip test over all cast_as variants: encrypt on WASM, decrypt on native and the reverse.

**FS-4 · Callers branching on DynamoDB error.code stop matching transport errors** (medium impact, plausible)

- Trigger: A consumer's retry or alerting logic keys off EncryptedDynamoDBError.code values such as ECONNRESET.
- Mechanism: handleError now returns the code only if isProtectErrorCode accepts it; otherwise DYNAMODB_ENCRYPTION_ERROR.
- Consequence: Retries on transient network faults stop firing, or errors are categorised differently in monitoring. The change is intentional, documented in the changeset and reversible by the caller.
- Affects: Error code surface (getErrorCode, DynamoDB handleError, EncryptedDynamoDBError.code)
- Evidence: `packages/stack/src/dynamodb/helpers.ts:55-58`; `.changeset/olive-pugs-invite.md:1-44`
- Existing verification: New handleError tests in resolve-decrypt.test.ts and getErrorCode tests in error-helpers.test.ts cover the foreign-code, valid-code and no-code paths (credential-free). Node 22/24/Bun test jobs passed. [ran_passed]
- Mitigation: Already documented in the major changeset. Optionally preserve the original error as `cause` so callers can still inspect transport codes.

### Recommended controls

- Change the native newClient call in packages/stack/src/encryption/index.ts to pass `authStrategy`, matching the WASM entry, and update init-strategy.test.ts. Alternatively, confirm from the 0.31.0 declarations that `strategy` is honoured on native. (review_focus; FS-2, VG-1)
- Make sure the identity integration suite runs rather than skips in CI, for example by failing when CLERK_MACHINE_TOKEN is absent on trusted runs. That gives live coverage of authStrategy on the native entry. (test; FS-2, VG-1)
- Lead the 2.0.0 release notes with the hex-only clientKey requirement and the wasm-inline recovery path. Consider a stack-side construction check that points at encoding. (documentation; FS-1, VG-2)
- Add a WASM-to-native round-trip test across all cast_as variants under 0.31.0. (compatibility_check; FS-3, VG-3)

### What this assessment could not see

- protect-ffi 0.31.0's source, typings and release notes were not available (no node_modules, no network). All claims about its behaviour (hex-only clientKey, strict unknown-key rejection, the `strategy` alias, Rust-side cast normalisation) come from the PR description, changeset and code comments in the diff. BC-2 and the triggers of FS-1 to FS-3 rest on the author's account of the dependency; they could not be independently confirmed.
- CI results give only job-level conclusions. Suites that gate themselves on secrets, such as the Clerk identity suite and the live error-codes suite, may have skipped inside a passing job. ran_passed is claimed only at job level; per-suite execution is unknown.
- The unknown-key concern was checked by reading every native FFI call site in packages/stack/src at head (encrypt, decrypt, encrypt-query batch, bulk-encrypt, bulk-decrypt, model-helpers) and the WASM bulk/model call sites. Only `id` was undeclared, and it is now stripped. Other packages (stack-prisma, cli, wizard) were not searched for direct protect-ffi calls. A direct protect-ffi caller outside packages/stack with extra keys would be missed; none were found among the drizzle/supabase src imports, which are type-only.
- The changeset config (fixed groups) and pnpm-lock.yaml were not read in detail. The claim that the fixed group bumps sibling packages to 2.0.0 is taken from the changeset text.

_Inputs unavailable: architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
