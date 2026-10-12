## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `970e759801..49325032a8`

Bumps the exact @cipherstash/protect-ffi pin 0.30.0 -> 0.31.0 for @cipherstash/stack (runtime dependency) and two adapters (devDependency) and adapts to its breaking changes: ProtectError class replaced by an isProtectErrorCode value check (native getErrorCode and DynamoDB handleError), WASM newClient options reshaped (authStrategy + clientOpts, no cast_as pre-normalisation), and the undeclared correlation `id` stripped from bulk/model payloads. The upgrade also makes an explicitly supplied clientKey hex-only, a deliberate breaking change carried as a `major` changeset, documented in the shipped stash-auth skill and guarded in CI by a new hex pre-flight. I checked that every native bulk/model call site now strips `id` while keeping positional correlation and lockContext, and that the WASM batch paths already built explicit payloads. The main residual risks are (1) customers with base64 keys failing at construction on upgrade, which is intentional and documented but is a runtime outage for them, and (2) the native entry still passing the OIDC/auth strategy under the old `strategy` key, which 0.31 renamed to `authStrategy`; nothing in CI exercises that path against the real 0.31 binding because the identity suites skip without USER_JWT. Error-code reclassification is intended and unit-tested. All 16 CI checks passed on head.

### Failure scenarios

**FS-1 · Deployments with a base64 clientKey fail every operation after upgrading stack** (high impact, plausible)

- Trigger: A customer upgrades @cipherstash/stack to the new major while CS_CLIENT_KEY or config.clientKey holds the base64 key (e.g. copied from ~/.cipherstash/secretkey.json), which 0.30 accepted.
- Mechanism: protect-ffi 0.31 decodes an explicit clientKey as hex only (changeset and CI-action comment); stack pins protect-ffi exactly, so there is no opt-out. The error message is intentionally terse and does not mention base64.
- Consequence: Client construction fails and every encryption/decryption in that deployment fails until the key is re-encoded. Loud, fails closed, no data corruption, but a full outage of encrypted reads/writes for affected services. On wasm-inline there is no profile-store fallback.
- Affects: @cipherstash/stack native entry (Encryption client, encryption operations), @cipherstash/stack/wasm-inline, Customer applications supplying clientKey explicitly
- Evidence: `.changeset/olive-pugs-invite.md:1-44`; pr_description; `.github/actions/require-cs-secrets/action.yml:44-57`; `packages/cli/src/commands/env/index.ts:425`
- Existing verification: require-cs-secrets hex pre-flight passed in every credentialed CI job, proving the repo's own CI key is hex and that the stack works with a hex key under 0.31 [ran_passed]
- Missing verification: No test asserts the base64 rejection or its message on either entry (the behaviour lives in protect-ffi, which was not available to inspect).; No data on how many customers set base64 keys.
- Mitigation: Already mitigated by the major version bump, changeset and stash-auth skill text. Make the 2.0.0 release notes lead with this item, and consider a stack-side pre-check that recognises a base64-shaped key and names the encoding in the error (without echoing key material).

**FS-2 · Native entry passes authStrategy under the pre-0.31 `strategy` key** (high impact, plausible)

- Trigger: A native-entry customer supplies config.authStrategy (e.g. OidcFederationStrategy for identity-bound lock context) and protect-ffi 0.31's native NewClientOptions does not honour `strategy`, or rejects it as an unknown key.
- Mechanism: This change renames the field to `authStrategy` for the WASM newClient (wasm-inline.ts:1554) because 0.31 renamed it and "both entries now deserialize the same NewClientOptions", but encryption/index.ts:143 still sends `strategy: config.authStrategy`. The only evidence that `strategy` still works is a test comment calling it a deprecated alias on the WASM side. Stack src is not typechecked in CI, so a removed field would not be caught at compile time either.
- Consequence: If the alias is rejected: every OIDC/identity-bound native client fails at construction. If it is silently ignored: the client falls back to CS_* credential auth, so operations run as the service rather than the end user, and identity-bound lock-context calls fail or lose their per-user authorisation.
- Affects: @cipherstash/stack native entry (Encryption client, encryption operations), Customers using config.authStrategy (OidcFederationStrategy / identity-bound lock context) on the native entry
- Evidence: `packages/stack/src/encryption/index.ts:134-145`; `packages/stack/src/wasm-inline.ts:1553-1562`; `packages/stack/__tests__/init-strategy.test.ts:22-57`; `packages/stack/__tests__/lock-context.test.ts:48-52`; `packages/stack/__tests__/wasm-inline-new-client.test.ts:133-136`
- Existing verification: init-strategy.test.ts asserts opts.strategy is forwarded, but against a mocked protect-ffi, so it cannot detect a 0.31 deserialisation change [exists_not_run]; Live lock-context / OIDC suites exist but skip without USER_JWT, which tests.yml does not provide [exists_not_run]
- Missing verification: A run of the native entry with config.authStrategy against the real 0.31 binding (live OIDC test with USER_JWT, or an offline test that constructs a client and asserts getToken() is invoked).; Confirmation from protect-ffi 0.31's NewClientOptions that `strategy` remains an accepted alias on the Neon entry.
- Mitigation: Pass `authStrategy: config.authStrategy` on the native newClient call, matching the WASM entry, and update init-strategy.test.ts. Or confirm the alias against the 0.31 source and record that in a comment.

**FS-3 · Callers branching on error.code see different values** (medium impact, plausible)

- Trigger: Application code branches on EncryptionError.code / EncryptedDynamoDBError.code, e.g. retrying on ECONNRESET from DynamoDB, or matching an FFI code that 0.31's isProtectErrorCode set does not include.
- Mechanism: handleError now replaces any code not accepted by isProtectErrorCode with DYNAMODB_ENCRYPTION_ERROR (dynamodb/helpers.ts:55-58). getErrorCode returns undefined for unrecognised codes (error-code.ts:20-21).
- Consequence: Retry or transport-error handling keyed on Node/AWS codes silently stops matching for DynamoDB operations. Any FFI code missing from the guard's set is flattened. Behavioural, recoverable, no data effect.
- Affects: @cipherstash/stack native entry (Encryption client, encryption operations), @cipherstash/stack/dynamodb (handleError)
- Evidence: `packages/stack/src/dynamodb/helpers.ts:54-58`; `packages/stack/src/encryption/helpers/error-code.ts:19-22`; `packages/stack/__tests__/dynamodb/resolve-decrypt.test.ts:384-486`; `.changeset/olive-pugs-invite.md:1-44`
- Existing verification: New unit tests for handleError and getErrorCode (foreign codes, a real FFI code, round trip through throwPreservingCode); part of the Run Tests jobs, which passed [ran_passed]
- Missing verification: No check that every code the 0.31 binding actually throws is accepted by isProtectErrorCode (only UNKNOWN_COLUMN and INVALID_JSON_PATH are asserted).
- Mitigation: Documented in the major changeset. Reviewers should confirm the code list stack exposes in its types matches 0.31's PROTECT_ERROR_CODES.

### Recommended controls

- Review encryption/index.ts:134-145: decide whether the native newClient should send `authStrategy` like the WASM entry. Confirm against protect-ffi 0.31's NewClientOptions. (review_focus; FS-2)
- Add a USER_JWT secret to the tests.yml run-tests job (or an offline real-binding test) so an identity-bound native round trip runs on every PR touching the protect-ffi pin. (test; FS-2, VG-1)
- Lead the 2.0.0 release notes with the hex-only clientKey requirement and the recovery steps per entry point; consider a stack-side pre-check that names the encoding problem without echoing key material. (documentation; FS-1, VG-2)
- Extend the Deno WASM E2E schema with bigint, date/timestamp and boolean columns to cover the removed client-side cast_as normalisation. (test; VG-3)
- Check that the set of codes accepted by isProtectErrorCode in 0.31 covers every code stack documents or callers branch on. (review_focus; FS-3)

### What this assessment could not see

- protect-ffi 0.31.0 itself (source, .d.ts, changelog) was not available; its behaviour (hex-only key, unknown-key rejection, strategy alias, Rust-side cast_as normalisation, PROTECT_ERROR_CODES) is taken from the PR description, changeset and code comments. FS-1 and FS-2 rest on second-hand descriptions of the dependency; FS-2 could be a non-issue if the native alias is confirmed.
- CI results are job-level only; I could not see which tests within Run Tests ran or skipped. ran_passed claims are attributed to the job, and I inferred that the stack __tests__ suite (including live bulk/model tests) ran in it.
- No deployment context: unknown how many customers use base64 keys or native authStrategy. Cannot judge how often FS-1/FS-2 would occur, only their impact.
- The WASM readErrorCode still passes through any string code (unlike the native fix), but that is unchanged by this PR, so it is not counted as a scenario. Inconsistent error-code semantics between entries remain after release.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
