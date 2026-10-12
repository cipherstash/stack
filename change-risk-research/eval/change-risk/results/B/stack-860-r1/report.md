## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `970e759801..49325032a8`

Bumps the exact pin of @cipherstash/protect-ffi from 0.30.0 to 0.31.0 (a release with breaking changes) and adapts @cipherstash/stack to it: error-code detection moves from `instanceof ProtectError` to a value check (`isProtectErrorCode`), the WASM `newClient` call moves credentials into `clientOpts` and renames `strategy` to `authStrategy`, the WASM entry stops pre-normalising `cast_as`, and the bulk/model paths strip the stack-side correlation `id` that 0.31 now rejects. The most material release consequence is intended and loud: an explicitly supplied base64 `clientKey` / `CS_CLIENT_KEY` now fails at client construction, which the change handles with a major changeset, skill documentation and a CI hex pre-check. The main open question is that the native `newClient` call (unchanged, packages/stack/src/encryption/index.ts) still passes the auth strategy under the old `strategy` key, which commit comments describe as a deprecated alias in 0.31; whether the native entry honours it could not be checked because the 0.31 package is not available here. Unit tests target every adapted seam but mock the FFI, and no test results were seen.

### Failure scenarios

**FS-1 · Native entry passes the auth strategy under the pre-0.31 `strategy` key** (high impact, plausible)

- Trigger: A native-entry caller supplies `config.authStrategy` (e.g. an OidcFederationStrategy for user-scoped, identity-bound encryption) and protect-ffi 0.31's Neon entry does not honour `strategy` as an alias of `authStrategy`.
- Mechanism: encryption/index.ts still calls `newClient({ ..., strategy: config.authStrategy, eqlVersion: 3 })`. The same change renames the WASM option to `authStrategy`, and its own comments say both entries now deserialize the same `NewClientOptions` and that `strategy` survives only as a deprecated alias. If the alias is missing or ignored on the native entry, the strategy is dropped silently and the client builds a default AutoStrategy from env/profile credentials.
- Consequence: Requests authenticate as the service credential rather than the end-user strategy; identity-bound operations either fail or run under the wrong identity. If the alias is present (as the commit claims for wasm), nothing happens.
- Affects: Native client construction (Encryption in encryption/index.ts), @cipherstash/stack (native entry)
- Evidence: `packages/stack/src/encryption/index.ts:134-145`; `packages/stack/src/wasm-inline.ts:1553-1561`; `packages/stack/__tests__/init-strategy.test.ts:57`
- Existing verification: init-strategy.test.ts asserts the strategy reaches a mocked newClient as `opts.strategy`; it pins stack's call shape, not what 0.31 accepts. [exists_not_run]; Typecheck of index.ts against the 0.31 `newClient` declarations would reject `strategy` if it were removed from the type; not run here. [unknown]
- Missing verification: Confirmation from the 0.31.0 Neon entry (types and runtime) that `strategy` is still accepted and forwarded.; A live test that a supplied authStrategy's getToken() is actually called on the native entry under 0.31.
- Mitigation: Pass `authStrategy` on the native call too (it is the current name per this change), or verify the alias in the 0.31 package and add a live assertion that getToken is invoked.

**FS-2 · Deployments with a base64 clientKey fail at client construction after upgrade** (high impact, plausible)

- Trigger: A consumer upgrades @cipherstash/stack with CS_CLIENT_KEY or config.clientKey copied in base64 form (e.g. from ~/.cipherstash/secretkey.json).
- Mechanism: The exact pin forces protect-ffi 0.31.0, whose explicit-clientKey decoder is hex-only; the error message omits the cause by design. On wasm-inline there is no profile-store fallback.
- Consequence: All encryption and decryption fail for that deployment until the key is re-encoded; loud, no data effect, recoverable by config change or rollback to the previous major.
- Affects: Customer applications supplying clientKey explicitly, @cipherstash/stack (native entry), @cipherstash/stack/wasm-inline
- Evidence: `.changeset/olive-pugs-invite.md:2-28`; pr_description (inferred); `skills/stash-auth/SKILL.md:209-227`
- Existing verification: CI pre-check in require-cs-secrets catches this for the repo's own secrets only. [exists_not_run]
- Missing verification: No stack-side test of the base64-rejection path; the behaviour is inherited from protect-ffi and asserted only in prose.
- Mitigation: Already mitigated by a major version bump, the changeset upgrade note and the stash-auth skill guidance. Release notes should lead with it.

**FS-3 · DynamoDB/operation callers branching on error.code see different codes** (medium impact, plausible)

- Trigger: A caller of the DynamoDB helpers branches on `error.code` values that were foreign (ECONNRESET, AWS SDK codes) or on a code the FFI emits that is not in isProtectErrorCode's set.
- Mechanism: handleError now maps any code not accepted by `isProtectErrorCode` to DYNAMODB_ENCRYPTION_ERROR, and getErrorCode returns undefined for it.
- Consequence: Retry/fail logic keyed on transport codes stops matching; the intended outcome is that transport faults are no longer mislabelled as encryption faults. Loud only if callers notice.
- Affects: @cipherstash/stack DynamoDB helpers, @cipherstash/stack (native entry)
- Evidence: `packages/stack/src/dynamodb/helpers.ts:55-58`; `packages/stack/src/encryption/helpers/error-code.ts:19-22`; `packages/stack/__tests__/error-helpers.test.ts:112-135`
- Existing verification: New unit tests for handleError (resolve-decrypt.test.ts) and getErrorCode (error-helpers.test.ts) cover foreign and known codes against the real predicate. [exists_not_run]
- Missing verification: Nothing shows every code 0.31 actually throws is in `isProtectErrorCode`'s set (the predicate is protect-ffi's own, which reduces the risk).
- Mitigation: Documented in the changeset; no further action beyond review.

**FS-4 · A remaining FFI call path still carries a key 0.31 rejects** (medium impact, speculative)

- Trigger: Any bulk/model/query payload sent to protect-ffi 0.31 that contains an undeclared top-level key.
- Mechanism: 0.31 forwards unknown keys to Rust, which rejects the whole call. The change strips `id` in bulk-encrypt, bulk-decrypt and all eight model helpers; query paths build explicit payloads. The native model-helper strip has no unit test; only live integration suites exercise it.
- Consequence: Every model/bulk operation on an unpatched path fails loudly (no wrong data).
- Affects: @cipherstash/stack (native entry)
- Evidence: `packages/stack/src/encryption/helpers/model-helpers.ts:92-96`; `packages/stack/src/encryption/operations/bulk-encrypt.ts:48-56`; `packages/stack/src/encryption/operations/bulk-decrypt.ts:27-36`
- Existing verification: wasm-inline-bulk.test.ts checks the WASM payloads; native model/bulk paths rely on live integration tests needing credentials. [exists_not_run]
- Missing verification: A unit test with a mocked FFI asserting native encryptBulk/decryptBulk payloads carry no `id`.
- Mitigation: Run the credentialed integration suites on this head before publishing.

### Recommended controls

- Confirm against the published protect-ffi 0.31.0 index.d.ts / Neon entry whether `strategy` is still honoured; prefer switching encryption/index.ts to `authStrategy` and updating init-strategy.test.ts. (review_focus; FS-1, VG-1)
- Run typecheck plus the credentialed integration suites (including an OIDC/authStrategy path on the native entry and bulk/model operations) on this head before publishing. (test; FS-1, FS-4, VG-2)
- Lead the 2.0.0 release notes with the hex-only clientKey requirement and the DynamoDB error.code change. (documentation; FS-2, FS-3)
- npm publish is irreversible; consumers hit by FS-2 can pin the previous major while re-encoding keys. (rollback_plan; FS-2)

### What this assessment could not see

- protect-ffi 0.31.0 sources, types and changelog were not available; claims about its behaviour (hex-only key, unknown-key rejection, strategy alias, cast_as canonicalisation) come from commit messages and code comments in the change. FS-1, FS-2 and FS-4 mechanisms rely on unverified statements about the dependency.
- Tests were not run (no node_modules, no network); no CI results supplied. Verification confidence capped at medium.
- Read closely: all src changes, CI action, changesets, wasm/new-client tests. Skimmed: lockfile, resolve-decrypt and error-helpers test bodies, stash-auth skill text. Pre-existing: native model helpers correlate results by index without a length check (model-helpers.ts forEach), unchanged here. Minor test-only details may be missed.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
