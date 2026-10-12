## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `970e759801..49325032a8`

Bumps the exact pin of @cipherstash/protect-ffi from 0.30.0 to 0.31.0 in @cipherstash/stack (runtime dependency, so every stack consumer gets it) and two adapters (devDependency), and adapts stack to four breaking FFI changes: the ProtectError class is replaced by a value check (isProtectErrorCode), the WASM newClient options move credentials into clientOpts and rename strategy to authStrategy, encryptConfig is no longer pre-normalised on WASM, and the stack-side correlation id is stripped from bulk payloads because 0.31 rejects unknown keys. The most material release risk is customer-facing and loud: an explicit base64 clientKey/CS_CLIENT_KEY that worked under 0.30 is now rejected at client construction, so affected deployments fail every operation after upgrading. It is mitigated by a major changeset, a skill note and a CI pre-flight. A smaller open question is that the native entry still passes the authentication strategy under the old `strategy` key, which the change itself describes as a deprecated alias; that is worth confirming against 0.31's native typings. All 16 CI checks passed on head, including credentialed unit, E2E, Deno WASM E2E and Drizzle/Supabase/Prisma integration jobs, which exercise the id-stripped bulk paths and the new WASM construction shape against the real 0.31 package.

### Failure scenarios

**FS-1 · Deployments with a base64 clientKey fail every operation after upgrading stack** (high impact, plausible)

- Trigger: A customer sets config.clientKey or CS_CLIENT_KEY to the base64 value from ~/.cipherstash/secretkey.json (accepted by 0.30) and upgrades @cipherstash/stack to the release carrying protect-ffi 0.31.0.
- Mechanism: stack pins protect-ffi exactly (packages/stack/package.json:219), so the upgrade forces 0.31.0, which per the changeset decodes an explicit clientKey as hex only and rejects base64 at construction. The error text ('invalid clientKey: expected a hex-encoded key') is intentionally terse. On wasm-inline there is no profile-store fallback.
- Consequence: Encryption() returns a ClientInitError and no encrypt/decrypt/query works for that application until the key is re-encoded: a full outage of encrypted-data access, though loud and with no data corruption. Rollback is downgrading stack.
- Affects: @cipherstash/stack (native entry: Encryption client and operations), @cipherstash/stack/wasm-inline, Customer applications configuring clientKey / CS_CLIENT_KEY explicitly
- Evidence: `packages/stack/package.json:219`; `.changeset/olive-pugs-invite.md:2-37`; pr_description; `skills/stash-auth/SKILL.md:209-227`
- Existing verification: CI pre-flight asserts the repository's own CS_CLIENT_KEY is hex; it passed on head, so CI exercised the hex path only. [ran_passed]
- Missing verification: No test shows the base64 rejection message or that profile-store keys still load on the native entry under 0.31.; No signal on how many customers supply base64 keys.
- Mitigation: Already mitigated by the major version bump, the changeset migration note and the stash-auth skill note. Consider making the release notes lead with the encoding change, and possibly a stack-side pre-check that recognises a base64-shaped key and names the encoding (without echoing the key).

**FS-2 · Native entry passes the auth strategy under the pre-0.31 `strategy` key** (high impact, speculative)

- Trigger: A caller supplies config.authStrategy (for example an OidcFederationStrategy for per-user tokens) to the native Encryption client, and 0.31's native newClient does not honour `strategy` as an alias.
- Mechanism: encryption/index.ts:143 still sends `strategy: config.authStrategy`, which this file did not change. The change's own WASM comments say 0.31 renamed the field to authStrategy and that both entries now deserialize the same NewClientOptions, with `strategy` kept as a deprecated alias (wasm-inline-new-client.test.ts:133). The native unit tests mock newClient and assert `opts.strategy`, so they cannot show what 0.31 does with it. If the alias were dropped or ignored, the client would fall back to credentials from clientOpts or the environment.
- Consequence: If the alias is ignored silently, ZeroKMS requests authenticate as the service/env identity instead of the caller-supplied strategy, which is an identity-binding change. If it is rejected, construction fails loudly for strategy users.
- Affects: @cipherstash/stack (native entry: Encryption client and operations), Native client construction with a custom authStrategy (e.g. OidcFederationStrategy)
- Evidence: `packages/stack/src/encryption/index.ts:134-145`; `packages/stack/__tests__/init-strategy.test.ts:107`; `packages/stack/__tests__/wasm-inline-new-client.test.ts:133-136`
- Existing verification: init-strategy.test.ts asserts the strategy reaches newClient as opts.strategy, against a mock. [exists_not_run]; Stack type tests and builds ran inside 'Run Tests (Node 22/24)', which passed; they would flag an excess `strategy` property only if 0.31's native typings forbid it, which could not be checked. [unknown]
- Missing verification: Confirm in protect-ffi 0.31.0's native newClient (types and Rust/JS option handling) that `strategy` is still honoured, or switch the native call to `authStrategy`.; A live test that constructs a native client with a custom strategy and observes its getToken being called.
- Mitigation: Pass `authStrategy` on the native entry, as the WASM entry now does, or confirm the alias in 0.31 before release.

**FS-3 · Callers branching on error.code see different codes** (medium impact, plausible)

- Trigger: Application code branches on EncryptedDynamoDBError.code, or an operation failure's `code`, for a non-FFI code such as ECONNRESET, or for an FFI-emitted code that is absent from 0.31's isProtectErrorCode set.
- Mechanism: handleError (dynamodb/helpers.ts:56-58) and getErrorCode (error-code.ts:19-21) now keep a code only if isProtectErrorCode accepts its value; anything else becomes DYNAMODB_ENCRYPTION_ERROR or undefined.
- Consequence: Retry or alerting logic keyed on transport codes stops matching for DynamoDB operations (documented in the changeset). If the guard's set were incomplete, specific encryption codes would degrade to generic ones. Error classification only; no data effect.
- Affects: @cipherstash/stack (native entry: Encryption client and operations), @cipherstash/stack DynamoDB helpers
- Evidence: `packages/stack/src/encryption/helpers/error-code.ts:19-22`; `packages/stack/src/dynamodb/helpers.ts:54-58`; `.changeset/olive-pugs-invite.md:32-38`
- Existing verification: error-helpers.test.ts and resolve-decrypt.test.ts cover getErrorCode/handleError with Node and FFI codes; the unit suite ran in 'Run Tests (Node 22/24)', which passed. [ran_passed]
- Missing verification: No check that every code the 0.31 Rust layer emits is in isProtectErrorCode's set (only UNKNOWN_COLUMN and INVALID_JSON_PATH are asserted).
- Mitigation: Already documented as a breaking change in the major changeset. Reviewers may want to confirm the guard's set matches the emitted codes.

### Recommended controls

- Check protect-ffi 0.31.0's native newClient option type and handling for `strategy` vs `authStrategy`; prefer changing encryption/index.ts:143 to `authStrategy` and updating init-strategy.test.ts. (review_focus; FS-2, VG-1)
- Lead the 2.0.0 release notes and upgrade guide with the hex-only clientKey requirement and a one-line re-encode command. (documentation; FS-1)
- Add a live or binding-level test that a base64 explicit key is rejected with the expected message and that the native profile-store path still loads. (test; FS-1, VG-2)
- Rollback for affected customers is pinning @cipherstash/stack to the last 1.x; confirm 1.x remains installable alongside the fixed-group 2.0.0 release. (rollback_plan; FS-1)

### What this assessment could not see

- protect-ffi 0.31.0 itself (changelog, type declarations, Rust option handling) was not available; claims about its behaviour come from the PR, changeset and code comments. BC-2 and FS-2 rest on inferred FFI behaviour.
- CI results are check-run conclusions only, with no logs, so it cannot be confirmed which tests (for example error-codes.test.ts, lock-context tests that need real user tokens) ran or were skipped. ran_passed is attributed only to the job level; lock-context payloads under 0.31's unknown-key strictness are not shown to be exercised.
- pnpm-lock.yaml was skimmed, not read in detail; other FFI call sites (single encrypt/decrypt, encrypt-query, wasm-inline bulk paths, adapters) were checked only for extra payload keys, by grep and spot reads. An unstripped unknown key on a path not covered by CI could fail loudly; none was found.
- Co-change signals (bulk-decrypt usually changed with decrypt/encrypt-query/types.ts) were treated as prompts; those files build payloads from explicit fields and did not need the id strip. No scenario raised from co-change alone.

_Inputs unavailable: architecture_docs, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
