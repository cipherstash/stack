## Change risk: Changes or verification required

**Impact if something goes wrong:** critical · **Verification confidence:** medium · `04ac44c812..385c84144b`

The change fixes cipherstash/stack#1045: OidcFederationStrategy used to hand one cached CTS token to every caller, so on a shared server a user's lock-context encryptions could be bound to another user's identity. It now asks the provider on every get_token, keys a bounded LRU of refresh engines on the SHA-256 of the whole JWT, stamps persisted tokens with that digest and serves stored tokens only to the matching JWT, adds getTokenForJwt and a cacheCapacity option to the napi, wasm and Go bindings, and moves the JS getJwt call into the caller's async context. The Rust core is closely and adversarially tested (forged-signature, concurrency, cancellation, refusal tests), though no test was run here. The main residual risk is guidance: docs and shipped agent skills now say one module-level strategy serves every user, but on the @cipherstash/stack native path protect-ffi calls getToken through a Neon Channel bound to the context that built the client, so an AsyncLocalStorage-based getJwt can silently read the wrong request (the same identity-binding failure the PR fixes); the caveat describes this only as the request being 'not visible' and no test covers that path. Secondary risks are CTS exchange volume and strategy-wide usage-limit lockouts when IdPs rotate JWTs often, and one-time cookie/store misses on upgrade.

### Failure scenarios

**FS-1 · Stack native client with a shared strategy runs getJwt in the client-creation request's context and binds users to the wrong identity** (critical impact, plausible)

- Trigger: An app follows the new guidance ('a module-level strategy is fine', 'one strategy serves every user') with an AsyncLocalStorage-based getJwt (Clerk auth(), Next.js headers()) and lazily builds a shared @cipherstash/stack Encryption() client inside its first request.
- Mechanism: protect-ffi stores the strategy's getToken (now the index.js own-property wrapper that awaits getJwt) and invokes it through a Neon Channel obtained from the JS context that called newClient (protect-ffi lib.rs 508-575). The PR's own reasoning for the napi ThreadsafeFunction is that such callbacks run in the async context where they were created; if the Channel behaves the same, getJwt reads the ALS store of the request that built the client on every later call. The per-JWT cache then faithfully returns the first user's token for every user. The docs/skills caveat describes this path only as the request being 'not visible', which suggests a loud failure, whereas this variant is silent. The added Node test covers only a strategy created outside any scope via the raw native getToken, not the stack/protect-ffi path or a client created inside a scope.
- Consequence: User B's ZeroKMS operations are authorised as user A; values encrypted under a lock context are bound to A's identity, so B cannot decrypt them and A can, with no error. This is the #1045 failure, reached through guidance this change introduced.
- Affects: @cipherstash/auth (napi index.js, wasm-inline.mjs, typings), @cipherstash/protect-ffi Neon JS strategy bridge, @cipherstash/stack Encryption client, Shipped agent skills and READMEs
- Evidence: `languages/typescript/packages/auth/index.js:127-148`; `languages/typescript/packages/auth/__tests__/oidc-federation-strategy.test.ts:456-492`; `skills/stash-auth/SKILL.md:291-325`; `README.md:118-126`; `languages/typescript/packages/stack/src/encryption/index.ts:797-807`; `languages/typescript/packages/protect-ffi/crates/protect-ffi/src/lib.rs:508-575`
- Existing verification: oidc-federation-strategy.test.ts: getToken() from two ALS scopes on a module-level strategy gets each caller's subject; raw native getToken from a third scope fails 'no request in scope'. [exists_not_run]
- Missing verification: An end-to-end test of @cipherstash/stack Encryption() with a shared OidcFederationStrategy and an ALS-based getJwt, with the client created both outside and inside a request scope, asserting each operation's token subject.; Confirmation of which async context Neon Channel callbacks observe in the supported Node versions.
- Mitigation: Until cipherstash/stack#1065 lands, keep the stack-facing guidance at 'build the client per request / capture req in the closure' without the 'module-level strategy is fine' framing nearby, and state that on this path getJwt may see the wrong request rather than none; or have the stack client snapshot the JWT in the caller's context per operation before crossing into protect-ffi.

**FS-2 · Frequent JWT rotation multiplies CTS exchanges and a usage-limit refusal locks out every rotating user for 60 s** (medium impact, plausible)

- Trigger: An identity provider whose session JWTs are short-lived and re-minted often (or a getJwt/OAuth2 token source that mints per call) on a server with many active users.
- Mechanism: The cache key is the whole JWT, so every rotation is a new engine and a POST /api/authorise; previously one strategy made one exchange per CTS token lifetime. When CTS answers an exchange with UsageLimitExceeded or OrgNotProvisioned, settle() records a strategy-wide StickyDenial and engine_for() returns it for every new JWT for the window, while only users whose exact JWT is cached keep working.
- Consequence: Higher auth latency and CTS load proportional to users x rotations; if that load trips a usage limit, all users whose JWT rotated in the next minute fail encryption/decryption operations. Availability degradation, not data corruption.
- Affects: stack-auth crate (OidcFederationStrategy, oidc_refresher, Token), CTS POST /api/authorise, Go stackauth / stackencrypt and wasm guest
- Evidence: `packages/stack-auth/src/oidc_federation_strategy.rs:367-396`; `packages/stack-auth/src/oidc_federation_strategy.rs:214-287`; `packages/stack-auth/src/oidc_federation_strategy/cache.rs:50-82`; `packages/stack-auth/src/oidc_refresher.rs:13-31`; `packages/stack-auth/src/oidc_refresher.rs:120-138`
- Existing verification: Rust tests for refusal memory across JWTs, refusal expiry, cached user not blocked, eviction and zero capacity. [exists_not_run]
- Missing verification: No load or rate measurement of /api/authorise under realistic rotation intervals for supported IdPs.; No metric/logging above debug for exchange rate or evictions.
- Mitigation: Release note naming the cost per rotation (partly present in the changeset); expose exchange/eviction counts at info or as metrics; check CTS rate/usage limits against expected users x rotations before rollout.

**FS-3 · Stored tokens from earlier releases, mixed-version deploys and shared stores miss the cache** (low impact, plausible)

- Trigger: Upgrade of @cipherstash/auth with existing cookies/TokenStores, a rolling deploy with old and new instances sharing a store, or a store shared by several users (e.g. Redis).
- Mechanism: BoundStore::load returns None unless the stored token's federated_from matches the caller's digest; old releases write unstamped tokens and (Token has no deny_unknown_fields) ignore the stamp on read, so during a mixed deploy new instances keep missing tokens written by old ones, and old ones still serve any stored token to any caller as before.
- Consequence: One extra exchange per user after upgrade, repeated re-exchange while versions are mixed, and effectively no store caching for a store shared across users. Old instances retain the pre-fix cross-user behaviour until fully replaced.
- Affects: Persisted tokens in customer TokenStores / cookies (cs_token_*), stack-auth crate (OidcFederationStrategy, oidc_refresher, Token), CTS POST /api/authorise
- Evidence: `packages/stack-auth/src/oidc_federation_strategy.rs:150-173`; `packages/stack-auth/src/token.rs:34-51`; `packages/stack-auth/src/oidc_refresher.rs:120-138`
- Existing verification: Rust tests: stamped store, served to matching JWT, other-JWT miss, unstamped miss, expired re-federated; JS test 'does not serve a stored token to a different JWT' and cookie round-trip test. [exists_not_run]
- Missing verification: No test of a token stamped by the new release being read by the previous release.
- Mitigation: Complete rollouts promptly (old instances keep #1045); document that a shared store caches only the most recent user (already in the changeset).

### Recommended controls

- Add an integration test: one OidcFederationStrategy shared by an Encryption() client created inside an ALS scope, operations from two other scopes, assert each operation's CTS subject (expect failure or per-user tokens, never the creator's). (test; FS-1, VG-1)
- Reword the stack-path caveat in stash-auth, stash-encryption, READMEs and the stack docstring to say getJwt may observe the request that created the client (silent wrong user), and keep 'build the client per request' as the rule for the stack native entry until #1065. (documentation; FS-1)
- Reviewer to confirm Neon Channel async-context semantics in protect-ffi on supported Node versions and whether getToken lookup binds to the wrapper's own property. (review_focus; FS-1)
- Watch /api/authorise rate and UsageLimitExceeded responses per workspace after release; consider info-level or metric counters for exchanges and evictions. (monitoring; FS-2, VG-3)
- Run the stack-auth (--features http), @cipherstash/auth (Node and wasm) and Go stackauth suites in CI and attach results before release. (test; VG-2)
- Roll out services fully rather than leaving mixed versions sharing a store, since old instances keep the cross-user behaviour and new ones re-exchange their unstamped tokens. (staged_rollout; FS-3)

### What this assessment could not see

- Neon Channel / napi threadsafe-function async-context behaviour was not verified by experiment; FS-1 relies on the PR's own statement for the napi case and on reading protect-ffi. FS-1 likelihood is uncertain; its impact rating stands on the mechanism if it occurs.
- Tests were not executed (approval for cargo/node runs unavailable) and no CI results were provided. Verification confidence is capped at medium and based on reading tests only.
- Read closely: oidc_federation_strategy.rs (non-test), cache.rs, oidc_refresher.rs (non-test), token.rs, index.js, wasm-inline.mjs, protect-ffi strategy bridge, skills and README diffs, Go binding diffs. Skimmed: napi/wasm Rust binding diffs, typings, test bodies, lockfiles. Defects confined to the napi/wasm Rust binding glue or typings could be missed.
- Platform native binary / JS wrapper version skew (index.js now requires native getTokenForJwt) was not analysed beyond noting the packages ship in a fixed changeset group. A skewed install would fail loudly on getToken; not rated.
- Real-world IdP JWT rotation intervals and CTS rate limits are outside the inputs. FS-2 magnitude is unknown.

_Inputs unavailable: pr_description, ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
