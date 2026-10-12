## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `04ac44c812..385c84144b`

Rewrites OidcFederationStrategy from one cached CTS token for the whole strategy to one token per provider JWT (SHA-256 keyed, bounded LRU of 1024, pending tier, cancellation guard, strategy-wide account-refusal memory). The provider callback is now called on every get_token, persisted tokens are stamped with federated_from and served only to the matching JWT, and the JS wrappers call getJwt in the caller's async context and hand it to a new getTokenForJwt. Bindings (napi, wasm, Go) gain an optional cache capacity. The change fixes a cross-user identity-binding defect (#1045) and is extensively unit-tested (tests exist, not run here). Residual release risk: (1) the shipped docs and skills now say one long-lived strategy serves every user, but on the @cipherstash/stack native entry protect-ffi calls getToken from a Neon background task where request AsyncLocalStorage is not visible, so the fix only holds there under a documented workaround (#1065 open); (2) the provider now sits on the hot path of every token fetch (and, in Go, under the strategy mutex), so IdP latency or errors now affect every operation; (3) exchange volume to CTS rises with JWT rotation, and an account-level refusal is now remembered across all JWTs. No observed defect found in the core cache logic.

### Failure scenarios

**FS-1 · Shared @cipherstash/stack client following the new 'one strategy serves every user' guidance still binds operations to the wrong user on the native entry** (high impact, plausible)

- Trigger: A Node server builds one long-lived Encryption() client with an OidcFederationStrategy (as the updated skills/README now encourage: 'a module-level strategy is fine') and either reads the user from AsyncLocalStorage in getJwt, or follows the doc example's closure `() => getUserJwt(req)` while caching the client beyond that request.
- Mechanism: protect-ffi calls strategy.getToken() from a Neon channel background task (encryption/index.ts comments, head). The wrapper's getToken() runs getJwt in that task's async context, where the request's AsyncLocalStorage is not visible (acknowledged in index.ts:800-805 and SKILL.md caveat, #1065 open). A closure that captured one request's `req` returns that user's JWT for every later caller. The per-JWT cache then faithfully serves the captured user's token to everyone.
- Consequence: Either loud failure (getJwt finds no request) or, in the captured-closure case, ZeroKMS operations for user B authenticated and audit-logged as user A, so lock-context identity binding is wrong: the #1045 defect persists on the most common consumer path for anyone who reads the general guidance but misses the caveat.
- Affects: @cipherstash/stack Encryption client (native entry), protect-ffi (Neon native client), Shipped agent skills (skills/stash-auth, stash-edge, stash-encryption, stash-supabase) and READMEs, @cipherstash/auth (napi native entry index.js, wasm-inline entry, type declarations)
- Evidence: `languages/typescript/packages/stack/src/encryption/index.ts:163-180`; `languages/typescript/packages/stack/src/encryption/index.ts:797-815`; `skills/stash-auth/SKILL.md:291-317`; `languages/typescript/packages/auth/index.js:127-148`
- Existing verification: TS test runs getJwt in the getToken() caller's async context for @cipherstash/auth used directly (not via protect-ffi). [exists_not_run]
- Missing verification: No test drives OidcFederationStrategy through the @cipherstash/stack native Encryption client / protect-ffi with two users and AsyncLocalStorage.; No check that the stack docs' closure example is only used with a per-request client.
- Mitigation: Keep the 'one Encryption() client per request' rule as the primary guidance for @cipherstash/stack native until #1065 lands; make the README/index.ts example build the client inside the request; consider a runtime warning when getJwt is invoked outside any AsyncLocalStorage store.

**FS-2 · Provider callback on the hot path: IdP latency or errors now hit every operation, serialized under the Go strategy lock** (medium impact, plausible)

- Trigger: A provider whose Token/getJwt call is slow, makes a network request (e.g. an oauth2 token source near refresh, a workload-identity fetch) or fails transiently, in a service with many concurrent encrypt/decrypt calls.
- Mechanism: get_token now calls provider.fetch() before any cache lookup (oidc_federation_strategy.rs:389-396), whereas the base returned the cached token without calling the provider (base :88-95). In Go, Strategy.Token holds s.mu for the whole guest call (strategy.go:184-193) and the provider runs inside it (transport.go:27-32), so every Token call on a strategy waits on the previous caller's IdP call.
- Consequence: Throughput drop and added p99 latency on every ZeroKMS operation; a transient IdP error fails operations that previously would have been served from a valid cached CTS token. Recoverable, but an availability regression on upgrade.
- Affects: packages/stack-auth (OidcFederationStrategy, oidc_refresher, token), Go stackauth / stackencrypt (wasm guest), @cipherstash/auth (napi native entry index.js, wasm-inline entry, type declarations)
- Evidence: `packages/stack-auth/src/oidc_federation_strategy.rs:367-396`; `packages/stack-auth/src/oidc_federation_strategy.rs:88-95` (base); `languages/golang/stackauth/strategy.go:184-193`; `languages/golang/stackauth/transport.go:19-35`
- Existing verification: Rust test a_provider_failure_is_returned_before_any_exchange and each_jwt_gets_its_own_token_and_the_provider_is_asked_every_time pin the new contract. [exists_not_run]; Go TestOIDCStrategyFederatesEachProviderTokenOnce. [exists_not_run]
- Missing verification: No latency/concurrency test for a slow provider under concurrent Token calls in Go.; No measurement of per-call provider cost with real SDKs (Clerk, oauth2.TokenSource).
- Mitigation: Release-note the contract change prominently (the title's '!' is the only breaking marker for Go/Rust callers); recommend a caching provider (oauth2.ReuseTokenSource); consider fetching the JWT outside the Go strategy mutex.

**FS-3 · JWT rotation multiplies CTS exchanges and can trip a strategy-wide usage-limit lockout** (medium impact, plausible)

- Trigger: An IdP that rotates session JWTs far faster than the ~15 min CTS token lifetime (short-lived session tokens), a provider that mints per call, or a store shared by several users (one slot), at production traffic.
- Mechanism: The cache is keyed on the whole JWT, so every rotation is a new engine and a new /api/authorise exchange (changeset lines 35-37); a shared single-slot store now misses whenever the user changes. If CTS answers USAGE_LIMIT_EXCEEDED, settle() records it strategy-wide (oidc_federation_strategy.rs:249-272) and engine_for returns it to every new JWT for the denial TTL.
- Consequence: Higher CTS request volume and usage-metered cost after upgrade; at the limit, every user whose JWT rotates in that window is refused until the TTL passes. Cached users continue to be served.
- Affects: packages/stack-auth (OidcFederationStrategy, oidc_refresher, token), CTS POST /api/authorise, Customer TokenStores / auth cookies holding persisted token JSON
- Evidence: `.changeset/oidc-federation-per-user-tokens.md:28-44`; `packages/stack-auth/src/oidc_federation_strategy.rs:214-287`; `packages/stack-auth/src/error.rs:625-649`; `packages/stack-auth/src/oidc_refresher.rs:260-266`
- Existing verification: Rust tests an_account_refusal_is_remembered_across_jwts_without_an_engine, a_remembered_refusal_does_not_block_a_cached_user, a_remembered_refusal_expires_after_its_window. [exists_not_run]
- Missing verification: No estimate of exchange volume per user for the supported IdPs' rotation intervals.; No monitoring identified for /api/authorise rate or eviction/denial logs (eviction is only logged at debug).
- Mitigation: Before release, estimate exchange rate with the shortest-lived supported IdP tokens and confirm CTS rate/usage limits; monitor /api/authorise volume after rollout; consider raising eviction logging above debug.

### Recommended controls

- Review README.md, encryption/index.ts and skills/stash-auth/SKILL.md together: make 'one client per request' the unambiguous guidance for @cipherstash/stack native until #1065 ships, and make the example build the client inside the request. (review_focus; FS-1, VG-1)
- Add an integration test that drives two users through one @cipherstash/stack native Encryption client (protect-ffi) with an AsyncLocalStorage-reading getJwt and asserts each request's token identity. (test; FS-1, VG-1)
- Run the stack-auth (features http), @cipherstash/auth vitest and Go stackauth suites in CI and attach results before release. (test; VG-2)
- Release-note the provider-on-every-call contract for Rust and Go callers (not only the npm changeset) and recommend caching providers. (documentation; FS-2)
- Watch /api/authorise request rate and USAGE_LIMIT_EXCEEDED responses per workspace after rollout; compare with pre-release baseline. (monitoring; FS-3, VG-3)

### What this assessment could not see

- Read closely: oidc_federation_strategy.rs (non-test), cache.rs, oidc_refresher.rs diff, token.rs diff, napi lib.rs, index.js, wasm-inline.mjs, Go strategy.go/transport.go, stack encryption/index.ts, stash-auth SKILL.md and changesets. Skimmed or not read: stack-auth-wasm lib.rs, .d.ts files, test bodies, stash-edge/encryption/supabase skills, lockfile diffs. Type-declaration drift or wasm-binding argument-order defects could be missed.
- protect-ffi source is not in the repository; its call pattern (Neon channel background task) is taken from comments at head. FS-1's exact AsyncLocalStorage behaviour on that path is inferred, not verified.
- No tests were run (running cargo/npm build tooling was not permitted in this session) and no CI results were supplied. Verification confidence rests on test existence only.
- Mixed-version deployments sharing a cookie: older releases ignore federated_from (Token has no deny_unknown_fields) and keep base behaviour; not separately assessed. Cross-version behaviour during rolling deploys is not characterised.
- No PR description, deployment context or CTS rate-limit information. FS-3 impact cannot be sized against real traffic.

_Inputs unavailable: pr_description, ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
