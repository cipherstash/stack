## Change risk: Focused review required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `04ac44c812..385c84144b`

Fixes a cross-user identity bug (#1045): OidcFederationStrategy now calls the provider on every getToken() and keeps one CTS token per SHA-256 of the whole provider JWT in a bounded LRU cache, stamps federated tokens with `federated_from`, and only serves a stored token to the JWT that produced it. Node and wasm-inline wrappers call getJwt on the JS side and hand it to a new getTokenForJwt; Go and JS gain a cacheCapacity option. The core Rust change is careful and well tested (per-JWT isolation, interleaved users, eviction, cancellation, stored-token matching), and CI on the head commit is green. The remaining risk is mostly outside the strategy: (1) the shipped docs and agent skills now say one long-lived strategy serves every user, while the @cipherstash/stack native client still calls getJwt from a Neon channel that does not carry the request's AsyncLocalStorage (#1065 open), so a shared client with an ALS-reading getJwt can still bind one user's data to another user's identity; (2) more CTS exchanges when IdPs rotate JWTs quickly, plus one re-federation per legacy stored token at upgrade; (3) in Go, one strategy shared across users runs every user's provider call and any CTS exchange under one per-strategy mutex. Release readiness: focused review of the customer-facing guidance and the Go locking, not a block on the core fix.

### Failure scenarios

**FS-1 · Shared @cipherstash/stack native client with an AsyncLocalStorage getJwt still binds users to the wrong identity** (high impact, plausible)

- Trigger: A customer follows the new 'one long-lived strategy serves many users / a module-level strategy is fine' guidance and builds one @cipherstash/stack (native entry) Encryption client lazily on the first request, with a getJwt that reads the request from AsyncLocalStorage (Clerk auth(), Next.js headers()).
- Mechanism: protect-ffi's NeonJsAuthStrategy calls `strategy.getToken` via a Neon Channel obtained at client construction (lib.rs 515-560). The new index.js wrapper runs getJwt inside that getToken, so getJwt sees the async context of the channel, not of the operation's request. The PR itself states the ALS request is not visible on this path (#1065 open). If the client was created inside request A, getJwt can resolve A's session for every later caller; the per-JWT cache then faithfully serves A's token. The skill headline says sharing is fine; the caveat is in a following paragraph.
- Consequence: Values encrypted under lock context for user B are bound to user A's identity: B cannot decrypt them, and audit logs show A. This is the #1045 bug kept alive by a configuration the new docs encourage. If no request is visible, the failure is loud (getJwt throws) rather than silent.
- Affects: @cipherstash/stack native Encryption client via protect-ffi NeonJsAuthStrategy, Shipped agent skills and READMEs (stash tarball, @cipherstash/stack README), @cipherstash/auth (Node native binding and wasm-inline entry)
- Evidence: `languages/typescript/packages/protect-ffi/crates/protect-ffi/src/lib.rs:510-560`; `languages/typescript/packages/auth/index.js:127-148`; `skills/stash-auth/SKILL.md:291-316`; `languages/typescript/packages/stack/src/encryption/index.ts:797-808`; pr_description
- Existing verification: Node test runs getJwt in each getToken() caller's ALS scope against @cipherstash/auth directly (not through protect-ffi). [ran_passed]
- Missing verification: No test drives a shared @cipherstash/stack native client from two ALS request scopes and checks which JWT getJwt saw.; No confirmation of which async context the Neon Channel callback runs in (creation-time context vs none).
- Mitigation: Until #1065 lands, make the stash-auth headline conditional: say plainly that the @cipherstash/stack native client must be built per request (or getJwt must close over req), and drop 'a module-level strategy is fine' from the general paragraph. Alternatively, have the native client fail closed or warn when getJwt resolves with no request context.

**FS-2 · Go strategy shared across users serialises every user's provider call and CTS exchange behind one mutex** (medium impact, plausible)

- Trigger: A Go service shares one stackencrypt/stackauth OIDC strategy across many users (as the new docs invite), and one user's provider call or first CTS exchange is slow or hangs.
- Mechanism: Strategy.Token takes s.mu for the whole guest call (strategy.go 184-193), and the provider runs inside that guest call while the ProfileStore is locked (transport.go 27-32). Before this change the provider and the exchange ran only on renewal of a single token; now the provider runs on every Token call and every new or rotated user JWT triggers an HTTP exchange while the lock is held.
- Consequence: Head-of-line blocking: token fetches for every user on that strategy wait on one user's IdP call or CTS round trip, raising p99 latency and possibly causing timeouts under load. Availability degradation, no data impact.
- Affects: Go stackauth / stackencrypt (WASI guest + host)
- Evidence: `languages/golang/stackauth/strategy.go:184-193`; `languages/golang/stackauth/transport.go:18-32`
- Existing verification: Go tests check each provider token is federated once and capacity zero exchanges every call; Go binding CI jobs passed. [ran_passed]
- Missing verification: No concurrent multi-user Go test with a slow provider or slow CTS to measure blocking.; No load or latency measurement of the per-call provider invocation through the WASI host.
- Mitigation: Document that a Go strategy serialises calls and size the deployment accordingly, or narrow the lock so cache hits do not wait on another user's exchange. Add a concurrency test with a gated provider.

**FS-3 · More CTS exchanges from JWT rotation and legacy stored tokens; an account refusal then blocks every new user** (medium impact, plausible)

- Trigger: An IdP issuing short-lived JWTs (rotated more often than the ~15 min CTS token lifetime), or the first request per user after upgrade when cookies hold unstamped tokens.
- Mechanism: The cache key is the whole JWT, so each rotation is a new entry and a new /api/authorise call (changeset says so). BoundStore treats tokens without federated_from as a miss, so every active user re-federates once after upgrade. If CTS answers UsageLimitExceeded, settle() stores a strategy-wide StickyDenial (60 s) that refuses new engines for all JWTs.
- Consequence: Higher exchange volume and per-operation latency on cache misses; if exchanges count toward a usage limit, a burst can lock out every user without a cached token for up to a minute at a time.
- Affects: stack-auth crate (OidcFederationStrategy, oidc_refresher, token, cache), Customer TokenStores / cookies (createWithStore, next.mjs helper), CipherStash CTS /api/authorise
- Evidence: `.changeset/oidc-federation-per-user-tokens.md:26-35`; `packages/stack-auth/src/oidc_federation_strategy.rs:156-173`; `packages/stack-auth/src/oidc_federation_strategy.rs:214-273`; `packages/stack-auth/src/error.rs:625-627`
- Existing verification: Rust tests cover unstamped and mismatched stored tokens as misses and an account refusal remembered across JWTs. [ran_passed]
- Missing verification: No measurement of exchange rate against real IdP rotation intervals (e.g. Clerk session tokens).; Unknown whether CTS meters or rate-limits /api/authorise per call.
- Mitigation: Call out the upgrade-time re-federation and rotation cost in release notes; watch /api/authorise rate and USAGE_LIMIT_EXCEEDED after release; consider a staged rollout to customers with high user counts.

**FS-4 · Guidance to share clients outlives the fix: version skew or rollback reintroduces #1045** (high impact, plausible)

- Trigger: A customer changes their code to share one client (per the new skills/READMEs) while running an @cipherstash/auth older than this fix, or the auth release is rolled back after customers adopted sharing.
- Mechanism: Docs ship as a `stash`/`@cipherstash/stack` patch and the fix as an `@cipherstash/auth` minor. @cipherstash/stack pins auth via workspace:* so its own release carries the fix, but a project using @cipherstash/auth directly, or skills copied by a newer stash CLI into a repo with an older auth, gets the sharing advice without the per-JWT cache. The skill names no minimum version. Older versions deserialise the new token JSON (no deny_unknown_fields) and serve the single cached token to everyone.
- Consequence: Cross-user identity binding as in #1045: data encrypted for one user bound to another, wrong audit identity.
- Affects: Shipped agent skills and READMEs (stash tarball, @cipherstash/stack README), @cipherstash/auth (Node native binding and wasm-inline entry)
- Evidence: `skills/stash-auth/SKILL.md:318-322`; `skills/stash-auth/SKILL.md:291-316`; `.changeset/oidc-federation-per-user-docs.md:1-4`; `languages/typescript/packages/stack/package.json:232`
- Missing verification: No check that the skills name the minimum @cipherstash/auth version that makes sharing safe.
- Mitigation: Once the release version is known, write the minimum @cipherstash/auth version into stash-auth 'Client lifetime'. Treat rollback of the auth release as unsafe without a customer notice to revert to per-request clients.

### Recommended controls

- Review stash-auth 'Client lifetime' and the READMEs: the general rule should not say a module-level strategy is fine for the @cipherstash/stack native client while #1065 is open. (review_focus; FS-1, VG-1)
- Add a protect-ffi or stack integration test that shares one client across two AsyncLocalStorage scopes and asserts which JWT getJwt received (expected to document the limitation or fail closed). (test; FS-1, VG-1)
- Add a Go test with two users on one strategy, one provider gated, asserting the other user's cached-token call does not wait (or document the serialisation). (test; FS-2, VG-2)
- After release, watch /api/authorise request rate and USAGE_LIMIT_EXCEEDED responses for federated workspaces, especially the first hours after upgrade. (monitoring; FS-3, VG-3)
- Put the minimum @cipherstash/auth version in the skills once it is known, and note in the release notes that rolling back requires reverting to per-request clients. (documentation; FS-4, VG-4)
- Treat rollback of @cipherstash/auth as a security-relevant action: pair it with a customer notice, since older versions serve one token to all callers. (rollback_plan; FS-4)

### What this assessment could not see

- Read closely: stack-auth oidc_federation_strategy.rs (implementation), cache.rs, oidc_refresher.rs, token.rs, auto_refresh.rs changes, Node index.js / lib.rs, wasm-inline.mjs, Go strategy.go/transport.go/guest auth.rs, skills and READMEs. Skimmed: the ~1000 lines of new Rust tests, Node and Go test bodies, lockfiles, stack-auth-wasm beyond the factory changes. Test strength is judged from names and a sample; a weak assertion in a skimmed test would not be noticed.
- Which async context a Neon Channel callback runs in was not verified from Neon source; FS-1 relies on the PR's own statement that the request is not visible there. FS-1 could be loud (no request, getJwt throws) rather than silent for many apps; the silent case needs a client created inside a request.
- CI results are check-run names and conclusions only; no logs, so which tests ran in each job is inferred from job names. ran_passed claims are at job level, not per test.
- No deployment context: CTS metering, rate limits, customer adoption of shared clients, release timing. Impact of FS-3 and FS-4 cannot be sized.
- History signal: credentials.go usually co-changes with credentials_test.go, which is not in this diff (only a doc comment changed in credentials.go). Checked; the credentials.go change is documentation only, so no missing test was inferred.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
