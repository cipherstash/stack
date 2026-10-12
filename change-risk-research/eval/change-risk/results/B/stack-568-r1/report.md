## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `814593681e..722408fe71`

Bumps @cipherstash/auth 0.40->0.41 (Result-returning API) and @cipherstash/protect-ffi 0.27->0.28, migrates the CLI, wizard and the stack WASM access-key path to unwrap Results, and renames the re-exported AuthError type to AuthFailure. The internal call-site migrations look consistent and the WASM access-key path is covered by unit tests plus a live Deno round-trip in CI. The main release risk is to consumers of @cipherstash/stack (a 0.x minor): the strategy constructors it re-exports (AccessKeyStrategy/OidcFederationStrategy .create) now return Result envelopes, yet the package's own JSDoc examples and the live lock-context test still pass `.create(...)` directly as `authStrategy`, so code written that way breaks after upgrade. Separately, whether protect-ffi 0.28's native (Node) newClient unwraps the new getToken() Result envelope is not shown anywhere: the changeset only claims the WASM newClient does, and the only live test of a real auth strategy on the native path is gated on USER_JWT, which CI does not provide. Identity-bound (OIDC) encryption on Node is the path most exposed. Failures would be loud (init or ZeroKMS request errors), not silent data issues.

### Failure scenarios

**FS-1 · Strategy constructors re-exported by @cipherstash/stack now return Result; documented `authStrategy: X.create(...)` usage breaks on upgrade** (high impact, observed in the code)

- Trigger: A consumer (or the repo's own lock-context test) passes `AccessKeyStrategy.create(...)` or `OidcFederationStrategy.create(...)` directly as `config.authStrategy`, as the package's JSDoc examples show, then upgrades to the new @cipherstash/stack minor.
- Mechanism: auth 0.41 `create` returns `{ data } | { failure }` (changeset line 9; resolveStrategy now unwraps it at wasm-inline.ts:474-480). @cipherstash/stack re-exports these constructors unchanged (index.ts:26-36), and its JSDoc still shows `authStrategy: AccessKeyStrategy.create(workspaceCrn, accessKey)` and `OidcFederationStrategy.create(...)` passed straight through (encryption/index.ts:756-781, identity/index.ts:64-74, wasm-inline.ts:44-56). Encryption forwards config.authStrategy verbatim to newClient (encryption/index.ts:166), so the Result envelope, which has no getToken, reaches protect-ffi. The in-repo live test lock-context.test.ts:38-45 does the same and was not updated.
- Consequence: Client init or the first ZeroKMS request fails for every app that builds its strategy this way, including identity-bound (lock-context) encryption. TypeScript users likely get a compile error; JS users get a runtime failure. Encryption on that path is unavailable until code is changed. The changeset lists only the AuthError rename as the stack breaking surface, so users are not warned.
- Affects: @cipherstash/stack public API (native entry: Encryption + re-exported strategies/types), @cipherstash/stack/wasm-inline, External consumers of @cipherstash/stack passing auth strategies, packages/stack lock-context live test
- Evidence: `.changeset/stack-auth-0-41-result-api.md:9-15`; `packages/stack/src/index.ts:26-36`; `packages/stack/src/encryption/index.ts:756-781`; `packages/stack/src/encryption/index.ts:157-168`; `packages/stack/__tests__/lock-context.test.ts:38-45`
- Existing verification: auth-reexports.test.ts checks only that the re-exports are defined functions equal to the auth bindings, not their return shape. [exists_not_run]; lock-context.test.ts exercises OidcFederationStrategy.create on the native path, but skips without USER_JWT, which CI does not set. [exists_not_run]
- Missing verification: A type-level or runtime test that the documented `authStrategy: XStrategy.create(...)` usage either works or is rejected with a clear error.; Running lock-context.test.ts (with USER_JWT) against auth 0.41 / protect-ffi 0.28.
- Mitigation: Update the JSDoc examples, README/skills and lock-context.test.ts to unwrap `.data` (or provide a stack-level helper that unwraps and throws). Call out the constructor return-type change as breaking in the changeset. Consider having Encryption detect a `{ data }`/`{ failure }` envelope passed as authStrategy and fail with a descriptive error.

**FS-2 · Native-path protect-ffi 0.28 handling of the getToken() Result envelope is unverified** (high impact, plausible)

- Trigger: A Node (native entry) user supplies a real auth 0.41 strategy (e.g. an unwrapped OidcFederationStrategy for lock context) or a custom `{ getToken: async () => ({ token }) }` strategy as config.authStrategy.
- Mechanism: Under auth 0.41 every strategy's getToken() returns `Result<TokenResult, AuthFailure>`. The changeset says protect-ffi 0.28 unwraps `.data.token` inside its WASM newClient and that 0.27 failed with `token field is not a string`; it says nothing about the native newClient. The stack still documents the AuthStrategy contract as `getToken(): Promise<{ token: string }>` (types.ts:21-31) and its unit test uses that shape with a mocked newClient (init-strategy.test.ts:49-58). If native 0.28 reads `.token`, real auth strategies fail on every ZeroKMS request; if it requires `.data.token`, custom `{ token }` strategies documented as supported break.
- Consequence: Explicit-strategy encryption/decryption on Node fails (loudly) for one of the two strategy shapes. Identity-bound encryption with OidcFederationStrategy on Node is the most exposed path. Default env/profile credentials (no authStrategy) are not affected by this mechanism.
- Affects: @cipherstash/stack public API (native entry: Encryption + re-exported strategies/types), External consumers of @cipherstash/stack passing auth strategies
- Evidence: `.changeset/stack-auth-0-41-result-api.md:9-15`; `packages/stack/src/encryption/index.ts:157-168`; `packages/stack/__tests__/init-strategy.test.ts:49-58`; `.github/workflows/tests.yml:88-95`; `packages/stack/src/types.ts:21-31`
- Existing verification: init-strategy.test.ts only asserts the strategy object is forwarded to a mocked newClient. [exists_not_run]; lock-context.test.ts is the only live native test with a real auth strategy; it skips without USER_JWT, which CI does not provide. [exists_not_run]
- Missing verification: A live native-path round-trip in CI using an explicit AccessKeyStrategy (unwrapped from Result) as authStrategy.; A live or contract test of a custom `{ getToken: () => ({ token }) }` strategy against protect-ffi 0.28 native.; Reading protect-ffi 0.28's native newClient / AuthStrategy type to confirm which shape it accepts.
- Mitigation: Confirm in protect-ffi 0.28 release notes or source which getToken shapes the native newClient accepts; add a CI live test for the explicit-strategy native path (CS_CLIENT_ACCESS_KEY is already available); update the AuthStrategy doc in types.ts to the accepted shape(s).

**FS-3 · Consumers importing the AuthError type from @cipherstash/stack stop compiling** (medium impact, plausible)

- Trigger: A TypeScript consumer imports `AuthError` from @cipherstash/stack and upgrades.
- Mechanism: src/index.ts:39-43 now exports AuthFailure instead of AuthError; no alias kept. Code branching on the old `error.code` must change to `failure.type`.
- Consequence: Compile failure for those consumers. Loud and fixable, and documented in the changeset.
- Affects: @cipherstash/stack public API (native entry: Encryption + re-exported strategies/types), External consumers of @cipherstash/stack passing auth strategies
- Evidence: `packages/stack/src/index.ts:39-43`; `.changeset/stack-auth-0-41-result-api.md:9-15`
- Missing verification: No deprecated alias or type test for the re-exported auth types.
- Mitigation: Keep a deprecated `export type AuthError = AuthFailure` alias for one release, or accept as documented breaking change in a 0.x minor.

**FS-4 · Wizard prerequisites check may throw instead of reporting missing credentials if auth 0.41 failure.type strings differ** (low impact, speculative)

- Trigger: A user without credentials runs the wizard and auth 0.41 reports the condition with a type other than 'NOT_AUTHENTICATED' or 'MISSING_WORKSPACE_CRN'.
- Mechanism: hasCredentials (prerequisites.ts:45-58) compares failure.type to the old error.code strings, typed as plain `string`, so a renamed variant is not caught at compile time. The stack's own test uses a PascalCase failure type ('InvalidWorkspaceCrn', wasm-inline-strategy.test.ts:79), so not every 0.41 type follows the old SCREAMING_CASE names. The mocked wizard test only covers the NOT_AUTHENTICATED case.
- Consequence: The wizard aborts with a raw auth error instead of listing 'missing credentials' guidance. Local, recoverable.
- Affects: @cipherstash/wizard
- Evidence: `packages/wizard/src/lib/prerequisites.ts:45-58`; `packages/stack/__tests__/wasm-inline-strategy.test.ts:70-97`
- Existing verification: prerequisites.test.ts mocks detect().getToken() returning a NOT_AUTHENTICATED failure. [exists_not_run]
- Missing verification: Confirming the AuthFailure type union in auth 0.41 still contains NOT_AUTHENTICATED and MISSING_WORKSPACE_CRN.
- Mitigation: Type the predicate against `AuthFailure['type']` so a renamed variant fails compilation.

### Recommended controls

- Update JSDoc examples (encryption/index.ts, identity/index.ts, wasm-inline.ts) and lock-context.test.ts to unwrap `.create(...).data`; list the re-exported strategy constructor return-type change as breaking in the changeset. (documentation; FS-1, VG-2)
- Add a CI live test on the native entry using an explicit AccessKeyStrategy (unwrapped) as authStrategy, and one using a custom `{ getToken }` object, against protect-ffi 0.28. (test; FS-2, VG-1)
- Confirm from protect-ffi 0.28 release notes/source which getToken return shapes the native newClient accepts, and update the AuthStrategy contract doc in types.ts accordingly. (compatibility_check; FS-2)
- Reviewer to confirm the auth 0.41 AuthFailure union still contains NOT_AUTHENTICATED / MISSING_WORKSPACE_CRN, and that every variant carries `.error` (CLI and wizard read `failure.error.message`). (review_focus; FS-4)
- Consider a deprecated `AuthError` type alias for one release. (other; FS-3)

### What this assessment could not see

- The source of @cipherstash/auth 0.41.0 and @cipherstash/protect-ffi 0.28.0 was not available (no node_modules, no network). Their behaviour is taken from the changeset and the repo's mocks. FS-1 relies on the changeset's statement that create returns Result; FS-2 cannot be confirmed or ruled out.
- No CI results; no tests were run. Verification confidence cannot exceed low/medium; the Deno WASM e2e and live stack tests are only known to exist.
- The e2e/wasm/deno.json import paths (protect-ffi dist/wasm/protect_ffi_inline.js, auth wasm-inline.mjs inside packages/stack/node_modules) could not be checked against the installed package layouts. A wrong path would fail the Deno CI job loudly; not treated as a release risk.
- Shipped skills/ and READMEs were searched for `Strategy.create(` / authStrategy with no hits; the external docs site (cipherstash.com/docs) was not available. External docs may carry the same stale pattern as FS-1.
- @cipherstash/stack depends on @byteslice/result 0.2.0 while auth 0.41 brings 0.3.0; type compatibility between the two was not checked. Possible type friction for consumers mixing stack and auth Result types; not assessed.

_Inputs unavailable: ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
