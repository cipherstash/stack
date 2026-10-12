## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `814593681e..722408fe71`

Bumps @cipherstash/auth (+6 native bindings) 0.40.0 -> 0.41.0, whose strategy factories, getToken() and device-code flow now return Result<T, AuthFailure> instead of throwing, and migrates the stack WASM resolveStrategy, the stash CLI login/init and the wizard credential checks to unwrap it. It also bumps the stack's encryption core @cipherstash/protect-ffi 0.27.0 -> 0.28.0 (in the changeset, not the PR description) because protect-ffi must now unwrap the token envelope. The in-repo migrations look complete and mechanical, and live CI (Node 22/24, Bun, E2E, Deno WASM round-trip) passed. The main open risk is the Node/native explicit `config.authStrategy` path: nothing shows that protect-ffi 0.28's native newClient unwraps the new Result-shaped getToken() (the changeset only claims this for WASM), or that plain `{ getToken(): { token } }` custom strategies still work, and no test exercises that path live. Second, @cipherstash/stack re-exports the auth factories, so their runtime return shape changes for stack consumers while the changeset presents only the AuthError type rename as breaking, and the shipped JSDoc examples still pass `XStrategy.create(...)` straight into authStrategy.

### Failure scenarios

**FS-1 · Node explicit authStrategy path fails every ZeroKMS request if protect-ffi 0.28 native does not unwrap the auth Result (or no longer accepts plain { token })** (high impact, plausible)

- Trigger: A Node/Bun application on the upgraded @cipherstash/stack passes `config.authStrategy` (OidcFederationStrategy for lock-context / identity-bound encryption, AccessKeyStrategy, or a custom `{ getToken(): Promise<{ token }> }` object).
- Mechanism: Encryption.init passes config.authStrategy straight to protect-ffi newClient as `strategy` (packages/stack/src/encryption/index.ts:148-166). With auth 0.41, a strategy's getToken() resolves to `{ data: { token } }`. The changeset says 0.27 read `.token` off this envelope and got undefined ('token field is not a string'), and that 0.28 unwraps it 'inside its WASM newClient'. Nothing in the change or the repo shows that the native newClient does the same. Conversely, stack still documents plain `{ getToken(): Promise<{ token }> }` objects as valid AuthStrategy values (types.ts:22-31, 155-157). If 0.28 only reads `.data.token`, those break instead. The protect-ffi 0.28 source and types were not available to check either case.
- Consequence: Every encrypt/decrypt/query on the affected path fails with an auth/token error. Identity-bound (lock context) deployments, which need OidcFederationStrategy, cannot encrypt or decrypt at all after upgrading. The failure is loud and has no data-integrity effect, but it is an outage for that integration path and needs a new release to fix.
- Affects: @cipherstash/stack (Node entry: Encryption with config.authStrategy), External integrators of @cipherstash/stack passing auth strategies or custom { getToken } objects
- Evidence: `.changeset/stack-auth-0-41-result-api.md:15`; `packages/stack/src/wasm-inline.ts:212-218`; `packages/stack/src/encryption/index.ts:148-166`; `packages/stack/src/types.ts:22-31`; `packages/stack/__tests__/init-strategy.test.ts:23-60`; `packages/stack/src/types.ts:1-10`
- Existing verification: Live CI (Node 22/24, Bun, E2E) passed with protect-ffi 0.28 and auth 0.41, but its credentials are CS_* env vars, so it exercises the default auto path, not an explicit authStrategy object. [ran_passed]; Deno WASM round-trip passed live, which supports the WASM-side unwrap claim for AccessKeyStrategy built by resolveStrategy. [ran_passed]; init-strategy.test.ts covers forwarding authStrategy to newClient, but mocks protect-ffi, so it cannot detect a token-shape mismatch. [exists_not_run]
- Missing verification: A live (or protect-ffi-unmocked) Node test that runs encrypt/decrypt with an explicit auth 0.41 AccessKeyStrategy / OidcFederationStrategy passed as config.authStrategy.; A test that a plain custom `{ getToken: async () => ({ token }) }` strategy still works against protect-ffi 0.28, or a documented decision that it no longer does.; The protect-ffi 0.28 release notes confirming native newClient handles the Result envelope.
- Mitigation: Before release, confirm from protect-ffi 0.28 (source or changelog) that native newClient accepts both `{ data: { token } }` and `{ token }`. Add a Node integration test using an explicit AccessKeyStrategy from @cipherstash/stack as authStrategy. If plain `{ token }` is no longer accepted, update the AuthStrategy docs and changeset, or add a small adapter in stack.

**FS-2 · Stack's re-exported auth factories change runtime return shape under a 'minor' changeset, and shipped JSDoc still shows the old usage** (medium impact, observed in the code)

- Trigger: An integrator upgrades @cipherstash/stack and keeps (or copies from the bundled docs) `authStrategy: OidcFederationStrategy.create(workspaceCrn, ...)` / `AccessKeyStrategy.create(...)`.
- Mechanism: @cipherstash/stack re-exports the auth 0.41 strategy classes as runtime values (src/index.ts:28-38), whose create()/detect() now return Result<Strategy, AuthFailure>. The JSDoc that ships in the published .d.ts still passes the factory result directly as authStrategy (encryption/index.ts:761, :779; identity/index.ts:71; wasm-inline.ts:47-51). The stack section of the changeset lists only the AuthError -> AuthFailure rename as breaking for stack consumers, and the package bump is minor.
- Consequence: TypeScript consumers get a compile error on upgrade. JavaScript consumers, or code using `as any`, pass a Result object as the strategy and fail at runtime when getToken is called. Developers and coding agents that follow the bundled examples write code that does not work. The failure is loud, not silent, and on the 0.x line a caret range does not pick up the minor bump automatically.
- Affects: @cipherstash/stack public exports (auth strategy re-exports and auth types), External integrators of @cipherstash/stack passing auth strategies or custom { getToken } objects
- Evidence: `packages/stack/src/index.ts:28-38`; `packages/stack/src/encryption/index.ts:756-781`; `packages/stack/src/identity/index.ts:64-73`; `packages/stack/src/wasm-inline.ts:43-52`; `.changeset/stack-auth-0-41-result-api.md:2-13`
- Existing verification: auth-reexports.test.ts only asserts the re-exported names are the real auth bindings; it does not check factory return shape or documented usage. [exists_not_run]
- Missing verification: A type test (test-d) showing the documented `authStrategy: X.create(...)` pattern no longer compiles, or a compiling replacement example.; Changeset wording that tells stack consumers that create()/detect()/getToken() on the re-exported strategies now return Result.
- Mitigation: Update the JSDoc examples to unwrap (`const r = OidcFederationStrategy.create(...); if (r.failure) ...; authStrategy: r.data`). Expand the stack changeset entry to call out the runtime return-shape change of the re-exported strategies, and consider whether this warrants clearer upgrade notes.

**FS-3 · Wizard reports an unexpected error instead of 'missing credentials' if auth 0.41's failure.type strings differ from the hard-coded ones** (medium impact, speculative)

- Trigger: A user with no CipherStash credentials runs the wizard.
- Mechanism: hasCredentials returns false only when failure.type is 'NOT_AUTHENTICATED' or 'MISSING_WORKSPACE_CRN', and rethrows any other failure (packages/wizard/src/lib/prerequisites.ts:45-58). These strings carry over the old error.code values; the auth 0.41 AuthFailure union could not be read. The repo's own mocks disagree on casing: the wasm-inline test uses type 'InvalidWorkspaceCrn' while the wizard test uses 'NOT_AUTHENTICATED'. The wizard test supplies the same string it checks, so it cannot catch a mismatch.
- Consequence: On a fresh machine the wizard aborts with a raw auth error instead of listing the missing-credentials prerequisite. This is a loud first-run UX failure with no data effect.
- Affects: @cipherstash/wizard
- Evidence: `packages/wizard/src/lib/prerequisites.ts:45-61`; `packages/wizard/src/__tests__/prerequisites.test.ts:8-22`; `packages/stack/__tests__/wasm-inline-strategy.test.ts:76-82` (inferred); `.changeset/stack-auth-0-41-result-api.md:15`
- Existing verification: prerequisites.test.ts mocks a NOT_AUTHENTICATED failure (self-consistent with the code, not with auth 0.41). [exists_not_run]
- Missing verification: A check against auth 0.41's exported AuthFailure type (e.g. typing the predicate against AuthFailure['type'] so a wrong literal fails typecheck).
- Mitigation: Type the `notAuthenticated` predicate against the imported AuthFailure type instead of `{ type: string }`, so tsc rejects literals that are not in the union.

### Recommended controls

- Confirm from protect-ffi 0.28's source or changelog that native newClient unwraps the auth Result envelope and still accepts `{ token }`. Also confirm it changes nothing in payload/wire format relative to 0.27. (compatibility_check; FS-1)
- Add a live Node integration test: Encryption({ config: { authStrategy: AccessKeyStrategy.create(crn, key).data } }) round-trips encrypt/decrypt. Add a unit test with a custom `{ token }` strategy against unmocked protect-ffi if feasible. (test; FS-1, VG-1)
- Fix the JSDoc examples in encryption/index.ts, identity/index.ts and wasm-inline.ts to unwrap the factory Result. Expand the stack changeset to state that the re-exported strategies' factories and getToken now return Result. (documentation; FS-2, VG-2)
- Type the wizard's notAuthenticated predicate against AuthFailure and check the literals against auth 0.41. (review_focus; FS-3, VG-3)
- Publishing is irreversible. If FS-1 occurs after release, be ready to ship a stack patch (adapter or protect-ffi pin) rather than relying on users downgrading. (rollback_plan; FS-1)

### What this assessment could not see

- No node_modules in the checkout and no network, so the @cipherstash/auth 0.41 and @cipherstash/protect-ffi 0.28 sources, types and changelogs were not read. Their behaviour is taken from the changeset and code comments. FS-1 and FS-3 stay plausible/speculative; I could not confirm or rule them out.
- Beyond the token-envelope unwrap, what protect-ffi 0.28 changes in the encryption core (payload shape, EQL output, search-term compatibility with installed SQL bundles) is unknown. The PR description does not mention the bump. Live round-trip CI passing is some evidence of same-version correctness, but none of cross-version compatibility with data written by 0.27. No mechanism was found, so no scenario is raised, but this is not evidence of safety.
- CI results are conclusions only; no logs, so I cannot tell which tests ran, were skipped, or whether integration tests were gated off. Passing CI is treated as coarse evidence only.
- pnpm-lock.yaml changes were skimmed, not checked entry by entry; the per-platform binding versions were checked in pnpm-workspace.yaml only. A lockfile anomaly would not be detected.
- The PR says root package.json was also bumped, but root package.json is not in the diff and has no @cipherstash dependency at head. Minor discrepancy between the PR description and the diff; no risk found from it.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
