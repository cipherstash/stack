## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `814593681e..722408fe71`

Bumps @cipherstash/auth 0.40 -> 0.41 (whose strategy constructors, getToken() and device-code flow now return Result envelopes instead of throwing) and @cipherstash/protect-ffi 0.27 -> 0.28, and migrates the in-repo call sites in stack (wasm-inline resolveStrategy), the stash CLI and the wizard. The in-repo migrations look internally consistent. The release risk sits in the published @cipherstash/stack surface: stack re-exports AccessKeyStrategy / OidcFederationStrategy / AutoStrategy / DeviceSessionStrategy unchanged, so their new Result-returning behaviour flows to every consumer, while stack's own JSDoc still shows `authStrategy: XStrategy.create(...)` and the changeset lists only the AuthError rename as breaking. On the Node path config.authStrategy is passed straight to protect-ffi's native newClient, and the changeset only claims that 0.28's WASM newClient unwraps the new getToken() envelope; whether the native binding does, and whether plain `{ token }` custom strategies still work, could not be checked. All changed tests mock auth and protect-ffi, no results were seen, and the only real round-trip (Deno e2e) skips without CS_* secrets. Verification of the cross-package token contract is the gap.

### Failure scenarios

**FS-1 · Node authStrategy path breaks if protect-ffi 0.28's native newClient does not handle the new getToken() Result envelope (or no longer accepts plain { token })** (high impact, plausible)

- Trigger: A Node consumer passes config.authStrategy: an auth 0.41 strategy (e.g. OidcFederationStrategy for identity-bound encryption, or AccessKeyStrategy), or a custom `{ getToken: async () => ({ token }) }` object as documented.
- Mechanism: EncryptionClient.init forwards config.authStrategy unchanged to protect-ffi's native newClient (packages/stack/src/encryption/index.ts:154-165). With auth 0.41 a strategy's getToken() resolves to `{ data: { token } }`. The changeset only asserts that protect-ffi 0.28 unwraps `.data.token` in its WASM newClient; it says 0.27 read `.token` and got undefined. Nothing in the diff or repo shows the native binding does the same, nor that 0.28 still accepts the un-enveloped `{ token }` shape that stack's AuthStrategy docs (types.ts:21-29, 155-157) still advertise.
- Consequence: Encryption client init or every ZeroKMS request fails ('token field is not a string'-style) for all Node users of config.authStrategy, including identity-bound (lock context) encryption; or, conversely, custom strategies break. Loud failure, but it is a runtime break of a published package across the authStrategy path.
- Affects: @cipherstash/stack (published npm package: Node entry and /wasm-inline entry), Encryption client init on the Node entry (EncryptionClient.init -> protect-ffi native newClient), External consumers of @cipherstash/stack that construct strategies or import AuthError
- Evidence: `.changeset/stack-auth-0-41-result-api.md:9-17` (inferred); `packages/stack/src/encryption/index.ts:146-166`; `packages/stack/src/types.ts:21-29`; `packages/stack/__tests__/init-strategy.test.ts:23-60`
- Existing verification: init-strategy.test.ts checks only that authStrategy is forwarded to newClient; protect-ffi is vi.mock'ed and the strategy returns a plain { token }. [exists_not_run]
- Missing verification: A Node integration round-trip (encrypt/decrypt) with config.authStrategy set to a real auth 0.41 AccessKeyStrategy/OidcFederationStrategy against protect-ffi 0.28's native binding.; Confirmation from protect-ffi 0.28 release notes/source that the native newClient accepts both the Result envelope and plain { token }.
- Mitigation: Run the Node e2e suite with authStrategy against real credentials before release; if native 0.28 only accepts one shape, normalise in stack (wrap the strategy so getToken() always yields what the FFI expects) and update the AuthStrategy docs.

**FS-2 · Re-exported strategy constructors now return Result envelopes, but stack docs and release note still show passing them directly as authStrategy** (high impact, plausible)

- Trigger: A consumer upgrades @cipherstash/stack and keeps (or copies from stack's JSDoc) `authStrategy: AccessKeyStrategy.create(crn, key)` / `OidcFederationStrategy.create(crn, getJwt)`, or uses AutoStrategy.detect()/DeviceSessionStrategy.fromProfile() from the stack re-export.
- Mechanism: packages/stack/src/index.ts:26-36 and wasm-inline.ts:90-93 re-export auth 0.41's strategy classes; per the changeset their create/detect/fromProfile now return `{ data } | { failure }`. Stack's own docs at encryption/index.ts:756-781, identity/index.ts:65-73 and wasm-inline.ts:44-56 were not updated and still pass the create() result straight into authStrategy. The changeset lists only the AuthError rename as the stack breaking change.
- Consequence: TypeScript consumers get compile errors (if protect-ffi's AuthStrategy type requires getToken); JS/Deno consumers pass a `{ data }` envelope whose getToken is undefined, so client init or the first encrypt/decrypt fails. Construction failures (bad CRN/key) that used to throw are now silently carried in `.failure` unless the consumer checks it.
- Affects: @cipherstash/stack (published npm package: Node entry and /wasm-inline entry), External consumers of @cipherstash/stack that construct strategies or import AuthError
- Evidence: `.changeset/stack-auth-0-41-result-api.md:9-17` (inferred); `packages/stack/src/index.ts:24-43`; `packages/stack/src/encryption/index.ts:756-781`; `packages/stack/src/identity/index.ts:65-73`
- Existing verification: wasm-inline-strategy.test.ts covers stack's internal unwrap in resolveStrategy (success and failure arms) using a mocked auth module; nothing covers consumer-side use of the re-exports. [exists_not_run]
- Missing verification: A type-level test (tsd / compile check) that the documented authStrategy examples compile against the published types.; Release-note review that the Result-returning re-exports are called out as breaking for @cipherstash/stack consumers.
- Mitigation: Update the JSDoc examples to unwrap `.data` (or provide a stack helper that unwraps/throws), and extend the changeset to state that the re-exported strategy constructors and getToken() now return Result.

**FS-3 · Wizard prerequisites rethrows instead of reporting 'not authenticated' if auth 0.41 failure type strings differ** (medium impact, speculative)

- Trigger: A user runs the wizard without credentials and auth 0.41 reports the condition with a `type` other than exactly 'NOT_AUTHENTICATED' or 'MISSING_WORKSPACE_CRN' (or detect() now fails for a reason that previously surfaced only at getToken()).
- Mechanism: hasCredentials matches on failure.type literal strings and throws failure.error for anything else (packages/wizard/src/lib/prerequisites.ts:44-58). These strings were carried over from the 0.40 `error.code` values (base prerequisites.ts:44-45); the auth 0.41 AuthFailure union could not be read. The only test feeds a hand-written mock with type 'NOT_AUTHENTICATED'; another new test in stack uses a differently-cased type ('InvalidWorkspaceCrn'), so the casing convention is not established in-repo.
- Consequence: Unauthenticated users see an uncaught auth error from the wizard instead of the missing-prerequisites guidance. Developer tooling only, loud and recoverable.
- Affects: @cipherstash/wizard prerequisites check, token acquisition and prompt fetch
- Evidence: `packages/wizard/src/lib/prerequisites.ts:39-61`; `packages/wizard/src/__tests__/prerequisites.test.ts:7-25`; `packages/stack/__tests__/wasm-inline-strategy.test.ts:18-97`
- Existing verification: prerequisites.test.ts mocks auth with a NOT_AUTHENTICATED failure from getToken(); detect() failure arm and other types untested. [exists_not_run]
- Missing verification: Check the AuthFailure `type` union in @cipherstash/auth 0.41 declarations against the two literals (a typed `failure.type === ...` comparison would be compile-checked only if the type is a literal union).
- Mitigation: Confirm the literals against auth 0.41's .d.ts; type the helper parameter as AuthFailure so mismatches fail compilation.

**FS-4 · Removal of the AuthError type export breaks TypeScript consumers that import it** (medium impact, observed in the code)

- Trigger: A consumer does `import type { AuthError } from '@cipherstash/stack'`.
- Mechanism: packages/stack/src/index.ts:39 (base) exported AuthError; head (index.ts:39-43) exports AuthFailure instead with no deprecated alias.
- Consequence: Compile error on upgrade; no runtime effect. Documented in the changeset and shipped as a minor bump on a 0.x package.
- Affects: @cipherstash/stack (published npm package: Node entry and /wasm-inline entry), External consumers of @cipherstash/stack that construct strategies or import AuthError
- Evidence: `packages/stack/src/index.ts:39` (base); `packages/stack/src/index.ts:24-43`
- Mitigation: Optionally keep `export type AuthError = AuthFailure` as a deprecated alias for one release.

### Recommended controls

- Before publishing, run a credentialed Node encrypt/decrypt round-trip with config.authStrategy set to a real auth 0.41 strategy and with a plain `{ getToken: async () => ({ token }) }` object, plus the Deno WASM e2e, and record the results. (test; FS-1, VG-1, VG-2)
- Update JSDoc in encryption/index.ts, identity/index.ts, wasm-inline.ts and types.ts (AuthStrategy shape) for the Result-returning constructors/getToken, and expand the changeset's breaking-change list beyond the AuthError rename. (documentation; FS-2, VG-3)
- Read protect-ffi 0.28 release notes or source to confirm the native newClient's accepted getToken() shapes, and the auth 0.41 AuthFailure type union, before release. (compatibility_check; FS-1, FS-3)
- Reviewer to check whether stack should normalise strategies itself (wrapper that unwraps create()/getToken()) rather than pushing the Result API onto consumers, and whether to keep a deprecated AuthError alias. (review_focus; FS-2, FS-4)

### What this assessment could not see

- node_modules is not installed and network access is not permitted, so the source, type declarations and changelogs of @cipherstash/auth 0.41.0 and @cipherstash/protect-ffi 0.28.0 could not be read. All claims about their behaviour come from the changeset and code comments in the diff. FS-1 and FS-3 cannot be confirmed or ruled out; impact is assessed on mechanism, not lowered for lack of visibility.
- No CI results or PR description were provided and no tests or type checks were run (dependencies not installed). All existing verification is exists_not_run; it is unknown whether the migrated call sites type-check against auth 0.41.
- pnpm-lock.yaml changes were checked for version consistency only (all seven auth entries move to 0.41.0; protect-ffi platform packages to 0.28.0); integrity hashes were not verified. Supply-chain integrity of the new packages is not assessed.
- Other workspace packages (e.g. packages/nextjs, drizzle, examples) were searched for auth strategy API usage by name only; no other call sites of the changed auth functions were found in source. An indirect consumer reached via dynamic access would be missed.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
