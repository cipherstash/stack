## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `7f67e116fa..9e082520fb`

Renames the @cipherstash/stack auth-strategy config field from `config.strategy` to `config.authStrategy` on both the Node `Encryption()` factory and the `wasm-inline` entry. The old field is kept as a deprecated alias that still works and logs a one-time console warning. The rest of the diff is TypeDoc and test updates. In the public factories the alias is resolved before the value reaches protect-ffi, and unit tests cover the new field, the alias, precedence when both are set and the WASM accessKey mutual-exclusion guard. Two lower-impact risks remain. First, the exported `EncryptionClient.init()` method (marked @internal) no longer reads `strategy`, so a direct JS caller that passes it would silently fall back to the default `auto` credentials instead of the intended (for example per-user OIDC) strategy. Second, test-only reset hooks are now exported from the public `./encryption` and `./wasm-inline` subpaths. None of the tests were run, because the checkout has no installed dependencies.

### Failure scenarios

**FS-1 · Direct EncryptionClient.init({ strategy }) silently drops the custom auth strategy** (medium impact, plausible)

- Trigger: A JavaScript caller, or a TypeScript caller using a cast or a non-literal config object, constructs `new EncryptionClient()` from `@cipherstash/stack/encryption` and calls `init({ ..., strategy })` instead of using `Encryption()`.
- Mechanism: At base, init read `config.strategy`. At head it reads only `config.authStrategy` (`packages/stack/src/encryption/index.ts:166`), and the alias is resolved only in `Encryption()` (lines 864-867). An unknown `strategy` key is ignored, so `newClient` receives `strategy: undefined` and falls back to the default auto strategy.
- Consequence: No error is raised. If CS_* env vars or a dev profile exist, ZeroKMS requests authenticate as the service or developer rather than the intended end user (OIDC federation), so data is encrypted under a different identity than intended. Lock-context operations would likely fail or behave differently. If no credentials are present, init fails with a misleading credentials error.
- Affects: @cipherstash/stack/encryption EncryptionClient.init, Downstream applications passing config.strategy (e.g. OIDC per-user / lock-context integrations)
- Evidence: `packages/stack/src/encryption/index.ts:123-168`; `packages/stack/src/encryption/index.ts:864-884`; `packages/stack/src/encryption/index.ts:123-168` (base)
- Existing verification: init-strategy.test.ts covers forwarding through `Encryption()` for authStrategy, the deprecated alias and precedence, but not direct `init()` calls. [exists_not_run]
- Missing verification: A test or type check that `init()` either accepts the deprecated `strategy` key or rejects it loudly.; A search of downstream/internal integrations for direct `.init(` calls on the stack EncryptionClient.
- Mitigation: Resolve `authStrategy ?? strategy` inside `init()` too (or make init private or non-exported), so every construction path honours the alias.

**FS-2 · Test-only latch reset becomes a published API on two entries** (low impact, observed in the code)

- Trigger: The release publishes dist/encryption/index.js and dist/wasm-inline.js, and their .d.ts files, with `__resetStrategyDeprecationWarningForTests` exported.
- Mechanism: Both functions are `export`ed from modules that are package subpath entries (`./encryption`, `./wasm-inline` in package.json). The comment says it is 'not re-exported from the package entry', but the subpath is itself a package entry. The build config has no stripInternal setting.
- Consequence: Consumers can import a test hook, and removing it later is technically a breaking change. There is no data or security effect.
- Affects: @cipherstash/stack/encryption EncryptionClient.init, @cipherstash/stack/wasm-inline
- Evidence: `packages/stack/src/wasm-inline.ts:420-422`; `packages/stack/package.json:188-191`
- Missing verification: An API-surface or exports snapshot check for the published entries.
- Mitigation: Move the latch to an internal module not mapped by package exports, or accept and document the export as @internal.

### Recommended controls

- Decide whether `EncryptionClient.init()` should also accept the deprecated `strategy` key; if so, move the alias resolution into init. (review_focus; FS-1)
- Add a test that calls `init({ strategy })` directly, plus type tests for ClientConfig/WasmClientConfig with authStrategy, strategy and both set. (test; VG-1, FS-1)
- Keep the test reset hooks out of the published subpath modules, or mark them explicitly as internal in the API docs. (other; FS-2)
- Update AGENTS.md to reference `config.authStrategy`. (documentation; )

### What this assessment could not see

- No node_modules in the checkout, so unit and type tests were not run. Test-based claims are exists_not_run only.
- Downstream consumers outside this repository (customer apps, other CipherStash repos) could not be searched. Whether anyone calls `EncryptionClient.init()` directly (FS-1) is unknown.
- protect-ffi behaviour when `strategy` is undefined was taken from the in-code comment and the base behaviour, not read from protect-ffi source. The fallback-to-auto consequence in FS-1 is inferred.

_Inputs unavailable: pr_description, ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
