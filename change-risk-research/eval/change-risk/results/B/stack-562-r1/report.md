## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `7f67e116fa..9e082520fb`

Renames the public auth-strategy config field of @cipherstash/stack from `config.strategy` to `config.authStrategy` on both the Node `Encryption()` entry and the `wasm-inline` entry, keeping `strategy` as a deprecated alias that still forwards (authStrategy wins when both are set) and logs a once-per-process console warning. The rest is TypeDoc. The public `Encryption()` path is backward compatible and the alias, precedence and warning behaviour are covered by new unit tests (not run here; no CI given). The one hard rename is the parameter of `EncryptionClient.init()` (marked @internal but reachable through the `@cipherstash/stack/encryption` subpath): a direct JS caller still passing `strategy` would have it silently dropped and fall back to the default `auto` credentials. No in-repo caller does this. Minor: test-only latch-reset functions are exported from two public entry points, and AGENTS.md still documents `config.strategy`. No payload, key, or SQL contract changes.

### Failure scenarios

**FS-1 · Direct EncryptionClient.init({ strategy }) callers silently fall back to the default auto credentials** (medium impact, plausible)

- Trigger: A consumer (plain JS, or TS passing a non-literal/spread config) constructs `new EncryptionClient()` from `@cipherstash/stack/encryption` and calls `init({ ..., strategy })` as worked at base.
- Mechanism: `init()` now reads only `config.authStrategy` (encryption/index.ts:130,166); a `strategy` key is ignored with no warning or error, so protect-ffi receives `strategy: undefined` and builds its default auto strategy from CS_* env vars or the dev profile. The deprecated-alias handling lives only in `Encryption()` (encryption/index.ts:864-867).
- Consequence: ZeroKMS requests authenticate as the service/env credentials instead of the intended strategy (e.g. an end user's OidcFederationStrategy). Without lock context, encryption may succeed under the wrong identity; with lock context it would likely fail at operation time. If no env credentials exist, init fails loudly.
- Affects: EncryptionClient.init via @cipherstash/stack/encryption subpath, Downstream applications passing config.strategy (e.g. OidcFederationStrategy users)
- Evidence: `packages/stack/src/encryption/index.ts:123-168`; `packages/stack/package.json:188-192`; `git -C repo grep -n -E '\.init\(' 9e08252 -- packages | grep -v __tests__`; `packages/stack/src/encryption/index.ts:118-122`
- Existing verification: init-strategy.test.ts covers the alias only through `Encryption()`, not direct `init()` calls. [exists_not_run]
- Missing verification: No test or guard for `EncryptionClient.init` receiving the legacy `strategy` key.; Unknown whether external consumers call init() directly; no dependency graph available.
- Mitigation: Have `init()` also accept `strategy` as a deprecated alias (`config.authStrategy ?? config.strategy`), or keep init's parameter named `strategy`, so the @internal method is not a silent break.

**FS-2 · Test-only deprecation-latch reset exported from public entry points** (low impact, plausible)

- Trigger: Consumers import `__resetStrategyDeprecationWarningForTests` from `@cipherstash/stack/encryption` or `@cipherstash/stack/wasm-inline`.
- Mechanism: Both functions are `export`ed from modules that are published entry points; the comment claims it stays off the public API surface, but it does not, unless the build strips @internal declarations (not verified).
- Consequence: An accidental public API that later removal would break; only affects log noise. Low.
- Affects: EncryptionClient.init via @cipherstash/stack/encryption subpath, @cipherstash/stack/wasm-inline entry
- Evidence: `packages/stack/package.json:188-192`; `packages/stack/src/encryption/index.ts:676-696`
- Missing verification: Check whether the build (tsup / d.ts generation) strips @internal exports.
- Mitigation: Move the reset hook to a non-exported test helper (e.g. vi.resetModules) or confirm @internal stripping.

### Recommended controls

- Decide whether `EncryptionClient.init` is truly internal; if not, add the `strategy` alias there too and a unit test for it. (review_focus; FS-1, VG-1)
- Run the stack unit suite (init-strategy, wasm-inline-strategy, lock-context) and type tests in CI before release; add a types.test-d.ts assertion that `strategy` is accepted but deprecated and `authStrategy` is accepted. (test; VG-1, VG-2)
- Update AGENTS.md:118 to `config.authStrategy`; keep the test-only reset hook off the public entry points. (documentation; FS-2)

### What this assessment could not see

- No node_modules in the checkout and no network, so tests and type checks were not run. Test coverage is known to exist but not shown to pass.
- No dependency graph or consumer inventory; external use of `EncryptionClient.init` is unknown. FS-1 likelihood cannot be estimated.
- Build config was not inspected to see whether @internal declarations are stripped from published .d.ts. Whether FS-2 and the init() rename are visible to typed consumers is unconfirmed.
- TypeDoc prose (auto strategy fallback to dev profile, keyset semantics) was not checked against protect-ffi / @cipherstash/auth behaviour. Possible documentation inaccuracies are not assessed.

_Inputs unavailable: pr_description, ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
