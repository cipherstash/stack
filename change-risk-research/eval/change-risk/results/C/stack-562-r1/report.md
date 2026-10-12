## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `7f67e116fa..9e082520fb`

Renames the client auth-strategy config field from `config.strategy` to `config.authStrategy` on both the Node entry (`Encryption()`) and the WASM entry (`@cipherstash/stack/wasm-inline`), keeping `strategy` as a deprecated alias that still forwards and emits a one-time console.warn; `authStrategy` wins when both are set. Most of the diff is TypeDoc. The public `Encryption()` path is backwards compatible and covered by updated unit tests for forwarding, alias, precedence and the WASM accessKey mutual-exclusion guard; CI test jobs (Node 22/24, Bun, E2E, WASM Deno E2E) report success. The one compatibility edge not covered by the alias is the `@internal` but runtime-public `EncryptionClient.init()` method, whose parameter was renamed without an alias: a direct caller still passing `strategy` would silently fall back to the default `auto` strategy. No in-repo caller does this. The FFI option name and payload format are unchanged, so there is no data-at-rest or wire-format effect. Advisory: focused review of the init() rename; otherwise low risk.

### Failure scenarios

**FS-1 · Direct EncryptionClient.init({ strategy }) caller silently loses its auth strategy** (medium impact, plausible)

- Trigger: A consumer (plain JS, or TS passing a non-literal/spread object) constructs `new EncryptionClient()` from `@cipherstash/stack/encryption` and calls `init({ ..., strategy })`, as worked at base.
- Mechanism: At base `init` forwarded `config.strategy` to newClient (base encryption/index.ts:130,166). At head `init` reads only `config.authStrategy` (head :166 forwards `config.authStrategy`); the deprecated alias is resolved only inside `Encryption()` (head :864-881). An unrecognised `strategy` key is dropped, so `strategy: undefined` reaches protect-ffi and it builds the default auto strategy from CS_* env vars or the local dev profile.
- Consequence: If ambient credentials exist, ZeroKMS requests authenticate as the service/dev principal rather than the intended per-user OidcFederationStrategy identity; no warning is emitted. With lock context the operation would likely fail loudly; without it the user-identity binding of requests is lost silently. If no ambient credentials exist, init fails loudly. No ciphertext format or key change.
- Affects: @cipherstash/stack Node entry (Encryption / EncryptionClient), External callers of EncryptionClient.init() via @cipherstash/stack/encryption
- Evidence: `packages/stack/src/encryption/index.ts:123-167`; `packages/stack/src/encryption/index.ts:123-166` (base); `packages/stack/src/encryption/index.ts:878-883`; `packages/stack/package.json:188-197`; `git -C repo grep -n -e 'EncryptionClient()' -e '.init(' 9e082520 -- packages/`
- Existing verification: init-strategy.test.ts exercises authStrategy/strategy only through Encryption(), not direct init() calls. [exists_not_run]
- Missing verification: No test or type check pinning EncryptionClient.init() behaviour when given the legacy `strategy` key.; No evidence of whether external consumers call init() directly.
- Mitigation: Either accept `strategy` in init() as an alias too (resolve `authStrategy ?? strategy` there), or confirm in review that init() is internal-only and call the rename out in the changeset.

**FS-2 · Deprecation console.warn surfaces in production logs for existing `strategy` users** (low impact, plausible)

- Trigger: Any existing deployment upgrades and still passes `config.strategy`.
- Mechanism: warnStrategyDeprecated() calls console.warn once per process when `strategy` is present (encryption/index.ts:678-690, wasm-inline.ts:405-414), bypassing the Stack logger level.
- Consequence: One extra warning line per process; could trip log-based alerting that treats warnings as signals. Behaviour is otherwise unchanged.
- Affects: @cipherstash/stack Node entry (Encryption / EncryptionClient), @cipherstash/stack/wasm-inline entry
- Evidence: `packages/stack/src/encryption/index.ts:678-696`; `packages/stack/src/wasm-inline.ts:405-422`; pr_description (inferred)
- Existing verification: Unit tests assert the warning fires for `strategy` and not for `authStrategy` only, on both entries. [exists_not_run]
- Mitigation: Intended behaviour; mention in release notes (changeset already does).

### Recommended controls

- Review EncryptionClient.init() (encryption/index.ts:123-167): decide whether to also honour `strategy` there, or confirm it is internal-only. (review_focus; FS-1, VG-1)
- Add a type test asserting `{ authStrategy }`, `{ strategy }` and `{ authStrategy, strategy }` compile for ClientConfig and WasmClientConfig, and that `{ authStrategy, accessKey }` does not. (test; VG-2)
- Update AGENTS.md:118, which still documents `config.strategy`. (documentation; )

### What this assessment could not see

- CI results give only check names and conclusions; I could not confirm init-strategy.test.ts and wasm-inline-strategy.test.ts ran inside the 'Run Tests' jobs. I did not run tests locally. Unit tests are cited as exists_not_run; CI success is supporting, not conclusive, evidence.
- External consumers of @cipherstash/stack (including direct EncryptionClient.init() callers) cannot be enumerated; only in-repo references at head were searched. FS-1 likelihood is unknown; impact is rated on mechanism.
- The TypeDoc rewrite was skimmed for accuracy only where it touched the strategy contract; claims about env-var fallback order and dashboard URLs were not verified against protect-ffi or the dashboard. Documentation inaccuracies, if any, are not assessed; they would not change runtime behaviour.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
