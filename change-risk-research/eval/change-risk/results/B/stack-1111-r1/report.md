## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `5dd37db087..063530d063`

CI-only change. Every cached jdx/mise-action step in 12 workflows (29 steps) gains a cache_key_prefix naming its job's runner image (mise-v1-ubuntu-2204 or mise-v1-ubuntu-2404), so ubuntu-22.04 and ubuntu-24.04 jobs stop sharing a mise cache entry that holds glibc-specific cargo-built tools. A new vitest guard (scripts/__tests__/workflow-mise-cache-image.test.mjs) enforces the prefix/runs-on pairing. No library, SQL, payload or release workflow behaviour changes; no shipped artefact is affected. A re-implementation of the guard's check over the head tree found every cached step's prefix matches its runs-on image and both composite actions cache only wasm-pack. Residual risks are CI-only: whether the older v3.6.3 pin honours cache_key_prefix (could not be verified offline), and a one-time cold cache on every job. Impact low; ready for normal review.

### Failure scenarios

**FS-1 · cache_key_prefix silently ignored on the v3.6.3 mise-action pin** (low impact, speculative)

- Trigger: The pinned jdx/mise-action@5228313 (v3.6.3) used by tests-rust.yml and integration-protect-ffi.yml does not accept or does not use cache_key_prefix in its key.
- Mechanism: GitHub Actions only warns on an unknown `with:` input. Two cached steps use the older v3.6.3 pin rather than v4 (1648a78). If that version ignores the input, those 2404 jobs keep the default, image-blind key, while the guard test still passes because it checks only the YAML.
- Consequence: The original GLIBC mismatch could persist for any job still on the shared default key; with 2204 jobs moved off it, the remaining sharers are only these two 2404 jobs, so the practical effect is small. CI-only, no shipped artefact.
- Affects: 12 CI workflows with cached mise-action steps (test-eql, tests-crates, tests-golang, tests-rust, fuzz, udeps, miri, mutants, crap-crates, bench-eql, macro-expand-eql, integration-protect-ffi)
- Evidence: `.github/workflows/integration-protect-ffi.yml:337-342`; `scripts/__tests__/workflow-mise-cache-image.test.mjs:7-35` (inferred)
- Existing verification: Guard test checks the YAML input is present, not that the action honours it [exists_not_run]
- Missing verification: Confirm from the v3.6.3 action.yml (or a CI log's cache key line) that cache_key_prefix is a supported input that feeds the key
- Mitigation: Check one CI run's 'Cache saved with key' line for tests-rust / integration-protect-ffi; or bump those pins to the v4 sha used elsewhere.

**FS-2 · One-time cold mise cache on every affected job** (low impact, plausible)

- Trigger: First run of each job after merge.
- Mechanism: New prefixes miss all existing entries, so mise reinstalls tools, including compiling cargo: tools (cargo-nextest, cargo-llvm-cov, cargo-mutants, cargo-udeps, cargo-fuzz) from source.
- Consequence: Slower first runs and more registry downloads; a transient upstream fetch failure would fail a job that previously hit cache. Loud and self-healing.
- Affects: 12 CI workflows with cached mise-action steps (test-eql, tests-crates, tests-golang, tests-rust, fuzz, udeps, miri, mutants, crap-crates, bench-eql, macro-expand-eql, integration-protect-ffi)
- Evidence: `scripts/__tests__/workflow-mise-cache-image.test.mjs`; `mise.test.toml:14-29`
- Mitigation: None needed beyond accepting slower first runs; re-run on transient fetch failure.

### Recommended controls

- Confirm the v3.6.3 pin (5228313) supports cache_key_prefix, e.g. from a CI log showing the saved key, or align it with the v4 pin. (review_focus; FS-1, VG-1)
- Let tests.yml's `pnpm run test:scripts` run on the PR so the new guard executes against the real tree. (test; VG-1)

### What this assessment could not see

- The mise-action source for either pinned version is not in the checkout and the network is unavailable, so the actual key format and support for cache_key_prefix were not verified. FS-1 remains speculative; the claim that the fix resolves the glibc collision rests on the test's documentation, not on the action's code.
- The vitest guard was not executed (dependencies not installed, no network); an equivalent Python check was run instead. The guard's own JS (e.g. YAML parsing quirks) is unverified; verification confidence held at medium.
- No CI results, PR description or CODEOWNERS were provided. Cannot confirm the PR #1094 failure the change describes, or that the fix clears it.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
