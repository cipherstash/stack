## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `5dd37db087..063530d063`

CI-only change. Every cached jdx/mise-action step in 12 workflows gains `cache_key_prefix: mise-v1-<ubuntu image>` matching its job's runs-on, so jobs on blacksmith ubuntu-2204 (glibc 2.35) and ubuntu-2404 (glibc 2.39) no longer share one mise cache entry holding source-built cargo tools. A new vitest guard (run by tests.yml's lint job via `pnpm run test:scripts`) enforces the rule for every workflow and limits composite actions to image-independent tools. An independent re-implementation of the guard over all workflows at head found all 29 cached steps keyed to the correct image and every publish/release path still `cache: false`. No shipped artefact, library code or release workflow is altered. Residual risk is low: the change relies on both pinned mise-action versions (v3.6.3 and v4) honouring `cache_key_prefix`, which could not be checked offline, and the first run after merge will be a cold cache for every job.

### Failure scenarios

**FS-1 · Pinned mise-action version ignores cache_key_prefix, so the guard passes while the shared key remains** (low impact, speculative)

- Trigger: A pinned mise-action revision (v3.6.3 at 5228313e, or v4 at 1648a781) does not declare or honour the cache_key_prefix input.
- Mechanism: GitHub Actions only warns on an undeclared `with:` input. The new test checks the YAML statically (E-2) and cannot tell whether the action uses the value, so an ignored input would leave the default distro-agnostic key in place with a green check.
- Consequence: The GLIBC_2.38 cross-image cache poisoning the change targets could recur on the next mise config change: CI jobs fail before tests run. No shipped artefact is affected; a loud CI failure, not a silent one.
- Affects: CI test/lint workflows using a cached mise-action (bench-eql, crap-crates, fuzz, integration-protect-ffi, macro-expand-eql, miri, mutants, test-eql, tests-crates, tests-golang, tests-rust, udeps)
- Evidence: `scripts/__tests__/workflow-mise-cache-image.test.mjs:71-179`; `.github/workflows/tests-rust.yml:84-89`; `.github/workflows/integration-protect-ffi.yml:337-342`
- Existing verification: Static guard asserting the prefix is set per runs-on image. [exists_not_run]
- Missing verification: Confirmation, from the action's action.yml at each pinned SHA or from a CI log line showing the restored key, that cache_key_prefix is honoured.
- Mitigation: On the PR's CI run, check a mise-action step log for a cache key starting `mise-v1-ubuntu-2204`/`mise-v1-ubuntu-2404` for one v3.6.3 job (tests-rust) and one v4 job (tests-crates).

**FS-2 · Cold mise caches after merge slow every job and may hit job timeouts** (low impact, plausible)

- Trigger: First run of each workflow on main and on each PR branch after merge, before the new keys are saved.
- Mechanism: New prefixes mean no existing entry matches; jobs install the whole mise toolset, including cargo: tools that build from source (E-11), uncached.
- Consequence: Longer CI runs and runner cost; a job with a tight timeout-minutes could fail once. Self-heals once each key is saved.
- Affects: CI test/lint workflows using a cached mise-action (bench-eql, crap-crates, fuzz, integration-protect-ffi, macro-expand-eql, miri, mutants, test-eql, tests-crates, tests-golang, tests-rust, udeps)
- Evidence: `.github/workflows/tests-crates.yml:99-109`
- Missing verification: CI timings for the PR run were not available.
- Mitigation: Accept a one-off slow run; re-run any timed-out job once the cache is populated.

### Recommended controls

- In the PR's CI logs, confirm the mise cache key printed by a v3.6.3 step (tests-rust / integration-protect-ffi) and a v4 step carries the image prefix, and that test:scripts passed in tests.yml's lint job. (review_focus; FS-1, VG-1)

### What this assessment could not see

- The jdx/mise-action source at the pinned SHAs was not available offline, so the semantics of cache_key_prefix (and that the default key omits the distro) are taken from the test file's comment. FS-1 cannot be ruled out or confirmed.
- The new vitest test was not run (no node_modules, no network). An equivalent Python check was run instead over all workflows at head. The JS test's own pass/fail is unknown; the workflow state it asserts was checked independently.
- Pre-existing, not introduced here: composite actions still use the default key, and entries previously saved under that key by full-toolset workflow jobs may persist until eviction. Whether a composite step restoring such an entry exposes those tools to later steps was not investigated. Possible residual cross-image cache reuse via composite actions until old entries expire; outside this change's scope.
- No CI results, PR description, or GitHub cache state were available. Verification confidence capped at medium.

_Inputs unavailable: pr_description, ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
