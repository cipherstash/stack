## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `5dd37db087..063530d063`

CI-only change. Each cached jdx/mise-action step in 12 workflows gets a cache_key_prefix (mise-v1-ubuntu-2204 or mise-v1-ubuntu-2404) that matches its job's runs-on image. This stops Ubuntu 22.04 jobs restoring cargo tools that were compiled against glibc 2.38/2.39 on 24.04. A new vitest guard holds every cached mise step to that rule. No library code, published artefact, or release workflow changes. Release workflows already set cache: false and are untouched. I checked every mise step at head with my own script, and each cached step's prefix matches its runs-on. CI on head is green, including the jobs that run the guard. The one thing nothing here proves is that both pinned mise-action versions (v4 and v3.6.3) actually build their cache key from cache_key_prefix. If one ignores it, the fix quietly does nothing for those steps and the loud glibc failure can come back. The worst case is CI-only and recoverable, so impact is low.

### Failure scenarios

**FS-1 · A pinned mise-action version ignores cache_key_prefix, so the shared key and the glibc failure come back** (low impact, speculative)

- Trigger: A PR that changes mise.toml or mise.test.toml (new config hash), where a 24.04 job saves the new entry first.
- Mechanism: GitHub Actions only warns on an unexpected `with:` input. If v4 (1648a78) or v3.6.3 (5228313) does not include cache_key_prefix in its key, every step still writes the default per-OS key. The guard checks only the YAML, so it would still pass.
- Consequence: The same failure the PR fixes: 22.04 Rust jobs fail with GLIBC_2.38 not found before any test runs, and re-runs keep failing. CI-only; no shipped artefact is affected.
- Affects: CI workflows with cached mise steps (12 workflow files), jdx/mise-action pinned at 1648a78 (v4) and 5228313 (v3.6.3)
- Evidence: `.github/workflows/tests-rust.yml:84-89` (inferred); `scripts/__tests__/workflow-mise-cache-image.test.mjs:71-101`; ci_result
- Existing verification: CI on head: Rust workspace crates, CRAP, fuzz regression, udeps, Mutants gate and Go jobs all passed. This PR does not change the mise config hash, so green CI does not show that entries are separated by image. [ran_passed]
- Missing verification: Read the action.yml and key-building code of mise-action at both pinned SHAs to confirm cache_key_prefix is a declared input that is used in the key.; Check a CI log from head for the restore/save key line showing the mise-v1-ubuntu-NNNN prefix.
- Mitigation: Before merging, check one head CI log for the cache key line. If v3.6.3 does not support the input, move tests-rust.yml and integration-protect-ffi.yml to the v4 pin or set cache: false on them.

**FS-2 · Cold cache after merge makes every job recompile its cargo tools** (low impact, plausible)

- Trigger: The first run per image on main (and per PR cache scope) after merge.
- Mechanism: The new prefixes match no existing entry, so mise compiles cargo-nextest, llvm-cov, crap, mutants, fuzz and udeps from source on the runner. Some jobs have tight timeouts, such as fuzz.yml at 30 minutes.
- Consequence: Slower CI, or a timeout that needs a re-run, until the entries are saved. Loud and self-healing.
- Affects: CI workflows with cached mise steps (12 workflow files)
- Evidence: `mise.test.toml:14-29`; `.github/workflows/fuzz.yml:69`; ci_result
- Existing verification: Head CI completed green on what were new keys for this PR, so the cold path probably fits within the timeouts. I could not see whether those runs actually missed the cache. [ran_passed]
- Missing verification: Cache hit/miss and step durations from the head CI logs.
- Mitigation: None needed beyond re-running a job that times out once.

### Recommended controls

- Check one head CI log from a v4 step and one from a v3.6.3 step (tests-rust.yml or integration-protect-ffi.yml) for the mise cache key, and confirm it starts with mise-v1-ubuntu-2204 or mise-v1-ubuntu-2404. (review_focus; FS-1, VG-1)
- Correct the counts in the PR description. It says 31 steps across 14 workflows; the diff changes 29 steps in 12 workflows. The two composite-action steps are intentionally unchanged. (documentation; VG-1)

### What this assessment could not see

- mise-action source at the pinned SHAs is not available offline (no network), so its handling of cache_key_prefix is unverified. FS-1 stays speculative rather than ruled out.
- I could not run the vitest guard locally because the checkout has no node_modules. I replicated its main check with a Python YAML scan instead. The guard's pass rests on CI check names (Run Tests (Node 22/24)) and on my equivalent scan, not on a local run of the test file.
- ci.json has no logs, so cache keys, hits and misses, and timings are not visible. Green CI shows the jobs pass. It does not show that the cache entries are now separated by image.

_Inputs unavailable: architecture_docs, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
