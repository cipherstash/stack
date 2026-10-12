## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `013e3ff31f..12d0ed73f5`

Lockfile-only change to packages/eql/Cargo.lock: reqwest 0.13.3 -> 0.13.4 pulls hickory-resolver/hickory-proto 0.25.2 -> 0.26.3 (new hickory-net crate, prefix-trie, system-configuration, ndk-context; enum-as-inner dropped) to pick up two security advisories, and re-resolves several Windows-only windows-sys edges to older versions. No Cargo.toml changed. The only path to reqwest/hickory from a workspace member is the unpublished eql_tests crate (publish = false) via cipherstash-client and stack-auth; the published eql-bindings crate and the SQL bundle do not depend on any changed package, and a library's Cargo.lock is not used by downstream consumers. The realistic failure is a loud one: the CI SQLx/e2e suite, which reaches ZeroKMS through cipherstash-client and so through the new DNS resolver, fails or flakes. test-eql.yml is path-triggered on Cargo.lock, so it should run on this change, but no CI result was supplied. Impact low; ready for normal review once CI is green.

### Failure scenarios

**FS-1 · EQL SQLx/e2e CI fails or flakes because the test harness's ZeroKMS client resolves DNS differently** (low impact, speculative)

- Trigger: CI runs the eql_tests e2e/fixture suite, which builds cipherstash-client/stack-auth against reqwest 0.13.4 + hickory-resolver 0.26.3 and makes network calls to ZeroKMS.
- Mechanism: hickory-resolver 0.26 is a breaking-range upgrade (new hickory-net crate, changed system-configuration handling). If its system resolver configuration handling or defaults differ on the CI runner, reqwest's lookups for ZeroKMS endpoints could fail or time out.
- Consequence: Loud failure: the eql test job fails or is flaky, blocking merges for EQL changes until reverted or fixed. No customer-facing artefact is affected because eql_tests is publish = false and the published crate and SQL do not contain these packages.
- Affects: eql_tests (packages/eql/tests/sqlx), test-eql CI workflow (SQLx matrix with ZeroKMS e2e)
- Evidence: `packages/eql/Cargo.lock:1605-1675`; `packages/eql/Cargo.lock:3101-3103`; `.github/workflows/test-eql.yml:96-97`; `packages/eql/mise.toml:110-117`
- Existing verification: test-eql.yml runs on any change to packages/eql/Cargo.lock and executes cargo test --features proptest-e2e with ZeroKMS credentials, which exercises the new resolver end to end. [exists_not_run]
- Missing verification: A green test-eql run (including the credentialed build-archive/e2e job) on this head sha; no CI result was supplied.
- Mitigation: Require the test-eql run to pass on this sha before merging; revert the lockfile if the e2e job regresses.

### Recommended controls

- Confirm the test-eql workflow (including the credentialed SQLx/e2e job) is green on 12d0ed73 before merge. (test; FS-1, VG-1)

### What this assessment could not see

- cargo was not available and network access was forbidden, so the lockfile was not checked for consistency (cargo metadata --locked) and the hickory 0.26 changelog and the cited advisories were not read. The upstream behaviour change in hickory 0.26 is known only from the lockfile; the windows-sys downgrades are assumed harmless because they only affect Windows targets and the eql CI jobs read run on Ubuntu runners.
- No CI results supplied. Verification confidence is capped at medium; nothing is claimed to have run or passed.
- Developer machines (macOS/Windows) building eql_tests locally pick up the new system-configuration/core-foundation 0.9.4 and older windows-sys edges; these are not exercised by Linux-only CI. A local-only build break on those platforms would not be caught by CI; low impact as it affects contributors only.

_Inputs unavailable: ci_results, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
