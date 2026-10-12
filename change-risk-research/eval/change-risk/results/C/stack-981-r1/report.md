## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** high · `013e3ff31f..12d0ed73f5`

Lockfile-only change to packages/eql/Cargo.lock. It moves reqwest 0.13.3 -> 0.13.4 and hickory-resolver/hickory-proto 0.25.2 -> 0.26.3, which pulls in hickory-net, prefix-trie, system-configuration, core-foundation 0.9.4 and ndk-context. Several Windows-only crates also shift between windows-sys versions. In this workspace the only path to reqwest/hickory is eql_tests (publish = false) -> cipherstash-client/stack-auth. The published crate eql-bindings does not depend on them, and a library's Cargo.lock does not ship to crates.io consumers. Nothing shipped to customers changes. The realistic failure is a DNS or HTTP behaviour change that breaks the test harness's connection to ZeroKMS. CI ran the e2e property suite, which uses that path, and it passed, as did all 28 check runs including osv-scanner. Impact is low and the change is ready for normal review.

### Failure scenarios

**FS-1 · hickory 0.26 / reqwest 0.13.4 behaviour change breaks ZeroKMS connectivity in the test harness** (low impact, plausible)

- Trigger: The new resolver handles DNS differently (system config, search domains, IPv6 ordering) or reqwest 0.13.4 changes connection behaviour in a given environment.
- Mechanism: cipherstash-client and stack-auth resolve and connect to ZeroKMS through reqwest, which now uses hickory-resolver 0.26.3 with a restructured crate layout (hickory-net split out).
- Consequence: Fixture generation or the e2e property suite fails to authenticate or encrypt, locally or in CI. This is a loud failure in test tooling. No shipped artefact or customer data is involved.
- Affects: eql_tests (packages/eql/tests/sqlx), test-eql.yml CI (Rust workspace crates, e2e property suite, sharded SQLx tests)
- Evidence: `packages/eql/Cargo.lock:1605-1675`; `packages/eql/Cargo.lock:3101-3110`; ci_result
- Existing verification: The e2e property suite (fresh encryption through ZeroKMS) and the PG17 shards ran on the head commit. [ran_passed]
- Missing verification: Fixture regeneration (fixture-gen feature) was not shown to have run against the new resolver.
- Mitigation: Revert the lockfile change if the harness breaks. No release action is involved.

**FS-2 · Re-resolved windows-sys / macOS system-configuration edges break non-Linux developer builds** (low impact, speculative)

- Trigger: A developer builds the eql workspace on Windows or macOS.
- Mechanism: The lockfile moves several crates to different windows-sys versions and adds system-configuration 0.7 / core-foundation 0.9.4 for macOS. CI runs only on Ubuntu runners, so these target-specific edges are not compiled there.
- Consequence: A local build fails on a developer machine. This is recoverable by re-locking, and nothing ships.
- Affects: packages/eql/Cargo.lock, eql_tests (packages/eql/tests/sqlx)
- Evidence: `packages/eql/Cargo.lock`; `.github/workflows/test-eql.yml:96-97`
- Missing verification: No macOS or Windows build of packages/eql in the CI results provided.
- Mitigation: Cargo only locks versions within each crate's declared range, so breakage is unlikely. Fix by re-locking if reported.

### Recommended controls

- Confirm that the only reqwest/hickory consumers in packages/eql remain the publish = false eql_tests crate, then approve as a routine security bump. (review_focus; FS-1)

### What this assessment could not see

- cargo was not run, so the dependency graph comes from reading Cargo.lock. The PR's cargo tree and cargo check claims were not reproduced. Affected-component reasoning relies on lockfile dependency lists, which name packages but not features or targets.
- The advisory contents (GHSA-q2qq-hmj6-3wpp, GHSA-3v94-mw7p-v465) and the hickory 0.26 changelog were not available offline. Whether the bump actually closes the advisories rests on the PR description and the osv-scanner CI result.

_Inputs unavailable: codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
