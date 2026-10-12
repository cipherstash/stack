## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `013e3ff31f..12d0ed73f5`

Lockfile-only change to the nested Cargo workspace at packages/eql: reqwest 0.13.3 -> 0.13.4, which moves hickory-resolver/hickory-proto 0.25.2 -> 0.26.3 (adds hickory-net, system-configuration, prefix-trie, ndk-context; drops enum-as-inner) and re-resolves several Windows-only windows-sys edges to older versions. No Cargo.toml changes. In this workspace reqwest is reachable only through cipherstash-client and stack-auth, which are dependencies of the unpublished eql_tests SQLx harness (publish = false). The published eql-bindings crate and the eql-codegen binary that builds the shipped SQL bundle do not depend on any changed crate, and a lockfile does not travel with a published library crate. The blast radius is therefore the EQL test/fixture harness in CI; any failure would be a loud build or test failure rather than a silent customer-facing one. Impact low; ready for normal review once the test-eql workflow (which path-filters on packages/eql/Cargo.lock) is green.

### Failure scenarios

**FS-1 · hickory 0.26 resolver change breaks the EQL test harness build or its ZeroKMS calls in CI** (low impact, speculative)

- Trigger: The eql_tests crate is compiled, or the e2e / fixture-generation suites run, with the new reqwest 0.13.4 + hickory 0.26.3 resolution.
- Mechanism: reqwest uses hickory-resolver for DNS in this graph (E-2). The 0.25 -> 0.26 move restructures the resolver (new hickory-net crate, new system-configuration dependency) and bumps rand to 0.10. A compile incompatibility or a changed resolver configuration on the CI runner would surface as a build error or as DNS/connection failures reaching ZeroKMS from cipherstash-client.
- Consequence: EQL SQLx/e2e CI jobs fail or fixture regeneration cannot reach ZeroKMS. Loud and confined to CI and developer tooling; no published artefact embeds this graph.
- Affects: eql_tests (packages/eql/tests/sqlx), test-eql.yml / bench-eql.yml CI
- Evidence: `packages/eql/Cargo.lock:3101-3110`; `packages/eql/Cargo.lock:553-587`; `.github/workflows/test-eql.yml:91-101`; `packages/eql/crates/eql-bindings/Cargo.toml:24-41`; `packages/eql/crates/eql-codegen/Cargo.toml:7-16`
- Existing verification: test-eql.yml runs on Cargo.lock changes and compiles eql_tests (test:sqlx:archive) and runs the credentialed e2e suite (test:sqlx:e2e), which exercises reqwest DNS resolution against ZeroKMS. [exists_not_run]
- Missing verification: CI results for this head were not provided.
- Mitigation: Require green test-eql jobs, including the credentialed sqlx e2e job, before merge. Reverting the lockfile is a complete rollback, since nothing is published from this graph.

### Recommended controls

- Confirm test-eql.yml is green, including the credentialed sqlx e2e job that makes real ZeroKMS calls through reqwest/hickory, and that `cargo tree --locked` succeeds in packages/eql. (test; FS-1, VG-1)

### What this assessment could not see

- No registry or crate sources offline, so the hickory 0.25 -> 0.26 changelog, whether 0.26.3 fixes the cited GHSAs, and which crate enables reqwest's hickory feature were not checked. The security benefit claimed in the commit message is unverified, and BC-1's behavioural description is based on lockfile structure, not on reading the library source.
- packages/protect-ffi/Cargo.lock, which builds the shipped native binding, pins hickory-proto/hickory-resolver 0.26.1 and is not touched here. Whether 0.26.1 is affected by the same advisories is unknown. If 0.26.1 is affected, this change does not remediate the advisories in shipped artefacts. That would be a pre-existing gap, not a risk introduced by this change.
- Windows-target effects of the windows-sys re-resolution (BC-2) were not assessed. No Windows build of this workspace was found in the workflows read. A Windows-only compile issue for local developers would not be caught by this assessment.

_Inputs unavailable: pr_description, ci_results, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
