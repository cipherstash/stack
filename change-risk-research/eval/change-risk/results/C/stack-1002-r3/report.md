## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `c93a39b034..2a38fb4e0d`

PR D of the stack-* crates import: adds an `auth` flag to the release gate, a `release-crates` job (stack-auth/stack-profile to crates.io) and `auth-artifacts`/`publish-auth` jobs (seven @cipherstash/auth npm tarballs), all intended to be inert until PR E deletes the @cipherstash/auth entries from FROZEN_PUBLISHERS. Reading the job conditions confirms the new publishing jobs cannot run at head: `release-crates` is gated on `crates-armed`, which reads the still-present @cipherstash/auth entry, and the npm auth jobs need a successful gate that reports auth=true, which a frozen unpublished auth version makes impossible. The one live behaviour change outside the new jobs is the widened push path filter on release-plz.yml: the already-ARMED EQL `release` job (crates.io OIDC, contents: write, GPG key when it decides to publish) now also starts on pushes that touch only the root Cargo.toml/Cargo.lock or the stack-auth/stack-profile crates, which the file's own comment calls a standing credential exposure. Impact if that goes wrong is medium; nothing here can publish an auth or stack-* artefact. Script tests for the new logic exist and the CI job that runs them passed. Advisory: focused review of the release-plz.yml trigger and of the arming coupling that PR E will exercise.

### Failure scenarios

**FS-1 · Armed EQL crates.io release job now starts on root-workspace Rust pushes** (medium impact, plausible)

- Trigger: Any push to main that touches only Cargo.lock / Cargo.toml (e.g. a Dependabot or toolchain bump of the stack-* crates) or packages/stack-auth/** / packages/stack-profile/**.
- Mechanism: The new paths sit in the workflow-level `on.push.paths` filter of release-plz.yml (lines 45-54), not on a per-job condition. The EQL `release` job (line 86) is gated only on `eql-armed`, and EQL is armed at head (no @cipherstash/eql entry in FROZEN_PUBLISHERS). So that job, holding id-token: write and contents: write, checks out with persisted credentials, queries crates.io, and imports GPG_PRIVATE_KEY whenever its preflight reads the eql-bindings version as unpublished, including when the crates.io API call fails (line 131).
- Consequence: A credentialed publishing job runs on pushes that release nothing on the EQL line, the standing credential exposure the file's own comment (line 37) set out to avoid. A transient crates.io API failure or a stale EQL state on such a push makes main red with an EQL release error on an unrelated Rust change, and if an eql-bindings version is genuinely unpublished it would publish from a push nobody intended as an EQL release. No auth or stack-* artefact is affected.
- Affects: .github/workflows/release-plz.yml (EQL `release` job and new stack-* crates jobs), eql-bindings crate on crates.io
- Evidence: `.github/workflows/release-plz.yml:45-54`; `.github/workflows/release-plz.yml:86-159`; `.github/workflows/release-plz.yml:31-37`; `scripts/release-gate.mjs:163-184`
- Existing verification: workflow-paths-filter-parity.test.mjs comments on the new paths but asserts only push-vs-pull_request asymmetry, not which jobs a path starts. [exists_not_run]
- Missing verification: A test or job condition asserting the EQL `release` job only runs when packages/eql/** changed (e.g. a dorny/paths-filter or a separate workflow file is not possible for crates.io, so a per-job changed-files check).
- Mitigation: Give the EQL `release` job a per-job condition on packages/eql/** having changed (or a cheap changed-files step before any credentialed step), or accept and document the wider trigger in the header comment that currently says the opposite.

**FS-2 · Arming the npm auth line also arms crates.io publishing in one deletion** (low impact, plausible)

- Trigger: PR E deletes the @cipherstash/auth FROZEN_PUBLISHERS entries before crates.io Trusted Publishing for stack-auth/stack-profile names cipherstash/stack + release-plz.yml, or before GPG_PRIVATE_KEY exists.
- Mechanism: LINES maps the `crates` line to the npm package `@cipherstash/auth` (eql-pipeline-armed.mjs line 44-52), so `crates-armed` flips with the npm switch. `release-crates` then runs `release-plz release` with workspace `publish = true` on the next matching push.
- Consequence: Not reachable in this PR. At arming time, a missing crates.io publisher entry or secret produces a failing release-plz.yml run on main (loud, nothing published); the coupling is intentional per the PR description but nothing in this repo checks the external prerequisites ahead of time.
- Affects: .github/workflows/release-plz.yml (EQL `release` job and new stack-* crates jobs), scripts/release-gate.mjs and scripts/eql-pipeline-armed.mjs, stack-auth and stack-profile crates on crates.io
- Evidence: `scripts/eql-pipeline-armed.mjs:44-52`; `release-plz.toml:17-31`; pr_description
- Existing verification: eql-pipeline-armed.test.mjs 'the stack-* crates line' asserts the switch keys on @cipherstash/auth and gates exactly release-crates; CI 'Run Tests (Node 22)' and '(Node 24)' succeeded. [ran_passed]
- Missing verification: A pre-arming checklist item for crates.io Trusted Publishing and GPG_PRIVATE_KEY in PR E.
- Mitigation: In PR E, confirm crates.io Trusted Publishing and the GPG secret before deleting the entries; dispatch auth-preflight.yml against the Version Packages branch first.

### Recommended controls

- Review the release-plz.yml `on.push.paths` widening against the header comment at line 31-37; decide whether the EQL `release` job should be scoped to packages/eql/** changes. (review_focus; FS-1, VG-1)
- Add a workflow-shape test that the EQL `release` job is not started (or exits before credentialed steps) for a push touching only root Cargo files. (test; FS-1, VG-1)
- Before PR E: dispatch auth-preflight.yml on the Version Packages branch, confirm npm and crates.io trusted publishers and GPG_PRIVATE_KEY, and keep re-adding the FROZEN_PUBLISHERS entries as the documented way to disarm both lines. (rollback_plan; FS-2, VG-2)

### What this assessment could not see

- I could not run the script tests or the gate locally (no node_modules; running changed scripts was not permitted in this session). Test results come only from CI check-run conclusions, without step logs. ran_passed for the script tests rests on the 'Run Tests (Node 22/24)' conclusions; I cannot confirm the test:scripts step was not skipped inside that job.
- _build-auth-artifacts.yml and auth-preflight.yml were read in full but not executed; correctness of napi cross-builds (darwin-x64 on macos-latest, musl) is unverified. Build failures at arming time would be loud and pre-publish (the wrapper job verifies seven distinct tarballs); not assessed further because the jobs are inert here.
- Test-only, docs and lint-target edits (AGENTS.md, CONTRIBUTING.md, cliff.toml, lint-no-auth-changeset message, tests-supply-chain/lint-release path lists) were skimmed only. Low-risk areas; a regression there would be a CI or wording issue.
- publish-auth uses tag-pinned actions (actions/download-artifact@v4, actions/setup-node@v6.5.0) in a job with id-token: write; this copies the existing publish-ffi pattern at base, so it is a pre-existing posture rather than a new risk. Not raised as a scenario; worth noting for the supply-chain owners.
- No visibility of repository secrets, npm/crates.io trusted-publisher configuration or branch protection. Statements about what can publish rely on workflow conditions and the frozen map only.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
