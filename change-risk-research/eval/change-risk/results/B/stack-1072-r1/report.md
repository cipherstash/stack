## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `c4df82de3f..792ddd0347`

CI-only change. The `Test JS` workflow (tests.yml: lint, unit/type tests, release gate, E2E, WASM E2E, Bun) gains a pull_request `paths: ['**', '!docs/plans/**']` filter, so a PR that touches only docs/plans/ no longer runs it; push to main stays unfiltered. To keep that safe, the frozen-publisher-docs test stops reading the EQL plan, a new test asserts no test file names a docs/plans/*.md path, and the workflow-filter guard tests are switched to a shared, order-aware `filterCovers` helper so they understand negations. No shipped package code changes. Mixed PRs still run the full workflow, and main still runs everything after merge, so the residual risks are a plan-only PR merging something a non-test CI step would have rejected (none found reading plans today), required checks left Pending if repository rules require Test JS jobs (the repo's own test-eql.yml comment warns about exactly this but also records that no checks are currently required), and the loss of the plan-vs-FROZEN_PUBLISHERS consistency guard. All are low impact and recoverable. Tests were not run.

### Failure scenarios

**FS-1 · A plan-only PR merges something a Test JS step would have rejected, turning main red** (low impact, plausible)

- Trigger: A PR touching only docs/plans/ when some step run by Test JS (release:gate, a lint:* script, code:check, or a test that builds a plan path at runtime) reads plan content.
- Mechanism: tests.yml no longer runs for that PR (E-1). The new guard (E-5) only scans test files for a literal docs/plans/<name>.md string, so a non-test CI script or a dynamically built path is not covered. I found no current reader: release-gate.mjs only names the plan in a message string (E-8) and lint-no-dead-package-paths excludes plans (E-10).
- Consequence: The break is first seen on the unfiltered push-to-main run (E-2), after merge; fixed by a follow-up or revert. No shipped artefact is affected.
- Affects: .github/workflows/tests.yml (Test JS: lint, run-tests, e2e-tests, wasm-e2e-tests, run-tests-bun), scripts/__tests__ workflow-guard suites and lib/paths-filter.mjs
- Evidence: `.github/workflows/tests.yml:7-14`; `.github/workflows/tests.yml:4-6`; `scripts/__tests__/plan-docs-unread-by-tests.test.mjs:14-51`; `scripts/release-gate.mjs:922-925`; `scripts/lint-no-dead-package-paths.mjs:11-37`
- Existing verification: plan-docs-unread-by-tests.test.mjs asserts no test file names a plan, with a positive control on release-gate.mjs. [exists_not_run]; paths-filter.test.mjs pins tests.yml's filter to exactly one negation, '!docs/plans/**'. [exists_not_run]
- Missing verification: The plan-reader scan does not include non-test scripts invoked by tests.yml (scripts/*.mjs run via pnpm run lint:* / release:gate).
- Mitigation: Accept (main still runs everything), or widen the scan's pathspecs to scripts/*.mjs excluding message-only references.

**FS-2 · Required Test JS checks stay Pending on plan-only PRs** (low impact, plausible)

- Trigger: A repository ruleset or branch protection requires any Test JS job (e.g. 'Lint (Biome)' or 'Run Tests (Node …)') and a PR changes only docs/plans/.
- Mechanism: A workflow skipped by a path filter reports no check run, so a required check never resolves. The repo itself documents this as the reason test-eql.yml has no pull_request path filter (E-9).
- Consequence: Plan-only PRs cannot merge without an admin override or an unrelated file change. Loud, no data or release impact.
- Affects: .github/workflows/tests.yml (Test JS: lint, run-tests, e2e-tests, wasm-e2e-tests, run-tests-bun), Repository branch rules / required status checks
- Evidence: `.github/workflows/tests.yml:7-14`; `.github/workflows/test-eql.yml:33-47`
- Missing verification: Current required-status-check configuration for main is not available to this assessment.
- Mitigation: Confirm no Test JS job is a required check; if one becomes required, switch to a changes-job + per-job `if:` pattern as test-eql.yml does.

**FS-3 · EQL cutover plan can drift from FROZEN_PUBLISHERS unchecked** (low impact, plausible)

- Trigger: @cipherstash/eql leaves FROZEN_PUBLISHERS (Phase-5 cutover) or the plan text is edited.
- Mechanism: The DOCS entry that asserted the plan carries its `@cipherstash/eql` instruction iff the map does was removed (E-3), while release-gate.mjs still directs an operator to that plan's Phase-5 cutover when the gate fails (E-8).
- Consequence: An operator or agent could follow a stale plan instruction during the cutover; detected only by human review.
- Affects: docs/plans/2026-08-13-eql-monorepo-absorption.md (EQL Phase-5 cutover plan)
- Evidence: `scripts/__tests__/frozen-publisher-docs.test.mjs:72-79` (base); `scripts/__tests__/frozen-publisher-docs.test.mjs:129-136`; `scripts/release-gate.mjs:922-925`
- Existing verification: AGENTS.md and SECURITY.md remain held to the map by frozen-publisher-docs.test.mjs. [exists_not_run]
- Missing verification: Nothing checks the plan's Phase-5 wording against the map any more.
- Mitigation: Intentional trade-off; consider moving the operational Phase-5 instruction out of the plan into a held doc, or pointing release-gate's message at SECURITY.md/AGENTS.md.

### Recommended controls

- Before merge, confirm in repository settings/rulesets that no Test JS job is a required status check. (other; FS-2, VG-2)
- Confirm `pnpm run test:scripts` passes on this PR's CI run (the guard suites and the new paths-filter / plan-docs-unread-by-tests suites). (test; VG-1)
- Review the plan-reader scan's pathspecs (tests only) and whether non-test CI scripts should be included. (review_focus; FS-1)

### What this assessment could not see

- GitHub's path filter evaluates a bounded number of changed files (documented limit of ~300 in the diff). A very large PR whose evaluated files are all under docs/plans/ could skip Test JS while also changing code. Not verified from the inputs. Low-likelihood path for code to merge without PR tests; push-to-main would still run them.
- Search for plan readers was text-based (git grep for docs/plans and 'plans'); runtime-constructed paths in tooling outside scripts/ were not exhaustively traced. FS-1 likelihood is an estimate.
- Only the PR title was available; no PR description, CI results, or deployment/ruleset context. Intent and required-check status are inferred.

_Inputs unavailable: ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
