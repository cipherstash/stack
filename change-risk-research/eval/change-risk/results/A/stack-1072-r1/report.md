## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `c4df82de3f..792ddd0347`

CI-only change. The `Test JS` workflow (tests.yml) gains a pull_request `paths:` filter ['**', '!docs/plans/**'], so PRs that touch only plan documents no longer run lint, unit, type, E2E or WASM jobs; push to main stays unfiltered and still runs everything after merge. The rest is test-suite work: a shared `filterCovers` helper that evaluates `paths:` lists in GitHub's last-match-wins order (used by three existing workflow-filter guards), a new guard that no test file names a `docs/plans/*.md` file, and removal of the EQL absorption plan from the frozen-publisher docs guard. Nothing shipped to customers changes. The material risks are low and loud: a check that reads plans without naming one literally would go red on main after a plan-only merge, and the EQL plan, still cited by release-gate output, loses its drift guard. Tests for the new behaviour exist but were not run here.

### Failure scenarios

**FS-1 · A check that reads plan documents goes red on main after a plan-only PR merges unchecked** (low impact, plausible)

- Trigger: A PR edits only docs/plans/ while some test, lint script or Biome rule run by tests.yml reads plan content without naming a literal docs/plans/*.md path (directory walk, glob, constructed path, or a non-test script).
- Mechanism: tests.yml no longer runs on the PR, so the breaking content merges; the unfiltered push-to-main run then fails. The new guard only greps test files for a literal plan filename, and by its own comment does not see paths built at run time or scripts outside the test globs.
- Consequence: main turns red until a follow-up fix; unrelated PRs may see confusing failures. Loud and easily reverted; no shipped artefact affected.
- Affects: .github/workflows/tests.yml (Test JS), scripts/__tests__ workflow-filter guards
- Evidence: `.github/workflows/tests.yml:7-14`; `.github/workflows/tests.yml:4-6`; `scripts/__tests__/plan-docs-unread-by-tests.test.mjs:5-51`; `scripts/__tests__/go-module-path.test.mjs:26`
- Existing verification: plan-docs-unread-by-tests.test.mjs fails if a test file names a plan file, with a self-check that the scan finds a known match. [exists_not_run]; push to main is unfiltered, so every merge still runs the full Test JS suite. [exists_not_run]
- Missing verification: No check covers non-test scripts run by tests.yml (release-gate, lint:* scripts, Biome) or runtime-built plan paths. Scans read here (go-module-path, lint-no-dead-package-paths) exclude docs/plans, but this was a sampled read, not exhaustive.
- Mitigation: Accept; main's unfiltered push run catches it. Optionally widen the guard's pathspec to scripts/*.mjs or note the limitation in AGENTS.md.

**FS-2 · EQL absorption plan drifts unguarded while release tooling still points operators to it** (low impact, plausible)

- Trigger: A later edit to docs/plans/2026-08-13-eql-monorepo-absorption.md reintroduces a freeze instruction, a foreign-publish claim or a live gate verdict, or a package is frozen again.
- Mechanism: The plan was removed from DOCS, so the iff check against FROZEN_PUBLISHERS and the LIVE_VERDICT_CLAIMS check no longer read it. release-gate.mjs's frozen-package failure output and release.yml's EQL summary still direct readers to that plan.
- Consequence: An agent or maintainer following the release-gate output could act on stale freeze/publish guidance. FROZEN_PUBLISHERS is empty at head, so the release-gate message that names the plan does not fire today.
- Affects: frozen-publisher-docs guard and the EQL absorption plan, release-gate.mjs failure output and release.yml EQL summary
- Evidence: `scripts/__tests__/frozen-publisher-docs.test.mjs:72-79` (base); `scripts/release-gate.mjs:922-926`; `.github/workflows/release.yml:1026`; `scripts/release-gate.mjs:163`; signal `co_change.omitted_co_changes[1]`
- Existing verification: AGENTS.md and SECURITY.md remain in DOCS and are still held to the map. [exists_not_run]
- Missing verification: Nothing checks the plan's text any more; the co-change history shows the guard and the plan usually changed together.
- Mitigation: Reviewer to confirm the plan is purely historical, or repoint the release-gate.mjs / release.yml references at a guarded document.

**FS-3 · Plan-only PRs stall if Test JS checks are or become required** (low impact, plausible)

- Trigger: A branch ruleset requires any Test JS job (e.g. 'Lint (Biome)', 'Run Tests (Node …)') as a status check.
- Mechanism: GitHub does not report a status for a workflow skipped by a paths filter, so a required check stays 'Expected' and blocks merge of plan-only PRs.
- Consequence: Plan-only PRs cannot merge without an admin bypass. Visible, no data or artefact impact.
- Affects: .github/workflows/tests.yml (Test JS), Branch protection / required status checks on main
- Evidence: `.github/workflows/tests.yml:7-14`; `.github/workflows/test-eql.yml:46-47`
- Missing verification: Live branch protection / ruleset configuration was not available; only the repo's comment that no required_status_checks rule exists was read.
- Mitigation: Confirm no Test JS job is a required check before merge; if one becomes required, add an always-reporting aggregator job as test-eql.yml does.

### Recommended controls

- Confirm that no Test JS job is a required status check on main (ruleset), so plan-only PRs do not stall. (review_focus; FS-3)
- After merge, open a throwaway plan-only PR and a PR touching a dotfile path (e.g. .github/**) to confirm Test JS skips the first and runs the second. (test; VG-2, FS-1)
- Decide whether release-gate.mjs and release.yml should keep pointing at the now-unguarded EQL plan. (documentation; FS-2)

### What this assessment could not see

- Could not run vitest (no installed dependencies, no network); CI results unavailable. All test evidence is exists_not_run; the claim that the modified guards still pass at head is unverified.
- Whether GitHub's '**' pattern matches dot-prefixed paths (e.g. .github/, .changeset/) could not be checked offline. If it did not, PRs touching only dotfile paths would also skip Test JS. This is believed not to be the case but is unverified.
- Search for code reading docs/plans was a git grep for the literal string plus a sample of repo-wide scanners, not an exhaustive audit of every script tests.yml runs. FS-1 cannot be ruled out, only bounded.
- Branch protection and ruleset settings were not available. FS-3 rests on an in-repo comment, not on the live setting.

_Inputs unavailable: pr_description, ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
