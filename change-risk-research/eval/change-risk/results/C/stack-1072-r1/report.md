## Change risk: Focused review required

**Impact if something goes wrong:** low · **Verification confidence:** medium · `c4df82de3f..792ddd0347`

CI-only change. The `pull_request` trigger of the Test JS workflow (tests.yml) gains `paths: ['**', '!docs/plans/**']`, so a PR touching only docs/plans/ no longer runs lint, Node/Bun/Deno or E2E jobs. `push` to main stays unfiltered. The change also removes the one test row that read a plan, adds a guard test that no test names a plan file, and adds a shared helper (scripts/__tests__/lib/paths-filter.mjs) that three existing workflow-filter guards now use to read ordered, negated `paths:` lists. Nothing that ships to customers changes. The worst plausible outcome is a plan-only PR that merges without checks and turns main red on the next push, which is detected on push and easy to recover from. A secondary concern is how the guards read filters: the guards that protect FFI and auth build coverage stay fail-closed, and only the comment-scope guard fails open. All Test JS jobs passed on the head commit, including the `test:scripts` step that runs the new and modified guards. The skip path itself has not run live, because this PR is not plan-only. Impact is low, and a short review of the helper is recommended.

### Failure scenarios

**FS-1 · A plan-only PR merges unchecked and turns main red** (low impact, plausible)

- Trigger: A PR changes only files under docs/plans/ and either (a) adds a file there of a type a whole-tree check scans (a .ts/.json that Biome checks, a package.json or Cargo.toml read by lint:eql-pins, a *.sh read by a test), or (b) changes a plan that some check reads through a path built at run time or a directory-wide scan.
- Mechanism: With `paths: ['**', '!docs/plans/**']`, GitHub starts no Test JS run for that PR. The new guard (plan-docs-unread-by-tests.test.mjs) only finds a literal `docs/plans/<name>.md` written in a test file, as its own header says. It cannot see a computed path or a by-type scan. Push to main is unfiltered, so the first run that sees the problem is the post-merge push.
- Consequence: Main goes red after the merge, and the next unrelated PR inherits the failure until someone fixes it. Nothing is published as a result, because release.yml is a separate workflow. Recovery is a follow-up commit.
- Affects: .github/workflows/tests.yml (Test JS), Checks in tests.yml that scan by file type anywhere in the tree (Biome code:check, lint:eql-pins, *.sh tests)
- Evidence: `.github/workflows/tests.yml:3-14`; `.github/workflows/tests.yml:22-54`; `scripts/__tests__/plan-docs-unread-by-tests.test.mjs:5-51`; pr_description; `.github/workflows/test-eql.yml:44-47`
- Existing verification: plan-docs-unread-by-tests.test.mjs asserts that no test file names a plan path literally, and checks that its scan finds one when there is one. It runs in test:scripts. [ran_passed]; paths-filter.test.mjs asserts that tests.yml's filter excludes docs/plans/nested/example.md, includes scripts/ and other docs/, and negates nothing else. [ran_passed]
- Missing verification: No live run of a plan-only PR shows the workflow is actually skipped and that no required check is left pending.; Nothing detects a check that reads docs/plans/ through a computed path or a by-type scan.
- Mitigation: Accept, since main's push run is the backstop. Optionally narrow the negation to '!docs/plans/**/*.md' so non-markdown files added under docs/plans/ still trigger Test JS. That closes the by-type gap the PR description names.

**FS-2 · The new filter evaluator makes a coverage guard pass for a filter that drops a binding input** (low impact, plausible)

- Trigger: A later edit adds a negation or a non-literal positive glob to the pull_request paths of a workflow that builds the FFI or auth binding.
- Mechanism: filterCovers treats `**` as covering every input and judges negations only by directory prefix. The coverage guards use negationSubtracts, which fails closed: any shared prefix, or a leading wildcard on either side, counts as removal. workflow-trigger-comments uses negationRemovesAll, which fails open. A file-type negation such as `!**/*.rs` therefore does not take a workflow out of IN_SCOPE, so the EXPECTED_IN_SCOPE check could stay green after a filter stopped reaching Rust binding inputs.
- Consequence: The comment-scope guard could miss a lost trigger. The two fail-closed coverage guards (auth-binding, wasm-build-inputs) would still fail for the same filter, so FFI/auth coverage loss is still caught for build inputs. The residual harm is limited to stale guidance in comments.
- Affects: Workflow-filter guard tests (scripts/__tests__ + lib/paths-filter.mjs)
- Evidence: `scripts/__tests__/lib/paths-filter.mjs:1-49`; `scripts/__tests__/workflow-trigger-comments.test.mjs:124-133`; `scripts/__tests__/paths-filter.test.mjs:1-112`
- Existing verification: paths-filter.test.mjs unit-tests both negation readers, including the fail-closed cases (equal, narrower, wildcard-leading negations) and the fail-open file-type case. [ran_passed]; The PR description says the author mutated filters to remove each input and saw each guard fail. That run's output was not provided. [unknown]
- Missing verification: No test drives a real workflow fixture with a negation through all three guards end to end.
- Mitigation: Review lib/paths-filter.mjs, focusing on the `entry === '**'` short-circuit and on which guard gets the fail-open reader.

**FS-3 · lint-release.yml's justification for not running test:scripts is now slightly out of date** (low impact, observed in the code)

- Trigger: A maintainer relies on the lint-release.yml comment that tests.yml runs test:scripts 'unfiltered on every PR'.
- Mechanism: The comments at lint-release.yml lines 28-29 and 66-67 were not updated. They are still effectively true for the files lint-release watches, because none of them lie under docs/plans/.
- Consequence: A comment slightly overstates coverage. No check is lost today.
- Affects: lint-release.yml rationale comments
- Evidence: `.github/workflows/lint-release.yml:26-29`; `.github/workflows/tests.yml:3-14`
- Missing verification: No test ties those comments to tests.yml's trigger.
- Mitigation: Reword the comment to 'on every PR except plan-only ones'.

### Recommended controls

- Review scripts/__tests__/lib/paths-filter.mjs: the `**` short-circuit, prefix-based negation, and the use of the fail-open negationRemovesAll only in workflow-trigger-comments. (review_focus; FS-2, VG-2)
- After merge, watch the first plan-only PR to confirm Test JS does not start and no check is left pending. Then watch main's push run after it merges. (other; FS-1, VG-1)
- Consider narrowing the negation to '!docs/plans/**/*.md' so a non-markdown file under docs/plans/ still triggers the by-type checks. (other; FS-1)
- Update the lint-release.yml comments that say tests.yml runs test:scripts unfiltered on every PR. (documentation; FS-3)

### What this assessment could not see

- Branch protection, rulesets and required checks are not visible. The test-eql.yml comment that none are required is a claim made at head, not checked here. Whether a skipped Test JS run blocks the merge of a plan-only PR is unknown.
- I did not exhaustively audit every check run by tests.yml for indirect reads of docs/plans/. I checked lint-no-dead-package-paths, which excludes it, and grepped scripts/ for docs/plans and ls-files. An indirect reader I missed would fall under FS-1. Its impact would still be bounded by the push run on main.
- I did not run the tests locally. Test results come only from ci.json check-run conclusions; per-test output was not available. ran_passed rests on the job-level success of Run Tests (Node 22/24), which includes the test:scripts step.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
