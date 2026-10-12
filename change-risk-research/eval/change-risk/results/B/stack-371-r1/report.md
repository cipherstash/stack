## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `cf8ebc2388..d257468c35`

Pure refactor in packages/cli: nine user-facing literals (help banner, usage lines, unknown-command errors, region prompt, cancel text, db migrate stub warning) move into a new src/messages.ts `as const` object, and prod call sites plus the two pty E2E test files import those constants. Every constant is byte-identical to the literal it replaces and is interpolated in the same position, so CLI output does not change. tsup bundles src/bin/stash.ts, so the new module is inlined into dist/bin/stash.js; it is not exported from the library entry. The one residual risk is a weaker guard: E2E assertions now share the source of truth with prod, so a future edit to messages.ts changes user-visible CLI output without any test failing. AGENTS.md guidance for agents is updated to match. Tests were not run (no node_modules, no CI results).

### Failure scenarios

**FS-1 · Future copy edits in messages.ts change CLI output with E2E staying green** (low impact, plausible)

- Trigger: A later change edits a value in src/messages.ts, e.g. renames 'Unknown command' or 'Cancelled.', on purpose or by accident.
- Mechanism: Prod and the E2E assertions read the same constant (messages.ts:12-29; smoke.e2e.test.ts:18-72), so the tests check that the binary prints whatever the constant holds, not that the wording stays stable. At base the tests hard-coded the literals and would fail on such an edit.
- Consequence: User-visible CLI text changes without a failing test. Scripts or docs that match that text could break. CLI stderr text is not a documented contract, so the expected effect is minor and easy to recover from.
- Affects: @cipherstash/cli `stash` binary (dist/bin/stash.js), packages/cli E2E suite (tests/e2e), External scripts or docs that match CLI output text
- Evidence: `packages/cli/src/messages.ts:12-29`; `packages/cli/tests/e2e/smoke.e2e.test.ts:5-72`; `packages/cli/tests/e2e/smoke.e2e.test.ts:17-69` (base)
- Existing verification: E2E still verifies that the built binary emits each constant, exit codes, and the user-supplied token, which guards against call-site regressions. [exists_not_run]
- Missing verification: No snapshot or literal assertion pins the user-facing wording itself.
- Mitigation: Accept as intended design (documented in AGENTS.md). If wording stability matters, add a small unit snapshot of the `messages` object so wording changes show up in review.

### Recommended controls

- Confirm `pnpm exec turbo run test:e2e --filter @cipherstash/cli` passes in CI for this head. That build-and-run also confirms vitest resolves the `../../src/messages.js` import to the .ts source. (test; VG-1)
- Reviewers of future PRs touching src/messages.ts should treat value edits as user-visible output changes, since tests will not flag them. (review_focus; FS-1)

### What this assessment could not see

- No node_modules or dist in the checkout and no network, so the build and tests could not be run. Test status is exists_not_run. Bundling and import resolution are inferred from tsup/vitest config, not observed.
- No PR description, CODEOWNERS input or CI results. Author intent comes from the title and code only. Ownership not assessed.
- The collector flagged usual co-changes (db/install.ts, init/providers/supabase.ts) that are absent here. Checked and judged irrelevant: this change only rewires literals in stash.ts and does not touch the command dispatch those files relate to.

_Inputs unavailable: ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
