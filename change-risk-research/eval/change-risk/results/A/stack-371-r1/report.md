## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `cf8ebc2388..d257468c35`

Behaviour-preserving refactor of the @cipherstash/cli package. Seven user-facing literals (help banner/usage prefixes, unknown command/subcommand errors, region prompt, cancel text, db migrate stub warning) are moved into a new internal `src/messages.ts` constant object and imported by both the production call sites and the E2E tests. Every extracted value is byte-identical to the literal it replaces and the surrounding template interpolation (`: ${token}`) is unchanged, so rendered CLI output is the same. messages.ts is bundled into dist/bin/stash.js by tsup (no new entry, export or dependency). The only material side effect is on test semantics: the E2E assertions now read their expected text from the same constants production uses, so they no longer detect a change to that copy, and an emptied constant would make the corresponding `toContain` trivially pass. AGENTS.md guidance is updated accordingly and is not part of the npm package files. Low impact; ready for normal review.

### Failure scenarios

**FS-1 · E2E tests no longer catch regressions in asserted CLI copy** (low impact, plausible)

- Trigger: A later edit changes or empties a value in src/messages.ts (e.g. a typo, or `usagePrefix: ''`), or a scripted consumer relies on the old wording.
- Mechanism: Tests take their expected strings from `messages.*` (smoke.e2e.test.ts lines 18-72, auth-login-cancel.e2e.test.ts lines 11-17), so expected and actual change together; `toContain('')` passes trivially for an emptied constant.
- Consequence: A user-visible copy regression (help banner, error prefix, cancel text) ships without a red test. Output is cosmetic; exit codes are still asserted separately.
- Affects: packages/cli E2E suite (tests/e2e), @cipherstash/cli `stash` binary (src/bin/stash.ts, commands/auth)
- Evidence: `packages/cli/src/messages.ts:12-29`; `packages/cli/tests/e2e/auth-login-cancel.e2e.test.ts:1-19`; `packages/cli/tests/e2e/smoke.e2e.test.ts:14-73`
- Existing verification: Exit codes and user-supplied tokens are still asserted with literals in smoke.e2e.test.ts. [exists_not_run]
- Missing verification: No check that messages.ts values are non-empty or match an intended snapshot.
- Mitigation: Accept as the intended design; optionally add a tiny unit/snapshot test over the `messages` object so copy changes are deliberate.

### Recommended controls

- Confirm `pnpm exec turbo run test:e2e --filter @cipherstash/cli` passes on this head (it builds dist first). (test; VG-1)
- Optionally snapshot the `messages` object (or assert non-empty values) so copy changes show up in review. (test; FS-1)

### What this assessment could not see

- No CI results, CODEOWNERS or PR body were provided; tests were not run (no network for dependency install). Verification confidence is capped at medium; test status is exists_not_run.
- External consumers that scrape CLI output (scripts, customer CI) cannot be enumerated from the repo. Not material here because rendered strings are unchanged, but consumers outside the repo were not checked.

_Inputs unavailable: ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
