## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `c8b1325a7e..c379d44a1b`

Documentation and test change with no runtime behaviour change. The source edits in client-v3.ts and wasm-inline.ts are JSDoc and comments only; the raw decrypt/bulkDecrypt methods remain bare delegations with no Date reconstruction, exactly as at base. README and the stash-encryption agent skill (which ships inside the `stash` CLI tarball) now document the raw-vs-model Date boundary and correct the stated reason; I checked the new claims against the code (raw paths delegate unchanged, bulkEncrypt is typed by { table, column }) and found them accurate. New runtime and type-level tests pin the existing boundary; they were not run here (no node_modules, no CI results). The changeset patch-bumps @cipherstash/stack and stash, which publishes doc-only releases. No material failure scenario identified.

No material failure scenarios identified.

### Recommended controls

- Confirm in CI that `vitest run` and `test:types` (vitest --typecheck.only over __tests__/**/*.test-d.ts) pass for packages/stack, since the new type assertions use instantiation expressions on overloaded methods and were not run during this assessment. (test; )
- Reviewer to read the new SKILL.md raw-path note (skills/stash-encryption/SKILL.md:369) for accuracy, since it is copied into customer repositories and is not type-checked. (review_focus; )

### What this assessment could not see

- Tests were not executed: no node_modules in the checkout and no network access; no CI results were supplied. Test status for the new runtime and type tests is exists_not_run; a typecheck failure in the new test-d assertions would surface only in CI (loud, not a release-safety issue).
- No PR description, architecture docs or deployment context were available. Intent was taken from the changeset text and code comments; release mechanics were judged from the changeset and tsup config only.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
