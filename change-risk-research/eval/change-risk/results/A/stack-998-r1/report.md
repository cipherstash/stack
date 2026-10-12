## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** medium · `e239a73c1f..09ec296f06`

Release-tooling fix in scripts/sync-lockstep-versions.mjs. At the base, bumpCargoPackageVersion threw 'did not find a version line' whenever the crate was already at the target version: String.replace returned an identical string, and the code took that to mean the line was missing. Because the root `version` script (changeset version && node scripts/sync-lockstep-versions.mjs) runs on every release, any release that did not bump @cipherstash/eql failed at this step. At head the function checks that a version line exists before it replaces anything, so an unchanged version returns the manifest as it was. A missing version line still throws. The new unit test pins the no-op case, and the existing test for a missing version line is unchanged. The only release-risk consequence is that non-EQL releases now reach the later steps of the hook (Cargo.lock refresh, skew-gated SQL asset preparation), which those releases could not reach before. Those steps were designed to run on every release, and they fail loudly rather than silently. Impact is low. Normal review is enough.

### Failure scenarios

**FS-1 · Non-EQL releases now reach the lock refresh and skew-gated asset steps that they previously never ran** (low impact, plausible)

- Trigger: A release with changesets that do not bump @cipherstash/eql, so the crate is already at V (3.0.5 at head) when the hook runs.
- Mechanism: At the base, the hook threw in step 2 for an unchanged version, so steps 3 and 4 never ran on a non-EQL release. At head, step 2 is a no-op and main() goes on to run `mise exec -- cargo update --package eql-bindings` against every discovered lock, then prepareBindingAssets. If the tree carries any lockstep skew at an unchanged version (a manifest, digest or SQL stamp that disagrees), prepareBindingAssets rebuilds the SQL under an already released number. AGENTS.md says that can produce a digest the registry does not carry, which then trips the release gate. A failure in cargo or mise in the release job would also stop the version step.
- Consequence: In the worst case the release job fails loudly at the version step or at the gate, and no Version Packages commit or publish happens. Nothing silent or irreversible results. The base already failed every non-EQL release at this step, so this is not a regression against the base.
- Affects: .github/workflows/release.yml changesets/action version step, Cargo.lock files that resolve eql-bindings from a path (e.g. packages/protect-ffi), EQL bundled SQL assets and release manifests
- Evidence: `scripts/sync-lockstep-versions.mjs:500-541`; `scripts/sync-lockstep-versions.mjs:458-498`; `AGENTS.md:451-465`
- Existing verification: The unit test for an unchanged version, and the existing missing-version-line test, in scripts/__tests__/sync-lockstep-versions.test.mjs, which `pnpm run test:scripts` runs in tests.yml. [exists_not_run]; prepareBindingAssets has a post-rebuild skew check that throws rather than leave a partial tree. [exists_not_run]
- Missing verification: No end-to-end run of `pnpm run version` on a changeset set that leaves EQL's version unchanged, confirming that the lock refresh is a no-op and that the asset step reports 'skipped'.
- Mitigation: Before merging, or on the next non-EQL Version Packages run, confirm that the hook logs '(skipped)' for bundled SQL assets and that the git diff of the Cargo.lock files is empty.

### Recommended controls

- On the first non-EQL release after merge, check the release job log for 'bundled SQL assets (skipped)' and check that the Version Packages commit does not touch Cargo.lock or the EQL SQL and manifests. (review_focus; FS-1, VG-1)

### What this assessment could not see

- No CI results were provided, and the vitest suite was not run (repo/node_modules is absent and network access is not allowed). Test status is exists_not_run. The claim that the new and existing unit tests pass is inferred from reading the code.
- I did not read eqlLockstepSkew in full or the mise release:prepare_bindings_assets task, and I cannot know whether the tree at release time carries skew. Whether FS-1's rebuild branch would actually fire on a non-EQL release is unknown. The design comments say it should skip.
- PR description, CODEOWNERS and deployment context were not inputs. The author's intended verification and the reviewers are unknown.

_Inputs unavailable: pr_description, ci_results, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
