## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `760ba20a8b..67dcd0b562`

The stash CLI now embeds, at build time, the workspace versions of six sibling packages (stash, @cipherstash/stack, -drizzle, -supabase, prisma-next, wizard) and pins every install it runs or recommends (init installs, missing-package hints, context.json installCommand, native-module hint, wizard npx spawn) to those exact versions. Init also adds a version-skew check that warns on any installed version that differs from the embedded one and, interactively, offers (default yes) to reinstall the embedded version. The change fixes a real dist-tag problem and is well unit- and E2E-tested (CI green). The residual risk is release-mechanical: the repo's Changesets config does not version these packages together and stash has no runtime dependency on the adapters or wizard, so a published stash pins whatever sibling versions sat in the workspace at its build. Two consequences reviewers should weigh: (1) after a sibling ships without a stash bump, init treats the newer sibling as 'skew' and offers to downgrade it, and the stash-cli skill tells agents to align; (2) if a pinned sibling version is not actually on the registry (partial publish), every pinned install and the wizard spawn fail where a bare install used to succeed, and only a new release fixes it. Neither is shown to occur; both are plausible. Overall impact medium; focused review recommended.

### Failure scenarios

**FS-1 · Stale pin after a sibling-only release makes init offer to downgrade a newer @cipherstash/* package** (medium impact, plausible)

- Trigger: A release publishes a newer @cipherstash/stack or adapter (e.g. a fix) without a changeset for stash; a user who has that newer version installed then runs stash init with the latest stash.
- Mechanism: Packages are not versioned together (.changeset/config.json fixed: [] and linked: []), and stash declares @cipherstash/stack only as a devDependency/optional peer with no dependency on the adapters or wizard, so a sibling bump does not necessarily republish stash. The published stash keeps the versions embedded at its own build. versionSkew() compares strings with !==, so a NEWER installed version is reported as skew; interactively the align is folded into a confirm with initialValue: true and installs pkg@<older embedded version>. The stash-cli skill tells agents to 'treat that warning as a real problem and align versions'.
- Consequence: Users or agents downgrade the encryption client or adapter to an older release, potentially reverting a fix (including a security fix) and changing package.json/lockfile, while the CLI frames the newer version as the problem. New installs also never receive the newer sibling until stash itself is re-released.
- Affects: stash CLI init install-deps step, Sibling npm packages (@cipherstash/stack, stack-drizzle, stack-supabase, prisma-next, wizard), Customer projects and coding agents running stash init
- Evidence: `packages/cli/src/commands/init/steps/install-deps.ts:64-77`; `packages/cli/src/commands/init/steps/install-deps.ts:214-228`; `skills/stash-cli/SKILL.md:39`; `packages/cli/package.json:48-78`; `.changeset/config.json:5-6`
- Existing verification: install-deps.test.ts covers skew where the installed version is OLDER (0.19.0) than expected; no case for a newer installed version. [ran_passed]
- Missing verification: A test (and a decision) for an installed version newer than the embedded one.; A release-process check that every release of a train package also re-releases stash, or that the pin set is refreshed.
- Mitigation: Only warn/offer alignment when the installed version is lower (semver compare) or on a different major/prerelease line; never default-confirm a downgrade. Alternatively add the train packages to a Changesets fixed/linked group, or enforce that stash is bumped whenever a train package is. Soften the stash-cli skill wording for newer-version skew.

**FS-2 · Pinned sibling version not on the registry breaks init installs and stash wizard for every new user** (medium impact, plausible)

- Trigger: During changeset publish, stash publishes but a sibling's publish fails or is skipped (publishes are per-package), or a sibling's workspace version is otherwise never published.
- Mechanism: The embed is taken from workspace manifests at build time (pnpm run build && changeset publish), not from what the registry accepted. The installs and the wizard runner now request pkg@<exact version>; npm/pnpm fail with ETARGET/404 if that version does not exist. Previously the bare name always resolved to something.
- Consequence: stash init fails to install dependencies (step reports still-missing packages) and stash wizard fails to launch for all users of that stash version; because npm publishes are irreversible, recovery requires publishing the missing sibling or a new stash release. Failure is loud, not silent.
- Affects: stash CLI build (tsup.config.ts) and release pipeline, Sibling npm packages (@cipherstash/stack, stack-drizzle, stack-supabase, prisma-next, wizard), stash wizard / init handoff spawn, Customer projects and coding agents running stash init
- Evidence: `packages/cli/tsup.config.ts:33-58`; `.github/workflows/release.yml:60-64`; `packages/cli/src/commands/wizard/index.ts:44-48`; `.changeset/config.json:5-6`
- Existing verification: runtime-versions-embed E2E test asserts the built bundles embed the workspace versions; it does not check registry availability. [ran_passed]
- Missing verification: A post-publish smoke check that every embedded pkg@version resolves on npm before or immediately after the release.; Knowledge of current registry state for prisma-next 0.4.0-rc.1 and wizard 0.5.0-rc.1 (unavailable here).
- Mitigation: Add a release-workflow step after changeset publish that runs npm view for each embedded spec and fails loudly; consider publishing stash last; keep a documented manual fallback (bare install) in the error path.

### Recommended controls

- Decide the intended behaviour when the installed version is newer than the pin; restrict the align offer to older/incompatible versions and avoid a default-yes downgrade. (review_focus; FS-1, VG-1)
- Ensure stash is re-released whenever a train package is released (Changesets fixed/linked group or a release-time check). (compatibility_check; FS-1)
- Post-publish check in release.yml that every embedded pkg@version resolves on npm, failing the workflow otherwise. (monitoring; FS-2, VG-2)
- Add an install-deps test with a newer installed version and assert the chosen behaviour. (test; VG-1)

### What this assessment could not see

- No access to the npm registry, dist-tags or publish logs; whether the pinned versions (e.g. @cipherstash/prisma-next 0.4.0-rc.1, @cipherstash/wizard 0.5.0-rc.1) are published is unknown. FS-2 likelihood cannot be judged; it is kept as plausible_failure.
- Test files were skimmed by test names and a few cases; the native.ts, missing-package and write-context changes were read only at the diff level. Minor edge cases in those hint paths may be missed; they only change printed text.
- CI job-to-step mapping: the CLI E2E step lives in the 'Run Tests (Node N)' jobs per tests.yml; individual step results were not visible, only job conclusions. ran_passed for the embed E2E test relies on the job conclusion including that step.
- CODEOWNERS and deployment context unavailable; the claim that a sibling bump does not republish stash rests on Changesets semantics for devDependencies/optional peers, not on an executed changeset version run. FS-1 mechanism partly inferred.

_Inputs unavailable: dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
