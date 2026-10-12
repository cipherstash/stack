## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `760ba20a8b..67dcd0b562`

The change makes the `stash` CLI pin every package it installs or recommends (@cipherstash/stack, the integration adapter, stash itself, and the one-shot @cipherstash/wizard run) to exact versions embedded at build time from sibling workspace manifests, and adds a version-skew check on already-installed packages that, interactively, offers to reinstall them at the embedded version. It touches no encryption, payload or key-handling code; the risk is release-train coherence. Because Changesets versions packages independently (`fixed: []`) and stash only peer-depends on @cipherstash/stack with a wide range, a sibling can release without a new stash release, leaving the published CLI pinning older versions. Init would then install the older release and, for projects already on the newer one, report it as skew and offer (default yes, bundled with any missing installs) to downgrade it. Pins also turn an unpublished train version (e.g. a partial publish) into a hard install failure where a bare install used to succeed. Unit, CLI E2E and a built-artifact embed check exist and the CI jobs passed, but none covers newer-than-expected installs or registry availability. Overall impact medium; focused review recommended.

### Failure scenarios

**FS-1 · Published CLI's pins go stale when a sibling releases alone; init installs, and offers to downgrade to, an older release** (medium impact, plausible)

- Trigger: A release bumps @cipherstash/stack (or an adapter) without a `stash` changeset, e.g. stack 1.0.0-rc.2 ships while stash stays 1.0.0-rc.1; or a user runs an older cached `npx stash` against a project already on a newer release.
- Mechanism: Versions are fixed into the CLI bundle at its build time (tsup.config.ts:33-58). Changesets versions packages independently (`fixed: []`) and stash only peer-depends on @cipherstash/stack with `>=1.0.0-rc.0` under onlyUpdatePeerDependentsWhenOutOfRange, and has no dependency at all on the adapters or wizard, so a sibling release does not force a stash release. The published stash then keeps pinning the previous versions. versionSkew compares exact strings (install-deps.ts:74), so a NEWER installed version is reported as skew; interactively the align specs are pushed into the same install command (install-deps.ts:216-221) behind a confirm whose default is yes (install-deps.ts:226).
- Consequence: Fresh `stash init` installs a release older than the current rc (the inverse of #661, now deterministic rather than dist-tag dependent), potentially reintroducing bugs fixed in the newer rc. A user who already upgraded and presses Enter (often because a missing adapter is being installed in the same prompt) has @cipherstash/stack/adapters downgraded. Recoverable by reinstalling, but silent unless the warning is read.
- Affects: stash init install-deps step, CLI build (packages/cli/tsup.config.ts) and published `stash` bundles, Sibling package manifests (stack, stack-drizzle, stack-supabase, prisma-next, wizard), Changesets release pipeline (release.yml -> `pnpm run release`), Customer projects and coding agents running `stash init` / reading .cipherstash/context.json
- Evidence: `packages/cli/tsup.config.ts:33-58`; `.changeset/config.json:5-12`; `packages/cli/package.json:68-78`; `packages/cli/src/commands/init/steps/install-deps.ts:64-77`; `packages/cli/src/commands/init/steps/install-deps.ts:175-228`; `packages/cli/src/commands/init/utils.ts:30-47`; `packages/cli/src/commands/init/steps/__tests__/install-deps.test.ts:153-237`
- Existing verification: install-deps unit tests cover skew where the installed version is OLDER (0.19.0) than expected, accept/decline and non-interactive paths; CI 'Run Tests' jobs passed. [ran_passed]
- Missing verification: No test for an installed version NEWER than the embedded one (direction-aware skew).; No release-process check that stash is republished whenever a release-train sibling is published.
- Mitigation: Make the release train coherent: add the train packages to a Changesets `fixed` group (or a CI check that a stash changeset accompanies any train-package changeset). In init, only offer alignment when the installed version is older, or make the align a separate confirm defaulting to No.

**FS-2 · A pinned version that is not on npm turns init and `stash wizard` into hard install failures** (medium impact, plausible)

- Trigger: A release-train manifest carries a version that was not (or not yet) published: a partially failed `changeset publish`, a package bumped but whose publish was rejected, or a train member not intended for publishing.
- Mechanism: The embed takes whatever version is in the workspace manifest at build time (tsup.config.ts:33-41) regardless of registry state; release builds all packages then publishes them (package.json:34). Install and the wizard spawn now request exactly that version (install-deps.ts:221/253, wizard/index.ts:48), where the previous bare name would have resolved some published version.
- Consequence: Every `stash init` for that CLI version fails to install the affected package (ETARGET/404), leaving init reporting 'Still missing'; `stash wizard` fails to start when not locally installed. Loud, but publishing is irreversible so the fix is a new release.
- Affects: stash init install-deps step, stash wizard command, Sibling package manifests (stack, stack-drizzle, stack-supabase, prisma-next, wizard), Changesets release pipeline (release.yml -> `pnpm run release`)
- Evidence: `packages/cli/tsup.config.ts:33-58`; `packages/cli/src/release-train.ts:18-25`; `package.json:34`; `packages/cli/src/commands/wizard/index.ts:48`; `packages/cli/src/commands/init/steps/install-deps.ts:221-253`
- Existing verification: release-train test asserts each train manifest exists and has a version (does not check publishability). [ran_passed]
- Missing verification: No check that every embedded version is published (or about to be published) before the CLI that pins it is published.; Whether @cipherstash/wizard@0.5.0-rc.1 and @cipherstash/prisma-next@0.4.0-rc.1 exist on npm could not be checked (no registry access).
- Mitigation: Post-publish smoke step that runs `npm view <pkg>@<embedded version>` for each train entry; publish train siblings before stash; consider falling back to the bare spec with a warning on ETARGET.

**FS-3 · Turbo build cache can reuse a CLI bundle with stale embedded adapter/wizard versions** (medium impact, plausible)

- Trigger: A local or cached `turbo build` after only stack-drizzle, stack-supabase, prisma-next or wizard manifests changed, whose output is then published or tested.
- Mechanism: The stash build task hashes `$TURBO_DEFAULT$` inputs of the CLI package plus upstream workspace deps (turbo.json:6); the adapters and wizard are not CLI dependencies, so changes to their package.json do not invalidate the CLI build, yet tsup reads them.
- Consequence: A CLI bundle pins outdated adapter/wizard versions without any build failure. The release workflow runs on a fresh GitHub runner with no cache restore configured, which reduces likelihood there.
- Affects: CLI build (packages/cli/tsup.config.ts) and published `stash` bundles, Sibling package manifests (stack, stack-drizzle, stack-supabase, prisma-next, wizard)
- Evidence: `turbo.json:4-8`; `packages/cli/src/release-train.ts:18-25`; `package.json:34`
- Existing verification: runtime-versions-embed e2e test compares the built bundle to current manifests, which would detect a stale cached bundle where it runs (CI test job, not release.yml). [exists_not_run]
- Missing verification: Release workflow does not run the embed check before `changeset publish`.
- Mitigation: Add the sibling manifests to the CLI build task's turbo `inputs` (or disable caching for the CLI build), and/or run the embed e2e check in release.yml before publishing.

### Recommended controls

- Review install-deps.ts:175-226: whether aligning existing installs should share the missing-install confirm with default Yes, and whether newer installed versions should be treated as skew at all. (review_focus; FS-1, VG-1)
- Put release-train packages in a Changesets `fixed` group or add a CI rule requiring a `stash` changeset whenever a train package has one, so the published CLI's pins track sibling releases. (compatibility_check; FS-1, VG-2)
- Add a unit test for installed-newer-than-expected and a post-publish smoke check (`npm view` per embedded pin) in release.yml. (test; FS-1, FS-2, VG-1, VG-2)
- Include sibling manifests in the CLI build's turbo inputs and run the embed e2e check before publish. (other; FS-3)

### What this assessment could not see

- No npm registry access: could not check which versions of the train packages are published or what dist-tags point at. FS-2 trigger likelihood is unknown; it is not ruled out.
- CI results are job-level only; inclusion of the new tests (e.g. runtime-versions-embed e2e in the CLI E2E step of 'Run Tests') is inferred from workflow config, not observed per test. ran_passed claims rest on job conclusions; individual test execution not confirmed.
- Test files were skimmed for case coverage, not read line by line; skills documentation changes were read but not cross-checked against other shipped docs. Codeowners and architecture docs were not inputs. Possible missed gaps in test assertions or docs drift; impact assessment unaffected.
- Omitted co-change signals (build-schema.ts, doctor/index.ts) were spot-checked only: build-schema.ts contains no install guidance; doctor/index.ts was not read. An unpinned install hint in doctor could remain; low impact.

_Inputs unavailable: architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
