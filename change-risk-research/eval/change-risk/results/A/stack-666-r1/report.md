## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `760ba20a8b..67dcd0b562`

The CLI (`stash`) now embeds, at build time, the versions of six release-train packages read from sibling workspace manifests, and `stash init` installs `@cipherstash/stack`, the integration adapter and `stash` pinned to those exact versions. The same pinning applies to install hints, `.cipherstash/context.json`'s installCommand, the native-module recovery hint and the `stash wizard` one-shot spawn. Init also reports version skew against already-installed packages and, interactively, offers to 'align' them in the same default-yes confirm. The change touches no encryption, payload or SQL code. The main release risk is a new coupling: the CLI now hard-depends on every pinned version being resolvable on npm. Changesets publishes packages independently (`fixed: []`), so a partial publish or an unpublished train member breaks `init` and `stash wizard` for that CLI release until a new release ships. A second, smaller risk is that skew alignment does not check direction, so an older CLI can offer, defaulted to yes, to downgrade a newer installed runtime. Unit tests and a build-artifact e2e test cover the logic and the embed, but I could not run them and saw no CI results. Overall impact is medium and a focused review is advised.

### Failure scenarios

**FS-1 · Pinned version not resolvable on npm breaks init and wizard for a whole CLI release** (medium impact, plausible)

- Trigger: A published `stash` embeds a train package version that is not on the registry. This can happen through a partial `changeset publish` (stash publishes, a sibling fails), a train member whose current workspace version was never published (for example wizard 0.5.0-rc.1 or prisma-next 0.4.0-rc.1, which could not be checked offline), or a locally built or pre-publish CLI run against the registry.
- Mechanism: Versions are read from workspace manifests at build time (tsup.config.ts:33-58) and used verbatim by pinnedSpec (runtime-versions.ts:88-94). The release builds and then publishes (package.json:34). Changesets versions packages independently and does not publish atomically (.changeset/config.json fixed/linked empty). Before this change, bare names resolved to whatever dist-tag existed, so a missing version did not block install.
- Consequence: `npm install @cipherstash/stack-drizzle@X` (or `npx @cipherstash/wizard@Y`) fails with ETARGET/404 for every new user of that CLI version. Init reports 'Still missing' and its manual-install hints are also pinned to the missing version. Recovery needs a new publish, because npm publishes are irreversible. The failure is loud, with no data impact.
- Affects: stash init install-deps step, Release JS workflow (changesets publish), stash wizard spawn and error-recovery hints (wizard/index.ts, native.ts, missing-package.ts, main.ts, install-eql.ts, write-context.ts), Customer projects running `stash init` / `stash wizard`, Published packages pinned by the CLI (@cipherstash/stack, stack-drizzle, stack-supabase, prisma-next, wizard)
- Evidence: `packages/cli/tsup.config.ts:33-58`; `package.json:34`; `.changeset/config.json:5-6`; `.github/workflows/release.yml:64`; `.changeset/pre.json:2-3`; `packages/cli/src/commands/init/steps/install-deps.ts:270-286`
- Existing verification: release-train.test.ts checks that every train manifest exists and has a version (source mode). runtime-versions-embed.e2e.test.ts checks that the built bundles contain the manifest versions. [exists_not_run]
- Missing verification: No release-time check that every embedded version is actually published (e.g. `npm view pkg@ver` after `changeset publish`, or a smoke `stash init` against the registry).; No check that train packages not bumped in a release have their current workspace version already on npm.
- Mitigation: Add a post-publish smoke step that runs `npm view` for each embedded spec, or a packed `stash init` in a temp project. Consider adding the train packages to a Changesets `fixed` group so they always publish together. Alternatively, fall back to the bare name or a dist-tag when the pinned install fails with ETARGET, with a warning.

**FS-2 · Skew 'align' offers, defaulted to yes, to downgrade a newer installed runtime to an older CLI's versions** (medium impact, plausible)

- Trigger: A user runs an older `stash init` (global install, cached npx, or a stale project-local CLI) in a project whose `@cipherstash/stack` or adapter is newer than the versions that CLI embeds.
- Mechanism: versionSkew flags any inequality (`installed !== expected`, install-deps.ts:74) with no ordering. With a TTY, offerAlign (line 175) adds the skewed packages to the install commands (line 216), and the confirm defaults to true (line 226). The message describes this as aligning 'to this release'.
- Consequence: Pressing Enter reinstalls the project's encryption client and adapter at an older version, which could reintroduce fixed bugs or mismatch the EQL/SQL bundle already installed. The prompt does show the exact commands and the change can be reverted with a reinstall. Non-interactive runs are not affected.
- Affects: stash init install-deps step, Customer projects running `stash init` / `stash wizard`
- Evidence: `packages/cli/src/commands/init/steps/install-deps.ts:64-77`; `packages/cli/src/commands/init/steps/install-deps.ts:175-228`
- Existing verification: install-deps.test.ts covers skew warning, align with the prod/dev split, decline, the non-interactive no-mutation path and an unreadable manifest. It only covers installed versions older than expected. [exists_not_run]
- Missing verification: No test where the installed version is newer than the CLI's embedded version.
- Mitigation: Compare with semver and only offer alignment when the installed version is older, or default the confirm to false when alignment would downgrade. Otherwise, say 'downgrade' explicitly in the prompt.

### Recommended controls

- Add a post-`changeset publish` step to release.yml that runs `npm view <pkg>@<embedded version> version` for every train entry (or `stash init --yes` in a temp project) and fails loudly if any is missing. (test; FS-1, VG-1)
- Before merging, confirm that @cipherstash/wizard 0.5.0-rc.1, @cipherstash/prisma-next 0.4.0-rc.1 and the 1.0.0-rc.1 packages exist on npm, or will be published by the next release together with stash. (review_focus; FS-1)
- Make the align offer direction-aware (or default to No on downgrade) and add a test for installed > expected. (test; FS-2, VG-2)
- If a broken pin ships, publish a patch `stash` immediately. Users can work around it with manual installs of the bare package names. (rollback_plan; FS-1)

### What this assessment could not see

- npm registry state (which train versions are published, dist-tags) could not be checked: no network. Whether FS-1 is already triggered by the current versions is unknown.
- Tests could not be run (no installed dependencies) and CI results were not provided. Verification confidence relies on reading test code only. Whether tsup resolves the `./src/release-train.js` import from its config is only shown by the e2e test, whose result is unknown.
- Skill markdown changes were skimmed, not checked line by line against CLI behaviour. Possible drift in bundled guidance is not assessed in detail.
- Not established whether the `stash` library entry (dist/index.js, imported by users' stash.config.ts) imports runtime-versions. The e2e test comment says it does. If it does, a malformed embed would throw on library import as well as in the CLI. This is guarded by tsup's double JSON.stringify and judged low.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
