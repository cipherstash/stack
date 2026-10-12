## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** low · `760ba20a8b..67dcd0b562`

The `stash` CLI now embeds, at build time, the exact versions of six sibling workspace packages (stash, @cipherstash/stack, the three integration adapters, @cipherstash/wizard). It uses them to pin every package `stash init` installs, every printed install hint, and the `stash wizard` one-shot spawn. `stash init` also gains a version-skew check on packages that are already installed. Interactively, the skew fix goes into the same default-yes confirm as the missing-package installs. The check uses plain string inequality, so a package newer than the embed counts as skew. The CLI is not bumped when only @cipherstash/stack or an adapter is released: stash has only an optional peer edge on stack, and changesets uses onlyUpdatePeerDependentsWhenOutOfRange. So after such a release, init and the shipped stash-cli skill push users and agents to downgrade the encryption client and its adapter to the CLI's older embedded versions (FS-1). Pinning also removes the dist-tag fallback. If any of the six embedded versions is missing from npm, for example after a partial `changeset publish`, init's install and `stash wizard` fail for that CLI release until a new one ships (FS-2). The change contains no encryption, payload or SQL changes. Tests were added for the parser, the skew paths and the build embed. None were run, and none cover an installed version that is newer than the embed. The release-train coupling behind FS-1 is acknowledged as unaddressed in the head commit message.

### Failure scenarios

**FS-1 · After a stack- or adapter-only release, init and the stash-cli skill steer users and agents to downgrade @cipherstash/stack** (medium impact, plausible)

- Trigger: A release bumps @cipherstash/stack and/or an adapter but not stash, for example a stack-only fix changeset. Changesets will not bump stash for this: its only link to stack is an optional peerDependency (>=1.0.0-rc.0), and onlyUpdatePeerDependentsWhenOutOfRange is true. A user who already has the newer stack then runs `npx stash init` with the latest published stash, which carries the older embed.
- Mechanism: versionSkew() flags any `installed !== expected`, including installed versions newer than the embed (install-deps.ts:64-76). Interactively, offerAlign merges `@cipherstash/stack@<older>` (and the adapter) into the same confirm as any missing install, with initialValue true (install-deps.ts:175-227). Accepting the missing-package install therefore also downgrades the encryption client. Non-interactively, init prints downgrade commands, and the shipped stash-cli skill tells agents to 'treat that warning as a real problem and align versions before continuing' (skills/stash-cli/SKILL.md:39). Fresh projects are also pinned to the stale stack instead of the fix release.
- Consequence: Customer projects (and agent-driven setups) get rolled back to an older encryption client and adapter. Fixes in the newer release are lost, and the user is told the newer version is the problem. Recovery is a manual reinstall. A new stash release realigns things, but only once someone notices.
- Affects: packages/cli `stash init` install-deps step, Customer projects running `stash init` (installed @cipherstash/stack, adapters, stash dev dep), Release pipeline: changesets pre-mode + release.yml, Shipped agent skills (skills/stash-cli and sibling skills)
- Evidence: `packages/cli/src/commands/init/steps/install-deps.ts:64-76`; `packages/cli/src/commands/init/steps/install-deps.ts:150-227`; `skills/stash-cli/SKILL.md:39`; `.changeset/config.json:4-12`; `packages/cli/package.json:68-78`; `packages/cli/src/commands/init/steps/__tests__/install-deps.test.ts:153-173`
- Existing verification: install-deps tests cover skew with an OLDER installed version (0.19.0 vs 9.9.9-test.1), decline, non-interactive and unreadable-manifest paths [exists_not_run]
- Missing verification: No test for an installed version NEWER than the embed (should not be offered as a downgrade by default); No release-process check that stash is bumped/republished whenever a release-train sibling is
- Mitigation: Compare with semver and only treat installed < expected (or a placeholder/prerelease mismatch) as skew to fix. Never default-accept a downgrade, and keep the align choice separate from the missing-package confirm. Add stash and the release-train packages to a changesets `fixed`/`linked` group, or add a real dependency edge, so stash is always republished with them. Soften the stash-cli skill wording so agents do not downgrade.

**FS-2 · An embedded version missing from npm breaks init installs and `stash wizard` for that CLI release** (medium impact, plausible)

- Trigger: The stash release embeds a version that is not on the registry. The likely cause is a partial `changeset publish` failure, where stash publishes but a sibling (stack, an adapter or wizard) does not. A sibling whose workspace version is never published would have the same effect.
- Mechanism: tsup embeds whatever version is in each workspace manifest at build time (tsup.config.ts:33-55), regardless of whether npm has it. pinnedSpec() then always emits `pkg@<that version>` (runtime-versions.ts:85-94), and there is no fallback to the dist-tag. The release script runs `pnpm run build && changeset publish` (package.json:34) with no post-publish check that every embedded version resolves. runWizardSpawn runs `npx @cipherstash/wizard@<embedded>` (wizard/index.ts:48).
- Consequence: `stash init` install commands and `stash wizard` fail with ETARGET/E404 for every user of that stash version. Previously the bare names would have resolved. Publishing is irreversible, so the fix is a follow-up release or manually publishing the missing package. The failure is loud and the hints print exact commands, so data is not at risk.
- Affects: packages/cli `stash init` install-deps step, stash CLI build (tsup.config.ts, release-train.ts, runtime-versions.ts), Customer projects running `stash init` (installed @cipherstash/stack, adapters, stash dev dep), Release pipeline: changesets pre-mode + release.yml, `stash wizard` / init wizard handoff
- Evidence: `packages/cli/tsup.config.ts:33-58`; `packages/cli/src/runtime-versions.ts:37-94`; `packages/cli/src/commands/wizard/index.ts:44-48`; `package.json:34`; `.github/workflows/release.yml:58-64`
- Existing verification: release-train.test.ts checks each train manifest exists and has a version; runtime-versions-embed.e2e.test.ts checks the built bundles carry the workspace versions [exists_not_run]
- Missing verification: No check that each embedded version is actually published (or being published in the same run) before or after `changeset publish`
- Mitigation: Add a post-publish step in release.yml that runs `npm view <pkg>@<embedded>` for every release-train entry, or publish stash last. Otherwise, fall back to an advisory (unpinned) install when the pinned spec fails to resolve.

### Recommended controls

- Review install-deps.ts:150-227. Should a newer installed version be offered for 'alignment' by default, and should alignment share the missing-install confirm? (review_focus; FS-1, VG-1)
- Add install-deps tests where the installed stack/adapter is newer than the embed, in both interactive and non-interactive modes, and assert that no downgrade happens by default. (test; FS-1, VG-1)
- Couple the release train in changesets (a `fixed`/`linked` group of stash with stack, the adapters and wizard), or document that every train release must include a stash changeset. (compatibility_check; FS-1, VG-2)
- After `changeset publish` in release.yml, verify that `npm view` resolves every RELEASE_TRAIN_MANIFESTS entry at its embedded version, and fail the job loudly if one does not. (monitoring; FS-2, VG-2)
- Run `pnpm --filter stash test` and `pnpm --filter stash build && pnpm --filter stash test:e2e` (the embed e2e) before merging. No results were available for this assessment. (test; VG-3)

### What this assessment could not see

- No access to the npm registry. Whether the currently embedded versions (e.g. @cipherstash/wizard 0.5.0-rc.1, @cipherstash/prisma-next 0.4.0-rc.1) are published could not be checked. FS-2 cannot be ruled in or out for the next release, so it stays plausible_failure.
- Tests and build could not be run (no node_modules, no network), and no CI results were provided. All existing verification is exists_not_run. Whether tsup resolves the `./src/release-train.js` import from its config, and whether `import.meta.url` resolves sibling manifests correctly in the bundled config, is unverified.
- There was no PR description. The head commit message (read as untrusted data) says the release-train coupling is unaddressed and tracked on the PR. I could not see what that tracking was. FS-1 may already have a planned mitigation that was not visible.
- The skill doc edits for stash-encryption, -supabase and -dynamodb were skimmed. They add the same version-note block as stash-drizzle. The test files were read only for case names and the skew/e2e cases. Minor wording drift in those skills may have been missed.
- The co-change signals (install-deps.ts with build-schema.ts; write-context.ts with setup-prompt and the handoff steps) were not investigated in depth. The change does not alter the interfaces those files share. A low-probability incomplete change outside the diff may have been missed.

_Inputs unavailable: pr_description, ci_results._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
