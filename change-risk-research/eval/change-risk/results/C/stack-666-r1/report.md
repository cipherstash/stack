## Change risk: Changes or verification required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `760ba20a8b..67dcd0b562`

The stash CLI now embeds, at build time, the versions of six release-train packages read from sibling workspace manifests, and uses them to pin every install `stash init` performs, every install hint, the context.json installCommand and the one-shot wizard spawn. It also warns on any exact-version mismatch between node_modules and the embed and, interactively, offers (default yes) to 'align' skewed packages. The fix is well tested for the stale-dist-tag case it targets, and CI (unit, E2E incl. a built-artifact embed check) passed. The main release risk is structural: Changesets versions these packages independently (no fixed group) and stash only dev/optional-peer depends on @cipherstash/stack, so a stack or adapter release does not rebuild stash. The embedded pins then go stale: init installs an older @cipherstash/stack/adapter than is current, and for projects already on the newer version it reports 'skew' and offers to downgrade them, which the shipped stash-cli skill tells agents to accept. That reverses the guarantee the PR claims ('can never disagree with what Changesets publishes') once releases stop moving together, e.g. after GA. A secondary, loud risk is a pin naming a version that was never published. Impact is medium; the downgrade path is untested.

### Failure scenarios

**FS-1 · Pins go stale after a sibling release; init installs older packages and offers to downgrade newer ones** (medium impact, plausible)

- Trigger: @cipherstash/stack (or an adapter, prisma-next, wizard) publishes a new version in a release that does not also bump stash, e.g. a stack patch after GA.
- Mechanism: Versions are captured only when stash is built (tsup.config.ts:33-58). Changesets has no fixed/linked group (.changeset/config.json:5-6) and stash depends on @cipherstash/stack only as a devDependency and an optional peer `>=1.0.0-rc.0` with onlyUpdatePeerDependentsWhenOutOfRange (packages/cli/package.json:68-78, config.json:12), so a stack release does not bump or rebuild stash; the adapters and wizard have no dependency edge to stash at all. The latest stash therefore keeps pinning the previous versions. versionSkew flags any inequality, including installed > expected (install-deps.ts:74), and interactively folds the 'align' reinstall into the install confirm with initialValue true (install-deps.ts:175-226). The stash-cli skill tells agents to 'treat that warning as a real problem and align versions' (skills/stash-cli/SKILL.md:39).
- Consequence: Fresh `stash init` silently installs an older encryption client/adapter than is current (missing fixes, potentially security fixes) and records it in context.json; projects already on the newer version get a skew warning, and accepting the default prompt or following the skill downgrades @cipherstash/stack/adapters. `stash wizard` runs an older wizard. Recoverable by reinstalling, but it happens through the official setup path and looks intentional.
- Affects: packages/cli init install-deps step, CLI build-time version embed (tsup.config.ts, release-train.ts, runtime-versions.ts), Release pipeline (Changesets pre-mode, `pnpm run build && changeset publish`), Customer projects running `stash init` / `stash wizard`, Shipped agent skills (skills/stash-*)
- Evidence: `packages/cli/src/commands/init/steps/install-deps.ts:64-77`; `packages/cli/src/commands/init/steps/install-deps.ts:175-227`; `.changeset/config.json:5-13`; `packages/cli/package.json:48-86`; `packages/cli/tsup.config.ts:33-58`; `skills/stash-cli/SKILL.md:39`; `packages/cli/src/commands/init/steps/__tests__/install-deps.test.ts:153-236`; pr_description (inferred)
- Existing verification: Unit tests cover skew where the installed version is OLDER than the embed (0.19.0 vs fixture) and the align path; CI unit runs passed. [ran_passed]
- Missing verification: A test where the installed version is newer than the embedded version (should not offer a downgrade, or should default to no).; A release-process check that stash is republished whenever any RELEASE_TRAIN package is published (or that the pins are allowed to lag).
- Mitigation: Only treat installed < expected (semver compare) as skew to align, and default the align confirm to false or separate it from the missing-install confirm; soften the skill wording. Release side: put the release-train packages in a Changesets `fixed` group, or pin with a range (e.g. ^embedded) after GA so newer compatible releases are accepted.

**FS-2 · An embedded pin names a version that is not installable from npm** (medium impact, speculative)

- Trigger: Within `pnpm run build && changeset publish`, stash publishes but a sibling's publish fails or is delayed, or a manifest carries a version that was never published.
- Mechanism: The build reads all six manifests before publish (package.json:34; tsup.config.ts:33-58), so the embed is whatever the manifests say, not what reached the registry. Previously a bare name always resolved to something; now an exact spec for a missing version fails the install (install-deps.ts pinned commands) and `stash wizard` fails to spawn.
- Consequence: `stash init` cannot install dependencies for every new user of that stash release until another stash release is published (npm publishes are irreversible). Loud, not silent; users can install manually.
- Affects: packages/cli init install-deps step, CLI build-time version embed (tsup.config.ts, release-train.ts, runtime-versions.ts), Release pipeline (Changesets pre-mode, `pnpm run build && changeset publish`), Customer projects running `stash init` / `stash wizard`
- Evidence: `packages/cli/tsup.config.ts:33-58`; `package.json:34`; `packages/cli/src/commands/wizard/index.ts:48`
- Existing verification: release-train.test.ts checks each train manifest exists with a version; it cannot check registry availability. [ran_passed]
- Missing verification: Post-publish smoke check that each embedded name@version resolves on npm before announcing the stash release.
- Mitigation: Add a post-publish step that runs `npm view <pkg>@<version>` for every embedded pin, or publish stash last in the release.

### Recommended controls

- Decide the intended policy for installed > embedded: do not offer a downgrade (semver-compare), and default the align confirm to false or split it from the missing-install confirm. Adjust skills/stash-cli/SKILL.md:39 accordingly. (review_focus; FS-1, VG-1)
- Add install-deps tests for installed-newer-than-embedded in interactive and non-interactive modes. (test; VG-1)
- Put the RELEASE_TRAIN_MANIFESTS packages in a Changesets `fixed` group (or otherwise force a stash release when any of them publishes), or switch to range pins after GA. (compatibility_check; FS-1, VG-2)
- After `changeset publish`, verify every embedded name@version resolves on the registry before the release is announced. (monitoring; FS-2, VG-2)

### What this assessment could not see

- No npm registry access: could not confirm that the currently embedded versions (e.g. @cipherstash/wizard 0.5.0-rc.1, @cipherstash/prisma-next 0.4.0-rc.1) are published. FS-2 trigger likelihood unknown.
- Could not observe how Changesets pre-mode / future GA releases are actually cut (which packages ship together); reasoning is from .changeset/config.json and package.json only. FS-1 trigger depends on release practice; it may be rare during the rc window when most packages move together.
- CI results give check-level conclusions only; individual test outcomes are inferred from those, and the PR's 471/57 counts are unverified claims. ran_passed statuses rest on the check-run conclusions.
- Tests and the four skill version notes were skimmed; install-deps.ts, runtime-versions.ts, tsup.config.ts, release-train.ts and wizard spawn were read closely. Package-manager-specific behaviour of exact prerelease specs (e.g. pnpm minimumReleaseAge cooldowns in customer projects) was not examined. Other install-time failure modes may exist.

_Inputs unavailable: dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
