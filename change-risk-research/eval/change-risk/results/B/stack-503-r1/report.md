## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** low · `fcb7e336de..c28b5e46fd`

Switches the release workflow from token-based npm publishing to npm OIDC trusted publishing. It removes NPM_TOKEN from the changesets step, upgrades npm globally to a floating ^11.5.1 range, and corrects or adds `repository` metadata (url + directory) on nine published packages so they match cipherstash/stack. Library code is unchanged. The risk is in the release pipeline. With the token fallback gone, publishing depends entirely on npmjs.com-side Trusted Publisher registration for all ten publishable packages (including the unscoped `stash` CLI). None of that registration is visible here, and the repo's own supply-chain skill lists it as deferred, pending npm org admin action. If some packages are registered and others are not, a partial release could ship packages whose pinned internal dependency versions were never published. The new floating npm install also runs inside the id-token: write job without the repo's 7-day release-age cooldown. Nothing in CI can exercise the publish path before merge. The first real verification is the next release on main. SECURITY.md still describes NPM_TOKEN publishing (doc drift, low impact).

### Failure scenarios

**FS-1 · Missing Trusted Publisher registration for some packages produces a partial, dependency-skewed release** (high impact, plausible)

- Trigger: The next merge to main with pending changesets, when npmjs.com has no Trusted Publisher configured for cipherstash/stack + release.yml on one or more of the ten publishable packages (the unscoped `stash`, recently added migrate/wizard/prisma-next, or legacy protectjs-era packages).
- Mechanism: NPM_TOKEN is removed (release.yml:63-68 head), so every package must authenticate through OIDC. The in-repo skill says registration of each package is npm-org-admin work 'tracked separately' and deferred (SKILL.md:110-117). changeset publish runs per package, so registered packages publish and unregistered ones fail (E404/ENEEDAUTH). Sibling dependencies declared as workspace:* are rewritten to concrete versions at publish time.
- Consequence: Some new versions are on npm and others are not. For example, a new `stash` or `@cipherstash/drizzle` can depend on a `@cipherstash/stack`/`@cipherstash/protect` version that does not exist, and installs fail for every consumer until a follow-up release run publishes the rest. Published versions cannot be withdrawn after 72h. If no package is registered, the release fails closed and nothing ships.
- Affects: .github/workflows/release.yml (Release JS), Published npm packages: stash, @cipherstash/{stack,protect,schema,drizzle,nextjs,protect-dynamodb,migrate,wizard,prisma-next}, Downstream npm consumers of internally dependent packages (e.g. stash -> @cipherstash/stack, @cipherstash/migrate; drizzle -> protect, schema)
- Evidence: `.github/workflows/release.yml:57-68`; `packages/cli/package.json:49-67`; `skills/stash-supply-chain-security/SKILL.md:110-117`; `package.json:52`
- Missing verification: Confirmation (screenshot/list from npm org settings) that every one of the ten publishable package names has a Trusted Publisher for cipherstash/stack, workflow release.yml; A dry run or a canary/snapshot publish through OIDC before relying on it for a real version bump
- Mitigation: Before merging, verify Trusted Publisher registration for all ten packages, including `stash`. Merge when no unrelated changesets are pending, or publish a low-risk patch first. Keep the NPM_TOKEN secret available, unused, so it can be restored quickly, and write down the rerun procedure (re-running changeset publish publishes only the missing versions).

**FS-2 · Floating npm@^11.5.1 install runs unvetted code inside the id-token: write publish job** (high impact, plausible)

- Trigger: A new npm 11.x release, malicious (account/registry compromise) or simply broken, appears before or during a release run.
- Mechanism: release.yml:51-52 (head) installs npm by caret range at run time, with no lockfile, integrity pin or release-age cooldown. The repo's 7-day minimumReleaseAge (pnpm-workspace.yaml:21) applies to pnpm only, not to `npm install -g`. That npm then performs the OIDC token exchange and publish for every package. The existing unpinned `npm install -g node-gyp` (base and head line 47) already has the same exposure, so this widens an existing pattern rather than creating a new class.
- Consequence: A compromised npm build could mint publish tokens and push tampered versions of CipherStash encryption packages with valid provenance. A broken one blocks releases (loud).
- Affects: .github/workflows/release.yml (Release JS), Published npm packages: stash, @cipherstash/{stack,protect,schema,drizzle,nextjs,protect-dynamodb,migrate,wizard,prisma-next}
- Evidence: `.github/workflows/release.yml:49-52`; `pnpm-workspace.yaml:21`; `.github/workflows/tests-supply-chain.yml:1-80`
- Existing verification: tests-supply-chain.yml lints release.yml only for disabled caching; it does not check version pinning of global installs. [exists_not_run]
- Missing verification: A lint rule or review check requiring exact versions for global tool installs in release.yml
- Mitigation: Pin an exact npm version (e.g. npm@11.x.y) that is at least as old as the repo's cooldown, or use a Node version that bundles npm >= 11.5.1. Do the same for node-gyp, and extend lint-no-workflow-caching (or a sibling lint) to reject floating global installs in release.yml.

**FS-3 · OIDC path not taken by the actual publisher, so every publish fails closed** (medium impact, speculative)

- Trigger: changeset publish in a pnpm workspace invokes `pnpm publish`, which might not delegate to the upgraded npm 11 or might not perform the OIDC exchange, or the upgraded npm might not be first on PATH after setup-node.
- Mechanism: The head comment (release.yml:49-50) asserts `changeset publish` shells out to the upgraded npm. That depends on @changesets/cli 2.31.0 and pnpm 10.33.2 internals (package.json:52,66), which cannot be checked offline (no node_modules, no network).
- Consequence: The release job fails with auth errors after the version PR merges. No packages ship until the workflow is fixed or NPM_TOKEN is restored. Recoverable, no consumer impact.
- Affects: .github/workflows/release.yml (Release JS), Published npm packages: stash, @cipherstash/{stack,protect,schema,drizzle,nextjs,protect-dynamodb,migrate,wizard,prisma-next}
- Evidence: `.github/workflows/release.yml:49-52`; `package.json:66` (inferred)
- Missing verification: Evidence from a branch/workflow_dispatch dry run that the publish step authenticates via OIDC
- Mitigation: Run a dry-run or canary publish from the workflow before the next real release, and watch the first release run.

### Recommended controls

- Have an npm org admin confirm Trusted Publisher entries (repo cipherstash/stack, workflow release.yml) exist for all ten publishable packages, including unscoped `stash`, before merge. (review_focus; FS-1, VG-1)
- Make the first OIDC release a deliberate, small one (or a snapshot/canary tag), and watch the run. (staged_rollout; FS-1, FS-3, VG-2)
- Keep the NPM_TOKEN secret in place, unused, until a full OIDC release succeeds. Document that re-running changeset publish publishes only the missing versions if a partial release occurs. (rollback_plan; FS-1, FS-3)
- Pin npm (and node-gyp) to exact, cooldown-aged versions in release.yml, and add a lint that rejects floating global installs. (other; FS-2, VG-3)
- Update SECURITY.md:140-141 and skills/stash-supply-chain-security/SKILL.md 'Deferred' section so they reflect OIDC-only publishing. (documentation; )

### What this assessment could not see

- npmjs.com Trusted Publisher configuration and the current state of the NPM_TOKEN secret are outside the repository and were not available. Whether FS-1 occurs depends entirely on that configuration, so the likelihood of FS-1 cannot be judged.
- changesets/action, @changesets/cli and pnpm publish behaviour under OIDC was not verified (no installed dependencies, no network). The claims in the workflow comments (npm/cli#8976, shelling out to npm) were taken as untrusted content and not confirmed. FS-3 is speculative. It may not occur at all.
- No CI results or PR description were provided. Nothing is known to have run. Verification confidence is low.
- The existing unpinned `npm install -g node-gyp` and `pnpm install` without --frozen-lockfile in release.yml predate this change. Noted as context for FS-2. Not attributed to this change.

_Inputs unavailable: pr_description, ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
