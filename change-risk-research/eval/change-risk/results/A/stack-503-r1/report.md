## Change risk: Changes or verification required

**Impact if something goes wrong:** critical · **Verification confidence:** low · `fcb7e336de..c28b5e46fd`

The change switches the npm release job from a long-lived NPM_TOKEN to npm OIDC trusted publishing. It removes NPM_TOKEN from the changesets/action step, adds a step that globally installs npm@^11.5.1 inside the job that holds id-token: write, and points repository.url (with directory) at cipherstash/stack for the published packages, which provenance requires. There is no library code change. The risk sits entirely in the release pipeline. The new auth path can only be exercised by a real publish on main, and its success depends on npm-side configuration that cannot be seen here: each of the 10 public packages must be registered as a trusted publisher for cipherstash/stack + release.yml. The first release after merge is therefore the test. If only some packages publish, the published packages pin workspace siblings at versions that never reached the registry, and npm releases cannot practically be undone. The floating npm range also adds unpinned code to the job that can mint publish credentials. Removing the long-lived token is a security improvement. SECURITY.md and the supply-chain skill still describe NPM_TOKEN / OIDC as deferred (documentation drift, low impact).

### Failure scenarios

**FS-1 · Partial release: some packages publish via OIDC, others fail, leaving published dependents pinned to unpublished sibling versions** (high impact, plausible)

- Trigger: A release run on main where at least one bumped package is not registered as a trusted publisher for cipherstash/stack + release.yml on npmjs.com. Other triggers are a package that has never been published (a trusted publisher cannot be configured for it) or a provenance repository mismatch.
- Mechanism: Without NPM_TOKEN (release.yml:63-68 head), each package's publish succeeds only if npm accepts the OIDC exchange for that package name. `changeset publish` (package.json:52) publishes every bumped package and reports failures per package. A run can therefore publish e.g. @cipherstash/drizzle, whose workspace:* dependency on @cipherstash/schema (packages/drizzle/package.json:70-71) has been rewritten to a version that failed to publish. The skill at head states that each package must be registered by an npm org admin (SKILL.md:117). That registration is not visible here.
- Consequence: Users installing the newly published dependent get ETARGET / no matching version for the sibling until a follow-up release fixes it. Published versions cannot practically be unpublished, so the broken version stays on the registry.
- Affects: .github/workflows/release.yml (Release JS job), Published npm packages: @cipherstash/stack, protect, schema, drizzle, nextjs, protect-dynamodb, migrate, wizard, prisma-next, stash, Downstream consumers installing packages with workspace:* sibling dependencies (drizzle→protect/schema, protect→schema, protect-dynamodb→protect, cli→stack/migrate, migrate/prisma-next→stack)
- Evidence: `.github/workflows/release.yml:57-68`; `package.json:52`; `packages/drizzle/package.json:70-71`; `packages/protect/package.json:74`; `packages/cli/package.json:49-67`; `skills/stash-supply-chain-security/SKILL.md:110-117`; `.changeset/config.json:1-14`
- Existing verification: No test or dry run in the repo exercises npm OIDC publishing. tests-supply-chain.yml checks only cache settings. [unknown]
- Missing verification: Confirmation, from npmjs.com settings, that all 10 public packages (including stash, @cipherstash/migrate, @cipherstash/wizard and @cipherstash/prisma-next) have a trusted publisher for cipherstash/stack, workflow release.yml.; A first OIDC publish observed end-to-end, e.g. of a low-risk prerelease or a single package, before a multi-package release.
- Mitigation: Before merge, verify the trusted-publisher registration for every public package. Merge when no changeset is pending, or release a single low-dependency package first. Keep the NPM_TOKEN secret and a revert ready until one OIDC release has succeeded.

**FS-2 · Unpinned npm@^11.5.1 is fetched into the job that can mint npm publish credentials** (critical impact, plausible)

- Trigger: A malicious or broken npm 11.x release is the latest 11.x when a release runs on main.
- Mechanism: release.yml:49-52 (head) runs `npm install -g npm@^11.5.1` from the registry without an exact version or integrity check. The job holds id-token: write (release.yml:5-8). Under trusted publishing, any code in the job can request the OIDC token and exchange it for publish rights to every registered package, with valid provenance. The installed npm is also the binary that performs the publish. The base job used the npm bundled with the Node 22 runtime from setup-node. node-gyp is already installed unpinned in this job (release.yml:46-47), so this widens an existing exposure rather than creating the first one.
- Consequence: A compromised npm build could publish tampered versions of the encryption client libraries. They would carry legitimate provenance and reach customers' applications that handle plaintext and keys. A merely broken 11.x minor would instead make the release fail.
- Affects: .github/workflows/release.yml (Release JS job), Published npm packages: @cipherstash/stack, protect, schema, drizzle, nextjs, protect-dynamodb, migrate, wizard, prisma-next, stash
- Evidence: `.github/workflows/release.yml:5-8`; `.github/workflows/release.yml:49-52`; `.github/workflows/release.yml:46-55`; `.github/workflows/tests-supply-chain.yml:21-80`
- Existing verification: The supply-chain lint checks for caching only, not for unpinned global installs. [exists_not_run]
- Missing verification: A lint rule or review gate that rejects floating version ranges in release.yml install steps.
- Mitigation: Pin an exact npm version (e.g. npm@11.x.y) and bump it deliberately through review or Dependabot. Alternatively, use a Node release whose bundled npm is >= 11.5.1. Consider restricting id-token: write to the publish job or step only.

**FS-3 · First post-merge release fails closed because the OIDC path is not actually used by changesets/pnpm** (medium impact, speculative)

- Trigger: Any release run after merge, if changesets/action v1.8.0 still writes a token .npmrc when NPM_TOKEN is unset, or if `pnpm publish` (pnpm 10.33.2) does not perform the OIDC exchange through npm >= 11.5.1.
- Mechanism: The head comment (release.yml:64-67) shows the author knows a token .npmrc shadows OIDC. Whether v1.8.0 skips writing it when the variable is absent could not be checked, because the action source is not in the checkout. `changeset publish` uses the workspace package manager (packageManager pnpm@10.33.2, package.json:66). The comment asserts it shells out to the upgraded npm, but this was not confirmed.
- Consequence: Every publish fails (401/404). The version PR has already been merged, so main carries bumped, unpublished versions until the auth is fixed and the job re-run. No broken artefact ships.
- Affects: .github/workflows/release.yml (Release JS job), Published npm packages: @cipherstash/stack, protect, schema, drizzle, nextjs, protect-dynamodb, migrate, wizard, prisma-next, stash
- Evidence: `.github/workflows/release.yml:64-67`; `.github/workflows/release.yml:59` (inferred); `package.json:66` (inferred)
- Missing verification: Read changesets/action v1.8.0 .npmrc handling and the publish path of pnpm 10.33.2 (offline sources not available here).
- Mitigation: Confirm both behaviours from upstream sources or a dry run on a fork. Have the revert (restore NPM_TOKEN) ready.

### Recommended controls

- Before merge, an npm org admin confirms that each public package (stack, protect, schema, drizzle, nextjs, protect-dynamodb, migrate, wizard, prisma-next, stash) lists cipherstash/stack / release.yml as its trusted publisher. (compatibility_check; FS-1, VG-1)
- Merge when no changesets are pending, then make the first OIDC release a single low-fan-out package and watch it succeed (with provenance) before the next multi-package release. (staged_rollout; FS-1, FS-3)
- Keep the NPM_TOKEN repository secret, plus a prepared revert that restores it, until one OIDC release has succeeded. Then revoke the token. (rollback_plan; FS-1, FS-3)
- Replace `npm@^11.5.1` with an exact version, and consider extending the supply-chain lint to reject floating ranges in release.yml. (review_focus; FS-2, VG-2)
- Update SECURITY.md (NPM_TOKEN mention) and skills/stash-supply-chain-security/SKILL.md (OIDC listed as deferred) to match. (documentation; )

### What this assessment could not see

- The npmjs.com trusted-publisher configuration, whether every package already exists on the registry, and whether the NPM_TOKEN secret still exists are not visible. FS-1 cannot be confirmed or ruled out. It is the main reason for the verdict.
- The source of changesets/action v1.8.0, @changesets/cli 2.31.0 and pnpm 10.33.2 is not in the checkout (no node_modules, no network). FS-3 rests on inference about how they handle .npmrc and publish delegation.
- No CI results were supplied, and the supply-chain lint could not be run because js-yaml is not installed. No check is recorded as passing.

_Inputs unavailable: pr_description, ci_results, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
