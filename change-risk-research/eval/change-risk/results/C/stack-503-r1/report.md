## Change risk: Changes or verification required

**Impact if something goes wrong:** medium · **Verification confidence:** low · `fcb7e336de..c28b5e46fd`

Switches the Release JS workflow from NPM_TOKEN to npm OIDC trusted publishing: removes NPM_TOKEN from the changesets/action env, installs npm@^11.5.1 globally before publishing, and points repository.url (with directory) at cipherstash/stack in 9 publishable package.json files so provenance validation can pass. There is no library code change. The risk is all in the release path. Merging to main runs the publish straight away for 7 pending versions, and whether that works depends on npmjs.com Trusted Publisher configuration made outside the repo for every package. CI cannot verify that. If any package is missing that config, the publish succeeds for some packages and fails for others. That can leave published versions such as @cipherstash/protect@12.0.0 depending on unpublished versions (workspace:* on @cipherstash/schema). The job also installs npm with a floating range in a job that has id-token: write and contents: write. All CI checks passed, but none of them exercise publishing. Minor doc drift: SECURITY.md still says the workflow uses an NPM_TOKEN.

### Failure scenarios

**FS-1 · Partial publish leaves released packages depending on unpublished siblings** (medium impact, plausible)

- Trigger: PR is merged before a Trusted Publisher is configured (or configured with a mismatched repo/workflow) for one or more pending packages, e.g. @cipherstash/schema.
- Mechanism: Merge to main runs Release JS straight away (release.yml:10-13). `changeset publish` publishes each pending package independently, and with NPM_TOKEN gone (base release.yml:59) each package authenticates only through its own Trusted Publisher record. A package without one fails while the others succeed. @cipherstash/protect lists `@cipherstash/schema: workspace:*` as a runtime dependency (packages/protect/package.json:74), which publishes as an exact version pin.
- Consequence: Versions such as @cipherstash/protect@12.0.0 or @cipherstash/prisma-next@0.3.1 can reach the registry while the sibling versions they pin (schema@3.0.0, stack@0.18.0) do not exist, so installs of those versions fail for customers. Published versions cannot be withdrawn after 72h. Recovery means configuring the missing publisher and re-running, or cutting new versions.
- Affects: .github/workflows/release.yml (Release JS), Published npm packages (@cipherstash/protect, protect-dynamodb, schema, stack, wizard, drizzle, nextjs, migrate, prisma-next, stash), Downstream consumers installing the pending versions
- Evidence: `.github/workflows/release.yml:5-13`; `.github/workflows/release.yml:59-68`; `package.json:52`; `packages/protect/package.json:74`; `packages/prisma-next/package.json:82`; pr_description (inferred)
- Existing verification: PR description requires configuring Trusted Publishers for all packages before merge. This is a manual step and cannot be checked from the repo. [unknown]
- Missing verification: Confirmation (screenshot or checklist) that all 10 packages have a Trusted Publisher pointing at cipherstash/stack release.yml with a blank environment.; A dry run or canary publish via OIDC before the real multi-package publish.
- Mitigation: Have an npm org admin confirm the Trusted Publisher config for every pending package before merge. Watch the first Release JS run and check that each of the 7 pending versions is on the registry. If some failed, fix the config and re-run the publish on the new commit straight away.

**FS-2 · Floating npm@^11.5.1 install runs unpinned code in the OIDC-capable release job** (medium impact, plausible)

- Trigger: A new npm 11.x release that is broken or malicious appears between runs (any 11.x >= 11.5.1 is accepted).
- Mechanism: release.yml:52 runs `npm install -g npm@^11.5.1` from the registry with no version pin or integrity lock. The job has id-token: write and contents: write (release.yml:5-8), and the installed npm is the binary that performs the publish. The cache gate does not check version pinning (tests-supply-chain.yml header).
- Consequence: A regression in a new npm minor release breaks publishing for every package (loud). In the worst case, a compromised npm release can mint OIDC tokens and publish trojaned @cipherstash packages with valid provenance. That worst case is a registry-wide supply-chain event, not something this repo controls alone.
- Affects: .github/workflows/release.yml (Release JS), Published npm packages (@cipherstash/protect, protect-dynamodb, schema, stack, wizard, drizzle, nextjs, migrate, prisma-next, stash), Supply-chain cache gate (tests-supply-chain.yml / lint-no-workflow-caching.mjs)
- Evidence: `.github/workflows/release.yml:46-52`; `.github/workflows/release.yml:5-13`; `.github/workflows/tests-supply-chain.yml:3-13`
- Existing verification: 'Verify no caching in release workflows' check passed on head. It covers caching only. [ran_passed]
- Missing verification: No check enforces exact version pins for tools installed in release.yml.
- Mitigation: Pin an exact npm version (e.g. npm@11.x.y) and bump it deliberately. Consider pinning node-gyp in the same job, which is already unpinned at base.

**FS-3 · OIDC auth path not actually taken by changeset publish, so every publish still fails** (low impact, speculative)

- Trigger: changesets/action v1.8.0 still writes or expects an .npmrc token without NPM_TOKEN, or pnpm publish does not delegate to the upgraded npm 11 on PATH.
- Mechanism: The fix depends on two claims this assessment could not check: that changesets/action only writes the token .npmrc when NPM_TOKEN is set, and that `pnpm run release` → `changeset publish` → pnpm publish ends up calling the globally upgraded npm (release.yml:49-52 comment). Neither can be checked offline, and no CI job runs the publish path.
- Consequence: Pending versions stay unpublished, which is the same state as at base. Failures are loud in the Release JS run and nothing wrong is written to the registry.
- Affects: .github/workflows/release.yml (Release JS), Published npm packages (@cipherstash/protect, protect-dynamodb, schema, stack, wizard, drizzle, nextjs, migrate, prisma-next, stash)
- Evidence: `.github/workflows/release.yml:59-68`; `.github/workflows/release.yml:46-52`; pr_description (inferred)
- Missing verification: No CI or dry-run exercise of the OIDC publish path.
- Mitigation: Watch the first post-merge Release JS run. If it fails, the base state is unchanged and a follow-up fix can be made.

### Recommended controls

- Before merge, have an npm org admin confirm a Trusted Publisher (cipherstash/stack, release.yml, blank environment) on all 10 publishable packages, and record that in the PR. (other; FS-1, VG-2)
- Watch the first post-merge Release JS run and check `npm view <pkg>@<version>` for each of the 7 pending versions, plus the provenance attestation. (monitoring; FS-1, FS-3, VG-1)
- If only some packages publish, fix the missing publisher config and re-run straight away. Do not leave dependents pinned to missing versions. Keep the NPM_TOKEN secret until a fully green publish, as the PR proposes. (rollback_plan; FS-1)
- Pin npm to an exact version in release.yml (and node-gyp). (review_focus; FS-2, VG-3)
- Update SECURITY.md:140-141, which still describes NPM_TOKEN-based publishing. (documentation; )

### What this assessment could not see

- No access to npmjs.com (Trusted Publisher config, which versions are already published), repository secrets or Release JS run logs. Cannot confirm the PR's diagnosis of the E404, which versions are pending, or whether the publish will succeed.
- changesets/action v1.8.0 and pnpm 10.33.2 publish internals are not in the checkout, and there is no network access. The claims that no .npmrc is written without NPM_TOKEN and that pnpm publish uses the upgraded npm are taken from the PR description and workflow comments (inferred).
- Assumed that provenance validation compares repository.url with the building repo, as the PR states. Not verified against npm documentation. If that assumption is wrong, the package.json changes are cosmetic metadata only. Either way they do not change runtime code.

_Inputs unavailable: codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
