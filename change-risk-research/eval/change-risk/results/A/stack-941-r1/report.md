## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** low · `c806cfd83c..37c32967ba`

Ports the EQL release pipeline (npm prerelease, SQL release, docs bundle, eql-bindings crate, postgres-eql image) from the never-executed packages/eql/.github/ into root workflows, gated behind a derived switch (eql-armed, true once @cipherstash/eql leaves FROZEN_PUBLISHERS). While @cipherstash/eql is frozen, every EQL publishing job is skipped. The only live change is to release.yml, the workflow that publishes every JS and FFI package. It gains workflow_dispatch, and a new classify job now sits in front of ffi-artifacts, publish-ffi and release. The change also deletes the @cipherstash/stack docs-rebuild webhook workflow. The most material risk is latent. Once armed, the production SQL/docs/image chain (eql-sql -> eql-docs -> eql-image) has no status-check function and sits downstream of publish-ffi, which is skipped on any release that moves no FFI version. Under GitHub's implicit success() semantics it is then likely skipped, so the npm package and crate would ship without the SQL release, docs or image. The guards that would catch this only check condition text, and they model only the FFI-included case. The live JS release path changes look correct on reading, but no CI result was available. Advisory: focused review before merge, and the chain must be fixed or rehearsed before the Phase-5 cutover.

### Failure scenarios

**FS-1 · After cutover, an EQL-only release publishes npm and crate but silently skips the SQL release, docs and image** (medium impact, plausible)

- Trigger: Pipeline armed (FROZEN_PUBLISHERS entry deleted), and a Version Packages merge publishes @cipherstash/eql without moving any @cipherstash/protect-ffi version, so gate reports ffi=false.
- Mechanism: `publish-ffi` is skipped when ffi != 'true' (release.yml:207). `release` survives that only through `always()` (release.yml:356-363). `eql-sql`, `eql-docs` and `eql-image` all need `release`, so `publish-ffi` is a transitive ancestor, and their `if:` has no status-check function (release.yml:541-581). GitHub then applies an implicit `success()`, which is false when any ancestor job was skipped. The release job's own comment states the direct-dependency half of this rule. The transitive half is platform behaviour I could not confirm offline. The FFI publish set is computed purely from the protect-ffi prefix, so an EQL-only release is the ordinary case (release-gate.mjs:56,80).
- Consequence: The npm package and (separately, via release-plz.yml) the crate ship at V, but no eql-<V> GitHub release, SQL assets, docs bundle or postgres-eql image is produced. This breaks the one-version, five-artefact contract the pipeline exists to keep. eql-summary renders the three jobs as `skipped` and prints no warning when armed and the gate succeeded (release.yml:850-856), so the run reads as normal. Recovery is manual: there is no dispatchable production eql-sql path.
- Affects: .github/workflows/release.yml (JS + FFI + EQL npm publishing), EQL GitHub release, docs bundle and postgres-eql image (eql-sql / eql-docs / eql-image + _build-eql-sql.yml, _build-eql-docs.yml, release-postgres-eql-image.yml), @cipherstash/eql npm package (packages/eql/packages/eql), eql-bindings crate via .github/workflows/release-plz.yml
- Evidence: `.github/workflows/release.yml:194-207`; `.github/workflows/release.yml:343-363`; `.github/workflows/release.yml:541-570`; `.github/workflows/release.yml:572-602`; `scripts/__tests__/workflow-dispatch-job-conditions.test.mjs:405-413`; `scripts/release-gate.mjs:56-81`; `.github/workflows/release.yml:850-856`
- Existing verification: workflow-dispatch-job-conditions.test.mjs evaluates job conditions, but its PERMISSIVE_NEEDS fixes gate.ffi='true' and publish-ffi='success', so the FFI-skipped case is never modelled. [exists_not_run]; eql-pipeline-armed.test.mjs asserts the armed guard text is present on exactly ten jobs; it does not evaluate needs/skip propagation. [exists_not_run]
- Missing verification: A condition test (or a dry run on a fork) with gate.ffi='false' and publish-ffi skipped, asserting eql-sql/eql-docs/eql-image still run.; A rehearsal of the armed production path before the Phase-5 cutover.
- Mitigation: Give eql-sql, eql-docs and eql-image an explicit status function keyed on the direct results, e.g. `always() && needs.release.result == 'success' && …` (and `needs.eql-sql.result == 'success'` downstream). Make eql-summary flag armed + eql_published=true with eql-sql skipped as an error.

**FS-2 · Once armed, any branch with a `chore(release):` HEAD can publish an EQL prerelease to npm and crates.io without review** (medium impact, plausible)

- Trigger: After cutover, someone with dispatch rights runs release.yml against an unmerged branch whose HEAD subject starts `chore(release):` and pins an X.Y.Z-(alpha|beta|rc).N version.
- Mechanism: classify selects prerelease for any non-main branch with that subject (release.yml:84-121). prerelease-eql-npm holds id-token: write and publishes from github.sha of that branch (release.yml:642-654). prerelease-eql-crate creates or force-moves release/eql-<V> to that SHA and dispatches release-plz.yml there (release.yml:756-786). release-plz.yml accepts workflow_dispatch from any ref (release-plz.yml:26-44). No `environment:` with required reviewers appears on these jobs. The commit message states that safety 'is the marker commit, the version regex and the tag short-circuit — not the branch name'.
- Consequence: Unreviewed package contents are published irreversibly under @cipherstash/eql and eql-bindings, with provenance naming cipherstash/stack. Exposure is limited by the prerelease dist-tag (PRE_GA_LATEST=false) and by semver prerelease matching on crates.io. Write-access users could already run arbitrary workflow code from a branch, so this lowers the effort more than it widens who can do it.
- Affects: .github/workflows/release.yml (JS + FFI + EQL npm publishing), @cipherstash/eql npm package (packages/eql/packages/eql), eql-bindings crate via .github/workflows/release-plz.yml
- Evidence: `.github/workflows/release.yml:613-640`; `.github/workflows/release.yml:642-654`; `.github/workflows/release.yml:756-786`; `packages/eql/packages/eql/scripts/npm-publish.mjs:16-19`; `git -C repo log --format=%B c806cfd83c5bff9df8d76a886f1658d6c9a5521c..37c32967ba73a69c10db604445c663bab92f1807`
- Existing verification: workflow-publish-permissions.test.mjs pins which jobs may hold id-token/contents write; it does not constrain the ref a publish can come from. [exists_not_run]
- Missing verification: Confirmation of the npm and crates.io trusted-publisher configuration (environment constraint) and of repository environment protection rules, neither visible here.
- Mitigation: Put prerelease-eql-npm, prerelease-eql-crate and release-plz.yml's release job behind a GitHub environment with required reviewers, and bind the npm/crates.io trusted publishers to that environment; or restrict prerelease dispatch to protected release/* branches.

**FS-3 · classify becomes a new prerequisite of every JS and FFI publish** (low impact, speculative)

- Trigger: The `classify` job fails or is cancelled on a push to main (checkout or runner failure), or the run is a dispatch against a non-main ref.
- Mechanism: ffi-artifacts, publish-ffi and release now require `needs.classify.outputs.mode == 'production'` (release.yml:194-207, 343-358). If classify does not succeed, mode is empty, so release is skipped despite `always()`. On main the classification is a plain branch-name comparison (release.yml:84-85), so a wrong verdict is unlikely.
- Consequence: No @cipherstash/stack / protect-ffi release and no Version Packages PR update for that push. The failure is loud (job failure) and recovered by re-running.
- Affects: .github/workflows/release.yml (JS + FFI + EQL npm publishing), @cipherstash/protect-ffi packages and @cipherstash/stack et al. (published through release.yml)
- Evidence: `.github/workflows/release.yml:36-43`; `.github/workflows/release.yml:58-130`; `.github/workflows/release.yml:194-207`
- Existing verification: workflow-dispatch-job-conditions.test.mjs asserts release, publish-ffi and ffi-artifacts run under a modelled main dispatch with mode=production. [exists_not_run]
- Missing verification: A CI run of release.yml on main after merge (no CI results were provided).
- Mitigation: Watch the first push-to-main release run after merge; re-run on a classify failure.

**FS-4 · Docs site no longer receives a rebuild webhook on @cipherstash/stack releases** (low impact, speculative)

- Trigger: A @cipherstash/stack tag is pushed by a human or a PAT (the only case in which the deleted workflow could have fired).
- Mechanism: rebuild-docs.yml is deleted (base lines 1-17) and nothing at head posts DOCS_WEBHOOK_URL. The author claims it never ran because changesets creates tags with GITHUB_TOKEN. AGENTS.md says the target site is retired. Neither claim can be checked offline.
- Consequence: If the webhook was still in use, the docs site goes stale after a release; easily fixed by a manual rebuild.
- Affects: Docs site rebuild webhook (DOCS_WEBHOOK_URL)
- Evidence: `.github/workflows/rebuild-docs.yml:1-17` (base); `rg DOCS_WEBHOOK_URL repo/.github/workflows (Grep tool, head checkout)`; `git -C repo log --format=%B c806cfd83c5bff9df8d76a886f1658d6c9a5521c..37c32967ba73a69c10db604445c663bab92f1807` (inferred)
- Missing verification: Confirmation (gh run list / docs-site owners) that the webhook is unused.
- Mitigation: Confirm with the docs-site owner before merge; delete the DOCS_WEBHOOK_URL secret if retired.

### Recommended controls

- Review the `if:` conditions of eql-sql, eql-docs and eql-image (release.yml:541-581) against GitHub's skipped-ancestor semantics; add `always() && needs.<direct>.result == 'success'` terms. (review_focus; FS-1)
- Extend workflow-dispatch-job-conditions (or a dedicated test) with an armed, gate.ffi='false', publish-ffi='skipped' context that models implicit success() over transitive needs, and assert that the EQL production chain runs. (test; FS-1, VG-1)
- Before the Phase-5 cutover, dry-run the armed pipeline on a fork or scratch repository for both an EQL-only release and a prerelease dispatch, and check that all five artefacts appear. (staged_rollout; FS-1, FS-2, VG-1)
- Gate the prerelease npm/crate publish jobs and release-plz.yml's release job on a protected GitHub environment, and bind the trusted publishers to it. (other; FS-2, VG-2)
- Watch the first release.yml run on main after merge (JS/FFI path through classify), and make eql-summary fail loudly when armed, eql_published=true and eql-sql did not succeed. (monitoring; FS-1, FS-3, VG-3)
- Confirm with docs-site owners that the @cipherstash/stack DOCS_WEBHOOK_URL rebuild is retired before deleting rebuild-docs.yml. (documentation; FS-4)

### What this assessment could not see

- GitHub Actions' handling of implicit success() over transitive skipped ancestors is taken from platform knowledge; it could not be checked against documentation or a live run offline. FS-1 is plausible_failure rather than observed_defect. If the platform evaluates only direct needs, FS-1 does not occur.
- No CI results, and the project's vitest script suite could not be installed or run. Running scripts/eql-pipeline-armed.mjs locally was not permitted in this session. All verification is exists_not_run; verification confidence is low.
- Repository secrets, environments, branch protection, npm/crates.io trusted-publisher configuration and GHCR package permissions are not visible. Cannot judge who can dispatch the publishing workflows or whether the inert state also depends on external configuration (FS-2).
- Read closely: release.yml (whole diff and the release/gate jobs), release-plz.yml, _build-eql-sql.yml, eql-pipeline-armed.mjs, the release-gate FROZEN map, npm-publish.mjs, verify-release-assets.mjs, lint-release.yml, the rebuild-docs deletion, and the arming, dispatch-condition and permissions tests. Skimmed: release-postgres-eql-image.yml, _build-eql-docs.yml, lint-no-workflow-caching.mjs, AGENTS.md/SECURITY.md/plan edits, and the remaining test edits. Not read: the deleted packages/eql/.github files beyond the stat. A defect inside the image workflow or the docs reusable could be missed; both are inert until cutover.
- Claims that rebuild-docs.yml never ran and that the docs site is retired come from commit messages and AGENTS.md (edited by this change) and are unverified. FS-4 rated low/speculative on that basis.

_Inputs unavailable: pr_description, ci_results, dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
