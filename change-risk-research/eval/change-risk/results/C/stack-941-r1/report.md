## Change risk: Focused review required

**Impact if something goes wrong:** medium · **Verification confidence:** medium · `c806cfd83c..37c32967ba`

Ports the EQL release pipeline (npm package, eql-bindings crate, SQL bundle, docs bundle, postgres-eql image) from the dead packages/eql/.github/ deposit to root workflows, kept inert by a switch derived from FROZEN_PUBLISHERS in scripts/release-gate.mjs. The only change that is live on merge for already-shipping packages is to the shared release.yml: a new workflow_dispatch trigger and a new `classify` job that every JS/FFI publishing job now depends on and is gated on (`mode == 'production'`). The root rebuild-docs.yml (docs webhook on @cipherstash/stack tags) is also removed. Every EQL publishing path is latent until the cutover deletes the FROZEN_PUBLISHERS entry, and the material risks sit there: an npm release can complete while the SQL/docs/image chain does not, with no automatic re-drive; the SQL attached to the GitHub release and baked into the image is rebuilt from source under `rust = latest` rather than taken from the bytes that shipped on npm; release-plz publishes the crate on its own trigger, independent of the release gate; and the production npm half of the switch is held by a different reader (the gate) than the other four artefacts. CI on the head commit is all green, including the job that runs the script self-tests that pin these gates, but none of the armed paths has ever executed. Impact is medium; verdict focused_review_required, with the latent scenarios best addressed before the cutover rather than before this merge.

### Failure scenarios

**FS-1 · After cutover, npm publishes EQL V but the SQL/docs/image chain does not, and a re-run cannot re-drive it** (medium impact, plausible)

- Trigger: Pipeline armed; on the push that publishes @cipherstash/eql@V, `eql-sql` (or `eql-docs`) fails — e.g. a build failure, the GHCR/release permission not yet in place, or a runner fault — after `release` has already published to npm.
- Mechanism: The EQL production chain keys on `release.outputs.eql_published`, which is computed from changesets' `publishedPackages` in that run (release.yml:508-532). The npm publish happens first and is irreversible. A fresh run (or 'Re-run all jobs') re-runs `changeset publish`, finds V already on npm, emits nothing, and the comment at release.yml:504-507 treats that skip as correct. Only 'Re-run failed jobs' preserves the earlier outputs; there is no workflow_dispatch path to rebuild a production SQL/docs release for an existing version (dispatch against main reclassifies as production and hits the same empty output).
- Consequence: @cipherstash/eql@V (and, independently, the crate) exist with no eql-V GitHub release, docs bundle or image; consumers fetching the SQL bundle by release tag get a 404 until someone hand-builds it. Recoverable manually, but the five-artefact lockstep the PR describes is broken for that version.
- Affects: EQL release workflows (release.yml EQL jobs, _build-eql-sql.yml, _build-eql-docs.yml, release-plz.yml, release-postgres-eql-image.yml), @cipherstash/eql npm package (publish scripts), GitHub release eql-<V> SQL assets and ghcr.io/cipherstash/postgres-eql image
- Evidence: `.github/workflows/release.yml:504-532`; `.github/workflows/release.yml:541-556`
- Existing verification: eql-pipeline-armed.test.mjs asserts which jobs carry the eql-armed guard; it does not model a partial-failure re-run. [ran_passed]
- Missing verification: No test or documented runbook for re-driving eql-sql/eql-docs/eql-image for a version already on npm.; The production EQL chain has never executed in this repository.
- Mitigation: Add a dispatch input (or separate workflow) that rebuilds and attaches the SQL/docs release for an explicit, already-published version; document 'Re-run failed jobs only' in the cutover runbook.

**FS-2 · SQL attached to the GitHub release and baked into the image is rebuilt, not the bytes npm and the crate shipped** (medium impact, plausible)

- Trigger: Pipeline armed; the Rust toolchain resolved by `rust = latest` (or any other build input) differs between the commit that produced the committed SQL and the release run.
- Mechanism: npm and the crate ship the committed, stamped SQL (verify-release-assets.mjs and the release-plz preflight check the stamp). `eql-sql` instead runs `mise run --force build --version V` from source (_build-eql-sql.yml:87), and the image workflow builds again (release-postgres-eql-image.yml:97-100). The mise config pins rust to `latest` (packages/eql/mise.toml:11) and AGENTS.md itself states nothing proves regenerating from source reproduces npm's published bytes. The stamp will agree, so the stamp-based checks cannot detect a byte difference.
- Consequence: Three different SQL payloads can carry the same version: the GitHub release asset's digest disagrees with the npm package's release-manifest, and a database installed from the image or the release asset can carry functions that differ from what `stash eql install` installs at the same version. Silent; no check compares them.
- Affects: GitHub release eql-<V> SQL assets and ghcr.io/cipherstash/postgres-eql image, @cipherstash/eql npm package (publish scripts), eql-bindings crate on crates.io
- Evidence: `.github/workflows/_build-eql-sql.yml:80-124`; `.github/workflows/release-postgres-eql-image.yml:57-100`; `packages/eql/mise.toml:11`; `AGENTS.md:427-430`
- Missing verification: No step compares the rebuilt release SQL (or image SQL) digest with the release-manifest.json committed for V.
- Mitigation: Attach the committed, already-verified SQL from packages/eql/packages/eql/sql (or packages/eql/crates/eql-bindings/sql) instead of rebuilding, or fail the job when the rebuilt digest differs from the committed manifest.

**FS-3 · release-plz publishes the crate on a push the release gate refused** (medium impact, plausible)

- Trigger: Pipeline armed; a push to main touching packages/eql/** carries a crate version not yet on crates.io while release.yml's `gate` fails or `changeset publish` fails (any other package problem, frozen-bytes skew, npm outage).
- Mechanism: release-plz.yml runs on its own `push` trigger and its `release` job is gated only on `eql-armed` (release-plz.yml:26-44, 75-78). eql-pipeline-armed.mjs deliberately does not consult the registry or the gate. Nothing ties the crate publish to the npm publish succeeding in the same commit.
- Consequence: eql-bindings@V is on crates.io (irreversible; can only be yanked) while @cipherstash/eql@V and the SQL release are not, breaking the one-version-five-artefacts invariant until a later release catches up.
- Affects: eql-bindings crate on crates.io, EQL release workflows (release.yml EQL jobs, _build-eql-sql.yml, _build-eql-docs.yml, release-plz.yml, release-postgres-eql-image.yml)
- Evidence: `.github/workflows/release-plz.yml:26-160`; `scripts/eql-pipeline-armed.mjs:24-38`
- Existing verification: The release-plz preflight verifies the committed SQL stamp and manifest match the crate version before publishing. [exists_not_run]
- Missing verification: No check that the npm package at the same version is published (or will be) before the crate goes out.
- Mitigation: Have release-plz.yml check that @cipherstash/eql@<crate version> is on npm before publishing (or dispatch it from release.yml after `release` reports eql_published, as the prerelease path already does).

**FS-4 · Production npm half of the EQL switch is held by a different reader than the other four artefacts** (medium impact, plausible)

- Trigger: Someone relaxes or breaks release-gate.mjs's frozen-publisher refusal while the FROZEN_PUBLISHERS entry remains (or the gate's checks pass because the committed version already exists on npm and a new version is introduced by a path the gate does not see).
- Mechanism: The production `release` job runs `changeset publish` gated on `needs.gate.result == 'success'` only (release.yml:356-363); @cipherstash/eql is not in changesets' ignore list per AGENTS.md. eql-armed gates the other jobs. AGENTS.md:335-356 states nothing asserts the two readers agree.
- Consequence: @cipherstash/eql could be published to npm from this repository (or attempted and fail mid-publish) while eql-armed reports false and the SQL/docs/crate/image all skip — the outcome the derived switch exists to prevent.
- Affects: scripts/release-gate.mjs FROZEN_PUBLISHERS, @cipherstash/eql npm package (publish scripts), EQL release workflows (release.yml EQL jobs, _build-eql-sql.yml, _build-eql-docs.yml, release-plz.yml, release-postgres-eql-image.yml)
- Evidence: `.github/workflows/release.yml:343-363`; `AGENTS.md:335-356`; `scripts/eql-pipeline-armed.mjs:24-38`
- Existing verification: release-gate.mjs runs in CI at PR time ('Lint — this tree can be published' step in the Run Tests job), which passed on the head commit. [ran_passed]
- Missing verification: No test asserting the gate refuses to publish @cipherstash/eql whenever eqlPipelineArmed() is false.
- Mitigation: Add a test (or a guard in the release job) that ties the production EQL npm publish to eql-armed, e.g. fail `release` if publishedPackages contains @cipherstash/eql and armed != 'true'.

**FS-5 · Live JS/FFI releases now depend on the new `classify` job** (medium impact, plausible)

- Trigger: Any push to main (live immediately on merge); `classify` fails or does not output `production` (checkout failure, runner fault, or a later edit to its shell).
- Mechanism: `ffi-artifacts`, `publish-ffi` and `release` now need `classify` and require `mode == 'production'` (release.yml:194-207, 356-358). `release` uses always(), so a failed classify yields an empty mode and the release is skipped rather than failed.
- Consequence: A release that should have published @cipherstash/stack/FFI packages is skipped; the run may not be red for `release`. Recoverable by re-running.
- Affects: release.yml JS/FFI production release (`ffi-artifacts`, `publish-ffi`, `release`)
- Evidence: `.github/workflows/release.yml:36-62`; `.github/workflows/release.yml:194-207`; `.github/workflows/release.yml:343-363`
- Existing verification: workflow-dispatch-job-conditions.test.mjs models a dispatch against main classified as production and requires every non-prerelease job to run; script tests ran in the Run Tests jobs, which passed. actionlint check passed. [ran_passed]
- Missing verification: The first push to main after merge is the first real execution of `classify` on the live release path.
- Mitigation: Watch the first post-merge release run; consider making `classify` failure fail the run visibly (the eql-summary job covers EQL only).

### Recommended controls

- Review release.yml `classify` and the `needs`/`if` changes on `ffi-artifacts`, `publish-ffi` and `release`; these are the only parts live on merge for already-shipping packages. Watch the first post-merge release run. (review_focus; FS-5)
- Before the cutover, make eql-sql (and the image) use or verify against the committed, stamped SQL so the GitHub release and image bytes match what npm and the crate ship. (compatibility_check; FS-2, VG-2)
- Add a test that the production npm publish of @cipherstash/eql is refused whenever eqlPipelineArmed() is false, and a check in release-plz.yml that npm already has the crate's version. (test; FS-3, FS-4, VG-3)
- Add a re-drive path (dispatch with explicit version) for the EQL SQL/docs/image release of an already-published npm version, and document it in the cutover runbook. (rollback_plan; FS-1)
- At cutover, cut a prerelease first through the dispatch path to exercise SQL, docs, npm, crate dispatch end-to-end before the first production final. (staged_rollout; VG-1, FS-1, FS-3)

### What this assessment could not see

- Read closely: release.yml diff, eql-pipeline-armed.mjs, release-plz.yml, release-postgres-eql-image.yml, _build-eql-sql.yml, npm-publish.mjs, verify-release-assets.mjs, lint-release.yml, lint-no-workflow-caching.mjs, Dockerfile and package.json diffs. Skimmed or not read: _build-eql-docs.yml, AGENTS.md/SECURITY.md/docs plan diffs in full, DEVELOPMENT.md/releasing.md, and most of the 12 changed test files. Defects in the docs reusable workflow or in the detail of the changed tests could be missed.
- Registry and repository configuration (npm/crates.io trusted publishers, GHCR package linkage, secrets such as GPG_PRIVATE_KEY, branch protections, whether DOCS_WEBHOOK_URL still drives a live site) is not visible. Cannot confirm whether the deleted root rebuild-docs.yml was still in use, or who can trigger the new workflow_dispatch paths. Tags pushed with GITHUB_TOKEN would not have triggered that workflow, so it may already have been inert; not verified.
- ci.json shows check-run conclusions only; which steps ran inside each job (e.g. that `test:scripts` executed in 'Run Tests (Node 22)') is inferred from tests.yml at head. ran_passed for script tests rests on the job conclusion plus the workflow definition, not step logs.
- Nothing was executed locally; the PR's verification claims (816 script tests, actionlint, a temporary bump exercise) are author claims. Only CI conclusions from ci.json are treated as run evidence.
- A writer could already run a modified release.yml from a branch before this change, so workflow_dispatch was not treated as a new trust boundary; no environment protections were visible to confirm or refute that. If environment or branch rules previously restricted publishing, the new dispatch path deserves separate review.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
