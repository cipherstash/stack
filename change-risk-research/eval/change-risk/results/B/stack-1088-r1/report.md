## Change risk: Focused review required

**Impact if something goes wrong:** low · **Verification confidence:** medium · `b6e6100c84..ac5f088a6e`

Titled as a vitest bump, the change does two things: (1) moves @cipherstash/auth and @cipherstash/profile devDependency vitest from ^3 to the repo catalog (4.1.11), removing vitest 3 from the lockfile; (2) relaxes the CI gate that requires an @cipherstash/auth changeset, adding a `--shipped` filter that drops test/example/config paths and binding manifests whose only change is devDependencies, and diffing with --no-renames. Nothing that ships to npm changes. The main risk is the release guard now failing open for devDependency-only manifest edits, which include @napi-rs/cli, the tool that builds the shipped native binary; the consequence is a toolchain change merged without its own release, not a broken package. The filter fails closed on unreadable/added/deleted manifests and on script errors, and has new unit and workflow-shape tests (not run here).

### Failure scenarios

**FS-1 · Build-toolchain devDependency bump in auth/package.json merges without an auth release** (low impact, plausible)

- Trigger: A PR changes only devDependencies of languages/typescript/packages/auth/package.json, e.g. bumping @napi-rs/cli (used by build:native) or typescript.
- Mechanism: UNSHIPPED_MANIFEST_FIELDS treats every devDependencies change as non-shipping, but @napi-rs/cli is a devDependency that drives `napi build`, which produces the shipped per-platform .node binaries. isShipped returns false, SHIPPED_CHANGES is empty, the workflow exits 0.
- Consequence: The toolchain change lands with no version bump and is picked up silently by the next unrelated auth release; a build regression it introduces surfaces only then, attributed to the wrong change. No published package changes at merge time.
- Affects: .github/workflows/require-auth-npm-changeset.yml, scripts/check-auth-npm-changeset.mjs, @cipherstash/auth npm release process
- Evidence: `scripts/check-auth-npm-changeset.mjs:25-93`; `languages/typescript/packages/auth/package.json:55-114`
- Existing verification: Unit test asserts devDependency-only manifest edits are dropped (intended behaviour), and that version/files/peerDependencies/dependencies/exports changes are kept. [exists_not_run]
- Missing verification: No rule or test distinguishing build-affecting devDependencies (@napi-rs/cli) from test-only ones (vitest).
- Mitigation: Decide explicitly whether @napi-rs/cli changes should require a release; if so, keep it out of the ignored set (e.g. ignore only named test devDependencies).

**FS-2 · Manifest compared against base tip rather than merge-base causes spurious changeset demands** (low impact, plausible)

- Trigger: A long-lived PR touches only auth devDependencies while main has since bumped the auth version (Version Packages PR).
- Mechanism: gitReader reads `$BASE_SHA:path` (base tip) while the path list comes from `BASE...HEAD`; the non-dev fields differ because of main's own change, so isShipped returns true.
- Consequence: Fails closed: the PR is asked for an unnecessary changeset until rebased. Friction only; no unreleased change escapes.
- Affects: .github/workflows/require-auth-npm-changeset.yml, scripts/check-auth-npm-changeset.mjs
- Evidence: `.github/workflows/require-auth-npm-changeset.yml:81-104`; `scripts/check-auth-npm-changeset.mjs:25-93`
- Missing verification: No test with a base that has advanced past the merge-base.
- Mitigation: Read the base side at `git merge-base $BASE_SHA HEAD`, or accept the friction.

**FS-3 · vitest 4 major upgrade changes auth/profile test behaviour** (low impact, speculative)

- Trigger: Running `vitest run` in the auth or profile package under 4.1.11.
- Mechanism: Major-version runner change (defaults, mocking, pools). Configs set only testTimeout, so removed v3 options are not in play.
- Consequence: Most likely a loud test failure in CI; dev-only, nothing shipped changes.
- Affects: auth and profile vitest suites
- Evidence: `languages/typescript/packages/profile/package.json:43`; `pnpm-workspace.yaml:45`; `languages/typescript/packages/auth/vitest.config.ts:1-7`
- Missing verification: CI results for the auth and profile test jobs at head were not provided.
- Mitigation: Confirm the auth and profile `test` jobs pass in CI on this PR.

### Recommended controls

- Reviewer to confirm the policy that all auth devDependencies (including @napi-rs/cli) are non-release-relevant, and the NEVER_SHIPPED list against the package `files` field. (review_focus; FS-1)
- Check CI results for scripts/__tests__/check-auth-npm-changeset.test.mjs and the auth/profile vitest runs before merging. (test; VG-1, FS-3)

### What this assessment could not see

- No CI results and no installed dependencies; no tests executed. All verification is exists_not_run; confidence capped at medium.
- Lockfile diff (249 lines) only spot-checked: vitest 3 entries absent at head, vitest 4.1.11 present. Transitive resolution changes and frozen-lockfile consistency not verified.
- PR description, CODEOWNERS and release workflow behaviour not assessed beyond the guard workflow. How the release pipeline uses changesets is taken from the workflow comment.

_Inputs unavailable: pr_description, ci_results, architecture_docs, dependency_graph, codeowners, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
