# EQL release process

How EQL is released: one workflow, two modes, four artifacts, one version.

## Architecture overview

There is a **single release entrypoint**, `.github/workflows/release.yml`. Its
`classify` job branches on the branch and the head commit:

| Branch | Condition | Mode |
|--------|-----------|------|
| `main` | any push | **production** — final release via Changesets |
| `eql_v3` | head commit subject is `chore(release): …` or `release: …` | **prerelease** — alpha/beta/rc |
| anything else | — | `skip` |

`workflow_dispatch` is available on any ref for manual testing.

Every release — production or prerelease — publishes the same four artifacts at
**one lockstep version `V`**, all from a single source commit:

| Artifact | Where | Git tag |
|----------|-------|---------|
| SQL surface (`cipherstash-encrypt.sql` + uninstaller) + docs bundle | GitHub Release | `eql-V` |
| `eql-bindings` Rust crate | crates.io | `eql-bindings-vV` |
| `@cipherstash/eql` npm package | npmjs.com | `eql-typescript-vV` |
| Postgres + EQL Docker image (production finals only) | `ghcr.io/cipherstash/postgres-eql` | image tags `:<pg>-V` |

There is no separate coordinator workflow and no per-language release task. The
old `release-alpha.yml` coordinator, `release-eql.yml`, and the `mise run
release:*` dispatch tasks were removed when this consolidated onto `release.yml`.

## Lockstep versioning

`@cipherstash/eql`'s `package.json` **version is the single source of truth**
for `V`. Everything else is derived from it, because the SQL surface, the crate,
and the npm package are all generated from one catalog (`eql-domains::CATALOG`)
at one commit.

The root `version` script is the mechanism:

```
pnpm run version  ==  changeset version && node scripts/sync-lockstep-versions.mjs
```

1. `changeset version` consumes the pending `.changeset/*.md` files and bumps
   `packages/eql/package.json` to the next `V`.
2. `scripts/sync-lockstep-versions.mjs` reads that `V` and propagates it:
   - sets `crates/eql-bindings/Cargo.toml` `[package] version = V`;
   - runs `mise run release:prepare_bindings_assets --version V`, which builds
     the **exact-version** SQL (`mise run build --version V`) and copies it —
     plus a sha256 `release-manifest.json` — into both `crates/eql-bindings/sql/`
     and `packages/eql/sql/`.

The result is one "Version Packages" commit where `package.json`, `Cargo.toml`,
and the bundled SQL all agree on `V`. release-plz later publishes the committed
`Cargo.toml` version verbatim (it has no absolute-version config), so the commit
must already carry the pin — which this script guarantees.

**Because all three targets move together, every releasable change needs a
changeset** — including SQL-only or crate-only changes. See `.changeset/README.md`.

## Production release (`main`)

Final releases use the standard two-step Changesets flow:

1. **Merge feature PRs to `main`.** Each carries a changeset. On each push to
   `main`, `release.yml`'s `release` job runs `changesets/action`, which opens or
   updates a **"Version Packages" PR** (running `pnpm run version` above — the
   lockstep bump).
2. **Merge the "Version Packages" PR.** With no pending changesets left, the
   `changesets/action` run instead executes `publish` (`pnpm run release` =
   `pnpm run build && changeset publish`) and publishes `@cipherstash/eql` to
   npm under the `latest` dist-tag (npm OIDC trusted publishing).

When the publish succeeds, the rest of `release.yml` fans out on the same commit:

- `build-sql` → creates and attaches the SQL installer/uninstaller to the
  `eql-V` GitHub Release, and fires the Multitudes production-deploy
  notification.
- `build-docs` → attaches the `eql-docs-*` bundle.
- `build-image` → dispatches `release-postgres-eql-image.yml` to build and push
  the multi-arch Postgres + EQL images, including the floating `:latest` /
  `:<pg>` / `:V` tags (production finals only).

The **Rust crate** publishes in parallel: merging the Version PR is a push to
`main`, which triggers `release-plz.yml` (publish-only — versioning is owned by
Changesets, not release-plz). It publishes the committed `Cargo.toml` `V` to
crates.io and tags `eql-bindings-vV`.

### Changelog

The release changelog is owned by **Changesets** — generated from the
`.changeset/*.md` files, not hand-edited. Changesets writes *per-package*
changelogs, so the file it maintains is **`packages/eql/CHANGELOG.md`**; since
SQL, the crate, and the npm package release in lockstep at one version, that
file is the changelog for the whole release. (The root `CHANGELOG.md` is the
frozen pre-3.0 archive and is no longer appended to.) Every releasable change
adds a changeset (`pnpm changeset`): its frontmatter selects the bump
(`patch`/`minor`/`major`) and its body becomes the entry. `changeset version`
(run in the "Version Packages" PR for finals, and locally in pre-mode when
pinning a prerelease) writes the versioned section and computes `V`. See
`.changeset/README.md` and the **"Release & changelog discipline"** section of
`CLAUDE.md`.

## Prerelease / alpha (`eql_v3`)

Prereleases are cut from the `eql_v3` feature branch. Unlike the production path,
the prerelease path does **not** run Changesets in CI — it publishes a version
that is **already pinned** in the repo.

1. **Enter pre-mode and pin the version locally.** Changesets pre-mode
   (`.changeset/pre.json`, `mode: "pre"`, `tag: "alpha"`) is what makes
   `changeset version` emit `X.Y.Z-alpha.N`. Run `changeset version` (which also
   runs `sync-lockstep-versions.mjs`) so `packages/eql/package.json`,
   `Cargo.toml`, and the bundled SQL all carry the prerelease identity.
2. **Commit with the release marker and push to `eql_v3`.** The commit subject
   must be exactly `chore(release): …` — that marker is what `classify` keys
   on (a bare `release:` prefix is deliberately NOT a marker, so an unrelated
   commit can't trigger a publish). `classify` reads the version from
   `package.json`, **rejects the run** if it is not prerelease-shaped (`*-*`),
   and **skips** it if the `eql-typescript-vV` tag already exists (the identity
   was already released — re-pushing a marker never republishes).

   > **Access model:** a prerelease publish is gated by push access to
   > `eql_v3` (plus this marker convention) — there is no separate release
   > approval or commit-signature gate. Branch protection on `eql_v3` is the
   > control; keep force-push restricted and reviews required there.
3. `release.yml` then runs the prerelease jobs:
   - `prerelease-build-sql` / `prerelease-build-docs` → create the prerelease
     `eql-V` GitHub Release with SQL + docs.
   - `prerelease-publish-npm` → publishes `@cipherstash/eql@V` (dist-tag `alpha`
     via `scripts/npm-publish.mjs`) and creates the `eql-typescript-vV` tag.
     Both steps are idempotent (`npm view` / `git ls-remote` guards) so a rerun
     after a partial failure converges.
   - `prerelease-publish-rust` → pins a `release/eql-V` **branch** at the
     release commit and dispatches `release-plz.yml` against it, so the crate
     publishes from the exact commit the SQL + npm artifacts shipped from even
     if `eql_v3` has advanced since. (A branch, not the `eql-V` tag:
     release-plz refuses detached HEADs.) release-plz also refuses to publish
     if the committed `crates/eql-bindings/sql/` bundle wasn't prepared for
     the crate's version (the DEV-placeholder guard).

Prereleases keep the pending changesets **unconsumed** — Changesets pre-mode
emits a `X.Y.Z-alpha.N` entry but the changesets are only finalized into the
release section when the final version is cut — and **do not** build the Docker
image (floating tags must not move for an alpha; build one on demand via the
image workflow's `workflow_dispatch`).

```bash
# Cut the prerelease (after the chore(release): commit is on eql_v3):
gh workflow run release.yml --ref eql_v3

# Dry-run the same flow on a scratch branch that contains the marker commit:
gh workflow run release.yml --ref <scratch-branch>
```

> **Footgun — exit pre-mode before a final release.** `.changeset/pre.json`
> lives on `eql_v3`. If it reaches `main`, `changeset version` there will emit
> alpha-suffixed "final" versions. Run `changeset pre exit` (and merge that)
> before cutting a production release from `main`.

## Artifacts & tag namespaces

Three independent git tag families, all keyed to the same identity `V`:

- **`eql-V`** (e.g. `eql-3.0.0`, `eql-3.0.0-alpha.2`) — the EQL **SQL surface**
  GitHub Release (installer + uninstaller + docs bundle). Drives the Docker
  image (production) and any `push: tags` consumers.
- **`eql-bindings-vV`** — the **`eql-bindings` Rust crate** on crates.io.
- **`eql-typescript-vV`** — the **`@cipherstash/eql` npm package**.

The npm dist-tag is `latest` for finals — and, **until 3.0.0 final ships**,
also for prereleases (the alphas are the only release line, so `latest`
tracks the newest alpha; see `PRE_GA_LATEST` in
`packages/eql/scripts/npm-publish.mjs`). After GA, prereleases return to
their channel dist-tag (`alpha` / `beta` / `rc`). Each language package bundles the **exact** self-contained
SQL it was generated against (`eql_bindings::sql`; npm `./sql` subpath), so a
consumer pins wire types and the matching DDL together.

## The `GITHUB_TOKEN` dispatch model

Why some steps run inline and others are dispatched: **a release or a tag created
using the automatic `GITHUB_TOKEN` does not trigger downstream `on: release` /
`on: push` workflows** — but a `workflow_dispatch` (or `repository_dispatch`)
*initiated* by `GITHUB_TOKEN` **does**. So `release.yml`:

- builds + attaches SQL and docs **inline** (reusable `_build-sql.yml` /
  `_build-docs.yml`);
- publishes npm **inline**;
- **dispatches** the crate publish (`release-plz.yml`) and the Docker image
  (`release-postgres-eql-image.yml`) via `gh workflow run`.

In production the crate publish is triggered by the human merge of the Version PR
(a real push to `main`), so release-plz runs from its own `on: push: main`. In
the prerelease path, `release.yml` dispatches release-plz explicitly.

Dispatched jobs are fire-and-forget: `release.yml` does not block on the
release-plz or image runs — check them in the Actions tab.

## Verify

The durable PR gate is `.github/workflows/lint-release.yml`: actionlint over the
release workflows, ShellCheck over `tasks/release/prepare-bindings-assets.sh`,
and the supply-chain cache guard (`lint:workflow-cache`) plus the script unit
tests (`test:scripts`). The generated-surface drift gates (`mise run
types:check`, `mise run codegen:parity`) run in the main test workflow.

Ordering guarantee — **a failed docs build blocks the package publish** — because
`prerelease-publish-npm` (and `-rust`) `needs` the docs job. To validate on a
scratch branch without a real publish: temporarily force the docs reusable to
fail, dispatch `release.yml` against the scratch branch, and confirm no publish
runs. Revert before any real release.

### Smoke-test a release

Install the standalone `eql_v3` surface into a clean database (no `eql_v2`):

```bash
gh release download eql-3.0.0-alpha.N -p 'cipherstash-encrypt.sql'
psql "$DATABASE_URL" -f cipherstash-encrypt.sql
psql "$DATABASE_URL" -c "\dn eql_v3"                 # eql_v3 schema present
psql "$DATABASE_URL" -c "SELECT eql_v3.version();"   # released semver
```

Confirm the lockstep tags point at one commit:

```bash
git fetch --tags
git rev-list -n1 eql-3.0.0-alpha.N
git rev-list -n1 eql-bindings-v3.0.0-alpha.N
git rev-list -n1 eql-typescript-v3.0.0-alpha.N
```
