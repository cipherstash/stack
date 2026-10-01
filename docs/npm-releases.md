# npm releases (changesets)

> Adopts [changesets](https://github.com/changesets/changesets) for the `@cipherstash`
> npm products while release-plz keeps owning the Rust crates. Tracking issue:
> [CIP-3278](https://linear.app/cipherstash/issue/CIP-3278). Covers the full
> loop: **versioning** (the Version Packages PR) **and publishing** (the native
> matrix workflows, auto-triggered when a version bump lands on `main`).

## Why

Releasing the `stack-auth` **crate** (release-plz → crates.io) is independent of
publishing the `@cipherstash/auth` **npm package** that binds to it. Hand-editing
the npm `package.json` version caused real drift (an unintended `0.39.0` publish, a
`0.40.0`/`0.38.0` mismatch, a reconstructed changelog — see PR #2057).

We do **not** want lock-step version numbers. We want a reliable, low-ceremony
npm release workflow — the same [changesets](https://github.com/changesets/changesets)
flow used in `cipherstash/stack`.

## The two-tool seam

release-plz and changesets coexist because they partition by **language +
registry** and never read or write each other's files:

| | release-plz | changesets |
|---|---|---|
| Reads/writes | `Cargo.toml`, `Cargo.lock`, Rust `CHANGELOG.md` (via `cliff.toml`) | `package.json`, npm `CHANGELOG.md`, `.changeset/*.md` |
| Publishes to | crates.io | npm |
| Tags | `stack-auth-v…`, `cipherstash-client-v…` | `@cipherstash/auth@…` / "Version Packages" PR |

## How a release works

1. **Contributor**: change a JS/TS package, then `npx changeset` (from repo root,
   after a root `npm install`) → pick package(s) + bump level + summary → commit
   the generated `.changeset/*.md` with your code. No hand-edited versions or
   changelogs.
2. **On merge to `main`**: `.github/workflows/release-npm.yml` runs the
   `changesets/action`, which opens/updates a **"Version Packages" PR** applying
   the accumulated bumps to `package.json` + `CHANGELOG.md` (and re-syncs the root
   `package-lock.json` via the `version-packages` script).
3. **Cut the release**: merge the Version Packages PR.
4. **Publish (automated)**: merging step 3 bumps each product's
   `node/package.json` on `main`. Each publish workflow
   (`publish-auth-npm.yml`, `publish-profile-npm.yml`) is **path-filtered on its
   own `node/package.json`**, so the bump triggers it; a `preflight` job then
   publishes **only if that version is not already on npm** (so any other push
   touching `package.json` is a no-op). It builds the napi matrix (+ wasm for
   auth) and publishes, reading the version changesets just wrote. The release
   workflow itself deliberately does **not** publish — napi packages need the
   matrix build the bespoke workflows own.

The seam: `release-npm.yml` versions; the `publish-*-npm.yml` matrix workflows
publish. The **Version Packages PR merge is the single human gate** — there is no
separate publish approval, matching `cipherstash/stack` (whose pure-JS packages
let `changesets/action` publish inline; ours can't because of the native matrix).

## Scope

- **Managed**: `@cipherstash/auth` (`packages/stack-auth/node`),
  `@cipherstash/profile` (`packages/stack-profile/node`).
- **Not managed** (build artifacts / private): the `npm/*` platform sub-packages
  (`@cipherstash/auth-darwin-x64`, …) — stamped from the main version at publish
  time (`publish-auth-npm.yml:198-221`); the `0.0.0-pre` wasm package; and
  non-product packages (`load-tests`, health-checks). Excluded purely by the
  `workspaces` globs in the root `package.json` — the `.changeset/config.json`
  `ignore` list is empty (see "Validation log" for why it was dropped).

## What this validates

- `changeset status` discovers **exactly** `@cipherstash/auth` and
  `@cipherstash/profile`, ignoring the platform sub-packages and wasm. (See
  "Validation log" below.)
- The root manifest is `private: true` and lists only the two products, so it has
  no effect on crates / release-plz.

## npm workspaces decision (resolved)

The root `package.json` introduces **npm workspaces** where there were none, so
the effect on the existing `npm install` steps was checked empirically:

- **The napi build is unaffected.** The publish pipeline's only Node dependency
  is the `napi` binary (`@napi-rs/cli`); the products have **zero runtime
  `dependencies`**. After a workspace install, `npx napi` still resolves from
  `packages/stack-auth/node/node_modules/.bin`, so `napi build` / `napi
  artifacts` work exactly as before — **no change to `publish-auth-npm.yml` is
  needed**.
- **Only the two products are in the workspace.** The other nested JS packages
  (`load-tests`, `health-checks/typescript`, `usage-metrics-tracker`,
  `cts-web`) are **not** matched by the `workspaces` globs — verified `npm
  prefix` from `load-tests/` returns its own dir and `npm ci` there still
  resolves against its own lockfile, so `test-load-tests.yml` (the only `npm ci`
  user) is untouched.
- **One lockfile is the source of truth.** A root `package-lock.json` governs
  the workspace; the per-package lockfiles under `stack-auth/node` and
  `stack-profile/node` are removed (npm ignores them in workspace mode). The
  build uses `npm install` (not `npm ci`), so it adapts platform-specific
  optional deps per runner.

The release workflow installs only the changesets CLI
(`npm ci --no-workspaces --ignore-scripts`), so the versioning job never
touches the napi toolchain.

### Operational notes

- **"Allow GitHub Actions to create and approve pull requests" must be on.**
  Without it, `release-npm.yml` runs green but silently opens no Version Packages
  PR (a 403 the workflow can't self-guard). Repo → Settings → Actions → General.
- **First `@cipherstash/profile` publish.** Profile and its `@cipherstash/profile-*`
  platform sub-packages are not yet on npm; the first Version Packages merge that
  bumps profile creates them. Auth is already published, so its guard skips until
  the next bump.
- **CHANGELOG handover.** The first `changeset version` will prepend a
  changesets-formatted section above the existing hand-written history (same
  `## x.y.z` shape), so no migration is required; merging this PR with no
  pending `.changeset/*.md` is a no-op.

### Still deferred (follow-ups, not blocking this PR)

- **npm provenance / OIDC trusted publishing.** The matrix workflows authenticate
  with `NPM_TOKEN`. Moving to OIDC trusted publishing (as `cipherstash/stack`
  does) would add provenance attestations; it needs per-package npm config and a
  GitHub-hosted publish runner.
- **Optional publish approval gate.** Publishing is gated only by the Version
  Packages PR review/merge. If a stricter gate is wanted, add a GitHub
  Environment (e.g. `npm-publish`) with required reviewers to the `publish` jobs.

## Extending to Python / C# / Ruby (and future stack-encrypt, stack-zerokms)

Changesets is npm-only — it does not generalize to PyPI / NuGet / RubyGems. The
principle that **does** generalize:

> One core crate per product (release-plz → crates.io). N language bindings, each
> its own artifact in its own registry, versioned independently, joined by
> **convention, not by a shared version number**.

| Binding | Registry | Tool options |
|---|---|---|
| Rust core | crates.io | release-plz (in place) |
| JS/TS + wasm | npm | changesets (this doc) |
| Python (PyO3/uniffi) | PyPI | release-please / python-semantic-release / maturin + bump |
| C# (uniffi) | NuGet | release-please (.NET) / MinVer / Nerdbank.GitVersioning |
| Ruby (magnus/uniffi) | RubyGems | release-please (Ruby) / rake release |

Two cross-cutting standards keep N tools manageable as products × languages grow:

1. **Provenance over lock-step.** Every binding artifact records the exact core
   crate **version + git SHA** it was built from (a metadata field in
   `package.json` / `pyproject.toml` / `.csproj` / `.gemspec`, ideally also a
   runtime constant). That is the real "in sync": not equal numbers, but "this
   published binding provably wraps core X.Y.Z @ sha".
2. **A uniform CI shape.** A reusable "binding release" workflow parameterized by
   `(product, language, registry)` — matrix build → stamp version + provenance →
   publish — instead of copy-pasting `publish-*-npm.yml` per product/language.

### Decision deferred to a second ticket

Two "intent" models would coexist: release-plz/cliff derive changelogs from
**conventional commits**; changesets uses **explicit `.changeset/*.md` files**.
Fine for two tools; confusing across five ecosystems. Options:

- **(A)** Per-ecosystem idiomatic tools + the provenance standard (recommended
  near-term).
- **(B)** Converge all bindings on `release-please` (multi-language), keep
  release-plz for crates, drop changesets.
- **(C)** Changesets as a polyglot intent layer with custom appliers for non-npm
  manifests.

Recommend **(A)** now; revisit **(B)** deliberately when a second binding
language is greenlit. Bake in provenance + the reusable workflow from the first
non-Rust binding regardless of which intent model wins.

## Validation log

Run during development with two throwaway changesets (since removed):

```
$ npx @changesets/cli status
info Packages to be bumped at patch:
- @cipherstash/auth
info Packages to be bumped at minor:
- @cipherstash/profile
info NO packages to be bumped at major
```

- Both products are discovered and bump independently (auth→patch, profile→minor).
- The `npm/*` platform sub-packages and the wasm package are **not** in the
  project at all: an early `ignore: ["@cipherstash/auth-*", …]` config was
  *rejected* with "not found in the project", which confirms changesets never
  enumerates them. The `ignore` list was therefore dropped as unnecessary.
