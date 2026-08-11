---
name: stash-supply-chain-security
description: Supply-chain security controls for the @cipherstash/stack monorepo. Covers post-install script policy (onlyBuiltDependencies), install cooldown (minimumReleaseAge), lockfile integrity (blockExoticSubdeps + lockfile registry check), frozen-lockfile CI, registry pinning (.npmrc), Dependabot cooldown, CODEOWNERS, and npm OIDC trusted publishing / provenance (including claiming a new package name). Use when modifying CI workflows, pnpm config, dependency updates, .github/dependabot.yml, release.yml, publishing a package to npm for the first time, or anything that touches how packages enter the build.
---

# Supply Chain Security

Controls applied in this repo to limit blast radius from compromised npm packages, lockfile injection, dependency confusion, and rushed dependency upgrades. Sourced from [lirantal/npm-security-best-practices](https://github.com/lirantal/npm-security-best-practices) and adapted for our pnpm workspace.

## When to Use This Skill

- Modifying any file under `.github/workflows/`
- Editing `pnpm-workspace.yaml`, `package.json` `pnpm` block, or `.npmrc`
- Updating `.github/dependabot.yml` or `.github/CODEOWNERS`
- Adding a dependency that needs a build script (i.e. `node-gyp`, `node-pty`, prebuilt binaries)
- Bypassing the install cooldown for a security fix
- Publishing a package to npm under a name that has never been published before
- Reviewing a PR that touches any of the above

## What's Enforced (Config + Test Gate)

Each control below is validated by `e2e/tests/supply-chain.e2e.test.ts` — the test suite fails CI if a control regresses, so silent removal isn't possible.

### 1. Post-install scripts disabled by default — practice #1

pnpm 10+ disables lifecycle scripts globally and only runs them for packages on the `onlyBuiltDependencies` allowlist.

- **Where**: `package.json` `pnpm.onlyBuiltDependencies`
- **Current allowlist**: `["node-pty"]` (PTY tests need the native module built)
- **Test asserts**: allowlist length ≤ 3 — adding a fourth entry forces explicit review

### 2. Install cooldown — practice #2

New package versions wait 7 days before they're eligible for install. Mirrors the Dependabot cooldown so manual + automated updates have the same community-discovery window.

- **Where**: `pnpm-workspace.yaml` `minimumReleaseAge: 10080` (minutes)
- **Test asserts**: ≥ 4320 minutes (3 days)

### 3. Lockfile injection prevented — practices #4, #16

Two layers:

- `pnpm-workspace.yaml` `blockExoticSubdeps: true` — pnpm refuses to install transitive deps that come from git or direct tarballs (pnpm ≥ 10.26)
- A test parses `pnpm-lock.yaml` and asserts every resolved tarball URL starts with `https://registry.npmjs.org/`

(Why not `lockfile-lint`? It only supports npm/yarn lockfiles. The pnpm-native test gives us the same protection.)

### 4. Frozen lockfile in CI — practice #5

CI uses `pnpm install --frozen-lockfile`. If `pnpm-lock.yaml` and any `package.json` drift, the install aborts — no silent registry fetches that bypass the locked versions.

- **Where**: every workflow under `.github/workflows/`, and every local composite action under `.github/actions/`
- **Test asserts**: no `pnpm install` step anywhere in that graph is missing `--frozen-lockfile`

The check used to read `tests.yml` alone, and `release.yml` — the one workflow
that publishes to npm — ran a bare `pnpm install` the whole time. The single
install allowed to resolve outside the lockfile was the one whose output goes to
the registry.

### 5. Cooldown'd auto-updates — practice #6

Dependabot opens grouped, cooldown'd PRs (7 days minor/patch) for `npm`, `cargo` and `github-actions`. Major bumps are not proposed at all — every entry ignores `version-update:semver-major`, so majors are reviewed and applied by hand.

There is deliberately **no `semver-major-days` cooldown** on any entry. It would delay major *version update* PRs, which the `ignore` above means Dependabot never opens, and cooldown does not reach the security path either ("the cooldown option is only available for version updates, not security updates"). Don't add one back as a safety net for the day the `ignore` is dropped — dead config reads as policy, and the test below fails on the pair.

`cargo` covers the in-tree Rust workspace at `packages/protect-ffi` (**not** the repo root — that is where `Cargo.toml`/`Cargo.lock` live). It runs monthly rather than weekly because each bump costs a native rebuild to validate, and it ignores the exact-pinned CipherStash crates (`cipherstash-client`, `cts-common`, `stack-auth`, `stack-profile`, `eql-bindings`, `vitaminc`) — they share a release train with the `@cipherstash/auth` catalog and must be bumped together, manually.

- **Where**: `.github/dependabot.yml`
- **Test asserts**: cooldown ≥ 3 days on npm/github-actions; every entry ignores `version-update:semver-major` for `*` **and** sets no `semver-major-days` (both ends, so neither half can drift alone); every lockfile present in the repo maps to a monitored `package-ecosystem`; every entry's `directory` actually contains the manifest its ecosystem reads

The ecosystem-coverage assertion is derived from the filesystem, so **adding a lockfile for a new language fails the suite until `dependabot.yml` covers it.** Two lockfiles are exempt because Dependabot has no ecosystem for them (`e2e/wasm/deno.lock`, `.flox/env/manifest.lock`); both are named with their reason in the test.

Note that `ignore` conditions suppress Dependabot **security** PRs too, not just version updates. The compensating control is OSV: `.github/workflows/osv-scanner.yml` scans `--recursive ./`, which reaches every lockfile in the tree (including `Cargo.lock`) and reports to code scanning.

### 6. Registry pinning — practice #16

`.npmrc` pins both the default registry and the `@cipherstash` scope to `https://registry.npmjs.org/`. Auth tokens stay in user-level `~/.npmrc` or env vars — never committed.

- **Test asserts**: `.npmrc` contains both pin lines and no `_authToken` / `NPM_TOKEN`

### 7. Governance (CODEOWNERS)

`.github/CODEOWNERS` requires `@cipherstash/developers` review for every supply-chain critical file. Combined with branch protection (configured in repo settings, not in this repo), this prevents single-actor changes to the chain.

- **Test asserts**: CODEOWNERS lists each critical path

## What's Documented but Not Enforced

These controls depend on developer environment or org-level configuration — we describe them here but don't gate CI on them.

### Harden installs locally — practice #3

For local installs of new packages, consider running them through one of:

- [`npq`](https://github.com/lirantal/npq) — security checks, package age, typosquatting, provenance: `npq install <pkg>`
- [Socket Firewall (`sfw`)](https://socket.dev) — real-time blocker for known-malicious packages: `sfw pnpm add <pkg>`

Neither is required, but they're cheap insurance when adding a new direct dependency.

### 2FA on npm accounts — practice #10

Every maintainer with publish access to `@cipherstash/*` should have:

```bash
npm profile enable-2fa auth-and-writes
```

Releases no longer depend on this — `release.yml` publishes via OIDC and holds no
long-lived token (see "Publishing" below). 2FA still matters for the manual
publishes that OIDC can't cover: claiming a new package name, `npm deprecate`,
and `npm dist-tag` changes.

### Reduce dependency tree — practice #13

Before adding a new direct dep, ask:

- Does Node ≥ 22 (our minimum) already provide this?
- Is the package actively maintained? Check Snyk's database (security.snyk.io) — practice #14
- What does `npm pack <pkg>` show in the actual tarball? (npmjs.org's web view can lie — practice #15)

### Secrets in CI

`tests.yml` writes `.env` files at CI time from GitHub Secrets. This is acceptable: secrets are never committed, scoped to the runner, and rotate via the GitHub UI. The `.env` files exist only for the lifetime of the job.

Do **not** commit any `.env` file to the repo.

## Publishing — OIDC trusted publishing + provenance (practices #11, #12)

`.github/workflows/release.yml` publishes to npm with **no `NPM_TOKEN`**. It
authenticates via npm OIDC trusted publishing, and provenance attestations are
generated automatically as a side effect. Verify any published version with:

```bash
npm view <pkg>@<version> --json | grep -A3 attestations
```

Constraints baked into that workflow — don't undo them:

- **`permissions: id-token: write`** is what mints the OIDC token. Without it every publish fails.
- **`runs-on: ubuntu-latest`, not a self-hosted/Blacksmith runner.** npm rejects provenance from non-GitHub-hosted runners with E422.
- **Never set `NPM_TOKEN`.** `changesets/action` writes a token `.npmrc` when it sees one, which shadows OIDC and fails every publish with E404 (npm/cli#8976).
- **npm ≥ 11.5.1 and Node ≥ 22.14.** Node 22 ships npm 10.x, so the workflow installs `npm@^11.5.1` explicitly before publishing.
- **No Actions cache in this workflow** (no `cache:`, `package-manager-cache: false`, `pnpm/action-setup` with `cache: false`). A poisoned cache entry would execute in a credential-bearing job. Enforced by `scripts/lint-no-workflow-caching.mjs`, which also follows any local composite action or reusable workflow the job reaches — the rule is about the whole call tree, not the one file.
- **Every published `uses:` must be in that script's `AUDITED_ACTIONS` allowlist.** The gate cannot open a published action to check whether it caches, and the ones that do are not all named "cache" — a `setup-<tool>` action that caches by default has no `cache:` input and no telling name. So the list is what is *permitted*, and an action it has never met fails by default. Adding a step to `release.yml`, `_build-ffi-artifacts.yml` or `tests-supply-chain.yml` means auditing the action and adding it there with the reason, in the same PR.
- **Three actions must disable caching *explicitly*, and the input differs for each.** Allowlisting an action is not the same as it being safe by default:

  | Action | Input | Its default | Required |
  |---|---|---|---|
  | `pnpm/action-setup` | `cache` | `false` | `cache: false` |
  | `actions/setup-node` | `package-manager-cache` | **`true`** | `package-manager-cache: false` |
  | `jdx/mise-action` | `cache` | **`true`** | `cache: false` |

  ```yaml
  - uses: jdx/mise-action@<sha> # v3.6.3
    with:
      install: true
      working_directory: packages/protect-ffi
      cache: false # defaults to TRUE — omitting this restores the Actions cache
  ```

  Omitting the key is not "no caching" for the bottom two, it is caching spelled invisibly. The gate's generic rule only fires on a *truthy* `cache:` value, so a missing key is invisible to it — which is exactly how a `mise-action` step with no `cache:` passed until each action got its own explicit-`false` assertion.

### The native-binding publish path

`@cipherstash/protect-ffi` and its six `@cipherstash/protect-ffi-<platform>`
packages ship compiled binaries, which `changeset publish` cannot produce: it
packs from the workspace, where `index.node` is a build output. So `release.yml`
publishes them itself, before changesets runs, and the same constraints apply to
that job — GitHub-hosted runner, `id-token: write`, no `NPM_TOKEN`,
npm ≥ 11.5.1, no Actions cache.

- `scripts/release-gate.mjs` asks the registry which committed versions are
  missing. It is not a cost optimisation: if it wrongly reports nothing to
  publish, changesets publishes six platform packages with no binary in them.
  Every failure mode in it throws rather than answering "nothing to publish".
- `_build-ffi-artifacts.yml` is a reusable workflow, and only builds — trusted
  publishing binds to `(repository, workflow filename)`, so the publish step has
  to live in the registered file. It is on the no-caching gate's target list for
  the same reason `release.yml` is: everything it produces gets published.
- Platform packages publish **before** the wrapper. The wrapper's six
  `optionalDependencies` are exact versions, so publishing it first exposes a
  version whose binaries do not exist yet.
- `ffi-preflight.yml` is the dry run — `changeset publish` has no `--dry-run`.
  Dispatch it against a Version Packages branch and it builds the real tarballs,
  checks each binary's architecture and libc, installs the host pair and loads
  it. It has no `id-token` permission, so it cannot publish.

Trusted publishing is configured **per package** on npmjs.com (package settings →
Trusted publisher → GitHub Actions): owner/repo `cipherstash/stack`, workflow
filename `release.yml` (filename only, with extension — not a path), environment
blank. npm does not validate this on save, so a typo only surfaces as a failed
publish. For configurations created after 2026-05-20 npm also requires an
explicit **Allowed actions** selection — pick `npm publish`.

**`repository.url` must exactly match the publishing repository**
(`https://github.com/cipherstash/stack`). npm checks it on a trusted publish and
rejects a mismatch; nothing warns beforehand. A package moved between
repositories needs its manifest updated in the same change as its publisher —
and for a package published from a subdirectory, `repository.directory` is
resolved from that repository's root, so it moves too.

### Publishing a package name for the first time

A trusted publisher can only be attached to a package that already exists on the
registry, so a brand-new name can't be released by `release.yml` on its own —
the first publish has to be manual. This is why `@cipherstash/stack-drizzle` and
`@cipherstash/stack-supabase` each carry a `0.0.0` placeholder version.

Do this **before** the release that would first publish the name:

1. `npm login` as a maintainer with publish rights on the `@cipherstash` scope.
2. Publish a placeholder to claim the name. Use `pnpm publish`, not `npm publish` — workspace packages depend on each other via `workspace:*` and only pnpm rewrites that protocol on pack:

   ```bash
   pnpm --filter <pkg> build
   cd packages/<dir>
   npm version 0.0.0 --no-git-tag-version
   pnpm publish --tag bootstrap --access public --no-git-checks
   git checkout package.json   # restore the real version
   ```

   This publish has no provenance — it predates the trusted-publisher config by
   definition. That's expected and is the only unattested version.
3. Register the trusted publisher on npmjs.com as described above.
4. `npm deprecate <pkg>@0.0.0 "Placeholder package"` so nothing installs it silently.
5. After the real release lands, clean up the placeholder tags — `changeset publish` never removes a tag it didn't create:

   ```bash
   npm dist-tag rm <pkg> bootstrap
   ```

The first publish also sets `latest` to `0.0.0` regardless of `--tag`, so keep the
gap between the placeholder and the real release short, and confirm
`npm view <pkg> dist-tags` afterwards.

Also confirm the package's `package.json` has `"publishConfig": {"access": "public"}` —
`.changeset/config.json` sets `access: "restricted"` repo-wide, and the per-package
field is what overrides it.

## Common Operations

### Add a dependency that needs a build script

1. Vet the package: latest version, active maintenance, reasonable download counts, source visible on GitHub.
2. Run `npm pack <pkg>` and inspect the tarball — confirm the install script is what you expect.
3. Add to `package.json` `pnpm.onlyBuiltDependencies`:
   ```json
   "pnpm": {
     "onlyBuiltDependencies": ["node-pty", "your-new-package"]
   }
   ```
4. Update the supply-chain test's allowlist threshold if you'd be adding the 4th entry — and explain in the PR why the count needs to grow.
5. Run `pnpm install` to confirm the build script executes.

### Bypass the install cooldown for a security fix

When CVE response needs a patch faster than 7 days:

1. Pin the exact patched version (a pnpm override scoped to the vulnerable
   range for transitive deps, or the manifest for direct deps) so the bypass
   run can only admit that one release.
2. Run a one-off install with the cooldown disabled for that single run
   (pnpm ≥ 10 has no dedicated flag; the CLI config override is the one-off
   equivalent and does not persist — kebab-case is the canonical form,
   though pnpm 10.x accepts the camelCase spelling too):

```bash
pnpm install --config.minimum-release-age=0
```

Once the patched version is in `pnpm-lock.yaml`, normal and
`--frozen-lockfile` installs succeed without any bypass — locked versions are
not re-age-checked. Do NOT add third-party packages to
`minimumReleaseAgeExclude`: that list is for first-party packages only and a
name-scoped entry exempts every future release of the package until removed.

Document the bypass in the PR description (CVE ID, why the cooldown was the bottleneck) so the next reviewer can follow the reasoning.

### Add a new dev dependency

No special steps — Dependabot will pick it up on the next weekly run (after the cooldown window). For immediate use, just `pnpm add -D <pkg>`.

### Change a CI workflow

CODEOWNERS will request review from `@cipherstash/developers`. The supply-chain test will fail if the change drops `--frozen-lockfile` or downgrades Node.

## Reference

- Source: [lirantal/npm-security-best-practices](https://github.com/lirantal/npm-security-best-practices)
- Test gate: [`e2e/tests/supply-chain.e2e.test.ts`](../../e2e/tests/supply-chain.e2e.test.ts)
- pnpm config: [`pnpm-workspace.yaml`](../../pnpm-workspace.yaml), root `package.json` `pnpm` block
- CI: [`.github/workflows/tests.yml`](../../.github/workflows/tests.yml)
- Updates: [`.github/dependabot.yml`](../../.github/dependabot.yml)
- Governance: [`.github/CODEOWNERS`](../../.github/CODEOWNERS)
