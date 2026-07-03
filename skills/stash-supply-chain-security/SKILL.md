---
name: stash-supply-chain-security
description: Supply-chain security controls for the @cipherstash/stack monorepo. Covers post-install script policy (onlyBuiltDependencies), install cooldown (minimumReleaseAge), lockfile integrity (blockExoticSubdeps + lockfile registry check), frozen-lockfile CI, registry pinning (.npmrc), Dependabot cooldown, and CODEOWNERS. Use when modifying CI workflows, pnpm config, dependency updates, .github/dependabot.yml, or anything that touches how packages enter the build.
---

# Supply Chain Security

Controls applied in this repo to limit blast radius from compromised npm packages, lockfile injection, dependency confusion, and rushed dependency upgrades. Sourced from [lirantal/npm-security-best-practices](https://github.com/lirantal/npm-security-best-practices) and adapted for our pnpm workspace.

## When to Use This Skill

- Modifying any file under `.github/workflows/`
- Editing `pnpm-workspace.yaml`, `package.json` `pnpm` block, or `.npmrc`
- Updating `.github/dependabot.yml` or `.github/CODEOWNERS`
- Adding a dependency that needs a build script (i.e. `node-gyp`, `node-pty`, prebuilt binaries)
- Bypassing the install cooldown for a security fix
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

- **Where**: `.github/workflows/tests.yml`
- **Test asserts**: every `pnpm install` invocation in tests.yml carries `--frozen-lockfile`

### 5. Cooldown'd auto-updates — practice #6

Dependabot opens grouped, cooldown'd PRs (7 days minor/patch, 14 days major) for both `npm` and `github-actions`. Major bumps stay un-grouped — one PR each, easier to review.

- **Where**: `.github/dependabot.yml`
- **Test asserts**: cooldown ≥ 3 days, both ecosystems present

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

(This becomes mostly moot once the deferred OIDC-trusted-publisher migration lands — the workflow won't need long-lived tokens at all. See "Deferred" below.)

### Reduce dependency tree — practice #13

Before adding a new direct dep, ask:

- Does Node ≥ 22 (our minimum) already provide this?
- Is the package actively maintained? Check Snyk's database (security.snyk.io) — practice #14
- What does `npm pack <pkg>` show in the actual tarball? (npmjs.org's web view can lie — practice #15)

### Secrets in CI

`tests.yml` writes `.env` files at CI time from GitHub Secrets. This is acceptable: secrets are never committed, scoped to the runner, and rotate via the GitHub UI. The `.env` files exist only for the lifetime of the job.

Do **not** commit any `.env` file to the repo.

## What's Deferred (Follow-Up PR)

These need npmjs.com-side configuration and are tracked separately:

- **Provenance attestations** — practice #11
- **OIDC trusted publishing** — practice #12

Both require the npm org admin to register each `@cipherstash/*` package as a Trusted Publisher (cipherstash/stack repo + release.yml). Once that's done, `release.yml` can drop `NPM_TOKEN` entirely, run `npm publish` with `id-token: write`, and provenance is auto-generated.

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
   equivalent and does not persist):

```bash
pnpm install --config.minimumReleaseAge=0
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
