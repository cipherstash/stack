# Contributing to CipherStash Stack

Thank you for your interest in contributing to the CipherStash Stack for TypeScript! This document walks you through the repository's structure, how to build and run the project locally, and how to make contributions effectively.

## I want to report a bug, or make a feature request

Please use the GitHub issue tracker to report bugs, suggest features, or documentation improvements.

[When filing an issue](https://github.com/cipherstash/stack/issues/new/choose), please check [existing open](https://github.com/cipherstash/stack/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc) or [recently closed](https://github.com/cipherstash/stack/issues?q=is%3Aissue+sort%3Aupdated-desc+is%3Aclosed) issues to make sure somebody else hasn't already reported it. Please include as much information as you can.

## Repository Structure

This is a [Turborepo](https://turbo.build/) monorepo managed with [pnpm](https://pnpm.io/) workspaces:

```text
.
├── packages/
│   ├── stack/            <-- Main package (@cipherstash/stack)
│   ├── cli/              <-- The `stash` CLI
│   └── ...               <-- stack-drizzle, stack-supabase, stack-prisma, nextjs, migrate, wizard, ...
├── examples/             <-- Runnable example apps
├── e2e/                  <-- Cross-package end-to-end tests
├── skills/               <-- Agent skills
├── .changeset/
└── package.json
```

See [AGENTS.md](./AGENTS.md) for a detailed layout, key APIs, environment variables, and gotchas — it's written for coding agents but is the most complete developer reference in the repo.

### `packages/stack`

**@cipherstash/stack** is the main package published to npm. It contains the encryption client and all integrations (Drizzle, Supabase, DynamoDB, secrets, identity). This is likely where you'll spend most of your time.

### `examples/` Directory

The `examples/` directory contains applications demonstrating how to use `@cipherstash/stack`. They reference the local workspace packages, so you can verify your changes in a real application scenario.

## Setup Instructions

### Prerequisites

- **Node.js** >= 22
- **pnpm** (the version pinned in `package.json`'s `packageManager` field)
- CipherStash credentials if you want to run integration tests or examples (see [AGENTS.md](./AGENTS.md) for the required environment variables)

### 1. Clone the Repo

```bash
git clone https://github.com/cipherstash/stack.git
cd stack
```

### 2. Install Dependencies

```bash
pnpm install
```

### 3. Build the Packages

```bash
pnpm run build
```

This triggers Turborepo's build pipeline, compiling each package in `packages/*` and linking them locally so the examples can reference them.

### 4. Run an Example App

Start the dev script, which watches for changes to the packages and is picked up by the example apps:

```bash
pnpm run dev
```

Then navigate to one of the examples in `examples/` and follow its README.

## Making Changes

1. **Create a new branch** from `main`:
   ```bash
   git checkout -b feat/my-new-feature
   ```

2. **Implement your changes** in the relevant package.

3. **Write tests** to cover any new functionality or bug fixes:
   ```bash
   pnpm --filter <package-name> test
   ```

4. **Format and lint** with Biome before pushing:
   ```bash
   pnpm run code:fix
   ```

5. **Add a changeset** if your change affects a published package's public behaviour (see below).

6. **Sign your commits** — every commit in a pull request must be signed (see below).

## Signing Your Commits

**All commits must be cryptographically signed.** This is a hard requirement: pull
requests containing unsigned commits will not be merged. Signing ties each commit to
a verified identity, which matters for a repository whose packages ship as
dependencies into other people's applications — an unsigned commit is an unattributable
change in a supply chain.

GitHub shows a **Verified** badge next to signed commits. If a commit in your PR
doesn't have one, it needs to be re-signed.

### Set up signing

You can sign with SSH (simplest if you already push over SSH) or GPG.

**SSH signing** (Git >= 2.34):

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

Then add the same public key to your GitHub account as a **Signing Key**
(Settings → SSH and GPG keys → New SSH key → key type "Signing Key"). A key
registered only as an authentication key will not produce a Verified badge.

**GPG signing:**

```bash
gpg --full-generate-key                       # if you don't already have a key
gpg --list-secret-keys --keyid-format=long    # copy the key ID
git config --global user.signingkey <KEY_ID>
git config --global commit.gpgsign true
```

Then export the public key (`gpg --armor --export <KEY_ID>`) and add it to GitHub
under Settings → SSH and GPG keys → New GPG key.

The email on your signing key must match the email in your Git config and be a
verified email on your GitHub account, or GitHub will mark the commit
**Unverified** rather than **Verified**.

Full instructions: [GitHub — signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

### Fixing unsigned commits

If you've already pushed unsigned commits, sign them retroactively and force-push
to your branch:

```bash
# Sign the last N commits (replace N with the number of commits in your PR)
git rebase --exec 'git commit --amend --no-edit -S' -i HEAD~N

# Or sign every commit on your branch relative to main
git rebase --exec 'git commit --amend --no-edit -S' main

git push --force-with-lease
```

Force-pushing rewrites history on your branch. Only do this on your own PR branch,
never on `main`, and check with the maintainers first if anyone else has based work
on your branch.

## Publish Process (via Changesets)

We use [**Changesets**](https://github.com/changesets/changesets) to manage versioning and publication to npm.

- When you've completed a feature or bug fix, **add a changeset** using `pnpm changeset`.
- Follow the prompts to indicate the type of version bump (patch, minor, major).
- The [GitHub Actions workflows](./.github/workflows/) handle the **publish** step to npm once your PR is merged and the changeset is committed to `main`.

Releases are **stable** — Changesets is not in pre mode. Merging a changeset to
`main` opens (or updates) a "Version Packages" PR with plain semver versions, and
merging that PR publishes to npm under the `latest` dist-tag.

The `stash` / `@cipherstash/stack` / `@cipherstash/stack-drizzle` /
`@cipherstash/stack-supabase` / `@cipherstash/stack-prisma` / `@cipherstash/wizard`
packages are a `fixed` group in [`.changeset/config.json`](./.changeset/config.json):
they always version together, so a bump to any one of them bumps all six.

## Pre-release process

The 1.0 line published its `1.0.0-rc.*` series through
[changesets pre mode](https://github.com/changesets/changesets/blob/main/docs/prereleases.md).
That mode is **exited** — do not re-enter it for ordinary work; a stable release
is the default.

If a future line genuinely needs a prerelease series:

1. Run `pnpm changeset pre enter rc` (this writes `.changeset/pre.json`)
2. Commit that file — from then on, every "Version Packages" PR produces
   `x.y.z-rc.N` versions and publishes under the `rc` dist-tag
3. When the line is ready to go stable, run `pnpm changeset pre exit` and commit
   the change. The next `changeset version` graduates every package to its final
   version, consumes the accumulated changesets into `CHANGELOG.md`, and deletes
   `.changeset/pre.json`

> [!IMPORTANT]
> Pre mode retains every consumed changeset until exit, so its markdown is what
> lands in the stable changelog — an entry that a later change made wrong stays
> wrong until someone edits it. Review `.changeset/*.md` as a set before exiting.
>
> This process can be dangerous, so please be careful when using it as it's difficult to undo mistakes.
> If you are unfamiliar with the process, please reach out to the maintainers for help.

## Supply-Chain Rules

This repo applies supply-chain controls that CI enforces (see [SECURITY.md](./SECURITY.md)). When contributing, keep in mind:

1. **CI uses `pnpm install --frozen-lockfile`** — don't drop the flag.
2. **Adding to `pnpm.onlyBuiltDependencies` is an audit decision** — vet the package and explain the addition in the PR.
3. **Never commit auth tokens in `.npmrc`** — tokens belong in your user-level `~/.npmrc` or environment variables.

## Additional Resources

- [AGENTS.md](./AGENTS.md) — detailed developer/agent reference for this repo
- [CipherStash documentation](https://cipherstash.com/docs)
- [Turborepo Documentation](https://turbo.build/repo/docs)
- [Changesets Documentation](https://github.com/changesets/changesets)

# Security issue notifications

If you discover a potential security issue in this project, we ask that you contact us at security@cipherstash.com.

Please do not create a public GitHub issue. See [SECURITY.md](./SECURITY.md) for our full security policy.

## Code of Conduct

This project has adopted the [Contributor Covenant](https://www.contributor-covenant.org/).
For more information see the [Code of Conduct FAQ](CODE_OF_CONDUCT.md) or contact support@cipherstash.com with any questions or comments.

## Licensing

See the [LICENSE](LICENSE.md) file for our project's licensing.
