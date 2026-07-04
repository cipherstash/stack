# Contributing to CipherStash Stack

Thank you for your interest in contributing to the CipherStash Stack for TypeScript! This document walks you through the repository's structure, how to build and run the project locally, and how to make contributions effectively.

## I want to report a bug, or make a feature request

Please use the GitHub issue tracker to report bugs, suggest features, or documentation improvements.

[When filing an issue](https://github.com/cipherstash/stack/issues/new/choose), please check [existing open](https://github.com/cipherstash/stack/issues?q=is%3Aissue+is%3Aopen+sort%3Aupdated-desc) or [recently closed](https://github.com/cipherstash/stack/issues?q=is%3Aissue+sort%3Aupdated-desc+is%3Aclosed) issues to make sure somebody else hasn't already reported it. Please include as much information as you can.

## Repository Structure

This is a [Turborepo](https://turbo.build/) monorepo managed with [pnpm](https://pnpm.io/) workspaces:

```
.
├── packages/
│   ├── stack/            <-- Main package (@cipherstash/stack)
│   ├── cli/              <-- The `stash` CLI
│   ├── protect/          <-- Core encryption library (re-exported via stack)
│   └── ...               <-- schema, drizzle, nextjs, prisma-next, migrate, wizard, ...
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

## Publish Process (via Changesets)

We use [**Changesets**](https://github.com/changesets/changesets) to manage versioning and publication to npm.

- When you've completed a feature or bug fix, **add a changeset** using `pnpm changeset`.
- Follow the prompts to indicate the type of version bump (patch, minor, major).
- The [GitHub Actions workflows](./.github/workflows/) handle the **publish** step to npm once your PR is merged and the changeset is committed to `main`.

## Pre release process

We currently use [changesets to manage pre-releasing](https://github.com/changesets/changesets/blob/main/docs/prereleases.md) the `next` version of the package, and the process is executed manually.

To do so, you need to:

1. Check out the `next` branch
2. Run `pnpm changeset pre enter next`
3. Run `pnpm changeset version`
4. Run `git add .`
5. Run `git commit -m "Enter prerelease mode and version packages"`
6. Run `pnpm changeset publish --tag next`
7. Run `git push --follow-tags`

When you are ready to release, you can run `pnpm changeset pre exit` to exit prerelease mode and commit the changes.
When you merge the PR, the `next` branch will be merged into `main`, and the package will be published to npm without the prerelease tag.

> [!IMPORTANT]
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
