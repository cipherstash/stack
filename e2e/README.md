# `@cipherstash/e2e`

End-to-end tests that exercise built CipherStash binaries and cross-package behaviour. Lives outside `packages/` because these tests are not tied to a single package — they verify how the published artefacts behave when a user actually runs them.

## Running

From the repo root:

```bash
pnpm run test:e2e
```

This delegates to turbo, which builds dependent packages first and then runs `vitest run` inside this workspace.

To run a single test file:

```bash
pnpm --filter @cipherstash/e2e exec vitest run tests/package-managers.e2e.test.ts
```

## What's covered

| Test file | Scope |
| --- | --- |
| `tests/package-managers.e2e.test.ts` | The `init` providers and the wizard binary render `bunx`/`pnpm dlx`/`yarn dlx`/`npx` based on detected package manager. |
| `tests/supply-chain.e2e.test.ts` | Lockfile/registry/CODEOWNERS controls from `skills/stash-supply-chain-security` are still enforced. |
| `tests/prisma-example-readme.e2e.test.ts` | Parses `examples/prisma/README.md`'s "Run it" section and asserts every command (skipping `stash auth login`) exits 0. |

## Auth-dependent suites

Some tests spawn the wizard binary, which runs an auth check before reaching the prerequisite path under test. These are wrapped in `describe.skipIf(!authConfigured)` and only run when:

- `~/.cipherstash/auth.json` exists (typical local dev), **or**
- `CS_CLIENT_ID` and `CS_CLIENT_KEY` are set in the environment (CI with secrets wired)

The CI job for this workspace exposes those env vars from repo secrets. Without them the wizard suite is skipped (the provider suite still runs).

## Adding a new e2e test

- File name must end in `.e2e.test.ts` to be picked up by `vitest.config.ts`.
- Prefer spawning the **built** binary (`packages/<pkg>/dist/bin/...`) over importing source — that's the value e2e gives over unit tests. If the binary isn't built when your test runs, fail fast with a clear message; turbo's `test:e2e` task declares `^build` + `build` deps so a top-level `pnpm run test:e2e` will build first.
- For tests that need a clean cwd, use `mkdtempSync(join(tmpdir(), 'stash-...-e2e-'))` and clean up in `afterEach`.
- Mock nothing. If you find yourself wanting to mock, the test belongs in a unit suite.
