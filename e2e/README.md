# `@cipherstash/e2e`

End-to-end tests that exercise built CipherStash binaries and cross-package behaviour. Lives outside `languages/typescript/packages/` because these tests are not tied to a single package — they verify how the published artefacts behave when a user actually runs them.

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
| `tests/prisma-example-readme.e2e.test.ts` | Parses `languages/typescript/examples/prisma/README.md`'s "Run it" section and asserts every command (skipping `stash auth login`) exits 0. |
| `tests/skill-map-parity.e2e.test.ts` | The CLI's and the wizard's `SKILL_MAP` install the same skills for each equivalent integration. Lives here because this is the only workspace declaring both packages. |

## Auth-dependent suites

Some tests spawn the wizard binary, which runs an auth check before reaching the prerequisite path under test. These are wrapped in `describe.skipIf(!authConfigured)` and only run when:

- `~/.cipherstash/auth.json` exists (typical local dev), **or**
- `CS_CLIENT_ID` and `CS_CLIENT_KEY` are set in the environment (CI with secrets wired)

The CI job for this workspace exposes those env vars from repo secrets. Without them the wizard suite is skipped (the provider suite still runs).

## Protect compatibility suites

These live suites are excluded from the default run. From an installed repository checkout, build the native binding, then use Turbo to build the workspace dependencies and run each suite:

```bash
pnpm --filter @cipherstash/protect-ffi run build:native
pnpm exec turbo run test:protect-compat --filter @cipherstash/e2e --env-mode=loose
pnpm exec turbo run test:protect-crossover --filter @cipherstash/e2e --env-mode=loose
```

The native build needs the repository's Rust toolchain and trusted mise configuration. Both suites require `CS_WORKSPACE_CRN`, `CS_CLIENT_ID`, `CS_CLIENT_KEY` and `CS_CLIENT_ACCESS_KEY` in the environment, `e2e/.env` or the root `.env`; missing configuration fails the run rather than skipping it. The crossover suite also requires `DATABASE_URL` pointing to a disposable Postgres database where it can install EQL and create test tables.

- `tests/protect-dynamodb-compat.e2e.test.ts` checks Protect.js → Stack reads, writes and equality terms using real encryption and in-memory DynamoDB item storage.
- `tests/protect-crossover.e2e.test.ts` checks ciphertext and HMAC transfer between DynamoDB item objects and real Postgres rows. The same runner includes `tests/protect-postgres-upgrade.e2e.test.ts` and `tests/protect-guide-example.e2e.test.ts` for the Postgres upgrade and executable guide examples.

See the [migration guide](../docs/migration/protect-dynamodb-to-stack.md) for the tested scope and limitations.

## Adding a new e2e test

- File name must end in `.e2e.test.ts` to be picked up by `vitest.config.ts`.
- Prefer spawning the **built** binary (`packages/<pkg>/dist/bin/...`) over importing source — that's the value e2e gives over unit tests. If the binary isn't built when your test runs, fail fast with a clear message; turbo's `test:e2e` task declares `^build` + `build` deps so a top-level `pnpm run test:e2e` will build first.
- For tests that need a clean cwd, use `mkdtempSync(join(tmpdir(), 'stash-...-e2e-'))` and clean up in `afterEach`.
- Mock nothing. If you find yourself wanting to mock, the test belongs in a unit suite.
