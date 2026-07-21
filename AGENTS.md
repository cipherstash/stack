This is the CipherStash Stack repository (`cipherstash/stack`) - End-to-end, per-value encryption for JavaScript/TypeScript with zero‑knowledge key management (via CipherStash ZeroKMS). Encrypted data is stored as EQL JSON payloads; searchable encryption is currently supported for PostgreSQL.

## Prerequisites

- **Node.js**: >= 22 (enforced in `package.json` engines)
- **pnpm**: 10.33.2 (this repo uses pnpm workspaces and catalogs)
- Internet access to install the prebuilt native module `@cipherstash/protect-ffi`

If running integration tests or examples, you will also need CipherStash credentials (see Environment variables below).

## Building and Running

### Install

```bash
pnpm install
```

### Build all packages

```bash
pnpm run build
# or only JS libraries
pnpm run build:js
```

Under the hood this uses Turborepo to build `./packages/*` with each package's `tsup` configuration.

### Dev/watch

```bash
pnpm run dev
```

### Tests

- Default: run package tests via Turborepo

```bash
pnpm test
```

- Filter to a single package (recommended for fast iteration):

```bash
pnpm --filter @cipherstash/stack test
pnpm --filter @cipherstash/nextjs test
```

Tests use **Vitest**. Many tests talk to the real CipherStash service; they require environment variables. Some tests (e.g., lock context) are skipped if optional tokens aren't present.

### Environment variables required for runtime/tests

Place these in a local `.env` at the repo root or specific example directory:

```bash
CS_WORKSPACE_CRN=
CS_CLIENT_ID=
CS_CLIENT_KEY=
CS_CLIENT_ACCESS_KEY=

# Optional – enables identity-aware encryption tests
USER_JWT=
USER_2_JWT=

# Logging (plaintext is never logged by design)
STASH_STACK_LOG=debug|info|error  # default: error (errors only)
```

If these variables are missing, tests that require live encryption will fail or be skipped; prefer filtering to specific packages and tests while developing.

## Repository Layout

- `packages/stack`: Main package (`@cipherstash/stack`) containing the encryption client and all integrations
  - Subpath exports: `@cipherstash/stack`, `@cipherstash/stack/client`, `@cipherstash/stack/identity`, `@cipherstash/stack/schema`, `@cipherstash/stack/eql/v3`, `@cipherstash/stack/v3`, `@cipherstash/stack/types`, `@cipherstash/stack/dynamodb`, `@cipherstash/stack/encryption`, `@cipherstash/stack/errors`, `@cipherstash/stack/adapter-kit`, `@cipherstash/stack/wasm-inline` (the Drizzle and Supabase integrations moved to their own packages — see below)
- `packages/protect`: Core encryption library (internal, re-exported via `@cipherstash/stack`)
  - `src/index.ts`: Public API (`Encryption`, exports)
  - `src/ffi/index.ts`: `EncryptionClient` implementation, bridges to `@cipherstash/protect-ffi`
  - `src/ffi/operations/*`: Encrypt/decrypt/model/bulk/query operations (thenable pattern with optional `.withLockContext()`)
  - `__tests__/*`: End-to-end and API contract tests (Vitest)
- `packages/cli`: The `stash` CLI — auth, init, encryption schema, and database setup (`stash eql install`). Has its own `AGENTS.md`.
- `packages/wizard`: AI-powered encryption setup (`@cipherstash/wizard`)
- `packages/migrate`: Plaintext-to-encrypted column migration (`@cipherstash/migrate`) — resumable backfill, per-column state
- `packages/prisma-next`: Prisma Next integration (`@cipherstash/prisma-next`) — searchable field-level encryption for Postgres. **EQL v3 only**: per-domain constructors (`cipherstash.TextSearch()` / `text()` / `bigIntOrd()` / …) and `cipherstashFromStack` (the `./v3` and `./stack` entries). The EQL v2 surface was removed — the adapter's baseline migration installs the EQL v3 bundle only (works on Supabase as a non-superuser)
- `packages/stack-drizzle`: Drizzle ORM integration (`@cipherstash/stack-drizzle`), depends on `@cipherstash/stack` — EQL v2 (`.`) and EQL v3 (`./v3`). Split out of `@cipherstash/stack`.
- `packages/stack-supabase`: Supabase integration (`@cipherstash/stack-supabase`), depends on `@cipherstash/stack` — `encryptedSupabase` (v2) and `encryptedSupabaseV3` (v3). Split out of `@cipherstash/stack`.
- `packages/schema`: Schema builder utilities and types (`encryptedTable`, `encryptedColumn`, `encryptedField`)
- `packages/nextjs`: Next.js helpers and Clerk integration (`./clerk` export)
- `packages/protect-dynamodb`: DynamoDB helpers (`encryptedDynamoDB`)
- `packages/utils`: Shared config (`utils/config`) and logger (`utils/logger`)
- `packages/bench`: Performance / index-engagement benchmarks (private, not published)
- `e2e/*`: Cross-package end-to-end tests (package managers, supply chain, Prisma example README)
- `examples/*`: Working apps (basic, prisma, supabase-worker)
- `docs/plans/*`: Internal design plans. User-facing documentation lives at https://cipherstash.com/docs (not in this repo).
- `skills/*`: Agent skills (`stash-cli`, `stash-encryption`, `stash-drizzle`, `stash-dynamodb`, `stash-supabase`, `stash-prisma-next`, `stash-supply-chain-security`)

## Agent Skills — these ship to customers

`skills/*/SKILL.md` are **published artifacts, not internal notes.** Treat a wrong
sentence in one of them the way you'd treat a wrong line of code:

- `packages/cli/tsup.config.ts` copies `skills/` into `dist/skills/`, so they ship
  inside the `stash` npm tarball (and the `@cipherstash/wizard` one).
- `installSkills()` (`packages/cli/src/commands/init/lib/install-skills.ts`) copies the
  per-integration set into the user's `.claude/skills/` or `.codex/skills/` at handoff time.
- `readBundledSkill()` inlines a skill's body into the user's `AGENTS.md` for editor
  agents (Cursor / Windsurf / Cline). Only `SKILL.md` is inlined — content split into
  sibling files is silently dropped on that path, so keep each `SKILL.md` self-sufficient.

**Every change to a package's public API, the CLI command surface, or a user-facing
workflow must check the affected skills in the same PR.** These skills drift silently:
nothing type-checks them, and the damage lands in a customer's repo, not ours.

| If you change… | Check |
|---|---|
| `packages/cli` commands, flags, or prompts | `skills/stash-cli` |
| `packages/stack` encryption API, schema builders, subpath exports | `skills/stash-encryption` |
| Drizzle / Supabase / Prisma Next / DynamoDB integrations | `skills/stash-drizzle`, `skills/stash-supabase`, `skills/stash-prisma-next`, `skills/stash-dynamodb` |
| The rollout/cutover lifecycle (`packages/migrate`, `stash encrypt *`) | `skills/stash-encryption` and `skills/stash-cli` |
| pnpm config, CI workflows, dependency policy | `skills/stash-supply-chain-security` |
| The durable agent rules themselves | `packages/cli/src/commands/init/doctrine/AGENTS-doctrine.md` |

For CLI changes there is a mechanical check — the command registry is the source of
truth, so diff the skill against it rather than proofreading:

```bash
pnpm --filter stash build
node packages/cli/dist/bin/stash.js manifest --json
```

Every command and flag named in `skills/stash-cli/SKILL.md` must resolve against that
manifest (the deprecated `db install` / `db upgrade` / `db status` aliases excepted —
they're intentionally absent from the registry).

Skills must not contain Linear issue IDs; they're public. GitHub issue numbers are fine.

## Supply Chain Security

This repo applies a set of supply-chain controls (post-install script policy, install cooldown, frozen-lockfile CI, registry pinning, Dependabot cooldown, CODEOWNERS) sourced from [lirantal/npm-security-best-practices](https://github.com/lirantal/npm-security-best-practices). They're validated by `e2e/tests/supply-chain.e2e.test.ts` so silent regressions fail CI. See `skills/stash-supply-chain-security/SKILL.md` for the full guide.

Three rules to remember when editing CI or pnpm config:

1. **CI uses `pnpm install --frozen-lockfile`.** Don't drop the flag.
2. **Adding to `pnpm.onlyBuiltDependencies` is an audit decision** — vet the package and explain the addition in the PR.
3. **Don't commit auth tokens in `.npmrc`.** Tokens belong in user-level `~/.npmrc` or environment variables.

## Key Concepts and APIs

- **Initialization**: `EncryptionV3({ schemas })` returns the typed EQL v3 client. (`Encryption({ schemas })` is the legacy v2 client.) Provide at least one `encryptedTable`.
- **Schema (EQL v3, the documented approach)**: Define tables/columns with `encryptedTable` and the `types.*` concrete-domain factories from `@cipherstash/stack/eql/v3` (`types.TextSearch`, `types.IntegerOrd`, `types.Json`, …) — each domain's query capabilities are fixed by its type; there are no chainable capability tuners. Build the client with `EncryptionV3` from `@cipherstash/stack/v3`. (Legacy EQL v2 — `Encryption` + `encryptedColumn(...).equality().freeTextSearch().orderAndRange().searchableJson()` from `@cipherstash/stack/schema` — remains for existing deployments and is what DynamoDB (`encryptedField`) still requires; see #657.)
- **Operations** (all return Result-like objects and support chaining `.withLockContext(lockContext)` and `.audit()` when applicable):
  - `encrypt(plaintext, { table, column })`
  - `decrypt(encryptedPayload)`
  - `encryptModel(model, table)` / `decryptModel(model)`
  - `bulkEncrypt(plaintexts[], { table, column })` / `bulkDecrypt(encrypted[])`
  - `bulkEncryptModels(models[], table)` / `bulkDecryptModels(models[])`
  - `encryptQuery(value, { table, column, queryType?, returnType? })` for searchable queries
  - `encryptQuery(terms[])` for batch query encryption
- **Identity-aware encryption**: Authenticate the client as the end user with `OidcFederationStrategy` (`config.authStrategy`, re-exported from `@cipherstash/stack`), then chain `.withLockContext({ identityClaim })` on operations to bind the data key to a claim. The same claim must be used for encrypt and decrypt. (`LockContext.identify()` from `@cipherstash/stack/identity` is deprecated — the strategy now handles token acquisition; `.withLockContext()` also accepts a `LockContext`.)
- **Integrations**:
  - **Drizzle ORM**: `encryptedType`, `extractEncryptionSchema`, `createEncryptionOperators` from `@cipherstash/stack-drizzle` (EQL v3 factories from `@cipherstash/stack-drizzle/v3`)
  - **Supabase**: `encryptedSupabase` (v2) / `encryptedSupabaseV3` (v3) from `@cipherstash/stack-supabase`
  - **DynamoDB**: `encryptedDynamoDB` from `@cipherstash/stack/dynamodb`

## Critical Gotchas (read before coding)

- **Native module vs WASM entry**: The default `@cipherstash/stack` entry relies on `@cipherstash/protect-ffi` (Node-API) and must be loaded via native Node.js `require` — if your tooling bundles server code with it, externalize the module. For bundled or non-Node runtimes (Deno, Bun, Cloudflare Workers, Supabase Edge Functions), use `@cipherstash/stack/wasm-inline` instead: it inlines the WASM build into the JS bundle, so no externalization is needed. See the bundling guide: https://cipherstash.com/docs/stack/deploy/bundling
- **Do not log plaintext**: The library never logs plaintext by design. Don't add logs that risk leaking sensitive data.
- **Result shape is contract**: Operations return `{ data }` or `{ failure }`. Preserve this shape and error `type` values in `EncryptionErrorTypes`.
- **Encrypted payload shape is contract**: Keys like `c` in the EQL payload are validated by tests and downstream tools. Don't change them.
- **Exports must support ESM and CJS**: Each package's `exports` maps must keep both `import` and `require` fields. Don't remove CJS.

## Development Workflow

- **Formatting/Linting**: Use Biome

```bash
pnpm run code:fix    # format + lint, auto-fixing what it can
pnpm run code:check  # read-only; this is what CI runs
```

  CI runs `code:check` (in `tests.yml`) and gates on **errors** — warnings are
  allowed (tracked for tightening). So `code:fix` must leave the tree
  error-free before you push.

  A Biome GritQL plugin (`biome-plugins/no-type-erasing-assertions.grit`) warns
  on `as any` / `as never` / `as unknown` in `src` — type-erasing assertions that
  silence the checker instead of narrowing. Fix the type or use a specific
  assertion; suppress a deliberate case with `// biome-ignore lint/plugin:
  <reason>`. The plugin is scoped to source via an `overrides` entry in
  `biome.json` (test/integration files excluded) — see the plugin file's header
  for why it must be scoped-in rather than globally-enabled-and-exempted.

- **Build**: `pnpm run build` (Turborepo + tsup per package)
- **Test**: `pnpm --filter <pkg> test` for targeted iterations
- **Releases**: Use Changesets

```bash
pnpm changeset        # create a changeset
pnpm changeset:version
pnpm changeset:publish
```

### Writing tests

- Use Vitest with `.test.ts` files under each package's `__tests__/`.
- Import `dotenv/config` at the top when tests need environment variables.
- Prefer testing via the public API. Avoid reaching into private internals.
- Some tests have larger timeouts (e.g., 30s) to accommodate network calls.
- `packages/cli` has a second suite — pty-driven E2E tests under
  `packages/cli/tests/e2e/**` run via `pnpm --filter stash
  test:e2e` (requires a build). See `packages/cli/AGENTS.md` for when to
  add or update them.

## Bundling and Deployment Notes

- Two deployment paths:
  - **Native (default entry)**: keep `@cipherstash/protect-ffi` external and loaded via Node's runtime require — e.g. Next.js `serverExternalPackages`. Covers Node servers where native modules are fine.
  - **WASM (`@cipherstash/stack/wasm-inline`)**: designed to be bundled — no native module, no externalization. Use for edge/serverless runtimes (Deno, Bun, Cloudflare Workers, Supabase Edge Functions) or wherever bundler externalization is awkward.
- For SST/serverless and npm-lockfile-v3 quirks on Linux, see the bundling guide: https://cipherstash.com/docs/stack/deploy/bundling

## Adding Features Safely (LLM checklist)

1. Identify the target package(s) in `packages/*` and confirm whether changes affect public APIs or payload shapes.
2. If modifying `packages/protect` operations or `EncryptionClient`, ensure:
   - The Result contract and error type strings remain stable.
   - `.withLockContext()` remains available for affected operations.
   - ESM/CJS exports continue to work (don't break `require`).
3. If changing schema behavior (`packages/schema`), update type definitions and ensure validation still works in `EncryptionClient.init`.
4. Add/extend tests in the same package. For features that require live credentials, guard with env checks or provide mock-friendly paths.
5. Run:
   - `pnpm run code:fix`
   - `pnpm --filter <changed-pkg> build`
   - `pnpm --filter <changed-pkg> test`
6. If APIs change, update usage examples in this repo and flag that the docs site (cipherstash.com/docs, maintained separately) needs a corresponding update.
7. **Keep the meta files honest.** If your change adds/removes/renames a
   package, example, skill, or subpath export, update the Repository
   Layout in this file and the package list in `SECURITY.md` in the
   same PR. These files have drifted badly before; don't let them.

8. **Check the skills.** If you changed a package's public API, the CLI
   command surface, or a user-facing workflow, open the affected
   `skills/*/SKILL.md` and fix anything your change made wrong — in the
   same PR. Skills ship inside the `stash` tarball and are copied into
   customer repos, so drift here becomes wrong guidance in someone
   else's codebase. See "Agent Skills — these ship to customers" above
   for the package→skill map and the `stash manifest --json` check.

9. **Add a changeset before opening or finalising the PR** when the
   change affects a published package's public behaviour or surface
   (new feature, bug fix, breaking change, UX-visible tweak). Run
   `pnpm changeset` (interactive) or hand-write a markdown file under
   `.changeset/` matching the existing format:

   ```
   ---
   '@cipherstash/<pkg>': minor   # or patch / major
   ---

   <user-facing description of what changed and why>
   ```

   The repo's `changeset-bot` GitHub app posts a "🦋 No Changeset
   found" warning on PRs missing one. Skip changesets only for
   internal-only changes (test-only PRs, internal refactors with no
   observable behaviour change, repo tooling). When in doubt, add
   one — releases use Changesets to drive version bumps and
   `CHANGELOG.md` entries, so a missing changeset means the change
   ships invisibly.

   A skills-only change is **not** internal: `skills/` ships inside the
   `stash` tarball, so it needs a `stash` patch changeset.

## Useful Links

- `README.md` for quickstart and feature overview
- `packages/cli/AGENTS.md` for CLI-specific guidance
- `e2e/README.md` for the cross-package E2E suite
- `skills/*/SKILL.md` for per-integration agent guides
- User-facing docs (concepts, reference, how-to) live on the docs site:
  - https://cipherstash.com/docs
  - https://cipherstash.com/docs/stack/quickstart
  - https://cipherstash.com/docs/stack/reference
  - https://cipherstash.com/docs/stack/deploy/bundling

## Troubleshooting

- Module load errors on Linux/serverless: switch to `@cipherstash/stack/wasm-inline`, or review the bundling guide (https://cipherstash.com/docs/stack/deploy/bundling).
- Can't decrypt after encrypting with a lock context: ensure the exact same lock context is provided to decrypt.
- Tests failing due to missing credentials: provide `CS_*` env vars; lock-context tests are skipped without `USER_JWT`.
- Performance testing: prefer bulk operations (`bulkEncrypt*` / `bulkDecrypt*`) to exercise ZeroKMS bulk speed.
