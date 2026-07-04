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
  - Subpath exports: `@cipherstash/stack`, `@cipherstash/stack/client`, `@cipherstash/stack/identity`, `@cipherstash/stack/secrets`, `@cipherstash/stack/schema`, `@cipherstash/stack/types`, `@cipherstash/stack/drizzle`, `@cipherstash/stack/dynamodb`, `@cipherstash/stack/supabase`, `@cipherstash/stack/encryption`, `@cipherstash/stack/errors`, `@cipherstash/stack/wasm-inline`
- `packages/protect`: Core encryption library (internal, re-exported via `@cipherstash/stack`)
  - `src/index.ts`: Public API (`Encryption`, exports)
  - `src/ffi/index.ts`: `EncryptionClient` implementation, bridges to `@cipherstash/protect-ffi`
  - `src/ffi/operations/*`: Encrypt/decrypt/model/bulk/query operations (thenable pattern with optional `.withLockContext()`)
  - `__tests__/*`: End-to-end and API contract tests (Vitest)
- `packages/cli`: The `stash` CLI — auth, init, encryption schema, database setup (`stash eql install`), and secrets. Has its own `AGENTS.md`.
- `packages/wizard`: AI-powered encryption setup (`@cipherstash/wizard`)
- `packages/migrate`: Plaintext-to-encrypted column migration (`@cipherstash/migrate`) — resumable backfill, per-column state
- `packages/prisma-next`: Prisma Next integration (`@cipherstash/prisma-next`) — searchable field-level encryption for Postgres
- `packages/schema`: Schema builder utilities and types (`encryptedTable`, `encryptedColumn`, `encryptedField`)
- `packages/drizzle`: Drizzle ORM integration (`encryptedType`, `extractEncryptionSchema`, `createEncryptionOperators`)
- `packages/nextjs`: Next.js helpers and Clerk integration (`./clerk` export)
- `packages/protect-dynamodb`: DynamoDB helpers (`encryptedDynamoDB`)
- `packages/utils`: Shared config (`utils/config`) and logger (`utils/logger`)
- `packages/bench`: Performance / index-engagement benchmarks (private, not published)
- `e2e/*`: Cross-package end-to-end tests (package managers, supply chain, Prisma example README)
- `examples/*`: Working apps (basic, prisma, supabase-worker)
- `docs/plans/*`: Internal design plans. User-facing documentation lives at https://cipherstash.com/docs (not in this repo).
- `skills/*`: Agent skills (`stash-cli`, `stash-encryption`, `stash-drizzle`, `stash-dynamodb`, `stash-secrets`, `stash-supabase`, `stash-supply-chain-security`)

## Supply Chain Security

This repo applies a set of supply-chain controls (post-install script policy, install cooldown, frozen-lockfile CI, registry pinning, Dependabot cooldown, CODEOWNERS) sourced from [lirantal/npm-security-best-practices](https://github.com/lirantal/npm-security-best-practices). They're validated by `e2e/tests/supply-chain.e2e.test.ts` so silent regressions fail CI. See `skills/stash-supply-chain-security/SKILL.md` for the full guide.

Three rules to remember when editing CI or pnpm config:

1. **CI uses `pnpm install --frozen-lockfile`.** Don't drop the flag.
2. **Adding to `pnpm.onlyBuiltDependencies` is an audit decision** — vet the package and explain the addition in the PR.
3. **Don't commit auth tokens in `.npmrc`.** Tokens belong in user-level `~/.npmrc` or environment variables.

## Key Concepts and APIs

- **Initialization**: `Encryption({ schemas })` returns an initialized `EncryptionClient`. Provide at least one `encryptedTable`.
- **Schema**: Define tables/columns with `encryptedTable` and `encryptedColumn` from `@cipherstash/stack/schema`. Add `.freeTextSearch().equality().orderAndRange()` to enable searchable encryption on PostgreSQL. Use `.searchableJson()` for encrypted JSONB queries. Use `encryptedField` for nested object encryption (DynamoDB).
- **Operations** (all return Result-like objects and support chaining `.withLockContext(lockContext)` and `.audit()` when applicable):
  - `encrypt(plaintext, { table, column })`
  - `decrypt(encryptedPayload)`
  - `encryptModel(model, table)` / `decryptModel(model)`
  - `bulkEncrypt(plaintexts[], { table, column })` / `bulkDecrypt(encrypted[])`
  - `bulkEncryptModels(models[], table)` / `bulkDecryptModels(models[])`
  - `encryptQuery(value, { table, column, queryType?, returnType? })` for searchable queries
  - `encryptQuery(terms[])` for batch query encryption
- **Identity-aware encryption**: Authenticate the client as the end user with `OidcFederationStrategy` (`config.strategy`, re-exported from `@cipherstash/stack`), then chain `.withLockContext({ identityClaim })` on operations to bind the data key to a claim. The same claim must be used for encrypt and decrypt. (`LockContext.identify()` from `@cipherstash/stack/identity` is deprecated — the strategy now handles token acquisition; `.withLockContext()` also accepts a `LockContext`.)
- **Integrations**:
  - **Drizzle ORM**: `encryptedType`, `extractEncryptionSchema`, `createEncryptionOperators` from `@cipherstash/stack/drizzle`
  - **Supabase**: `encryptedSupabase` from `@cipherstash/stack/supabase`
  - **DynamoDB**: `encryptedDynamoDB` from `@cipherstash/stack/dynamodb`
- **Secrets management**: `Secrets` class from `@cipherstash/stack/secrets` for encrypted secret storage and retrieval.

## Critical Gotchas (read before coding)

- **Native Node.js module**: `@cipherstash/stack` relies on `@cipherstash/protect-ffi` (Node-API). It must be loaded via native Node.js `require`. Do NOT bundle this module; configure bundlers to externalize it. See the bundling guide: https://cipherstash.com/docs/stack/deploy/bundling
- **Do not log plaintext**: The library never logs plaintext by design. Don't add logs that risk leaking sensitive data.
- **Result shape is contract**: Operations return `{ data }` or `{ failure }`. Preserve this shape and error `type` values in `EncryptionErrorTypes`.
- **Encrypted payload shape is contract**: Keys like `c` in the EQL payload are validated by tests and downstream tools. Don't change them.
- **Exports must support ESM and CJS**: Each package's `exports` maps must keep both `import` and `require` fields. Don't remove CJS.

## Development Workflow

- **Formatting/Linting**: Use Biome

```bash
pnpm run code:fix
```

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

- When integrating into frameworks/build tools, ensure native modules are externalized and loaded via Node's runtime require.
- For Next.js, configure `serverExternalPackages`; for SST/serverless and npm-lockfile-v3 quirks on Linux, see the bundling guide: https://cipherstash.com/docs/stack/deploy/bundling

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
7. **Add a changeset before opening or finalising the PR** when the
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

- Module load errors on Linux/serverless: review the bundling guide (https://cipherstash.com/docs/stack/deploy/bundling).
- Can't decrypt after encrypting with a lock context: ensure the exact same lock context is provided to decrypt.
- Tests failing due to missing credentials: provide `CS_*` env vars; lock-context tests are skipped without `USER_JWT`.
- Performance testing: prefer bulk operations (`bulkEncrypt*` / `bulkDecrypt*`) to exercise ZeroKMS bulk speed.
