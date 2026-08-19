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
  - Subpath exports: `@cipherstash/stack`, `@cipherstash/stack/identity`, `@cipherstash/stack/schema`, `@cipherstash/stack/eql/v3`, `@cipherstash/stack/v3`, `@cipherstash/stack/types`, `@cipherstash/stack/dynamodb`, `@cipherstash/stack/encryption`, `@cipherstash/stack/errors`, `@cipherstash/stack/adapter-kit`, `@cipherstash/stack/wasm-inline` (the Drizzle and Supabase integrations moved to their own packages — see below)
- `packages/cli`: The `stash` CLI — auth, init, encryption schema, and database setup (`stash eql install`). Has its own `AGENTS.md`.
- `packages/wizard`: AI-powered encryption setup (`@cipherstash/wizard`)
- `packages/migrate`: Plaintext-to-encrypted column migration (`@cipherstash/migrate`) — resumable backfill, per-column state
- `packages/stack-prisma`: Prisma Next integration (`@cipherstash/stack-prisma`) — searchable field-level encryption for Postgres. **EQL v3 only**: per-domain constructors (`cipherstash.TextSearch()` / `text()` / `bigIntOrd()` / …) and `cipherstashFromStack` (the `./v3` and `./stack` entries). The EQL v2 surface was removed — the adapter's baseline migration installs the EQL v3 bundle only (works on Supabase as a non-superuser)
- `packages/stack-drizzle`: Drizzle ORM integration (`@cipherstash/stack-drizzle`), depends on `@cipherstash/stack` — **EQL v3 only**, on the package root (the v2 surface was removed and the old `./v3` subpath collapsed into `.`). Split out of `@cipherstash/stack`.
- `packages/stack-supabase`: Supabase integration (`@cipherstash/stack-supabase`), depends on `@cipherstash/stack` — **EQL v3 only**: `encryptedSupabase` is the v3 factory (`encryptedSupabaseV3` remains as a `@deprecated` alias). Split out of `@cipherstash/stack`.
- `packages/nextjs`: Next.js helpers and Clerk integration (`./clerk` export)
- `packages/utils`: Shared config (`utils/config`) and logger (`utils/logger`)
- `packages/bench`: Performance / index-engagement benchmarks (private, not published)
- `packages/protect-ffi`: Native FFI bindings to the CipherStash Client SDK (`@cipherstash/protect-ffi`) — the Rust core that `packages/stack` encrypts and decrypts through, absorbed from `cipherstash/protectjs-ffi`. Contains a **nested Cargo workspace** (`crates/`) and six per-platform binary packages under `platforms/*`, each published as `@cipherstash/protect-ffi-<platform>` and linked here via `workspace:*`. See the "Working on protect-ffi" notes below before touching it — its default `test` and `build` are deliberately Rust-free.
- `packages/eql`: The Encrypt Query Language subtree — the SQL bundle that stores and queries encrypted payloads — absorbed from `cipherstash/encrypt-query-language`. **The directory is the subtree root, not the package.** It was imported at a *verbatim prefix* so its repo-root-relative paths (mise tasks, `Doxyfile`, `sync-generated.mjs`) keep resolving, which puts the npm package `@cipherstash/eql` two levels down at `packages/eql/packages/eql` — the same shape as `packages/protect-ffi/platforms/*`, and enrolled the same way, by an explicit `packages/eql/packages/*` glob in `pnpm-workspace.yaml`. The subtree root deliberately carries no `package.json`. Also contains a **nested Cargo workspace** at `packages/eql/crates/` (`eql-bindings`, published in lockstep with the npm package, plus `eql-domains` / `eql-codegen` / `eql-tests-macros`, which are not), a SQLx test crate at `packages/eql/tests/sqlx`, an ~900-line `mise.toml` task surface, its own `AGENTS.md`, and `docs/`. See the "Working on EQL" notes below before touching it.
- `e2e/*`: Cross-package end-to-end tests (package managers, supply chain, Prisma example README)
- `examples/*`: Working apps (basic, prisma, supabase-worker)
- `docs/plans/*`: Internal design plans. User-facing documentation lives at https://cipherstash.com/docs (not in this repo).
- `skills/*`: Agent skills (`stash-cli`, `stash-encryption`, `stash-indexing`, `stash-deployment`, `stash-zerokms`, `stash-auth`, `stash-postgres`, `stash-edge`, `stash-drizzle`, `stash-dynamodb`, `stash-supabase`, `stash-prisma`, `stash-supply-chain-security`)

## Working on protect-ffi

`packages/protect-ffi` carries one of this repo's two Cargo workspaces (the
other is `packages/eql/crates`), and its scripts are split so a Rust toolchain
stays optional for everyone else.

- **The default `test` and `build` never invoke cargo.** Root `pnpm test` runs
  `turbo test --filter './packages/**'`, which reaches this package — so a cargo
  process on that path is a Rust toolchain on every contributor's machine.
  `test` is the JS chain; `build` is `tsc`.
- **CI does build the binding, in the jobs that need it.** That is the limit of
  the rule above: it keeps cargo off the *scripts*, not out of the pipeline.
  Absorbing protect-ffi turned `lib/`, `index.node` and `dist/wasm/**` from
  tarball contents into build outputs, so every job that encrypts, decrypts, or
  typechecks against the package builds them first via
  `.github/actions/build-ffi-binding` — passing `wasm: 'true'` only where the
  job loads the real WASM build, which is the minority and costs a second cargo
  build against wasm32. The action caches `index.node` on a content hash of the
  Rust inputs, so a PR touching no Rust pays a restore rather than a compile.
  **A new job that runs live encryption needs this step** — without it the
  failure is `Cannot find module '.../protect-ffi-linux-x64-gnu/index.node'`,
  reported once per test rather than once per job.
  `scripts/__tests__/ffi-binding-step-order.test.mjs` holds both halves of this:
  every job that receives a `CS_*` credential must build the binding, and the
  `require-cs-secrets` pre-flight must come first. Both scan the workflow
  directory rather than a list, so a new job is covered the day it lands.
- **Rust checks live behind `test:cargo`** (`cargo test` + `cargo fmt --check`)
  and `mise run lint:rust` (clippy, host and wasm32). `build:native` carries
  `cargo build --release`.
- **`src/lintWiring.test.ts` enforces the split**: no `test:*` script may be
  unreachable from both entry points, nothing cargo may be reachable from
  `test`, and every cargo check must be reachable from `test:cargo`. A check
  nothing invokes reads exactly like a check that passes — that is why the file
  exists.
- **Do not write `pnpm run <script> -- --flag`.** npm strips the `--`; pnpm
  forwards it verbatim, and these scripts end in `> cargo.log`, so the flag
  lands after the redirect and cargo rejects it. lintWiring asserts this too.
- **`lib/` is the package `main` and is generated**, so a workspace consumer
  resolves an empty package until `build` has run. `turbo.json` carries a
  `@cipherstash/protect-ffi#build` override declaring `outputs: ["lib/**"]`;
  without it Turbo caches the repo-wide `dist/**` and a cache hit restores
  nothing while reporting success.
- **Three WASM declaration files are tracked** (`dist/wasm/*.d.ts`) so stack's
  declaration build resolves `@cipherstash/protect-ffi/wasm-inline` without
  Rust. Everything else under `dist/` stays ignored. The re-inclusion chain
  spans the root `.gitignore`, the package's own, and a `.gitignore` wasm-pack
  generates — see the comments in each.
- **Publishing has not moved yet.** All seven packages are still published from
  `cipherstash/protectjs-ffi` until npm trusted publishing is repointed, so a
  changeset naming any of them fails CI (`scripts/lint-no-ffi-changeset.mjs`).
  Change the package freely — but write the changeset and park it as
  `.changeset/<name>.md.deferred`, don't skip it. Changesets and the guard both
  select on `.endsWith('.md')`, so that extension is inert to
  `changeset version`; the cutover PR renames **every** one of them back
  (`for f in .changeset/*.md.deferred; do git mv "$f" "${f%.deferred}"; done`).
  Check what is parked rather than assuming a single file — `ls
  .changeset/*.md.deferred`. Two are waiting today: the lazy native load, and
  the manifest repoint to `cipherstash/stack`.
- **The pipeline that will publish them is built and inert.** `release.yml`
  asks `scripts/release-gate.mjs` which committed versions are missing from npm;
  if any FFI one is, `_build-ffi-artifacts.yml` compiles the six platforms with
  an explicit `CARGO_BUILD_TARGET` each, packs all seven tarballs, and
  `publish-ffi` publishes the six platform packages **before** the wrapper and
  tags all seven — because `changeset publish` packs from the workspace, where
  `index.node` does not exist, and tags only what it published itself. Nothing
  fires until a version is unpublished, which the changeset guard above
  prevents. `ffi-preflight.yml` is the dry run (`changeset publish` has no
  `--dry-run`); dispatch it against the Version Packages branch before the
  cutover. The seven manifests already name `cipherstash/stack`, which npm
  requires of the publishing repository — so a publish attempted from the old
  repository would now be rejected, and nothing publishes from there.

### The `integration-tests/` suite

`packages/protect-ffi/integration-tests/` is 19 files of **live** coverage —
encrypt/decrypt, lock context, keysets, JS auth strategies, JSON SteVec,
Postgres (EQL v2 *and* v3), and a WASM round trip — and it is the only place
several of those paths are exercised at all. It needs three things a normal
`pnpm test` does not have: **Docker**, **CipherStash credentials**, and **both
EQL versions installed** in the database.

- **It is not a pnpm workspace member.** `pnpm-workspace.yaml` globs
  `packages/*` (one level) plus `packages/protect-ffi/platforms/*`, so this
  directory is invisible to pnpm and has its own `package-lock.json` with pins
  that deliberately differ from the repo catalog (`@cipherstash/auth ^0.39.0`,
  `vitest ^3.1.3`, `@cipherstash/eql 3.0.2`). `npm ci` installs it. Absorbing it
  into the workspace is a follow-up, not a tidy-up: it changes those pins, and
  only a credentialed run can prove the change is neutral.
- **Run it locally** from `packages/protect-ffi`:

  ```bash
  mise run setup                 # npm ci, docker compose up, EQL v2 + v3
  mise run test:integration:all  # includes tests/lock-context.test.ts
  ```

  `mise run test:integration` is the same suite **minus** lock context — prefer
  `:all`, which is what CI runs. Both tasks live in
  `integration-tests/tasks.toml`, included from `mise.toml`'s `[task_config]`,
  and both build the binding themselves (debug) before invoking vitest. Postgres
  is on **5436** (`docker-compose.yml` publishes `5436:5432`); `mise.toml`'s
  `[env]` carries the matching `PG*` values, and mise's `[env]` overrides an
  inherited one, so a stale `PGPORT` in your shell cannot misroute the tests.
- **In CI it runs from `.github/workflows/integration-protect-ffi.yml`** —
  path-filtered to this package (and the two actions it uses), credentialed, and
  fork-PR-skipped like the other `integration-*.yml` jobs. Two things there are
  deliberately *not* copies of upstream: it builds the binding with
  `.github/actions/build-ffi-binding` (`wasm: 'true'`) rather than
  `mise run build:debug`, because a **release** `index.node` at the package root
  satisfies `src/load.cts`'s `debug:` fallback and that action caches it; and it
  invokes vitest directly, since the mise task would recompile in the debug
  profile over the artifact the rest of CI already paid for. It does **not** use
  `.github/actions/integration-db` — the EQL installs in `tasks.toml` pipe SQL
  through `docker exec -i protect-ffi-postgres`, which only this suite's own
  compose file produces, and that action provides no EQL at all.
- **Nothing else in the repo installs EQL v2.** `eql:download` pulls the
  `eql-2.2.1` release bundle from GitHub and `eql:install` applies it;
  `tests/postgres.test.ts` needs it (`eql_v2_encrypted`,
  `eql_v2.add_encrypted_constraint`) while `tests/postgres-v3.test.ts` needs the
  `eql_v3_*` domains. Skip either and half the suite fails on missing SQL
  functions.
- **`src/integrationSuiteCi.test.ts` asserts a root workflow still runs it.**
  The suite ran on every upstream PR and then ran *nowhere* for the whole
  absorption, because the workflow that drove it was deposited under
  `packages/protect-ffi/.github/` — a directory GitHub never reads. That test is
  what stops it going quiet again, and it deliberately scans only the repo-root
  workflow directory.

## Working on EQL

`packages/eql` is a subtree import, not a package directory, and almost
everything surprising about it follows from that. Its own `AGENTS.md`
(`packages/eql/AGENTS.md`) covers EQL-internal work — SQL authoring, the codegen
pipeline, documentation standards. The notes below cover the *seams* with this
monorepo, which is where the silent failures are.

- **The package is at `packages/eql/packages/eql`, two levels down.** The
  subtree root has no `package.json` by design, so a tool that globs one level
  under `packages/` selects the root — a directory with no manifest and no
  scripts — and not the package. That is why root `pnpm test` is
  `turbo test --filter './packages/**'` and not `'./packages/*'`: under the
  one-level filter the task graph contained `@cipherstash/eql#build` (pulled in
  transitively by its consumers) and **no `#test` at all**, so its Vitest suite
  ran nowhere while CI stayed green. `build` can stay one-level because
  consumers pull it through `^build`. Anything else that walks `packages/*` needs
  the same treatment — `scripts/lint-typecheck-scope.mjs` already carries the
  two nested roots explicitly.
- **Anything invoking a mise task must run with `working_directory:
  packages/eql`.** `packages/eql/mise.toml` is ~900 lines and its
  `[task_config].includes` pulls in `tasks/`, `tasks/postgres.toml` and
  `tasks/fixtures.toml`; task bodies address `tasks/…`, `release/…` and
  `tests/sqlx/…` relative to the subtree root. mise reads config from the
  current directory and its parents, so invoking from the repo root finds no EQL
  config and fails with a *trust* error that reads like a broken toolchain
  rather than a wrong directory. `[env]` also pins `EQL_ROOT = {{config_root}}`,
  because two task scripts use `git rev-parse --show-toplevel`, which after the
  import returns the **monorepo** root — and one of them,
  `tasks/test/doc-anchors.sh`, fails silently when that is wrong.
- **`packages/eql/.github/` is a dead deposit.** GitHub reads workflows from the
  repo root and nowhere else, so the eleven files there run on nothing. Seven
  are workflows — four publish something (`release.yml`, `release-plz.yml`,
  `release-postgres-eql-image.yml`, `rebuild-docs.yml`) and three exist only to
  serve them (two `workflow_call` reusables and `lint-release.yml`) — alongside
  a `workflows/README.md`, the release-notes config, and two
  repository-settings files. `scripts/__tests__/eql-suite-ci.test.mjs` holds
  them as a **shrinking allowlist** (`UNPORTED_DEPOSIT`), asserted by equality so
  it fails in both directions: porting a workflow means deleting it from the
  deposit *and* from the list in the same commit, and dropping a new file in
  there without listing it fails too. The same test asserts that the three SQLx
  suite tasks are invoked by name from a root workflow, that every
  `dorny/paths-filter` path is scoped to `packages/eql/`, and that every mise
  task shelling out to cargo is either reachable from a root workflow or
  exempted with a written reason. It is the guard against the failure this
  absorption keeps rediscovering: a check that arrives as a file and executes on
  no event reads exactly like a check that passes.
- **One version, five artefacts.** `@cipherstash/eql` (npm), the `eql-bindings`
  crate, the SQL bundle, the docs and the `postgres-eql` image all ship at a
  single version V. The npm package's `version` is the source of truth
  (`changeset version` owns it) and `scripts/sync-lockstep-versions.mjs`
  propagates it to the crate and, via `mise run
  release:prepare_bindings_assets`, to the stamped SQL and release manifests. It
  runs from the root `version` script — Changesets only invokes the *root* one,
  which is why the script lives at the repo root and derives the subtree path
  itself. **`mise run build --version X` does not treat `--version` as a
  cache-key input**: it is absent from `tasks/build.sh`'s `#MISE sources`, so on
  unchanged SQL and Rust it is a cache hit that re-serves whatever version the
  previous build stamped. `tasks/release/prepare-bindings-assets.sh` passes
  `--force` for exactly that reason and then greps the stamp back out of the
  SQL before writing a manifest over it — read its comment before touching that
  path. Without both, the bundle ships stamped one version under a manifest,
  crate and npm package claiming another, and every digest still verifies.
- **`eql-bindings` resolves by path from `packages/protect-ffi`, never from
  crates.io**, and `scripts/lint-no-eql-registry-pins.mjs` (`pnpm run
  lint:eql-pins`) is what keeps it that way. The two halves of EQL are the Rust
  that EMITS a payload and the SQL that STORES and queries one; a registry pin
  lets them drift apart silently — it compiles, it passes CI, and it fails in a
  database. The linter reads every `Cargo.toml` and `package.json` plus
  `pnpm-workspace.yaml` (pnpm resolves `overrides` and `catalogs` from there,
  and a top-level npm-format `overrides` block in a `package.json` is silently
  ignored, so it is the one place a workspace-wide pin can be written and take
  effect). It exits **2**, not 0, when its own configuration has gone stale —
  a source it could not read, a declaration it expected and no longer sees, or
  an exemption excusing nothing. There is one exemption today
  (`packages/protect-ffi/integration-tests`, which installs with `npm ci` and
  cannot take a `workspace:` specifier); adding another means writing the reason
  down.
- **Two SQLx test constants are keyed to this repo's CI workspace.** SteVec
  selectors are MACs over (column context, JSONPath) under a *workspace keyset*,
  so `SELECTOR` in `tests/sqlx/src/fixtures/v3_doc_integer.rs` and `SEL_HELLO_OP`
  in `tests/sqlx/src/fixtures/v3_ste_vec.rs` changed value — with no change to
  Rust, SQL or fixture logic — the moment CI moved to this repo's
  `CS_WORKSPACE_CRN` (`9467cc5d`, `da141339`). Each has a drift guard that
  prints the candidate selectors and their discriminators rather than inferring
  a replacement, because guessing wrong re-pins to the wrong leaf silently —
  which had already happened once, `SEL_HELLO_OP` naming `$.number` while
  claiming `$.hello` and surviving because an equality-only assertion cannot
  separate them. **If you run the suite against your own CipherStash workspace
  the guards will fire: do not commit your local value.** Rotating
  `CS_WORKSPACE_CRN` re-pins both. `tests/sqlx/src/selectors.rs` holds five more
  workspace-keyed constants with no consumers and no guard — delete or guard
  them before using any of them.
- **Publishing has not moved yet.** npm trusted publishing for `@cipherstash/eql`
  still names `cipherstash/encrypt-query-language` — the SLSA provenance on
  `@cipherstash/eql@3.0.4` records that repository and
  `.github/workflows/release.yml` — and the package's own `repository` / `bugs`
  fields still point there, as do the `eql-bindings` crate's. Repointing all of
  it is the Phase-5 cutover, together with the nine parked workflows above.
  This is protect-ffi's situation with one difference: the guard is not a
  changeset lint but `scripts/release-gate.mjs`, and it is the stronger of the
  two. Its `FROZEN_PUBLISHERS` map lists every package that lives here but is
  published from another repository, and the gate **exits non-zero** — failing
  the `gate` job, which skips `release` entirely — if such a package's committed
  version is missing from npm, or if any published package carries a runtime
  `workspace:` range that only that package could satisfy. It fires today on the
  hand-applied 3.0.5 bump, which a changeset-side guard could not see, and it
  blocks the Version Packages PR as well as the publish. `tests.yml` runs the
  same script at PR time so the answer arrives a merge earlier. Delete the
  `@cipherstash/eql` entry in the Phase-5 cutover — and note the FFI half of
  that map is what turns `lint-no-ffi-changeset.mjs`'s unstated assumption
  ("all seven are already on npm at the workspace version") into a checked one.
  Note too that 3.0.5 did *not* come from `changeset version` —
  eleven unrelated changesets were pending, so the bump was entered by hand in
  `packages/eql/packages/eql/CHANGELOG.md` and the parked
  `rename-ste-vec-contains.md.deferred` deleted with it, precisely so the
  cutover cannot apply the same bump twice. Read that CHANGELOG entry before
  assuming a version's provenance.
- **Changesets for `@cipherstash/eql` go in the repo-root `.changeset/`.**
  `packages/eql/.changeset/` is an empty leftover of the subtree.

## Agent Skills — these ship to customers

`skills/*/SKILL.md` are **published artifacts, not internal notes.** Treat a wrong
sentence in one of them the way you'd treat a wrong line of code:

- `packages/cli/tsup.config.ts` copies `skills/` into `dist/skills/`, so they ship
  inside the `stash` npm tarball (and the `@cipherstash/wizard` one).
- `installSkills()` (`packages/cli/src/commands/init/lib/install-skills.ts`) copies the
  per-integration set into the user's `.claude/skills/` or `.codex/skills/` at handoff time.
- `readBundledSkill()` inlines a skill's body into the user's `AGENTS.md` for editor
  agents (Cursor / Windsurf / Cline), and as the Codex fallback for skills that could
  not be copied into `.codex/skills/` (#736). Only `SKILL.md` is inlined — content split
  into sibling files is silently dropped on that path, so keep each `SKILL.md`
  self-sufficient.

**Every change to a package's public API, the CLI command surface, or a user-facing
workflow must check the affected skills in the same PR.** These skills drift silently:
nothing type-checks them, and the damage lands in a customer's repo, not ours.

| If you change… | Check |
|---|---|
| `packages/cli` commands, flags, or prompts | `skills/stash-cli` |
| `packages/stack` encryption API, schema builders, subpath exports | `skills/stash-encryption` |
| Drizzle / Supabase / Prisma Next / DynamoDB integrations | `skills/stash-drizzle`, `skills/stash-supabase`, `skills/stash-prisma`, `skills/stash-dynamodb` |
| The rollout/cutover lifecycle (`packages/migrate`, `stash encrypt *`) | `skills/stash-encryption` and `skills/stash-cli` |
| The deploy sequencing / deploy-gate story, `stash env`, or platform-specific deployment guidance | `skills/stash-deployment` |
| The `@cipherstash/eql` pin, `eql install`/`eql migration` behaviour, or index-related SQL guidance | `skills/stash-indexing` |
| The EQL operator/domain surface (`eql_v3.query_*` casts, predicate forms) | `skills/stash-postgres` |
| The keyset/client model (`config.keyset`, grants, the ZeroKMS access story) | `skills/stash-zerokms` — the canonical source; other skills should point here rather than restate it |
| Auth strategies (`config.authStrategy`), the `CS_*` variables, lock context, `stash env` / `auth login` behaviour | `skills/stash-auth` — the canonical source; other skills should point here rather than restate it |
| `packages/stack/src/wasm-inline.ts`, the WASM entry's exports, or `stash env` | `skills/stash-edge` |
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

- **Initialization**: `Encryption({ schemas })` is the single client factory. It requires at least one concrete EQL v3 `encryptedTable` and returns `EncryptionClient<S>`, whose model and query types are derived from that schema tuple. The `EncryptionV3`, `typedClient`, `EncryptionClientFor`, and nominal-client surfaces have been removed.
- **Schema**: Define tables/columns with `encryptedTable` and the `types.*` concrete-domain factories from `@cipherstash/stack/eql/v3` (`types.TextSearch`, `types.IntegerOrd`, `types.Json`, …) — each domain's query capabilities are fixed by its type; there are no chainable capability tuners. Build the client with `Encryption` (import `Encryption`, `encryptedTable`, and `types` from `@cipherstash/stack/v3`). Schema authoring and all writes are EQL v3-only; `config.eqlVersion` and the public EQL v2 schema builders have been removed. Both the native and `wasm-inline` clients still decrypt existing v2 payloads. DynamoDB legacy reads use the same v3 table descriptor plus `{ storedEqlVersion: 2 }`, and the table must be one given to `Encryption({ schemas })`; nested v3 fields use a flat dotted column path (`'profile.ssn': types.TextEq(...)`).
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
  - **Drizzle ORM**: `types.*` column factories, `extractEncryptionSchema`, `createEncryptionOperators` from `@cipherstash/stack-drizzle`
  - **Supabase**: `encryptedSupabase` from `@cipherstash/stack-supabase` (EQL v3; `encryptedSupabaseV3` is a `@deprecated` alias)
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
2. If modifying `packages/stack` encryption operations or `EncryptionClient`, ensure:
   - The Result contract and error type strings remain stable.
   - `.withLockContext()` remains available for affected operations.
   - ESM/CJS exports continue to work (don't break `require`).
3. If changing schema behavior (`packages/stack` schema builders, `@cipherstash/stack/schema`), update type definitions and ensure validation still works in `EncryptionClient.init`.
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
