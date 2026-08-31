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
  - Subpath exports: `@cipherstash/stack`, `@cipherstash/stack/identity`, `@cipherstash/stack/schema`, `@cipherstash/stack/eql/v3`, `@cipherstash/stack/v3`, `@cipherstash/stack/types`, `@cipherstash/stack/dynamodb`, `@cipherstash/stack/encryption`, `@cipherstash/stack/errors`, `@cipherstash/stack/adapter-kit`, `@cipherstash/stack/wasm-inline`, `@cipherstash/stack/diagnostics` (the Drizzle and Supabase integrations moved to their own packages — see below)
- `packages/cli`: The `stash` CLI — auth, init, encryption schema, and database setup (`stash eql install`). Has its own `AGENTS.md`.
- `packages/wizard`: AI-powered encryption setup (`@cipherstash/wizard`)
- `packages/migrate`: Plaintext-to-encrypted column migration (`@cipherstash/migrate`) — resumable backfill, per-column state
- `packages/stack-prisma`: Prisma Next integration (`@cipherstash/stack-prisma`) — searchable field-level encryption for Postgres. **EQL v3 only**: per-domain constructors (`cipherstash.TextSearch()` / `text()` / `bigIntOrd()` / …) and `cipherstashFromStack` (the `./v3` and `./stack` entries). The EQL v2 surface was removed — the adapter's baseline migration installs the EQL v3 bundle only (works on Supabase as a non-superuser)
- `packages/stack-drizzle`: Drizzle ORM integration (`@cipherstash/stack-drizzle`), depends on `@cipherstash/stack` — **EQL v3 only**, on the package root (the v2 surface was removed and the old `./v3` subpath collapsed into `.`). Split out of `@cipherstash/stack`.
- `packages/stack-supabase`: Supabase integration (`@cipherstash/stack-supabase`), depends on `@cipherstash/stack` — **EQL v3 only**: `encryptedSupabase` is the v3 factory (`encryptedSupabaseV3` remains as a `@deprecated` alias). Split out of `@cipherstash/stack`. Two entries: the package root (native engine, Node) and `./wasm-inline` (WASM engine, edge — ESM-only, and declared-`schemas` only since it carries no Postgres driver).
- `packages/nextjs`: Next.js helpers and Clerk integration (`./clerk` export)
- `packages/utils`: Shared config (`utils/config`) and logger (`utils/logger`)
- `packages/bench`: Performance / index-engagement benchmarks (private, not published)
- `packages/protect-ffi`: Native FFI bindings to the CipherStash Client SDK (`@cipherstash/protect-ffi`) — the Rust core that `packages/stack` encrypts and decrypts through, absorbed from `cipherstash/protectjs-ffi`. Contains a **nested Cargo workspace** (`crates/`) and six per-platform binary packages under `platforms/*`, each published as `@cipherstash/protect-ffi-<platform>` and linked here via `workspace:*`. Also holds the repo's live FFI integration suite at `integration-tests/` — a private workspace member (`@cipherstash/ffi-integration-tests`) enrolled by its own literal entry in `pnpm-workspace.yaml`, needing Docker and credentials, and deliberately carrying **no `test` script** so `pnpm test` cannot reach it. See the "Working on protect-ffi" notes below before touching it — its default `test` and `build` are deliberately Rust-free.
- `packages/eql`: The Encrypt Query Language subtree — the SQL bundle that stores and queries encrypted payloads — absorbed from `cipherstash/encrypt-query-language`. **The directory is the subtree root, not the package.** It was imported at a *verbatim prefix* so its repo-root-relative paths (mise tasks, `Doxyfile`, `sync-generated.mjs`) keep resolving, which puts the npm package `@cipherstash/eql` two levels down at `packages/eql/packages/eql` — the same shape as `packages/protect-ffi/platforms/*`, and enrolled the same way, by an explicit `packages/eql/packages/*` glob in `pnpm-workspace.yaml`. The subtree root deliberately carries no `package.json`. Also contains a **nested Cargo workspace** at `packages/eql/crates/` (`eql-bindings`, published in lockstep with the npm package, plus `eql-domains` / `eql-codegen` / `eql-tests-macros`, which are not), a SQLx test crate at `packages/eql/tests/sqlx`, an ~900-line `mise.toml` task surface, its own `AGENTS.md`, and `docs/`. See the "Working on EQL" notes below before touching it.
- `e2e/*`: Cross-package end-to-end tests (package managers, supply chain, Prisma example README)
- `examples/*`: Working apps (basic, prisma, supabase-worker)
- `docs/plans/*`: Internal design plans. User-facing documentation lives at https://cipherstash.com/docs (not in this repo).
- `skills/*`: Agent skills (`stash-cli`, `stash-encryption`, `stash-indexing`, `stash-deployment`, `stash-zerokms`, `stash-auth`, `stash-postgres`, `stash-edge`, `stash-drizzle`, `stash-dynamodb`, `stash-supabase`, `stash-prisma`, `stash-managed-platforms`, `stash-supply-chain-security`)

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
- **Rust checks live behind `test:cargo`** (`cargo test --locked` + `cargo fmt
  --check`) and `mise run lint:rust` (clippy, host and wasm32). `build:native`
  carries `cargo build --release`.
  **`--locked` is on the CHECK and deliberately not on the builds.** Nothing in
  this repo passed it at all until the #915 follow-up, and the bill came due
  through `sync-lockstep-versions.mjs`: it rewrites `eql-bindings`'s crate
  version on every lockstep bump, `packages/protect-ffi` depends on that crate
  by path, so its `Cargo.lock` records the version — and nothing updated it.
  After the 3.0.5 bump `cargo metadata --locked` exited 101 while every cargo
  command in CI regenerated the lock in memory, built against the regenerated
  one and threw it away with the runner. Nothing went red. `build:native` is a
  documented local command, and a contributor who has just edited `Cargo.toml`
  regenerates the lock on their next build, legitimately — `--locked` there is
  a failure at the end of a compile. The check answers the same question on the
  same commit without standing in front of a build.
  `src/lintWiring.test.ts` holds this: every cargo script reachable from
  `test:cargo` must carry `--locked` or be exempted with a reason, and the one
  exemption (`cargo fmt`, an external subcommand that resolves nothing and
  forwards the flag to rustfmt) expires if it ever stops applying.
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
- **Publishing has moved here, and the path is proven.** npm trusted publishing
  for all seven packages is repointed at this repo, bound to `release.yml`, so
  write changesets for them normally. `@cipherstash/protect-ffi@0.32.0` was
  published from here: its SLSA provenance names
  `https://github.com/cipherstash/stack` and `.github/workflows/release.yml`,
  which is the only evidence that settles it —

  ```
  curl -s https://registry.npmjs.org/-/npm/v1/attestations/@cipherstash%2fprotect-ffi@0.32.0
  ```

  This paragraph said the opposite until 2026-08-20. It was written while
  0.31.0 was newest and true then; 0.32.0 landed and nothing brought the
  sentence with it, so "treat the path as configured rather than proven"
  outlived the release that proved it. Check the registry before repeating a
  claim about what has or has not shipped. The remaining steps live in
  `docs/plans/2026-08-04-protect-ffi-monorepo-absorption.md`, Phase 4.
- **A `.md.deferred` changeset is now a CI failure, having briefly been inert.**
  The parking convention and the `lint-no-ffi-changeset` guard that enforced it
  are both gone — `e77bfcec` retired the guard and renamed the two files parked
  at the time in one commit, and they released in
  `@cipherstash/protect-ffi@0.32.0`. A file still carrying that suffix is
  invisible to `@changesets/read`, so whatever it describes would ship with an
  empty changelog entry and nothing in `changeset version` or `changeset
  publish` would say so.
  **Before renaming one back, check whether it has already released** — a
  long-lived branch cut before the cutover still carries both files, and
  reactivating them there republishes a shipped entry and re-bumps the package
  for a change two versions old. Delete in that case; `git mv` back to `.md`
  only if it is genuinely unreleased.
  `scripts/__tests__/no-parked-changesets.test.mjs` fails on a parked file
  either way, and also fails if the retired guard is reinstated alongside it —
  the two rules contradict each other, and a half-retired convention is what
  produces a parked file in the first place.
- **The pipeline that publishes them.** `release.yml` asks
  `scripts/release-gate.mjs` which committed versions are missing from npm; if
  any FFI one is, `_build-ffi-artifacts.yml` compiles the six platforms with an
  explicit `CARGO_BUILD_TARGET` each, packs all seven tarballs, and
  `publish-ffi` publishes the six platform packages **before** the wrapper and
  tags all seven — because `changeset publish` packs from the workspace, where
  `index.node` does not exist, and tags only what it published itself. Nothing
  fires unless a committed version is absent from the registry, so a push that
  bumps nothing is a no-op for all seven. `ffi-preflight.yml` is the dry run
  (`changeset publish` has no `--dry-run`); dispatch it against the Version
  Packages branch before merging a release that moves an FFI version.
- **Trusted publishing binds to (repository, workflow filename).** Keep
  `release.yml` as the single npm entry point; a rename silently invalidates all
  seven publisher configurations. Each one must also list `npm publish` under
  **Allowed actions** — npm made that field required for configurations created
  after 2026-05-20, and a stage-only setting reads as configured while failing
  every `npm publish`. Check with `npm trust list <pkg>`.

### The `integration-tests/` suite

`packages/protect-ffi/integration-tests/` is 19 files of **live** coverage —
encrypt/decrypt, lock context, keysets, JS auth strategies, JSON SteVec,
Postgres (EQL v2 *and* v3), and a WASM round trip — and it is the only place
several of those paths are exercised at all. It needs three things a normal
`pnpm test` does not have: **Docker**, **CipherStash credentials**, and **both
EQL versions installed** in the database.

- **It is a pnpm workspace member, and `pnpm test` must never reach it.** Named
  literally in `pnpm-workspace.yaml` (the `packages/*` glob is one level deep and
  stops short of it), so its dependencies come from the repo lockfile:
  `@cipherstash/eql` at `workspace:^`, `@cipherstash/protect-ffi` at
  `workspace:*`, `@cipherstash/auth` / `vitest` / `typescript` from
  `catalog:repo`. It had its own `package-lock.json` and an `npm ci` until
  CIP-3744; the pin that mattered was `@cipherstash/eql 3.0.2`, the last place in
  the tree where the SQL that STORES a payload could disagree with the Rust that
  EMITS it — and it would have disagreed in a database, not in CI.

  The cost of membership: root `pnpm test` is `turbo test --filter
  './packages/**'`, which now reaches this package. It is kept out by **naming no
  live script after a turbo task** — the suite's runners are `vitest:live` and
  `vitest:live:coverage`, which `turbo.json` knows nothing about. `test` is the
  obvious trap and `test:integration` is the less obvious one (a real turbo task,
  invoked by four integration workflows — all `--filter`ed today, so an
  unfiltered `turbo run test:integration` is what would bite).
  `src/integrationSuiteCi.test.ts` derives the forbidden set from `turbo.json`
  rather than listing it, so a task added there tomorrow is covered.

  `typecheck` is the deliberate exception: it *should* run under `turbo run
  typecheck`, and does, from `tests.yml`, on every PR. It needs no credentials
  and no database, and its tsconfig sets `checkJs` so the suite's two `.cjs`
  fixtures are compiled too — one of them is a real `AccessKeyStrategy` call
  site, and a `tests/**/*.ts` scope would leave it checked by nothing but the
  path-filtered credentialed job.
- **Run it locally** from `packages/protect-ffi`:

  ```bash
  mise run setup                 # pnpm install, docker compose up, EQL v2 + v3
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
- **`eql:v3:install` builds `@cipherstash/eql` first, and has to.** The task
  reads the bundle through `@cipherstash/eql/sql`, which the package's `exports`
  map resolves to `dist/sql.js` — a tsup output. That was free while `npm ci`
  unpacked a published tarball with `dist/` already in it; from the workspace it
  is a build. Without it the task dies on `ERR_MODULE_NOT_FOUND`, which reads as
  a broken dependency rather than an unbuilt one.
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
- **`packages/eql/.github/` is gone, and a test fails if it returns.** It was a
  dead deposit: GitHub reads workflows from the repo root and nowhere else, so
  the eleven files that arrived with the subtree ran on nothing.
  `scripts/__tests__/eql-suite-ci.test.mjs` held them as a shrinking allowlist
  until the release port emptied it, and now asserts the directory is gone.
  **Never put a workflow under a package.** That same test also asserts that the three SQLx suite tasks are
  invoked by name from a root workflow, that every `dorny/paths-filter` path is
  scoped to `packages/eql/`, and that every mise task shelling out to cargo is
  either reachable from a root workflow or exempted with a written reason.
  That scan now follows a task's `tasks/*.sh` delegations **transitively**
  (cycle-guarded, and it throws rather than truncating past
  `MAX_SCRIPT_DEPTH`), and it reads the `run:` bodies of composite actions a
  workflow reaches through `uses: ./…`. Both used to stop at one hop, and both
  failure directions were live: a cargo helper reached only at depth 2 dropped
  out of `CARGO_TASKS` entirely — no orphan reported, no exemption demanded,
  and the job running it stopped counting as a Rust job for the cache check —
  while a mise task invoked from a composite action read as run by nobody,
  whose natural repair is an exemption claiming CI does not run it.
- **The EQL release pipeline is built and INERT, and the switch that arms it is
  derived rather than flipped.** Five artefacts ship at one version — the npm
  package, the `eql-bindings` crate, the SQL bundle, the docs bundle and the
  `postgres-eql` image — and the workflows that produce them all live at the
  repo root now:

  | file | what it does |
  |---|---|
  | `release.yml` | `classify` + the EQL production and prerelease jobs. It is one file with the JS and FFI releases because npm trusted publishing binds a package to a repository **and a workflow filename** |
  | `_build-eql-sql.yml`, `_build-eql-docs.yml` | `workflow_call` reusables, called from both EQL paths so there is one build path per artefact |
  | `release-plz.yml` | the crate. **Its filename cannot change** — crates.io Trusted Publishing binds to it |
  | `release-postgres-eql-image.yml` | the GHCR image, dispatched by `release.yml` on production finals |
  | `lint-release.yml` | merged into the root file of the same name |
  | ~~`rebuild-docs.yml`~~ | **not ported.** It targeted the retired docs site through the deprecated `DOCS_WEBHOOK_URL`; versioned docs artifacts are still built by `_build-eql-docs.yml` |

  **Inertness is a derived switch, not a flag somebody flips.** The one piece
  of state is `FROZEN_PUBLISHERS` in `scripts/release-gate.mjs` — the existing
  map recording "this package lives here but is published elsewhere" — and
  every job that publishes an EQL artefact is gated on its answer. **Deleting
  the `@cipherstash/eql` entry at the Phase-5 cutover is what arms the
  pipeline**, and there is no second thing to remember, because the cutover has
  to delete it anyway: the release gate blocks every release until it does. A
  separate flag would have failed silently in the worst direction — an npm
  package published with no SQL release, no docs and no crate.

  **Two readers, one map, and they are not the same code path.** Say which you
  mean:

  - `scripts/eql-pipeline-armed.mjs` imports the map and answers "may this
    repository publish EQL at all?". Ten jobs across `release.yml`,
    `release-plz.yml` and `release-postgres-eql-image.yml` carry
    `if: needs.eql-armed.outputs.armed == 'true'`. That covers the SQL bundle,
    the docs, the crate, the image and the *prerelease* npm publish.
  - The **production npm publish does not.** `release.yml`'s `release` job runs
    `changeset publish` gated only on `needs.gate.result == 'success'`, and
    `.changeset/config.json` has `"ignore": []`, so `@cipherstash/eql` is
    publishable like any other workspace member. What holds it is
    `release-gate.mjs` exiting non-zero for a frozen publisher, which fails the
    `gate` job and skips `release` entirely.

  Both keyed on the same entry, so one deletion still arms all five. But
  nothing asserts the two agree: relax the gate and the npm half opens while
  `eql-armed` still reports `false` and the other four jobs skip correctly —
  which is exactly the outcome the derived switch exists to prevent. This
  paragraph said "every one sits behind `eql-pipeline-armed.mjs`" until an
  audit read the `needs:` list. Run `node scripts/release-gate.mjs` for what
  the gate is doing right now rather than inferring it from here.

  **The cutover needs two more things, neither of which a workflow can assert
  ahead of time:** a `GPG_PRIVATE_KEY` secret (release-plz signs its commit and
  tag, and this repository has none); write access from here to the
  `ghcr.io/cipherstash/postgres-eql` package, still linked to
  `cipherstash/encrypt-query-language`. The old docs-site webhook is not a
  cutover dependency: that site and `DOCS_WEBHOOK_URL` are retired.
- **A release workflow may not restore a cache, including a Rust one.**
  `lint-no-workflow-caching.mjs` forbids a cache restore anywhere an artefact is
  published; `eql-suite-ci.test.mjs` wants `Swatinem/rust-cache` on every job
  that compiles Rust. Four EQL release jobs do both, so they pay a cold compile.
  The exemption is derived from the linter's own target list rather than copied,
  so the two cannot disagree about which jobs those are.
- **The EQL path filters are three copies of one list, and the list is derived
  now, not remembered.** `test-eql.yml` writes it twice (an `on: push: paths:`
  filter deciding whether the workflow starts at all, and a
  `dorny/paths-filter` `relevant:` block gating the heavy jobs inside a pull
  request); `bench-eql.yml` writes a third copy. GitHub has no YAML anchors, so
  nothing but `scripts/__tests__/eql-workflow-filters.test.mjs` keeps them
  together. That file now also walks each `mise run` in both workflows out to
  the task it names — through `[tasks."…"]` tables, file tasks under `tasks/`,
  `depends`, and nested `mise run` calls — and fails if the `push` filter does
  not select a path those task bodies name. That is what found
  `packages/eql/docs/**`, `packages/eql/docker/**`, `packages/eql/README.md`
  and `packages/eql/SUPABASE.md` missing from all three copies while
  `docs-static`'s `mise run test:docs_v3_grep` scanned every one of them: a
  push to main touching only documentation started no EQL workflow at all.
  **`pull_request` was never affected** — it applies no `paths:` filter, and
  `docs-static` and `doc-anchors` are deliberately not relevance-gated. The
  derivation reads paths that are WRITTEN DOWN; it cannot see `postgres:up`
  picking up `tests/docker-compose.yml` from its working directory, or the glob
  pathspec in `tasks/test/doc-anchors.sh` (`git ls-files '*.md'`, i.e. every
  tracked markdown file in the subtree). Those are still read by hand.
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
  `scripts/__tests__/eql-sql-asset-freshness.test.mjs` is what holds the
  result. It compares the npm package's `version` against every
  `release-manifest.json` under the subtree, against
  `src/generated/release-manifest.ts`, against the `eql-bindings` crate
  manifest, and — the one the cache hit actually breaks — against the `COMMENT
  ON SCHEMA eql_v3 IS '…'` stamp inside the install bundle itself. All of those
  are needed: the digests are recomputed over whatever bytes were served, so a
  stale bundle verifies perfectly; only the stamp records which build produced
  it. The predicate lives in `scripts/sync-lockstep-versions.mjs`
  (`eqlLockstepSkew`) because the release hook needs the same answer, and a
  PR-time guard that could disagree with the release-time decision is two
  guards. **It is deliberately not keyed to `FROZEN_PUBLISHERS`.** The gate's
  `FROZEN_ARTEFACT_DIGESTS` check compares the tree against *npm* and is
  deleted at the Phase-5 cutover; this compares the tree against *itself*,
  which is a property of a lockstep release rather than of who publishes it, so
  it survives.
- **The version hook no longer rewrites the SQL assets on a release that does
  not bump EQL.** `scripts/sync-lockstep-versions.mjs` runs on *every* release,
  and its step 4 (`mise run release:prepare_bindings_assets`) re-hashed freshly
  built SQL and overwrote all four release manifests plus both copies of the
  bundle — unconditionally, including when the version had not moved.
  `packages/eql/mise.toml` pins `rust = { version = "latest" }`, so the
  toolchain compiling `eql-codegen` is not the same one month to month, and
  nothing anywhere proves that regenerating from in-tree source reproduces
  npm's published bytes. Put those together and a release that never touched
  EQL can pick up a new digest under an unchanged version, at which point the
  next `release-gate.mjs` run fires `frozen-bytes-skew`, the `gate` job exits
  non-zero and `release` is skipped — the whole release blocked by an artefact
  nobody was releasing, *after* `changeset version` has already rewritten every
  manifest and CHANGELOG in the tree.
  Step 4 now runs only when `eqlLockstepSkew` finds a disagreement, and
  re-checks afterwards that the copy actually landed in both directories. A
  real bump always disagrees (`package.json` moves first), so the skip is not
  reachable by bumping. What it declines is the no-op — and for in-tree SQL
  *source* changed without a changeset, declining is the correct answer rather
  than a missed one: regenerating there republishes different bytes under a
  released number, which is precisely what the gate refuses. The changeset is
  what brings the rebuild back.
  **Pinning `rust` in `packages/eql/mise.toml` was considered and rejected**:
  it is a one-line divergence in the ~900-line file upstream edits most, it
  changes what the whole EQL CI surface compiles against, and with the skip in
  place the release-stopper is closed without it. If wanted, the pin belongs
  upstream and arrives by subtree pull.
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
  an exemption excusing nothing. There are **no exemptions today**: the only one
  there had ever been (`packages/protect-ffi/integration-tests`, which installed
  with `npm ci` and could not take a `workspace:` specifier) was retired when
  that directory joined the pnpm workspace, and the guard's own staleness rule —
  keyed on "excuses nothing", not "names nothing" — is what forced it out in the
  same commit rather than leaving a standing permission behind. Adding one means
  writing the reason down.
  It also reads the Cargo redirect tables — `[patch.*]` (including
  `[patch."https://…"]` and the dotted `[patch.crates-io.eql-bindings]` form)
  and `[replace]` — plus **`.cargo/config.toml`**, because cargo honours a
  `[patch]` written there and a walk keyed on manifest filenames never opens
  it. That is the `pnpm-workspace.yaml` failure one ecosystem along: the
  quietest place to re-point a dependency is the file the linter was not
  reading. Still not read: `[source.*] replace-with`, which redirects the whole
  registry rather than naming a crate, so there is no `eql-bindings`
  declaration to classify — closing it is a different check (does this tree
  redirect crates.io at all), not an extension of this one.
  **`packages/eql`'s own cargo tasks still pass no `--locked`.** `mise run
  test:crates`, `codegen:parity` and the SQLx archive/partition tasks all shell
  to a plain `cargo …`. `cargo tree --locked` exits 0 there today, so the flag
  would pass if added — and this is the workspace whose `Cargo.lock` the
  lockstep bump actually moves. Left open only because it means editing the
  subtree's `mise.toml`.
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
- **`FROZEN_PUBLISHERS` is what stops this repo publishing EQL, and it is a
  mechanism, not a status.** `scripts/release-gate.mjs` carries a map of every
  package that lives here but is published from another repository. For each,
  the gate **exits non-zero** — failing the `gate` job, which skips `release`
  entirely — on any of three conditions:

  1. the package's committed version is missing from npm;
  2. any published package carries a runtime `workspace:` range that only that
     package could satisfy;
  3. the frozen package's in-tree artefact is **not the bytes published under
     the version the tree claims**.

  Any one stops the Version Packages PR and the publish alike. A changeset-side
  guard sees none of them.

  **Whether the gate is blocking anything right now is a question for the
  registry, not for this file: run `node scripts/release-gate.mjs` and read what
  it says.** `tests.yml` runs the same script at PR time so the answer arrives a
  merge earlier. Which registry publishes what, and whether trusted publishing
  has been repointed, is likewise configuration — check the registry, do not
  read it here. This bullet used to narrate that state and was wrong twice.

  **Delete the `@cipherstash/eql` entry in the Phase-5 cutover.**
  `scripts/__tests__/frozen-publisher-docs.test.mjs` fails until this paragraph
  goes with it, and `SECURITY.md`'s "Note on publishing" is the third document
  it holds — the one file that tells a reporter which pipeline built the
  artefact they are reporting on. `release-gate.test.mjs` also asserts the map
  carries no FFI name: the seven protect-ffi packages were left in it after
  their own cutover, which armed the gate against the first release that
  cutover had just enabled.

  **Check 3 is the one worth understanding before you touch `packages/eql`.**
  For a package this repo publishes, in-tree bytes differing from npm is an
  unreleased change — every pull request. For a frozen one it is a
  contradiction: the version cannot be released from here, so the tree is not
  proposing those bytes, it is *asserting they are already on npm under that
  number*. Nothing local can notice when that stops being true, because
  `sql/release-manifest.json` is regenerated with the SQL and goes on agreeing
  with it; only the registry disagrees. That has happened, and the SQL would
  have reached a customer database through `stash eql install`, carrying
  functions the version it reports does not define.

  The CLI now refuses a bundle whose bytes do not hash to its own release
  manifest (`packages/cli/src/installer/bundle-digest.ts`), but that catches a
  corrupt or tampered `node_modules`, **not** this — a frozen-package skew
  regenerates the manifest alongside the SQL, so the two agree locally. The
  release gate is still the only thing that notices. It `npm pack`s the frozen
  package and compares the two release manifests; `FROZEN_ARTEFACT_DIGESTS`
  says which artefact, keyed identically to `FROZEN_PUBLISHERS` and deleted
  with it.

  That `npm pack` path was itself executed by **no test** until the #915
  follow-up: every unit test injected both digests and the process test shimmed
  `npm` to answer `npm view` only. Driving it for real found two defects —
  `--silent` suppressed the error text the function classified on, and npm
  answers a missing *version* of an existing package with `ETARGET`, not
  `E404`, so the exact case the function documents became an uncaught throw
  that swallowed the actionable remedy. Assume a guard is untested until you
  have watched it fail.

  Note also that `@cipherstash/eql@3.0.5` did not come from `changeset
  version`: eleven unrelated changesets were pending, so the bump was entered
  by hand in `packages/eql/packages/eql/CHANGELOG.md`. Read that CHANGELOG
  entry before assuming a version's provenance.
- **Changesets for `@cipherstash/eql` go in the repo-root `.changeset/`.** The
  subtree's own `.changeset/` was deleted with the import; there is no second
  one to put them in by mistake.

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
| The managed AI platform path (Lovable, v0, Bolt, Replit) — headless auth, non-`postgres` roles, PostgREST limits | `skills/stash-managed-platforms` |
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
