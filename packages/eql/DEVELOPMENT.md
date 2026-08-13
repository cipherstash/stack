# Developing CipherStash EQL

## Table of Contents

- [How this project is organised](#how-this-project-is-organised)
  - [The `eql_v3` surface](#the-eql_v3-surface)
  - [Repository layout](#repository-layout)
- [Set up a local development environment](#set-up-a-local-development-environment)
  - [Installing mise](#installing-mise)
- [Building](#building)
  - [The catalog and code generation](#the-catalog-and-code-generation)
  - [The dependency system](#the-dependency-system)
  - [Building a release locally](#building-a-release-locally)
- [Testing](#testing)
  - [Running tests locally](#running-tests-locally)
  - [Rust workspace tests (no database)](#rust-workspace-tests-no-database)
- [Adding to the `eql_v3` surface](#adding-to-the-eql_v3-surface)
  - [Adding a scalar encrypted-domain type](#adding-a-scalar-encrypted-domain-type)
  - [Hand-written SQL](#hand-written-sql)
  - [Documentation comments](#documentation-comments)
- [Releasing](#releasing)
  - [dbdev](#dbdev)

## How this project is organised

Encrypt Query Language (EQL) is a PostgreSQL extension for searchable
encryption. Development is managed through [mise](https://mise.jdx.dev/), both
locally and [in CI](https://github.com/cipherstash/encrypt-query-language/actions).

mise has tasks for:

- Building the EQL install and uninstall scripts (`build`)
- Starting and stopping PostgreSQL containers (`postgres:up`, `postgres:down`)
- Running tests and resetting database state (`test`, `reset`)
- Regenerating the encrypted-domain SQL surface from the Rust catalog (run as
  part of `build`)
- Validating and generating documentation (`docs:validate`, `docs:generate`)

### The `eql_v3` surface

EQL installs a single, self-contained PostgreSQL schema, **`eql_v3`**, which
namespaces the encrypted-domain **scalar type families** (`integer`, `smallint`,
`bigint`, `date`, `timestamp`, `numeric`, `text`, `boolean`, `real`, `double`).
It owns its own copies of the searchable-encrypted-metadata (SEM) index-term
types it needs (`eql_v3.hmac_256`, `eql_v3.ore_block_256`, `eql_v3.bloom_filter`),
so the surface has no dependency on any other EQL schema and installs into a
database with nothing else present.

> **About `eql_v2`.** Earlier EQL releases shipped an `eql_v2` schema — a
> composite encrypted column type, database-side configuration management, and
> operator-class-on-column indexing. That surface was **removed in 3.0.0**; the
> repo now builds and ships only `eql_v3`, and the encryption client
> (CipherStash Proxy / CipherStash Stack) owns the configuration model the database-side
> `eql_v2` functions previously provided. You will still see `eql_v2` named in
> fork-provenance comments under `src/v3/` (the v3 SEM types were forked from the
> old v2 originals) and in historical records (`CHANGELOG.md`, the v2.x upgrade
> guides) — those mentions are deliberate and do not mean `eql_v2` is installed.

### Repository layout

These are the important files and directories in the repo:

```text
.
├── mise.toml                  <-- the main config file for mise
├── tasks/                     <-- mise task scripts (build, test, reset, docs, …)
│   ├── build.sh               <-- regenerates + assembles the release SQL
│   ├── test.sh                <-- runs the SQLx test suite
│   ├── reset.sh               <-- uninstall + install EQL into local postgres
│   ├── postgres.toml          <-- postgres:up / postgres:down / postgres:reset
│   ├── docs/                  <-- documentation generate/validate tasks
│   └── test/                  <-- additional test tasks (self_contained_v3, …)
├── crates/                    <-- Rust workspace: catalog, code generator, types
│   ├── eql-domains/           <-- THE catalog (eql-domains::CATALOG): source of truth
│   ├── eql-codegen/           <-- renders the eql_v3 scalar SQL from the catalog
│   ├── eql-bindings/             <-- shared Rust types + generated TS/JSON Schema bindings
│   └── eql-tests-macros/      <-- proc-macros used by the SQLx test matrix
├── src/                       <-- SQL components that make up EQL
│   ├── v3/                    <-- the self-contained eql_v3 surface
│   │   ├── schema.sql         <-- defines the eql_v3 PostgreSQL schema
│   │   ├── crypto.sql         <-- crypto helpers (forked for v3)
│   │   ├── common.sql         <-- shared helper functions (forked for v3)
│   │   ├── version.sql        <-- eql_v3.version() — generated from version.template
│   │   ├── version.template   <-- template for version.sql
│   │   ├── sem/               <-- hand-written SEM index-term types (hmac_256, ore_block_256, …)
│   │   ├── scalars/           <-- generated scalar domain families, one dir per type
│   │   │   ├── functions.sql  <-- shared blocker for native jsonb operators
│   │   │   └── <T>/           <-- e.g. integer/, text/, boolean/ (generated, committed in place)
│   │   ├── jsonb/             <-- jsonb SteVec support
│   │   └── lint/              <-- structural lints
│   ├── deps-ordered-v3.txt    <-- install order, emitted by `eql-codegen order`
│   └── README.md
├── docs/                      <-- reference, concept, and API documentation
├── tests/                     <-- test framework and fixtures
│   ├── docker-compose.yml     <-- Docker config for PostgreSQL 14–17 (port 7432)
│   └── sqlx/                  <-- Rust/SQLx test suite
└── release/                   <-- build artifacts produced by `mise run build`
    ├── cipherstash-encrypt.sql           <-- installer
    └── cipherstash-encrypt-uninstall.sql <-- uninstaller
```

> [!IMPORTANT]
> The per-type scalar SQL files (`src/v3/scalars/<T>/<T>_types.sql`,
> `*_functions.sql`, `*_operators.sql`, `*_aggregates.sql`) are **generated**
> but **committed in place** (so the shipped SQL is reviewable in diffs and the
> file is consistent with the committed Rust bindings). Never hand-edit them —
> they are overwritten on every build and CI's `codegen:parity` gate fails on any
> drift. See [The catalog and code generation](#the-catalog-and-code-generation).

## Set up a local development environment

> [!IMPORTANT]
> **Before you follow this how-to** you need to have this software installed:
>
> - [mise](https://mise.jdx.dev/) — see the [installing mise](#installing-mise) instructions
> - [Docker](https://www.docker.com/) — see Docker's [documentation for installing](https://docs.docker.com/get-started/get-docker/)

Local development quickstart:

```shell
# Clone the repo
git clone https://github.com/cipherstash/encrypt-query-language
cd encrypt-query-language

# Trust the mise config and install tooling (Rust toolchain, sqlx-cli, …)
mise trust --yes

# (Optional, recommended) Install the git pre-commit hook that drift-gates the
# generated surfaces (committed SQL + bindings) locally, before push.
mise run install-hooks

# Build the EQL installer and uninstaller, outputting to release/
mise run build

# Start a postgres instance (defaults to PostgreSQL 17)
mise run postgres:up --extra-args "--detach --wait"

# Run the tests (defaults to PostgreSQL 17)
mise run test

# Stop and remove all containers and networks
mise run postgres:down
```

### Installing mise

> [!IMPORTANT]
> You must complete this step to set up a local development environment.

Local development and task running in CI is managed through [mise](https://mise.jdx.dev/).

To install mise:

- If you're on macOS, run `brew install mise`
- If you're on another platform, check out the mise [installation methods documentation](https://mise.jdx.dev/installing-mise.html#installation-methods)

Then add mise to your shell:

```shell
# If you're running Bash
echo 'eval "$(mise activate bash)"' >> ~/.bashrc

# If you're running Zsh
echo 'eval "$(mise activate zsh)"' >> ~/.zshrc
```

We use [`cargo-binstall`](https://github.com/cargo-bins/cargo-binstall) for
faster installation of tools installed via mise and Cargo. It is installed via
mise when bootstrapping development and testing dependencies.

> [!TIP]
> Many tasks have short aliases. For example, `mise run build` can be
> abbreviated to `mise r b`, and `mise run clean` to `mise r k`.
> Run `mise tasks --extended` to see the available tasks and shortcuts.

## Building

The build regenerates the `eql_v3` scalar SQL surface from the Rust catalog,
resolves SQL dependencies into a single ordered file, and writes the install
and uninstall scripts to `release/`.

### The catalog and code generation

The `eql_v3` scalar encrypted-domain types are **generated** from a single Rust
source of truth — the `CATALOG` const in
[`crates/eql-domains/src/lib.rs`](./crates/eql-domains/src/lib.rs). There is no
TOML manifest and no Python.

Each scalar type is one `DomainFamily` row in `CATALOG`, declaring:

- the type `name` (e.g. `bigint`),
- its `ScalarKind` (the `kind` field),
- the `Domain`s mapping each generated (bare) domain name to its fixed index
  `Term`s (`eq => [Hm]`, `ord` / `ord_ore => [Ore]`), and
- the plaintext `Fixture` value list the SQLx test matrix consumes.

`mise run build` invokes `cargo run -p eql-codegen`, which regenerates the SQL
surface into `src/v3/scalars/<T>/` from `CATALOG` at the start of every build.
For an unchanged catalog, regeneration is deterministic and byte-identical.

The generated files
(`<T>_types.sql` / `<T>_functions.sql` / `<T>_operators.sql` /
`<T>_aggregates.sql`) carry an `-- AUTOMATICALLY GENERATED FILE` header (the
project-wide marker that `docs:validate` greps for) and are **committed in
place** under `src/v3/scalars/<T>/`. Because regeneration is deterministic, a
catalog change shows up as a reviewable diff in these files; `mise run build`
keeps them fresh, and `mise run codegen:parity` (CI + the optional pre-commit
hook) fails if the committed copy ever drifts from the catalog. If
`mise run build` produces unexpected output, the change is in
`crates/eql-domains/src` (the catalog/terms) or `crates/eql-codegen/src` (the
renderers), not in run-to-run variation.

### The dependency system

SQL sources under `src/v3/` are split into small modules. Dependencies between
them are declared with `-- REQUIRE:` comments at the top of each file — every
file should `REQUIRE` the source of any other object it references.

At minimum, a file references the schema:

```text
-- REQUIRE: src/v3/schema.sql
```

`cargo run -p eql-codegen -- order` walks the whole `src/v3` tree once, collects
these edges, and topologically sorts them into `src/deps-ordered-v3.txt`; the
build then concatenates the files in that order to produce a single installer.
Generated and hand-written files are ordered together, so nothing can fall
between two enumerations and be dropped. The build fails loudly if a `-- REQUIRE:`
target does not exist, if an edge leaves `src/v3`, or if the edges form a cycle.
`mise run test:installer_complete` then asserts the installer actually contains
every ordered file's body.

The `eql_v3` surface is **self-contained**: no `eql_v2.<symbol>` reference
appears anywhere under `src/v3/`. This invariant is enforced in CI by
`mise run test:self_contained_v3`.

### Building a release locally

To build a release locally, run:

```bash
# alias: mise r b
mise run build
```

This produces two SQL files in `release/`:

- An installer (`cipherstash-encrypt.sql`), and
- An uninstaller (`cipherstash-encrypt-uninstall.sql`)

> [!TIP]
> A bare build can leave stale generated files. When in doubt, run a clean
> build:
>
> ```bash
> mise run clean && mise run build   # alias: mise r k && mise r b
> ```

## Testing

EQL is tested against PostgreSQL versions 14–17. The suite is written in Rust
using the SQLx framework and lives in `tests/sqlx/`. Container configuration is
in `tests/docker-compose.yml`; the database listens on **port 7432**
(`localhost:7432`, user `cipherstash`, password `password`).

> [!IMPORTANT]
> EQL is searchable encryption, so tests run against **real ciphertexts and
> index terms** produced by the actual crypto — never hand-curated or synthetic
> blobs. Fixtures are generated by encrypting plaintext through
> cipherstash-client, so the SQLx suite **requires** CipherStash credentials
> (ZeroKMS auth plus a client key). CI has them. Do not add static/committed
> fixtures to dodge this dependency. See the `test:sqlx:prep` comment in
> `mise.toml` for the exact environment variables.

### Running tests locally

> [!IMPORTANT]
> **Before you run the tests locally** you need to
> [set up a local dev environment](#set-up-a-local-development-environment).

To run the tests against PostgreSQL 17:

```shell
# Start a postgres instance (defaults to PostgreSQL 17)
mise run postgres:up --extra-args "--detach --wait"

# Run the tests (defaults to PostgreSQL 17)
mise run test

# Stop and remove all containers and networks
mise run postgres:down
```

You can run the same tasks against Postgres 14, 15, and 16 by specifying
arguments:

```shell
# Start a postgres 14 instance
mise run postgres:up postgres-14 --extra-args "--detach --wait"

# Run the tests against postgres 14
mise run test --postgres 14

# Stop postgres and remove all containers and networks
mise run postgres:down
```

Limitations:

- **Volumes for Postgres containers are not persistent.** If you need to look at
  data in the container, uncomment a volume in `tests/docker-compose.yml`.
- **You can't run multiple Postgres containers at the same time.** All the
  containers bind to the same port (`7432`). To run multiple containers
  concurrently, change the ports in `tests/docker-compose.yml`.

### Rust workspace tests (no database)

The catalog, code generator, and shared types have fast tests that do not need a
database:

```bash
# Catalog + generator tests (eql-domains, eql-codegen)
mise run test:codegen

# Compile, lint, and test the std-only workspace crates
mise run test:crates

# Drift gate: regenerate the SQL surface and fail if committed src/v3/scalars drifts
mise run codegen:parity

# Assert the eql_v3 surface is self-contained (no eql_v2 leakage)
mise run test:self_contained_v3
```

The catalog is validated by the Rust compiler (an undefined term or unknown
scalar is a compile error) plus catalog `#[test]`s, so many mistakes are caught
without a database at all.

## Adding to the `eql_v3` surface

### Adding a scalar encrypted-domain type

Adding a scalar encrypted-domain type (e.g. a new ordered numeric scalar) is one
`DomainFamily` row in `eql-domains::CATALOG`
([`crates/eql-domains/src/lib.rs`](./crates/eql-domains/src/lib.rs)). New term
behaviour belongs in the `Term` enum's `impl` methods (with tests), not in
free-form catalog data. After editing the catalog, run `mise run build` to
regenerate the SQL surface.

Follow the reference guide:
[`docs/reference/adding-a-scalar-encrypted-domain-type.md`](./docs/reference/adding-a-scalar-encrypted-domain-type.md).
The mechanics are fixed for ordered scalar domains; the catalog row only
declares the name, kind, bare domain names, and terms.

A few footguns the generator exists to prevent — worth knowing when reading the
output:

- **Blockers must never be `STRICT`** and must be `LANGUAGE plpgsql`, not
  `LANGUAGE sql`. A blocker exists to always `RAISE`; a `STRICT` or inlinable
  body lets the planner skip it and silently bypass the "operator not supported"
  exception.
- **No domain-over-domain** (`CREATE DOMAIN a AS b`) and **no operator class on
  a domain.** Index through a functional index on the extractor
  (`eq_term` / `ord_term`).
- **Inlinable functions** (extractors, comparison wrappers) need `LANGUAGE sql`,
  a single-statement `SELECT`, `IMMUTABLE`, and **no `SET` clause** — a pinned
  `search_path` disables inlining.

### Hand-written SQL

Generated files are overwritten on every build (and CI fails on any drift), so
hand-written SQL never goes in them — even though they are committed. Hand-written
SQL beyond the fixed generated surface goes in
`src/v3/scalars/<T>/<T>_extensions.sql` — no auto-generated header, explicit
`-- REQUIRE:` edges, and it is committed (and, unlike the generated files, never
rewritten by the generator). The hand-written SEM index-term types live under
`src/v3/sem/`.

When adding SQL, follow these conventions:

- Never drop the configuration table — it may contain customer data and must
  survive across EQL versions.
- Everything else should have a `DROP IF EXISTS`.
- Functions should be `DROP` then `CREATE` (not `CREATE OR REPLACE`) — data
  types cannot be changed once created, so dropping first is more flexible.
- Keep `DROP` and `CREATE` together in the code.
- In general, put operator wrappers in `operators.sql` and the larger
  implementation functions in `functions.sql`. Operator functions are thin
  wrappers around the functions that do the actual work.

### Documentation comments

All SQL functions and types must be documented with Doxygen-style comments using
the `--!` prefix. At minimum provide `@brief`, plus `@param` for parameters and
`@return` for non-void returns. Verify coverage and required tags with:

```bash
mise run docs:validate
```

See the **Documentation Standards** section in
[`CLAUDE.md`](./CLAUDE.md) for the full tag list, an annotated example, and the
generation tasks (`mise run docs:generate`).

## Releasing

EQL releases through a single workflow, `.github/workflows/release.yml`, driven
by **[Changesets](https://github.com/changesets/changesets)** — you do not create
GitHub releases by hand. Finals are cut from `main` (merge the Changesets
"Version Packages" PR); prereleases from `eql_v3` (an explicit `chore(release):`
commit). `release.yml` builds and attaches the SQL + docs artifacts, publishes
the `@cipherstash/eql` npm package and the `eql-bindings` crate, and creates the
`eql-<version>` release — all at one lockstep version.

For the full runbook and release architecture, see
**[`docs/development/releasing.md`](./docs/development/releasing.md)**.

User-facing changes need a **changeset** in the same PR (`pnpm changeset`) —
Changesets assembles `CHANGELOG.md` and computes the version from these files, so
do not hand-edit `CHANGELOG.md`. Behaviour callers should be aware of also needs
a numbered upgrade note under `docs/upgrading/`.

#### Public documentation updates

When a tag with the `eql-` prefix is pushed (for example, `eql-1.2.3`), the
workflow at `.github/workflows/rebuild-docs.yml` runs and sends a webhook to the
Vercel-hosted public docs site to trigger a rebuild.

What happens end-to-end:

- Release EQL builds EQL artifacts and generates API docs (HTML, XML, Markdown).
  The Markdown frontmatter includes the release version.
- Rebuild Docs posts to the `DOCS_WEBHOOK_URL` secret, which Vercel uses to kick
  off a fresh build of the public docs.
- The public docs site pulls the latest generated reference
  (`docs/api/markdown/API.md`) and publishes it under the corresponding version.

Manual triggers and troubleshooting:

- You can re-run the "Rebuild Docs" workflow from the Actions tab if a build
  fails downstream.
- Ensure the repository secret `DOCS_WEBHOOK_URL` is set and valid; the workflow
  simply POSTs to that URL.

### dbdev

We publish a Trusted Language Extension for PostgreSQL for use on
[dbdev](https://database.dev/). You can find the extension on
[dbdev's extension catalog](https://database.dev/cipherstash/eql).

> [!NOTE]
> Publishing to dbdev is currently manual, so the dbdev version may lag the
> GitHub releases until the process is automated. You need the
> [dbdev CLI](https://supabase.github.io/dbdev/cli/) installed and logged in.

Steps to publish:

1. Run `mise run build` to build the extension artifacts.
1. Update the artifact file name and the `eql.control` file with the new version
   number.
1. Run `dbdev publish` to publish the extension to dbdev.
