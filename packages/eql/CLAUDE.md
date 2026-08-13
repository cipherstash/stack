# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

This project uses `mise` for task management. Common commands:

- `mise run build` (alias: `mise r b`) - Build SQL into single release file
- `mise run test` (alias: `mise r test`) - Build, reset and run tests
- `mise run postgres:up` - Start PostgreSQL container
- `mise run postgres:down` - Stop PostgreSQL containers
- `mise run reset` - Reset database state
- `mise run clean` (alias: `mise r k`) - Clean release files

### Documentation
- `mise run docs:generate` - Generate API documentation (requires doxygen)
  - Outputs XML (primary) and HTML (preview) formats
  - XML suitable for downstream processing/website integration
  - Output is written to `docs/api/` (generated, gitignored)
- `mise run docs:generate:markdown` - Convert XML to Markdown API reference
  - Generates single-file API reference: `docs/api/markdown/API.md` (all documented functions with parameters, return values, and source links)
- `mise run docs:validate` - Validate documentation coverage and tags
- `mise run docs:package` - Package XML docs for distribution (~230KB archive)

### Testing
- Run all tests: `mise run test`
- Run SQLx tests directly: `mise run test:sqlx`
- Run SQLx tests in watch mode: `mise run test:sqlx:watch`
- Tests are located in `tests/sqlx/` using Rust and SQLx framework
- Property-based tests for the `eql_v3` encrypted scalar domains live in three suites — **catalog** (pure-Rust catalog invariants, no DB), **fixture** (oracle over committed ciphertext), and **e2e** (oracle over fresh end-to-end encryption, gated behind the `proptest-e2e` cargo feature). The structure, the shared all-pairs oracle engine, and the conventions/footguns (e.g. why they must not live under `scalars::`) are documented in `tests/sqlx/tests/encrypted_domain/property/README.md`.
- Verify the scalar matrix coverage snapshot: `mise run test:matrix:inventory` (no database required). Committed token-normalized baselines under `tests/sqlx/snapshots/` pin the set of `scalars::<T>::*` test names so a silently dropped/renamed/`#[cfg]`-gated test fails CI's `matrix-coverage` job. The task discovers the present scalar types from the test binary's `--list` and cross-checks them against `cargo run -p eql-codegen -- list-types`, so a catalog type missing its matrix wiring also fails. When you change which matrix tests the macro emits, regenerate and commit the affected baseline in the same change. `tests/sqlx/snapshots/README.md` is the source of truth for which baselines exist and how each is regenerated.

### Build System
- Dependencies are resolved using `-- REQUIRE:` comments in SQL files
- Build outputs to `release/` directory (a single installer + uninstaller, assembled from `src/v3` alone):
  - `cipherstash-encrypt.sql` - The sole installer: the self-contained `eql_v3` surface, globbed from `src/v3` only (no `eql_v2`; installable into a DB with no `eql_v2` present)
  - `cipherstash-encrypt-uninstall.sql` - Matching uninstaller

There are no longer separate Main / Supabase / Protect / v3-only build variants. The combined `eql_v2` build that previously produced multiple artefacts has been removed; the v3 surface now ships as one self-contained installer under the canonical `cipherstash-encrypt.sql` name (`eql-codegen order` walks `src/v3` only). Because the surface owns no `eql_v2` dependency, it is already Supabase / managed-Postgres compatible (functional indexes over extractors, no superuser-only operator classes) without a dedicated subset build. Self-containment — no `-- REQUIRE:` edge pointing outside `src/v3`, no `eql_v2.<symbol>` anywhere in the surface — is enforced at build time by `surface_order`'s `OutsideSurface` error (`crates/eql-codegen/src/ordering.rs`) and CI-gated by `mise run test:self_contained_v3`.

## Project Architecture

This is the **Encrypt Query Language (EQL)** - a PostgreSQL extension for searchable encryption. Key architectural components:

### Core Structure
- **Schema**: EQL ships two PostgreSQL schemas. `eql_v3` is the public API: the encrypted-domain type families (`integer`, `smallint`, `bigint`, `date`, `timestamp`, `numeric`, `text`, `boolean`, `real`, `double`), query operators, index extractors (`eq_term`/`ord_term`/`match_term`), `min`/`max` aggregates, `version()`, `lints()`, **and the operator-backing comparison wrappers** (`eq`/`neq`/`lt`/`lte`/`gt`/`gte`/`contains`/`contained_by`, plus the jsonb containment helpers `jsonb_contains`/`jsonb_contained_by`/`jsonb_array`/`ste_vec_contains`). The wrappers are public because they are the function-form equivalent of every supported operator — platforms without operator support (Supabase/PostgREST invoke functions, not operators) call them by name (gated by `tests/sqlx/tests/v3_operator_equivalents_tests.rs`). `eql_v3_internal` holds INTERNAL objects only: the searchable-encrypted-metadata (SEM) index-term **types** (`eql_v3_internal.hmac_256`, `eql_v3_internal.ore_block_256`, `eql_v3_internal.bloom_filter`, `eql_v3_internal.ope_cllw`, hand-written under `src/v3/sem/`) and their support/constructor/comparator functions, the generated **blockers** (which only raise on unsupported ops), the **aggregate state functions**, and the SteVec CHECK validators. Splitting the index-term TYPES into `eql_v3_internal` keeps the Supabase Studio Table Builder type picker (which lists every type in every non-hidden schema) free of index-term-only types. **Design decision: EQL never grants permissions automatically — the installer issues no `GRANT`/`REVOKE`; access to either schema is strictly opt-in (see `docs/reference/permissions.md`).** Together the two schemas are **self-contained** and install into a database with no other EQL schema present. The earlier `eql_v2` schema (composite `eql_v2_encrypted` column type, database-side configuration management, operator-class-on-column indexing) was **removed in 3.0.0** — see the `[Unreleased]`/3.0.0 entry in `CHANGELOG.md`. `eql_v2` is no longer built or shipped; it survives only in fork-provenance comments under `src/v3/` (the v3 SEM types were forked from the old v2 originals) and in historical records (`CHANGELOG.md`, the v2.x upgrade guides).

### Directory Structure
- `src/` - contains only the self-contained `v3` surface (the modular `eql_v2` component directories were removed in 3.0.0)
- `crates/` - Rust workspace: `eql-domains` (the catalog), `eql-codegen` (SQL/bindings generator), `eql-bindings` (payload bindings), `eql-tests-macros`
- `src/v3/` - Self-contained `eql_v3` / `eql_v3_internal` surface: `src/v3/schema.sql` (creates both schemas), forked `src/v3/crypto.sql` / `src/v3/common.sql`, hand-written SEM index-term types under `src/v3/sem/` (`hmac_256`, `ore_block_256`) — now created in `eql_v3_internal` — the generated scalar encrypted-domain families under `src/v3/scalars/<T>/` (user-column domains in `public`; extractors **and the supported comparison wrappers** in `eql_v3`; only the blockers and aggregate state functions in `eql_v3_internal`; plus the shared blocker `src/v3/scalars/functions.sql`), and the hand-written encrypted-JSONB (SteVec) surface under `src/v3/json/` (`types.sql`, `functions.sql`, `operators.sql`, `aggregates.sql`, `blockers.sql` — the `public.eql_v3_json_search` / `public.eql_v3_json_entry` column domains and their CHECK validators live in `public`, while the containment needle `eql_v3.query_json` — a query operand, never a column type — lives in `eql_v3`; typed operators, `json_entry` comparison wrappers, the containment engine (`ste_vec_contains`), and raw-jsonb GIN helpers (`jsonb_array` / `jsonb_contains` / `jsonb_contained_by`) live in `eql_v3`; only the `is_ste_vec_array` helper and aggregate state functions live in `eql_v3_internal`)
- `tasks/` - mise task scripts
- `tests/sqlx/` - Rust/SQLx test framework (PostgreSQL 14-17 support)
- `release/` - Generated SQL installation files

### Key Concepts
- **Dependency System**: SQL files declare dependencies via `-- REQUIRE:` comments
- **Encrypted Data**: Stored as JSONB payloads with metadata
- **Index Terms**: SEM index-term types in `eql_v3_internal` (`hmac_256`, `ore_block_256`, `bloom_filter`, `ope_cllw`)
- **Operators**: Support comparisons between encrypted and plain JSONB data
- **Encryption client**: CipherStash Stack or CipherStash Proxy is required for encryption/decryption operations

### Encrypted-Domain Types

`src/v3/scalars/` holds the generated **encrypted-domain type families** — jsonb-backed PostgreSQL domains in the **`public` schema**, one domain per operator/index capability (`public.<T>` storage-only, `public.<T>_eq`, `public.<T>_ord`), plus an `eql_v3.query_<T>_<cap>` **query-operand twin** per term-bearing domain (index-terms-only, no ciphertext `c`; in `eql_v3`, not `public`, because a query operand is never a column type). The domains are `public.eql_v3_integer`, `public.eql_v3_integer_eq`, `public.eql_v3_integer_ord`, `public.eql_v3_integer_ord_ore`; their extractors (`eql_v3.eq_term`, `eql_v3.ord_term`), aggregates (`eql_v3.min`/`max`), **and the supported comparison wrappers** (`eq`/`neq`/`lt`/`lte`/`gt`/`gte`/`contains`/`contained_by`) all live in **`eql_v3`** — the wrappers are public so every operator has a callable function equivalent (Supabase/PostgREST). Only the **blockers** (for unsupported operators — they just raise), the **aggregate state functions**, and the SEM index-term types the extractors/wrappers return and construct (`eql_v3_internal.hmac_256`, `eql_v3_internal.ore_block_256`) live in **`eql_v3_internal`** — hand-written under `src/v3/sem/`, schema-qualified via the codegen's `INTERNAL_SCHEMA` constant for the generated surface (the codegen's `SCHEMA` constant qualifies the public wrappers; the `operator_entry` renderer picks the backing function's schema by whether the operator is supported) — so the whole v3 surface (both schemas together) is self-contained (no `eql_v2.<symbol>` appears anywhere in v3 SQL; CI gates this via `mise run test:self_contained_v3` and the self-contained `release/cipherstash-encrypt.sql` installer). `public.eql_v3_integer` (PR #239, supersedes #225) is the reference scalar implementation; the catalog now generates a full surface for `integer`, `smallint`, `bigint`, `date`, `timestamp`, `numeric`, `text`, `boolean`, `real`, and `double`, all following this materializer pattern. `json` is a `CATALOG` family too, but a **mixed** one: its three SteVec domains (`public.eql_v3_json_search` document, `public.eql_v3_json_entry`, `eql_v3.query_json`) carry `Shape::SteVec` (the `Shape` enum in `crates/eql-domains/src/lib.rs` has two variants, `Scalar` and `SteVec`; the three SteVec domains are disambiguated by `Domain.name`, not distinct variants) instead of `Shape::Scalar`, and their SQL lives permanently hand-written under `src/v3/json/` rather than `src/v3/scalars/<T>/`. Alongside them the family carries **one generated `Shape::Scalar` storage domain**, `public.eql_v3_json` (bare `name: ""`, ciphertext-only, no index terms — the JSON analogue of `public.eql_v3_boolean`), which the scalar materializer renders into `src/v3/scalars/json/` like every other storage-only domain. `eql-codegen`'s SQL/bindings drivers iterate `families_with_scalar_domains()` (families with ≥1 scalar domain) and render each family's scalar domains only — so a fully-scalar family is unchanged, `json`'s scalar storage domain is generated, and its hand-written SteVec domains are skipped (the family stays non-scalar because `is_scalar()` is `.all()`, so `scalar_families()` still excludes it wholesale). The searchable SteVec surface is a deliberate, permanent hand-written split, not a gap awaiting a future generator; only the ciphertext-only storage domain is materialized.

Adding a scalar encrypted-domain type is one row in the Rust catalog `eql-domains::CATALOG` (`crates/eql-domains/src/lib.rs`): a `DomainFamily` giving the type `name` (e.g. `bigint`), its `ScalarKind` (the `kind` field), the `Domain`s mapping each generated (bare) domain name to its fixed index `Term`s (`eq => [Hm]`, `ord`/`ord_ore => [Ore]`), and the `Fixture` value list. Term capabilities are fixed in the `Term` enum's `impl` methods (with unit tests): `Hm` provides equality, and `Ore` provides equality plus ordering. There is no TOML manifest and no Python — the catalog is the source of truth, validated by the compiler (an undefined term or unknown scalar is a compile error) plus catalog `#[test]`s. `mise run build` runs `cargo run -p eql-codegen`, which regenerates the scalar SQL surface into `src/v3/scalars/<T>/` from `CATALOG` at the start of every build; that surface includes supported comparison wrappers plus blockers for native `json` operators that would otherwise be reachable through domain fallback. `cargo run -p eql-codegen` regenerates every type at once (the same call `mise run build` uses; there is no per-type codegen task). The generated `*_types.sql` / `*_functions.sql` / `*_operators.sql` / `*_aggregates.sql` files are **committed in place** under `src/v3/scalars/<T>/` and drift-gated by `mise run codegen:parity` (regenerate in place + `git diff` + untracked check — the same regenerate-and-diff pattern `types:check` uses for the committed bindings). They are still machine-generated: change the catalog and rebuild, never hand-edit (CI fails on drift). The per-type plaintext fixture lists the SQLx matrix consumes are **not** a generated file — they are materialised from each `CATALOG` row at compile time as `eql_domains::INT4_VALUES` / `INT2_VALUES` (the `int_values!` macro) and read directly by `ScalarType::FIXTURE_VALUES`; a Rust source of truth no longer round-trips through a committed generated `.rs`. Generated SQL carries a `-- AUTOMATICALLY GENERATED FILE` header (the project-wide marker `docs:validate` greps on); change the catalog and rebuild, never hand-edit. Hand-written SQL beyond the fixed surface goes in `src/v3/scalars/<T>/<T>_extensions.sql` with no auto-generated header and explicit `-- REQUIRE:` edges — that file IS committed. `json`'s **SteVec** domains never enter this pipeline, but its **scalar storage domain does**: `generate_all` iterates `eql_domains::families_with_scalar_domains()` and renders each family's scalar domains (so `public.eql_v3_json` is generated into `src/v3/scalars/json/`), while `list-types` and the SQLx matrix still iterate `eql_domains::scalar_families()`, which excludes the whole non-scalar `json` family — so `json` stays out of the operator/coverage matrix by construction (a storage-only domain carries no operator matrix), even though its ciphertext-only storage domain now has a generated SQL surface.

The same generator also emits the **Rust payload bindings** under `crates/eql-bindings/src/v3/<family>.rs` (structs + `DomainType` impls) and the `inventory.rs` `all()` list, from the same `CATALOG` — committed with a `// @generated` header (the bindings must exist on a clean clone because `ts-rs`/`schemars` derive the committed TypeScript/JSON Schema off them; the SQL surface is now committed too, so both generated targets are handled consistently — committed in place, drift-gated by regenerate-and-`git diff`). The hand-written `DomainType` trait, the shared newtypes (`SchemaVersion`/`Identifier`/`Ciphertext`/`Hmac256`/`OreBlock256`/`BloomFilter`), the `PhantomData` plumbing, and the architectural module doc (including the non-derivable float-NaN and bool storage-only caveats) stay hand-written in `crates/eql-bindings/src/v3/{mod,domain_type,terms}.rs`. Generated structs carry a catalog-derived struct doc — a summary line (`` `eql_v3.<name>` — <capability>. ``) plus a detail line listing the supported operators and required payload keys, all derived from data the catalog already holds (the capability label, `Term::operators_for_terms`, and `ENVELOPE_KEYS` ++ `Term::term_json_keys` — see `struct_doc_lines` in `crates/eql-codegen/src/bindings.rs`). The required-key list makes structural distinctions visible — e.g. `text_ord` lists `` `v` `i` `c` `hm` `ob` `` (dual-term) versus an integer `integer_ord`'s `` `v` `i` `c` `ob` ``. There are **no per-field docs**: per-field/term semantics live on the shared term newtypes (`terms.rs`, flowing into the TS term files and JSON Schema `$defs`), and non-derivable per-family caveats (float-NaN, bool storage-only) in `mod.rs`. Free-form prose belongs at the **struct level** (a future optional catalog `doc` field emitted as extra `#[doc]` lines), never as per-field docs. JSON Schemas are emitted by **schemars 1.x** as JSON Schema 2020-12. `mise run types:generate` regenerates the Rust bindings (via `eql-codegen bindings`) then the TS/JSON; `mise run types:check` is the committed-reference drift gate — it regenerates and `git diff`s all three (`crates/eql-bindings/src/v3` + `bindings/` + `schema/`), the same regenerate-and-diff pattern `codegen:parity` now uses for the committed SQL surface. Both gates run in CI; `mise run install-hooks` wires a pre-commit hook that runs both locally whenever a commit touches the catalog, the generator, or a committed generated surface. The `json` family's **SteVec** structs (`SteVecDocument`, `SteVecEntry`, `SteVecQuery`, and `SteVecQueryEntry`) are hand-written for the same reason as their SQL — in `crates/eql-bindings/src/v3/json.rs`, symmetric with `src/v3/json/`. Their direct optional fields and `deny_unknown_fields` validation keep the Rust, TypeScript, JSON Schema, and PostgreSQL entry contracts aligned. The family's scalar storage struct **is** generated (a flat `{v,i,c}` struct, `Json`), via `render_scalar_only_bindings(&JSON)` into `crates/eql-bindings/src/v3/json_storage.rs`; the hand-written `json.rs` re-exports it (`pub use crate::v3::json_storage::Json;`) so `super::json::Json` resolves for the generated inventory/payload. Only inventory membership and ordering are catalog-driven: `inventory.rs::all()` iterates the full `CATALOG` (not `scalar_families()`), branching on `Shape` to include the three SteVec structs plus the generated `Json` alongside the other scalar structs.

**Adding a new encrypted-domain type: follow `docs/reference/adding-a-scalar-encrypted-domain-type.md`.** The mechanics are fixed for ordered scalar domains; the catalog row only declares the name, kind, bare domain names, and terms. New term behavior belongs in the `Term` enum's `impl` methods in `crates/eql-domains/src` with tests, not in free-form catalog data.

Regeneration is deterministic: an identical `CATALOG` produces byte-identical SQL. If `mise run build` produces unexpected output, the change is in `crates/eql-domains/src` (the catalog/terms) or `crates/eql-codegen/src` (the renderers) — not in random run-to-run variation.

**Committed generated code is never "in conflict" and never needs analysis — the generator is the source of truth.** After anything that changes the catalog (a merge/rebase that pulls in catalog changes, a `crates/eql-domains` edit), the committed generated surfaces (`src/v3/scalars/`, `crates/eql-bindings/{bindings,schema}`, `packages/eql/src/generated`) are brought up to date by **regenerating and committing** — it is a deterministic no-op, not a merge to resolve:

```
cargo clean   # only if a stale incremental cache makes eql-codegen misbehave (see below)
mise run types:generate && mise run typescript:generate   # regenerate bindings
mise run build                                            # regenerate SQL surface
git add -A && git commit
```

Do **not** run the drift gates (`types:check` / `typescript:check` / `codegen:parity`) to "diagnose" a stale generated tree — a failing gate after a catalog change trivially means "regenerate and commit," nothing more; run the gates only to *confirm* after committing. And if `eql-codegen` fails to compile against source that is byte-identical to a base that compiles (e.g. `no method named …` on a catalog type), it is a **stale cargo incremental cache**, not a semantic merge break — `cargo clean` fixes it; do not go forensic on the code.

Footguns the spec exists to prevent:

- **Blockers must never be `STRICT`.** A `STRICT` blocker lets PostgreSQL skip the body and return `NULL` on a `NULL` argument, silently bypassing the "operator not supported" exception.
- **No domain-over-domain** (`CREATE DOMAIN a AS b`). Operators resolve against the ultimate base type (`jsonb`), so a derived domain does not inherit the base domain's operator surface — blockers stop engaging.
- **No operator class on a domain.** Index through a functional index on the extractor (`eq_term` / `ord_term`), whose return type already carries a default opclass.
- **Inlinable functions** (extractors, comparison wrappers) need `LANGUAGE sql`, a single-statement `SELECT`, `IMMUTABLE`, and **no `SET` clause** — a pinned `search_path` disables inlining. No per-type allowlist edit: the `pin_search_path.sql` structural rule recognises encrypted-domain functions intrinsically and `tasks/test/splinter.sh` covers the converged extractor/wrapper names.
- **Blockers must be `LANGUAGE plpgsql`, not `LANGUAGE sql`.** The inverse of the rule above. A blocker exists to always raise, but a `LANGUAGE sql` body is inlinable and the planner can elide the call when the result is provably unused (dead `CASE` branch, folded predicate). `LANGUAGE plpgsql` is opaque to the planner, so the call — and its `RAISE` — survives. The blocker renderers in `crates/eql-codegen/src` enforce this; don't "simplify" the rendered blockers to `LANGUAGE sql` even though the body is a single expression.
- **Build with `mise run clean && mise run build`** — a bare build can leave stale `release/*.sql`.

### Testing Infrastructure
- Tests are written in Rust using SQLx, located in `tests/sqlx/`
- Tests run against PostgreSQL 14, 15, 16, 17 using Docker containers
- Use `mise run test --postgres 14|15|16|17` to test against a specific version
- Container configuration in `tests/docker-compose.yml`
- Database connection: `localhost:7432` (cipherstash/password)

#### Tests run against real encrypted data (hard requirement)

EQL is searchable encryption; tests MUST use real ciphertexts/index terms from the actual crypto,
never hand-curated or synthetic blobs. Fixtures are **generated** by encrypting plaintext through
cipherstash-client: `mise run test:sqlx:prep` runs `fixture:generate:all` (the
`generate_all_fixtures` test, `--features fixture-gen`, over `eql-domains::CATALOG`) → gitignored
`tests/sqlx/fixtures/eql_v3_*.sql`.

- The SQLx suite **requires** CipherStash creds — ZeroKMS auth (`CS_CLIENT_ACCESS_KEY` +
  `CS_WORKSPACE_CRN`) AND a client key (`CS_CLIENT_ID` + `CS_CLIENT_KEY`); see the
  `test:sqlx:prep` comment in `mise.toml`. CI has them. This is expected, not a reason to avoid
  generated fixtures.
- Do NOT add static/committed fixtures to dodge the creds dependency. There are no committed
  fixture exceptions: the jsonb SteVec document fixture `tests/sqlx/fixtures/v3_ste_vec.sql` is
  now generated through the same `FixtureSpec` machinery (`tests/sqlx/src/fixtures/v3_ste_vec.rs`)
  and gitignored/regenerated like every scalar fixture — it is not a committed blob to copy.

## Documentation Standards

### Doxygen Comments

All SQL functions and types must be documented using Doxygen-style comments:

- **Comment Style**: Use `--!` prefix for Doxygen comments (not `--`)
- **Required Tags**:
  - `@brief` - Short description (required for all functions/files)
  - `@param` - Parameter description (required for functions with parameters)
  - `@return` - Return value description (required for functions with non-void returns)
- **Optional Tags**:
  - `@throws` - Exception conditions
  - `@note` - Important notes or caveats
  - `@warning` - Warning messages (e.g., for DDL-executing functions)
  - `@see` - Cross-references to related functions
  - `@example` - Usage examples
  - `@internal` - Mark internal/private functions
  - `@file` - File-level documentation

### Documentation Example

```sql
--! @brief Convert JSONB hex array to bytea array
--! @internal
--!
--! Converts a JSONB array of hex-encoded strings into a PostgreSQL bytea array.
--! Used for deserializing binary data (like ORE terms) from JSONB storage.
--!
--! @param val jsonb JSONB array of hex-encoded strings
--! @return bytea[] Array of decoded binary values
--!
--! @note Returns NULL if input is JSON null
CREATE FUNCTION ...
```

(Adapted from a real block in `src/v3/common.sql` — use existing `src/v3` files as the reference for style.)

### Validation Tools

Verify documentation quality:

```bash
# Using mise (recommended - validates coverage and tags)
mise run docs:validate

# Or run individual scripts directly
mise run docs:validate:coverage       # Check 100% coverage
mise run docs:validate:required-tags  # Verify @brief, @param, @return tags
mise run docs:validate:documented-sql # Validate SQL syntax (requires database)
```

### Template Files

Template files (e.g., `version.template`) must be documented. The Doxygen comments are automatically included in generated files during build.

### Generated Documentation Format

The documentation is generated in **XML format** as the primary output:

- **Location**: `docs/api/xml/`
- **Format**: Doxygen XML (v1.15.0) with XSD schemas
- **Usage**: Machine-readable, suitable for downstream processing
- **Publishing**: Package with `mise run docs:package` → creates `eql-docs-xml-<version>.tar.gz`
- **Integration**: XML output ships with XSD schemas for downstream transformation

HTML output is also generated in `docs/api/html/` for local preview only.

## Development Notes

- SQL files are modular - put operator wrappers in `operators.sql`, implementation in `functions.sql`
- All SQL files must have `-- REQUIRE:` dependency declarations
- Build system resolves dependency order with `cargo run -p eql-codegen -- order`, which walks the whole `src/v3` surface once and topologically sorts it from the `-- REQUIRE:` edges. Dangling targets, edges leaving `src/v3`, and cycles all fail the build.
- **Documentation**: All functions/types must have Doxygen comments (see Documentation Standards above)

### Function Language Choice (SQL vs PL/pgSQL)

Prefer `LANGUAGE SQL` over `LANGUAGE plpgsql` unless you need procedural features.

| Aspect            | LANGUAGE SQL                      | LANGUAGE plpgsql        |
|-------------------|-----------------------------------|-------------------------|
| Inlining          | ✅ Can be inlined by planner       | ❌ Never inlined         |
| Call overhead     | Lower (can be optimized away)     | Higher (context switch) |
| Index performance | Better for GIN index expressions  | Worse                   |
| Control flow      | CASE expression                   | IF/THEN/ELSE            |

**Why SQL wins for simple functions:**

1. **Inlining** - PostgreSQL can inline simple SQL functions into the calling query, eliminating function call overhead entirely. PL/pgSQL functions are never inlined.
2. **Index context** - Functions used in index expressions (e.g., `CREATE INDEX ... USING GIN (eql_v3.jsonb_array(col))`) are called on every row insertion/update. Inlining matters.
3. **Simple logic** - A CASE expression is a single statement. PL/pgSQL's procedural features aren't needed.

**When PL/pgSQL is appropriate:**

- Multiple statements with intermediate variables
- Exception handling (`BEGIN...EXCEPTION...END`)
- Complex control flow (loops, early returns)
- Dynamic SQL (`EXECUTE`)
- Functions that must remain opaque to the planner — typically blockers whose only job is to `RAISE`. `LANGUAGE sql` would be inlined and may be elided when the result is provably unused; `LANGUAGE plpgsql` is never inlined, so the body always runs. See the encrypted-domain footgun list above and the blocker renderers in `crates/eql-codegen/src`.

## Release & changelog discipline

EQL's release version and changelog are both owned by **[Changesets](https://github.com/changesets/changesets)**. `@cipherstash/eql`'s package version is the single source of truth for the release identity `V` (SQL, the crate, and npm all ship at `V` — see `docs/development/releasing.md`), and the release changelog — **`packages/eql/CHANGELOG.md`** (Changesets writes per-package changelogs; with everything in lockstep at one version, that file covers the whole release) — is **generated from the `.changeset/*.md` files** you add, not hand-edited. The root `CHANGELOG.md` is the frozen pre-3.0 archive. Per-version upgrade guides live under `docs/upgrading/`. What follows is what to do when working in this repo.

**Cutting a release is scripted — don't hand-roll `gh release create`, and don't hand-edit `CHANGELOG.md`.** The single entrypoint is `.github/workflows/release.yml`:

- **Final (non-prerelease) release** — from `main`. Changesets maintains a "Version Packages" PR that bumps `V` **and writes the `CHANGELOG.md` section** from the pending changesets; merging that PR triggers `release.yml` to publish npm, publish the crate (via `release-plz.yml`, which crates.io Trusted Publishing requires as the entry point), and build + attach the `eql-<V>` SQL + docs release.
- **Prerelease (alpha/beta/rc)** — from `eql_v3`, via an explicit conventional release commit (`chore(release): ...`) that already pins the prerelease version (Changesets pre-mode). `release.yml` builds SQL + docs and publishes all language packages in one run. Validate on a scratch branch before cutting a real prerelease — a package publish is irreversible.

Full reference for both: **`docs/development/releasing.md`**.

The **language binding packages** are generated from the same `eql-domains::CATALOG` as the SQL surface: the **`eql-bindings` crate** (published to crates.io by **release-plz**, tagged `eql-bindings-v<semver>`) and the **`@cipherstash/eql` npm package** (published via npm Trusted Publishing from `release.yml`, tagged `eql-typescript-v<identity>`). Both bundle the exact self-contained SQL installer/uninstaller they were generated against (the crate exposes it as `eql_bindings::sql`; the npm package via its `./sql` subpath exports). Prerelease release commits on `eql_v3` carry the committed version and bundled SQL for the release; `release.yml` publishes that commit as the prerelease and then dispatches `release-plz.yml` for the crate. release-plz publishes the committed `Cargo.toml` version verbatim and has no absolute-version config, so the release commit must already carry the version pin.

### When you make a user-facing change

If your PR adds, changes, removes, deprecates, or fixes anything observable to a caller — new function, new operator, behaviour change, error message change, performance characteristic that callers might notice (e.g. an index now engages), changed default — **add a changeset in the same PR** (`pnpm changeset`, or hand-write a `.changeset/<name>.md`). Do **not** edit `CHANGELOG.md` directly — Changesets assembles it from changeset files at release time.

Because SQL, the crate, and npm all release in lockstep at one version, **every releasable change needs a changeset** — including SQL-only or crate-only changes. See `.changeset/README.md`.

User-facing means: someone outside EQL would care. If in doubt, add the changeset; it's cheap.

What does *not* need an entry:

- Internal refactors that don't change observable behaviour
- Test-only changes
- CI / tooling-only changes
- Documentation typo fixes
- Doxygen comments

### How to write the changeset

A changeset is a small markdown file: YAML frontmatter selecting the bump type, then the entry body.

```md
---
'@cipherstash/eql': minor   # patch | minor | major — see Versioning below
---

**Lead with the user-visible fact.** Then a short "Why." explanation. Match the tone
and density of existing entries — a single dense paragraph, not a bullet list.
```

The body becomes the `CHANGELOG.md` entry; Changesets adds the version heading and the PR/commit link (don't add one by hand). Example body (adapted from `2.3.0`):

> **`=`, `<>`, `~~` (`LIKE`), `~~*` (`ILIKE`) on `eql_v2_encrypted` are now inlinable SQL functions.** The planner can structurally match these operators against the documented functional indexes (`eql_v2.hmac_256(col)` for equality, `eql_v2.bloom_filter(col)` for `LIKE`/`ILIKE`), so bare-form queries (`WHERE col = $1`) engage the index without per-query rewriting. Previously these operators wrapped multi-branch PL/pgSQL bodies that the planner could not inline, forcing seq scans on Supabase / managed Postgres installations that lack operator-class indexes.

### When a change warrants an upgrade note

If the change has *behaviour callers should be aware of* — even when no API breaks — add a numbered upgrade note (`U-NNN`) to the active `docs/upgrading/v<version>.md` file. Examples of what warrants an upgrade note:

- Recommended recipe shifts (e.g. opclass → functional indexes)
- Tightened error semantics (e.g. "raises now where it used to silently NULL")
- Required payload terms changing (e.g. equality requires `hm`)
- Anything where a caller might need to audit their schema or queries

The entry under `Changed` / `Deprecated` should cross-link to the `U-NNN`. See `docs/upgrading/v2.3.md` for the format — TL;DR, compatibility table, numbered notes, verification checklist, rollback.

### Versioning

The `eql_v3` PostgreSQL schema name is part of the public API and is **independent of the EQL release version**: major-version bumps to EQL do not rename the schema. `eql_v3` is **not** a rename of `eql_v2` — it is a distinct surface (the encrypted-domain scalar type families). The earlier `eql_v2` schema was removed in 3.0.0 (a major, public-API-breaking change); it is no longer shipped, and `eql_v3` is the sole surface going forward. When deciding on a version bump:

- **Patch (`2.3.x`)** — bug fixes, no behaviour changes
- **Minor (`2.x.0`)** — additive changes, behaviour changes that don't break the public API (signatures, schema name, payload format, operator names)
- **Major (`3.0.0`)** — only for changes that break the public API. Do not reach for a major bump just because a behaviour change has wide blast radius — that's what upgrade notes are for.

Declare the chosen bump in your changeset's frontmatter (`'@cipherstash/eql': patch|minor|major`). Changesets aggregates all pending changesets to compute the next `V`, which `sync-lockstep-versions.mjs` then propagates to the crate and the bundled SQL.

### Cutting a release

Releases are cut by **Changesets**, not by hand — see **`docs/development/releasing.md`** for the full runbook (production and prerelease). In short, for a final release from `main`:

1. Ensure the work to release has merged to `main`, each PR carrying a changeset.
2. Changesets maintains a **"Version Packages" PR** that bumps `V` and writes the `CHANGELOG.md` section from the pending changesets. Review it.
3. Merge that PR. `release.yml` then publishes npm, dispatches the crate publish, and builds + attaches the `eql-<V>` SQL + docs release automatically.

Do not hand-edit `CHANGELOG.md` or create the GitHub release manually — Changesets and `release.yml` own all of it.
