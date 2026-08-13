# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Scalar query-operand bindings.** Every term-bearing scalar
  domain now has a generated query twin — `IntegerEqQuery`, `IntegerOrdOpeQuery`,
  `TextSearchQuery`, … — the **enveloped term-only** operand `{v, i, <terms>}`
  (envelope minus the ciphertext `c`) for its `eql_v3.query_<name>` query
  domain, with matching TypeScript bindings (`bindings/v3/*Query.ts`) and JSON
  Schemas (`schema/v3/query_<name>.json`). Storage-only domains (no operators)
  get no twin. `QueryPayload` is now catalog-generated — a variant per query
  twin plus the SteVec containment needle — superseding the hand-written
  single-variant enum. A new `all_query()` inventory exposes the query twins
  separately from `all()` (which stays the stored + SteVec conversion-target
  inventory).

### Changed

- **Query-operand domain names switched to the `query_<name>` prefix, homed
  in the `eql_v3` schema.** The SQL domain names carried by the
  query twins — in `DomainType::sql_domain`, the names `QueryPayload::parse`
  accepts, and the exported JSON Schema file names — are now `query_<name>` /
  `eql_v3.query_<name>` (e.g. `query_integer_eq`), and the SteVec containment
  needle is `eql_v3.query_jsonb` (was `public.jsonb_query`).
  `DomainType::domain` now strips whichever schema qualifies `sql_domain`
  (`public.` for column domains, `eql_v3.` for query operands) instead of
  assuming `public.`. Matches the renamed/relocated SQL surface — query
  operands are never column types, so they leave the `public` column-type
  namespace; supersedes the `public.<name>_query` naming shipped only in
  3.0.0 pre-releases.
- **`from_v2_query` / `from_v2_query_typed` now convert scalar query targets.**
  A term-bearing scalar target hoists the v2 payload's required terms into the
  `{v: 3, i, <terms>}` operand for its `query_<name>` domain (dropping the
  stored `c`/`k`; `bf` reinterpreted to signed `smallint[]`), validated through
  the generated `QueryPayload`. Storage-only scalar targets still return
  `UnsupportedQueryTarget`. Previously every scalar query target failed closed.

## [0.4.2] - 2026-07-03

### Fixed

- Compiling the crate no longer emits ts-rs's "failed to parse serde
  attribute" warning for `skip_serializing_if` on `SteVecEntry.a` (the
  `no-serde-warnings` feature is enabled). The attribute was always ignored
  by design — TS optionality is declared explicitly with
  `#[ts(optional = nullable)]` — and the emitted TS/JSON is byte-identical.

## [0.4.1] - 2026-07-03

### Fixed

- The `from_v2_query_typed` rustdoc links only public items, fixing the
  `private_intra_doc_links` lint on docs.rs builds. No API changes.

## [0.4.0] - 2026-07-03

### Added

- `QueryPayload` — a hand-written enum spanning every v3 QUERY payload shape.
  Today that is exactly one variant: `SteVec(SteVecQuery)`, the jsonb
  containment needle. The single-term scalar query variants (an Ore / Ope /
  Bloom / Hm term value) are deliberately absent until the eql-mapper
  redesign defines a v3 scalar-query wire shape — fail-closed, no invented
  shapes. Serialize-only (`#[serde(untagged)]` — the wire form is exactly the
  inner type's) and constructed only from a known domain
  (`QueryPayload::parse`), never inferred from bytes. No ts-rs/schemars
  derives: the enum adds no wire shape of its own, so the exported TS /
  JSON-Schema artifacts are unchanged.
- `from_v2_query_typed(&Value, TargetDomain) -> Result<QueryPayload,
  FromV2Error>` — the typed counterpart to `from_v2_query`, sharing its
  conversion core and performing the single strict parse as parse-and-keep
  instead of validate-and-discard. `from_v2_query -> Value` is unchanged, and
  scalar targets still fail with `UnsupportedQueryTarget` on both entry
  points.

## [0.3.0] - 2026-07-03

### Added

- `DomainPayload` — a catalog-generated enum spanning every stored-payload
  domain type (all scalar binding structs plus `SteVecDocument`), emitted by
  eql-codegen so it cannot drift when the catalog grows a domain.
  Serialize-only (`#[serde(untagged)]` — the wire form is exactly the inner
  struct's) and constructed only from a known `TargetDomain`, never inferred
  from bytes (cross-token payloads are byte-identical on the wire).
- `from_v2_typed(&Value, TargetDomain) -> Result<DomainPayload, FromV2Error>`
  — the typed counterpart to `from_v2`, sharing its conversion core and
  performing the single strict parse as parse-and-keep instead of
  validate-and-discard. `from_v2 -> Value` is unchanged.

## [0.2.0] - 2026-07-03

### Changed

- **BREAKING**: the EQL envelope version is now `v: 3` (was `v: 2`) —
  `EQL_SCHEMA_VERSION`, the `SchemaVersion` newtype, the emitted TypeScript
  alias, and the JSON Schema `const` accept exactly `3`, matching the
  `eql_v3` domain CHECKs.

### Added

- `from_v2` — EQL v2.3 → v3 wire payload conversion: `from_v2(&Value,
  TargetDomain)` for storage payloads (fail-closed on missing terms, drops
  the v2 `k` discriminator, strict-parses through the target binding type),
  `from_v2_query` for jsonb containment needles, and `is_v3_payload` for
  envelope sniffing. Zero cipherstash-client dependency.
- SteVec (encrypted JSONB) document surface: `SteVecDocument` (carrying the
  `k: "sv"` form discriminator), entry/query types, and the `OreCllw` /
  `Selector` term newtypes, with generated inventory, TypeScript bindings,
  and JSON Schemas.
- CLLW-OPE ordering term: the `OpeCllw` newtype (`op` wire key) and the
  `<T>OrdOpe` binding types for every ordered scalar family.
- `TargetDomain::parse` resolving domain names via the catalog-generated
  inventory; `term_json_keys` / `parse_value` threaded through `DomainType`.
