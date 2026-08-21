//! Type-checked fixture generation framework.
//!
//! A fixture is one Rust file under `src/fixtures/` declaring a `FixtureSpec`.
//! `FixtureSpec::run()` generates the SQLx fixture script
//! `tests/sqlx/fixtures/<name>.sql` (gitignored — regenerated on every
//! `mise run test:sqlx`).

pub mod validation;

pub mod eql_plaintext;

pub use eql_plaintext::EqlPlaintext;

pub mod index_kind;

pub use index_kind::IndexKind;

pub mod spec;

pub use spec::FixtureSpec;

#[macro_use]
pub mod scalar_fixture;

pub mod cipherstash;

pub mod driver;

// The v2 → v3 envelope conversion seam: generated client payloads (`v: 2`)
// are routed through `eql_bindings::from_v2` before staging, so every
// written fixture satisfies the `v = '3'` domain CHECKs.

// The v3 json (SteVec document) fixture — a hand-written `FixtureSpec`
// over `serde_json::Value`, generated through the same pipeline as the
// scalar `eql_v3_<T>` fixtures. Not a CATALOG scalar, so it is registered
// here directly rather than via `scalar_types!`.
pub mod v3_ste_vec;

// The storage-only / encryption-only json fixture — a hand-written
// `FixtureSpec<serde_json::Value>` with NO index, so each document encrypts to a
// plain `{v, i, c}` envelope for the storage-only `public.eql_v3_json` domain.
// Same pipeline as `v3_ste_vec`, minus the SteVec index.
pub mod v3_json_storage;

// The scalar-shaped SteVec document fixture — a SteVec document carrying one
// integer scalar at `$.field` per `eql_domains::INTEGER_VALUES`. A SPLIT fixture
// (jsonb-document encryption input, integer plaintext oracle), so it uses the
// `run_with_payloads` seam rather than `FixtureSpec::run`. Drives the
// jsonb-entry behaviour matrix (`JsonbEntryInteger`).
pub mod v3_doc_integer;

// The numeric scale-equivalence collision fixture (`1`, `1.0`, `2`). Not a
// CATALOG scalar — the catalog distinctness guard forbids the value-equal pair
// `1`/`1.0` — so it is hand-written and registered here directly (like the
// other `v3_` fixtures). Gives the `1 == 1.0` ORE collision an always-on
// (generated-fixture) home instead of a creds-gated runtime encryption.
pub mod v3_numeric_collision;

// The empty-string ordered-text fixture (`""`, `"frank"`, `"zebra"`). Not a
// CATALOG scalar — `eql-domains::TEXT_FIXTURES` deliberately excludes `""`
// (issue #262) — so it is hand-written and registered here directly (like the
// other `v3_` fixtures). Gives the "empty sorts first" contract (ORDER BY /
// min / max over `text_ord`) a generated real-ciphertext home.
pub mod v3_text_empty;

// The empty-bloom fuzzy-match fixture (`"pq"`, `"aardvark"`). Not a CATALOG
// scalar — `eql-domains::TEXT_FIXTURES` has no sub-trigram value, so no catalog
// value produces an empty bloom (`bf: []`) — so it is hand-written and
// registered here directly (like the other `v3_` fixtures). Gives the
// empty-needle guard in `eql_v3.matches` a generated real-ciphertext home.
pub mod v3_text_empty_bloom;

// Per-type "doubles" fixtures (each plaintext encrypted twice) for the
// cross-ciphertext-equality test. Non-catalog, like `v3_numeric_collision`.
pub mod eql_doubles;

// The per-type scalar fixture modules (`eql_v3_integer`, `eql_v3_smallint`, …) are
// generated from the harness list in `scalar_types.rs`. Each expands to
// `pub mod eql_v3_<T> { … scalar_fixture! … }`, reading its plaintext values
// directly from the catalog (`eql_domains::<TOKEN>_VALUES`).
crate::scalar_types!(fixture_modules);
