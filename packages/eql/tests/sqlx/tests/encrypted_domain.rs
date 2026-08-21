//! Umbrella integration-test binary for the encrypted-domain type family.
//!
//! Cargo's default discovery picks this file up as a test binary; the
//! module tree under `encrypted_domain/` is pulled in via the `#[path]`
//! attributes below. Legacy tests under `tests/sqlx/tests/*.rs` continue
//! to compile as their own separate binaries.

#[path = "encrypted_domain/family/mod.rs"]
mod family;

#[path = "encrypted_domain/scalars/mod.rs"]
mod scalars;

// Text-specific behavioural suites (literal-payload smoke + fixture-backed
// match-containment). Deliberately NOT under `scalars::` — the matrix-inventory
// gate treats every `scalars::<X>::` prefix as a scalar type, so these would be
// mis-discovered as types `text_smoke` / `text_match`.
#[path = "encrypted_domain/text/text_smoke.rs"]
mod text_smoke;

#[path = "encrypted_domain/text/text_match.rs"]
mod text_match;

// CLLW-OPE (`op` term, `*_ord_ope` domains) smoke suites: hand-built literal
// hex payloads for the SQL surface (routing, inlining, CHECK discipline) PLUS
// real-ciphertext fixture tests ( — cipherstash-client 0.38.1 emits
// `op` and the generated fixtures carry it). One TOP-LEVEL module per ordered
// scalar, named `<t>_ord_ope`, so the `test:matrix:catalog-coverage` gate's
// dedicated-module pattern (`<t>_<seg>::*`) sees every catalog `ord_ope`
// domain covered — the same mechanism `text_match` uses for the Bloom domain.
// Deliberately NOT under `scalars::` — the matrix-inventory gate treats every
// `scalars::<X>::` prefix as a scalar type (same rationale as the text
// suites). The per-test name set is pinned by `snapshots/ope_tests.txt`
// (`mise run test:matrix:inventory:ope`). `ope_support` carries the shared
// payload builder and the `ope_ord_smoke!` / `ope_ord_fixture_smoke!` macros
// the per-type modules invoke.
#[path = "encrypted_domain/ope/support.rs"]
mod ope_support;

#[path = "encrypted_domain/ope/integer_ord_ope.rs"]
mod integer_ord_ope;

#[path = "encrypted_domain/ope/smallint_ord_ope.rs"]
mod smallint_ord_ope;

#[path = "encrypted_domain/ope/bigint_ord_ope.rs"]
mod bigint_ord_ope;

#[path = "encrypted_domain/ope/date_ord_ope.rs"]
mod date_ord_ope;

#[path = "encrypted_domain/ope/timestamp_ord_ope.rs"]
mod timestamp_ord_ope;

#[path = "encrypted_domain/ope/numeric_ord_ope.rs"]
mod numeric_ord_ope;

#[path = "encrypted_domain/ope/text_ord_ope.rs"]
mod text_ord_ope;

#[path = "encrypted_domain/ope/real_ord_ope.rs"]
mod real_ord_ope;

#[path = "encrypted_domain/ope/double_ord_ope.rs"]
mod double_ord_ope;

// Signed-only sign-boundary suite (`int`, `date`). Like the text suites it
// lives outside `scalars::` so the matrix-inventory snapshot (which pins the
// uniform per-type set) does not see the signed-only delta.
#[path = "encrypted_domain/signed.rs"]
mod signed;

// Float edge-case behavioural suite (NaN / ±0 / ±Inf). Creds/e2e-gated: it
// encrypts the special values FRESH at test time, so NaN never enters the shared
// double fixture table (where it would corrupt the all-pairs oracle). Deliberately
// NOT under `scalars::` so the matrix-inventory snapshot does not mis-read it as a
// scalar type (same rationale as `signed` / `text_match`).
#[cfg(feature = "proptest-e2e")]
#[path = "encrypted_domain/float_special.rs"]
mod float_special;

// Table-level SQL constraint coverage (UNIQUE / NOT NULL / FOREIGN KEY) on
// `eql_v3` encrypted-domain columns — the v3 analogue of v2's
// `constraint_tests.rs`. Outside `scalars::` so the matrix-inventory snapshot
// does not mis-read it as a scalar type (same rationale as `signed`).
#[path = "encrypted_domain/constraints.rs"]
mod constraints;

// SteVec jsonb-entry behaviour matrix (the reduced `jsonb_entry_matrix!`).
// Deliberately NOT under `scalars::` — `JsonbEntryInteger` is not a catalog scalar,
// so its names live under `jsonb_entry::…` and are pinned by the separate
// `test:matrix:inventory:jsonb_entry` task, not the scalar inventory.
#[path = "encrypted_domain/jsonb_entry.rs"]
mod jsonb_entry;

// Property-based + edge-case tests. Three suites under `property::`
// (catalog, fixture, e2e), kept outside `scalars::` so the matrix-inventory gate
// does not mis-read them as scalar types. See `encrypted_domain/property/mod.rs`.
#[path = "encrypted_domain/property/mod.rs"]
mod property;
