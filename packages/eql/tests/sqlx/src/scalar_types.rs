//! The single declarative list of scalar types under matrix test — the harness
//! source of truth.
//!
//! To add a scalar encrypted-domain type to the SQLx matrix, add one
//! `token => rust_type` line below (plus the catalog row in `eql-domains` and
//! the `EqlPlaintext` impl, owned separately — see
//! `docs/reference/adding-a-scalar-encrypted-domain-type.md` §3). The entry
//! carries no shape marker: whether a type is temporal (chrono-backed) or
//! equality-only is read from its `eql-domains::CATALOG` row
//! (`ScalarKind::is_temporal()` / `DomainFamily::is_eq_only()`). A temporal
//! scalar generates its `impl ScalarType` via `temporal_values!` in
//! `scalar_domains.rs` and gets pivot-presence fixture asserts instead of the
//! integer signed-extreme ones.
//!
//! The harness pieces live in three separate compilation contexts (the
//! `eql-tests` lib, the `encrypted_domain` integration-test binary, and the
//! `generate_all_fixtures` integration-test binary), so no single proc-macro
//! invocation can reach all three. The list is held here once, inside the
//! `scalar_types!` `macro_rules!`; each call site invokes `scalar_types!(<mode>)`
//! to forward it to the matching `eql_tests_macros` proc-macro:
//!
//! - `scalar_type_impls` — `scalar_domains.rs` (lib): the `impl ScalarType` block.
//! - `fixture_modules` — `fixtures/mod.rs` (lib): the `pub mod eql_v3_<T>` modules.
//! - `matrix_suites` — `tests/encrypted_domain/scalars/mod.rs` (test binary):
//!   the `scalar_matrix!` suites.
//! - `fixture_dispatch` — `tests/generate_all_fixtures.rs` (test binary): the
//!   `generate_for_token` dispatch fn.
//!
//! The matrix-inventory cross-check (`mise run test:matrix:inventory`) compares
//! the type set the binary emits against `eql-codegen list-types`, so a catalog
//! type missing from this list fails loudly.

/// Forward the canonical scalar-type list to the `eql_tests_macros` proc-macro
/// selected by `$mode` (see module docs for call sites).
///
/// This is the only place the harness token set is declared. Keep it in sync
/// with `eql-domains::CATALOG`; the matrix-inventory cross-check enforces it.
#[macro_export]
macro_rules! scalar_types {
    (scalar_type_impls) => {
        $crate::scalar_types!(@dispatch emit_scalar_type_impls);
    };
    (fixture_modules) => {
        $crate::scalar_types!(@dispatch emit_scalar_fixture_modules);
    };
    (matrix_suites) => {
        $crate::scalar_types!(@dispatch emit_scalar_matrix_suites);
    };
    (fixture_dispatch) => {
        $crate::scalar_types!(@dispatch emit_fixture_dispatch);
    };
    (@dispatch $emitter:ident) => {
        $crate::eql_tests_macros::$emitter! {
            integer => i32,
            smallint => i16,
            bigint => i64,
            date => chrono::NaiveDate,
            timestamp => chrono::DateTime<chrono::Utc>,
            numeric => rust_decimal::Decimal,
            text => String,
            boolean => bool,
            real => eql_tests::scalar_domains::F4,
            double => eql_tests::scalar_domains::F8,
        }
    };
}
