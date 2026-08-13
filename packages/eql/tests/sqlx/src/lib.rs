//! EQL test framework infrastructure
//!
//! Provides assertion builders and test helpers for EQL functionality tests.

// Self-alias so this crate can be named `eql_tests::…` in paths that must resolve
// identically whether they expand inside the lib (e.g. `scalar_types!(fixture_modules)`)
// or inside an integration-test binary (e.g. `scalar_types!(matrix_suites)` in
// `tests/encrypted_domain/scalars/mod.rs`). Local harness types like
// `scalar_domains::F4`/`F8` are referenced from the `scalar_types.rs` dispatch list
// via the absolute `eql_tests::scalar_domains::F4` path — `crate::…` would resolve to
// the test binary's own crate root in the matrix-suite expansion, not to this lib.
extern crate self as eql_tests;

use sqlx::PgPool;

pub mod assertions;
pub mod fixtures;
pub mod helpers;
pub mod jsonb_entry;
pub mod known_failure;
pub mod matrix;
pub mod property;
pub mod scalar_domains;
#[macro_use]
pub mod scalar_types;
pub mod selectors;

// Re-export `paste` under a stable path so the `scalar_domain_matrix!` macro
// can refer to `$crate::paste::paste!` without requiring callers to depend on
// the `paste` crate directly.
#[doc(hidden)]
pub use paste;

// Re-export the harness proc-macro crate under a stable path so the
// `scalar_types!` macro can refer to `$crate::eql_tests_macros::<emitter>!`
// without each call site depending on the proc-macro crate directly.
#[doc(hidden)]
pub use eql_tests_macros;

pub use assertions::{assert_db_error, QueryAssertion};
pub use helpers::PLACEHOLDER_PAYLOAD;
pub use known_failure::known_failure;
pub use scalar_domains::{
    assert_null, assert_raises, assert_scalar_plaintexts, blocker_msg, commute_op,
    fetch_fixture_payload, sql_string_literal, ScalarDomainSpec, ScalarType, Variant,
};
pub use selectors::Selectors;

/// Reset pg_stat_user_functions tracking before tests
pub async fn reset_function_stats(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query("SELECT pg_stat_reset()").execute(pool).await?;
    Ok(())
}
