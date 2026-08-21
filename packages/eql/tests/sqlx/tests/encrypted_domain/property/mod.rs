//! Property-based and edge-case tests for the eql_v3 encrypted scalar domains
//!. Deliberately NOT under `scalars::` — the matrix-inventory gate
//! (`mise run test:matrix:inventory`) discovers scalar types from every
//! `scalars::<X>::` test-name prefix, so a `scalars::property::…` test would be
//! mis-read as a scalar type and break the catalog cross-check.

/// The embedded SQLx migration set (`tests/sqlx/migrations`) — the SAME one
/// `#[sqlx::test]` applies to its scratch DBs. Only the e2e suite needs it: it
/// connects to the base DB directly (its proptest case loop is sync and it
/// batch-encrypts via ZeroKMS), so it applies the migrations itself to reach the
/// migrated state the rest of the suite gets for free (see
/// `property::ensure_eql_installed`). The fixture suite is a `#[sqlx::test]` and
/// needs none of this. The macro embeds the files at compile time and resolves
/// `./migrations` against the `eql_tests` crate root (`tests/sqlx`); kept in the
/// test target, not the lib, so the lib never embeds the gitignored generated
/// `001_install_eql.sql`. Gated to the e2e feature so it is not dead code in the
/// default (shard) build.
#[cfg(feature = "proptest-e2e")]
pub(crate) fn migrator() -> sqlx::migrate::Migrator {
    sqlx::migrate!("./migrations")
}

// NULL / blocker / CHECK-constraint unit tests.
mod edge_cases;
// fixture suite: operator + function-double oracles over the generated fixture
// rows (real ciphertext), plus term-extractor identity.
mod fixture_oracle;
// fixture suite: example-based bloom match smoke over the text `_match` fixtures.
mod match_smoke;
// fixture suite: cross-ciphertext equality over the per-type doubles fixtures
// (each plaintext encrypted twice) — proves two independent encryptions of one
// value compare equal through both the hm (`_eq`) and ORE (`_ord`/`_ord_ore`)
// paths.
mod cross_ciphertext;
// e2e suite: oracle over freshly generated + batch-encrypted values.
#[cfg(feature = "proptest-e2e")]
mod e2e_oracle;
// e2e suite: the empty-bloom needle guard in `eql_v3.matches` over freshly
// generated (incl. sub-trigram) plaintexts — follow-up to PR #421.
#[cfg(feature = "proptest-e2e")]
mod empty_bloom_guard;
