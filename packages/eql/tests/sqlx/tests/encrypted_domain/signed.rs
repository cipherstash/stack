//! Sign-boundary coverage for **signed** scalars (`smallint`/`integer`/`bigint`, `date`,
//! `timestamp`, `real`/`double`) — the `SignedScalar` delta on top of the
//! uniform ordered matrix.
//!
//! ORE encrypts signed values as an offset from a numeric origin (`0` for
//! integers and floats, the epoch for `date`/`timestamp`). This suite asserts the ORE block ordering is
//! **monotonic across that origin**: a fixture below the origin orders before
//! the origin, which orders before a fixture above it — through the encrypted
//! `_ord` domain, with no decryption.
//!
//! It is deliberately **outside** the `scalars::<T>::` namespace (like the
//! `text_match` suites) so the matrix-inventory snapshot — which pins the
//! *uniform* per-type test set — does not see it. The generic body bounds on
//! `eql_tests::scalar_domains::SignedScalar`, so a `text` (`!SignedScalar`)
//! instantiation is a **compile error**: lexicographic text has no origin.
// `SignedScalar` is the bound; its supertrait methods (`min_pivot`/`max_pivot`
// from `OrderedScalar`, `PG_TYPE` from `ScalarType`) are reachable through it.
use eql_tests::scalar_domains::{fetch_fixture_payload, sql_string_literal, SignedScalar};
use sqlx::PgPool;

/// `min_pivot() < origin() < max_pivot()` holds through the encrypted `_ord`
/// domain's `<` operator (ORE block comparison), spanning the sign boundary.
async fn sign_boundary_is_monotonic<T: SignedScalar>(pool: &PgPool) -> anyhow::Result<()> {
    let d = format!("public.eql_v3_{}_ord", T::PG_TYPE);

    // Fixtures straddling the origin: min is below it, max above it.
    let below = sql_string_literal(&fetch_fixture_payload::<T>(pool, T::min_pivot()).await?);
    let origin = sql_string_literal(&fetch_fixture_payload::<T>(pool, T::origin()).await?);
    let above = sql_string_literal(&fetch_fixture_payload::<T>(pool, T::max_pivot()).await?);

    let sql = format!(
        "SELECT \
           ({below}::jsonb::{d} < {origin}::jsonb::{d}) AND \
           ({origin}::jsonb::{d} < {above}::jsonb::{d}) AND \
           ({below}::jsonb::{d} < {above}::jsonb::{d})"
    );
    let monotonic: bool = sqlx::query_scalar(&sql).fetch_one(pool).await?;
    assert!(
        monotonic,
        "{}: ORE ordering must be monotonic across the origin (below < origin < above):\n{sql}",
        T::PG_TYPE,
    );
    Ok(())
}

#[sqlx::test(fixtures(path = "../../fixtures", scripts("eql_v3_integer")))]
async fn integer_sign_boundary(pool: PgPool) -> anyhow::Result<()> {
    sign_boundary_is_monotonic::<i32>(&pool).await
}

#[sqlx::test(fixtures(path = "../../fixtures", scripts("eql_v3_date")))]
async fn date_sign_boundary(pool: PgPool) -> anyhow::Result<()> {
    sign_boundary_is_monotonic::<chrono::NaiveDate>(&pool).await
}

#[sqlx::test(fixtures(path = "../../fixtures", scripts("eql_v3_smallint")))]
async fn smallint_sign_boundary(pool: PgPool) -> anyhow::Result<()> {
    sign_boundary_is_monotonic::<i16>(&pool).await
}

#[sqlx::test(fixtures(path = "../../fixtures", scripts("eql_v3_bigint")))]
async fn bigint_sign_boundary(pool: PgPool) -> anyhow::Result<()> {
    sign_boundary_is_monotonic::<i64>(&pool).await
}

#[sqlx::test(fixtures(path = "../../fixtures", scripts("eql_v3_timestamp")))]
async fn timestamp_sign_boundary(pool: PgPool) -> anyhow::Result<()> {
    sign_boundary_is_monotonic::<chrono::DateTime<chrono::Utc>>(&pool).await
}

#[sqlx::test(fixtures(path = "../../fixtures", scripts("eql_v3_real")))]
async fn real_sign_boundary(pool: PgPool) -> anyhow::Result<()> {
    sign_boundary_is_monotonic::<eql_tests::scalar_domains::F4>(&pool).await
}

#[sqlx::test(fixtures(path = "../../fixtures", scripts("eql_v3_double")))]
async fn double_sign_boundary(pool: PgPool) -> anyhow::Result<()> {
    sign_boundary_is_monotonic::<eql_tests::scalar_domains::F8>(&pool).await
}
