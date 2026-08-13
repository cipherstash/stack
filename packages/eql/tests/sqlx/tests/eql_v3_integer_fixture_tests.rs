//! Structural verification of the generated `eql_v3_integer` fixture.
//!
//! Vanilla SQL over `fixtures.eql_v3_integer` — `payload` is plain `jsonb`, no
//! domain type required. The `plaintext` column is the in-table oracle; no
//! Rust value constant is shared with the generator. #224 verifies the
//! fixture is well-formed; #225 verifies the domain operators on it.

use anyhow::Result;
use sqlx::PgPool;

/// The 17 values from `src/fixtures/eql_v3_integer.rs`, in id order. Kept here
/// only to assert the in-table `plaintext` oracle matches what was generated.
/// If `plaintext_column_matches_the_generated_values` fails, the generator's
/// `VALUES` and this constant have drifted — re-run
/// `mise run fixture:generate eql_v3_integer` and update this list to match.
const EXPECTED_PLAINTEXTS: &[i32] = &[
    i32::MIN,
    -100,
    -1,
    0,
    1,
    2,
    5,
    10,
    17,
    25,
    42,
    50,
    100,
    250,
    1000,
    9999,
    i32::MAX,
];

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn fixture_has_seventeen_rows(pool: PgPool) -> Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fixtures.eql_v3_integer")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 17, "eql_v3_integer fixture should have 17 rows");
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn ids_are_sequential_one_to_seventeen(pool: PgPool) -> Result<()> {
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM fixtures.eql_v3_integer ORDER BY id")
        .fetch_all(&pool)
        .await?;
    assert_eq!(ids, (1..=17).collect::<Vec<i64>>());
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn plaintext_column_matches_the_generated_values(pool: PgPool) -> Result<()> {
    let plaintexts: Vec<i32> =
        sqlx::query_scalar("SELECT plaintext FROM fixtures.eql_v3_integer ORDER BY id")
            .fetch_all(&pool)
            .await?;
    assert_eq!(plaintexts, EXPECTED_PLAINTEXTS);
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn every_payload_carries_the_hmac_equality_term(pool: PgPool) -> Result<()> {
    // `hm` drives equality. Every row's payload must carry an `hm` string term.
    let missing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM fixtures.eql_v3_integer
         WHERE payload->'hm' IS NULL OR jsonb_typeof(payload->'hm') <> 'string'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(missing, 0, "every payload must carry an `hm` string term");
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn every_payload_carries_the_ore_block_term(pool: PgPool) -> Result<()> {
    // `ob` drives ordering. Every row's payload must carry a non-null ob array.
    let missing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM fixtures.eql_v3_integer
         WHERE payload->'ob' IS NULL OR jsonb_typeof(payload->'ob') <> 'array'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(missing, 0, "every payload must carry an `ob` array term");
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn every_payload_carries_a_ciphertext(pool: PgPool) -> Result<()> {
    // `c` is the ciphertext. Every row's payload must carry a `c` string.
    let missing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM fixtures.eql_v3_integer
         WHERE payload->'c' IS NULL OR jsonb_typeof(payload->'c') <> 'string'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        missing, 0,
        "every payload must carry a `c` ciphertext string"
    );
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn plaintext_oracle_supports_value_filtering(pool: PgPool) -> Result<()> {
    // The in-table `plaintext` oracle: a consuming test can filter on it
    // directly. Exactly one row has plaintext = 42.
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM fixtures.eql_v3_integer WHERE plaintext = 42 ORDER BY id",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        ids,
        vec![11],
        "expected exactly one row with plaintext = 42 at id 11"
    );
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn hmac_equality_terms_are_distinct_for_distinct_values(pool: PgPool) -> Result<()> {
    // All 17 plaintext values are distinct, so all 17 `hm` terms must be too.
    let distinct_hm: i64 =
        sqlx::query_scalar("SELECT COUNT(DISTINCT payload->>'hm') FROM fixtures.eql_v3_integer")
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        distinct_hm, 17,
        "17 distinct values -> 17 distinct hm terms"
    );
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn every_payload_declares_eql_payload_version_v3(pool: PgPool) -> Result<()> {
    // Every `eql_v3` domain CHECK pins `VALUE->>'v' = '3'` (the #340
    // envelope bump), and the generator routes the pinned client's v2
    // output through `eql_bindings::from_v2` before writing the fixture.
    // Asserting equality here (not just presence) means a future envelope
    // bump fails this test loudly, forcing the maintainer to regenerate the
    // fixture and audit consumers for semantic changes.
    let mismatched: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM fixtures.eql_v3_integer
         WHERE payload->'v' IS NULL OR payload->>'v' <> '3'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(mismatched, 0, "every payload must declare v = '3'");
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn no_payload_carries_the_v2_form_discriminator(pool: PgPool) -> Result<()> {
    // The v2 wire's `k: "ct"` discriminator is dropped by the from_v2
    // conversion — its presence would mean a raw client payload bypassed
    // the conversion seam.
    let with_k: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM fixtures.eql_v3_integer WHERE payload ? 'k'")
            .fetch_one(&pool)
            .await?;
    assert_eq!(with_k, 0, "no converted scalar payload may carry `k`");
    Ok(())
}
