//! `public.eql_v3_text_ord_ope` smoke suite: the shared `_ord_ope` tests plus the
//! text-specific routing contract — `=` / `<>` resolve through `hm` (exact
//! HMAC), never the OPE term, because OPE over text is not equality-lossless
//! (the same rule as `text_ord`'s `[Hm, Ore]`).

use crate::ope_support::ope_cast;

crate::ope_ord_smoke!("eql_v3_text_ord_ope");

// Real-ciphertext coverage: the generated fixture's client-emitted
// `op` terms must order and compare like the plaintext oracle.
crate::ope_ord_fixture_smoke!("eql_v3_text_ord_ope", String, "eql_v3_text");

#[sqlx::test]
async fn equality_routes_through_hm_not_op(pool: PgPool) -> anyhow::Result<()> {
    // Same hm, different op => equal (hm routing). An op-routed `=` would say
    // not-equal here.
    let same_hm: bool = sqlx::query_scalar(&format!(
        "SELECT ({}) = ({})",
        ope_cast("eql_v3_text_ord_ope", "deadbeef", "00"),
        ope_cast("eql_v3_text_ord_ope", "deadbeef", "ff")
    ))
    .fetch_one(&pool)
    .await?;
    assert!(same_hm, "text `=` must route through hm, not op");

    // Different hm, same op => not equal (hm routing). An op-routed `=` would
    // say equal here.
    let diff_hm: bool = sqlx::query_scalar(&format!(
        "SELECT ({}) = ({})",
        ope_cast("eql_v3_text_ord_ope", "deadbeef", "00"),
        ope_cast("eql_v3_text_ord_ope", "feedface", "00")
    ))
    .fetch_one(&pool)
    .await?;
    assert!(!diff_hm, "different hm must not compare equal");

    // Ordering still routes through op: hm order here disagrees with op order.
    let lt: bool = sqlx::query_scalar(&format!(
        "SELECT ({}) < ({})",
        ope_cast("eql_v3_text_ord_ope", "feedface", "00"),
        ope_cast("eql_v3_text_ord_ope", "deadbeef", "ff")
    ))
    .fetch_one(&pool)
    .await?;
    assert!(lt, "text `<` must route through op");
    Ok(())
}
