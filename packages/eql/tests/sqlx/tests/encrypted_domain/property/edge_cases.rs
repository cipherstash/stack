//! Unit edge cases for the eql_v3 scalar domains: NULL propagation on
//! supported operators, blocker functions raising on unsupported operators
//! (equality, ordering, path, and containment families — the documented
//! domain-fallback footgun), ordering blocked on the equality-only `_eq` domain,
//! and domain CHECK-constraint rejection of malformed payloads. No encryption.

use anyhow::Result;
use eql_tests::scalar_domains::{
    assert_null, assert_raises, blocker_msg, ScalarDomainSpec, Variant,
};
use sqlx::PgPool;

/// A well-formed integer storage/eq payload literal — has v/i/c + hm + ob, so it
/// casts into any integer domain. Hand-written (no encryption needed); the term
/// VALUES are placeholders, which is fine for NULL/blocker/CHECK shape tests.
const WELL_FORMED: &str =
    r#"{"v":3,"i":{"t":"edge","c":"payload"},"c":"AAAA","hm":"deadbeef","ob":["00"]}"#;

fn integer(variant: Variant) -> String {
    ScalarDomainSpec::new::<i32>(variant).sql_domain
}

#[sqlx::test]
async fn eq_propagates_null(pool: PgPool) -> Result<()> {
    let d = integer(Variant::Eq);
    // A supported operator with a NULL operand must yield NULL, not raise.
    let sql = format!("SELECT ($1::jsonb::{d}) = (NULL::{d})");
    assert_null(&pool, &sql, &[Some(WELL_FORMED)]).await
}

#[sqlx::test]
async fn lt_blocker_raises_on_eq_domain(pool: PgPool) -> Result<()> {
    // `<` is not supported on the equality-only domain; the blocker must RAISE,
    // and must NOT be elided even on a NULL operand (blockers are never STRICT).
    let d = integer(Variant::Eq);
    let sql = format!("SELECT ($1::jsonb::{d}) < ($1::jsonb::{d})");
    assert_raises(&pool, &sql, &[Some(WELL_FORMED)], &blocker_msg(&d, "<")).await?;
    // NULL operand: still raises (proves the blocker is not STRICT).
    let sql_null = format!("SELECT (NULL::{d}) < (NULL::{d})");
    assert_raises(&pool, &sql_null, &[], &blocker_msg(&d, "<")).await
}

#[sqlx::test]
async fn path_blocker_raises_on_eq_domain(pool: PgPool) -> Result<()> {
    // A native-jsonb PATH operator (`->`) reachable through domain fallback must
    // hit the blocker, not silently return a jsonb sub-value (the documented
    // footgun). The domain ships its own `->` operator that always raises.
    let d = integer(Variant::Eq);
    let sql = format!("SELECT ($1::jsonb::{d}) -> 'sel'::text");
    assert_raises(&pool, &sql, &[Some(WELL_FORMED)], &blocker_msg(&d, "->")).await?;
    // NULL operand: still raises (proves the blocker is not STRICT, so a NULL
    // argument cannot let PostgreSQL skip the body and fall through to NULL).
    let sql_null = format!("SELECT (NULL::{d}) -> 'sel'::text");
    assert_raises(&pool, &sql_null, &[], &blocker_msg(&d, "->")).await
}

#[sqlx::test]
async fn containment_blocker_raises_on_eq_domain(pool: PgPool) -> Result<()> {
    // A native-jsonb CONTAINMENT operator (`@>`) must likewise hit the blocker
    // on a domain that does not support it (integer_eq carries only `hm`/equality).
    let d = integer(Variant::Eq);
    let sql = format!("SELECT ($1::jsonb::{d}) @> ($1::jsonb::{d})");
    assert_raises(&pool, &sql, &[Some(WELL_FORMED)], &blocker_msg(&d, "@>")).await?;
    // NULL operand: still raises (not STRICT).
    let sql_null = format!("SELECT (NULL::{d}) @> (NULL::{d})");
    assert_raises(&pool, &sql_null, &[], &blocker_msg(&d, "@>")).await
}

#[sqlx::test]
async fn ordering_blocked_on_timestamp_eq_domain(pool: PgPool) -> Result<()> {
    // timestamp is an ordered scalar on the `eql_v3` base (its `_ord`/`_ord_ore`
    // domains order via the wide-ORE comparator). But the equality-only `_eq`
    // domain still must NOT answer ordering: an ordering operator on
    // `timestamp_eq` must RAISE (and be non-STRICT), not silently mis-order —
    // exactly as `integer_eq` does. Callers order via the `_ord` twins, not `_eq`.
    let d = ScalarDomainSpec::new::<chrono::DateTime<chrono::Utc>>(Variant::Eq).sql_domain;
    let sql = format!("SELECT (NULL::{d}) < (NULL::{d})");
    assert_raises(&pool, &sql, &[], &blocker_msg(&d, "<")).await
}

#[sqlx::test]
async fn every_eql_v3_blocker_is_non_strict_plpgsql(pool: PgPool) -> Result<()> {
    // The footgun guard, applied to EVERY generated blocker at once.
    //
    // Codegen emits a blocker for each native-jsonb operator a domain does NOT
    // support (`->`, `->>`, `@>`, `<@`, `||`, `?`, `?|`, `?&`, `@?`, `@@`, `#>`,
    // `#>>`, `-`, `#-`, plus the unsupported comparison ops) across every
    // eql_v3 scalar domain (storage / _eq / _ord / _ord_ore / _match). Each MUST
    // be `LANGUAGE plpgsql` and MUST NOT be `STRICT`:
    //   * a `STRICT` blocker is skipped on a NULL argument, silently returning
    //     NULL instead of raising — falling through to native jsonb semantics;
    //   * a `LANGUAGE sql` blocker is inlinable and the planner can elide the
    //     call (and its RAISE) when the result is provably unused.
    // The behavioural tests above prove the raise for representative operators
    // (`<`, `->`, `@>`); this proves the structural contract for the WHOLE set,
    // and against the *installed* catalog (catching build/install drift the
    // codegen golden test cannot see). Blockers are identified by their RAISE
    // body — the `'operator % is not supported for %'` message every blocker
    // carries and nothing else does.
    let (total, strict, non_plpgsql): (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT count(*),
               count(*) FILTER (WHERE p.proisstrict),
               count(*) FILTER (WHERE l.lanname <> 'plpgsql')
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_catalog.pg_language  l ON l.oid = p.prolang
        WHERE n.nspname IN ('eql_v3', 'eql_v3_internal')
          AND p.prosrc LIKE '%is not supported for %'
        "#,
    )
    .fetch_one(&pool)
    .await?;

    anyhow::ensure!(
        total > 0,
        "found no eql_v3 blocker functions — did the extension install?"
    );
    anyhow::ensure!(
        strict == 0,
        "{strict} of {total} eql_v3 blocker(s) are STRICT — a STRICT blocker is \
         elided on a NULL argument, bypassing the not-supported RAISE"
    );
    anyhow::ensure!(
        non_plpgsql == 0,
        "{non_plpgsql} of {total} eql_v3 blocker(s) are not LANGUAGE plpgsql — a \
         LANGUAGE sql blocker is inlinable and can be elided when the result is \
         provably unused"
    );
    Ok(())
}

#[sqlx::test]
async fn check_rejects_payload_missing_envelope(pool: PgPool) -> Result<()> {
    // The storage domain's CHECK requires the EQL envelope (`v`, `i`, `c`). A
    // payload missing the top-level ciphertext `c` must be rejected at the cast.
    let d = integer(Variant::Storage);
    let no_c = r#"{"v":3,"i":{"t":"edge","c":"payload"}}"#;
    let sql = format!("SELECT $1::jsonb::{d}");
    assert_raises(&pool, &sql, &[Some(no_c)], "violates check constraint").await
}

#[sqlx::test]
async fn check_rejects_payload_missing_hm(pool: PgPool) -> Result<()> {
    // The _eq domain CHECK requires `hm`. A payload without it must be rejected
    // at the cast with a CHECK-constraint violation (not some unrelated error).
    let d = integer(Variant::Eq);
    let no_hm = r#"{"v":3,"i":{"t":"edge","c":"payload"},"c":"AAAA","ob":["00"]}"#;
    let sql = format!("SELECT $1::jsonb::{d}");
    assert_raises(&pool, &sql, &[Some(no_hm)], "violates check constraint").await
}

#[sqlx::test]
async fn check_ord_rejects_payload_missing_op(pool: PgPool) -> Result<()> {
    // Post CLLW-OPE flip, the `_ord` domain is OPE-backed and its CHECK requires
    // `op` (not `ob`). A payload carrying `ob` (and `hm`) but no `op` must be
    // rejected at the cast — proving `_ord` genuinely needs the OPE term, not the
    // ORE `ob` array it no longer references.
    let d = integer(Variant::Ord);
    let no_op = r#"{"v":3,"i":{"t":"edge","c":"payload"},"c":"AAAA","hm":"deadbeef","ob":["00"]}"#;
    let sql = format!("SELECT $1::jsonb::{d}");
    assert_raises(&pool, &sql, &[Some(no_op)], "violates check constraint").await
}

#[sqlx::test]
async fn check_ord_ore_rejects_payload_missing_ob(pool: PgPool) -> Result<()> {
    // The `_ord_ore` domain is ORE-backed and its CHECK requires the `ob` array.
    // A payload carrying `op` (and `hm`) but no `ob` must be rejected at the cast
    // — proving `_ord_ore` genuinely needs the ORE term, not the OPE `op` scalar.
    let d = integer(Variant::OrdOre);
    let no_ob = r#"{"v":3,"i":{"t":"edge","c":"payload"},"c":"AAAA","hm":"deadbeef","op":"00"}"#;
    let sql = format!("SELECT $1::jsonb::{d}");
    assert_raises(&pool, &sql, &[Some(no_ob)], "violates check constraint").await
}
