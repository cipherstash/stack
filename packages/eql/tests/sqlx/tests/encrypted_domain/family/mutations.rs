//! Negative controls (mutation tests) for the scalar-domain matrix.
//!
//! A green matrix proves the SUT behaves correctly *today*, but it cannot
//! prove the matrix arms would catch a regression — an arm could be
//! vacuous and still pass. Each test here applies one surgical mutation to
//! the installed `eql_v3` schema and asserts that the property a specific
//! matrix arm guards now flips. If a mutation does NOT flip the property,
//! that arm has no teeth.
//!
//! Mechanism: `CREATE OR REPLACE FUNCTION` keeps the function oid, so the
//! operators / aggregates that reference it keep resolving to the (now
//! mutated) body — that's what lets us re-route a comparison or disable a
//! blocker without touching operator definitions. Each `#[sqlx::test]`
//! gets its own fresh database (EQL pre-installed via the auto-applied
//! `migrations/001_install_eql.sql`), so the mutation is discarded when the
//! per-test DB is dropped — no cleanup, no rebuild.
//!
//! Pattern per test: assert the baseline property holds, mutate, assert it
//! now breaks. The baseline assertion is load-bearing — it proves the
//! probe is non-vacuous before the mutation.

use anyhow::{ensure, Result};
use eql_tests::{
    assert_null, assert_raises, blocker_msg, fetch_fixture_payload, ScalarType, PLACEHOLDER_PAYLOAD,
};
use sqlx::PgPool;

/// Apply one DDL mutation to the installed schema.
async fn mutate(pool: &PgPool, ddl: &str) -> Result<()> {
    sqlx::query(ddl).execute(pool).await?;
    Ok(())
}

// 1. Storage `=` blocker — disabling it lets the storage variant compare
//    equal. Proves the `blocker` arm (and `typed_column_blocker`) would
//    catch a blocker that silently stopped raising.
#[sqlx::test]
async fn disabling_storage_eq_blocker_flips_blocker_arm(pool: PgPool) -> Result<()> {
    let sql = "SELECT $1::jsonb::public.eql_v3_integer = $2::jsonb::public.eql_v3_integer";

    // Baseline: the storage `=` blocker raises.
    assert_raises(
        &pool,
        sql,
        &[Some(PLACEHOLDER_PAYLOAD), Some(PLACEHOLDER_PAYLOAD)],
        &blocker_msg("public.eql_v3_integer", "="),
    )
    .await?;

    // Mutation: replace the plpgsql blocker with an inlinable SQL body that
    // returns true. CREATE OR REPLACE keeps the oid, so the `=` operator on
    // (public.eql_v3_integer, public.eql_v3_integer) now resolves to this no-raise body.
    mutate(
        &pool,
        "CREATE OR REPLACE FUNCTION eql_v3_internal.eq(a public.eql_v3_integer, b public.eql_v3_integer) \
         RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$ SELECT true $$",
    )
    .await?;

    // Post: the operator returns true instead of raising — arm has teeth.
    let result: Option<bool> = sqlx::query_scalar(sql)
        .bind(PLACEHOLDER_PAYLOAD)
        .bind(PLACEHOLDER_PAYLOAD)
        .fetch_one(&pool)
        .await?;
    ensure!(
        result == Some(true),
        "after disabling the storage `=` blocker, `=` must return true (got {result:?})"
    );
    Ok(())
}

// 2. Planner-metadata RESTRICT selectivity — unsetting it makes the
//    `planner_metadata` arm's `oprrest <> 0` check report false. (COMMUTATOR
//    cannot be unset via ALTER, so RESTRICT is the pragmatic teeth probe for
//    this arm.)
#[sqlx::test]
async fn unsetting_restrict_flips_planner_metadata_arm(pool: PgPool) -> Result<()> {
    async fn restrict_present(pool: &PgPool) -> Result<bool> {
        let present: bool = sqlx::query_scalar(
            r#"
            SELECT o.oprrest::oid <> 0
            FROM pg_catalog.pg_operator o
            JOIN pg_catalog.pg_type lt ON lt.oid = o.oprleft
            JOIN pg_catalog.pg_type rt ON rt.oid = o.oprright
            WHERE o.oprname = '='
              AND lt.typname = 'eql_v3_integer_ord'
              AND rt.typname = 'eql_v3_integer_ord'
            "#,
        )
        .fetch_one(pool)
        .await?;
        Ok(present)
    }

    // Baseline: `=` on (ord, ord) declares a RESTRICT estimator.
    ensure!(
        restrict_present(&pool).await?,
        "baseline: `=` on public.eql_v3_integer_ord must declare a RESTRICT estimator"
    );

    // Mutation: unset RESTRICT. DROP OPERATOR would hit COMMUTATOR/NEGATOR
    // dependency links; ALTER ... SET (RESTRICT = NONE) avoids that.
    mutate(
        &pool,
        "ALTER OPERATOR = (public.eql_v3_integer_ord, public.eql_v3_integer_ord) SET (RESTRICT = NONE)",
    )
    .await?;

    // Post: the planner-metadata check now reports false — arm has teeth.
    ensure!(
        !restrict_present(&pool).await?,
        "after SET (RESTRICT = NONE), the planner-metadata check must report false"
    );
    Ok(())
}

// 3. `_ord` equality must route through its ordering term — `ord_term`
//    (`op`) since the default flipped to CLLW-OPE — never HMAC.
//    Rerouting it through `hmac_256` (`hm`) over hm-stripped rows makes `=`
//    stop matching. Proves the `ord_routes_through_*` arm has teeth.
#[sqlx::test(fixtures(path = "../../../fixtures", scripts("eql_v3_integer")))]
async fn rerouting_ord_eq_through_hm_flips_ord_routes_arm(pool: PgPool) -> Result<()> {
    // Strip `hm` per-row inline; the `_ord` CHECK only requires `op`, so the
    // cast still succeeds. The pivot is likewise hm-stripped.
    let pivot: i32 = 42;
    let pivot_payload: String = sqlx::query_scalar(&format!(
        "SELECT (payload - 'hm')::text FROM fixtures.eql_v3_integer WHERE plaintext = {pivot}",
    ))
    .fetch_one(&pool)
    .await?;

    let count_sql = "SELECT count(*) FROM fixtures.eql_v3_integer \
                     WHERE (payload - 'hm')::public.eql_v3_integer_ord = $1::jsonb::public.eql_v3_integer_ord";

    // Baseline: with `hm` stripped, `=` still matches the pivot via
    // `ord_term` (the `op` term survives) — exactly one row.
    let baseline: i64 = sqlx::query_scalar(count_sql)
        .bind(&pivot_payload)
        .fetch_one(&pool)
        .await?;
    ensure!(
        baseline == 1,
        "baseline: `_ord` `=` must match exactly the pivot via op with hm stripped (got {baseline})"
    );

    // Mutation: reroute `_ord` `=` through HMAC. `eql_v3_internal.hmac_256(jsonb)` is
    // STRICT and the `hm` key is absent, so it yields NULL and `=` matches
    // nothing.
    mutate(
        &pool,
        "CREATE OR REPLACE FUNCTION eql_v3.eq(a public.eql_v3_integer_ord, b public.eql_v3_integer_ord) \
         RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE \
         AS $$ SELECT eql_v3_internal.hmac_256(a::jsonb) = eql_v3_internal.hmac_256(b::jsonb) $$",
    )
    .await?;

    // Post: routing through the absent `hm` matches zero rows — arm has teeth.
    let mutated: i64 = sqlx::query_scalar(count_sql)
        .bind(&pivot_payload)
        .fetch_one(&pool)
        .await?;
    ensure!(
        mutated == 0,
        "after rerouting `_ord` `=` through hm, it must match zero hm-stripped rows (got {mutated})"
    );
    Ok(())
}

// 4. Supported `=` on `_eq` is STRICT — it must propagate NULL. Dropping
//    STRICT (and returning non-NULL) makes `x = NULL` return a value. Proves
//    the `supported_null` arm has teeth.
#[sqlx::test]
async fn dropping_strict_on_eq_flips_supported_null_arm(pool: PgPool) -> Result<()> {
    let sql = "SELECT $1::jsonb::public.eql_v3_integer_eq = $2::jsonb::public.eql_v3_integer_eq";

    // Baseline: STRICT `=` propagates NULL when one side is NULL.
    assert_null(&pool, sql, &[Some(PLACEHOLDER_PAYLOAD), None]).await?;

    // Mutation: drop STRICT and return a constant non-NULL. CREATE OR REPLACE
    // keeps the oid; the operator now ignores NULL semantics.
    mutate(
        &pool,
        "CREATE OR REPLACE FUNCTION eql_v3.eq(a public.eql_v3_integer_eq, b public.eql_v3_integer_eq) \
         RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$ SELECT true $$",
    )
    .await?;

    // Post: `x = NULL` returns true instead of NULL — arm has teeth.
    let result: Option<bool> = sqlx::query_scalar(sql)
        .bind(PLACEHOLDER_PAYLOAD)
        .bind(Option::<&str>::None)
        .fetch_one(&pool)
        .await?;
    ensure!(
        result == Some(true),
        "after dropping STRICT on `_eq` `=`, `x = NULL` must return true, not NULL (got {result:?})"
    );
    Ok(())
}

// 5. Ord `<` correctness routes through `eql_v3.lt`. Turning `lt` into a
//    blocker makes `<` raise — proving the ord `<` correctness arm has teeth.
//    Crucially, ORDER BY routes through `ord_term`, NOT `<`, so it must stay
//    green here. This is the #5-vs-#7 split: #5 attacks `<`, #7 attacks the
//    sort key. Blocking `<` alone must not disturb ORDER BY.
#[sqlx::test(fixtures(path = "../../../fixtures", scripts("eql_v3_integer")))]
async fn blocking_lt_flips_lt_arm_but_not_order_by(pool: PgPool) -> Result<()> {
    let lt_sql =
        "SELECT $1::jsonb::public.eql_v3_integer_ord < $2::jsonb::public.eql_v3_integer_ord";
    let order_by_sql = "SELECT plaintext FROM fixtures.eql_v3_integer \
                        ORDER BY eql_v3.ord_term(payload::public.eql_v3_integer_ord) ASC";

    let mut ascending: Vec<i32> = <i32 as ScalarType>::fixture_values().to_vec();
    ascending.sort();

    // Baseline: `<` works (no raise) and ORDER BY is plaintext-sorted. Uses two
    // REAL fixture ORE payloads (smallest two plaintexts), not PLACEHOLDER_PAYLOAD
    // — the latter carries a 1-byte `ob` stub that the N-block comparator's
    // well-formedness guard now (correctly) rejects. PLACEHOLDER stays in the
    // post-mutation `assert_raises` below, where the `lt` blocker raises before
    // the comparator ever inspects the term.
    let lt_baseline: Option<bool> = sqlx::query_scalar(
        "SELECT (SELECT payload FROM fixtures.eql_v3_integer WHERE plaintext = $1)::public.eql_v3_integer_ord \
              < (SELECT payload FROM fixtures.eql_v3_integer WHERE plaintext = $2)::public.eql_v3_integer_ord",
    )
    .bind(ascending[0])
    .bind(ascending[1])
    .fetch_one(&pool)
    .await?;
    ensure!(
        lt_baseline == Some(true),
        "baseline: smaller `_ord` `<` larger must be true (got {lt_baseline:?})"
    );
    let order_baseline: Vec<i32> = sqlx::query_scalar(order_by_sql).fetch_all(&pool).await?;
    ensure!(
        order_baseline == ascending,
        "baseline: ORDER BY ord_term ASC must be plaintext-sorted"
    );

    // Mutation: turn `eql_v3.lt(_ord, _ord)` into a blocker. Must be
    // LANGUAGE plpgsql and non-STRICT so the RAISE always fires.
    mutate(
        &pool,
        "CREATE OR REPLACE FUNCTION eql_v3.lt(a public.eql_v3_integer_ord, b public.eql_v3_integer_ord) \
         RETURNS boolean LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE \
         AS $$ BEGIN RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_integer_ord', '<'); END; $$",
    )
    .await?;

    // Post: `<` now raises — the ord `<` arm has teeth.
    assert_raises(
        &pool,
        lt_sql,
        &[Some(PLACEHOLDER_PAYLOAD), Some(PLACEHOLDER_PAYLOAD)],
        &blocker_msg("public.eql_v3_integer_ord", "<"),
    )
    .await?;

    // Post: ORDER BY is UNCHANGED — it routes through ord_term, not `<`.
    // This is the whole point of separating #5 from #7.
    let order_after: Vec<i32> = sqlx::query_scalar(order_by_sql).fetch_all(&pool).await?;
    ensure!(
        order_after == ascending,
        "blocking `<` must NOT disturb ORDER BY (it routes through ord_term); got {order_after:?}"
    );
    Ok(())
}

// 6. `_eq` equality must route through `eq_term` (`hm`), never ORE — the
//    mirror of #3 for the eq path. Rerouting it through
//    `ore_block_256` (`ob`) over ob-stripped rows breaks equality.
//
//    Two notes on why this is shaped differently from the plan's literal
//    "returns 0 where forward expects 1":
//    - The fixture payloads carry BOTH `hm` and `ob`, so rerouting `_eq`
//      `=` through ORE on the RAW fixture would still match (both terms are
//      injective per plaintext) — vacuous. Stripping `ob` forces the
//      rerouted operator onto an absent term, exactly as #3 strips `hm`.
//    - `ore_block_256(jsonb)` RAISES on an absent `ob` ("Expected an
//      ore index (ob)"), whereas `hmac_256(jsonb)` returns NULL on an absent
//      `hm`. So the eq path breaks via a raise, not a 0-count. Either way the
//      correct hm-routed equality matches and the rerouted one does not.
#[sqlx::test(fixtures(path = "../../../fixtures", scripts("eql_v3_integer")))]
async fn rerouting_eq_eq_through_ob_flips_eq_arm(pool: PgPool) -> Result<()> {
    // Strip `ob` per-row inline; the `_eq` CHECK only requires `hm`, so the
    // cast still succeeds. The pivot is likewise ob-stripped.
    let pivot: i32 = 42;
    let pivot_payload: String = sqlx::query_scalar(&format!(
        "SELECT (payload - 'ob')::text FROM fixtures.eql_v3_integer WHERE plaintext = {pivot}",
    ))
    .fetch_one(&pool)
    .await?;

    let count_sql = "SELECT count(*) FROM fixtures.eql_v3_integer \
                     WHERE (payload - 'ob')::public.eql_v3_integer_eq = $1::jsonb::public.eql_v3_integer_eq";

    // Baseline: with `ob` stripped, `=` still matches the pivot via `eq_term`
    // (the `hm` term survives) — exactly one row.
    let baseline: i64 = sqlx::query_scalar(count_sql)
        .bind(&pivot_payload)
        .fetch_one(&pool)
        .await?;
    ensure!(
        baseline == 1,
        "baseline: `_eq` `=` must match exactly the pivot via hm with ob stripped (got {baseline})"
    );

    // Mutation: reroute `_eq` `=` through ORE. The `ob` key is absent, so
    // `eql_v3_internal.ore_block_256(jsonb)` raises rather than matching.
    mutate(
        &pool,
        "CREATE OR REPLACE FUNCTION eql_v3.eq(a public.eql_v3_integer_eq, b public.eql_v3_integer_eq) \
         RETURNS boolean LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE \
         AS $$ SELECT eql_v3_internal.ore_block_256(a::jsonb) = eql_v3_internal.ore_block_256(b::jsonb) $$",
    )
    .await?;

    // Post: routing through the absent `ob` raises ("Expected an ore index")
    // instead of matching the pivot — equality is broken, arm has teeth.
    let err = sqlx::query_scalar::<_, i64>(count_sql)
        .bind(&pivot_payload)
        .fetch_one(&pool)
        .await
        .expect_err("rerouting `_eq` `=` through the absent ob term must fail")
        .to_string();
    ensure!(
        err.contains("Expected an ore index"),
        "rerouted `_eq` `=` must fail on the absent ob term; got: {err}"
    );
    Ok(())
}

// 7. ORDER BY routes through `ord_term` — the sort key, NOT `<` (see #5).
//    Collapsing `ord_term` to a constant makes ORDER BY DESC no longer
//    plaintext-sorted. Proves the ORDER BY arm has teeth independently of the
//    `<` arm.
//
//    A constant key collapses ASC and DESC to the same heap order. The
//    fixture inserts rows in ascending plaintext (id 1..n), so a seq scan
//    returns ascending order — which can never equal the descending
//    expectation. Asserting against DESC therefore detects the collapse
//    regardless of heap order (the ascending-fixture caveat from the plan).
#[sqlx::test(fixtures(path = "../../../fixtures", scripts("eql_v3_integer")))]
async fn collapsing_ord_term_flips_order_by_arm(pool: PgPool) -> Result<()> {
    let order_by_desc = "SELECT plaintext FROM fixtures.eql_v3_integer \
                         ORDER BY eql_v3.ord_term(payload::public.eql_v3_integer_ord) DESC";

    let mut descending: Vec<i32> = <i32 as ScalarType>::fixture_values().to_vec();
    descending.sort();
    descending.reverse();

    // Baseline: ORDER BY ord_term DESC is plaintext-descending.
    let baseline: Vec<i32> = sqlx::query_scalar(order_by_desc).fetch_all(&pool).await?;
    ensure!(
        baseline == descending,
        "baseline: ORDER BY ord_term DESC must be plaintext-descending"
    );

    // Mutation: collapse ord_term to a constant OPE term. Use a REAL fixture
    // payload as the source (guaranteed to carry a valid `op`) and a
    // unique dollar-quote tag so the embedded jsonb literal can't break the
    // function body.
    let const_payload = fetch_fixture_payload::<i32>(&pool, 0).await?;
    let ddl = format!(
        "CREATE OR REPLACE FUNCTION eql_v3.ord_term(a public.eql_v3_integer_ord) \
         RETURNS eql_v3_internal.ope_cllw LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE \
         AS $mutbody$ SELECT eql_v3_internal.ope_cllw('{esc}'::jsonb) $mutbody$",
        esc = const_payload.replace('\'', "''"),
    );
    mutate(&pool, &ddl).await?;

    // Post: every row now sorts equal, so DESC collapses to heap (ascending)
    // order and can no longer equal the descending expectation — arm has teeth.
    let mutated: Vec<i32> = sqlx::query_scalar(order_by_desc).fetch_all(&pool).await?;
    ensure!(
        mutated != descending,
        "after collapsing ord_term to a constant, ORDER BY DESC must no longer be \
         plaintext-descending (got {mutated:?})"
    );
    Ok(())
}

// 8. ORDER BY NULLS placement depends on `ord_term` being STRICT: a NULL domain
//    value yields a NULL sort key, so `NULLS LAST` parks those rows at the tail.
//    Dropping STRICT (coalescing a NULL input to a real payload) gives NULL-valued
//    rows a concrete sort key, so they stop clustering at the end. Proves the
//    ORDER BY NULLS arm has teeth on the NULL-placement dimension — one #5 (block
//    `lt`) and #7 (collapse `ord_term`) do not exercise, since both run on the
//    NULL-free fixture. A UNION ALL subquery supplies the NULL rows inline, so no
//    session-local temp table is needed and the global `mutate()` stays valid.
#[sqlx::test(fixtures(path = "../../../fixtures", scripts("eql_v3_integer")))]
async fn making_ord_term_non_strict_flips_order_by_nulls_arm(pool: PgPool) -> Result<()> {
    const NULL_ROWS: usize = 3;
    let order_by = format!(
        "SELECT plaintext FROM ( \
           SELECT plaintext, payload::public.eql_v3_integer_ord AS value FROM fixtures.eql_v3_integer \
           UNION ALL \
           SELECT NULL::integer, NULL::public.eql_v3_integer_ord FROM generate_series(1, {NULL_ROWS}) \
         ) s \
         ORDER BY eql_v3.ord_term(value) ASC NULLS LAST"
    );

    let tail_all_none =
        |rows: &[Option<i32>]| rows.iter().rev().take(NULL_ROWS).all(|x| x.is_none());

    // Baseline: STRICT ord_term -> NULL value -> NULL sort key -> NULLS LAST
    // parks the NULL-valued rows at the tail.
    let baseline: Vec<Option<i32>> = sqlx::query_scalar(&order_by).fetch_all(&pool).await?;
    ensure!(
        tail_all_none(&baseline),
        "baseline: the {NULL_ROWS} NULL-valued rows must cluster at the tail under \
         NULLS LAST (got {baseline:?})"
    );

    // Mutation: drop STRICT and coalesce a NULL input to a REAL fixture payload,
    // so NULL-valued rows gain a concrete (non-NULL) sort key; non-NULL rows are
    // unchanged. Unique dollar-quote tag guards the embedded jsonb literal.
    let const_payload = fetch_fixture_payload::<i32>(&pool, 0).await?;
    let ddl = format!(
        "CREATE OR REPLACE FUNCTION eql_v3.ord_term(a public.eql_v3_integer_ord) \
         RETURNS eql_v3_internal.ope_cllw LANGUAGE sql IMMUTABLE PARALLEL SAFE \
         AS $mutbody$ SELECT eql_v3_internal.ope_cllw(\
         coalesce(a, '{esc}'::jsonb::public.eql_v3_integer_ord)::jsonb) $mutbody$",
        esc = const_payload.replace('\'', "''"),
    );
    mutate(&pool, &ddl).await?;

    // Post: NULL-valued rows now carry a concrete key, so they no longer park at
    // the tail — the NULLS arm catches the lost STRICT contract.
    let mutated: Vec<Option<i32>> = sqlx::query_scalar(&order_by).fetch_all(&pool).await?;
    ensure!(
        !tail_all_none(&mutated),
        "after dropping STRICT on ord_term, the NULL-valued rows must no longer \
         cluster at the tail (got {mutated:?})"
    );
    Ok(())
}
