//!  conformance: a term-only query operand (`eql_v3.query_<name>` — the
//! index terms only, NO ciphertext `c`) matches stored rows through the
//! generated query operators, using FRESH ZeroKMS encryption for both the
//! stored values AND the query value.
//!
//! This is the end-to-end proof the operator surface exists for: two
//! INDEPENDENT encryptions of the same plaintext produce equal index terms that
//! the `(storage_domain, query_<name>)` operator equates — with the query
//! operand carrying no decryptable ciphertext. Gated behind `proptest-e2e`
//! (needs `CS_*` creds at test time), like the rest of the fresh-encryption
//! suite.
#![cfg(feature = "proptest-e2e")]

use anyhow::Result;
use eql_tests::fixtures::cipherstash::encrypt_store;
use eql_tests::fixtures::index_kind::IndexKind;
use serde_json::Value;
use sqlx::PgPool;

/// Drop the ciphertext `c` from a stored v3 payload, yielding the term-only
/// query operand a client sends (structurally what `from_v2_query` produces).
fn to_query_operand(mut stored: Value) -> Value {
    stored
        .as_object_mut()
        .expect("a v3 payload is a JSON object")
        .remove("c");
    stored
}

/// One fresh ZeroKMS encryption of a single value, returned as its v3 payload.
async fn encrypt_one(value: i32, indexes: &[IndexKind]) -> Result<Value> {
    let mut payloads = encrypt_store("qtest", "payload", &[value], indexes).await?;
    Ok(payloads.pop().expect("one value in, one payload out"))
}

#[sqlx::test]
async fn eq_term_only_operand_matches_exactly_the_equal_rows(pool: PgPool) -> Result<()> {
    // Store 10, 20, 30, 20 (a deliberate duplicate 20) as `integer_eq`.
    let stored = encrypt_store(
        "qtest",
        "payload",
        &[10i32, 20, 30, 20],
        &[IndexKind::Unique],
    )
    .await?;
    sqlx::query(
        "CREATE TABLE q (id int GENERATED ALWAYS AS IDENTITY, val public.eql_v3_integer_eq)",
    )
    .execute(&pool)
    .await?;
    for p in &stored {
        sqlx::query("INSERT INTO q (val) VALUES ($1::jsonb::public.eql_v3_integer_eq)")
            .bind(p.to_string())
            .execute(&pool)
            .await?;
    }

    // INDEPENDENTLY encrypt the query value 20 → term-only operand (no `c`).
    let operand = to_query_operand(encrypt_one(20, &[IndexKind::Unique]).await?);
    assert!(
        !operand.as_object().unwrap().contains_key("c"),
        "the query operand must carry no ciphertext"
    );

    let matches: i64 =
        sqlx::query_scalar("SELECT count(*) FROM q WHERE val = $1::jsonb::eql_v3.query_integer_eq")
            .bind(operand.to_string())
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        matches, 2,
        "a term-only operand for 20 matches exactly the two stored 20s"
    );

    // A value never stored matches nothing (the eq-false branch).
    let absent = to_query_operand(encrypt_one(99, &[IndexKind::Unique]).await?);
    let none: i64 =
        sqlx::query_scalar("SELECT count(*) FROM q WHERE val = $1::jsonb::eql_v3.query_integer_eq")
            .bind(absent.to_string())
            .fetch_one(&pool)
            .await?;
    assert_eq!(none, 0, "a value never stored matches no rows");
    Ok(())
}

#[sqlx::test]
async fn ord_term_only_operand_orders_via_the_ope_operator(pool: PgPool) -> Result<()> {
    // Store 10, 20, 30 as `integer_ord`, whose ordering SEM is CLLW-OPE: the
    // domain CHECK requires the `op` term, so an `ob`-bearing (block-ORE)
    // payload is rejected. `_ord_ore` is the block-ORE surface.
    let stored = encrypt_store("qtest", "payload", &[10i32, 20, 30], &[IndexKind::Ope]).await?;
    sqlx::query(
        "CREATE TABLE q (id int GENERATED ALWAYS AS IDENTITY, val public.eql_v3_integer_ord)",
    )
    .execute(&pool)
    .await?;
    for p in &stored {
        sqlx::query("INSERT INTO q (val) VALUES ($1::jsonb::public.eql_v3_integer_ord)")
            .bind(p.to_string())
            .execute(&pool)
            .await?;
    }

    // A term-only ordering operand for 25 (never stored): `< 25` → {10, 20}.
    let operand = to_query_operand(encrypt_one(25, &[IndexKind::Ope]).await?);
    let below: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM q WHERE val < $1::jsonb::eql_v3.query_integer_ord",
    )
    .bind(operand.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(below, 2, "`< 25` matches the two rows below 25 (10, 20)");

    // The commutator direction resolves too: `operand > val`.
    let above: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM q WHERE $1::jsonb::eql_v3.query_integer_ord > val",
    )
    .bind(operand.to_string())
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        above, 2,
        "`25 > val` resolves the commutator and matches 10, 20"
    );
    Ok(())
}

#[sqlx::test]
async fn query_domain_rejects_a_ciphertext_bearing_operand(pool: PgPool) -> Result<()> {
    // The no-`c` CHECK is the security contract: a full storage payload (with
    // `c`) must not be accepted as a query operand.
    let stored = encrypt_one(7, &[IndexKind::Unique]).await?;
    assert!(stored.as_object().unwrap().contains_key("c"));
    let err = sqlx::query("SELECT $1::jsonb::eql_v3.query_integer_eq")
        .bind(stored.to_string())
        .execute(&pool)
        .await
        .expect_err("a ciphertext-bearing operand must violate the query-domain CHECK");
    assert!(
        err.to_string().contains("violates check constraint"),
        "expected a CHECK violation, got: {err}"
    );
    Ok(())
}
