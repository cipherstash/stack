//! Behavioural gates for the `eql_v3.grouped_value(jsonb)` aggregate
//! (src/v3/aggregates.sql).
//!
//! `grouped_value` re-creates the eql_v2 aggregate on the eql_v3 surface. Its
//! purpose is to let a query project an encrypted column while grouping by that
//! column's equality term: `GROUP BY eql_v3.eq_term(col)` groups encrypted rows
//! by equality, but PostgreSQL then rejects a bare `SELECT col` because it
//! cannot prove the column is constant within each group. Wrapping the column in
//! `grouped_value` returns one representative value per group and satisfies the
//! GROUP BY rule.
//!
//! `grouped_value` returns its input unchanged — it never inspects, decrypts, or
//! compares the value — so it has nothing to do with encryption, and plain
//! `jsonb` literals fully exercise it. These tests pin its semantics:
//!
//!   * `first_non_null_per_group` — with an explicit intra-aggregate ORDER BY the
//!     result is the first non-null value; NULLs are skipped.
//!   * `all_null_group_is_null` — a group of only NULLs aggregates to NULL.
//!   * `bare_encrypted_column_projection_is_rejected` — the motivating failure:
//!     `SELECT col ... GROUP BY <expr on col>` raises grouping_error (42803).
//!   * `grouped_value_makes_group_by_term_projection_valid` — the fix: the same
//!     shape with `grouped_value(col)` succeeds and returns a representative
//!     member of each group.
//!   * `distinct_on_eq_term_is_the_non_aggregate_alternative` — the `DISTINCT`
//!     counterpart: `DISTINCT ON (eql_v3.eq_term(col))` deduplicates without an
//!     aggregate, so `grouped_value` is not involved there.

use anyhow::Result;
use sqlx::{PgPool, Row};

/// A NULL then two non-null values: with an intra-aggregate ORDER BY the
/// aggregate resolves to the first non-null value and skips the NULL.
#[sqlx::test]
async fn first_non_null_per_group(pool: PgPool) -> Result<()> {
    let got: Option<serde_json::Value> = sqlx::query_scalar(
        r#"
        SELECT eql_v3.grouped_value(v ORDER BY v)
        FROM (VALUES (NULL::jsonb), ('"a"'::jsonb), ('"b"'::jsonb)) AS t(v)
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(got, Some(serde_json::json!("a")));
    Ok(())
}

/// A group made entirely of SQL NULLs has no non-null value to represent it, so
/// the aggregate returns NULL (the STRICT state function is never seeded).
#[sqlx::test]
async fn all_null_group_is_null(pool: PgPool) -> Result<()> {
    let got: Option<serde_json::Value> = sqlx::query_scalar(
        r#"
        SELECT eql_v3.grouped_value(v)
        FROM (VALUES (NULL::jsonb), (NULL::jsonb)) AS t(v)
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(got, None);
    Ok(())
}

/// The motivating failure `grouped_value` exists to fix: grouping by an
/// expression over an (encrypted) column and then projecting the bare column
/// raises grouping_error (SQLSTATE 42803) — "column must appear in the GROUP BY
/// clause or be used in an aggregate function".
#[sqlx::test]
async fn bare_encrypted_column_projection_is_rejected(pool: PgPool) -> Result<()> {
    let err = sqlx::query(
        r#"
        SELECT payload
        FROM (VALUES ('{"t":"A"}'::jsonb), ('{"t":"A"}'::jsonb)) AS t(payload)
        GROUP BY (payload -> 't')
        "#,
    )
    .execute(&pool)
    .await
    .expect_err("bare column projection under GROUP BY on an expression must fail");

    let code = err
        .as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.into_owned());
    assert_eq!(
        code.as_deref(),
        Some("42803"),
        "expected grouping_error (42803), got: {err}"
    );
    Ok(())
}

/// The fix: wrapping the column in `grouped_value` makes the same
/// group-by-an-expression-over-the-column query valid. Each group's
/// representative value is a genuine member of that group — here, one whose `t`
/// field equals the group key.
#[sqlx::test]
async fn grouped_value_makes_group_by_term_projection_valid(pool: PgPool) -> Result<()> {
    // Two groups keyed by `payload -> 't'`: "A" (2 rows) and "B" (1 row).
    let rows = sqlx::query(
        r#"
        SELECT eql_v3.grouped_value(payload) AS rep, count(*) AS n
        FROM (VALUES
          ('{"t":"A","c":"a1"}'::jsonb),
          ('{"t":"A","c":"a2"}'::jsonb),
          ('{"t":"B","c":"b1"}'::jsonb)
        ) AS t(payload)
        GROUP BY (payload -> 't')
        ORDER BY (payload -> 't')
        "#,
    )
    .fetch_all(&pool)
    .await?;

    assert_eq!(rows.len(), 2, "expected two groups");

    let counts: Vec<i64> = rows.iter().map(|r| r.get::<i64, _>("n")).collect();
    assert_eq!(counts, vec![2, 1], "group row counts (A then B)");

    // Each representative is non-null and belongs to its group: its `t` matches
    // the group key ("A" for the first group, "B" for the second).
    for (row, expected_t) in rows.iter().zip(["A", "B"]) {
        let rep: serde_json::Value = row.get("rep");
        assert_eq!(
            rep.get("t").and_then(|v| v.as_str()),
            Some(expected_t),
            "representative must be a member of its group"
        );
        assert!(
            rep.get("c").and_then(|v| v.as_str()).is_some(),
            "representative is a whole row payload, unchanged"
        );
    }
    Ok(())
}

/// The `DISTINCT` counterpart, for the question "is DISTINCT the same
/// mechanism?": it is related but NOT the same. `DISTINCT ON` / `DISTINCT` have
/// no projection restriction — you can select the column directly — so
/// `grouped_value` is neither needed nor involved here. To deduplicate encrypted
/// values you still key on the equality term (`eql_v3.eq_term`), never the raw
/// ciphertext, because encryption is non-deterministic. This pins the recommended
/// no-aggregate dedup shape.
#[sqlx::test]
async fn distinct_on_eq_term_is_the_non_aggregate_alternative(pool: PgPool) -> Result<()> {
    // Same data as the GROUP BY test: two groups keyed by `payload -> 't'`.
    // DISTINCT ON projects the bare column with no aggregate and no grouping
    // error, returning one representative row per group.
    let reps: Vec<serde_json::Value> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT ON (payload -> 't') payload
        FROM (VALUES
          ('{"t":"A","c":"a1"}'::jsonb),
          ('{"t":"A","c":"a2"}'::jsonb),
          ('{"t":"B","c":"b1"}'::jsonb)
        ) AS t(payload)
        ORDER BY (payload -> 't')
        "#,
    )
    .fetch_all(&pool)
    .await?;

    let group_keys: Vec<Option<&str>> = reps
        .iter()
        .map(|p| p.get("t").and_then(|v| v.as_str()))
        .collect();
    assert_eq!(
        group_keys,
        vec![Some("A"), Some("B")],
        "DISTINCT ON (term) yields one representative row per group, column projected directly"
    );
    Ok(())
}
