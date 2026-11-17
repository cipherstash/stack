//! A storage domain compared with ANOTHER domain's query twin must
//! raise, never fall through to native `jsonb <op> jsonb`.
//!
//! Every `public.eql_v3_<T>_<d>` and `eql_v3.query_<T>_<d>` is a domain over
//! `jsonb`, and PostgreSQL resolves an operator against the base type unless an
//! operator with the exact argument types exists. Before the cross-pair
//! blockers, `eql_v3_text_ord = $1::eql_v3.query_text_eq` therefore compared the
//! two envelopes as plain JSON and answered false for equal values, with no
//! error. This suite enumerates the pairs from the installed catalog (so a new
//! domain is covered the day it lands) and asserts each one is claimed by an
//! exact-signature blocker. Creds-free.

use anyhow::Result;
use sqlx::PgPool;

/// `(storage, query_twin)` for every term-bearing domain: the pairs that are
/// MEANT to compare. Derived from the catalog: a query twin is
/// `eql_v3.query_<name>` for storage domain `public.eql_v3_<name>`.
async fn twins(pool: &PgPool) -> Result<Vec<(String, String)>> {
    Ok(sqlx::query_as(
        r#"SELECT 'public.eql_v3_' || substr(q.typname, 7), 'eql_v3.' || q.typname
           FROM pg_type q
           JOIN pg_namespace qn ON qn.oid = q.typnamespace AND qn.nspname = 'eql_v3'
           JOIN pg_type s ON s.typname = 'eql_v3_' || substr(q.typname, 7)
           JOIN pg_namespace sn ON sn.oid = s.typnamespace AND sn.nspname = 'public'
           WHERE q.typtype = 'd' AND q.typname LIKE 'query\_%'
             -- the SteVec query operand has no scalar storage twin of this shape
             AND q.typname <> 'query_json'
           ORDER BY 1"#,
    )
    .fetch_all(pool)
    .await?)
}

/// The family of a domain name: everything before the index suffix
/// (`text_ord_ope` → `text`).
fn family(storage: &str) -> &str {
    let name = storage.trim_start_matches("public.eql_v3_");
    name.split('_').next().expect("a domain name has a family")
}

/// Operators a storage domain SUPPORTS (a public `eql_v3` wrapper backs its
/// `(domain, domain)` overload, as opposed to an `eql_v3_internal` blocker).
async fn supported_ops(pool: &PgPool, storage: &str) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        r#"SELECT o.oprname
           FROM pg_operator o
           JOIN pg_proc p ON p.oid = o.oprcode
           JOIN pg_namespace pn ON pn.oid = p.pronamespace
           WHERE o.oprleft = $1::regtype AND o.oprright = $1::regtype
             AND pn.nspname = 'eql_v3'
             AND o.oprname IN ('=', '<>', '<', '<=', '>', '>=', '@@')
           ORDER BY 1"#,
    )
    .bind(storage)
    .fetch_all(pool)
    .await?)
}

/// Run `NULL::<left> <op> NULL::<right>` and return the error text, if any.
/// NULL operands are enough: a blocker raises unconditionally, while native
/// `jsonb <op> jsonb` (the silent fallback) returns NULL.
async fn probe(pool: &PgPool, left: &str, op: &str, right: &str) -> Option<String> {
    sqlx::query(&format!("SELECT NULL::{left} {op} NULL::{right}"))
        .fetch_all(pool)
        .await
        .err()
        .map(|e| e.to_string())
}

#[sqlx::test]
async fn every_same_family_cross_domain_pair_raises_in_both_directions(pool: PgPool) -> Result<()> {
    let twins = twins(&pool).await?;
    assert!(twins.len() > 20, "catalog enumeration found {twins:?}");

    let mut checked = 0;
    let mut leaks = Vec::new();
    for (storage, _) in &twins {
        let storage_ops = supported_ops(&pool, storage).await?;
        for (other, query) in &twins {
            if other == storage || family(other) != family(storage) {
                continue;
            }
            // `query` is the twin of `other`; pair it with `storage`.
            for op in supported_ops(&pool, other).await? {
                if !storage_ops.contains(&op) {
                    continue;
                }
                for (l, r) in [(storage, query), (query, storage)] {
                    checked += 1;
                    match probe(&pool, l, &op, r).await {
                        Some(e) if e.contains("use the query domain that matches the column") => {}
                        other => leaks.push(format!("{l} {op} {r}: {other:?}")),
                    }
                }
            }
        }
    }

    assert!(checked > 500, "only {checked} pairs checked");
    assert!(
        leaks.is_empty(),
        "{} of {checked} same-family cross-domain pairs did not raise:\n{}",
        leaks.len(),
        leaks.join("\n")
    );
    Ok(())
}

/// The reported cases (`@@` across families already errored: "operator is not
/// unique"), spelled out so a regression names the exact predicate.
#[sqlx::test]
async fn reported_mismatches_raise(pool: PgPool) -> Result<()> {
    for (l, op, r) in [
        ("public.eql_v3_text_ord", "=", "eql_v3.query_text_eq"),
        ("public.eql_v3_text_search", "=", "eql_v3.query_text_eq"),
        ("public.eql_v3_text_ord", "<", "eql_v3.query_text_ord_ope"),
        ("eql_v3.query_text_ord_ope", "<", "public.eql_v3_text_ord"),
    ] {
        let err = probe(&pool, l, op, r)
            .await
            .unwrap_or_else(|| panic!("{l} {op} {r} fell through to native jsonb"));
        assert!(err.contains("is not supported for"), "{l} {op} {r}: {err}");
    }
    Ok(())
}

/// Control: the matching twin is untouched — it still resolves to the wrapper.
#[sqlx::test]
async fn matching_twin_still_compares(pool: PgPool) -> Result<()> {
    for (l, op, r) in [
        ("public.eql_v3_text_eq", "=", "eql_v3.query_text_eq"),
        ("public.eql_v3_text_ord", "<", "eql_v3.query_text_ord"),
        ("public.eql_v3_text_match", "@@", "eql_v3.query_text_match"),
        (
            "public.eql_v3_integer_ord",
            ">=",
            "eql_v3.query_integer_ord",
        ),
    ] {
        assert_eq!(probe(&pool, l, op, r).await, None, "{l} {op} {r}");
    }
    Ok(())
}

/// The blockers are recognised as blockers by `eql_v3.lints()` (it matches their
/// message text), so none is reported as an inlinability or blocker-shape error.
/// Without the shared `is not supported for` marker every one of them is
/// misclassified as an ordinary operator wrapper that fails to inline.
#[sqlx::test]
async fn cross_pair_blockers_are_recognised_by_the_lints(pool: PgPool) -> Result<()> {
    let flagged: Vec<(String, String, String)> = sqlx::query_as(
        r#"SELECT severity, category, object_name FROM eql_v3.lints()
           WHERE severity = 'error'
             AND object_name LIKE 'operator %'
             AND object_name LIKE '%query\_%'"#,
    )
    .fetch_all(&pool)
    .await?;
    assert!(
        flagged.is_empty(),
        "lint errors on query-twin operators: {flagged:?}"
    );

    let blockers: i64 = sqlx::query_scalar(
        r#"SELECT count(*) FROM pg_proc p
           JOIN pg_namespace n ON n.oid = p.pronamespace AND n.nspname = 'eql_v3_internal'
           WHERE p.prosrc LIKE '%use the query domain that matches the column%'"#,
    )
    .fetch_one(&pool)
    .await?;
    assert!(
        blockers > 500,
        "only {blockers} cross-pair blockers installed"
    );
    Ok(())
}
