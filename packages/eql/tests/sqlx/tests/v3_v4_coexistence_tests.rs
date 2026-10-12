//! EQL v3 and v4 installed side by side in one database (ADR-0002).
//!
//! The two bundles are the same SQL under two names: `eql_v3` for terms written
//! by cipherstash-client, `eql_v4` for terms written by Stack Encrypt. These
//! tests pin what the separate names do and do not enforce when both are
//! installed:
//!
//! - both install without clashing, and each owns its own domains;
//! - a payload of the wrong version fails the domain CHECK on insert;
//! - the function form across versions (`eql_v3.eq(v3col, v4term)`) is
//!   ambiguous, so it errors;
//! - the operator form across versions (`v3col = v4term`) does NOT error.
//!   With no operator defined for the exact pair, Postgres treats both domains
//!   as `jsonb` and uses the built-in `jsonb = jsonb`, which returns no rows.
//!   That is pinned here so it cannot change unnoticed. ADR-0002 defers the
//!   cross-version blocker operators that would make it an error; when they
//!   land, those assertions flip to expecting one.
//!
//! The payloads are real cipherstash-client ciphertexts from the
//! `eql_v3_integer` fixture. A v4 payload is the same row with its envelope
//! version set to 4: the two bundles share their SQL, so only the version
//! decides which domain admits it.

use anyhow::Result;
use sqlx::PgPool;

const V4_INSTALLER: &str = "../../release/cipherstash-encrypt-v4.sql";

/// SQLSTATE `check_violation`.
const CHECK_VIOLATION: &str = "23514";
/// SQLSTATE `ambiguous_function`.
const AMBIGUOUS_FUNCTION: &str = "42725";

/// Install the v4 bundle into a test database that the migrations have
/// already given v3.
async fn install_v4(pool: &PgPool) -> Result<()> {
    let sql = std::fs::read_to_string(V4_INSTALLER).unwrap_or_else(|e| {
        panic!(
            "failed to read {V4_INSTALLER}: {e} — run `mise run build` \
             (or, in CI, ensure the nextest-archive artifact shipped release/*.sql)"
        )
    });
    sqlx::raw_sql(&sql).execute(pool).await?;
    Ok(())
}

/// One `integer_eq` column per version, each holding the fixture row for 42,
/// written as that version's payload.
async fn tables_with_one_row(pool: &PgPool) -> Result<()> {
    sqlx::raw_sql(
        "CREATE TABLE t3 (c public.eql_v3_integer_eq);
         CREATE TABLE t4 (c public.eql_v4_integer_eq);
         INSERT INTO t3 SELECT payload::public.eql_v3_integer_eq
           FROM fixtures.eql_v3_integer WHERE plaintext = 42;
         INSERT INTO t4 SELECT jsonb_set(payload, '{v}', '4')::public.eql_v4_integer_eq
           FROM fixtures.eql_v3_integer WHERE plaintext = 42;",
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// The term-only query operand for 42 (no ciphertext `c`), as `version`.
fn query_term(version: u8) -> String {
    format!(
        "(SELECT jsonb_set(payload - 'c', '{{v}}', '{version}') \
         FROM fixtures.eql_v3_integer WHERE plaintext = 42)::eql_v{version}.query_integer_eq"
    )
}

fn sqlstate(err: &sqlx::Error) -> Option<String> {
    match err {
        sqlx::Error::Database(e) => e.code().map(|c| c.into_owned()),
        _ => None,
    }
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn v3_and_v4_install_side_by_side(pool: PgPool) -> Result<()> {
    install_v4(&pool).await?;

    let schemas: Vec<String> = sqlx::query_scalar(
        "SELECT nspname::text FROM pg_namespace WHERE nspname LIKE 'eql\\_v_%' ORDER BY 1",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        schemas,
        ["eql_v3", "eql_v3_internal", "eql_v4", "eql_v4_internal"]
    );

    let (v3, v4): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE typname LIKE 'eql\\_v3\\_%'),
                count(*) FILTER (WHERE typname LIKE 'eql\\_v4\\_%')
         FROM pg_type WHERE typnamespace = 'public'::regnamespace AND typtype = 'd'",
    )
    .fetch_one(&pool)
    .await?;
    assert!(v3 > 0, "v3 installed no public domains");
    assert_eq!(v3, v4, "each version owns the same set of public domains");

    let (a, b): (String, String) = sqlx::query_as("SELECT eql_v3.version(), eql_v4.version()")
        .fetch_one(&pool)
        .await?;
    assert_eq!(a, b, "both bundles come from one build");
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn each_version_matches_its_own_terms(pool: PgPool) -> Result<()> {
    install_v4(&pool).await?;
    tables_with_one_row(&pool).await?;

    for (table, version) in [("t3", 3), ("t4", 4)] {
        let n: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM {table} WHERE c = {}",
            query_term(version)
        ))
        .fetch_one(&pool)
        .await?;
        assert_eq!(n, 1, "{table} = its own version's term must match");
    }
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn wrong_version_insert_fails_the_domain_check(pool: PgPool) -> Result<()> {
    install_v4(&pool).await?;

    for (domain, version) in [
        ("public.eql_v3_integer_eq", 4),
        ("public.eql_v4_integer_eq", 3),
    ] {
        let err = sqlx::query(&format!(
            "SELECT jsonb_set(payload, '{{v}}', '{version}')::{domain} \
             FROM fixtures.eql_v3_integer WHERE plaintext = 42"
        ))
        .execute(&pool)
        .await
        .expect_err("a payload of the other version must not fit the domain");
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some(CHECK_VIOLATION),
            "a version-{version} payload cast to {domain}: {err}"
        );
    }
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn function_form_across_versions_is_ambiguous(pool: PgPool) -> Result<()> {
    install_v4(&pool).await?;
    tables_with_one_row(&pool).await?;

    for (table, function, term) in [("t3", "eql_v3.eq", 4), ("t4", "eql_v4.eq", 3)] {
        let err = sqlx::query(&format!(
            "SELECT count(*) FROM {table} WHERE {function}(c, {})",
            query_term(term)
        ))
        .execute(&pool)
        .await
        .expect_err("a cross-version function call must not resolve");
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some(AMBIGUOUS_FUNCTION),
            "{function}({table}.c, v{term} term): {err}"
        );
    }
    Ok(())
}

/// Pins a known gap: see the module docs. When cross-version blocker operators
/// exist, these comparisons raise instead, and this test changes with them.
#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn operator_across_versions_returns_no_rows(pool: PgPool) -> Result<()> {
    install_v4(&pool).await?;
    tables_with_one_row(&pool).await?;

    for (table, term) in [("t3", 4), ("t4", 3)] {
        let n: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM {table} WHERE c = {}",
            query_term(term)
        ))
        .fetch_one(&pool)
        .await?;
        assert_eq!(n, 0, "{table}.c = v{term} term runs, and finds nothing");

        // Why: no EQL operator takes this pair, so the planner chose the
        // built-in jsonb equality on the two domains' base type.
        let plan: Vec<String> = sqlx::query_scalar(&format!(
            "EXPLAIN (COSTS OFF) SELECT * FROM {table} WHERE c = {}",
            query_term(term)
        ))
        .fetch_all(&pool)
        .await?;
        let plan = plan.join("\n");
        assert!(
            plan.contains("(c)::jsonb = "),
            "{table}.c = v{term} term should fall back to jsonb = jsonb:\n{plan}"
        );
    }

    let joined: i64 = sqlx::query_scalar("SELECT count(*) FROM t3 JOIN t4 ON t3.c = t4.c")
        .fetch_one(&pool)
        .await?;
    assert_eq!(joined, 0, "a v3 column joined to a v4 column finds nothing");
    Ok(())
}
