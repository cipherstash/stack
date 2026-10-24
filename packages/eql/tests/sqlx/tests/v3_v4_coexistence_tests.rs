//! EQL v3 and v4 installed side by side in one database (ADR-0002).
//!
//! The two bundles are the same SQL under two names: `eql_v3` for terms written
//! by cipherstash-client, `eql_v4` for terms written by Stack Encrypt, plus the
//! files confined to v4 with `-- ONLY EQL VERSION: 4` (the JSON tree family).
//! These tests pin what the separate names do and do not enforce when both are
//! installed:
//!
//! - both install without clashing, each owns its own domains (v4 every one
//!   of v3's and the v4-only ones besides), and each version's `lints()`
//!   stays clean with the other installed;
//! - a payload of the wrong version fails the domain CHECK on insert;
//! - the function form across versions (`eql_v3.eq(v3col, v4term)`) is
//!   ambiguous, so it errors, and so is `OPERATOR(public.=)` between a v3 and
//!   a v4 column;
//! - the operator form across versions (`v3col = v4term`) does NOT error.
//!   With no operator defined for the exact pair, Postgres treats both domains
//!   as `jsonb` and uses the built-in `jsonb = jsonb`, which returns no rows.
//!   That is pinned here so it cannot change unnoticed. ADR-0002 defers the
//!   cross-version blocker operators that would make it an error; when they
//!   land, those assertions flip to expecting one.
//! - `eql_v3.eq_term(v3col) = eql_v4.eq_term(v4col)` does not error either: it
//!   compares two text terms.
//!
//! The payloads are real cipherstash-client ciphertexts from the
//! `eql_v3_integer` fixture. A v4 payload is the same row with its envelope
//! version set to 4: the two bundles share their SQL, so only the version
//! decides which domain admits it.

use std::collections::BTreeSet;

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

/// Which equality `{table}.c = <v{term} query term>` binds, read from the
/// catalog rather than from EXPLAIN text, whose deparse can change between
/// Postgres majors. The comparison is stored as a view: a user-defined operator
/// it binds is recorded in `pg_depend`, and a built-in one, which is pinned and
/// so has no dependency row, is the `opno` in the view's stored query tree.
/// Returns the EQL (non-built-in) operators bound, and whether `jsonb = jsonb`
/// is.
async fn bound_equality(pool: &PgPool, table: &str, term: u8) -> Result<(Vec<String>, bool)> {
    let term_json: String =
        sqlx::query_scalar(&format!("SELECT ({})::jsonb::text", query_term(term)))
            .fetch_one(pool)
            .await?;
    let view = format!("{table}_v{term}_probe");
    sqlx::raw_sql(&format!(
        "CREATE OR REPLACE VIEW {view} AS SELECT * FROM {table} \
         WHERE c = '{}'::eql_v{term}.query_integer_eq",
        term_json.replace('\'', "''")
    ))
    .execute(pool)
    .await?;
    let eql_operators: Vec<String> = sqlx::query_scalar(
        "SELECT d.refobjid::regoperator::text
           FROM pg_depend d
           JOIN pg_rewrite r ON r.oid = d.objid
          WHERE d.classid = 'pg_rewrite'::regclass
            AND d.refclassid = 'pg_operator'::regclass
            AND r.ev_class = $1::regclass
          ORDER BY 1",
    )
    .bind(&view)
    .fetch_all(pool)
    .await?;
    let jsonb_eq: bool = sqlx::query_scalar(
        "SELECT ev_action::text ~ (':opno ' || '=(jsonb,jsonb)'::regoperator::oid || ' ')
           FROM pg_rewrite
          WHERE ev_class = $1::regclass",
    )
    .bind(&view)
    .fetch_one(pool)
    .await?;
    Ok((eql_operators, jsonb_eq))
}

fn sqlstate(err: &sqlx::Error) -> Option<String> {
    match err {
        sqlx::Error::Database(e) => e.code().map(|c| c.into_owned()),
        _ => None,
    }
}

/// The public domains each version owns, by name: `eql_v3_*` and `eql_v4_*`.
async fn public_domains(pool: &PgPool) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT typname::text FROM pg_type
          WHERE typnamespace = 'public'::regnamespace AND typtype = 'd'
            AND (typname LIKE 'eql\\_v3\\_%' OR typname LIKE 'eql\\_v4\\_%')
          ORDER BY 1",
    )
    .fetch_all(pool)
    .await?;
    let (v3, v4): (BTreeSet<String>, BTreeSet<String>) = names
        .into_iter()
        .partition(|name| name.starts_with("eql_v3_"));
    Ok((v3, v4))
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

    // Every public domain v3 owns, v4 owns under its own prefix. v4 also
    // owns the domains of the files confined to it with `-- ONLY EQL
    // VERSION: 4` (`tasks/build.sh`): today the JSON tree family, which Stack
    // Encrypt writes and cipherstash-client does not. Those are the only
    // domains v4 may have that v3 lacks, and v3 may own nothing v4 lacks.
    let (v3, v4) = public_domains(&pool).await?;
    assert!(!v3.is_empty(), "v3 installed no public domains");
    let to_v3 = |name: &String| name.replacen("eql_v4_", "eql_v3_", 1);
    let missing_from_v4: Vec<&str> = v3
        .iter()
        .filter(|name| !v4.iter().any(|v4_name| to_v3(v4_name) == **name))
        .map(String::as_str)
        .collect();
    assert!(
        missing_from_v4.is_empty(),
        "v3 owns public domains v4 does not: {missing_from_v4:?}"
    );
    let v4_only: Vec<&str> = v4
        .iter()
        .filter(|name| !v3.contains(&to_v3(name)))
        .map(String::as_str)
        .collect();
    assert_eq!(
        v4_only,
        ["eql_v4_json_tree", "eql_v4_json_tree_entry"],
        "the only public domains v4 owns and v3 does not are the JSON tree family"
    );

    let (a, b): (String, String) = sqlx::query_as("SELECT eql_v3.version(), eql_v4.version()")
        .fetch_one(&pool)
        .await?;
    assert_eq!(a, b, "both bundles come from one build");

    // Each lint judges only its own version's public domains. Before that was
    // scoped, each version reported thousands of errors about the other's
    // blocker operators.
    for schema in ["eql_v3", "eql_v4"] {
        let errors: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT category || ': ' || object_name FROM {schema}.lints() \
             WHERE severity = 'error' ORDER BY 1 LIMIT 5"
        ))
        .fetch_all(&pool)
        .await?;
        assert!(
            errors.is_empty(),
            "{schema}.lints() reports errors with both versions installed: {errors:#?}"
        );
    }
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

        // Why: no EQL operator takes this pair, so the parser bound the
        // built-in jsonb equality on the two domains' base type.
        let (eql_operators, jsonb_eq) = bound_equality(&pool, table, term).await?;
        assert!(
            eql_operators.is_empty(),
            "{table}.c = v{term} term should bind no EQL operator, got {eql_operators:?}"
        );
        assert!(
            jsonb_eq,
            "{table}.c = v{term} term should fall back to jsonb = jsonb"
        );
    }

    // Control: the same-version comparison binds the EQL operator, so the
    // empty list above is a finding, not a probe that sees nothing.
    for (table, version) in [("t3", 3), ("t4", 4)] {
        let (eql_operators, jsonb_eq) = bound_equality(&pool, table, version).await?;
        assert_eq!(
            eql_operators,
            [format!(
                "=(eql_v{version}_integer_eq,eql_v{version}.query_integer_eq)"
            )],
            "{table}.c = v{version} term"
        );
        assert!(
            !jsonb_eq,
            "{table}.c = v{version} term does not use jsonb = jsonb"
        );
    }

    let joined: i64 = sqlx::query_scalar("SELECT count(*) FROM t3 JOIN t4 ON t3.c = t4.c")
        .fetch_one(&pool)
        .await?;
    assert_eq!(joined, 0, "a v3 column joined to a v4 column finds nothing");
    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn qualified_operator_across_versions_is_ambiguous(pool: PgPool) -> Result<()> {
    install_v4(&pool).await?;
    tables_with_one_row(&pool).await?;

    let err = sqlx::query("SELECT count(*) FROM t3 JOIN t4 ON t3.c OPERATOR(public.=) t4.c")
        .execute(&pool)
        .await
        .expect_err("OPERATOR(public.=) between a v3 and a v4 column must not resolve");
    assert_eq!(
        sqlstate(&err).as_deref(),
        Some(AMBIGUOUS_FUNCTION),
        "t3.c OPERATOR(public.=) t4.c: {err}"
    );
    Ok(())
}

/// Pins a second silent path: see the module docs. The terms are text, so
/// comparing them across versions is ordinary text equality. The fixture's v4
/// row reuses the v3 row's terms, so here it even matches; with real Stack
/// Encrypt terms it finds nothing. Either way nothing refuses it.
#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn eq_term_across_versions_compares_text(pool: PgPool) -> Result<()> {
    install_v4(&pool).await?;
    tables_with_one_row(&pool).await?;

    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM t3 JOIN t4 ON eql_v3.eq_term(t3.c) = eql_v4.eq_term(t4.c)",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        n, 1,
        "the cross-version term comparison runs as text equality"
    );
    Ok(())
}

/// SQLSTATE `invalid_parameter_value`.
const INVALID_PARAMETER_VALUE: &str = "22023";

/// A text search query operand of `version` built from the first fixture row
/// whose filter is not empty, minus the ciphertext, the block ORE term and
/// the keys in `drop`.
fn search_operand(version: u8, drop: &[&str]) -> String {
    let mut operand = format!(
        "jsonb_set((SELECT payload - 'c' - 'ob' FROM fixtures.eql_v3_text \
         WHERE jsonb_array_length(payload -> 'bf') > 0 ORDER BY id LIMIT 1), '{{v}}', '{version}')"
    );
    for key in drop {
        operand = format!("({operand} - '{key}')");
    }
    format!("({operand})::eql_v{version}.query_text_search")
}

/// The two versions part on the text search query operand (ADR-0002,
/// amended 2026-10-19). v3's is cipherstash-client's and needs `hm`, `op`
/// and `bf`. v4's needs any one of them, since Stack Encrypt sends only the
/// term its operator reads, and each v4 operator refuses an operand without
/// its term instead of comparing a NULL and matching no row.
#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_text")))]
async fn a_v4_search_query_needs_one_term_and_a_v3_one_needs_all(pool: PgPool) -> Result<()> {
    install_v4(&pool).await?;

    let one_term: [&[&str]; 3] = [&["op", "bf"], &["hm", "bf"], &["hm", "op"]];
    sqlx::query(&format!("SELECT {}", search_operand(3, &[])))
        .execute(&pool)
        .await?;
    for drop in one_term {
        let err = sqlx::query(&format!("SELECT {}", search_operand(3, drop)))
            .execute(&pool)
            .await
            .expect_err("a v3 search query needs every term");
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some(CHECK_VIOLATION),
            "v3 without {drop:?}: {err}"
        );
    }
    for drop in std::iter::once(&[][..]).chain(one_term) {
        sqlx::query(&format!("SELECT {}", search_operand(4, drop)))
            .execute(&pool)
            .await
            .unwrap_or_else(|e| panic!("v4 without {drop:?}: {e}"));
    }
    let err = sqlx::query(&format!(
        "SELECT {}",
        search_operand(4, &["hm", "op", "bf"])
    ))
    .execute(&pool)
    .await
    .expect_err("a v4 search query needs a term");
    assert_eq!(sqlstate(&err).as_deref(), Some(CHECK_VIOLATION), "{err}");

    sqlx::raw_sql(
        "CREATE TABLE t4s (c public.eql_v4_text_search);
         INSERT INTO t4s SELECT jsonb_set(payload - 'ob', '{v}', '4')::public.eql_v4_text_search
           FROM fixtures.eql_v3_text WHERE jsonb_array_length(payload -> 'bf') > 0;",
    )
    .execute(&pool)
    .await?;
    for (op, term, rest) in [
        ("=", "hm", ["op", "bf"]),
        ("<=", "op", ["hm", "bf"]),
        ("@@", "bf", ["hm", "op"]),
    ] {
        // With its term, the operator answers: the operand's own row.
        let n: i64 = sqlx::query_scalar(&format!(
            "SELECT count(*) FROM t4s WHERE c {op} {}",
            search_operand(4, &rest)
        ))
        .fetch_one(&pool)
        .await?;
        assert!(n >= 1, "c {op} with only {term} finds its own row");
        // Without it, the operator refuses, naming the term.
        let err = sqlx::query(&format!(
            "SELECT count(*) FROM t4s WHERE c {op} {}",
            search_operand(4, &[term])
        ))
        .execute(&pool)
        .await
        .expect_err("an operator refuses an operand without its term");
        assert_eq!(
            sqlstate(&err).as_deref(),
            Some(INVALID_PARAMETER_VALUE),
            "c {op} without {term}: {err}"
        );
        assert!(
            err.to_string().contains(&format!(
                "eql_v4.query_text_search value has no \"{term}\" term"
            )),
            "c {op} without {term}: {err}"
        );
    }
    Ok(())
}
