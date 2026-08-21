//! EQL lint runtime tests
//!
//! These tests run `eql_v3.lints()` against the installed EQL surface and
//! assert on the shape of the result.
//!
//! The lint is intentionally noisy on the current state of EQL — every
//! plpgsql / VOLATILE / SET-clause-bearing operator implementation is
//! reported. The tests here validate that the lint *runs* and that its
//! schema is sensible. A separate stacked PR (#193, the Phase 1 operator
//! inlining work) reduces the violation count, and at that point a
//! tighter test asserting `count = 0` for specific operators becomes
//! appropriate.

use anyhow::Result;
use eql_tests::Variant;
use sqlx::PgPool;

/// Pg-type tokens for the encrypted-scalar-domain families currently
/// materialised. Extending the family (e.g. when `bigint`/`bool`/`date`
/// land) is a one-line array extension here — every downstream
/// parameterised test picks it up automatically.
const SCALAR_PG_TYPES: &[&str] = &["integer", "smallint"];

#[derive(Debug, sqlx::FromRow)]
struct LintRow {
    severity: String,
    category: String,
    object_name: String,
    #[allow(dead_code)]
    message: String,
}

async fn fetch_lints(pool: &PgPool) -> Result<Vec<LintRow>> {
    let rows = sqlx::query_as::<_, LintRow>(
        "SELECT severity, category, object_name, message FROM eql_v3.lints() ORDER BY category, object_name",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

#[sqlx::test]
async fn lint_function_exists_and_row_schema_parses(pool: PgPool) -> Result<()> {
    // Schema-only check: `eql_v3.lints()` exists and its rows decode into
    // `LintRow`. Previous incarnation asserted `!rows.is_empty()` and so
    // would fail on a *cleaner* build (e.g. when Phase 1+ removes the
    // current noisy violations), reading like a regression for a good
    // reason. The rule-specific tests below pin actual behaviour.
    let _rows = fetch_lints(&pool).await?;
    Ok(())
}

/// `eql_v3_internal.owned_schemas()` is the single source of truth every
/// `eql_v3.lints()` schema-scoped CTE (and `tasks/pin_search_path_v3.sql`)
/// joins against instead of repeating the `('eql_v3', 'eql_v3_internal')`
/// literal at each call site. Pin its exact contract: an edit that adds,
/// drops, or typos an entry silently narrows or widens every lint/pin scope
/// at once, so this failing loudly here is cheaper than tracing a missed
/// violation back to a one-character array typo.
#[sqlx::test]
async fn owned_schemas_returns_exactly_the_two_v3_schemas(pool: PgPool) -> Result<()> {
    let schemas: Vec<String> =
        sqlx::query_scalar("SELECT unnest(eql_v3_internal.owned_schemas())::text ORDER BY 1")
            .fetch_all(&pool)
            .await?;
    assert_eq!(
        schemas,
        vec!["eql_v3".to_string(), "eql_v3_internal".to_string()],
        "eql_v3_internal.owned_schemas() must return exactly {{eql_v3, eql_v3_internal}}"
    );
    Ok(())
}

#[sqlx::test]
async fn lint_severity_values_are_well_known(pool: PgPool) -> Result<()> {
    let rows = fetch_lints(&pool).await?;
    for row in rows {
        assert!(
            matches!(row.severity.as_str(), "error" | "warning" | "info"),
            "Unexpected severity {:?} for {} ({})",
            row.severity,
            row.object_name,
            row.category
        );
    }
    Ok(())
}

#[sqlx::test]
async fn lint_categories_are_well_known(pool: PgPool) -> Result<()> {
    let rows = fetch_lints(&pool).await?;
    let allowed = [
        "inlinability_language",
        "inlinability_volatility",
        "inlinability_set_clause",
        "inlinability_secdef",
        "inlinability_transitive",
        "blocker_language",
        "blocker_strict",
        "domain_over_domain",
        "domain_opclass",
        "schema_placement",
    ];
    for row in rows {
        assert!(
            allowed.contains(&row.category.as_str()),
            "Unexpected lint category {:?} for {}",
            row.category,
            row.object_name
        );
    }
    Ok(())
}

/// A blocker rendered in `LANGUAGE sql` instead of `plpgsql` is the
/// inverse of the extractor/wrapper inlinability rule: a blocker's job is
/// to RAISE, and `LANGUAGE sql` bodies are inlinable — which means the
/// planner can fold or elide the call when the result is provably unused
/// (a dead CASE branch, a folded predicate), silently bypassing the RAISE
/// and re-enabling the operator. See CLAUDE.md footguns. This test plants
/// a fake LANGUAGE sql blocker on `public.eql_v3_integer` and asserts the lint
/// surfaces it under category `blocker_language`.
#[sqlx::test]
async fn lint_flags_blocker_in_language_sql(pool: PgPool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE FUNCTION eql_v3.test_bad_blocker_sql(a public.eql_v3_integer, b public.eql_v3_integer)
        RETURNS boolean LANGUAGE sql IMMUTABLE
        AS $$ SELECT eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_integer', '=') $$;
        "#,
    )
    .execute(&pool)
    .await?;

    let rows = fetch_lints(&pool).await?;
    let violations: Vec<&LintRow> = rows
        .iter()
        .filter(|r| {
            r.category == "blocker_language" && r.object_name.contains("test_bad_blocker_sql")
        })
        .collect();

    assert!(
        !violations.is_empty(),
        "Expected `blocker_language` to flag the LANGUAGE sql fake blocker, \
         but got no matching row. All lint rows:\n{:#?}",
        rows
    );
    assert_eq!(
        violations[0].severity, "error",
        "blocker_language must be severity=error"
    );
    Ok(())
}

/// A blocker marked `STRICT` lets PostgreSQL skip the body and return NULL
/// on a NULL argument — silently bypassing the "operator not supported"
/// RAISE. See CLAUDE.md footguns. This test plants a fake STRICT plpgsql
/// blocker on `public.eql_v3_integer` and asserts the lint surfaces it under
/// `blocker_strict`.
#[sqlx::test]
async fn lint_flags_strict_blocker(pool: PgPool) -> Result<()> {
    sqlx::query(
        r#"
        CREATE FUNCTION eql_v3.test_bad_blocker_strict(a public.eql_v3_integer, b public.eql_v3_integer)
        RETURNS boolean LANGUAGE plpgsql IMMUTABLE STRICT
        AS $$ BEGIN RETURN eql_v3_internal.encrypted_domain_unsupported_bool('public.eql_v3_integer', '='); END; $$;
        "#,
    )
    .execute(&pool)
    .await?;

    let rows = fetch_lints(&pool).await?;
    let violations: Vec<&LintRow> = rows
        .iter()
        .filter(|r| {
            r.category == "blocker_strict" && r.object_name.contains("test_bad_blocker_strict")
        })
        .collect();

    assert!(
        !violations.is_empty(),
        "Expected `blocker_strict` to flag the STRICT fake blocker, \
         but got no matching row. All lint rows:\n{:#?}",
        rows
    );
    assert_eq!(
        violations[0].severity, "error",
        "blocker_strict must be severity=error"
    );
    Ok(())
}

/// Generated encrypted-domain blockers intentionally use non-inlinable
/// plpgsql functions. They should be checked by the blocker-specific lint
/// rules, not reported as normal operator inlinability failures.
#[sqlx::test]
async fn lint_does_not_report_generated_blockers_as_inlinability_errors(
    pool: PgPool,
) -> Result<()> {
    let rows = fetch_lints(&pool).await?;
    let violations: Vec<&LintRow> = rows
        .iter()
        .filter(|r| {
            matches!(
                r.category.as_str(),
                "inlinability_language"
                    | "inlinability_volatility"
                    | "inlinability_set_clause"
                    | "inlinability_secdef"
            ) && r.object_name.contains("public.eql_v3_integer")
                && (r.object_name.contains("operator =(")
                    || r.object_name.contains("operator ->(")
                    || r.object_name.contains("operator ?("))
        })
        .collect();

    assert!(
        violations.is_empty(),
        "generated encrypted-domain blockers must not be reported by direct \
         inlinability rules; got: {violations:#?}"
    );
    Ok(())
}

/// An `eql_v3` domain whose base type is another `eql_v3` encrypted domain
/// (not jsonb) silently bypasses the storage variant's blockers: operators
/// resolve against the ultimate base type, so a derived domain does not
/// inherit the base domain's operator surface. See CLAUDE.md footguns.
/// This test plants a domain-over-domain offender and asserts the lint
/// surfaces it under `domain_over_domain`.
#[sqlx::test]
async fn lint_flags_domain_over_domain(pool: PgPool) -> Result<()> {
    sqlx::query(r#"CREATE DOMAIN eql_v3.test_baddom AS public.eql_v3_integer;"#)
        .execute(&pool)
        .await?;

    let rows = fetch_lints(&pool).await?;
    let violations: Vec<&LintRow> = rows
        .iter()
        .filter(|r| r.category == "domain_over_domain" && r.object_name.contains("test_baddom"))
        .collect();

    assert!(
        !violations.is_empty(),
        "Expected `domain_over_domain` to flag the derived domain, \
         but got no matching row. All lint rows:\n{:#?}",
        rows
    );
    assert_eq!(
        violations[0].severity, "error",
        "domain_over_domain must be severity=error"
    );
    Ok(())
}

/// An operator class declared `FOR TYPE` on an `eql_v3` domain bypasses
/// the operator-resolution that the storage blockers depend on. The
/// recommended pattern is a functional index on the extractor; opclasses
/// on domains must never appear. See CLAUDE.md footguns. The current
/// build emits zero opclasses on `eql_v3` domains, so this test is
/// negative: it asserts the rule category is well-known and surfaces no
/// rows. A positive test would require constructing a valid opclass on a
/// domain, which is non-trivial scaffolding — the `domain_opclass`
/// structural guard in `tests/encrypted_domain/family/inlinability.rs` is the
/// independent net for regressions.
#[sqlx::test]
async fn lint_domain_opclass_surface_is_clean(pool: PgPool) -> Result<()> {
    let rows = fetch_lints(&pool).await?;
    let violations: Vec<&LintRow> = rows
        .iter()
        .filter(|r| r.category == "domain_opclass")
        .collect();
    assert!(
        violations.is_empty(),
        "domain_opclass surface should be empty in a clean build, got: {:#?}",
        violations
    );
    Ok(())
}

/// The public `eql_v3` schema must hold only jsonb-backed encrypted-domain
/// types; a naked composite/enum type there is an internal index-term type in
/// the wrong schema (Table-Builder-picker clutter the split exists to prevent).
/// A clean build has none, so this is negative: `schema_placement` surfaces no
/// rows. The independent net is the placement invariant in
/// `tests/v3_public_surface_tests.rs`.
#[sqlx::test]
async fn lint_schema_placement_surface_is_clean(pool: PgPool) -> Result<()> {
    let rows = fetch_lints(&pool).await?;
    let violations: Vec<&LintRow> = rows
        .iter()
        .filter(|r| r.category == "schema_placement")
        .collect();
    assert!(
        violations.is_empty(),
        "schema_placement surface should be empty in a clean build, got: {:#?}",
        violations
    );
    Ok(())
}

/// Planting a naked composite type in the public `eql_v3` schema must be flagged
/// under `schema_placement` — the exact regression (an internal index-term type
/// created in the public schema) the split exists to prevent.
#[sqlx::test]
async fn lint_flags_composite_type_in_eql_v3(pool: PgPool) -> Result<()> {
    sqlx::query(r#"CREATE TYPE eql_v3.test_bad_placement AS (x integer);"#)
        .execute(&pool)
        .await?;

    let rows = fetch_lints(&pool).await?;
    let violations: Vec<&LintRow> = rows
        .iter()
        .filter(|r| {
            r.category == "schema_placement" && r.object_name.contains("test_bad_placement")
        })
        .collect();

    assert!(
        !violations.is_empty(),
        "Expected `schema_placement` to flag the composite type in eql_v3, \
         but got no matching row. All lint rows:\n{:#?}",
        rows
    );
    assert_eq!(
        violations[0].severity, "error",
        "schema_placement must be severity=error"
    );
    Ok(())
}

/// Every encrypted-scalar-domain family's inlinable operator surface
/// must report zero lint violations. The supported operators on the
/// `_eq`, `_ord`, and `_ord_ore` variants are codegen-emitted SQL
/// wrappers (LANGUAGE sql, IMMUTABLE, no pinned `search_path`); the
/// planner can fold them into the documented functional indexes. A
/// regression to plpgsql or a pinned `search_path` breaks index
/// engagement.
///
/// Storage-only variants (the bare `eql_v3.<T>` domain with no
/// capability suffix) are intentionally excluded — every operator on
/// them is a non-STRICT plpgsql blocker, which doesn't need to be
/// inlinable.
///
/// Discovers the eligible operator set from `pg_operator` rather than
/// hardcoding the integer inventory — when `bigint` (or `bool`, `date`, ...)
/// lands, this test picks it up automatically with no edit. The earlier
/// hardcoded list was a copy-paste hazard.
#[sqlx::test]
async fn scalar_family_inlinable_operators_are_clean(pool: PgPool) -> Result<()> {
    // Build the inline-critical signature set Rust-side from
    // `SCALAR_PG_TYPES × Variant::ALL × supported-operators`. Eq-only
    // variants declare `<`/`<=`/`>`/`>=` as blockers (intentionally
    // non-inlinable), so they must NOT be expected to be clean here —
    // only the ops the variant actually supports as wrappers count.
    //
    // Storage variants contribute no inline-critical surface; their
    // entire operator set is blockers by design.
    let mut prefixes: Vec<String> = Vec::new();
    for pg_type in SCALAR_PG_TYPES {
        for variant in Variant::ALL {
            if matches!(variant, Variant::Storage) {
                continue;
            }
            // Not every scalar declares every variant (only `text` declares
            // `_search`); skip variants this scalar does not carry.
            if !variant.is_declared_for(pg_type) {
                continue;
            }
            let domain = format!("eql_v3.{pg_type}{}", variant.suffix());
            let supported_ops: &[&str] = if variant.supports_ord(pg_type) {
                &["=", "<>", "<", "<=", ">", ">="]
            } else {
                // Eq variants support equality only; ordering ops on `_eq`
                // are blockers.
                &["=", "<>"]
            };
            for op in supported_ops {
                // Domain-on-left and jsonb-on-left arg shapes both
                // need to be inlinable; the domain-on-right shape is
                // the `(jsonb, domain)` operator.
                prefixes.push(format!("operator {op}({domain},"));
                prefixes.push(format!("operator {op}(jsonb, {domain})"));
            }
        }
    }

    let rows = fetch_lints(&pool).await?;
    let violations: Vec<&LintRow> = rows
        .iter()
        .filter(|row| prefixes.iter().any(|p| row.object_name.starts_with(p)))
        .collect();

    assert!(
        violations.is_empty(),
        "scalar-family inline-critical operators should report zero \
         lint violations, but got: {violations:#?}"
    );
    Ok(())
}
