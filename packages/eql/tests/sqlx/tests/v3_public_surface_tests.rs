//! Public-surface gates for the `eql_v3` schema (the split's raison d'être).
//!
//! `eql_v3` is the public API; `eql_v3_internal` holds implementation detail
//! (SEM index-term types, wrappers/blockers/state functions, the jsonb engine).
//! The split exists to keep index-term-only TYPES out of what a Supabase Studio
//! Table Builder user sees. Nothing else in the suite pins *what lives in
//! `eql_v3`*, so a new internal object accidentally created in the public schema
//! would ship unnoticed. These tests close that gap two ways:
//!
//!   * `eql_v3_public_surface_matches_golden` — an exhaustive committed snapshot
//!     of every EQL-owned function, aggregate, operator, and cast. Any
//!     addition/removal/rename forces a conscious
//!     snapshot update, mirroring the `snapshots/matrix_tests.txt` gate.
//!   * The placement invariants — structural rules (no naked composite/enum
//!     types in the public schema; every user-column type is a public
//!     jsonb-backed domain; SEM index-term types stay internal) that are cheaper
//!     to reason about than the golden and independent of a frozen text file.
//!
//! The golden is regenerated in place with `EQL_UPDATE_SNAPSHOTS=1` (see
//! `mise run test:surface:snapshot:regen`); the file lives next to the matrix
//! snapshots under `tests/sqlx/snapshots/`.

use anyhow::Result;
use sqlx::PgPool;

/// The committed golden snapshot, embedded at compile time. Embedding (not
/// runtime `std::fs`) is required because CI compiles the test binary on one
/// runner (`cargo nextest archive`) and executes it on another, where the
/// build-machine `CARGO_MANIFEST_DIR` path no longer exists — the same reason
/// fixtures are `include_str!`'d in this suite.
const GOLDEN: &str = include_str!("../snapshots/eql_v3_public_surface.txt");

/// Filesystem path to the golden, used ONLY by the local regen path
/// (`EQL_UPDATE_SNAPSHOTS=1`), which always runs on the build machine where this
/// compile-time path is valid.
const GOLDEN_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/snapshots/eql_v3_public_surface.txt"
);

/// Enumerates every EQL-owned public function, aggregate, operator, and cast as
/// normalized, schema-qualified text lines. Run on a connection with
/// `search_path = pg_catalog` so `regtype`/identity-argument rendering
/// fully-qualifies non-catalog schemas (`eql_v3.*`, `public.*`) and leaves
/// built-ins (`jsonb`) bare — deterministic across environments and PG
/// versions.
const SURFACE_SQL: &str = r#"
    SELECT format('%s %s.%s(%s)',
      CASE p.prokind
        WHEN 'a' THEN 'aggregate'
        WHEN 'w' THEN 'window'
        WHEN 'p' THEN 'procedure'
        ELSE 'function'
      END,
      n.nspname, p.proname,
      pg_catalog.pg_get_function_identity_arguments(p.oid))
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'eql_v3'

    UNION ALL

    SELECT format('operator %s.%s(%s,%s)',
      n.nspname, o.oprname, o.oprleft::regtype, o.oprright::regtype)
    FROM pg_catalog.pg_operator o
    JOIN pg_catalog.pg_namespace n ON n.oid = o.oprnamespace
    WHERE n.nspname = 'eql_v3'

    UNION ALL

    SELECT format('cast %s -> %s', c.castsource::regtype, c.casttarget::regtype)
    FROM pg_catalog.pg_cast c
    JOIN pg_catalog.pg_proc p ON p.oid = c.castfunc
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = 'eql_v3'
"#;

/// Fetch the sorted public-surface entry list.
async fn public_surface(pool: &PgPool) -> Result<Vec<String>> {
    let mut conn = pool.acquire().await?;
    sqlx::query("SET search_path = pg_catalog")
        .execute(&mut *conn)
        .await?;
    let mut entries: Vec<String> = sqlx::query_scalar(SURFACE_SQL)
        .fetch_all(&mut *conn)
        .await?;
    // Byte-order sort to match the `LC_ALL=C sort` convention used by the other
    // committed snapshots.
    entries.sort();
    Ok(entries)
}

/// User-column domain names, as they appear in SQL: scalar-family domains plus
/// the hand-written JSON/JSONB column domains. These MUST live in `public`
/// (never `eql_v3` or `eql_v3_internal`) so application tables using them
/// survive EQL schema uninstall. The query-operand domains are deliberately
/// NOT here — they are never column types and live in `eql_v3`;
/// see [`query_domain_names`].
fn user_domain_names() -> Vec<String> {
    // Installed typnames: the catalog join carrying the eql_v3_ version
    // prefix — resolved through the same DomainFamily::domain_name
    // the SQL surface is generated through.
    let mut names = Vec::new();
    for family in eql_domains::scalar_families() {
        for domain in family.domains {
            names.push(family.domain_name(domain));
        }
    }
    names.extend(
        ["eql_v3_json", "eql_v3_json_search", "eql_v3_json_entry"]
            .into_iter()
            .map(String::from),
    );
    names.sort();
    names
}

/// Query-operand domain names: the `query_<name>` twin of every term-bearing
/// scalar domain plus the jsonb containment needle. These MUST live in
/// `eql_v3` (never `public`) — a query operand is not a column type, so it
/// stays out of the column-type namespace and is uninstalled with the EQL
/// surface.
fn query_domain_names() -> Vec<String> {
    let mut names: Vec<String> = eql_domains::scalar_families()
        .flat_map(|f| {
            f.domains
                .iter()
                .filter(|d| !d.terms.is_empty())
                .map(move |d| d.query_name(f.name))
        })
        .collect();
    names.push("query_json".to_string());
    names.sort();
    names
}

/// #1 — Exhaustive golden snapshot of the `eql_v3` public surface.
#[sqlx::test]
async fn eql_v3_public_surface_matches_golden(pool: PgPool) -> Result<()> {
    let entries = public_surface(&pool).await?;
    let actual = format!("{}\n", entries.join("\n"));

    if std::env::var_os("EQL_UPDATE_SNAPSHOTS").is_some() {
        std::fs::write(GOLDEN_PATH, &actual)?;
        eprintln!(
            "wrote golden snapshot ({} entries): {GOLDEN_PATH}",
            entries.len()
        );
        return Ok(());
    }

    if actual != GOLDEN {
        let expected_lines: std::collections::BTreeSet<&str> = GOLDEN.lines().collect();
        let actual_lines: std::collections::BTreeSet<&str> = actual.lines().collect();
        let added: Vec<&str> = actual_lines.difference(&expected_lines).copied().collect();
        let removed: Vec<&str> = expected_lines.difference(&actual_lines).copied().collect();
        panic!(
            "eql_v3 public surface drifted from the committed golden.\n\
             Objects added to eql_v3 (not in golden):\n  {}\n\
             Objects removed from eql_v3 (still in golden):\n  {}\n\
             If this change is intentional, regenerate with \
             `EQL_UPDATE_SNAPSHOTS=1 mise run test:surface:snapshot:regen` and commit \
             {GOLDEN_PATH}.\n\
             If an object should be internal, create it in eql_v3_internal instead.",
            if added.is_empty() {
                "(none)".to_string()
            } else {
                added.join("\n  ")
            },
            if removed.is_empty() {
                "(none)".to_string()
            } else {
                removed.join("\n  ")
            },
        );
    }
    Ok(())
}

/// #2 — Placement invariant: `eql_v3` contains no naked composite or enum types.
/// Every SEM index-term composite (`ore_block_256_term`, …) belongs in
/// `eql_v3_internal`; a composite/enum in the public schema is exactly the
/// Table-Builder-picker clutter the split exists to prevent.
#[sqlx::test]
async fn eql_v3_has_no_naked_composite_or_enum_types(pool: PgPool) -> Result<()> {
    let offenders: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT format('%I (typtype=%s)', t.typname, t.typtype)
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = 'eql_v3'
          AND t.typtype IN ('c', 'e')
        ORDER BY 1
        "#,
    )
    .fetch_all(&pool)
    .await?;
    assert!(
        offenders.is_empty(),
        "eql_v3 must contain no naked composite/enum types — these belong in \
         eql_v3_internal so they stay out of the Supabase type picker. Found: {offenders:?}"
    );
    Ok(())
}

/// #2 — Placement invariant: every user-column domain is public and jsonb-backed.
/// These are application-column types, so they live in `public` instead of an
/// EQL-owned schema and are domains directly over `pg_catalog.jsonb`.
#[sqlx::test]
async fn user_column_domains_are_public_jsonb_domains(pool: PgPool) -> Result<()> {
    let installed: Vec<(String, String)> = sqlx::query_as(
        r#"
        SELECT t.typname::text, bt.typname::text
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        JOIN pg_catalog.pg_type bt ON bt.oid = t.typbasetype
        WHERE n.nspname = 'public'
          AND t.typtype = 'd'
          AND t.typname = ANY($1)
        ORDER BY t.typname
        "#,
    )
    .bind(user_domain_names())
    .fetch_all(&pool)
    .await?;

    let installed: std::collections::BTreeMap<String, String> = installed.into_iter().collect();
    let missing: Vec<String> = user_domain_names()
        .into_iter()
        .filter(|name| !installed.contains_key(name))
        .collect();
    assert!(
        missing.is_empty(),
        "user-column domain(s) missing from public: {missing:?}"
    );

    let non_jsonb: Vec<(String, String)> = installed
        .into_iter()
        .filter(|(_, base)| base != "jsonb")
        .collect();
    assert!(
        non_jsonb.is_empty(),
        "public user-column domains must be jsonb-backed domains: {non_jsonb:?}"
    );
    Ok(())
}

/// #2 — Placement invariant: user-column domains are absent from EQL-owned
/// schemas. `eql_v3` / `eql_v3_internal` can be uninstalled independently; a
/// user table column type must not depend on either schema.
#[sqlx::test]
async fn user_column_domains_absent_from_eql_owned_schemas(pool: PgPool) -> Result<()> {
    let offenders: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT format('%I.%I', n.nspname, t.typname)
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname IN ('eql_v3', 'eql_v3_internal')
          AND t.typtype = 'd'
          AND t.typname = ANY($1)
        ORDER BY 1
        "#,
    )
    .bind(user_domain_names())
    .fetch_all(&pool)
    .await?;
    assert!(
        offenders.is_empty(),
        "user-column domains must not exist in droppable EQL-owned schemas: {offenders:?}"
    );
    Ok(())
}

/// #2 — Placement invariant (mirror): every query-operand domain lives in
/// `eql_v3` as a jsonb-backed domain, and none leaks into `public`. A query
/// operand is never a column type, so it is versioned and uninstalled with
/// the EQL surface instead of sharing the column domains' `public` home.
/// The expected type set is derived from the encrypted-domain catalog.
#[sqlx::test]
async fn query_operand_domains_are_eql_v3_jsonb_domains(pool: PgPool) -> Result<()> {
    let installed: Vec<(String, String, String)> = sqlx::query_as(
        r#"
        SELECT n.nspname::text, t.typname::text, bt.typname::text
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        JOIN pg_catalog.pg_type bt ON bt.oid = t.typbasetype
        WHERE n.nspname IN ('public', 'eql_v3', 'eql_v3_internal')
          AND t.typtype = 'd'
          AND t.typname = ANY($1)
        ORDER BY t.typname
        "#,
    )
    .bind(query_domain_names())
    .fetch_all(&pool)
    .await?;

    let misplaced: Vec<String> = installed
        .iter()
        .filter(|(schema, _, _)| schema != "eql_v3")
        .map(|(schema, name, _)| format!("{schema}.{name}"))
        .collect();
    assert!(
        misplaced.is_empty(),
        "query-operand domains must live in eql_v3 only: {misplaced:?}"
    );

    let in_eql_v3: Vec<&String> = installed
        .iter()
        .filter(|(schema, _, _)| schema == "eql_v3")
        .map(|(_, name, _)| name)
        .collect();
    let missing: Vec<String> = query_domain_names()
        .into_iter()
        .filter(|name| !in_eql_v3.contains(&name))
        .collect();
    assert!(
        missing.is_empty(),
        "query-operand domain(s) missing from eql_v3: {missing:?}"
    );

    let non_jsonb: Vec<String> = installed
        .iter()
        .filter(|(_, _, base)| base != "jsonb")
        .map(|(_, name, base)| format!("{name} (base {base})"))
        .collect();
    assert!(
        non_jsonb.is_empty(),
        "eql_v3 query-operand domains must be jsonb-backed domains: {non_jsonb:?}"
    );
    Ok(())
}

/// #2 — Dependency invariant: public user-column domain CHECK constraints do not
/// depend on objects in droppable EQL-owned schemas. Otherwise an EQL uninstall
/// can still cascade into application table columns even when the domain type
/// itself lives in `public`.
#[sqlx::test]
async fn public_user_domain_constraints_do_not_depend_on_eql_owned_schemas(
    pool: PgPool,
) -> Result<()> {
    let textual_refs: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT format('%I.%I.%I: %s', tn.nspname, t.typname, c.conname,
                      pg_catalog.pg_get_constraintdef(c.oid))
        FROM pg_catalog.pg_constraint c
        JOIN pg_catalog.pg_type t ON t.oid = c.contypid
        JOIN pg_catalog.pg_namespace tn ON tn.oid = t.typnamespace
        WHERE tn.nspname = 'public'
          AND t.typtype = 'd'
          AND t.typname = ANY($1)
          AND pg_catalog.pg_get_constraintdef(c.oid) ~ '\m(eql_v3|eql_v3_internal)\.'
        ORDER BY 1
        "#,
    )
    .bind(user_domain_names())
    .fetch_all(&pool)
    .await?;
    assert!(
        textual_refs.is_empty(),
        "public user-domain CHECK constraint(s) reference EQL-owned schemas: {textual_refs:?}"
    );

    let dependency_refs: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT format('%I.%I.%I depends on function %I.%I(%s)',
                      tn.nspname, t.typname, c.conname,
                      pn.nspname, p.proname,
                      pg_catalog.pg_get_function_identity_arguments(p.oid))
        FROM pg_catalog.pg_constraint c
        JOIN pg_catalog.pg_type t ON t.oid = c.contypid
        JOIN pg_catalog.pg_namespace tn ON tn.oid = t.typnamespace
        JOIN pg_catalog.pg_depend d ON d.classid = 'pg_constraint'::regclass
                                   AND d.objid = c.oid
        JOIN pg_catalog.pg_proc p ON p.oid = d.refobjid
        JOIN pg_catalog.pg_namespace pn ON pn.oid = p.pronamespace
        WHERE tn.nspname = 'public'
          AND t.typtype = 'd'
          AND t.typname = ANY($1)
          AND pn.nspname IN ('eql_v3', 'eql_v3_internal')
        ORDER BY 1
        "#,
    )
    .bind(user_domain_names())
    .fetch_all(&pool)
    .await?;
    assert!(
        dependency_refs.is_empty(),
        "public user-domain CHECK constraint(s) depend on EQL-owned functions: {dependency_refs:?}"
    );
    Ok(())
}

/// #2 — Placement invariant: SEM index-term types remain internal. These are
/// transient implementation types used by extractors, indexes, and comparator
/// functions; exposing them as user-column domains would leak implementation
/// detail into type pickers.
#[sqlx::test]
async fn sem_index_term_types_remain_internal(pool: PgPool) -> Result<()> {
    let expected = ["bloom_filter", "hmac_256", "ope_cllw", "ore_block_256"];
    let present: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT t.typname::text
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = 'eql_v3_internal'
          AND t.typname = ANY($1)
        ORDER BY 1
        "#,
    )
    .bind(expected)
    .fetch_all(&pool)
    .await?;
    let present: std::collections::BTreeSet<String> = present.into_iter().collect();
    let missing: Vec<&str> = expected
        .into_iter()
        .filter(|name| !present.contains(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "SEM/index-term type(s) missing from eql_v3_internal: {missing:?}"
    );

    let misplaced: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT format('%I.%I', n.nspname, t.typname)
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE t.typname = ANY($1)
          AND n.nspname <> 'eql_v3_internal'
        ORDER BY 1
        "#,
    )
    .bind(expected)
    .fetch_all(&pool)
    .await?;
    assert!(
        misplaced.is_empty(),
        "SEM/index-term types must stay internal: {misplaced:?}"
    );
    Ok(())
}
