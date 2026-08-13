//! Uninstall-symmetry gate for the `eql_v3` / `eql_v3_internal` split.
//!
//! Clean separation includes clean teardown: the shipped uninstaller must drop
//! BOTH schemas the installer creates, leaving nothing behind. Before this test,
//! the only uninstaller coverage was a file-existence check
//! (`build_validation_tests::v3_uninstaller_exists`); nothing ran it and
//! asserted the effect.
//!
//! This runs the ACTUAL shipped artifact — `release/cipherstash-encrypt-uninstall.sql`,
//! read from disk exactly as `build_validation_tests` does. In CI the shard
//! runners get `release/*.sql` from the `nextest-archive` artifact; locally it
//! is produced by `mise run build` (which `test:sqlx:prep` runs before the
//! suite). The `#[sqlx::test]` harness has already installed both schemas via
//! the `001_install_eql.sql` migration, so this test uninstalls on top of a real
//! install and verifies the schemas are gone.

use anyhow::Result;
use sqlx::PgPool;

/// The shipped uninstaller, relative to the test crate root (`tests/sqlx`).
/// `tasks/build.sh` produces it by appending `tasks/uninstall-v3.sql` verbatim,
/// so this file IS the shipped teardown.
const UNINSTALLER: &str = "../../release/cipherstash-encrypt-uninstall.sql";
const INSTALLER: &str = "../../release/cipherstash-encrypt.sql";

async fn schema_count(pool: &PgPool) -> Result<i64> {
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_namespace WHERE nspname IN ('eql_v3', 'eql_v3_internal')",
    )
    .fetch_one(pool)
    .await?;
    Ok(n)
}

async fn run_shipped_uninstaller(pool: &PgPool) -> Result<()> {
    let uninstall_sql = std::fs::read_to_string(UNINSTALLER).unwrap_or_else(|e| {
        panic!(
            "failed to read shipped uninstaller {UNINSTALLER}: {e} — run `mise run build` \
             (or, in CI, ensure the nextest-archive artifact shipped release/*.sql)"
        )
    });

    sqlx::raw_sql(&uninstall_sql).execute(pool).await?;
    Ok(())
}

async fn run_shipped_installer(pool: &PgPool) -> Result<()> {
    let install_sql = std::fs::read_to_string(INSTALLER).unwrap_or_else(|e| {
        panic!(
            "failed to read shipped installer {INSTALLER}: {e} — run `mise run build` \
             (or, in CI, ensure the nextest-archive artifact shipped release/*.sql)"
        )
    });

    sqlx::raw_sql(&install_sql).execute(pool).await?;
    Ok(())
}

async fn table_exists(pool: &PgPool, table: &str) -> Result<bool> {
    let exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
          SELECT 1
          FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public'
            AND c.relname = $1
            AND c.relkind = 'r'
        )
        "#,
    )
    .bind(table)
    .fetch_one(pool)
    .await?;
    Ok(exists)
}

fn normalize_regtype_name(name: String) -> String {
    name.replace("public.\"json\"", "public.eql_v3_json_search")
}

#[sqlx::test]
async fn uninstaller_drops_both_schemas(pool: PgPool) -> Result<()> {
    // Sanity: the migration installed both schemas, so the teardown has
    // something to remove (guards against a false pass if the install changed).
    assert_eq!(
        schema_count(&pool).await?,
        2,
        "expected both eql_v3 and eql_v3_internal installed by the migration before uninstall"
    );

    run_shipped_uninstaller(&pool).await?;

    assert_eq!(
        schema_count(&pool).await?,
        0,
        "the shipped uninstaller must drop BOTH eql_v3 and eql_v3_internal"
    );

    // CASCADE removes everything the schemas contained; assert no objects remain
    // pinned to either namespace (types, functions, and the like).
    let leftover_objects: i64 = sqlx::query_scalar(
        r#"
        SELECT
          (SELECT count(*) FROM pg_catalog.pg_type t
             JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
            WHERE n.nspname IN ('eql_v3', 'eql_v3_internal'))
        + (SELECT count(*) FROM pg_catalog.pg_proc p
             JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname IN ('eql_v3', 'eql_v3_internal'))
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        leftover_objects, 0,
        "no eql_v3 / eql_v3_internal objects should survive uninstall"
    );

    Ok(())
}

#[sqlx::test]
async fn shipped_installer_can_run_over_existing_public_domains(pool: PgPool) -> Result<()> {
    assert_eq!(
        schema_count(&pool).await?,
        2,
        "expected both eql_v3 schemas installed by the migration before repeat install"
    );

    run_shipped_installer(&pool).await?;

    assert_eq!(
        schema_count(&pool).await?,
        2,
        "repeat install must recreate both EQL-owned schemas"
    );

    let mut public_domains: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT format('%I.%I', n.nspname, t.typname)
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = 'public'
          AND t.typname IN ('eql_v3_integer_eq', 'eql_v3_json_search', 'eql_v3_json_entry')
        ORDER BY 1
        "#,
    )
    .fetch_all(&pool)
    .await?
    .into_iter()
    .map(normalize_regtype_name)
    .collect();
    public_domains.sort();
    assert_eq!(
        public_domains,
        vec![
            "public.eql_v3_integer_eq",
            "public.eql_v3_json_entry",
            "public.eql_v3_json_search"
        ],
        "repeat install must keep public user-column domains available"
    );

    // The query-operand domains are NOT column types and live in the EQL-owned
    // eql_v3 schema; a repeat install recreates them there.
    let mut query_domains: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT format('%I.%I', n.nspname, t.typname)
        FROM pg_catalog.pg_type t
        JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname = 'eql_v3'
          AND t.typname IN ('query_integer_eq', 'query_json')
        ORDER BY 1
        "#,
    )
    .fetch_all(&pool)
    .await?
    .into_iter()
    .map(normalize_regtype_name)
    .collect();
    query_domains.sort();
    assert_eq!(
        query_domains,
        vec!["eql_v3.query_integer_eq", "eql_v3.query_json"],
        "repeat install must recreate the eql_v3 query-operand domains"
    );

    Ok(())
}

#[sqlx::test]
async fn uninstaller_preserves_application_tables_with_public_domain_columns(
    pool: PgPool,
) -> Result<()> {
    assert_eq!(
        schema_count(&pool).await?,
        2,
        "expected both eql_v3 schemas installed before uninstall"
    );

    let scalar_payload = r#"{"v":3,"i":{},"c":"scalar-42","hm":"hm-42"}"#;
    // SteVec entries carry no `hm`: an op path entry / term-less entry.
    let json_payload = r#"{"i":{},"v":3,"h":"kh","sv":[{"s":"age","c":"cipher-age","op":"ab"}]}"#;
    let entry_payload = r#"{"s":"age","c":"cipher-age","op":"ab"}"#;

    sqlx::query(
        r#"
        CREATE TABLE public.eql_v3_uninstall_preserve (
          id integer PRIMARY KEY,
          scalar_value public.eql_v3_integer_eq NOT NULL,
          doc_value public.eql_v3_json_search NOT NULL,
          entry_value public.eql_v3_json_entry
        )
        "#,
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO public.eql_v3_uninstall_preserve
          (id, scalar_value, doc_value, entry_value)
        VALUES
          (
            1,
            $1::jsonb::public.eql_v3_integer_eq,
            $2::jsonb::public.eql_v3_json_search,
            $3::jsonb::public.eql_v3_json_entry
          )
        "#,
    )
    .bind(scalar_payload)
    .bind(json_payload)
    .bind(entry_payload)
    .execute(&pool)
    .await?;

    // The inverse contract: a query-operand domain is NOT a column
    // type and lives in the EQL-owned eql_v3 schema, so a column misusing it
    // is dropped with the schema. Pin that a table holding one loses exactly
    // that column on uninstall (CASCADE), while the table itself survives.
    sqlx::query(
        r#"
        CREATE TABLE public.eql_v3_uninstall_query_misuse (
          id integer PRIMARY KEY,
          misused_query_value eql_v3.query_json
        )
        "#,
    )
    .execute(&pool)
    .await?;

    run_shipped_uninstaller(&pool).await?;

    assert_eq!(
        schema_count(&pool).await?,
        0,
        "uninstaller must drop both EQL-owned schemas"
    );
    assert!(
        table_exists(&pool, "eql_v3_uninstall_preserve").await?,
        "application table with public domain columns must survive uninstall"
    );

    let row_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.eql_v3_uninstall_preserve")
            .fetch_one(&pool)
            .await?;
    assert_eq!(row_count, 1, "row must survive uninstall");

    let column_types: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT format('%I.%I', tn.nspname, t.typname)
        FROM pg_catalog.pg_attribute a
        JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
        JOIN pg_catalog.pg_namespace cn ON cn.oid = c.relnamespace
        JOIN pg_catalog.pg_type t ON t.oid = a.atttypid
        JOIN pg_catalog.pg_namespace tn ON tn.oid = t.typnamespace
        WHERE cn.nspname = 'public'
          AND c.relname = 'eql_v3_uninstall_preserve'
          AND a.attnum > 0
          AND NOT a.attisdropped
        ORDER BY a.attnum
        "#,
    )
    .fetch_all(&pool)
    .await?
    .into_iter()
    .map(normalize_regtype_name)
    .collect();
    assert_eq!(
        column_types,
        vec![
            "pg_catalog.int4",
            "public.eql_v3_integer_eq",
            "public.eql_v3_json_search",
            "public.eql_v3_json_entry",
        ]
    );

    let values: (serde_json::Value, serde_json::Value, serde_json::Value) = sqlx::query_as(
        r#"
        SELECT
          scalar_value::jsonb,
          doc_value::jsonb,
          entry_value::jsonb
        FROM public.eql_v3_uninstall_preserve
        WHERE id = 1
        "#,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        values.0,
        serde_json::from_str::<serde_json::Value>(scalar_payload)?
    );
    assert_eq!(
        values.1,
        serde_json::from_str::<serde_json::Value>(json_payload)?
    );
    assert_eq!(
        values.2,
        serde_json::from_str::<serde_json::Value>(entry_payload)?
    );

    // The misuse table survives, but its query-operand column went down with
    // the eql_v3 schema (DROP SCHEMA ... CASCADE drops the domain, which
    // cascades to columns of that type).
    assert!(
        table_exists(&pool, "eql_v3_uninstall_query_misuse").await?,
        "the misuse table itself must survive uninstall"
    );
    let misuse_columns: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT a.attname
        FROM pg_catalog.pg_attribute a
        JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
        JOIN pg_catalog.pg_namespace cn ON cn.oid = c.relnamespace
        WHERE cn.nspname = 'public'
          AND c.relname = 'eql_v3_uninstall_query_misuse'
          AND a.attnum > 0
          AND NOT a.attisdropped
        ORDER BY a.attnum
        "#,
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        misuse_columns,
        vec!["id"],
        "a column typed as an eql_v3 query-operand domain is dropped with the schema"
    );

    Ok(())
}
