//! Privilege/exposure gate for the `eql_v3` / `eql_v3_internal` split.
//!
//! The installer grants nothing automatically: a runtime role gets access only
//! via explicit `GRANT`. `docs/reference/permissions.md` documents that a runtime
//! (query) role which uses the supported *operators* needs USAGE + EXECUTE on
//! BOTH `eql_v3` and `eql_v3_internal` — the public wrappers/extractors inline a
//! call to an `eql_v3_internal` index-term constructor (e.g. `eq_term` →
//! `eql_v3_internal.hmac_256(jsonb)`, `ord_term` → `eql_v3_internal.ope_cllw`),
//! and aggregates dispatch into `eql_v3_internal.*_sfunc`, so granting only the
//! public schema is not enough. These tests make that contract executable.
//!
//! Not every path crosses the boundary, and the tests below pin the difference:
//! the hand-written jsonb (SteVec) `jsonb_document_contains` read path is `plpgsql`
//! (never inlined) and runs under the public grant alone. Casting raw jsonb to
//! `public.eql_v3_json_search` also stays outside `eql_v3_internal`: the domain CHECK calls
//! public validators so application table columns can survive EQL schema
//! uninstall without dependency edges back into the droppable schemas.
//!
//! The `#[sqlx::test]` harness runs as a cluster superuser, so it can
//! `CREATE ROLE` / `SET ROLE`. Roles are cluster-global (not per-database), so
//! each test derives a unique role name from its isolated database name and
//! drops it (with `DROP OWNED BY` first, to clear grant dependencies) on the way
//! out to stay parallel-safe and leak-free.

use anyhow::Result;
use sqlx::PgPool;

/// A real equality query (`=` on `integer_eq`) over the committed fixture. The `=`
/// operator binds the public wrapper `eql_v3.eq`, whose (inlinable) body calls
/// `eql_v3.eq_term`, which in turn calls the `eql_v3_internal.hmac_256(jsonb)`
/// constructor — inlined into the query, that constructor call requires the
/// caller to hold `eql_v3_internal`, so the path exercises BOTH schemas.
const EQ_QUERY: &str = "SELECT count(*) FROM fixtures.eql_v3_integer \
     WHERE payload::public.eql_v3_integer_eq = payload::public.eql_v3_integer_eq";

/// A real ordering query using the `<` *operator* on `integer_ord`, which dispatches
/// through `eql_v3.lt` → `eql_v3.ord_term` → the `eql_v3_internal.ope_cllw`
/// constructor. NB: `ORDER BY payload::public.eql_v3_integer_ord` alone does
/// NOT work here — a bare domain sorts by its jsonb base, not the encrypted
/// ordering, so it silently falls back to built-in jsonb ordering and never
/// crosses into `eql_v3_internal`. The `<` operator (which routes through
/// `ord_term`) is what genuinely exercises the encrypted ordering path.
const ORD_QUERY: &str =
    "SELECT count(*) FROM fixtures.eql_v3_integer a, fixtures.eql_v3_integer b \
     WHERE a.payload::public.eql_v3_integer_ord < b.payload::public.eql_v3_integer_ord";

/// The block-ORE counterpart of [`ORD_QUERY`]: the `<` *operator* on
/// `integer_ord_ore`, dispatching through `eql_v3.lt` → `eql_v3.ord_term_ore` →
/// the `eql_v3_internal.ore_block_256` comparator, whose comparison calls
/// pgcrypto `encrypt()` (resolved through the `extensions` schema via the
/// comparator's `SET search_path = pg_catalog, extensions, public`). Unlike the
/// CLLW-OPE `ORD_QUERY`, this path needs USAGE on `extensions`.
const ORD_ORE_QUERY: &str =
    "SELECT count(*) FROM fixtures.eql_v3_integer a, fixtures.eql_v3_integer b \
     WHERE a.payload::public.eql_v3_integer_ord_ore < b.payload::public.eql_v3_integer_ord_ore";

/// A real aggregate (`eql_v3.min` on `integer_ord`). The public aggregate dispatches
/// into its state function `eql_v3_internal.min_sfunc`, so it requires the
/// internal grant.
const AGG_QUERY: &str = "SELECT eql_v3.min(payload::public.eql_v3_integer_ord) \
     FROM fixtures.eql_v3_integer";

/// A real jsonb (SteVec) containment READ path. `eql_v3.jsonb_document_contains` is
/// `plpgsql` (never inlined), so — unlike the scalar operators — it runs under
/// the public `eql_v3` grant alone. Self-containment makes the result true.
const JSONB_READ_QUERY: &str = "SELECT eql_v3.jsonb_document_contains(payload, payload) \
     FROM fixtures.v3_ste_vec LIMIT 1";

/// A real jsonb WRITE path: casting raw jsonb to the `public.eql_v3_json_search` domain fires
/// the domain CHECK, which calls public validators and does not cross into
/// `eql_v3_internal`.
const JSONB_WRITE_QUERY: &str = "SELECT (payload::jsonb)::public.eql_v3_json_search \
     FROM fixtures.v3_ste_vec LIMIT 1";

/// Derive a unique, valid role name from the per-test database name so parallel
/// tests (and reruns) never collide on the cluster-global role namespace.
///
/// Hash the db name to a short token rather than embedding it: PostgreSQL
/// truncates identifiers at 63 bytes, and the raw `_sqlx_test_<rand>` db name
/// pushes an `eqlpriv_<db>` role over that limit — the stored (truncated) name
/// would then never match a `rolname = <full>` lookup, silently breaking cleanup.
async fn unique_role(conn: &mut sqlx::PgConnection) -> Result<String> {
    use std::hash::{Hash, Hasher};
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&mut *conn)
        .await?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    db.hash(&mut hasher);
    Ok(format!("eqlpriv_{:016x}", hasher.finish()))
}

/// Create a fresh, isolated NOLOGIN role, clearing any leftover of the same name
/// first. Returns the role name.
async fn create_isolated_role(conn: &mut sqlx::PgConnection) -> Result<String> {
    let role = unique_role(&mut *conn).await?;
    drop_role(&mut *conn, &role).await?;
    sqlx::query(&format!("CREATE ROLE \"{role}\" NOSUPERUSER NOLOGIN"))
        .execute(&mut *conn)
        .await?;
    Ok(role)
}

/// Drop a role if it exists. Grants create `pg_shdepend` dependencies, so a bare
/// `DROP ROLE` fails with "cannot be dropped because some objects depend on it";
/// `DROP OWNED BY` first revokes every privilege granted to the role in the
/// current database (and drops anything it owns), letting the role drop cleanly.
async fn drop_role(conn: &mut sqlx::PgConnection, role: &str) -> Result<()> {
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)")
            .bind(role)
            .fetch_one(&mut *conn)
            .await?;
    if exists {
        sqlx::query(&format!("DROP OWNED BY \"{role}\""))
            .execute(&mut *conn)
            .await?;
        sqlx::query(&format!("DROP ROLE \"{role}\""))
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// Grant the common, non-EQL-schema prerequisites a runtime role always needs:
/// read the named fixture table(s). (USAGE on `public` is granted to PUBLIC by
/// default, which is where the domain operators live.)
async fn grant_fixture_access(
    conn: &mut sqlx::PgConnection,
    role: &str,
    tables: &[&str],
) -> Result<()> {
    sqlx::query(&format!("GRANT USAGE ON SCHEMA fixtures TO \"{role}\""))
        .execute(&mut *conn)
        .await?;
    for table in tables {
        sqlx::query(&format!("GRANT SELECT ON fixtures.{table} TO \"{role}\""))
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

/// Grant USAGE + EXECUTE on an EQL schema (`eql_v3` or `eql_v3_internal`).
async fn grant_schema(conn: &mut sqlx::PgConnection, role: &str, schema: &str) -> Result<()> {
    sqlx::query(&format!("GRANT USAGE ON SCHEMA {schema} TO \"{role}\""))
        .execute(&mut *conn)
        .await?;
    sqlx::query(&format!(
        "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA {schema} TO \"{role}\""
    ))
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Assert a query error is a PostgreSQL `insufficient_privilege` (42501).
fn assert_insufficient_privilege(err: sqlx::Error, context: &str) {
    let db_err = err
        .as_database_error()
        .unwrap_or_else(|| panic!("{context}: expected a database error, got: {err:?}"));
    assert_eq!(
        db_err.code().as_deref(),
        Some("42501"),
        "{context}: expected insufficient_privilege (42501) referencing eql_v3_internal, got: {db_err:?}"
    );
}

/// Assert a query failed at the pgcrypto / `extensions` boundary: a database
/// error whose message names pgcrypto's `encrypt` or the `extensions` schema.
///
/// The ORE comparator calls `encrypt()` unqualified, resolved through its
/// `SET search_path = pg_catalog, extensions, public`. When the caller lacks
/// USAGE on `extensions`, PostgreSQL skips that schema during name resolution,
/// so this surfaces as `undefined_function` ("function encrypt(...) does not
/// exist") rather than a plain `permission denied for schema extensions`
/// (`insufficient_privilege`). Both name the boundary, so the assertion pins the
/// message reference, not the exact SQLSTATE.
fn assert_pgcrypto_boundary_error(err: sqlx::Error, context: &str) {
    let db_err = err
        .as_database_error()
        .unwrap_or_else(|| panic!("{context}: expected a database error, got: {err:?}"));
    let msg = db_err.message().to_ascii_lowercase();
    assert!(
        msg.contains("encrypt") || msg.contains("extensions"),
        "{context}: expected an error naming the pgcrypto `encrypt` / `extensions` boundary, got: {db_err:?}"
    );
}

// ============================================================================
// Scalar operator surface
// ============================================================================

/// Positive: a runtime role granted USAGE + EXECUTE on BOTH schemas (exactly the
/// README recipe) can run the documented equality, ordering, and aggregate paths.
#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn runtime_role_with_both_schema_grants_can_query(pool: PgPool) -> Result<()> {
    // A single connection for the whole test: SET ROLE is connection-scoped.
    let mut conn = pool.acquire().await?;
    let role = create_isolated_role(&mut conn).await?;

    grant_fixture_access(&mut conn, &role, &["eql_v3_integer"]).await?;
    grant_schema(&mut conn, &role, "eql_v3").await?;
    grant_schema(&mut conn, &role, "eql_v3_internal").await?;
    // NB: no `extensions` (pgcrypto) grant is needed here. The default `_ord`
    // ordering path is CLLW-OPE (`eql_v3.ord_term` → `eql_v3_internal.ope_cllw`),
    // which compares hex-decoded `bytea` natively and never calls pgcrypto
    // `encrypt()`. Only the by-name block-ORE variants (`_ord_ore` /
    // `text_search_ore`) reach pgcrypto and would need USAGE on `extensions`.

    sqlx::query(&format!("SET ROLE \"{role}\""))
        .execute(&mut *conn)
        .await?;

    let eq_count: i64 = sqlx::query_scalar(EQ_QUERY).fetch_one(&mut *conn).await?;
    assert_eq!(
        eq_count, 17,
        "equality query should match all 17 fixture rows under the runtime role"
    );

    let ord_pairs: i64 = sqlx::query_scalar(ORD_QUERY).fetch_one(&mut *conn).await?;
    assert!(
        ord_pairs > 0,
        "ordering query should find ordered pairs under the runtime role"
    );

    // Aggregate returns an encrypted value; we only care that it executes.
    sqlx::query(AGG_QUERY).fetch_one(&mut *conn).await?;

    sqlx::query("RESET ROLE").execute(&mut *conn).await?;
    drop_role(&mut conn, &role).await?;
    Ok(())
}

/// Negative: a runtime role granted the PUBLIC schema (`eql_v3`) but NOT
/// `eql_v3_internal` cannot run the operator/aggregate paths — each dispatches
/// into `eql_v3_internal`, so a missing internal grant raises
/// `insufficient_privilege` (42501). Pins *why* the docs require the internal
/// grant: `eql_v3` alone is not enough for the supported operators.
#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn runtime_role_without_internal_grant_is_denied(pool: PgPool) -> Result<()> {
    let mut conn = pool.acquire().await?;
    let role = create_isolated_role(&mut conn).await?;

    grant_fixture_access(&mut conn, &role, &["eql_v3_integer"]).await?;
    // Public schema ONLY — deliberately omit eql_v3_internal.
    grant_schema(&mut conn, &role, "eql_v3").await?;

    sqlx::query(&format!("SET ROLE \"{role}\""))
        .execute(&mut *conn)
        .await?;

    // Every supported operator/aggregate path must be denied for lack of the
    // eql_v3_internal grant.
    for (label, query) in [
        ("equality", EQ_QUERY),
        ("ordering", ORD_QUERY),
        ("aggregate", AGG_QUERY),
    ] {
        let err = sqlx::query(query)
            .fetch_one(&mut *conn)
            .await
            .expect_err(&format!(
                "{label} must be denied without eql_v3_internal grant"
            ));
        assert_insufficient_privilege(err, label);
    }

    sqlx::query("RESET ROLE").execute(&mut *conn).await?;
    drop_role(&mut conn, &role).await?;
    Ok(())
}

/// Boundary (OPE vs ORE): a runtime role granted USAGE + EXECUTE on BOTH EQL
/// schemas and read on the fixture — but deliberately NOT USAGE on `extensions`
/// (pgcrypto) — can run the default CLLW-OPE ordering path (`_ord`) yet is denied
/// the block-ORE ordering path (`_ord_ore`). Pins the pgcrypto boundary that
/// motivates preferring `_ord`: the OPE comparator (`eql_v3_internal.ope_cllw`)
/// compares hex-decoded `bytea` natively and never touches pgcrypto, so it needs
/// no `extensions` grant; the ORE comparator (`eql_v3_internal.ore_block_256`)
/// calls pgcrypto `encrypt()` (resolved through `extensions`), so under the
/// identical grant set the same `<` query fails at the crypto call.
///
/// The positive `runtime_role_with_both_schema_grants_can_query` already runs
/// `_ord` without an `extensions` grant; this adds the contrasting ORE denial
/// under the SAME grants, so the two ordering paths are proven to diverge on
/// exactly the `extensions` grant — not on anything else.
#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
async fn runtime_role_ope_ok_ore_needs_extensions(pool: PgPool) -> Result<()> {
    let mut conn = pool.acquire().await?;
    let role = create_isolated_role(&mut conn).await?;

    grant_fixture_access(&mut conn, &role, &["eql_v3_integer"]).await?;
    grant_schema(&mut conn, &role, "eql_v3").await?;
    grant_schema(&mut conn, &role, "eql_v3_internal").await?;
    // Deliberately NO grant on `extensions` (pgcrypto) — the whole point: it is
    // what separates the OPE path (below, allowed) from the ORE path (denied).

    sqlx::query(&format!("SET ROLE \"{role}\""))
        .execute(&mut *conn)
        .await?;

    // (a) The CLLW-OPE `_ord` ordering path succeeds without the extensions grant.
    let ope_pairs: i64 = sqlx::query_scalar(ORD_QUERY).fetch_one(&mut *conn).await?;
    assert!(
        ope_pairs > 0,
        "the CLLW-OPE `_ord` ordering path must succeed without an `extensions` grant"
    );

    // (b) The block-ORE `_ord_ore` ordering path is denied: its comparator calls
    // pgcrypto `encrypt()` in `extensions`, which this role cannot reach.
    let err = sqlx::query(ORD_ORE_QUERY)
        .fetch_one(&mut *conn)
        .await
        .expect_err("the block-ORE `_ord_ore` path must fail without an `extensions` grant");
    assert_pgcrypto_boundary_error(err, "ore ordering without extensions grant");

    sqlx::query("RESET ROLE").execute(&mut *conn).await?;
    drop_role(&mut conn, &role).await?;
    Ok(())
}

// ============================================================================
// jsonb (SteVec) surface — read and write/validate paths avoid eql_v3_internal
// ============================================================================

/// Positive (jsonb): a runtime role granted USAGE + EXECUTE on BOTH schemas can
/// run both the SteVec containment read and the `public.eql_v3_json_search` cast (write) path.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn runtime_role_with_both_schema_grants_can_query_json(pool: PgPool) -> Result<()> {
    let mut conn = pool.acquire().await?;
    let role = create_isolated_role(&mut conn).await?;

    grant_fixture_access(&mut conn, &role, &["v3_ste_vec"]).await?;
    grant_schema(&mut conn, &role, "eql_v3").await?;
    grant_schema(&mut conn, &role, "eql_v3_internal").await?;

    sqlx::query(&format!("SET ROLE \"{role}\""))
        .execute(&mut *conn)
        .await?;

    let contains: bool = sqlx::query_scalar(JSONB_READ_QUERY)
        .fetch_one(&mut *conn)
        .await?;
    assert!(
        contains,
        "a SteVec document contains itself; containment should return true under the runtime role"
    );

    // Cast (write) path fires the public CHECK validator and succeeds with the
    // full runtime grants.
    sqlx::query(JSONB_WRITE_QUERY).fetch_one(&mut *conn).await?;

    sqlx::query("RESET ROLE").execute(&mut *conn).await?;
    drop_role(&mut conn, &role).await?;
    Ok(())
}

/// Boundary (jsonb): a runtime role granted only the PUBLIC schema (`eql_v3`)
/// characterises the SteVec split precisely — both the `plpgsql` containment
/// READ and the `public.eql_v3_json_search` domain CHECK validator path run without the
/// internal grant.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn runtime_role_without_internal_grant_jsonb_boundary(pool: PgPool) -> Result<()> {
    let mut conn = pool.acquire().await?;
    let role = create_isolated_role(&mut conn).await?;

    grant_fixture_access(&mut conn, &role, &["v3_ste_vec"]).await?;
    // Public schema ONLY — deliberately omit eql_v3_internal.
    grant_schema(&mut conn, &role, "eql_v3").await?;

    sqlx::query(&format!("SET ROLE \"{role}\""))
        .execute(&mut *conn)
        .await?;

    // Read path: allowed under the public grant alone (plpgsql, never inlined).
    let contains: bool = sqlx::query_scalar(JSONB_READ_QUERY)
        .fetch_one(&mut *conn)
        .await?;
    assert!(
        contains,
        "SteVec containment read should succeed with the public eql_v3 grant alone"
    );

    // Write/validate path: allowed without eql_v3_internal because CHECK
    // validators live in public and are not EQL-owned schema dependencies.
    sqlx::query(JSONB_WRITE_QUERY).fetch_one(&mut *conn).await?;

    sqlx::query("RESET ROLE").execute(&mut *conn).await?;
    drop_role(&mut conn, &role).await?;
    Ok(())
}
