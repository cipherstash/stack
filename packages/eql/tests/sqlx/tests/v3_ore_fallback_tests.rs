//! Non-superuser install gate for the ORE capability-detection fallback
//!.
//!
//! `CREATE OPERATOR CLASS` requires superuser, and managed platforms (cloud
//! Supabase and most hosted Postgres) run the installer as a non-superuser
//! role. The installer ATTEMPTS the ORE opclass creation and, on
//! `insufficient_privilege`, skips it — and then `src/v3/scalars/ore_fallback.sql`
//! poisons every ORE-carrying domain (and its `eql_v3.query_*` twin) with an
//! always-raising CHECK constraint, so the domains fail loudly on first use
//! instead of silently installing half-working (seq-scan-only comparisons,
//! opaque errors from `CREATE INDEX` / bare `ORDER BY`).
//!
//! These tests run the ACTUAL shipped installer — `release/cipherstash-encrypt.sql`,
//! read from disk exactly as `v3_uninstall_tests` does — under `SET ROLE` to a
//! NOSUPERUSER role, against a database with no prior EQL install
//! (`migrations = false`; the standard migration installs as superuser, which
//! would create the opclass and make the fallback a no-op — and would leave
//! superuser-owned domains a non-superuser re-install could not `ALTER`).
//!
//! The poisoned/functional split is derived from the SAME catalog the
//! generator renders from (`eql_domains::scalar_families()`), so a new
//! ORE-carrying domain is covered here by construction, not by a hand-kept
//! list.
//!
//! Roles are cluster-global (not per-database), so each test derives a unique
//! role name from its isolated database name and drops it (with `DROP OWNED BY`
//! first) on the way out — same pattern as `v3_privilege_tests`.

use anyhow::Result;
use eql_domains::Term;
use sqlx::PgPool;

/// The shipped installer, relative to the test crate root (`tests/sqlx`).
const INSTALLER: &str = "../../release/cipherstash-encrypt.sql";

/// SQLSTATE for `feature_not_supported`, which the poison CHECK raises with.
const FEATURE_NOT_SUPPORTED: &str = "0A000";

/// Derive a unique, valid role name from the per-test database name so parallel
/// tests (and reruns) never collide on the cluster-global role namespace.
async fn unique_role(conn: &mut sqlx::PgConnection) -> Result<String> {
    use std::hash::{Hash, Hasher};
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&mut *conn)
        .await?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    db.hash(&mut hasher);
    Ok(format!("eqlore_{:016x}", hasher.finish()))
}

/// A minimal payload accepted by a column domain's structural CHECK: the
/// envelope (`v`/`i`/`c`) plus every term key, with nonempty-array keys (`ob`,
/// `bf`) as arrays. Mirrors what the generated CHECK validates (key presence +
/// array shape); the values are inert — no crypto runs at the CHECK layer.
fn column_payload(terms: &[Term]) -> String {
    // `v` is a JSON number: the wire contract (`SchemaVersion`, the published
    // bindings) pins integer 3; the domain CHECK's `->>` would also accept a
    // string, but the fixtures here should model conforming payloads.
    let mut payload = String::from(r#"{"v":3,"i":{"t":"t","c":"c"},"c":"ct""#);
    for t in Term::payload_terms(terms) {
        let key = t.json_key();
        if t.nonempty_array_key().is_some() {
            payload.push_str(&format!(r#","{key}":["aa"]"#));
        } else {
            payload.push_str(&format!(r#","{key}":"aa""#));
        }
    }
    payload.push('}');
    payload
}

/// A minimal payload accepted by a query-twin domain's CHECK: envelope minus
/// `c` (the twins require `NOT (VALUE ? 'c')`) plus every term key.
fn query_payload(terms: &[Term]) -> String {
    let mut payload = String::from(r#"{"v":3,"i":{"t":"t","c":"c"}"#);
    for t in Term::payload_terms(terms) {
        let key = t.json_key();
        if t.nonempty_array_key().is_some() {
            payload.push_str(&format!(r#","{key}":["aa"]"#));
        } else {
            payload.push_str(&format!(r#","{key}":"aa""#));
        }
    }
    payload.push('}');
    payload
}

/// True when the default btree operator class for
/// `eql_v3_internal.ore_block_256` exists — the condition the fallback reads.
async fn ore_opclass_exists(pool: &PgPool) -> Result<bool> {
    let exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
          SELECT 1
          FROM pg_catalog.pg_opclass c
          JOIN pg_catalog.pg_am am ON am.oid = c.opcmethod
          WHERE am.amname = 'btree'
            AND c.opcdefault
            AND c.opcintype = 'eql_v3_internal.ore_block_256'::regtype
        )
        "#,
    )
    .fetch_one(pool)
    .await?;
    Ok(exists)
}

/// Cast `payload` into `domain`, returning the error if it raises.
async fn try_cast(pool: &PgPool, domain: &str, payload: &str) -> Result<(), sqlx::Error> {
    sqlx::query(&format!("SELECT $1::jsonb::{domain}"))
        .bind(payload)
        .execute(pool)
        .await
        .map(|_| ())
}

/// Assert `err` is the poison raise: `feature_not_supported`, naming the
/// domain, with the alternatives HINT.
fn assert_poison_error(err: sqlx::Error, domain: &str) {
    let db_err = match err {
        sqlx::Error::Database(e) => e,
        other => panic!(
            "expected the poison CHECK to raise a database error for {domain}, got {other:?}"
        ),
    };
    assert_eq!(
        db_err.code().as_deref(),
        Some(FEATURE_NOT_SUPPORTED),
        "poison raise for {domain} must use ERRCODE feature_not_supported: {db_err}"
    );
    assert!(
        db_err.message().contains(domain)
            && db_err.message().contains("cannot be used on this platform"),
        "poison message for {domain} must name the domain and the platform limitation: {db_err}"
    );
}

/// Install the shipped installer under `SET ROLE role` on a single connection,
/// so every statement executes with non-superuser privileges.
async fn install_as(conn: &mut sqlx::PgConnection, role: &str) -> Result<()> {
    let install_sql = std::fs::read_to_string(INSTALLER).unwrap_or_else(|e| {
        panic!(
            "failed to read shipped installer {INSTALLER}: {e} — run `mise run build` \
             (or, in CI, ensure the nextest-archive artifact shipped release/*.sql)"
        )
    });
    sqlx::query(&format!("SET ROLE {role}"))
        .execute(&mut *conn)
        .await?;
    sqlx::raw_sql(&install_sql).execute(&mut *conn).await?;
    sqlx::query("RESET ROLE").execute(&mut *conn).await?;
    Ok(())
}

/// Cluster-global role teardown: drop everything the role owns in this
/// database, then the role itself.
async fn drop_role(conn: &mut sqlx::PgConnection, role: &str) -> Result<()> {
    sqlx::query(&format!("DROP OWNED BY {role} CASCADE"))
        .execute(&mut *conn)
        .await?;
    sqlx::query(&format!("DROP ROLE {role}"))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The full  contract, catalog-driven: a non-superuser install
/// succeeds, skips the ORE opclass, and poisons exactly the ORE-carrying
/// domains (columns AND query twins), while every non-ORE domain stays fully
/// functional.
///
/// NB: keep this test's NAME short — the `#[sqlx::test]` harness derives the
/// per-test database name from it, and a name past PostgreSQL's 63-byte
/// identifier limit is created truncated but connected to untruncated
/// ("database does not exist").
#[sqlx::test(migrations = false)]
async fn nosuper_install_poisons_ore_domains(pool: PgPool) -> Result<()> {
    let mut conn = pool.acquire().await?;
    let role = unique_role(&mut conn).await?;
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&mut *conn)
        .await?;

    // Self-heal from a prior failed run: the role is cluster-global and a
    // teardown that never ran (test process killed, assertion panic before
    // cleanup) leaves it behind, deterministically colliding on rerun.
    sqlx::query(&format!(
        "DO $$ BEGIN
           IF EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') THEN
             EXECUTE 'DROP OWNED BY {role} CASCADE';
             EXECUTE 'DROP ROLE {role}';
           END IF;
         END $$"
    ))
    .execute(&mut *conn)
    .await?;

    // NOSUPERUSER is the default, spelled out because it is the point.
    sqlx::query(&format!("CREATE ROLE {role} NOSUPERUSER"))
        .execute(&mut *conn)
        .await?;
    // The installer creates schemas + the pgcrypto extension (trusted since
    // PG13, so CREATE on the database suffices) and domains in public. The
    // database name MUST be quoted: the sqlx harness generates mixed-case
    // names, which an unquoted identifier would case-fold into oblivion.
    sqlx::query(&format!("GRANT CREATE ON DATABASE \"{db}\" TO {role}"))
        .execute(&mut *conn)
        .await?;
    sqlx::query(&format!("GRANT CREATE ON SCHEMA public TO {role}"))
        .execute(&mut *conn)
        .await?;

    let result = async {
        install_as(&mut conn, &role).await?;
        drop(conn);

        assert!(
            !ore_opclass_exists(&pool).await?,
            "a NOSUPERUSER install must not have created the ORE opclass"
        );

        for spec in eql_domains::scalar_families() {
            for d in spec.domains {
                if d.terms.is_empty() {
                    continue; // storage-only: no term keys, no query twin, not poisoned
                }
                let column = format!("public.{}", spec.domain_name(d));
                let query = format!("eql_v3.{}", d.query_name(spec.name));
                let col_payload = column_payload(d.terms);
                let q_payload = query_payload(d.terms);
                if d.terms.contains(&Term::Ore) {
                    let err = try_cast(&pool, &column, &col_payload)
                        .await
                        .expect_err(&format!(
                            "{column} must be poisoned on a NOSUPERUSER install"
                        ));
                    assert_poison_error(err, &column);
                    let err = try_cast(&pool, &query, &q_payload)
                        .await
                        .expect_err(&format!(
                            "{query} must be poisoned on a NOSUPERUSER install"
                        ));
                    assert_poison_error(err, &query);
                } else {
                    try_cast(&pool, &column, &col_payload)
                        .await
                        .unwrap_or_else(|e| {
                            panic!("{column} must stay functional on a NOSUPERUSER install: {e}")
                        });
                    try_cast(&pool, &query, &q_payload)
                        .await
                        .unwrap_or_else(|e| {
                            panic!("{query} must stay functional on a NOSUPERUSER install: {e}")
                        });
                }
            }
        }

        // The poison must fire for NULL too (a STRICT poison function would be
        // skipped on NULL input and let NULLs into the domain silently). One
        // representative domain suffices — the CHECK wiring is identical.
        sqlx::query("CREATE TABLE ore_fallback_null_probe (x public.eql_v3_integer_ord_ore)")
            .execute(&pool)
            .await?;
        let err = sqlx::query("INSERT INTO ore_fallback_null_probe VALUES (NULL)")
            .execute(&pool)
            .await
            .expect_err("inserting NULL into a poisoned domain column must raise");
        assert_poison_error(err, "public.eql_v3_integer_ord_ore");

        Ok::<(), anyhow::Error>(())
    }
    .await;

    // Teardown the cluster-global role whether or not the assertions passed;
    // never let a teardown error mask the real failure.
    let mut conn = pool.acquire().await?;
    sqlx::query("RESET ROLE").execute(&mut *conn).await.ok();
    if let Err(e) = drop_role(&mut conn, &role).await {
        if result.is_ok() {
            return Err(e);
        }
        eprintln!("teardown: failed to drop role {role}: {e}");
    }
    result
}

/// The superuser path is unchanged: opclass created, nothing poisoned, ORE
/// domains accept values. Runs on the standard migration install.
#[sqlx::test]
async fn superuser_install_creates_opclass_and_poisons_nothing(pool: PgPool) -> Result<()> {
    assert!(
        ore_opclass_exists(&pool).await?,
        "a superuser install must create the ORE opclass"
    );

    let poison_constraints: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint WHERE conname = 'eql_ore_unavailable'",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        poison_constraints, 0,
        "a superuser install must not poison any domain"
    );

    // Re-point at the ORE domain: `_ord` is OPE (UNPOISONABLE by construction),
    // so casting into it proves nothing about the superuser path. `_ord_ore` is
    // the poisonable ORE domain — on a superuser install it must NOT be poisoned
    // and must accept values, making this a meaningful positive control.
    let ord_ore = eql_domains::scalar_families()
        .find(|s| s.name == "integer")
        .and_then(|s| s.domains.iter().find(|d| d.name == "ord_ore"))
        .expect("integer_ord_ore in catalog");
    try_cast(
        &pool,
        "public.eql_v3_integer_ord_ore",
        &column_payload(ord_ore.terms),
    )
    .await
    .expect("integer_ord_ore accepts values on a superuser install");
    Ok(())
}

/// The demotion scenario the NOT VALID poison exists for: a role installs as
/// superuser, ORE data is stored, the role is demoted (managed-platform
/// reality: the capability is lost), and the installer re-runs. Without
/// NOT VALID, `ALTER DOMAIN ... ADD CONSTRAINT` validates the stored rows
/// against the always-raising poison and aborts the whole install — for
/// exactly the users the fallback exists to help. The re-install must
/// succeed, keep the pre-existing rows readable, and poison only new writes.
/// A third install run pins non-superuser-over-non-superuser re-install
/// idempotency on a data-bearing, already-poisoned database.
#[sqlx::test(migrations = false)]
async fn reinstall_over_ore_data(pool: PgPool) -> Result<()> {
    let mut conn = pool.acquire().await?;
    let role = unique_role(&mut conn).await?;
    let db: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&mut *conn)
        .await?;

    // Self-heal from a prior failed run (see nosuper_install_poisons_ore_domains).
    sqlx::query(&format!(
        "DO $$ BEGIN
           IF EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') THEN
             EXECUTE 'DROP OWNED BY {role} CASCADE';
             EXECUTE 'DROP ROLE {role}';
           END IF;
         END $$"
    ))
    .execute(&mut *conn)
    .await?;

    // Start SUPERUSER: the first install runs with full privileges (opclass
    // created, nothing poisoned) and — the point of same-role demotion — the
    // role OWNS every EQL object, so the demoted re-install can drop and
    // alter them.
    sqlx::query(&format!("CREATE ROLE {role} SUPERUSER"))
        .execute(&mut *conn)
        .await?;
    // No-ops while the role is superuser; load-bearing after the demotion.
    sqlx::query(&format!("GRANT CREATE ON DATABASE \"{db}\" TO {role}"))
        .execute(&mut *conn)
        .await?;
    sqlx::query(&format!("GRANT CREATE ON SCHEMA public TO {role}"))
        .execute(&mut *conn)
        .await?;

    let ord_ore = eql_domains::scalar_families()
        .find(|s| s.name == "integer")
        .and_then(|s| s.domains.iter().find(|d| d.name == "ord_ore"))
        .expect("integer_ord_ore in catalog");
    let payload = column_payload(ord_ore.terms);
    let expected_poisoned: i64 = eql_domains::scalar_families()
        .flat_map(|s| s.domains.iter())
        .filter(|d| d.terms.contains(&Term::Ore))
        .count() as i64
        * 2; // column domain + query twin

    let result = async {
        install_as(&mut conn, &role).await?;

        // Store ORE data while the domain is fully functional, owned by the
        // role so teardown's DROP OWNED BY cleans it up.
        sqlx::query(&format!("SET ROLE {role}"))
            .execute(&mut *conn)
            .await?;
        sqlx::query("CREATE TABLE ore_reinstall_probe (x public.eql_v3_integer_ord_ore)")
            .execute(&mut *conn)
            .await?;
        sqlx::query("INSERT INTO ore_reinstall_probe VALUES ($1::jsonb)")
            .bind(&payload)
            .execute(&mut *conn)
            .await?;
        sqlx::query("RESET ROLE").execute(&mut *conn).await?;

        sqlx::query(&format!("ALTER ROLE {role} NOSUPERUSER"))
            .execute(&mut *conn)
            .await?;

        // The demoted re-install must not abort validating the stored row.
        install_as(&mut conn, &role).await?;
        drop(conn);

        assert!(
            !ore_opclass_exists(&pool).await?,
            "the demoted re-install must not have recreated the ORE opclass"
        );
        let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM ore_reinstall_probe")
            .fetch_one(&pool)
            .await?;
        assert_eq!(stored, 1, "pre-demotion ORE rows must stay readable");
        let err = sqlx::query("INSERT INTO ore_reinstall_probe VALUES ($1::jsonb)")
            .bind(&payload)
            .execute(&pool)
            .await
            .expect_err("new writes into the poisoned domain must raise");
        assert_poison_error(err, "public.eql_v3_integer_ord_ore");

        // Non-superuser over non-superuser: a further re-run over the same
        // data-bearing, already-poisoned database is idempotent.
        let mut conn = pool.acquire().await?;
        install_as(&mut conn, &role).await?;
        drop(conn);
        let poison_constraints: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_constraint WHERE conname = 'eql_ore_unavailable'",
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(
            poison_constraints, expected_poisoned,
            "re-install re-poisons every ORE-carrying domain"
        );
        let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM ore_reinstall_probe")
            .fetch_one(&pool)
            .await?;
        assert_eq!(stored, 1, "rows survive repeated re-installs");

        Ok::<(), anyhow::Error>(())
    }
    .await;

    // Teardown mirrors nosuper_install_poisons_ore_domains: never let a
    // teardown error mask the real failure.
    let mut conn = pool.acquire().await?;
    sqlx::query("RESET ROLE").execute(&mut *conn).await.ok();
    if let Err(e) = drop_role(&mut conn, &role).await {
        if result.is_ok() {
            return Err(e);
        }
        eprintln!("teardown: failed to drop role {role}: {e}");
    }
    result
}
