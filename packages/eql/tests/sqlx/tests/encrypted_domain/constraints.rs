//! Table-level SQL constraint coverage for `eql_v3` encrypted-domain columns.
//!
//! Covers UNIQUE / NOT NULL / FOREIGN KEY on the jsonb-backed `eql_v3.<T>`
//! domains (the reference scalar `integer`). The domains are jsonb under the hood, so a table-level constraint
//! constrains the *raw jsonb payload value*, NOT the semantic plaintext or the
//! `eq_term` / `ord_term_ore` index term — see the documented findings on each test.
//!
//! Like the sibling `signed.rs` suite it lives OUTSIDE the `scalars::`
//! namespace, so the matrix-inventory snapshot (which pins the uniform per-type
//! test set) does not mis-read it as a scalar type.
//!
//! All ciphertext is REAL: every payload comes from the generated
//! `fixtures.eql_v3_integer` table (Proxy-encrypted, HMAC + ORE block terms) via
//! `fetch_fixture_payload::<i32>`. No synthetic / hand-written encrypted blobs.
//!
//! ## What a constraint on a jsonb-backed domain actually constrains
//!
//! The fixture table stores ONE fixed payload per plaintext. Two reads of the
//! same fixture row return byte-identical jsonb, so "insert the same fetched
//! payload twice" deterministically collides on a UNIQUE jsonb domain column,
//! and an FK referencing that exact jsonb value resolves. This is the same
//! deterministic-test-data property the v2 FK test relies on (see its PRODUCTION
//! LIMITATION comment). In production EQL encryption is non-deterministic at the
//! envelope level: two independent encryptions of the same plaintext produce
//! different jsonb (`c` differs), so a UNIQUE/FK over the raw jsonb domain value
//! provides byte-identity integrity, NOT semantic (plaintext-equality)
//! integrity. The hmac `eq_term` is what carries semantic equality; a UNIQUE
//! constraint on the bare domain column does not consult it.

use eql_tests::{assert_db_error, fetch_fixture_payload, sql_string_literal};
use sqlx::PgPool;

/// Fetch the real fixture ciphertext for an `integer` plaintext as an
/// escaped SQL string literal ready to interpolate as `{lit}::jsonb::<domain>`.
async fn integer_payload_literal(pool: &PgPool, plaintext: i32) -> anyhow::Result<String> {
    let payload = fetch_fixture_payload::<i32>(pool, plaintext).await?;
    Ok(sql_string_literal(&payload))
}

// ===========================================================================
// NOT NULL — on the storage-only `public.eql_v3_integer` domain column.
// ===========================================================================

/// A `NOT NULL` column attribute on an `public.eql_v3_integer` (storage) column rejects a
/// NULL insert (SQLSTATE 23502) and accepts a real encrypted value.
#[sqlx::test(fixtures(path = "../../fixtures", scripts("eql_v3_integer")))]
async fn not_null_on_integer_storage_column(pool: PgPool) -> anyhow::Result<()> {
    sqlx::query(
        "CREATE TABLE v3_not_null (id bigint PRIMARY KEY, val public.eql_v3_integer NOT NULL)",
    )
    .execute(&pool)
    .await?;

    // NULL into the NOT NULL column is rejected. NOT NULL is a column attribute,
    // not a named constraint, so `constraint()` is None — pin only the SQLSTATE
    // (matches the v2 `not_null_constraint_on_encrypted_column` convention).
    let err = sqlx::query("INSERT INTO v3_not_null (id, val) VALUES (1, NULL)")
        .execute(&pool)
        .await
        .expect_err("NOT NULL must reject a NULL public.eql_v3_integer value");
    assert_db_error(&err, "23502", None);

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v3_not_null")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 0, "no row after the rejected NULL insert");

    // A real encrypted value is accepted.
    let lit = integer_payload_literal(&pool, 42).await?;
    sqlx::query(&format!(
        "INSERT INTO v3_not_null (id, val) VALUES (2, {lit}::jsonb::public.eql_v3_integer)"
    ))
    .execute(&pool)
    .await?;

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v3_not_null")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 1, "real encrypted value satisfies NOT NULL");

    Ok(())
}

// ===========================================================================
// UNIQUE — on the equality `public.eql_v3_integer_eq` domain column.
//
// `_eq` is the interesting variant: equality routes through `eq_term` (hmac).
// But a bare UNIQUE constraint on the domain column does NOT use `eq_term` — it
// uses the base type's (jsonb) btree equality on the WHOLE payload. The test
// documents this: identical payload bytes collide; distinct payloads do not.
// ===========================================================================

/// A `UNIQUE` constraint on an `public.eql_v3_integer_eq` column rejects a second row
/// carrying the byte-identical fixture payload (23505) and accepts a different
/// plaintext's payload.
///
/// FINDING — UNIQUE here constrains the RAW JSONB payload value, not the
/// semantic plaintext nor the `eq_term` hmac. The constraint resolves against
/// the domain's base type (`jsonb`) btree equality over the full payload object.
/// Because the fixture returns one fixed payload per plaintext, re-inserting the
/// SAME fetched payload is a byte-identical jsonb and collides. Two DIFFERENT
/// plaintexts have different payloads and are both accepted. In production, two
/// independent (non-deterministic) encryptions of the SAME plaintext would NOT
/// collide on this constraint despite being semantically equal — UNIQUE on a
/// bare encrypted-domain column is byte-identity uniqueness, not
/// plaintext-uniqueness.
#[sqlx::test(fixtures(path = "../../fixtures", scripts("eql_v3_integer")))]
async fn unique_on_integer_eq_column_constrains_raw_payload(pool: PgPool) -> anyhow::Result<()> {
    sqlx::query(
        "CREATE TABLE v3_unique (id bigint PRIMARY KEY, val public.eql_v3_integer_eq UNIQUE NOT NULL)",
    )
    .execute(&pool)
    .await?;

    let p42 = integer_payload_literal(&pool, 42).await?;
    let p100 = integer_payload_literal(&pool, 100).await?;

    // First insert of the 42-payload succeeds.
    sqlx::query(&format!(
        "INSERT INTO v3_unique (id, val) VALUES (1, {p42}::jsonb::public.eql_v3_integer_eq)"
    ))
    .execute(&pool)
    .await?;

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v3_unique")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 1, "first encrypted value inserted");

    // A DIFFERENT plaintext's payload (distinct jsonb) is accepted — UNIQUE does
    // not reject distinct payloads.
    sqlx::query(&format!(
        "INSERT INTO v3_unique (id, val) VALUES (2, {p100}::jsonb::public.eql_v3_integer_eq)"
    ))
    .execute(&pool)
    .await?;

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v3_unique")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 2, "distinct encrypted value accepted under UNIQUE");

    // Re-inserting the BYTE-IDENTICAL 42-payload violates UNIQUE (23505). The
    // constraint name is `<table>_<column>_key` per PostgreSQL's auto-naming.
    let err = sqlx::query(&format!(
        "INSERT INTO v3_unique (id, val) VALUES (3, {p42}::jsonb::public.eql_v3_integer_eq)"
    ))
    .execute(&pool)
    .await
    .expect_err("UNIQUE must reject the byte-identical payload");
    assert_db_error(&err, "23505", Some("v3_unique_val_key"));

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v3_unique")
        .fetch_one(&pool)
        .await?;
    assert_eq!(count, 2, "count unchanged after the rejected duplicate");

    Ok(())
}

// ===========================================================================
// FOREIGN KEY — child referencing a parent `public.eql_v3_integer` PRIMARY KEY column.
//
// FK on a jsonb-backed domain IS feasible: a PRIMARY KEY / UNIQUE on the parent
// column resolves against the base type (`jsonb`) btree opclass (jsonb has a
// default btree opclass), so the referenced column has the unique index FK
// requires. This is distinct from the "no operator class on a domain" footgun,
// which is about adding a *custom* index opclass to a domain — a plain
// PK/UNIQUE uses the inherited jsonb btree opclass and works.
// ===========================================================================

/// A FOREIGN KEY from a child `public.eql_v3_integer` column to a parent `public.eql_v3_integer`
/// PRIMARY KEY column: a matching (byte-identical) reference is accepted, a
/// dangling reference is rejected (23503).
///
/// FINDING — FK on a jsonb-backed `eql_v3` domain is FEASIBLE. The parent
/// PRIMARY KEY resolves against the inherited jsonb btree opclass, giving FK the
/// unique index it requires; no custom domain opclass is involved (so the
/// "no operator class on a domain" footgun does not apply to a plain PK). As
/// with v2 and with UNIQUE above, referential integrity is over the RAW JSONB
/// payload (byte identity), not the semantic plaintext: the child reference
/// resolves only because the test reuses the exact fixture payload bytes. Under
/// production non-deterministic encryption, a re-encryption of the same
/// plaintext would be a different jsonb and would NOT satisfy the FK — so FK on
/// a bare encrypted-domain column does not provide plaintext-level referential
/// integrity.
#[sqlx::test(fixtures(path = "../../fixtures", scripts("eql_v3_integer")))]
async fn foreign_key_on_integer_domain_columns(pool: PgPool) -> anyhow::Result<()> {
    // Parent with a PRIMARY KEY on an public.eql_v3_integer (jsonb-backed domain) column.
    sqlx::query("CREATE TABLE v3_parent (ref public.eql_v3_integer PRIMARY KEY)")
        .execute(&pool)
        .await?;

    // Child referencing the parent encrypted column.
    sqlx::query(
        "CREATE TABLE v3_child (
             id bigint PRIMARY KEY,
             parent_ref public.eql_v3_integer REFERENCES v3_parent(ref)
         )",
    )
    .execute(&pool)
    .await?;

    // Sanity: the FK constraint exists.
    let fk_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT FROM information_schema.table_constraints
             WHERE table_name = 'v3_child' AND constraint_type = 'FOREIGN KEY'
         )",
    )
    .fetch_one(&pool)
    .await?;
    assert!(fk_exists, "FK constraint must exist on v3_child");

    let p42 = integer_payload_literal(&pool, 42).await?;
    let p100 = integer_payload_literal(&pool, 100).await?;

    // Seed the parent with the 42-payload.
    sqlx::query(&format!(
        "INSERT INTO v3_parent (ref) VALUES ({p42}::jsonb::public.eql_v3_integer)"
    ))
    .execute(&pool)
    .await?;

    // Child row with a byte-identical reference resolves (deterministic fixture
    // bytes), so the FK is satisfied.
    sqlx::query(&format!(
        "INSERT INTO v3_child (id, parent_ref) VALUES (1, {p42}::jsonb::public.eql_v3_integer)"
    ))
    .execute(&pool)
    .await?;

    let child_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v3_child")
        .fetch_one(&pool)
        .await?;
    assert_eq!(child_count, 1, "matching FK reference accepted");

    // Child row referencing a payload NOT present in the parent (different
    // plaintext → different jsonb) violates the FK (23503).
    let err = sqlx::query(&format!(
        "INSERT INTO v3_child (id, parent_ref) VALUES (2, {p100}::jsonb::public.eql_v3_integer)"
    ))
    .execute(&pool)
    .await
    .expect_err("FK must reject a dangling reference");
    assert_db_error(&err, "23503", Some("v3_child_parent_ref_fkey"));

    let child_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM v3_child")
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        child_count, 1,
        "count unchanged after the rejected FK insert"
    );

    Ok(())
}
