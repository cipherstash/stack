//! End-to-end empty-string contract for the ordered `eql_v3` text domains,
//! which now differs by ordering SEM (issue #262).
//!
//! Encrypting the empty string `""` as ordered text produces an empty **ORE**
//! term (`ob: []`, verified against cipherstash-client) — the only value that
//! does. Rather than ordering such a degenerate term, the ORE-bearing
//! `public.eql_v3_text_ord_ore` rejects it at the boundary: its `CHECK` requires `ob`
//! to be a non-empty array, so casting an empty-`ob` payload fails with a check
//! violation (SQLSTATE `23514`). The comparator's "empty sorts first"
//! cardinality guard remains in place as defense-in-depth for any path that
//! bypasses the domain (e.g. a composite built directly).
//!
//! The empty term is an ORE-only failure mode. The same encryption yields a
//! well-formed **OPE** term (`op: "00"` — the bare domain-tag byte), which
//! hex-decodes to a 1-byte `bytea` that sorts before every non-empty term. So
//! the OPE-backed `public.eql_v3_text_ord` ACCEPTS `""` and orders it first. There is
//! no non-empty-array clause on its CHECK because `op` is a scalar hex string,
//! not an array (`Term::Ope::nonempty_array_key()` is `None`).
//!
//! These tests ride the generated `v3_text_empty` fixture (real ciphertexts for
//! `""`, `"frank"`, `"zebra"`; ids 1/2/3). The fixture's `payload` column is
//! plain `jsonb`, so every row loads; the rejection happens at the cast in the
//! `_ord_ore` test, not at fixture load. The fixture carries `hm` + `ob` + `op`
//! (Unique + Ore + Ope, no bloom), so it exercises `text_ord` and
//! `text_ord_ore` — not `text_search`, which additionally requires a `bf` key
//! the fixture does not emit.

use anyhow::Result;
use eql_tests::assert_db_error;
use sqlx::PgPool;

/// Casting the empty-string row (`id = 1`, `ob: []`) to `public.eql_v3_text_ord_ore` is
/// rejected by the domain's non-empty-`ob` CHECK.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_text_empty")))]
async fn empty_string_rejected_by_text_ord_ore(pool: PgPool) -> Result<()> {
    let err = sqlx::query(
        "SELECT payload::public.eql_v3_text_ord_ore FROM fixtures.v3_text_empty WHERE id = 1",
    )
    .fetch_all(&pool)
    .await
    .expect_err("empty ORE term (ob: []) must violate the text_ord_ore CHECK");
    // Auto-generated domain constraint name is not pinned — only the SQLSTATE.
    assert_db_error(&err, "23514", None);
    Ok(())
}

/// The OPE-backed `public.eql_v3_text_ord` ACCEPTS the empty string: its `op` term is
/// well-formed (a single hex string), so no CHECK rejects it. This is the
/// behaviour change from flipping `_ord` off block-ORE — `text_ord_ore` above
/// still rejects the very same row.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_text_empty")))]
async fn empty_string_accepted_by_text_ord(pool: PgPool) -> Result<()> {
    let plaintext: String = sqlx::query_scalar(
        "SELECT plaintext FROM fixtures.v3_text_empty \
         WHERE id = 1 AND payload::public.eql_v3_text_ord IS NOT NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        plaintext, "",
        "the empty string must cast cleanly into the OPE-backed text_ord"
    );
    Ok(())
}

/// …and it orders FIRST. The `op` term for `""` is the bare domain-tag byte,
/// a proper prefix of every non-empty term, so native bytea comparison sorts it
/// below `"frank"` and `"zebra"` — exactly where the plaintext belongs. This is
/// the ordering the empty ORE term could not express.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_text_empty")))]
async fn empty_string_orders_first_under_text_ord(pool: PgPool) -> Result<()> {
    let plaintexts: Vec<String> = sqlx::query_scalar(
        "SELECT plaintext FROM fixtures.v3_text_empty \
         ORDER BY eql_v3.ord_term(payload::public.eql_v3_text_ord) ASC",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        plaintexts,
        vec!["".to_string(), "frank".to_string(), "zebra".to_string()],
        "the empty string must sort before every non-empty term"
    );
    Ok(())
}

/// The non-empty controls (`"frank"`, `"zebra"`) carry a real `op` term, so
/// they cast cleanly into `public.eql_v3_text_ord`.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_text_empty")))]
async fn non_empty_controls_accepted_by_text_ord(pool: PgPool) -> Result<()> {
    let plaintexts: Vec<String> = sqlx::query_scalar(
        "SELECT plaintext FROM fixtures.v3_text_empty \
         WHERE id IN (2, 3) AND payload::public.eql_v3_text_ord IS NOT NULL \
         ORDER BY id",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        plaintexts,
        vec!["frank".to_string(), "zebra".to_string()],
        "non-empty ordered text must cast cleanly into text_ord"
    );
    Ok(())
}

/// The non-empty controls carry a real `ob` array too, so they cast cleanly
/// into `public.eql_v3_text_ord_ore` — its CHECK rejects only the empty term, not
/// ordered text in general.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_text_empty")))]
async fn non_empty_controls_accepted_by_text_ord_ore(pool: PgPool) -> Result<()> {
    let plaintexts: Vec<String> = sqlx::query_scalar(
        "SELECT plaintext FROM fixtures.v3_text_empty \
         WHERE id IN (2, 3) AND payload::public.eql_v3_text_ord_ore IS NOT NULL \
         ORDER BY id",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        plaintexts,
        vec!["frank".to_string(), "zebra".to_string()],
        "non-empty ordered text must cast cleanly into text_ord_ore"
    );
    Ok(())
}

/// The controls order correctly via `ord_term` once cast into `text_ord`.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_text_empty")))]
async fn non_empty_controls_order_under_text_ord(pool: PgPool) -> Result<()> {
    let plaintexts: Vec<String> = sqlx::query_scalar(
        "SELECT plaintext FROM fixtures.v3_text_empty \
         WHERE id IN (2, 3) \
         ORDER BY eql_v3.ord_term(payload::public.eql_v3_text_ord) ASC",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        plaintexts,
        vec!["frank".to_string(), "zebra".to_string()],
        "frank must order before zebra"
    );
    Ok(())
}

/// The controls order correctly via `ord_term_ore` once cast into `text_ord_ore` —
/// the non-empty-`ob` CHECK does not disturb ordering of real values.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_text_empty")))]
async fn non_empty_controls_order_under_text_ord_ore(pool: PgPool) -> Result<()> {
    let plaintexts: Vec<String> = sqlx::query_scalar(
        "SELECT plaintext FROM fixtures.v3_text_empty \
         WHERE id IN (2, 3) \
         ORDER BY eql_v3.ord_term_ore(payload::public.eql_v3_text_ord_ore) ASC",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        plaintexts,
        vec!["frank".to_string(), "zebra".to_string()],
        "frank must order before zebra"
    );
    Ok(())
}
