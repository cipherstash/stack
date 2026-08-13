//! Parse REAL generated SteVec ciphertext rows into the hand-written bindings —
//! the one test that ties eql-bindings to real cipherstash crypto AND to the
//! hand-written src/v3/jsonb/types.sql domain CHECK simultaneously.
//!
//! The fixture (`fixtures.v3_ste_vec`, column `payload public.eql_v3_json_search`) is GENERATED
//! by encrypting JSON documents through cipherstash-client's SteVec pipeline
//! (`mise run fixture:generate:all`), so this exercises the bindings against the
//! same wire shape the domain CHECK (`is_valid_ste_vec_document_payload`)
//! validated at INSERT — not a hand-written literal.

use eql_bindings::v3::json::{SteVecDocument, SteVecEntry, SteVecQuery};
use sqlx::PgPool;

#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn real_ste_vec_row_parses_into_document_and_entries(pool: PgPool) -> anyhow::Result<()> {
    // Whole document parses (real ciphertext, real SQL-validated shape).
    let doc_json: serde_json::Value =
        sqlx::query_scalar("SELECT payload::jsonb FROM fixtures.v3_ste_vec ORDER BY id LIMIT 1")
            .fetch_one(&pool)
            .await?;
    let doc: SteVecDocument = serde_json::from_value(doc_json)?;
    assert!(
        !doc.sv.is_empty(),
        "a real SteVec document must have sv entries"
    );

    // Every real sv element across the whole fixture parses as a (lax) entry with
    // a real term. Deterministic ordering (id, then selector) so the sample is
    // stable; no LIMIT so both leaf kinds are guaranteed present.
    let elems: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT elem FROM fixtures.v3_ste_vec, \
         jsonb_array_elements(payload::jsonb -> 'sv') AS elem \
         ORDER BY id, elem ->> 's'",
    )
    .fetch_all(&pool)
    .await?;
    assert!(!elems.is_empty());

    // Assert BOTH entry kinds actually occur in real data — not merely that
    // entries parse. A real document mixes term-less entries (value entries,
    // non-orderable path entries — exact matching is selector presence) and
    // ordered path entries (`op`, CLLW-OPE); a fixture or binding regression
    // that collapsed one kind would slip past a bare "parses" check. `hm` is
    // retired and must never appear.
    let (mut saw_termless, mut saw_op) = (false, false);
    for e in elems {
        assert!(
            e.get("hm").is_none(),
            "hm is retired and must not appear on any real entry"
        );
        // Fails if the real wire shape drifts from the bindings.
        let entry: SteVecEntry = serde_json::from_value(e)?;
        if entry.op.is_some() {
            saw_op = true;
        } else {
            saw_termless = true;
        }
    }
    assert!(
        saw_termless,
        "real SteVec entries must include term-less (value / structural) entries"
    );
    assert!(
        saw_op,
        "real SteVec entries must include an op (CLLW-OPE) term"
    );

    Ok(())
}

#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn real_ste_vec_query_parses_into_bindings(pool: PgPool) -> anyhow::Result<()> {
    // `eql_v3.to_ste_vec_query` turns an encrypted document into a containment
    // needle (`eql_v3.query_json`), the shape a caller builds a `@>` / `<@`
    // query from. Parse a REAL one into `SteVecQuery` (and, transitively, its
    // `SteVecQueryEntry` elements), tying those two bindings to real crypto and
    // the hand-written `is_valid_ste_vec_query_payload` CHECK — the document/entry
    // test above covers the other two SteVec bindings.
    let query_json: serde_json::Value = sqlx::query_scalar(
        "SELECT eql_v3.to_ste_vec_query(payload)::jsonb \
         FROM fixtures.v3_ste_vec ORDER BY id LIMIT 1",
    )
    .fetch_one(&pool)
    .await?;
    let query: SteVecQuery = serde_json::from_value(query_json)?;
    assert!(
        !query.sv.is_empty(),
        "a real SteVec query must have sv entries"
    );
    // The canonical SQL projection is selector-only.
    assert!(query.sv.iter().all(|entry| entry.op.is_none()));
    Ok(())
}
