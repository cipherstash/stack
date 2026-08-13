#![cfg(feature = "proptest-e2e")]
//! End-to-end conformance for exact field EQUALITY on encrypted JSON,
//! with the query needle encrypted FRESH through cipherstash-client rather than
//! reconstructed from the stored document.
//!
//! ## Why this suite exists
//!
//! `v3_jsonb_tests` proves value-selector containment by lifting a selector out of
//! a fixture row and searching for it — the answer is extracted from the data it is
//! then checked against, so no client-side encryption bug can fail it. Here the
//! needle is derived INDEPENDENTLY: a `(path, value)` goes through ZeroKMS at test
//! time and never touches the stored rows. Two independent encryptions of the same
//! `(path, value)` must produce byte-equal VALUE SELECTORS that containment equates
//! — the actual runtime equality contract.
//!
//! ## What scopes a query
//!
//! Exact field EQUALITY is document containment: `col @> $1::eql_v3.query_json`,
//! where the needle carries a VALUE selector `SEL(tag ‖ path ‖ canonical(value))`
//! whose presence in the stored document is the exact match — path AND value baked
//! into one selector, injective (so `"café"` ≠ `"cafe"`, `2^53` ≠ `2^53+1`). The
//! client derives it via `ste_vec_query_value_selector`; nothing is pinned as a
//! constant, so the suite cannot drift onto the wrong field/value.
//!
//! RANGE operands are also derived independently here. The fixture-only suites
//! prove the SQL oracle; these tests additionally prove that a freshly encrypted
//! selector and `op` operand correspond to independently encrypted stored rows.

use anyhow::Result;
use cipherstash_client::encryption::Plaintext;
use serde_json::{json, Value};
use sqlx::PgPool;

use eql_tests::fixtures::cipherstash::{
    decrypt_ste_vec_entries_fallible, encrypt_store, ste_vec_query_selector, ste_vec_query_term,
    ste_vec_query_value_selector, PAYLOAD_COLUMN,
};
use eql_tests::fixtures::index_kind::IndexKind;
use eql_tests::scalar_domains::F8;

/// The identifier the `v3_ste_vec` fixture rows were encrypted under
/// (`FixtureSpec::working_table` → `_fixture_<name>`). A value selector is a
/// deterministic MAC of (keyset, column, path, canonical(value)); the identifier's
/// table/column keep the needle honest about the column it targets.
const FIXTURE_TABLE: &str = "_fixture_v3_ste_vec";

/// Assert a freshly-derived needle contains one plausible value selector, so a
/// malformed or empty operand cannot make containment vacuously match nothing.
fn assert_value_selector_needle(needle: &serde_json::Value, what: &str) {
    let sel = needle
        .get("sv")
        .and_then(serde_json::Value::as_array)
        .and_then(|entries| entries.first())
        .and_then(|entry| entry.get("s"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("{what} must contain one value selector; got {needle}"));
    assert!(
        !sel.is_empty()
            && sel.len().is_multiple_of(2)
            && sel.bytes().all(|b| b.is_ascii_hexdigit()),
        "{what} must be a non-empty even-length hex string; got {sel:?}"
    );
}

fn value_selector(needle: &serde_json::Value) -> &str {
    needle["sv"][0]["s"]
        .as_str()
        .expect("validated value-selector needle has one string selector")
}

fn v3_operand(op_hex: &str, hm_hex: Option<&str>) -> String {
    let mut obj = serde_json::Map::new();
    obj.insert("v".into(), json!(3));
    obj.insert("i".into(), json!({"t": FIXTURE_TABLE, "c": PAYLOAD_COLUMN}));
    obj.insert("op".into(), json!(op_hex));
    if let Some(hm) = hm_hex {
        obj.insert("hm".into(), json!(hm));
    }
    Value::Object(obj).to_string()
}

fn assert_hex_term(term: &str, what: &str) {
    assert!(
        !term.is_empty()
            && term.len().is_multiple_of(2)
            && term.bytes().all(|b| b.is_ascii_hexdigit()),
        "{what} must be a non-empty even-length hex string; got {term:?}"
    );
}

/// Rows whose stored document CONTAINS the given client-generated value-selector
/// needle — the exact field-equality path (`col @> $1::eql_v3.query_json`).
async fn contains_ids(pool: &PgPool, needle: &serde_json::Value) -> Result<Vec<i64>> {
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM fixtures.v3_ste_vec \
         WHERE payload @> $1::jsonb::eql_v3.query_json ORDER BY id",
    )
    .bind(needle.to_string())
    .fetch_all(pool)
    .await?;
    Ok(ids)
}

/// Plaintext oracle over the fixture's own `plaintext` jsonb column.
async fn oracle_ids(pool: &PgPool, predicate: &str) -> Result<Vec<i64>> {
    let ids: Vec<i64> = sqlx::query_scalar(&format!(
        "SELECT id FROM fixtures.v3_ste_vec WHERE {predicate} ORDER BY id"
    ))
    .fetch_all(pool)
    .await?;
    Ok(ids)
}

async fn assert_selector_resolves(pool: &PgPool, selector: &str, path: &str) -> Result<()> {
    let resolved: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM fixtures.v3_ste_vec \
         WHERE (payload -> $1::text) IS NOT NULL",
    )
    .bind(selector)
    .fetch_one(pool)
    .await?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM fixtures.v3_ste_vec")
        .fetch_one(pool)
        .await?;
    assert_eq!(
        resolved, total,
        "the client-derived selector for {path} must resolve on every fixture row"
    );
    Ok(())
}

async fn matching_ids(
    pool: &PgPool,
    selector: &str,
    operand: &str,
    op: &str,
    operand_ty: &str,
) -> Result<Vec<i64>> {
    Ok(sqlx::query_scalar(&format!(
        "SELECT id FROM fixtures.v3_ste_vec \
         WHERE (payload -> $1::text)::public.eql_v3_json_entry {op} \
               $2::jsonb::{operand_ty} ORDER BY id"
    ))
    .bind(selector)
    .bind(operand)
    .fetch_all(pool)
    .await?)
}

/// #1 — NUMERIC leaf (`$.number`, values 1..=10). A FRESH value selector for
/// `$.number = 2` must be contained in exactly row 2's independently-encrypted
/// document, and no other — the two-independent-encryptions proof for EQUALITY.
///
/// Numbers canonicalise (jsonb numeric equality), so `json!(2)` matches the stored
/// `2` without the float-vs-int hazard the `op` term has — the value selector keys
/// on `canonical(value)`, not on an orderable f64 encoding.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn fresh_numeric_value_selector_equality(pool: PgPool) -> Result<()> {
    let eq_oracle = oracle_ids(&pool, "(plaintext ->> 'number')::int = 2").await?;
    assert_eq!(
        eq_oracle,
        vec![2],
        "fixture precondition: exactly row 2 has $.number = 2"
    );

    let vsel =
        ste_vec_query_value_selector(FIXTURE_TABLE, PAYLOAD_COLUMN, "$.number", &json!(2)).await?;
    assert_value_selector_needle(&vsel, "the fresh $.number=2 value selector");
    let contained = contains_ids(&pool, &vsel).await?;
    assert_eq!(
        contained, eq_oracle,
        "a FRESHLY derived value selector for `$.number = 2` must be contained in exactly \
         row 2's independently-encrypted document, and no other"
    );

    // Negative: a value NOT in the fixture matches nothing — so the positive above
    // is a real, injective match, not a vacuous always-contain.
    let vsel_absent =
        ste_vec_query_value_selector(FIXTURE_TABLE, PAYLOAD_COLUMN, "$.number", &json!(999))
            .await?;
    let absent = contains_ids(&pool, &vsel_absent).await?;
    assert!(
        absent.is_empty(),
        "a value selector for an absent value (`$.number = 999`) must match no rows; got {absent:?}"
    );
    Ok(())
}

/// #2 — TEXT leaf (`$.hello`, `"world-1"`..`"world-10"`). Exact TEXT equality — the
/// exact-match capability the collating `op` term could not provide
/// (`"café"` == `"cafe"` under `op`, but the value selector is injective). A FRESH
/// value selector for `$.hello = "world-2"` must be contained in exactly row 2.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn fresh_text_value_selector_equality(pool: PgPool) -> Result<()> {
    let eq_oracle = oracle_ids(&pool, "plaintext ->> 'hello' = 'world-2'").await?;
    assert_eq!(
        eq_oracle,
        vec![2],
        "fixture precondition: exactly row 2 has $.hello = \"world-2\""
    );

    let vsel =
        ste_vec_query_value_selector(FIXTURE_TABLE, PAYLOAD_COLUMN, "$.hello", &json!("world-2"))
            .await?;
    assert_value_selector_needle(&vsel, "the fresh $.hello=\"world-2\" value selector");
    let contained = contains_ids(&pool, &vsel).await?;
    assert_eq!(
        contained, eq_oracle,
        "a FRESHLY derived value selector for `$.hello = \"world-2\"` must be contained in \
         exactly row 2 — exact text equality the collating `op` term cannot provide"
    );

    // Negative: a string NOT in the fixture matches nothing.
    let vsel_absent = ste_vec_query_value_selector(
        FIXTURE_TABLE,
        PAYLOAD_COLUMN,
        "$.hello",
        &json!("world-999"),
    )
    .await?;
    let absent = contains_ids(&pool, &vsel_absent).await?;
    assert!(
        absent.is_empty(),
        "a value selector for an absent value (`$.hello = \"world-999\"`) must match no rows; got {absent:?}"
    );
    Ok(())
}

/// The two known collision classes from the retired `op`-equality path must be
/// distinct under value-selector containment, not merely mentioned in prose.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn fresh_value_selectors_distinguish_legacy_ope_collisions(pool: PgPool) -> Result<()> {
    let accented =
        ste_vec_query_value_selector(FIXTURE_TABLE, PAYLOAD_COLUMN, "$.accented", &json!("café"))
            .await?;
    let ascii =
        ste_vec_query_value_selector(FIXTURE_TABLE, PAYLOAD_COLUMN, "$.accented", &json!("cafe"))
            .await?;
    assert_ne!(
        value_selector(&accented),
        value_selector(&ascii),
        "value selectors must distinguish café from cafe even though their OPE terms collide"
    );
    assert_eq!(contains_ids(&pool, &accented).await?, vec![1]);
    assert_eq!(contains_ids(&pool, &ascii).await?, vec![2]);

    let above_f64_precision = ste_vec_query_value_selector(
        FIXTURE_TABLE,
        PAYLOAD_COLUMN,
        "$.large",
        &json!(9_007_199_254_740_993_i64),
    )
    .await?;
    let f64_boundary = ste_vec_query_value_selector(
        FIXTURE_TABLE,
        PAYLOAD_COLUMN,
        "$.large",
        &json!(9_007_199_254_740_992_i64),
    )
    .await?;
    assert_ne!(
        value_selector(&above_f64_precision),
        value_selector(&f64_boundary),
        "value selectors must preserve adjacent integers above f64's exact range"
    );
    assert_eq!(contains_ids(&pool, &above_f64_precision).await?, vec![1]);
    assert_eq!(contains_ids(&pool, &f64_boundary).await?, vec![2]);
    Ok(())
}

/// A fresh numeric `op` operand and path selector must reproduce the plaintext
/// range oracle. JSON numbers use the client's floating-point SteVec encoding,
/// so the operand is intentionally encrypted as `F8`.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn fresh_numeric_range_operand_matches_plaintext_oracle(pool: PgPool) -> Result<()> {
    let selector = ste_vec_query_selector(FIXTURE_TABLE, PAYLOAD_COLUMN, "$.number").await?;
    assert_selector_resolves(&pool, &selector, "$.number").await?;
    let term = ste_vec_query_term(FIXTURE_TABLE, PAYLOAD_COLUMN, &F8(2.0)).await?;
    assert_hex_term(&term, "the fresh $.number=2 range term");
    let operand = v3_operand(&term, None);

    let actual = matching_ids(&pool, &selector, &operand, ">", "eql_v3.query_integer_ord").await?;
    let expected = oracle_ids(&pool, "(plaintext ->> 'number')::int > 2").await?;
    assert!(!expected.is_empty() && expected.len() < 10);
    assert_eq!(actual, expected);
    Ok(())
}

/// A fresh text `op` operand must follow string order. `world-10` is the
/// discriminating row: it sorts below `world-2` lexically but above it
/// numerically.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn fresh_text_range_operand_matches_plaintext_oracle(pool: PgPool) -> Result<()> {
    let selector = ste_vec_query_selector(FIXTURE_TABLE, PAYLOAD_COLUMN, "$.hello").await?;
    assert_selector_resolves(&pool, &selector, "$.hello").await?;
    let needle = "world-2".to_owned();
    let term = ste_vec_query_term(FIXTURE_TABLE, PAYLOAD_COLUMN, &needle).await?;
    assert_hex_term(&term, "the fresh $.hello=world-2 range term");

    // query_text_ord also requires a real hm term for its scalar-column
    // capability. It is shape-only on the json_entry range path.
    let encrypted = encrypt_store(
        FIXTURE_TABLE,
        PAYLOAD_COLUMN,
        &[needle],
        &[IndexKind::Unique],
    )
    .await?;
    let hm = encrypted[0]["hm"]
        .as_str()
        .expect("unique-indexed text operand carries hm");
    let operand = v3_operand(&term, Some(hm));
    let actual = matching_ids(&pool, &selector, &operand, ">", "eql_v3.query_text_ord").await?;
    let expected = oracle_ids(&pool, "plaintext ->> 'hello' > 'world-2'").await?;
    assert!(!expected.is_empty() && !expected.contains(&10));
    assert_eq!(actual, expected);
    Ok(())
}

/// SQL extraction must graft the document header onto each entry, and the
/// selector must authenticate the ciphertext. Swapping ciphertexts between the
/// genuine empty-string path entry and its value-selector sentinel must fail.
#[sqlx::test(fixtures(path = "../fixtures", scripts("v3_ste_vec")))]
async fn extracted_entry_decrypts_but_ciphertext_graft_fails(pool: PgPool) -> Result<()> {
    let path_selector = ste_vec_query_selector(FIXTURE_TABLE, PAYLOAD_COLUMN, "$.empty").await?;
    let value_needle =
        ste_vec_query_value_selector(FIXTURE_TABLE, PAYLOAD_COLUMN, "$.empty", &json!("")).await?;
    let value_selector = value_selector(&value_needle);

    let path_entry: Value = sqlx::query_scalar(
        "SELECT (payload -> $1::text)::jsonb FROM fixtures.v3_ste_vec WHERE id = 1",
    )
    .bind(&path_selector)
    .fetch_one(&pool)
    .await?;
    let value_entry: Value = sqlx::query_scalar(
        "SELECT (payload -> $1::text)::jsonb FROM fixtures.v3_ste_vec WHERE id = 1",
    )
    .bind(value_selector)
    .fetch_one(&pool)
    .await?;
    let mut grafted = path_entry.clone();
    grafted["c"] = value_entry["c"].clone();

    let results = decrypt_ste_vec_entries_fallible(&[path_entry, value_entry, grafted]).await?;
    let path_plaintext = Plaintext::from_slice(results[0].as_ref().expect("path entry decrypts"))?;
    assert!(matches!(
        path_plaintext,
        Plaintext::Json(Some(Value::String(ref value))) if value.is_empty()
    ));
    let sentinel = results[1].as_ref().expect("value entry decrypts");
    assert!(
        Plaintext::from_slice(sentinel).is_err(),
        "the value-entry sentinel must not parse as a genuine empty-string plaintext"
    );
    assert_ne!(
        results[0].as_ref().unwrap(),
        sentinel,
        "a genuine empty string and the value-entry sentinel must remain distinct"
    );
    assert!(
        results[2].is_err(),
        "a ciphertext grafted onto a different selector must fail authentication"
    );
    Ok(())
}
