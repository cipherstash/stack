//! The `v3_ste_vec` jsonb (SteVec document) fixture — the document analogue
//! of the scalar `eql_v3_<T>` fixtures, generated through the SAME
//! `FixtureSpec` machinery.
//!
//! A `serde_json::Value` is a first-class `EqlPlaintext` (see
//! `eql_plaintext.rs`), so the document fixture is just a
//! `FixtureSpec<serde_json::Value>` with the `IndexKind::SteVec` index and an
//! `public.eql_v3_json_search` generated `payload` column. `FixtureSpec::run` encrypts each
//! document through cipherstash-client into a SteVec payload, stages it, and
//! writes `tests/sqlx/fixtures/v3_ste_vec.sql` (gitignored — regenerated on
//! every `mise run test:sqlx`) with the identical
//! `fixtures.<name> (id, plaintext, payload)` shape the scalar fixtures use.
//!
//! Unlike the scalars there is no plaintext-vs-decrypt oracle column relation
//! to maintain; the `plaintext` column simply carries the source JSON document
//! for debuggability, exactly as the scalar fixtures carry the source scalar.

use anyhow::Result;
use serde_json::{json, Value};

use super::index_kind::IndexKind;
use super::spec::FixtureSpec;

/// The canonical fixture name → table `fixtures.v3_ste_vec`, script
/// `v3_ste_vec.sql`, SQLx ref `scripts("v3_ste_vec")`.
const NAME: &str = "v3_ste_vec";

/// The `$.hello` **string** leaf's `op` selector, pinned from the generated
/// fixture. THE one shared copy — every suite that names this selector imports
/// it from here (`eql_tests::fixtures::v3_ste_vec::SEL_HELLO_OP`), so a fixture
/// or keyset regeneration is a single edit. The selector is a deterministic
/// MAC of (column context, JSONPath), so it changes only on a keyset change,
/// not per regeneration.
///
/// History: an earlier copy of this constant named `$.number` — the fixture's
/// INTEGER leaf — while claiming `$.hello`, and survived because the suites
/// that used it were equality-only (the fixture pairs `number = i` with
/// `hello = "world-i"` 1:1, so both leaves induce identical equality
/// partitions). Only ORDER separates the leaves, which
/// `v3_json_entry_cross_type_tests::json_entry_text_ord_cross_type_matches_plaintext_ordering`
/// now pins — and duplication is exactly how the mis-pin escaped notice, hence
/// the single shared copy.
///
/// To re-derive rather than trust this hex: `ste_vec_query_selector(…, "$.hello")`
/// asks cipherstash-client directly (see the `proptest-e2e` suite
/// `v3_json_entry_query_operand_e2e_tests`, which needs no constant at all).
/// Creds-free, the fixture's term LENGTHS distinguish the two leaves: a string
/// `op` is `8 * (len + 1) + 1` bits, so `$.hello` is 132 hex chars for
/// `"world-1"`..`"world-9"` and 148 for `"world-10"`, while `$.number` is a
/// fixed-width 65-bit number term — 132 on every row.
pub const SEL_HELLO_OP: &str = "b325a0c77b130af97b805c12ff853ab3";

/// The canonical `payload` column type — the `public.eql_v3_json_search` DOMAIN, so the
/// domain CHECK runs when the fixture loads.
const PAYLOAD_TYPE: &str = "public.eql_v3_json_search";

/// Number of fixture rows. Ten matches the historical fixture and gives the
/// harness's containment / index tests a non-trivial set.
const ROW_COUNT: i64 = 10;

/// The ten plaintext documents — the source of truth for the fixture.
///
/// `hello` VARIES across all rows (10 distinct values → 10 distinct `$.hello`
/// `op` leaves and value selectors) so exact containment can isolate one row
/// and the D11 OPE-btree test has real discrimination. `number` also
/// varies (its own `$.number` op). `accented` and `large` carry the two known
/// collision pairs from the retired OPE-equality path, while `empty` pins the
/// genuine empty-string leaf against the value-entry sentinel. `nested` is a
/// constant object so its structural and value selectors are stable across
/// all rows.
fn documents() -> Vec<Value> {
    (1..=ROW_COUNT)
        .map(|i| {
            json!({
                "hello": format!("world-{i}"),
                "number": i,
                "accented": match i {
                    1 => "café".to_string(),
                    2 => "cafe".to_string(),
                    _ => format!("accented-{i}"),
                },
                "large": match i {
                    1 => 9_007_199_254_740_993_i64,
                    2 => 9_007_199_254_740_992_i64,
                    _ => i,
                },
                "empty": "",
                "nested": { "deep": "constant" },
            })
        })
        .collect()
}

/// Generate `tests/sqlx/fixtures/v3_ste_vec.sql` by encrypting the plaintext
/// documents through the shared `FixtureSpec` pipeline (connection-from-env,
/// stage → `format('%L')` render → drop-on-error teardown → file write — the
/// same code path the scalar fixtures use). The document set lives for the
/// duration of the call; the spec borrows it and `run()` completes before
/// return.
pub async fn generate() -> Result<()> {
    let docs = documents();
    FixtureSpec::new(NAME)
        .with_index(IndexKind::SteVec)
        .with_column_type(PAYLOAD_TYPE)
        .with_values(&docs)
        .run()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documents_are_ten_rows_with_distinct_hello_and_varying_number() {
        let docs = documents();
        assert_eq!(docs.len(), 10);
        // `$.hello` must be DISTINCT per row (oracle discrimination — Risk #0).
        let hellos: std::collections::HashSet<&str> =
            docs.iter().map(|d| d["hello"].as_str().unwrap()).collect();
        assert_eq!(hellos.len(), 10, "$.hello must be distinct across all rows");
        // `nested` is constant, and every row carries a genuine empty-string
        // leaf so its path entry cannot be confused with a value-entry sentinel.
        assert!(docs
            .iter()
            .all(|d| d["nested"] == json!({ "deep": "constant" })));
        assert!(docs.iter().all(|d| d["empty"] == json!("")));
        let numbers: Vec<i64> = docs.iter().map(|d| d["number"].as_i64().unwrap()).collect();
        assert_eq!(numbers, (1..=10).collect::<Vec<_>>());
        assert_eq!(docs[0]["accented"], json!("café"));
        assert_eq!(docs[1]["accented"], json!("cafe"));
        assert_eq!(docs[0]["large"], json!(9_007_199_254_740_993_i64));
        assert_eq!(docs[1]["large"], json!(9_007_199_254_740_992_i64));
    }

    #[test]
    fn spec_builds_a_json_document_fixture() {
        let docs = documents();
        let spec = FixtureSpec::new(NAME)
            .with_index(IndexKind::SteVec)
            .with_column_type(PAYLOAD_TYPE)
            .with_values(&docs);
        assert_eq!(spec.fixture_table(), "fixtures.v3_ste_vec");
        assert_eq!(spec.column_type().as_str(), "public.eql_v3_json_search");
        assert_eq!(spec.indexes(), &[IndexKind::SteVec]);
        assert!(spec.check_complete().is_ok());
    }
}
