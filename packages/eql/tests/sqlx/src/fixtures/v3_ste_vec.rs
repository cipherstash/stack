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
use super::ste_vec_selector;

/// The canonical fixture name → table `fixtures.v3_ste_vec`, script
/// `v3_ste_vec.sql`, SQLx ref `scripts("v3_ste_vec")`.
const NAME: &str = "v3_ste_vec";

/// The fixture table the selector helpers read.
pub const TABLE: &str = "fixtures.v3_ste_vec";

/// The rule that picks out the `$.hello` **string** leaf's `op` selector.
///
/// A string `op` term encrypts `1 + 8 * (bytes + 1)` plaintext bits (a type
/// tag, the collated bytes, a NUL terminator) to one byte per bit plus a
/// leading byte, so its hex length is `16 * bytes + 20`: one more character is
/// exactly [`ONE_CHARACTER_HEX`] more. `hello` is `"world-1"`..`"world-9"`
/// (equal length) plus the one-longer `"world-10"`, so `$.hello` is the only
/// op-carrying selector present on every row whose `op` takes exactly two
/// lengths, one character apart, with exactly one row at the longer length.
/// `$.number` and `$.large` are fixed-width numeric terms (one length), and
/// `$.empty` / `$.nested.deep` are constant. `$.accented` spans THREE lengths
/// (84 for the `café`/`cafe` collision pair, 180 for `accented-3..9`, 196 for
/// `accented-10`), and it is the two-lengths and one-character clauses that
/// exclude it: it does have exactly one row at its longest length, so the
/// one-row clause alone would not. Checking only "two lengths" is not enough
/// either: on a nine-row fixture `$.accented` takes exactly two.
///
/// The rule matters because the leaves are easy to confuse: an earlier pinned
/// copy of this selector named `$.number` while claiming `$.hello`, and survived
/// because the suites using it were equality-only (`number = i` and
/// `hello = "world-i"` induce the same equality partition). Only ORDER
/// separates them, which
/// `v3_json_entry_cross_type_tests::json_entry_text_ord_cross_type_matches_plaintext_ordering`
/// pins.
pub const HELLO_OP_RULE: &str = "op-carrying on every row, with exactly two distinct op lengths \
     one character (16 hex) apart and exactly one row at the longer \
     (world-1..9 vs world-10)";

/// Hex characters one more plaintext character adds to a string `op` term
/// (8 more plaintext bits, one ciphertext byte each).
const ONE_CHARACTER_HEX: i64 = 16;

/// The `$.hello` op selector of the LOADED `v3_ste_vec` fixture.
///
/// A SteVec selector is a keyed MAC over (workspace keyset, prefix, path), so
/// it differs per CipherStash workspace and is read from the fixture rather
/// than pinned (issue #1200). Fails, naming every candidate with its row count
/// and op lengths, unless exactly one selector satisfies [`HELLO_OP_RULE`].
pub async fn hello_op_selector<'e, E>(executor: E) -> Result<String>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let candidates = ste_vec_selector::op_selector_candidates(executor, TABLE).await?;
    ste_vec_selector::pick_one(TABLE, HELLO_OP_RULE, &candidates, is_hello_op)
}

/// [`HELLO_OP_RULE`] as a predicate.
fn is_hello_op(c: &ste_vec_selector::OpSelectorCandidate) -> bool {
    c.rows == c.total_rows
        && c.distinct_op_lengths == 2
        && c.max_op_length - c.min_op_length == ONE_CHARACTER_HEX
        && c.rows_at_max_op_length == 1
}

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

    /// The documents have the shape the `$.hello` rule and the leaf tests rely on.
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

    /// A candidate on every one of `rows` rows.
    fn leaf(
        selector: &str,
        rows: i64,
        lengths: i64,
        min: i64,
        max: i64,
        rows_at_max: i64,
    ) -> ste_vec_selector::OpSelectorCandidate {
        ste_vec_selector::test_candidate(selector, rows, rows, lengths, min, max, rows_at_max)
    }

    /// The `$.hello` rule against the leaf profile the fixture documents
    /// produce (op hex length `16 * chars + 20`): only `$.hello` is on every
    /// row with two op lengths one character apart, split 9/1.
    #[test]
    fn hello_op_rule_singles_out_the_two_length_leaf() {
        let n = ROW_COUNT;
        let candidates = [
            leaf("sel-empty", n, 1, 20, 20, n),
            leaf("sel-accented", n, 3, 84, 196, 1),
            leaf("sel-nested-deep", n, 1, 148, 148, n),
            leaf("sel-number", n, 1, 132, 132, n),
            leaf("sel-large", n, 1, 132, 132, n),
            leaf("sel-hello", n, 2, 132, 148, 1),
        ];
        let got = ste_vec_selector::pick_one(TABLE, HELLO_OP_RULE, &candidates, is_hello_op);
        assert_eq!(got.unwrap(), "sel-hello");

        // A two-length leaf missing from a row is not `$.hello`.
        let mut partial = candidates[5].clone();
        partial.rows = ROW_COUNT - 1;
        let err = ste_vec_selector::pick_one(TABLE, HELLO_OP_RULE, &[partial], is_hello_op)
            .unwrap_err()
            .to_string();
        assert!(err.contains("found 0"), "{err}");
    }

    /// Regression: the rule must enforce the documented `world-1..9` vs
    /// `world-10` split, not merely "two lengths on every row".
    ///
    /// Profile of the same documents with `ROW_COUNT = 9`, using the op hex
    /// length the 10-row profile above implies for a string leaf
    /// (`16 * chars + 20`: `""` = 20, `"cafe"` = 84, `"world-1"` = 132,
    /// `"constant"` = 148, `"accented-3"` = 180). `$.hello` collapses to ONE
    /// length (`world-1..9`), while `$.accented` drops `accented-10` and
    /// becomes exactly TWO lengths on every row (`café`/`cafe` = 84 vs
    /// `accented-3..9` = 180). A rule that only counts lengths silently picks
    /// `$.accented` as `$.hello`; the documented rule (two lengths one
    /// character apart) matches nothing and fails loudly.
    #[test]
    fn hello_op_rule_rejects_a_two_length_leaf_that_is_not_the_one_character_split() {
        let n = ROW_COUNT - 1;
        let candidates = [
            leaf("sel-empty", n, 1, 20, 20, n),
            leaf("sel-accented", n, 2, 84, 180, n - 2),
            leaf("sel-nested-deep", n, 1, 148, 148, n),
            leaf("sel-number", n, 1, 132, 132, n),
            leaf("sel-large", n, 1, 132, 132, n),
            leaf("sel-hello", n, 1, 132, 132, n),
        ];
        let got = ste_vec_selector::pick_one(TABLE, HELLO_OP_RULE, &candidates, is_hello_op);
        assert!(
            got.is_err(),
            "HELLO_OP_RULE ({HELLO_OP_RULE}) must not accept $.accented's \
             84/180 two-length profile as $.hello; picked {got:?}",
        );
    }

    /// The gap and split clauses of [`HELLO_OP_RULE`] are each load-bearing: a
    /// one-character pair NOT split 9/1, and a 9/1 split NOT one character
    /// apart, are both rejected, while the true profile is accepted. The split
    /// clause does not exclude the real `$.accented`, which also has one row at
    /// its longest length; its three lengths and their 112-hex spread do
    /// (`hello_op_rule_singles_out_the_two_length_leaf`).
    #[test]
    fn hello_op_rule_needs_both_the_one_character_gap_and_the_nine_one_split() {
        let n = ROW_COUNT;
        assert!(is_hello_op(&leaf("hello", n, 2, 132, 148, 1)));
        assert!(
            !is_hello_op(&leaf("even-split", n, 2, 132, 148, n / 2)),
            "a one-character pair split {}/{} is not world-1..9 vs world-10",
            n / 2,
            n - n / 2,
        );
        assert!(
            !is_hello_op(&leaf("two-characters", n, 2, 132, 164, 1)),
            "a 9/1 split two characters apart is not world-1..9 vs world-10",
        );
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
