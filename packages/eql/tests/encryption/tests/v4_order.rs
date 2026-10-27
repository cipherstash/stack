//! The OPE-ordered EQL v4 types Stack Encrypt produces: `IntegerOrd`,
//! `BigintOrd`, `RealOrd`, `DoubleOrd`, `TextOrd`, `DateOrd`,
//! `TimestampOrd`, `NumericOrd` and their `OrdOpe` twins.
//!
//! EQL compares the `op` term as `bytea` after decoding its hex, which is
//! lexicographic byte order. So the stored terms must sort as ADR-0002's
//! order keys sort: integers by value, floats as PostgreSQL's `float8` sorts
//! them (`-0.0` ties `0.0`, every NaN is one value after `+Infinity`), text
//! by its fold (case and accents folded, Unicode 16), dates by day,
//! timestamps by the microsecond and decimals by value. These tests hold
//! that through both entry points, pin the query twins to the stored terms,
//! and, against an EQL v4 database, check that `<`, `<=`, `>`, `>=`, `=` and
//! `ORDER BY` find exactly the rows the plaintexts say.

mod common;

use eql_bindings::encryption::targets::{self as targets};
use eql_bindings::v4::{bigint, double, integer, real, text};
use eql_bindings::Identifier;
use stack_encrypt::dynamic::ValueFrame;
use stack_encrypt::value::{Date, Decimal, Timestamp};
use stack_encrypt::{Encrypt, Label, NonEmpty};

fn frame<T: Encrypt>(value: T) -> ValueFrame {
    ValueFrame::of(value).unwrap()
}

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("rankings", "level").unwrap()
}

fn label() -> Label {
    Label::new(["rankings", "level"]).unwrap()
}

/// Every type this file covers, with the plaintext kind it takes.
const ORDERED: &[&str] = &[
    "IntegerOrd",
    "IntegerOrdOpe",
    "SmallintOrd",
    "SmallintOrdOpe",
    "BigintOrd",
    "BigintOrdOpe",
    "RealOrd",
    "RealOrdOpe",
    "DoubleOrd",
    "DoubleOrdOpe",
    "TextOrd",
    "TextOrdOpe",
    "DateOrd",
    "DateOrdOpe",
    "TimestampOrd",
    "TimestampOrdOpe",
    "NumericOrd",
    "NumericOrdOpe",
];

/// The stored JSON the named type writes for `value`, through the by-name
/// dispatch a Go plan reaches.
async fn stored(
    keyset: &stack_encrypt::KeysetCipher<'_, common::Observed>,
    name: &str,
    value: ValueFrame,
) -> serde_json::Value {
    let bytes = targets::encrypt(name, keyset, &label(), value)
        .unwrap()
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The query operand the named type's twin derives for `value`.
async fn query(
    keyset: &stack_encrypt::KeysetCipher<'_, common::Observed>,
    name: &str,
    value: ValueFrame,
) -> serde_json::Value {
    let bytes = targets::query(name, &common::index_of(name), keyset, &label(), value)
        .unwrap()
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The `op` term of a stored value or query, as its hex. Lower-case hex
/// sorts as the bytes it encodes (each byte is two digits, and `0`–`9` sort
/// before `a`–`f`), so comparing the strings is comparing the `bytea` EQL
/// compares.
fn op(value: &serde_json::Value) -> &str {
    value["op"].as_str().expect("an ordered value carries op")
}

/// Every producible `Ord` and `OrdOpe` type is in [`ORDERED`] and the other
/// way round: a type that becomes producible is covered here or fails.
/// `TextSearch` carries an OPE term too; its query carries one term per
/// operator, and `v4_text_search.rs` covers it.
#[test]
fn the_ordered_producible_types_are_these() {
    let mut ordered: Vec<&str> = targets::targets()
        .iter()
        .filter(|t| t.producible && t.indexes.contains(&"ope"))
        .map(|t| t.name)
        .filter(|name| *name != "TextSearch")
        .collect();
    ordered.sort_unstable();
    let mut expected = ORDERED.to_vec();
    expected.sort_unstable();
    assert_eq!(ordered, expected);
    // No type carries a CLLW ORE term: EQL's ORE term is block ORE.
    assert!(targets::targets()
        .iter()
        .filter(|t| t.producible)
        .all(|t| !t.indexes.contains(&"ore")));
}

/// The stored keys of each type: the ciphertext and the OPE term, and the
/// equality term too for text, whose order term folds case and so cannot
/// answer `=`.
#[tokio::test]
async fn each_ordered_type_stores_its_catalog_terms() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for name in ORDERED {
        let value = if name.starts_with("Text") {
            frame("alice")
        } else if name.starts_with("Integer") {
            frame::<i32>(7)
        } else if name.starts_with("Smallint") {
            frame::<i16>(7)
        } else if name.starts_with("Bigint") {
            frame::<i64>(7)
        } else if name.starts_with("Real") {
            frame::<f32>(7.0)
        } else if name.starts_with("Date") {
            frame(Date::from_days_since_epoch(7).unwrap())
        } else if name.starts_with("Timestamp") {
            frame(Timestamp::new(7, 8).unwrap())
        } else if name.starts_with("Numeric") {
            frame(Decimal::new(750, 2).unwrap())
        } else {
            frame::<f64>(7.0)
        };
        let json = stored(&keyset, name, value.clone()).await;
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        let expected: &[&str] = if name.starts_with("Text") {
            &["c", "hm", "i", "op", "v"]
        } else {
            &["c", "i", "op", "v"]
        };
        assert_eq!(keys, expected, "{name}");
        assert_eq!(json["v"], 4, "{name}");

        let q = query(&keyset, name, value.clone()).await;
        assert!(
            q.get("c").is_none(),
            "{name}: a query carries no ciphertext"
        );
        assert_eq!(op(&q), op(&json), "{name}: the query's op is the stored op");
        assert_eq!(q["hm"], json["hm"], "{name}: and so is its hm, if any");

        let opened = targets::decrypt(name, &cipher, &label(), json.to_string().as_bytes())
            .unwrap()
            .await
            .unwrap();
        assert_eq!(opened.risky_ref(), value.risky_ref(), "{name}: opens back");
    }
}

/// Assert that the terms `values` store under `name` sort as `expected`
/// says: each entry's group is its rank, so equal groups must store one
/// term and a lower group a lower term.
async fn sorts_as(
    keyset: &stack_encrypt::KeysetCipher<'_, common::Observed>,
    name: &str,
    values: Vec<(usize, ValueFrame, &str)>,
) {
    let mut terms = Vec::new();
    for (group, value, shown) in values {
        let json = stored(keyset, name, value).await;
        terms.push((group, op(&json).to_owned(), shown));
    }
    for a in &terms {
        for b in &terms {
            assert_eq!(
                a.1.cmp(&b.1),
                a.0.cmp(&b.0),
                "{name}: {} vs {}: the terms must order as the order keys do",
                a.2,
                b.2
            );
        }
    }
}

#[tokio::test]
async fn integer_terms_order_by_value() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let ints = [i32::MIN, -70_000, -1, 0, 1, 255, 256, 70_000, i32::MAX];
    for name in ["IntegerOrd", "IntegerOrdOpe"] {
        let values = ints
            .iter()
            .enumerate()
            .map(|(rank, v)| (rank, frame(*v), "an i32"))
            .collect();
        sorts_as(&keyset, name, values).await;
    }
    let smalls = [i16::MIN, -300, -1, 0, 1, 255, 256, i16::MAX];
    for name in ["SmallintOrd", "SmallintOrdOpe"] {
        let values = smalls
            .iter()
            .enumerate()
            .map(|(rank, v)| (rank, frame(*v), "an i16"))
            .collect();
        sorts_as(&keyset, name, values).await;
    }
    let bigs = [i64::MIN, -(1 << 40), -1, 0, 1, 1 << 40, i64::MAX];
    for name in ["BigintOrd", "BigintOrdOpe"] {
        let values = bigs
            .iter()
            .enumerate()
            .map(|(rank, v)| (rank, frame(*v), "an i64"))
            .collect();
        sorts_as(&keyset, name, values).await;
    }
}

/// A date orders by day, a timestamp by the microsecond (floored, so a
/// nanosecond before the epoch ties the microsecond before it), and a
/// decimal by value whatever its scale.
#[tokio::test]
async fn date_timestamp_and_decimal_terms_order_by_value() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let day = |days| frame(Date::from_days_since_epoch(days).unwrap());
    for name in ["DateOrd", "DateOrdOpe"] {
        let values = vec![
            (0, day(-719_162), "0001-01-01"),
            (1, day(-1), "1969-12-31"),
            (2, day(0), "1970-01-01"),
            (3, day(19_782), "2024-02-29"),
        ];
        sorts_as(&keyset, name, values).await;
    }
    let at = |seconds, nanos| frame(Timestamp::new(seconds, nanos).unwrap());
    for name in ["TimestampOrd", "TimestampOrdOpe"] {
        let values = vec![
            (0, at(-1, 999_999_000), "-1us"),
            (0, at(-1, 999_999_999), "-1ns, floored"),
            (1, at(0, 0), "the epoch"),
            (1, at(0, 999), "999ns"),
            (2, at(0, 1_000), "1us"),
            (3, at(1_700_000_000, 0), "2023"),
        ];
        sorts_as(&keyset, name, values).await;
    }
    let number = |mantissa, scale| frame(Decimal::new(mantissa, scale).unwrap());
    for name in ["NumericOrd", "NumericOrdOpe"] {
        let values = vec![
            (0, number(-1_000, 0), "-1000"),
            (1, number(-15, 1), "-1.5"),
            (2, number(0, 0), "0"),
            (2, number(0, 3), "0.000"),
            (3, number(15, 1), "1.5"),
            (3, number(150, 2), "1.50"),
            (4, number(2, 0), "2"),
        ];
        sorts_as(&keyset, name, values).await;
    }
}

#[tokio::test]
async fn float_terms_order_as_postgres_float8_does() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for name in ["DoubleOrd", "DoubleOrdOpe"] {
        let values = vec![
            (0, frame(f64::NEG_INFINITY), "-inf"),
            (1, frame(f64::MIN), "MIN"),
            (2, frame(-1.5f64), "-1.5"),
            (3, frame(-0.0f64), "-0.0"),
            (3, frame(0.0f64), "0.0"),
            (4, frame(f64::MIN_POSITIVE), "MIN_POSITIVE"),
            (5, frame(1.5f64), "1.5"),
            (6, frame(f64::MAX), "MAX"),
            (7, frame(f64::INFINITY), "+inf"),
            (8, frame(f64::NAN), "NaN"),
            (
                8,
                frame(f64::from_bits(0xfff8_0000_0000_beef)),
                "another NaN",
            ),
        ];
        sorts_as(&keyset, name, values).await;
    }
    for name in ["RealOrd", "RealOrdOpe"] {
        let values = vec![
            (0, frame(f32::NEG_INFINITY), "-inf"),
            (1, frame(f32::MIN), "MIN"),
            (2, frame(-1.5f32), "-1.5"),
            (3, frame(-0.0f32), "-0.0"),
            (3, frame(0.0f32), "0.0"),
            (4, frame(1.5f32), "1.5"),
            (5, frame(f32::MAX), "MAX"),
            (6, frame(f32::INFINITY), "+inf"),
            (7, frame(f32::NAN), "NaN"),
            (7, frame(f32::from_bits(0xffc0_1234)), "another NaN"),
        ];
        sorts_as(&keyset, name, values).await;
    }
}

/// A `float32` orders as the `float64` it widens to, so a `RealOrd` and a
/// `DoubleOrd` column under one name store one term for one value.
#[tokio::test]
async fn a_real_orders_as_the_double_it_widens_to() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for v in [-1.5f32, 0.0, 1.5, f32::INFINITY, f32::NAN] {
        let real = stored(&keyset, "RealOrd", frame(v)).await;
        let double = stored(&keyset, "DoubleOrd", frame(f64::from(v))).await;
        assert_eq!(op(&real), op(&double), "{v}");
    }
}

/// Text orders by its fold: case and accents tie, `é` sorts with `e`, and
/// `alice` comes before `Zoe`. A prefix sorts first.
#[tokio::test]
async fn text_terms_order_by_the_fold() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for name in ["TextOrd", "TextOrdOpe"] {
        let values = vec![
            (0, frame(""), "the empty string"),
            (1, frame("al"), "al"),
            (2, frame("alice"), "alice"),
            (2, frame("ALICE"), "ALICE"),
            (3, frame("bob"), "bob"),
            (4, frame("cafe"), "cafe"),
            (4, frame("Café"), "Café"),
            (4, frame("CAFE\u{301}"), "CAFE with a combining accent"),
            (5, frame("cafes"), "cafes"),
            (6, frame("Zoe"), "Zoe"),
        ];
        sorts_as(&keyset, name, values).await;
    }
}

/// `=` on a `TextOrd` column reads the equality term, which folds no case:
/// `Café` and `cafe` tie in order and are still two values to `=`. The
/// equality term is `TextEq`'s for the same column.
#[tokio::test]
async fn text_order_ties_are_not_equal() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let a = stored(&keyset, "TextOrd", frame("Café")).await;
    let b = stored(&keyset, "TextOrd", frame("cafe")).await;
    assert_eq!(op(&a), op(&b));
    assert_ne!(a["hm"], b["hm"]);
    let eq = stored(&keyset, "TextEq", frame("Café")).await;
    assert_eq!(a["hm"], eq["hm"], "TextOrd's hm is TextEq's");
}

/// A family's `Ord` and `OrdOpe` types are the same index under two names:
/// they store one term for one value under one column.
#[tokio::test]
async fn ord_and_ord_ope_store_one_term() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let pairs = [
        ("IntegerOrd", "IntegerOrdOpe", frame::<i32>(-9)),
        ("SmallintOrd", "SmallintOrdOpe", frame::<i16>(-9)),
        ("BigintOrd", "BigintOrdOpe", frame::<i64>(1 << 50)),
        ("RealOrd", "RealOrdOpe", frame::<f32>(2.5)),
        ("DoubleOrd", "DoubleOrdOpe", frame::<f64>(-2.5)),
        ("TextOrd", "TextOrdOpe", frame("Zoë")),
    ];
    for (ord, ope, value) in pairs {
        let a = stored(&keyset, ord, value.clone()).await;
        let b = stored(&keyset, ope, value).await;
        assert_eq!(op(&a), op(&b), "{ord} and {ope}");
    }
}

/// Text with a code point Unicode 16 does not assign has no fold, so no
/// order term: refused stored and queried, before any term reaches a row.
#[tokio::test]
async fn text_with_no_fold_is_refused() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let unassigned = "a\u{0378}b";
    for name in ["TextOrd", "TextOrdOpe"] {
        let stored = match targets::encrypt(name, &keyset, &label(), frame(unassigned)) {
            Ok(pending) => pending.await,
            Err(error) => panic!("{name}: refused before the plan ran: {error}"),
        };
        assert!(stored.is_err(), "{name}: stored text with no fold");
        let queried = match targets::query(
            name,
            &common::index_of(name),
            &keyset,
            &label(),
            frame(unassigned),
        ) {
            Ok(pending) => pending.await,
            Err(error) => panic!("{name}: refused before the plan ran: {error}"),
        };
        assert!(queried.is_err(), "{name}: queried text with no fold");
    }
    let typed: Result<text::TextOrd, _> = keyset.encrypt_as(&unassigned.to_owned(), column()).await;
    assert!(typed.is_err(), "the typed entry point refuses it too");
}

/// The typed entry point writes what the by-name dispatch writes: the same
/// terms, and a ciphertext that opens to the exact value.
#[tokio::test]
async fn the_typed_entry_point_stores_the_dispatchs_terms() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();

    let typed: integer::IntegerOrd = keyset.encrypt_as(&-9i32, column()).await.unwrap();
    let named = stored(&keyset, "IntegerOrd", frame(-9i32)).await;
    assert_eq!(serde_json::to_value(&typed.op).unwrap(), named["op"]);
    let opened: i32 = cipher.decrypt_as(typed, column().into()).await.unwrap();
    assert_eq!(opened, -9);

    let typed: bigint::BigintOrdOpeQuery = keyset.encrypt_as(&7i64, column()).await.unwrap();
    let named = query(&keyset, "BigintOrdOpe", frame(7i64)).await;
    assert_eq!(serde_json::to_value(&typed.op).unwrap(), named["op"]);

    let typed: real::RealOrd = keyset.encrypt_as(&-0.0f32, column()).await.unwrap();
    let named = stored(&keyset, "RealOrd", frame(0.0f32)).await;
    assert_eq!(
        serde_json::to_value(&typed.op).unwrap(),
        named["op"],
        "-0.0 ties 0.0 in the term"
    );
    let opened: f32 = cipher.decrypt_as(typed, column().into()).await.unwrap();
    assert_eq!(
        opened.to_bits(),
        (-0.0f32).to_bits(),
        "and keeps its sign in c"
    );

    let typed: double::DoubleOrdOpe = keyset.encrypt_as(&f64::NAN, column()).await.unwrap();
    let named = stored(&keyset, "DoubleOrdOpe", frame(f64::NAN)).await;
    assert_eq!(serde_json::to_value(&typed.op).unwrap(), named["op"]);

    let typed: text::TextOrdQuery = keyset
        .encrypt_as(&"Café".to_owned(), column())
        .await
        .unwrap();
    let named = query(&keyset, "TextOrd", frame("Café")).await;
    assert_eq!(serde_json::to_value(&typed).unwrap(), named);
}

/// `fixtures/v4_ordered_queries.json`: a query operand for one value of each
/// ordered type, under `FakeDataKeySource`'s index key (keyset nil), read by
/// the Go SDK's hermetic test, which derives the same operands through
/// generated `Lt` methods and asserts the bytes are equal. Regenerate with
/// `EQL_UPDATE_FIXTURES=1`; the bytes must not change otherwise.
#[tokio::test]
async fn the_ordered_query_fixture_is_what_the_dispatch_derives() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let query = |name: &'static str, column: &'static str, value: ValueFrame| {
        let keyset = &keyset;
        async move {
            let label = Label::new(["rankings", column]).unwrap();
            let bytes = targets::query(name, &common::index_of(name), keyset, &label, value)
                .unwrap()
                .await
                .unwrap();
            String::from_utf8(bytes).unwrap()
        }
    };
    let fixture = serde_json::json!({
        "_comment": "The v4 query operands eql-bindings derives for one plaintext of each OPE-ordered type under FakeDataKeySource's index key (keyset nil), read by the Go SDK's hermetic test; regenerate with EQL_UPDATE_FIXTURES=1, do not edit.",
        "table": "rankings",
        "level": {"plaintext": 10, "query": query("IntegerOrd", "level", frame::<i32>(10)).await},
        "floor": {"plaintext": -3, "query": query("IntegerOrdOpe", "floor", frame::<i32>(-3)).await},
        "points": {"plaintext": 5_000_000_000_i64, "query": query("BigintOrd", "points", frame::<i64>(5_000_000_000)).await},
        "total": {"plaintext": -1, "query": query("BigintOrdOpe", "total", frame::<i64>(-1)).await},
        "speed": {"plaintext": 2.5, "query": query("RealOrd", "speed", frame::<f32>(2.5)).await},
        "pace": {"plaintext": -0.5, "query": query("RealOrdOpe", "pace", frame::<f32>(-0.5)).await},
        "score": {"plaintext": 9.75, "query": query("DoubleOrd", "score", frame::<f64>(9.75)).await},
        "mean": {"plaintext": 0.0, "query": query("DoubleOrdOpe", "mean", frame::<f64>(0.0)).await},
        "title": {"plaintext": "Mango", "query": query("TextOrd", "title", frame("Mango")).await},
        "handle": {"plaintext": "carol", "query": query("TextOrdOpe", "handle", frame("carol")).await},
    });
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/v4_ordered_queries.json");
    let rendered = serde_json::to_string_pretty(&fixture).unwrap() + "\n";
    if std::env::var_os("EQL_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &rendered).unwrap();
    }
    let committed = std::fs::read_to_string(&path)
        .expect("fixtures/v4_ordered_queries.json is committed; EQL_UPDATE_FIXTURES=1 writes it");
    assert_eq!(
        committed, rendered,
        "the committed fixture is what the dispatch derives today"
    );
}

/// `fixtures/v4_ordered_rows.json`: `Ranking` rows the Go SDK's generated
/// code sealed over the deterministic EQL guest
/// (`TestV4OrderedRowsMatchTheCommittedFixture` in languages/golang/encrypt
/// writes it).
mod go_rows {
    use super::*;
    use serde::de::DeserializeOwned;
    use std::collections::BTreeMap;

    #[derive(serde::Deserialize)]
    pub struct Fixture {
        pub seed: String,
        pub table: String,
        pub rows: Vec<Row>,
    }
    #[derive(serde::Deserialize)]
    pub struct Row {
        pub id: i32,
        pub plaintext: Plain,
        pub stored: BTreeMap<String, serde_json::Value>,
    }
    #[derive(serde::Deserialize, Clone)]
    pub struct Plain {
        pub level: i32,
        pub floor: i32,
        pub points: i64,
        pub total: i64,
        pub speed: f32,
        pub pace: f32,
        pub score: f64,
        pub mean: f64,
        pub title: String,
        pub handle: String,
    }

    pub fn fixture() -> Fixture {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures/v4_ordered_rows.json");
        let raw = std::fs::read_to_string(path).expect(
            "fixtures/v4_ordered_rows.json is written by the Go SDK's \
             TestV4OrderedRowsMatchTheCommittedFixture",
        );
        serde_json::from_str(&raw).unwrap()
    }

    pub async fn cipher(seed: &str) -> stack_encrypt::StackCipher<stack_kms::DeterministicSource> {
        let seed: [u8; 32] = seed.as_bytes().try_into().expect("a 32-byte seed");
        stack_encrypt::StackCipher::builder()
            .kms(stack_kms::DeterministicSource::new(seed))
            .init()
            .await
            .unwrap()
    }

    pub fn column(name: &str) -> NonEmpty<Identifier> {
        Identifier::for_column("rankings", name).unwrap()
    }

    pub fn parsed<T: DeserializeOwned>(row: &Row, column: &str) -> T {
        serde_json::from_value(row.stored[column].clone())
            .unwrap_or_else(|e| panic!("row {} {column}: {e}", row.id))
    }

    /// Open every field of `row` and check it against what Go sealed.
    pub async fn open_row(
        cipher: &stack_encrypt::StackCipher<stack_kms::DeterministicSource>,
        row: &Row,
    ) {
        let p = &row.plaintext;
        macro_rules! open {
            ($ty:ty, $plain:ty, $column:literal) => {{
                let opened: $plain = cipher
                    .decrypt_as(parsed::<$ty>(row, $column), column($column).into())
                    .await
                    .unwrap();
                opened
            }};
        }
        assert_eq!(open!(integer::IntegerOrd, i32, "level"), p.level);
        assert_eq!(open!(integer::IntegerOrdOpe, i32, "floor"), p.floor);
        assert_eq!(open!(bigint::BigintOrd, i64, "points"), p.points);
        assert_eq!(open!(bigint::BigintOrdOpe, i64, "total"), p.total);
        assert_eq!(
            open!(real::RealOrd, f32, "speed").to_bits(),
            p.speed.to_bits()
        );
        assert_eq!(
            open!(real::RealOrdOpe, f32, "pace").to_bits(),
            p.pace.to_bits()
        );
        assert_eq!(
            open!(double::DoubleOrd, f64, "score").to_bits(),
            p.score.to_bits()
        );
        assert_eq!(
            open!(double::DoubleOrdOpe, f64, "mean").to_bits(),
            p.mean.to_bits()
        );
        assert_eq!(open!(text::TextOrd, String, "title"), p.title);
        assert_eq!(open!(text::TextOrdOpe, String, "handle"), p.handle);
    }
}

/// What the Go SDK sealed parses as each ordered v4 type and opens in Rust.
#[tokio::test]
async fn ordered_rows_the_go_sdk_sealed_open_in_rust() {
    let fixture = go_rows::fixture();
    assert_eq!(fixture.table, "rankings");
    assert!(fixture.rows.len() > 1);
    let cipher = go_rows::cipher(&fixture.seed).await;
    for row in &fixture.rows {
        go_rows::open_row(&cipher, row).await;
    }
}

/// The ordered columns and their SQL types, for the PostgreSQL tests:
/// (column, stored domain, query domain).
const COLUMNS: &[(&str, &str, &str)] = &[
    ("level", "integer_ord", "query_integer_ord"),
    ("floor", "integer_ord_ope", "query_integer_ord_ope"),
    ("points", "bigint_ord", "query_bigint_ord"),
    ("total", "bigint_ord_ope", "query_bigint_ord_ope"),
    ("speed", "real_ord", "query_real_ord"),
    ("pace", "real_ord_ope", "query_real_ord_ope"),
    ("score", "double_ord", "query_double_ord"),
    ("mean", "double_ord_ope", "query_double_ord_ope"),
    ("title", "text_ord", "query_text_ord"),
    ("handle", "text_ord_ope", "query_text_ord_ope"),
];

fn connect() -> postgres::Client {
    postgres::Client::connect(
        &std::env::var("EQL_TEST_DATABASE_URL").expect("EQL_TEST_DATABASE_URL"),
        postgres::NoTls,
    )
    .unwrap()
}

fn create_table(db: &mut postgres::Client, table: &str) {
    let columns: Vec<String> = COLUMNS
        .iter()
        .map(|(column, domain, _)| format!("{column} public.eql_v4_{domain}"))
        .collect();
    db.batch_execute(&format!(
        "CREATE TEMP TABLE {table} (id int PRIMARY KEY, {});",
        columns.join(", ")
    ))
    .unwrap();
}

fn insert(db: &mut postgres::Client, table: &str, id: i32, stored: &[String]) {
    let placeholders: Vec<String> = COLUMNS
        .iter()
        .enumerate()
        .map(|(n, (_, domain, _))| format!("${}::text::jsonb::public.eql_v4_{domain}", n + 2))
        .collect();
    let mut params: Vec<&(dyn postgres::types::ToSql + Sync)> = vec![&id];
    params.extend(
        stored
            .iter()
            .map(|s| s as &(dyn postgres::types::ToSql + Sync)),
    );
    db.execute(
        &format!(
            "INSERT INTO {table} VALUES ($1, {})",
            placeholders.join(", ")
        ),
        &params,
    )
    .unwrap();
}

fn ids(db: &mut postgres::Client, sql: &str, query: &str) -> Vec<i32> {
    db.query(sql, &[&query])
        .unwrap_or_else(|e| panic!("{sql}: {e}"))
        .iter()
        .map(|r| r.get(0))
        .collect()
}

/// Needs an EQL v4 installation. Rows written through the by-name dispatch:
/// each ordered column answers `<`, `<=`, `>`, `>=` and `=` with exactly the
/// rows the plaintexts say, and `ORDER BY eql_v4.ord_term(column)` sorts
/// them as the order keys do.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_compares_and_orders_ope_rows() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = connect();
    create_table(&mut db, "v4_ordered");

    // One value per column per row. Row 3 ties row 2 in every column's order
    // key: equal integers, `-0.0` against `0.0`, and text that differs only
    // in case and accents.
    struct Plain(i32, i64, f32, f64, &'static str);
    let rows = [
        (1, Plain(-5, i64::MIN, f32::NEG_INFINITY, -1.5, "alice")),
        (2, Plain(0, 0, 0.0, 0.0, "Cafe")),
        (3, Plain(0, 0, -0.0, -0.0, "café")),
        (4, Plain(7, 1 << 40, 2.5, 1e300, "carol")),
        (5, Plain(i32::MAX, i64::MAX, f32::NAN, f64::NAN, "Zoe")),
    ];
    let frames = |p: &Plain| -> Vec<(&'static str, ValueFrame)> {
        vec![
            ("IntegerOrd", frame(p.0)),
            ("IntegerOrdOpe", frame(p.0)),
            ("BigintOrd", frame(p.1)),
            ("BigintOrdOpe", frame(p.1)),
            ("RealOrd", frame(p.2)),
            ("RealOrdOpe", frame(p.2)),
            ("DoubleOrd", frame(p.3)),
            ("DoubleOrdOpe", frame(p.3)),
            ("TextOrd", frame(p.4)),
            ("TextOrdOpe", frame(p.4)),
        ]
    };
    let under = |column: &str| Label::new(["rankings", column]).unwrap();
    for (id, plain) in &rows {
        let stored: Vec<String> = runtime.block_on(async {
            let mut stored = Vec::new();
            for ((column, _, _), (name, value)) in COLUMNS.iter().zip(frames(plain)) {
                let bytes = targets::encrypt(name, &keyset, &under(column), value)
                    .unwrap()
                    .await
                    .unwrap();
                stored.push(String::from_utf8(bytes).unwrap());
            }
            stored
        });
        insert(&mut db, "v4_ordered", *id, &stored);
    }

    // The query operand for the middle row's values (row 2), per column.
    let probes: Vec<String> = runtime.block_on(async {
        let mut probes = Vec::new();
        for ((column, _, _), (name, value)) in COLUMNS.iter().zip(frames(&rows[1].1)) {
            let bytes = targets::query(
                name,
                &common::index_of(name),
                &keyset,
                &under(column),
                value,
            )
            .unwrap()
            .await
            .unwrap();
            probes.push(String::from_utf8(bytes).unwrap());
        }
        probes
    });

    for ((column, _, query_domain), probe) in COLUMNS.iter().zip(&probes) {
        let cmp = |op: &str| {
            format!(
                "SELECT id FROM v4_ordered WHERE {column} {op} $1::text::jsonb::eql_v4.{query_domain} ORDER BY id"
            )
        };
        let text = column == &"title" || column == &"handle";
        assert_eq!(ids(&mut db, &cmp("<"), probe), [1], "{column} <");
        assert_eq!(ids(&mut db, &cmp("<="), probe), [1, 2, 3], "{column} <=");
        assert_eq!(ids(&mut db, &cmp(">"), probe), [4, 5], "{column} >");
        assert_eq!(ids(&mut db, &cmp(">="), probe), [2, 3, 4, 5], "{column} >=");
        // `=` reads the order term on a number column, where -0.0 ties 0.0
        // as in float8, and the case-sensitive equality term on text.
        let equal: &[i32] = if text { &[2] } else { &[2, 3] };
        assert_eq!(ids(&mut db, &cmp("="), probe), equal, "{column} =");

        // The query operand may stand on the left too.
        let flipped = format!(
            "SELECT id FROM v4_ordered WHERE $1::text::jsonb::eql_v4.{query_domain} > {column} ORDER BY id"
        );
        assert_eq!(
            ids(&mut db, &flipped, probe),
            [1],
            "{column}: query > column"
        );

        // Ascending by the order term: row 1 first, the tied rows 2 and 3
        // together (broken by id), then 4 and 5.
        let ordered: Vec<i32> = db
            .query(
                &format!("SELECT id FROM v4_ordered ORDER BY eql_v4.ord_term({column}), id"),
                &[],
            )
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        assert_eq!(ordered, [1, 2, 3, 4, 5], "{column}: ORDER BY ord_term");
    }

    // MIN and MAX over the order term name the extreme rows' values.
    let back: String = db
        .query_one("SELECT eql_v4.max(level)::text FROM v4_ordered", &[])
        .map(|r| r.get(0))
        .unwrap_or_else(|e| panic!("max(level): {e}"));
    let opened: i32 = runtime
        .block_on(async {
            cipher
                .decrypt_as(
                    serde_json::from_str::<integer::IntegerOrd>(&back).unwrap(),
                    column().into(),
                )
                .await
        })
        .unwrap();
    assert_eq!(opened, i32::MAX);
}

/// The Go-sealed rows in PostgreSQL: each value passes its domain check,
/// `<`, `<=`, `>` and `>=` with the fixture's query operands (which the Go
/// SDK's test derives byte for byte) find the rows whose plaintext is on
/// that side of the query's, and `ORDER BY eql_v4.ord_term(column)` sorts
/// Go's rows as their plaintexts do.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_compares_rows_the_go_sdk_sealed() {
    let fixture = go_rows::fixture();
    let mut db = connect();
    create_table(&mut db, "go_rankings");
    for row in &fixture.rows {
        let stored: Vec<String> = COLUMNS
            .iter()
            .map(|(column, _, _)| row.stored[*column].to_string())
            .collect();
        insert(&mut db, "go_rankings", row.id, &stored);
    }
    let queries: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/v4_ordered_queries.json"),
        )
        .unwrap(),
    )
    .unwrap();
    // A column's order key, as a value that sorts as the order term does.
    #[derive(PartialEq, PartialOrd, Debug)]
    enum Key {
        Int(i64),
        Float(f64),
        Text(String),
    }
    let fold = |s: &str| {
        // The fixture's text is ASCII, so lower-casing is the fold here.
        assert!(s.is_ascii(), "{s}: the expectation folds ASCII only");
        Key::Text(s.to_ascii_lowercase())
    };
    let key = |column: &str, p: &go_rows::Plain| -> Key {
        match column {
            "level" => Key::Int(p.level.into()),
            "floor" => Key::Int(p.floor.into()),
            "points" => Key::Int(p.points),
            "total" => Key::Int(p.total),
            "speed" => Key::Float(p.speed.into()),
            "pace" => Key::Float(p.pace.into()),
            "score" => Key::Float(p.score),
            "mean" => Key::Float(p.mean),
            "title" => fold(&p.title),
            "handle" => fold(&p.handle),
            other => panic!("no order key for {other}"),
        }
    };
    let query_key = |column: &str, plain: &serde_json::Value| -> Key {
        match column {
            "level" | "floor" | "points" | "total" => Key::Int(plain.as_i64().unwrap()),
            "speed" | "pace" | "score" | "mean" => Key::Float(plain.as_f64().unwrap()),
            "title" | "handle" => fold(plain.as_str().unwrap()),
            other => panic!("no order key for {other}"),
        }
    };
    for (column, _, query_domain) in COLUMNS {
        let probe = query_key(column, &queries[*column]["plaintext"]);
        // Sorted, as the SQL below sorts its ids: the assertion is about
        // which rows, not the order the fixture lists them in.
        let side = |keep: &dyn Fn(&Key) -> bool| -> Vec<i32> {
            let mut ids: Vec<i32> = fixture
                .rows
                .iter()
                .filter(|r| keep(&key(column, &r.plaintext)))
                .map(|r| r.id)
                .collect();
            ids.sort_unstable();
            ids
        };
        let below = side(&|k| *k < probe);
        let above = side(&|k| *k > probe);
        assert!(
            !below.is_empty() && !above.is_empty(),
            "{column}: the fixture has rows on both sides of the query"
        );
        let not_below = side(&|k| *k >= probe);
        let not_above = side(&|k| *k <= probe);

        let query = queries[*column]["query"].as_str().unwrap();
        let cmp = |op: &str| {
            format!(
                "SELECT id FROM go_rankings WHERE {column} {op} $1::text::jsonb::eql_v4.{query_domain} ORDER BY id"
            )
        };
        assert_eq!(
            ids(&mut db, &cmp("<"), query),
            below,
            "< over Go-sealed {column}"
        );
        assert_eq!(
            ids(&mut db, &cmp("<="), query),
            not_above,
            "<= over Go-sealed {column}"
        );
        assert_eq!(
            ids(&mut db, &cmp(">"), query),
            above,
            "> over Go-sealed {column}"
        );
        assert_eq!(
            ids(&mut db, &cmp(">="), query),
            not_below,
            ">= over Go-sealed {column}"
        );

        // Go's terms sort among themselves as the plaintexts do, ties
        // broken by id.
        let mut by_plaintext: Vec<(Key, i32)> = fixture
            .rows
            .iter()
            .map(|r| (key(column, &r.plaintext), r.id))
            .collect();
        by_plaintext.sort_by(|a, b| a.partial_cmp(b).expect("the fixture's keys are finite"));
        let expected: Vec<i32> = by_plaintext.into_iter().map(|(_, id)| id).collect();
        let ordered: Vec<i32> = db
            .query(
                &format!("SELECT id FROM go_rankings ORDER BY eql_v4.ord_term({column}), id"),
                &[],
            )
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        assert_eq!(
            ordered, expected,
            "ORDER BY ord_term over Go-sealed {column}"
        );
    }
}
