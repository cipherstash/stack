//! The EQL v4 types Stack Encrypt produces besides `TextEq`: the
//! storage-only integer, bigint, boolean, float and text types, the integer
//! and float equality types, and `TextMatch`. `Json` is not producible yet: a
//! JSON value seals as a tree of leaves and EQL's `c` holds one.
//!
//! Each type must round-trip through both entry points (the typed
//! `encrypt_as` and the by-name dispatch a Go plan reaches), seal exactly the
//! leaf vitaminc's value enum seals for the same value (what the Go SDK writes
//! for a plain field of that kind) and open the leaf the value enum sealed,
//! and refuse a value of another kind.

mod common;

use eql_bindings::encryption::plaintext::{Bool, Float32, Float64, Int32, Int64};
use eql_bindings::encryption::targets::{self as targets, TargetError};
use eql_bindings::encryption::{CiphertextVisitor, NativeCiphertextVisitor as NativeLeaf};
use eql_bindings::v3::terms::Ciphertext;
use eql_bindings::v4::{bigint, boolean, double, integer, real, text};
use eql_bindings::Identifier;
use serde::{de::DeserializeOwned, Serialize};
use stack_encrypt::dynamic::{FfiValue, ValueKind};
use stack_encrypt::target::transcode::{Reader, Visitor};
use stack_encrypt::{CipherText, Label, NonEmpty};

fn column() -> NonEmpty<Identifier> {
    Identifier::for_column("users", "age").unwrap()
}

fn label() -> Label {
    Label::new(["users", "age"]).unwrap()
}

/// The refusal a dispatch returned; `Pending` has no `Debug`.
fn refused<T>(result: Result<T, TargetError>) -> TargetError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("the dispatch accepted what it should have refused"),
    }
}

/// The JSON a stored v4 value serializes to: version 4, the column, and the
/// ciphertext with the producer marker.
fn assert_v4_envelope<T: Serialize>(stored: &T, keys: &[&str]) {
    let json = serde_json::to_value(stored).unwrap();
    assert_eq!(json["v"], 4, "Stack Encrypt writes EQL v4");
    assert_eq!(json["i"], serde_json::json!({"t": "users", "c": "age"}));
    assert!(json["c"].as_str().unwrap().starts_with("stack-encrypt:1:"));
    let mut found: Vec<&str> = json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    found.sort_unstable();
    let mut expected = keys.to_vec();
    expected.sort_unstable();
    assert_eq!(found, expected);
}

/// What the stored ciphertext opens to when read as vitaminc's value enum:
/// the leaf the Go SDK would have sealed for the same value.
async fn as_value_enum(
    cipher: &stack_encrypt::StackCipher<common::Observed>,
    c: Ciphertext,
) -> FfiValue {
    let native = c.read(NativeLeaf).unwrap();
    cipher.decrypt(native, column()).await.unwrap()
}

/// The other direction: the `c` a plain field of `value`'s kind gets when the
/// value enum seals it, as a Go SDK field without an EQL type does.
async fn sealed_by_value_enum(
    keyset: &stack_encrypt::KeysetCipher<'_, common::Observed>,
    value: FfiValue,
) -> Ciphertext {
    match keyset.encrypt(value, column()).await.unwrap() {
        CipherText::Single(leaf) => CiphertextVisitor.sealed(leaf).unwrap(),
        _ => panic!("a scalar seals as one leaf"),
    }
}

/// A storage-only v4 value of type `T` around `c`, for this test's column.
fn stored_as<T: DeserializeOwned>(c: Ciphertext) -> T {
    serde_json::from_value(serde_json::json!({
        "v": 4,
        "i": {"t": "users", "c": "age"},
        "c": c,
    }))
    .unwrap()
}

/// Run one named target over `value` and read the stored JSON back as `T`.
async fn by_name<T: DeserializeOwned>(
    keyset: &stack_encrypt::KeysetCipher<'_, common::Observed>,
    name: &str,
    value: FfiValue,
) -> T {
    let bytes = targets::encrypt(name, keyset, &label(), value)
        .unwrap()
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Whether two scalar values are the same value, bit for bit for floats.
fn same(a: &FfiValue, b: &FfiValue) -> bool {
    match (a, b) {
        (FfiValue::Int32(a), FfiValue::Int32(b)) => a == b,
        (FfiValue::Int64(a), FfiValue::Int64(b)) => a == b,
        (FfiValue::Bool(a), FfiValue::Bool(b)) => a == b,
        (FfiValue::Float32(a), FfiValue::Float32(b)) => a.to_bits() == b.to_bits(),
        (FfiValue::Float64(a), FfiValue::Float64(b)) => a.to_bits() == b.to_bits(),
        (FfiValue::String(a), FfiValue::String(b)) => a.risky_ref() == b.risky_ref(),
        _ => false,
    }
}

/// A sample plaintext of each kind a producible type takes.
fn sample(kind: ValueKind) -> FfiValue {
    match kind {
        ValueKind::Int32 => FfiValue::Int32(-42),
        ValueKind::Int64 => FfiValue::Int64(i64::MIN + 1),
        ValueKind::Bool => FfiValue::Bool(true),
        ValueKind::Float32 => FfiValue::Float32(-0.0),
        ValueKind::Float64 => FfiValue::Float64(f64::NAN),
        ValueKind::String => FfiValue::String("a private note".into()),
        other => panic!("no sample for {other:?}: add one with the type that takes it"),
    }
}

#[tokio::test]
async fn integers_round_trip_and_seal_the_value_enum_leaf() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for value in [0, 42, -7, i32::MIN, i32::MAX] {
        let stored: integer::Integer = keyset.encrypt_as(&Int32(value), column()).await.unwrap();
        assert_v4_envelope(&stored, &["v", "i", "c"]);

        let opened: Int32 = cipher
            .decrypt_as(stored.clone(), column().into())
            .await
            .unwrap();
        assert_eq!(opened.0, value);
        assert!(matches!(
            as_value_enum(&cipher, stored.c.clone()).await,
            FfiValue::Int32(v) if v == value
        ));

        // The by-name dispatch runs the same plan.
        let named: integer::Integer = by_name(&keyset, "Integer", FfiValue::Int32(value)).await;
        let opened = targets::decrypt(
            "Integer",
            &cipher,
            &label(),
            &serde_json::to_vec(&named).unwrap(),
        )
        .unwrap()
        .await
        .unwrap();
        assert!(matches!(opened, FfiValue::Int32(v) if v == value));
    }

    for value in [0i64, -1, i64::MIN, i64::MAX] {
        let stored: bigint::Bigint = keyset.encrypt_as(&Int64(value), column()).await.unwrap();
        assert_v4_envelope(&stored, &["v", "i", "c"]);
        let opened: Int64 = cipher
            .decrypt_as(stored.clone(), column().into())
            .await
            .unwrap();
        assert_eq!(opened.0, value);
        assert!(matches!(
            as_value_enum(&cipher, stored.c.clone()).await,
            FfiValue::Int64(v) if v == value
        ));
    }
}

/// The `hm` the named type stores for `value`, and the one its query twin
/// derives.
async fn eq_terms(
    keyset: &stack_encrypt::KeysetCipher<'_, common::Observed>,
    name: &str,
    value: FfiValue,
) -> (serde_json::Value, serde_json::Value) {
    let stored: serde_json::Value = by_name(keyset, name, value.clone()).await;
    let query = targets::query(name, keyset, &label(), value)
        .unwrap()
        .await
        .unwrap();
    let query: serde_json::Value = serde_json::from_slice(&query).unwrap();
    (stored["hm"].clone(), query["hm"].clone())
}

/// The equality term follows ADR-0002's semantic baseline: integers of
/// either width share one term for one value, and a float's `-0.0` and every
/// NaN fold to one value each, as Postgres's own `float8 =` treats them.
#[tokio::test]
async fn number_equality_terms_follow_the_semantic_baseline() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let hm = |name: &'static str, value: FfiValue| {
        let keyset = &keyset;
        async move {
            let (stored, query) = eq_terms(keyset, name, value).await;
            assert!(stored.is_string(), "{name} stores an hm: {stored}");
            assert_eq!(stored, query, "{name}: the query probes the stored term");
            stored
        }
    };

    assert_ne!(
        hm("IntegerEq", FfiValue::Int32(42)).await,
        hm("IntegerEq", FfiValue::Int32(43)).await
    );
    assert_eq!(
        hm("IntegerEq", FfiValue::Int32(42)).await,
        hm("BigintEq", FfiValue::Int64(42)).await,
        "one integer domain for every width"
    );

    assert_eq!(
        hm("RealEq", FfiValue::Float32(-0.0)).await,
        hm("RealEq", FfiValue::Float32(0.0)).await
    );
    assert_eq!(
        hm("RealEq", FfiValue::Float32(f32::from_bits(0xffc0_1234))).await,
        hm("RealEq", FfiValue::Float32(f32::NAN)).await
    );
    assert_eq!(
        hm("DoubleEq", FfiValue::Float64(-0.0)).await,
        hm("DoubleEq", FfiValue::Float64(0.0)).await
    );
    assert_eq!(
        hm(
            "DoubleEq",
            FfiValue::Float64(f64::from_bits(0xfff8_0000_0000_beef))
        )
        .await,
        hm("DoubleEq", FfiValue::Float64(f64::NAN)).await
    );
    assert_ne!(
        hm("DoubleEq", FfiValue::Float64(1.5)).await,
        hm("DoubleEq", FfiValue::Float64(2.5)).await
    );
    assert_eq!(
        hm("RealEq", FfiValue::Float32(1.5)).await,
        hm("DoubleEq", FfiValue::Float64(1.5)).await,
        "an f32 hashes as the f64 it widens to"
    );
    // An integer and a float are different kinds, even at one value.
    assert_ne!(
        hm("BigintEq", FfiValue::Int64(1)).await,
        hm("DoubleEq", FfiValue::Float64(1.0)).await
    );
}

/// The typed entry point stores the same term as the by-name dispatch, and
/// the ciphertext keeps the value exactly: `-0.0` folds in the term only.
#[tokio::test]
async fn number_equality_types_round_trip_through_the_typed_entry_point() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();

    let stored: integer::IntegerEq = keyset.encrypt_as(&Int32(-7), column()).await.unwrap();
    assert_v4_envelope(&stored, &["v", "i", "c", "hm"]);
    let named: serde_json::Value = by_name(&keyset, "IntegerEq", FfiValue::Int32(-7)).await;
    assert_eq!(serde_json::to_value(&stored).unwrap()["hm"], named["hm"]);
    let opened: Int32 = cipher.decrypt_as(stored, column().into()).await.unwrap();
    assert_eq!(opened.0, -7);

    let stored: bigint::BigintEq = keyset.encrypt_as(&Int64(i64::MIN), column()).await.unwrap();
    assert_v4_envelope(&stored, &["v", "i", "c", "hm"]);
    let opened: Int64 = cipher.decrypt_as(stored, column().into()).await.unwrap();
    assert_eq!(opened.0, i64::MIN);

    let stored: real::RealEq = keyset.encrypt_as(&Float32(-0.0), column()).await.unwrap();
    assert_v4_envelope(&stored, &["v", "i", "c", "hm"]);
    let opened: Float32 = cipher.decrypt_as(stored, column().into()).await.unwrap();
    assert_eq!(opened.0.to_bits(), (-0.0f32).to_bits());

    let stored: double::DoubleEq = keyset
        .encrypt_as(&Float64(f64::NAN), column())
        .await
        .unwrap();
    assert_v4_envelope(&stored, &["v", "i", "c", "hm"]);
    let opened: Float64 = cipher.decrypt_as(stored, column().into()).await.unwrap();
    assert_eq!(opened.0.to_bits(), f64::NAN.to_bits());
}

#[tokio::test]
async fn booleans_and_floats_round_trip_as_storage_only_types() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for value in [true, false] {
        let stored: boolean::Boolean = keyset.encrypt_as(&Bool(value), column()).await.unwrap();
        assert_v4_envelope(&stored, &["v", "i", "c"]);
        let opened: Bool = cipher
            .decrypt_as(stored.clone(), column().into())
            .await
            .unwrap();
        assert_eq!(opened.0, value);
        assert!(matches!(
            as_value_enum(&cipher, stored.c).await,
            FfiValue::Bool(v) if v == value
        ));
    }
    // Floats seal their bit pattern: -0.0 and a NaN's payload survive.
    for value in [1.5f32, -0.0, f32::NAN, f32::INFINITY] {
        let stored: real::Real = keyset.encrypt_as(&Float32(value), column()).await.unwrap();
        let opened: Float32 = cipher
            .decrypt_as(stored.clone(), column().into())
            .await
            .unwrap();
        assert_eq!(opened.0.to_bits(), value.to_bits());
        assert!(matches!(
            as_value_enum(&cipher, stored.c).await,
            FfiValue::Float32(v) if v.to_bits() == value.to_bits()
        ));
    }
    for value in [2.25f64, -0.0, f64::NAN] {
        let stored: double::Double = keyset.encrypt_as(&Float64(value), column()).await.unwrap();
        let opened: Float64 = cipher
            .decrypt_as(stored.clone(), column().into())
            .await
            .unwrap();
        assert_eq!(opened.0.to_bits(), value.to_bits());
        assert!(matches!(
            as_value_enum(&cipher, stored.c).await,
            FfiValue::Float64(v) if v.to_bits() == value.to_bits()
        ));
    }
}

/// The direction `LeafVisitor` and `BoolVisitor` implement: a leaf the value
/// enum sealed, as a plain Go field writes it, opens as the typed plaintext.
#[tokio::test]
async fn a_leaf_the_value_enum_sealed_opens_as_the_typed_plaintext() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let c = sealed_by_value_enum(&keyset, FfiValue::Int32(-7)).await;
    let opened: Int32 = cipher
        .decrypt_as(stored_as::<integer::Integer>(c), column().into())
        .await
        .unwrap();
    assert_eq!(opened.0, -7);

    let c = sealed_by_value_enum(&keyset, FfiValue::Int64(i64::MAX)).await;
    let opened: Int64 = cipher
        .decrypt_as(stored_as::<bigint::Bigint>(c), column().into())
        .await
        .unwrap();
    assert_eq!(opened.0, i64::MAX);

    let c = sealed_by_value_enum(&keyset, FfiValue::Bool(true)).await;
    let opened: Bool = cipher
        .decrypt_as(stored_as::<boolean::Boolean>(c), column().into())
        .await
        .unwrap();
    assert!(opened.0);

    let c = sealed_by_value_enum(&keyset, FfiValue::Float32(-0.0)).await;
    let opened: Float32 = cipher
        .decrypt_as(stored_as::<real::Real>(c), column().into())
        .await
        .unwrap();
    assert_eq!(opened.0.to_bits(), (-0.0f32).to_bits());

    let c = sealed_by_value_enum(&keyset, FfiValue::Float64(f64::NAN)).await;
    let opened: Float64 = cipher
        .decrypt_as(stored_as::<double::Double>(c), column().into())
        .await
        .unwrap();
    assert_eq!(opened.0.to_bits(), f64::NAN.to_bits());
}

/// Every producible row of the generated table, through all three by-name
/// entry points: a swapped type or plaintext in the generator fails here.
#[tokio::test]
async fn every_producible_type_dispatches_by_name() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let producible: Vec<_> = targets::targets().iter().filter(|t| t.producible).collect();
    assert!(!producible.is_empty());
    for target in producible {
        let name = target.name;
        let kind = target
            .plaintext_kind()
            .expect("a producible type names its kind");
        let stored = targets::encrypt(name, &keyset, &label(), sample(kind))
            .unwrap()
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&stored).unwrap();
        assert_eq!(json["v"], 4, "{name}");
        let opened = targets::decrypt(name, &cipher, &label(), &stored)
            .unwrap()
            .await
            .unwrap();
        assert!(same(&opened, &sample(kind)), "{name}: opened another value");

        match target.query {
            None => {
                let error = refused(targets::query(name, &keyset, &label(), sample(kind)));
                assert!(
                    matches!(error, TargetError::NoQuery { .. }),
                    "{name}: {error}"
                );
            }
            Some(_) => {
                let query = targets::query(name, &keyset, &label(), sample(kind))
                    .unwrap()
                    .await
                    .unwrap();
                let query: serde_json::Value = serde_json::from_slice(&query).unwrap();
                assert!(
                    query.get("c").is_none(),
                    "{name}: a query carries no ciphertext"
                );
                if target.indexes.contains(&"eq") {
                    assert_eq!(
                        query["hm"], json["hm"],
                        "{name}: the query probes the stored term"
                    );
                }
            }
        }
    }
}

#[tokio::test]
async fn storage_only_text_round_trips_through_both_entry_points() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let stored: text::Text = keyset
        .encrypt_as(&"a private note".to_owned(), column())
        .await
        .unwrap();
    assert_v4_envelope(&stored, &["v", "i", "c"]);
    let opened: String = cipher.decrypt_as(stored, column().into()).await.unwrap();
    assert_eq!(opened, "a private note");

    let named: text::Text = by_name(&keyset, "Text", FfiValue::String("note".into())).await;
    let opened: String = cipher.decrypt_as(named, column().into()).await.unwrap();
    assert_eq!(opened, "note");
    // A storage-only type answers no query.
    let error = refused(targets::query(
        "Text",
        &keyset,
        &label(),
        FfiValue::String("note".into()),
    ));
    assert!(
        matches!(error, TargetError::NoQuery { name: "Text" }),
        "{error}"
    );
}

/// A match query's filter positions, which EQL's `@@` tests for containment.
fn positions(filter: &eql_bindings::v3::terms::BloomFilter) -> std::collections::BTreeSet<i16> {
    filter.0.iter().copied().collect()
}

#[tokio::test]
async fn text_match_filters_contain_their_substrings() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let stored: text::TextMatch = keyset
        .encrypt_as(&"Alice@Example.com".to_owned(), column())
        .await
        .unwrap();
    assert_v4_envelope(&stored, &["v", "i", "c", "bf"]);
    assert!(
        stored.bf.0.iter().all(|&p| (0..2048).contains(&p)),
        "a 2048-bit filter"
    );
    let opened: String = cipher
        .decrypt_as(stored.clone(), column().into())
        .await
        .unwrap();
    assert_eq!(opened, "Alice@Example.com");

    // `true` is a property of the filter: every bit a contained needle sets
    // is set in the stored value's. `false` is not: a Bloom filter can cover
    // an absent needle's bits by chance. "bob" is clear of it under the
    // test key source and the pinned configuration, so a change to either
    // can flip that case with no bug behind it.
    let all = positions(&stored.bf);
    for (needle, contained) in [
        ("alice", true),
        ("EXAMPLE", true),
        ("ice@ex", true),
        ("bob", false),
    ] {
        let query: text::TextMatchQuery = keyset
            .encrypt_as(&needle.to_owned(), column())
            .await
            .unwrap();
        assert_eq!(
            positions(&query.bf).is_subset(&all),
            contained,
            "{needle:?} in Alice@Example.com"
        );
    }

    // The dispatch derives the same filter.
    let named: text::TextMatch = by_name(
        &keyset,
        "TextMatch",
        FfiValue::String("Alice@Example.com".into()),
    )
    .await;
    assert_eq!(named.bf, stored.bf);

    // Text shorter than a 3-gram has no tokens. eql-bindings refuses it for a
    // stored value as well as a query: one filter type builds both, and an
    // empty filter as a query would match every row. So a short value cannot
    // be written to a TextMatch column yet.
    let short: Result<text::TextMatch, _> = keyset.encrypt_as(&"ab".to_owned(), column()).await;
    assert!(short.is_err());
    let short_query: Result<text::TextMatchQuery, _> =
        keyset.encrypt_as(&"ab".to_owned(), column()).await;
    assert!(short_query.is_err(), "a short query would match every row");
}

/// The filter bits for one query under the test key source. The
/// configuration is part of the stored format (`EqlMatch`): if these move,
/// every stored filter stops agreeing with new queries, so a change here must
/// arrive as a new domain or payload version.
#[tokio::test]
async fn text_match_filter_positions_are_pinned() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let query: text::TextMatchQuery = keyset
        .encrypt_as(&"alice".to_owned(), column())
        .await
        .unwrap();
    // 3 tokens ("ali", "lic", "ice") at 6 positions each, de-duplicated.
    assert_eq!(query.bf.0, PINNED_ALICE);
}

const PINNED_ALICE: [i16; 18] = [
    9, 203, 351, 542, 626, 697, 748, 872, 917, 1023, 1062, 1190, 1251, 1355, 1613, 1710, 1792, 2025,
];

#[tokio::test]
async fn a_value_of_another_kind_is_refused_not_converted() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for (name, value, expected) in [
        ("Integer", FfiValue::Int64(1), ValueKind::Int32),
        ("Bigint", FfiValue::Int32(1), ValueKind::Int64),
        ("Boolean", FfiValue::Int32(1), ValueKind::Bool),
        ("Real", FfiValue::Float64(1.0), ValueKind::Float32),
        ("Text", FfiValue::Int32(1), ValueKind::String),
    ] {
        let error = refused(targets::encrypt(name, &keyset, &label(), value));
        assert!(
            matches!(error, TargetError::Plaintext { target, expected: e, .. } if target == name && e == expected),
            "{name}: {error}"
        );
    }

    // A ciphertext moved into a type of another kind does not open: the tag
    // is authenticated, and each plaintext reads only its own.
    let narrow: integer::Integer = keyset.encrypt_as(&Int32(42), column()).await.unwrap();
    let moved = bigint::Bigint {
        v: narrow.v,
        i: narrow.i,
        c: narrow.c,
    };
    let opened: Result<Int64, _> = cipher.decrypt_as(moved, column().into()).await;
    assert!(opened.is_err());
}

/// Needs an EQL v4 installation; uses fresh real ciphertext with a fake key
/// source.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_stores_and_queries_every_producible_v4_type() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = postgres::Client::connect(
        &std::env::var("EQL_TEST_DATABASE_URL").expect("EQL_TEST_DATABASE_URL"),
        postgres::NoTls,
    )
    .unwrap();
    db.batch_execute(
        "CREATE TEMP TABLE v4_types (
            id int PRIMARY KEY,
            age public.eql_v4_integer,
            balance public.eql_v4_bigint,
            active public.eql_v4_boolean,
            ratio public.eql_v4_real,
            score public.eql_v4_double,
            note public.eql_v4_text,
            name public.eql_v4_text_match
        );",
    )
    .unwrap();

    let json = |value: &dyn erased::Json| value.to_json();
    for (id, age, balance) in [(1, 42, 10i64), (2, 7, 20), (3, 42, 30)] {
        let row = runtime.block_on(async {
            (
                keyset
                    .encrypt_as::<_, integer::Integer>(&Int32(age), column())
                    .await
                    .unwrap(),
                keyset
                    .encrypt_as::<_, bigint::Bigint>(&Int64(balance), column())
                    .await
                    .unwrap(),
                keyset
                    .encrypt_as::<_, boolean::Boolean>(&Bool(id % 2 == 0), column())
                    .await
                    .unwrap(),
                keyset
                    .encrypt_as::<_, real::Real>(&Float32(0.5), column())
                    .await
                    .unwrap(),
                keyset
                    .encrypt_as::<_, double::Double>(&Float64(0.25), column())
                    .await
                    .unwrap(),
                keyset
                    .encrypt_as::<_, text::Text>(&"note".to_owned(), column())
                    .await
                    .unwrap(),
                keyset
                    .encrypt_as::<_, text::TextMatch>(&format!("user{id}@example.com"), column())
                    .await
                    .unwrap(),
            )
        });
        db.execute(
            "INSERT INTO v4_types VALUES ($1,
                $2::text::jsonb::public.eql_v4_integer,
                $3::text::jsonb::public.eql_v4_bigint,
                $4::text::jsonb::public.eql_v4_boolean,
                $5::text::jsonb::public.eql_v4_real,
                $6::text::jsonb::public.eql_v4_double,
                $7::text::jsonb::public.eql_v4_text,
                $8::text::jsonb::public.eql_v4_text_match)",
            &[
                &id,
                &json(&row.0),
                &json(&row.1),
                &json(&row.2),
                &json(&row.3),
                &json(&row.4),
                &json(&row.5),
                &json(&row.6),
            ],
        )
        .unwrap();
    }

    let mut matching = |needle: &str| -> Vec<i32> {
        let probe: text::TextMatchQuery = runtime
            .block_on(async { keyset.encrypt_as(&needle.to_owned(), column()).await })
            .unwrap();
        db.query(
            "SELECT id FROM v4_types WHERE name @@ $1::text::jsonb::eql_v4.query_text_match ORDER BY id",
            &[&json(&probe)],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
    };
    assert_eq!(matching("example.com"), [1, 2, 3], "TextMatch: every row");
    assert_eq!(matching("user2"), [2], "TextMatch: one row");
    assert_eq!(matching("nobody"), Vec::<i32>::new(), "TextMatch: none");

    // Known gap in the SQL (#1171), pinned so its fix shows here: with the
    // query on the left, `@@` asks whether the query's filter contains the
    // stored value's, so that operand order finds nothing. Only
    // `stored @@ query` works until then; the README says so.
    let probe: text::TextMatchQuery = runtime
        .block_on(async { keyset.encrypt_as(&"user2".to_owned(), column()).await })
        .unwrap();
    let reversed: Vec<i32> = db
        .query(
            "SELECT id FROM v4_types WHERE $1::text::jsonb::eql_v4.query_text_match @@ name",
            &[&json(&probe)],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(
        reversed,
        Vec::<i32>::new(),
        "query @@ stored still finds nothing (#1171); when the SQL is fixed this becomes [2]"
    );

    // Every stored value reads back from its domain and opens.
    let row = db
        .query_one(
            "SELECT age::text, balance::text, active::text, ratio::text, score::text, note::text
             FROM v4_types WHERE id = 2",
            &[],
        )
        .unwrap();
    let open = |i: usize| -> String { row.get(i) };
    runtime.block_on(async {
        let opened: Int32 = cipher
            .decrypt_as(
                serde_json::from_str::<integer::Integer>(&open(0)).unwrap(),
                column().into(),
            )
            .await
            .unwrap();
        assert_eq!(opened.0, 7);
        let opened: Int64 = cipher
            .decrypt_as(
                serde_json::from_str::<bigint::Bigint>(&open(1)).unwrap(),
                column().into(),
            )
            .await
            .unwrap();
        assert_eq!(opened.0, 20);
        let opened: Bool = cipher
            .decrypt_as(
                serde_json::from_str::<boolean::Boolean>(&open(2)).unwrap(),
                column().into(),
            )
            .await
            .unwrap();
        assert!(opened.0);
        let opened: Float32 = cipher
            .decrypt_as(
                serde_json::from_str::<real::Real>(&open(3)).unwrap(),
                column().into(),
            )
            .await
            .unwrap();
        assert_eq!(opened.0, 0.5);
        let opened: Float64 = cipher
            .decrypt_as(
                serde_json::from_str::<double::Double>(&open(4)).unwrap(),
                column().into(),
            )
            .await
            .unwrap();
        assert_eq!(opened.0, 0.25);
        let opened: String = cipher
            .decrypt_as(
                serde_json::from_str::<text::Text>(&open(5)).unwrap(),
                column().into(),
            )
            .await
            .unwrap();
        assert_eq!(opened, "note");
    });

    // A storage-only column has no equality operator: it is blocked, not
    // silently compared as jsonb.
    let err = db
        .query("SELECT id FROM v4_types WHERE age = age", &[])
        .unwrap_err();
    let message = err.as_db_error().map(|e| e.message()).unwrap_or_default();
    assert!(
        message.contains("is not supported for public.eql_v4_integer"),
        "{message}"
    );
}

/// Needs an EQL v4 installation. `=` on each number equality type finds
/// exactly the rows its query names, with `-0.0` and NaN treated as
/// Postgres's own `float8 =` treats them.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_finds_number_equality_rows() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (cipher, _) = runtime.block_on(common::cipher());
    let keyset = cipher.default_keyset();
    let mut db = postgres::Client::connect(
        &std::env::var("EQL_TEST_DATABASE_URL").expect("EQL_TEST_DATABASE_URL"),
        postgres::NoTls,
    )
    .unwrap();
    db.batch_execute(
        "CREATE TEMP TABLE v4_number_eq (
            id int PRIMARY KEY,
            age public.eql_v4_integer_eq,
            balance public.eql_v4_bigint_eq,
            ratio public.eql_v4_real_eq,
            score public.eql_v4_double_eq
        );",
    )
    .unwrap();

    let json = |value: &dyn erased::Json| value.to_json();
    let rows = [
        (1, 42, 10i64, 0.5f32, 0.0f64),
        (2, 7, -1, -0.0, f64::NAN),
        (3, 42, i64::MAX, 0.0, -0.0),
    ];
    for (id, age, balance, ratio, score) in rows {
        let stored = runtime.block_on(async {
            (
                keyset
                    .encrypt_as::<_, integer::IntegerEq>(&Int32(age), column())
                    .await
                    .unwrap(),
                keyset
                    .encrypt_as::<_, bigint::BigintEq>(&Int64(balance), column())
                    .await
                    .unwrap(),
                keyset
                    .encrypt_as::<_, real::RealEq>(&Float32(ratio), column())
                    .await
                    .unwrap(),
                keyset
                    .encrypt_as::<_, double::DoubleEq>(&Float64(score), column())
                    .await
                    .unwrap(),
            )
        });
        db.execute(
            "INSERT INTO v4_number_eq VALUES ($1,
                $2::text::jsonb::public.eql_v4_integer_eq,
                $3::text::jsonb::public.eql_v4_bigint_eq,
                $4::text::jsonb::public.eql_v4_real_eq,
                $5::text::jsonb::public.eql_v4_double_eq)",
            &[
                &id,
                &json(&stored.0),
                &json(&stored.1),
                &json(&stored.2),
                &json(&stored.3),
            ],
        )
        .unwrap();
    }

    let mut ids = |column_name: &str, query_domain: &str, query: String| -> Vec<i32> {
        db.query(
            &format!(
                "SELECT id FROM v4_number_eq WHERE {column_name} = $1::text::jsonb::eql_v4.{query_domain} ORDER BY id"
            ),
            &[&query],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
    };
    let q = |stored: Result<String, stack_encrypt::Error>| stored.unwrap();
    let age = |v: i32| {
        q(runtime.block_on(async {
            keyset
                .encrypt_as::<_, integer::IntegerEqQuery>(&Int32(v), column())
                .await
                .map(|q| json(&q))
        }))
    };
    let balance = |v: i64| {
        q(runtime.block_on(async {
            keyset
                .encrypt_as::<_, bigint::BigintEqQuery>(&Int64(v), column())
                .await
                .map(|q| json(&q))
        }))
    };
    let ratio = |v: f32| {
        q(runtime.block_on(async {
            keyset
                .encrypt_as::<_, real::RealEqQuery>(&Float32(v), column())
                .await
                .map(|q| json(&q))
        }))
    };
    let score = |v: f64| {
        q(runtime.block_on(async {
            keyset
                .encrypt_as::<_, double::DoubleEqQuery>(&Float64(v), column())
                .await
                .map(|q| json(&q))
        }))
    };
    let (age_42, age_8) = (age(42), age(8));
    let (balance_max, balance_0) = (balance(i64::MAX), balance(0));
    let (ratio_zero, ratio_half) = (ratio(0.0), ratio(0.5));
    let (score_neg_zero, score_nan) = (score(-0.0), score(f64::from_bits(0xfff8_0000_0000_beef)));

    assert_eq!(ids("age", "query_integer_eq", age_42), [1, 3]);
    assert_eq!(ids("age", "query_integer_eq", age_8), Vec::<i32>::new());
    assert_eq!(ids("balance", "query_bigint_eq", balance_max), [3]);
    assert_eq!(
        ids("balance", "query_bigint_eq", balance_0),
        Vec::<i32>::new()
    );
    assert_eq!(
        ids("ratio", "query_real_eq", ratio_zero),
        [2, 3],
        "-0.0 = 0.0"
    );
    assert_eq!(ids("ratio", "query_real_eq", ratio_half), [1]);
    assert_eq!(
        ids("score", "query_double_eq", score_neg_zero),
        [1, 3],
        "-0.0 = 0.0"
    );
    assert_eq!(
        ids("score", "query_double_eq", score_nan),
        [2],
        "NaN = NaN, whatever its payload"
    );
}

/// A stored value's JSON text, for binding as `$n::text::jsonb`.
mod erased {
    pub trait Json {
        fn to_json(&self) -> String;
    }
    impl<T: serde::Serialize> Json for T {
        fn to_json(&self) -> String {
            serde_json::to_string(self).unwrap()
        }
    }
}

/// `fixtures/v4_queries.json`: the query operands the Rust dispatch derives
/// for one value of each v4 type that answers a query, under the key source
/// every test in the repository derives terms under (`FakeDataKeySource`'s
/// index key, keyset nil). The Go SDK's hermetic test derives the same
/// queries through generated code over the deterministic guest build, whose
/// index key is the same, and asserts the bytes are equal: a Go field typed
/// `encrypt_into=TextMatch` runs this plan and no other. Regenerate with
/// `EQL_UPDATE_FIXTURES=1`; the bytes must not change otherwise.
#[tokio::test]
async fn the_v4_query_fixture_is_what_the_dispatch_derives() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let query = |name: &'static str, column: &'static str, value: FfiValue| {
        let keyset = &keyset;
        async move {
            let label = Label::new(["profiles", column]).unwrap();
            let bytes = targets::query(name, keyset, &label, value)
                .unwrap()
                .await
                .unwrap();
            String::from_utf8(bytes).unwrap()
        }
    };
    let fixture = serde_json::json!({
        "_comment": "The v4 query operands eql-bindings derives for each plaintext under FakeDataKeySource's index key (keyset nil), read by the Go SDK's hermetic test; regenerate with EQL_UPDATE_FIXTURES=1, do not edit.",
        "table": "profiles",
        "name": {
            "plaintext": "alice",
            "query": query("TextMatch", "name", FfiValue::String("alice".into())).await,
        },
        "age": {
            "plaintext": 42,
            "query": query("IntegerEq", "age", FfiValue::Int32(42)).await,
        },
        "rank": {
            "plaintext": 7,
            "query": query("BigintEq", "rank", FfiValue::Int64(7)).await,
        },
        "weight": {
            "plaintext": 1.5,
            "query": query("RealEq", "weight", FfiValue::Float32(1.5)).await,
        },
        "price": {
            "plaintext": 9.75,
            "query": query("DoubleEq", "price", FfiValue::Float64(9.75)).await,
        },
    });
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/v4_queries.json");
    let rendered = serde_json::to_string_pretty(&fixture).unwrap() + "\n";
    if std::env::var_os("EQL_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &rendered).unwrap();
    }
    let committed = std::fs::read_to_string(&path)
        .expect("fixtures/v4_queries.json is committed; EQL_UPDATE_FIXTURES=1 writes it");
    assert_eq!(
        committed, rendered,
        "the committed fixture is what the dispatch derives today"
    );
}

/// `fixtures/v4_rows.json`: `Profile` rows the Go SDK's generated code sealed
/// over the deterministic EQL guest (`TestV4RowsMatchTheCommittedFixture` in
/// languages/golang/encrypt writes it). The guest derives its keys with
/// stack-kms's `DeterministicSource`, so a cipher over the same seed opens
/// what Go sealed.
mod go_rows {
    use super::*;
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
        pub visits: i32,
        pub balance: i64,
        pub active: bool,
        pub ratio: f32,
        pub score: f64,
        pub note: String,
        pub name: String,
        pub age: i32,
        pub rank: i64,
        pub weight: f32,
        pub price: f64,
    }

    /// The committed rows, or the file `EQL_V4_ROWS` names: CI points it at
    /// rows the Go SDK sealed in the same job, so today's Go ciphertexts
    /// reach Rust, not only the committed ones.
    pub fn fixture() -> Fixture {
        let path = std::env::var_os("EQL_V4_ROWS").map_or_else(
            || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/v4_rows.json"),
            std::path::PathBuf::from,
        );
        let raw = std::fs::read_to_string(path).expect(
            "fixtures/v4_rows.json is written by the Go SDK's TestV4RowsMatchTheCommittedFixture",
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
        Identifier::for_column("profiles", name).unwrap()
    }

    /// The stored value under `column`, parsed as its v4 type: the shape, the
    /// version and the terms the Go code wrote.
    pub fn parsed<T: DeserializeOwned>(row: &Row, column: &str) -> T {
        serde_json::from_value(row.stored[column].clone())
            .unwrap_or_else(|e| panic!("row {} {column}: {e}", row.id))
    }

    /// Open every field of `row` and check it against the plaintext Go
    /// sealed.
    pub async fn open_row(
        cipher: &stack_encrypt::StackCipher<stack_kms::DeterministicSource>,
        row: &Row,
    ) {
        let p = &row.plaintext;
        let visits: Int32 = cipher
            .decrypt_as(
                parsed::<integer::Integer>(row, "visits"),
                column("visits").into(),
            )
            .await
            .unwrap();
        assert_eq!(visits.0, p.visits);
        let balance: Int64 = cipher
            .decrypt_as(
                parsed::<bigint::Bigint>(row, "balance"),
                column("balance").into(),
            )
            .await
            .unwrap();
        assert_eq!(balance.0, p.balance);
        let active: Bool = cipher
            .decrypt_as(
                parsed::<boolean::Boolean>(row, "active"),
                column("active").into(),
            )
            .await
            .unwrap();
        assert_eq!(active.0, p.active);
        let ratio: Float32 = cipher
            .decrypt_as(parsed::<real::Real>(row, "ratio"), column("ratio").into())
            .await
            .unwrap();
        assert_eq!(ratio.0.to_bits(), p.ratio.to_bits());
        let score: Float64 = cipher
            .decrypt_as(
                parsed::<double::Double>(row, "score"),
                column("score").into(),
            )
            .await
            .unwrap();
        assert_eq!(score.0.to_bits(), p.score.to_bits());
        let note: String = cipher
            .decrypt_as(parsed::<text::Text>(row, "note"), column("note").into())
            .await
            .unwrap();
        assert_eq!(note, p.note);
        let name: String = cipher
            .decrypt_as(
                parsed::<text::TextMatch>(row, "name"),
                column("name").into(),
            )
            .await
            .unwrap();
        assert_eq!(name, p.name);
        let age: Int32 = cipher
            .decrypt_as(
                parsed::<integer::IntegerEq>(row, "age"),
                column("age").into(),
            )
            .await
            .unwrap();
        assert_eq!(age.0, p.age);
        let rank: Int64 = cipher
            .decrypt_as(
                parsed::<bigint::BigintEq>(row, "rank"),
                column("rank").into(),
            )
            .await
            .unwrap();
        assert_eq!(rank.0, p.rank);
        let weight: Float32 = cipher
            .decrypt_as(
                parsed::<real::RealEq>(row, "weight"),
                column("weight").into(),
            )
            .await
            .unwrap();
        assert_eq!(weight.0.to_bits(), p.weight.to_bits());
        let price: Float64 = cipher
            .decrypt_as(
                parsed::<double::DoubleEq>(row, "price"),
                column("price").into(),
            )
            .await
            .unwrap();
        assert_eq!(price.0.to_bits(), p.price.to_bits());
    }
}

/// What the Go SDK sealed parses as each v4 type and opens in Rust, field by
/// field, under the column it was stored under.
#[tokio::test]
async fn rows_the_go_sdk_sealed_open_in_rust() {
    let fixture = go_rows::fixture();
    assert_eq!(fixture.table, "profiles");
    assert!(!fixture.rows.is_empty());
    let cipher = go_rows::cipher(&fixture.seed).await;
    for row in &fixture.rows {
        go_rows::open_row(&cipher, row).await;
    }
}

/// The Go-sealed rows in PostgreSQL: each value passes its `eql_v4_*` domain
/// check, `@@` and `=` find the rows with the fixture's query operands (which
/// the Go SDK's test derives byte for byte), and what comes back out still
/// opens.
#[test]
#[ignore = "requires EQL_TEST_DATABASE_URL pointing to an EQL v4 database"]
fn postgres_stores_and_queries_rows_the_go_sdk_sealed() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let fixture = go_rows::fixture();
    let cipher = runtime.block_on(go_rows::cipher(&fixture.seed));
    let mut db = postgres::Client::connect(
        &std::env::var("EQL_TEST_DATABASE_URL").expect("EQL_TEST_DATABASE_URL"),
        postgres::NoTls,
    )
    .unwrap();
    db.batch_execute(
        "CREATE TEMP TABLE go_profiles (
            id int PRIMARY KEY,
            visits public.eql_v4_integer,
            balance public.eql_v4_bigint,
            active public.eql_v4_boolean,
            ratio public.eql_v4_real,
            score public.eql_v4_double,
            note public.eql_v4_text,
            name public.eql_v4_text_match,
            age public.eql_v4_integer_eq,
            rank public.eql_v4_bigint_eq,
            weight public.eql_v4_real_eq,
            price public.eql_v4_double_eq
        );",
    )
    .unwrap();
    for row in &fixture.rows {
        let v = |column: &str| row.stored[column].to_string();
        db.execute(
            "INSERT INTO go_profiles VALUES ($1,
                $2::text::jsonb::public.eql_v4_integer,
                $3::text::jsonb::public.eql_v4_bigint,
                $4::text::jsonb::public.eql_v4_boolean,
                $5::text::jsonb::public.eql_v4_real,
                $6::text::jsonb::public.eql_v4_double,
                $7::text::jsonb::public.eql_v4_text,
                $8::text::jsonb::public.eql_v4_text_match,
                $9::text::jsonb::public.eql_v4_integer_eq,
                $10::text::jsonb::public.eql_v4_bigint_eq,
                $11::text::jsonb::public.eql_v4_real_eq,
                $12::text::jsonb::public.eql_v4_double_eq)",
            &[
                &row.id,
                &v("visits"),
                &v("balance"),
                &v("active"),
                &v("ratio"),
                &v("score"),
                &v("note"),
                &v("name"),
                &v("age"),
                &v("rank"),
                &v("weight"),
                &v("price"),
            ],
        )
        .unwrap();
    }

    let queries: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/v4_queries.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let needle = queries["name"]["plaintext"].as_str().unwrap();
    let ids: Vec<i32> = db
        .query(
            "SELECT id FROM go_profiles WHERE name @@ $1::text::jsonb::eql_v4.query_text_match ORDER BY id",
            &[&queries["name"]["query"].as_str().unwrap()],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    // `@@` folds case, so the expectation does too. It is exact only because
    // no committed row's filter covers the needle's bits by chance: a Bloom
    // filter may, and a regenerated fixture that turns one up fails here
    // against a correct database.
    let needle_folded = needle.to_lowercase();
    let expected: Vec<i32> = fixture
        .rows
        .iter()
        .filter(|r| r.plaintext.name.to_lowercase().contains(&needle_folded))
        .map(|r| r.id)
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(ids, expected, "@@ {needle:?} over Go-sealed names");

    // `=` on each equality column, against the rows whose plaintext equals
    // the query's.
    let equal = |column_name: &str, query_domain: &str, holds: &dyn Fn(&go_rows::Plain) -> bool| {
        let expected: Vec<i32> = fixture
            .rows
            .iter()
            .filter(|r| holds(&r.plaintext))
            .map(|r| r.id)
            .collect();
        assert!(!expected.is_empty(), "{column_name}: a row matches");
        (expected, column_name.to_owned(), query_domain.to_owned())
    };
    let plain = |key: &str| queries[key]["plaintext"].clone();
    let checks = [
        equal("age", "query_integer_eq", &|p| {
            serde_json::json!(p.age) == plain("age")
        }),
        equal("rank", "query_bigint_eq", &|p| {
            serde_json::json!(p.rank) == plain("rank")
        }),
        equal("weight", "query_real_eq", &|p| {
            f64::from(p.weight) == plain("weight").as_f64().unwrap()
        }),
        equal("price", "query_double_eq", &|p| {
            p.price == plain("price").as_f64().unwrap()
        }),
    ];
    for (expected, column_name, query_domain) in checks {
        let ids: Vec<i32> = db
            .query(
                &format!(
                    "SELECT id FROM go_profiles WHERE {column_name} = $1::text::jsonb::eql_v4.{query_domain} ORDER BY id"
                ),
                &[&queries[column_name.as_str()]["query"].as_str().unwrap()],
            )
            .unwrap()
            .iter()
            .map(|r| r.get(0))
            .collect();
        assert_eq!(ids, expected, "= over Go-sealed {column_name}");
    }

    // Read back from the domains and open again.
    for row in &fixture.rows {
        let back = db
            .query_one(
                "SELECT (to_jsonb(p) - 'id')::text FROM go_profiles p WHERE id = $1",
                &[&row.id],
            )
            .unwrap();
        let stored: String = back.get(0);
        let round_tripped = go_rows::Row {
            id: row.id,
            plaintext: row.plaintext.clone(),
            stored: serde_json::from_str(&stored).unwrap(),
        };
        runtime.block_on(go_rows::open_row(&cipher, &round_tripped));
    }
}
