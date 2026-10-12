//! The EQL v4 types Stack Encrypt produces besides `TextEq`: the
//! storage-only integer, bigint, boolean, float and text types, and
//! `TextMatch`. `Json` is not producible yet: a JSON value seals as a tree of
//! leaves and EQL's `c` holds one. `IntegerEq` and `BigintEq` are held back:
//! their equality term moves to vitaminc 0.6's shared integer PRF domain, and
//! terms stored before that would stop matching.
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
use stack_encrypt::target::transcode::{Reader, Visitor};
use stack_encrypt::{CipherText, Label, NonEmpty};
use vitaminc_aead_value::{FfiValue, ValueKind};

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

/// Withdrawn until vitaminc 0.6: a later re-enable is a deliberate change to
/// this test, not a side effect of a regenerated table.
#[tokio::test]
async fn integer_equality_types_are_held_back_with_their_reason() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for (name, value) in [
        ("IntegerEq", FfiValue::Int32(1)),
        ("BigintEq", FfiValue::Int64(1)),
    ] {
        let target = targets::target(name).expect("in the table");
        assert!(!target.producible, "{name}");
        let error = refused(targets::encrypt(name, &keyset, &label(), value));
        assert!(
            matches!(&error, TargetError::Unproducible { reason, .. } if reason.contains("integer-orderable/v1")),
            "{name}: {error}"
        );
    }
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

    // Text shorter than a 3-gram has no tokens. Stack Encrypt 0.2 refuses it
    // for a stored value as well as a query, so a short value cannot be
    // written to a TextMatch column yet.
    let short: Result<text::TextMatch, _> = keyset.encrypt_as(&"ab".to_owned(), column()).await;
    assert!(short.is_err());
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
    52, 99, 224, 311, 899, 1190, 1228, 1232, 1290, 1378, 1486, 1505, 1529, 1613, 1763, 1848, 1880,
    2027,
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
/// `encrypt_into=IntegerEq` runs this plan and no other. Regenerate with
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
        "age": { "plaintext": 42, "query": query("IntegerEq", "age", FfiValue::Int32(42)).await },
        "balance": {
            "plaintext": 1_234_567_890_123i64,
            "query": query("BigintEq", "balance", FfiValue::Int64(1_234_567_890_123)).await,
        },
        "name": {
            "plaintext": "alice",
            "query": query("TextMatch", "name", FfiValue::String("alice".into())).await,
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
