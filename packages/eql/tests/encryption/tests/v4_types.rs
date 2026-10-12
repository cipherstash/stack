//! The EQL v4 types Stack Encrypt produces besides `TextEq`: the integer,
//! bigint, boolean, float and storage-only text types. `Json` is not
//! producible yet: a JSON value seals as a tree of leaves and EQL's `c`
//! holds one.
//!
//! Each must round-trip through both entry points (the typed `encrypt_as`
//! and the by-name dispatch a Go plan reaches), seal exactly the leaf
//! vitaminc's value enum seals for the same value (what the Go SDK writes for
//! a plain field of that kind), derive the equality term a plain `i32` or
//! `i64` derives, and refuse a value of another kind.

mod common;

use eql_bindings::encryption::plaintext::{Bool, Float32, Float64, Int32, Int64};
use eql_bindings::encryption::targets::{self as targets, TargetError};
use eql_bindings::encryption::NativeCiphertextVisitor as NativeLeaf;
use eql_bindings::v3::terms::Hmac256;
use eql_bindings::v4::{bigint, boolean, double, integer, real, text};
use eql_bindings::Identifier;
use serde::{de::DeserializeOwned, Serialize};
use stack_encrypt::target::transcode::{Reader, Transcode};
use stack_encrypt::{Label, NonEmpty};
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
    c: eql_bindings::v3::terms::Ciphertext,
) -> FfiValue {
    let native = c.read(NativeLeaf).unwrap();
    cipher.decrypt(native, column()).await.unwrap()
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

#[tokio::test]
async fn integers_round_trip_and_seal_the_value_enum_leaf() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for value in [0, 42, -7, i32::MIN, i32::MAX] {
        let stored: integer::IntegerEq = keyset.encrypt_as(&Int32(value), column()).await.unwrap();
        assert_v4_envelope(&stored, &["v", "i", "c", "hm"]);

        let opened: Int32 = cipher
            .decrypt_as(stored.clone(), column().into())
            .await
            .unwrap();
        assert_eq!(opened.0, value);
        assert!(matches!(
            as_value_enum(&cipher, stored.c.clone()).await,
            FfiValue::Int32(v) if v == value
        ));

        // The term is a plain i32's, so it matches an `int32` field with an
        // equality index written by the Go SDK.
        let plain: Hmac256 = keyset
            .equality_term(value, column())
            .await
            .unwrap()
            .read(Hmac256::visitor())
            .unwrap();
        assert_eq!(stored.hm, plain, "{value}: the equality term of the i32");

        // The query twin derives the same term and carries no ciphertext.
        let query: integer::IntegerEqQuery =
            keyset.encrypt_as(&Int32(value), column()).await.unwrap();
        assert_eq!(query.hm, stored.hm);

        // The by-name dispatch runs the same plan.
        let named: integer::IntegerEq = by_name(&keyset, "IntegerEq", FfiValue::Int32(value)).await;
        assert_eq!(named.hm, stored.hm);
        let opened = targets::decrypt(
            "IntegerEq",
            &cipher,
            &label(),
            &serde_json::to_vec(&stored).unwrap(),
        )
        .unwrap()
        .await
        .unwrap();
        assert!(matches!(opened, FfiValue::Int32(v) if v == value));

        let storage: integer::Integer = keyset.encrypt_as(&Int32(value), column()).await.unwrap();
        assert_v4_envelope(&storage, &["v", "i", "c"]);
    }

    for value in [0i64, -1, i64::MIN, i64::MAX] {
        let stored: bigint::BigintEq = keyset.encrypt_as(&Int64(value), column()).await.unwrap();
        assert_v4_envelope(&stored, &["v", "i", "c", "hm"]);
        let opened: Int64 = cipher
            .decrypt_as(stored.clone(), column().into())
            .await
            .unwrap();
        assert_eq!(opened.0, value);
        assert!(matches!(
            as_value_enum(&cipher, stored.c.clone()).await,
            FfiValue::Int64(v) if v == value
        ));
        let plain: Hmac256 = keyset
            .equality_term(value, column())
            .await
            .unwrap()
            .read(Hmac256::visitor())
            .unwrap();
        assert_eq!(stored.hm, plain, "{value}: the equality term of the i64");
    }
}

#[tokio::test]
async fn equal_values_of_different_widths_have_different_terms() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let narrow: integer::IntegerEq = keyset.encrypt_as(&Int32(42), column()).await.unwrap();
    let wide: bigint::BigintEq = keyset.encrypt_as(&Int64(42), column()).await.unwrap();
    assert_ne!(
        narrow.hm, wide.hm,
        "the term binds the width, as the separate domains do"
    );
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

#[tokio::test]
async fn a_value_of_another_kind_is_refused_not_converted() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    for (name, value, expected) in [
        ("IntegerEq", FfiValue::Int64(1), ValueKind::Int32),
        ("BigintEq", FfiValue::Int32(1), ValueKind::Int64),
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
            age public.eql_v4_integer_eq,
            balance public.eql_v4_bigint_eq,
            age_only public.eql_v4_integer,
            active public.eql_v4_boolean,
            ratio public.eql_v4_real,
            score public.eql_v4_double,
            note public.eql_v4_text
        );
        CREATE INDEX v4_types_age_idx ON v4_types (eql_v4.eq_term(age));",
    )
    .unwrap();

    let json = |value: &dyn erased::Json| value.to_json();
    for (id, age, balance) in [(1, 42, 10i64), (2, 7, 20), (3, 42, 30)] {
        let row = runtime.block_on(async {
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
                    .encrypt_as::<_, integer::Integer>(&Int32(age), column())
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
            )
        });
        db.execute(
            "INSERT INTO v4_types VALUES ($1,
                $2::text::jsonb::public.eql_v4_integer_eq,
                $3::text::jsonb::public.eql_v4_bigint_eq,
                $4::text::jsonb::public.eql_v4_integer,
                $5::text::jsonb::public.eql_v4_boolean,
                $6::text::jsonb::public.eql_v4_real,
                $7::text::jsonb::public.eql_v4_double,
                $8::text::jsonb::public.eql_v4_text)",
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

    let probe: integer::IntegerEqQuery = runtime
        .block_on(async { keyset.encrypt_as(&Int32(42), column()).await })
        .unwrap();
    let ids: Vec<i32> = db
        .query(
            "SELECT id FROM v4_types WHERE age = $1::text::jsonb::eql_v4.query_integer_eq ORDER BY id",
            &[&json(&probe)],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(ids, [1, 3], "IntegerEq equality finds both 42s");

    let probe: bigint::BigintEqQuery = runtime
        .block_on(async { keyset.encrypt_as(&Int64(20), column()).await })
        .unwrap();
    let ids: Vec<i32> = db
        .query(
            "SELECT id FROM v4_types WHERE balance = $1::text::jsonb::eql_v4.query_bigint_eq",
            &[&json(&probe)],
        )
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(ids, [2], "BigintEq equality");

    // Every stored value reads back and opens.
    let row = db
        .query_one(
            "SELECT age::text, active::text, score::text, note::text FROM v4_types WHERE id = 2",
            &[],
        )
        .unwrap();
    let opened: Int32 = runtime
        .block_on(async {
            cipher
                .decrypt_as(
                    serde_json::from_str::<integer::IntegerEq>(row.get(0)).unwrap(),
                    column().into(),
                )
                .await
        })
        .unwrap();
    assert_eq!(opened.0, 7);
    let opened: Bool = runtime
        .block_on(async {
            cipher
                .decrypt_as(
                    serde_json::from_str::<boolean::Boolean>(row.get(1)).unwrap(),
                    column().into(),
                )
                .await
        })
        .unwrap();
    assert!(opened.0);
    let opened: Float64 = runtime
        .block_on(async {
            cipher
                .decrypt_as(
                    serde_json::from_str::<double::Double>(row.get(2)).unwrap(),
                    column().into(),
                )
                .await
        })
        .unwrap();
    assert_eq!(opened.0, 0.25);
    let opened: String = runtime
        .block_on(async {
            cipher
                .decrypt_as(
                    serde_json::from_str::<text::Text>(row.get(3)).unwrap(),
                    column().into(),
                )
                .await
        })
        .unwrap();
    assert_eq!(opened, "note");
    // A storage-only column has no equality operator: it is blocked, not
    // silently compared as jsonb.
    let err = db
        .query("SELECT id FROM v4_types WHERE age_only = age_only", &[])
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
