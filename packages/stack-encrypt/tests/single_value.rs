//! Tests that the run-time interface (`dynamic::value`) and the typed
//! interface (`keyset.encrypt`, `keyset.decrypt`) agree on one value as one
//! ciphertext.
//!
//! In these tests, "seal" means encrypt and authenticate a value. "Open"
//! means decrypt a ciphertext and check it. A leaf is the one sealed scalar
//! inside a ciphertext.
//!
//! Each sealed leaf has a random AES-GCM nonce, so two ciphertexts of one
//! value never have the same bytes. The two interfaces must agree on every
//! other part:
//!
//! - the bytes before the output of the leaf's authenticated encryption:
//!   the format version, the keyset, and the IV and tag of the data key
//! - the length of the ciphertext
//! - the plaintext that the leaf was sealed with
//!
//! The tests seal each value through both interfaces, and compare those
//! parts. Each interface gets a new deterministic key source with the same
//! seed. The tests also open the ciphertext of each interface through the
//! other interface.
// The typed `Uuid` case needs the `uuid` feature. The `dynamic` feature
// does not turn `uuid` on.
#![cfg(all(feature = "dynamic", feature = "uuid"))]

mod common;

use std::sync::atomic::Ordering;

use common::frames::{frame, owned};
use common::leaves::{kept_cipher, parts, Parts};
use miette::Diagnostic as _;
use proptest::prelude::*;
use serde_json::json;
use stack_encrypt::dynamic::{self, frame::OwnedFrame, value, Reason, ValueKind};
use stack_encrypt::json::JsonPlaintext;
use stack_encrypt::kms::IdentifiedBy;
use stack_encrypt::value::{Date, Decimal, Timestamp, Uuid as UuidValue};
use stack_encrypt::{CipherText, Ciphertext, ContextPiece, Error, IntoContext, OpaqueEncode};
use vitaminc_aead::frame::PASSTHROUGH;
use vitaminc_aead::plaintext::{FixedType, Int, Logical, Physical, Raw, Width};

const SEED: [u8; 32] = *b"stack-encrypt single value v1   ";

/// A context that a test seals under, other than the empty context.
fn column() -> ContextPiece<'static> {
    ("users", "value").into_context().into_owned()
}

/// The empty context. `keyset.encrypt` and `value::encrypt` use it.
fn no_context() -> ContextPiece<'static> {
    ().into_context()
}

/// `value` sealed by the typed call, over a new key source of the seed.
async fn typed<S: OpaqueEncode>(value: S, context: &ContextPiece<'static>) -> (Ciphertext, Parts) {
    let (cipher, keys) = kept_cipher(SEED).await;
    let sealed = cipher
        .default_keyset()
        .encrypt_with_context(value, context.clone())
        .await
        .expect("the typed call seals");
    (sealed.clone(), parts(&keys, sealed, context.clone()))
}

/// `value` sealed by the run-time call, over a new key source of the seed.
async fn run_time(
    value: &OwnedFrame,
    kind: Option<ValueKind>,
    context: &ContextPiece<'static>,
) -> (Ciphertext, Parts) {
    let (cipher, keys) = kept_cipher(SEED).await;
    let sealed = value::encrypt_with_context(
        &cipher.default_keyset(),
        value.frame(),
        kind,
        context.clone(),
    )
    .expect("the run-time call takes the value")
    .await
    .expect("the run-time call seals");
    (sealed.clone(), parts(&keys, sealed, context.clone()))
}

/// The run-time call and the typed call seal the same parts for one value,
/// and each call opens the ciphertext of the other. `typed_value` builds the
/// typed value. `frame_of` builds the frame that a binding passes. `stored`
/// builds the frame that the value opens as.
async fn assert_same_ciphertext<S, T>(
    name: &str,
    typed_value: impl Fn() -> S,
    frame_of: &OwnedFrame,
    kind: Option<ValueKind>,
    stored: &OwnedFrame,
    read_back: impl Fn(&T) -> OwnedFrame,
) where
    S: OpaqueEncode,
    T: stack_encrypt::OpaqueDecode,
{
    for context in [no_context(), column()] {
        let (typed_ciphertext, typed_parts) = typed(typed_value(), &context).await;
        let (run_time_ciphertext, run_time_parts) = run_time(frame_of, kind, &context).await;
        assert_eq!(
            run_time_parts, typed_parts,
            "{name}: the run-time ciphertext differs from the typed one in a part that is not the nonce"
        );

        let (cipher, _) = kept_cipher(SEED).await;
        let keyset = cipher.default_keyset();
        let opened: T = keyset
            .decrypt_with_context(run_time_ciphertext, context.clone())
            .await
            .unwrap_or_else(|error| {
                panic!("{name}: the typed call opens the run-time ciphertext: {error}")
            });
        assert_eq!(
            read_back(&opened).frame(),
            stored.frame(),
            "{name}: the typed call reads another value from the run-time ciphertext"
        );
        let opened = value::decrypt_with_context(&keyset, typed_ciphertext, None, context.clone())
            .await
            .unwrap_or_else(|error| {
                panic!("{name}: the run-time call opens the typed ciphertext: {error}")
            });
        assert_eq!(
            opened.frame(),
            stored.frame(),
            "{name}: the run-time call reads another value from the typed ciphertext"
        );
    }
}

fn int(int: Int) -> OwnedFrame {
    frame(Raw(None, Physical::Int(int)))
}

fn date() -> Date {
    Date::new("2024-02-29".parse::<jiff::civil::Date>().expect("a date"))
}

fn timestamp() -> Timestamp {
    Timestamp::new(
        "2026-10-17T01:02:03.123456789Z"
            .parse::<jiff::Timestamp>()
            .expect("an instant"),
    )
    .expect("in range")
}

fn decimal() -> Decimal {
    Decimal::new(
        "-1234.5600"
            .parse::<rust_decimal::Decimal>()
            .expect("a decimal"),
    )
}

fn uuid_value() -> UuidValue {
    UuidValue::new(uuid::Uuid::from_u128(
        0x123e_4567_e89b_12d3_a456_4266_1417_4000,
    ))
}

mod the_run_time_ciphertext_is_the_typed_one {
    use super::*;

    /// A value of a Rust type whose frame is of the same kind. The test
    /// runs with the kind declared and with no declared kind.
    macro_rules! same {
        ($name:literal, $kind:expr, $ty:ty, $value:expr) => {{
            let stored = frame($value);
            for declared in [None, Some($kind)] {
                assert_same_ciphertext(
                    $name,
                    || $value,
                    &stored,
                    declared,
                    &stored,
                    |opened: &$ty| frame(opened),
                )
                .await;
            }
        }};
    }

    #[tokio::test]
    async fn for_every_scalar_kind_a_rust_type_spells() {
        same!("bool", ValueKind::Bool, bool, true);
        same!("int8", ValueKind::Int8, i8, -8i8);
        same!("int16", ValueKind::Int16, i16, -300i16);
        same!("int32", ValueKind::Int32, i32, -2i32);
        same!("int64", ValueKind::Int64, i64, -9_007_199_254_740_993i64);
        same!("int128", ValueKind::Int128, i128, i128::MIN);
        same!("uint16", ValueKind::UInt16, u16, 60_000u16);
        same!("uint32", ValueKind::UInt32, u32, 4_000_000_000u32);
        same!("uint64", ValueKind::UInt64, u64, u64::MAX);
        same!("uint128", ValueKind::UInt128, u128, u128::MAX);
        same!("float32", ValueKind::Float32, f32, 1.5f32);
        same!("float64", ValueKind::Float64, f64, -0.0f64);
        same!("string", ValueKind::String, String, String::from("café"));
        same!("empty string", ValueKind::String, String, String::new());
        same!("bytes", ValueKind::Bytes, Vec<u8>, vec![0u8, 255, 16]);
        same!("date", ValueKind::Date, Date, date());
        same!("timestamp", ValueKind::Timestamp, Timestamp, timestamp());
        same!("decimal", ValueKind::Decimal, Decimal, decimal());
        same!("uuid", ValueKind::Uuid, UuidValue, uuid_value());
    }

    /// No Rust type spells a lone `u8`: a `Vec<u8>` is a byte string. So
    /// the test compares the run-time leaf with another leaf: the one that
    /// the cipher seals for the same scalar walked as a tree.
    #[tokio::test]
    async fn for_an_unsigned_8_bit_integer() {
        let context = column();
        let scalar = || Raw(None, Physical::Int(Int::U8(200)));
        let (cipher, keys) = kept_cipher(SEED).await;
        let tree = cipher
            .default_keyset()
            .encrypt_tree(scalar(), context.clone())
            .await
            .expect("a scalar seals as a tree of one leaf");
        let CipherText::Single(leaf) = tree else {
            panic!("a scalar seals as one leaf");
        };
        let walked = parts(&keys, Ciphertext::from(leaf), context.clone());
        for declared in [None, Some(ValueKind::UInt8)] {
            let (_, run_time_parts) = run_time(&frame(scalar()), declared, &context).await;
            assert_eq!(
                run_time_parts, walked,
                "uint8 declared as {declared:?}: the run-time leaf differs from the cipher's own"
            );
        }
    }

    /// A number of another width or kind seals as the value of the
    /// declared kind. The typed call makes the same ciphertext parts for
    /// that value.
    #[tokio::test]
    async fn for_a_number_converted_to_its_declared_kind() {
        assert_same_ciphertext(
            "float64 34 as uint64",
            || 34u64,
            &frame(34.0f64),
            Some(ValueKind::UInt64),
            &frame(34u64),
            |opened: &u64| frame(*opened),
        )
        .await;
        assert_same_ciphertext(
            "int64 -7 as int8",
            || -7i8,
            &frame(-7i64),
            Some(ValueKind::Int8),
            &frame(-7i8),
            |opened: &i8| frame(*opened),
        )
        .await;
        assert_same_ciphertext(
            "int32 12 as float64",
            || 12.0f64,
            &frame(12i32),
            Some(ValueKind::Float64),
            &frame(12.0f64),
            |opened: &f64| frame(*opened),
        )
        .await;
        assert_same_ciphertext(
            "int64 5 as decimal",
            || Decimal::new(rust_decimal::Decimal::new(5, 0)),
            &frame(5i64),
            Some(ValueKind::Decimal),
            &frame(Decimal::new(rust_decimal::Decimal::new(5, 0))),
            |opened: &Decimal| frame(opened),
        )
        .await;
    }

    /// A document arrives as JSON text, as a text value or a bytes value.
    /// `encrypt` seals it as the typed call seals the document: as its
    /// compact JSON text.
    #[tokio::test]
    async fn for_a_json_document() {
        let text = r#"{ "b": [1, 2.5, null], "a": "é" }"#;
        let document = || JsonPlaintext::parse(text).expect("a document");
        // What a `String` reads back: the text that the document was sealed as.
        let sealed_text = frame(r#"{"a":"é","b":[1,2.5,null]}"#);
        for (name, crossing) in [
            ("json as text", frame(text)),
            ("json as bytes", frame(text.as_bytes().to_vec())),
        ] {
            assert_same_ciphertext(
                name,
                document,
                &crossing,
                Some(ValueKind::Json),
                &sealed_text,
                |opened: &String| frame(opened.as_str()),
            )
            .await;
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// For any scalar, any context, and the scalar's own kind as the
        /// declared kind, the run-time ciphertext has the parts of the typed
        /// ciphertext.
        #[test]
        fn for_any_generated_scalar(
            scalar in any_scalar(),
            declare in any::<bool>(),
            context in proptest::option::of("[a-z]{1,8}"),
        ) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a runtime");
            let context = match &context {
                Some(context) => context.as_str().into_context().into_owned(),
                None => no_context(),
            };
            let (run_time_parts, typed_parts) = runtime.block_on(async {
                let declared = declare.then_some(scalar.kind());
                let (_, run_time_parts) = run_time(&scalar.frame(), declared, &context).await;
                (run_time_parts, scalar.typed_parts(&context).await)
            });
            prop_assert_eq!(
                run_time_parts,
                typed_parts,
                "a {:?} sealed at run time differs from the typed ciphertext",
                scalar.kind()
            );
        }
    }

    /// One generated scalar, of a kind that a Rust type spells.
    #[derive(Debug, Clone)]
    enum Scalar {
        Bool(bool),
        Int64(i64),
        UInt64(u64),
        Float64(f64),
        Text(String),
        Bytes(Vec<u8>),
    }

    fn any_scalar() -> impl Strategy<Value = Scalar> {
        prop_oneof![
            any::<bool>().prop_map(Scalar::Bool),
            any::<i64>().prop_map(Scalar::Int64),
            any::<u64>().prop_map(Scalar::UInt64),
            any::<f64>().prop_map(Scalar::Float64),
            ".{0,24}".prop_map(Scalar::Text),
            proptest::collection::vec(any::<u8>(), 0..24).prop_map(Scalar::Bytes),
        ]
    }

    impl Scalar {
        fn kind(&self) -> ValueKind {
            match self {
                Scalar::Bool(_) => ValueKind::Bool,
                Scalar::Int64(_) => ValueKind::Int64,
                Scalar::UInt64(_) => ValueKind::UInt64,
                Scalar::Float64(_) => ValueKind::Float64,
                Scalar::Text(_) => ValueKind::String,
                Scalar::Bytes(_) => ValueKind::Bytes,
            }
        }

        fn frame(&self) -> OwnedFrame {
            match self {
                Scalar::Bool(value) => frame(*value),
                Scalar::Int64(value) => frame(*value),
                Scalar::UInt64(value) => frame(*value),
                Scalar::Float64(value) => frame(*value),
                Scalar::Text(value) => frame(value.as_str()),
                Scalar::Bytes(value) => frame(value.clone()),
            }
        }

        async fn typed_parts(&self, context: &ContextPiece<'static>) -> Parts {
            match self {
                Scalar::Bool(value) => typed(*value, context).await.1,
                Scalar::Int64(value) => typed(*value, context).await.1,
                Scalar::UInt64(value) => typed(*value, context).await.1,
                Scalar::Float64(value) => typed(*value, context).await.1,
                Scalar::Text(value) => typed(value.clone(), context).await.1,
                Scalar::Bytes(value) => typed(value.clone(), context).await.1,
            }
        }
    }
}

/// A frame written by hand: a passthrough of the text `clear`.
fn passthrough() -> OwnedFrame {
    let mut bytes = vec![PASSTHROUGH];
    bytes.extend_from_slice(frame("clear").frame().as_bytes());
    owned(&bytes)
}

fn typed_null() -> OwnedFrame {
    OwnedFrame::typed_null(FixedType::plain(Width::I64).expect("a fixed type"))
}

fn undefined() -> OwnedFrame {
    frame(Raw(Some(Logical::Undefined), Physical::Null))
}

/// The refusal that `value::encrypt` makes for `value` under `kind`. Also
/// checks that the call made no key request.
async fn refused(value: &OwnedFrame, kind: Option<ValueKind>) -> dynamic::Error {
    let (cipher, generates, retrieves) = common::counting_cipher().await;
    let keyset = cipher.default_keyset();
    let single = match value::encrypt(&keyset, value.frame(), kind) {
        Err(error) => error,
        Ok(_) => panic!("a value under {kind:?} was taken where a refusal was expected"),
    };
    let with_context =
        match value::encrypt_with_context(&keyset, value.frame(), kind, "users/value") {
            Err(error) => error,
            Ok(_) => panic!("the form with a context took what the form without refused"),
        };
    assert_eq!(
        with_context.reason(),
        single.reason(),
        "the form with a context refuses for the same reason"
    );
    assert_eq!(
        generates.load(Ordering::SeqCst),
        0,
        "a refused value requests no data key"
    );
    assert_eq!(
        retrieves.load(Ordering::SeqCst),
        0,
        "a refused value retrieves no data key"
    );
    single
}

/// A single-value refusal has its own variant and code, the reason, and a
/// message about one value. The message mentions no record, plan, or field.
fn assert_value_refusal(error: &dynamic::Error, reason: Reason, what: &str) {
    use stack_encrypt::ErrorPayload as _;
    assert!(
        matches!(error, dynamic::Error::Value { .. }),
        "{what}: expected a single-value refusal, got: {error:?}"
    );
    assert_eq!(error.reason(), Some(reason), "{what}: the reason");
    assert_eq!(error.field(), None, "{what}: one value names no field");
    assert_eq!(
        error.code().map(|code| code.to_string()).as_deref(),
        Some("stack_encrypt::dynamic_value"),
        "{what}: the diagnostic code"
    );
    assert_eq!(
        error
            .payload()
            .get("reason")
            .and_then(|value| value.as_str()),
        Some(reason.as_str()),
        "{what}: the payload carries the reason"
    );
    // The display text of two reasons mentions a field of a record. One
    // value has no field, so `Error::Value` has its own text for those
    // reasons.
    let found = match reason {
        Reason::FieldType => "it does not convert exactly to the declared kind".to_owned(),
        Reason::Undefined => "it is undefined".to_owned(),
        found => found.to_string(),
    };
    let message = error.to_string();
    assert_eq!(
        message,
        format!("the value cannot be encrypted as one ciphertext: {found}"),
        "{what}: the message is about one value"
    );
    for word in ["field", "record", "plan"] {
        assert!(
            !message.contains(word),
            "{what}: the message speaks of a {word}, and one value has none: {message}"
        );
    }
}

mod encrypt_refuses_before_any_key_request {
    use super::*;

    #[tokio::test]
    async fn a_value_that_is_not_one_scalar() {
        let cases = [
            ("an array", frame(vec!["a", "b"]), Reason::Array),
            ("an empty array", frame(Vec::<String>::new()), Reason::Array),
            (
                "an object",
                frame(std::collections::BTreeMap::from([("a", 1u32)])),
                Reason::Object,
            ),
            ("a passthrough", passthrough(), Reason::Passthrough),
            ("a plain null", OwnedFrame::null(), Reason::Null),
            ("a typed null", typed_null(), Reason::Null),
        ];
        for (what, value, reason) in &cases {
            // With no declared kind, and with a kind of each shape. The refusal
            // reports what was found, whatever kind was declared.
            for kind in [
                None,
                Some(ValueKind::Int64),
                Some(ValueKind::Array),
                Some(ValueKind::Object),
                Some(ValueKind::Json),
            ] {
                let error = refused(value, kind).await;
                assert_value_refusal(&error, *reason, &format!("{what} under {kind:?}"));
            }
        }
    }

    /// `undefined` is most often a misspelt property name. No typed call
    /// could read it back. So `encrypt` refuses it with a declared kind and
    /// with none.
    #[tokio::test]
    async fn undefined_whatever_kind_is_declared() {
        for kind in [
            None,
            Some(ValueKind::Int64),
            Some(ValueKind::String),
            Some(ValueKind::Json),
            Some(ValueKind::Array),
        ] {
            let error = refused(&undefined(), kind).await;
            assert_value_refusal(
                &error,
                Reason::Undefined,
                &format!("undefined under {kind:?}"),
            );
        }
    }

    #[tokio::test]
    async fn a_value_that_is_not_of_the_declared_kind() {
        let cases = [
            ("text as int64", frame("34"), ValueKind::Int64),
            ("a fraction as uint64", frame(34.5f64), ValueKind::UInt64),
            ("300 as int8", frame(300i64), ValueKind::Int8),
            ("an integer as string", frame(34i64), ValueKind::String),
            ("an integer as date", frame(0i32), ValueKind::Date),
            ("a scalar as array", frame(34i64), ValueKind::Array),
            ("a scalar as object", frame("a"), ValueKind::Object),
            ("an integer as json", frame(1i64), ValueKind::Json),
            ("a boolean as json", frame(true), ValueKind::Json),
        ];
        for (what, value, kind) in &cases {
            let error = refused(value, Some(*kind)).await;
            assert_value_refusal(&error, Reason::FieldType, what);
        }
    }

    #[tokio::test]
    async fn text_that_is_not_a_json_document() {
        let cases = [
            ("not JSON", r#"{"a": "#, Reason::JsonSyntax),
            (
                "a repeated member",
                r#"{"a":1,"a":2}"#,
                Reason::JsonDuplicateKey,
            ),
            (
                "an integer outside 64 bits",
                "18446744073709551616",
                Reason::JsonIntegerRange,
            ),
        ];
        for (what, text, reason) in cases {
            for crossing in [frame(text), frame(text.as_bytes().to_vec())] {
                let error = refused(&crossing, Some(ValueKind::Json)).await;
                assert_value_refusal(&error, reason, what);
            }
        }
    }

    /// A refusal names the kind of value that was found, and contains no
    /// part of the value.
    #[tokio::test]
    async fn without_any_of_the_value_in_the_error() {
        let secret = "sk_live_4242424242";
        let cases = [
            (frame(vec![secret]), None),
            (frame(secret), Some(ValueKind::Int64)),
            (
                frame(format!(r#"{{"key": "{secret}""#)),
                Some(ValueKind::Json),
            ),
        ];
        for (value, kind) in &cases {
            let error = refused(value, *kind).await;
            let shown = format!(
                "{error} {error:?} {:?}",
                error.help().map(|h| h.to_string())
            );
            assert!(
                !shown.contains(secret) && !shown.contains("4242"),
                "the refusal under {kind:?} shows the value: {shown}"
            );
        }
    }
}

mod encrypt_with_no_declared_kind {
    use super::*;

    /// A scalar of a logical type that this build does not define. The frame
    /// and the leaf record the id of the type, and no kind names it.
    fn unknown_logical() -> OwnedFrame {
        let unknown = Logical::from_wire(200, 9).expect("an id no build knows yet");
        frame(Raw(Some(unknown), Physical::Int(Int::I32(7))))
    }

    /// The leaf format records a logical type that this build does not
    /// define. So an older build can store a value of a newer type. The
    /// value is one scalar. `encrypt` seals it as it arrived.
    #[tokio::test]
    async fn seals_a_scalar_of_an_unknown_logical_type_as_it_arrived() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let value = unknown_logical();
        assert_eq!(value.frame().kind(), None, "no kind names the type");
        let sealed = value::encrypt(&keyset, value.frame(), None)
            .expect("a scalar of an unknown logical type is one scalar")
            .await
            .expect("it seals");
        let opened = value::decrypt(&keyset, sealed.clone(), None)
            .await
            .expect("it opens with no declared kind");
        assert_eq!(
            opened.frame(),
            value.frame(),
            "the value opens with its type id"
        );

        // The ciphertext opens as no declared kind, and as no Rust type.
        let as_int = value::decrypt(&keyset, sealed.clone(), Some(ValueKind::Int32)).await;
        assert!(
            matches!(as_int, Err(Error::OpenedType { expected: "int32" })),
            "an unknown logical type is not an int32, got: {as_int:?}"
        );
        let typed = keyset.decrypt::<i32>(sealed).await;
        assert!(
            matches!(typed, Err(Error::OpenedType { .. })),
            "no Rust type reads an unknown logical type, got: {typed:?}"
        );
    }

    #[tokio::test]
    async fn refuses_an_unknown_logical_type_under_a_declared_kind() {
        for kind in [ValueKind::Int32, ValueKind::Date, ValueKind::Json] {
            let error = refused(&unknown_logical(), Some(kind)).await;
            assert_value_refusal(
                &error,
                Reason::FieldType,
                &format!("an unknown logical type as {kind}"),
            );
        }
    }

    /// A known logical type over a value that the type does not admit never
    /// reaches `encrypt`, because no frame can contain one. The frame
    /// writer refuses to write it. The frame reader refuses bytes that spell
    /// it.
    #[test]
    fn a_logical_type_over_a_value_it_does_not_admit_is_not_a_frame() {
        let short_uuid = Raw(Some(Logical::Uuid), Physical::Bytes(&[7; 15]));
        assert!(
            OwnedFrame::of(short_uuid).is_err(),
            "the writer must refuse a UUID of fifteen bytes"
        );
        // The frame of a real UUID, with one byte removed from the payload and
        // from the length.
        let uuid = frame(Raw(Some(Logical::Uuid), Physical::Bytes(&[7; 16])));
        let mut bytes = uuid.frame().as_bytes().to_vec();
        let length = bytes.len() - 16 - 4;
        assert_eq!(
            bytes[length..length + 4],
            16u32.to_le_bytes(),
            "the payload's length sits before the payload"
        );
        bytes[length..length + 4].copy_from_slice(&15u32.to_le_bytes());
        let _ = bytes.pop();
        assert!(
            vitaminc_aead::Frame::parse(&bytes).is_err(),
            "the reader must refuse a UUID of fifteen bytes"
        );

        let out_of_range = Raw(Some(Logical::Date), Physical::Int(Int::I64(i64::MAX)));
        assert!(
            OwnedFrame::of(out_of_range).is_err(),
            "the writer must refuse a date outside the range"
        );
    }

    #[tokio::test]
    async fn seals_a_scalar_at_the_width_it_arrived_with() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let sealed = value::encrypt(&keyset, int(Int::U8(7)).frame(), None)
            .expect("a uint8 is one scalar")
            .await
            .expect("it seals");
        let opened = value::decrypt(&keyset, sealed, None)
            .await
            .expect("it opens");
        assert_eq!(
            opened.frame().kind(),
            Some(ValueKind::UInt8),
            "no declared kind converts nothing"
        );
    }
}

mod encrypt_with_a_context {
    use super::*;

    #[tokio::test]
    async fn binds_the_ciphertext_to_it() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let sealed = value::encrypt_with_context(
            &keyset,
            frame("ada@example.com").frame(),
            None,
            ("users", "email"),
        )
        .expect("one scalar")
        .await
        .expect("it seals");

        let without = value::decrypt(&keyset, sealed.clone(), None).await;
        assert!(
            matches!(without, Err(Error::Aead)),
            "the empty context must not open it, got: {without:?}"
        );
        let other =
            value::decrypt_with_context(&keyset, sealed.clone(), None, ("users", "name")).await;
        assert!(
            matches!(other, Err(Error::Aead)),
            "another context must not open it, got: {other:?}"
        );
        let opened = value::decrypt_with_context(&keyset, sealed, None, ("users", "email"))
            .await
            .expect("the same context opens it");
        assert_eq!(
            opened.frame(),
            frame("ada@example.com").frame(),
            "the value under its context"
        );
    }

    /// The call shows the context that it will use, as the typed call does.
    #[tokio::test]
    async fn runs_under_the_context_the_typed_call_runs_under() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let run_time =
            value::encrypt_with_context(&keyset, frame(34i64).frame(), None, ("users", "age"))
                .expect("one scalar");
        let typed = keyset.encrypt_with_context(34i64, ("users", "age"));
        assert_eq!(
            run_time.context(),
            typed.context(),
            "the two calls name different contexts"
        );
        let run_time = value::encrypt(&keyset, frame(34i64).frame(), None).expect("one scalar");
        let typed = keyset.encrypt(34i64);
        assert_eq!(
            run_time.context(),
            typed.context(),
            "the two calls name different empty contexts"
        );
    }
}

/// The run-time interface has no batch call. A binding makes one call for
/// each value, and merges the calls with `Pending::all`. The merged call
/// sends one key request.
mod many_values_merged_with_pending_all {
    use super::*;

    #[tokio::test]
    async fn seal_and_open_in_one_key_request_each_and_keep_their_order() {
        let (cipher, generates, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        // Each value has its own declared kind. The last value also has its own
        // context.
        let values = [frame(1.0f64), frame("two"), frame(true), frame(4i64)];
        let kinds = [
            Some(ValueKind::UInt32),
            Some(ValueKind::String),
            None,
            Some(ValueKind::Int64),
        ];
        let mut calls = Vec::new();
        for (value, kind) in values.iter().zip(kinds).take(3) {
            calls.push(value::encrypt(&keyset, value.frame(), kind).expect("one scalar"));
        }
        calls.push(
            value::encrypt_with_context(&keyset, values[3].frame(), kinds[3], ("users", "n"))
                .expect("one scalar"),
        );
        assert_eq!(
            generates.load(Ordering::SeqCst),
            0,
            "a call requests no key until it is awaited"
        );
        let sealed = stack_encrypt::Pending::all(&keyset, calls)
            .await
            .expect("the merged call seals");
        assert_eq!(sealed.len(), 4, "one ciphertext for each value");
        assert_eq!(
            generates.load(Ordering::SeqCst),
            1,
            "one key request seals the batch"
        );

        retrieves.store(0, Ordering::SeqCst);
        let mut calls = Vec::new();
        for (ciphertext, kind) in sealed.iter().cloned().zip(kinds).take(3) {
            calls.push(value::decrypt(&keyset, ciphertext, kind));
        }
        calls.push(value::decrypt_with_context(
            &keyset,
            sealed[3].clone(),
            kinds[3],
            ("users", "n"),
        ));
        let opened = stack_encrypt::Pending::all(&keyset, calls)
            .await
            .expect("the merged call opens");
        assert_eq!(
            retrieves.load(Ordering::SeqCst),
            1,
            "one key request opens the batch"
        );
        let expected = [frame(1u32), frame("two"), frame(true), frame(4i64)];
        assert_eq!(
            opened.len(),
            expected.len(),
            "one frame for each ciphertext"
        );
        for (position, (opened, expected)) in opened.iter().zip(&expected).enumerate() {
            assert_eq!(
                opened.frame(),
                expected.frame(),
                "the value at position {position} is in its call's place"
            );
        }

        // A value sealed under a context opens only under that context.
        let without = value::decrypt(&keyset, sealed[3].clone(), kinds[3]).await;
        assert!(
            matches!(without, Err(Error::Aead)),
            "the empty context must not open a value sealed under one, got: {without:?}"
        );
    }

    #[tokio::test]
    async fn a_refused_value_stops_the_batch_before_any_key_request() {
        let (cipher, generates, _) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let values = [frame("a"), OwnedFrame::null(), frame(vec!["b"])];
        let calls: Result<Vec<_>, dynamic::Error> = values
            .iter()
            .map(|value| value::encrypt(&keyset, value.frame(), None))
            .collect();
        let error = match calls {
            Err(error) => error,
            Ok(_) => panic!("a batch holding a null was taken"),
        };
        assert_value_refusal(&error, Reason::Null, "the first refused value");
        assert_eq!(
            generates.load(Ordering::SeqCst),
            0,
            "a batch with a refused value requests no data key"
        );
    }

    #[tokio::test]
    async fn a_value_of_another_kind_fails_the_merged_decrypt() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let sealed = [
            keyset.encrypt(1i64).await.expect("it seals"),
            keyset.encrypt(String::from("two")).await.expect("it seals"),
            keyset.encrypt(3i64).await.expect("it seals"),
        ];
        let open_all = |kind: Option<ValueKind>| {
            let calls = sealed
                .iter()
                .cloned()
                .map(|ciphertext| value::decrypt(&keyset, ciphertext, kind))
                .collect();
            stack_encrypt::Pending::all(&keyset, calls)
        };
        let opened = open_all(Some(ValueKind::Int64)).await;
        assert!(
            matches!(opened, Err(Error::OpenedType { expected: "int64" })),
            "a batch holding text must not open as int64, got: {opened:?}"
        );
        let opened = open_all(None)
            .await
            .expect("with no declared kind each value opens as it was sealed");
        assert_eq!(
            opened
                .iter()
                .map(|value| value.frame().kind())
                .collect::<Vec<_>>(),
            [
                Some(ValueKind::Int64),
                Some(ValueKind::String),
                Some(ValueKind::Int64)
            ],
            "each value keeps its own kind"
        );
    }
}

mod decrypt {
    use super::*;

    #[tokio::test]
    async fn returns_the_value_as_it_was_sealed_with_no_declared_kind() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let sealed = keyset.encrypt(34u64).await.expect("it seals");
        let opened = value::decrypt(&keyset, sealed, None)
            .await
            .expect("it opens");
        assert_eq!(opened.frame(), frame(34u64).frame(), "the sealed value");
    }

    #[tokio::test]
    async fn returns_a_value_of_the_declared_kind_and_converts_nothing() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let sealed = keyset.encrypt(34u64).await.expect("it seals");
        let opened = value::decrypt(&keyset, sealed.clone(), Some(ValueKind::UInt64))
            .await
            .expect("a uint64 opens as uint64");
        assert_eq!(opened.frame(), frame(34u64).frame(), "the sealed value");

        // An integer of another width is another kind. `decrypt` converts
        // nothing, as a typed field of a record converts nothing when it opens.
        let narrower = value::decrypt(&keyset, sealed, Some(ValueKind::UInt32)).await;
        assert!(
            matches!(narrower, Err(Error::OpenedType { expected: "uint32" })),
            "a uint64 must not open as uint32, got: {narrower:?}"
        );
    }

    /// A refusal names the kind that was expected. A refusal never says
    /// what the value opened as.
    #[tokio::test]
    async fn refuses_another_kind_without_saying_what_the_value_is() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let sealed = keyset
            .encrypt(String::from("sk_live_4242424242"))
            .await
            .expect("it seals");
        let error = value::decrypt(&keyset, sealed, Some(ValueKind::Int64))
            .await
            .expect_err("text must not open as int64");
        assert!(
            matches!(error, Error::OpenedType { expected: "int64" }),
            "expected OpenedType naming int64, got: {error:?}"
        );
        let shown = format!(
            "{error} {error:?} {:?}",
            error.help().map(|h| h.to_string())
        );
        assert!(
            !shown.contains("string") && !shown.contains("String") && !shown.contains("4242"),
            "the refusal says what the value opened as: {shown}"
        );
    }

    #[tokio::test]
    async fn refuses_an_array_or_an_object_kind_before_any_key_request() {
        let (cipher, _, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let sealed = keyset.encrypt(34u64).await.expect("it seals");
        for (kind, name) in [(ValueKind::Array, "array"), (ValueKind::Object, "object")] {
            let one = value::decrypt(&keyset, sealed.clone(), Some(kind)).await;
            assert!(
                matches!(one, Err(Error::OpenedType { expected }) if expected == name),
                "a ciphertext must not open as {name}, got: {one:?}"
            );
        }
        assert_eq!(
            retrieves.load(Ordering::SeqCst),
            0,
            "a kind no ciphertext holds is refused with no key request"
        );
    }

    #[tokio::test]
    async fn opens_a_null_only_with_no_declared_kind() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let tree = keyset
            .encrypt_tree(None::<i64>, ("users", "age"))
            .await
            .expect("a null seals as a tree of one leaf");
        let CipherText::Single(leaf) = tree else {
            panic!("a null seals as one leaf");
        };
        let sealed = Ciphertext::from(leaf);
        let opened = value::decrypt_with_context(&keyset, sealed.clone(), None, ("users", "age"))
            .await
            .expect("a null leaf opens with no declared kind");
        assert!(
            opened.frame().is_null(),
            "a null leaf opens as the null frame"
        );

        let declared =
            value::decrypt_with_context(&keyset, sealed, Some(ValueKind::Int64), ("users", "age"))
                .await;
        assert!(
            matches!(declared, Err(Error::OpenedType { expected: "int64" })),
            "a null is not a value of the declared kind, got: {declared:?}"
        );
    }

    #[tokio::test]
    async fn opens_only_its_own_keysets_ciphertext_through_a_keyset() {
        let (cipher, _, retrieves) = common::counting_cipher().await;
        let other = cipher.keyset(IdentifiedBy::Name("another-keyset".to_owned().into()));
        let sealed = value::encrypt(&other, frame("elsewhere").frame(), None)
            .expect("one scalar")
            .await
            .expect("it seals under the other keyset");
        retrieves.store(0, Ordering::SeqCst);

        let keyset = cipher.default_keyset();
        let foreign = value::decrypt(&keyset, sealed.clone(), None).await;
        assert!(
            matches!(foreign, Err(Error::ForeignKeyset { .. })),
            "a keyset must not open another keyset's ciphertext, got: {foreign:?}"
        );
        assert_eq!(
            retrieves.load(Ordering::SeqCst),
            0,
            "a foreign ciphertext is refused before any key is retrieved"
        );

        let opened = value::decrypt(&cipher, sealed, None)
            .await
            .expect("the cipher opens a ciphertext of any of its keysets");
        assert_eq!(opened.frame(), frame("elsewhere").frame(), "the value");
    }
}

mod decrypt_a_json_document {
    use super::*;

    /// The frame that a `json` value opens as: its JSON text as a bytes value.
    fn document(text: &str) -> OwnedFrame {
        frame(text.as_bytes().to_vec())
    }

    #[tokio::test]
    async fn returns_the_documents_text_in_a_bytes_leaf() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let sealed = keyset
            .encrypt(JsonPlaintext::from(json!({"name": "Ada", "n": [1.5, -2]})))
            .await
            .expect("a document seals");
        let opened = value::decrypt(&keyset, sealed.clone(), Some(ValueKind::Json))
            .await
            .expect("a document opens as json");
        assert_eq!(
            opened.frame(),
            document(r#"{"n":[1.5,-2],"name":"Ada"}"#).frame(),
            "the document's text, in a bytes leaf"
        );
        assert_eq!(
            opened.frame(),
            dynamic::json_frame(&json!({"name": "Ada", "n": [1.5, -2]}))
                .expect("a document frames")
                .frame(),
            "the frame a record's json field opens as"
        );

        // With no declared kind, the leaf comes back as it was sealed: as text.
        let as_sealed = value::decrypt(&keyset, sealed, None)
            .await
            .expect("it opens");
        assert_eq!(
            as_sealed.frame().kind(),
            Some(ValueKind::String),
            "a document is sealed as a text leaf"
        );
    }

    #[tokio::test]
    async fn round_trips_what_encrypt_sealed_as_json() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let sealed = value::encrypt(
            &keyset,
            document(r#"{ "a" : [ 1 , null ] }"#).frame(),
            Some(ValueKind::Json),
        )
        .expect("a document")
        .await
        .expect("it seals");
        let opened = value::decrypt(&keyset, sealed.clone(), Some(ValueKind::Json))
            .await
            .expect("it opens as json");
        assert_eq!(
            opened.frame(),
            document(r#"{"a":[1,null]}"#).frame(),
            "the document, as the engine writes it"
        );
        let typed: JsonPlaintext = keyset
            .decrypt(sealed)
            .await
            .expect("the typed call opens it");
        assert_eq!(
            typed.value(),
            &json!({"a": [1, null]}),
            "the typed document"
        );
    }

    #[tokio::test]
    async fn refuses_a_value_that_is_not_a_document() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let not_documents = [
            (
                "text that is not JSON",
                keyset.encrypt(String::from("{not json")).await,
            ),
            ("an integer", keyset.encrypt(7i64).await),
            // The typed document reads only a text leaf. `decrypt` as `json` does the
            // same.
            (
                "JSON text in a bytes leaf",
                keyset.encrypt(b"{}".to_vec()).await,
            ),
        ];
        for (what, sealed) in not_documents {
            let sealed = sealed.expect("it seals");
            let opened = value::decrypt(&keyset, sealed, Some(ValueKind::Json)).await;
            assert!(
                matches!(opened, Err(Error::OpenedType { expected: "json" })),
                "{what} must not open as json, got: {opened:?}"
            );
        }
    }

    /// `json` is a declared kind, and the engine stores a document as text.
    /// So a string and a document have one stored form. A kind check cannot
    /// distinguish them.
    #[tokio::test]
    async fn opens_a_string_that_holds_json_text_and_returns_it_as_the_engine_writes_it() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let cases = [
            ("42", "42"),
            (r#""ada""#, r#""ada""#),
            (
                r#"{ "b" : [ 1 , null ], "a" : true }"#,
                r#"{"a":true,"b":[1,null]}"#,
            ),
        ];
        for (sealed_text, opened_text) in cases {
            let sealed = keyset
                .encrypt(String::from(sealed_text))
                .await
                .expect("a string seals");
            let opened = value::decrypt(&keyset, sealed.clone(), Some(ValueKind::Json))
                .await
                .unwrap_or_else(|error| {
                    panic!("the string {sealed_text} holds JSON text and opens as json: {error}")
                });
            assert_eq!(
                opened.frame(),
                document(opened_text).frame(),
                "the string {sealed_text} opens as json to the text the engine writes"
            );
            // The same ciphertext still opens as the string that was sealed.
            let as_string = value::decrypt(&keyset, sealed, Some(ValueKind::String))
                .await
                .expect("a string opens as string");
            assert_eq!(
                as_string.frame(),
                frame(sealed_text).frame(),
                "the string {sealed_text} opens as string unchanged"
            );
        }
    }

    #[tokio::test]
    async fn opens_a_sealed_document_as_a_string() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let sealed = keyset
            .encrypt(JsonPlaintext::from(json!({"name": "Ada", "n": [1.5, -2]})))
            .await
            .expect("a document seals");
        let opened = value::decrypt(&keyset, sealed, Some(ValueKind::String))
            .await
            .expect("a document is stored as text, so it opens as string");
        assert_eq!(
            opened.frame(),
            frame(r#"{"n":[1.5,-2],"name":"Ada"}"#).frame(),
            "the frame holds the JSON text that was sealed, in a text leaf"
        );
    }
}
