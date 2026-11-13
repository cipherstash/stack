//! Tests for `JsonPlaintext`, which encrypts a JSON document as one
//! ciphertext. They cover round trips, the stored format, refusals, and
//! cleanup. No service credentials are needed.
use proptest::prelude::*;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;

use stack_encrypt::json::JsonPlaintext;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{equality, Borrowed, CallerContext};
use stack_encrypt::{nonempty, Ciphertext, Controlled, DecryptFrom, EncryptInto, Error, Protected};
use zeroize::Zeroize;

mod common;

const COLUMN: (&str, &str) = ("users", "profile");

/// A document of `levels` nested arrays: `[[[..]]]`.
fn nested(levels: usize) -> Value {
    (0..levels).fold(Value::Null, |inner, _| Value::Array(vec![inner]))
}

fn profile() -> Value {
    json!({
        "name": "Ada Lovelace",
        "age": 36,
        "tags": ["maths", "engines"],
        "nickname": null,
        "address": {"city": "London", "since": 1835.5},
    })
}

mod given_a_document {
    use super::*;

    #[tokio::test]
    async fn it_round_trips_through_every_scalar_entry_point() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();

        let stored = keyset
            .encrypt(JsonPlaintext::from(profile()))
            .await
            .unwrap();
        let opened = keyset.decrypt::<JsonPlaintext>(stored).await.unwrap();
        assert_eq!(opened.value(), &profile());

        let stored = keyset
            .encrypt_with_context(JsonPlaintext::from(profile()), COLUMN)
            .await
            .unwrap();
        let opened = JsonPlaintext::decrypt_from_with_context(stored, &keyset, COLUMN)
            .await
            .unwrap();
        assert_eq!(opened.value(), &profile());

        let stored: Ciphertext = JsonPlaintext::from(profile())
            .encrypt_into_with_context(&keyset, COLUMN)
            .await
            .unwrap();
        let opened = keyset
            .decrypt_with_context::<JsonPlaintext>(stored, COLUMN)
            .await
            .unwrap();
        assert_eq!(opened.value(), &profile());
    }

    #[tokio::test]
    async fn every_kind_of_document_round_trips() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        for document in [
            json!(null),
            json!(false),
            json!(0),
            json!(-9_223_372_036_854_775_808i64),
            json!(18_446_744_073_709_551_615u64),
            json!(0.1),
            json!(""),
            json!("é \u{1F600} \"quoted\" \\ \n"),
            json!([]),
            json!({}),
            json!([[[]], {"": {"": []}}]),
        ] {
            let stored = keyset
                .encrypt_with_context(JsonPlaintext::from(document.clone()), COLUMN)
                .await
                .unwrap();
            let opened = keyset
                .decrypt_with_context::<JsonPlaintext>(stored, COLUMN)
                .await
                .unwrap();
            assert_eq!(opened.value(), &document);
        }
    }

    #[tokio::test]
    async fn it_decrypts_into_a_protected() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let stored = keyset
            .encrypt_with_context(JsonPlaintext::from(profile()), COLUMN)
            .await
            .unwrap();
        let opened = keyset
            .decrypt_with_context::<Protected<JsonPlaintext>>(stored, COLUMN)
            .await
            .unwrap();
        assert_eq!(opened.risky_ref().value(), &profile());
    }
}

mod given_the_stored_format {
    use super::*;

    /// The plaintext of the ciphertext is the document's compact JSON text
    /// in a text leaf: it opens as a `String` holding that text.
    #[tokio::test]
    async fn the_leaf_holds_the_documents_compact_json_text() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let stored = keyset
            .encrypt_with_context(
                JsonPlaintext::from(json!({"b": [1, 2.5, null], "a": "é"})),
                COLUMN,
            )
            .await
            .unwrap();
        let text = keyset
            .decrypt_with_context::<String>(stored, COLUMN)
            .await
            .unwrap();
        assert_eq!(text, r#"{"a":"é","b":[1,2.5,null]}"#);
    }

    /// The other direction: JSON text sealed as a `String`, by this crate
    /// or by another writer of the same leaf, opens as a document. The text
    /// is parsed by the engine's rules, whatever its spacing.
    #[tokio::test]
    async fn json_text_sealed_as_a_string_opens_as_a_document() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let stored = keyset
            .encrypt_with_context(
                r#" { "age" : 3.60e1 , "name" : "Ada" } "#.to_owned(),
                COLUMN,
            )
            .await
            .unwrap();
        let opened = keyset
            .decrypt_with_context::<JsonPlaintext>(stored, COLUMN)
            .await
            .unwrap();
        assert_eq!(opened.value(), &json!({"age": 36.0, "name": "Ada"}));
    }

    /// The ciphertext is as long as the text it seals, plus a constant: a
    /// document one byte longer seals one byte longer.
    #[tokio::test]
    async fn the_ciphertext_is_as_long_as_the_text() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let mut lengths = Vec::new();
        for name in ["Ada", "Adam"] {
            let stored = keyset
                .encrypt_with_context(JsonPlaintext::from(json!({"name": name})), COLUMN)
                .await
                .unwrap();
            lengths.push(stored.to_bytes().len());
        }
        assert_eq!(lengths[1], lengths[0] + 1);
    }
}

/// A document is sealed only if decrypting can read it back. The parser
/// reads at most 127 levels of containers, and a `Value` can hold more.
mod given_a_document_that_would_not_open {
    use super::*;

    #[tokio::test]
    async fn the_deepest_document_the_parser_reads_round_trips() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let stored = keyset
            .encrypt_with_context(JsonPlaintext::from(nested(127)), COLUMN)
            .await
            .unwrap();
        let opened = keyset
            .decrypt_with_context::<JsonPlaintext>(stored, COLUMN)
            .await
            .unwrap();
        assert_eq!(opened.value(), &nested(127));
    }

    #[tokio::test]
    async fn a_deeper_document_is_refused_before_any_key_is_requested() {
        let (cipher, generates, _) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        for levels in [128, 200, 3_000] {
            let refused = keyset
                .encrypt_with_context(JsonPlaintext::from(nested(levels)), COLUMN)
                .await
                .unwrap_err();
            assert!(matches!(refused, Error::Aead), "{levels}: {refused:?}");
        }
        assert_eq!(
            generates.load(Ordering::SeqCst),
            0,
            "nothing was sealed, so no key was requested"
        );
        // The same document as text is refused when it is built.
        let text = serde_json::to_string(&nested(128)).unwrap();
        assert!(JsonPlaintext::parse(&text).is_err());
    }
}

/// A document is a single value, so a target that derives an equality term
/// from one can derive it from a document: the term of its JSON text.
mod given_an_equality_term {
    use super::*;

    fn caller() -> CallerContext {
        CallerContext::from(nonempty!("users/profile"))
    }

    #[tokio::test]
    async fn it_is_the_term_of_the_documents_json_text() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        // The equality term of a value of type `$ty`, under one context.
        macro_rules! term {
            ($ty:ty, $value:expr) => {{
                let value: $ty = $value;
                let term: EqualityTerm = keyset
                    .run(equality::<$ty, _, Borrowed>(), &value, caller())
                    .await
                    .unwrap();
                term
            }};
        }
        macro_rules! term_of_document {
            ($document:expr) => {
                term!(JsonPlaintext, JsonPlaintext::from($document))
            };
        }
        let document = term_of_document!(json!({"b": [1, 2.5], "a": "x"}));
        let text = term!(String, r#"{"a":"x","b":[1,2.5]}"#.to_owned());
        assert_eq!(document.as_bytes(), text.as_bytes());
        // Equal documents have one term, whatever order they were built in.
        let reordered = term_of_document!(json!({"a": "x", "b": [1, 2.5]}));
        assert_eq!(document.as_bytes(), reordered.as_bytes());
        // A different document has another, and `1` is not `1.0`.
        let other = term_of_document!(json!({"a": "y", "b": [1, 2.5]}));
        assert_ne!(document.as_bytes(), other.as_bytes());
        assert_ne!(
            term_of_document!(json!(1)).as_bytes(),
            term_of_document!(json!(1.0)).as_bytes()
        );
    }
}

mod given_a_ciphertext_that_is_not_a_document {
    use super::*;

    #[tokio::test]
    async fn text_that_is_not_json_is_refused_as_another_type() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        for text in [
            "not json",
            "{",
            r#"{"a": 1, "a": 2}"#,
            "18446744073709551616",
            "",
        ] {
            let stored = keyset
                .encrypt_with_context(text.to_owned(), COLUMN)
                .await
                .unwrap();
            let refused = keyset
                .decrypt_with_context::<JsonPlaintext>(stored, COLUMN)
                .await
                .unwrap_err();
            assert!(
                matches!(
                    refused,
                    Error::OpenedType {
                        expected: "JSON document"
                    }
                ),
                "{text:?}: {refused:?}"
            );
            // The message names the type wanted, and none of the text.
            assert_eq!(
                refused.to_string(),
                "the ciphertext opened, but it does not hold a value of the type JSON document"
            );
        }
    }

    #[tokio::test]
    async fn a_leaf_of_another_kind_is_refused_as_another_type() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        // A number is a JSON document as text, and not as an integer leaf.
        let number = keyset.encrypt_with_context(36i64, COLUMN).await.unwrap();
        // The bytes of JSON text: a document is stored as text.
        let bytes = keyset
            .encrypt_with_context(b"{}".to_vec(), COLUMN)
            .await
            .unwrap();
        for stored in [number, bytes] {
            assert!(matches!(
                keyset
                    .decrypt_with_context::<JsonPlaintext>(stored, COLUMN)
                    .await,
                Err(Error::OpenedType {
                    expected: "JSON document"
                })
            ));
        }
    }

    #[tokio::test]
    async fn a_document_does_not_open_as_another_scalar() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let stored = keyset
            .encrypt_with_context(JsonPlaintext::from(json!(36)), COLUMN)
            .await
            .unwrap();
        assert!(matches!(
            keyset.decrypt_with_context::<i64>(stored, COLUMN).await,
            Err(Error::OpenedType { .. })
        ));
    }

    #[tokio::test]
    async fn a_wrong_context_or_changed_bytes_do_not_open() {
        let cipher = common::stack_cipher().await;
        let keyset = cipher.default_keyset();
        let stored = keyset
            .encrypt_with_context(JsonPlaintext::from(profile()), COLUMN)
            .await
            .unwrap();
        assert!(matches!(
            keyset
                .decrypt_with_context::<JsonPlaintext>(stored.clone(), ("users", "other"))
                .await,
            Err(Error::Aead)
        ));
        let mut bytes = stored.to_bytes();
        *bytes.last_mut().unwrap() ^= 1;
        let changed = Ciphertext::from_bytes(&bytes).unwrap();
        assert!(matches!(
            keyset
                .decrypt_with_context::<JsonPlaintext>(changed, COLUMN)
                .await,
            Err(Error::Aead)
        ));
    }
}

mod given_a_plaintext_to_clean_up {
    use super::*;

    #[test]
    fn zeroize_wipes_the_document_to_a_null() {
        let mut document = JsonPlaintext::from(profile());
        document.zeroize();
        assert_eq!(document.value(), &Value::Null);
    }

    #[test]
    fn debug_shows_none_of_the_document() {
        let shown = format!("{:?}", JsonPlaintext::from(profile()));
        assert_eq!(shown, "JsonPlaintext(<redacted>)");
    }
}

/// Any document: scalars of every JSON kind, and containers of them, a few
/// levels deep.
fn any_document() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        // A float that is not finite is not a JSON number.
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(Value::from),
        ".*".prop_map(Value::from),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::from),
            prop::collection::btree_map(".*", inner, 0..6)
                .prop_map(|members| Value::Object(members.into_iter().collect())),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// A document opens as the document that was sealed, and the text it
    /// is stored as is the text `serde_json` writes for it.
    #[test]
    fn any_document_round_trips_as_its_json_text(document in any_document()) {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        runtime.block_on(async {
            let cipher = common::stack_cipher().await;
            let keyset = cipher.default_keyset();
            let stored = keyset
                .encrypt_with_context(JsonPlaintext::from(document.clone()), COLUMN)
                .await
                .unwrap();
            let text = keyset
                .decrypt_with_context::<String>(stored.clone(), COLUMN)
                .await
                .unwrap();
            prop_assert_eq!(&text, &serde_json::to_string(&document).unwrap());
            let opened = keyset
                .decrypt_with_context::<JsonPlaintext>(stored, COLUMN)
                .await
                .unwrap();
            prop_assert_eq!(opened.value(), &document);
            Ok(())
        })?;
    }
}
