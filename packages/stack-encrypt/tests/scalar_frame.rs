//! A `dynamic::ScalarFrame` seals the leaf `keyset.encrypt` seals for the
//! same Rust value, and opens back into a frame of the kind it was sealed as.
//!
//! Every leaf carries a fresh random nonce, so two seals of one value are
//! never the same bytes. What the tests hold equal is everything else:
//!
//! - the tagged plaintext and the associated data vitaminc plans for the
//!   leaf, byte for byte (`vitaminc_aead::plan`, the step every opaque seal
//!   runs before the cipher);
//! - the data key, under the deterministic key source: each seal runs on a
//!   fresh cipher with the same seed, so equal key tags mean the same
//!   descriptor and the same key;
//! - the envelope's length;
//! - and each ciphertext opens as the other side's type, so the associated
//!   data and the type tag agree.
//!
//! The same holds between `keyset.encrypt_with_context(value, context)` and
//! `keyset.encrypt_tree(value, context)`, and between `keyset.encrypt(value)`
//! and `keyset.encrypt_tree(value, ())`: one leaf, the same apart from its
//! nonce.
#![cfg(feature = "dynamic")]
// `keyset.encrypt` seals a value through a borrow of it, so these tests walk
// the borrow (`&ScalarFrame`, `&ValueFrame`) where the owned value would
// also compile.
#![allow(clippy::needless_borrows_for_generic_args)]

mod common;

use common::{deterministic_cipher, hex, DeterministicSource};
use proptest::prelude::*;
use serde::Deserialize;
use stack_encrypt::dynamic::{ScalarFrame, ValueFrame, ValueKind};
use stack_encrypt::value::{Date, Decimal, Timestamp};
use stack_encrypt::{
    CipherText, Ciphertext, Encrypt, OpaqueDecode, OpaqueEncode, StackCipher, StackCipherText,
};
use vitaminc_aead::plaintext::{Int, Logical, Physical, Raw};
use vitaminc_protected::Controlled as _;

const SEED: [u8; 32] = *b"stack-encrypt scalar frame v1   ";

/// The context every leaf here is sealed under.
const CONTEXT: (&str, &str) = ("users", "value");

/// A fresh cipher over the deterministic source: its first seal draws the
/// same key as any other fresh cipher's first seal of the same descriptor.
async fn cipher() -> StackCipher<DeterministicSource> {
    deterministic_cipher(SEED).await
}

fn run<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(future)
}

fn frame<P: Encrypt>(value: P) -> ValueFrame {
    ValueFrame::of(value).expect("a value in the model")
}

fn scalar<P: Encrypt>(value: P) -> ScalarFrame {
    ScalarFrame::new(frame(value)).expect("one scalar")
}

/// The one leaf vitaminc plans for `source` under [`CONTEXT`], as the
/// tagged plaintext and the associated data, in bytes.
fn planned<P: Encrypt>(source: P) -> (Vec<u8>, Vec<u8>) {
    let tree = vitaminc_aead::plan::<_, (), _>(source, CONTEXT).expect("plans");
    match tree {
        CipherText::Single(leaf) => (
            leaf.plaintext.risky_ref().clone(),
            leaf.aad.as_bytes().to_vec(),
        ),
        _ => panic!("one value plans as one leaf"),
    }
}

async fn seal_frame(value: ScalarFrame) -> Ciphertext {
    cipher()
        .await
        .default_keyset()
        .encrypt_with_context(value, CONTEXT)
        .await
        .expect("a scalar frame seals")
}

async fn seal_tree<P: Encrypt>(value: P) -> Ciphertext {
    match cipher()
        .await
        .default_keyset()
        .encrypt_tree(value, CONTEXT)
        .await
        .expect("seals")
    {
        CipherText::Single(leaf) => Ciphertext::from(leaf),
        _ => panic!("one scalar seals as one leaf"),
    }
}

async fn open<P: OpaqueDecode>(ciphertext: Ciphertext) -> P {
    cipher()
        .await
        .default_keyset()
        .decrypt_with_context(ciphertext, CONTEXT)
        .await
        .expect("opens")
}

mod assertions {
    use super::*;

    /// Two seals of one value under one key and context: the same key tag
    /// and length. The bytes differ by the nonce alone.
    pub(super) fn same_leaf_but_the_nonce(left: &Ciphertext, right: &Ciphertext, what: &str) {
        assert_eq!(
            left.key_tag(),
            right.key_tag(),
            "{what}: the same descriptor and data key"
        );
        assert_eq!(
            left.to_bytes().len(),
            right.to_bytes().len(),
            "{what}: the same envelope length"
        );
    }

    /// A ciphertext opened into a frame is the frame it was sealed from,
    /// byte for byte, and of its kind.
    pub(super) fn opens_as(opened: &ValueFrame, expected: &ValueFrame, what: &str) {
        assert!(
            opened == expected,
            "{what}: opens to the frame it was sealed from"
        );
        assert_eq!(opened.kind(), expected.kind(), "{what}: of the same kind");
    }
}

/// A Rust value `keyset.encrypt` seals, and the same value as a binding
/// hands it over: the leaf, the key, the length and the opened values agree.
async fn same_as_keyset_encrypt<S>(value: S)
where
    S: OpaqueEncode + OpaqueDecode,
    for<'a> &'a S: Encrypt,
{
    let expected = frame(&value);
    let what = format!("{:?}", expected.kind());
    assert_eq!(
        planned(&scalar(&value)),
        planned(&value),
        "{what}: the same tagged plaintext and associated data"
    );

    let from_frame = seal_frame(scalar(&value)).await;
    let from_rust = cipher()
        .await
        .default_keyset()
        .encrypt_with_context(value, CONTEXT)
        .await
        .expect("a Rust scalar seals");
    assertions::same_leaf_but_the_nonce(&from_frame, &from_rust, &what);

    // Each opens as the other side's type.
    let rust: S = open(from_frame.clone()).await;
    assertions::opens_as(&frame(&rust), &expected, &what);
    let opened: ValueFrame = open(from_rust).await;
    assertions::opens_as(&opened, &expected, &what);
    let opened: ValueFrame = open(from_frame).await;
    assertions::opens_as(&opened, &expected, &what);
}

/// A value of the model that no `OpaqueEncode` type spells (a null, an
/// `undefined`, a `uint8`): the leaf `keyset.encrypt_tree` seals for the
/// same Rust source.
async fn same_as_encrypt_tree<P: Encrypt + Copy>(source: P) {
    let expected = frame(source);
    let what = format!("{:?}", expected.kind());
    assert_eq!(
        planned(&scalar(source)),
        planned(source),
        "{what}: the same tagged plaintext and associated data"
    );
    let from_frame = seal_frame(scalar(source)).await;
    let from_tree = seal_tree(source).await;
    assertions::same_leaf_but_the_nonce(&from_frame, &from_tree, &what);
    let opened: ValueFrame = open(from_frame).await;
    assertions::opens_as(&opened, &expected, &what);
    let opened: ValueFrame = open(from_tree).await;
    assertions::opens_as(&opened, &expected, &what);
}

fn date() -> impl Strategy<Value = Date> {
    (-9999i16..=9999, 1i8..=12, 1i8..=28)
        .prop_map(|(y, m, d)| Date::new(jiff::civil::date(y, m, d)))
}

fn timestamp() -> impl Strategy<Value = Timestamp> {
    (-377_705_023_201i64..=253_402_207_199, 0i32..1_000_000_000)
        .prop_filter_map("an instant vitaminc carries", |(seconds, nanos)| {
            Timestamp::new(jiff::Timestamp::new(seconds, nanos).ok()?).ok()
        })
}

fn decimal() -> impl Strategy<Value = Decimal> {
    const MAX: i128 = (1 << 96) - 1;
    (-MAX..=MAX, 0u32..=28).prop_map(|(mantissa, scale)| {
        Decimal::new(
            rust_decimal::Decimal::try_from_i128_with_scale(mantissa, scale)
                .expect("a mantissa of 96 bits"),
        )
    })
}

mod given_a_scalar_of_each_kind {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn it_seals_as_keyset_encrypt_seals_a_bool(value in any::<bool>()) {
            run(same_as_keyset_encrypt(value));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_an_i8(value in any::<i8>()) {
            run(same_as_keyset_encrypt(value));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_an_i16(value in any::<i16>()) {
            run(same_as_keyset_encrypt(value));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_an_i32(value in any::<i32>()) {
            run(same_as_keyset_encrypt(value));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_an_i64(value in any::<i64>()) {
            run(same_as_keyset_encrypt(value));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_an_i128(value in any::<i128>()) {
            run(same_as_keyset_encrypt(value));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_a_u16(value in any::<u16>()) {
            run(same_as_keyset_encrypt(value));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_a_u32(value in any::<u32>()) {
            run(same_as_keyset_encrypt(value));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_a_u64(value in any::<u64>()) {
            run(same_as_keyset_encrypt(value));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_a_u128(value in any::<u128>()) {
            run(same_as_keyset_encrypt(value));
        }

        /// Any bit pattern, NaNs and both zeros included: a frame keeps a
        /// float's bits.
        #[test]
        fn it_seals_as_keyset_encrypt_seals_an_f32(bits in any::<u32>()) {
            run(same_as_keyset_encrypt(f32::from_bits(bits)));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_an_f64(bits in any::<u64>()) {
            run(same_as_keyset_encrypt(f64::from_bits(bits)));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_a_string(value in "\\PC{0,40}") {
            run(same_as_keyset_encrypt(value));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_bytes(value in proptest::collection::vec(any::<u8>(), 0..64)) {
            run(same_as_keyset_encrypt(value));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_a_date(value in date()) {
            run(same_as_keyset_encrypt(value));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_a_timestamp(value in timestamp()) {
            run(same_as_keyset_encrypt(value));
        }

        #[test]
        fn it_seals_as_keyset_encrypt_seals_a_decimal(value in decimal()) {
            run(same_as_keyset_encrypt(value));
        }

        /// `u8` is not a source on its own (a `Vec<u8>` is a byte string),
        /// so no `OpaqueEncode` type spells a `uint8`.
        #[test]
        fn it_seals_as_encrypt_tree_seals_a_u8(value in any::<u8>()) {
            run(same_as_encrypt_tree(Raw(None, Physical::Int(Int::U8(value)))));
        }
    }

    /// No `OpaqueEncode` type is absent: `Option<T>` is not one. A null is
    /// sealed as `encrypt_tree` seals one.
    #[tokio::test]
    async fn a_null_seals_as_encrypt_tree_seals_it() {
        same_as_encrypt_tree(Raw(None, Physical::Null)).await;
    }

    /// A frame does not keep a null's type: an absent `Option<i64>` is a
    /// plain null, sealed unpadded, so it is shorter than a present `i64`.
    /// `encrypt_tree(None::<i64>)` pads it, from the Rust type; a frame has
    /// no type to pad it from.
    #[tokio::test]
    async fn a_null_of_a_fixed_width_type_seals_unpadded() {
        assert!(
            frame(None::<i64>) == frame(Raw(None, Physical::Null)),
            "the frame of an absent i64 is a plain null"
        );
        assert_eq!(
            planned(&scalar(None::<i64>)),
            planned(Raw(None, Physical::Null)),
            "it plans as a plain null"
        );
        assert_ne!(
            planned(&scalar(None::<i64>)),
            planned(None::<i64>),
            "not as Rust's padded null"
        );
        let present = seal_frame(scalar(7i64)).await;
        let absent = seal_frame(scalar(None::<i64>)).await;
        assert!(
            absent.to_bytes().len() < present.to_bytes().len(),
            "an absent value is shorter than a present one"
        );
    }

    #[tokio::test]
    async fn an_undefined_seals_as_encrypt_tree_seals_it() {
        same_as_encrypt_tree(Raw(Some(Logical::Undefined), Physical::Null)).await;
    }

    /// The owned frame walks as its borrow does.
    #[test]
    fn the_owned_frame_plans_as_its_borrow() {
        assert_eq!(planned(scalar("alice")), planned(&scalar("alice")));
    }
}

/// `keyset.encrypt_tree(value, context)` seals one scalar as the same leaf
/// as `keyset.encrypt_with_context(value, context)`, and with no context as
/// `keyset.encrypt(value)` does under `()`.
mod given_encrypt_tree {
    use super::*;

    #[tokio::test]
    async fn it_seals_one_scalar_as_keyset_encrypt_does() {
        for value in [frame("alice"), frame(42i64), frame(-2.5f64), frame(true)] {
            let what = format!("{:?}", value.kind());
            let expected = frame(&value);
            let opaque = seal_frame(ScalarFrame::new(value).unwrap()).await;
            let tree = seal_tree(&expected).await;
            assertions::same_leaf_but_the_nonce(&opaque, &tree, &what);

            // Each opens through the other's call.
            let opened: StackCipherText = CipherText::Single(opaque.into());
            let opened: ValueFrame = cipher()
                .await
                .default_keyset()
                .decrypt_tree(opened, CONTEXT)
                .await
                .unwrap();
            assertions::opens_as(&opened, &expected, &what);
            let opened: ValueFrame = open(tree).await;
            assertions::opens_as(&opened, &expected, &what);
        }
    }

    #[tokio::test]
    async fn with_no_context_it_seals_as_keyset_encrypt_does() {
        let keyset_cipher = cipher().await;
        let opaque = keyset_cipher
            .default_keyset()
            .encrypt(scalar("alice"))
            .await
            .unwrap();
        let tree = match cipher()
            .await
            .default_keyset()
            .encrypt_tree(&frame("alice"), ())
            .await
            .unwrap()
        {
            CipherText::Single(leaf) => Ciphertext::from(leaf),
            _ => panic!("one leaf"),
        };
        assertions::same_leaf_but_the_nonce(&opaque, &tree, "no context");
        let opened: ValueFrame = keyset_cipher.default_keyset().decrypt(tree).await.unwrap();
        assertions::opens_as(&opened, &frame("alice"), "no context");
    }
}

mod given_a_ciphertext_sealed_from_a_scalar_frame {
    use super::*;

    /// A value is sealed under its context: under another it does not
    /// open.
    #[tokio::test]
    async fn it_opens_only_under_its_context() {
        let stored = seal_frame(scalar("alice")).await;
        let refused = cipher()
            .await
            .default_keyset()
            .decrypt_with_context::<ValueFrame>(stored, ("users", "other"))
            .await;
        assert!(refused.is_err(), "a value opens under its own context only");
    }

    /// Opened as a Rust type of another kind, it is refused for its type.
    #[tokio::test]
    async fn it_opens_only_as_its_own_type() {
        let stored = seal_frame(scalar("alice")).await;
        let refused = cipher()
            .await
            .default_keyset()
            .decrypt_with_context::<i64>(stored, CONTEXT)
            .await;
        assert!(
            matches!(refused, Err(stack_encrypt::Error::OpenedType { .. })),
            "{refused:?}"
        );
    }
}

/// The shared value corpus's inputs, each as one value: every case that
/// spells a frame seals from a `ScalarFrame` and opens back to that frame.
/// The cases are written for records; this reads their inputs only, and
/// adds no case.
mod given_the_shared_value_corpus {
    use super::*;
    use common::conformance::{value, Input};

    #[derive(Deserialize)]
    struct Corpus {
        profile: String,
        cases: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        id: String,
        input: Input,
        frame: Option<String>,
    }

    #[tokio::test]
    async fn every_value_with_a_frame_opens_to_that_frame() {
        let corpus: Corpus = serde_json::from_str(include_str!(
            "../../../conformance/stack-encrypt/v1/record-values-v1.cases.json"
        ))
        .unwrap();
        assert_eq!(corpus.profile, "record-values-v1");
        let keyset_cipher = cipher().await;
        let keyset = keyset_cipher.default_keyset();
        let mut checked = 0;
        for case in &corpus.cases {
            let Some(frozen) = &case.frame else { continue };
            let stored = keyset
                .encrypt_with_context(ScalarFrame::new(value(&case.input)).unwrap(), CONTEXT)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", case.id));
            let opened: ValueFrame = keyset
                .decrypt_with_context(stored, CONTEXT)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", case.id));
            assert_eq!(&hex(opened.risky_ref()), frozen, "{}", case.id);
            assert!(
                opened.kind().is_some_and(|kind| kind != ValueKind::Array),
                "{}: a scalar of a kind",
                case.id
            );
            checked += 1;
        }
        assert!(checked > 40, "the corpus has frames to check: {checked}");
    }
}
