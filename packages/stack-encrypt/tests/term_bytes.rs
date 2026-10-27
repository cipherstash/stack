//! Byte-level pins for the SEM term derivations.
//!
//! These lock the exact bytes a term derives from: the PAE domain label, the
//! framing of the context, and the order the pieces go in. A change to any of
//! them changes every stored term — and because terms are compared for
//! equality server-side, the failure mode is not an error but a query that
//! silently stops matching. Breaking one of these tests means the derivation
//! moved, and the version suffix in the domain labels has to move with it.
//!
//! Keyed by `FakeDataKeySource`'s deterministic index key, so the expected
//! bytes are stable without ZeroKMS.
//!
//! The pins moved once without the derivation moving: vitaminc 0.5 changed
//! the canonical encoding of a context (typed leaves, one encoding for the
//! AEAD and the PRF), so the bytes under every label changed while the
//! labels and framing here did not. That was a prerelease wire break, taken
//! deliberately; the `/v1` suffixes stayed because nothing of
//! this crate's own moved.
//!
//! The equality and match pins moved again with the labels, to `/v2`, when
//! both began deriving through `vitaminc-normalize`: an equality term is the
//! PRF over the value's normalized bytes under vitaminc's domain for its
//! kind, and match text is tokenized in Unicode 16 NFC. No stored term
//! existed to keep. The ORE and OPE derivations did not move.
//!
//! The ORE and OPE pins moved with their key labels, to `/v2`, when order
//! terms began encrypting through cllw-ore's vitaminc schemes: every value
//! is encoded by `vitaminc-ore` at its type's order target (integers at
//! their width, text by the system ADR-0002's fold, behind cllw-ore's
//! marker byte) and encrypted under a column salt that binds the scheme
//! and the target. Terms written by 0.1.0 and 0.2.0 do not compare with
//! these (the CHANGELOG says so). Floats are ordered by the same path:
//! `F64`'s encoding folds `-0.0` into `0.0` and every NaN into one, which
//! cllw-ore's own float encoding did not.
//!
//! The ORE and OPE pins moved again, with no label of this crate's moving,
//! when cllw-ore became `clww-ore` 0.6 on vitaminc 0.8. Its keystream was
//! fixed and its schemes' names, which every term's salt binds, became
//! `clww-ore` and `clww-ope`, so every order term changed. The marker byte
//! in front of text moved from the scheme to `vitaminc-ore` without
//! changing the bytes encrypted. As with vitaminc 0.5, nothing of this
//! crate's own derivation moved, so the `/v2` suffixes stay.

use stack_encrypt::nonempty;
use stack_encrypt::sem::{DefaultMatch, MatchConfig, MatchOptions};
use stack_encrypt::StackCipher;
use stack_kms::FakeDataKeySource;

async fn cipher() -> StackCipher<FakeDataKeySource> {
    StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await
        .expect("build cipher")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn equality_term_bytes_are_pinned() {
    let cipher = cipher().await;
    let term = cipher
        .default_keyset()
        .equality_term("alice", nonempty!("users/email"))
        .await
        .unwrap();

    assert_eq!(
        hex(term.as_bytes()),
        "0aa0df4adabbad408580770b6e156aecca21a1d45f84e554ad4a1a0f76006fef"
    );
}

/// Equality compares text in Unicode 16 NFC and numbers whatever their
/// width: two spellings of one string, and one number at two widths, are
/// one term each.
#[tokio::test]
async fn equality_terms_are_one_per_normal_form() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let term = |value: &'static str| keyset.equality_term(value, nonempty!("users/email"));
    assert_eq!(
        term("cafe\u{301}").await.unwrap(),
        term("caf\u{e9}").await.unwrap(),
        "a combining accent and the precomposed letter are one string"
    );
    assert_eq!(
        keyset
            .equality_term(34u32, nonempty!("users/age"))
            .await
            .unwrap(),
        keyset
            .equality_term(34i64, nonempty!("users/age"))
            .await
            .unwrap(),
        "34 is one number at every width"
    );
}

#[tokio::test]
async fn match_term_positions_are_pinned() {
    let cipher = cipher().await;
    let term = cipher
        .default_keyset()
        .match_terms::<DefaultMatch>("alice smith", nonempty!("users/name"))
        .await
        .unwrap();

    // Pins the tokenizer, the per-token PRF framing, and the Bloom folding
    // together: any of the three moving changes this set.
    assert_eq!(
        term.positions(),
        [
            6, 15, 28, 40, 51, 54, 55, 61, 64, 92, 115, 148, 151, 153, 155, 161, 163, 172, 177,
            179, 186, 187, 197, 216, 246, 251, 254
        ]
    );
}

#[tokio::test]
async fn ore_term_bytes_are_pinned() {
    // The ORE key is a PRF of the descriptor, so this pins the key derivation
    // as much as the CLLW encryption.
    let cipher = cipher().await;
    let term = cipher
        .default_keyset()
        .ore_term(42u32, nonempty!("users/age"))
        .await
        .unwrap();

    assert_eq!(
        hex(term.as_ref()),
        "1ba4d59ccb15d505519ad854229ec0c106644fa8b8944ec54c68a1f324499d82"
    );
}

#[tokio::test]
async fn ope_term_bytes_are_pinned() {
    // Distinct from the ORE pin above under the same descriptor: the two
    // schemes derive their keys under different domains and must never share
    // one (OPE ciphertexts are encrypt-only).
    let cipher = cipher().await;
    let term = cipher
        .default_keyset()
        .ope_term(42u32, nonempty!("users/age"))
        .await
        .unwrap();

    assert_eq!(
        hex(term.as_ref()),
        "00a77ed973ff1af2e5d5e3779471df246d17a515f0131eb87e35e02e7a80aa5292"
    );
}

/// A filter wider than 256 bits: the default's mask keeps only the low byte
/// of each 2-byte slice, so the pin above cannot see which byte fills the
/// high half. Here every position uses both.
struct WideMatch;

impl MatchConfig for WideMatch {
    fn options() -> MatchOptions {
        MatchOptions {
            m: 65536,
            ..Default::default()
        }
    }
}

#[tokio::test]
async fn match_term_positions_are_pinned_for_a_wide_filter() {
    let cipher = cipher().await;
    let term = cipher
        .default_keyset()
        .match_terms::<WideMatch>("alice smith", nonempty!("users/name"))
        .await
        .unwrap();

    assert_eq!(
        term.positions(),
        [
            6398, 8087, 11318, 13096, 14587, 16924, 19131, 21007, 22427, 22518, 24792, 25004,
            34675, 35505, 35770, 36919, 38067, 41990, 42949, 45716, 48448, 55869, 56883, 57753,
            58019, 60065, 65116
        ],
        "positions for a 65536-bit filter are frozen: both bytes of each slice are in play"
    );
}

/// Text orders by the system ADR-0002's fold (`Ab` is encoded as `ab`,
/// behind `vitaminc-ore`'s marker byte, so three bytes), under the column salt
/// of the `Text` target. Pins the fold, the salt and the CLLW encryption
/// together.
#[tokio::test]
async fn text_order_term_bytes_are_pinned() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ore = keyset
        .ore_term("Ab".to_string(), nonempty!("users/surname"))
        .await
        .unwrap();
    let ope = keyset
        .ope_term("Ab".to_string(), nonempty!("users/surname"))
        .await
        .unwrap();
    assert_eq!(
        hex(ore.as_ref()),
        "b05ac63e0d2816d83868f90110b5226ad3c976f75e3a4b24"
    );
    assert_eq!(
        hex(ope.as_ref()),
        "00bfac54f18ed40b78b19468df90f4e3550a5c046f3f283e89"
    );
}

/// Folded equivalents are one order term, in every owned form text takes:
/// case, a precomposed accent and a combining one all fold away.
#[tokio::test]
async fn text_order_terms_fold_case_and_accents() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ore = |text: String| keyset.ore_term(text, nonempty!("users/surname"));
    let ope = |text: String| keyset.ope_term(text, nonempty!("users/surname"));
    let want_ore = ore("cafe".into()).await.unwrap();
    let want_ope = ope("cafe".into()).await.unwrap();
    for text in ["Caf\u{e9}", "CAF\u{c9}", "cafe\u{301}", "CAFE"] {
        assert_eq!(ore(text.into()).await.unwrap(), want_ore, "{text:?} ore");
        assert_eq!(ope(text.into()).await.unwrap(), want_ope, "{text:?} ope");
    }
}

/// A text term is not the term of the same bytes as bytes: the column salt
/// binds the target, `Text` or `Bytes`.
#[tokio::test]
async fn a_text_order_term_is_keyed_apart_from_bytes() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let text = keyset
        .ore_term("cafe".to_string(), nonempty!("users/surname"))
        .await
        .unwrap();
    let bytes = keyset
        .ore_term(b"cafe".to_vec(), nonempty!("users/surname"))
        .await
        .unwrap();
    assert_eq!(text.as_ref().len(), bytes.as_ref().len());
    assert_ne!(text, bytes);
}

/// Text holding a code point Unicode 16 does not assign has no known fold,
/// so it has no order term: vitaminc-ore refuses to encode it.
#[tokio::test]
async fn text_with_no_fold_has_no_order_term() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    assert!(keyset
        .ore_term("a\u{378}b".to_string(), nonempty!("users/surname"))
        .await
        .is_err());
    assert!(keyset
        .ope_term("a\u{378}b".to_string(), nonempty!("users/surname"))
        .await
        .is_err());
}

/// A float's order term: clww-ore's encryption of its ADR-0002 order key,
/// the `f64` with zero signs and NaN payloads folded, under the column salt
/// of the `F64` target. Pins the key, the salt and the encryption.
#[tokio::test]
async fn float_order_term_bytes_are_pinned() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ore = keyset
        .ore_term(1.5f64, nonempty!("users/score"))
        .await
        .unwrap();
    let ope = keyset
        .ope_term(1.5f64, nonempty!("users/score"))
        .await
        .unwrap();
    assert_eq!(hex(ore.as_ref()), "6c487f77b33ab3b4e0d37e79f84b24b92843d9cb591d492fd8d092afebba96e50e7d6733935a6e94faa8e7945f04471385553a35aa00ca30fb77d0b7a7a9a9a3");
    assert_eq!(hex(ope.as_ref()), "00836260f898d58c06c8e23b8754e05d7d352c676b714e8523582c930f9e83640ad87d56aa35b7c3ecdc44dfb29a7378fb95738bca93f5ee9ca2a066c63ecb6aaf");
}

/// Floats order as Postgres's `float8` does: `-0.0` ties `0.0`, every NaN is
/// one value, and it sorts above `+Infinity`. The ORE terms compare in that
/// order, and the OPE terms' bytes do.
#[tokio::test]
async fn float_order_terms_follow_the_semantic_baseline() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ore = |value: f64| keyset.ore_term(value, nonempty!("users/score"));
    let ope = |value: f64| keyset.ope_term(value, nonempty!("users/score"));

    assert_eq!(ore(-0.0).await.unwrap(), ore(0.0).await.unwrap());
    assert_eq!(ope(-0.0).await.unwrap(), ope(0.0).await.unwrap());
    let nans = [
        f64::NAN,
        -f64::NAN,
        f64::from_bits(0x7ff8_0000_0000_beef),
        f64::from_bits(0x7ff0_0000_0000_0001),
    ];
    for nan in nans {
        assert_eq!(
            ore(nan).await.unwrap(),
            ore(f64::NAN).await.unwrap(),
            "{nan:?}"
        );
        assert_eq!(
            ope(nan).await.unwrap(),
            ope(f64::NAN).await.unwrap(),
            "{nan:?}"
        );
    }

    let ascending = [
        f64::NEG_INFINITY,
        f64::MIN,
        -1.5,
        -f64::MIN_POSITIVE,
        0.0,
        f64::MIN_POSITIVE,
        1.5,
        f64::MAX,
        f64::INFINITY,
        f64::NAN,
    ];
    for pair in ascending.windows(2) {
        let (lo, hi) = (pair[0], pair[1]);
        assert!(
            ore(lo).await.unwrap() < ore(hi).await.unwrap(),
            "ore: {lo:?} < {hi:?}"
        );
        assert!(
            ope(lo).await.unwrap().as_ref() < ope(hi).await.unwrap().as_ref(),
            "ope: {lo:?} < {hi:?}"
        );
    }
}

/// An `f32` is ordered as the `f64` it widens to (ADR-0002): its target
/// is `F64`, and vitaminc widens it exactly, so its terms are the `f64`'s.
#[tokio::test]
async fn an_f32_is_ordered_as_the_f64_it_widens_to() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    for value in [1.5f32, -0.0, f32::NAN, f32::MIN_POSITIVE, f32::INFINITY] {
        let wide = f64::from(value);
        assert_eq!(
            keyset
                .ore_term(value, nonempty!("users/score"))
                .await
                .unwrap(),
            keyset
                .ore_term(wide, nonempty!("users/score"))
                .await
                .unwrap(),
            "ore {value:?}"
        );
        assert_eq!(
            keyset
                .ope_term(value, nonempty!("users/score"))
                .await
                .unwrap(),
            keyset
                .ope_term(wide, nonempty!("users/score"))
                .await
                .unwrap(),
            "ope {value:?}"
        );
    }
}

/// Every integer width of 16 bits or more is encoded at its own target: an
/// ORE term of one byte per bit of the width and an OPE term of one more,
/// each ordering as the values do, from the width's minimum through its
/// maximum. (A `u8` and an `i8` have no order term.)
#[tokio::test]
async fn every_integer_width_orders_by_its_own_key() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    macro_rules! width {
        ($($ty:ty),+) => {$({
            let values: [$ty; 3] = [<$ty>::MIN, <$ty>::MIN / 2 + <$ty>::MAX / 2 + 1, <$ty>::MAX];
            let bits = <$ty>::BITS as usize;
            let mut ores = Vec::new();
            let mut opes = Vec::new();
            for value in values {
                let ore = keyset.ore_term(value, nonempty!("users/n")).await.unwrap();
                let ope = keyset.ope_term(value, nonempty!("users/n")).await.unwrap();
                assert_eq!(ore.as_ref().len(), bits, "{} ore", stringify!($ty));
                assert_eq!(ope.as_ref().len(), bits + 1, "{} ope", stringify!($ty));
                ores.push(ore);
                opes.push(ope.as_ref().to_vec());
            }
            assert!(ores[0] < ores[1] && ores[1] < ores[2], "{} ore order", stringify!($ty));
            assert!(opes[0] < opes[1] && opes[1] < opes[2], "{} ope order", stringify!($ty));
        })+};
    }
    width!(u16, u32, u64, u128, i16, i32, i64, i128);
}

/// Short-word tokens under a 65536-bit filter: the word domain
/// (`stack-encrypt/sem/match/word/v1`) and its framing, pinned. "ng" alone is
/// the word's token and nothing else; "Mike Ng" is its trigrams and the same
/// word, so it holds every one of "ng"'s positions.
struct WideShortWords;

impl MatchConfig for WideShortWords {
    fn options() -> MatchOptions {
        MatchOptions {
            short_words: true,
            m: 65536,
            ..Default::default()
        }
    }
}

#[tokio::test]
async fn short_word_positions_are_pinned() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let word = keyset
        .match_terms::<WideShortWords>("Ng", nonempty!("users/name"))
        .await
        .unwrap();
    assert_eq!(
        word.positions(),
        PINNED_NG,
        "the word token's positions are frozen"
    );
    let whole = keyset
        .match_terms::<WideShortWords>("Mike Ng", nonempty!("users/name"))
        .await
        .unwrap();
    assert!(
        whole.contains(&word),
        "\"Mike Ng\" carries the word token of \"Ng\""
    );
}

const PINNED_NG: [u16; 3] = [47881, 55268, 60379];
