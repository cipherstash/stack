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
//! Text ORE and OPE terms moved once, and only for text: they derive over
//! the text's order key (the system ADR-0002's fold, from `vitaminc-ore`)
//! in place of cllw-ore's own collation, under a key framing that adds the
//! fold's frozen label. None was deployed.
//!
//! Every other order term then moved the same way: each derives over its
//! value's ADR-0002 order key from `vitaminc-ore`, under a key framing that
//! names the key's frozen domain label (`vitaminc/ore/value/uint32/v1`, and
//! so on). An integer's key is the bytes cllw-ore already encrypted, so only
//! the framing moved its terms; a float's key folds `-0.0` into `0.0` and
//! every NaN into one, which cllw-ore's own float encoding did not. None
//! was deployed. The text pins did not move: their framing already named
//! the fold.

use stack_encrypt::nonempty;
use stack_encrypt::sem::{DefaultMatch, MatchConfig, MatchOptions, TermError};
use stack_encrypt::{Error, StackCipher};
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
        "70fe4ffe4d6a6972cb9bd05bd860f7bfc6dba897bb1620eaf614928c8f61a658"
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
        "0004863f4a43b48103f4c3c8c873d77182d5c9084bc50b67eb4b84699bdee611b0"
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

/// Text orders by its order key, the system ADR-0002's fold (`Ab` derives
/// over `ab`), under a key whose framing names the fold's label. Pins the
/// fold, the framing and the CLLW encryption together.
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
    assert_eq!(hex(ore.as_ref()), "5395281a56386ee6aa4cb925fbf601a7");
    assert_eq!(hex(ope.as_ref()), "002d9bf26fd01fadf9adefce5b1eeb1547");
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
    let borrowed = keyset
        .ore_term("Caf\u{e9}", nonempty!("users/surname"))
        .await
        .unwrap();
    assert_eq!(borrowed, want_ore, "a &'static str folds too");
}

/// A text order key's term is not the term of the same bytes as bytes: the
/// key is derived under a framing that names the fold.
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
/// so it has no order term.
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

/// A float's order term: the CLLW encryption of its ADR-0002 order key, the
/// `f64` with zero signs and NaN payloads folded, under a key whose framing
/// names the float domain. Pins the key, the framing and the encryption.
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
    assert_eq!(hex(ore.as_ref()), "87caa31faf8f17ef7a226791343e523a62f06edc95cf6d00848741cf50bb8ae18e87c4d4bd17941a7babf9832587555ff933c191dcc922807059ec7d54572c13");
    assert_eq!(hex(ope.as_ref()), "010a8bc2a08ebae3e7d117253af85177ebd70178af8a43f2511c14b31e4163aebe36e1e069b21c58ed6f7fc903baa3e29533be2936809f891ae14f48aefc9acfa3");
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

/// An `f32` has no order term of its own: ADR-0002 orders it as the `f64`
/// it widens to, so the typed path asks for that `f64`.
#[tokio::test]
async fn an_f32_is_ordered_as_the_f64_it_widens_to() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ore = keyset.ore_term(1.5f32, nonempty!("users/score")).await;
    assert!(
        matches!(ore, Err(Error::Term(TermError::NarrowFloat))),
        "{ore:?}"
    );
    let ope = keyset.ope_term(1.5f32, nonempty!("users/score")).await;
    assert!(
        matches!(ope, Err(Error::Term(TermError::NarrowFloat))),
        "{ope:?}"
    );
}

/// Every integer width derives over its own order key: an ORE term of one
/// byte per bit of the width and an OPE term of one more, each ordering as
/// the values do, from the width's minimum through its maximum.
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
    width!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);
}
