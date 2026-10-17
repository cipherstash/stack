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
//! deliberately (CIP-4036); the `/v1` suffixes stayed because nothing of
//! this crate's own moved.
//!
//! The equality and match pins moved again with the labels, to `/v2`, when
//! both began deriving through `vitaminc-normalize`: an equality term is the
//! PRF over the value's normalized bytes under vitaminc's domain for its
//! kind, and match text is tokenized in Unicode 16 NFC. No stored term
//! existed to keep. The ORE and OPE derivations did not move.

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
        "1ae5f8558dc2d7dddd6c5b714e9d285586a1b8390d9140421e78906cba1bd651"
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
        "00837615a1ea2fdcbebf7efe34cf4d2ee432c7eeff84fbd72e1bf05efa2338033c"
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
