//! Byte-level pins for the SEM term derivations.
//!
//! These lock the exact bytes a term derives from: the PAE domain label, the
//! framing of the context, and the order the pieces go in. A change to any of
//! them changes every stored term — and because terms are compared for
//! equality server-side, the failure mode is not an error but a query that
//! silently stops matching. Breaking one of these tests means the derivation
//! moved, and the `/v1` suffix in the domain labels has to move with it.
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

use stack_encrypt::nonempty;
use stack_encrypt::sem::DefaultMatch;
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
        "c101ef066547cb33003c352dcd02a42bfe4a24e2d0609caca0189d9f1af8262a"
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
            4, 5, 10, 13, 14, 30, 39, 53, 56, 61, 85, 94, 95, 100, 111, 125, 127, 156, 173, 188,
            189, 202, 208, 224, 229, 239
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
