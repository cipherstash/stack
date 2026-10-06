//! Byte-level pins for the SEM term derivations.
//!
//! These lock the exact bytes a term derives from: the PAE domain label, the
//! framing of the context, and the order the pieces go in. A change to any of
//! them changes every stored term — and because terms are compared for
//! equality server-side, the failure mode is not an error but a query that
//! silently stops matching. Breaking one of these tests means the derivation
//! moved, and the `/v1` suffix in the domain labels has to move with it.
//!
//! Keyed by `FakeKeysetRegistry`'s deterministic index key, so the expected
//! bytes are stable without ZeroKMS.
//!
//! The pins moved once without the derivation moving: vitaminc 0.5 changed
//! the canonical encoding of a context (typed leaves, one encoding for the
//! AEAD and the PRF), so the bytes under every label changed while the
//! labels and framing here did not. That was a prerelease wire break, taken
//! deliberately (CIP-4036); the `/v1` suffixes stayed because nothing of
//! this crate's own moved.

use stack_encrypt::nonempty;
use stack_encrypt::registry::fake::FakeKeysetRegistry;
use stack_encrypt::sem::{DefaultMatch, MatchConfig, MatchOptions};
use stack_encrypt::StackCipher;
use stack_encrypt::StackCipherBuilder;

async fn cipher() -> StackCipher<FakeKeysetRegistry> {
    StackCipherBuilder::new()
        .registry(FakeKeysetRegistry::new())
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
        "4dc2ba6bbf77704d99bc7b762430cb801f1649f87cd39b95f08e208a3952d001"
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
            1, 36, 46, 55, 58, 66, 77, 102, 111, 138, 143, 144, 147, 153, 158, 159, 168, 169, 177,
            183, 189, 198, 201, 209, 219, 224, 249
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
        "4670ea1803ebb80320366cd5cc006e9eb235e85450c68096ec98874d407c8b5d"
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
        "00f6bb865fbb63936656ce27932e3a2f061e6b21ba10a6fb12b91dcf74c2e290ba"
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
            480, 1847, 6056, 7056, 8125, 9417, 23729, 23967, 26521, 28563, 32721, 40550, 40740,
            41217, 42095, 43422, 46249, 46894, 47814, 48015, 50234, 51021, 52443, 53497, 53570,
            54199, 61322
        ],
        "positions for a 65536-bit filter are frozen: both bytes of each slice are in play"
    );
}
