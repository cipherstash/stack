//! Byte-level pins for the frozen storage encodings — the byte formats
//! stack-encrypt commits to across languages and database columns:
//!
//! * the [`SealedValue`] leaf layout
//!   (`version ‖ iv ‖ tag_len ‖ tag ‖ local_ciphertext`), and
//! * the index-term encodings (equality: raw 32 bytes; match: LE `u16`
//!   positions; ORE/OPE: raw CLLW ciphertext bytes).
//!
//! These are the vectors a language binding's decoder tests against — the
//! Go side decodes exactly these hex strings. `tests/term_bytes.rs` pins the
//! *derivations* (PRF domains and framing); this file pins the *encodings*
//! of the results. Breaking a pin here means the storage format moved: for
//! the leaf that demands a `SealedValue::FORMAT_VERSION` bump, for terms it
//! means stored rows silently stop comparing.

use stack_encrypt::sem::{DefaultMatch, EqualityTerm, MatchTerm, OpeTerm, OreTerm};
use stack_encrypt::target::EncryptInto;
use stack_encrypt::{CipherText, LeafBytesError, SealedValue, StackCipher};
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

// =============================================================================
// SealedValue leaf
// =============================================================================

/// A leaf from fixed parts, so the encoding is deterministic. The
/// "ciphertext" is not a real AEAD output — encoding is structural and must
/// not care.
fn fixture_leaf() -> SealedValue {
    let iv: stack_kms::Iv = *b"0123456789abcdef";
    SealedValue::from_parts(iv, vec![0xAA, 0xBB, 0xCC], vec![0xDE, 0xAD, 0xBE, 0xEF])
        .expect("fixture tag fits the length field")
}

#[test]
fn sealed_value_layout_is_pinned() {
    let bytes = fixture_leaf().to_bytes();

    // version(01) ‖ iv(16 bytes: ASCII "0123456789abcdef") ‖
    // tag_len(0300 — 3, u16 LE) ‖ tag(aabbcc) ‖ local_ciphertext(deadbeef)
    assert_eq!(
        hex(&bytes),
        "01303132333435363738396162636465660300aabbccdeadbeef"
    );
}

#[test]
fn sealed_value_from_bytes_inverts_to_bytes() {
    let original = fixture_leaf();
    let bytes = original.to_bytes();
    let decoded = SealedValue::from_bytes(&bytes).expect("decode leaf");

    assert_eq!(decoded.iv(), original.iv());
    assert_eq!(decoded.tag(), original.tag());
    assert_eq!(decoded.ciphertext(), original.ciphertext());

    // The std conversion is the same decoder.
    let converted = SealedValue::try_from(bytes.as_slice()).expect("TryFrom decode");
    assert_eq!(converted.ciphertext(), original.ciphertext());
}

#[test]
fn sealed_value_rejects_unknown_version() {
    let mut bytes = fixture_leaf().to_bytes();
    bytes[0] = 2;
    assert!(matches!(
        SealedValue::from_bytes(&bytes),
        Err(LeafBytesError::UnknownVersion(2))
    ));
}

#[test]
fn sealed_value_rejects_truncation() {
    let bytes = fixture_leaf().to_bytes();

    // Every prefix shorter than the tag's end is truncated: empty, mid-iv,
    // mid-length-field, and mid-tag. (Anything at or past the tag's end
    // parses — the local ciphertext takes the remainder, and proving *it*
    // whole is the AEAD open's job.)
    let tag_end = 1 + 16 + 2 + 3;
    for len in 0..tag_end {
        assert!(
            matches!(
                SealedValue::from_bytes(&bytes[..len]),
                Err(LeafBytesError::Truncated)
            ),
            "prefix of {len} bytes must be rejected"
        );
    }
    assert!(SealedValue::from_bytes(&bytes[..tag_end]).is_ok());
}

#[test]
fn sealed_value_rejects_oversized_tag_on_construction() {
    // `to_bytes` is infallible because the tag can never outgrow the `u16`
    // length field: the only constructor that could admit one rejects it.
    let result = SealedValue::from_parts(
        [0; 16],
        vec![0; usize::from(u16::MAX) + 1],
        vec![0xDE, 0xAD],
    );
    assert!(matches!(
        result,
        Err(LeafBytesError::TagTooLong(len)) if len == usize::from(u16::MAX) + 1
    ));
}

#[tokio::test]
async fn sealed_leaf_survives_persistence_via_bytes() {
    // The format round-trips a *real* leaf: encrypt, encode, decode, decrypt.
    let cipher = cipher().await;
    let ct = cipher
        .encrypt("durable".to_string(), b"ctx".as_slice())
        .await
        .expect("encrypt");
    let leaf = match ct {
        CipherText::Single(leaf) => leaf,
        other => panic!("expected a Single leaf, got {other:?}"),
    };
    let bytes = leaf.to_bytes();
    let restored = SealedValue::from_bytes(&bytes).expect("decode leaf");

    let pt: String = cipher
        .decrypt(CipherText::Single(restored), b"ctx".as_slice())
        .await
        .expect("decoded leaf must decrypt");
    assert_eq!(pt, "durable");
}

// =============================================================================
// Terms
// =============================================================================

#[tokio::test]
async fn equality_term_encoding_is_the_raw_prf_bytes() {
    let term = cipher()
        .await
        .equality_term("alice", "users/email")
        .await
        .expect("equality term");

    // The derivation is pinned in term_bytes.rs; here: encoding = identity
    // over those 32 bytes, and from_bytes is its inverse.
    assert_eq!(term.as_ref(), term.as_bytes());
    assert_eq!(EqualityTerm::from_bytes(*term.as_bytes()), term);
}

#[tokio::test]
async fn match_term_bytes_are_pinned() {
    let term = cipher()
        .await
        .match_terms::<DefaultMatch>("alice smith", "users/name")
        .await
        .expect("match term");

    // The little-endian u16 encoding of the positions pinned in
    // term_bytes.rs, in sorted order.
    let bytes = term.to_bytes();
    assert_eq!(
        hex(&bytes),
        "2100220028002c002d0034003c003f005400620063006b0071007d007f0097009800a400a600a800a900d200d400fd00"
    );
    assert_eq!(
        MatchTerm::<DefaultMatch>::from_bytes(&bytes).expect("decode match term"),
        term
    );
}

#[test]
fn match_term_from_bytes_rejects_odd_length() {
    assert!(MatchTerm::<DefaultMatch>::from_bytes(&[0x21]).is_err());
}

#[tokio::test]
async fn ore_term_encoding_is_the_raw_cllw_bytes() {
    let cipher = cipher().await;
    let term: OreTerm<u32> = 42u32
        .encrypt_into_with_context(&cipher, "users/age")
        .await
        .expect("ore term");

    // Byte-identical to the raw CLLW output pinned in term_bytes.rs — the
    // wrapper adds no framing. Same *shape* as the CLLW bytes EQL stores, but
    // not comparable with rows cipherstash-client wrote: the key derivations
    // differ (see the `sem` module docs).
    assert_eq!(
        hex(term.as_bytes()),
        "d757854cffc68e9f3dfa9dba7ec400a30c80dd57122ebbc064eeff5a81069fc7"
    );
    assert_eq!(term.to_bytes(), term.as_bytes());
    assert_eq!(term.as_ref(), term.as_bytes());
    assert_eq!(
        OreTerm::<u32>::from_bytes(term.as_bytes()).expect("decode ore term"),
        term
    );
}

#[tokio::test]
async fn ope_term_encoding_is_the_raw_cllw_bytes() {
    let cipher = cipher().await;
    let term: OpeTerm<u32> = 42u32
        .encrypt_into_with_context(&cipher, "users/age")
        .await
        .expect("ope term");

    assert_eq!(
        hex(term.as_bytes()),
        "00470b57be663ba84635c72c1bdfa8ed263e7e57504002db51d3e695ba0b499833"
    );
    assert_eq!(
        OpeTerm::<u32>::from_bytes(term.as_bytes()).expect("decode ope term"),
        term
    );
}

#[test]
fn ore_term_from_bytes_rejects_wrong_length() {
    // u32 → OreCllw8V1<32>: exactly 32 bytes.
    assert!(OreTerm::<u32>::from_bytes(&[0u8; 31]).is_err());
    assert!(OreTerm::<u32>::from_bytes(&[0u8; 33]).is_err());
    // u32 → OpeCllw8V1<33>: exactly 33 bytes.
    assert!(OpeTerm::<u32>::from_bytes(&[0u8; 32]).is_err());
}

#[tokio::test]
async fn variable_length_ore_and_ope_terms_decode() {
    // String sources produce variable-length CLLW ciphertexts (8 bytes per
    // plaintext byte; OPE adds a leading carry byte) — their decode path is
    // the length-validating TryFrom in cllw-ore.
    let cipher = cipher().await;
    let ore: OreTerm<String> = "alice"
        .to_string()
        .encrypt_into_with_context(&cipher, "users/name")
        .await
        .expect("ore term");
    assert_eq!(ore.as_bytes().len(), 5 * 8);
    assert_eq!(
        OreTerm::<String>::from_bytes(ore.as_bytes()).expect("decode"),
        ore
    );
    assert!(OreTerm::<String>::from_bytes(&ore.as_bytes()[1..]).is_err());

    let ope: OpeTerm<String> = "alice"
        .to_string()
        .encrypt_into_with_context(&cipher, "users/name")
        .await
        .expect("ope term");
    assert_eq!(ope.as_bytes().len(), 5 * 8 + 1);
    assert_eq!(
        OpeTerm::<String>::from_bytes(ope.as_bytes()).expect("decode"),
        ope
    );
    assert!(OpeTerm::<String>::from_bytes(&ope.as_bytes()[1..]).is_err());
}
