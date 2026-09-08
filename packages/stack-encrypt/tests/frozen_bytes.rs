//! Byte-level pins for the frozen encodings stack-encrypt commits to across
//! languages:
//!
//! * the [`SealedValue`] leaf layout
//!   (`version ‖ iv ‖ tag_len ‖ tag ‖ local_ciphertext`) — the storage
//!   format a database column holds, and
//! * the index-term encodings (equality: raw 32 bytes; match: LE `u16`
//!   positions; ORE/OPE: raw CLLW ciphertext bytes).
//!
//! These are the vectors a language binding's decoder tests against — the
//! Go side decodes exactly these hex strings. `tests/term_bytes.rs` pins the
//! *derivations* (PRF domains and framing); this file pins the *encodings*
//! of the results. Breaking a pin here breaks a consumer: for the leaf it
//! moves the storage format and demands a `SealedValue::FORMAT_VERSION` bump;
//! for the equality and ORE/OPE terms it moves the bytes a column holds; for
//! the match term it moves the wasm/FFI transport shape (no column holds
//! that byte string — the stored and queried contract is the position list,
//! which maps to an integer-array column), and every binding decoding it
//! silently stops agreeing.

use std::borrow::Cow;

use stack_encrypt::nonempty;
use stack_encrypt::sem::{DefaultMatch, EqualityTerm, MatchTerm, OpeTerm, OreTerm, TermBytesError};
use stack_encrypt::target::EncryptInto;
use stack_encrypt::{CipherText, Error, LeafBytesError, SealedValue, StackCipher};
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyPayload, IdentifiedBy,
    IndexKey, IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
};
use uuid::Uuid;

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

/// Delegates to [`FakeDataKeySource`] but inflates every generated key tag
/// past the `u16` length field — the misbehaving custom [`DataKeySource`] the
/// seal path must reject, rather than build a leaf whose `to_bytes` writes a
/// saturated length field that `from_bytes` no longer inverts.
struct OversizedTagSource(FakeDataKeySource);

impl DataKeySource for OversizedTagSource {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
        let mut keys = self
            .0
            .generate_keys(payloads, keyset_id, unverified_context)
            .await?;
        for key in &mut keys {
            key.tag = vec![0; usize::from(u16::MAX) + 1];
        }
        Ok(keys)
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_kms::Error> {
        self.0
            .retrieve_keys(payloads, keyset_id, unverified_context)
            .await
    }
}

impl IndexKeySource for OversizedTagSource {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
        self.0.load_index_key(keyset_id).await
    }
}

#[tokio::test]
async fn seal_rejects_a_key_tag_the_length_field_cannot_frame() {
    let cipher = StackCipher::builder()
        .kms(OversizedTagSource(FakeDataKeySource::new()))
        .init()
        .await
        .expect("build cipher");

    let result = cipher
        .encrypt("boundary".to_string(), b"ctx".as_slice())
        .await;
    assert!(
        matches!(result, Err(Error::Aead)),
        "an oversized key tag must fail the seal, not mis-encode: {result:?}"
    );
}

// =============================================================================
// Terms
// =============================================================================

#[tokio::test]
async fn equality_term_encoding_is_the_raw_prf_bytes() {
    let term = cipher()
        .await
        .equality_term("alice", nonempty!("users/email"))
        .await
        .expect("equality term");

    // The derivation is pinned in term_bytes.rs; here: encoding = identity
    // over those 32 bytes, and from_bytes is its inverse.
    assert_eq!(term.as_ref(), term.as_bytes());
    assert_eq!(term.to_bytes(), term.as_bytes());
    assert_eq!(EqualityTerm::from_bytes(*term.as_bytes()), term);

    // The std conversion is the same decoder, over a slice of unknown length.
    assert_eq!(
        EqualityTerm::try_from(term.to_bytes().as_slice()).expect("TryFrom decode"),
        term
    );
}

#[test]
fn equality_term_try_from_rejects_wrong_length() {
    assert_eq!(
        EqualityTerm::try_from([0u8; 31].as_slice()),
        Err(TermBytesError::WrongEqualityTermLength(31))
    );
    assert_eq!(
        EqualityTerm::try_from([0u8; 33].as_slice()),
        Err(TermBytesError::WrongEqualityTermLength(33))
    );
}

#[tokio::test]
async fn match_term_bytes_are_pinned() {
    let term = cipher()
        .await
        .match_terms::<DefaultMatch>("alice smith", nonempty!("users/name"))
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
    // The std conversion is the same decoder.
    assert_eq!(
        MatchTerm::<DefaultMatch>::try_from(bytes.as_slice()).expect("TryFrom decode"),
        term
    );
}

#[test]
fn match_term_from_bytes_rejects_odd_length() {
    assert_eq!(
        MatchTerm::<DefaultMatch>::from_bytes(&[0x21]),
        Err(TermBytesError::OddMatchTermLength(1))
    );
}

#[test]
fn match_term_from_bytes_rejects_positions_outside_the_filter() {
    // `DefaultMatch` is a 256-bit filter, so genuine positions are 0..256 and
    // the high byte of every LE u16 is zero. A position at the filter size,
    // and the 0xffff a wrong-endian decoder produces, are both rejected —
    // they would otherwise decode cleanly and then silently never match.
    assert_eq!(
        MatchTerm::<DefaultMatch>::from_bytes(&[0x00, 0x01]),
        Err(TermBytesError::MatchPositionOutOfRange {
            position: 256,
            filter_size: 256,
        })
    );
    assert_eq!(
        MatchTerm::<DefaultMatch>::from_bytes(&[0xff, 0xff]),
        Err(TermBytesError::MatchPositionOutOfRange {
            position: 0xffff,
            filter_size: 256,
        })
    );
    // Byte-swapping a genuine term is exactly that failure: position 0x21
    // becomes 0x2100.
    assert!(matches!(
        MatchTerm::<DefaultMatch>::from_bytes(&[0x00, 0x21]),
        Err(TermBytesError::MatchPositionOutOfRange { .. })
    ));

    // In-range positions round-trip, through both constructors.
    let positions = vec![0u16, 1, 255];
    let term = MatchTerm::<DefaultMatch>::from_positions(positions.clone()).expect("in range");
    assert_eq!(term.positions(), positions.as_slice());
    assert_eq!(
        MatchTerm::<DefaultMatch>::from_bytes(&term.to_bytes()).expect("decode"),
        term
    );
    assert_eq!(
        MatchTerm::<DefaultMatch>::from_positions(vec![256]),
        Err(TermBytesError::MatchPositionOutOfRange {
            position: 256,
            filter_size: 256,
        })
    );
}

#[tokio::test]
async fn ore_term_encoding_is_the_raw_cllw_bytes() {
    let cipher = cipher().await;
    let term: OreTerm<u32> = 42u32
        .encrypt_into_with_context(&cipher, nonempty!("users/age"))
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
    // The std conversion is the same decoder.
    assert_eq!(
        OreTerm::<u32>::try_from(term.as_bytes()).expect("TryFrom decode"),
        term
    );
}

#[tokio::test]
async fn ope_term_encoding_is_the_raw_cllw_bytes() {
    let cipher = cipher().await;
    let term: OpeTerm<u32> = 42u32
        .encrypt_into_with_context(&cipher, nonempty!("users/age"))
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
    assert_eq!(
        OpeTerm::<u32>::try_from(term.as_bytes()).expect("TryFrom decode"),
        term
    );
}

#[test]
fn ore_term_from_bytes_rejects_wrong_length() {
    // u32 → OreCllw8V1<32>: exactly 32 bytes.
    assert_eq!(
        OreTerm::<u32>::from_bytes(&[0u8; 31]),
        Err(TermBytesError::MalformedCllwCiphertext(31))
    );
    assert_eq!(
        OreTerm::<u32>::from_bytes(&[0u8; 33]),
        Err(TermBytesError::MalformedCllwCiphertext(33))
    );
    // u32 → OpeCllw8V1<33>: exactly 33 bytes.
    assert_eq!(
        OpeTerm::<u32>::from_bytes(&[0u8; 32]),
        Err(TermBytesError::MalformedCllwCiphertext(32))
    );
}

#[tokio::test]
async fn variable_length_ore_and_ope_terms_decode() {
    // String sources produce variable-length CLLW ciphertexts (8 bytes per
    // plaintext byte; OPE adds a leading carry byte) — their decode path is
    // the length-validating TryFrom in cllw-ore.
    let cipher = cipher().await;
    let ore: OreTerm<String> = "alice"
        .to_string()
        .encrypt_into_with_context(&cipher, nonempty!("users/name"))
        .await
        .expect("ore term");
    assert_eq!(ore.as_bytes().len(), 5 * 8);
    assert_eq!(
        OreTerm::<String>::from_bytes(ore.as_bytes()).expect("decode"),
        ore
    );
    assert_eq!(
        OreTerm::<String>::from_bytes(&ore.as_bytes()[1..]),
        Err(TermBytesError::MalformedCllwCiphertext(5 * 8 - 1))
    );

    let ope: OpeTerm<String> = "alice"
        .to_string()
        .encrypt_into_with_context(&cipher, nonempty!("users/name"))
        .await
        .expect("ope term");
    assert_eq!(ope.as_bytes().len(), 5 * 8 + 1);
    assert_eq!(
        OpeTerm::<String>::from_bytes(ope.as_bytes()).expect("decode"),
        ope
    );
    assert_eq!(
        OpeTerm::<String>::from_bytes(&ope.as_bytes()[1..]),
        Err(TermBytesError::MalformedCllwCiphertext(5 * 8))
    );
}
