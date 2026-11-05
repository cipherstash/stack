//! Byte-level pins for the frozen encodings stack-encrypt commits to across
//! languages:
//!
//! * the [`SealedValue`] leaf layouts — v1
//!   (`version ‖ keyset_id ‖ iv ‖ tag_len ‖ tag ‖ local_ciphertext`, which
//!   ZeroKMS writes) and v2
//!   (`version ‖ backend ‖ mode ‖ keyset_id ‖ iv ‖ tag_len ‖ tag ‖
//!   local_ciphertext`, which a key vendor backend writes) — the storage
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
use stack_encrypt::sem::{
    DefaultMatch, EqualityTerm, MatchTerms, OpeTerm, OreTerm, TermBytesError,
};

use stack_encrypt::target::legacy::EncryptInto;
use stack_encrypt::{CipherText, Error, LeafBytesError, SealedValue, StackCipher};
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, DeterministicSource, FakeDataKeySource,
    GenerateKeyPayload, IdentifiedBy, IndexKey, IndexKeySource, KeyBackend, KeyMode, KeyVendor,
    RetrieveKeyPayload, UnverifiedContext,
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

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

// =============================================================================
// SealedValue leaf
// =============================================================================

/// A leaf from fixed parts, so the encoding is deterministic. The
/// "ciphertext" is not a real AEAD output — encoding is structural and must
/// not care.
fn fixture_leaf() -> SealedValue {
    let keyset_id = Uuid::from_bytes(*b"keyset-fixture16");
    let iv: stack_kms::Iv = *b"0123456789abcdef";
    SealedValue::from_parts(
        keyset_id,
        iv,
        vec![0xAA, 0xBB, 0xCC],
        vec![0xDE, 0xAD, 0xBE, 0xEF],
    )
    .expect("fixture tag fits the length field")
}

#[test]
fn sealed_value_layout_is_pinned() {
    let bytes = fixture_leaf().to_bytes();

    // version(01) ‖ keyset_id(16 raw UUID bytes: ASCII "keyset-fixture16") ‖
    // iv(16 bytes: ASCII "0123456789abcdef") ‖ tag_len(0300 — 3, u16 LE) ‖
    // tag(aabbcc) ‖ local_ciphertext(deadbeef)
    assert_eq!(
        hex(&bytes),
        "016b65797365742d666978747572653136303132333435363738396162636465660300aabbccdeadbeef"
    );
}

#[test]
fn sealed_value_from_bytes_inverts_to_bytes() {
    let original = fixture_leaf();
    let bytes = original.to_bytes();
    let decoded = SealedValue::from_bytes(&bytes).expect("decode leaf");

    assert_eq!(decoded.keyset_id(), original.keyset_id());
    assert_eq!(decoded.iv(), original.iv());
    assert_eq!(decoded.tag(), original.tag());
    assert_eq!(decoded.ciphertext(), original.ciphertext());

    // The std conversion is the same decoder.
    let converted = SealedValue::try_from(bytes.as_slice()).expect("TryFrom decode");
    assert_eq!(converted.keyset_id(), original.keyset_id());
    assert_eq!(converted.ciphertext(), original.ciphertext());
}

#[test]
fn sealed_value_rejects_unknown_version() {
    let mut bytes = fixture_leaf().to_bytes();
    for version in [0, 3, u8::MAX] {
        bytes[0] = version;
        assert_eq!(
            SealedValue::from_bytes(&bytes).map(|_| ()),
            Err(LeafBytesError::UnknownVersion(version))
        );
    }
}

/// A known-answer test for a real v1 leaf: these bytes were sealed once by
/// [`DeterministicSource`] (seed `[7; 32]`) under the context
/// `users/email`, and must open, unchanged, for as long as v1 is read. A
/// change to the v1 framing, the v1 leaf AAD or the v1 decoder fails here.
#[tokio::test]
async fn a_pinned_v1_leaf_still_opens() {
    const V1_LEAF: &str = "010000000000000000000000000000000045608626b2b6c6de1bfc90dd87c420ac2000d702c5b01099cca8d52801ec7a9ee26928d0f8c71e120a2a62cc9b7f2e96579a01c9186cd1c3d5e396fe5a727d374ab5cddf8abae2b708de5ceed1925f75508b9c4b271f1bff53234b";
    let bytes = unhex(V1_LEAF);
    let leaf = SealedValue::from_bytes(&bytes).expect("decode the pinned v1 leaf");
    assert_eq!(leaf.format_version(), SealedValue::FORMAT_VERSION);
    assert_eq!(leaf.key_backend(), KeyBackend::ZeroKms);
    assert_eq!(leaf.key_mode(), None);
    assert_eq!(
        hex(&leaf.to_bytes()),
        V1_LEAF,
        "v1 re-encodes byte for byte"
    );

    let cipher = StackCipher::builder()
        .kms(DeterministicSource::new([7; 32]))
        .init()
        .await
        .expect("build cipher");
    let plaintext: String = cipher
        .decrypt(CipherText::Single(leaf), b"users/email".as_slice())
        .await
        .expect("the pinned v1 leaf opens");
    assert_eq!(plaintext, "known answer");
}

// =============================================================================
// SealedValue v2 leaf
// =============================================================================

/// [`fixture_leaf`]'s parts as a v2 leaf of `vendor` in `mode`.
fn fixture_v2_leaf(vendor: KeyVendor, mode: KeyMode) -> SealedValue {
    let (keyset_id, iv, tag, ciphertext) = fixture_leaf().into_parts();
    SealedValue::from_vendor_parts(vendor, mode, keyset_id, iv, tag, ciphertext)
        .expect("fixture tag fits the length field")
}

#[test]
fn v2_sealed_value_layout_is_pinned() {
    let bytes = fixture_v2_leaf(KeyVendor::Aws, KeyMode::Wrapped).to_bytes();

    // version(02) ‖ backend(01 — AWS KMS) ‖ mode(01 — wrapped) ‖ then the
    // v1 fields: keyset_id ‖ iv ‖ tag_len ‖ tag ‖ local_ciphertext.
    assert_eq!(
        hex(&bytes),
        "0201016b65797365742d666978747572653136303132333435363738396162636465660300aabbccdeadbeef"
    );
    // Past the two extra header bytes, v2 is the v1 layout.
    assert_eq!(&bytes[3..], &fixture_leaf().to_bytes()[1..]);
}

#[test]
fn v2_sealed_value_from_bytes_inverts_to_bytes_for_every_backend_and_mode() {
    for vendor in KeyVendor::ALL {
        for mode in KeyMode::ALL {
            let original = fixture_v2_leaf(vendor, mode);
            let bytes = original.to_bytes();
            assert_eq!(&bytes[..3], &[2, vendor.byte(), mode.byte()]);
            let decoded = SealedValue::from_bytes(&bytes).expect("decode v2 leaf");
            assert_eq!(decoded.format_version(), SealedValue::VENDOR_FORMAT_VERSION);
            assert_eq!(decoded.key_backend(), KeyBackend::Vendor(vendor));
            assert_eq!(decoded.key_mode(), Some(mode));
            assert_eq!(decoded.keyset_id(), original.keyset_id());
            assert_eq!(decoded.iv(), original.iv());
            assert_eq!(decoded.tag(), original.tag());
            assert_eq!(decoded.ciphertext(), original.ciphertext());
            assert_eq!(decoded.to_bytes(), bytes);
            assert_eq!(
                decoded.clone().to_bytes(),
                bytes,
                "a clone keeps the v2 header"
            );
        }
    }
}

#[test]
fn v2_sealed_value_rejects_an_unknown_backend_or_mode() {
    let bytes = fixture_v2_leaf(KeyVendor::Static, KeyMode::Derived).to_bytes();
    for byte in [0, 6, u8::MAX] {
        let mut backend = bytes.clone();
        backend[1] = byte;
        assert_eq!(
            SealedValue::from_bytes(&backend).map(|_| ()),
            Err(LeafBytesError::UnknownBackend(byte))
        );
    }
    for byte in [0, 3, u8::MAX] {
        let mut mode = bytes.clone();
        mode[2] = byte;
        assert_eq!(
            SealedValue::from_bytes(&mode).map(|_| ()),
            Err(LeafBytesError::UnknownMode(byte))
        );
    }
}

#[test]
fn v2_sealed_value_rejects_truncation() {
    let bytes = fixture_v2_leaf(KeyVendor::Vault, KeyMode::Wrapped).to_bytes();
    let tag_end = 3 + 16 + 16 + 2 + 3;
    for len in 0..tag_end {
        assert_eq!(
            SealedValue::from_bytes(&bytes[..len]).map(|_| ()),
            Err(LeafBytesError::Truncated),
            "prefix of {len} bytes must be rejected"
        );
    }
    assert!(SealedValue::from_bytes(&bytes[..tag_end]).is_ok());
}

/// Under derived data keys the tag is empty: the shortest v2 leaf is the
/// header and the fixed-width fields.
#[test]
fn v2_sealed_value_decodes_the_shortest_leaf_the_layout_allows() {
    let leaf = SealedValue::from_vendor_parts(
        KeyVendor::Static,
        KeyMode::Derived,
        Uuid::nil(),
        [7; 16],
        Vec::new(),
        Vec::new(),
    )
    .expect("empty tag fits");
    let bytes = leaf.to_bytes();
    assert_eq!(bytes.len(), 3 + 16 + 16 + 2);
    let decoded = SealedValue::from_bytes(&bytes).expect("the fixed fields alone are a leaf");
    assert!(decoded.tag().is_empty());
    assert!(decoded.ciphertext().is_empty());
    assert_eq!(
        SealedValue::from_bytes(&bytes[..bytes.len() - 1]).map(|_| ()),
        Err(LeafBytesError::Truncated)
    );
}

#[test]
fn v2_sealed_value_rejects_oversized_tag_on_construction() {
    let result = SealedValue::from_vendor_parts(
        KeyVendor::Aws,
        KeyMode::Wrapped,
        Uuid::nil(),
        [0; 16],
        vec![0; usize::from(u16::MAX) + 1],
        Vec::new(),
    );
    assert_eq!(
        result.map(|_| ()),
        Err(LeafBytesError::TagTooLong(usize::from(u16::MAX) + 1))
    );
}

#[test]
fn sealed_value_rejects_truncation() {
    let bytes = fixture_leaf().to_bytes();

    // Every prefix shorter than the tag's end is truncated: empty,
    // mid-keyset-id, mid-iv, mid-length-field, and mid-tag. (Anything at or
    // past the tag's end parses — the local ciphertext takes the remainder,
    // and proving *it* whole is the AEAD open's job.)
    let tag_end = 1 + 16 + 16 + 2 + 3;
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
fn sealed_value_decodes_the_shortest_leaf_the_layout_allows() {
    // An empty tag and an empty ciphertext leave exactly the fixed-width
    // fields: version ‖ keyset_id ‖ iv ‖ tag_len. That is a whole leaf —
    // structurally, whatever the AEAD makes of it — and one byte less is
    // truncated. With a non-empty tag the tag check would reject a short
    // buffer anyway, so only this shape pins the fixed-width check itself.
    let leaf = SealedValue::from_parts(Uuid::nil(), [7; 16], Vec::new(), Vec::new())
        .expect("an empty tag fits");
    let bytes = leaf.to_bytes();
    assert_eq!(
        bytes.len(),
        1 + 16 + 16 + 2,
        "an empty tag and ciphertext should leave only the fixed-width fields"
    );

    let decoded = SealedValue::from_bytes(&bytes).expect("the fixed fields alone are a leaf");
    assert_eq!(
        decoded.keyset_id(),
        Uuid::nil(),
        "the keyset id should survive the round trip"
    );
    assert_eq!(
        decoded.iv(),
        &[7; 16],
        "the iv should survive the round trip"
    );
    assert!(decoded.tag().is_empty(), "the tag should decode as empty");
    assert!(
        decoded.ciphertext().is_empty(),
        "the ciphertext should decode as empty"
    );

    assert!(
        matches!(
            SealedValue::from_bytes(&bytes[..bytes.len() - 1]),
            Err(LeafBytesError::Truncated)
        ),
        "one byte short of the fixed-width fields should be truncated"
    );
}

#[test]
fn sealed_value_accepts_the_longest_tag_the_length_field_frames() {
    // `u16::MAX` bytes is the last tag the length field can state, so it is
    // a valid leaf — and it must survive the byte format intact.
    let tag = vec![0x5A; usize::from(u16::MAX)];
    let leaf = SealedValue::from_parts(Uuid::nil(), [0; 16], tag.clone(), vec![0xDE, 0xAD])
        .expect("a u16::MAX-byte tag fits the length field");

    let decoded = SealedValue::from_bytes(&leaf.to_bytes()).expect("decode leaf");
    assert_eq!(
        decoded.tag(),
        tag.as_slice(),
        "a u16::MAX-byte tag should survive the round trip intact"
    );
    assert_eq!(
        decoded.ciphertext(),
        [0xDE, 0xAD].as_slice(),
        "the ciphertext after the longest tag should still be framed correctly"
    );
}

#[test]
fn sealed_value_rejects_oversized_tag_on_construction() {
    // `to_bytes` is infallible because the tag can never outgrow the `u16`
    // length field: the only constructor that could admit one rejects it.
    let result = SealedValue::from_parts(
        Uuid::nil(),
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
    let keyset = cipher.default_keyset();
    let ct = keyset
        .encrypt_tree("durable".to_string(), b"ctx".as_slice())
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

#[tokio::test]
async fn sealed_value_keyset_id_is_authenticated() {
    // The keyset id is bound into the leaf's AAD: a leaf re-pointed at another
    // keyset fails to open. (The fake source ignores keyset ids, so the key
    // retrieve itself succeeds — the AEAD is what refuses.)
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let aad = b"ctx".as_slice();
    let ct = keyset
        .encrypt_tree("durable".to_string(), aad)
        .await
        .expect("encrypt");
    let leaf = match ct {
        CipherText::Single(leaf) => leaf,
        other => panic!("expected a Single leaf, got {other:?}"),
    };
    let (keyset_id, iv, tag, bytes) = leaf.into_parts();
    let other_keyset = Uuid::from_bytes(*b"another-keyset16");
    assert_ne!(keyset_id, other_keyset);
    let tampered = SealedValue::from_parts(other_keyset, iv, tag, bytes).expect("rebuild leaf");

    let result = cipher
        .decrypt::<String, _>(CipherText::Single(tampered), aad)
        .await;
    assert!(
        matches!(result, Err(Error::Aead)),
        "a leaf re-pointed at another keyset must not decrypt: {result:?}"
    );
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
        .default_keyset()
        .encrypt_tree("boundary".to_string(), b"ctx".as_slice())
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
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let term = keyset
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
    // And the owned conversion out is the same encoding.
    let bytes = term.to_bytes();
    assert_eq!(
        Vec::<u8>::from(term),
        bytes,
        "the owned conversion should produce the same encoding as to_bytes"
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
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let term = keyset
        .match_terms::<DefaultMatch>("alice smith", nonempty!("users/name"))
        .await
        .expect("match term");

    // The little-endian u16 encoding of the positions pinned in
    // term_bytes.rs, in sorted order.
    let bytes = term.to_bytes();
    assert_eq!(
        hex(&bytes),
        "06000f001c0028003300360037003d0040005c0073009400970099009b00a100a300ac00b100b300ba00bb00c500d800f600fb00fe00"
    );
    assert_eq!(
        MatchTerms::<DefaultMatch>::from_bytes(&bytes).expect("decode match term"),
        term
    );
    // The std conversion is the same decoder.
    assert_eq!(
        MatchTerms::<DefaultMatch>::try_from(bytes.as_slice()).expect("TryFrom decode"),
        term
    );
}

/// `Debug` shows the positions — the stored, queried form — and nothing
/// else.
#[test]
fn match_term_debug_is_its_positions() {
    let term = MatchTerms::<DefaultMatch>::from_positions(vec![17, 3]).expect("in range");
    assert_eq!(
        format!("{term:?}"),
        "MatchTerms { positions: [3, 17] }",
        "Debug should show only the sorted positions"
    );
}

#[test]
fn match_term_from_bytes_rejects_odd_length() {
    assert_eq!(
        MatchTerms::<DefaultMatch>::from_bytes(&[0x21]),
        Err(TermBytesError::OddMatchTermsLength(1))
    );
}

#[test]
fn match_term_from_bytes_rejects_positions_outside_the_filter() {
    // `DefaultMatch` is a 256-bit filter, so genuine positions are 0..256 and
    // the high byte of every LE u16 is zero. A position at the filter size,
    // and the 0xffff a wrong-endian decoder produces, are both rejected —
    // they would otherwise decode cleanly and then silently never match.
    assert_eq!(
        MatchTerms::<DefaultMatch>::from_bytes(&[0x00, 0x01]),
        Err(TermBytesError::MatchPositionOutOfRange {
            position: 256,
            filter_size: 256,
        })
    );
    assert_eq!(
        MatchTerms::<DefaultMatch>::from_bytes(&[0xff, 0xff]),
        Err(TermBytesError::MatchPositionOutOfRange {
            position: 0xffff,
            filter_size: 256,
        })
    );
    // Byte-swapping a genuine term is exactly that failure: position 0x21
    // becomes 0x2100.
    assert!(matches!(
        MatchTerms::<DefaultMatch>::from_bytes(&[0x00, 0x21]),
        Err(TermBytesError::MatchPositionOutOfRange { .. })
    ));

    // In-range positions round-trip, through both constructors.
    let positions = vec![0u16, 1, 255];
    let term = MatchTerms::<DefaultMatch>::from_positions(positions.clone()).expect("in range");
    assert_eq!(term.positions(), positions.as_slice());
    assert_eq!(
        MatchTerms::<DefaultMatch>::from_bytes(&term.to_bytes()).expect("decode"),
        term
    );
    assert_eq!(
        MatchTerms::<DefaultMatch>::from_positions(vec![256]),
        Err(TermBytesError::MatchPositionOutOfRange {
            position: 256,
            filter_size: 256,
        })
    );
}

#[tokio::test]
async fn ore_term_encoding_is_the_raw_cllw_bytes() {
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let term: OreTerm<u32> = 42u32
        .encrypt_into_with_context(&keyset, nonempty!("users/age"))
        .await
        .expect("ore term");

    // Byte-identical to the raw CLLW output pinned in term_bytes.rs — the
    // wrapper adds no framing. Same *shape* as the CLLW bytes EQL stores, but
    // not comparable with rows cipherstash-client wrote: the key derivations
    // differ (see the `sem` module docs).
    assert_eq!(
        hex(term.as_bytes()),
        "1ba4d59ccb15d505519ad854229ec0c106644fa8b8944ec54c68a1f324499d82"
    );
    assert_eq!(term.to_bytes(), term.as_bytes());
    assert_eq!(term.as_ref(), term.as_bytes());
    assert_eq!(
        OreTerm::<u32>::from_bytes(term.to_bytes()).expect("decode ore term"),
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
    let keyset = cipher.default_keyset();
    let term: OpeTerm<u32> = 42u32
        .encrypt_into_with_context(&keyset, nonempty!("users/age"))
        .await
        .expect("ope term");

    assert_eq!(
        hex(term.as_bytes()),
        "00a77ed973ff1af2e5d5e3779471df246d17a515f0131eb87e35e02e7a80aa5292"
    );
    assert_eq!(
        OpeTerm::<u32>::from_bytes(term.to_bytes()).expect("decode ope term"),
        term
    );
    assert_eq!(
        OpeTerm::<u32>::try_from(term.as_bytes()).expect("TryFrom decode"),
        term
    );
}

#[test]
fn ore_term_from_bytes_rejects_wrong_length() {
    // Every order term is clww-ore's variable-length ciphertext: ORE is
    // one byte per plaintext bit (a multiple of 8, a u32's 32 here), OPE
    // that plus a leading carry byte. The length checks are structural:
    // the type parameter names the source, and nothing in the bytes does.
    assert_eq!(
        OreTerm::<u32>::from_bytes(vec![0u8; 31]),
        Err(TermBytesError::MalformedCllwCiphertext(31))
    );
    assert_eq!(
        OreTerm::<u32>::from_bytes(vec![0u8; 33]),
        Err(TermBytesError::MalformedCllwCiphertext(33))
    );
    assert_eq!(
        OpeTerm::<u32>::from_bytes(vec![0u8; 32]),
        Err(TermBytesError::MalformedCllwCiphertext(32))
    );
}

#[tokio::test]
async fn variable_length_ore_and_ope_terms_decode() {
    // Text is encoded behind vitaminc-ore's one marker byte, so `alice` is six
    // plaintext bytes: 48 ORE bytes, and 49 for OPE with its leading carry
    // byte. The decode path is the length-validating TryFrom in clww-ore.
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ore: OreTerm<String> = "alice"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await
        .expect("ore term");
    assert_eq!(ore.as_bytes().len(), 6 * 8);
    assert_eq!(
        OreTerm::<String>::from_bytes(ore.to_bytes()).expect("decode"),
        ore
    );
    assert_eq!(
        OreTerm::<String>::from_bytes(ore.as_bytes()[1..].to_vec()),
        Err(TermBytesError::MalformedCllwCiphertext(6 * 8 - 1))
    );

    let ope: OpeTerm<String> = "alice"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
        .await
        .expect("ope term");
    assert_eq!(ope.as_bytes().len(), 6 * 8 + 1);
    assert_eq!(
        OpeTerm::<String>::from_bytes(ope.to_bytes()).expect("decode"),
        ope
    );
    assert_eq!(
        OpeTerm::<String>::from_bytes(ope.as_bytes()[1..].to_vec()),
        Err(TermBytesError::MalformedCllwCiphertext(6 * 8))
    );
}
