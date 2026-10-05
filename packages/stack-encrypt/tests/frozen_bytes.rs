//! Byte-level pins for the frozen encodings stack-encrypt commits to across
//! languages:
//!
//! * the [`SealedValue`] leaf layout
//!   (`version ‖ keyset_id ‖ iv ‖ tag_len ‖ tag ‖ local_ciphertext`) — the
//!   storage
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

use stack_encrypt::nonempty;
use stack_encrypt::registry::fake::{FakeKeysetRegistry, FakeProvider};
use stack_encrypt::registry::{
    Binding, BindingSupport, GeneratedDataKey, IndexKeyMaterial, IndexKeyProvider, KeyId,
    KeyIsolation, KeyProvider, KeyReconstruction, ProviderProtected, Resolved,
};
use stack_encrypt::sem::{
    DefaultMatch, EqualityTerm, MatchTerms, OpeTerm, OreTerm, TermBytesError,
};
use stack_encrypt::target::EncryptInto;
use stack_encrypt::{
    CipherText, Error, LeafBytesError, SealedValue, StackCipher, StackCipherBuilder,
};
use stack_encrypt::{KeysetId, KeysetRef, KeysetRegistry};
use uuid::Uuid;

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

// =============================================================================
// SealedValue leaf
// =============================================================================

/// A leaf from fixed parts, so the encoding is deterministic. The
/// "ciphertext" is not a real AEAD output — encoding is structural and must
/// not care.
fn fixture_leaf() -> SealedValue {
    let keyset_id = KeysetId::new(Uuid::from_bytes(*b"keyset-fixture16"));
    SealedValue::from_parts(
        keyset_id,
        vec![0xAA, 0xBB, 0xCC],
        vec![0xDE, 0xAD, 0xBE, 0xEF],
    )
    .expect("fixture key id fits the length field")
}

#[test]
fn sealed_value_layout_is_pinned() {
    let bytes = fixture_leaf().to_bytes();

    // version(01) ‖ keyset_id(16 raw UUID bytes: ASCII "keyset-fixture16") ‖
    // key_id_len(0300 — 3, u16 LE) ‖ key_id(aabbcc) ‖
    // local_ciphertext(deadbeef)
    assert_eq!(
        hex(&bytes),
        "016b65797365742d6669787475726531360300aabbccdeadbeef"
    );
}

#[test]
fn sealed_value_from_bytes_inverts_to_bytes() {
    let original = fixture_leaf();
    let bytes = original.to_bytes();
    let decoded = SealedValue::from_bytes(&bytes).expect("decode leaf");

    assert_eq!(decoded.keyset_id(), original.keyset_id());
    assert_eq!(decoded.key_id(), original.key_id());
    assert_eq!(decoded.ciphertext(), original.ciphertext());

    // The std conversion is the same decoder.
    let converted = SealedValue::try_from(bytes.as_slice()).expect("TryFrom decode");
    assert_eq!(converted.keyset_id(), original.keyset_id());
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

    // Every prefix shorter than the key id's end is truncated: empty,
    // mid-keyset-id, mid-length-field, and mid-key-id. (Anything at or past
    // the key id's end parses — the local ciphertext takes the remainder,
    // and proving *it* whole is the AEAD open's job.)
    let key_id_end = 1 + 16 + 2 + 3;
    for len in 0..key_id_end {
        assert!(
            matches!(
                SealedValue::from_bytes(&bytes[..len]),
                Err(LeafBytesError::Truncated)
            ),
            "prefix of {len} bytes must be rejected"
        );
    }
    assert!(SealedValue::from_bytes(&bytes[..key_id_end]).is_ok());
}

#[test]
fn sealed_value_decodes_the_shortest_leaf_the_layout_allows() {
    // An empty key id and an empty ciphertext leave exactly the fixed-width
    // fields: version ‖ keyset_id ‖ key_id_len. That is a whole leaf —
    // structurally, whatever the AEAD makes of it — and one byte less is
    // truncated. With a non-empty key id the key-id check would reject a
    // short buffer anyway, so only this shape pins the fixed-width check
    // itself.
    let leaf = SealedValue::from_parts(KeysetId::new(Uuid::nil()), Vec::new(), Vec::new())
        .expect("an empty key id fits");
    let bytes = leaf.to_bytes();
    assert_eq!(
        bytes.len(),
        1 + 16 + 2,
        "an empty key id and ciphertext should leave only the fixed-width fields"
    );

    let decoded = SealedValue::from_bytes(&bytes).expect("the fixed fields alone are a leaf");
    assert_eq!(
        decoded.keyset_id(),
        KeysetId::new(Uuid::nil()),
        "the keyset id should survive the round trip"
    );
    assert!(
        decoded.key_id().is_empty(),
        "the key id should decode as empty"
    );
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
fn sealed_value_accepts_the_longest_key_id_the_length_field_frames() {
    // `u16::MAX` bytes is the last key id the length field can state, so it
    // is a valid leaf — and it must survive the byte format intact.
    let key_id = vec![0x5A; usize::from(u16::MAX)];
    let leaf =
        SealedValue::from_parts(KeysetId::new(Uuid::nil()), key_id.clone(), vec![0xDE, 0xAD])
            .expect("a u16::MAX-byte key id fits the length field");

    let decoded = SealedValue::from_bytes(&leaf.to_bytes()).expect("decode leaf");
    assert_eq!(
        decoded.key_id(),
        key_id.as_slice(),
        "a u16::MAX-byte key id should survive the round trip intact"
    );
    assert_eq!(
        decoded.ciphertext(),
        [0xDE, 0xAD].as_slice(),
        "the ciphertext after the longest key id should still be framed correctly"
    );
}

#[test]
fn sealed_value_rejects_oversized_key_id_on_construction() {
    // `to_bytes` is infallible because the key id can never outgrow the
    // `u16` length field: the only constructor that could admit one rejects
    // it.
    let result = SealedValue::from_parts(
        KeysetId::new(Uuid::nil()),
        vec![0; usize::from(u16::MAX) + 1],
        vec![0xDE, 0xAD],
    );
    assert!(matches!(
        result,
        Err(LeafBytesError::KeyIdTooLong(len)) if len == usize::from(u16::MAX) + 1
    ));
}

#[tokio::test]
async fn sealed_leaf_survives_persistence_via_bytes() {
    // The format round-trips a *real* leaf: encrypt, encode, decode, decrypt.
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let ct = keyset
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

#[tokio::test]
async fn sealed_value_keyset_id_is_authenticated() {
    // The keyset id is bound into the leaf's AAD: a leaf re-pointed at another
    // keyset fails to open. (The fake source ignores keyset ids, so the key
    // retrieve itself succeeds — the AEAD is what refuses.)
    let cipher = cipher().await;
    let keyset = cipher.default_keyset();
    let aad = b"ctx".as_slice();
    let ct = keyset
        .encrypt("durable".to_string(), aad)
        .await
        .expect("encrypt");
    let leaf = match ct {
        CipherText::Single(leaf) => leaf,
        other => panic!("expected a Single leaf, got {other:?}"),
    };
    let (keyset_id, key_id, bytes) = leaf.into_parts();
    let other_keyset = KeysetId::new(Uuid::from_bytes(*b"another-keyset16"));
    assert_ne!(keyset_id, other_keyset);
    let tampered = SealedValue::from_parts(other_keyset, key_id, bytes).expect("rebuild leaf");

    // Two layers refuse this, and the outer one speaks first: a keyset *is*
    // a provider now, so a re-pointed leaf is sent to a provider that never
    // minted its key and is refused before any crypto runs. The keyset id
    // stays bound into the leaf AAD underneath that — see
    // `leaf_aad_bytes_are_pinned` — so a deployment that mapped two keysets
    // onto one backend key would still catch it.
    let result = cipher
        .decrypt::<String, _>(CipherText::Single(tampered), aad)
        .await;
    assert!(
        result.is_err(),
        "a leaf re-pointed at another keyset must not decrypt: {result:?}"
    );
}

/// Delegates to the fake registry but inflates every generated key id past
/// the `u16` length field — the misbehaving provider the seal path must
/// reject, rather than build a leaf whose `to_bytes` writes a saturated
/// length field that `from_bytes` no longer inverts.
struct OversizedKeyIdRegistry(FakeKeysetRegistry);

#[derive(Clone)]
struct OversizedKeyIds(FakeProvider);

impl KeyProvider<32> for OversizedKeyIds {
    type Error = <FakeProvider as KeyProvider<32>>::Error;

    const RECONSTRUCTION: KeyReconstruction = <FakeProvider as KeyProvider<32>>::RECONSTRUCTION;
    const ISOLATION: KeyIsolation = <FakeProvider as KeyProvider<32>>::ISOLATION;
    const BINDING: BindingSupport = <FakeProvider as KeyProvider<32>>::BINDING;

    async fn generate_keys(
        &self,
        bindings: &[Binding<'_>],
    ) -> Result<Vec<GeneratedDataKey<32>>, Self::Error> {
        let mut keys = self.0.generate_keys(bindings).await?;
        for key in &mut keys {
            key.key_id = KeyId::new(vec![0; usize::from(u16::MAX) + 1]);
        }
        Ok(keys)
    }

    async fn retrieve_keys(
        &self,
        keys: &[(KeyId, Binding<'_>)],
    ) -> Result<Vec<ProviderProtected<[u8; 32]>>, Self::Error> {
        self.0.retrieve_keys(keys).await
    }
}

impl IndexKeyProvider<32> for OversizedKeyIds {
    type Error = <FakeProvider as IndexKeyProvider<32>>::Error;

    async fn load_index_key(&self) -> Result<IndexKeyMaterial<32>, Self::Error> {
        self.0.load_index_key().await
    }
}

impl KeysetRegistry for OversizedKeyIdRegistry {
    type Provider = OversizedKeyIds;
    type Error = <FakeKeysetRegistry as KeysetRegistry>::Error;

    async fn resolve(
        &self,
        keyset: &KeysetRef,
    ) -> Result<Option<Resolved<Self::Provider>>, Self::Error> {
        Ok(self.0.resolve(keyset).await?.map(|resolved| Resolved {
            id: resolved.id,
            name: resolved.name,
            provider: OversizedKeyIds(resolved.provider),
        }))
    }
}

#[tokio::test]
async fn seal_rejects_a_key_id_the_length_field_cannot_frame() {
    let cipher = StackCipherBuilder::new()
        .registry(OversizedKeyIdRegistry(FakeKeysetRegistry::new()))
        .init()
        .await
        .expect("build cipher");

    let result = cipher
        .default_keyset()
        .encrypt("boundary".to_string(), b"ctx".as_slice())
        .await;
    assert!(
        matches!(result, Err(Error::Aead)),
        "an oversized key id must fail the seal, not mis-encode: {result:?}"
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
        "010024002e0037003a0042004d0066006f008a008f009000930099009e009f00a800a900b100b700bd00c600c900d100db00e000f900"
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
        "4670ea1803ebb80320366cd5cc006e9eb235e85450c68096ec98874d407c8b5d"
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
    let keyset = cipher.default_keyset();
    let term: OpeTerm<u32> = 42u32
        .encrypt_into_with_context(&keyset, nonempty!("users/age"))
        .await
        .expect("ope term");

    assert_eq!(
        hex(term.as_bytes()),
        "00f6bb865fbb63936656ce27932e3a2f061e6b21ba10a6fb12b91dcf74c2e290ba"
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
    let keyset = cipher.default_keyset();
    let ore: OreTerm<String> = "alice"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
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
        .encrypt_into_with_context(&keyset, nonempty!("users/name"))
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
