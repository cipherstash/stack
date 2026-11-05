//! The key derivations and the associated data of a key vendor backend.
//!
//! These bytes are a storage commitment: a stored value opens only if its
//! data key derives, or unwraps, exactly as it did when it was sealed. The
//! tests pin them.
//!
//! # Framing
//!
//! Every label, info and associated data is a list of byte strings framed
//! with [`frame`]: the count of pieces, then each piece as its length and
//! its bytes, every number a `u64` little-endian. The framing is
//! prefix-free, so two different lists never give the same bytes.
//!
//! # Derived data keys
//!
//! * data key = `HKDF-SHA256(ikm = root key, salt = iv, info =
//!   frame[DATA_KEY_LABEL, keyset id, descriptor])`, 32 bytes.
//! * index key = `HKDF-SHA256(ikm = root key, salt = none, info =
//!   frame[INDEX_KEY_LABEL, keyset id])`, 32 bytes.
//!
//! The iv is 16 random bytes per value, stored in the leaf, and the leaf's
//! tag is empty.
//!
//! # Associated data
//!
//! * The wrapped key in a keyset record (the root key under derived data
//!   keys, the index key under wrapped data keys) is wrapped with
//!   `frame[RECORD_KEY_LABEL, purpose, keyset id, vendor byte, mode byte]`.
//!   A record whose id, vendor or mode was changed does not unwrap.
//! * A wrapped data key is wrapped with `frame[WRAPPED_DATA_KEY_LABEL,
//!   keyset id, iv, descriptor]`. A wrapped data key moved to another
//!   keyset, value or field does not unwrap.

use hkdf::Hkdf;
use sha2::Sha256;
use stack_kms::{KeyMode, KeyVendor};
use uuid::Uuid;
use vitaminc::protected::{Controlled, Protected};
use zeroize::Zeroizing;

use crate::vendor::KeyBytes;

/// The HKDF info label of a derived data key.
pub const DATA_KEY_LABEL: &[u8] = b"stack-kms-vendor/derived-data-key/v1";
/// The HKDF info label of a derived index key.
pub const INDEX_KEY_LABEL: &[u8] = b"stack-kms-vendor/derived-index-key/v1";
/// The associated-data label of the key a keyset record wraps.
pub const RECORD_KEY_LABEL: &[u8] = b"stack-kms-vendor/keyset-record-key/v1";
/// The associated-data label of a wrapped data key.
pub const WRAPPED_DATA_KEY_LABEL: &[u8] = b"stack-kms-vendor/wrapped-data-key/v1";

/// Frame a list of byte strings without ambiguity (see the module docs).
pub fn frame(pieces: &[&[u8]]) -> Vec<u8> {
    let len = 8 + pieces.iter().map(|piece| 8 + piece.len()).sum::<usize>();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&(pieces.len() as u64).to_le_bytes());
    for piece in pieces {
        out.extend_from_slice(&(piece.len() as u64).to_le_bytes());
        out.extend_from_slice(piece);
    }
    out
}

/// What the key in a keyset record is, by key mode: the root key under
/// derived data keys, the index key under wrapped data keys.
pub fn record_key_purpose(mode: KeyMode) -> &'static [u8] {
    match mode {
        KeyMode::Derived => b"root-key",
        KeyMode::Wrapped => b"index-key",
    }
}

/// The associated data the key in a keyset record is wrapped with.
pub fn record_key_aad(keyset_id: Uuid, vendor: KeyVendor, mode: KeyMode) -> Vec<u8> {
    frame(&[
        RECORD_KEY_LABEL,
        record_key_purpose(mode),
        keyset_id.as_bytes(),
        &[vendor.byte()],
        &[mode.byte()],
    ])
}

/// The associated data a wrapped data key is wrapped with.
pub fn wrapped_data_key_aad(keyset_id: Uuid, iv: &[u8; 16], descriptor: &str) -> Vec<u8> {
    frame(&[
        WRAPPED_DATA_KEY_LABEL,
        keyset_id.as_bytes(),
        iv,
        descriptor.as_bytes(),
    ])
}

/// `HKDF-SHA256(ikm, salt, info)`, 32 bytes, into a key that wipes itself.
fn hkdf(ikm: &KeyBytes, salt: Option<&[u8]>, info: &[u8]) -> KeyBytes {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm.risky_ref());
    let mut okm = Zeroizing::new([0u8; 32]);
    // 32 bytes is far below HKDF-SHA256's limit of 255 * 32.
    #[allow(clippy::expect_used)]
    hkdf.expand(info, okm.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Protected::new(*okm)
}

/// The data key of one value under derived data keys.
pub fn derived_data_key(
    root: &KeyBytes,
    keyset_id: Uuid,
    iv: &[u8; 16],
    descriptor: &str,
) -> KeyBytes {
    let info = frame(&[DATA_KEY_LABEL, keyset_id.as_bytes(), descriptor.as_bytes()]);
    hkdf(root, Some(iv), &info)
}

/// The index key of a keyset under derived data keys.
pub fn derived_index_key(root: &KeyBytes, keyset_id: Uuid) -> KeyBytes {
    let info = frame(&[INDEX_KEY_LABEL, keyset_id.as_bytes()]);
    hkdf(root, None, &info)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 5869 test case 1, cut to the first 32 bytes of output (one
    /// HMAC block, which is all a 32-byte key uses). Proves the HKDF here
    /// is plain HKDF-SHA256.
    #[test]
    fn hkdf_matches_rfc_5869_test_case_1() {
        let ikm = Protected::new([0x0bu8; 22]);
        let hk = Hkdf::<Sha256>::new(
            Some(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            ikm.risky_ref(),
        );
        let mut okm = [0u8; 32];
        hk.expand(
            &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9],
            &mut okm,
        )
        .unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );
    }

    #[test]
    fn framing_is_prefix_free() {
        assert_ne!(frame(&[b"ab", b"c"]), frame(&[b"a", b"bc"]));
        assert_ne!(frame(&[b"abc"]), frame(&[b"abc", b""]));
        assert_eq!(hex(&frame(&[b"a"])), "0100000000000000010000000000000061");
    }

    /// The derivations are a storage commitment: these pins fail if one
    /// moves.
    #[test]
    fn the_derivations_are_pinned() {
        let root = Protected::new([7u8; 32]);
        let id = Uuid::from_u128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
        let data = derived_data_key(&root, id, &[9u8; 16], "users/email");
        let index = derived_index_key(&root, id);
        assert_eq!(
            hex(data.risky_ref()),
            hex(derived_data_key(&root, id, &[9u8; 16], "users/email").risky_ref())
        );
        assert_ne!(data.risky_ref(), index.risky_ref());
        assert_eq!(
            hex(data.risky_ref()),
            "93a33099260b4c29872102658969dfe9f28622e17875f26afdd5d1895f638c83"
        );
        assert_eq!(
            hex(index.risky_ref()),
            "80fd8f8c664080afae35d02ebb8b34cb1f6c90643dbd83fec572c0686f8eee25"
        );
    }

    #[test]
    fn every_input_changes_the_data_key() {
        let root = Protected::new([7u8; 32]);
        let id = Uuid::from_u128(1);
        let base = derived_data_key(&root, id, &[1u8; 16], "d");
        let others = [
            derived_data_key(&Protected::new([8u8; 32]), id, &[1u8; 16], "d"),
            derived_data_key(&root, Uuid::from_u128(2), &[1u8; 16], "d"),
            derived_data_key(&root, id, &[2u8; 16], "d"),
            derived_data_key(&root, id, &[1u8; 16], "e"),
        ];
        for other in others {
            assert_ne!(base.risky_ref(), other.risky_ref());
        }
        assert_ne!(
            derived_index_key(&root, id).risky_ref(),
            derived_index_key(&root, Uuid::from_u128(2)).risky_ref()
        );
    }

    #[test]
    fn the_record_aad_binds_every_field() {
        let id = Uuid::from_u128(1);
        let base = record_key_aad(id, KeyVendor::Aws, KeyMode::Derived);
        assert_ne!(
            base,
            record_key_aad(Uuid::from_u128(2), KeyVendor::Aws, KeyMode::Derived)
        );
        assert_ne!(base, record_key_aad(id, KeyVendor::Vault, KeyMode::Derived));
        assert_ne!(base, record_key_aad(id, KeyVendor::Aws, KeyMode::Wrapped));
        let data = wrapped_data_key_aad(id, &[1u8; 16], "d");
        assert_ne!(data, wrapped_data_key_aad(id, &[2u8; 16], "d"));
        assert_ne!(data, wrapped_data_key_aad(id, &[1u8; 16], "e"));
        assert_ne!(
            data,
            wrapped_data_key_aad(Uuid::from_u128(2), &[1u8; 16], "d")
        );
    }
}
