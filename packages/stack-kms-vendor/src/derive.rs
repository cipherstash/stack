//! The key derivations and the associated data of a key vendor backend.
//!
//! These bytes are a storage commitment: a stored value opens only if its
//! data key derives exactly as it did when it was sealed. The tests pin
//! them.
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
//!   frame[DATA_KEY_LABEL, keyset id, vendor byte, mode byte,
//!   descriptor])`, 32 bytes.
//! * index key = `HKDF-SHA256(ikm = root key, salt = none, info =
//!   frame[INDEX_KEY_LABEL, keyset id, vendor byte, mode byte])`, 32
//!   bytes.
//!
//! The iv is 16 random bytes per value, stored in the leaf, and the leaf's
//! tag is empty. The leaf is the v1 leaf and names no key backend, so the
//! backend and the mode are bound here instead: a
//! keyset record whose vendor or mode was changed derives other keys, and
//! every value fails authentication.
//!
//! # Associated data
//!
//! The root key in a keyset record is wrapped with
//! `frame[RECORD_KEY_LABEL, "root-key", keyset id, vendor byte, mode
//! byte]`. A record whose id, vendor or mode was changed does not unwrap.

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

/// What the key in a keyset record is: the root key. The purpose is bound
/// into the record's associated data, so that a key wrapped for another
/// purpose by a later key mode does not unwrap as a root key.
pub const RECORD_KEY_PURPOSE: &[u8] = b"root-key";

/// The associated data the root key in a keyset record is wrapped with.
pub fn record_key_aad(keyset_id: Uuid, vendor: KeyVendor, mode: KeyMode) -> Vec<u8> {
    frame(&[
        RECORD_KEY_LABEL,
        RECORD_KEY_PURPOSE,
        keyset_id.as_bytes(),
        &[vendor.byte()],
        &[mode.byte()],
    ])
}

/// Split bytes made by [`frame`] back into their pieces. `None` if the
/// bytes are not exactly one frame.
pub fn unframe(bytes: &[u8]) -> Option<Vec<&[u8]>> {
    fn take_u64(bytes: &[u8]) -> Option<(usize, &[u8])> {
        let (head, rest) = bytes.split_at_checked(8)?;
        let value = u64::from_le_bytes(head.try_into().ok()?);
        Some((usize::try_from(value).ok()?, rest))
    }
    let (count, mut rest) = take_u64(bytes)?;
    // Each piece takes at least 8 bytes, so a larger count cannot fit.
    if count > rest.len() / 8 {
        return None;
    }
    let mut pieces = Vec::with_capacity(count);
    for _ in 0..count {
        let (len, after) = take_u64(rest)?;
        let (piece, after) = after.split_at_checked(len)?;
        pieces.push(piece);
        rest = after;
    }
    rest.is_empty().then_some(pieces)
}

/// What a vendor may show of the associated data it is given, for audit
/// logs and access policies: the vendor's own context fields (AWS KMS
/// encryption context, for example). See [`describe_aad`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AadDescription<'a> {
    /// What the wrapped key is: `root-key`, the key in a keyset record.
    pub purpose: &'a str,
    /// The keyset the key belongs to.
    pub keyset_id: Uuid,
}

/// Describe associated data made by [`record_key_aad`]. `None` for any
/// other bytes.
///
/// The description is for a vendor that shows its associated data as
/// fields. It does not replace the associated data: the vendor must still
/// bind all of `aad` (see
/// [`KeyVendorBackend`](crate::KeyVendorBackend)), because the description
/// leaves out the vendor byte and the mode byte.
pub fn describe_aad(aad: &[u8]) -> Option<AadDescription<'_>> {
    let pieces = unframe(aad)?;
    match pieces.as_slice() {
        [label, purpose, id, vendor, mode]
            if *label == RECORD_KEY_LABEL
                && *purpose == RECORD_KEY_PURPOSE
                && vendor.len() == 1
                && mode.len() == 1 =>
        {
            Some(AadDescription {
                purpose: "root-key",
                keyset_id: Uuid::from_slice(id).ok()?,
            })
        }
        _ => None,
    }
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

/// The data key of one value under derived data keys, for a keyset of
/// `vendor` in `mode`.
pub fn derived_data_key(
    root: &KeyBytes,
    keyset_id: Uuid,
    vendor: KeyVendor,
    mode: KeyMode,
    iv: &[u8; 16],
    descriptor: &str,
) -> KeyBytes {
    let info = frame(&[
        DATA_KEY_LABEL,
        keyset_id.as_bytes(),
        &[vendor.byte()],
        &[mode.byte()],
        descriptor.as_bytes(),
    ]);
    hkdf(root, Some(iv), &info)
}

/// The index key of a keyset of `vendor` in `mode`, under derived data
/// keys.
pub fn derived_index_key(
    root: &KeyBytes,
    keyset_id: Uuid,
    vendor: KeyVendor,
    mode: KeyMode,
) -> KeyBytes {
    let info = frame(&[
        INDEX_KEY_LABEL,
        keyset_id.as_bytes(),
        &[vendor.byte()],
        &[mode.byte()],
    ]);
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

    const AWS: KeyVendor = KeyVendor::Aws;
    const DERIVED: KeyMode = KeyMode::Derived;

    /// The derivations are a storage commitment: these pins fail if one
    /// moves.
    #[test]
    fn the_derivations_are_pinned() {
        let root = Protected::new([7u8; 32]);
        let id = Uuid::from_u128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
        let data = derived_data_key(&root, id, AWS, DERIVED, &[9u8; 16], "users/email");
        let index = derived_index_key(&root, id, AWS, DERIVED);
        assert_eq!(
            hex(data.risky_ref()),
            hex(derived_data_key(&root, id, AWS, DERIVED, &[9u8; 16], "users/email").risky_ref())
        );
        assert_ne!(data.risky_ref(), index.risky_ref());
        assert_eq!(
            hex(data.risky_ref()),
            "f61d938e85e3a0ac8c23f7272710a7a7e2539597a2f5ae7c71512b5d2cd0945c"
        );
        assert_eq!(
            hex(index.risky_ref()),
            "b64982a8d277024fbec5e2ce37ab24db3fe3af17788593da8edc47c1b60819c9"
        );
    }

    #[test]
    fn every_input_changes_the_data_key() {
        let root = Protected::new([7u8; 32]);
        let id = Uuid::from_u128(1);
        let base = derived_data_key(&root, id, AWS, DERIVED, &[1u8; 16], "d");
        let others = [
            derived_data_key(
                &Protected::new([8u8; 32]),
                id,
                AWS,
                DERIVED,
                &[1u8; 16],
                "d",
            ),
            derived_data_key(&root, Uuid::from_u128(2), AWS, DERIVED, &[1u8; 16], "d"),
            derived_data_key(&root, id, KeyVendor::Vault, DERIVED, &[1u8; 16], "d"),
            derived_data_key(&root, id, AWS, DERIVED, &[2u8; 16], "d"),
            derived_data_key(&root, id, AWS, DERIVED, &[1u8; 16], "e"),
        ];
        for other in others {
            assert_ne!(base.risky_ref(), other.risky_ref());
        }
        let index = derived_index_key(&root, id, AWS, DERIVED);
        assert_ne!(
            index.risky_ref(),
            derived_index_key(&root, Uuid::from_u128(2), AWS, DERIVED).risky_ref()
        );
        assert_ne!(
            index.risky_ref(),
            derived_index_key(&root, id, KeyVendor::Gcp, DERIVED).risky_ref(),
            "the vendor is bound into the index key"
        );
    }

    /// The mode byte is in the info of both derivations, so a record with
    /// another mode byte cannot derive the keys of a derived keyset.
    /// Checked on the frame, since there is no other mode.
    #[test]
    fn the_vendor_and_mode_bytes_are_in_the_info() {
        let id = Uuid::from_u128(1);
        let info = frame(&[INDEX_KEY_LABEL, id.as_bytes(), &[AWS.byte()], &[1]]);
        let root = Protected::new([7u8; 32]);
        assert_ne!(
            hkdf(&root, None, &info).risky_ref(),
            derived_index_key(&root, id, AWS, DERIVED).risky_ref()
        );
    }

    #[test]
    fn unframe_reverses_frame_and_refuses_anything_else() {
        let pieces: [&[u8]; 3] = [b"ab", b"", b"cde"];
        let framed = frame(&pieces);
        assert_eq!(unframe(&framed).unwrap(), pieces);
        assert_eq!(unframe(&frame(&[])).unwrap(), Vec::<&[u8]>::new());
        let mut long = framed.clone();
        long.push(0);
        assert_eq!(unframe(&long), None);
        assert_eq!(unframe(&framed[..framed.len() - 1]), None);
        assert_eq!(unframe(&[1, 0, 0]), None);
        assert_eq!(unframe(&u64::MAX.to_le_bytes()), None);
    }

    #[test]
    fn describe_aad_names_the_purpose_and_keyset() {
        let id = Uuid::from_u128(7);
        assert_eq!(
            describe_aad(&record_key_aad(id, AWS, DERIVED)),
            Some(AadDescription {
                purpose: "root-key",
                keyset_id: id,
            })
        );
        assert_eq!(describe_aad(b"not a frame"), None);
        assert_eq!(describe_aad(&frame(&[b"other-label", id.as_bytes()])), None);
        assert_eq!(
            describe_aad(&frame(&[RECORD_KEY_LABEL, b"x", id.as_bytes(), &[1], &[2]])),
            None
        );
        assert_eq!(
            describe_aad(&frame(&[
                RECORD_KEY_LABEL,
                RECORD_KEY_PURPOSE,
                b"short",
                &[1],
                &[2]
            ])),
            None
        );
    }

    #[test]
    fn the_record_aad_binds_every_field() {
        let id = Uuid::from_u128(1);
        let base = record_key_aad(id, AWS, DERIVED);
        assert_ne!(base, record_key_aad(Uuid::from_u128(2), AWS, DERIVED));
        assert_ne!(base, record_key_aad(id, KeyVendor::Vault, DERIVED));
        assert_eq!(
            hex(&base),
            "05000000000000002500000000000000737461636b2d6b6d732d76656e646f722f6b65797365742d7265636f72642d6b65792f76310800000000000000726f6f742d6b6579100000000000000000000000000000000000000000000001010000000000000001010000000000000002"
        );
    }
}
