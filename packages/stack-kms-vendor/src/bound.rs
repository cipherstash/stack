//! Associated data bound by us, for a vendor key that cannot bind it.
//!
//! [`KeyVendorBackend`](crate::KeyVendorBackend) requires that `unwrap`
//! fails unless its `aad` is the `aad` given to `wrap`. Some vendor keys
//! have no associated data of their own: an Azure Managed HSM `oct-HSM`
//! key (`wrapkey` takes none), or a HashiCorp Vault Transit key that is not derived (Vault ignores
//! `context` on such a key, and older Vault versions ignore
//! `associated_data`). For these, the vendor encrypts a **bound key**
//! instead of the bare key:
//!
//! ```text
//! bound key = version(1) = 1 ‖ SHA-256(frame[BOUND_KEY_LABEL, aad]) (32) ‖ key (32)
//! ```
//!
//! On unwrap, [`open_bound_key`] recomputes the digest from the `aad` it is
//! given and compares it in constant time. A wrapped key moved to another
//! keyset, value or field decrypts, but does not open.
//!
//! # The rule for the vendor
//!
//! This is sound only if both of these are true of the vendor's encryption:
//!
//! 1. **Only the vendor key can make a wrapped key.** The digest has no
//!    secret key, so anyone who can wrap can wrap a bound key of their own
//!    choice under any `aad`. The wrap must therefore need the vendor key:
//!    a symmetric key that the vendor holds. Public-key encryption
//!    (RSA-OAEP, for example) must not be used: anyone with the public key
//!    could put a root key that they know into a keyset record.
//! 2. **It is non-malleable.** An attacker who holds a wrapped key must not
//!    be able to change its digest without the vendor key. An AEAD
//!    (AES-GCM, ChaCha20-Poly1305) and AES key wrap (RFC 3394) are
//!    non-malleable. Unauthenticated modes (AES-CBC, AES-CTR) are not, and
//!    must not be used.
//!
//! The bound key is 65 bytes.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use vitaminc::protected::{Controlled, Protected};
use zeroize::Zeroizing;

use crate::derive::frame;
use crate::vendor::KeyBytes;

/// The label of the associated-data digest in a bound key.
pub const BOUND_KEY_LABEL: &[u8] = b"stack-kms-vendor/bound-key/v1";
/// The version byte of a bound key.
pub const BOUND_KEY_VERSION: u8 = 1;
/// The length of a bound key: version, digest, key.
pub const BOUND_KEY_LEN: usize = 1 + 32 + 32;

/// A bound key did not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BoundKeyError {
    /// The bytes are not a bound key: wrong length or version.
    #[error("the vendor plaintext is not a bound key")]
    Malformed,
    /// The key was wrapped with other associated data.
    #[error("the wrapped key belongs to other associated data")]
    WrongAad,
}

/// The digest of `aad` that a bound key carries.
fn aad_digest(aad: &[u8]) -> [u8; 32] {
    Sha256::digest(frame(&[BOUND_KEY_LABEL, aad])).into()
}

/// The bound key of `key` under `aad`: the plaintext a vendor encrypts in
/// place of `key`. Wiped on drop.
pub fn bind_key(key: &KeyBytes, aad: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(BOUND_KEY_LEN));
    out.push(BOUND_KEY_VERSION);
    out.extend_from_slice(&aad_digest(aad));
    out.extend_from_slice(key.risky_ref());
    out
}

/// The key in `bound`, if `bound` is a bound key made under `aad`.
pub fn open_bound_key(bound: &[u8], aad: &[u8]) -> Result<KeyBytes, BoundKeyError> {
    if bound.len() != BOUND_KEY_LEN || bound[0] != BOUND_KEY_VERSION {
        return Err(BoundKeyError::Malformed);
    }
    let (digest, key) = bound[1..].split_at(32);
    if !bool::from(digest.ct_eq(&aad_digest(aad))) {
        return Err(BoundKeyError::WrongAad);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(key);
    Ok(Protected::new(*out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn a_bound_key_opens_under_its_own_aad_only() {
        let key = Protected::new([5u8; 32]);
        let bound = bind_key(&key, b"aad");
        assert_eq!(bound.len(), BOUND_KEY_LEN);
        assert_eq!(
            open_bound_key(&bound, b"aad").unwrap().risky_ref(),
            &[5u8; 32]
        );
        assert_eq!(
            open_bound_key(&bound, b"other").unwrap_err(),
            BoundKeyError::WrongAad
        );
        assert_eq!(
            open_bound_key(&bound, b"").unwrap_err(),
            BoundKeyError::WrongAad
        );
    }

    #[test]
    fn anything_but_a_bound_key_is_malformed() {
        let bound = bind_key(&Protected::new([5u8; 32]), b"aad");
        assert_eq!(
            open_bound_key(&bound[..64], b"aad").unwrap_err(),
            BoundKeyError::Malformed
        );
        let mut long = bound.to_vec();
        long.push(0);
        assert_eq!(
            open_bound_key(&long, b"aad").unwrap_err(),
            BoundKeyError::Malformed
        );
        let mut version = bound.to_vec();
        version[0] = 2;
        assert_eq!(
            open_bound_key(&version, b"aad").unwrap_err(),
            BoundKeyError::Malformed
        );
        assert_eq!(
            open_bound_key(&[5u8; 32], b"aad").unwrap_err(),
            BoundKeyError::Malformed
        );
    }

    /// A storage commitment: a wrapped key bound today must open later.
    #[test]
    fn the_bound_key_is_pinned() {
        let bound = bind_key(&Protected::new([5u8; 32]), b"aad");
        assert_eq!(
            hex(&bound),
            concat!(
                "01",
                "ae51a3bebe8d3505fbec2c4045a899e0ffc51efd1fa0b91d1ce298ceb042e693",
                "0505050505050505050505050505050505050505050505050505050505050505"
            )
        );
    }
}
