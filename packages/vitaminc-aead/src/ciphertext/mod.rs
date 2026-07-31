mod read_monads;
mod write_monads;
use bytes::Bytes;
use read_monads::CipherTextReader;
use serde::{Deserialize, Serialize};
pub use write_monads::CipherTextBuilder;

/// First byte of every [`LocalCipherText`] — the wire-format version.
///
/// The leaf is the only byte-format commitment the crate makes (the
/// container tree has no canonical encoding), so the version discriminator
/// lives here and rides inside every persisted leaf for free. Bump it on
/// any break to the leaf layout *or* to the AAD derivation rules; decrypt
/// rejects versions it does not know how to parse.
///
/// The byte is authenticated, not merely parsed: every leaf's effective
/// AAD binds it via [`Aad::for_leaf`](crate::Aad::for_leaf), so relabeling
/// a stored leaf's version fails tag verification instead of selecting a
/// different (perhaps weaker) set of derivation rules — a downgrade is
/// foreclosed by construction, not by parser luck.
pub const WIRE_VERSION: u8 = 1;

/// A sealed leaf: `version(1) ‖ nonce ‖ ciphertext ‖ tag`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LocalCipherText(Bytes);

impl LocalCipherText {
    pub fn into_inner(self) -> Bytes {
        self.0
    }

    pub fn into_reader(self) -> CipherTextReader {
        CipherTextReader::new(self.0)
    }

    /// The stored wire-format version, readable without the key — for
    /// diagnostics and migration tooling (an operator can tell "old
    /// format" from "current format" on a decrypt failure). `None` means
    /// the buffer is empty. This is an *unauthenticated peek*: trust it
    /// for triage, never for parsing decisions outside the reader, which
    /// re-checks it under the AEAD tag.
    pub fn wire_version(&self) -> Option<u8> {
        self.0.first().copied()
    }
}

impl AsRef<[u8]> for LocalCipherText {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Vec<u8>> for LocalCipherText {
    fn from(bytes: Vec<u8>) -> Self {
        LocalCipherText(Bytes::from(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Nonce;
    use vitaminc_protected::{Controlled, Protected};

    #[test]
    fn test_ciphertext_builder_with_plaintext_in_place() -> Result<(), ()> {
        let nonce = Nonce::new([1u8; 12]);
        let plaintext = vec![0u8; 10];
        let ciphertext = CipherTextBuilder::new()
            .append_nonce(nonce)
            .append_target_plaintext(plaintext)
            .accepts_ciphertext_and_tag_ok(|mut ciphertext| {
                ciphertext.copy_from_slice(&[2u8; 10]);
                ciphertext.extend([3u8; 16]);
                Ok(ciphertext)
            })
            .build()?;

        // version(1) ‖ nonce(12) ‖ ciphertext(10) ‖ tag(16)
        assert_eq!(ciphertext.0.len(), 39);
        assert_eq!(ciphertext.0[0], WIRE_VERSION);
        assert_eq!(ciphertext.wire_version(), Some(WIRE_VERSION));
        assert_eq!(&ciphertext.0[1..13], &[1u8; 12]);
        assert_eq!(&ciphertext.0[13..23], &[2u8; 10]);
        assert_eq!(&ciphertext.0[23..], &[3u8; 16]);

        Ok(())
    }

    #[test]
    fn test_ciphertext_reader() -> Result<(), ()> {
        let nonce = Nonce::new([1u8; 12]);
        let plaintext: Protected<Vec<u8>> = Protected::new(vec![0u8; 10]);

        let ciphertext = CipherTextBuilder::new()
            .append_nonce(nonce)
            .append_target_plaintext(plaintext)
            .accepts_ciphertext_and_tag_ok(|mut ciphertext| {
                ciphertext.copy_from_slice(&[2u8; 10]);
                ciphertext.extend([3u8; 16]);
                Ok(ciphertext)
            })
            .build()?;

        let (nonce, reader) = ciphertext
            .into_reader()
            .read_version()
            .map_err(|_| ())?
            .read_nonce::<12>()
            .map_err(|_| ())?;

        let plaintext = reader
            .accepts_plaintext_ok(|data| {
                assert_eq!(data.len(), 26);
                assert_eq!(&data[..10], [2u8; 10]);
                assert_eq!(&data[10..], [3u8; 16]);
                // Write in the same way as AWS-LC/Ring does
                data[..10].copy_from_slice(&[0u8; 10]);
                Ok(10)
            })
            .read()?;

        assert_eq!(nonce.into_inner(), [1u8; 12]);
        assert_eq!(plaintext.risky_unwrap()[..10], vec![0u8; 10]);

        Ok(())
    }
}
