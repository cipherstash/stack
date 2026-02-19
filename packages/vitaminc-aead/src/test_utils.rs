//! Test utilities for `vitaminc-aead`.
//!
//! Provides [`TestCipher`], a no-dependency cipher for use in doctests and
//! examples. It is **not** cryptographically secure — it simply stores the
//! plaintext alongside the AAD so that decryption can verify the AAD matches.

use crate::{Cipher, IntoAad, LocalCipherText, Unspecified};

/// A cipher that performs no real encryption.
///
/// `TestCipher` embeds the AAD into the "ciphertext" during encryption and
/// verifies it during decryption. This allows doctests to exercise the full
/// encrypt/decrypt round-trip — including AAD mismatch detection — without
/// depending on a real cipher implementation.
pub struct TestCipher;

impl Cipher for TestCipher {
    fn encrypt_slice<'a, A>(
        &self,
        plaintext: &'a [u8],
        aad: A,
    ) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>,
    {
        let aad_bytes = aad.into_aad();
        let aad_bytes = aad_bytes.as_bytes();
        let aad_len = (aad_bytes.len() as u32).to_le_bytes();

        let mut out = Vec::with_capacity(4 + aad_bytes.len() + plaintext.len());
        out.extend_from_slice(&aad_len);
        out.extend_from_slice(aad_bytes);
        out.extend_from_slice(plaintext);
        Ok(LocalCipherText::from(out))
    }

    fn encrypt_vec<'a, A>(&self, plaintext: Vec<u8>, aad: A) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>,
    {
        let aad_bytes = aad.into_aad();
        let aad_bytes = aad_bytes.as_bytes();
        let aad_len = (aad_bytes.len() as u32).to_le_bytes();

        let mut out = Vec::with_capacity(4 + aad_bytes.len() + plaintext.len());
        out.extend_from_slice(&aad_len);
        out.extend_from_slice(aad_bytes);
        out.extend_from_slice(&plaintext);
        Ok(LocalCipherText::from(out))
    }

    fn decrypt_vec<'a, A>(
        &self,
        ciphertext: LocalCipherText,
        aad: A,
    ) -> Result<Vec<u8>, Unspecified>
    where
        A: IntoAad<'a>,
    {
        let data = ciphertext.into_inner();
        if data.len() < 4 {
            return Err(Unspecified);
        }

        let aad_len = u32::from_le_bytes(data[..4].try_into().map_err(|_| Unspecified)?) as usize;
        if data.len() < 4 + aad_len {
            return Err(Unspecified);
        }

        let stored_aad = &data[4..4 + aad_len];
        let expected_aad = aad.into_aad();
        if stored_aad != expected_aad.as_bytes() {
            return Err(Unspecified);
        }

        Ok(data[4 + aad_len..].to_vec())
    }
}
