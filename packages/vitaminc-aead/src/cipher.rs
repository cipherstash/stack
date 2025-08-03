use crate::{aad::IntoAad, LocalCipherText};

/// An error that provides no information about the failure.
/// It is crucial when returning an error from a cipher operation
/// that does not reveal any details about the failure as this can lead to side channel attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unspecified;

pub trait Cipher {
    type Key;

    fn encrypt_bytes<'a, A>(
        &self,
        plaintext: Vec<u8>,
        key: &Self::Key,
        aad: A,
    ) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>;

    fn encrypt_array<'a, const N: usize, A>(
        &self,
        plaintext: [u8; N],
        key: &Self::Key,
        aad: A,
    ) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>;

    fn decrypt_bytes<'a, A>(
        &self,
        ciphertext: LocalCipherText,
        key: &Self::Key,
        aad: A,
    ) -> Result<Vec<u8>, Unspecified>
    where
        A: IntoAad<'a>;

    fn decrypt_array<'a, const N: usize, A>(
        &self,
        ciphertext: LocalCipherText,
        key: &Self::Key,
        aad: A,
    ) -> Result<[u8; N], Unspecified>
    where
        A: IntoAad<'a>;
}
