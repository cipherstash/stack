use crate::{aad::IntoAad, LocalCipherText};

/// An error that provides **no information** about the failure.
/// It is crucial when returning an error from a cipher operation
/// that does not reveal any details about the failure as this can lead to side channel attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unspecified;

impl std::fmt::Display for Unspecified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unspecified error")
    }
}

impl std::error::Error for Unspecified {}

pub trait Cipher {
    fn encrypt_slice<'a, A>(
        &self,
        plaintext: &'a [u8],
        aad: A,
    ) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>;

    fn encrypt_vec<'a, A>(
        &self,
        plaintext: Vec<u8>,
        aad: A,
    ) -> Result<LocalCipherText, Unspecified>
    where
        A: IntoAad<'a>;

    fn decrypt_vec<'a, A>(
        &self,
        ciphertext: LocalCipherText,
        aad: A,
    ) -> Result<Vec<u8>, Unspecified>
    where
        A: IntoAad<'a>;
}
