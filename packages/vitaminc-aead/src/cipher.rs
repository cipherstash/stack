use crate::{aad::IntoAad, LocalCipherText};

pub trait Cipher {
    type Error;
    type Key;

    fn encrypt_bytes<'a, A>(
        &self,
        plaintext: Vec<u8>,
        key: &Self::Key,
        aad: A,
    ) -> Result<LocalCipherText, Self::Error>
    where
        A: IntoAad<'a>;

    fn encrypt_array<'a, const N: usize, A>(
        &self,
        plaintext: [u8; N],
        key: &Self::Key,
        aad: A,
    ) -> Result<LocalCipherText, Self::Error>
    where
        A: IntoAad<'a>;

    fn decrypt_bytes<'a, A>(
        &self,
        ciphertext: LocalCipherText,
        key: &Self::Key,
        aad: A,
    ) -> Result<Vec<u8>, Self::Error>
    where
        A: IntoAad<'a>;

    fn decrypt_array<'a, const N: usize, A>(
        &self,
        ciphertext: LocalCipherText,
        key: &Self::Key,
        aad: A,
    ) -> Result<[u8; N], Self::Error>
    where
        A: IntoAad<'a>;
}
