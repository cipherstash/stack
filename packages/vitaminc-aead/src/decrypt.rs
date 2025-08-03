use crate::{aad::IntoAad, cipher::Unspecified, Cipher, LocalCipherText};
use zeroize::Zeroize;

pub trait Decrypt: Sized {
    type Encrypted;

    // FIXME: Reverse the order of the key and encrypted parameters
    fn decrypt<C>(encrypted: Self::Encrypted, key: &C::Key, cipher: &C) -> Result<Self, Unspecified>
    where
        C: Cipher,
    {
        Self::decrypt_with_aad(encrypted, key, cipher, ())
    }

    fn decrypt_with_aad<'a, C, A>(
        encrypted: Self::Encrypted,
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>;
}

impl Decrypt for Vec<u8> {
    type Encrypted = LocalCipherText;

    fn decrypt_with_aad<'a, C, A>(
        encrypted: Self::Encrypted,
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.decrypt_vec(encrypted, key, aad)
    }
}

impl<const N: usize> Decrypt for [u8; N] {
    type Encrypted = LocalCipherText;

    fn decrypt_with_aad<'a, C, A>(
        encrypted: Self::Encrypted,
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        let mut result_vec = cipher.decrypt_vec(encrypted, key, aad)?;
        if result_vec.len() != N {
            // Discard and zeroize the result vector if the length doesn't match
            result_vec.zeroize();
            return Err(Unspecified);
        }
        result_vec.try_into().map_err(|_| Unspecified)
    }
}

impl Decrypt for String {
    type Encrypted = LocalCipherText;

    fn decrypt_with_aad<'a, C, A>(
        encrypted: Self::Encrypted,
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        let bytes = cipher.decrypt_vec(encrypted, key, aad)?;
        String::from_utf8(bytes).map_err(|_| Unspecified)
    }
}
