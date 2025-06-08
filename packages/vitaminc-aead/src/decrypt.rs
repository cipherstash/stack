use crate::{aad::IntoAad, Cipher, LocalCipherText};

pub trait Decrypt: Sized {
    type Encrypted;

    // FIXME: Reverse the order of the key and encrypted parameters
    fn decrypt<C>(encrypted: Self::Encrypted, key: &C::Key, cipher: &C) -> Result<Self, C::Error>
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
    ) -> Result<Self, C::Error>
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
    ) -> Result<Self, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.decrypt_bytes(encrypted, key, aad)
    }
}

impl<const N: usize> Decrypt for [u8; N] {
    type Encrypted = LocalCipherText;

    fn decrypt_with_aad<'a, C, A>(
        encrypted: Self::Encrypted,
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.decrypt_array(encrypted, key, aad)
    }
}

impl Decrypt for String {
    type Encrypted = LocalCipherText;

    fn decrypt_with_aad<'a, C, A>(
        encrypted: Self::Encrypted,
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        let bytes = cipher.decrypt_bytes(encrypted, key, aad)?;
        // TODO: Don't unwrap here - we might need a custom error type (like Serde)
        Ok(String::from_utf8(bytes).unwrap())
    }
}
