use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;
use crate::{aad::IntoAad, cipher::Unspecified, Cipher, LocalCipherText};

pub trait Decrypt: Sized {
    type Encrypted;

    fn decrypt<C>(encrypted: Self::Encrypted, cipher: &C) -> Result<Self, Unspecified>
    where
        C: Cipher,
    {
        Self::decrypt_with_aad(encrypted, cipher, ())
    }

    fn decrypt_with_aad<'a, C, A>(
        encrypted: Self::Encrypted,
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
        cipher: &C,
        aad: A,
    ) -> Result<Self, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.decrypt_vec(encrypted, aad)
    }
}

impl<const N: usize> Decrypt for [u8; N] {
    type Encrypted = LocalCipherText;

    fn decrypt_with_aad<'a, C, A>(
        encrypted: Self::Encrypted,
        cipher: &C,
        aad: A,
    ) -> Result<Self, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        let mut result_vec = cipher.decrypt_vec(encrypted, aad)?;
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
        cipher: &C,
        aad: A,
    ) -> Result<Self, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        let bytes = cipher.decrypt_vec(encrypted, aad)?;
        String::from_utf8(bytes).map_err(|_| Unspecified)
    }
}

impl<T> Decrypt for Protected<T>
where
    Self: Controlled,
    <Protected<T> as Controlled>::Inner: Decrypt,
{
    type Encrypted = <<Protected<T> as Controlled>::Inner as Decrypt>::Encrypted;

    fn decrypt_with_aad<'a, C, A>(
        encrypted: Self::Encrypted,
        cipher: &C,
        aad: A,
    ) -> Result<Self, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        let inner =
            <Protected<T> as Controlled>::Inner::decrypt_with_aad(encrypted, cipher, aad)?;
        Ok(Protected::init_from_inner(inner))
    }
}
