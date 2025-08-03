use crate::{
    aad::IntoAad,
    cipher::{Cipher, Unspecified},
    Decrypt, LocalCipherText,
};
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

pub trait Encrypt: Sized {
    type Encrypted;

    fn encrypt<C>(self, key: &C::Key, cipher: &C) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
    {
        self.encrypt_with_aad(key, cipher, ())
    }

    fn encrypt_with_aad<'a, C, A>(
        self,
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
        Self: 'a;

}

impl Encrypt for Vec<u8> {
    type Encrypted = LocalCipherText;

    fn encrypt_with_aad<'a, C, A>(
        self,
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_vec(self, key, aad)
    }
}

impl Encrypt for String {
    type Encrypted = LocalCipherText;

    fn encrypt_with_aad<'a, C, A>(
        self,
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_vec(self.into_bytes(), key, aad)
    }
}

impl Encrypt for &str {
    type Encrypted = LocalCipherText;

    fn encrypt_with_aad<'a, C, A>(
        self,
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
        Self: 'a,
    {
        cipher.encrypt_slice(self.as_bytes(), key, aad)
    }
}

impl<const N: usize> Encrypt for [u8; N] {
    type Encrypted = LocalCipherText;

    fn encrypt_with_aad<'a, C, A>(
        mut self,
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        let bytes = self.to_vec();
        let result = cipher.encrypt_vec(bytes, key, aad);
        // `to_vec` copies the bytes, do we must zeroize the original
        self.zeroize();
        result
    }
}

impl<T> Encrypt for Protected<T>
where
    Self: Controlled,
    <Protected<T> as Controlled>::Inner: Encrypt,
{
    type Encrypted = <<Protected<T> as Controlled>::Inner as Encrypt>::Encrypted;

    fn encrypt_with_aad<'a, C, A>(
        self,
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
        Self: 'a,
    {
        self.risky_unwrap().encrypt_with_aad(key, cipher, aad)
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
        key: &C::Key,
        cipher: &C,
        aad: A,
    ) -> Result<Self, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        let inner =
            <Protected<T> as Controlled>::Inner::decrypt_with_aad(encrypted, key, cipher, aad)?;
        Ok(Protected::init_from_inner(inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Decrypt;

    struct Foo {
        sensitive: String,
        public: String,
    }

    struct EncryptedFoo {
        sensitive: LocalCipherText,
        public: String,
    }

    impl Encrypt for Foo {
        type Encrypted = EncryptedFoo;

        fn encrypt_with_aad<'a, C, A>(
            self,
            key: &C::Key,
            cipher: &C,
            aad: A,
        ) -> Result<Self::Encrypted, Unspecified>
        where
            C: Cipher,
            A: IntoAad<'a>,
        {
            let sensitive = self.sensitive.encrypt_with_aad(key, cipher, aad)?;
            Ok(EncryptedFoo {
                sensitive,
                public: self.public,
            })
        }
    }

    impl Decrypt for Foo {
        type Encrypted = EncryptedFoo;

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
            String::decrypt_with_aad(encrypted.sensitive, key, cipher, aad).map(|sensitive| Foo {
                sensitive,
                public: encrypted.public,
            })
        }
    }
}
