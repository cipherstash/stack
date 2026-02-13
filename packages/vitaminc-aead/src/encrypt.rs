use crate::{
    aad::IntoAad,
    cipher::{Cipher, Unspecified},
    LocalCipherText,
};
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

pub trait Encrypt<'a>: Sized + 'a {
    type Encrypted;

    fn encrypt<C>(self, cipher: &C) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
    {
        self.encrypt_with_aad(cipher, ())
    }

    fn encrypt_with_aad<C, A>(self, cipher: &C, aad: A) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>;
}

impl<'a> Encrypt<'a> for Vec<u8> {
    type Encrypted = LocalCipherText;

    fn encrypt_with_aad<C, A>(self, cipher: &C, aad: A) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_vec(self, aad)
    }
}

impl<'a> Encrypt<'a> for String {
    type Encrypted = LocalCipherText;

    fn encrypt_with_aad<C, A>(self, cipher: &C, aad: A) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_vec(self.into_bytes(), aad)
    }
}

impl<'a> Encrypt<'a> for &'a str {
    type Encrypted = LocalCipherText;

    fn encrypt_with_aad<C, A>(self, cipher: &C, aad: A) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        cipher.encrypt_slice(self.as_bytes(), aad)
    }
}

impl<'a, const N: usize> Encrypt<'a> for [u8; N] {
    type Encrypted = LocalCipherText;

    fn encrypt_with_aad<C, A>(
        mut self,
        cipher: &C,
        aad: A,
    ) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        let bytes = self.to_vec();
        let result = cipher.encrypt_vec(bytes, aad);
        // `to_vec` copies the bytes, do we must zeroize the original
        self.zeroize();
        result
    }
}

impl<'a, T> Encrypt<'a> for Protected<T>
where
    Self: Controlled + 'a,
    <Protected<T> as Controlled>::Inner: Encrypt<'a>,
{
    type Encrypted = <<Protected<T> as Controlled>::Inner as Encrypt<'a>>::Encrypted;

    fn encrypt_with_aad<C, A>(self, cipher: &C, aad: A) -> Result<Self::Encrypted, Unspecified>
    where
        C: Cipher,
        A: IntoAad<'a>,
    {
        self.risky_unwrap().encrypt_with_aad(cipher, aad)
    }
}

// FIXME: check with @coderdan if this should be converted to a static assertion that it simply *compiles*
#[allow(dead_code)]
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

    impl<'a> Encrypt<'a> for Foo {
        type Encrypted = EncryptedFoo;

        fn encrypt_with_aad<C, A>(
            self,
            cipher: &C,
            aad: A,
        ) -> Result<Self::Encrypted, Unspecified>
        where
            C: Cipher,
            A: IntoAad<'a>,
        {
            let sensitive = self.sensitive.encrypt_with_aad(cipher, aad)?;
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
            cipher: &C,
            aad: A,
        ) -> Result<Self, Unspecified>
        where
            C: Cipher,
            A: IntoAad<'a>,
        {
            String::decrypt_with_aad(encrypted.sensitive, cipher, aad).map(|sensitive| Foo {
                sensitive,
                public: encrypted.public,
            })
        }
    }
}
