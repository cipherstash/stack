use crate::{Encrypt, IntoAad};

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

/*pub trait Cipher {
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
}*/

pub trait Cipher: Sized {
    type Ok;
    type Error;
    type SeqCipher: SeqCipher<Ok = Self::Ok, Error = Self::Error>;
    type MapCipher: MapCipher<Ok = Self::Ok, Error = Self::Error>;

    fn encrypt_bytes_vec<'a, A>(self, data: Vec<u8>, aad: A) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>;

    fn encrypt_bytes_array<'a, const N: usize, A>(
        self,
        data: [u8; N],
        aad: A,
    ) -> Result<Self::Ok, Self::Error>
    where
        A: IntoAad<'a>,
    {
        // TODO: We should probably zeroize the data here (what does to_vec do internally?)
        self.encrypt_bytes_vec(data.to_vec(), aad)
    }

    fn encrypt_seq(self, size_hint: Option<usize>) -> Self::SeqCipher;

    fn encrypt_map(self) -> Self::MapCipher;

    // TODO: Implement encrypt_some, encrypt_none, and passthrough
    // fn encrypt_some<T>(self, value: T) -> Result<Self::Ok, Self::Error>
    // where
    //     T: Encrypt,
    // {
    //     value.encrypt(self)
    // }
    //
    // fn encrypt_none(self) -> Result<Self::Ok, Self::Error>;
    //
    // fn passthrough<T: 'static>(self, data: T) -> Result<Self::Ok, Self::Error>;
}

pub trait SeqCipher: Sized {
    type Ok;
    type Error;

    fn encrypt_next<'a, T, A>(self, data: T, aad: A) -> Result<Self, Self::Error>
    where
        T: Encrypt,
        A: IntoAad<'a>;

    fn end(self) -> Result<Self::Ok, Self::Error>;
}

pub trait MapCipher: Sized {
    type Ok;
    type Error;

    fn encrypt_key(self, key: &'static str) -> Result<Self, Self::Error>;
    fn encrypt_value<'a, T, A>(self, value: T, aad: A) -> Result<Self, Self::Error>
    where
        T: Encrypt,
        A: IntoAad<'a>;

    fn encrypt_entry<'a, T, A>(
        self,
        key: &'static str,
        value: T,
        aad: A,
    ) -> Result<Self, Self::Error>
    where
        T: Encrypt,
        A: IntoAad<'a>,
        Self: Sized,
    {
        self.encrypt_key(key)
            .and_then(|mc| mc.encrypt_value(value, aad))
    }

    /*fn encrypt_passthrough_entry<T>(self, key: &'static str, value: T) -> Self
    where
        T: erased_serde::Serialize + Send + Sync + 'static,
        Self: Sized,
    {
        self.encrypt_key(key).passthrough(value)
    }*/

    fn end(self) -> Result<Self::Ok, Self::Error>;
}
