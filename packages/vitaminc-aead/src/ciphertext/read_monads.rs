use crate::Nonce;
use bytes::{Buf, Bytes};
use std::array;
use vitaminc_protected::{Controlled, Protected};

pub struct CipherTextReader(Bytes);

impl CipherTextReader {
    pub(super) fn new(bytes: Bytes) -> Self {
        Self(bytes)
    }

    pub fn read_nonce<const N: usize>(self) -> (Nonce<N>, CiphertextAndTagReader) {
        let mut buf = self.0.take(N);
        let nonce_inner: [u8; N] = array::from_fn(|_| buf.get_u8());

        (
            Nonce::new(nonce_inner),
            CiphertextAndTagReader::new(buf.into_inner()),
        )
    }
}

pub struct CiphertextAndTagReader(Protected<Vec<u8>>);

impl CiphertextAndTagReader {
    fn new(bytes: Bytes) -> Self {
        Self(Protected::new(bytes.into()))
    }

    /// Provides a closure that takes the ciphertext and tag and to which the plaintext must be written.
    /// The closure must return a `Result<Vec<u8>, E>`.
    /// The result is kept inside a `Protected` to avoid leaking the plaintext.
    pub fn accepts_plaintext_ok<E>(
        self,
        f: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Plaintext<E> {
        Plaintext(self.0.map_ok(|mut raw| {
            let len = f(&mut raw)?;
            raw.truncate(len);
            Ok(raw)
        }))
    }
}

pub struct Plaintext<E>(Result<Protected<Vec<u8>>, E>);

impl<E> Plaintext<E> {
    /// Returns the plaintext if the decryption was successful.
    pub fn read(self) -> Result<Protected<Vec<u8>>, E> {
        self.0
    }
}
