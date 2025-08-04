use super::LocalCipherText;
use crate::Nonce;
use bytes::BytesMut;
use vitaminc_protected::{Controlled, Protected};

#[derive(Default)]
pub struct CipherTextBuilder();

impl CipherTextBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn append_nonce<const N: usize>(self, nonce: Nonce<N>) -> NonceWritten<N> {
        NonceWritten(nonce)
    }
}

pub struct NonceWritten<const N: usize>(Nonce<N>);

impl<const N: usize> NonceWritten<N> {
    pub fn append_target_plaintext(
        self,
        plaintext: impl Into<Protected<Vec<u8>>>,
    ) -> PlaintextWritten<N> {
        PlaintextWritten::new(self.0, plaintext.into())
    }
}

pub struct PlaintextWritten<const N: usize>(Nonce<N>, Protected<Vec<u8>>);

impl<const N: usize> PlaintextWritten<N> {
    fn new(nonce: Nonce<N>, plaintext: Protected<Vec<u8>>) -> Self {
        Self(nonce, plaintext)
    }

    /// Provides a closure that takes the plaintext and to which the ciphertext and tag must be written.
    pub fn accepts_ciphertext_and_tag_ok<E>(
        self,
        f: impl FnOnce(Vec<u8>) -> Result<Vec<u8>, E>,
    ) -> EncryptedWithTag<N, E> {
        EncryptedWithTag::new(self.0, self.1.map_ok(f))
    }
}

pub struct EncryptedWithTag<const N: usize, E> {
    nonce: Nonce<N>,
    bytes: Result<Protected<Vec<u8>>, E>,
}

impl<const N: usize, E> EncryptedWithTag<N, E> {
    fn new(nonce: Nonce<N>, bytes: Result<Protected<Vec<u8>>, E>) -> Self {
        Self { bytes, nonce }
    }

    pub fn build(self) -> Result<LocalCipherText, E> {
        // The value has been encrypted, so we can unwrap it
        let inner = self.bytes?.risky_unwrap();
        let mut bytes = BytesMut::with_capacity(N + inner.len());
        bytes.extend(self.nonce.into_inner());
        bytes.extend(inner);
        Ok(LocalCipherText(bytes.freeze()))
    }
}
