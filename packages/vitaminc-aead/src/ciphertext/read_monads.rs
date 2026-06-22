use crate::{Nonce, Unspecified};
use bytes::{Buf, Bytes};
use std::array;
use vitaminc_protected::{Controlled, Protected};

pub struct CipherTextReader(Bytes);

impl CipherTextReader {
    pub(super) fn new(bytes: Bytes) -> Self {
        Self(bytes)
    }

    /// Split off the leading `N`-byte nonce, returning it plus a reader over the
    /// remaining ciphertext-and-tag bytes.
    ///
    /// Returns [`Unspecified`] if fewer than `N` bytes are available, rather
    /// than panicking — the input may be attacker-controlled (e.g. a
    /// deserialized [`LocalCipherText`](crate::LocalCipherText) built from
    /// untrusted bytes), so a short buffer must be a recoverable error.
    pub fn read_nonce<const N: usize>(
        self,
    ) -> Result<(Nonce<N>, CiphertextAndTagReader), Unspecified> {
        if self.0.len() < N {
            return Err(Unspecified);
        }
        let mut buf = self.0.take(N);
        let nonce_inner: [u8; N] = array::from_fn(|_| buf.get_u8());

        Ok((
            Nonce::new(nonce_inner),
            CiphertextAndTagReader::new(buf.into_inner()),
        ))
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

#[cfg(test)]
mod tests {
    use super::CipherTextReader;
    use bytes::Bytes;
    use vitaminc_protected::Controlled;

    // `read_nonce` works on attacker-controlled bytes, so two things must hold:
    // the `len() < N` guard at the exact boundary (tested at `N-1`/`N`/`N+1`),
    // and the split — the first N bytes become the nonce and the rest carry
    // through untouched. Both are asserted so a wrong-but-in-bounds read or a
    // mis-split can't survive. See #209.
    const N: usize = 4;

    #[test]
    fn read_nonce_fewer_than_n_bytes_errors() {
        let reader = CipherTextReader::new(Bytes::from_static(&[1, 2, 3]));
        assert!(reader.read_nonce::<N>().is_err());
    }

    #[test]
    fn read_nonce_exactly_n_bytes_succeeds() {
        // Exactly N bytes: the nonce is all of them and nothing is left over.
        // Also kills `<` -> `<=` and `<` -> `==`, which would reject this case.
        let reader = CipherTextReader::new(Bytes::from_static(&[1, 2, 3, 4]));
        let (nonce, rest) = reader.read_nonce::<N>().expect("N bytes available");
        assert_eq!(nonce.into_inner(), [1, 2, 3, 4]);
        assert!(rest.0.risky_ref().is_empty());
    }

    #[test]
    fn read_nonce_more_than_n_bytes_succeeds() {
        // The nonce is the first N bytes; the remainder carries through intact.
        let reader = CipherTextReader::new(Bytes::from_static(&[1, 2, 3, 4, 5, 6]));
        let (nonce, rest) = reader
            .read_nonce::<N>()
            .expect("more than N bytes available");
        assert_eq!(nonce.into_inner(), [1, 2, 3, 4]);
        assert_eq!(rest.0.risky_ref(), &vec![5, 6]);
    }
}
