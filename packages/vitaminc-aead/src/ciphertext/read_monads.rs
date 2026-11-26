use crate::{Nonce, Unspecified};
use bytes::{Buf, Bytes};
use std::array;
use vitaminc_protected::{Controlled, Protected};

pub struct CipherTextReader(Bytes);

impl CipherTextReader {
    pub(super) fn new(bytes: Bytes) -> Self {
        Self(bytes)
    }

    /// Split off the leading wire-version byte, returning a reader over the
    /// rest. `read_nonce` lives on the returned [`VersionedReader`], so the
    /// type system forces every decrypt path through this check.
    ///
    /// Rejects an empty buffer and any version other than
    /// [`WIRE_VERSION`](super::WIRE_VERSION): an unknown version means the
    /// layout of everything after this byte is unknown, so there is nothing
    /// safe to read. The byte is *also* bound into the
    /// leaf AAD ([`Context::for_leaf`](crate::Context::for_leaf)), so a relabeled
    /// version that happens to parse still fails tag verification.
    pub fn read_version(self) -> Result<VersionedReader, Unspecified> {
        self.read_version_in(&[super::WIRE_VERSION])
            .map(|(_, reader)| reader)
    }

    /// Like [`read_version`](Self::read_version), but accepts any version in
    /// `accepted` and returns the one it read, so the caller can bind that
    /// version into the leaf AAD. Only a reader that knows where its older
    /// leaves came from should pass a version other than
    /// [`WIRE_VERSION`](super::WIRE_VERSION); see that constant for why.
    pub fn read_version_in(self, accepted: &[u8]) -> Result<(u8, VersionedReader), Unspecified> {
        let mut buf = self.0;
        if buf.is_empty() {
            return Err(Unspecified);
        }
        let version = buf.get_u8();
        if !accepted.contains(&version) {
            return Err(Unspecified);
        }
        Ok((version, VersionedReader(buf)))
    }
}

/// A reader whose wire version has been read and accepted — the only type
/// that can read the nonce.
pub struct VersionedReader(Bytes);

impl VersionedReader {
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
    ///
    /// A backend decrypts in place and checks the tag afterwards, so when
    /// it refuses the leaf the buffer may hold the plaintext of a genuine
    /// ciphertext with a tampered tag. It is wiped on that path too.
    pub fn accepts_plaintext_ok<E>(
        self,
        f: impl FnOnce(&mut [u8]) -> Result<usize, E>,
    ) -> Plaintext<E> {
        Plaintext(self.0.map_ok(|raw| {
            let mut raw = zeroize::Zeroizing::new(raw);
            let len = f(&mut raw)?;
            raw.truncate(len);
            Ok(core::mem::take(&mut *raw))
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
    use super::{CipherTextReader, VersionedReader};
    use crate::ciphertext::WIRE_VERSION;
    use bytes::Bytes;
    use vitaminc_protected::Controlled;

    // Both readers work on attacker-controlled bytes, so the exact
    // boundaries must hold: `read_version` at empty/known/unknown,
    // `read_nonce`'s `len() < N` guard at `N-1`/`N`/`N+1`, and the split —
    // the first N bytes become the nonce and the rest carry through
    // untouched. All asserted so a wrong-but-in-bounds read or a mis-split
    // can't survive. See #209.
    const N: usize = 4;

    fn versioned(bytes: &'static [u8]) -> VersionedReader {
        let mut buf = vec![WIRE_VERSION];
        buf.extend_from_slice(bytes);
        CipherTextReader::new(Bytes::from(buf))
            .read_version()
            .expect("known version")
    }

    #[test]
    fn read_version_empty_buffer_errors() {
        let reader = CipherTextReader::new(Bytes::new());
        assert!(reader.read_version().is_err());
    }

    #[test]
    fn read_version_unknown_version_errors() {
        // Exhaustive over every byte value except the current version,
        // version 1 included: an older or newer version is read only where
        // a caller asks for it, never by accident.
        for version in 0..=u8::MAX {
            if version == WIRE_VERSION {
                continue;
            }
            let reader = CipherTextReader::new(Bytes::from(vec![version, 1, 2, 3, 4]));
            assert!(
                reader.read_version().is_err(),
                "version {version} must be rejected"
            );
        }
    }

    #[test]
    fn read_version_in_accepts_only_the_listed_versions() {
        for version in 0..=u8::MAX {
            let read = CipherTextReader::new(Bytes::from(vec![version, 9]))
                .read_version_in(&[1, WIRE_VERSION])
                .map(|(read, rest)| (read, rest.0));
            if version == 1 || version == WIRE_VERSION {
                assert_eq!(read, Ok((version, Bytes::from_static(&[9]))));
            } else {
                assert!(read.is_err(), "version {version} must be rejected");
            }
        }
        let empty = CipherTextReader::new(Bytes::new()).read_version_in(&[1, WIRE_VERSION]);
        assert!(empty.is_err());
    }

    #[test]
    fn read_version_strips_exactly_one_byte() {
        let (nonce, rest) = versioned(&[1, 2, 3, 4, 5])
            .read_nonce::<N>()
            .expect("nonce available");
        assert_eq!(nonce.into_inner(), [1, 2, 3, 4]);
        assert_eq!(rest.0.risky_ref(), &vec![5]);
    }

    #[test]
    fn read_nonce_fewer_than_n_bytes_errors() {
        assert!(versioned(&[1, 2, 3]).read_nonce::<N>().is_err());
    }

    #[test]
    fn read_nonce_exactly_n_bytes_succeeds() {
        // Exactly N bytes: the nonce is all of them and nothing is left over.
        // Also kills `<` -> `<=` and `<` -> `==`, which would reject this case.
        let (nonce, rest) = versioned(&[1, 2, 3, 4])
            .read_nonce::<N>()
            .expect("N bytes available");
        assert_eq!(nonce.into_inner(), [1, 2, 3, 4]);
        assert!(rest.0.risky_ref().is_empty());
    }

    #[test]
    fn read_nonce_more_than_n_bytes_succeeds() {
        // The nonce is the first N bytes; the remainder carries through intact.
        let (nonce, rest) = versioned(&[1, 2, 3, 4, 5, 6])
            .read_nonce::<N>()
            .expect("more than N bytes available");
        assert_eq!(nonce.into_inner(), [1, 2, 3, 4]);
        assert_eq!(rest.0.risky_ref(), &vec![5, 6]);
    }
}
