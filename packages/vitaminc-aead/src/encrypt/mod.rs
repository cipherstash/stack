use crate::{cipher::Cipher, Aad, IntoAad};
pub mod impls;

/// A type that knows how to encrypt itself by driving a [`Cipher`].
///
/// Analogous to serde's `Serialize`. Implementations only need to provide
/// [`encrypt_with_aad`](Encrypt::encrypt_with_aad); [`encrypt`](Encrypt::encrypt)
/// is a convenience that supplies empty associated data.
pub trait Encrypt {
    /// Encrypt `self` with no associated data.
    fn encrypt<C>(self, cipher: C) -> Result<C::Ok, C::Error>
    where
        Self: Sized,
        C: Cipher,
    {
        self.encrypt_with_aad(cipher, Aad::empty())
    }

    /// Encrypt `self` with the supplied associated data.
    ///
    /// This is the method implementations should provide — `encrypt` is just a
    /// convenience wrapper around it.
    fn encrypt_with_aad<'a, C, A>(self, cipher: C, aad: A) -> Result<C::Ok, C::Error>
    where
        C: Cipher,
        A: IntoAad<'a>;
}
