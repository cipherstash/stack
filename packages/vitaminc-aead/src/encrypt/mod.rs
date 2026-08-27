use crate::{cipher::Cipher, Aad, IntoAad};
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;
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

    /// Encrypt a `Protected<Self>` without exposing the inner value.
    ///
    /// This is the seam the blanket `impl Encrypt for Protected<T>` goes
    /// through. The default unwraps `this` and defers to
    /// [`encrypt_with_aad`](Encrypt::encrypt_with_aad), which is right for
    /// composite types: each field re-wraps itself before it reaches the
    /// cipher, so the only bare value is the container being taken apart.
    ///
    /// Byte leaves — `[u8; N]` and `Vec<u8>` — override it to hand the
    /// still-wrapped value straight to the cipher's `Protected`-taking entry
    /// point ([`Cipher::encrypt_bytes_array`] / [`Cipher::encrypt_bytes_vec`]),
    /// so a `Protected<[u8; 32]>` key, or a newtype deriving `Encrypt` around
    /// one, is never copied onto the stack as a bare array on its way in.
    /// Override it whenever `Self` has a way to reach the cipher that keeps
    /// the plaintext wrapped end-to-end.
    fn encrypt_protected<'a, C, A>(
        this: Protected<Self>,
        cipher: C,
        aad: A,
    ) -> Result<C::Ok, C::Error>
    where
        Self: Sized + Zeroize,
        C: Cipher,
        A: IntoAad<'a>,
    {
        this.risky_unwrap().encrypt_with_aad(cipher, aad)
    }
}
