//! The decrypt-side counterpart to the [`encrypt`](crate::encrypt) module.
//!
//! [`Decrypt`] is to [`Decipher`](crate::Decipher) what
//! [`Encrypt`](crate::Encrypt) is to [`Cipher`](crate::Cipher): the trait a
//! plaintext type implements to describe how it decodes itself, kept separate
//! from the traits a cipher backend implements to drive that decoding.

pub mod impls;

use crate::{Aad, Decipher, IntoAad};

/// The counterpart to `Encrypt` — a type that knows how to decrypt itself using a `Decipher`.
/// Analogous to serde's `Deserialize`.
pub trait Decrypt<'c>: Sized + Send {
    /// Decrypt `Self` from the given decipher with no associated data.
    ///
    /// Convenience wrapper around [`decrypt_with_aad`](Decrypt::decrypt_with_aad), mirroring
    /// [`Encrypt::encrypt`](crate::Encrypt::encrypt).
    fn decrypt<D: Decipher<'c>>(decipher: D) -> D::Ok<Self> {
        Self::decrypt_with_aad(decipher, Aad::empty())
    }

    /// Decrypt `Self` from the given decipher, authenticating against `aad`.
    ///
    /// This is the method implementations provide; it mirrors
    /// [`Encrypt::encrypt_with_aad`](crate::Encrypt::encrypt_with_aad). The `aad` must match
    /// the associated data bound at encrypt time or decryption fails.
    fn decrypt_with_aad<'a, D, A>(decipher: D, aad: A) -> D::Ok<Self>
    where
        D: Decipher<'c>,
        A: IntoAad<'a>;
}
