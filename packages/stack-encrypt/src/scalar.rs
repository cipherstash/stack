//! Single opaque ciphertexts over the existing sealed-leaf storage format.

use crate::target::{
    DecryptFrom, DecryptSource, Decryption, EncryptInto, EncryptTarget, Encryption,
    OptionalContext, Pending, ScalarContext,
};
use crate::{CipherText, Decrypt, Error, KeysetCipher, LeafBytesError, SealedValue};
use vitaminc_aead::plaintext::{Encrypt, Sink};
use zeroize::Zeroize;

mod sealed {
    pub trait Scalar {
        fn visit<S: vitaminc_aead::plaintext::Sink>(&self, sink: S) -> Result<S::Ok, S::Error>;
    }
}

/// An owned Rust scalar supported by the single-ciphertext API.
///
/// Supported types are `bool`, fixed-width signed integers, unsigned integers from `u16`
/// through `u128`, `f32`, `f64`, and `String`. Collections and borrowed values
/// deliberately do not implement this sealed trait. `u8` support requires
/// separating Vitamin C's byte-buffer and element representations and is
/// deferred; it must not make `Vec<u8>` an implicit single ciphertext.
pub trait Scalar: sealed::Scalar + Zeroize + Decrypt + Send + 'static {}

macro_rules! scalars {
    ($($ty:ty),* $(,)?) => {$(
        impl sealed::Scalar for $ty {
            fn visit<S: Sink>(&self, sink: S) -> Result<S::Ok, S::Error> {
                Encrypt::visit(self, sink)
            }
        }
        impl Scalar for $ty {}
    )*};
}
scalars!(bool, i8, i16, i32, i64, i128, u16, u32, u64, u128, f32, f64, String);

pub(crate) struct ScalarRef<'a, S>(pub &'a S);
impl<S: Scalar> Encrypt for ScalarRef<'_, S> {
    const DEPTH: Option<usize> = Some(0);
    fn visit<V: Sink>(self, sink: V) -> Result<V::Ok, V::Error> {
        sealed::Scalar::visit(self.0, sink)
    }
}

/// One opaque ciphertext, with no exposed structural node variants.
///
/// Its bytes are exactly the existing [`SealedValue`] v1 envelope. Parsing
/// validates the envelope shape, not authenticity; only decryption authenticates
/// it. No new storage framing or cryptographic context is introduced.
#[derive(Clone)]
pub struct Ciphertext(pub(crate) SealedValue);
impl std::fmt::Debug for Ciphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ciphertext").finish_non_exhaustive()
    }
}
impl Ciphertext {
    /// Encode the existing canonical sealed-leaf storage format.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
    /// Parse that format. Authentication occurs only when decrypting.
    ///
    /// # Errors
    /// Rejects truncated envelopes, unsupported versions and invalid lengths.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LeafBytesError> {
        SealedValue::from_bytes(bytes).map(Self)
    }
    /// The provider tag carried by the envelope, without decrypting.
    /// This is untrusted metadata until a successful opening.
    pub fn tag(&self) -> &[u8] {
        self.0.tag()
    }
    pub(crate) fn from_node(node: crate::StackCipherText) -> Result<Self, Error> {
        match node {
            CipherText::Single(leaf) => Ok(Self(leaf)),
            _ => Err(Error::Aead),
        }
    }
}
impl<S: Scalar> EncryptTarget<S> for Ciphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
    where
        S: 's,
    {
        crate::target::scalar_ciphertext()
    }
}
impl<P: Scalar> DecryptSource<P> for Ciphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<P, K> {
        let context = context.piece();
        Decryption::from_open(move |cipher| {
            crate::target::core::open_native(CipherText::Single(self.0), cipher, context)
        })
    }
}
impl<K: 'static> KeysetCipher<'_, K> {
    /// Consume and encrypt a scalar as one opaque ciphertext with empty context.
    /// The owned source is wiped before this returns the batched pending request.
    ///
    /// # Errors
    /// Awaiting reports encoding, provider or encryption failures.
    pub fn encrypt<S: Scalar>(&self, value: S) -> Pending<'_, Ciphertext, K> {
        value.encrypt_into(self)
    }
    /// Consume and encrypt a scalar, authenticating the supplied context.
    /// Context conversion preserves the existing canonical AAD encoding.
    ///
    /// # Errors
    /// Awaiting reports invalid descriptors, encoding, provider or encryption failures.
    pub fn encrypt_with_context<'c, S: Scalar>(
        &self,
        value: S,
        context: impl crate::IntoContext<'c>,
    ) -> Pending<'_, Ciphertext, K> {
        value.encrypt_into_with_context(self, context)
    }
    /// Open a scalar sealed with empty context, constrained to this keyset.
    /// The caller owns and is responsible for wiping the returned plaintext.
    ///
    /// # Errors
    /// Refuses foreign keysets before retrieval; also reports provider,
    /// authentication and plaintext type errors.
    pub fn decrypt<P: Scalar>(&self, ciphertext: Ciphertext) -> Pending<'_, P, K> {
        P::decrypt_from(ciphertext, self)
    }
    /// Open a scalar under the same context used when encrypting it.
    ///
    /// # Errors
    /// Refuses foreign keysets before retrieval; wrong context or altered
    /// ciphertext fails authentication. Provider and type errors propagate.
    pub fn decrypt_with_context<'c, P: Scalar>(
        &self,
        ciphertext: Ciphertext,
        context: impl crate::IntoContext<'c>,
    ) -> Pending<'_, P, K> {
        P::decrypt_from_with_context(ciphertext, self, ScalarContext::from(context))
    }
}
