//! Single opaque ciphertexts over the existing sealed-leaf storage format.

use crate::target::{
    DecryptFrom, DecryptSource, Decryption, EncryptInto, EncryptTarget, Encryption,
    OptionalContext, Pending, ScalarContext,
};
use crate::{CipherText, Decrypt, Error, KeysetCipher, LeafBytesError, SealedValue};
use base64ct::{Base64, Encoding};
use vitaminc_aead::plaintext::{Encrypt, Sink};
use zeroize::Zeroize;

mod sealed {
    pub trait Encode {
        fn visit<S: vitaminc_aead::plaintext::Sink>(&self, sink: S) -> Result<S::Ok, S::Error>;
    }
    pub trait Decode {}
}

/// A plaintext type that encrypts as one opaque [`Ciphertext`].
///
/// Implemented for `bool`, the fixed-width signed integers, the unsigned
/// integers from `u16` through `u128`, `f32`, `f64` and `String`. The trait is
/// sealed: collections and borrowed values deliberately do not implement it.
/// `u8` waits on separating Vitamin C's byte-buffer and element
/// representations, and must not make `Vec<u8>` an implicit single
/// ciphertext.
pub trait OpaqueEncode: sealed::Encode + Zeroize + Send + 'static {}

/// A plaintext type that one opaque [`Ciphertext`] decrypts to: the types
/// that implement [`OpaqueEncode`]. Sealed, like it.
pub trait OpaqueDecode: sealed::Decode + Decrypt + Zeroize + Send + 'static {}

macro_rules! opaque {
    ($($ty:ty),* $(,)?) => {$(
        impl sealed::Encode for $ty {
            fn visit<S: Sink>(&self, sink: S) -> Result<S::Ok, S::Error> {
                Encrypt::visit(self, sink)
            }
        }
        impl sealed::Decode for $ty {}
        impl OpaqueEncode for $ty {}
        impl OpaqueDecode for $ty {}
    )*};
}
opaque!(bool, i8, i16, i32, i64, i128, u16, u32, u64, u128, f32, f64, String);

pub(crate) struct ScalarRef<'a, S>(pub &'a S);
impl<S: OpaqueEncode> Encrypt for ScalarRef<'_, S> {
    const DEPTH: Option<usize> = Some(0);
    fn visit<V: Sink>(self, sink: V) -> Result<V::Ok, V::Error> {
        sealed::Encode::visit(self.0, sink)
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
    /// The key provider's tag carried by the envelope, read without
    /// decrypting. This is the ZeroKMS key tag, not the AEAD tag, and it is
    /// untrusted metadata until a successful opening.
    pub fn key_tag(&self) -> &[u8] {
        self.0.tag()
    }
    // Any tree other than one leaf is a shape refusal, not tampering.
    pub(crate) fn from_tree(tree: crate::StackCipherText) -> Result<Self, Error> {
        match tree {
            CipherText::Single(leaf) => Ok(Self(leaf)),
            _ => Err(Error::OpenedType {
                expected: "a single ciphertext",
            }),
        }
    }
}
/// Human-readable formats store the canonical bytes as padded standard
/// Base64; binary formats store them as bytes.
impl serde::Serialize for Ciphertext {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&Base64::encode_string(&bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}
impl<'de> serde::Deserialize<'de> for Ciphertext {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Ciphertext;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a sealed ciphertext as Base64 text or bytes")
            }
            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Ciphertext, E> {
                let bytes = Base64::decode_vec(text).map_err(E::custom)?;
                self.visit_bytes(&bytes)
            }
            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Ciphertext, E> {
                Ciphertext::from_bytes(bytes).map_err(E::custom)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Ciphertext, A::Error> {
                // The hint is a length the input declares, unchecked: a few
                // bytes can declare billions. Reserve at most a typical
                // envelope's worth and let a longer one grow as it is read.
                let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(256));
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }
                self.visit_bytes(&bytes)
            }
        }
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(V)
        } else {
            deserializer.deserialize_bytes(V)
        }
    }
}
impl<S: OpaqueEncode> EncryptTarget<S> for Ciphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
    where
        S: 's,
    {
        crate::target::scalar_ciphertext()
    }
}
impl<P: OpaqueDecode> DecryptSource<P> for Ciphertext {
    type ContextInput = OptionalContext<ScalarContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<P, K> {
        let context = context.piece();
        Decryption::from_open(move |cipher| {
            crate::target::core::open_opaque(CipherText::Single(self.0), cipher, context)
        })
    }
}
impl<K: 'static> KeysetCipher<'_, K> {
    /// Consume and encrypt a scalar as one opaque ciphertext with empty context.
    /// The owned source is wiped before this returns the batched pending request.
    ///
    /// # Errors
    /// Awaiting reports encoding, provider or encryption failures.
    pub fn encrypt<S: OpaqueEncode>(&self, value: S) -> Pending<'_, Ciphertext, K> {
        value.encrypt_into(self)
    }
    /// Consume and encrypt a scalar, authenticating the supplied context.
    /// Context conversion preserves the existing canonical AAD encoding.
    ///
    /// # Errors
    /// Awaiting reports invalid descriptors, encoding, provider or encryption failures.
    pub fn encrypt_with_context<'c, S: OpaqueEncode>(
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
    pub fn decrypt<P: OpaqueDecode>(&self, ciphertext: Ciphertext) -> Pending<'_, P, K> {
        P::decrypt_from(ciphertext, self)
    }
    /// Open a scalar under the same context used when encrypting it.
    ///
    /// # Errors
    /// Refuses foreign keysets before retrieval; wrong context or altered
    /// ciphertext fails authentication. Provider and type errors propagate.
    pub fn decrypt_with_context<'c, P: OpaqueDecode>(
        &self,
        ciphertext: Ciphertext,
        context: impl crate::IntoContext<'c>,
    ) -> Pending<'_, P, K> {
        P::decrypt_from_with_context(ciphertext, self, ScalarContext::from(context))
    }
}
