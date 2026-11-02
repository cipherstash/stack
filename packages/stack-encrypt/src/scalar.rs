//! Single opaque ciphertexts over the existing sealed-leaf storage format.

use crate::target::{
    DecryptFrom, DecryptSource, Decryption, EncryptInto, EncryptTarget, Encryption,
    OptionalContext, Pending, ScalarContext,
};
use crate::{CipherText, ContextPiece, Error, KeysetCipher, LeafBytesError, SealedValue};
use vitaminc_aead::plaintext::{Encrypt, Sink};
use vitaminc_protected::OpaqueDebug;
use zeroize::{Zeroize, Zeroizing};

pub(crate) mod sealed {
    use crate::target::Pending;
    use crate::{Ciphertext, ContextPiece, KeysetCipher, SealedValue, StackCipher};

    /// How a value becomes one sealed leaf. Planning, and for a blob the
    /// encoding before it, runs synchronously inside this call, so the
    /// pending it returns holds no plaintext the caller still owns.
    pub trait Encode: Sized {
        fn seal<'a, K: 'static>(
            &self,
            cipher: &'a KeysetCipher<'_, K>,
            context: ContextPiece<'static>,
        ) -> Pending<'a, Ciphertext, K>;
    }

    /// A scalar's own Vitamin C encoding, by reference: what `ScalarRef`
    /// forwards to.
    pub(crate) trait Scalar {
        const DEPTH: Option<usize>;
        const FIXED: Option<vitaminc_aead::plaintext::FixedType>;
        fn visit<S: vitaminc_aead::plaintext::Sink>(&self, sink: S) -> Result<S::Ok, S::Error>;
    }

    /// How one sealed leaf opens to a value. The leaf authenticates inside
    /// the pending, before any decoding the type adds on top.
    pub trait Decode: Sized {
        fn open<'a, K: 'static>(
            leaf: SealedValue,
            cipher: &'a StackCipher<K>,
            context: ContextPiece<'static>,
        ) -> Pending<'a, Self, K>;
    }
}

/// A plaintext type that encrypts as one opaque [`Ciphertext`].
///
/// Implemented for `bool`, the fixed-width signed integers, the unsigned
/// integers from `u16` through `u128`, `f32`, `f64` and `String`; for
/// [`OpaqueBlob<T>`](crate::OpaqueBlob), which encodes a whole `Serialize`
/// value as one storage blob first; and for `Zeroizing` of any of those. The
/// trait is sealed: collections and borrowed values deliberately do not
/// implement it, and there is no blanket `Serialize` fallback. A composite
/// value is encrypted as one ciphertext only by naming `OpaqueBlob`.
/// `u8` waits on separating Vitamin C's byte-buffer and element
/// representations, and must not make `Vec<u8>` an implicit single
/// ciphertext.
/// Nullable `Option<T>` values are also deferred in this scalar slice. Use
/// [`KeysetCipher::encrypt_tree`] and [`KeysetCipher::decrypt_tree`] for them;
/// fixed-width nullable values retain Vitamin C's padded-null representation.
pub trait OpaqueEncode: sealed::Encode + Zeroize + Send + 'static {}

/// A plaintext type that one opaque [`Ciphertext`] decrypts to: the types
/// that implement [`OpaqueEncode`]. Sealed, like it.
///
/// A successful decrypt returns an ordinary owned value, and nothing wipes
/// it when it is dropped: `Zeroize` is the bound, not a drop guard. Ask for
/// `Zeroizing<P>` in place of `P` to have the result wiped on drop.
pub trait OpaqueDecode: sealed::Decode + Zeroize + Send + 'static {}

macro_rules! opaque {
    ($($ty:ty),* $(,)?) => {$(
        impl sealed::Scalar for $ty {
            const DEPTH: Option<usize> = <&$ty as Encrypt>::DEPTH;
            const FIXED: Option<vitaminc_aead::plaintext::FixedType> = <&$ty as Encrypt>::FIXED;
            fn visit<S: Sink>(&self, sink: S) -> Result<S::Ok, S::Error> {
                Encrypt::visit(self, sink)
            }
        }
        impl sealed::Encode for $ty {
            fn seal<'a, K: 'static>(
                &self,
                cipher: &'a KeysetCipher<'_, K>,
                context: ContextPiece<'static>,
            ) -> Pending<'a, Ciphertext, K> {
                crate::target::core::encrypt_opaque(ScalarRef(self), cipher, context)
                    .try_map(Ciphertext::from_tree)
            }
        }
        impl sealed::Decode for $ty {
            fn open<'a, K: 'static>(
                leaf: SealedValue,
                cipher: &'a crate::StackCipher<K>,
                context: ContextPiece<'static>,
            ) -> Pending<'a, Self, K> {
                crate::target::core::open_opaque(CipherText::Single(leaf), cipher, context)
            }
        }
        impl OpaqueEncode for $ty {}
        impl OpaqueDecode for $ty {}
    )*};
}
opaque!(bool, i8, i16, i32, i64, i128, u16, u32, u64, u128, f32, f64, String);

/// A `Zeroizing<S>` encrypts as its `S` does: the way to hand the scalar
/// API a value that is wiped even if it is dropped before it is consumed.
impl<S: OpaqueEncode> sealed::Encode for Zeroizing<S> {
    fn seal<'a, K: 'static>(
        &self,
        cipher: &'a KeysetCipher<'_, K>,
        context: ContextPiece<'static>,
    ) -> Pending<'a, Ciphertext, K> {
        S::seal(self, cipher, context)
    }
}
impl<S: OpaqueEncode> OpaqueEncode for Zeroizing<S> {}

/// Decrypting to `Zeroizing<P>` is the opt-in drop-guarded result: the
/// value is opened as a `P` and wrapped before it is returned, so dropping
/// it wipes it. The wrap is a move, and a move does not erase what a `Copy`
/// value left on the stack; the guard covers the value's own storage (a
/// `String`'s buffer, a struct's fields) from then on.
impl<P: OpaqueDecode> sealed::Decode for Zeroizing<P> {
    fn open<'a, K: 'static>(
        leaf: SealedValue,
        cipher: &'a crate::StackCipher<K>,
        context: ContextPiece<'static>,
    ) -> Pending<'a, Self, K> {
        P::open(leaf, cipher, context).map(Zeroizing::new)
    }
}
impl<P: OpaqueDecode> OpaqueDecode for Zeroizing<P> {}

pub(crate) struct ScalarRef<'a, S>(pub &'a S);
// Vitamin C 0.8 implements Encrypt for &Protected<T>, but not ProtectedRef<T>.
// This bridge preserves its encoding metadata while the owned conversion keeps
// the source in Protected. Replace it when the encoder accepts protected borrows.
impl<S: sealed::Scalar> Encrypt for ScalarRef<'_, S> {
    const DEPTH: Option<usize> = <S as sealed::Scalar>::DEPTH;
    const FIXED: Option<vitaminc_aead::plaintext::FixedType> = <S as sealed::Scalar>::FIXED;
    fn visit<V: Sink>(self, sink: V) -> Result<V::Ok, V::Error> {
        sealed::Scalar::visit(self.0, sink)
    }
}

/// One opaque ciphertext, with no exposed structural node variants.
///
/// Its bytes are exactly the existing [`SealedValue`] v1 envelope. Parsing
/// validates the envelope shape, not authenticity; only decryption authenticates
/// it. No new storage framing or cryptographic context is introduced.
#[derive(Clone, OpaqueDebug)]
pub struct Ciphertext(pub(crate) SealedValue);
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
/// The one sealed leaf, as the structural API holds it. The bytes are the
/// same: this is how a caller holding a `CipherText::Single` from
/// [`KeysetCipher::encrypt_tree`] opens it through the owned API.
impl From<SealedValue> for Ciphertext {
    fn from(leaf: SealedValue) -> Self {
        Self(leaf)
    }
}
impl From<Ciphertext> for SealedValue {
    fn from(ciphertext: Ciphertext) -> Self {
        ciphertext.0
    }
}
/// Human-readable formats store the canonical bytes as padded standard
/// Base64; binary formats store them as bytes.
impl serde::Serialize for Ciphertext {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes = self.to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&crate::json::base64(&bytes))
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
                let bytes = crate::json::unbase64(text).map_err(E::custom)?;
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
        Decryption::from_open(move |cipher| P::open(self.0, cipher, context))
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

#[cfg(test)]
mod tests {
    use super::ScalarRef;
    use crate::{CipherText, StackCipher};

    #[tokio::test]
    async fn scalar_ref_preserves_fixed_width_nullable_padding() {
        let cipher = StackCipher::builder()
            .kms(stack_kms::FakeDataKeySource::new())
            .init()
            .await
            .unwrap();
        let keyset = cipher.default_keyset();
        macro_rules! check {
            ($value:expr, $ty:ty) => {{
                let value: $ty = $value;
                let some = keyset
                    .encrypt_tree(Some(ScalarRef(&value)), "nullable")
                    .await
                    .unwrap();
                let none = keyset
                    .encrypt_tree(None::<ScalarRef<'_, $ty>>, "nullable")
                    .await
                    .unwrap();
                let (CipherText::Single(present), CipherText::Single(absent)) = (&some, &none)
                else {
                    panic!("nullable scalars must remain single leaves");
                };
                assert_eq!(present.to_bytes().len(), absent.to_bytes().len());
                assert_eq!(
                    keyset
                        .decrypt_tree::<Option<$ty>, _>(some, "nullable")
                        .await
                        .unwrap(),
                    Some(value)
                );
                assert_eq!(
                    keyset
                        .decrypt_tree::<Option<$ty>, _>(none, "nullable")
                        .await
                        .unwrap(),
                    None
                );
            }};
        }
        check!(42, i32);
        check!(42, u128);
        check!(42.5, f64);
    }
}
