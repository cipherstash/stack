//! Single opaque ciphertexts over the existing sealed-leaf storage format.

use crate::target::{
    DecryptFrom, DecryptSource, Decryption, EncryptInto, EncryptTarget, Encryption,
    OptionalContext, Pending, ScalarContext,
};
use crate::{CipherText, Decrypt, Error, KeysetCipher, LeafBytesError, SealedValue};
use vitaminc_aead::plaintext::{Encrypt, Scalar, Sink};
use vitaminc_aead::FromScalar;
use vitaminc_protected::OpaqueDebug;
use zeroize::Zeroize;

mod sealed {
    pub trait Encode {
        const DEPTH: Option<usize>;
        const FIXED: Option<vitaminc_aead::plaintext::FixedType>;
        fn visit<S: vitaminc_aead::plaintext::Sink>(&self, sink: S) -> Result<S::Ok, S::Error>;
    }
    pub trait Decode {}
}

/// A plaintext type that encrypts as one opaque [`Ciphertext`].
///
/// `OpaqueEncode` is implemented for every owned type `S` that meets two
/// conditions:
///
/// - `&S` implements Vitamin C's [`Scalar`] marker, so Vitamin C encrypts it
///   as a single value.
/// - `S` implements [`Zeroize`], so it can be wiped.
///
/// These built-in types meet both conditions:
///
/// - `bool`, `f32`, `f64`, and `String`
/// - the fixed-width signed integers
/// - the unsigned integers from `u16` to `u128`
/// - the byte strings `Vec<u8>` and `[u8; N]`
/// A type of your own
/// meets them if its borrow implements `Scalar` and the type implements
/// `Zeroize`. The trait is sealed, so you cannot implement it directly.
///
/// A sequence is not a `Scalar`, so `Vec<u8>` is the only `Vec` that encrypts
/// into one `Ciphertext`. A `Vec` of any other `OpaqueEncode` type encrypts
/// element by element into a `Vec<Ciphertext>`, through [`EncryptInto`]. The
/// crate docs on collections explain how. `u8` is not an `OpaqueEncode` type,
/// because Vitamin C encrypts a `Vec<u8>` as one byte string, not as a
/// collection of bytes.
///
/// A nullable `Option<T>` is not an `OpaqueEncode` type either. Use
/// [`KeysetCipher::encrypt_tree`] and [`KeysetCipher::decrypt_tree`] for
/// nullable values. A fixed-width nullable value keeps Vitamin C's padded
/// form for null.
pub trait OpaqueEncode: sealed::Encode + Zeroize + Send + 'static {}

/// A plaintext type that one opaque [`Ciphertext`] decrypts to.
///
/// `OpaqueDecode` is implemented for every [`FromScalar`] type that also
/// implements [`Zeroize`]. Every built-in [`OpaqueEncode`] type is one. The trait is sealed, as `OpaqueEncode` is.
pub trait OpaqueDecode: sealed::Decode + Decrypt + Zeroize + Send + 'static {}

// The bridge from an owned `S` to its borrow's walk: `OpaqueEncode`'s
// callers hold `&S`, and only this impl's where clause knows `&S` encrypts.
impl<S> sealed::Encode for S
where
    S: Zeroize + Send + 'static,
    for<'a> &'a S: Scalar,
{
    const DEPTH: Option<usize> = <&S as Encrypt>::DEPTH;
    const FIXED: Option<vitaminc_aead::plaintext::FixedType> = <&S as Encrypt>::FIXED;
    fn visit<V: Sink>(&self, sink: V) -> Result<V::Ok, V::Error> {
        Encrypt::visit(self, sink)
    }
}
impl<S> OpaqueEncode for S
where
    S: Zeroize + Send + 'static,
    for<'a> &'a S: Scalar,
{
}
impl<P: FromScalar + Zeroize + Send + 'static> sealed::Decode for P {}
impl<P: FromScalar + Zeroize + Send + 'static> OpaqueDecode for P {}

pub(crate) struct ScalarRef<'a, S>(pub &'a S);
// The owned conversion keeps the source in Protected and hands this a borrow.
// It carries the scalar's encoding metadata through `sealed::Encode`, whose
// supertrait bound is what lets a generic caller walk `&S` at all.
impl<S: OpaqueEncode> Encrypt for ScalarRef<'_, S> {
    const DEPTH: Option<usize> = <S as sealed::Encode>::DEPTH;
    const FIXED: Option<vitaminc_aead::plaintext::FixedType> = <S as sealed::Encode>::FIXED;
    fn visit<V: Sink>(self, sink: V) -> Result<V::Ok, V::Error> {
        sealed::Encode::visit(self.0, sink)
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
