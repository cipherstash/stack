//! Single opaque ciphertexts over the existing sealed-leaf storage format.

use crate::target::{
    DecryptFrom, DecryptSource, Decryption, EncryptInto, EncryptTarget, Encryption,
    OptionalContext, Pending, ScalarContext,
};
use crate::{CipherText, ContextPiece, Decrypt, Error, KeysetCipher, LeafBytesError, SealedValue};
use vitaminc_aead::plaintext::{Encrypt, Scalar, Sink};
use vitaminc_protected::OpaqueDebug;
use zeroize::Zeroize;

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
/// - [`JsonPlaintext`](crate::json::JsonPlaintext), a JSON document, which
///   is sealed as its JSON text
///
/// A type of your own meets them if its borrow implements `Scalar` and the
/// type implements `Zeroize`.
///
/// [`OpaqueBlob<T>`](crate::OpaqueBlob) is an `OpaqueEncode` type too. It
/// encodes a whole `Serialize` value as one storage blob first.
///
/// The trait is sealed, so you cannot implement it directly. There is no
/// blanket `Serialize` fallback: a composite value is encrypted as one
/// ciphertext only by naming `OpaqueBlob`.
///
/// A sequence is not a `Scalar`, so `Vec<u8>` is the only `Vec` that encrypts
/// into one `Ciphertext`. A `Vec` of any other `OpaqueEncode` type encrypts
/// element by element into a `Vec<Ciphertext>`, through [`EncryptInto`]. The
/// [crate docs on collections](crate#collections) explain how. `u8` is not an `OpaqueEncode` type,
/// because Vitamin C encrypts a `Vec<u8>` as one byte string, not as a
/// collection of bytes.
///
/// # Nullable values
///
/// A nullable `Option<T>` is not an `OpaqueEncode` type either, so
/// `keyset.encrypt(Some(34i64))` does not compile. Encrypt a nullable value
/// with [`KeysetCipher::encrypt_tree`], which returns a [`StackCipherText`](crate::StackCipherText).
/// Decrypt it with [`KeysetCipher::decrypt_tree`].
///
/// A `None` of a fixed-width type, such as `Option<i64>`, is encrypted as a
/// null that is padded to the type's width. So its ciphertext is as long as
/// the ciphertext of a `Some`, and the length does not show whether a value
/// was present. Text has no fixed width, so the ciphertext of an
/// `Option<String>` that is `None` is shorter than one that is `Some`.
///
/// ```
/// # async fn example() -> Result<(), stack_encrypt::Error> {
/// use stack_encrypt::StackCipher;
/// // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
/// // the environment, or from the profile that `npx stash auth login` writes.
/// let cipher = StackCipher::builder()
/// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
///
/// // A value that is present.
/// let stored = keyset.encrypt_tree(Some(34i64), ("users", "age")).await?;
/// let age: Option<i64> = keyset.decrypt_tree(stored, ("users", "age")).await?;
/// assert_eq!(age, Some(34));
///
/// // A value that is absent. Its ciphertext is as long as a present one's.
/// let stored = keyset.encrypt_tree(None::<i64>, ("users", "age")).await?;
/// let age: Option<i64> = keyset.decrypt_tree(stored, ("users", "age")).await?;
/// assert_eq!(age, None);
/// # Ok(())
/// # }
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
/// ```
pub trait OpaqueEncode: sealed::Encode + Zeroize + Send + 'static {}

/// A plaintext type that one opaque [`Ciphertext`] decrypts to.
///
/// `OpaqueDecode` is implemented for every [`Decrypt`] type that also
/// implements [`Zeroize`], and for [`OpaqueBlob<T>`](crate::OpaqueBlob).
/// The `Decrypt` types include each scalar, such as `String`, and a
/// [`Protected`](vitaminc_protected::Protected) of one, such as
/// `Protected<String>`. The trait is sealed, as `OpaqueEncode` is.
///
/// A scalar decrypted into a bare type, such as `String`, is an ordinary
/// owned value, and nothing wipes it when it is dropped: `Zeroize` is the
/// bound, not a drop guard. Decrypt into a `Protected` to have it wiped on
/// drop. A decrypted `OpaqueBlob<T>` also wipes its value on drop.
///
/// A `Ciphertext` holds one scalar. A target that is not a scalar, such as
/// `Vec<String>`, compiles, but decryption refuses it with
/// [`Error::OpenedType`].
pub trait OpaqueDecode: sealed::Decode + Zeroize + Send + 'static {}

// The bridge from an owned `S` to its borrow's walk: `OpaqueEncode`'s
// callers hold `&S`, and only this impl's where clause knows `&S` encrypts.
impl<S> sealed::Scalar for S
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
impl<S> sealed::Encode for S
where
    S: Zeroize + Send + 'static,
    for<'a> &'a S: Scalar,
{
    fn seal<'a, K: 'static>(
        &self,
        cipher: &'a KeysetCipher<'_, K>,
        context: ContextPiece<'static>,
    ) -> Pending<'a, Ciphertext, K> {
        crate::target::core::encrypt_opaque(ScalarRef(self), cipher, context)
            .try_map(Ciphertext::from_tree)
    }
}
impl<S> OpaqueEncode for S
where
    S: Zeroize + Send + 'static,
    for<'a> &'a S: Scalar,
{
}
impl<P: Decrypt + Zeroize + Send + 'static> sealed::Decode for P {
    fn open<'a, K: 'static>(
        leaf: SealedValue,
        cipher: &'a crate::StackCipher<K>,
        context: ContextPiece<'static>,
    ) -> Pending<'a, Self, K> {
        crate::target::core::open_opaque(CipherText::Single(leaf), cipher, context)
    }
}
impl<P: Decrypt + Zeroize + Send + 'static> OpaqueDecode for P {}

pub(crate) struct ScalarRef<'a, S>(pub &'a S);
// The owned conversion keeps the source in Protected and hands this a borrow.
// It carries the scalar's encoding metadata through `sealed::Scalar`, whose
// blanket impl is what lets a generic caller walk `&S` at all.
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
/// A ciphertext is what a record decrypts. As a field of a derived record, it
/// is the field that can be decrypted, beside any terms.
impl crate::target::Decryptable for Ciphertext {
    const DECRYPTABLE: bool = true;
}
impl<P: OpaqueDecode, Ctx: Into<OptionalContext<ScalarContext>>> crate::target::DecryptField<P, Ctx>
    for Ciphertext
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
        Some(self.decryption(context.into()))
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
    /// To have it wiped on drop, decrypt into a `Protected`:
    /// `keyset.decrypt::<Protected<String>>(ciphertext)`.
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
