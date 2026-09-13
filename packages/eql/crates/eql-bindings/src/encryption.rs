//! Opt-in Stack Encrypt support for [`TextEq`] and [`TextEqQuery`].
//!
//! The target declares its operations; Stack Encrypt invokes Vitamin C's
//! plaintext implementations. These adapters only encode encrypted outputs.
//! Equality uses Vitamin C's exact string semantics: no normalization or case
//! folding. The stored identifier supplies context for ciphertext and terms.
//!
//! This is a new producer profile, independent of existing cipherstash-client
//! ciphertext and terms. The EQL envelope and SQL domains remain unchanged.
//!
//! [`TextEq`]: crate::v3::text::TextEq
//! [`TextEqQuery`]: crate::v3::text::TextEqQuery
//!
//! Query terms cannot recover plaintext:
//! ```compile_fail
//! use eql_bindings::v3::text::TextEqQuery;
//! fn require<T: stack_encrypt::DecryptInto<String>>() {}
//! require::<TextEqQuery>();
//! ```
//! An encrypted EQL record is not a plaintext value:
//! ```compile_fail
//! use eql_bindings::v3::text::TextEq;
//! fn require<T: stack_encrypt::Encrypt>() {}
//! require::<TextEq>();
//! ```
//! The text domain accepts text, and requires a concrete column identifier:
//! ```compile_fail
//! use eql_bindings::v3::text::TextEq;
//! fn require<T: stack_encrypt::EncryptFrom<u32>>() {}
//! require::<TextEq>();
//! ```
//! ```compile_fail
//! use eql_bindings::v3::text::TextEq;
//! fn require<T: stack_encrypt::EncryptFrom<String, Context = ()>>() {}
//! require::<TextEq>();
//! ```

use base64::{engine::general_purpose::STANDARD, Engine as _};
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::transcode::{Reader, Transcode, Visitor};
use stack_encrypt::target::{self, AeadContext, CallerContext};
use stack_encrypt::{
    Aad, AadPiece, CipherText, Decrypt, DecryptField, DecryptInto, Decryptable, Decryption,
    Encrypt, EncryptFrom, Encryption, Error, IntoAad, IntoPrfContext, MaybeEmpty, NonEmpty,
    PrfContext, SealedValue, StackCipherText,
};
use vitaminc_prf::PrfValue;

use crate::{
    v3::terms::{Ciphertext, Hmac256},
    Identifier,
};

// An explicit producer/version marker prevents a legacy EQL ciphertext from
// being interpreted as a native Stack Encrypt leaf. The body is base64 of the
// cipher's own SealedValue encoding, never a serialization of the plaintext.
const CIPHERTEXT_PREFIX: &str = "stack-encrypt:1:";

fn codec(error: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Other(Box::new(error))
}

impl Identifier {
    /// Validate the table and column used for writes and equality probes.
    pub fn for_column(
        table: impl Into<String>,
        column: impl Into<String>,
    ) -> Result<NonEmpty<Self>, stack_encrypt::EmptyError> {
        NonEmpty::new(Self {
            t: table.into(),
            c: column.into(),
        })
    }
}

impl MaybeEmpty for Identifier {
    fn is_empty(&self) -> bool {
        self.t.is_empty() || self.c.is_empty()
    }
}
impl<'a> IntoAad<'a> for Identifier {
    fn into_aad(self) -> Aad<'a> {
        (self.t, self.c).into_aad()
    }
    fn into_aad_piece(self) -> AadPiece<'a> {
        (self.t, self.c).into_aad_piece()
    }
}
impl<'a> IntoPrfContext<'a> for Identifier {
    fn into_prf_context(self) -> PrfContext<'a> {
        (self.t, self.c).into_prf_context()
    }
}

/// Builds the final EQL ciphertext string from a native sealed leaf.
#[doc(hidden)]
pub struct CiphertextVisitor;
impl Visitor for CiphertextVisitor {
    type Value = Ciphertext;
    fn sealed(self, leaf: SealedValue) -> Result<Self::Value, Error> {
        let mut encoded = String::from(CIPHERTEXT_PREFIX);
        STANDARD.encode_string(leaf.to_bytes(), &mut encoded);
        Ok(Ciphertext(encoded))
    }
}
impl Transcode for Ciphertext {
    type Visitor = CiphertextVisitor;
    fn visitor() -> Self::Visitor {
        CiphertextVisitor
    }
}
impl Reader for Ciphertext {
    fn read<V: Visitor>(self, visitor: V) -> Result<V::Value, Error> {
        let body = self
            .0
            .strip_prefix(CIPHERTEXT_PREFIX)
            .ok_or_else(|| Error::Other("unsupported EQL ciphertext producer or version".into()))?;
        let bytes = STANDARD.decode(body).map_err(codec)?;
        visitor.sealed(SealedValue::from_bytes(&bytes).map_err(codec)?)
    }
}

impl<S: Encrypt + Clone> EncryptFrom<S> for Ciphertext {
    type Context = AeadContext;
    fn encryption<'s, K: 'static>(context: Self::Context) -> Encryption<'s, S, Self, K>
    where
        S: 's,
    {
        target::ciphertext(context).transcode()
    }
}

struct NativeCiphertextVisitor;
impl Visitor for NativeCiphertextVisitor {
    type Value = StackCipherText;
    fn sealed(self, leaf: SealedValue) -> Result<Self::Value, Error> {
        Ok(CipherText::Single(leaf))
    }
}
impl<P: Decrypt<'static> + 'static> DecryptInto<P> for Ciphertext {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<P, K> {
        match self.read(NativeCiphertextVisitor) {
            Ok(native) => target::open(native, context),
            Err(error) => Decryption::failed(error),
        }
    }
}
impl Decryptable for Ciphertext {
    const DECRYPTABLE: bool = true;
}
impl<P, Ctx> DecryptField<P, Ctx> for Ciphertext
where
    Self: DecryptInto<P>,
    Ctx: Into<<Self as DecryptInto<P>>::Context>,
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
        Some(self.decryption(context.into()))
    }
}

/// Builds EQL's hex equality term from the native HMAC output.
#[doc(hidden)]
pub struct EqualityVisitor;
impl Visitor for EqualityVisitor {
    type Value = Hmac256;
    fn equality(self, term: EqualityTerm) -> Result<Self::Value, Error> {
        Ok(Hmac256(hex::encode(term.as_bytes())))
    }
}
impl Transcode for Hmac256 {
    type Visitor = EqualityVisitor;
    fn visitor() -> Self::Visitor {
        EqualityVisitor
    }
}
impl<S: PrfValue + Clone> EncryptFrom<S> for Hmac256 {
    type Context = CallerContext;
    fn encryption<'s, K: 'static>(context: Self::Context) -> Encryption<'s, S, Self, K>
    where
        S: 's,
    {
        target::equality(context).transcode()
    }
}
impl Decryptable for Hmac256 {
    const DECRYPTABLE: bool = false;
}
impl<P, Ctx> DecryptField<P, Ctx> for Hmac256 {
    fn decryption_field<K: 'static>(self, _: Ctx) -> Option<Decryption<P, K>> {
        None
    }
}
