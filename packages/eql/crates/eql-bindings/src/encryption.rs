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
//! # Example
//!
//! Enable the `stack-encrypt` feature on `eql-bindings`. Both targets accept
//! a [`String`] as plaintext and a [`NonEmpty<Identifier>`] as context.
//! [`Identifier::for_column`] validates the table and column; the returned
//! identifier is passed directly to `encrypt_as` and stored in the output's `i`.
//! The output type selects the encryption operations: [`TextEq`] includes
//! ciphertext and an equality term, while [`TextEqQuery`] contains only the term.
//!
//! An [`Identifier`] is Stack Encrypt's [`Describe`]: its ZeroKMS descriptor is
//! the table and the column as two parts, rendered `users/email`, the same
//! context and descriptor as the two-segment [`stack_encrypt::Label`]. A
//! direct consumer of Stack Encrypt names its data with a `Label`; an EQL
//! consumer names it with an `Identifier`, and the two interoperate.
//!
//! This complete example runs locally without credentials. It uses real
//! encryption with `stack_kms::FakeDataKeySource`, whose keys exist only for
//! this process. Add `stack-encrypt`, `stack-kms` (with `default-features = false`
//! and `features = ["test-support"]`), and `tokio` (with `features = ["rt", "macros"]`)
//! to your example's dependencies.
//!
//! The code below is executed by `cargo test -p eql-encryption-tests --test
//! text_eq_example`. It is excluded from this crate's doctests so its optional
//! test key source and runtime remain in the separate encryption test crate.
#![doc = concat!("```rust,ignore\n", include_str!("encryption/example.rs"), "\n```")]
//!
//! For ZeroKMS, enable Stack Encrypt's `http` feature and replace the fake-key
//! builder with `StackCipher::new().await?`, using your configured CipherStash
//! credentials. The encryption and decryption calls are identical.
//!
//! Use the same table and column identifier for writes and queries. Passing
//! `column.into()` on decryption also checks that the stored identifier matches
//! the expected destination before retrieving keys. `Default::default()` instead
//! uses the stored identifier alone.
//!
//! # Unsupported conversions
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
    CipherText, ContextPiece, Decrypt, DecryptField, DecryptInto, Decryptable, Decryption,
    Describe, DescriptorBuilder, Encrypt, EncryptFrom, Encryption, Error, IntoContext, MaybeEmpty,
    NonEmpty, SealedValue, StackCipherText,
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
/// The identifier's descriptor is the table and the column, two parts: it
/// renders `users/email` in the ZeroKMS log, and a table or column that
/// contains `/` is escaped rather than read as two. The same two parts are the
/// context the ciphertext is sealed under and the equality term is derived
/// under ([`IntoContext`] below returns [`Describe::to_context`]), so the
/// descriptor ZeroKMS binds and the AAD never disagree. It is the same
/// context as the two-segment [`stack_encrypt::Label`] and as the pair a
/// `#[stash(struct = .., context = "<table>")]` derive binds.
impl Describe for Identifier {
    fn describe(&self, out: &mut DescriptorBuilder) {
        let _ = out.text(self.t.as_str()).text(self.c.as_str());
    }
}

// One context view serves both derivations: vitaminc's `IntoAad` and
// `IntoPrfContext` are blankets over `IntoContext`, so the ciphertext AAD, the
// ZeroKMS descriptor and the equality term's PRF context all see the same
// (table, column) pair — the one `Describe` pushes.
impl<'a> IntoContext<'a> for Identifier {
    fn into_context(self) -> ContextPiece<'a> {
        self.to_context()
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
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        target::ciphertext().transcode()
    }
}

/// Reads a stored `c` back as the native sealed leaf it encodes. Public for
/// the encryption test crate, which opens the leaf with Stack Encrypt directly
/// to prove the two decryption paths agree; not part of the supported API.
#[doc(hidden)]
pub struct NativeCiphertextVisitor;
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
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        target::equality().transcode()
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

#[cfg(test)]
mod tests {
    use stack_encrypt::{nonempty, Descriptor, Label};

    use super::*;

    fn id(t: &str, c: &str) -> Identifier {
        Identifier {
            t: t.into(),
            c: c.into(),
        }
    }

    #[test]
    fn an_identifier_describes_as_table_slash_column() {
        let email = id("users", "email");
        assert_eq!(email.descriptor().as_str(), "users/email");
        assert_eq!(Descriptor::of(email.clone()).as_str(), "users/email");
        // Through `for_column`, the context the targets are sealed under.
        let column = Identifier::for_column("users", "email").unwrap();
        assert_eq!(Descriptor::of(column).as_str(), "users/email");
    }

    #[test]
    fn an_identifier_is_the_two_segment_label_and_the_derive_pair() {
        let email = id("users", "email");
        let label = Label::new(["users", "email"]).unwrap();
        assert_eq!(email.to_context(), label.to_context());
        assert_eq!(email.clone().into_context(), label.into_context());
        assert_eq!(
            email.into_context(),
            nonempty!("users").with("email").into_context()
        );
    }

    #[test]
    fn a_separator_in_a_name_is_escaped_never_a_third_part() {
        let odd = id("users/email", "x");
        assert_eq!(odd.descriptor().as_str(), "b64:dXNlcnMvZW1haWw=/x");
        assert_ne!(odd.descriptor(), id("users", "email").descriptor());
        assert_ne!(
            odd.descriptor(),
            Descriptor::of(nonempty!("users").with("email").with("x"))
        );
    }
}
