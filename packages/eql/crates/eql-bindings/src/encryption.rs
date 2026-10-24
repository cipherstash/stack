//! Opt-in Stack Encrypt support for [`TextEq`] and [`TextEqQuery`].
//!
//! The target declares its operations; Stack Encrypt invokes Vitamin C's
//! plaintext implementations. These adapters only encode encrypted outputs.
//! Equality compares text in Unicode 16 NFC, the normal form
//! `vitaminc-normalize` gives it, and folds no case: `café` written with a
//! precomposed `é` and with `e` and a combining accent is one value, `Café`
//! another. The stored identifier supplies context for ciphertext and terms.
//!
//! Order (the `op` term of the `Ord` and `OrdOpe` types) compares ADR-0002's
//! order key, which folds text's case and accents: `Café` and `cafe` are
//! neither `<` nor `>` each other, while `=` on a `TextOrd` column, which
//! reads the equality term, still tells them apart.
//!
//! This is a new producer profile, independent of existing cipherstash-client
//! ciphertext and terms, so it writes the `eql_v4` domains ([`crate::v4`]),
//! never `eql_v3` (ADR-0002).
//!
//! [`TextEq`]: crate::v4::text::TextEq
//! [`TextEqQuery`]: crate::v4::text::TextEqQuery
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
#![cfg_attr(
    feature = "targets",
    doc = "A binding that holds no Rust type to name reaches the same plans by the type's *name* through [`targets`] (`targets` feature): the catalog-generated table of EQL types a data plan may name as a field target, and `encrypt` / `decrypt` / `query` dispatching on that name."
)]
#![cfg_attr(
    not(feature = "targets"),
    doc = "A binding that holds no Rust type to name reaches the same plans by the type's *name* through `targets`, with the `targets` feature: the catalog-generated table of EQL types a data plan may name as a field target, and `encrypt` / `decrypt` / `query` dispatching on that name."
)]
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
//! use eql_bindings::v4::text::TextEqQuery;
//! fn require<T: stack_encrypt::DecryptInto<String>>() {}
//! require::<TextEqQuery>();
//! ```
//! An encrypted EQL record is not a plaintext value:
//! ```compile_fail
//! use eql_bindings::v4::text::TextEq;
//! fn require<T: stack_encrypt::Encrypt>() {}
//! require::<TextEq>();
//! ```
//! The text domain accepts text, and requires a concrete column identifier:
//! ```compile_fail
//! use eql_bindings::v4::text::TextEq;
//! fn require<T: stack_encrypt::EncryptFrom<u32>>() {}
//! require::<TextEq>();
//! ```
//! ```compile_fail
//! use eql_bindings::v4::text::TextEq;
//! fn require<T: stack_encrypt::EncryptFrom<String, Context = ()>>() {}
//! require::<TextEq>();
//! ```

pub mod query;

// The by-name dispatch over the EQL v4 types (`targets` feature). A plain
// comment: a doc comment here would resolve the module's own links from
// this scope.
#[cfg(feature = "targets")]
pub mod targets;

use base64::{engine::general_purpose::STANDARD, Engine as _};
#[allow(deprecated)]
use stack_encrypt::sem::MatchTerm;
use stack_encrypt::sem::{EqualityTerm, MatchConfig, MatchOptions, TermError, Tokenizer};
use stack_encrypt::target::transcode::{Reader, Transcode, Visitor};
use stack_encrypt::target::{self, AeadContext, CallerContext, IndexSpec};
use stack_encrypt::{
    CipherText, ContextPiece, Decrypt, DecryptField, DecryptInto, Decryptable, Decryption,
    Describe, Description, Encrypt, EncryptFrom, Encryption, Error, IntoContext, MaybeEmpty,
    NonEmpty, SealedValue, StackCipherText,
};

use crate::{
    v3::terms::{BloomFilter, Ciphertext, Hmac256},
    v4::terms::SearchBloomFilter,
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

    /// The column a two-segment label names, table then column, or `None`
    /// for a label of any other length. One reading of a label for the
    /// by-name dispatch (`targets::Identifier::from_label`) and the typed
    /// query chain ([`query`]).
    pub(crate) fn column_of(label: &stack_encrypt::Label) -> Option<NonEmpty<Self>> {
        let mut segments = label.segments();
        let (Some(table), Some(column), None) = (segments.next(), segments.next(), segments.next())
        else {
            return None;
        };
        // A label segment is plain, so never empty.
        Self::for_column(table, column).ok()
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
    fn describe(&self) -> Description {
        Description::text(self.t.as_str()).then_text(self.c.as_str())
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
impl<P: Decrypt + Send + 'static> DecryptInto<P> for Ciphertext {
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
        Ok(hmac256(&term))
    }
}

/// EQL's `hm` for an equality term: the HMAC, hex encoded. One encoding for
/// stored values and query twins alike.
fn hmac256(term: &EqualityTerm) -> Hmac256 {
    Hmac256(hex::encode(term.as_bytes()))
}
impl Transcode for Hmac256 {
    type Visitor = EqualityVisitor;
    fn visitor() -> Self::Visitor {
        EqualityVisitor
    }
}
impl<S: Encrypt + Clone> EncryptFrom<S> for Hmac256 {
    type Context = CallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        target::equality().transcode()
    }
    /// The equality index: a plan for a type holding an `hm` answers
    /// `op::Eq` through it.
    fn indexes() -> Vec<IndexSpec> {
        vec![IndexSpec::Equality]
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

/// The match configuration of EQL v4's `TextMatch`: 3-grams of the
/// lower-cased text, `k = 6` positions per token in a 2048-bit filter.
///
/// Pinned here rather than taken from Stack Encrypt's default, because it is
/// part of the stored format: a stored filter and a query filter agree only
/// when both were built under the same values, and nothing in the payload
/// records them. Changing any of them is a new domain or payload version,
/// never an edit in place. Every position is below 2048, so it fits a
/// `smallint`.
///
/// A filter is a set of bits, so `@@` can return rows that do not contain the
/// query (false positives) and never misses one that does. 2048 bits keeps
/// that rate low for text of a few hundred characters; re-check matches
/// after decrypting where it matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EqlMatch;
impl MatchConfig for EqlMatch {
    fn options() -> MatchOptions {
        MatchOptions {
            tokenizer: Tokenizer::Ngram { length: 3 },
            downcase: true,
            k: 6,
            m: 2048,
        }
    }
}

/// Builds EQL's bloom filter, the set bit positions as `smallint`s, from the
/// native match terms built under [`EqlMatch`]. Stored values and queries
/// take it from the same type, so they always agree; matching
/// cipherstash-client's parameters is not a goal, because cipherstash-client
/// never writes an `eql_v4` column.
///
/// Text that cuts no token (empty, separator-only, or shorter than a 3-gram)
/// is refused with [`TermError::EmptyTermText`], stored or queried. Stack
/// Encrypt stores such a value as the empty filter, but this type is the
/// filter of every match query, and a query's filter must never be empty;
/// it is also `TextMatch`'s stored filter, and a `TextMatch` value with an
/// empty filter is a row no operator can find. A search domain's stored
/// filter, which `=` and `<` find through its other terms, is
/// [`SearchBloomFilter`] and takes the empty filter ([`SearchMatchVisitor`]).
#[doc(hidden)]
pub struct MatchVisitor;
impl Visitor for MatchVisitor {
    type Value = BloomFilter;
    // `MatchTerm` is the type's name in the crates.io stack-encrypt this
    // crate publishes against, and a deprecated alias of `MatchTerms` in the
    // tree: the one spelling that compiles against both.
    #[allow(deprecated)]
    fn matching<O: MatchConfig>(self, terms: MatchTerm<O>) -> Result<Self::Value, Error> {
        if terms.positions().is_empty() {
            return Err(Error::Term(TermError::EmptyTermText));
        }
        bloom_filter(terms.positions())
    }
}

/// EQL's `bf` for a filter's set positions, each as a `smallint`. One
/// encoding for stored values and query twins alike.
fn bloom_filter(positions: &[u16]) -> Result<BloomFilter, Error> {
    positions
        .iter()
        .map(|&position| {
            i16::try_from(position).map_err(|_| {
                Error::Other(
                    "a match position does not fit a smallint; EQL's bloom filter stores \
                     filters of at most 32768 bits"
                        .into(),
                )
            })
        })
        .collect::<Result<_, _>>()
        .map(BloomFilter)
}
impl Transcode for BloomFilter {
    type Visitor = MatchVisitor;
    fn visitor() -> Self::Visitor {
        MatchVisitor
    }
}
impl<S: AsRef<str>> EncryptFrom<S> for BloomFilter {
    type Context = CallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        // The type names the configuration and lets inference fill the rest:
        // `matching` takes three type parameters in the crates.io
        // stack-encrypt this crate publishes against and four in the tree,
        // so a turbofish compiles against only one of them.
        #[allow(deprecated)]
        let terms: Encryption<'s, S, MatchTerm<EqlMatch>, K, CallerContext> = target::matching();
        terms.transcode()
    }
    /// The match index under [`EqlMatch`]: a plan for a type holding a
    /// `bf` answers `op::Matches` through it.
    fn indexes() -> Vec<IndexSpec> {
        vec![IndexSpec::Match(EqlMatch::options())]
    }
}
impl Decryptable for BloomFilter {
    const DECRYPTABLE: bool = false;
}
impl<P, Ctx> DecryptField<P, Ctx> for BloomFilter {
    fn decryption_field<K: 'static>(self, _: Ctx) -> Option<Decryption<P, K>> {
        None
    }
}

/// Builds a stored search value's filter: [`MatchVisitor`]'s filter, except
/// that text which cuts no token stores the empty filter instead of being
/// refused (see [`SearchBloomFilter`]).
#[doc(hidden)]
pub struct SearchMatchVisitor;
impl Visitor for SearchMatchVisitor {
    type Value = SearchBloomFilter;
    // As in `MatchVisitor`: the one spelling of the terms' type that compiles
    // against both the crates.io stack-encrypt and the tree.
    #[allow(deprecated)]
    fn matching<O: MatchConfig>(self, terms: MatchTerm<O>) -> Result<Self::Value, Error> {
        if terms.positions().is_empty() {
            return Ok(SearchBloomFilter(BloomFilter(Vec::new())));
        }
        MatchVisitor.matching(terms).map(SearchBloomFilter)
    }
}
impl Transcode for SearchBloomFilter {
    type Visitor = SearchMatchVisitor;
    fn visitor() -> Self::Visitor {
        SearchMatchVisitor
    }
}
impl<S: AsRef<str>> EncryptFrom<S> for SearchBloomFilter {
    type Context = CallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        // Configuration named by the type, as for `BloomFilter`.
        #[allow(deprecated)]
        let terms: Encryption<'s, S, MatchTerm<EqlMatch>, K, CallerContext> = target::matching();
        terms.transcode()
    }
}
impl Decryptable for SearchBloomFilter {
    const DECRYPTABLE: bool = false;
}
impl<P, Ctx> DecryptField<P, Ctx> for SearchBloomFilter {
    fn decryption_field<K: 'static>(self, _: Ctx) -> Option<Decryption<P, K>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use stack_encrypt::{nonempty, Descriptor, Label};

    use super::*;

    /// The stored format: a change here strands every filter already stored
    /// under the old values, so it must arrive as a new domain or payload
    /// version, and this test makes that a deliberate edit.
    #[test]
    fn the_match_configuration_is_pinned() {
        let options = EqlMatch::options();
        assert!(matches!(options.tokenizer, Tokenizer::Ngram { length: 3 }));
        assert!(options.downcase);
        assert_eq!(options.k, 6);
        assert_eq!(options.m, 2048);
        assert!(
            options.m <= 1 << 15,
            "every position must fit EQL's smallint filter"
        );
    }

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
