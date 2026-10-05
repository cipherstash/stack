//! Indexes as types: what a field is searchable by, composed once in the
//! engine instead of once per caller.
//!
//! An *index* is an operation that derives a search term beside a
//! ciphertext: [`Equality`], [`Match`], [`Ore`] or [`Ope`]. Each is a type
//! implementing [`Index<S>`] for exactly the plaintexts its scheme is defined
//! over, so an index that does not apply does not compile: `Match` is text
//! only, so a match index on an integer is a type error, not a runtime one.
//!
//! A field's indexes are one value: a single index, or a tuple of them
//! ([`Indexes<S>`]). `()` is deliberately not a set of indexes, so asking for
//! an indexed field with no index is a compile error rather than a quiet
//! ciphertext-only field; a field with no index is [`ciphertext`] alone.
//!
//! [`indexed`] does the composition every caller used to spell by hand —
//! `ciphertext().accepting().zip(equality()).zip(ore()).map(..)`, with its
//! nested-pair bookkeeping — and produces an [`Encrypted<Terms>`]: the
//! ciphertext, and the terms as a tuple read by destructuring.
//!
//! ```
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::kms::FakeDataKeySource;
//! use stack_encrypt::sem::{EqualityTerm, OreTerm};
//! use stack_encrypt::target::{indexed, Borrowed, CallerContext, Encrypted, Equality, Ore};
//! use stack_encrypt::{nonempty, StackCipher};
//!
//! let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! let keyset = cipher.default_keyset();
//!
//! let age = 34u32;
//! let out: Encrypted<(EqualityTerm, OreTerm<u32>)> = keyset
//!     .run(
//!         indexed::<u32, _, Borrowed, _>((Equality, Ore)),
//!         &age,
//!         CallerContext::from(nonempty!("users/age")),
//!     )
//!     .await?;
//! let (eq, ore) = out.terms;
//! # let _ = (eq, ore, out.ciphertext);
//! # Ok(())
//! # }
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
//! ```
//!
//! On the query side a field's indexes answer one at a time, with no
//! ciphertext: [`Indexes::select`] picks the index by type and
//! [`Index::operation`] is its term alone.
//!
//! For the FFI and for saved plans an index lowers to data,
//! [`IndexSpec`], through [`Index::spec`]. Parameters live on the index
//! (a [`Match`]'s tokenizer and filter size, through its [`MatchConfig`])
//! and lower with it.
use std::fmt;
use std::marker::PhantomData;

use super::context::{AeadContext, CallerContext};
use super::operations::{ciphertext, equality, matching, ope, open, ore};
use super::source::{ConsumeSource, ShareSource};
use super::{DecryptInto, Decryption, Encryption};
use crate::sem::{
    DefaultMatch, EqualityTerm, MatchConfig, MatchOptions, MatchTerms, OpeTerm, OreTerm,
};
use crate::StackCipherText;

/// An index lowered to data: what crosses the FFI boundary and what a saved
/// plan holds. The Rust side keeps the type ([`Index`]); a binding, which
/// has no type to name, speaks this. It is the one data form of an index:
/// the `dynamic` record plan, its term derivation and the Go guest all
/// spell an index as an `IndexSpec`, options included.
///
/// The [`key`](Self::key) strings are the output keys of the `dynamic` record
/// format (`"eq"`, `"match"`, `"ore"`, `"ope"`), so they are wire format;
/// that is why this enum is exhaustive: a new index is something every
/// binding has to be taught. With the `dynamic` feature, a plan spells an
/// index as its key, or, for a match index with non-default options, as an
/// object carrying them; `dynamic::record::plan` documents that shape, and
/// `IndexSpec::from_value` / `IndexSpec::to_value` read and write it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IndexSpec {
    /// Equality (exact match).
    Equality,
    /// Full-text match, with the options its terms are generated under.
    Match(MatchOptions),
    /// Order-revealing comparison.
    Ore,
    /// Order-preserving comparison.
    Ope,
}

impl IndexSpec {
    /// The output key this index's term rides under in a record.
    ///
    /// This is the kind alone. It is the whole wire form of every index but
    /// a match index with non-default options, whose options it drops; to
    /// write an index to a plan, use the serialiser (`IndexSpec::to_value`,
    /// with the `dynamic` feature), which keeps them.
    pub fn key(&self) -> &'static str {
        match self {
            IndexSpec::Equality => "eq",
            IndexSpec::Match(_) => "match",
            IndexSpec::Ore => "ore",
            IndexSpec::Ope => "ope",
        }
    }
}

impl fmt::Display for IndexSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.key())
    }
}

/// An operation that derives one search term of `S`.
///
/// Implemented for exactly the plaintexts the index's scheme is defined
/// over, which is what makes an inapplicable index a compile error: there is
/// no `Index<u32>` for [`Match`], because match is defined over text.
///
/// An index does not seal anything. [`indexed`] puts a ciphertext beside the
/// indexes of a field; [`operation`](Self::operation) on its own is the term
/// alone, which is the query side.
///
/// The trait is open: an index defined in another crate implements it by
/// composing this module's public operations, as the four here do.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not an index of `{S}`",
    label = "this index is not defined over `{S}`",
    note = "an index applies only to the plaintexts its scheme is defined over: `Match` takes text, and `Equality`, `Ore` and `Ope` take the types their schemes encode"
)]
pub trait Index<S> {
    /// The term this index derives.
    type Term: 'static;
    /// This index as data, with its parameters.
    fn spec(&self) -> IndexSpec;
    /// The description that derives this index's term of `S`, under the
    /// [`CallerContext`] it is handed when it runs.
    ///
    /// A fresh description per call: a description is single-use, and an
    /// index is not, so a saved plan asks again each time it runs.
    fn operation<'s, K: 'static, M: ConsumeSource<'s, S>>(
        &self,
    ) -> Encryption<'s, S, Self::Term, K, CallerContext, M>
    where
        S: 's;
}

/// The equality (exact-match) index: one PRF block over the whole value.
/// Defined for every `S` with a PRF encoding.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Equality;

/// The order-revealing index: a CLLW ORE ciphertext of the value, under a
/// key derived from the field's context. Defined for every `S` the scheme
/// can order (text and integers among them).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Ore;

/// The order-preserving index; see [`Ore`]. Defined for the same `S`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Ope;

/// The full-text match index, over text only, with the tokenizer and filter
/// parameters its [`MatchConfig`] `O` fixes.
///
/// `Match::default()` is the default configuration ([`DefaultMatch`]);
/// `Match::<MyConfig>::new()` is another. The configuration is on the type so
/// that a stored field and the query probing it agree on it by construction.
pub struct Match<O = DefaultMatch>(PhantomData<fn() -> O>);

impl<O> Match<O> {
    /// The match index under the configuration `O`.
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}
impl Default for Match {
    fn default() -> Self {
        Self::new()
    }
}
// By hand, so `O` (a marker type) need not be `Clone`, `Debug` or `PartialEq`.
impl<O> Clone for Match<O> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<O> Copy for Match<O> {}
impl<O> fmt::Debug for Match<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Match")
    }
}

impl<S: vitaminc_prf::PrfValue> Index<S> for Equality {
    type Term = EqualityTerm;
    fn spec(&self) -> IndexSpec {
        IndexSpec::Equality
    }
    fn operation<'s, K: 'static, M: ConsumeSource<'s, S>>(
        &self,
    ) -> Encryption<'s, S, Self::Term, K, CallerContext, M>
    where
        S: 's,
    {
        equality()
    }
}
impl<S: AsRef<str>, O: MatchConfig + 'static> Index<S> for Match<O> {
    type Term = MatchTerms<O>;
    fn spec(&self) -> IndexSpec {
        IndexSpec::Match(O::options())
    }
    fn operation<'s, K: 'static, M: ConsumeSource<'s, S>>(
        &self,
    ) -> Encryption<'s, S, Self::Term, K, CallerContext, M>
    where
        S: 's,
    {
        matching()
    }
}
impl<S> Index<S> for Ore
where
    S: cllw_ore::CllwOreEncrypt + Send + 'static,
    S::Output: Send + 'static,
{
    type Term = OreTerm<S>;
    fn spec(&self) -> IndexSpec {
        IndexSpec::Ore
    }
    fn operation<'s, K: 'static, M: ConsumeSource<'s, S>>(
        &self,
    ) -> Encryption<'s, S, Self::Term, K, CallerContext, M>
    where
        S: 's,
    {
        ore()
    }
}
impl<S> Index<S> for Ope
where
    S: cllw_ore::CllwOpeEncrypt + Send + 'static,
    S::Output: Send + 'static,
{
    type Term = OpeTerm<S>;
    fn spec(&self) -> IndexSpec {
        IndexSpec::Ope
    }
    fn operation<'s, K: 'static, M: ConsumeSource<'s, S>>(
        &self,
    ) -> Encryption<'s, S, Self::Term, K, CallerContext, M>
    where
        S: 's,
    {
        ope()
    }
}

/// A non-empty set of indexes over `S`: one [`Index`], or a tuple of two to
/// four of them.
///
/// Not implemented for `()`. An indexed field with no index would be a
/// ciphertext-only field that says otherwise; that field is [`ciphertext`]
/// alone, and asking [`indexed`] for one does not compile.
///
/// The terms come out in the order the indexes are named: one index's
/// [`Terms`](Self::Terms) is its term, a tuple's is the tuple of its terms.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a set of indexes over `{S}`",
    label = "expected one index, or a tuple of two to four, each defined over `{S}`",
    note = "`()` is not a set of indexes: a field with no index is `ciphertext()` alone"
)]
pub trait Indexes<S> {
    /// What the indexes derive: one term, or a tuple of terms in order.
    type Terms: 'static;
    /// The indexes as data, in order.
    fn specs(&self) -> Vec<IndexSpec>;
    /// The description that derives every term, under the one
    /// [`CallerContext`] it is handed, settling them in one batch.
    ///
    /// Several indexes over one owned plaintext share it, so in
    /// [`Owned`](super::Owned) mode `S` must be `Clone` (see [`ShareSource`]).
    fn operations<'s, K: 'static, M>(&self) -> Encryption<'s, S, Self::Terms, K, CallerContext, M>
    where
        S: 's,
        M: ConsumeSource<'s, S> + ShareSource<'s, S>;
    /// The one index of type `I` in this set, for the query side, where a
    /// query asks one index for one term and needs no ciphertext; its
    /// [`operation`](Index::operation) is that term alone.
    ///
    /// `P` is where `I` sits (the position [`Select`] names) and is inferred;
    /// leave it `_`. Asking for an index the set does not hold does not
    /// compile, and neither does asking for one the set holds twice, since
    /// its place is then ambiguous.
    ///
    /// A concrete tuple is a set of indexes over many plaintexts, so there
    /// the plaintext is named:
    ///
    /// ```
    /// use stack_encrypt::target::{Equality, Index, IndexSpec, Indexes, Ore};
    ///
    /// let indexes = (Equality, Ore);
    /// let ore = Indexes::<u32>::select::<Ore, _>(&indexes);
    /// assert_eq!(Index::<u32>::spec(ore), IndexSpec::Ore);
    /// ```
    ///
    /// In code generic over the set, the position is a type parameter too,
    /// and the set must be bounded by [`Select`] for it: `X: Indexes<S>`
    /// alone does not let the call compile.
    ///
    /// ```
    /// use stack_encrypt::target::{Equality, Index, IndexSpec, Indexes, Ore, Select};
    ///
    /// fn ore_spec<X, P>(indexes: &X) -> IndexSpec
    /// where
    ///     X: Indexes<u32> + Select<Ore, P>,
    /// {
    ///     Index::<u32>::spec(indexes.select::<Ore, P>())
    /// }
    /// assert_eq!(ore_spec(&(Equality, Ore)), IndexSpec::Ore);
    /// ```
    fn select<I: Index<S>, P>(&self) -> &I
    where
        Self: Select<I, P>,
    {
        Select::get(self)
    }
}

/// Where an index sits in a set of indexes, for [`Indexes::select`]: the
/// set *is* the index ([`Whole`]), or holds it at position `N` ([`At`]).
/// Implemented for every index and every tuple position; the position is
/// inferred, so a caller never names it.
pub trait Select<I, Position> {
    /// The index at that position.
    fn get(&self) -> &I;
}

/// [`Select`]'s position for a set that is one index.
#[derive(Debug)]
pub enum Whole {}

/// [`Select`]'s position for the `N`th index of a tuple, counting from zero.
#[derive(Debug)]
pub struct At<const N: usize>;

impl<I> Select<I, Whole> for I {
    fn get(&self) -> &I {
        self
    }
}

/// One index is a set of one. Implemented per index rather than as a
/// blanket over every `Index`, which would overlap the tuple impls below.
macro_rules! single_index {
    ($([$($generics:tt)*] $index:ty),+ $(,)?) => {$(
        impl<S, $($generics)*> Indexes<S> for $index
        where
            $index: Index<S>,
        {
            type Terms = <$index as Index<S>>::Term;
            fn specs(&self) -> Vec<IndexSpec> {
                vec![self.spec()]
            }
            fn operations<'s, K: 'static, M>(
                &self,
            ) -> Encryption<'s, S, Self::Terms, K, CallerContext, M>
            where
                S: 's,
                M: ConsumeSource<'s, S> + ShareSource<'s, S>,
            {
                self.operation()
            }
        }
    )+};
}
single_index!([] Equality, [O] Match<O>, [] Ore, [] Ope);

/// A tuple of indexes: each index's operation, zipped left to right, and the
/// nested pairs `zip` builds flattened back into one tuple of terms.
macro_rules! tuple_of_indexes {
    ($(($($name:ident $at:tt),+) => $nested:pat,)+) => {$(
        impl<S, $($name: Index<S>),+> Indexes<S> for ($($name,)+) {
            type Terms = ($($name::Term,)+);
            fn specs(&self) -> Vec<IndexSpec> {
                vec![$(self.$at.spec()),+]
            }
            fn operations<'s, K: 'static, M>(
                &self,
            ) -> Encryption<'s, S, Self::Terms, K, CallerContext, M>
            where
                S: 's,
                M: ConsumeSource<'s, S> + ShareSource<'s, S>,
            {
                tuple_of_indexes!(@zip self, $($at),+)
                    .map(|$nested| ($($name,)+))
            }
        }
        tuple_of_indexes!(@select [$($name),+] $($name $at),+);
    )+};
    (@zip $self:ident, $first:tt $(, $rest:tt)*) => {
        $self.$first.operation()$(.zip($self.$rest.operation()))*
    };
    // One `Select` impl per position, each over the whole tuple.
    (@select [$($all:ident),+] $name:ident $at:tt $(, $rest:ident $rest_at:tt)*) => {
        impl<$($all),+> Select<$name, At<$at>> for ($($all,)+) {
            fn get(&self) -> &$name {
                &self.$at
            }
        }
        tuple_of_indexes!(@select [$($all),+] $($rest $rest_at),*);
    };
    (@select [$($all:ident),+]) => {};
}
// The closure's pattern re-binds each term under its index's type name, so
// the body can list them in order.
#[allow(non_snake_case)]
mod tuples {
    use super::*;
    tuple_of_indexes! {
        (A 0, B 1) => (A, B),
        (A 0, B 1, C 2) => ((A, B), C),
        (A 0, B 1, C 2, D 3) => (((A, B), C), D),
    }
}

/// One value, sealed, with the terms of its indexes beside it: what
/// [`indexed`] produces.
///
/// The terms are a tuple in the order the indexes were named, and are read
/// by destructuring:
///
/// ```text
/// let (eq, ore) = out.terms;
/// ```
///
/// There are deliberately no named accessors (`out.ore()`): they would need
/// a type-level search of the tuple to serve a case that barely exists. A
/// struct with named fields is what `#[derive(EncryptFrom)]` is for.
///
/// Decrypting it opens the ciphertext: the terms are one-way.
#[derive(Debug)]
pub struct Encrypted<Terms> {
    /// The sealed value.
    pub ciphertext: StackCipherText,
    /// The terms, one per index, in order.
    pub terms: Terms,
}

impl<P: crate::Decrypt<'static> + 'static, Terms> DecryptInto<P> for Encrypted<Terms> {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<P, K> {
        open(self.ciphertext, context)
    }
}

/// Seal `S` and derive the terms of `indexes` beside it, under the one
/// [`CallerContext`] the description is handed: the ciphertext takes its
/// AEAD half, every term the whole.
///
/// This is `ciphertext().accepting().zip(..).map(..)` composed once, here,
/// so a field with indexes is one line and its output is an
/// [`Encrypted<Terms>`]. The bytes are exactly the hand composition's.
///
/// The ciphertext and every term share the plaintext, so in
/// [`Owned`](super::Owned) mode `S` must be `Clone`; a plaintext that must
/// never be copied can still be sealed alone ([`ciphertext`]) or indexed
/// alone ([`Index::operation`]).
///
/// The type parameters are in the order [`ciphertext`]'s are, with the
/// indexes last: `indexed::<u32, _, Borrowed, _>((Equality, Ore))`.
pub fn indexed<'s, S, K, M, X>(
    indexes: X,
) -> Encryption<'s, S, Encrypted<X::Terms>, K, CallerContext, M>
where
    S: crate::Encrypt + 's,
    K: 'static,
    M: ConsumeSource<'s, S> + ShareSource<'s, S>,
    X: Indexes<S>,
{
    ciphertext::<S, K, M>()
        .accepting::<CallerContext>()
        .zip(indexes.operations())
        .map(|(ciphertext, terms)| Encrypted { ciphertext, terms })
}
