//! Indexes as types: what a field is searchable by, composed once in the
//! engine instead of once per caller.
//!
//! An *index* is an operation that derives a search term beside a
//! ciphertext: [`Equality`], [`Match`], [`Ore`], [`Ope`], [`OreBlock`] or
//! [`Json`]. Each is a type implementing [`Index<S>`] for exactly the
//! plaintexts its scheme is defined over, so an index that does not apply
//! does not compile: `Match` is text only, so a match index on an integer is
//! a type error, not a runtime one; `Json` is defined over a JSON document
//! alone.
//!
//! A field's indexes are one value: a single index, or a tuple of them
//! ([`Indexes<S>`]). `()` is deliberately not a set of indexes, so asking for
//! an indexed field with no index is a compile error rather than a quiet
//! ciphertext-only field; a field with no index is [`ciphertext`] alone.
//!
//! [`indexed`] does the composition a caller would otherwise spell by hand —
//! `ciphertext().accepting().zip(equality()).zip(ore()).map(..)`, with its
//! nested-pair bookkeeping — and produces an [`Encrypted<Terms>`]: the
//! ciphertext, and the terms as a tuple read by destructuring.
//!
//! ```
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::sem::{EqualityTerm, OreTerm};
//! use stack_encrypt::target::{indexed, Borrowed, CallerContext, Encrypted, Equality, Ore};
//! use stack_encrypt::{nonempty, StackCipher};
//!
//! // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
//! // the environment, or from the profile that `npx stash auth login` writes.
//! let cipher = StackCipher::builder()
//! #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//!     .init()
//!     .await?;
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
//! One term can be derived alone, with no ciphertext: [`Indexes::select`]
//! picks an index out of a set by type, and [`Index::operation`] is its
//! term alone. A field query does not use `select`: the field's
//! target type names the index that answers each operator
//! ([`Answers`](crate::op::Answers)).
//!
//! For the FFI and for saved plans an index lowers to data,
//! [`IndexSpec`], through [`Index::spec`]. Parameters live on the index
//! (a [`Match`]'s tokenizer and filter size, through its [`MatchConfig`])
//! and lower with it.
use std::fmt;
use std::marker::PhantomData;

use super::context::{AeadContext, CallerContext};
use super::operations::{
    ciphertext, equality, json_terms, matching, matching_query, ope, open, ore, ore_block,
};
use super::source::{Owned, WipeSource};
use super::{
    DecryptField, DecryptSource, Decryptable, Decryption, EncryptTarget, Encryption,
    RequiredContext,
};
use crate::json::{JsonOptions, JsonTerms};
use crate::op::Op;
use crate::sem::{
    DefaultMatch, EqualityTerm, MatchConfig, MatchOptions, MatchTerms, OpeTerm, OreBlockTerm,
    OreTerm,
};
use crate::StackCipherText;

/// An index lowered to data: what crosses the FFI boundary and what a saved
/// plan holds. The Rust side keeps the type ([`Index`]); a binding, which
/// has no type to name, speaks this. It is the one data form of an index:
/// the `dynamic` record plan, its term derivation and the Go guest all
/// spell an index as an `IndexSpec`, options included.
///
/// The [`key`](Self::key) strings are the output keys of the `dynamic` record
/// format (`"eq"`, `"match"`, `"ore"`, `"ope"`, `"ore_block"`, `"json"`), so
/// they are wire format; that is why this enum is exhaustive: a new index is
/// something every binding has to be taught. With the `dynamic` feature, a
/// plan spells an index as its key, or, for a match or JSON index with
/// non-default options, as an object carrying them; `dynamic::record::plan`
/// documents that shape, and `IndexSpec::from_value` / `IndexSpec::to_value`
/// read and write it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IndexSpec {
    /// Equality (exact match).
    Equality,
    /// Full-text match, with the options its terms are generated under.
    Match(MatchOptions),
    /// Order-revealing comparison, CLLW ORE.
    Ore,
    /// Order-preserving comparison, CLLW OPE.
    Ope,
    /// Order-revealing comparison, 6-bit block ORE: the term EQL v4's
    /// `_ord_ore` domains store as `ob`.
    OreBlock,
    /// The JSON index: a searchable document, with the layout options it
    /// is written under. A data plan names it but cannot run it yet
    /// (`Reason::JsonIndexPending`); the typed path can.
    Json(JsonOptions),
}

impl IndexSpec {
    /// The output key this index's term rides under in a record, and the
    /// string a binding spells it as.
    ///
    /// It is an output key, not a serialisation: it drops a match index's
    /// options, so a data form must go through the serialiser
    /// (`IndexSpec::to_value`, with the `dynamic` feature), which keeps
    /// them, never through `key()`.
    pub fn key(&self) -> &'static str {
        match self {
            IndexSpec::Equality => "eq",
            IndexSpec::Match(_) => "match",
            IndexSpec::Ore => "ore",
            IndexSpec::Ope => "ope",
            IndexSpec::OreBlock => "ore_block",
            IndexSpec::Json(_) => "json",
        }
    }

    /// The operators this index declares: the one declaration each index
    /// type carries (`Equality::OPERATORS`, `Ore::OPERATORS`, …), which the
    /// typed `Supports` impls are written beside, so the typed and the
    /// dynamic lookup read one table. An index declared as data has the
    /// operators its type has, whatever its options.
    pub fn operators(&self) -> &'static [Op] {
        match self {
            IndexSpec::Equality => Equality::OPERATORS,
            IndexSpec::Match(_) => Match::<DefaultMatch>::OPERATORS,
            IndexSpec::Ore => Ore::OPERATORS,
            IndexSpec::Ope => Ope::OPERATORS,
            IndexSpec::OreBlock => OreBlock::OPERATORS,
            IndexSpec::Json(_) => Json::OPERATORS,
        }
    }

    /// Whether this index, as configured, answers `op`: the operator is in
    /// its [declaration](Self::operators), and for a JSON index an ordering
    /// at a path, or an element predicate built of them, only when the
    /// index orders some path.
    pub fn answers(&self, op: Op) -> bool {
        if !self.operators().contains(&op) {
            return false;
        }
        match self {
            IndexSpec::Json(options) if json_ordering(op) => !options.ordered.is_empty(),
            _ => true,
        }
    }
}

/// The JSON operators answered only by an index that orders some path.
fn json_ordering(op: Op) -> bool {
    matches!(
        op,
        Op::LtAt | Op::LteAt | Op::GtAt | Op::GteAt | Op::BetweenAt | Op::ElementMatch
    )
}

/// Two indexes of `indexes` that declare one operator, with that operator:
/// a field declares at most one index per operator, so the lookup for an
/// operator finds zero or one index. `(Equality, Ore)` declares none in
/// common; `(Ore, Ope)`, `(Ore, OreBlock)` and two match indexes do. The
/// first pair in declaration order, and its first common operator.
pub(crate) fn overlapping(indexes: &[IndexSpec]) -> Option<(&IndexSpec, &IndexSpec, Op)> {
    indexes.iter().enumerate().find_map(|(i, first)| {
        indexes[i + 1..].iter().find_map(|second| {
            first
                .operators()
                .iter()
                .find(|op| second.operators().contains(op))
                .map(|op| (first, second, *op))
        })
    })
}

/// Refuse a set of indexes that one value cannot declare together: one
/// index named twice, or two indexes that answer one operator.
///
/// Two match indexes with different options are still one index twice: a
/// value has one term for each kind of index. `Ore` and `Ope` both answer
/// the orderings, so a query for one would have to choose between them.
/// The dynamic path refuses the same declarations when it parses a plan.
///
/// A target calls this when it is described, so the refusal comes before
/// any key is requested: [`Encrypted<Terms>`] used as a target checks the
/// indexes its terms name, and a derived `plaintext = T` record checks the
/// indexes of its fields.
///
/// The combinator [`indexed`] does not call it. A description built by
/// hand from `indexed((Ore, Ope))` and run with
/// [`KeysetCipher::run`](crate::KeysetCipher::run) derives both terms.
///
/// # Errors
///
/// [`PlanError::DuplicateIndex`](crate::PlanError::DuplicateIndex) or
/// [`PlanError::IndexOverlap`](crate::PlanError::IndexOverlap), in
/// [`Error::Plan`](crate::Error::Plan).
#[doc(hidden)]
pub fn check_indexes(indexes: &[IndexSpec]) -> Result<(), crate::Error> {
    const AT: &str = "the value";
    for (i, index) in indexes.iter().enumerate() {
        if indexes[..i]
            .iter()
            .any(|earlier| earlier.key() == index.key())
        {
            return Err(crate::PlanError::DuplicateIndex {
                at: AT.to_owned(),
                index: index.key(),
            }
            .into());
        }
    }
    if let Some((first, second, operator)) = overlapping(indexes) {
        return Err(crate::PlanError::IndexOverlap {
            at: AT.to_owned(),
            first: first.key(),
            second: second.key(),
            operator,
        }
        .into());
    }
    Ok(())
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
/// no `Index<u32>` for [`Match`](struct@Match), because match is defined over text.
///
/// An index does not seal anything. [`indexed`] puts a ciphertext beside the
/// indexes of a field; [`operation`](Self::operation) on its own is the term
/// alone, and [`query_operation`](Self::query_operation) is the term a query
/// sends.
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
    fn operation<'s, K: 'static, M: WipeSource<'s, S>>(
        &self,
    ) -> Encryption<'s, S, Self::Term, K, CallerContext, M>
    where
        S: 's;
    /// The description that derives the term a query of `S` sends, under
    /// the [`CallerContext`] it is handed when it runs: what a field query
    /// derives. By default [`operation`](Self::operation)'s, since most
    /// indexes send what they store. A match index cuts a query differently
    /// from a stored value ([`matching_query`]), so it overrides this. An
    /// index that wraps another forwards both.
    fn query_operation<'s, K: 'static, M: WipeSource<'s, S>>(
        &self,
    ) -> Encryption<'s, S, Self::Term, K, CallerContext, M>
    where
        S: 's,
    {
        self.operation()
    }
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

/// The block ORE index: ore-rs's 6-bit block ORE ciphertext of the value,
/// under a key derived from the field's context
/// ([`OreBlockTerm`](crate::sem::OreBlockTerm)). Defined for the same `S`
/// as [`Ore`].
///
/// [`Ore`] and [`Ope`] are CLLW schemes. This is the other ORE family, the
/// one EQL v4's `_ord_ore` domains store (`ob`), named as EQL names it: an
/// ORE *block* term. Its terms leak less than [`Ore`]'s (a stored term's
/// right half is randomised, and a comparison reveals the first differing
/// six-bit block rather than the first differing bit), cost more (about
/// 300 bytes for an `i64`, 600 for short text), and need a comparator
/// that is not byte order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct OreBlock;

/// The JSON index, over a [`serde_json::Value`] alone: one searchable
/// document per value, with a path selector per node, a token chain, and
/// a containment projection of the nodes' value selectors grouped by array
/// element (the [`json`](crate::json) module).
///
/// Its term is a [`JsonTerms`], the document's one-way terms, which every
/// query term is built from; the stored document is the output of the
/// separate sealing operation, [`json_document`](super::json_document),
/// and a [`JsonDocument`](crate::json::JsonDocument) target names it by
/// type. The index answers `op::Contains`, `op::ContainedBy`, `op::AtPath(op::Eq)`
/// and the orderings at a path, `op::AtPath(op::Gte)` and the rest.
///
/// The value [`Json`](constant@Json) is the index under the default
/// options ([`JsonOptions::default`], the root sealed); `Json::new(options)`
/// is another. The options are part of the index's identity, as a match
/// index's are: a stored document and the query probing it agree on them
/// through the plan that declares the index.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Json {
    pub(crate) options: JsonOptions,
}

/// The JSON index under the default options, as a value: `.with(Json)`.
#[allow(non_upper_case_globals)]
pub const Json: Json = Json::new(JsonOptions::new());

impl Json {
    /// The index under `options`.
    pub const fn new(options: JsonOptions) -> Self {
        Self { options }
    }
}

/// The full-text match index, over text only, with the tokenizer and filter
/// parameters its [`MatchConfig`] `O` fixes.
///
/// The value [`Match`](constant@Match) is the index under the default
/// configuration ([`DefaultMatch`]), as `PhantomData` is a value of its
/// type; `Match::<MyConfig>::new()` is another. The configuration is on the
/// type, so a field's type fixes the one its stored filter and its queries
/// are cut under: a query made from the field's reference answers through
/// the field's own `Match<O>` ([`Answers`](crate::op::Answers)).
pub struct Match<O = DefaultMatch> {
    config: PhantomData<fn() -> O>,
}

/// The match index under the default configuration, as a value:
/// `.with((Equality, Match))`.
#[allow(non_upper_case_globals)]
pub const Match: Match = Match::new();

impl<O> Match<O> {
    /// The match index under the configuration `O`.
    pub const fn new() -> Self {
        Self {
            config: PhantomData,
        }
    }
}
impl<O> Default for Match<O> {
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

impl<S: crate::Encrypt + vitaminc_aead::EncryptRef> Index<S> for Equality {
    type Term = EqualityTerm;
    fn spec(&self) -> IndexSpec {
        IndexSpec::Equality
    }
    fn operation<'s, K: 'static, M: WipeSource<'s, S>>(
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
    fn operation<'s, K: 'static, M: WipeSource<'s, S>>(
        &self,
    ) -> Encryption<'s, S, Self::Term, K, CallerContext, M>
    where
        S: 's,
    {
        matching()
    }
    fn query_operation<'s, K: 'static, M: WipeSource<'s, S>>(
        &self,
    ) -> Encryption<'s, S, Self::Term, K, CallerContext, M>
    where
        S: 's,
    {
        matching_query()
    }
}
impl<S> Index<S> for Ore
where
    S: crate::Orderable + vitaminc_aead::EncryptRef + 'static,
{
    type Term = OreTerm<S>;
    fn spec(&self) -> IndexSpec {
        IndexSpec::Ore
    }
    fn operation<'s, K: 'static, M: WipeSource<'s, S>>(
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
    S: crate::Orderable + vitaminc_aead::EncryptRef + 'static,
{
    type Term = OpeTerm<S>;
    fn spec(&self) -> IndexSpec {
        IndexSpec::Ope
    }
    fn operation<'s, K: 'static, M: WipeSource<'s, S>>(
        &self,
    ) -> Encryption<'s, S, Self::Term, K, CallerContext, M>
    where
        S: 's,
    {
        ope()
    }
}
impl<S> Index<S> for OreBlock
where
    S: crate::Orderable + vitaminc_aead::EncryptRef + 'static,
{
    type Term = OreBlockTerm<S>;
    fn spec(&self) -> IndexSpec {
        IndexSpec::OreBlock
    }
    fn operation<'s, K: 'static, M: WipeSource<'s, S>>(
        &self,
    ) -> Encryption<'s, S, Self::Term, K, CallerContext, M>
    where
        S: 's,
    {
        ore_block()
    }
}

/// The JSON index's operation derives the document's terms and seals
/// nothing: it only reads the value, so it runs in either source mode
/// without a copy. Sealing is [`json_document`](super::json_document).
impl Index<serde_json::Value> for Json {
    type Term = JsonTerms;
    fn spec(&self) -> IndexSpec {
        IndexSpec::Json(self.options.clone())
    }
    fn operation<'s, K: 'static, M: WipeSource<'s, serde_json::Value>>(
        &self,
    ) -> Encryption<'s, serde_json::Value, Self::Term, K, CallerContext, M> {
        json_terms::<K, M>(self.options.clone())
    }
}

/// A non-empty set of indexes over `S`: one [`Index`], or a tuple of two to
/// five of them.
///
/// Not implemented for `()`. An indexed field with no index would be a
/// ciphertext-only field that says otherwise; that field is [`ciphertext`]
/// alone, and asking [`indexed`] for one does not compile.
///
/// The terms come out in the order the indexes are named: one index's
/// [`Terms`](Self::Terms) is its term, a tuple's is the tuple of its terms.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a set of indexes over `{S}`",
    label = "expected one index, or a tuple of two to five, each defined over `{S}`",
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
    /// Several indexes over one plaintext all read it in place, so nothing
    /// is copied in either mode. In [`Owned`](super::Owned) mode the first
    /// index is handed the value, once the others have read it.
    fn operations<'s, K: 'static, M>(&self) -> Encryption<'s, S, Self::Terms, K, CallerContext, M>
    where
        S: 's,
        M: WipeSource<'s, S>;
    /// The description that derives every term a query of `S` sends, each
    /// index's [`query_operation`](Index::query_operation), under the one
    /// [`CallerContext`] it is handed and settled in one batch, as
    /// [`operations`](Self::operations) settles the stored terms. A set
    /// that holds a [`Match`](struct@Match) index sends the filter of the
    /// tokens the query keeps, where [`operations`](Self::operations)
    /// derives a stored value's.
    ///
    /// By default [`operations`](Self::operations)'s, since most indexes
    /// send what they store. Every set in this crate derives each index's
    /// query term; a set defined elsewhere that holds a
    /// [`Match`](struct@Match) index overrides this, as an index that wraps
    /// another forwards [`Index::query_operation`].
    fn query_operations<'s, K: 'static, M>(
        &self,
    ) -> Encryption<'s, S, Self::Terms, K, CallerContext, M>
    where
        S: 's,
        M: WipeSource<'s, S>,
    {
        self.operations()
    }
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
                M: WipeSource<'s, S>,
            {
                self.operation()
            }
            fn query_operations<'s, K: 'static, M>(
                &self,
            ) -> Encryption<'s, S, Self::Terms, K, CallerContext, M>
            where
                S: 's,
                M: WipeSource<'s, S>,
            {
                self.query_operation()
            }
        }
    )+};
}
single_index!([] Equality, [O] Match<O>, [] Ore, [] Ope, [] OreBlock, [] Json, [] IndexSpec);

/// A tuple of indexes: each index's operation (or query operation), zipped
/// left to right, and the nested pairs `zip` builds flattened back into one
/// tuple of terms.
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
                M: WipeSource<'s, S>,
            {
                tuple_of_indexes!(@zip self, operation, $($at),+)
                    .map(|$nested| ($($name,)+))
            }
            fn query_operations<'s, K: 'static, M>(
                &self,
            ) -> Encryption<'s, S, Self::Terms, K, CallerContext, M>
            where
                S: 's,
                M: WipeSource<'s, S>,
            {
                tuple_of_indexes!(@zip self, query_operation, $($at),+)
                    .map(|$nested| ($($name,)+))
            }
        }
        tuple_of_indexes!(@select [$($name),+] $($name $at),+);
    )+};
    (@zip $self:ident, $operation:ident, $first:tt $(, $rest:tt)*) => {
        $self.$first.$operation()$(.zip($self.$rest.$operation::<K, super::super::Borrowed>()))*
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
        (A 0, B 1, C 2, D 3, E 4) => ((((A, B), C), D), E),
    }
}

/// A set of indexes whose size is known only at run time: what a plan
/// lowered from data holds, where the indexes arrive as a list rather than
/// a tuple. The terms come out as a `Vec`, one per index, in order.
///
/// A `Vec` cannot be refused for being empty at compile time as `()` is, so
/// an empty one is refused when it runs, with
/// [`PlanError::EmptyIndexes`](crate::PlanError::EmptyIndexes), before any
/// key is requested: a field declared indexed derives at least one term.
/// [`select`](Indexes::select) is not available on a `Vec`; a binding
/// answers a query by index key, through its own `Index` impl.
impl<S, I: Index<S>> Indexes<S> for Vec<I> {
    type Terms = Vec<I::Term>;
    fn specs(&self) -> Vec<IndexSpec> {
        self.iter().map(Index::spec).collect()
    }
    fn operations<'s, K: 'static, M>(&self) -> Encryption<'s, S, Self::Terms, K, CallerContext, M>
    where
        S: 's,
        M: WipeSource<'s, S>,
    {
        let mut indexes = self.iter();
        let Some(first) = indexes.next() else {
            return Encryption::failed(crate::PlanError::EmptyIndexes.into());
        };
        indexes.fold(first.operation().map(|term| vec![term]), |terms, index| {
            terms
                .zip(index.operation::<K, super::Borrowed>())
                .map(|(mut terms, term)| {
                    terms.push(term);
                    terms
                })
        })
    }
    fn query_operations<'s, K: 'static, M>(
        &self,
    ) -> Encryption<'s, S, Self::Terms, K, CallerContext, M>
    where
        S: 's,
        M: WipeSource<'s, S>,
    {
        let mut indexes = self.iter();
        let Some(first) = indexes.next() else {
            return Encryption::failed(crate::PlanError::EmptyIndexes.into());
        };
        indexes.fold(
            first.query_operation().map(|term| vec![term]),
            |terms, index| {
                terms
                    .zip(index.query_operation::<K, super::Borrowed>())
                    .map(|(mut terms, term)| {
                        terms.push(term);
                        terms
                    })
            },
        )
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
/// struct with named fields is what `#[derive(EncryptTarget)]` is for.
///
/// Decrypting it opens the ciphertext: the terms are one-way.
#[derive(Debug)]
pub struct Encrypted<Terms> {
    /// The sealed value.
    pub ciphertext: StackCipherText,
    /// The terms, one per index, in order.
    pub terms: Terms,
}

/// `Encrypted<Terms>` is a target, so a record field or a caller names a
/// ciphertext with its terms by type alone:
/// `email: Encrypted<(EqualityTerm, MatchTerms)>`. The terms name their
/// indexes ([`TermSet`]), and the description is [`indexed`] over them, under
/// the one caller context that the record field or the caller supplies.
///
/// The owned form is handed the value. The terms read it in place, and then
/// the ciphertext takes it. Vitamin C wipes it when it is sealed, and the
/// ciphertext wipes it when the context is refused. Nothing is copied.
impl<S, Terms> EncryptTarget<S> for Encrypted<Terms>
where
    S: crate::Encrypt + vitaminc_aead::EncryptRef + zeroize::Zeroize,
    Terms: TermSet<S>,
{
    type ContextInput = RequiredContext<CallerContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
    where
        S: 's,
    {
        let described = indexed(Terms::INDEXES).accepting();
        if let Err(error) = check_indexes(&Terms::INDEXES.specs()) {
            // Refused with the leaves' contexts kept, so `contexts()`
            // still shows the field.
            return described.refused(error);
        }
        described
    }
    fn owned_encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput, Owned>
    where
        S: 's,
    {
        let described = indexed::<S, K, Owned, _>(Terms::INDEXES).accepting();
        if let Err(error) = check_indexes(&Terms::INDEXES.specs()) {
            // The refused value is the description's to wipe. The leaves'
            // contexts are kept, as in the borrowed form.
            return described.refused_wiping(error);
        }
        described
    }
    fn indexes() -> Vec<IndexSpec> {
        Terms::INDEXES.specs()
    }
}
impl<P: crate::Decrypt + zeroize::Zeroize + Send + 'static, Terms> DecryptSource<P>
    for Encrypted<Terms>
{
    type ContextInput = RequiredContext<AeadContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<P, K> {
        open(self.ciphertext, context.into_inner())
    }
}

/// The ciphertext is what a record opens; the terms are one-way.
impl<Terms> Decryptable for Encrypted<Terms> {
    const DECRYPTABLE: bool = true;
}
impl<P: zeroize::Zeroize + 'static, Ctx, Terms> DecryptField<P, Ctx> for Encrypted<Terms>
where
    Self: DecryptSource<P>,
    Ctx: Into<<Self as DecryptSource<P>>::ContextInput>,
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
        Some(<Self as DecryptSource<P>>::decryption(self, context.into()))
    }
}

/// The terms of a set of indexes, named from the terms' side: one term type,
/// or a tuple of two or three, each naming the index that derives it. This is
/// what lets [`Encrypted<Terms>`] be a target with no value in hand: its type
/// says which indexes to run.
///
/// [`INDEXES`](Self::INDEXES) is the set of indexes whose terms are `Self`,
/// in the same order, so `<(EqualityTerm, OreTerm<u32>)>::INDEXES` is
/// `(Equality, Ore)`.
///
/// A match term names its configuration in its type (`MatchTerms<O>`), so
/// the index it names is `Match<O>`, the configuration included.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a set of terms over `{S}`",
    label = "expected one term, or a tuple of two or three terms over `{S}`",
    note = "a value holds at most one term for each family of operators (equality, match and the orderings), so a tuple of terms has at most three"
)]
pub trait TermSet<S>: Sized + 'static {
    /// The indexes that derive these terms.
    type Indexes: Indexes<S, Terms = Self>;
    /// Those indexes, as a value.
    const INDEXES: Self::Indexes;
}
impl<S: crate::Encrypt + vitaminc_aead::EncryptRef> TermSet<S> for EqualityTerm {
    type Indexes = Equality;
    const INDEXES: Equality = Equality;
}
impl<S: AsRef<str>, O: MatchConfig + 'static> TermSet<S> for MatchTerms<O> {
    type Indexes = Match<O>;
    const INDEXES: Match<O> = Match::new();
}
impl<S> TermSet<S> for OreTerm<S>
where
    S: crate::Orderable + vitaminc_aead::EncryptRef + 'static,
{
    type Indexes = Ore;
    const INDEXES: Ore = Ore;
}
impl<S> TermSet<S> for OpeTerm<S>
where
    S: crate::Orderable + vitaminc_aead::EncryptRef + 'static,
{
    type Indexes = Ope;
    const INDEXES: Ope = Ope;
}
impl<S> TermSet<S> for OreBlockTerm<S>
where
    S: crate::Orderable + vitaminc_aead::EncryptRef + 'static,
{
    type Indexes = OreBlock;
    const INDEXES: OreBlock = OreBlock;
}

/// A tuple of terms names the tuple of their indexes. Each element must be
/// one term (its set is one index), as a tuple of indexes holds indexes.
///
/// A tuple has at most three terms. A value holds at most one term for each
/// family of operators: equality, match, and the orderings. Four terms
/// would include two that answer one family, which [`check_indexes`]
/// refuses every time, so there is no impl for four or five.
macro_rules! tuple_of_terms {
    ($(($($name:ident),+),)+) => {$(
        impl<S, $($name),+> TermSet<S> for ($($name,)+)
        where
            $($name: TermSet<S>, $name::Indexes: Index<S, Term = $name>,)+
        {
            type Indexes = ($($name::Indexes,)+);
            const INDEXES: Self::Indexes = ($($name::INDEXES,)+);
        }
    )+};
}
#[allow(non_snake_case)]
mod term_tuples {
    use super::*;
    tuple_of_terms! {
        (A, B),
        (A, B, C),
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
/// The ciphertext and every term read the same plaintext in place, so
/// nothing is copied in either mode. In [`Owned`](super::Owned) mode the
/// terms read the value first, and then the ciphertext takes it.
///
/// The type parameters are in the order [`ciphertext`]'s are, with the
/// indexes last: `indexed::<u32, _, Borrowed, _>((Equality, Ore))`.
///
/// This does not check the set of indexes. A set that names one index
/// twice, or two indexes that answer one operator, derives every term it
/// names. The target [`Encrypted<Terms>`] refuses such a set before any
/// key is requested.
pub fn indexed<'s, S, K, M, X>(
    indexes: X,
) -> Encryption<'s, S, Encrypted<X::Terms>, K, CallerContext, M>
where
    S: crate::Encrypt + vitaminc_aead::EncryptRef + 's,
    K: 'static,
    M: WipeSource<'s, S>,
    X: Indexes<S>,
{
    ciphertext::<S, K, M>()
        .accepting::<CallerContext>()
        .zip(indexes.operations::<K, super::Borrowed>())
        .map(|(ciphertext, terms)| Encrypted { ciphertext, terms })
}
