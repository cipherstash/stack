//! Operators: what a query asks of the server, as a type.
//!
//! A query names an *operator* ([`Eq`](struct@Eq), [`Lt`], [`Lte`],
//! [`Gt`], [`Gte`], [`Between`], [`Matches`](struct@Matches), and the
//! JSON operators [`Contains`], [`ContainedBy`] and [`AtPath`]), and the
//! plan it runs on finds the index that answers it. The operator is a unit
//! type passed by value, as an index is (`.via(Ore)`), and it decides what
//! the query takes: one value for most, a pair of bounds for `Between`, a
//! path and the leaf operator's input for `AtPath`. The JSON operators are
//! answered by the [`Json`](struct@crate::target::Json) index, over a
//! `serde_json::Value`.
//!
//! ```
//! # async fn example() -> Result<(), stack_encrypt::Error> {
//! use stack_encrypt::kms::FakeDataKeySource;
//! use stack_encrypt::{op, Equality, Match, Ore, Plan, StackCipher};
//!
//! let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! let email_plan = Plan::context("users/email")
//!     .with::<String, _>((Equality, Match))
//!     .build()?;
//! let age_plan = Plan::context("users/age").with::<u32, _>(Ore).build()?;
//!
//! let exact = cipher.query(op::Eq, "bob@example.com").on(&email_plan).await?;
//! let search = cipher.query(op::Matches, "bob").on(&email_plan).await?;
//! let under = cipher.query(op::Lt, &40u32).on(&age_plan).await?;
//! let range = cipher.query(op::Between, &(18u32, 65)).on(&age_plan).await?;
//! # let _ = (exact, search, under, range);
//! # Ok(())
//! # }
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
//! ```
//!
//! Three traits connect an operator to an index, and ADR-0009 records why:
//!
//! - [`Supports<Op, In>`] is on an index, for each operator it can answer
//!   and the input `In` the query takes, and names the [`QueryTerm`] it
//!   sends. That term is not the stored term: an equality index sends the
//!   same HMAC it stores, but a match index sends a filter over the query's
//!   value ([`MatchQuery`]), where it stores a filter over the stored value
//!   ([`MatchTerms`]), and an ORE index sends one [`RangeQuery`] for
//!   `Between`, carrying both bounds, where it stores one term per value.
//! - [`Answers<Op, In>`] is on a target type, a domain type such as an EQL
//!   type, and names the index that answers `Op` for it. It is written by
//!   hand per type, because the choice decides what the query term reveals.
//! - [`DefaultIndex<In>`] is on an operator, and names the index a plan that
//!   declares its indexes, rather than a target type, answers it with.
//!
//! What a query takes is the operator's [`Arity`]: [`One`] plaintext, a
//! [`Pair`] of them as a tuple, or for an accessor a path and its leaf
//! operator's input ([`Pathed<A>`](Pathed), where `A` is the leaf's arity).
//! [`Input<A>`] says, for the value a query is given, which plaintext the
//! index is declared over (`S` for `(S, S)`), so the plan's type is checked
//! against it. An input of a `Pathed` arity is a path and the leaf's input,
//! `("$.address.city", "Sydney")`, over the JSON index's document.
//!
//! What the types can see is checked at compile time: a match query on an
//! integer, an ordering on bytes, an operator a target type does not answer,
//! and, on a one-value plan, an index the plan does not hold or a
//! case-sensitive match against a case-folding index. A field of a fields
//! plan is data, so there an index the field does not declare, or declares
//! with other options, is refused when the query is awaited, before any
//! key is requested. So is a match configuration whose [`MatchCase`]
//! disagrees with its options, and so is the one query value the library
//! refuses: match text that cuts no token under the index's tokenizer,
//! whose filter would match every row ([`TermError::EmptyTermText`]). The
//! stored side has no such refusal: a value with no tokens is stored as
//! the empty filter, which no query matches. A `Between` whose low bound is
//! above its high bound is not refused either: as SQL's `BETWEEN`, it
//! matches nothing.
//!
//! [`TermError::EmptyTermText`]: crate::sem::TermError::EmptyTermText
//! [`RangeQuery`]: crate::sem::RangeQuery
//!
//! The module is meant to be used by path (`op::Eq`): an imported `Eq`
//! would shadow the prelude's `Eq` trait.
//!
//! [`MatchQuery`]: crate::sem::MatchQuery
//! [`MatchTerms`]: crate::sem::MatchTerms
use std::fmt;
use std::marker::PhantomData;

use stack_kms::MaybeSend;

pub(crate) mod stats;
pub use stats::{Limit, Stats, DEFAULT_CONFIDENCE, MAX_ROWS};

use crate::sem::{
    DefaultMatch, EqualityTerm, MatchConfig, MatchQuery, MatchTerms, OpeTerm, Orderable,
    OreBlockTerm, OreTerm, QueryTokens, RangeQuery,
};
use crate::target::{DeclaredContext, Equality, Index, Match, Ope, Ore, OreBlock, Owned, Pending};
use crate::{Error, KeysetCipher, Label, NonEmpty, PlanError};

/// A query operator: a unit type naming what a query asks of the server,
/// and how many plaintexts it asks about ([`Arity`]).
///
/// The trait is open, as [`Index`] is: an operator defined in another crate
/// is answered by the indexes that implement [`Supports`] for it.
pub trait Operator: Copy + 'static {
    /// What a query for this operator takes: [`One`] plaintext, a
    /// [`Pair`] of them as a tuple, or for [`AtPath`] a path and its leaf
    /// operator's input ([`Pathed`]).
    type Arity: Arity;
}

/// Equality: rows whose value equals the query's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Eq;

impl Operator for Eq {
    type Arity = One;
}

/// Less than: rows whose value is below the query's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Lt;

/// Less than or equal: rows whose value is at or below the query's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Lte;

/// Greater than: rows whose value is above the query's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Gt;

/// Greater than or equal: rows whose value is at or above the query's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Gte;

/// A range: rows whose value is between the query's two bounds, inclusive
/// at both ends. It takes a [`Pair`], `cipher.query(op::Between, &(lo, hi))`,
/// derives both bounds under one context, and sends them as one term
/// ([`RangeQuery`]), so no statement can pair the
/// low bound of one query with the high bound of another. One value is
/// `(v, v)`. A pair whose low bound is above its high bound is not
/// refused: as SQL's `BETWEEN`, it matches nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Between;

impl Operator for Lt {
    type Arity = One;
}
impl Operator for Lte {
    type Arity = One;
}
impl Operator for Gt {
    type Arity = One;
}
impl Operator for Gte {
    type Arity = One;
}
impl Operator for Between {
    type Arity = Pair;
}

/// JSON containment: rows whose document contains the query's document
/// (`@>`). Exact, as PostgreSQL's own `jsonb @>` is, across array elements
/// included: answered by the [`Json`](struct@crate::target::Json) index with a
/// [`JsonQuery`](crate::json::JsonQuery).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Contains;

/// JSON containment the other way: rows whose document is contained by
/// the query's (`<@`). Exact, and answered by the JSON index, as
/// [`Contains`] is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ContainedBy;

/// The accessor: `Op` applied at a JSON path, `op::AtPath(op::Eq)`. It
/// takes a path and `Op`'s input, and inherits the fidelity of `Op`
/// ([`TermFor`]): `AtPath<Eq>` and `AtPath<Lt>` are exact, and an accessor
/// over a probabilistic leaf operator would be `Probabilistic`.
///
/// `Op` is a [`Leaf`] operator, one that compares a single value at the
/// path: `AtPath<Contains>` and `AtPath<AtPath<Eq>>` are not operators,
/// since neither is one selector and value.
///
/// Its arity is [`Pathed<Op::Arity>`](Pathed), so `AtPath<Eq>` (a path and
/// a value, `("$.address.city", "Sydney")`) and `AtPath<Between>` (a path
/// and a pair of bounds, `("$.score", (10, 20))`) take different inputs.
/// The path is parsed when the query is checked
/// ([`JsonPath`](crate::json::JsonPath)); the JSON index answers `Eq` with
/// containment and the orderings with a leaf term. `AtPath<Matches>` is
/// declared and answered by nothing: the index derives no match term at a
/// leaf.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AtPath<Op>(pub Op);

impl Operator for Contains {
    type Arity = One;
}
impl Operator for ContainedBy {
    type Arity = One;
}
impl<Op: Leaf> Operator for AtPath<Op> {
    type Arity = Pathed<Op::Arity>;
}

/// An operator that compares one value, or one pair of bounds, and so can
/// be applied at a JSON path ([`AtPath`]): [`Eq`](struct@Eq), [`Lt`],
/// [`Lte`], [`Gt`], [`Gte`], [`Between`] and [`Matches`](struct@Matches).
/// Containment compares whole documents and an accessor already has a
/// path, so neither is a leaf.
///
/// The trait is open, as [`Operator`] is, but its arity is [`One`] or
/// [`Pair`] ([`LeafArity`], sealed), so an accessor never nests.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a leaf operator, so it cannot be applied at a path",
    label = "`op::AtPath` takes a leaf operator",
    note = "`op::AtPath` applies `op::Eq`, `Lt`, `Lte`, `Gt`, `Gte`, `Between` or `Matches` at a path; `op::Contains` and `op::ContainedBy` compare whole documents, and an accessor does not nest"
)]
pub trait Leaf: Operator<Arity: LeafArity> {}

impl Leaf for Eq {}
impl Leaf for Lt {}
impl Leaf for Lte {}
impl Leaf for Gt {}
impl Leaf for Gte {}
impl Leaf for Between {}
impl<C: Case> Leaf for Matches<C> {}

/// How many plaintexts a query for an operator takes: [`One`] or a
/// [`Pair`], or for an accessor a path and its leaf's input ([`Pathed`]).
/// Sealed: the chain derives a term per plaintext and joins them as the
/// arity says, so there are exactly these.
pub trait Arity: sealed::Sealed + 'static {}

/// The arity of a [`Leaf`] operator: [`One`] or [`Pair`], never
/// [`Pathed`]. Sealed.
pub trait LeafArity: Arity {}

/// One plaintext: the query is given an `S` (`Eq`, `Lt`, `Matches`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct One;

/// Two plaintexts: the query is given an `(S, S)` (`Between`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Pair;

/// A path and a leaf operator's input, of the leaf's arity `A`: what
/// [`AtPath<Op>`] takes. `Pathed<One>` is a path and a value,
/// `Pathed<Pair>` a path and a pair of bounds, so an input can derive one
/// term or two as the leaf needs. Its [`Input`]s are `(P, V)` and `(P, (V,
/// V))` for any path text `P` and any `V` that converts into a
/// `serde_json::Value`, over the JSON index's document.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Pathed<A>(PhantomData<A>);

impl Arity for One {}
impl Arity for Pair {}
impl<A: LeafArity> Arity for Pathed<A> {}
impl LeafArity for One {}
impl LeafArity for Pair {}

/// What a query of arity `A` is given, and the plaintext its index is
/// declared over: an `S` is an input of [`One`] over `S`, and an `(S, S)`
/// an input of [`Pair`] over `S`. The chain's value type is the input, and
/// the plan is checked against the plaintext.
///
/// A `(P, V)` is an input of [`Pathed<One>`] over a `serde_json::Value`,
/// and a `(P, (V, V))` of [`Pathed<Pair>`]: the path and the value become
/// the document that holds the value at the path, and the JSON index's
/// terms of it. The arity decides how the chain derives terms from the
/// input, which is what [`derive`](Self::derive) does.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not what a query of arity `{A}` takes",
    label = "the operator takes another input",
    note = "an operator of arity `One` takes one value, `op::Between` (arity `Pair`) takes a pair, `&(lo, hi)`, and `op::AtPath` (arity `Pathed`) takes a path and the leaf's input, `&(\"$.a\", value)` or `&(\"$.a\", (lo, hi))`"
)]
pub trait Input<A: Arity>: Sized + 'static {
    /// The plaintext the index is declared over.
    type Plaintext: 'static;
    /// The index's terms for this input: one, or a pair of them.
    type Terms<T: 'static>: 'static;

    /// Derive the index's term for each plaintext of the input under
    /// `label`, as one pending. Only a query chain calls this.
    #[doc(hidden)]
    fn derive<'a, 'p, I, K>(
        self,
        index: &I,
        keyset: &'p KeysetCipher<'a, K>,
        label: Label,
        extend: DeclaredContext,
    ) -> Pending<'p, Self::Terms<I::Term>, K>
    where
        I: Index<Self::Plaintext>,
        K: 'static;
}

impl<S: 'static> Input<One> for S {
    type Plaintext = S;
    type Terms<T: 'static> = T;

    fn derive<'a, 'p, I, K>(
        self,
        index: &I,
        keyset: &'p KeysetCipher<'a, K>,
        label: Label,
        extend: DeclaredContext,
    ) -> Pending<'p, I::Term, K>
    where
        I: Index<S>,
        K: 'static,
    {
        keyset.run(
            index.operation::<K, Owned>().under(NonEmpty::from(label)),
            self,
            extend,
        )
    }
}

/// Both bounds under the one label, settled together.
impl<S: 'static> Input<Pair> for (S, S) {
    type Plaintext = S;
    type Terms<T: 'static> = (T, T);

    fn derive<'a, 'p, I, K>(
        self,
        index: &I,
        keyset: &'p KeysetCipher<'a, K>,
        label: Label,
        extend: DeclaredContext,
    ) -> Pending<'p, (I::Term, I::Term), K>
    where
        I: Index<S>,
        K: 'static,
    {
        let (lo, hi) = self;
        let lo = keyset.run(
            index
                .operation::<K, Owned>()
                .under(NonEmpty::from(label.clone())),
            lo,
            extend.clone(),
        );
        let hi = keyset.run(
            index.operation::<K, Owned>().under(NonEmpty::from(label)),
            hi,
            extend,
        );
        lo.zip(hi)
    }
}

/// A plaintext the ordering operators ([`Lt`], [`Lte`], [`Gt`], [`Gte`],
/// [`Between`]) are answered over: the integers of 16 bits and wider, the
/// floats (`f32` and `f64`), text (`String`), and dates, timestamps and
/// decimals ([`value`](crate::value)). Not `u8` or `i8`, which have no
/// order term ([`Orderable`] says why), as `bool` has none. Each is encoded
/// as its [`Orderable`] target and its terms order as clww-ore orders that
/// encoding: integers as numbers; floats as Postgres's `float8` does,
/// `-0.0` tied with `0.0` and every NaN one value above `+Infinity`, an
/// `f32` as the `f64` it widens to; text by the system ADR-0002's fold,
/// Unicode 16 NFC with case and accents folded, so `Café`, `cafe` and
/// `CAFÉ` tie and `alice` orders before `Zoe` (ADR-0009); dates by day;
/// timestamps by the microsecond, so instants within one microsecond tie;
/// and decimals by value, so `1.5` ties `1.50`.
///
/// Sealed: a type joins only when the order its terms compare in is the
/// one its operators promise, so a type whose terms could order otherwise
/// (a newtype over folded text, say) must not be able to join. A type that
/// meets every other bound is still refused:
///
/// ```compile_fail
/// use stack_encrypt::op::Ordered;
///
/// struct Folded(u32);
///
/// impl Ordered for Folded {} // `Ordered` is sealed
/// ```
///
/// [`Orderable`]: crate::sem::Orderable
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not ordered: the ordering operators are answered over the integers of 16 bits and wider, the floats, text, dates, timestamps and decimals",
    label = "no ordering operator over this type",
    note = "`Lt`, `Lte`, `Gt`, `Gte` and `Between` take `u16` to `u128`, `i16` to `i128`, `f32`, `f64`, a `String`, or a `value::Date`, `value::Timestamp` or `value::Decimal`; a `u8`, an `i8` and a `bool` have no order term"
)]
pub trait Ordered: sealed::Sealed + Orderable {}

macro_rules! ordered {
    ($($ty:ty),+ $(,)?) => {$(
        impl sealed::Sealed for $ty {}
        impl Ordered for $ty {}
    )+};
}
ordered!(
    u16,
    u32,
    u64,
    u128,
    i16,
    i32,
    i64,
    i128,
    f32,
    f64,
    String,
    crate::value::Date,
    crate::value::Timestamp,
    crate::value::Decimal,
);

/// Text search: rows whose text contains the query's tokens, under the
/// match index's tokenizer. Not containment: a Bloom match is order- and
/// multiplicity-insensitive.
///
/// `C` is the case the query is asked in, [`CaseInsensitive`] unless named
/// otherwise. A match index answers only the case its configuration fixes
/// ([`MatchCase`]), so asking a case-folding index for a case-sensitive
/// match is a compile error rather than a query that quietly folds case.
///
/// The value [`Matches`](constant@Matches) is the case-insensitive operator,
/// as `PhantomData` is a value of its type; [`case_sensitive`](Matches::case_sensitive)
/// is the other.
pub struct Matches<C = CaseInsensitive> {
    case: PhantomData<fn() -> C>,
}

/// The case-insensitive text search operator, as a value:
/// `cipher.query(op::Matches, "ali")`.
#[allow(non_upper_case_globals)]
pub const Matches: Matches = Matches::new();

impl<C> Matches<C> {
    /// The operator in the case `C`: `Matches::<CaseSensitive>::new()`.
    pub const fn new() -> Self {
        Self { case: PhantomData }
    }
}

impl Matches {
    /// The case-sensitive text search operator:
    /// `cipher.query(op::Matches.case_sensitive(), "Ali")`. Only a match
    /// index whose configuration does not fold case answers it.
    pub const fn case_sensitive(self) -> Matches<CaseSensitive> {
        Matches::new()
    }
}

// By hand, so `C` (a marker type) need not implement them.
impl<C> Clone for Matches<C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<C> Copy for Matches<C> {}
impl<C> Default for Matches<C> {
    fn default() -> Self {
        Self::new()
    }
}
impl<C> PartialEq for Matches<C> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl<C> std::cmp::Eq for Matches<C> {}
impl<C> std::hash::Hash for Matches<C> {
    fn hash<H: std::hash::Hasher>(&self, _: &mut H) {}
}
impl<C: Case> fmt::Debug for Matches<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Matches<{}>", C::NAME)
    }
}

impl<C: Case> Operator for Matches<C> {
    type Arity = One;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::CaseInsensitive {}
    impl Sealed for super::CaseSensitive {}
    impl Sealed for super::One {}
    impl Sealed for super::Pair {}
    impl<A> Sealed for super::Pathed<A> {}
}

/// The case a text operator is asked in: [`CaseInsensitive`] or
/// [`CaseSensitive`]. Sealed: there are exactly two.
pub trait Case: sealed::Sealed + 'static {
    /// Whether text is lower-cased before it is tokenised.
    const FOLDS: bool;
    /// The case's name, for `Debug`.
    const NAME: &'static str;
}

/// Case-insensitive: text is lower-cased before it is tokenised.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CaseInsensitive;

/// Case-sensitive: text is tokenised as written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CaseSensitive;

impl Case for CaseInsensitive {
    const FOLDS: bool = true;
    const NAME: &'static str = "CaseInsensitive";
}
impl Case for CaseSensitive {
    const FOLDS: bool = false;
    const NAME: &'static str = "CaseSensitive";
}

/// The case a match configuration fixes, as a type, so the operators its
/// index answers are known at compile time.
///
/// `Case::FOLDS` must equal the configuration's
/// [`MatchOptions::downcase`](crate::sem::MatchOptions::downcase): the type
/// cannot see the options, so a query through a configuration whose two
/// disagree is refused when it is awaited, with
/// [`PlanError::MatchCase`]. A configuration
/// that does not implement this can still store match terms, but nothing
/// queries them: [`Matches`](struct@Matches) needs this impl, and there is
/// no index-level query. Implementing it is one line, `type Case =
/// CaseSensitive;` or `type Case = CaseInsensitive;`, matching `downcase`.
pub trait MatchCase: MatchConfig {
    /// The case the configuration's index answers.
    type Case: Case;
}

impl MatchCase for DefaultMatch {
    type Case = CaseInsensitive;
}

/// A value a query sends to the server to compare against stored terms.
///
/// This trait says only that a value is a query term. How far the server's
/// answer can be trusted is said by the traits that refine it: a term that
/// can return false positives says how a row is checked (ADR-0009,
/// decision 4), and one that refines nothing is exact.
pub trait QueryTerm {}

impl QueryTerm for EqualityTerm {}
impl<O> QueryTerm for MatchQuery<O> {}
impl<S: Orderable> QueryTerm for OreTerm<S> {}
impl<S: Orderable> QueryTerm for OpeTerm<S> {}
impl<S: Orderable> QueryTerm for OreBlockTerm<S> {}
impl<T: QueryTerm> QueryTerm for RangeQuery<T> {}

/// A query term whose answer can hold **false positives and no false
/// negatives**: a row the server returns may not match, and a row that
/// matches is always returned.
///
/// [`verify`](Self::verify) is the operator's own meaning, run on a
/// decrypted value: it decides whether a row the server returned is a real
/// match. The library never runs a query, so it cannot drop the false
/// positives itself; a caller filters the decrypted rows with `verify`.
///
/// An exact term does not implement this, so `verify` on one is a compile
/// error rather than a method that is always `true`.
pub trait Probabilistic: QueryTerm {
    /// The decrypted value `verify` reads: the plaintext the index was
    /// declared over, which is not always the value the user wrote.
    type Plaintext: ?Sized;

    /// Whether `value`, a row's decrypted value, really matches the query.
    ///
    /// Infallible: it runs on a value already decrypted and already the type
    /// the index was declared over, so every outcome other than a match is
    /// `false`, never an error.
    fn verify(&self, value: &Self::Plaintext) -> bool;

    /// How many candidate rows to fetch so that, at the confidence `stats`
    /// names, `want` of them [`verify`](Self::verify), when the table holds
    /// that many matches.
    ///
    /// A probabilistic bound, not a guarantee: at 99% confidence one query
    /// in a hundred draws more false positives than it allows for, and the
    /// model assumes a non-matching row shares no token with the query,
    /// which natural text does not honour, so the confidence is nominal.
    /// The candidate count says which case a fetch is in. If the server
    /// returned fewer rows than the limit, the predicate is exhausted, and
    /// fewer than `want` verified rows means fewer than `want` matches. If
    /// it returned exactly the limit and fewer than `want` verified, the
    /// result is a page: carry on from its last row with a cursor.
    fn target_limit(&self, want: u64, stats: &Stats) -> Limit;
}

/// The query terms that may answer the operator `Op`: what
/// [`Supports::Query`] must be.
///
/// Most operators take any [`QueryTerm`]. One whose answer is inherently
/// approximate requires more: a term that answers [`Matches`](struct@Matches) must be
/// [`Probabilistic`], so none of this crate's indexes can claim a text
/// match without saying how its answer is checked.
///
/// The rule binds this crate's terms, through the blanket impls below. A
/// term defined in another crate can implement this for an operator by
/// hand, and coherence lets it; the bound is a guide there, not a proof. An
/// operator defined in another crate states its requirement the same way,
/// one term type at a time.
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot answer `{Op}`",
    label = "this query term does not meet the operator's requirement",
    note = "a term that answers `op::Matches` must implement `op::Probabilistic`"
)]
pub trait TermFor<Op: Operator>: QueryTerm {}

impl<T: QueryTerm> TermFor<Eq> for T {}
impl<T: QueryTerm> TermFor<Lt> for T {}
impl<T: QueryTerm> TermFor<Lte> for T {}
impl<T: QueryTerm> TermFor<Gt> for T {}
impl<T: QueryTerm> TermFor<Gte> for T {}
impl<T: QueryTerm> TermFor<Between> for T {}
impl<T: QueryTerm> TermFor<Contains> for T {}
impl<T: QueryTerm> TermFor<ContainedBy> for T {}
impl<C: Case, T: Probabilistic> TermFor<Matches<C>> for T {}
/// An accessor inherits its leaf's requirement: what answers `Op` at a
/// path is held to what answers `Op`.
impl<Op: Leaf, T: TermFor<Op>> TermFor<AtPath<Op>> for T {}

/// An index that answers the operator `Op` for the input `In`, and the
/// query term it sends for it.
///
/// `In` is what the query is given: the plaintext the index is declared
/// over for an operator of arity [`One`] (`Supports<Eq, S>`), a pair of
/// them for [`Between`] (`Supports<Between, (S, S)>`); [`Input`] relates
/// the two.
///
/// [`Index::Term`] is what the index derives, once per plaintext of the
/// input; [`query`](Self::query) makes the query term from those and from
/// the query's [`Verifier`](Self::Verifier). For an equality index the two
/// are the same HMAC and there is nothing to verify. For a match index they
/// are not: the query is a filter over the query's value, which matches
/// some rows that do not hold the value, so the query keeps that value's
/// tokens to [`verify`](Probabilistic::verify) each decrypted row.
/// For `Between` the two terms of the bounds become one
/// [`RangeQuery`].
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not answer `{Op}` given `{In}`",
    label = "this index cannot answer the operator for this input",
    note = "an equality index answers `op::Eq`; a match index answers `op::Matches` over text, in the case its configuration fixes; an ORE or OPE index answers `op::Lt`, `Lte`, `Gt` and `Gte` over an integer, and `op::Between` over a pair of them"
)]
pub trait Supports<Op: Operator, In: Input<Op::Arity>>: Index<In::Plaintext> {
    /// What this index sends for `Op`.
    type Query: TermFor<Op>;
    /// What the query term keeps of its input so that it can later check a
    /// decrypted row, taken before the input is consumed.
    ///
    /// An exact term checks nothing, so its verifier is `()`. A match
    /// query's is [`crate::sem::QueryTokens`]: `Supports<Matches,
    /// String> for Match` cuts `"alice"` into `ali`, `lic`, `ice`, and
    /// [`MatchQuery::verify`](Probabilistic::verify) passes a row only if
    /// its own text holds all three. The filter cannot give the tokens back,
    /// so without the verifier a Bloom false positive would reach the caller.
    type Verifier: MaybeSend + 'static;
    /// Why this index cannot answer `Op` as configured, or for `input`, if
    /// it cannot: a match index whose [`MatchCase`] disagrees with its
    /// options ([`PlanError::MatchCase`]), a match query of text that cuts
    /// no token ([`TermError::EmptyTermText`](crate::sem::TermError::EmptyTermText)),
    /// whose filter would match every row.
    /// Run when the query is awaited, before any key is requested; an
    /// index that refuses nothing returns `Ok(())`.
    fn check(&self, input: &In) -> Result<(), Error>;
    /// The verifier of the query's `input`.
    fn verifier(&self, input: &In) -> Self::Verifier;
    /// [`check`](Self::check), then [`verifier`](Self::verifier): the query's
    /// verifier of `input`, or why the index refuses it. A query chain
    /// calls this when it derives the term. An index whose check and verifier
    /// do the same work overrides it to do that work once: a match index
    /// tokenises the query's value for both.
    fn admit(&self, input: &In) -> Result<Self::Verifier, Error> {
        self.check(input)?;
        Ok(self.verifier(input))
    }
    /// Why this index cannot answer a query whose terms are derived under
    /// `label`, the plan's or the call's, extended by parts the call gave
    /// (`.extend(..)`) when `extended` is true: for an index whose query term
    /// records the context it was derived under, a context it cannot record.
    /// An EQL query value stores the column it queries, so its index refuses
    /// a label that names no column, and any extension, which the column
    /// cannot hold. Run when the query is awaited, before [`check`](Self::check)
    /// and before any keyset is resolved; every index in this crate takes
    /// any context and returns `Ok(())`.
    fn check_label(&self, _label: &Label, _extended: bool) -> Result<(), Error> {
        Ok(())
    }
    /// The query term, from the verifier and the terms the index derived
    /// for the input's plaintexts. Only a query chain calls this:
    /// `QueryToken` cannot be made outside this crate, so no caller can
    /// pair one query's tokens with another value's filter, or pass a
    /// stored term off as a query.
    ///
    /// The token carries the context the terms were derived under
    /// ([`QueryToken::label`], [`QueryToken::is_extended`]), for a query
    /// term that records it beside its terms. The chain calls this only
    /// after [`check_label`](Self::check_label) accepted that context, so a
    /// term built from it need not refuse it again.
    fn query(
        verifier: Self::Verifier,
        terms: In::Terms<Self::Term>,
        token: QueryToken,
    ) -> Self::Query;
}

/// Proof that [`Supports::query`] is called by a query chain, and the
/// context the query's terms were derived under. Only this crate can make
/// one, so an index in another crate can implement [`Supports`] but no
/// caller can turn a term into a query term by hand, or name a context its
/// terms were not derived under.
#[derive(Debug)]
pub struct QueryToken {
    label: Label,
    extended: bool,
}

impl QueryToken {
    pub(crate) fn new(label: Label, extended: bool) -> Self {
        Self { label, extended }
    }

    /// The label the query's terms were derived under, before any
    /// extension: the plan's or the call's, the context the write used for
    /// the field. It is the whole context exactly when
    /// [`is_extended`](Self::is_extended) is false.
    pub fn label(&self) -> &Label {
        &self.label
    }

    /// Whether the call extended the label by parts of its own
    /// (`.extend(..)`), so the terms were derived under the label followed
    /// by those parts rather than the label alone.
    pub fn is_extended(&self) -> bool {
        self.extended
    }
}

impl<S: crate::Encrypt + 'static> Supports<Eq, S> for Equality {
    type Query = EqualityTerm;
    type Verifier = ();
    fn check(&self, _: &S) -> Result<(), Error> {
        Ok(())
    }
    fn verifier(&self, _: &S) {}
    fn query((): (), term: EqualityTerm, _: QueryToken) -> EqualityTerm {
        term
    }
}

impl<S, O> Supports<Matches<O::Case>, S> for Match<O>
where
    S: AsRef<str> + 'static,
    O: MatchCase,
{
    type Query = MatchQuery<O>;
    type Verifier = QueryTokens;
    fn check(&self, value: &S) -> Result<(), Error> {
        self.admit(value).map(drop)
    }
    fn verifier(&self, value: &S) -> QueryTokens {
        // `admit` refuses text the index cannot normalize, so this is the
        // query's tokens; a query that got here otherwise verifies nothing.
        QueryTokens::of::<O>(value.as_ref()).unwrap_or_default()
    }
    fn admit(&self, value: &S) -> Result<QueryTokens, Error> {
        let folds = O::options().downcase;
        if folds != O::Case::FOLDS {
            return Err(PlanError::MatchCase {
                declared: O::Case::NAME,
                folds,
            }
            .into());
        }
        // Options the index cannot use, checked before the text is
        // tokenised (an n-gram length of zero would otherwise reach the
        // tokenizer), then a query with no tokens, which would match every
        // row: the stored side keeps such a value as the empty filter, the
        // query side refuses it here, before any term is derived.
        Ok(QueryTokens::of_query(value.as_ref(), &O::options())?)
    }
    fn query(tokens: QueryTokens, term: MatchTerms<O>, _: QueryToken) -> MatchQuery<O> {
        MatchQuery::new(term, tokens)
    }
}

/// The ordering operators on the ORE, OPE and block ORE indexes, over the
/// [`Ordered`] types. The query term for a comparison is the index's own
/// term for the value. CLLW ORE's ciphertext has no left half to send
/// alone, so what is sent is what is stored, as for an HMAC. Block ORE's
/// does, but EQL v4's comparator reads the right half of the operand a
/// btree index or `between` passes second, which is the query, so a block
/// ORE query is the full ciphertext too. `Between` sends both bounds'
/// terms as one `RangeQuery`.
macro_rules! orders {
    ($($index:ident => $term:ident),+ $(,)?) => {$(
        orders!(@one $index => $term; Lt, Lte, Gt, Gte);
        impl<S: Ordered> Supports<Between, (S, S)> for $index {
            type Query = RangeQuery<$term<S>>;
            type Verifier = ();
            fn check(&self, _: &(S, S)) -> Result<(), Error> {
                Ok(())
            }
            fn verifier(&self, _: &(S, S)) {}
            fn query((): (), (lo, hi): ($term<S>, $term<S>), _: QueryToken) -> Self::Query {
                RangeQuery::new(lo, hi)
            }
        }
        impl<S: Ordered> Answers<Between, (S, S)> for $term<S> {
            type Via = $index;
        }
    )+};
    (@one $index:ident => $term:ident; $($op:ident),+) => {$(
        impl<S: Ordered> Supports<$op, S> for $index {
            type Query = $term<S>;
            type Verifier = ();
            fn check(&self, _: &S) -> Result<(), Error> {
                Ok(())
            }
            fn verifier(&self, _: &S) {}
            fn query((): (), term: $term<S>, _: QueryToken) -> $term<S> {
                term
            }
        }
        impl<S: Ordered> Answers<$op, S> for $term<S> {
            type Via = $index;
        }
    )+};
}
orders!(Ore => OreTerm, Ope => OpeTerm, OreBlock => OreBlockTerm);

/// The ordering operators default to the ORE index; an OPE or block ORE
/// index is named with `.via(Ope)` or `.via(OreBlock)`.
macro_rules! default_ore {
    ($($op:ident),+ $(,)?) => {$(
        impl<S: Ordered> DefaultIndex<S> for $op {
            type Via = Ore;
        }
    )+};
}
default_ore!(Lt, Lte, Gt, Gte);

impl<S: Ordered> DefaultIndex<(S, S)> for Between {
    type Via = Ore;
}

/// A target type that answers the operator `Op` for the input `In`, and
/// the index it answers it with.
///
/// Written by hand per type: a type with two indexes that both answer an
/// operator chooses the cheaper or the more private, as the indexes in play
/// dictate, and that choice decides what the query term reveals. A type
/// that does not answer an operator has no impl, and the query does not
/// compile.
///
/// To be queried on a typed plan (`Plan::value::<S>().encrypt_into::<T>()`),
/// the type must also implement [`LabelledTarget`], whatever context it is
/// sealed under: an `Answers` impl alone answers no query.
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not answer `{Op}` given `{In}`",
    label = "this target type does not answer the operator",
    note = "a target answers the operators its type implements `Answers` for; `.via(index)` names an index the target declares"
)]
pub trait Answers<Op: Operator, In: Input<Op::Arity>> {
    /// The index that answers `Op` for this type. An index is a unit type,
    /// so its `Default` is the index.
    type Via: Supports<Op, In> + Default;
}

/// A target type whose stored terms were derived under the context a
/// query's label names, so a plan for it
/// (`Plan::value::<S>().encrypt_into::<T>()`) answers the operators its
/// [`Answers`] impls name, with each query derived under the plan's label.
///
/// Implementing it is a claim about the stored values: a query term derived
/// under the label equals the stored term only if the stored term was
/// derived under the same context. This crate's term targets
/// ([`EqualityTerm`], [`MatchTerms`], [`OreTerm`], [`OpeTerm`], and
/// [`Encrypted`](crate::target::Encrypted) or a ciphertext beside one
/// term) are sealed under the caller's context, which is the label. An EQL
/// v4 type is sealed under the column it stores, which a two-segment label
/// names, and its index refuses any other label
/// ([`Supports::check_label`]). A type sealed under a context no label
/// names, such as an integer tenant id, must not implement it: a query on
/// its plan would match nothing, with no error.
///
/// A query on such a plan derives through the index alone and never runs
/// the target's own encryption, so the target need not accept the label as
/// its context: an EQL type, sealed under a column identifier, cannot be
/// encrypted through its plan and is queried through it all the same.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not queried under a plan's label",
    label = "a typed plan for this target type answers no query",
    note = "a target type answers queries on its plan when it implements `op::LabelledTarget`: its stored terms were derived under the context the plan's label names"
)]
pub trait LabelledTarget {}

impl LabelledTarget for EqualityTerm {}
impl<O> LabelledTarget for MatchTerms<O> {}
impl<S: Orderable> LabelledTarget for OreTerm<S> {}
impl<S: Orderable> LabelledTarget for OpeTerm<S> {}
impl<T: LabelledTarget> LabelledTarget for (crate::StackCipherText, T) {}
/// As the terms beside it are: a ciphertext is sealed under the caller's
/// context, so the terms decide whether the label names theirs.
impl<T: LabelledTarget> LabelledTarget for crate::target::Encrypted<T> {}

impl<S: crate::Encrypt + 'static> Answers<Eq, S> for EqualityTerm {
    type Via = Equality;
}

impl<S, O> Answers<Matches<O::Case>, S> for MatchTerms<O>
where
    S: AsRef<str> + 'static,
    O: MatchCase,
{
    type Via = Match<O>;
}

/// A ciphertext with one term beside it, the shape of a `plaintext = ..`
/// record without the struct, answers what its term answers.
impl<Op: Operator, In: Input<Op::Arity>, T: Answers<Op, In>> Answers<Op, In>
    for (crate::StackCipherText, T)
{
    type Via = T::Via;
}

/// A ciphertext with one term, as [`indexed`](crate::target::indexed)
/// produces it, answers what its term answers. One with several terms
/// names the index with `.via(index)`.
impl<Op: Operator, In: Input<Op::Arity>, T: Answers<Op, In>> Answers<Op, In>
    for crate::target::Encrypted<T>
{
    type Via = T::Via;
}

/// The index a plan that declares its indexes answers an operator with:
/// a field of a fields plan, or a one-value plan built `with` indexes.
///
/// A plan that declares a different index for the operator, such as a
/// match index with its own configuration, names it with `.via(index)`.
/// So does a typed field of a fields plan (`encrypt_into::<T, _>(name)`):
/// the field's type is not known where the query is written, so its
/// [`Answers`] impl is not consulted, and a field whose type answers
/// through another index needs `via`.
#[diagnostic::on_unimplemented(
    message = "`{Self}` has no default index given `{In}`",
    label = "no default index answers this operator here",
    note = "`op::Eq` defaults to `Equality`; `op::Matches` defaults to `Match` with the default configuration, which is case-insensitive and over text only; `op::Lt`, `Lte`, `Gt`, `Gte` and `Between` default to `Ore` over an integer, and `Between` takes a pair; name another index, such as `Ope`, with `.via(index)`; `op::Contains`, `op::ContainedBy` and `op::AtPath` default to `Json` over a `serde_json::Value`"
)]
pub trait DefaultIndex<In: Input<Self::Arity>>: Operator {
    /// The index. An index is a unit type, so its `Default` is the index.
    type Via: Supports<Self, In> + Default;
}

impl<S: crate::Encrypt + 'static> DefaultIndex<S> for Eq {
    type Via = Equality;
}

impl<S: AsRef<str> + 'static> DefaultIndex<S> for Matches<<DefaultMatch as MatchCase>::Case> {
    type Via = Match;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_match_configuration_folds_case_as_its_type_says() {
        assert_eq!(
            <DefaultMatch as MatchCase>::Case::FOLDS,
            DefaultMatch::options().downcase
        );
    }

    /// A match index's verifier is the query's tokens: a query built from
    /// it verifies a row that holds them and no other. A query chain takes
    /// them through `admit`, so this is the one test that calls `verifier`.
    #[test]
    fn a_match_verifier_is_the_query_tokens() {
        let index = Match::<DefaultMatch>::default();
        let verifier =
            Supports::<Matches<CaseInsensitive>, String>::verifier(&index, &"alice".to_owned());
        let filter = MatchTerms::<DefaultMatch>::from_positions(vec![1]).expect("in range");
        let query = MatchQuery::new(filter, verifier);
        assert!(Probabilistic::verify(&query, "say hi to Alice"));
        assert!(!Probabilistic::verify(&query, "bob"));
    }

    #[test]
    fn an_operator_is_equal_to_itself() {
        assert_eq!(Matches::<CaseInsensitive>::new(), Matches);
        assert_eq!(Eq, Eq);
    }

    #[test]
    fn an_operator_debugs_with_its_case() {
        assert_eq!(
            format!("{:?}", Matches.case_sensitive()),
            "Matches<CaseSensitive>"
        );
        assert_eq!(format!("{:?}", Eq), "Eq");
        assert_eq!(format!("{:?}", Between), "Between");
        assert_eq!(format!("{:?}", AtPath(Gte)), "AtPath(Gte)");
        assert_eq!(AtPath(Matches.case_sensitive()).0, Matches.case_sensitive());
    }

    /// An accessor is held to its leaf's requirement: an exact term
    /// answers `AtPath<Eq>` and `AtPath<Lt>`, and only a probabilistic one
    /// answers `AtPath<Matches>`. Containment takes any term.
    #[test]
    fn an_accessor_inherits_the_fidelity_of_its_leaf() {
        fn answers<Op: Operator, T: TermFor<Op>>() {}
        answers::<AtPath<Eq>, EqualityTerm>();
        answers::<AtPath<Lt>, OreTerm<u32>>();
        answers::<AtPath<Between>, RangeQuery<OpeTerm<i64>>>();
        answers::<AtPath<Matches>, MatchQuery>();
        answers::<Contains, EqualityTerm>();
        answers::<ContainedBy, EqualityTerm>();
        // `answers::<AtPath<Matches>, EqualityTerm>()` does not compile:
        // `tests/ui/op_at_path_inherits_fidelity.rs`. Nor does an accessor
        // over a non-leaf: `tests/ui/op_at_path_not_a_leaf.rs`.
    }

    /// An accessor's arity carries its leaf's, so an input can tell a path
    /// and a value from a path and a pair of bounds.
    #[test]
    fn an_accessor_takes_its_leafs_arity_under_a_path() {
        fn arity<Op: Operator<Arity = A>, A: Arity>() {}
        arity::<AtPath<Eq>, Pathed<One>>();
        arity::<AtPath<Matches>, Pathed<One>>();
        arity::<AtPath<Between>, Pathed<Pair>>();
    }

    /// An ordering refuses no value: a range whose bounds are the wrong way
    /// round matches nothing, as SQL's `BETWEEN` does.
    #[test]
    fn an_ordering_refuses_no_value() {
        let ok = |pair: (u32, u32)| Supports::<Between, (u32, u32)>::check(&Ore, &pair).is_ok();
        assert!(ok((1, 2)));
        assert!(ok((2, 2)));
        assert!(ok((3, 2)));
        assert!(Supports::<Between, (i64, i64)>::check(&Ope, &(1, -1)).is_ok());
        assert!(Supports::<Lt, u16>::check(&Ore, &7).is_ok());
        assert!(Supports::<Gte, i128>::check(&Ope, &-7).is_ok());
    }

    /// A date, a timestamp and a decimal are ordered, through every order
    /// index, and `Between` takes a pair of each.
    #[test]
    fn dates_timestamps_and_decimals_are_ordered() {
        use crate::value::{Date, Decimal, Timestamp};
        fn answers<Op: Operator, T: TermFor<Op>>() {}
        answers::<Lt, OreTerm<Date>>();
        answers::<Gte, OpeTerm<Timestamp>>();
        answers::<Between, RangeQuery<OreTerm<Decimal>>>();
        let day = || Date::from_days_since_epoch(19_782).expect("in range");
        let at = || Timestamp::new(1_700_000_000, 5).expect("in range");
        let price = || Decimal::new(150, 2).expect("in range");
        assert!(Supports::<Lt, Date>::check(&Ore, &day()).is_ok());
        assert!(Supports::<Lte, Timestamp>::check(&Ope, &at()).is_ok());
        assert!(Supports::<Gt, Decimal>::check(&OreBlock, &price()).is_ok());
        assert!(Supports::<Between, (Date, Date)>::check(&Ore, &(day(), day())).is_ok());
    }
}
