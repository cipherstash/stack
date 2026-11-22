//! Querying an EQL v4 field from Rust, through a field reference.
//!
//! A typed query of an EQL type starts from a field of a derived record.
//! `#[derive(EncryptTarget)]` on a `struct = ..` record gives each field a
//! field reference, an associated constant named after the field
//! ([`stack_encrypt::field_reference`]). The field reference has a method for each operator
//! the field's type answers:
//! `EncryptedMember::EMAIL.eq("bob@example.com").encrypt(&keyset)`. An EQL
//! v4 type says which operators it answers through its [`op::Answers`]
//! impls, and the term that comes back is the type's *query twin*: the
//! value of the `eql_v4.query_*` domain the SQL compares against the
//! column.
//!
//! | type | field reference method | operator | query term |
//! |---|---|---|---|
//! | `TextEq` | `eq` | [`op::Eq`](struct@op::Eq) | `TextEqQuery` |
//! | `SmallintEq` | `eq` | [`op::Eq`](struct@op::Eq) | `SmallintEqQuery` |
//! | `IntegerEq` | `eq` | [`op::Eq`](struct@op::Eq) | `IntegerEqQuery` |
//! | `BigintEq` | `eq` | [`op::Eq`](struct@op::Eq) | `BigintEqQuery` |
//! | `RealEq` | `eq` | [`op::Eq`](struct@op::Eq) | `RealEqQuery` |
//! | `DoubleEq` | `eq` | [`op::Eq`](struct@op::Eq) | `DoubleEqQuery` |
//! | `DateEq` | `eq` | [`op::Eq`](struct@op::Eq) | `DateEqQuery` |
//! | `TimestampEq` | `eq` | [`op::Eq`](struct@op::Eq) | `TimestampEqQuery` |
//! | `NumericEq` | `eq` | [`op::Eq`](struct@op::Eq) | `NumericEqQuery` |
//! | `TextMatch` | `matches` | [`op::Matches`](struct@op::Matches) | [`MatchTwin<TextMatchQuery>`](MatchTwin) |
//! | `SmallintOrd`, `IntegerOrd`, `BigintOrd`, `RealOrd`, `DoubleOrd`, `DateOrd`, `TimestampOrd`, `NumericOrd`, and each `…OrdOpe` and `…OrdOre` | `lt`, `lte`, `gt`, `gte` | [`op::Lt`], [`op::Lte`], [`op::Gt`], [`op::Gte`] | `IntegerOrdQuery`, … |
//! | `TextOrd`, `TextOrdOpe`, `TextOrdOre` | `eq`, `lt`, `lte`, `gt`, `gte` | [`op::Eq`](struct@op::Eq) and the orderings | `TextOrdQuery`, `TextOrdOpeQuery`, `TextOrdOreQuery` |
//! | `TextSearch`, `TextSearchOre` | `eq`, `lt`, `lte`, `gt`, `gte`, `matches` | [`op::Eq`](struct@op::Eq), the orderings and [`op::Matches`](struct@op::Matches) | `TextSearchQuery`, `TextSearchOreQuery`; [`MatchTwin`] of one for `matches` |
//!
//! eql-codegen writes those impls from the catalog, by the rule Stack
//! Encrypt's data path answers an EQL type's operators with: `Eq` through
//! the equality index, `Matches` through the match index, and the orderings
//! through the type's order index (OPE or block ORE). Each type is also an
//! [`op::LabelledTarget`], which is what lets its field reference be
//! queried. An operator a type does not answer does not compile: no EQL
//! type answers [`op::Between`] from a field reference, as the data path
//! answers no `between` on an EQL type. A field reference names its
//! field's type and no index, so a query cannot send another index's term
//! in place of the type's twin.
//!
//! The twin carries what the type's query domain requires, as the data
//! path's does. The twin of an ordered type other than text carries its one
//! order term. A `TextOrd` twin carries the equality term and the order
//! term whatever the operator, since `eql_v4.query_text_ord` requires both:
//! the query derives the two terms for the one value, and is refused,
//! before any key is requested, for text either index refuses. A text
//! search twin's terms are optional, so its query carries the term of the
//! index that answers the operator alone.
//!
//! The query is derived under the field reference's label: the record's scope, then
//! the field's name (or its `identity`). That is the column the field
//! stores in `i`, so a reference to the field `email` of a record with
//! `scope = "users"` queries the values written under
//! `Identifier::for_column("users", "email")`, by the record or by the
//! type on its own. A field reference's label always has those two segments, so it
//! always names a column. The derive accepts only plain segments
//! ([`Label`]): none may start with a digit or `-`, for instance, though
//! `Identifier::for_column` takes such a name. A column whose table or
//! column name is not a plain segment can be written by the type on its
//! own, but it cannot be a record field, so it cannot be queried this way.
//!
//! A record can list a scope, such as a tenant. A query from its field reference
//! then takes the scope with `.scope(..)` before it can be encrypted. Its
//! term is derived under the column and the scope, and matches the values
//! the record stored under the same scope. The twin stores the column
//! alone, as the stored value does: a scope is never stored in `i`.
//!
//! The query is the bytes Stack Encrypt's data path derives for a field
//! that names the same type (`stack_encrypt::dynamic::query_term`), which
//! is what the Go SDK sends.
//!
//! # Example
//!
//! The code below is executed by `cargo test -p eql-encryption-tests --test
//! query_example`, for the reason the [encryption example](super#example)
//! gives. It derives `zeroize::Zeroize` for its plaintext struct, so it
//! also needs `zeroize` with its `derive` feature.
#![doc = concat!("```rust,ignore\n", include_str!("query_example.rs"), "\n```")]
//!
//! # Operators a type does not answer
//!
//! A `TextEq` field answers `eq`:
//! ```
//! use eql_bindings::v4::text::TextEq;
//! use stack_encrypt::EncryptTarget;
//! use zeroize::Zeroize;
//!
//! #[derive(Zeroize)]
//! struct User {
//!     email: String,
//! }
//!
//! #[derive(EncryptTarget)]
//! #[stash(struct = User, scope = "users")]
//! struct EncryptedUser {
//!     email: TextEq,
//! }
//!
//! let _ = EncryptedUser::EMAIL.eq("bob");
//! ```
//! and no ordering, since `TextEq` carries no order term:
//! ```compile_fail
//! use eql_bindings::v4::text::TextEq;
//! use stack_encrypt::EncryptTarget;
//! use zeroize::Zeroize;
//!
//! #[derive(Zeroize)]
//! struct User {
//!     email: String,
//! }
//!
//! #[derive(EncryptTarget)]
//! #[stash(struct = User, scope = "users")]
//! struct EncryptedUser {
//!     email: TextEq,
//! }
//!
//! let _ = EncryptedUser::EMAIL.lt("bob");
//! ```
//! An `IntegerEq` field answers `eq`:
//! ```
//! use eql_bindings::v4::integer::IntegerEq;
//! use stack_encrypt::EncryptTarget;
//! use zeroize::Zeroize;
//!
//! #[derive(Zeroize)]
//! struct User {
//!     age: i32,
//! }
//!
//! #[derive(EncryptTarget)]
//! #[stash(struct = User, scope = "users")]
//! struct EncryptedUser {
//!     age: IntegerEq,
//! }
//!
//! let _ = EncryptedUser::AGE.eq(42i32);
//! ```
//! and no text match:
//! ```compile_fail
//! use eql_bindings::v4::integer::IntegerEq;
//! use stack_encrypt::EncryptTarget;
//! use zeroize::Zeroize;
//!
//! #[derive(Zeroize)]
//! struct User {
//!     age: i32,
//! }
//!
//! #[derive(EncryptTarget)]
//! #[stash(struct = User, scope = "users")]
//! struct EncryptedUser {
//!     age: IntegerEq,
//! }
//!
//! let _ = EncryptedUser::AGE.matches("42");
//! ```
//! An `IntegerOrd` field answers the orderings:
//! ```
//! use eql_bindings::v4::integer::IntegerOrd;
//! use stack_encrypt::EncryptTarget;
//! use zeroize::Zeroize;
//!
//! #[derive(Zeroize)]
//! struct User {
//!     age: i32,
//! }
//!
//! #[derive(EncryptTarget)]
//! #[stash(struct = User, scope = "users")]
//! struct EncryptedUser {
//!     age: IntegerOrd,
//! }
//!
//! let _ = EncryptedUser::AGE.gt(30i32);
//! let _ = EncryptedUser::AGE.lte(65i32);
//! ```
//! and no `eq`, since `IntegerOrd` carries no equality term:
//! ```compile_fail
//! use eql_bindings::v4::integer::IntegerOrd;
//! use stack_encrypt::EncryptTarget;
//! use zeroize::Zeroize;
//!
//! #[derive(Zeroize)]
//! struct User {
//!     age: i32,
//! }
//!
//! #[derive(EncryptTarget)]
//! #[stash(struct = User, scope = "users")]
//! struct EncryptedUser {
//!     age: IntegerOrd,
//! }
//!
//! let _ = EncryptedUser::AGE.eq(42i32);
//! ```
//! nor `between`. A range query sends both bounds in one operand, and a
//! field reference cannot build that operand yet:
//! ```compile_fail
//! use eql_bindings::v4::integer::IntegerOrd;
//! use stack_encrypt::EncryptTarget;
//! use zeroize::Zeroize;
//!
//! #[derive(Zeroize)]
//! struct User {
//!     age: i32,
//! }
//!
//! #[derive(EncryptTarget)]
//! #[stash(struct = User, scope = "users")]
//! struct EncryptedUser {
//!     age: IntegerOrd,
//! }
//!
//! let _ = EncryptedUser::AGE.between(18i32, 65i32);
//! ```
//! The index a type answers through is a [`TwinIndex`]. It answers for its
//! twin's own plaintext only ([`QueryTwin::Plaintext`]): `TextEqQuery`'s
//! for a `String`,
//! ```
//! use eql_bindings::encryption::query::TwinIndex;
//! use eql_bindings::v4::text::TextEqQuery;
//! use stack_encrypt::{op, Equality};
//! fn answers<I: op::Supports<op::Eq, String>>() {}
//! answers::<TwinIndex<Equality, TextEqQuery>>();
//! ```
//! and not `IntegerEqQuery`'s, whose plaintext is an `i32`:
//! ```compile_fail
//! use eql_bindings::encryption::query::TwinIndex;
//! use eql_bindings::v4::integer::IntegerEqQuery;
//! use stack_encrypt::{op, Equality};
//! fn answers<I: op::Supports<op::Eq, String>>() {}
//! answers::<TwinIndex<Equality, IntegerEqQuery>>();
//! ```
//! A `TextMatch` query verifies a row; a `TextEq` query is exact, so it has
//! nothing to verify and no `verify`:
//! ```compile_fail
//! use eql_bindings::v4::text::TextEqQuery;
//! use stack_encrypt::op::Probabilistic;
//! fn rows(query: &TextEqQuery) -> bool {
//!     query.verify("bob")
//! }
//! ```
//!
//! [`op::Answers`]: stack_encrypt::op::Answers
//! [`op::LabelledTarget`]: stack_encrypt::op::LabelledTarget

use std::fmt;
use std::marker::PhantomData;

use serde::{Serialize, Serializer};
use stack_encrypt::kms::MaybeSend;
use stack_encrypt::op::{self, Limit, Probabilistic, QueryTerm, QueryToken, Stats, Supports};
use stack_encrypt::sem::{EqualityTerm, MatchQuery, MatchTerms, QueryTokens};
use stack_encrypt::target::{CallerContext, Encryption, Index, IndexSpec, Indexes, WipeSource};
use stack_encrypt::{Encrypt, EncryptRef, Equality, Error, Label, Match, NonEmpty, Orderable};
use zeroize::Zeroize;

use super::{bloom_filter, hmac256, EqlMatch};
use crate::v3::terms::Hmac256;
use crate::v4::terms::QueryBloomFilter;
use crate::Identifier;

/// An EQL v4 query twin, assembled from the column it queries and the
/// terms `T` its type's indexes derived for the query's value, as EQL
/// stores them. eql-codegen implements it for the twin of every type that
/// answers an operator, with the version every v4 value carries:
/// [`TextEqQuery`] from an [`Hmac256`], [`TextMatchQuery`] from a
/// [`QueryBloomFilter`], `IntegerOrdQuery` from an
/// [`OpeTerm<i32>`](stack_encrypt::sem::OpeTerm), and
/// [`TextOrdQuery`] from the pair `(Hmac256, OpeTerm<String>)`, its terms in
/// catalog order. A twin whose terms are optional, such as
/// `TextSearchQuery`, implements it once per term, each assembling that
/// term alone.
///
/// [`TextEqQuery`]: crate::v4::text::TextEqQuery
/// [`TextMatchQuery`]: crate::v4::text::TextMatchQuery
/// [`TextOrdQuery`]: crate::v4::text::TextOrdQuery
pub trait QueryTwin<T>: Sized {
    /// The plaintext the twin's type is produced from: `String` for
    /// `TextEqQuery`, `i32` for `IntegerEqQuery`. A [`TwinIndex`] answers
    /// for this plaintext only, so no query can send one type's twin for
    /// another type's value.
    type Plaintext;
    /// The twin of `terms`, derived under `column`.
    fn assemble(column: Identifier, terms: T) -> Self;
}

/// The index an EQL v4 type answers an operator through: Stack Encrypt's
/// index `I`, whose query is sent as the type's query twin `Q`, built from
/// the terms of the indexes `D`.
///
/// `D` is the indexes whose terms the twin carries. It is `I` alone for a
/// twin that carries one term (`TextEqQuery`, `IntegerOrdQuery`) or whose
/// terms are optional (`TextSearchQuery`), and every index of the type, in
/// catalog order, for a twin that carries them all whatever the operator:
/// `TextOrd` answers [`op::Lt`] through
/// `TwinIndex<Ope, TextOrdQuery, (Equality, Ope)>`, and [`op::Eq`](struct@op::Eq) through
/// `TwinIndex<Equality, TextOrdQuery, (Equality, Ope)>`.
///
/// It derives the terms of `D`, under the label of the field's field
/// reference and any scope the query carries. Before any key is requested
/// it refuses what each index of `D` refuses for the value, as the data
/// path does, and a label that names no column; it then writes the terms
/// into the twin, with the column the label names. It is declared as
/// `I` is ([`Index::spec`]). It answers for the twin's own plaintext
/// ([`QueryTwin::Plaintext`]) only. `TextEq` answers [`op::Eq`](struct@op::Eq) through
/// `TwinIndex<Equality, TextEqQuery>`, `IntegerOrd` answers [`op::Gt`]
/// through `TwinIndex<Ope, IntegerOrdQuery>`, and `TextMatch` answers
/// [`op::Matches`](struct@op::Matches) through
/// `TwinIndex<Match<EqlMatch>, TextMatchQuery>`.
pub struct TwinIndex<I, Q, D = I> {
    index: I,
    terms: D,
    twin: PhantomData<fn() -> Q>,
}

impl<I: Default, Q, D: Default> Default for TwinIndex<I, Q, D> {
    fn default() -> Self {
        Self {
            index: I::default(),
            terms: D::default(),
            twin: PhantomData,
        }
    }
}

impl<I: Clone, Q, D: Clone> Clone for TwinIndex<I, Q, D> {
    fn clone(&self) -> Self {
        Self {
            index: self.index.clone(),
            terms: self.terms.clone(),
            twin: PhantomData,
        }
    }
}

impl<I: fmt::Debug, Q, D: fmt::Debug> fmt::Debug for TwinIndex<I, Q, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TwinIndex")
            .field("index", &self.index)
            .field("terms", &self.terms)
            .field("twin", &std::any::type_name::<Q>())
            .finish()
    }
}

/// Declared as `I` is, so it is the index that answers the operator, and
/// derives the terms of `D` for one value, under one context: `I`'s term
/// alone when `D` is `I`. A query derives each index's query term
/// ([`Indexes::query_operations`]), so a match term is the filter of the
/// tokens the query keeps, as `I`'s own query is.
impl<S, I: Index<S>, Q, D: Indexes<S>> Index<S> for TwinIndex<I, Q, D> {
    type Term = D::Terms;
    fn spec(&self) -> IndexSpec {
        self.index.spec()
    }
    fn operation<'s, K: 'static, M: WipeSource<'s, S>>(
        &self,
    ) -> Encryption<'s, S, Self::Term, K, CallerContext, M>
    where
        S: 's,
    {
        self.terms.operations()
    }
    fn query_operation<'s, K: 'static, M: WipeSource<'s, S>>(
        &self,
    ) -> Encryption<'s, S, Self::Term, K, CallerContext, M>
    where
        S: 's,
    {
        self.terms.query_operations()
    }
}

/// Refuse a label no EQL query value can record: one that names no column
/// (it must be two segments, table then column). Before any term is
/// derived.
///
/// A scope the query carries is not refused. The twin stores the column
/// alone, and so does a value a record stored under that scope: the scope
/// is in the term, and in neither `i`.
fn check_column(label: &Label) -> Result<(), Error> {
    if Identifier::column_of(label).is_none() {
        return Err(Error::Other(Box::new(QueryLabelError::NotAColumn {
            label: label.to_string(),
        })));
    }
    Ok(())
}

/// Why a typed query on an EQL v4 type was refused for its context, before
/// any term was derived. It arrives as [`Error::Other`]; match it with
/// `downcast_ref::<QueryLabelError>()`.
///
/// The label of a derived record's field reference is the record's scope and
/// the field's name, two segments, so a query from such a field reference is never
/// refused this way.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum QueryLabelError {
    /// The label names no column: an EQL query value stores the
    /// [`Identifier`] it queries, a two-segment label, table then column.
    /// The data path refuses the same label as `TargetError::Context`.
    NotAColumn {
        /// The label, rendered.
        label: String,
    },
}

impl fmt::Display for QueryLabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAColumn { label } => write!(
                f,
                "{label:?} is not an EQL column identifier: expected two segments, table and column"
            ),
        }
    }
}

impl std::error::Error for QueryLabelError {}

/// The column a query's label names. A field query calls `query` only
/// after `check_label` accepted the label (`Supports::query`), and every
/// `Supports` impl here delegates `check_label` to [`check_column`], so the
/// label is two segments; a label that is not would be a broken invariant,
/// and fails here rather than as a twin with an empty column.
fn column(token: &QueryToken) -> Identifier {
    Identifier::column_of(token.label())
        .map(NonEmpty::into_inner)
        .expect("check_label accepted the query's label as a column before any term was derived")
}

/// Equality: the twin's `hm` is the HMAC the equality index derives, hex
/// encoded as the stored value's is, so the twin equals the stored value's
/// term under the same column. Only for the plaintext the twin's type is
/// produced from.
impl<Q> Supports<op::Eq, Q::Plaintext> for TwinIndex<Equality, Q>
where
    Q: QueryTwin<Hmac256> + QueryTerm + MaybeSend + 'static,
    Q::Plaintext: Encrypt + EncryptRef + Zeroize + 'static,
{
    type Query = Q;
    type Verifier = ();
    fn prepare(&self, value: &Q::Plaintext) -> Result<(), Error> {
        Supports::<op::Eq, Q::Plaintext>::prepare(&self.index, value)
    }
    fn check_label(&self, label: &Label, _extended: bool) -> Result<(), Error> {
        check_column(label)
    }
    fn query((): (), term: EqualityTerm, token: QueryToken) -> Q {
        Q::assemble(column(&token), hmac256(&term))
    }
}

/// Equality on a twin that carries an order term beside its `hm`
/// (`TextOrdQuery`, from `(Equality, O)`): the HMAC the equality index
/// derives, hex encoded as the stored value's is, and the term the order
/// index `O` derives for the same value, under the same context,
/// since the type's query domain requires both. Refuses what the equality
/// index refuses, then what `O` refuses, as the data path does for `=` on a
/// field that names the type: the query derives both terms. An order index
/// refuses the same values for every ordering, so its `Lt` stands for
/// them. Only for the plaintext the twin's type is produced from.
impl<Q, O, P> Supports<op::Eq, P> for TwinIndex<Equality, Q, (Equality, O)>
where
    O: Supports<op::Lt, P, Verifier = ()> + Index<P>,
    Q: QueryTwin<(Hmac256, <O as Index<P>>::Term), Plaintext = P> + QueryTerm + MaybeSend + 'static,
    P: Orderable + Encrypt + EncryptRef + Zeroize + 'static,
{
    type Query = Q;
    type Verifier = ();
    fn prepare(&self, value: &P) -> Result<(), Error> {
        let (equality, order) = &self.terms;
        Supports::<op::Eq, P>::prepare(equality, value)?;
        Supports::<op::Lt, P>::prepare(order, value)
    }
    fn check_label(&self, label: &Label, _extended: bool) -> Result<(), Error> {
        check_column(label)
    }
    fn query(
        (): (),
        (equality, order): (EqualityTerm, <O as Index<P>>::Term),
        token: QueryToken,
    ) -> Q {
        Q::assemble(column(&token), (hmac256(&equality), order))
    }
}

// The orderings, through an order index `O` (OPE or block ORE): on a twin
// that carries `O`'s term alone (`IntegerOrdQuery` from an `OpeTerm<i32>`),
// and on one that carries an `hm` beside it (`TextOrdQuery`, from
// `(Equality, O)`), as the pair's equality impl does. The term is the one
// `O` sends for the operator, which is what it stores, so the twin compares
// against the stored value's term under the same column. Refuses what `O`
// refuses for the operator; on the pair, what the equality index refuses
// first, since the query derives both terms. Only for the plaintext the
// twin's type is produced from.
macro_rules! twin_orderings {
    ($($operator:ident),+ $(,)?) => {$(
        #[doc = concat!("`op::", stringify!($operator), "` on a twin that carries the order index's term alone.")]
        impl<Q, O, P> Supports<op::$operator, P> for TwinIndex<O, Q>
        where
            O: Supports<op::$operator, P, Verifier = ()> + Indexes<P>,
            Q: QueryTwin<<O as Indexes<P>>::Terms, Plaintext = P> + QueryTerm + MaybeSend + 'static,
            P: Orderable + Zeroize + 'static,
        {
            type Query = Q;
            type Verifier = ();
            fn prepare(&self, value: &P) -> Result<(), Error> {
                Supports::<op::$operator, P>::prepare(&self.index, value)
            }
            fn check_label(&self, label: &Label, _extended: bool) -> Result<(), Error> {
                check_column(label)
            }
            fn query(
                (): (),
                order: <O as Indexes<P>>::Terms,
                token: QueryToken,
            ) -> Q {
                Q::assemble(column(&token), order)
            }
        }

        #[doc = concat!("`op::", stringify!($operator), "` on a twin that carries an `hm` beside the order index's term.")]
        impl<Q, O, P> Supports<op::$operator, P> for TwinIndex<O, Q, (Equality, O)>
        where
            O: Supports<op::$operator, P, Verifier = ()> + Index<P>,
            Q: QueryTwin<(Hmac256, <O as Index<P>>::Term), Plaintext = P>
                + QueryTerm
                + MaybeSend
                + 'static,
            P: Orderable + Encrypt + EncryptRef + Zeroize + 'static,
        {
            type Query = Q;
            type Verifier = ();
            fn prepare(&self, value: &P) -> Result<(), Error> {
                let (equality, order) = &self.terms;
                Supports::<op::Eq, P>::prepare(equality, value)?;
                Supports::<op::$operator, P>::prepare(order, value)
            }
            fn check_label(&self, label: &Label, _extended: bool) -> Result<(), Error> {
                check_column(label)
            }
            fn query(
                (): (),
                (equality, order): (EqualityTerm, <O as Index<P>>::Term),
                token: QueryToken,
            ) -> Q {
                Q::assemble(column(&token), (hmac256(&equality), order))
            }
        }
    )+};
}
twin_orderings!(Lt, Lte, Gt, Gte);

/// Text match: the twin's `bf` is the filter EQL's match index derives
/// over the tokens the query keeps (its two-letter words only when it cuts
/// no 3-gram, [`QueryBloomFilter`]), and the query keeps those tokens to
/// [`verify`](Probabilistic::verify) each decrypted row, as Stack Encrypt's
/// `MatchQuery` does. A query whose text cuts no token is refused before
/// any term exists. Only for the plaintext the twin's type is produced
/// from.
impl<Q> Supports<op::Matches, Q::Plaintext> for TwinIndex<Match<EqlMatch>, Q>
where
    Q: QueryTwin<QueryBloomFilter> + MaybeSend + 'static,
    Q::Plaintext: AsRef<str> + Zeroize + 'static,
{
    type Query = MatchTwin<Q>;
    type Verifier = QueryTokens;
    fn prepare(&self, value: &Q::Plaintext) -> Result<QueryTokens, Error> {
        Supports::<op::Matches, Q::Plaintext>::prepare(&self.index, value)
    }
    fn check_label(&self, label: &Label, _extended: bool) -> Result<(), Error> {
        check_column(label)
    }
    fn query(tokens: QueryTokens, terms: MatchTerms<EqlMatch>, token: QueryToken) -> MatchTwin<Q> {
        let column = column(&token);
        let query =
            <Match<EqlMatch> as Supports<op::Matches, Q::Plaintext>>::query(tokens, terms, token);
        // `EqlMatch`'s filter is 2048 bits, so every position fits a
        // smallint (`the_match_configuration_is_pinned`); and `prepare`
        // refused a query with no tokens, so the filter is not empty.
        let bf = bloom_filter(query.positions())
            .expect("EqlMatch's 2048-bit filter keeps every position within a smallint");
        MatchTwin {
            twin: Q::assemble(column, QueryBloomFilter(bf)),
            query,
        }
    }
}

/// A text match query on an EQL v4 type: the type's query twin `Q`, which
/// is what the SQL binds, and the query's tokens, which decide whether a
/// row the server returned is a real match.
///
/// A Bloom filter can hold every bit of the query without the value holding
/// the query's text, so the server's answer can include rows that do not
/// match, and never misses one that does. [`verify`](Probabilistic::verify)
/// checks a decrypted value against the query's tokens, under EQL's match
/// configuration ([`EqlMatch`]), and
/// [`target_limit`](Probabilistic::target_limit) says how many rows to fetch
/// to expect a number of real matches. Both answer exactly as Stack
/// Encrypt's data path answers for the same query (`dynamic::verify` and
/// `dynamic::target_limit`).
///
/// It serializes as the twin, so it binds as one: `sqlx::types::Json(&query)`
/// with `$1::eql_v4.query_text_match`. The tokens are plaintext: they are
/// never serialized, never appear in `Debug`, and are zeroized when the
/// query is dropped.
#[derive(Clone, Debug, PartialEq)]
pub struct MatchTwin<Q> {
    twin: Q,
    query: MatchQuery<EqlMatch>,
}

impl<Q> MatchTwin<Q> {
    /// The query twin, to bind.
    pub fn twin(&self) -> &Q {
        &self.twin
    }

    /// The query twin, without the tokens that verify rows.
    pub fn into_twin(self) -> Q {
        self.twin
    }
}

impl<Q> QueryTerm for MatchTwin<Q> {}

impl<Q> Probabilistic for MatchTwin<Q> {
    type Plaintext = str;

    fn verify(&self, value: &str) -> bool {
        self.query.verify(value)
    }

    fn target_limit(&self, want: u64, stats: &Stats) -> Limit {
        self.query.target_limit(want, stats)
    }
}

/// The twin alone: what the server compares.
impl<Q: Serialize> Serialize for MatchTwin<Q> {
    fn serialize<Ser: Serializer>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error> {
        self.twin.serialize(serializer)
    }
}
