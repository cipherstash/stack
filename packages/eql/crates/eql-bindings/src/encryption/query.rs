//! Querying an EQL v4 field through Stack Encrypt's typed query chain.
//!
//! A query names an operator, and the plan it runs on finds the index that
//! answers it (Stack Encrypt's ADR-0009):
//! `cipher.query(op::Eq, "bob@example.com").on(&plan)`. On a plan built for
//! an EQL v4 type, `Plan::value::<String>().encrypt_into::<TextEq>()`, the
//! type says which operators it answers through its
//! [`op::Answers`] impls, and the term that comes back is the type's
//! *query twin*: the value of the `eql_v4.query_*` domain the SQL compares
//! against the column.
//!
//! | type | operator | query term |
//! |---|---|---|
//! | `TextEq` | [`op::Eq`](struct@op::Eq) | `TextEqQuery` |
//! | `IntegerEq` | [`op::Eq`](struct@op::Eq) | `IntegerEqQuery` |
//! | `BigintEq` | [`op::Eq`](struct@op::Eq) | `BigintEqQuery` |
//! | `RealEq` | [`op::Eq`](struct@op::Eq) | `RealEqQuery` |
//! | `DoubleEq` | [`op::Eq`](struct@op::Eq) | `DoubleEqQuery` |
//! | `TextMatch` | [`op::Matches`](struct@op::Matches) | [`MatchTwin<TextMatchQuery>`](MatchTwin) |
//!
//! eql-codegen writes those impls from the catalog, by the rule Stack
//! Encrypt's data path answers an EQL type's operators with: `Eq` through
//! the equality index, `Matches` through the match index. Each type is also
//! an [`op::LabelledTarget`], which is what lets its plan be queried. The
//! ordered types (`IntegerOrdOre`, `TextOrd` and the rest) are not produced
//! yet, so they answer nothing. An operator a type does not answer does not
//! compile, and neither does naming another index with `.via(..)`: the
//! plan sends the type's twin or nothing.
//!
//! The query is derived under the plan's label, which must name the column
//! the value was written under: a two-segment label, table then column, is
//! the [`Identifier`] the value stores, so
//! `"users/email"` queries values written with
//! `Identifier::for_column("users", "email")`. A label's segments are plain
//! ([`Label`]): none may start with a digit or `-`, for
//! instance, though `Identifier::for_column` takes such a name. A column
//! whose table or column name is not a plain segment can be written but
//! not named on a plan, so it cannot be queried this way. A label of any other length
//! names no column, and a query extended with `.extend(..)` is derived under
//! more than the column the twin stores, so the awaited query refuses both,
//! before any keyset is resolved or term derived.
//!
//! The plan is for queries. Stack Encrypt runs a plan's encryption under
//! the label, and an EQL type is sealed under its column instead, so write
//! with `keyset.encrypt_as(&value, column)` and open with
//! `cipher.decrypt_as(stored, column.into())`, as the
//! [encryption example](super#example) does.
//!
//! The query is the bytes Stack Encrypt's data path derives for a field
//! that names the same type (`stack_encrypt::dynamic::query_term`), which
//! is what the Go SDK sends.
//!
//! # Example
//!
//! The code below is executed by `cargo test -p eql-encryption-tests --test
//! query_example`, for the reason the [encryption example](super#example)
//! gives.
#![doc = concat!("```rust,ignore\n", include_str!("query_example.rs"), "\n```")]
//!
//! # Operators a type does not answer
//!
//! A plan for `TextEq` answers `Eq`:
//! ```no_run
//! use eql_bindings::v4::text::TextEq;
//! use stack_encrypt::plan::{Typed, ValuePlan};
//! use stack_encrypt::{op, StackCipher};
//! fn query<K: 'static>(cipher: &StackCipher<K>, plan: &ValuePlan<String, Typed<TextEq>>) {
//!     let _ = cipher.query(op::Eq, "bob").on(plan);
//! }
//! ```
//! and no ordering, since `TextEq` carries no order term:
//! ```compile_fail
//! use eql_bindings::v4::text::TextEq;
//! use stack_encrypt::plan::{Typed, ValuePlan};
//! use stack_encrypt::{op, StackCipher};
//! fn query<K: 'static>(cipher: &StackCipher<K>, plan: &ValuePlan<String, Typed<TextEq>>) {
//!     let _ = cipher.query(op::Lt, "bob").on(plan);
//! }
//! ```
//! A plan for `IntegerEq` answers `Eq`:
//! ```no_run
//! use eql_bindings::v4::integer::IntegerEq;
//! use stack_encrypt::plan::{Typed, ValuePlan};
//! use stack_encrypt::{op, StackCipher};
//! fn query<K: 'static>(cipher: &StackCipher<K>, plan: &ValuePlan<i32, Typed<IntegerEq>>) {
//!     let _ = cipher.query(op::Eq, &42).on(plan);
//! }
//! ```
//! and no text match:
//! ```compile_fail
//! use eql_bindings::v4::integer::IntegerEq;
//! use stack_encrypt::plan::{Typed, ValuePlan};
//! use stack_encrypt::{op, StackCipher};
//! fn query<K: 'static>(cipher: &StackCipher<K>, plan: &ValuePlan<i32, Typed<IntegerEq>>) {
//!     let _ = cipher.query(op::Matches, &42).on(plan);
//! }
//! ```
//! Nor does a plan for `TextEq` take another index, whose term the type's
//! SQL would not take, such as the bare equality index:
//! ```compile_fail
//! use eql_bindings::v4::text::TextEq;
//! use stack_encrypt::plan::{Typed, ValuePlan};
//! use stack_encrypt::{op, Equality, StackCipher};
//! fn query<K: 'static>(cipher: &StackCipher<K>, plan: &ValuePlan<String, Typed<TextEq>>) {
//!     let _ = cipher.query(op::Eq, "bob").via(Equality).on(plan);
//! }
//! ```
//! or another type's twin index, which answers that type's plaintext only:
//! ```compile_fail
//! use eql_bindings::encryption::query::TwinIndex;
//! use eql_bindings::v4::integer::IntegerEqQuery;
//! use eql_bindings::v4::text::TextEq;
//! use stack_encrypt::plan::{Typed, ValuePlan};
//! use stack_encrypt::{op, Equality, StackCipher};
//! fn query<K: 'static>(cipher: &StackCipher<K>, plan: &ValuePlan<String, Typed<TextEq>>) {
//!     let index = TwinIndex::<Equality, IntegerEqQuery>::default();
//!     let _ = cipher.query(op::Eq, "bob").via(index).on(plan);
//! }
//! ```
//! The twin index answers for its twin's own plaintext only
//! ([`QueryTwin::Plaintext`]): `TextEqQuery`'s for a `String`,
//! ```no_run
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
use stack_encrypt::op::{
    self, CaseInsensitive, Limit, MatchCase, Probabilistic, QueryTerm, QueryToken, Stats, Supports,
};
use stack_encrypt::sem::{EqualityTerm, MatchQuery, MatchTerms, QueryTokens};
use stack_encrypt::target::{CallerContext, ConsumeSource, Encryption, Index, IndexSpec};
use stack_encrypt::{Encrypt, Equality, Error, Label, Match, NonEmpty};

use super::{bloom_filter, hmac256, EqlMatch};
use crate::v3::terms::{BloomFilter, Hmac256};
use crate::Identifier;

/// EQL's match configuration folds case, so its index answers the
/// case-insensitive [`op::Matches`](struct@op::Matches).
impl MatchCase for EqlMatch {
    type Case = CaseInsensitive;
}

/// An EQL v4 query twin, assembled from the column it queries and the one
/// term its type's index derived for the query's value. eql-codegen
/// implements it for the twin of every type that answers an operator
/// ([`TextEqQuery`] from an [`Hmac256`], [`TextMatchQuery`] from a
/// [`BloomFilter`]), with the version every v4 value carries.
///
/// [`TextEqQuery`]: crate::v4::text::TextEqQuery
/// [`TextMatchQuery`]: crate::v4::text::TextMatchQuery
pub trait QueryTwin<T>: Sized {
    /// The plaintext the twin's type is produced from: `String` for
    /// `TextEqQuery`, `i32` for `IntegerEqQuery`. A [`TwinIndex`] answers
    /// for this plaintext only, so no plan can send one type's twin for
    /// another type's value.
    type Plaintext;
    /// The twin of `term`, derived under `column`.
    fn assemble(column: Identifier, term: T) -> Self;
}

/// The index an EQL v4 type answers an operator through: Stack Encrypt's
/// index `I`, whose query term is sent as the type's query twin `Q`.
///
/// It derives exactly what `I` derives, under the plan's label, and checks
/// and refuses what `I` refuses, as well as a label that names no column
/// and any extension; it then writes the term into the twin, with the
/// column the label names. It answers for the twin's own plaintext
/// ([`QueryTwin::Plaintext`]) only. `TextEq` answers [`op::Eq`](struct@op::Eq) through
/// `TwinIndex<Equality, TextEqQuery>`, and `TextMatch` answers
/// [`op::Matches`](struct@op::Matches) through
/// `TwinIndex<Match<EqlMatch>, TextMatchQuery>`.
pub struct TwinIndex<I, Q> {
    index: I,
    twin: PhantomData<fn() -> Q>,
}

impl<I: Default, Q> Default for TwinIndex<I, Q> {
    fn default() -> Self {
        Self {
            index: I::default(),
            twin: PhantomData,
        }
    }
}

impl<I: Clone, Q> Clone for TwinIndex<I, Q> {
    fn clone(&self) -> Self {
        Self {
            index: self.index.clone(),
            twin: PhantomData,
        }
    }
}

impl<I: fmt::Debug, Q> fmt::Debug for TwinIndex<I, Q> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TwinIndex")
            .field("index", &self.index)
            .field("twin", &std::any::type_name::<Q>())
            .finish()
    }
}

/// The index `I`, unchanged: the same spec, so a plan holds it as it holds
/// `I`, and the same derivation, so its term is `I`'s.
impl<S, I: Index<S>, Q> Index<S> for TwinIndex<I, Q> {
    type Term = I::Term;
    fn spec(&self) -> IndexSpec {
        self.index.spec()
    }
    fn operation<'s, K: 'static, M: ConsumeSource<'s, S>>(
        &self,
    ) -> Encryption<'s, S, Self::Term, K, CallerContext, M>
    where
        S: 's,
    {
        self.index.operation()
    }
}

/// Refuse a query context no EQL query value can record: a label that
/// names no column (it must be two segments, table then column), or any
/// extension (`.extend(..)`), since the terms would be derived under the
/// column and the extension while the twin stores the column alone, and
/// would match nothing. Before any keyset is resolved or term derived.
fn check_column(label: &Label, extended: bool) -> Result<(), Error> {
    if Identifier::column_of(label).is_none() {
        return Err(Error::Other(Box::new(QueryLabelError::NotAColumn {
            label: label.to_string(),
        })));
    }
    if extended {
        return Err(Error::Other(Box::new(QueryLabelError::Extended)));
    }
    Ok(())
}

/// Why a typed query on an EQL v4 type was refused for its context, before
/// any keyset was resolved. It arrives as [`Error::Other`]; match it with
/// `downcast_ref::<QueryLabelError>()`.
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
    /// The query was extended with `.extend(..)`, so its terms would be
    /// derived under more than the column the twin stores, and would match
    /// nothing.
    Extended,
}

impl fmt::Display for QueryLabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAColumn { label } => write!(
                f,
                "{label:?} is not an EQL column identifier: expected two segments, table and column"
            ),
            Self::Extended => f.write_str(
                "an EQL query value stores the column it queries and nothing else, so its query \
                 cannot be extended",
            ),
        }
    }
}

impl std::error::Error for QueryLabelError {}

/// The column a query's label names. The chain calls `query` only after
/// `check_label` accepted the label (`Supports::query`), and every
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
    Q::Plaintext: Encrypt + 'static,
{
    type Query = Q;
    type Verifier = ();
    fn check(&self, value: &Q::Plaintext) -> Result<(), Error> {
        Supports::<op::Eq, Q::Plaintext>::check(&self.index, value)
    }
    fn check_label(&self, label: &Label, extended: bool) -> Result<(), Error> {
        check_column(label, extended)
    }
    fn verifier(&self, _: &Q::Plaintext) {}
    fn query((): (), term: EqualityTerm, token: QueryToken) -> Q {
        Q::assemble(column(&token), hmac256(&term))
    }
}

/// Text match: the twin's `bf` is the filter EQL's match index derives
/// over the query's text, and the query keeps that text's tokens to
/// [`verify`](Probabilistic::verify) each decrypted row, as Stack Encrypt's
/// `MatchQuery` does. A query whose text cuts no token is refused before
/// any term exists. Only for the plaintext the twin's type is produced
/// from.
impl<Q> Supports<op::Matches, Q::Plaintext> for TwinIndex<Match<EqlMatch>, Q>
where
    Q: QueryTwin<BloomFilter> + MaybeSend + 'static,
    Q::Plaintext: AsRef<str> + 'static,
{
    type Query = MatchTwin<Q>;
    type Verifier = QueryTokens;
    fn check(&self, value: &Q::Plaintext) -> Result<(), Error> {
        Supports::<op::Matches, Q::Plaintext>::check(&self.index, value)
    }
    fn check_label(&self, label: &Label, extended: bool) -> Result<(), Error> {
        check_column(label, extended)
    }
    fn verifier(&self, value: &Q::Plaintext) -> QueryTokens {
        Supports::<op::Matches, Q::Plaintext>::verifier(&self.index, value)
    }
    fn admit(&self, value: &Q::Plaintext) -> Result<QueryTokens, Error> {
        Supports::<op::Matches, Q::Plaintext>::admit(&self.index, value)
    }
    fn query(tokens: QueryTokens, terms: MatchTerms<EqlMatch>, token: QueryToken) -> MatchTwin<Q> {
        let column = column(&token);
        let query =
            <Match<EqlMatch> as Supports<op::Matches, Q::Plaintext>>::query(tokens, terms, token);
        // `EqlMatch`'s filter is 2048 bits, so every position fits a
        // smallint (`the_match_configuration_is_pinned`); and `admit`
        // refused a query with no tokens, so the filter is not empty.
        let bf = bloom_filter(query.positions())
            .expect("EqlMatch's 2048-bit filter keeps every position within a smallint");
        MatchTwin {
            twin: Q::assemble(column, bf),
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
