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
//! Every operator is declared once, with its type, its arity and its wire
//! name ([`Op`], the dynamic vocabulary): `op::Eq`, `Op::Eq` and `"eq"`
//! are three faces of one operator. Every index declares the operators it
//! answers once as well (`Equality::OPERATORS`, `Ore::OPERATORS`, …), and
//! a plan reads that declaration: a field declares at most one index per
//! operator, so `(Equality, Ore)` is allowed and `(Ore, Ope)` is refused
//! when the plan is built ([`PlanError::IndexOverlap`](crate::PlanError::IndexOverlap)).
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
//!   Its [`prepare`](Supports::prepare) is what a query is refused for
//!   before any key is requested, and what it keeps to check a row later.
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
//! and, on a one-value plan, an index the plan does not hold. A field of a
//! fields plan is data, so there an index the field does not declare, or
//! declares with other options, is refused when the query is awaited,
//! before any key is requested. So are the values a query refuses, which
//! the `sem` module states once for the typed chain and the dynamic path:
//! match text that cuts no token under the index's tokenizer, whose filter
//! would match every row ([`TermError::EmptyTermText`]), and text an
//! equality or order index cannot normalize. The stored side has no
//! token refusal: a value with no tokens is stored as the empty filter,
//! which no query matches. A `Between` whose low bound is above its high
//! bound is not refused either: as SQL's `BETWEEN`, it matches nothing.
//! Case is the match index's alone: its configuration says whether text is
//! folded, for the stored filter and the query alike.
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
    query, EqualityTerm, MatchConfig, MatchQuery, MatchTerms, OpeTerm, Orderable, OreBlockTerm,
    OreTerm, QueryTokens, RangeQuery,
};
use crate::target::{DeclaredContext, Equality, Index, Match, Ope, Ore, OreBlock, Owned, Pending};
use crate::{Error, KeysetCipher, Label, NonEmpty};

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
    /// This operator in the dynamic vocabulary ([`Op`]), or `None` for an
    /// operator the dynamic path has no name for: one defined in another
    /// crate, or an accessor over a leaf that has no path form
    /// (`AtPath<Matches>`). Rust is the superset; the dynamic path is a
    /// named subset.
    const OP: Option<Op>;
}

/// Equality: rows whose value equals the query's.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Eq;

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

/// Text search: rows whose text holds the query's text, as the match
/// index's tokenizer cuts both. Probabilistic: the index is a Bloom filter,
/// so the server's answer can hold rows that do not match, and the query
/// term ([`MatchQuery`]) keeps the query's tokens to
/// [`verify`](Probabilistic::verify) each decrypted row.
///
/// Case is the index's: a match index folds case when its configuration's
/// [`downcase`](crate::sem::MatchOptions::downcase) says so, and the query
/// is cut the same way, so a field and the queries on it agree by the one
/// configuration. The operator itself has no case.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Matches;

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

impl<L: Leaf> Operator for AtPath<L> {
    type Arity = Pathed<L::Arity>;
    const OP: Option<Op> = L::AT;
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
pub trait Leaf: Operator<Arity: LeafArity> {
    /// This operator at a path, in the dynamic vocabulary: `Op::EqAt` for
    /// [`Eq`](struct@Eq), or `None` for a leaf the dynamic path has no
    /// path form of.
    const AT: Option<Op>;
}

/// Every operator, declared once: its type, its arity, and the name the
/// dynamic path and the wire give it. The [`Op`] enum, each type's
/// [`Operator::OP`] and [`Leaf::AT`], and [`Op::name`] are all generated
/// from this list, so the three faces of an operator (`op::Eq`, `Op::Eq`
/// and `"eq"`) cannot drift apart. The leaves come first, then the
/// document operators, then the leaves at a path, then the reads, which is
/// the order a catalog lists them in ([`Op::ALL`]).
macro_rules! operators {
    (
        leaves { $( $leaf:ident : $larity:ident {
            $(#[$lm:meta])* $lv:ident = $lw:literal,
            $( $(#[$am:meta])* $av:ident = $aw:literal, )?
        } )+ }
        documents { $( $doc:ident : $darity:ident { $(#[$dm:meta])* $dv:ident = $dw:literal, } )+ }
        reads { $( $(#[$rm:meta])* $rv:ident = $rw:literal, )+ }
    ) => {
        $(
            impl Operator for $leaf {
                type Arity = $larity;
                const OP: Option<Op> = Some(Op::$lv);
            }
            impl Leaf for $leaf {
                const AT: Option<Op> = operators!(@at $($av)?);
            }
        )+
        $(
            impl Operator for $doc {
                type Arity = $darity;
                const OP: Option<Op> = Some(Op::$dv);
            }
        )+

        /// An operator, named at run time: the runtime form of this
        /// module's operator types, as
        /// [`IndexSpec`](crate::target::IndexSpec) is of the index types.
        /// A plan written as data names its operators this way
        /// (`"eq"`, `"between"`, `"matches"`), and so does a binding.
        ///
        /// Generated from the one list of operators, with their types:
        /// `Op::Eq` is [`op::Eq`](struct@Eq)'s [`Operator::OP`], and
        /// [`name`](Self::name) is its wire name. Not `#[non_exhaustive]`:
        /// the names are wire format, and a new operator is one every
        /// binding has to be taught.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum Op {
            $( $(#[$lm])* $lv, )+
            $( $(#[$dm])* $dv, )+
            $( $( $(#[$am])* $av, )? )+
            $( $(#[$rm])* $rv, )+
        }

        impl Op {
            /// Every operator, in declaration order: the leaves, the
            /// document operators, the leaves at a path, then the reads.
            /// The order a catalog lists them in.
            pub const ALL: [Op; Self::COUNT] = [
                $( Op::$lv, )+
                $( Op::$dv, )+
                $( $( Op::$av, )? )+
                $( Op::$rv, )+
            ];

            const COUNT: usize = 0 $( + 1 $( + operators!(@one $av) )? )+ $( + operators!(@one $dv) )+ $( + operators!(@one $rv) )+;

            /// The operator's wire name: `"eq"`, `"between"`, `"matches"`.
            pub fn name(self) -> &'static str {
                match self {
                    $( Op::$lv => $lw, )+
                    $( Op::$dv => $dw, )+
                    $( $( Op::$av => $aw, )? )+
                    $( Op::$rv => $rw, )+
                }
            }
        }
    };
    (@at $av:ident) => { Some(Op::$av) };
    (@at) => { None };
    (@one $x:ident) => { 1 };
}

operators! {
    leaves {
        Eq: One {
            /// `"eq"`: [`op::Eq`](struct@Eq).
            Eq = "eq",
            /// `"eq_at"`: [`op::AtPath`](AtPath)`(op::Eq)`, a scalar at a
            /// path.
            EqAt = "eq_at",
        }
        Lt: One {
            /// `"lt"`: [`op::Lt`](Lt).
            Lt = "lt",
            /// `"lt_at"`: `op::AtPath(op::Lt)`, at a path the index orders.
            LtAt = "lt_at",
        }
        Lte: One {
            /// `"lte"`: [`op::Lte`](Lte).
            Lte = "lte",
            /// `"lte_at"`: `op::AtPath(op::Lte)`.
            LteAt = "lte_at",
        }
        Gt: One {
            /// `"gt"`: [`op::Gt`](Gt).
            Gt = "gt",
            /// `"gt_at"`: `op::AtPath(op::Gt)`.
            GtAt = "gt_at",
        }
        Gte: One {
            /// `"gte"`: [`op::Gte`](Gte).
            Gte = "gte",
            /// `"gte_at"`: `op::AtPath(op::Gte)`.
            GteAt = "gte_at",
        }
        Between: Pair {
            /// `"between"`: [`op::Between`](Between), whose input is a
            /// pair of bounds, low then high, inclusive.
            Between = "between",
            /// `"between_at"`: `op::AtPath(op::Between)`, two bounds,
            /// inclusive.
            BetweenAt = "between_at",
        }
        Matches: One {
            /// `"matches"`: [`op::Matches`](struct@Matches), in the case
            /// the field's match index fixes.
            Matches = "matches",
        }
    }
    documents {
        Contains: One {
            /// `"contains"`: [`op::Contains`](Contains), a stored
            /// document containing a JSON document (`@>`). Answered by the
            /// JSON index of a field that stores a document. The inputs of
            /// this and the operators below are named by `Op::input`
            /// (with the `dynamic` feature); `dynamic::query_term` derives
            /// their operands and `dynamic::json_open` opens their reads.
            Contains = "contains",
        }
        ContainedBy: One {
            /// `"contained_by"`: [`op::ContainedBy`](ContainedBy), a
            /// stored document contained by a JSON document (`<@`).
            ContainedBy = "contained_by",
        }
    }
    reads {
        /// `"selector"`: the selector of a path, which `->` and the path
        /// functions take
        /// ([`KeysetCipher::json_selector`](crate::KeysetCipher::json_selector)).
        Selector = "selector",
        /// `"subtree"`: the tokens of a read of the node at a path,
        /// wildcards expanded to a bound, which `json_tree_subtree` takes
        /// ([`KeysetCipher::json_subtree_key_with_bound`](crate::KeysetCipher::json_subtree_key_with_bound)).
        Subtree = "subtree",
        /// `"children"`: the token of the node at a path with no wildcard,
        /// which `json_tree_children` takes.
        Children = "children",
        /// `"child_count"`: the same token, which `json_tree_child_count`
        /// takes.
        ChildCount = "child_count",
        /// `"element_match"`: a predicate on one element of an array,
        /// each member a field of the element at an ordered path with its
        /// bounds, which `json_tree_element_match` takes. True of a row
        /// where some one element satisfies every member.
        ElementMatch = "element_match",
        /// `"match"`: a jsonpath predicate and its variables, compiled to
        /// a tree of the other operators' operands, which
        /// `json_tree_match` and `@@` take: the one-parameter form of
        /// `jsonb_path_match`. Its input is `{"predicate", "vars"?,
        /// "wildcard_bound"?}`, `vars` the JSON text of the object
        /// `jsonb_path_match` takes. It reads the subset of SQL/JSON path
        /// predicates the index's terms answer: comparisons of a path
        /// (`$.a.b`, `$.a[*].b`, `$."a b"`) with a variable or a literal,
        /// `exists(path)`, `exists(path[*] ? (@.x == $v && @.y > $w))`,
        /// `&&`, `||`, `!` and parentheses; and refuses anything else at
        /// the byte it starts (`dynamic::Error::Predicate`). The text is
        /// PostgreSQL's [SQL/JSON path language](https://www.postgresql.org/docs/current/functions-json.html#FUNCTIONS-SQLJSON-PATH).
        /// It is true of jsonpath's rows, and its answer is jsonpath's,
        /// three-valued, save that an ordering of a JSON `null` is unknown
        /// rather than false except under an odd number of `!` (which
        /// picks the same rows, and keeps a `null` needle out of the
        /// operand), a path is read as written (lax mode's unwrapping of an
        /// array the path names no `[*]` for, and its wrapping of a value
        /// that is not an array where it does, are not applied), a
        /// comparison of two kinds of value is decided by the terms where
        /// jsonpath answers unknown, and an ordering or a filter of more
        /// than one condition compares by the ordering terms, as
        /// `element_match` does. `dynamic::check_query`'s documentation
        /// has an example.
        Match = "match",
    }
}

impl Op {
    /// The operator a name names, or `None` for a name that is not one.
    /// Names match exactly: `"eq"`, not `"Eq"` or `"="`.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.name() == name)
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

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

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::One {}
    impl Sealed for super::Pair {}
    impl<A> Sealed for super::Pathed<A> {}
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
impl<T: Probabilistic> TermFor<Matches> for T {}
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
    /// Prepare a query of `input`: what this index refuses, and what the
    /// query keeps. A refusal is what the index cannot answer as
    /// configured, or for `input`: a match query of text that cuts no
    /// token ([`TermError::EmptyTermText`](crate::sem::TermError::EmptyTermText)),
    /// whose filter would match every row; match options the index cannot
    /// use; text an equality or order index cannot normalize. The verifier
    /// is what the query keeps of `input` to check a row later, taken
    /// before the input is consumed; an index that refuses nothing and
    /// keeps nothing returns `Ok(())`.
    ///
    /// A query chain calls this once, when the query is awaited, before any
    /// keyset is resolved, and keeps the verifier until the term is
    /// derived. So a verifier exists only for an input the index accepted,
    /// and a refused query costs no key request. The refusals are the
    /// `sem` module's, one function per index, which the dynamic path
    /// calls as well: what a binding refuses at its boundary is what this
    /// refuses.
    fn prepare(&self, input: &In) -> Result<Self::Verifier, Error>;
    /// Why this index cannot answer a query whose terms are derived under
    /// `label`, the plan's or the call's, extended by parts the call gave
    /// (`.extend(..)`) when `extended` is true: for an index whose query term
    /// records the context it was derived under, a context it cannot record.
    /// An EQL query value stores the column it queries, so its index refuses
    /// a label that names no column, and any extension, which the column
    /// cannot hold. Run when the query is awaited, before [`prepare`](Self::prepare)
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

/// The equality index answers `Eq` over any plaintext with an equality
/// domain, and refuses text it cannot normalize (a code point unassigned
/// in Unicode 16) before any keyset is resolved, as the dynamic path does.
/// The check normalizes a copy of the value, which vitaminc wipes as it
/// reads it, so the plaintext is `Clone`, as every scalar is.
impl<S> Supports<Eq, S> for Equality
where
    S: crate::Encrypt + Clone + 'static,
{
    type Query = EqualityTerm;
    type Verifier = ();
    fn prepare(&self, value: &S) -> Result<(), Error> {
        Ok(query::equality(value.clone())?)
    }
    fn query((): (), term: EqualityTerm, _: QueryToken) -> EqualityTerm {
        term
    }
}
impl Equality {
    /// The operators this index answers: its one declaration, which the
    /// typed impls above and [`IndexSpec::operators`](crate::target::IndexSpec::operators)
    /// both read.
    pub const OPERATORS: &'static [Op] = &[Op::Eq];
}

impl<S, O> Supports<Matches, S> for Match<O>
where
    S: AsRef<str> + 'static,
    O: MatchConfig,
{
    type Query = MatchQuery<O>;
    type Verifier = QueryTokens;
    fn prepare(&self, value: &S) -> Result<QueryTokens, Error> {
        // Options the index cannot use, then text that cuts no token,
        // which would match every row: the stored side keeps such a value
        // as the empty filter, the query side refuses it here. The tokens
        // are cut once, here, and kept as the verifier.
        Ok(query::match_tokens(value.as_ref(), &O::options())?)
    }
    fn query(tokens: QueryTokens, term: MatchTerms<O>, _: QueryToken) -> MatchQuery<O> {
        MatchQuery::new(term, tokens)
    }
}
impl<O> Match<O> {
    /// The operators this index answers, under any configuration: its one
    /// declaration, as [`Equality::OPERATORS`].
    pub const OPERATORS: &'static [Op] = &[Op::Matches];
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
    ($($index:ident => $term:ident, block: $block:literal),+ $(,)?) => {$(
        orders!(@one $index => $term, $block; Lt, Lte, Gt, Gte);
        impl<S: Ordered> Supports<Between, (S, S)> for $index {
            type Query = RangeQuery<$term<S>>;
            type Verifier = ();
            fn prepare(&self, (lo, hi): &(S, S)) -> Result<(), Error> {
                query::order(lo, $block)?;
                Ok(query::order(hi, $block)?)
            }
            fn query((): (), (lo, hi): ($term<S>, $term<S>), _: QueryToken) -> Self::Query {
                RangeQuery::new(lo, hi)
            }
        }
        impl<S: Ordered> Answers<Between, (S, S)> for $term<S> {
            type Via = $index;
        }
        impl $index {
            /// The operators this index answers: its one declaration, as
            /// [`Equality::OPERATORS`].
            pub const OPERATORS: &'static [Op] = &[Op::Lt, Op::Lte, Op::Gt, Op::Gte, Op::Between];
        }
    )+};
    (@one $index:ident => $term:ident, $block:literal; $($op:ident),+) => {$(
        impl<S: Ordered> Supports<$op, S> for $index {
            type Query = $term<S>;
            type Verifier = ();
            fn prepare(&self, value: &S) -> Result<(), Error> {
                Ok(query::order(value, $block)?)
            }
            fn query((): (), term: $term<S>, _: QueryToken) -> $term<S> {
                term
            }
        }
        impl<S: Ordered> Answers<$op, S> for $term<S> {
            type Via = $index;
        }
    )+};
}
orders!(Ore => OreTerm, block: false, Ope => OpeTerm, block: false, OreBlock => OreBlockTerm, block: true);

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

impl<S> Answers<Eq, S> for EqualityTerm
where
    S: crate::Encrypt + Clone + 'static,
{
    type Via = Equality;
}

impl<S, O> Answers<Matches, S> for MatchTerms<O>
where
    S: AsRef<str> + 'static,
    O: MatchConfig,
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

impl<S> DefaultIndex<S> for Eq
where
    S: crate::Encrypt + Clone + 'static,
{
    type Via = Equality;
}

impl<S: AsRef<str> + 'static> DefaultIndex<S> for Matches {
    type Via = Match;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sem::DefaultMatch;

    /// A match index's verifier is the query's tokens: a query built from
    /// it verifies a row that holds them and no other. A query chain takes
    /// them through `prepare`, once.
    #[test]
    fn a_match_verifier_is_the_query_tokens() {
        let index = Match::<DefaultMatch>::default();
        let verifier =
            Supports::<Matches, String>::prepare(&index, &"alice".to_owned()).expect("tokens");
        let filter = MatchTerms::<DefaultMatch>::from_positions(vec![1]).expect("in range");
        let query = MatchQuery::new(filter, verifier);
        assert!(Probabilistic::verify(&query, "say hi to Alice"));
        assert!(!Probabilistic::verify(&query, "bob"));
    }

    #[test]
    fn an_operator_is_equal_to_itself() {
        assert_eq!(Matches, Matches);
        assert_eq!(Eq, Eq);
    }

    #[test]
    fn an_operator_debugs_by_its_name() {
        assert_eq!(format!("{:?}", Matches), "Matches");
        assert_eq!(format!("{:?}", Eq), "Eq");
        assert_eq!(format!("{:?}", Between), "Between");
        assert_eq!(format!("{:?}", AtPath(Gte)), "AtPath(Gte)");
        assert_eq!(AtPath(Matches).0, Matches);
    }

    /// The three faces of an operator name one operator: the type's `OP`
    /// is the enum's variant, the variant's name is the wire name, and the
    /// name parses back to the variant. Every variant is in `ALL` once.
    #[test]
    fn an_operators_three_faces_agree() {
        fn face<O: Operator>(op: Op, name: &str) {
            assert_eq!(O::OP, Some(op));
            assert_eq!(op.name(), name);
            assert_eq!(Op::parse(name), Some(op));
            assert_eq!(op.to_string(), name);
        }
        face::<Eq>(Op::Eq, "eq");
        face::<Lt>(Op::Lt, "lt");
        face::<Lte>(Op::Lte, "lte");
        face::<Gt>(Op::Gt, "gt");
        face::<Gte>(Op::Gte, "gte");
        face::<Between>(Op::Between, "between");
        face::<Matches>(Op::Matches, "matches");
        face::<Contains>(Op::Contains, "contains");
        face::<ContainedBy>(Op::ContainedBy, "contained_by");
        face::<AtPath<Eq>>(Op::EqAt, "eq_at");
        face::<AtPath<Lt>>(Op::LtAt, "lt_at");
        face::<AtPath<Lte>>(Op::LteAt, "lte_at");
        face::<AtPath<Gt>>(Op::GtAt, "gt_at");
        face::<AtPath<Gte>>(Op::GteAt, "gte_at");
        face::<AtPath<Between>>(Op::BetweenAt, "between_at");
        // A leaf with no path form in the dynamic vocabulary.
        assert_eq!(<AtPath<Matches> as Operator>::OP, None);
        // The reads have no typed operator; they are named all the same.
        for (op, name) in [
            (Op::Selector, "selector"),
            (Op::Subtree, "subtree"),
            (Op::Children, "children"),
            (Op::ChildCount, "child_count"),
            (Op::ElementMatch, "element_match"),
            (Op::Match, "match"),
        ] {
            assert_eq!(op.name(), name);
            assert_eq!(Op::parse(name), Some(op));
        }
        assert_eq!(Op::ALL.len(), 21);
        let mut seen = std::collections::HashSet::new();
        for op in Op::ALL {
            assert!(seen.insert(op.name()), "{op} is listed twice");
            assert_eq!(Op::parse(op.name()), Some(op));
        }
        assert_eq!(Op::parse("Eq"), None);
        assert_eq!(Op::parse("="), None);
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

    /// An ordering refuses no integer: a range whose bounds are the wrong
    /// way round matches nothing, as SQL's `BETWEEN` does. Text it cannot
    /// normalize is refused, before any key, as the dynamic path refuses
    /// it; block ORE refuses a fold over its limit as well.
    #[test]
    fn an_ordering_refuses_only_text_it_cannot_encode() {
        let ok = |pair: (u32, u32)| Supports::<Between, (u32, u32)>::prepare(&Ore, &pair).is_ok();
        assert!(ok((1, 2)));
        assert!(ok((2, 2)));
        assert!(ok((3, 2)));
        assert!(Supports::<Between, (i64, i64)>::prepare(&Ope, &(1, -1)).is_ok());
        assert!(Supports::<Lt, u16>::prepare(&Ore, &7).is_ok());
        assert!(Supports::<Gte, i128>::prepare(&Ope, &-7).is_ok());
        let unassigned = String::from("a\u{0378}b");
        assert!(matches!(
            Supports::<Lt, String>::prepare(&Ore, &unassigned),
            Err(Error::Term(crate::sem::TermError::Normalize(_)))
        ));
        assert!(matches!(
            Supports::<Between, (String, String)>::prepare(&Ope, &("a".to_owned(), unassigned)),
            Err(Error::Term(crate::sem::TermError::Normalize(_)))
        ));
        let long = "a".repeat(2000);
        assert!(Supports::<Lt, String>::prepare(&Ore, &long).is_ok());
        assert!(matches!(
            Supports::<Lt, String>::prepare(&OreBlock, &long),
            Err(Error::Term(crate::sem::TermError::OreBlockTooLong))
        ));
    }

    /// An equality query of text that cannot be normalized is refused
    /// before any key is requested, as the dynamic path refuses it.
    #[test]
    fn an_equality_query_refuses_text_with_no_normal_form() {
        assert!(Supports::<Eq, String>::prepare(&Equality, &"ada".to_owned()).is_ok());
        assert!(Supports::<Eq, u32>::prepare(&Equality, &7).is_ok());
        assert!(matches!(
            Supports::<Eq, String>::prepare(&Equality, &String::from("a\u{0378}b")),
            Err(Error::Term(crate::sem::TermError::Normalize(_)))
        ));
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
        assert!(Supports::<Lt, Date>::prepare(&Ore, &day()).is_ok());
        assert!(Supports::<Lte, Timestamp>::prepare(&Ope, &at()).is_ok());
        assert!(Supports::<Gt, Decimal>::prepare(&OreBlock, &price()).is_ok());
        assert!(Supports::<Between, (Date, Date)>::prepare(&Ore, &(day(), day())).is_ok());
    }
}
