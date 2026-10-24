//! Queries named by operator, for a binding.
//!
//! A Rust caller names an operator as a type, `cipher.query(op::Matches,
//! "ali").on(&plan)`, and the compiler finds the index that answers it
//! (ADR-0009). A binding has no type to name: its plan arrives as data and
//! its operator as a string. This module is the runtime form of that query,
//! written once here rather than once per language binding (ADR-0007,
//! amended 2026-10-16):
//!
//! - [`OpSpec`] names an operator, as [`IndexSpec`] names an index, and
//!   [`OpSpec::answered_by`] is the table the typed path's `DefaultIndex`
//!   impls state: which declared index answers the operator for a field of
//!   a kind, if any does.
//! - [`query_term`] derives the query term for a plan field, an operator and
//!   its input: the field's own index term for the input, or, for a field
//!   that names an EQL type, that type's query value. It refuses an operator
//!   the field does not answer as it refuses a value of the wrong type, with
//!   [`Error::Source`] naming the field.
//! - [`field_operators`] lists the operators a plan field answers, each with
//!   the index that answers it ([`OperatorEntry`] is one's wire form): what a
//!   generator asks before the program runs, so it writes one query method
//!   per operator the engine answers and holds no copy of the table.
//! - [`verify`] and [`target_limit`] are a probabilistic term's two
//!   questions, [`Probabilistic::verify`] and
//!   [`Probabilistic::target_limit`], over a page of decrypted values and
//!   over [`Stats`]. They run the same code the typed `MatchQuery` runs, with
//!   the match index's options read from the plan, and need no key.
//!
//! An exact term has neither question: [`verify`] and [`target_limit`]
//! refuse an exact operator ([`Reason::ExactOperator`]) rather than answer
//! `true` for every row, as the typed path does not compile the call.
//!
//! # Which operators a field answers
//!
//! A field with indexes answers what [`OpSpec::answered_by`] says for its
//! declared kind: `eq` through an equality index, `matches` through a match
//! index over text, and the orderings (`lt`, `lte`, `gt`, `gte`,
//! `between`) through an ORE index over an integer of 16 bits or wider, a
//! float, text, a date, a timestamp or a decimal, else a block ORE index,
//! else an OPE index. The typed
//! path's default for an ordering is ORE, and block ORE and OPE are the
//! typed path's `.via(OreBlock)` and `.via(Ope)`; here a field that
//! declares only one of them is answered through it. Every order term is
//! derived over the value's ADR-0002 order key: a float's ties `-0.0` with
//! `0.0` and sorts every NaN last, and text's is its fold. An ordering over
//! bytes is not answered, as `op::Ordered` does not cover them. Nor is one
//! over an 8-bit integer, which has no order term. A timestamp orders by the
//! microsecond and a decimal by value, so `1.5` ties `1.50`.
//!
//! A field that names an EQL type answers what its
//! [`TargetDescriptor::operators`] lists: the operators of a single value
//! whose index the type carries, for a type the engine produces and that
//! has a query twin. The term is the twin, which carries every term of the
//! type; one query domain per operator is EQL v4's (ADR-0009, decision 8).
//! `matches` is answered through a type whose descriptor carries its match
//! options ([`TargetDescriptor::with_match_options`]), since [`verify`]
//! must cut the query's tokens as the stored filter was cut: `TextMatch`
//! answers it through `TextMatchQuery`, whose `bf` is the filter, and
//! [`verify`] and [`target_limit`] run under the type's options. A type
//! with a match index and no options answers no probabilistic operator.
//!
//! # Wire format
//!
//! An operator is its [`name`](OpSpec::name). A query term is the object
//! [`QueryTerm`] serializes to, the statistics the frame object
//! [`Stats::from_frame`] reads, and a limit [`Limit::rows`]: an unsigned
//! 64-bit integer, or null for no finite fetch. Each answer is written to a
//! frame by serde (`vitaminc_aead_frame::serde`) and documented on its
//! type.
//!
//! [`Probabilistic::verify`]: crate::op::Probabilistic::verify
//! [`Probabilistic::target_limit`]: crate::op::Probabilistic::target_limit

use serde::{Serialize, Serializer};

use super::WireBytes;
use std::fmt;

use stack_kms::DataKeySource;

use super::record::{FieldPlan, Plan};
use super::term::OneScalar;
use super::term::{derive, Use};
use super::value_frame::Parts;
use super::ValueKind;
use super::{admits, read, Error, Reason, TargetDescriptor, TargetResolver, ValueFrame};
use crate::op::{Limit, Stats};
use crate::sem::{match_limit, MatchOptions, QueryTokens, TermError};
use crate::target::IndexSpec;
use crate::{KeysetCipher, Pending};
use vitaminc_aead::plaintext::{Logical, Physical};
use vitaminc_aead::Encrypt;

/// An operator, named at run time: the runtime form of the
/// [`op`](crate::op) module's operator types, as [`IndexSpec`] is of the
/// index types.
///
/// Not `#[non_exhaustive]`, for the reason the [module docs](super#stability)
/// give for [`IndexSpec`]: the names are wire format, and a new operator is
/// one every binding has to be taught.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpSpec {
    /// `"eq"`: [`op::Eq`](struct@crate::op::Eq).
    Eq,
    /// `"lt"`: [`op::Lt`](crate::op::Lt).
    Lt,
    /// `"lte"`: [`op::Lte`](crate::op::Lte).
    Lte,
    /// `"gt"`: [`op::Gt`](crate::op::Gt).
    Gt,
    /// `"gte"`: [`op::Gte`](crate::op::Gte).
    Gte,
    /// `"between"`: [`op::Between`](crate::op::Between), whose input is a
    /// pair of bounds, low then high, inclusive.
    Between,
    /// `"matches"`: [`op::Matches`](struct@crate::op::Matches), in the case
    /// the field's match index fixes.
    Matches,
}

impl OpSpec {
    /// Every operator, in declaration order: the order a catalog lists them
    /// in.
    pub const ALL: [OpSpec; 7] = [
        OpSpec::Eq,
        OpSpec::Lt,
        OpSpec::Lte,
        OpSpec::Gt,
        OpSpec::Gte,
        OpSpec::Between,
        OpSpec::Matches,
    ];

    /// The operator a name names, or `None` for a name that is not one.
    /// Names match exactly: `"eq"`, not `"Eq"` or `"="`.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.name() == name)
    }

    /// The operator's wire name.
    pub fn name(self) -> &'static str {
        match self {
            OpSpec::Eq => "eq",
            OpSpec::Lt => "lt",
            OpSpec::Lte => "lte",
            OpSpec::Gt => "gt",
            OpSpec::Gte => "gte",
            OpSpec::Between => "between",
            OpSpec::Matches => "matches",
        }
    }

    /// How far the server's answer to this operator can be trusted: what
    /// the typed path says by the trait the term implements.
    pub fn fidelity(self) -> Fidelity {
        match self {
            OpSpec::Matches => Fidelity::Probabilistic,
            _ => Fidelity::Exact,
        }
    }

    /// Whether the operator takes a pair of values, low then high, rather
    /// than one: `between` does.
    pub fn takes_pair(self) -> bool {
        self == OpSpec::Between
    }

    /// The index among `indexes` that answers this operator for a field of
    /// `kind`, or `None` when none does: the typed path's `DefaultIndex`
    /// table, stated over a kind and the indexes a field declares.
    ///
    /// ```
    /// use stack_encrypt::dynamic::{OpSpec, ValueKind};
    /// use stack_encrypt::target::IndexSpec;
    ///
    /// let both = [IndexSpec::Ope, IndexSpec::Ore];
    /// assert_eq!(OpSpec::Lt.answered_by(ValueKind::UInt32, &both), Some(&IndexSpec::Ore));
    /// assert_eq!(OpSpec::Lt.answered_by(ValueKind::String, &both), Some(&IndexSpec::Ore));
    /// assert_eq!(OpSpec::Lt.answered_by(ValueKind::Float32, &both), Some(&IndexSpec::Ore));
    /// assert_eq!(OpSpec::Lt.answered_by(ValueKind::Bytes, &both), None);
    /// assert_eq!(OpSpec::Eq.answered_by(ValueKind::UInt32, &both), None);
    /// ```
    pub fn answered_by(self, kind: ValueKind, indexes: &[IndexSpec]) -> Option<&IndexSpec> {
        let declared = |wanted: fn(&IndexSpec) -> bool| indexes.iter().find(|index| wanted(index));
        match self {
            OpSpec::Eq => declared(|index| matches!(index, IndexSpec::Equality)),
            OpSpec::Matches => declared(|index| matches!(index, IndexSpec::Match(_))),
            OpSpec::Lt | OpSpec::Lte | OpSpec::Gt | OpSpec::Gte | OpSpec::Between => {
                if !ordered(kind) {
                    return None;
                }
                declared(|index| matches!(index, IndexSpec::Ore))
                    .or_else(|| declared(|index| matches!(index, IndexSpec::OreBlock)))
                    .or_else(|| declared(|index| matches!(index, IndexSpec::Ope)))
            }
        }
        .filter(|index| admits(kind, index))
    }
}

impl fmt::Display for OpSpec {
    /// Writes [`name`](Self::name).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The kinds the ordering operators are answered over: the integers of 16
/// bits and wider, `int16` to `uint128`, the floats, text, and dates,
/// timestamps and decimals, as [`op::Ordered`](crate::op::Ordered) covers
/// them in the typed path. Not `int8` or `uint8`, which have no order term.
/// Each orders by its ADR-0002 order key; a `float32` is ordered as the
/// `f64` it widens to, as the typed path asks.
fn ordered(kind: ValueKind) -> bool {
    matches!(
        kind,
        ValueKind::Int16
            | ValueKind::Int32
            | ValueKind::Int64
            | ValueKind::Int128
            | ValueKind::UInt16
            | ValueKind::UInt32
            | ValueKind::UInt64
            | ValueKind::UInt128
            | ValueKind::Float32
            | ValueKind::Float64
            | ValueKind::String
            | ValueKind::Decimal
            | ValueKind::Date
            | ValueKind::Timestamp
    )
}

/// How far the server's answer to an operator can be trusted (ADR-0009,
/// decision 4), as a catalog reports it.
///
/// The typed path says this with traits, not a value: a term that
/// implements [`Probabilistic`](crate::op::Probabilistic) can be verified,
/// and one that does not cannot. A binding's generator asks before the
/// program runs, so it needs the answer as data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fidelity {
    /// `"exact"`: the server's answer is the answer.
    Exact,
    /// `"probabilistic"`: the answer can hold false positives and no false
    /// negatives; [`verify`] decides each row, and [`target_limit`] sizes
    /// the fetch.
    Probabilistic,
}

impl Fidelity {
    /// The fidelity's wire name.
    pub fn name(self) -> &'static str {
        match self {
            Fidelity::Exact => "exact",
            Fidelity::Probabilistic => "probabilistic",
        }
    }
}

/// The operators an EQL type answers, as [`TargetDescriptor::operators`]
/// lists them: none for a type the engine does not produce or that has no
/// query twin, and otherwise every operator of one value that one of the
/// type's indexes answers for its plaintext kind, `matches` only when the
/// type's match options are known. The match index answers under those
/// options. See the [module docs](self#which-operators-a-field-answers).
pub(super) fn target_operators(target: &TargetDescriptor) -> Vec<(OpSpec, IndexSpec)> {
    let Some(kind) = target
        .plaintext
        .filter(|_| target.producible && target.query.is_some())
    else {
        return Vec::new();
    };
    let indexes: Vec<IndexSpec> = target
        .indexes
        .iter()
        .filter_map(
            |key| match (IndexSpec::parse(key)?, &target.match_options) {
                (IndexSpec::Match(_), Some(options)) => Some(IndexSpec::Match(options.clone())),
                (IndexSpec::Match(_), None) => None,
                (index, _) => Some(index),
            },
        )
        .collect();
    OpSpec::ALL
        .into_iter()
        .filter(|op| !op.takes_pair())
        .filter_map(|op| {
            op.answered_by(kind, &indexes)
                .map(|index| (op, index.clone()))
        })
        .collect()
}

/// A query term a binding asked for by operator: the operand to bind in
/// SQL, and what it is.
///
/// The bytes are not plaintext: an index term, or an EQL query value, which
/// is what the server compares. The query's own tokens, which
/// [`verify`] needs, are plaintext and are not here; [`verify`] cuts them
/// again from the query's input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryTerm {
    operator: OpSpec,
    index: IndexSpec,
    domain: Option<String>,
    operand: Operand,
}

/// What a [`QueryTerm`] binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operand {
    /// One term: an index term's frozen bytes ([`TermBytes`](super::TermBytes)), or an EQL
    /// query value's JSON bytes.
    One(Vec<u8>),
    /// A range's two terms, each the index term of one bound, inclusive.
    Range {
        /// The low bound's term.
        lo: Vec<u8>,
        /// The high bound's term.
        hi: Vec<u8>,
    },
}

/// The term in its wire form: an object with every key present, an
/// absent value null.
///
/// | key | value |
/// |---|---|
/// | `operator` | string: the [operator's name](OpSpec::name), `"matches"` |
/// | `fidelity` | string: `"exact"` or `"probabilistic"` ([`Fidelity::name`]) |
/// | `index` | string: the [key](IndexSpec::key) of the index that answers, `"match"` |
/// | `domain` | string or null: the query value's PostgreSQL domain, for a field that names an EQL type |
/// | `term` | bytes: the term, or for `between` a list of two byte strings, the low bound's term then the high's |
impl Serialize for QueryTerm {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            operator: &'static str,
            fidelity: &'static str,
            index: &'static str,
            domain: Option<&'a str>,
            term: Term<'a>,
        }
        #[derive(Serialize)]
        #[serde(untagged)]
        enum Term<'a> {
            One(WireBytes<'a>),
            Range([WireBytes<'a>; 2]),
        }
        Wire {
            operator: self.operator.name(),
            fidelity: self.fidelity().name(),
            index: self.index.key(),
            domain: self.domain.as_deref(),
            term: match &self.operand {
                Operand::One(term) => Term::One(WireBytes(term)),
                Operand::Range { lo, hi } => Term::Range([WireBytes(lo), WireBytes(hi)]),
            },
        }
        .serialize(s)
    }
}

impl QueryTerm {
    /// The operator the term answers.
    pub fn operator(&self) -> OpSpec {
        self.operator
    }

    /// How far the server's answer to it can be trusted.
    pub fn fidelity(&self) -> Fidelity {
        self.operator.fidelity()
    }

    /// The index that answers the operator for the field.
    pub fn index(&self) -> &IndexSpec {
        &self.index
    }

    /// The PostgreSQL domain the operand is cast to, for a field that names
    /// an EQL type; `None` for a field with indexes, whose terms are bytes.
    pub fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    /// What the term binds.
    pub fn operand(&self) -> &Operand {
        &self.operand
    }
}

/// The field a query is about, and the index that answers its operator.
struct Answer<'p> {
    field: &'p FieldPlan,
    kind: ValueKind,
    index: IndexSpec,
    target: Option<TargetDescriptor>,
}

/// The input of a query, read as its field's kind.
enum Input {
    One(ValueFrame),
    Pair(ValueFrame, ValueFrame),
}

/// Find `field` in `plan` and the index that answers `operator` for it.
///
/// # Errors
///
/// [`Error::Plan`] for a field the plan does not have
/// ([`Reason::NoSuchField`]), [`Error::Target`] for a target the resolver
/// refuses, and [`Error::Source`]
/// ([`Reason::OperatorNotAnswered`]) for an operator the field does not
/// answer.
fn answer<'p>(
    plan: &'p Plan,
    field: &str,
    operator: OpSpec,
    resolver: &(impl TargetResolver + ?Sized),
) -> Result<Answer<'p>, Error> {
    let found = find(plan, field)?;
    let not_answered = || Error::Source {
        field: Some(field.to_owned()),
        reason: Reason::OperatorNotAnswered,
    };
    let kind = found.field_type().ok_or_else(not_answered)?;
    let (operators, target) = answers(found, resolver)?;
    let index = operators
        .into_iter()
        .find_map(|(op, index)| (op == operator).then_some(index));
    Ok(Answer {
        field: found,
        kind,
        index: index.ok_or_else(not_answered)?,
        target,
    })
}

/// The field named `field`, or [`Error::Plan`] with
/// [`Reason::NoSuchField`].
fn find<'p>(plan: &'p Plan, field: &str) -> Result<&'p FieldPlan, Error> {
    plan.fields()
        .iter()
        .find(|candidate| candidate.name() == field)
        .ok_or_else(|| Error::Plan {
            field: Some(field.to_owned()),
            reason: Reason::NoSuchField,
        })
}

/// Operators a field answers, each with the index that answers it.
type Operators = Vec<(OpSpec, IndexSpec)>;

/// Every operator `field` answers with the index that answers it, and the
/// EQL type it names, resolved: the one table [`answer`] and
/// [`field_operators`] both read, so what a generator is told a field
/// answers is what a query on it finds.
fn answers(
    field: &FieldPlan,
    resolver: &(impl TargetResolver + ?Sized),
) -> Result<(Operators, Option<TargetDescriptor>), Error> {
    let Some(kind) = field.field_type() else {
        return Ok((Vec::new(), None));
    };
    if let Some(name) = field.target() {
        let target = resolver.resolve(name).map_err(Error::Target)?;
        return Ok((target_operators(&target), Some(target)));
    }
    let indexes = field.indexes();
    let operators = OpSpec::ALL
        .into_iter()
        .filter_map(|op| {
            op.answered_by(kind, &indexes)
                .map(|index| (op, index.clone()))
        })
        .collect();
    Ok((operators, None))
}

/// The operators a field of a plan answers, each with the index that
/// answers it, in [`OpSpec::ALL`]'s order: exactly the operators
/// [`query_term`] derives a term for on that field, so a generator asks the
/// engine which query methods to write rather than holding a copy of the
/// table.
///
/// A field with indexes answers each operator [`OpSpec::answered_by`] finds
/// an index for under its declared kind; a field that names an EQL type
/// answers what the type's [`TargetDescriptor::operators`] lists; a field
/// with no declared kind answers none. The context does not matter, so a
/// plan whose context is a field of each record is taken. Write each entry
/// as an [`OperatorEntry`].
///
/// ```
/// use stack_encrypt::dynamic::{field_operators, record, NoTargets, OpSpec};
/// use stack_encrypt::target::IndexSpec;
///
/// let plan = record::plan(&vitaminc_aead_frame::serde::to_vec(&serde_json::json!({
///     "age": { "context": ["users", "age"], "outputs": ["c", "eq", "ore"], "type": "uint32" },
/// }))?)?;
///
/// let operators = field_operators(&plan, "age", &NoTargets)?;
/// assert_eq!(operators[0], (OpSpec::Eq, IndexSpec::Equality));
/// assert_eq!(operators[1], (OpSpec::Lt, IndexSpec::Ore));
/// assert_eq!(operators.len(), 6, "eq, the four comparisons and between");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// [`Error::Plan`] for a field the plan does not have
/// ([`Reason::NoSuchField`]), and [`Error::Target`] for a target the
/// resolver refuses.
pub fn field_operators(
    plan: &Plan,
    field: &str,
    resolver: &(impl TargetResolver + ?Sized),
) -> Result<Vec<(OpSpec, IndexSpec)>, Error> {
    answers(find(plan, field)?, resolver).map(|(operators, _)| operators)
}

/// One operator a field answers in its wire form, as a catalog lists it: an
/// object with every key present.
///
/// | key | value |
/// |---|---|
/// | `operator` | string: the operator's name, `eq` ([`OpSpec::name`]) |
/// | `fidelity` | string: `exact` or `probabilistic` ([`Fidelity::name`]) |
/// | `arity` | string: `one`, or `pair` for an operator whose input is two values, low then high |
/// | `index` | string: the [key](IndexSpec::key) of the index that answers it, `eq` |
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct OperatorEntry {
    operator: &'static str,
    fidelity: &'static str,
    arity: &'static str,
    index: &'static str,
}

impl OperatorEntry {
    /// The entry for `operator`, answered by `index`.
    pub fn new(operator: OpSpec, index: &IndexSpec) -> Self {
        Self {
            operator: operator.name(),
            fidelity: operator.fidelity().name(),
            arity: if operator.takes_pair() { "pair" } else { "one" },
            index: index.key(),
        }
    }
}

/// Refuse a plan whose context is a field of each record: a term derives
/// under a context, and such a plan has none until a record names it, so a
/// binding sends the plan under the context its query names.
/// [`verify`] and [`target_limit`] derive nothing and take such a plan.
fn has_context(plan: &Plan, field: &str) -> Result<(), Error> {
    match plan.context_field() {
        Some(_) => Err(Error::Plan {
            field: Some(field.to_owned()),
            reason: Reason::QueryContextField,
        }),
        None => Ok(()),
    }
}

/// Read a query's input as the field's kind ([`read`]): one value, or for
/// `between` a list of two, low then high.
///
/// # Errors
///
/// [`Error::Source`] naming the field: [`Reason::FieldType`] for a value
/// that cannot be read as the kind, [`Reason::NotARange`] for a `between`
/// input that is not a list of two values.
fn read_input(answer: &Answer<'_>, operator: OpSpec, input: impl Encrypt) -> Result<Input, Error> {
    let name = answer.field.name();
    if !operator.takes_pair() {
        let input = ValueFrame::of(input).map_err(|_| Error::Source {
            field: Some(name.to_owned()),
            reason: Reason::FieldType,
        })?;
        // A null is found by its equality term, which a field that seals
        // its nulls stores beside each one (#1298); nothing else has one.
        if input.is_null() {
            let sealed = answer.field.null() == Some(super::NullMode::Sealed);
            return match (sealed, &answer.index) {
                (true, IndexSpec::Equality) => Ok(Input::One(input)),
                _ => Err(Error::Source {
                    field: Some(name.to_owned()),
                    reason: Reason::NullQuery,
                }),
            };
        }
        return read(answer.kind, &input)
            .map(Input::One)
            .map_err(|error| error.in_field(name));
    }
    let one = |value: ValueFrame| read(answer.kind, value).map_err(|error| error.in_field(name));
    let bounds = ValueFrame::of(input)
        .and_then(|input| input.parts())
        .map_err(|_| not_a_range(name))?;
    match bounds {
        Parts::Seq(bounds) => match <[ValueFrame; 2]>::try_from(bounds) {
            Ok([lo, hi]) => Ok(Input::Pair(one(lo)?, one(hi)?)),
            Err(_) => Err(not_a_range(name)),
        },
        _ => Err(not_a_range(name)),
    }
}

fn not_a_range(field: &str) -> Error {
    Error::Source {
        field: Some(field.to_owned()),
        reason: Reason::NotARange,
    }
}

/// The refusals the typed path makes when a query is awaited, before any
/// term exists ([`Supports::check`](crate::op::Supports::check)): match
/// text the index cannot normalize or that cuts no token, and equality
/// text the scheme cannot normalize. Each index's own derivation refuses
/// these again; asking here lets a binding refuse at its boundary. A range
/// whose low bound is above its high bound is not refused: as SQL's
/// `BETWEEN`, it matches nothing.
fn check_input(index: &IndexSpec, input: &Input) -> Result<(), Error> {
    let refused = |error: TermError| Error::Cipher(error.into());
    match (index, input) {
        // Order text the fold cannot take (a code point unassigned in
        // Unicode 16) is refused here, before a term or a keyset, as
        // derivation would refuse it after one.
        (IndexSpec::Ore | IndexSpec::Ope, Input::One(value)) => {
            order_text(value).map_err(refused)?;
        }
        (IndexSpec::Ore | IndexSpec::Ope, Input::Pair(lo, hi)) => {
            order_text(lo).map_err(refused)?;
            order_text(hi).map_err(refused)?;
        }
        // Block ORE refuses more order text: a fold longer than 1023
        // bytes, or one that ends in NUL.
        (IndexSpec::OreBlock, Input::One(value)) => {
            ore_block_text(value).map_err(refused)?;
        }
        (IndexSpec::OreBlock, Input::Pair(lo, hi)) => {
            ore_block_text(lo).map_err(refused)?;
            ore_block_text(hi).map_err(refused)?;
        }
        (IndexSpec::Match(options), Input::One(value)) => {
            query_tokens(value, options).map(drop)?;
        }
        // Equality text the scheme cannot normalize (a code point
        // unassigned in Unicode 16) is refused here, before a term or a
        // keyset, as derivation would refuse it after one.
        (IndexSpec::Equality, Input::One(value)) => {
            crate::sem::normalized(value).map(drop).map_err(refused)?;
        }
        _ => {}
    }
    Ok(())
}

/// Whether `value`, if it is order text, has a fold: `vitaminc-ore`'s
/// `Text` encoding, the one an order index encrypts, refuses a code point
/// Unicode 16 does not assign. Anything but text has nothing to refuse.
fn order_text(value: &ValueFrame) -> Result<(), TermError> {
    value
        .visit(OneScalar::new(
            |ty: Option<Logical>, value: Physical<'_>| match (ty, value) {
                (None, Physical::Text(text)) => Ok(vitaminc_ore::text(text)
                    .map(drop)
                    .map_err(TermError::Normalize)),
                _ => Err(None),
            },
        ))
        // Not one text scalar: nothing to refuse here.
        .unwrap_or(Ok(()))
}

/// Whether `value`, if it is order text, has a block ORE term: its fold
/// exists, is at most 1023 bytes and does not end in NUL
/// ([`crate::sem::ore_block_text`]). Anything but text has nothing to
/// refuse here.
fn ore_block_text(value: &ValueFrame) -> Result<(), TermError> {
    value
        .visit(OneScalar::new(
            |ty: Option<Logical>, value: Physical<'_>| match (ty, value) {
                (None, Physical::Text(text)) => Ok(crate::sem::ore_block_text(text)),
                _ => Err(None),
            },
        ))
        // Not one text scalar: nothing to refuse here.
        .unwrap_or(Ok(()))
}

/// The tokens a match query of `value` keeps, under the index's options.
///
/// # Errors
///
/// [`Error::Cipher`] with [`TermError::InvalidOptions`] for options the
/// index cannot use (a [`FieldPlan`] built by hand is not
/// checked, and an n-gram length of zero would panic in the tokenizer),
/// [`TermError::Normalize`] for text the index cannot normalize, and
/// [`TermError::EmptyTermText`] for text that cuts no token, whose filter
/// would match every row. [`Error::Internal`] for a value that is not text,
/// which [`read_input`] has ruled out.
fn query_tokens(value: &ValueFrame, options: &MatchOptions) -> Result<QueryTokens, Error> {
    value
        .visit(OneScalar::new(
            |ty: Option<Logical>, value: Physical<'_>| match (ty, value) {
                // The query chain's rule, from the same helper.
                (None, Physical::Text(text)) => Ok(QueryTokens::of_query(text, options)
                    .map_err(|error| Error::Cipher(error.into()))),
                _ => Err(None),
            },
        ))
        .map_err(|_| Error::Internal)?
}

/// Check a query without a cipher: everything [`query_term`] refuses before
/// it derives anything. A binding calls this at its boundary, so a bad
/// query is refused before a keyset is resolved.
///
/// # Errors
///
/// As [`query_term`].
pub fn check_query(
    plan: &Plan,
    field: &str,
    operator: OpSpec,
    input: impl Encrypt,
    resolver: &(impl TargetResolver + ?Sized),
) -> Result<(), Error> {
    let answer = answer(plan, field, operator, resolver)?;
    has_context(plan, field)?;
    let input = read_input(&answer, operator, input)?;
    check_input(&answer.index, &input)
}

/// Derive the query term for one field of a plan, an operator and its
/// input: one value for most operators, a list of two for
/// [`between`](OpSpec::Between).
///
/// The input is read as the field's declared kind first ([`read`]), so a
/// host's `34` as a float queries a `uint64` field as the `u64` it stored.
/// A field with indexes derives the term of the index that answers the
/// operator ([`OpSpec::answered_by`]) under the field's context, by the
/// derivation its stored terms came from; a range derives one term per
/// bound under that one context. A field that names an EQL type runs the
/// type's query twin through `resolver`. Nothing is requested: the pending
/// settles without I/O, as a typed query's does.
///
/// # Examples
///
/// ```
/// use stack_encrypt::dynamic::{query_term, record, NoTargets, OpSpec, Operand};
/// use stack_encrypt::kms::FakeDataKeySource;
/// use stack_encrypt::{op, Ore, Plan, StackCipher};
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
/// let keyset = cipher.default_keyset();
/// let plan = record::plan(&vitaminc_aead_frame::serde::to_vec(&serde_json::json!({
///     "age": { "context": ["users", "age"], "outputs": ["c", "ore"], "type": "uint32" },
/// }))?)?;
///
/// let term = query_term(&keyset, &plan, "age", OpSpec::Lt, 40u32, &NoTargets)?.await?;
///
/// // The typed path's term for the same query.
/// let typed_plan = Plan::context("users/age").with::<u32, _>(Ore).build()?;
/// let typed = cipher.query(op::Lt, &40u32).on(&typed_plan).await?;
/// assert_eq!(term.operand(), &Operand::One(typed.to_bytes()));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// # }).unwrap();
/// ```
///
/// # Errors
///
/// [`Error::Plan`] for a field the plan does not have
/// ([`Reason::NoSuchField`]), or a plan that takes its context from a field
/// of each record ([`Reason::QueryContextField`]): a query names the
/// context such a plan's records hold, so a binding sends the plan under
/// that context. [`Error::Source`] naming the field for an operator the
/// field does not answer ([`Reason::OperatorNotAnswered`]), an input that
/// cannot be read as the field's kind ([`Reason::FieldType`]) and a
/// `between` input that is not two values ([`Reason::NotARange`]).
/// [`Error::Cipher`] for the query refusals the typed path makes: match
/// text that cuts no token ([`TermError::EmptyTermText`]), and text the
/// index cannot normalize ([`TermError::Normalize`]). A range whose low
/// bound is above its high bound is not refused: as SQL's `BETWEEN`, it
/// matches nothing.
/// [`Error::Target`] for what the resolver refuses.
pub fn query_term<'a, K>(
    cipher: &'a KeysetCipher<'_, K>,
    plan: &Plan,
    field: &str,
    operator: OpSpec,
    input: impl Encrypt,
    resolver: &(impl TargetResolver + ?Sized),
) -> Result<Pending<'a, QueryTerm, K>, Error>
where
    K: DataKeySource + Sync + 'static,
{
    let answer = answer(plan, field, operator, resolver)?;
    has_context(plan, field)?;
    let input = read_input(&answer, operator, input)?;
    check_input(&answer.index, &input)?;
    let index = answer.index.clone();
    let made = move |domain: Option<String>, operand| QueryTerm {
        operator,
        index,
        domain,
        operand,
    };
    if let Some(target) = answer.target {
        let Input::One(value) = input else {
            return Err(Error::Internal);
        };
        let domain = target.query_sql_domain;
        // The answering index goes to the resolver: a type whose query
        // carries only its operator's term derives that index's alone.
        return Ok(
            super::record::query(cipher, plan, field, &answer.index, value, resolver)?
                .map(move |json| made(domain, Operand::One(json))),
        );
    }
    let context = answer.field.context();
    let term = |value: &ValueFrame| {
        derive(cipher, value, &answer.index, context.clone(), Use::Query)
            .map_err(|error| error.in_field(field))
    };
    Ok(match input {
        Input::One(value) => {
            term(&value)?.map(move |term| made(None, Operand::One(term.into_bytes())))
        }
        Input::Pair(lo, hi) => term(&lo)?.zip(term(&hi)?).map(move |(lo, hi)| {
            made(
                None,
                Operand::Range {
                    lo: lo.into_bytes(),
                    hi: hi.into_bytes(),
                },
            )
        }),
    })
}

/// The options of the match index that answers a probabilistic operator
/// for the field, and whether the field names an EQL type (whose query
/// term is the twin's JSON rather than the filter's bytes), or the refusal
/// for an exact operator.
fn probabilistic(
    plan: &Plan,
    field: &str,
    operator: OpSpec,
    resolver: &(impl TargetResolver + ?Sized),
) -> Result<(MatchOptions, bool), Error> {
    let answer = answer(plan, field, operator, resolver)?;
    let target = answer.target.is_some();
    // A match index answers `matches` alone, and `matches` is the one
    // probabilistic operator, so the index says which this is.
    match answer.index {
        IndexSpec::Match(options) => Ok((options, target)),
        _ => Err(Error::Source {
            field: Some(field.to_owned()),
            reason: Reason::ExactOperator,
        }),
    }
}

/// Whether each of a page of decrypted values really matches a
/// probabilistic query, in order: [`Probabilistic::verify`] for every
/// value, run by the code the typed `MatchQuery` runs, under the options of
/// the field's match index.
///
/// The query is named as it was derived, by the plan, the field, the
/// operator and the input, and the input's tokens are cut again here: they
/// are plaintext, so no query term carries them across a binding. The
/// result needs no key.
///
/// A value that does not hold the query's tokens is `false`, and so is a
/// null (a row whose field is empty holds no token), as
/// [`Probabilistic::verify`] is `false` for every outcome but a match.
///
/// [`Probabilistic::verify`]: crate::op::Probabilistic::verify
///
/// # Errors
///
/// As [`query_term`] for the field, the operator and the input, before any
/// value is read, save that a plan whose context is a field of each record
/// is taken, since verifying derives nothing; [`Error::Source`] with
/// [`Reason::ExactOperator`] for an exact operator, which has nothing to
/// verify; and [`Error::Source`] with [`Reason::FieldType`] for a value
/// that is neither a string nor null.
pub fn verify<V: Encrypt>(
    plan: &Plan,
    field: &str,
    operator: OpSpec,
    input: impl Encrypt,
    values: impl IntoIterator<Item = V>,
    resolver: &(impl TargetResolver + ?Sized),
) -> Result<Vec<bool>, Error> {
    let (options, _) = probabilistic(plan, field, operator, resolver)?;
    let input = read(ValueKind::String, input).map_err(|error| error.in_field(field))?;
    let tokens = query_tokens(&input, &options)?;
    // Each value is walked in place to its one scalar: text is checked for
    // the query's tokens, a null holds none, and anything else is not a
    // value of the field.
    values
        .into_iter()
        .map(|value| {
            value
                .visit(OneScalar::new(
                    |ty: Option<Logical>, value: Physical<'_>| match (ty, value) {
                        (None, Physical::Text(text)) => Ok(tokens.verify(text, &options)),
                        (None, Physical::Null) => Ok(false),
                        _ => Err(None),
                    },
                ))
                .map_err(|_| Error::Source {
                    field: Some(field.to_owned()),
                    reason: Reason::FieldType,
                })
        })
        .collect()
}

/// How many rows to fetch so that, at the confidence `stats` names, `want`
/// of them [`verify`]: [`Probabilistic::target_limit`] for the term
/// [`query_term`] derived, run by the code the typed `MatchQuery` runs.
///
/// `term` is the term's bytes as [`query_term`] returned them, from which
/// the number of bits the query sets is read: a match index term's
/// positions, or for a field that names an EQL type, the `bf` of the query
/// twin's JSON (`TextMatchQuery`). The field's match index
/// declares no `expected_tokens` prior in a data plan, so a [`Stats`] with
/// no measured histogram answers [`Limit::Unbounded`]. The result needs no
/// key.
///
/// [`Probabilistic::target_limit`]: crate::op::Probabilistic::target_limit
///
/// # Errors
///
/// As [`verify`] for the plan, the field and the operator; and
/// [`Error::Source`] with [`Reason::NotAQueryTerm`] for bytes that are not
/// a match query term under the field's options: not whole positions, a
/// position outside the filter, positions out of order or repeated, or
/// none at all. For a field that names an EQL type, the same for the
/// twin's `bf`, and bytes that are not a JSON object holding one.
pub fn target_limit(
    plan: &Plan,
    field: &str,
    operator: OpSpec,
    term: &[u8],
    want: u64,
    stats: &Stats,
    resolver: &(impl TargetResolver + ?Sized),
) -> Result<Limit, Error> {
    let (options, target) = probabilistic(plan, field, operator, resolver)?;
    let bits = if target {
        twin_query_bits(term, &options)
    } else {
        query_bits(term, &options)
    };
    let bits = bits.ok_or_else(|| Error::Source {
        field: Some(field.to_owned()),
        reason: Reason::NotAQueryTerm,
    })?;
    Ok(match_limit(bits, &options, None, want, stats))
}

/// The number of positions a match query term sets, if `term` is one the
/// index derives under `options`: little-endian `u16` positions, each in
/// the filter, strictly ascending, at least one.
fn query_bits(term: &[u8], options: &MatchOptions) -> Option<usize> {
    if term.is_empty() || !term.len().is_multiple_of(2) {
        return None;
    }
    let positions: Vec<u32> = term
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_le_bytes([pair[0], pair[1]])))
        .collect();
    let in_filter = positions.iter().all(|&position| position < options.m);
    let ascending = positions.windows(2).all(|pair| pair[0] < pair[1]);
    (in_filter && ascending).then_some(positions.len())
}

/// The number of positions a match query twin's JSON sets, if `term` is an
/// object whose `bf` holds the positions the type derives under `options`:
/// integers, each in the filter, strictly ascending, at least one.
fn twin_query_bits(term: &[u8], options: &MatchOptions) -> Option<usize> {
    let value: serde_json::Value = serde_json::from_slice(term).ok()?;
    let positions = value
        .as_object()?
        .get("bf")?
        .as_array()?
        .iter()
        .map(|position| {
            position
                .as_u64()
                .filter(|&position| position < u64::from(options.m))
        })
        .collect::<Option<Vec<u64>>>()?;
    let ascending = positions.windows(2).all(|pair| pair[0] < pair[1]);
    (!positions.is_empty() && ascending).then_some(positions.len())
}

impl Stats {
    /// Read statistics from their wire form, a frame object:
    ///
    /// | key | value |
    /// |---|---|
    /// | `rows` | integer, required: the rows the query scans |
    /// | `histogram` | optional, or null: a list of `[bits, rows]` pairs of integers, a measured histogram of the stored filters' set-bit counts ([`Stats::measured`]); absent, the declared prior ([`Stats::declared`]) |
    /// | `confidence` | optional, or null: a float, the confidence to target instead of 99% ([`Stats::with_confidence`]) |
    ///
    /// Integers are read at any width up to 64 bits and must not be
    /// negative; `bits` must fit a `u32`. A confidence is a float of either
    /// width, never an integer.
    ///
    /// # Errors
    ///
    /// [`Error::Source`] with [`Reason::NotStats`] for anything else: not a
    /// frame, not an object, no `rows`, a key given twice or not one of the
    /// three, or a value of another type.
    pub fn from_frame(bytes: &[u8]) -> Result<Self, Error> {
        let wire: StatsWire = vitaminc_aead_frame::serde::from_slice(bytes)
            .map_err(|_| Error::bad_source(Reason::NotStats))?;
        let stats = match wire.histogram {
            Some(histogram) => Stats::measured(wire.rows, histogram),
            None => Stats::declared(wire.rows),
        };
        Ok(match wire.confidence {
            Some(Confidence(confidence)) => stats.with_confidence(confidence),
            None => stats,
        })
    }
}

/// [`Stats`] as a binding writes it ([`Stats::from_frame`]).
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StatsWire {
    rows: u64,
    #[serde(default)]
    histogram: Option<Vec<(u32, u64)>>,
    #[serde(default)]
    confidence: Option<Confidence>,
}

/// A confidence: a float of either width. serde's own `f64` would also take
/// an integer, which the wire form refuses.
struct Confidence(f64);

impl<'de> serde::Deserialize<'de> for Confidence {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Confidence;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a float")
            }
            fn visit_f32<E>(self, v: f32) -> Result<Confidence, E> {
                Ok(Confidence(f64::from(v)))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Confidence, E> {
                Ok(Confidence(v))
            }
        }
        d.deserialize_any(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::test_frame::Tree;
    use crate::dynamic::test_frame::{frame_of, value_of};

    fn operator_value(operator: OpSpec, index: &IndexSpec) -> Tree {
        value_of(&OperatorEntry::new(operator, index))
    }

    /// Statistics as a binding sends them.
    fn stats_frame(value: &Tree) -> Result<Stats, Error> {
        Stats::from_frame(&crate::dynamic::test_frame::frame_of(value))
    }
    use crate::dynamic::{record, NoTargets, TargetError};
    use crate::op::{self, Probabilistic as _};
    use crate::sem::MatchTerms;
    use crate::{Equality, Label, Match, Ope, Ore, StackCipher};
    use stack_kms::FakeDataKeySource;

    async fn cipher() -> StackCipher<FakeDataKeySource> {
        StackCipher::builder()
            .kms(FakeDataKeySource::new())
            .init()
            .await
            .expect("build cipher")
    }

    fn text(s: &str) -> Tree {
        Tree::String(s.into())
    }

    fn vf(value: &Tree) -> ValueFrame {
        ValueFrame::of(value).expect("a value")
    }

    /// One field of `users`, as a binding spells it.
    fn field(name: &str, kind: &str, outputs: Vec<Tree>) -> (String, Tree) {
        (
            name.to_owned(),
            Tree::Object(vec![
                (
                    "context".into(),
                    Tree::Array(vec![text("users"), text(name)]),
                ),
                ("outputs".into(), Tree::Array(outputs)),
                ("type".into(), text(kind)),
            ]),
        )
    }

    /// The plan every test queries: an email with equality, a name with
    /// match, an age with ORE and OPE, a score with OPE alone, a nickname
    /// with ORE over text, and a case-sensitive handle.
    fn users() -> Plan {
        let case_sensitive = Tree::Object(vec![(
            "match".into(),
            Tree::Object(vec![("downcase".into(), Tree::Bool(false))]),
        )]);
        record::plan(&frame_of(&Tree::Object(vec![
            field("email", "string", vec![text("c"), text("eq")]),
            field("name", "string", vec![text("c"), text("match")]),
            field("age", "uint32", vec![text("c"), text("ope"), text("ore")]),
            field("score", "int64", vec![text("ope")]),
            field("nickname", "string", vec![text("c"), text("ore")]),
            field("handle", "string", vec![text("c"), case_sensitive]),
            field("ratio", "float32", vec![text("c"), text("ore")]),
            field("rating", "float64", vec![text("c"), text("ope")]),
        ])))
        .expect("the plan parses")
    }

    async fn query(
        keyset: &KeysetCipher<'_, FakeDataKeySource>,
        name: &str,
        operator: OpSpec,
        input: impl Encrypt,
    ) -> Result<QueryTerm, Error> {
        query_term(keyset, &users(), name, operator, input, &NoTargets)?
            .await
            .map_err(Error::Cipher)
    }

    fn reason_of(error: &Error) -> (Option<&str>, Option<Reason>) {
        (error.field(), error.reason())
    }

    fn term_error(error: &Error) -> Option<&TermError> {
        match error {
            Error::Cipher(crate::Error::Term(term)) => Some(term),
            _ => None,
        }
    }

    #[test]
    fn an_operator_reads_back_from_its_name_and_no_other() {
        for op in OpSpec::ALL {
            assert_eq!(OpSpec::parse(op.name()), Some(op), "{op}");
            assert_eq!(op.to_string(), op.name());
        }
        let names: std::collections::BTreeSet<&str> =
            OpSpec::ALL.iter().map(|op| op.name()).collect();
        assert_eq!(names.len(), OpSpec::ALL.len(), "names are distinct");
        for not_one in ["Eq", "=", "", "contains", "at_path", "matches "] {
            assert_eq!(OpSpec::parse(not_one), None, "{not_one:?}");
        }
    }

    #[test]
    fn only_matches_is_probabilistic_and_only_between_takes_a_pair() {
        for op in OpSpec::ALL {
            assert_eq!(
                op.fidelity() == Fidelity::Probabilistic,
                op == OpSpec::Matches,
                "{op}"
            );
            assert_eq!(op.takes_pair(), op == OpSpec::Between, "{op}");
        }
        assert_eq!(Fidelity::Exact.name(), "exact");
        assert_eq!(Fidelity::Probabilistic.name(), "probabilistic");
    }

    /// The typed path's `DefaultIndex` table, over kinds: equality answers
    /// `eq`, match answers `matches` over text, and the orderings go to ORE
    /// over an integer, or to OPE when there is no ORE.
    #[test]
    fn the_answering_index_is_the_typed_paths_default() {
        let all = [
            IndexSpec::Equality,
            IndexSpec::Match(MatchOptions::default()),
            IndexSpec::Ope,
            IndexSpec::Ore,
        ];
        let answered =
            |op: OpSpec, kind, indexes: &[IndexSpec]| op.answered_by(kind, indexes).cloned();
        assert_eq!(
            answered(OpSpec::Eq, ValueKind::String, &all),
            Some(IndexSpec::Equality)
        );
        assert_eq!(
            answered(OpSpec::Eq, ValueKind::Bool, &all),
            None,
            "a boolean has no equality term"
        );
        assert_eq!(
            answered(OpSpec::Matches, ValueKind::String, &all),
            Some(IndexSpec::Match(MatchOptions::default()))
        );
        assert_eq!(answered(OpSpec::Matches, ValueKind::UInt64, &all), None);
        for op in [
            OpSpec::Lt,
            OpSpec::Lte,
            OpSpec::Gt,
            OpSpec::Gte,
            OpSpec::Between,
        ] {
            for kind in [ValueKind::Int8, ValueKind::UInt8, ValueKind::Bool] {
                assert_eq!(
                    answered(op, kind, &all),
                    None,
                    "{op} {kind}: an 8-bit integer has no order term, as a boolean has none"
                );
            }
            for kind in [
                ValueKind::Int16,
                ValueKind::Int32,
                ValueKind::Int64,
                ValueKind::Int128,
                ValueKind::UInt16,
                ValueKind::UInt32,
                ValueKind::UInt64,
                ValueKind::UInt128,
                ValueKind::Float32,
                ValueKind::Float64,
                ValueKind::String,
                ValueKind::Decimal,
                ValueKind::Date,
                ValueKind::Timestamp,
            ] {
                assert_eq!(
                    answered(op, kind, &all),
                    Some(IndexSpec::Ore),
                    "{op} {kind}"
                );
                assert_eq!(
                    answered(op, kind, &[IndexSpec::Ope]),
                    Some(IndexSpec::Ope),
                    "{op} {kind}"
                );
                assert_eq!(
                    answered(op, kind, &[IndexSpec::Equality]),
                    None,
                    "{op} {kind}"
                );
            }
            for kind in [ValueKind::Bytes, ValueKind::Bool] {
                assert_eq!(
                    answered(op, kind, &all),
                    None,
                    "{op} is not answered over {kind}"
                );
            }
        }
        // A decimal, a date and a timestamp answer `eq` through equality.
        for kind in [ValueKind::Decimal, ValueKind::Date, ValueKind::Timestamp] {
            assert_eq!(
                answered(OpSpec::Eq, kind, &all),
                Some(IndexSpec::Equality),
                "{kind}"
            );
        }
        for op in OpSpec::ALL {
            assert_eq!(
                answered(op, ValueKind::UInt32, &[]),
                None,
                "no index answers nothing"
            );
        }
    }

    #[tokio::test]
    async fn eq_derives_the_typed_paths_equality_term() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let term = query(&keyset, "email", OpSpec::Eq, text("bob@example.com"))
            .await
            .unwrap();
        let plan = crate::Plan::context("users/email")
            .with::<String, _>(Equality)
            .build()
            .unwrap();
        let typed = cipher
            .query(op::Eq, "bob@example.com")
            .on(&plan)
            .await
            .unwrap();
        assert_eq!(term.operand(), &Operand::One(typed.to_bytes()));
        assert_eq!(term.operator(), OpSpec::Eq);
        assert_eq!(term.fidelity(), Fidelity::Exact);
        assert_eq!(term.index(), &IndexSpec::Equality);
        assert_eq!(term.domain(), None, "a field with indexes binds bytes");
    }

    #[tokio::test]
    async fn an_ordering_derives_the_typed_paths_ore_term_and_reads_the_input_as_the_fields_kind() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = crate::Plan::context("users/age")
            .with::<u32, _>(Ore)
            .build()
            .unwrap();
        let typed = cipher.query(op::Lt, &40u32).on(&plan).await.unwrap();
        for input in [Tree::UInt32(40), Tree::Float64(40.0), Tree::Int64(40)] {
            let term = query(&keyset, "age", OpSpec::Lt, input).await.unwrap();
            assert_eq!(term.operand(), &Operand::One(typed.to_bytes()));
            assert_eq!(term.index(), &IndexSpec::Ore, "ORE before OPE");
        }
    }

    #[tokio::test]
    async fn between_derives_both_bounds_under_one_context_as_the_typed_range() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = crate::Plan::context("users/age")
            .with::<u32, _>(Ore)
            .build()
            .unwrap();
        let typed = cipher
            .query(op::Between, &(18u32, 65))
            .on(&plan)
            .await
            .unwrap();
        let term = query(
            &keyset,
            "age",
            OpSpec::Between,
            Tree::Array(vec![Tree::UInt32(18), Tree::UInt32(65)]),
        )
        .await
        .unwrap();
        assert_eq!(
            term.operand(),
            &Operand::Range {
                lo: typed.lo().to_bytes(),
                hi: typed.hi().to_bytes()
            }
        );
        let one = query(
            &keyset,
            "age",
            OpSpec::Between,
            Tree::Array(vec![Tree::UInt32(7), Tree::UInt32(7)]),
        )
        .await;
        assert!(one.is_ok(), "(v, v) is one value: {one:?}");

        let plan = crate::Plan::context("users/score")
            .with::<i64, _>(Ope)
            .build()
            .unwrap();
        let typed = cipher
            .query(op::Between, &(-5i64, 5))
            .via(Ope)
            .on(&plan)
            .await
            .unwrap();
        let term = query(
            &keyset,
            "score",
            OpSpec::Between,
            Tree::Array(vec![Tree::Int64(-5), Tree::Int64(5)]),
        )
        .await
        .unwrap();
        assert_eq!(
            term.index(),
            &IndexSpec::Ope,
            "OPE when the field declares no ORE"
        );
        assert_eq!(
            term.operand(),
            &Operand::Range {
                lo: typed.lo().to_bytes(),
                hi: typed.hi().to_bytes()
            }
        );
    }

    #[tokio::test]
    async fn matches_derives_the_typed_paths_filter() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = crate::Plan::context("users/name")
            .with::<String, _>(Match::default())
            .build()
            .unwrap();
        let typed = cipher.query(op::Matches, "alice").on(&plan).await.unwrap();
        let term = query(&keyset, "name", OpSpec::Matches, text("alice"))
            .await
            .unwrap();
        assert_eq!(term.operand(), &Operand::One(typed.to_bytes()));
        assert_eq!(term.fidelity(), Fidelity::Probabilistic);
    }

    #[tokio::test]
    async fn a_query_the_field_does_not_answer_is_refused_naming_the_field() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let cases = [
            ("name", OpSpec::Eq, text("x"), Reason::OperatorNotAnswered),
            (
                "email",
                OpSpec::Matches,
                text("bob"),
                Reason::OperatorNotAnswered,
            ),
            (
                "nickname",
                OpSpec::Eq,
                text("bob"),
                Reason::OperatorNotAnswered,
            ),
            (
                "age",
                OpSpec::Eq,
                Tree::UInt32(1),
                Reason::OperatorNotAnswered,
            ),
            ("age", OpSpec::Lt, text("40"), Reason::FieldType),
            ("age", OpSpec::Lt, Tree::Float64(40.5), Reason::FieldType),
            ("age", OpSpec::Between, Tree::UInt32(40), Reason::NotARange),
            (
                "age",
                OpSpec::Between,
                Tree::Array(vec![Tree::UInt32(1)]),
                Reason::NotARange,
            ),
            (
                "age",
                OpSpec::Between,
                Tree::Array(vec![Tree::UInt32(1), text("2")]),
                Reason::FieldType,
            ),
        ];
        for (name, op, input, reason) in cases {
            let what = format!("{op} on {name}");
            let error = query(&keyset, name, op, input.clone()).await.unwrap_err();
            assert!(matches!(error, Error::Source { .. }), "{what}: {error:?}");
            assert_eq!(reason_of(&error), (Some(name), Some(reason)), "{what}");
            let checked = check_query(&users(), name, op, input, &NoTargets).unwrap_err();
            assert_eq!(
                reason_of(&checked),
                (Some(name), Some(reason)),
                "{what}: checked alike"
            );
        }
        let error = query(&keyset, "phone", OpSpec::Eq, text("1"))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::Plan { .. }));
        assert_eq!(
            reason_of(&error),
            (Some("phone"), Some(Reason::NoSuchField))
        );
    }

    #[tokio::test]
    async fn the_typed_paths_query_refusals_are_made_before_any_term() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let one = |text: &str| ValueFrame::of(text).expect("a value");
        let two = |lo: &str, hi: &str| ValueFrame::of(vec![lo, hi]).expect("a value");
        let cases = [
            ("nickname", OpSpec::Lt, one("a\u{0378}"), "normalize"),
            (
                "nickname",
                OpSpec::Between,
                two("a", "b\u{0378}"),
                "normalize",
            ),
            (
                "nickname",
                OpSpec::Between,
                two("a\u{0378}", "b"),
                "normalize",
            ),
            ("name", OpSpec::Matches, one("al"), "empty"),
            ("name", OpSpec::Matches, one("\u{0378}abc"), "normalize"),
            ("email", OpSpec::Eq, one("a\u{0378}bc"), "normalize"),
        ];
        for (name, op, input, what) in cases {
            for error in [
                query(&keyset, name, op, &input).await.unwrap_err(),
                check_query(&users(), name, op, &input, &NoTargets).unwrap_err(),
            ] {
                let term = term_error(&error);
                let expected = match what {
                    "empty" => matches!(term, Some(TermError::EmptyTermText)),
                    _ => matches!(term, Some(TermError::Normalize(_))),
                };
                assert!(expected, "{name} {what}: {error:?}");
            }
        }
        // The terms of folded equivalents are one term.
        let cafe = query(&keyset, "nickname", OpSpec::Lt, "cafe")
            .await
            .unwrap();
        let folded = query(&keyset, "nickname", OpSpec::Lt, "CAF\u{c9}")
            .await
            .unwrap();
        assert_eq!(folded.operand, cafe.operand);

        // A float32 orders as the f64 it widens to: `-0.0` ties `0.0`, so
        // the two are one term.
        let zero = query(&keyset, "ratio", OpSpec::Lt, 0.0f32).await.unwrap();
        let negative_zero = query(&keyset, "ratio", OpSpec::Lt, -0.0f32).await.unwrap();
        assert_eq!(negative_zero.operand, zero.operand);
    }

    /// Block ORE takes order text whose fold is at most 1023 bytes and does
    /// not end in NUL. A query is refused for any other, either bound of a
    /// range included, before any term exists, by the key-free check too.
    #[tokio::test]
    async fn block_ore_refuses_text_it_has_no_term_for_before_any_term() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = record::plan(&frame_of(&Tree::Object(vec![field(
            "title",
            "string",
            vec![text("c"), text("ore_block")],
        )])))
        .expect("the plan parses");
        let one = |text: &str| ValueFrame::of(text).expect("a value");
        let two = |lo: &str, hi: &str| ValueFrame::of(vec![lo, hi]).expect("a value");
        let longest = "a".repeat(1023);
        let too_long = "a".repeat(1024);
        let refused = [
            (OpSpec::Lt, one(&too_long), "long"),
            (OpSpec::Gt, one("a\0"), "nul"),
            (OpSpec::Between, two("a", &too_long), "long"),
            (OpSpec::Between, two(&too_long, "b"), "long"),
            (OpSpec::Between, two("a\0", "b"), "nul"),
            (OpSpec::Between, two("a", "b\0"), "nul"),
        ];
        for (op, input, what) in refused {
            let derived = match query_term(&keyset, &plan, "title", op, &input, &NoTargets) {
                Ok(pending) => pending.await.map_err(Error::Cipher).map(|_| ()),
                Err(error) => Err(error),
            };
            for error in [
                derived.unwrap_err(),
                check_query(&plan, "title", op, &input, &NoTargets).unwrap_err(),
            ] {
                let term = term_error(&error);
                let expected = match what {
                    "long" => matches!(term, Some(TermError::OreBlockTooLong)),
                    _ => matches!(term, Some(TermError::OreBlockTrailingNul)),
                };
                assert!(expected, "{op:?} {what}: {error:?}");
            }
        }
        for input in [one(&longest), one("a\0b"), one("")] {
            check_query(&plan, "title", OpSpec::Lt, &input, &NoTargets)
                .expect("block ORE takes it");
            let term = query_term(&keyset, &plan, "title", OpSpec::Lt, &input, &NoTargets)
                .expect("a query")
                .await
                .expect("a term");
            assert_eq!(term.index, IndexSpec::OreBlock);
        }
    }

    /// A plan whose context is a field of each record has no context a
    /// query could derive under; the binding sends the plan under the
    /// context it names.
    #[tokio::test]
    async fn a_plan_whose_context_is_a_record_field_is_refused() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let one = |name: &str, kind: &str, output: &str| {
            (
                name.to_owned(),
                Tree::Object(vec![
                    ("context".into(), Tree::Array(vec![text(name)])),
                    ("outputs".into(), Tree::Array(vec![text(output)])),
                    ("type".into(), text(kind)),
                ]),
            )
        };
        let plan = record::plan(&frame_of(&Tree::Object(vec![
            ("context_field".into(), text("tenant")),
            one("tenant", "string", "passthrough"),
            one("email", "string", "eq"),
        ])))
        .unwrap();
        let error = query_term(&keyset, &plan, "email", OpSpec::Eq, text("a"), &NoTargets)
            .map(drop)
            .unwrap_err();
        assert_eq!(
            reason_of(&error),
            (Some("email"), Some(Reason::QueryContextField))
        );
        let checked = check_query(&plan, "email", OpSpec::Eq, text("a"), &NoTargets).unwrap_err();
        assert_eq!(
            reason_of(&checked),
            (Some("email"), Some(Reason::QueryContextField))
        );
        // Verifying derives nothing, so it needs no context.
        let error = verify(
            &plan,
            "email",
            OpSpec::Eq,
            text("a"),
            Vec::<Tree>::new(),
            &NoTargets,
        )
        .unwrap_err();
        assert_eq!(
            reason_of(&error),
            (Some("email"), Some(Reason::ExactOperator)),
            "refused for its operator, not its context"
        );
    }

    /// `verify` is the typed `MatchQuery::verify`, value for value, under
    /// the options the field declares, and needs no key.
    #[tokio::test]
    async fn verify_answers_as_the_typed_match_query() {
        let cipher = cipher().await;
        let plan = crate::Plan::context("users/name")
            .with::<String, _>(Match::default())
            .build()
            .unwrap();
        let typed = cipher.query(op::Matches, "alice").on(&plan).await.unwrap();
        let page = ["Alice Smith", "alicia", "Bob", "MALICE", "", "ali ce"];
        let values: Vec<Tree> = page.iter().map(|v| text(v)).collect();
        let verified = verify(
            &users(),
            "name",
            OpSpec::Matches,
            text("alice"),
            &values,
            &NoTargets,
        )
        .unwrap();
        let expected: Vec<bool> = page.iter().map(|v| typed.verify(v)).collect();
        assert_eq!(verified, expected);
        assert!(
            verified.contains(&true) && verified.contains(&false),
            "{verified:?}"
        );

        let nulls = verify(
            &users(),
            "name",
            OpSpec::Matches,
            text("alice"),
            &[Tree::Null],
            &NoTargets,
        )
        .unwrap();
        assert_eq!(nulls, [false], "a null holds no token");
        let empty = verify(
            &users(),
            "name",
            OpSpec::Matches,
            text("alice"),
            Vec::<Tree>::new(),
            &NoTargets,
        )
        .unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn verify_cuts_tokens_under_the_fields_own_options() {
        let sensitive = |input: &str, value: &str| {
            verify(
                &users(),
                "handle",
                OpSpec::Matches,
                text(input),
                &[text(value)],
                &NoTargets,
            )
            .unwrap()[0]
        };
        assert!(sensitive("Alice", "Alice"));
        assert!(
            !sensitive("Alice", "alice"),
            "the handle's index does not fold case"
        );
        let folding = verify(
            &users(),
            "name",
            OpSpec::Matches,
            text("Alice"),
            &[text("alice")],
            &NoTargets,
        )
        .unwrap();
        assert_eq!(folding, [true], "the name's index folds case");
    }

    #[test]
    fn verify_refuses_what_it_cannot_answer() {
        let refused = |name: &str, op: OpSpec, input: Tree, values: &[Tree]| {
            verify(&users(), name, op, input, values, &NoTargets).unwrap_err()
        };
        let error = refused("email", OpSpec::Eq, text("a"), &[text("a")]);
        assert_eq!(
            reason_of(&error),
            (Some("email"), Some(Reason::ExactOperator))
        );
        let error = refused("age", OpSpec::Lt, Tree::UInt32(1), &[]);
        assert_eq!(
            reason_of(&error),
            (Some("age"), Some(Reason::ExactOperator))
        );
        let error = refused("email", OpSpec::Matches, text("abc"), &[]);
        assert_eq!(
            reason_of(&error),
            (Some("email"), Some(Reason::OperatorNotAnswered))
        );
        let error = refused("name", OpSpec::Matches, text("alice"), &[Tree::UInt32(1)]);
        assert_eq!(reason_of(&error), (Some("name"), Some(Reason::FieldType)));
        let error = refused("name", OpSpec::Matches, Tree::UInt32(1), &[]);
        assert_eq!(reason_of(&error), (Some("name"), Some(Reason::FieldType)));
        let error = refused("name", OpSpec::Matches, text("al"), &[text("al")]);
        assert!(
            matches!(term_error(&error), Some(TermError::EmptyTermText)),
            "{error:?}"
        );
    }

    /// Match options on a field plan built by hand are not checked when the
    /// plan is, so the query chain refuses them before it cuts a token: an
    /// n-gram length of zero would otherwise panic in the tokenizer.
    #[test]
    fn invalid_match_options_are_refused_before_tokenising() {
        let options = MatchOptions {
            tokenizer: crate::sem::Tokenizer::Ngram { length: 0 },
            ..MatchOptions::default()
        };
        let context = crate::dynamic::context(
            &vitaminc_aead_frame::serde::to_vec(&("users", "name")).expect("frames"),
        )
        .expect("context");
        let field = FieldPlan::new(
            "name",
            context,
            vec![record::Output::Term(IndexSpec::Match(options))],
        )
        .and_then(|field| field.with_type(ValueKind::String))
        .expect("the field");
        let plan = Plan::new(vec![field]).expect("the plan");
        let invalid = |error: Error| {
            assert!(
                matches!(term_error(&error), Some(TermError::InvalidOptions(_))),
                "{error:?}"
            );
        };
        invalid(
            check_query(&plan, "name", OpSpec::Matches, text("alice"), &NoTargets).unwrap_err(),
        );
        invalid(
            verify(
                &plan,
                "name",
                OpSpec::Matches,
                text("alice"),
                &[text("alice")],
                &NoTargets,
            )
            .unwrap_err(),
        );
    }

    /// `target_limit` is the typed `MatchQuery::target_limit` for the term
    /// `query_term` returned, read from its bytes.
    #[tokio::test]
    async fn target_limit_answers_as_the_typed_match_query() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = crate::Plan::context("users/name")
            .with::<String, _>(Match::default())
            .build()
            .unwrap();
        let typed = cipher.query(op::Matches, "ali").on(&plan).await.unwrap();
        let term = query(&keyset, "name", OpSpec::Matches, text("ali"))
            .await
            .unwrap();
        let Operand::One(bytes) = term.operand() else {
            panic!("one term");
        };
        let measured = Stats::measured(1_000_000, [(40, 500_000), (120, 500_000)]);
        for stats in [
            measured.clone(),
            measured.clone().with_confidence(0.5),
            Stats::declared(1_000_000),
        ] {
            let limit = target_limit(
                &users(),
                "name",
                OpSpec::Matches,
                bytes,
                10,
                &stats,
                &NoTargets,
            )
            .unwrap();
            assert_eq!(limit, typed.target_limit(10, &stats), "{stats:?}");
        }
        assert!(matches!(
            target_limit(&users(), "name", OpSpec::Matches, bytes, 10, &measured, &NoTargets),
            Ok(Limit::Rows(rows)) if rows > 10
        ));
        assert_eq!(
            target_limit(
                &users(),
                "name",
                OpSpec::Matches,
                bytes,
                10,
                &Stats::declared(1_000_000),
                &NoTargets
            )
            .unwrap(),
            Limit::Unbounded,
            "a data plan's match index declares no prior"
        );
    }

    #[test]
    fn target_limit_refuses_a_term_its_index_would_not_derive() {
        let stats = Stats::measured(100, [(10, 100)]);
        let limit = |name: &str, op: OpSpec, term: &[u8]| {
            target_limit(&users(), name, op, term, 1, &stats, &NoTargets)
        };
        let positions = |p: &[u16]| p.iter().flat_map(|p| p.to_le_bytes()).collect::<Vec<u8>>();
        assert!(limit("name", OpSpec::Matches, &positions(&[1, 2, 255])).is_ok());
        for (what, bytes) in [
            ("none", positions(&[])),
            ("half a position", vec![1, 0, 2]),
            ("outside the filter", positions(&[1, 256])),
            ("out of order", positions(&[2, 1])),
            ("repeated", positions(&[2, 2])),
        ] {
            let error = limit("name", OpSpec::Matches, &bytes).unwrap_err();
            assert_eq!(
                reason_of(&error),
                (Some("name"), Some(Reason::NotAQueryTerm)),
                "{what}"
            );
        }
        let error = limit("email", OpSpec::Eq, &[0; 32]).unwrap_err();
        assert_eq!(
            reason_of(&error),
            (Some("email"), Some(Reason::ExactOperator))
        );
        // A stored filter under the same options reads as a term too: the
        // bytes say nothing of which side derived them, and the limit is a
        // number, not a query.
        let stored = MatchTerms::<crate::sem::DefaultMatch>::from_positions(vec![3, 9]).unwrap();
        assert!(limit("name", OpSpec::Matches, &stored.to_bytes()).is_ok());
    }

    #[test]
    fn statistics_read_from_their_wire_form() {
        let object = |entries: Vec<(&str, Tree)>| {
            Tree::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v))
                    .collect(),
            )
        };
        let pair = |bits: u32, rows: u64| Tree::Array(vec![Tree::UInt32(bits), Tree::UInt64(rows)]);
        assert_eq!(
            stats_frame(&object(vec![("rows", Tree::UInt64(9))])).unwrap(),
            Stats::declared(9)
        );
        assert_eq!(
            stats_frame(&object(vec![
                ("rows", Tree::Int64(9)),
                ("histogram", Tree::Null),
                ("confidence", Tree::Null),
            ]))
            .unwrap(),
            Stats::declared(9)
        );
        assert_eq!(
            stats_frame(&object(vec![
                ("histogram", Tree::Array(vec![pair(3, 4), pair(5, 6)])),
                ("confidence", Tree::Float64(0.9)),
                ("rows", Tree::UInt32(10)),
            ]))
            .unwrap(),
            Stats::measured(10, [(3, 4), (5, 6)]).with_confidence(0.9)
        );
        for (what, bad) in [
            ("not an object", Tree::UInt64(9)),
            ("an array by position", Tree::Array(vec![Tree::UInt64(9)])),
            (
                "every key by position",
                Tree::Array(vec![
                    Tree::UInt64(9),
                    Tree::Array(vec![pair(3, 4)]),
                    Tree::Float64(0.5),
                ]),
            ),
            ("no rows", object(vec![])),
            ("null rows", object(vec![("rows", Tree::Null)])),
            ("negative rows", object(vec![("rows", Tree::Int64(-1))])),
            ("float rows", object(vec![("rows", Tree::Float64(9.0))])),
            (
                "rows twice",
                object(vec![("rows", Tree::UInt64(1)), ("rows", Tree::UInt64(1))]),
            ),
            (
                "unknown key",
                object(vec![("rows", Tree::UInt64(1)), ("want", Tree::Null)]),
            ),
            (
                "bucket not a pair",
                object(vec![
                    ("rows", Tree::UInt64(1)),
                    ("histogram", Tree::Array(vec![Tree::UInt32(3)])),
                ]),
            ),
            (
                "bits too wide",
                object(vec![
                    ("rows", Tree::UInt64(1)),
                    (
                        "histogram",
                        Tree::Array(vec![Tree::Array(vec![
                            Tree::UInt64(u64::from(u32::MAX) + 1),
                            Tree::UInt64(1),
                        ])]),
                    ),
                ]),
            ),
            (
                "confidence as text",
                object(vec![
                    ("rows", Tree::UInt64(1)),
                    ("confidence", text("high")),
                ]),
            ),
            (
                "confidence as an integer",
                object(vec![
                    ("rows", Tree::UInt64(1)),
                    ("confidence", Tree::UInt64(1)),
                ]),
            ),
        ] {
            let error = stats_frame(&bad).unwrap_err();
            assert_eq!(reason_of(&error), (None, Some(Reason::NotStats)), "{what}");
        }
    }

    /// The new kinds query as the typed path does: an `int8` field's
    /// orderings are the typed `i8` ORE terms, whatever integer width the
    /// host sends; an `int128` field's range is the typed `i128` range; a
    /// date, timestamp and decimal answer `eq` with the equality term the
    /// record path stores; and an integer reads as a decimal, so `34`
    /// finds `34.00`.
    #[tokio::test]
    async fn the_new_kinds_derive_the_typed_paths_terms() {
        use vitaminc_aead::plaintext::{Int, Logical, Physical, Raw, TimeUnit};
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = record::plan(&frame_of(&Tree::Object(vec![
            field("tiny", "int16", vec![text("c"), text("ore")]),
            field("huge", "int128", vec![text("c"), text("ope")]),
            field("day", "date", vec![text("c"), text("eq")]),
            field("at", "timestamp", vec![text("c"), text("eq")]),
            field("price", "decimal", vec![text("c"), text("eq")]),
        ])))
        .expect("the plan parses");
        let frame = |ty: Option<Logical>, value: Physical<'_>| {
            ValueFrame::of(Raw(ty, value)).expect("a value")
        };
        let int = |int: Int| frame(None, Physical::Int(int));
        let ask = |name: &'static str, operator: OpSpec, input: ValueFrame| {
            let plan = &plan;
            let keyset = &keyset;
            async move {
                query_term(keyset, plan, name, operator, input, &NoTargets)?
                    .await
                    .map_err(Error::Cipher)
            }
        };

        let tiny = crate::Plan::context("users/tiny")
            .with::<i16, _>(Ore)
            .build()
            .unwrap();
        let typed = cipher.query(op::Lt, &-8i16).on(&tiny).await.unwrap();
        for input in [
            int(Int::I8(-8)),
            vf(&Tree::Int64(-8)),
            vf(&Tree::Float64(-8.0)),
        ] {
            let term = ask("tiny", OpSpec::Lt, input).await.unwrap();
            assert_eq!(term.operand(), &Operand::One(typed.to_bytes()));
        }
        let refused = ask("tiny", OpSpec::Lt, vf(&Tree::Int64(70_000))).await;
        assert!(
            matches!(&refused, Err(error) if reason_of(error) == (Some("tiny"), Some(Reason::FieldType))),
            "70000 is no int16: {refused:?}"
        );

        let huge = crate::Plan::context("users/huge")
            .with::<i128, _>(Ope)
            .build()
            .unwrap();
        let typed = cipher
            .query(op::Between, &(i128::MIN, i128::MAX))
            .via(Ope)
            .on(&huge)
            .await
            .unwrap();
        let bounds = ValueFrame::of(vec![
            Raw(None, Physical::Int(Int::I128(i128::MIN))),
            Raw(None, Physical::Int(Int::I128(i128::MAX))),
        ])
        .unwrap();
        let term = ask("huge", OpSpec::Between, bounds).await.unwrap();
        assert_eq!(
            term.operand(),
            &Operand::Range {
                lo: typed.lo().to_bytes(),
                hi: typed.hi().to_bytes(),
            }
        );
        let inverted = ValueFrame::of(vec![
            Raw(None, Physical::Int(Int::I128(1))),
            Raw(None, Physical::Int(Int::I128(0))),
        ])
        .unwrap();
        assert!(
            ask("huge", OpSpec::Between, inverted).await.is_ok(),
            "an inverted 128-bit range is not refused"
        );

        let stored = |value: &ValueFrame, name: &'static str| {
            let keyset = &keyset;
            let ctx = super::super::context(
                &vitaminc_aead_frame::serde::to_vec(&("users", name)).expect("frames"),
            )
            .expect("context");
            let value = value.clone();
            async move {
                super::super::term(keyset, &value, &IndexSpec::Equality, ctx)
                    .await
                    .unwrap()
            }
        };
        let day = frame(Some(Logical::Date), Physical::Int(Int::I32(19_782)));
        let term = ask("day", OpSpec::Eq, day.clone()).await.unwrap();
        assert_eq!(term.operand(), &Operand::One(stored(&day, "day").await));
        let at = frame(
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I128(1_760_662_923_123_456_789)),
        );
        let term = ask("at", OpSpec::Eq, at.clone()).await.unwrap();
        assert_eq!(term.operand(), &Operand::One(stored(&at, "at").await));
        let price = frame(
            Some(Logical::Decimal { scale: 2 }),
            Physical::Int(Int::I64(3400)),
        );
        let thirty_four = stored(&price, "price").await;
        for input in [
            frame(
                Some(Logical::Decimal { scale: 0 }),
                Physical::Int(Int::I64(34)),
            ),
            vf(&Tree::Int32(34)),
            int(Int::U8(34)),
        ] {
            let term = ask("price", OpSpec::Eq, input).await.unwrap();
            assert_eq!(
                term.operand(),
                &Operand::One(thirty_four.clone()),
                "34 is 34.00"
            );
        }
        for (name, operator) in [
            ("day", OpSpec::Lt),
            ("at", OpSpec::Gt),
            ("price", OpSpec::Between),
        ] {
            let refused = ask(name, operator, vf(&Tree::Int32(1))).await;
            assert!(
                matches!(&refused, Err(error) if reason_of(error) == (Some(name), Some(Reason::OperatorNotAnswered))),
                "{name} answers no ordering: {refused:?}"
            );
        }
        let operators = |name: &str| {
            field_operators(&plan, name, &NoTargets)
                .unwrap()
                .into_iter()
                .map(|(op, _)| op)
                .collect::<Vec<_>>()
        };
        assert_eq!(operators("day"), [OpSpec::Eq]);
        assert_eq!(operators("price"), [OpSpec::Eq]);
        assert_eq!(
            operators("tiny"),
            [
                OpSpec::Lt,
                OpSpec::Lte,
                OpSpec::Gt,
                OpSpec::Gte,
                OpSpec::Between
            ]
        );
    }

    /// A range whose low bound is above its high bound is not refused, as
    /// SQL's `BETWEEN` is not: it is checked, and its terms derived, like
    /// any other range, and matches nothing.
    #[tokio::test]
    async fn an_inverted_range_is_a_query_like_any_other() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        // `score` declares OPE alone, whose terms compare as bytes.
        let inverted = Tree::Array(vec![Tree::Int64(65), Tree::Int64(18)]);
        assert!(check_query(
            &users(),
            "score",
            OpSpec::Between,
            vf(&inverted),
            &NoTargets
        )
        .is_ok());
        let term = query(&keyset, "score", OpSpec::Between, inverted)
            .await
            .expect("derived");
        let Operand::Range { lo, hi } = term.operand() else {
            panic!("a range");
        };
        assert!(lo > hi, "the bounds as given, and the terms in their order");
    }

    #[test]
    fn a_count_is_read_at_any_width_and_never_negative() {
        let rows = |value: Tree| stats_frame(&Tree::Object(vec![("rows".into(), value)]));
        for value in [
            Tree::Int32(7),
            Tree::Int64(7),
            Tree::UInt32(7),
            Tree::UInt64(7),
        ] {
            assert_eq!(rows(value).unwrap(), Stats::declared(7));
        }
        for value in [Tree::Int32(-7), Tree::Int64(-7), Tree::Float64(7.0)] {
            assert!(rows(value).is_err());
        }
        let confidence = stats_frame(&Tree::Object(vec![
            ("rows".into(), Tree::Int32(3)),
            ("confidence".into(), Tree::Float32(0.5)),
        ]))
        .unwrap();
        assert_eq!(confidence, Stats::declared(3).with_confidence(0.5));
    }

    #[test]
    fn a_limit_is_its_rows_or_null() {
        assert!(matches!(
            value_of(&Limit::Rows(11).rows()),
            Tree::UInt64(11)
        ));
        assert!(matches!(value_of(&Limit::Unbounded.rows()), Tree::Null));
    }

    #[tokio::test]
    async fn a_query_term_writes_every_key_in_order() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let term = query(
            &keyset,
            "age",
            OpSpec::Between,
            Tree::Array(vec![Tree::UInt32(1), Tree::UInt32(2)]),
        )
        .await
        .unwrap();
        let Tree::Object(entries) = value_of(&term) else {
            panic!("an object");
        };
        let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["operator", "fidelity", "index", "domain", "term"]);
        assert!(matches!(&entries[0].1, Tree::String(s) if s.as_bytes() == b"between"));
        assert!(matches!(&entries[1].1, Tree::String(s) if s.as_bytes() == b"exact"));
        assert!(matches!(&entries[2].1, Tree::String(s) if s.as_bytes() == b"ore"));
        assert!(matches!(&entries[3].1, Tree::Null));
        let Operand::Range { lo, hi } = term.operand() else {
            panic!("a range");
        };
        assert!(matches!(
            &entries[4].1,
            Tree::Array(bounds) if matches!(
                bounds.as_slice(),
                [Tree::Bytes(l), Tree::Bytes(h)] if l.as_slice() == lo && h.as_slice() == hi
            )
        ));
    }

    fn descriptor(
        kind: Option<ValueKind>,
        indexes: &[&str],
        query: bool,
        producible: bool,
    ) -> TargetDescriptor {
        TargetDescriptor::new(
            "Some",
            "some",
            "",
            kind,
            "public.some",
            indexes.iter().map(|i| (*i).to_owned()).collect(),
            query.then(|| "SomeQuery".to_owned()),
            query.then(|| "eql_v3.query_some".to_owned()),
            producible,
            (!producible).then(|| "not yet".to_owned()),
        )
    }

    /// A type answers the exact operators of one value its indexes answer,
    /// and only once the engine produces it and it has a query twin.
    #[test]
    fn a_target_answers_the_exact_single_value_operators_of_its_indexes() {
        let string = Some(ValueKind::String);
        let int = Some(ValueKind::Int64);
        assert_eq!(
            descriptor(string, &["eq"], true, true).operators(),
            [OpSpec::Eq]
        );
        assert_eq!(
            descriptor(int, &["eq", "ore"], true, true).operators(),
            [OpSpec::Eq, OpSpec::Lt, OpSpec::Lte, OpSpec::Gt, OpSpec::Gte],
            "no between: the twin is one value"
        );
        assert!(
            descriptor(string, &["match"], true, true)
                .operators()
                .is_empty(),
            "no probabilistic operator until the descriptor carries the index's options"
        );
        let options = eql_match();
        let with_options =
            descriptor(string, &["match"], true, true).with_match_options(options.clone());
        assert_eq!(with_options.operators(), [OpSpec::Matches]);
        assert_eq!(
            target_operators(&with_options),
            [(OpSpec::Matches, IndexSpec::Match(options))],
            "the type's match index answers under the type's options"
        );
        assert!(descriptor(string, &["eq"], true, false)
            .operators()
            .is_empty());
        assert!(descriptor(string, &["eq"], false, true)
            .operators()
            .is_empty());
        assert!(descriptor(None, &["eq"], true, true).operators().is_empty());
        assert!(descriptor(Some(ValueKind::Object), &["json"], true, true)
            .operators()
            .is_empty());
    }

    #[test]
    fn a_targets_operators_are_listed_in_its_wire_form() {
        let Tree::Object(entries) =
            value_of(&descriptor(Some(ValueKind::Int64), &["ore"], true, true))
        else {
            panic!("an object");
        };
        let (key, Tree::Array(operators)) = &entries[10] else {
            panic!("a list");
        };
        assert_eq!(key, "operators");
        assert_eq!(operators.len(), 4);
        let Tree::Object(first) = &operators[0] else {
            panic!("an object");
        };
        let first: Vec<(&str, &[u8])> = first
            .iter()
            .map(|(k, v)| match v {
                Tree::String(s) => (k.as_str(), s.as_bytes()),
                _ => panic!("{k} is a string"),
            })
            .collect();
        assert_eq!(
            first,
            [
                ("operator", b"lt".as_slice()),
                ("fidelity", b"exact".as_slice()),
                ("arity", b"one".as_slice()),
                ("index", b"ore".as_slice())
            ]
        );
    }

    /// What a field is said to answer is what a query on it finds: every
    /// listed operator derives a term through the listed index, and every
    /// other is refused as not answered.
    #[tokio::test]
    async fn a_fields_operators_are_exactly_the_queries_it_answers() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let input = |kind: &str, op: OpSpec| {
            let one = if kind == "string" {
                text("alice smith")
            } else {
                Tree::UInt32(7)
            };
            if op.takes_pair() {
                Tree::Array(vec![one.clone(), one])
            } else {
                one
            }
        };
        for (name, kind, want) in [
            ("email", "string", vec![(OpSpec::Eq, IndexSpec::Equality)]),
            (
                "name",
                "string",
                vec![(OpSpec::Matches, IndexSpec::Match(MatchOptions::default()))],
            ),
            (
                "age",
                "uint32",
                vec![
                    (OpSpec::Lt, IndexSpec::Ore),
                    (OpSpec::Lte, IndexSpec::Ore),
                    (OpSpec::Gt, IndexSpec::Ore),
                    (OpSpec::Gte, IndexSpec::Ore),
                    (OpSpec::Between, IndexSpec::Ore),
                ],
            ),
            (
                "nickname",
                "string",
                vec![
                    (OpSpec::Lt, IndexSpec::Ore),
                    (OpSpec::Lte, IndexSpec::Ore),
                    (OpSpec::Gt, IndexSpec::Ore),
                    (OpSpec::Gte, IndexSpec::Ore),
                    (OpSpec::Between, IndexSpec::Ore),
                ],
            ),
        ] {
            let listed = field_operators(&users(), name, &NoTargets).unwrap();
            assert_eq!(listed, want, "{name}");
            for op in OpSpec::ALL {
                let found = query(&keyset, name, op, input(kind, op)).await;
                match (listed.iter().find(|(listed, _)| *listed == op), found) {
                    (Some((_, index)), Ok(term)) => {
                        assert_eq!(term.index(), index, "{name} {op}");
                    }
                    (Some(_), Err(error)) => panic!("{name} {op} is listed and refused: {error}"),
                    (None, Ok(_)) => panic!("{name} {op} is not listed and answered"),
                    (None, Err(error)) => assert_eq!(
                        reason_of(&error),
                        (Some(name), Some(Reason::OperatorNotAnswered)),
                        "{name} {op}"
                    ),
                }
            }
        }
    }

    #[test]
    fn a_field_the_plan_lacks_has_no_operators() {
        let error = field_operators(&users(), "phone", &NoTargets).unwrap_err();
        assert_eq!(
            reason_of(&error),
            (Some("phone"), Some(Reason::NoSuchField))
        );
    }

    #[test]
    fn an_operator_is_written_with_every_key_in_order() {
        let Tree::Object(entries) = operator_value(OpSpec::Between, &IndexSpec::Ope) else {
            panic!("an object");
        };
        let entries: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(k, v)| match v {
                Tree::String(s) => (k.as_str(), s.as_bytes()),
                _ => panic!("{k} is a string"),
            })
            .collect();
        assert_eq!(
            entries,
            [
                ("operator", b"between".as_slice()),
                ("fidelity", b"exact".as_slice()),
                ("arity", b"pair".as_slice()),
                ("index", b"ope".as_slice())
            ]
        );
        let Tree::Object(entries) =
            operator_value(OpSpec::Matches, &IndexSpec::Match(MatchOptions::default()))
        else {
            panic!("an object");
        };
        assert!(matches!(&entries[1].1, Tree::String(s) if s.as_bytes() == b"probabilistic"));
        assert!(matches!(&entries[2].1, Tree::String(s) if s.as_bytes() == b"one"));
    }

    /// EQL's match options: not the default, so a test that passes under
    /// them did not fall back to the default by mistake.
    fn eql_match() -> MatchOptions {
        MatchOptions {
            k: 6,
            m: 2048,
            ..MatchOptions::default()
        }
    }

    /// A resolver holding one type with a match index built under
    /// [`eql_match`], whose query twin is a fixed JSON value with a `bf`.
    struct MatchType;

    impl TargetResolver for MatchType {
        fn targets(&self) -> Vec<TargetDescriptor> {
            vec![descriptor(Some(ValueKind::String), &["match"], true, true)
                .with_match_options(eql_match())]
        }
        fn encrypt<'a, K: 'static>(
            &self,
            _: &str,
            _: &'a KeysetCipher<'_, K>,
            _: &Label,
            _: ValueFrame,
        ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
            unreachable!("a query encrypts nothing")
        }
        fn decrypt<'a, K: 'static>(
            &self,
            _: &str,
            _: &'a crate::StackCipher<K>,
            _: &Label,
            _: &[u8],
        ) -> Result<Pending<'a, ValueFrame, K>, TargetError> {
            unreachable!("a query decrypts nothing")
        }
        fn query<'a, K: 'static>(
            &self,
            _: &str,
            _: &IndexSpec,
            keyset: &'a KeysetCipher<'_, K>,
            _: &Label,
            _: ValueFrame,
        ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
            Ok(Pending::ready(keyset, Ok(br#"{"bf":[1,5,2047]}"#.to_vec())))
        }
    }

    fn match_type_plan() -> Plan {
        record::plan_with(
            &frame_of(&Tree::Object(vec![(
                "name".into(),
                Tree::Object(vec![
                    (
                        "context".into(),
                        Tree::Array(vec![text("users"), text("name")]),
                    ),
                    ("target".into(), text("Some")),
                ]),
            )])),
            &MatchType,
        )
        .unwrap()
    }

    /// A type whose match options are known answers `matches` through its
    /// twin: the term is the twin's JSON under its query domain, the
    /// query's refusals come first, and `verify` and `target_limit` run
    /// under the type's options, reading the twin's `bf`.
    #[tokio::test]
    async fn a_target_with_match_options_answers_matches_through_its_twin() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = match_type_plan();
        assert_eq!(
            field_operators(&plan, "name", &MatchType).unwrap(),
            [(OpSpec::Matches, IndexSpec::Match(eql_match()))]
        );
        let term = query_term(
            &keyset,
            &plan,
            "name",
            OpSpec::Matches,
            text("Alice"),
            &MatchType,
        )
        .unwrap()
        .await
        .unwrap();
        assert_eq!(
            term.operand(),
            &Operand::One(br#"{"bf":[1,5,2047]}"#.to_vec())
        );
        assert_eq!(term.domain(), Some("eql_v3.query_some"));
        assert_eq!(term.fidelity(), Fidelity::Probabilistic);

        // Text that cuts no token is refused before the twin is asked for.
        let error = query_term(
            &keyset,
            &plan,
            "name",
            OpSpec::Matches,
            text("al"),
            &MatchType,
        )
        .map(drop)
        .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Cipher(crate::Error::Term(TermError::EmptyTermText))
            ),
            "{error:?}"
        );
        let error = query_term(
            &keyset,
            &plan,
            "name",
            OpSpec::Eq,
            text("Alice"),
            &MatchType,
        )
        .map(drop)
        .unwrap_err();
        assert_eq!(
            reason_of(&error),
            (Some("name"), Some(Reason::OperatorNotAnswered))
        );

        assert_eq!(
            verify(
                &plan,
                "name",
                OpSpec::Matches,
                text("ALICE"),
                &[text("say alice nguyen"), text("alison"), Tree::Null],
                &MatchType,
            )
            .unwrap(),
            [true, false, false]
        );

        let stats = Stats::declared(1_000_000);
        let options = eql_match();
        assert_eq!(
            target_limit(
                &plan,
                "name",
                OpSpec::Matches,
                br#"{"bf":[1,5,2047]}"#,
                10,
                &stats,
                &MatchType
            )
            .unwrap(),
            match_limit(3, &options, None, 10, &stats),
            "three positions read from the twin's bf"
        );
        for refused in [
            br#"{"bf":[]}"#.as_slice(),
            br#"{"bf":[5,1]}"#,
            br#"{"bf":[5,5]}"#,
            br#"{"bf":[1,2048]}"#,
            br#"{"bf":[-1]}"#,
            br#"{"hm":"00"}"#,
            br#"[1,5]"#,
            &[1, 0, 5, 0],
        ] {
            let error = target_limit(
                &plan,
                "name",
                OpSpec::Matches,
                refused,
                10,
                &stats,
                &MatchType,
            )
            .unwrap_err();
            assert_eq!(
                reason_of(&error),
                (Some("name"), Some(Reason::NotAQueryTerm)),
                "{}",
                String::from_utf8_lossy(refused)
            );
        }
    }

    /// A resolver holding one type that answers `eq`, whose query is a
    /// fixed JSON value: what a target field's query term carries.
    struct OneType;

    impl TargetResolver for OneType {
        fn targets(&self) -> Vec<TargetDescriptor> {
            vec![descriptor(Some(ValueKind::String), &["eq"], true, true)]
        }
        fn encrypt<'a, K: 'static>(
            &self,
            _: &str,
            _: &'a KeysetCipher<'_, K>,
            _: &Label,
            _: ValueFrame,
        ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
            unreachable!("a query encrypts nothing")
        }
        fn decrypt<'a, K: 'static>(
            &self,
            _: &str,
            _: &'a crate::StackCipher<K>,
            _: &Label,
            _: &[u8],
        ) -> Result<Pending<'a, ValueFrame, K>, TargetError> {
            unreachable!("a query decrypts nothing")
        }
        fn query<'a, K: 'static>(
            &self,
            _: &str,
            _: &IndexSpec,
            keyset: &'a KeysetCipher<'_, K>,
            _: &Label,
            _: ValueFrame,
        ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
            Ok(Pending::ready(keyset, Ok(br#"{"hm":"00"}"#.to_vec())))
        }
    }

    #[tokio::test]
    async fn a_target_field_answers_with_its_types_query_and_domain() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = record::plan_with(
            &frame_of(&Tree::Object(vec![(
                "email".into(),
                Tree::Object(vec![
                    (
                        "context".into(),
                        Tree::Array(vec![text("users"), text("email")]),
                    ),
                    ("target".into(), text("Some")),
                ]),
            )])),
            &OneType,
        )
        .unwrap();
        let term = query_term(&keyset, &plan, "email", OpSpec::Eq, text("a"), &OneType)
            .unwrap()
            .await
            .unwrap();
        assert_eq!(term.operand(), &Operand::One(br#"{"hm":"00"}"#.to_vec()));
        assert_eq!(term.domain(), Some("eql_v3.query_some"));
        assert_eq!(term.index(), &IndexSpec::Equality);
        assert_eq!(
            field_operators(&plan, "email", &OneType).unwrap(),
            [(OpSpec::Eq, IndexSpec::Equality)],
            "a target field answers what its type lists"
        );
        for op in [OpSpec::Lt, OpSpec::Matches, OpSpec::Between] {
            let error = query_term(&keyset, &plan, "email", op, text("a"), &OneType)
                .map(drop)
                .unwrap_err();
            assert_eq!(
                reason_of(&error),
                (Some("email"), Some(Reason::OperatorNotAnswered)),
                "{op}"
            );
        }
        let error = verify(
            &plan,
            "email",
            OpSpec::Eq,
            text("a"),
            Vec::<Tree>::new(),
            &OneType,
        )
        .unwrap_err();
        assert_eq!(
            reason_of(&error),
            (Some("email"), Some(Reason::ExactOperator))
        );
    }
}

/// The engine's answers, pinned byte for byte: these are the frames the
/// Tree encoders wrote before the answers were written by serde, and a
/// binding reads them.
#[cfg(test)]
mod wire_bytes {
    use super::*;
    use crate::sem::{MatchOptions, Tokenizer};
    use vitaminc_aead_frame::serde::to_vec;

    fn hex<T: Serialize>(value: &T) -> String {
        to_vec(value)
            .expect("frames")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn indexes() -> Vec<IndexSpec> {
        vec![
            IndexSpec::Equality,
            IndexSpec::Match(MatchOptions::default()),
            IndexSpec::Match(MatchOptions {
                tokenizer: Tokenizer::Standard,
                downcase: false,
                k: 4,
                m: 512,
            }),
            IndexSpec::Match(MatchOptions {
                tokenizer: Tokenizer::Ngram { length: 4 },
                ..MatchOptions::default()
            }),
            IndexSpec::Ore,
            IndexSpec::Ope,
        ]
    }

    fn descriptor(
        kind: Option<ValueKind>,
        indexes: &[&str],
        query: bool,
        producible: bool,
    ) -> TargetDescriptor {
        TargetDescriptor::new(
            "Some",
            "some",
            "",
            kind,
            "public.some",
            indexes.iter().map(|i| (*i).to_owned()).collect(),
            query.then(|| "SomeQuery".to_owned()),
            query.then(|| "eql_v3.query_some".to_owned()),
            producible,
            (!producible).then(|| "not yet".to_owned()),
        )
    }

    /// Every index, and every operator entry under it; three query terms,
    /// one a range and one with a domain; four limits; three pages of
    /// verdicts; four catalog entries.
    #[test]
    fn every_answer_writes_its_pinned_bytes() {
        let mut written = Vec::new();
        for index in indexes() {
            written.push(hex(&index));
            for op in OpSpec::ALL {
                written.push(hex(&OperatorEntry::new(op, &index)));
            }
        }
        for term in [
            QueryTerm {
                operator: OpSpec::Eq,
                index: IndexSpec::Equality,
                domain: None,
                operand: Operand::One(vec![1, 2, 3]),
            },
            QueryTerm {
                operator: OpSpec::Between,
                index: IndexSpec::Ope,
                domain: Some("eql_v4.query_int".to_owned()),
                operand: Operand::Range {
                    lo: vec![4],
                    hi: vec![5, 6],
                },
            },
            QueryTerm {
                operator: OpSpec::Matches,
                index: IndexSpec::Match(MatchOptions::default()),
                domain: None,
                operand: Operand::One(Vec::new()),
            },
        ] {
            written.push(hex(&term));
        }
        for limit in [
            Limit::Rows(0),
            Limit::Rows(11),
            Limit::Rows(u64::MAX),
            Limit::Unbounded,
        ] {
            written.push(hex(&limit.rows()));
        }
        for page in [vec![], vec![true], vec![true, false, true]] {
            written.push(hex(&page));
        }
        for target in [
            descriptor(Some(ValueKind::String), &["eq", "match"], true, true),
            descriptor(Some(ValueKind::String), &["eq", "match"], true, true)
                .with_match_options(MatchOptions::default()),
            descriptor(Some(ValueKind::Int64), &["ore"], true, true),
            descriptor(None, &[], false, false),
        ] {
            written.push(hex(&target));
        }
        assert_eq!(written, PINNED);
    }

    const PINNED: [&str; 62] = [
        "0a020000006571",
        "f104000000080000006f70657261746f720a02000000657108000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a020000006571",
        "f104000000080000006f70657261746f720a020000006c7408000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a020000006571",
        "f104000000080000006f70657261746f720a030000006c746508000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a020000006571",
        "f104000000080000006f70657261746f720a02000000677408000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a020000006571",
        "f104000000080000006f70657261746f720a0300000067746508000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a020000006571",
        "f104000000080000006f70657261746f720a070000006265747765656e08000000666964656c6974790a0500000065786163740500000061726974790a040000007061697205000000696e6465780a020000006571",
        "f104000000080000006f70657261746f720a070000006d61746368657308000000666964656c6974790a0d00000070726f626162696c69737469630500000061726974790a030000006f6e6505000000696e6465780a020000006571",
        "0a050000006d61746368",
        "f104000000080000006f70657261746f720a02000000657108000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a020000006c7408000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a030000006c746508000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a02000000677408000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a0300000067746508000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a070000006265747765656e08000000666964656c6974790a0500000065786163740500000061726974790a040000007061697205000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a070000006d61746368657308000000666964656c6974790a0d00000070726f626162696c69737469630500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f101000000050000006d61746368f10400000009000000746f6b656e697a65720a080000007374616e6461726408000000646f776e6361736502010000006b070400000000000000010000006d070002000000000000",
        "f104000000080000006f70657261746f720a02000000657108000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a020000006c7408000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a030000006c746508000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a02000000677408000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a0300000067746508000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a070000006265747765656e08000000666964656c6974790a0500000065786163740500000061726974790a040000007061697205000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a070000006d61746368657308000000666964656c6974790a0d00000070726f626162696c69737469630500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f101000000050000006d61746368f10400000009000000746f6b656e697a6572f101000000050000006e6772616d07040000000000000008000000646f776e6361736503010000006b070300000000000000010000006d070001000000000000",
        "f104000000080000006f70657261746f720a02000000657108000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a020000006c7408000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a030000006c746508000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a02000000677408000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a0300000067746508000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a070000006265747765656e08000000666964656c6974790a0500000065786163740500000061726974790a040000007061697205000000696e6465780a050000006d61746368",
        "f104000000080000006f70657261746f720a070000006d61746368657308000000666964656c6974790a0d00000070726f626162696c69737469630500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "0a030000006f7265",
        "f104000000080000006f70657261746f720a02000000657108000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a030000006f7265",
        "f104000000080000006f70657261746f720a020000006c7408000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a030000006f7265",
        "f104000000080000006f70657261746f720a030000006c746508000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a030000006f7265",
        "f104000000080000006f70657261746f720a02000000677408000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a030000006f7265",
        "f104000000080000006f70657261746f720a0300000067746508000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a030000006f7265",
        "f104000000080000006f70657261746f720a070000006265747765656e08000000666964656c6974790a0500000065786163740500000061726974790a040000007061697205000000696e6465780a030000006f7265",
        "f104000000080000006f70657261746f720a070000006d61746368657308000000666964656c6974790a0d00000070726f626162696c69737469630500000061726974790a030000006f6e6505000000696e6465780a030000006f7265",
        "0a030000006f7065",
        "f104000000080000006f70657261746f720a02000000657108000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a030000006f7065",
        "f104000000080000006f70657261746f720a020000006c7408000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a030000006f7065",
        "f104000000080000006f70657261746f720a030000006c746508000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a030000006f7065",
        "f104000000080000006f70657261746f720a02000000677408000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a030000006f7065",
        "f104000000080000006f70657261746f720a0300000067746508000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a030000006f7065",
        "f104000000080000006f70657261746f720a070000006265747765656e08000000666964656c6974790a0500000065786163740500000061726974790a040000007061697205000000696e6465780a030000006f7065",
        "f104000000080000006f70657261746f720a070000006d61746368657308000000666964656c6974790a0d00000070726f626162696c69737469630500000061726974790a030000006f6e6505000000696e6465780a030000006f7065",
        "f105000000080000006f70657261746f720a02000000657108000000666964656c6974790a05000000657861637405000000696e6465780a02000000657106000000646f6d61696e00040000007465726d0b03000000010203",
        "f105000000080000006f70657261746f720a070000006265747765656e08000000666964656c6974790a05000000657861637405000000696e6465780a030000006f706506000000646f6d61696e0a1000000065716c5f76342e71756572795f696e74040000007465726df0020000000b01000000040b020000000506",
        "f105000000080000006f70657261746f720a070000006d61746368657308000000666964656c6974790a0d00000070726f626162696c697374696305000000696e6465780a050000006d6174636806000000646f6d61696e00040000007465726d0b00000000",
        "070000000000000000",
        "070b00000000000000",
        "07ffffffffffffffff",
        "00",
        "f000000000",
        "f00100000003",
        "f003000000030203",
        "f10b000000040000006e616d650a04000000536f6d650600000066616d696c790a04000000736f6d65060000007375666669780a0000000009000000706c61696e746578740a06000000737472696e670a00000073716c5f646f6d61696e0a0b0000007075626c69632e736f6d6507000000696e6465786573f0020000000a0200000065710a050000006d617463680500000071756572790a09000000536f6d6551756572791000000071756572795f73716c5f646f6d61696e0a1100000065716c5f76332e71756572795f736f6d650a00000070726f64756369626c650306000000726561736f6e00090000006f70657261746f7273f001000000f104000000080000006f70657261746f720a02000000657108000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a020000006571",
        "f10b000000040000006e616d650a04000000536f6d650600000066616d696c790a04000000736f6d65060000007375666669780a0000000009000000706c61696e746578740a06000000737472696e670a00000073716c5f646f6d61696e0a0b0000007075626c69632e736f6d6507000000696e6465786573f0020000000a0200000065710a050000006d617463680500000071756572790a09000000536f6d6551756572791000000071756572795f73716c5f646f6d61696e0a1100000065716c5f76332e71756572795f736f6d650a00000070726f64756369626c650306000000726561736f6e00090000006f70657261746f7273f002000000f104000000080000006f70657261746f720a02000000657108000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a020000006571f104000000080000006f70657261746f720a070000006d61746368657308000000666964656c6974790a0d00000070726f626162696c69737469630500000061726974790a030000006f6e6505000000696e6465780a050000006d61746368",
        "f10b000000040000006e616d650a04000000536f6d650600000066616d696c790a04000000736f6d65060000007375666669780a0000000009000000706c61696e746578740a05000000696e7436340a00000073716c5f646f6d61696e0a0b0000007075626c69632e736f6d6507000000696e6465786573f0010000000a030000006f72650500000071756572790a09000000536f6d6551756572791000000071756572795f73716c5f646f6d61696e0a1100000065716c5f76332e71756572795f736f6d650a00000070726f64756369626c650306000000726561736f6e00090000006f70657261746f7273f004000000f104000000080000006f70657261746f720a020000006c7408000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a030000006f7265f104000000080000006f70657261746f720a030000006c746508000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a030000006f7265f104000000080000006f70657261746f720a02000000677408000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a030000006f7265f104000000080000006f70657261746f720a0300000067746508000000666964656c6974790a0500000065786163740500000061726974790a030000006f6e6505000000696e6465780a030000006f7265",
        "f10b000000040000006e616d650a04000000536f6d650600000066616d696c790a04000000736f6d65060000007375666669780a0000000009000000706c61696e74657874000a00000073716c5f646f6d61696e0a0b0000007075626c69632e736f6d6507000000696e6465786573f000000000050000007175657279001000000071756572795f73716c5f646f6d61696e000a00000070726f64756369626c650206000000726561736f6e0a070000006e6f7420796574090000006f70657261746f7273f000000000",
    ];
}
