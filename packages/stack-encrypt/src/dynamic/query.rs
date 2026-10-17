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
//!   the index that answers it ([`operator_to_value`] writes one): what a
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
//! `between`) through an ORE index over an integer, or an OPE index when
//! the field declares no ORE. The typed path's default for an ordering is
//! ORE, and OPE is the typed path's `.via(Ope)`; here a field that declares
//! only OPE is answered through it. An ordering over text, bytes or a float
//! is not answered, as `op::Ordered` covers the integers only.
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
//! [`QueryTerm::to_value`] writes, the statistics the object
//! [`Stats::from_value`] reads, and a limit the value
//! [`limit_to_value`] writes; each is documented where it is written.
//!
//! [`Probabilistic::verify`]: crate::op::Probabilistic::verify
//! [`Probabilistic::target_limit`]: crate::op::Probabilistic::target_limit

use std::cmp::Ordering;
use std::fmt;

use stack_kms::DataKeySource;

use super::record::{FieldPlan, Plan};
use super::term::OneScalar;
use super::term::{derive, Use};
use super::value_frame::Parts;
use super::ValueKind;
use super::{admits, read, Error, FfiValue, Reason, TargetDescriptor, TargetResolver, ValueFrame};
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
    /// assert_eq!(OpSpec::Lt.answered_by(ValueKind::String, &both), None);
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

/// The kinds the ordering operators are answered over: the integers, as
/// [`op::Ordered`](crate::op::Ordered) covers them in the typed path.
fn ordered(kind: ValueKind) -> bool {
    matches!(
        kind,
        ValueKind::Int32 | ValueKind::Int64 | ValueKind::UInt32 | ValueKind::UInt64
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
    pub fn to_value(&self) -> FfiValue {
        let bytes = |b: &[u8]| FfiValue::Bytes(vitaminc_protected::Protected::new(b.to_vec()));
        let term = match &self.operand {
            Operand::One(term) => bytes(term),
            Operand::Range { lo, hi } => FfiValue::Array(vec![bytes(lo), bytes(hi)]),
        };
        FfiValue::Object(vec![
            (
                "operator".to_owned(),
                FfiValue::String(self.operator.name().into()),
            ),
            (
                "fidelity".to_owned(),
                FfiValue::String(self.fidelity().name().into()),
            ),
            (
                "index".to_owned(),
                FfiValue::String(self.index.key().into()),
            ),
            (
                "domain".to_owned(),
                self.domain
                    .as_deref()
                    .map_or(FfiValue::Null, |domain| FfiValue::String(domain.into())),
            ),
            ("term".to_owned(), term),
        ])
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
/// with [`operator_to_value`].
///
/// ```
/// use stack_encrypt::dynamic::{field_operators, record, FfiValue, NoTargets, OpSpec};
/// use stack_encrypt::target::IndexSpec;
///
/// let text = |s: &str| FfiValue::String(s.into());
/// let plan = record::plan(FfiValue::Object(vec![(
///     "age".into(),
///     FfiValue::Object(vec![
///         ("context".into(), FfiValue::Array(vec![text("users"), text("age")])),
///         ("outputs".into(), FfiValue::Array(vec![text("c"), text("eq"), text("ore")])),
///         ("type".into(), text("uint32")),
///     ]),
/// )]))?;
///
/// let operators = field_operators(&plan, "age", &NoTargets)?;
/// assert_eq!(operators[0], (OpSpec::Eq, IndexSpec::Equality));
/// assert_eq!(operators[1], (OpSpec::Lt, IndexSpec::Ore));
/// assert_eq!(operators.len(), 6, "eq, the four comparisons and between");
/// # Ok::<(), stack_encrypt::dynamic::Error>(())
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
pub fn operator_to_value(operator: OpSpec, index: &IndexSpec) -> FfiValue {
    let text = |s: &str| FfiValue::String(s.into());
    FfiValue::Object(vec![
        ("operator".to_owned(), text(operator.name())),
        ("fidelity".to_owned(), text(operator.fidelity().name())),
        (
            "arity".to_owned(),
            text(if operator.takes_pair() { "pair" } else { "one" }),
        ),
        ("index".to_owned(), text(index.key())),
    ])
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
        return read(answer.kind, input)
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
/// term exists ([`Supports::check`](crate::op::Supports::check)): a range
/// whose low bound is above its high bound, and match text the index
/// cannot normalize or that cuts no token. The match index's own
/// derivation refuses the last two again; asking here lets a binding
/// refuse at its boundary.
fn check_input(index: &IndexSpec, input: &Input) -> Result<(), Error> {
    let refused = |error: TermError| Error::Cipher(error.into());
    match (index, input) {
        (_, Input::Pair(lo, hi)) => {
            if integer_order(lo, hi) == Some(Ordering::Greater) {
                return Err(refused(TermError::InvertedRange));
            }
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

/// The order of two integers of one kind, or `None` for anything else.
fn integer_order(lo: &ValueFrame, hi: &ValueFrame) -> Option<Ordering> {
    let (lo_kind, lo) = integer_of(lo)?;
    let (hi_kind, hi) = integer_of(hi)?;
    (lo_kind == hi_kind).then(|| lo.cmp(&hi))
}

/// An integer scalar's kind and value, or `None` for anything else.
fn integer_of(value: &ValueFrame) -> Option<(ValueKind, i128)> {
    let kind = value.kind()?;
    let int = value
        .visit(OneScalar::new(
            |ty: Option<Logical>, value: Physical<'_>| match (ty, value) {
                (None, Physical::Int(int)) => int.to_i128().ok_or(None),
                _ => Err(None),
            },
        ))
        .ok()?;
    Some((kind, int))
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
/// use stack_encrypt::dynamic::{query_term, record, FfiValue, NoTargets, OpSpec, Operand};
/// use stack_encrypt::kms::FakeDataKeySource;
/// use stack_encrypt::{op, Ore, Plan, StackCipher};
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
/// let keyset = cipher.default_keyset();
/// let text = |s: &str| FfiValue::String(s.into());
/// let plan = record::plan(FfiValue::Object(vec![(
///     "age".into(),
///     FfiValue::Object(vec![
///         ("context".into(), FfiValue::Array(vec![text("users"), text("age")])),
///         ("outputs".into(), FfiValue::Array(vec![text("c"), text("ore")])),
///         ("type".into(), text("uint32")),
///     ]),
/// )]))?;
///
/// let term = query_term(&keyset, &plan, "age", OpSpec::Lt, FfiValue::UInt32(40), &NoTargets)?.await?;
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
/// [`Error::Cipher`] for the query refusals the typed path makes: a range
/// whose low bound is above its high ([`TermError::InvertedRange`]), and
/// match text that cuts no token ([`TermError::EmptyTermText`]) or that
/// the index cannot normalize ([`TermError::Normalize`]).
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
        return Ok(super::record::query(cipher, plan, field, value, resolver)?
            .map(move |json| made(domain, Operand::One(json))));
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
    /// Read statistics from their wire form, an object:
    ///
    /// | key | value |
    /// |---|---|
    /// | `rows` | integer, required: the rows the query scans |
    /// | `histogram` | optional, or null: a list of `[bits, rows]` pairs of integers, a measured histogram of the stored filters' set-bit counts ([`Stats::measured`]); absent, the declared prior ([`Stats::declared`]) |
    /// | `confidence` | optional, or null: a float, the confidence to target instead of 99% ([`Stats::with_confidence`]) |
    ///
    /// Integers are read at any width and must not be negative.
    ///
    /// # Errors
    ///
    /// [`Error::Source`] with [`Reason::NotStats`] for anything else: not an
    /// object, no `rows`, a key given twice or not one of the three, or a
    /// value of another type.
    pub fn from_value(value: &FfiValue) -> Result<Self, Error> {
        let refused = || Error::bad_source(Reason::NotStats);
        let FfiValue::Object(entries) = value else {
            return Err(refused());
        };
        let mut seen: Vec<&str> = Vec::with_capacity(entries.len());
        let (mut rows, mut histogram, mut confidence) = (None, None, None);
        for (key, value) in entries {
            if seen.contains(&key.as_str()) {
                return Err(refused());
            }
            seen.push(key);
            match (key.as_str(), value) {
                ("histogram" | "confidence", FfiValue::Null) => {}
                ("rows", rows_value) => rows = Some(unsigned(rows_value).ok_or_else(refused)?),
                ("histogram", FfiValue::Array(buckets)) => {
                    histogram = Some(
                        buckets
                            .iter()
                            .map(|bucket| match bucket {
                                FfiValue::Array(pair) => match pair.as_slice() {
                                    [bits, rows] => Some((
                                        u32::try_from(unsigned(bits)?).ok()?,
                                        unsigned(rows)?,
                                    )),
                                    _ => None,
                                },
                                _ => None,
                            })
                            .collect::<Option<Vec<(u32, u64)>>>()
                            .ok_or_else(refused)?,
                    );
                }
                ("confidence", FfiValue::Float64(c)) => confidence = Some(*c),
                ("confidence", FfiValue::Float32(c)) => confidence = Some(f64::from(*c)),
                _ => return Err(refused()),
            }
        }
        let rows = rows.ok_or_else(refused)?;
        let stats = match histogram {
            Some(histogram) => Stats::measured(rows, histogram),
            None => Stats::declared(rows),
        };
        Ok(match confidence {
            Some(confidence) => stats.with_confidence(confidence),
            None => stats,
        })
    }
}

/// A non-negative integer of any width.
fn unsigned(value: &FfiValue) -> Option<u64> {
    match value {
        FfiValue::Int32(v) => u64::try_from(*v).ok(),
        FfiValue::Int64(v) => u64::try_from(*v).ok(),
        FfiValue::UInt32(v) => Some(u64::from(*v)),
        FfiValue::UInt64(v) => Some(*v),
        _ => None,
    }
}

/// A limit in its wire form: the rows to fetch as an unsigned 64-bit
/// integer, or null for [`Limit::Unbounded`].
pub fn limit_to_value(limit: Limit) -> FfiValue {
    limit.rows().map_or(FfiValue::Null, FfiValue::UInt64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::{record, NoTargets, TargetError};
    use crate::op::{self, Probabilistic as _};
    use crate::sem::MatchTerms;
    use crate::{Equality, Label, Match, Ope, Ore, StackCipher};
    use stack_kms::FakeDataKeySource;
    use vitaminc_protected::Controlled;

    async fn cipher() -> StackCipher<FakeDataKeySource> {
        StackCipher::builder()
            .kms(FakeDataKeySource::new())
            .init()
            .await
            .expect("build cipher")
    }

    fn text(s: &str) -> FfiValue {
        FfiValue::String(s.into())
    }

    fn vf(value: &FfiValue) -> ValueFrame {
        ValueFrame::of(value).expect("a value")
    }

    /// One field of `users`, as a binding spells it.
    fn field(name: &str, kind: &str, outputs: Vec<FfiValue>) -> (String, FfiValue) {
        (
            name.to_owned(),
            FfiValue::Object(vec![
                (
                    "context".into(),
                    FfiValue::Array(vec![text("users"), text(name)]),
                ),
                ("outputs".into(), FfiValue::Array(outputs)),
                ("type".into(), text(kind)),
            ]),
        )
    }

    /// The plan every test queries: an email with equality, a name with
    /// match, an age with ORE and OPE, a score with OPE alone, a nickname
    /// with ORE over text, and a case-sensitive handle.
    fn users() -> Plan {
        let case_sensitive = FfiValue::Object(vec![(
            "match".into(),
            FfiValue::Object(vec![("downcase".into(), FfiValue::Bool(false))]),
        )]);
        record::plan(FfiValue::Object(vec![
            field("email", "string", vec![text("c"), text("eq")]),
            field("name", "string", vec![text("c"), text("match")]),
            field("age", "uint32", vec![text("c"), text("ope"), text("ore")]),
            field("score", "int64", vec![text("ope")]),
            field("nickname", "string", vec![text("c"), text("ore")]),
            field("handle", "string", vec![text("c"), case_sensitive]),
        ]))
        .expect("the plan parses")
    }

    async fn query(
        keyset: &KeysetCipher<'_, FakeDataKeySource>,
        name: &str,
        operator: OpSpec,
        input: FfiValue,
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
            for kind in [
                ValueKind::Int32,
                ValueKind::Int64,
                ValueKind::UInt32,
                ValueKind::UInt64,
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
            for kind in [
                ValueKind::String,
                ValueKind::Bytes,
                ValueKind::Float64,
                ValueKind::Bool,
            ] {
                assert_eq!(
                    answered(op, kind, &all),
                    None,
                    "{op} is answered over integers only: {kind}"
                );
            }
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
        for input in [
            FfiValue::UInt32(40),
            FfiValue::Float64(40.0),
            FfiValue::Int64(40),
        ] {
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
            FfiValue::Array(vec![FfiValue::UInt32(18), FfiValue::UInt32(65)]),
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
            FfiValue::Array(vec![FfiValue::UInt32(7), FfiValue::UInt32(7)]),
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
            FfiValue::Array(vec![FfiValue::Int64(-5), FfiValue::Int64(5)]),
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
                OpSpec::Lt,
                text("bob"),
                Reason::OperatorNotAnswered,
            ),
            (
                "age",
                OpSpec::Eq,
                FfiValue::UInt32(1),
                Reason::OperatorNotAnswered,
            ),
            ("age", OpSpec::Lt, text("40"), Reason::FieldType),
            (
                "age",
                OpSpec::Lt,
                FfiValue::Float64(40.5),
                Reason::FieldType,
            ),
            (
                "age",
                OpSpec::Between,
                FfiValue::UInt32(40),
                Reason::NotARange,
            ),
            (
                "age",
                OpSpec::Between,
                FfiValue::Array(vec![FfiValue::UInt32(1)]),
                Reason::NotARange,
            ),
            (
                "age",
                OpSpec::Between,
                FfiValue::Array(vec![FfiValue::UInt32(1), text("2")]),
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
        let pair = |lo, hi| FfiValue::Array(vec![FfiValue::UInt32(lo), FfiValue::UInt32(hi)]);
        let cases = [
            ("age", OpSpec::Between, pair(65, 18), "inverted"),
            ("name", OpSpec::Matches, text("al"), "empty"),
            ("name", OpSpec::Matches, text("\u{0378}abc"), "normalize"),
            ("email", OpSpec::Eq, text("a\u{0378}bc"), "normalize"),
        ];
        for (name, op, input, what) in cases {
            for error in [
                query(&keyset, name, op, input.clone()).await.unwrap_err(),
                check_query(&users(), name, op, input, &NoTargets).unwrap_err(),
            ] {
                let term = term_error(&error);
                let expected = match what {
                    "inverted" => matches!(term, Some(TermError::InvertedRange)),
                    "empty" => matches!(term, Some(TermError::EmptyTermText)),
                    _ => matches!(term, Some(TermError::Normalize(_))),
                };
                assert!(expected, "{what}: {error:?}");
            }
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
                FfiValue::Object(vec![
                    ("context".into(), FfiValue::Array(vec![text(name)])),
                    ("outputs".into(), FfiValue::Array(vec![text(output)])),
                    ("type".into(), text(kind)),
                ]),
            )
        };
        let plan = record::plan(FfiValue::Object(vec![
            ("context_field".into(), text("tenant")),
            one("tenant", "string", "passthrough"),
            one("email", "string", "eq"),
        ]))
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
            Vec::<FfiValue>::new(),
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
        let values: Vec<FfiValue> = page.iter().map(|v| text(v)).collect();
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
            &[FfiValue::Null],
            &NoTargets,
        )
        .unwrap();
        assert_eq!(nulls, [false], "a null holds no token");
        let empty = verify(
            &users(),
            "name",
            OpSpec::Matches,
            text("alice"),
            Vec::<FfiValue>::new(),
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
        let refused = |name: &str, op: OpSpec, input: FfiValue, values: &[FfiValue]| {
            verify(&users(), name, op, input, values, &NoTargets).unwrap_err()
        };
        let error = refused("email", OpSpec::Eq, text("a"), &[text("a")]);
        assert_eq!(
            reason_of(&error),
            (Some("email"), Some(Reason::ExactOperator))
        );
        let error = refused("age", OpSpec::Lt, FfiValue::UInt32(1), &[]);
        assert_eq!(
            reason_of(&error),
            (Some("age"), Some(Reason::ExactOperator))
        );
        let error = refused("email", OpSpec::Matches, text("abc"), &[]);
        assert_eq!(
            reason_of(&error),
            (Some("email"), Some(Reason::OperatorNotAnswered))
        );
        let error = refused(
            "name",
            OpSpec::Matches,
            text("alice"),
            &[FfiValue::UInt32(1)],
        );
        assert_eq!(reason_of(&error), (Some("name"), Some(Reason::FieldType)));
        let error = refused("name", OpSpec::Matches, FfiValue::UInt32(1), &[]);
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
        let context = crate::dynamic::context(FfiValue::Array(vec![text("users"), text("name")]))
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
        let object = |entries: Vec<(&str, FfiValue)>| {
            FfiValue::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v))
                    .collect(),
            )
        };
        let pair = |bits: u32, rows: u64| {
            FfiValue::Array(vec![FfiValue::UInt32(bits), FfiValue::UInt64(rows)])
        };
        assert_eq!(
            Stats::from_value(&object(vec![("rows", FfiValue::UInt64(9))])).unwrap(),
            Stats::declared(9)
        );
        assert_eq!(
            Stats::from_value(&object(vec![
                ("rows", FfiValue::Int64(9)),
                ("histogram", FfiValue::Null),
                ("confidence", FfiValue::Null),
            ]))
            .unwrap(),
            Stats::declared(9)
        );
        assert_eq!(
            Stats::from_value(&object(vec![
                ("histogram", FfiValue::Array(vec![pair(3, 4), pair(5, 6)])),
                ("confidence", FfiValue::Float64(0.9)),
                ("rows", FfiValue::UInt32(10)),
            ]))
            .unwrap(),
            Stats::measured(10, [(3, 4), (5, 6)]).with_confidence(0.9)
        );
        for (what, bad) in [
            ("not an object", FfiValue::UInt64(9)),
            ("no rows", object(vec![])),
            ("null rows", object(vec![("rows", FfiValue::Null)])),
            ("negative rows", object(vec![("rows", FfiValue::Int64(-1))])),
            ("float rows", object(vec![("rows", FfiValue::Float64(9.0))])),
            (
                "rows twice",
                object(vec![
                    ("rows", FfiValue::UInt64(1)),
                    ("rows", FfiValue::UInt64(1)),
                ]),
            ),
            (
                "unknown key",
                object(vec![
                    ("rows", FfiValue::UInt64(1)),
                    ("want", FfiValue::Null),
                ]),
            ),
            (
                "bucket not a pair",
                object(vec![
                    ("rows", FfiValue::UInt64(1)),
                    ("histogram", FfiValue::Array(vec![FfiValue::UInt32(3)])),
                ]),
            ),
            (
                "bits too wide",
                object(vec![
                    ("rows", FfiValue::UInt64(1)),
                    (
                        "histogram",
                        FfiValue::Array(vec![FfiValue::Array(vec![
                            FfiValue::UInt64(u64::from(u32::MAX) + 1),
                            FfiValue::UInt64(1),
                        ])]),
                    ),
                ]),
            ),
            (
                "confidence as text",
                object(vec![
                    ("rows", FfiValue::UInt64(1)),
                    ("confidence", text("high")),
                ]),
            ),
        ] {
            let error = Stats::from_value(&bad).unwrap_err();
            assert_eq!(reason_of(&error), (None, Some(Reason::NotStats)), "{what}");
        }
    }

    /// A range is refused the wrong way round for every integer kind a
    /// field can declare, and two values of different kinds have no order
    /// here: the input was read as one kind first.
    #[test]
    fn a_range_is_ordered_within_each_integer_kind() {
        let cases = [
            (FfiValue::Int32(-1), FfiValue::Int32(1)),
            (FfiValue::Int64(-1), FfiValue::Int64(1)),
            (FfiValue::UInt32(1), FfiValue::UInt32(2)),
            (FfiValue::UInt64(1), FfiValue::UInt64(2)),
        ];
        for (lo, hi) in cases {
            let (lo, hi) = (vf(&lo), vf(&hi));
            assert_eq!(integer_order(&lo, &hi), Some(Ordering::Less));
            assert_eq!(integer_order(&hi, &lo), Some(Ordering::Greater));
            assert_eq!(integer_order(&lo, &lo), Some(Ordering::Equal));
        }
        assert_eq!(
            integer_order(&vf(&FfiValue::UInt32(1)), &vf(&FfiValue::UInt64(2))),
            None
        );
        assert_eq!(integer_order(&vf(&text("a")), &vf(&text("b"))), None);
    }

    #[test]
    fn a_count_is_read_at_any_width_and_never_negative() {
        assert_eq!(unsigned(&FfiValue::Int32(7)), Some(7));
        assert_eq!(unsigned(&FfiValue::Int64(7)), Some(7));
        assert_eq!(unsigned(&FfiValue::UInt32(7)), Some(7));
        assert_eq!(unsigned(&FfiValue::UInt64(7)), Some(7));
        assert_eq!(unsigned(&FfiValue::Int32(-7)), None);
        assert_eq!(unsigned(&FfiValue::Int64(-7)), None);
        assert_eq!(unsigned(&FfiValue::Float64(7.0)), None);
        let confidence = Stats::from_value(&FfiValue::Object(vec![
            ("rows".into(), FfiValue::Int32(3)),
            ("confidence".into(), FfiValue::Float32(0.5)),
        ]))
        .unwrap();
        assert_eq!(confidence, Stats::declared(3).with_confidence(0.5));
    }

    #[test]
    fn a_limit_is_its_rows_or_null() {
        assert!(matches!(
            limit_to_value(Limit::Rows(11)),
            FfiValue::UInt64(11)
        ));
        assert!(matches!(limit_to_value(Limit::Unbounded), FfiValue::Null));
    }

    #[tokio::test]
    async fn a_query_term_writes_every_key_in_order() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let term = query(
            &keyset,
            "age",
            OpSpec::Between,
            FfiValue::Array(vec![FfiValue::UInt32(1), FfiValue::UInt32(2)]),
        )
        .await
        .unwrap();
        let FfiValue::Object(entries) = term.to_value() else {
            panic!("an object");
        };
        let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["operator", "fidelity", "index", "domain", "term"]);
        assert!(matches!(&entries[0].1, FfiValue::String(s) if s.risky_ref() == b"between"));
        assert!(matches!(&entries[1].1, FfiValue::String(s) if s.risky_ref() == b"exact"));
        assert!(matches!(&entries[2].1, FfiValue::String(s) if s.risky_ref() == b"ore"));
        assert!(matches!(&entries[3].1, FfiValue::Null));
        let Operand::Range { lo, hi } = term.operand() else {
            panic!("a range");
        };
        assert!(matches!(
            &entries[4].1,
            FfiValue::Array(bounds) if matches!(
                bounds.as_slice(),
                [FfiValue::Bytes(l), FfiValue::Bytes(h)] if l.risky_ref() == lo && h.risky_ref() == hi
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
        let FfiValue::Object(entries) =
            descriptor(Some(ValueKind::Int64), &["ore"], true, true).to_value()
        else {
            panic!("an object");
        };
        let (key, FfiValue::Array(operators)) = &entries[10] else {
            panic!("a list");
        };
        assert_eq!(key, "operators");
        assert_eq!(operators.len(), 4);
        let FfiValue::Object(first) = &operators[0] else {
            panic!("an object");
        };
        let first: Vec<(&str, &[u8])> = first
            .iter()
            .map(|(k, v)| match v {
                FfiValue::String(s) => (k.as_str(), s.risky_ref()),
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
                FfiValue::UInt32(7)
            };
            if op.takes_pair() {
                FfiValue::Array(vec![one.clone(), one])
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
            ("nickname", "string", vec![]),
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
        let FfiValue::Object(entries) = operator_to_value(OpSpec::Between, &IndexSpec::Ope) else {
            panic!("an object");
        };
        let entries: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(k, v)| match v {
                FfiValue::String(s) => (k.as_str(), s.risky_ref()),
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
        let FfiValue::Object(entries) =
            operator_to_value(OpSpec::Matches, &IndexSpec::Match(MatchOptions::default()))
        else {
            panic!("an object");
        };
        assert!(matches!(&entries[1].1, FfiValue::String(s) if s.risky_ref() == b"probabilistic"));
        assert!(matches!(&entries[2].1, FfiValue::String(s) if s.risky_ref() == b"one"));
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
            keyset: &'a KeysetCipher<'_, K>,
            _: &Label,
            _: ValueFrame,
        ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
            Ok(Pending::ready(keyset, Ok(br#"{"bf":[1,5,2047]}"#.to_vec())))
        }
    }

    fn match_type_plan() -> Plan {
        record::plan_with(
            FfiValue::Object(vec![(
                "name".into(),
                FfiValue::Object(vec![
                    (
                        "context".into(),
                        FfiValue::Array(vec![text("users"), text("name")]),
                    ),
                    ("target".into(), text("Some")),
                ]),
            )]),
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
                &[text("say alice nguyen"), text("alison"), FfiValue::Null],
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
            FfiValue::Object(vec![(
                "email".into(),
                FfiValue::Object(vec![
                    (
                        "context".into(),
                        FfiValue::Array(vec![text("users"), text("email")]),
                    ),
                    ("target".into(), text("Some")),
                ]),
            )]),
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
            Vec::<FfiValue>::new(),
            &OneType,
        )
        .unwrap_err();
        assert_eq!(
            reason_of(&error),
            (Some("email"), Some(Reason::ExactOperator))
        );
    }
}
