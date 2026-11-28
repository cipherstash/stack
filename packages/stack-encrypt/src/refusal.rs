//! Refusals of the caller's input: [`Error`] and its [`Reason`].
//!
//! The dynamic interface returns them directly, as `dynamic::Error` and
//! `dynamic::Reason`. Where an operation's failure is the crate's
//! [`Error`](crate::Error), a refusal of the input arrives as
//! [`Error::Input`](crate::Error::Input): a field reference's JSON query whose
//! input has the wrong shape, say, or a data plan run through
//! `dynamic::Planned` with a source that does not fit it. The code and the
//! payload are the refusal's own, so both paths report one refusal the same
//! way.
//!
//! The module compiles without the `dynamic` feature too, because the typed
//! JSON queries check their inputs with the same code as the dynamic
//! interface, and refuse them with the same reasons.
// Without the `dynamic` feature the JSON queries raise only some of the
// variants and reasons, and the dynamic items the docs link to are not
// built, so those links show as text.
#![cfg_attr(
    not(feature = "dynamic"),
    allow(dead_code, rustdoc::broken_intra_doc_links)
)]

use std::fmt;

use vitaminc_aead::plaintext::ValueKind;

use crate::target::IndexSpec;

/// What went wrong in a dynamic operation, or in the input of a typed JSON
/// query ([`crate::Error::Input`]).
///
/// The split that matters to a caller is malformed input versus something
/// else. Every variant is a statement about the value or the request,
/// decided before any key is minted or retrieved, except three:
///
/// - [`Cipher`](Error::Cipher): the operation failed.
/// - [`Internal`](Error::Internal): this module's own bug.
/// - [`Target`](Error::Target) holding
///   [`TargetError::Other`](crate::dynamic::TargetError::Other): the target
///   resolver failed for a reason of its own.
///
/// A binding maps them to its own status codes on those lines, and must not
/// report `Internal` or a resolver's failure as the caller's fault: the
/// caller cannot correct either by changing its input. As
/// [`crate::Error`], those two are [`Error::Other`](crate::Error::Other)
/// and every input refusal is [`Error::Input`](crate::Error::Input). The
/// record path's operations hand back the engine's
/// [`Pending`](crate::Pending), whose failure is the crate's
/// [`Error`](crate::Error); a [`Plan`](crate::Error::Plan) failure there is
/// again a statement about the caller's data.
///
/// Each input error names the field it is about, where there is one: in the
/// message and in the [`ErrorPayload`](crate::ErrorPayload) (`field`), so a
/// binding's caller can tell a bad plan field from a bad record field
/// without parsing text. A field is `None` where the error is about the
/// whole plan, value or record, or where the function that raised it never
/// sees a field ([`context`](crate::dynamic::context()),
/// [`read`](crate::dynamic::read)); [`in_field`](Self::in_field) names it
/// from the caller's side.
///
/// Some operations take an object: a plan, a record to encrypt, or a
/// stored record to decrypt. When the caller passes another kind of value,
/// the error names that kind as a [`Found`]. For example, the error says
/// that the record is a null or an array. The error never includes the
/// value. The kind is in the message, in [`found`](Self::found), and in the
/// payload field `found`.
///
/// An error names a kind only when the engine can read that kind without
/// decrypting anything. There are two such kinds:
///
/// - The kind of a value the caller sent.
/// - The kind of a node in the unencrypted structure of a stored record,
///   such as a list, an encrypted value, or a passthrough. A passthrough
///   is a value stored without encryption.
///
/// An error about a decrypted value never names the kind that the value
/// decrypted to. That kind was inside the ciphertext, so the kind is part
/// of the plaintext.
///
/// When the input is a batch, some errors name the row by its position,
/// counted from 0. The row is in the message, in [`row`](Self::row), and in
/// the payload field `row`. An error names the row in any of these cases:
///
/// - The row is not an object.
/// - A value in the row returned an error of its own while the engine read
///   it ([`SourceFailed`](Error::SourceFailed)).
/// - The engine could not copy a value in the row. For example, the value
///   repeats a map key, does not fit its logical type, or is nested too
///   deep.
///
/// An error from comparing the fields of a row with the plan names the
/// field and no row. Examples are a missing field, a field that the plan
/// does not name, and a value of another type than the field declares.
///
/// Not every variant has a [`Reason`]. These variants have one:
/// [`Context`](Error::Context), [`Plan`](Error::Plan),
/// [`Source`](Error::Source), [`SourceFailed`](Error::SourceFailed),
/// [`Record`](Error::Record), and [`Predicate`](Error::Predicate). The
/// reason is in the message, in [`reason`](Self::reason), and in the payload
/// (`reason`). The others carry their own payload fields instead:
/// [`Term`](Error::Term) names the index it was asked for (`index`),
/// [`UntypedIndex`](Error::UntypedIndex) the field (`field`), `Target` and
/// `Cipher` carry the payload of the error they hold, and `Internal` carries
/// none. A binding reads `reason` when it is there, and does not require it.
///
/// `Debug` prints every field as a derived `Debug` would, with one
/// exception. For [`SourceFailed`](Error::SourceFailed), `Debug` prints the
/// cause as `SourceError(..)`. The cause is an error from the caller's own
/// code. The text of that error can include the value that failed.
#[derive(thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum Error {
    /// A value used as an encryption context is not one — a boolean, float,
    /// null, object or passthrough, or a string that is not UTF-8 — or it is
    /// a context that renders empty. Leaves take a
    /// [`NonEmpty`](vitaminc_protected::NonEmpty) and nothing else, so an
    /// empty context is refused where it is read rather than sealed under.
    #[error(
        "value cannot be read as a non-empty encryption context: {reason}{}",
        in_field_text(field)
    )]
    #[diagnostic(
        code(stack_encrypt::dynamic_context),
        help("A context is a string, an integer, bytes, or a list of them, and renders to at least one byte.")
    )]
    Context {
        /// The plan field whose context it is, if it is one.
        field: Option<String>,
        /// What was wrong with it.
        reason: Reason,
    },

    /// A term was asked for a value the scheme defines no such term for: a
    /// container, null or passthrough (which have no term semantics at all),
    /// or a scalar outside the kind's domain — equality over a boolean,
    /// match over anything but text, an order term over a boolean. See
    /// [`IndexSpec::defines`].
    #[error("no {kind} term is defined for this value{}", in_field_text(field))]
    #[diagnostic(code(stack_encrypt::dynamic_term))]
    Term {
        /// The plan field the value is for, if it is one.
        field: Option<String>,
        /// The index that was asked for.
        kind: IndexSpec,
    },

    /// A record plan is malformed. The [`Reason`] names the rule that the
    /// plan breaks. For example:
    ///
    /// - The bytes are not one transport frame. A transport frame is the
    ///   binary encoding of one value.
    /// - The plan is not an object of field specs, or the plan is empty. A
    ///   field spec is the entry that describes one field.
    /// - A field has no output, or lists an output twice.
    /// - A field spec has a key that is not `"context"`, `"outputs"`,
    ///   `"target"`, `"type"`, or `"null"`.
    /// - A field names a type that does not exist.
    /// - A field asks for an index that is not defined for its declared
    ///   type.
    /// - A field's context is not a label that a plan can encrypt the field
    ///   under.
    /// - The plan declares two fields under one identity, or fields under
    ///   different contexts. No plan allows either.
    #[error(
        "record plan is malformed: {}",
        misfit_text(Subject::Plan, *reason, *found, None, field)
    )]
    #[diagnostic(code(stack_encrypt::dynamic_plan))]
    Plan {
        /// The plan field at fault, if the fault is one field's.
        field: Option<String>,
        /// What was wrong with the plan.
        reason: Reason,
        /// The kind of value that the plan or the field spec is, when it
        /// is not an object. `Some` only when `reason` is
        /// [`Reason::NotAnObject`].
        found: Option<Found>,
    },

    /// A record plan field has a term output (`"eq"`, `"match"`, `"ore"`,
    /// `"ope"`) and declares no `"type"`. The field's terms derive from the
    /// one declared kind, never from whatever tag each value arrived with,
    /// so the plan is refused when it is built, before any value arrives.
    /// Its own variant rather than a [`Plan`](Error::Plan) reason because
    /// it is the refusal a plan written before types were required meets
    /// first, and the one a caller fixes field by field.
    #[error("record plan field {field:?} has a term output and no declared type")]
    #[diagnostic(
        code(stack_encrypt::dynamic_untyped_index),
        help("Declare the field's \"type\" (\"string\", \"int64\", ...): its index terms derive from that type.")
    )]
    UntypedIndex {
        /// The field's name — its key in the plan.
        field: String,
    },

    /// A record source, or the input of a query, does not match the plan.
    ///
    /// A record source is the value that the caller asks to encrypt: one
    /// record, or an array of records. A record source gets this error in
    /// any of these cases:
    ///
    /// - The source is not an object or an array of objects. For an array,
    ///   the error names the row that is not an object.
    /// - The source has a field that the plan does not name.
    /// - The source lacks a field that the plan names, or has that field
    ///   twice.
    /// - A field that the plan encrypts contains a passthrough, or a map
    ///   that repeats a key. A passthrough is a value marked to be stored
    ///   without encryption.
    /// - A value has another type than its field declares, with no exact
    ///   conversion to that type.
    /// - A field that declares a type has the value `undefined`.
    ///
    /// The input of a query also gets this error. The error names the
    /// field. The cases are:
    ///
    /// - The field's type does not support the operator.
    /// - The input cannot be read as the field's type
    ///   ([`read`](crate::dynamic::read)), or is not the pair of values
    ///   that a range takes.
    /// - A page of values to verify contains a value of another type.
    /// - The statistics or the term are not the ones that
    ///   [`target_limit`](crate::dynamic::target_limit) reads.
    #[error("{}", source_text(*reason, *found, *row, field))]
    #[diagnostic(code(stack_encrypt::dynamic_source))]
    Source {
        /// The source field at fault, if the fault is one field's.
        field: Option<String>,
        /// The position of the row in a batch, counted from 0. `Some` when
        /// the row is not an object, or when the engine could not copy a
        /// value in the row.
        row: Option<usize>,
        /// What was wrong with the source.
        reason: Reason,
        /// The kind of value that the source or the row is, when it is not
        /// an object of fields. `Some` only when `reason` is
        /// [`Reason::NotAnObject`].
        found: Option<Found>,
    },

    /// A value in the record source returned an error of its own while the
    /// engine read it.
    ///
    /// Examples are a property getter in the caller's language that throws,
    /// and a JSON document that is nested too deep. The value's error is
    /// the cause of this error, and
    /// [`source`](std::error::Error::source) returns it.
    ///
    /// The message and `Debug` leave the cause out, because the text of the
    /// caller's error can include the value. `Debug` prints the cause as
    /// `SourceError(..)`. The reason is [`Reason::SourceFailed`].
    #[error("record source failed while it was read{}", place_text(*row, field))]
    #[diagnostic(
        code(stack_encrypt::dynamic_source_failed),
        help("The value's own error is this error's cause. It is left out of the message, because it can quote the value.")
    )]
    SourceFailed {
        /// The field whose value the engine was reading. `None` when the
        /// error happened outside the value of any field.
        field: Option<String>,
        /// The position of the row that the engine was reading, counted
        /// from 0. `None` when the source is one record, or when the error
        /// happened between two rows.
        row: Option<usize>,
        /// The error that the value returned.
        #[source]
        cause: vitaminc_aead::plaintext::SourceError,
    },

    /// A stored record to decrypt does not match the plan, in one of these
    /// ways:
    ///
    /// - The record is not a map or a sequence of maps. For a sequence, the
    ///   error names the row that is not a map.
    /// - A field with a ciphertext output is absent, or is given twice.
    /// - A field with a ciphertext output has no `"c"` node, or has two.
    ///   The `"c"` node contains the ciphertext.
    /// - A map under `"c"` repeats a key.
    /// - A passthrough is under `"c"`. A passthrough is an unencrypted
    ///   value. The engine refuses it, because the caller would get
    ///   unauthenticated bytes back as if the engine had decrypted them.
    /// - A passthrough field is absent, has no `"passthrough"` node, or has
    ///   a value of another type than the field declares.
    ///
    /// An encrypted field can decrypt to a value of another type than the
    /// field declares. That fault is not this error, because the type tag
    /// is inside the ciphertext. The [`Pending`](crate::Pending) operation
    /// fails with [`PlanError::FieldType`](crate::PlanError::FieldType)
    /// instead.
    #[error(
        "stored record does not fit the plan: {}",
        misfit_text(Subject::Record, *reason, *found, *row, field)
    )]
    #[diagnostic(code(stack_encrypt::dynamic_record))]
    Record {
        /// The stored field at fault, if the fault is one field's.
        field: Option<String>,
        /// The position of the row in a batch, counted from 0. `Some` when
        /// the row is not a map.
        row: Option<usize>,
        /// What was wrong with the stored record.
        reason: Reason,
        /// The kind of node that the stored record or the row is, when it
        /// is not a map of stored fields. `Some` only when `reason` is
        /// [`Reason::NotAnObject`].
        found: Option<Found>,
    },

    /// A `match` predicate is refused at a place in its text: text the
    /// grammar does not read, a construct of SQL/JSON path the JSON index
    /// cannot answer, a variable its `vars` do not hold, or a value of a
    /// type its comparison cannot take. The error names the construct in
    /// the grammar's own words and the byte offset in the caller's
    /// predicate text, and nothing of the text itself: a key name or a
    /// value in it can be customer data.
    #[error(
        "the predicate is refused at byte {at}: {reason} ({construct}){}",
        in_field_text(field)
    )]
    #[diagnostic(
        code(stack_encrypt::dynamic_predicate),
        help("A predicate compares a path (`$.a.b`, `$.a[*].b`, `$.\"a b\"`) with a variable (`$v`) or a literal by `==`, `!=`, `<`, `<=`, `>` or `>=`, tests `exists($.path)` or `exists($.array[*] ? (@.x == $v && @.y > $w))`, and combines them with `&&`, `||`, `!` and parentheses.")
    )]
    Predicate {
        /// The plan field the predicate is for, if one is named yet.
        field: Option<String>,
        /// What was wrong.
        reason: Reason,
        /// The construct refused, in the grammar's words: never text from
        /// the predicate.
        construct: &'static str,
        /// The byte offset in the predicate text the construct starts at.
        at: usize,
    },

    /// An invariant this module maintains did not hold — a slot count that
    /// did not line up, a re-proof that should not have been able to fail.
    /// Always a bug here, never a statement about the caller's data.
    #[error("internal invariant violated")]
    #[diagnostic(code(stack_encrypt::dynamic_internal))]
    Internal,

    /// A plan field names an EQL type as its target and the name, the
    /// field's label or type, or the value does not fit: the build holds no
    /// EQL types, no type has the name, the engine cannot produce it yet,
    /// the label is not a column, or the value is of another kind. Decided when
    /// the plan is built or the value is read, before any key is touched
    /// — save [`TargetError::Other`](crate::dynamic::TargetError::Other), which is the resolver's own failure.
    #[cfg(feature = "dynamic")]
    #[error(transparent)]
    #[diagnostic(transparent)]
    Target(#[from] crate::dynamic::TargetError),

    /// Sealing, opening or deriving failed.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Cipher(#[from] crate::Error),
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Context { field, reason } => f
                .debug_struct("Context")
                .field("field", field)
                .field("reason", reason)
                .finish(),
            Self::Term { field, kind } => f
                .debug_struct("Term")
                .field("field", field)
                .field("kind", kind)
                .finish(),
            Self::Plan {
                field,
                reason,
                found,
            } => f
                .debug_struct("Plan")
                .field("field", field)
                .field("reason", reason)
                .field("found", found)
                .finish(),
            Self::UntypedIndex { field } => f
                .debug_struct("UntypedIndex")
                .field("field", field)
                .finish(),
            Self::Source {
                field,
                row,
                reason,
                found,
            } => f
                .debug_struct("Source")
                .field("field", field)
                .field("row", row)
                .field("reason", reason)
                .field("found", found)
                .finish(),
            // The cause comes from the caller's code, and its text can
            // include the value that failed. `Debug` prints a placeholder
            // for the cause. A caller gets the cause from `source()`.
            Self::SourceFailed { field, row, .. } => f
                .debug_struct("SourceFailed")
                .field("field", field)
                .field("row", row)
                .field("cause", &format_args!("SourceError(..)"))
                .finish(),
            Self::Record {
                field,
                row,
                reason,
                found,
            } => f
                .debug_struct("Record")
                .field("field", field)
                .field("row", row)
                .field("reason", reason)
                .field("found", found)
                .finish(),
            Self::Predicate {
                field,
                reason,
                construct,
                at,
            } => f
                .debug_struct("Predicate")
                .field("field", field)
                .field("reason", reason)
                .field("construct", construct)
                .field("at", at)
                .finish(),
            Self::Internal => f.write_str("Internal"),
            #[cfg(feature = "dynamic")]
            Self::Target(error) => f.debug_tuple("Target").field(error).finish(),
            Self::Cipher(error) => f.debug_tuple("Cipher").field(error).finish(),
        }
    }
}

/// ` (field "age")`, or nothing: the tail of an input error's message.
fn in_field_text(field: &Option<String>) -> String {
    field
        .as_deref()
        .map(|field| format!(" (field {field:?})"))
        .unwrap_or_default()
}

/// The end of the message of an error that can name a row and a field.
///
/// The text is ` (row 2, field "age")`, ` (row 2)`, ` (field "age")`, or an
/// empty string when the error names neither.
fn place_text(row: Option<usize>, field: &Option<String>) -> String {
    match (row, field.as_deref()) {
        (Some(row), Some(field)) => format!(" (row {row}, field {field:?})"),
        (Some(row), None) => format!(" (row {row})"),
        (None, _) => in_field_text(field),
    }
}

/// The message of an [`Error::Source`].
///
/// The message starts with "query input does not fit the field" when only
/// the input of a query can cause the reason ([`answers_a_query`]). For
/// every other reason, the message starts with "record source does not fit
/// the plan".
fn source_text(
    reason: Reason,
    found: Option<Found>,
    row: Option<usize>,
    field: &Option<String>,
) -> String {
    let what = if answers_a_query(reason) {
        "query input does not fit the field"
    } else {
        "record source does not fit the plan"
    };
    format!(
        "{what}: {}",
        misfit_text(Subject::Source, reason, found, row, field)
    )
}

/// Returns `true` when only the input of a query can cause `reason`.
///
/// Those reasons are about an operator, a range, a term, statistics, a
/// null query, or the input of a JSON operator.
///
/// [`Reason::FieldType`] returns `false`. A query and a record both get
/// that reason for a value that cannot be read as the field's type. So the
/// message for that reason keeps the wording for a record.
fn answers_a_query(reason: Reason) -> bool {
    use Reason::*;
    matches!(
        reason,
        UnknownOperator
            | OperatorNotAnswered
            | NotARange
            | ExactOperator
            | NotAQueryTerm
            | NotStats
            | NullQuery
            | JsonInput
            | JsonSyntax
            | JsonDuplicateKey
            | JsonIntegerRange
            | JsonPathPosition
            | JsonPathWildcard
            | JsonPathNoWildcard
            | JsonNoPredicates
            | JsonWildcardBoundZero
            | JsonUnknownPredicateOp
    )
}

/// The input that an error message is about: the plan, the record source,
/// or the stored record.
#[derive(Clone, Copy)]
enum Subject {
    Plan,
    Source,
    Record,
}

/// The main part of the message of an error about a plan, a record
/// source, or a stored record.
///
/// With a [`Found`], the text is a sentence that names the input, the kind
/// of value the input is, and the kind the operation takes. An example is
/// `row 2 of the records to encrypt is null, not an object of fields`.
/// Without a [`Found`], the text is the reason, then the row and the field
/// if the error names them.
fn misfit_text(
    subject: Subject,
    reason: Reason,
    found: Option<Found>,
    row: Option<usize>,
    field: &Option<String>,
) -> String {
    let Some(found) = found else {
        return format!("{reason}{}", place_text(row, field));
    };
    let what = match (subject, row, field) {
        (Subject::Plan, _, None) => "the plan".to_owned(),
        (Subject::Plan, _, Some(_)) => "the field's spec".to_owned(),
        (Subject::Source, None, _) => "the record to encrypt".to_owned(),
        (Subject::Source, Some(row), _) => format!("row {row} of the records to encrypt"),
        (Subject::Record, None, _) => "the record to decrypt".to_owned(),
        (Subject::Record, Some(row), _) => format!("row {row} of the records to decrypt"),
    };
    let expected = match (subject, field) {
        (Subject::Plan, None) => "an object of field specs",
        (Subject::Plan, Some(_)) => "an object",
        (Subject::Source, _) => "an object of fields",
        (Subject::Record, _) => "an object of stored fields",
    };
    format!("{what} is {found}, not {expected}{}", in_field_text(field))
}

impl Error {
    /// A context error with no field named yet.
    pub(crate) fn bad_context(reason: Reason) -> Self {
        Self::Context {
            field: None,
            reason,
        }
    }

    /// A plan error with no field named yet.
    pub(crate) fn bad_plan(reason: Reason) -> Self {
        Self::Plan {
            field: None,
            reason,
            found: None,
        }
    }

    /// A source error with no field named yet.
    pub(crate) fn bad_source(reason: Reason) -> Self {
        Self::Source {
            field: None,
            row: None,
            reason,
            found: None,
        }
    }

    /// A stored-record error with no field named yet.
    pub(crate) fn bad_record(reason: Reason) -> Self {
        Self::Record {
            field: None,
            row: None,
            reason,
            found: None,
        }
    }

    /// Name the field an input error is about, where it names none yet.
    ///
    /// For a binding that calls something that never sees a field —
    /// [`read`](crate::dynamic::read) for a query value, [`context`](crate::dynamic::context()) for a field's
    /// context — and knows which field it was for. An error that already
    /// names a field, or is not an input error, comes back unchanged.
    pub fn in_field(mut self, name: &str) -> Self {
        match &mut self {
            Self::Context { field, .. }
            | Self::Term { field, .. }
            | Self::Plan { field, .. }
            | Self::Source { field, .. }
            | Self::SourceFailed { field, .. }
            | Self::Record { field, .. }
            | Self::Predicate { field, .. }
                if field.is_none() =>
            {
                *field = Some(name.to_owned());
            }
            _ => {}
        }
        self
    }

    /// The field an input error is about, if it names one.
    pub fn field(&self) -> Option<&str> {
        match self {
            Self::Context { field, .. }
            | Self::Term { field, .. }
            | Self::Plan { field, .. }
            | Self::Source { field, .. }
            | Self::SourceFailed { field, .. }
            | Self::Record { field, .. }
            | Self::Predicate { field, .. } => field.as_deref(),
            Self::UntypedIndex { field } => Some(field),
            #[cfg(feature = "dynamic")]
            Self::Target(_) => None,
            Self::Internal | Self::Cipher(_) => None,
        }
    }

    /// The refusal as the crate's [`Error`](crate::Error), for an operation
    /// whose failure can only be that. A cipher error is already the
    /// crate's and passes through, so a refused term keeps its kind. This
    /// module's own bug, and a target resolver's own failure, are not the
    /// input's fault, so they are [`Other`](crate::Error::Other). Every
    /// other refusal is [`Input`](crate::Error::Input).
    pub(crate) fn into_crate(self) -> crate::Error {
        match self {
            Self::Cipher(error) => error,
            Self::Internal => crate::Error::Other(Box::new(self)),
            #[cfg(feature = "dynamic")]
            Self::Target(crate::dynamic::TargetError::Other(_)) => {
                crate::Error::Other(Box::new(self))
            }
            input => crate::Error::Input(Box::new(input)),
        }
    }

    /// What was wrong, for a context, plan, source, record or predicate
    /// error.
    pub fn reason(&self) -> Option<Reason> {
        match self {
            Self::Context { reason, .. }
            | Self::Plan { reason, .. }
            | Self::Source { reason, .. }
            | Self::Record { reason, .. }
            | Self::Predicate { reason, .. } => Some(*reason),
            Self::SourceFailed { .. } => Some(Reason::SourceFailed),
            #[cfg(feature = "dynamic")]
            Self::Target(_) => None,
            Self::Term { .. } | Self::UntypedIndex { .. } | Self::Internal | Self::Cipher(_) => {
                None
            }
        }
    }

    /// The position of the row in a batch that the error is about, counted
    /// from 0.
    ///
    /// `Some` in any of these cases:
    ///
    /// - A row of a record source or of a stored record is not an object.
    /// - A value in the row returned an error of its own
    ///   ([`SourceFailed`](Error::SourceFailed)).
    /// - The engine could not copy a value in the row of a record source.
    ///
    /// `None` when the input is one record and not a batch, and for every
    /// other error.
    pub fn row(&self) -> Option<usize> {
        match self {
            Self::Source { row, .. }
            | Self::SourceFailed { row, .. }
            | Self::Record { row, .. } => *row,
            _ => None,
        }
    }

    /// The kind of value that the caller passed where the operation takes
    /// an object.
    ///
    /// The value is a plan, a field spec, a record source, a stored record,
    /// or a row of a batch. `Some` only for an error whose reason is
    /// [`Reason::NotAnObject`]. `None` for every other error.
    pub fn found(&self) -> Option<Found> {
        match self {
            Self::Plan { found, .. } | Self::Source { found, .. } | Self::Record { found, .. } => {
                *found
            }
            _ => None,
        }
    }
}

impl crate::ErrorPayload for Error {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut fields = match self {
            #[cfg(feature = "dynamic")]
            Self::Target(error) => return error.payload(),
            Self::Cipher(error) => return error.payload(),
            Self::Term { kind, .. } => crate::diagnostic::payload([("index", kind.key().into())]),
            Self::Predicate { construct, at, .. } => crate::diagnostic::payload([
                ("construct", (*construct).into()),
                ("at", (*at as u64).into()),
            ]),
            _ => serde_json::Map::new(),
        };
        if let Some(field) = self.field() {
            let _ = fields.insert("field".to_owned(), field.into());
        }
        if let Some(reason) = self.reason() {
            let _ = fields.insert("reason".to_owned(), reason.as_str().into());
        }
        if let Some(row) = self.row() {
            let _ = fields.insert("row".to_owned(), (row as u64).into());
        }
        if let Some(found) = self.found() {
            let _ = fields.insert("found".to_owned(), found.as_str().into());
        }
        fields
    }
}

/// Declares [`Reason`] from one list: each variant with its `snake_case`
/// name and the phrase its `Display` writes. One list, so a reason cannot be
/// added without both, and [`Reason::ALL`] cannot miss one.
macro_rules! reasons {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $snake:literal, $phrase:literal;
            )*
        }
    ) => {
        $(#[$meta])*
        pub enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )*
        }

        impl $name {
            /// Every reason, in declaration order: what a binding's test
            /// iterates.
            pub const ALL: &'static [$name] = &[$(Self::$variant,)*];

            /// Each reason's `snake_case` name and phrase, at its
            /// discriminant: the variants and these entries come from one
            /// list, in one order.
            const WORDS: &'static [(&'static str, &'static str)] = &[$(($snake, $phrase),)*];
        }
    };
}

reasons! {
    /// What was wrong with a context, plan, source, stored record or query: the
    /// reason a dynamic input error carries beside the field it names.
    ///
    /// One vocabulary for all five, since several reasons apply to more than
    /// one (a field given twice is a misfit in a source and in a stored
    /// record). [`as_str`](Self::as_str) is the `snake_case` name a binding
    /// reports in its payload's `reason` field; `Display` is the phrase the
    /// message uses. `#[non_exhaustive]`: a reason added later is not a break,
    /// and a binding that switches on one keeps a fallback.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum Reason {
        /// A plan, field spec, source or stored record is not an object (a
        /// map), or a list of them, where one is expected.
        /// [`Error::found`] returns the kind of that value. For a batch,
        /// [`Error::row`] returns the position of the row.
        NotAnObject => "not_an_object", "not an object where one is expected";
        /// A context value is of a kind a context cannot hold: a boolean,
        /// float, null, object or passthrough.
        ContextKind => "context_kind", "a boolean, float, null, object or passthrough cannot be a context";
        /// A context string is not UTF-8. No longer produced: a frame's
        /// text is UTF-8 by construction. Kept so a binding that switches on
        /// it still compiles.
        ContextNotUtf8 => "context_not_utf8", "a context string is not UTF-8";
        /// A context renders empty.
        EmptyContext => "empty_context", "the context renders empty";
        /// A part of the plan's `"bind"` list is empty. A binding ties a row
        /// to a context of its own, and an empty one would bind every row
        /// to one context.
        EmptyBinding => "empty_binding", "a binding is empty";
        /// A field's context is not a label of at least two plain segments,
        /// optionally extended by scalar parts.
        ContextNotLabel => "context_not_label", "the context is not a label of at least two plain segments, optionally extended";
        /// The plan's fields sit under different contexts, or carry different
        /// extensions.
        MixedContexts => "mixed_contexts", "the fields sit under different contexts or extensions";
        /// The plan has no fields.
        NoFields => "no_fields", "the plan has no fields";
        /// A field is named twice in the plan.
        DuplicateField => "duplicate_field", "a field is named twice";
        /// A field spec has a key other than `"context"`, `"outputs"`,
        /// `"target"`, `"type"` and `"null"`.
        UnknownKey => "unknown_key", r#"a key other than "context", "outputs", "target", "type" and "null""#;
        /// A key is given twice: in a field spec, or in a map inside a source
        /// value or a stored record.
        RepeatedKey => "repeated_key", "a key is given twice";
        /// A field spec has no `"context"`.
        MissingContext => "missing_context", r#"no "context""#;
        /// A field spec has neither `"outputs"` nor `"target"`.
        MissingOutputs => "missing_outputs", r#"neither "outputs" nor "target""#;
        /// A field spec has both `"outputs"` and `"target"`, or a field is
        /// declared both as a target and with data verbs.
        OutputsWithTarget => "outputs_with_target", r#"both "outputs" and "target""#;
        /// `"outputs"` is not a list.
        OutputsNotList => "outputs_not_list", r#""outputs" is not a list"#;
        /// An output is not `"c"`, `"passthrough"` or an index in its wire
        /// form, or a match index's options are not valid.
        UnknownOutput => "unknown_output", r#"an output is not "c", "passthrough" or a valid index"#;
        /// A field's output list, or its index set, is empty.
        NoOutputs => "no_outputs", "no outputs";
        /// A field names one output, or one index, twice.
        DuplicateOutput => "duplicate_output", "an output is named twice";
        /// Two outputs answer one operator: `ore` beside `ope`, or two match
        /// indexes. A field declares at most one index per operator, as the
        /// typed plan does (`PlanError::IndexOverlap`).
        OverlappingOutputs => "overlapping_outputs", "two outputs answer one operator: a field declares at most one index per operator";
        /// A field names `"passthrough"` beside another output.
        PassthroughWithOutputs => "passthrough_with_outputs", r#""passthrough" beside another output"#;
        /// `"target"` is not a non-empty string, nor an object of a
        /// non-empty `"name"` and the target's `"options"`; or the options
        /// do not parse as the target's (an unknown option, a path that is
        /// not one, an ordered path naming a position).
        InvalidTarget => "invalid_target", r#""target" is not a non-empty string or a {"name", "options"} object the target reads"#;
        /// `"type"` is not a string naming a value type.
        UnknownType => "unknown_type", r#""type" does not name a value type"#;
        /// The field's declared type has no such index: match on an integer,
        /// equality or an order index on a boolean, an order index on an
        /// 8-bit integer or on bytes, any index on a composite.
        IndexNotAdmitted => "index_not_admitted", "the declared type has no such index";
        /// The field declares the JSON index as an output. A data plan
        /// reaches the JSON index through a target that stores a document
        /// (`JsonSearch`, with the `json` type), whose options are the
        /// index's; the index is not an output of its own.
        JsonIndexPending => "json_index_pending", "the JSON index is reached through a target that stores a document, not as an output";
        /// The field declares the `json` type and names no target: a JSON
        /// document is stored through a target that stores one
        /// (`JsonSearch`).
        JsonNeedsTarget => "json_needs_target", r#"a "json" field names a target that stores a document"#;
        /// The field gives its target options the target does not take: a
        /// target takes the options of the index it carries, and this one
        /// carries none that has any.
        TargetOptions => "target_options", "the target takes no options";
        /// Two fields are keyed under one identity.
        SharedIdentity => "shared_identity", "two fields are keyed under one identity";
        /// The plan has no field of the name asked for.
        NoSuchField => "no_such_field", "the plan has no such field";
        /// The field asked for does not name an EQL type.
        NotATarget => "not_a_target", "the field does not name an EQL type";
        /// The field a plan takes its context from (`"context_field"`) is not a
        /// string passthrough, or the plan-level `"context_field"` key is not a
        /// string.
        ContextField => "context_field", r#"the context field is not a string passthrough, or "context_field" is not a string"#;
        /// `"bind"` is reserved at the top level of a plan for the caller's
        /// bindings, a list of scalar context parts: it is not a field name,
        /// and its value is nothing else, so a grouped part is refused.
        Bind => "bind", r#""bind" is reserved for the caller's bindings: not a field name, and its value is a list of scalar context parts"#;
        /// The plan was refused for a reason none of the above names.
        Refused => "refused", "the plan was refused";
        /// A field the plan names is not there.
        FieldMissing => "field_missing", "a field the plan names is missing";
        /// A field is there twice.
        FieldRepeated => "field_repeated", "a field is given twice";
        /// A field is there that the plan does not name.
        UnknownField => "unknown_field", "a field the plan does not name";
        /// A value is not of the type its field declares, and does not
        /// convert to it exactly ([`read`](crate::dynamic::read)).
        FieldType => "field_type", "a value is not of the type its field declares";
        /// A value is JavaScript's `undefined` where its field declares a
        /// type. A typed field takes a value of its type or a null, and
        /// `undefined` is not a null: storing it as one would hide a
        /// property name spelt wrong. Inside a container, or in a field
        /// that declares no type, `undefined` is kept as it is.
        Undefined => "undefined", "a value is undefined where its field declares a type";
        /// A passthrough sits where a sealed value, or a ciphertext, must be.
        Passthrough => "passthrough", "a passthrough where a sealed value must be";
        /// A passthrough value cannot be stored as a frame: it nests deeper,
        /// or holds text, bytes or a key longer, than a frame carries.
        Unframeable => "unframeable", "a passthrough value nests deeper, or holds a longer value, than a frame carries";
        /// A stored field is not a map of outputs.
        OutputsNotMap => "outputs_not_map", "a stored field is not a map of outputs";
        /// A stored sealed field has no `"c"` node.
        NoCiphertextNode => "no_ciphertext_node", r#"no "c" node"#;
        /// A stored passthrough field has no `"passthrough"` node.
        NoPassthroughNode => "no_passthrough_node", r#"no "passthrough" node"#;
        /// A stored target field has no `"eql"` node.
        NoEqlNode => "no_eql_node", r#"no "eql" node"#;
        /// A stored `"passthrough"` or `"eql"` node is not a passthrough
        /// carrying a value of the kind it holds.
        NotPassthrough => "not_passthrough", "a node does not carry a value of the kind it holds";
        /// A plan takes its context from a field of each record, so a query on
        /// it has no context: the caller names the context, and sends the plan
        /// under it.
        QueryContextField => "query_context_field", "the plan takes its context from a field of each record, so a query has none";
        /// The plan carries a binding, which is not in the query context, so
        /// a query cannot take it.
        BindInQuery => "bind_in_query", "a query takes no binding: a binding is in the stored context only";
        /// An operator name is not one the engine knows ([`Op::parse`](crate::dynamic::Op::parse)).
        UnknownOperator => "unknown_operator", "the operator is not one the engine knows";
        /// The field's type does not answer the operator: no index it declares
        /// answers it, or the EQL type it names does not ([`Op::answered_by`](crate::dynamic::Op::answered_by)).
        OperatorNotAnswered => "operator_not_answered", "the field's type does not answer the operator";
        /// A range's input is not a list of two values.
        NotARange => "not_a_range", "a range is not a list of two values";
        /// The operator's answer is exact, so there is nothing to verify and no
        /// fetch to size.
        ExactOperator => "exact_operator", "the operator's answer is exact, so there is nothing to verify or size";
        /// The term is not one the field's index derives for the operator.
        NotAQueryTerm => "not_a_query_term", "the term is not one the field's index derives for the operator";
        /// Statistics are not a row count with an optional histogram and
        /// confidence ([`Stats::from_frame`](crate::op::Stats::from_frame)).
        NotStats => "not_stats", "the statistics are not a row count with an optional histogram and confidence";
        /// A JSON operator's input or a read's request or rows are not the
        /// object the operator takes ([`json_open`](crate::dynamic::json_open), the JSON operators of
        /// [`Op`](crate::dynamic::Op)): a missing or unknown key, a value of another kind,
        /// a row that is not an entry, or more than one entry for a
        /// selector or a child.
        JsonInput => "json_input", "the input is not the object the JSON operator takes";
        /// A JSON value in an input is not JSON text the engine reads.
        JsonSyntax => "json_syntax", "a JSON value is not JSON text";
        /// A JSON value in an input names an object member twice.
        JsonDuplicateKey => "json_duplicate_key", "a JSON object names a member twice";
        /// A JSON value in an input has an integer literal outside the 64-bit
        /// range.
        JsonIntegerRange => "json_integer_range", "a JSON integer literal is outside the 64-bit range";
        /// A path names an array position where the operand is a selector,
        /// which reads every position as the wildcard: read a position with
        /// a subtree read.
        JsonPathPosition => "json_path_position", "a selector reads a position as the wildcard; read a position with subtree";
        /// A path has a wildcard where the operator names one node.
        JsonPathWildcard => "json_path_wildcard", "the operator names one node, and a wildcard names many";
        /// `"null"` is not `"sealed"` or `"sql"`.
        UnknownNull => "unknown_null", r#""null" is not "sealed" or "sql""#;
        /// A passthrough field says how to store a null: it carries one as
        /// it is.
        NullPassthrough => "null_passthrough", r#"a passthrough carries a null as it is, and takes no "null""#;
        /// A field with `"null": "sealed"` derives a term other than
        /// equality's, or names an EQL type that carries one: a null has an
        /// equality term and no other, so its absence would show in
        /// that term's column.
        SealedNullIndex => "sealed_null_index", r#"a null has an equality term and no other, so a field with another index takes "null": "sql""#;
        /// A field with `"null": "sealed"` declares no type, or one of no
        /// fixed width (text, bytes, a container), whose absence the length
        /// of its ciphertext would show.
        SealedNullType => "sealed_null_type", "a sealed null needs a declared type of fixed width: a bool, a number, a date, a timestamp, a decimal or a UUID";
        /// A query's input is a null, and the field does not seal its nulls
        /// beside an equality term: only `eq` on a `"null": "sealed"` field
        /// finds a null by its term. A `"null": "sql"` field's nulls are SQL
        /// `NULL`, which `IS NULL` finds.
        NullQuery => "null_query", r#"a null is found by its term only with eq on a field with "null": "sealed"; a "null": "sql" field's nulls are SQL NULL"#;
        /// An element predicate's path has no wildcard: the predicate is
        /// over the elements of an array, which `[*]` names.
        JsonPathNoWildcard => "json_path_no_wildcard", "an element predicate is over an array's elements, and the path names no wildcard";
        /// An element predicate has no predicates: it would be true of
        /// every row with an element.
        JsonNoPredicates => "json_no_predicates", "an element predicate needs at least one predicate";
        /// An element predicate's `wildcard_bound` is `0`: its reads would
        /// send the probe alone, so the predicate could never be true.
        JsonWildcardBoundZero => "json_wildcard_bound_zero", "an element predicate reads at least one element, and a wildcard_bound of 0 reads none";
        /// A predicate of an element predicate has an `op` that is not
        /// `eq`, `lt`, `lte`, `gt`, `gte` or `between`.
        JsonUnknownPredicateOp => "json_unknown_predicate_op", r#"a predicate's "op" is not eq, lt, lte, gt, gte or between"#;
        /// A `match` predicate is not text the SQL/JSON path predicate
        /// grammar reads: an unexpected character, an unterminated string,
        /// a literal that is not JSON, or text after the predicate.
        JsonPredicateSyntax => "json_predicate_syntax", "the predicate is not SQL/JSON path predicate text";
        /// A `match` predicate uses a construct of SQL/JSON path the JSON
        /// index cannot answer: arithmetic, `like_regex`, `starts with`,
        /// `is unknown`, a method, a `strict` or `lax` mode, `.*`, `.**`,
        /// a slice, `last`, a comparison of two paths or of two values, a
        /// filter outside `exists`, or `||`, `!` or `!=` inside a filter.
        JsonPredicateUnsupported => "json_predicate_unsupported", "the predicate uses a construct the JSON index cannot answer";
        /// A `match` predicate names a variable (`$v`) its `vars` do not
        /// hold.
        JsonPredicateUnknownVariable => "json_predicate_unknown_variable", "the predicate names a variable its vars do not hold";
        /// A value in a `match` predicate, a literal or a variable, is of a
        /// JSON type its comparison cannot take: an object or array
        /// anywhere, and anything but a number or a string beside `<`,
        /// `<=`, `>`, `>=` or in an element-scoped filter of more than one
        /// equality.
        JsonPredicateValueType => "json_predicate_value_type", "a value in the predicate is of a type its comparison cannot take";
        /// `!=` at a path with a wildcard: jsonpath answers it true when
        /// some element differs, which no term of the index can say.
        JsonPredicateNotEqualAtWildcard => "json_predicate_not_equal_at_wildcard", "!= at a path with a wildcard asks whether some element differs, which the index cannot answer";
        /// A `match` predicate nests parentheses, `!` and `exists` deeper
        /// than the engine reads, or names a path with more steps than a
        /// document has levels.
        JsonPredicateTooDeep => "json_predicate_too_deep", "the predicate nests too deep";
        /// The bytes given as a plan are not one transport frame. A
        /// transport frame is the binary encoding of one value. The bytes
        /// are empty, end early, repeat a key at any depth, or continue
        /// after the value ends. A plan sent as JSON text gets this reason.
        NotAFrame => "not_a_frame", "the bytes are not one transport frame";
        /// A value returned an error of its own while the engine read it
        /// ([`Error::SourceFailed`]).
        SourceFailed => "source_failed", "a value failed while it was read";
    }
}

impl Reason {
    /// The reason's `snake_case` name, as a binding reports it.
    pub fn as_str(self) -> &'static str {
        Self::WORDS[self as usize].0
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::WORDS[*self as usize].1)
    }
}

/// The kind of value that the caller passed where the operation takes an
/// object.
///
/// A `Found` names the kind of a value and never contains the value.
/// [`as_str`](Self::as_str) returns the name in the payload field `found`,
/// for a binding to read. `Display` writes the phrase that the error
/// message uses, such as "a passthrough value".
///
/// The enum is `#[non_exhaustive]`, so a later version can add a kind
/// without a breaking change. A binding that matches on the kind needs a
/// fallback case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Found {
    /// A null, with or without a declared type. The name is `"null"`.
    Null,
    /// JavaScript's `undefined`. The name is `"undefined"`.
    Undefined,
    /// A passthrough: a value marked to be stored without encryption. The
    /// name is `"passthrough"`.
    Passthrough,
    /// An encrypted value in the place of a stored record or of a row. The
    /// value is one ciphertext, or the marker of an encrypted empty list or
    /// map. The name is `"sealed"`.
    Sealed,
    /// A value of this [`ValueKind`]. The name is the schema name of the
    /// kind, such as `"string"`, `"uint32"`, or `"array"`.
    Kind(ValueKind),
    /// A scalar whose logical type this build does not define. The name is
    /// `"unknown"`.
    Unknown,
}

impl Found {
    /// The name of the kind, as the payload field `found` contains it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Undefined => "undefined",
            Self::Passthrough => "passthrough",
            Self::Sealed => "sealed",
            Self::Kind(kind) => kind.name(),
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Found {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::Undefined => f.write_str("undefined"),
            Self::Passthrough => f.write_str("a passthrough value"),
            Self::Sealed => f.write_str("a sealed value"),
            Self::Kind(kind) => {
                let name = kind.name();
                write!(f, "{} {name}", crate::plan::article(name))
            }
            Self::Unknown => f.write_str("a value of a type this build does not know"),
        }
    }
}
