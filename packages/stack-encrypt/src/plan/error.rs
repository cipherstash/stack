//! Why a plan was refused.
use crate::op::Op;
use crate::LabelError;

/// Why a plan was refused: when it was parsed, or when it was run against a
/// value, a stored record or a query that does not match it.
///
/// Every refusal of a plan is raised before any key is requested: a plan
/// that does not hold up never reaches ZeroKMS. Carried in [`Error::Plan`].
///
/// [`Error::Plan`]: crate::Error::Plan
///
/// Every variant has a `stack_encrypt::` miette code, and names the field
/// it is about where there is one, in its message and its
/// [`ErrorPayload`](crate::ErrorPayload). Field names describe the
/// schema, not the data, so a message may carry them. A context is data,
/// so a one-value plan's errors name `the value` in its place.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum PlanError {
    /// The plan's context is not a plain label.
    #[error("the plan's context is not a plain label: {0}")]
    #[diagnostic(code(stack_encrypt::plan_context_label))]
    ContextLabel(
        #[source]
        #[diagnostic_source]
        LabelError,
    ),
    /// A sealed or indexed field is keyed under an identity (its name,
    /// unless one is pinned) that is not a plain label segment. A
    /// passthrough field is under no label, so its name is never refused
    /// for this.
    #[error("field {field:?} is not keyed under a plain label segment: {source}")]
    #[diagnostic(
        code(stack_encrypt::plan_field_label),
        help("A field's name, or the identity pinned for it, is a plain label segment: no `/`, control characters or parentheses, and not starting with `b64:`, a digit or `-`. Pin a plain identity with `identity` to keep the name.")
    )]
    FieldLabel {
        /// The field.
        field: String,
        /// Why its name or identity is not plain.
        #[source]
        #[diagnostic_source]
        source: LabelError,
    },
    /// A field was named twice.
    #[error("field {field:?} is named twice")]
    #[diagnostic(code(stack_encrypt::plan_duplicate_field))]
    DuplicateField {
        /// The field.
        field: String,
    },
    /// Two sealed or indexed fields are keyed under one identity, so their
    /// data would share one context and their terms would be
    /// interchangeable. A passthrough field keys nothing and shares no
    /// identity.
    #[error("fields {first:?} and {second:?} are both keyed under identity {identity:?}")]
    #[diagnostic(
        code(stack_encrypt::plan_shared_identity),
        help("Give each sealed or indexed field its own identity: rename one, or pin another with `identity`.")
    )]
    SharedIdentity {
        /// The identity both use.
        identity: String,
        /// The field declared first.
        first: String,
        /// The field declared second.
        second: String,
    },
    /// A field, or a record of one value, names the same index twice.
    #[error("{at:?} names the {index} index twice")]
    #[diagnostic(code(stack_encrypt::plan_duplicate_index))]
    DuplicateIndex {
        /// The field, or `the value` for a typed declaration.
        at: String,
        /// The index named twice, as its key (`"eq"`, `"match"`, ...).
        index: &'static str,
    },
    /// A field was declared indexed with an index set that holds no index.
    /// A tuple of indexes cannot be empty, so this is only reachable through
    /// an index set sized at run time (a `Vec`), as a plan lowered from data
    /// builds.
    #[error("an indexed field declares no index")]
    #[diagnostic(code(stack_encrypt::plan_empty_indexes))]
    EmptyIndexes,
    /// The value has a field the plan does not name.
    #[error("the value has a field {field:?} the plan does not name")]
    #[diagnostic(
        code(stack_encrypt::plan_field_not_in_plan),
        help("Add the field to the plan, or leave it out of the value.")
    )]
    NotInPlan {
        /// The field.
        field: String,
    },
    /// The plan names a field the value, or the stored record, does not
    /// have.
    #[error("the plan names a field {field:?} the value does not have")]
    #[diagnostic(code(stack_encrypt::plan_field_not_in_value))]
    NotInValue {
        /// The field.
        field: String,
    },
    /// A field is not of the type the plan declares for it, so the plan
    /// cannot resolve how to seal, index or read it.
    #[error("field {field:?} is not {article} {expected}", article = article(expected))]
    #[diagnostic(
        code(stack_encrypt::plan_field_type),
        help("Give the field a value of the type the plan declares. A row stored as another type opens only after it is re-encrypted as the declared one.")
    )]
    FieldType {
        /// The field.
        field: String,
        /// The type the plan declares.
        expected: &'static str,
    },
    /// The plan has no field of that name.
    #[error("the plan has no field {field:?}")]
    #[diagnostic(code(stack_encrypt::plan_no_such_field))]
    NoSuchField {
        /// The field asked for.
        field: String,
    },
    /// A field declares two indexes that answer one operator, so a query
    /// for it would have two terms to choose from and the plan has to
    /// guess. A field declares at most one index per operator:
    /// `(Equality, Ore)` answer different operators; `(Ore, Ope)` and
    /// `(Ore, OreBlock)` do not. (Two match indexes are one index twice,
    /// [`DuplicateIndex`](Self::DuplicateIndex), which is checked first.)
    /// The second index would store a term no query uses, and an order
    /// term tells anyone who reads the column how its values order.
    #[error("field {at:?} declares two indexes that answer {operator}: {first} and {second}")]
    #[diagnostic(
        code(stack_encrypt::plan_index_overlap),
        help("Declare one index per operator on the field: drop one of the two.")
    )]
    IndexOverlap {
        /// The field, or `the value` for a one-value plan.
        at: String,
        /// The first index, as its key.
        first: &'static str,
        /// The second index, as its key.
        second: &'static str,
        /// An operator both answer.
        operator: Op,
    },
    /// The plan's context was given twice. A plan takes its context from
    /// exactly one place: the plan, the call that runs it, or a context
    /// field.
    #[error("the plan's context is given twice: by {first} and by {second}")]
    #[diagnostic(
        code(stack_encrypt::plan_two_context_sources),
        help(
            "Give the context in one place: the plan, the call that runs it, or a context field."
        )
    )]
    TwoContextSources {
        /// Who gave it first: `"the plan"`, `"the call"` or
        /// `"a context field"`.
        first: &'static str,
        /// Who gave it again.
        second: &'static str,
    },
    /// A query was extended by a binding. A binding is in the stored
    /// context alone, so a query cannot carry one: the row is found by its
    /// scopes, and the binding is checked when the row is opened.
    #[error("a query takes no binding: a binding is in the stored context only")]
    #[diagnostic(
        code(stack_encrypt::plan_bind_in_query),
        help(
            "Extend the query by its scopes alone. The binding is checked when the row is opened."
        )
    )]
    BindInQuery,
    /// A scope or binding the caller passed is empty: an empty text or byte
    /// string. A part names a tenant or a row, and an empty one would put
    /// every row under one context. Refused before any key is requested.
    #[error("a scope or binding is empty")]
    #[diagnostic(
        code(stack_encrypt::plan_empty_part),
        help("Give the scope or binding a value. An empty part would put every row under one context.")
    )]
    EmptyPart,
    /// A field's type stores the field's own context in the row, and
    /// cannot store this one. The own context is the declared part: the
    /// record's scope and the field's name. An EQL type stores it as a
    /// table and a column, so the own context must be two text parts.
    ///
    /// The scopes and bindings of the record are not stored, so they never
    /// cause this error. Refused before any key is requested.
    #[error("field {field:?}: its type cannot store the field's own context")]
    #[diagnostic(
        code(stack_encrypt::plan_context_not_storable),
        help("A field type that stores its context, such as an EQL type, stores the field's own context: the record's scope and the field's name. Declare the field in a `struct = ..` record with a `scope = \"..\"`, which gives it an own context of two text parts, or give the field a type that does not store its context.")
    )]
    ContextNotStorable {
        /// The field's own context, as it renders: the record's scope and
        /// the field's name, `members/email`. A context that no record
        /// built for a field has no own part. This is then the whole query
        /// context that the type was given.
        field: String,
    },
}

impl crate::ErrorPayload for PlanError {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        use crate::diagnostic::payload;
        match self {
            Self::ContextLabel(label) => label.payload(),
            Self::FieldLabel { field, source } => {
                let mut fields = source.payload();
                let _ = fields.insert("field".to_owned(), field.as_str().into());
                fields
            }
            Self::DuplicateField { field }
            | Self::NotInPlan { field }
            | Self::NotInValue { field }
            | Self::NoSuchField { field }
            | Self::ContextNotStorable { field } => payload([("field", field.as_str().into())]),
            Self::SharedIdentity {
                identity,
                first,
                second,
            } => payload([
                ("identity", identity.as_str().into()),
                ("first", first.as_str().into()),
                ("second", second.as_str().into()),
            ]),
            Self::DuplicateIndex { at, index } => {
                payload([("field", at.as_str().into()), ("index", (*index).into())])
            }
            Self::FieldType { field, expected } => payload([
                ("field", field.as_str().into()),
                ("expected", (*expected).into()),
            ]),
            Self::IndexOverlap {
                at,
                first,
                second,
                operator,
            } => payload([
                ("field", at.as_str().into()),
                ("first", (*first).into()),
                ("second", (*second).into()),
                ("operator", operator.name().into()),
            ]),
            Self::TwoContextSources { first, second } => {
                payload([("first", (*first).into()), ("second", (*second).into())])
            }
            Self::EmptyIndexes | Self::BindInQuery | Self::EmptyPart => serde_json::Map::new(),
        }
    }
}

/// The indefinite article for a type's name, as it is read aloud: "an" before
/// a vowel sound (`an int8`, `an i64`, `an object`), and "a" otherwise. A name
/// starting with `u` is read as "you" (`a uint8`, `a u32`), so it takes "a".
fn article(name: &str) -> &'static str {
    match name.chars().next().map(|c| c.to_ascii_lowercase()) {
        Some('a' | 'e' | 'i' | 'o') => "an",
        _ => "a",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_type_refusal_reads_with_the_right_article() {
        let message = |expected| {
            PlanError::FieldType {
                field: "f".to_owned(),
                expected,
            }
            .to_string()
        };
        assert_eq!(message("int8"), r#"field "f" is not an int8"#);
        assert_eq!(message("object"), r#"field "f" is not an object"#);
        assert_eq!(message("i64"), r#"field "f" is not an i64"#);
        assert_eq!(message("uint8"), r#"field "f" is not a uint8"#);
        assert_eq!(message("u32"), r#"field "f" is not a u32"#);
        assert_eq!(message("string"), r#"field "f" is not a string"#);
        assert_eq!(message("decimal"), r#"field "f" is not a decimal"#);
        assert_eq!(message(""), r#"field "f" is not a "#);
    }
}
