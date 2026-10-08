//! Why a plan was refused.
use crate::target::IndexSpec;
use crate::LabelError;

/// Why a plan was refused: when it was built, or when it was run against a
/// value, a stored record or a query that does not match it.
///
/// Every refusal of a plan, at build or when it runs, is raised before any
/// key is requested: a plan that does not hold up never reaches ZeroKMS.
/// [`FieldValues::take`](super::FieldValues::take) reuses two of these
/// ([`NotInValue`](Self::NotInValue), [`FieldType`](Self::FieldType)) for a
/// record already in hand. Carried in [`Error::Plan`].
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
    /// `identity` was called before any field was declared, so there was no
    /// field for it to pin.
    #[error("identity was set before any field was declared")]
    #[diagnostic(code(stack_encrypt::plan_identity_without_field))]
    IdentityWithoutField,
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
    /// A field was declared both passthrough and indexed. A passthrough
    /// field is carried unsealed and unauthenticated; one that must be
    /// searchable is sealed, with its indexes beside it.
    #[error("field {field:?} is declared both passthrough and indexed")]
    #[diagnostic(
        code(stack_encrypt::plan_passthrough_indexed),
        help("A passthrough field is stored unsealed. Seal the field to index it.")
    )]
    PassthroughIndexed {
        /// The field.
        field: String,
    },
    /// A field, or a one-value plan, names the same index twice.
    #[error("{at:?} names the {index} index twice")]
    #[diagnostic(code(stack_encrypt::plan_duplicate_index))]
    DuplicateIndex {
        /// The field, or `the value` for a one-value plan.
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
    #[error("field {field:?} is not a {expected}")]
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
    /// The chains given to one [`all`](crate::all) were started on
    /// different ciphers. A batch settles through one client and resolves
    /// every keyset it names there, so a chain from another cipher would
    /// run under a keyset its own cipher never chose.
    #[error("the chains in one batch were started on different ciphers")]
    #[diagnostic(
        code(stack_encrypt::plan_mixed_ciphers),
        help("Start every chain in one batch on the same cipher.")
    )]
    MixedCiphers,
    /// A query asked a field for an index the field never declared, so it
    /// would have matched nothing.
    #[error("field {field:?} declares no {index} index")]
    #[diagnostic(
        code(stack_encrypt::plan_index_not_declared),
        help("Query the field through an index it declares, or declare the index on the field.")
    )]
    IndexNotDeclared {
        /// The field, or `the value` for a one-value plan.
        field: String,
        /// The index asked for, as its key.
        index: &'static str,
    },
    /// A query asked a field for an index the field declares with other
    /// options (a match index under another tokenizer or filter size), so
    /// its terms would never have matched.
    #[error(
        "field {field:?} declares a {} index with other options: declared {declared:?}, asked {asked:?}",
        declared.key()
    )]
    #[diagnostic(
        code(stack_encrypt::plan_index_options),
        help("Query with the options the field declares: terms derived under other options never match.")
    )]
    IndexOptions {
        /// The field, or `the value` for a one-value plan.
        field: String,
        /// The index as the field declares it.
        declared: IndexSpec,
        /// The index as the query asked for it.
        asked: IndexSpec,
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
    /// The plan was run with no context: it was built without one and has
    /// no context field, and the call named none.
    #[error(
        "the plan has no context: build it with one, name one in the call, or use a context field"
    )]
    #[diagnostic(code(stack_encrypt::plan_no_context))]
    NoContext,
    /// A field was declared both as a typed target (`encrypt_into`) and with
    /// a data verb. A field is one or the other: the target's type decides
    /// its layout and its queries.
    #[error("field {field:?} is declared both as a typed target and with data verbs")]
    #[diagnostic(code(stack_encrypt::plan_target_with_verbs))]
    TargetWithVerbs {
        /// The field.
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
            | Self::PassthroughIndexed { field }
            | Self::NotInPlan { field }
            | Self::NotInValue { field }
            | Self::NoSuchField { field }
            | Self::TargetWithVerbs { field } => payload([("field", field.as_str().into())]),
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
            Self::IndexNotDeclared { field, index } => {
                payload([("field", field.as_str().into()), ("index", (*index).into())])
            }
            Self::IndexOptions {
                field,
                declared,
                asked,
            } => payload([
                ("field", field.as_str().into()),
                ("index", declared.key().into()),
                ("declared", index_value(declared)),
                ("asked", index_value(asked)),
            ]),
            Self::TwoContextSources { first, second } => {
                payload([("first", (*first).into()), ("second", (*second).into())])
            }
            Self::IdentityWithoutField
            | Self::EmptyIndexes
            | Self::MixedCiphers
            | Self::NoContext => serde_json::Map::new(),
        }
    }
}

/// An index as a plan writes it: its key, or for a match index the object of
/// all four options (`{"match": {"tokenizer": "standard", "downcase": true,
/// "k": 3, "m": 256}}`, an n-gram tokenizer as `{"ngram": 3}`). A caller in
/// another language can read it, and it does not move when a field is added
/// to the Rust type, as `Debug` text would.
fn index_value(index: &IndexSpec) -> serde_json::Value {
    use crate::sem::Tokenizer;
    match index {
        IndexSpec::Match(options) => {
            let tokenizer = match options.tokenizer {
                Tokenizer::Standard => serde_json::Value::from("standard"),
                Tokenizer::Ngram { length } => serde_json::json!({ "ngram": length }),
            };
            serde_json::json!({
                "match": {
                    "tokenizer": tokenizer,
                    "downcase": options.downcase,
                    "k": options.k,
                    "m": options.m,
                }
            })
        }
        IndexSpec::Equality | IndexSpec::Ore | IndexSpec::Ope => index.key().into(),
    }
}
