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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// The plan's context is not a plain label.
    #[error("the plan's context is not a plain label: {0}")]
    ContextLabel(#[source] LabelError),
    /// A sealed or indexed field is keyed under an identity (its name,
    /// unless one is pinned) that is not a plain label segment. A
    /// passthrough field is under no label, so its name is never refused
    /// for this.
    #[error("field {field:?} is not keyed under a plain label segment: {source}")]
    FieldLabel {
        /// The field.
        field: String,
        /// Why its name or identity is not plain.
        #[source]
        source: LabelError,
    },
    /// `identity` was called before any field was declared, so there was no
    /// field for it to pin.
    #[error("identity was set before any field was declared")]
    IdentityWithoutField,
    /// A field was named twice.
    #[error("field {field:?} is named twice")]
    DuplicateField {
        /// The field.
        field: String,
    },
    /// Two sealed or indexed fields are keyed under one identity, so their
    /// data would share one context and their terms would be
    /// interchangeable. A passthrough field keys nothing and shares no
    /// identity.
    #[error("fields {first:?} and {second:?} are both keyed under identity {identity:?}")]
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
    PassthroughIndexed {
        /// The field.
        field: String,
    },
    /// A field, or a one-value plan, names the same index twice.
    #[error("{at:?} names the {index} index twice")]
    DuplicateIndex {
        /// The field, or the context of a one-value plan.
        at: String,
        /// The index named twice, as its key (`"eq"`, `"match"`, ...).
        index: &'static str,
    },
    /// A field was declared indexed with an index set that holds no index.
    /// A tuple of indexes cannot be empty, so this is only reachable through
    /// an index set sized at run time (a `Vec`), as a plan lowered from data
    /// builds.
    #[error("an indexed field declares no index")]
    EmptyIndexes,
    /// The value has a field the plan does not name.
    #[error("the value has a field {field:?} the plan does not name")]
    NotInPlan {
        /// The field.
        field: String,
    },
    /// The plan names a field the value, or the stored record, does not
    /// have.
    #[error("the plan names a field {field:?} the value does not have")]
    NotInValue {
        /// The field.
        field: String,
    },
    /// A field is not of the type the plan declares for it, so the plan
    /// cannot resolve how to seal, index or read it.
    #[error("field {field:?} is not a {expected}")]
    FieldType {
        /// The field.
        field: String,
        /// The type the plan declares.
        expected: &'static str,
    },
    /// The plan has no field of that name.
    #[error("the plan has no field {field:?}")]
    NoSuchField {
        /// The field asked for.
        field: String,
    },
    /// The chains given to one [`all`](crate::all) were started on
    /// different ciphers. A batch settles through one client and resolves
    /// every keyset it names there, so a chain from another cipher would
    /// run under a keyset its own cipher never chose.
    #[error("the chains in one batch were started on different ciphers")]
    MixedCiphers,
    /// A query asked a field for an index the field never declared, so it
    /// would have matched nothing.
    #[error("field {field:?} declares no {index} index")]
    IndexNotDeclared {
        /// The field, or the context of a one-value plan.
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
    IndexOptions {
        /// The field, or the context of a one-value plan.
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
    NoContext,
    /// A field was declared both as a typed target (`encrypt_into`) and with
    /// a data verb. A field is one or the other: the target's type decides
    /// its layout and its queries.
    #[error("field {field:?} is declared both as a typed target and with data verbs")]
    TargetWithVerbs {
        /// The field.
        field: String,
    },
}
