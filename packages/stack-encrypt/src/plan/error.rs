//! Why a plan was refused.
use crate::LabelError;

/// Why a plan was refused: when it was built, or when it was run against a
/// value, a stored record or a query that does not match it.
///
/// Every one of these is raised before any key is requested: a plan that
/// does not hold up never reaches ZeroKMS. Carried in [`Error::Plan`].
///
/// [`Error::Plan`]: crate::Error::Plan
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// The plan's context is not a plain label.
    #[error("the plan's context is not a plain label: {0}")]
    ContextLabel(#[source] LabelError),
    /// A sealed or indexed field's name, or the identity it is keyed
    /// under, is not a plain label segment. A passthrough field is under no
    /// label, so its name is never refused for this.
    #[error("field {field:?} is not a plain label segment: {source}")]
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
        /// The field.
        field: String,
        /// The index asked for, as its key.
        index: &'static str,
    },
}
