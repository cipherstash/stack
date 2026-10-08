//! Encrypting values whose type is known only at runtime.
//!
//! Everything else in this crate is typed: a target names its source type,
//! and the operations it composes are reached through bounds — `Encrypt` for
//! a ciphertext, [`PrfValue`](vitaminc_prf::PrfValue) for an equality term,
//! `AsRef<str>` for a match term. That is what makes a term a cross-language
//! contract: `equality_term(34u32)` derives the same bytes wherever it is
//! called from, because `34u32` is the same value everywhere.
//!
//! An FFI binding cannot reach those bounds. Its field types arrive as wire
//! data, so there is no Rust type to name — and no dynamic value can satisfy
//! `AsRef<str>`, which is total. Something has to look at the value and pick
//! the typed operation. This module is that something, written once here
//! rather than once per language binding.
//!
//! The runtime value is [`FfiValue`], vitaminc's language-neutral value tree
//! and the type every binding already funnels through.
//!
//! # What is here
//!
//! * [`context`](context()) — an [`FfiValue`] read as an encryption context.
//! * [`term`](term()) — one index term for a value, dispatched on its variant.
//! * [`record`] — a fields plan spelled as data, *lowered* into the plan
//!   builder ([`Plan`](crate::Plan)) and run by the engine: the same code a
//!   Rust chain and the derive run, so a record written from any language
//!   is the same bytes (ADR-0007). The one step that stays dynamic is
//!   dispatching a value whose type is known only at run time to the typed
//!   term operation, which [`IndexSpec`]'s `Index` impls do.
//! * [`TargetResolver`] — the EQL types a build holds, installed by the host
//!   that links them, so a plan field may name one as its target and the
//!   lowering runs that type's own plan in the same request; [`NoTargets`]
//!   is the build without them.
//! * [`Value`] — an [`FfiValue`] as a plan field's plaintext, the type of
//!   every field lowered from data; [`TermBytes`] — the term such a field
//!   derives, as its frozen bytes.
//! * [`Scope`] — which cipher an opening operation decrypts through.
//!
//! # What is not here
//!
//! Encrypting a whole value is not: [`FfiValue`] implements `Encrypt`
//! already, so `keyset.encrypt(value, aad)` is the whole of it and needs
//! nothing from this module. Nor is a second executor: nothing here calls
//! the term functions or the seal path to produce a record. A capability a
//! data plan needs and the builder lacks is added to the builder, once.
//!
//! # Stability
//!
//! The output keys this module spells (`"c"`, `"eq"`, `"match"`, `"ore"`,
//! `"ope"`, `"passthrough"`) are **wire format**, not just API: they are map
//! keys in stored ciphertext, so a row written under one spelling is read
//! under the same spelling or not at all. They are fixed here so that
//! bindings in different languages agree on them by construction rather
//! than by each re-deriving them. Their long-term home is beside vitaminc's
//! frozen tag table, which already owns this class of constant.
//!
//! A plan field's `"type"` names (`"int64"`, `"string"`, …) are wire format
//! in the same way: a binding spells them, and a stored row opens only under
//! the type it was sealed as. They are not this crate's: a declared type is
//! vitaminc's [`ValueKind`], re-exported here, whose names vitaminc freezes
//! beside its tag table. This crate adds only what a kind means to an index
//! ([`admits`]) and to a query value ([`read`]); it decides nothing about
//! the bytes ([`record`]). Every field with a term output declares one;
//! a plan whose indexed field has none is refused when it is built
//! ([`Error::UntypedIndex`], naming the field).
//!
//! For the same reason the enums that spell them — [`Output`],
//! [`IndexSpec`] and [`ValueKind`] — are *not* `#[non_exhaustive]`, against this workspace's
//! usual rule for public enums: a new output is a wire-format addition every
//! binding has to be taught, and an exhaustive match is how the compiler
//! tells a binding author that. [`Scope`] is exhaustive for a different
//! reason, given on the type.
mod context;
mod kind;
pub mod record;
mod target;
mod term;
mod value;

use std::fmt;

pub use context::{borrowed, context};
pub use kind::{admits, read};
pub use record::{FieldPlan, Output, Plan};
pub use target::{NoTargets, TargetDescriptor, TargetError, TargetResolver};
pub use term::{term, Scalar, TermBytes};
pub use value::Value;
/// vitaminc's language-neutral value tree — the runtime value every binding
/// funnels through. Its transport codec is `vitaminc_aead_value::transport`,
/// which stays the binding's: this crate takes and returns values, never
/// encoded bytes.
pub use vitaminc_aead_value::FfiValue;
/// vitaminc's value kinds: the type a plan field declares in its `"type"`
/// key. Its names are frozen wire format; see [`admits`] and [`read`] for
/// what a kind means to this engine.
pub use vitaminc_aead_value::ValueKind;

use crate::target::IndexSpec;
use crate::{KeysetCipher, StackCipher};

/// Which cipher an opening operation decrypts through: the client, or one
/// of its keysets.
///
/// This is the runtime form of the crate's *scope* (what a `Pending` is
/// built through, and so what it may open — [`CipherScope`](crate::CipherScope)
/// is the trait both ciphers implement). [`StackCipher`] and
/// [`KeysetCipher`] both open, and neither is the other's supertype: the
/// client opens a leaf sealed under any of its keysets, while a keyset
/// cipher opens only its own and fails a foreign leaf with
/// [`Error::ForeignKeyset`](crate::Error::ForeignKeyset). That refusal is
/// the keyset cipher's, made when the pending is built and before any key
/// is retrieved; this enum only names which of the two a call goes through,
/// because a binding's caller makes that choice at runtime and a typed
/// caller makes it by naming the cipher.
///
/// Not `#[non_exhaustive]`: the two variants are the two ciphers this crate
/// has, and a binding dispatches on them (the Go guest does, per selector).
/// A third would be a new cipher type, which is a larger change than adding
/// a variant here.
pub enum Scope<'c, K> {
    /// Leaves from any keyset the client holds: one batched retrieval per
    /// keyset the leaves were sealed under.
    Client(&'c StackCipher<K>),
    /// Leaves from this keyset only.
    Keyset(KeysetCipher<'c, K>),
}

// By hand rather than derived, so `K: Debug` is not demanded: neither cipher
// demands it of its own `Debug`, and a data-key source rarely offers one.
impl<K> fmt::Debug for Scope<'_, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Scope::Client(cipher) => f.debug_tuple("Client").field(cipher).finish(),
            Scope::Keyset(keyset) => f.debug_tuple("Keyset").field(keyset).finish(),
        }
    }
}

/// The UTF-8 inside a string leaf. Valid by `Utf8String`'s construction
/// invariant; checked rather than assumed because this is boundary code.
fn utf8(s: &vitaminc_aead_value::Utf8String) -> Option<&str> {
    std::str::from_utf8(s.risky_ref()).ok()
}

/// What went wrong in a dynamic operation.
///
/// The split that matters to a caller is malformed input versus something
/// else: every variant but [`Cipher`](Error::Cipher) and
/// [`Internal`](Error::Internal) is a statement about the value or the
/// request, decided before any key is minted or retrieved. `Cipher` is the
/// operation failing; `Internal` is this module's own bug. A binding maps
/// them to its own status codes on those lines, and must not report
/// `Internal` as the caller's fault. The record path's operations hand back
/// the engine's [`Pending`](crate::Pending), whose failure is the crate's
/// [`Error`](crate::Error); a [`Plan`](crate::Error::Plan) failure there is
/// again a statement about the caller's data.
///
/// Each input error names the field it is about, where there is one, and
/// says what was wrong with a [`Reason`]: both are in the message and in the
/// [`ErrorPayload`](crate::ErrorPayload) (`field`, `reason`), so a binding's
/// caller can tell a bad plan field from a bad record field without parsing
/// text. A field is `None` where the error is about the whole plan, value or
/// record, or where the function that raised it never sees a field
/// ([`context`](context()), [`read`]); [`in_field`](Self::in_field) names
/// it from the caller's side.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
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
    /// or a scalar outside the kind's domain — equality over a float or a
    /// boolean, match over anything but text. See
    /// [`IndexSpec::supports`].
    #[error("no {kind} term is defined for this value{}", in_field_text(field))]
    #[diagnostic(code(stack_encrypt::dynamic_term))]
    Term {
        /// The plan field the value is for, if it is one.
        field: Option<String>,
        /// The index that was asked for.
        kind: IndexSpec,
    },

    /// A record plan is malformed: not an object of field specs, empty,
    /// missing or duplicating an output, carrying a key that is not
    /// `"context"`, `"outputs"`, `"target"` or `"type"`, naming a type that
    /// is not one, asking for an index its declared type is not defined
    /// for, giving a field a context that is not a label a fields plan can
    /// seal it under, or declaring what the plan builder refuses (two fields
    /// under one identity, fields under different contexts).
    #[error("record plan is malformed: {reason}{}", in_field_text(field))]
    #[diagnostic(code(stack_encrypt::dynamic_plan))]
    Plan {
        /// The plan field at fault, if the fault is one field's.
        field: Option<String>,
        /// What was wrong with the plan.
        reason: Reason,
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

    /// A record source does not fit its plan: not an object (or an array of
    /// them), a field the plan does not name, a plan field the source does
    /// not carry or carries twice, or a passthrough or a repeated map key
    /// under a field the plan seals, or a value of another type than its
    /// field declares. Also a query value that cannot be read as its field's
    /// type ([`read`]).
    #[error(
        "record source does not fit the plan: {reason}{}",
        in_field_text(field)
    )]
    #[diagnostic(code(stack_encrypt::dynamic_source))]
    Source {
        /// The source field at fault, if the fault is one field's.
        field: Option<String>,
        /// What was wrong with the source.
        reason: Reason,
    },

    /// A stored record does not fit its plan: not a map (or a sequence of
    /// them), a ciphertext-bearing field that is absent or given twice, or
    /// has no `"c"` node or two of them, a repeated map key under `"c"`, a
    /// passthrough under `"c"` — which would hand back unauthenticated
    /// bytes as if they had been opened — or a passthrough field that is
    /// absent, carries no `"passthrough"` node, or carries a value of
    /// another type than it declares. A sealed field that opens to a value
    /// of another type than it declares fails the pending instead
    /// ([`PlanError::FieldType`](crate::PlanError::FieldType)): the type tag
    /// is inside the AEAD envelope.
    #[error(
        "stored record does not fit the plan: {reason}{}",
        in_field_text(field)
    )]
    #[diagnostic(code(stack_encrypt::dynamic_record))]
    Record {
        /// The stored field at fault, if the fault is one field's.
        field: Option<String>,
        /// What was wrong with the stored record.
        reason: Reason,
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
    /// the plan is extended, or the value is of another kind. Decided when
    /// the plan is built or the value is read, before any key is touched
    /// — save [`TargetError::Other`], which is the resolver's own failure.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Target(#[from] TargetError),

    /// Sealing, opening or deriving failed.
    #[error(transparent)]
    #[diagnostic(transparent)]
    Cipher(#[from] crate::Error),
}

/// ` (field "age")`, or nothing: the tail of an input error's message.
fn in_field_text(field: &Option<String>) -> String {
    field
        .as_deref()
        .map(|field| format!(" (field {field:?})"))
        .unwrap_or_default()
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
        }
    }

    /// A source error with no field named yet.
    pub(crate) fn bad_source(reason: Reason) -> Self {
        Self::Source {
            field: None,
            reason,
        }
    }

    /// A stored-record error with no field named yet.
    pub(crate) fn bad_record(reason: Reason) -> Self {
        Self::Record {
            field: None,
            reason,
        }
    }

    /// Name the field an input error is about, where it names none yet.
    ///
    /// For a binding that calls something that never sees a field —
    /// [`read`] for a query value, [`context`](context()) for a field's
    /// context — and knows which field it was for. An error that already
    /// names a field, or is not an input error, comes back unchanged.
    pub fn in_field(mut self, name: &str) -> Self {
        match &mut self {
            Self::Context { field, .. }
            | Self::Term { field, .. }
            | Self::Plan { field, .. }
            | Self::Source { field, .. }
            | Self::Record { field, .. }
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
            | Self::Record { field, .. } => field.as_deref(),
            Self::UntypedIndex { field } => Some(field),
            Self::Internal | Self::Target(_) | Self::Cipher(_) => None,
        }
    }

    /// What was wrong, for a context, plan, source or record error.
    pub fn reason(&self) -> Option<Reason> {
        match self {
            Self::Context { reason, .. }
            | Self::Plan { reason, .. }
            | Self::Source { reason, .. }
            | Self::Record { reason, .. } => Some(*reason),
            Self::Term { .. }
            | Self::UntypedIndex { .. }
            | Self::Internal
            | Self::Target(_)
            | Self::Cipher(_) => None,
        }
    }
}

impl crate::ErrorPayload for Error {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut fields = match self {
            Self::Target(error) => return error.payload(),
            Self::Cipher(error) => return error.payload(),
            Self::Term { kind, .. } => crate::diagnostic::payload([("index", kind.key().into())]),
            _ => serde_json::Map::new(),
        };
        if let Some(field) = self.field() {
            let _ = fields.insert("field".to_owned(), field.into());
        }
        if let Some(reason) = self.reason() {
            let _ = fields.insert("reason".to_owned(), reason.as_str().into());
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
    /// What was wrong with a context, plan, source or stored record: the reason
    /// a dynamic input error carries beside the field it names.
    ///
    /// One vocabulary for all four, since several reasons apply to more than
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
        NotAnObject => "not_an_object", "not an object where one is expected";
        /// A context value is of a kind a context cannot hold: a boolean,
        /// float, null, object or passthrough.
        ContextKind => "context_kind", "a boolean, float, null, object or passthrough cannot be a context";
        /// A context string is not UTF-8.
        ContextNotUtf8 => "context_not_utf8", "a context string is not UTF-8";
        /// A context renders empty.
        EmptyContext => "empty_context", "the context renders empty";
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
        /// `"target"` and `"type"`.
        UnknownKey => "unknown_key", r#"a key other than "context", "outputs", "target" and "type""#;
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
        /// A field names `"passthrough"` beside another output.
        PassthroughWithOutputs => "passthrough_with_outputs", r#""passthrough" beside another output"#;
        /// `"target"` is not a non-empty string.
        InvalidTarget => "invalid_target", r#""target" is not a non-empty string"#;
        /// `"type"` is not a string naming a value type.
        UnknownType => "unknown_type", r#""type" does not name a value type"#;
        /// The field's declared type has no such index: match on an integer,
        /// equality on a float, any index on a composite.
        IndexNotAdmitted => "index_not_admitted", "the declared type has no such index";
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
        /// The plan builder refused the plan for a reason none of the above
        /// names.
        Refused => "refused", "the plan builder refused it";
        /// A field the plan names is not there.
        FieldMissing => "field_missing", "a field the plan names is missing";
        /// A field is there twice.
        FieldRepeated => "field_repeated", "a field is given twice";
        /// A field is there that the plan does not name.
        UnknownField => "unknown_field", "a field the plan does not name";
        /// A value is not of the type its field declares.
        FieldType => "field_type", "a value is not of the type its field declares";
        /// A passthrough sits where a sealed value, or a ciphertext, must be.
        Passthrough => "passthrough", "a passthrough where a sealed value must be";
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
