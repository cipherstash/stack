//! Records from data: a plan spelled as a value, lowered into the plan
//! builder.
//!
//! A binding has no types to name, so it declares a record as data: per
//! field, a context, what to produce and, optionally, what type the values
//! are. This module reads that declaration ([`plan`]) and *lowers* it into
//! the same [`Plan`](crate::Plan) a Rust chain writes and the derive emits:
//! `Plan::context(c).fields()`, then `encrypt`, `encrypt_index`, `index` or
//! `passthrough` per field. Encrypting runs that plan's description through
//! [`KeysetCipher::run`](crate::KeysetCipher::run); decrypting runs its
//! opener. There is no second executor here: every field's context, every
//! key request and the one batch they settle in are the engine's, so a
//! record written from Go and one written from Rust under the same
//! declaration are the same bytes because they ran the same code (ADR-0007).
//!
//! What stays dynamic is one step: a field whose type is known only when its
//! value arrives dispatches to the typed term operation then, through
//! [`IndexSpec`]'s [`Index`](crate::target::Index) impl (`scalar_term` in the `term` module is the
//! one table).
//!
//! # What a field's `"context"` must be
//!
//! A plan has **one** context, and every field is sealed under
//! `<context>/<identity>`; a declaration gives each field its whole label,
//! as a database column is named: `["users", "age"]`. The lowering reads the
//! label's last segment as the field's identity and the rest as the plan's
//! context, so every field of one plan must share that prefix, and a label
//! has at least two segments. A field's label may be extended by the
//! caller's parts, nested to the left as a binding extends one part at a
//! time (`[["users", "age"], 7]`, then `[[["users", "age"], 7], "eu"]`), and
//! every field must carry the same extension: it becomes the call's
//! `.extend(..)`. A context that is not a label (one text part `"users/age"`,
//! an integer, bytes) is refused as a plan a fields plan cannot express.
//!
//! # A plan whose context is a field of the record
//!
//! The plan builder's third context source, `context_field`, has a data
//! form too: a plan-level key, `"context_field": "<field name>"`, beside
//! the field specs. The named field's value in each record is then the
//! context every other field is sealed under — a tenant label such as
//! `"tenants/acme"`, which must parse as a plain [`Label`] — and the field
//! itself is carried as a passthrough of type `"string"`, so the stored
//! record names its own context. With a context field the plan has no
//! context of its own, so each field's `"context"` is its identity alone, a
//! one-segment label (`["email"]`), extended by the caller's parts exactly
//! as above (`[["email"], 7]`). The context field's own spec names its
//! identity the same way, asks for `"passthrough"` and nothing else, and
//! declares `"string"` or no type (it is a string either way). Opening a
//! record reads the stored context field and opens every field under it;
//! [`decrypt`] takes the context the caller expects, when it has one, and
//! refuses a record whose stored context differs with
//! [`Error::ContextMismatch`](crate::Error::ContextMismatch) before any
//! key is requested. A stored context changed in storage opens nothing
//! either way: every field was sealed under the original. The key
//! `"context_field"` is reserved at the top level of a plan, so no field
//! may be called that. A plan without the key is read exactly as before:
//! the two-segment and shared-prefix rules hold, and it seals the same
//! bytes.
//!
//! # A field that names an EQL type
//!
//! Instead of outputs, a field may name an EQL type as its **target**:
//! `{"context": [...], "target": "TextEq"}`. The two forms are exclusive —
//! a field with both is refused — and the lowering runs the named type's
//! own plan through the [`TargetResolver`] the host installed
//! ([`plan_with`], [`encrypt_with`], [`decrypt_with`], [`query`]), zipping
//! its [`Pending`] into the record's so the whole record is still one
//! ZeroKMS request. The bare entry points ([`plan`], [`encrypt`],
//! [`decrypt`]) run with [`NoTargets`], the resolver of a build without EQL
//! types, which refuses every target name when the plan is built: a plan
//! that parses there has no target field.
//!
//! A target field's label must be a column, `<table>/<column>`, because
//! that is what an EQL value stores in its `i`: [`Plan::new_with`] refuses
//! a target field whose label has any other number of segments
//! ([`TargetError::Column`]) — [`FieldPlan::with_target`] itself takes any
//! label, as every field constructor does; the segment rules are the
//! plan's — and an extended plan (a tenant part on every
//! label) has no column for it and is refused with
//! [`TargetError::Extended`] rather than silently dropping the extension,
//! as is a plan with a context field, whose labels are identities alone
//! under whatever table each record names ([`TargetError::ContextField`]).
//! The field's `"type"`, when declared, must be the kind the EQL type is
//! produced from ([`TargetError::Kind`]); undeclared, it is that kind, so
//! every value is checked against it as any typed field's is.
//!
//! # What a field's `"type"` decides, and what it does not
//!
//! Every field lowered from data is a [`Value`]: its plaintext type is the
//! runtime value itself, and it seals in vitaminc's self-describing tagged
//! leaf encoding (`[tag] ++ payload`) whatever its declared `"type"`. The
//! type decides which indexes the field admits ([`admits`]), which values it
//! seals and which it opens to (checked by kind, both ways), and nothing
//! about the bytes: declaring a type on a field written without one changes
//! no leaf. A field with any index declares its type, and a plan whose
//! indexed field has none is refused when it is built
//! ([`Error::UntypedIndex`], naming the field): the term then derives
//! from the one declared kind, every value checked against it, never from
//! whatever tag each value arrived with (`34` sent once as a float and once
//! as an integer would otherwise store two terms under one field). A field
//! that only seals, or only carries its value through, may leave the type
//! out. A field's terms dispatch on the value's variant — the declared kind,
//! once checked — to the typed term operation, so they are the bytes a Rust
//! `u32` or `String` field derives under the same label.
//!
//! The ciphertext is where a data plan and a Rust chain over bare types part:
//! a Rust `u32` field seals four bare bytes and a `String` field its bare
//! UTF-8, a `Value` seals the tagged leaf, and the two encodings cannot be
//! told apart by inspection — a bare string that begins with U+000A is a
//! valid tagged string, and a tagged string is a valid bare one with a line
//! feed in front — so neither reader can refuse the other's leaf and a
//! mis-declared one may read as changed plaintext rather than fail. The
//! lowering therefore never chooses an encoding from the type. A Rust record
//! whose rows a binding must open declares its fields as [`Value`]
//! (`encrypt_index(pick("age", |u: &User| &u.age), (IndexSpec::Equality,
//! IndexSpec::Ore))` over a `Value` field is the same declaration as the
//! data plan's, and the two interchange, leaves included — see
//! `tests/record_lowering.rs`); a Rust `u32` field shares a data field's
//! terms and nothing else. Closing that gap — one leaf encoding both authors
//! read, or the encoding bound into the leaf's context so the wrong reader
//! fails closed — is a change to the Rust chain's bytes, and so a decision
//! tracked in #1118, not something the lowering can take on its own.
//!
//! # The stored record is wire format
//!
//! A record is stored as `field → { output-key → node }`: `"c"` is the
//! field's ciphertext, each term rides under its index key (`"eq"`,
//! `"match"`, `"ore"`, `"ope"`) as a passthrough byte node, a passthrough
//! field rides under `"passthrough"`, and a target field's EQL value rides
//! under [`EQL_KEY`] (`"eql"`) as a passthrough byte node holding the EQL
//! JSON. A row written under one spelling is read under the same spelling
//! or not at all, so the keys are fixed here and every binding agrees on
//! them by construction.
//!
//! The `"eql"` node is a passthrough on the wire and that is safe where a
//! passthrough under `"c"` is not: its bytes are not handed back as
//! plaintext. Opening them runs the EQL type's own decryption, which reads
//! the ciphertext *inside* the JSON, authenticates it under the field's
//! column and refuses a different stored identifier — so a forged `"eql"`
//! node opens to nothing, as a forged `"c"` leaf does.
//!
//! Under `"c"` a passthrough is refused in both directions, and that is
//! load-bearing: opening a passthrough retrieves no key and opens no AEAD,
//! it hands the payload back — so without the decrypt-side refusal an
//! attacker with write access to the stored tree could replace a field's
//! `"c"` subtree with a passthrough carrying forged plaintext and have it
//! reported as a successful decrypt. The encrypt-side refusal is what makes
//! that a round-trip invariant rather than data loss.

use vitaminc_aead_value::{FfiValue, ValueKind};
use vitaminc_protected::Controlled;

use super::{
    admits, utf8, Error, NoTargets, Reason, Scalar, Scope, TargetError, TargetResolver, TermBytes,
    Value,
};
use crate::plan::{FieldValues, FieldsBuilder, Opens, Runs};
use crate::target::{CallerContext, DeclaredContext, Decryption, Encrypted, IndexSpec};
use crate::{
    BoxedPassthrough, CipherText, ContextPiece, KeysetCipher, Label, NonEmpty, Pending,
    StackCipherText,
};

/// The map key a target field's EQL value rides under in a stored record:
/// wire format, like the output keys (see the
/// [module docs](self#the-stored-record-is-wire-format)).
pub const EQL_KEY: &str = "eql";

/// What a plan field asks for.
///
/// The keys are wire format twice over: they are how a binding spells an
/// output, *and* the keys of the per-field output map in the stored result.
/// That is why this enum is exhaustive — see the [module docs](super#stability).
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum Output {
    /// `"c"` — the field's [`StackCipherText`].
    Ciphertext,
    /// An index term, keyed `"eq"`, `"match"`, `"ore"` or `"ope"`: the
    /// index, with its options, that derives it.
    Term(IndexSpec),
    /// `"passthrough"` — the field carried as it is, **unsealed and
    /// unauthenticated**, so the record is whole. A field's only output
    /// when it has it.
    Passthrough,
}

impl Output {
    /// The output a bare key names, or `None` for a key that is not one. A
    /// `"match"` key names the match index under default options; a plan
    /// spells other options in the object form [`from_value`](Self::from_value)
    /// reads.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "c" => Some(Output::Ciphertext),
            "passthrough" => Some(Output::Passthrough),
            _ => IndexSpec::parse(s).map(Output::Term),
        }
    }

    /// Read one entry of a plan's `"outputs"` list: `"c"`, `"passthrough"`,
    /// or an index in its wire form ([`IndexSpec::from_value`]; see [`plan`]).
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] for anything else.
    pub fn from_value(value: &FfiValue) -> Result<Self, Error> {
        match value {
            FfiValue::String(s) if utf8(s) == Some("c") => Ok(Output::Ciphertext),
            FfiValue::String(s) if utf8(s) == Some("passthrough") => Ok(Output::Passthrough),
            _ => IndexSpec::from_value(value).map(Output::Term),
        }
    }

    /// The map key this output rides under.
    pub fn key(&self) -> &'static str {
        match self {
            Output::Ciphertext => "c",
            Output::Term(kind) => kind.key(),
            Output::Passthrough => "passthrough",
        }
    }
}

/// The verb a field's outputs lower to: one of the plan builder's four, or
/// a target, which the resolver runs beside the lowered plan.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verb {
    Encrypt,
    EncryptIndex,
    Index,
    Passthrough,
    Target,
}

/// One field of a record plan: what to call it, what label to seal it
/// under, what to produce for it, and, optionally, what type its values are.
///
/// A field may declare the type of its values (a [`ValueKind`]), and must
/// when it has a term output: [`Plan::new_with`] refuses the plan otherwise
/// ([`Error::UntypedIndex`]). A typed field admits only the indexes that
/// kind is defined for ([`admits`], checked when the plan is built), seals
/// only values of that kind and opens only to one (checked per value), so
/// the engine verifies what a binding hands it rather than trusting the
/// binding's tagging. A field that only seals, or only carries its value
/// through, may leave the type out; see the
/// [module docs](self#what-a-fields-type-decides-and-what-it-does-not).
#[derive(Clone, Debug)]
pub struct FieldPlan {
    name: String,
    context: NonEmpty<ContextPiece<'static>>,
    label: Label,
    extension: Vec<ContextPiece<'static>>,
    outputs: Vec<Output>,
    target: Option<String>,
    field_type: Option<ValueKind>,
}

impl FieldPlan {
    /// A field plan.
    ///
    /// `context` is the field's whole context as a binding spells it: its
    /// label, a list of plain segments, extended by zero or more scalar
    /// parts nested to the left (see the
    /// [module docs](self#what-a-fields-context-must-be)). Build one from a
    /// value with [`super::context`](super::context()). How many segments
    /// the label needs is the plan's rule, not the field's: two or more
    /// under a plan with a context of its own ([`Plan::new`]), exactly one
    /// under a plan that takes its context from a field
    /// ([`Plan::with_context_field`]).
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] if `outputs` is empty, names an output twice (two
    /// outputs with the same [key](Output::key) are the same output — two
    /// match indexes under different options would both ride under
    /// `"match"`), or names [`Output::Passthrough`] beside another output;
    /// or if `context` is not a label, optionally extended.
    pub fn new(
        name: impl Into<String>,
        context: NonEmpty<ContextPiece<'static>>,
        outputs: Vec<Output>,
    ) -> Result<Self, Error> {
        let name = name.into();
        let refuse = |reason| Error::Plan {
            field: Some(name.clone()),
            reason,
        };
        if outputs.is_empty() {
            return Err(refuse(Reason::NoOutputs));
        }
        for (at, output) in outputs.iter().enumerate() {
            if outputs[..at]
                .iter()
                .any(|prior| prior.key() == output.key())
            {
                return Err(refuse(Reason::DuplicateOutput));
            }
        }
        if outputs.contains(&Output::Passthrough) && outputs.len() > 1 {
            return Err(refuse(Reason::PassthroughWithOutputs));
        }
        let (label, extension) = field_context(&name, context.get())?;
        Ok(Self {
            name,
            context,
            label,
            extension,
            outputs,
            target: None,
            field_type: None,
        })
    }

    /// A field plan that names an EQL type as its target instead of
    /// outputs: the type's own plan decides what is sealed and which terms
    /// sit beside it. Whether the name is one this build can run is decided
    /// when the plan is built ([`Plan::new_with`]), against the resolver.
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] if `target` is empty, or if `context` is not a label,
    /// optionally extended. How many segments the label needs is the plan's
    /// rule ([`Plan::new_with`]), as it is for [`new`](Self::new).
    pub fn with_target(
        name: impl Into<String>,
        context: NonEmpty<ContextPiece<'static>>,
        target: impl Into<String>,
    ) -> Result<Self, Error> {
        let name = name.into();
        let target = target.into();
        if target.is_empty() {
            return Err(Error::Plan {
                field: Some(name),
                reason: Reason::InvalidTarget,
            });
        }
        let (label, extension) = field_context(&name, context.get())?;
        Ok(Self {
            name,
            context,
            label,
            extension,
            outputs: Vec::new(),
            target: Some(target),
            field_type: None,
        })
    }

    /// Declare the type of this field's values.
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] if the field asks for an index the kind is not
    /// defined for ([`admits`]): match on an integer, equality on a float,
    /// any index on a composite.
    pub fn with_type(mut self, field_type: ValueKind) -> Result<Self, Error> {
        for output in &self.outputs {
            if let Output::Term(index) = output {
                if !admits(field_type, index) {
                    return Err(Error::Plan {
                        field: Some(self.name.clone()),
                        reason: Reason::IndexNotAdmitted,
                    });
                }
            }
        }
        self.field_type = Some(field_type);
        Ok(self)
    }

    /// The field's name — its key in the source and in the result.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The field's whole context as it was declared: its label, extended
    /// by the call's parts if any. What a probe for the field takes.
    pub fn context(&self) -> &NonEmpty<ContextPiece<'static>> {
        &self.context
    }

    /// The label the field is sealed and indexed under before any
    /// extension: the plan's context, then the field's identity — or the
    /// identity alone, under a plan that takes its context from a field.
    pub fn label(&self) -> &Label {
        &self.label
    }

    /// The label segment the field's data is keyed under: the last segment
    /// of its label.
    pub fn identity(&self) -> &str {
        // A label has at least one segment by construction (`new`), so
        // this never falls back.
        self.label.segments().last().unwrap_or("")
    }

    /// What the field produces. Empty for a field that names a target: its
    /// outputs are the EQL type's own.
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    /// The EQL type this field names as its target, if it does.
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// The declared type of the field's values, if the plan declares one.
    /// A host with no types of its own reads this to know what a decrypted
    /// value is.
    pub fn field_type(&self) -> Option<ValueKind> {
        self.field_type
    }

    /// Whether the field has a ciphertext to seal and open.
    pub fn has_ciphertext(&self) -> bool {
        self.outputs.contains(&Output::Ciphertext)
    }

    /// Whether the field comes back from [`decrypt`]: sealed and passthrough
    /// fields do, index-only fields do not.
    fn opens(&self) -> bool {
        self.verb() != Verb::Index
    }

    fn verb(&self) -> Verb {
        if self.target.is_some() {
            Verb::Target
        } else if self.outputs.contains(&Output::Passthrough) {
            Verb::Passthrough
        } else if self.has_ciphertext() {
            if self.indexes().is_empty() {
                Verb::Encrypt
            } else {
                Verb::EncryptIndex
            }
        } else {
            Verb::Index
        }
    }

    /// The indexes the field declares, in output order.
    fn indexes(&self) -> Vec<IndexSpec> {
        self.outputs
            .iter()
            .filter_map(|output| match output {
                Output::Term(index) => Some(index.clone()),
                Output::Ciphertext | Output::Passthrough => None,
            })
            .collect()
    }

    /// The plan context the field's label sits under: every segment but
    /// the last.
    fn prefix(&self) -> Result<Label, Error> {
        let segments: Vec<&str> = self.label.segments().collect();
        let Some((_, prefix)) = segments.split_last() else {
            return Err(Error::Internal);
        };
        Label::new(prefix).map_err(|_| Error::Plan {
            field: Some(self.name.clone()),
            reason: Reason::ContextNotLabel,
        })
    }

    /// What the output adapters need of the field: no context, which is the
    /// engine's by then.
    fn shape(&self) -> FieldShape {
        FieldShape {
            name: self.name.clone(),
            verb: self.verb(),
            keys: self.indexes().iter().map(IndexSpec::key).collect(),
            kind: self.field_type,
        }
    }

    /// Whether the field is run by the resolver rather than the lowered plan.
    fn is_target(&self) -> bool {
        self.target.is_some()
    }
}

/// The text of a text part.
fn text_of<'a>(piece: &'a ContextPiece<'_>) -> Option<&'a str> {
    match piece {
        ContextPiece::Text(text) => Some(text.as_ref()),
        _ => None,
    }
}

/// A field's declared context, taken apart into its label and the
/// extension parts around it.
///
/// A non-empty list of plain text segments is the label. A two-element list
/// whose second element is a scalar is a context extended by that part,
/// nested to the left, so the first element is taken apart in turn.
/// Anything else — a bare part, an empty list, a list mixing segments and
/// other parts, a part that is itself a list — is not a context a fields
/// plan can give a field. A one-segment label is a label here; whether the
/// plan admits one is [`Plan::new`]'s and [`Plan::with_context_field`]'s
/// rule.
fn split_context(piece: &ContextPiece<'_>) -> Option<(Label, Vec<ContextPiece<'static>>)> {
    let ContextPiece::List(parts) = piece else {
        return None;
    };
    if let Some(segments) = parts.iter().map(text_of).collect::<Option<Vec<&str>>>() {
        if !segments.is_empty() {
            let label = Label::new(segments).ok()?;
            return Some((label, Vec::new()));
        }
    }
    match parts.as_slice() {
        [inner, part] if !matches!(part, ContextPiece::List(_)) => {
            let (label, mut extension) = split_context(inner)?;
            extension.push(part.clone().into_owned());
            Some((label, extension))
        }
        _ => None,
    }
}

/// [`split_context`] for the field `name`, refusing a context that is not
/// a label, optionally extended, as that field's.
fn field_context(
    name: &str,
    piece: &ContextPiece<'_>,
) -> Result<(Label, Vec<ContextPiece<'static>>), Error> {
    split_context(piece).ok_or_else(|| Error::Plan {
        field: Some(name.to_owned()),
        reason: Reason::ContextNotLabel,
    })
}

/// A refusal of the plan builder or the engine's own check, as the field it
/// names and the nearest [`Reason`]. Matched exhaustively, so a new
/// [`PlanError`](crate::PlanError) says here which reason it reads as; an
/// engine failure that is not a plan refusal is [`Reason::Refused`].
fn refusal(error: crate::Error) -> (Option<String>, Reason) {
    use crate::PlanError as P;
    let crate::Error::Plan(error) = error else {
        return (None, Reason::Refused);
    };
    match error {
        P::ContextLabel(_) => (None, Reason::ContextNotLabel),
        P::FieldLabel { field, .. } => (Some(field), Reason::ContextNotLabel),
        P::DuplicateField { field } => (Some(field), Reason::DuplicateField),
        P::SharedIdentity { second, .. } => (Some(second), Reason::SharedIdentity),
        P::PassthroughIndexed { field } => (Some(field), Reason::PassthroughWithOutputs),
        P::DuplicateIndex { at, .. } => (Some(at), Reason::DuplicateOutput),
        P::EmptyIndexes => (None, Reason::NoOutputs),
        P::NotInPlan { field } => (Some(field), Reason::UnknownField),
        P::NotInValue { field } => (Some(field), Reason::FieldMissing),
        P::FieldType { field, .. } => (Some(field), Reason::FieldType),
        P::NoSuchField { field } => (Some(field), Reason::NoSuchField),
        P::TargetWithVerbs { field } => (Some(field), Reason::OutputsWithTarget),
        P::IndexNotDeclared { field, .. } | P::IndexOptions { field, .. } => {
            (Some(field), Reason::Refused)
        }
        P::IdentityWithoutField | P::MixedCiphers | P::TwoContextSources { .. } | P::NoContext => {
            (None, Reason::Refused)
        }
    }
}

/// A record plan: the fields a record has, each with what to call it, what
/// label to seal it under, and what to produce for it.
///
/// Opaque, because the operations over a plan rely on properties of the
/// whole that no single [`FieldPlan`] can carry: there is at least one
/// field, no two fields share a name, every field's label sits under the
/// one plan context (or, under a context field, is its identity alone) and
/// carries the one extension, and the whole lowers to a
/// [`Plan`](crate::Plan) that builds. Both the parser ([`plan`]) and the
/// manual constructors ([`Plan::new`], [`Plan::with_context_field`]) go
/// through the one check, so a plan in hand is a plan that holds them,
/// whichever way it was built.
#[derive(Clone, Debug)]
pub struct Plan {
    context: Context,
    extension: Vec<ContextPiece<'static>>,
    fields: Vec<FieldPlan>,
}

/// Where a data plan takes its context from: the builder's first and third
/// sources. The second, the call, has no data form: a binding names the
/// context in the declaration it sends.
#[derive(Clone, Debug)]
enum Context {
    /// The plan's own label, which every field's label extends.
    Label(Label),
    /// The named field of each record, whose value is the context.
    Field(String),
}

impl Plan {
    /// A plan over `fields`, in the order given — which is the order of the
    /// fields in every result — under the context every field's label
    /// shares, for a build without EQL types: [`new_with`](Self::new_with)
    /// under [`NoTargets`], so a field that names a target is refused.
    ///
    /// # Errors
    ///
    /// As [`new_with`](Self::new_with).
    pub fn new(fields: Vec<FieldPlan>) -> Result<Self, Error> {
        Self::new_with(fields, &NoTargets)
    }

    /// A plan over `fields`, in the order given — which is the order of the
    /// fields in every result — under the context every field's label
    /// shares, resolving each target field's name through `resolver`.
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] if `fields` is empty, names a field twice, has a
    /// field whose label has fewer than two segments, has fields whose
    /// labels sit under different contexts or carry different extensions,
    /// or does not build as a fields plan: two sealed or indexed fields
    /// keyed under one identity, for instance, whose terms would be
    /// interchangeable. [`Error::UntypedIndex`], naming the field, if a field
    /// with a term output declares no type: every constructor shares that
    /// rule, so a parsed and a hand-built plan are refused alike.
    /// [`Error::Target`] if a target field names a type the
    /// resolver does not know or cannot produce, declares a `"type"` other
    /// than the kind that type is produced from, or sits in an extended plan.
    pub fn new_with(
        mut fields: Vec<FieldPlan>,
        resolver: &(impl TargetResolver + ?Sized),
    ) -> Result<Self, Error> {
        let Some(first) = fields.first() else {
            return Err(Error::bad_plan(Reason::NoFields));
        };
        let context = first.prefix()?;
        let extension = first.extension.clone();
        for field in &fields {
            // `prefix` refuses a one-segment label, which has nothing to
            // sit under; a longer one must sit under the first field's.
            if field.prefix()? != context {
                return Err(Error::Plan {
                    field: Some(field.name.clone()),
                    reason: Reason::MixedContexts,
                });
            }
        }
        for field in fields.iter_mut().filter(|field| field.is_target()) {
            let name = field.target.clone().unwrap_or_default();
            let descriptor = resolver.resolve(&name)?;
            if !extension.is_empty() {
                return Err(TargetError::Extended {
                    name: field.name.clone(),
                    label: field.label.to_string(),
                }
                .into());
            }
            // An EQL value is stored under a table and a column, so the
            // label is exactly two segments. Decided here, where the plan is
            // built and se_plan_check reports it, not at the first value: a
            // generator that asks the engine must be told before it writes
            // the code. The resolver re-checks, since it is public API.
            if field.label.segments().len() != 2 {
                return Err(TargetError::Column {
                    name: field.name.clone(),
                    label: field.label.to_string(),
                    reason: "an EQL column is a two-segment label: table and column".to_owned(),
                }
                .into());
            }
            match (field.field_type, descriptor.plaintext) {
                (Some(declared), expected) if expected != Some(declared) => {
                    return Err(TargetError::Kind {
                        name: field.name.clone(),
                        target: name,
                        expected,
                        declared,
                    }
                    .into());
                }
                (None, Some(kind)) => field.field_type = Some(kind),
                _ => {}
            }
        }
        Self::build(Context::Label(context), fields)
    }

    /// A plan over `fields` that takes its context from the field named
    /// `context_field`: the plan builder's
    /// [`context_field`](FieldsBuilder::context_field), as data. That
    /// field's value in each record is the context every other field is
    /// sealed under, and the field is carried as a passthrough of type
    /// string. Each field's label is its identity alone, a one-segment
    /// label, optionally extended; see the
    /// [module docs](self#a-plan-whose-context-is-a-field-of-the-record).
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] as [`new`](Self::new) refuses, and if no field is
    /// named `context_field`, that field asks for anything but
    /// [`Output::Passthrough`] (a context is not sealed, and indexing it
    /// would derive a term from a value that is not secret), declares a
    /// type other than [`ValueKind::String`], or any field's label has
    /// more than one segment. [`Error::UntypedIndex`], naming the field, as
    /// [`new_with`](Self::new_with) refuses. [`Error::Target`]
    /// ([`TargetError::ContextField`]) if a field names an EQL type as its
    /// target: an EQL value is stored under a table the declaration fixes,
    /// and a plan with a context field has none.
    pub fn with_context_field(
        context_field: impl Into<String>,
        fields: Vec<FieldPlan>,
    ) -> Result<Self, Error> {
        let context_field = context_field.into();
        let refuse = |reason| Error::Plan {
            field: Some(context_field.clone()),
            reason,
        };
        let Some(field) = fields.iter().find(|field| field.name == context_field) else {
            return Err(refuse(Reason::NoSuchField));
        };
        if field.outputs != [Output::Passthrough]
            || field
                .field_type
                .is_some_and(|kind| kind != ValueKind::String)
        {
            return Err(refuse(Reason::ContextField));
        }
        if let Some(field) = fields
            .iter()
            .find(|field| field.label.segments().count() != 1)
        {
            return Err(Error::Plan {
                field: Some(field.name.clone()),
                reason: Reason::ContextNotLabel,
            });
        }
        // A target field's label must be a column, `<table>/<column>`,
        // which a context field's one-segment identity is not: the table
        // is each record's own, and an EQL value stores one fixed by the
        // declaration. The same refusal as an extended plan's.
        if let Some(target) = fields.iter().find(|field| field.is_target()) {
            return Err(TargetError::ContextField {
                name: target.name.clone(),
                context_field,
            }
            .into());
        }
        let fields = fields
            .into_iter()
            .map(|mut field| {
                if field.name == context_field {
                    // A string whether or not the declaration says so: the
                    // value is read as a label, and the opener checks the
                    // stored one is text before any key is requested.
                    field.field_type = Some(ValueKind::String);
                }
                field
            })
            .collect();
        Self::build(Context::Field(context_field), fields)
    }

    /// The rules both constructors share: fields named once, one extension,
    /// every field with a term output typed, and a whole the builder accepts.
    fn build(context: Context, fields: Vec<FieldPlan>) -> Result<Self, Error> {
        let Some(first) = fields.first() else {
            return Err(Error::bad_plan(Reason::NoFields));
        };
        let extension = first.extension.clone();
        for (at, field) in fields.iter().enumerate() {
            let refuse = |reason| Error::Plan {
                field: Some(field.name.clone()),
                reason,
            };
            if fields[..at].iter().any(|prior| prior.name == field.name) {
                return Err(refuse(Reason::DuplicateField));
            }
            if field.extension != extension {
                return Err(refuse(Reason::MixedContexts));
            }
            // An indexed field declares its type: every value's term derives
            // from the one declared kind, never from whatever tag each value
            // arrived with. A target field's kind is the type's own.
            if !field.is_target() && !field.indexes().is_empty() && field.field_type.is_none() {
                return Err(Error::UntypedIndex {
                    field: field.name.clone(),
                });
            }
            // A target field is keyed under its identity like a sealed one;
            // the builder checks that rule for the fields it lowers, so the
            // target fields are checked against every field here.
            if field.is_target()
                && fields[..at]
                    .iter()
                    .any(|prior| prior.identity() == field.identity())
            {
                return Err(refuse(Reason::SharedIdentity));
            }
            if !field.is_target()
                && fields[..at]
                    .iter()
                    .any(|prior| prior.is_target() && prior.identity() == field.identity())
            {
                return Err(refuse(Reason::SharedIdentity));
            }
        }
        let plan = Self {
            context,
            extension,
            fields,
        };
        // The whole-plan rules the builder holds (names once, labels plain,
        // no shared identity) are checked by building, so a plan in hand
        // lowers. `()` stands in for the key source: the check does not
        // depend on it.
        let _ = plan.lower::<()>().map_err(|error| {
            let (field, reason) = refusal(error);
            Error::Plan { field, reason }
        })?;
        Ok(plan)
    }

    /// The plan's fields, in result order. Never empty, and no two share a
    /// name. Under a context field, that field is among them.
    pub fn fields(&self) -> &[FieldPlan] {
        &self.fields
    }

    /// The plan's one context: the label every field's label extends.
    /// `None` for a plan that takes its context from a field
    /// ([`context_field`](Self::context_field)), as the builder's
    /// [`Plan::label`](crate::Plan::label) is.
    pub fn label(&self) -> Option<&Label> {
        match &self.context {
            Context::Label(label) => Some(label),
            Context::Field(_) => None,
        }
    }

    /// The field the plan takes its context from, if it has one: the
    /// builder's [`Plan::context_field`](crate::Plan::context_field).
    pub fn context_field(&self) -> Option<&str> {
        match &self.context {
            Context::Field(name) => Some(name),
            Context::Label(_) => None,
        }
    }

    /// The parts every field's label is extended by, in order; empty when
    /// the declaration carries none.
    pub fn extension(&self) -> &[ContextPiece<'static>] {
        &self.extension
    }

    /// The fields plan this declaration lowers to, for a cipher over `K`.
    ///
    /// Built afresh per call: a built plan is bound to its key source type,
    /// and a declaration is not. Every field is declared by name, as a
    /// [`Value`], read out of the [`FieldValues`] the source is converted
    /// into. A context field is declared through the builder's own
    /// `context_field`, which carries it as a passthrough and reads it as
    /// the context; the loop then skips it.
    fn lower<K: 'static>(&self) -> Result<crate::Plan<FieldValues, K>, crate::Error> {
        let mut builder = match &self.context {
            Context::Label(label) => crate::Plan::context(label.clone()).fields::<FieldValues, K>(),
            Context::Field(name) => {
                crate::Plan::fields::<FieldValues, K>().context_field::<Value>(name.as_str())
            }
        };
        for field in &self.fields {
            // The context field is declared by `context_field` above; a
            // target field is the resolver's.
            if self.context_field() == Some(field.name.as_str()) || field.is_target() {
                continue;
            }
            builder = declare(builder, field);
            if field.identity() != field.name {
                builder = builder.identity(field.identity());
            }
        }
        builder.build()
    }

    /// The extension every field's label is run under, as the chain's
    /// `.extend(..)` would carry it.
    fn declared_context(&self) -> DeclaredContext {
        self.extension
            .iter()
            .cloned()
            .fold(DeclaredContext::default(), |context, part| {
                context.with(CallerContext::from_piece(part))
            })
    }

    fn shape(&self) -> Vec<FieldShape> {
        self.fields.iter().map(FieldPlan::shape).collect()
    }

    /// The fields that name a target, in plan order: the resolver's.
    fn target_fields(&self) -> impl Iterator<Item = &FieldPlan> + '_ {
        self.fields.iter().filter(|field| field.is_target())
    }
}

/// One field's verb, over a [`Value`]; its indexes are the [`IndexSpec`]s
/// the plan named, each an [`Index`] of a `Value`.
fn declare<K: 'static>(
    builder: FieldsBuilder<FieldValues, K>,
    field: &FieldPlan,
) -> FieldsBuilder<FieldValues, K> {
    let name = field.name.as_str();
    match field.verb() {
        Verb::Encrypt => builder.encrypt::<Value>(name),
        Verb::EncryptIndex => builder.encrypt_index::<Value>(name, field.indexes()),
        Verb::Index => builder.index::<Value>(name, field.indexes()),
        Verb::Passthrough => builder.passthrough::<Value>(name),
        // `lower` never hands a target field here: the resolver runs it.
        Verb::Target => builder,
    }
}

/// Read a record plan from a decoded value, for a build without EQL types:
/// [`plan_with`] under [`NoTargets`], so a field that names a `"target"` is
/// refused ([`TargetError::NoTargets`]).
///
/// # Errors
///
/// As [`plan_with`].
pub fn plan(value: FfiValue) -> Result<Plan, Error> {
    plan_with(value, &NoTargets)
}

/// Read a record plan from a decoded value, resolving each target field's
/// name through `resolver`.
///
/// The plan is an [`FfiValue::Object`]:
///
/// ```text
/// { <field>: { "context": <context>, "outputs": [ "c" | "passthrough" | <index>, ... ], "type": <type> }, ... }
/// ```
///
/// with one optional key beside the field specs, `"context_field":
/// "<field name>"`, which makes the plan take its context from that field
/// of each record ([`Plan::with_context_field`]; the
/// [module docs](self#a-plan-whose-context-is-a-field-of-the-record) give
/// the shape). The key is reserved: a top-level `"context_field"` whose
/// value is not a string is refused rather than read as a field of that
/// name.
///
/// A field may name an EQL type as its target instead of outputs:
///
/// ```text
/// { <field>: { "context": <context>, "target": "<EQL type name>", "type": <type> }, ... }
/// ```
///
/// A field has `"outputs"` or `"target"`, never both. `"target"` is the
/// type's name as the resolver lists it (`"TextEq"`), resolved when the plan
/// is built so a name the build cannot run fails here and not at the first
/// value; its `"type"`, when given, must be the kind the type is produced
/// from. See the [module docs](self#a-field-that-names-an-eql-type). A
/// target field needs a column for its label, so it is refused under a
/// context field ([`TargetError::ContextField`]).
///
/// `<index>` is an index in its wire form, which is its key — `"eq"`,
/// `"match"`, `"ore"` or `"ope"` — save for a match index with options other
/// than the defaults, which is a one-entry object mapping `"match"` to them:
///
/// ```text
/// { "match": { "tokenizer": "standard" | { "ngram": <length> },
///              "downcase": <bool>, "k": <int>, "m": <int> } }
/// ```
///
/// A bare `"match"` is the default options ([`MatchOptions::default`]:
/// 3-grams, downcased, `k = 3`, `m = 256`), so a plan written before options
/// had a wire form means what it always meant. In the object form each
/// option is optional and defaults the same way; an unknown or repeated
/// option, or a set the match scheme refuses (`k` outside `3..=16`, `m` not
/// a power of two in `32..=65536`, a zero n-gram length), is refused. The
/// other three indexes have no options and no object form. A field names
/// each output key at most once, so it carries at most one match index.
/// [`IndexSpec::to_value`] writes this form and [`IndexSpec::from_value`]
/// reads it. `"passthrough"` is a field's only output when it has it.
///
/// [`MatchOptions::default`]: crate::sem::MatchOptions::default
///
/// `"type"` names a [`ValueKind`] (`"int64"`, `"string"`, …; see
/// [`ValueKind::name`]): vitaminc's vocabulary, not one of this crate's. It
/// is **required on every field with a term output** (`"eq"`, `"match"`,
/// `"ore"`, `"ope"`): the field's terms derive from that one kind, and every
/// value is checked against it on the way in and on the way out, so a
/// binding is never trusted to have tagged each value alike (a `34` sent once
/// as a `Float64` and once as an `Int64` would store two terms under one
/// field). A field with term outputs and no `"type"` is refused when the plan
/// is built ([`Error::UntypedIndex`], naming the field). It is optional on a
/// field whose only output is `"c"` or
/// `"passthrough"`, and on a target field, whose kind is the EQL type's own.
/// Declared, it is checked against the field's outputs here ([`admits`]) and
/// decides nothing about the bytes (see the
/// [module docs](self#what-a-fields-type-decides-and-what-it-does-not)).
///
/// `<context>` is read by [`super::context`](super::context()) and must be
/// the field's label, optionally extended; the
/// [module docs](self#what-a-fields-context-must-be) give the shape.
///
/// # Examples
///
/// ```
/// use stack_encrypt::dynamic::{record, FfiValue, NoTargets, Output};
/// use stack_encrypt::target::IndexSpec;
///
/// // As a binding would decode it from its caller: seal `age` under the
/// // label users/age and index it for equality.
/// let plan = record::plan_with(FfiValue::Object(vec![(
///     "age".to_string(),
///     FfiValue::Object(vec![
///         (
///             "context".to_string(),
///             FfiValue::Array(vec![
///                 FfiValue::String("users".into()),
///                 FfiValue::String("age".into()),
///             ]),
///         ),
///         (
///             "outputs".to_string(),
///             FfiValue::Array(vec![
///                 FfiValue::String("c".into()),
///                 FfiValue::String("eq".into()),
///             ]),
///         ),
///         ("type".to_string(), FfiValue::String("uint32".into())),
///     ]),
/// )]), &NoTargets)?;
///
/// assert_eq!(plan.fields().len(), 1);
/// assert_eq!(plan.fields()[0].name(), "age");
/// assert_eq!(plan.label().map(ToString::to_string).as_deref(), Some("users"));
/// assert_eq!(
///     plan.fields()[0].outputs(),
///     [Output::Ciphertext, Output::Term(IndexSpec::Equality)]
/// );
/// # Ok::<(), stack_encrypt::dynamic::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Plan`] for a plan that is not an object of field specs, an
/// empty plan, a field named twice, a spec with a key other than
/// `"context"`, `"outputs"`, `"target"` and `"type"` or with one given
/// twice, missing `"context"`, having neither `"outputs"` nor `"target"`
/// or having both, an output list that is not a list of outputs (above),
/// is empty, names an output key twice or names `"passthrough"` beside
/// another output, a `"target"` that is not a non-empty string, a `"type"`
/// that is not a string naming a [`ValueKind`], a type that does not admit
/// one of the field's index outputs, a context that is not a label of at
/// least two segments (optionally extended), fields under different
/// contexts or extensions, or a plan the builder refuses ([`Plan::new`]);
/// with `"context_field"`, a value that is not a string, given twice,
/// naming no field of the plan, or a plan [`Plan::with_context_field`]
/// refuses. [`Error::UntypedIndex`], naming the field, for a field with a
/// term output and no `"type"`. [`Error::Context`] for a `"context"` that
/// is present but is not a context at all, or renders empty.
/// [`Error::Target`] for a target the resolver refuses ([`Plan::new_with`]).
///
/// The transport codec refuses duplicate object keys before a binding's
/// value reaches here, but an [`FfiValue`] can be built with them directly
/// and this is a public parser, so it refuses them itself rather than
/// letting the last one win.
pub fn plan_with(
    value: FfiValue,
    resolver: &(impl TargetResolver + ?Sized),
) -> Result<Plan, Error> {
    let FfiValue::Object(entries) = value else {
        return Err(Error::bad_plan(Reason::NotAnObject));
    };
    let mut fields: Vec<FieldPlan> = Vec::with_capacity(entries.len());
    let mut context_field: Option<String> = None;
    for (name, spec) in entries {
        if name == "context_field" {
            // Reserved: the plan-level key, never a field. A second one, or
            // one that is not a string, is refused rather than read as a
            // field spec.
            if context_field.is_some() {
                return Err(Error::bad_plan(Reason::RepeatedKey));
            }
            let FfiValue::String(s) = &spec else {
                return Err(Error::bad_plan(Reason::ContextField));
            };
            let s = utf8(s).ok_or(Error::bad_plan(Reason::ContextField))?;
            context_field = Some(s.to_owned());
            continue;
        }
        let refuse = |reason| Error::Plan {
            field: Some(name.clone()),
            reason,
        };
        let FfiValue::Object(spec) = spec else {
            return Err(refuse(Reason::NotAnObject));
        };
        let mut context: Option<NonEmpty<ContextPiece<'static>>> = None;
        let mut outputs: Option<Vec<Output>> = None;
        let mut target: Option<String> = None;
        let mut field_type: Option<ValueKind> = None;
        for (key, value) in spec {
            match key.as_str() {
                "context" if context.is_none() => {
                    context = Some(super::context(value).map_err(|error| error.in_field(&name))?);
                }
                "target" if target.is_none() => {
                    let FfiValue::String(s) = &value else {
                        return Err(refuse(Reason::InvalidTarget));
                    };
                    target = Some(
                        utf8(s)
                            .ok_or_else(|| refuse(Reason::InvalidTarget))?
                            .to_owned(),
                    );
                }
                "outputs" if outputs.is_none() => {
                    let FfiValue::Array(items) = value else {
                        return Err(refuse(Reason::OutputsNotList));
                    };
                    let parsed = items
                        .iter()
                        .map(Output::from_value)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|error| error.in_field(&name))?;
                    outputs = Some(parsed);
                }
                "type" if field_type.is_none() => {
                    let FfiValue::String(s) = &value else {
                        return Err(refuse(Reason::UnknownType));
                    };
                    let kind = utf8(s).ok_or_else(|| refuse(Reason::UnknownType))?;
                    field_type = Some(kind.parse().map_err(|_| refuse(Reason::UnknownType))?);
                }
                // One of the four given twice.
                "context" | "target" | "outputs" | "type" => {
                    return Err(refuse(Reason::RepeatedKey))
                }
                _ => return Err(refuse(Reason::UnknownKey)),
            }
        }
        let context = context.ok_or_else(|| refuse(Reason::MissingContext))?;
        // One form or the other: a field with both, or neither, is refused.
        let field = match (outputs, target) {
            (Some(outputs), None) => FieldPlan::new(name, context, outputs)?,
            (None, Some(target)) => FieldPlan::with_target(name, context, target)?,
            (Some(_), Some(_)) => return Err(refuse(Reason::OutputsWithTarget)),
            (None, None) => return Err(refuse(Reason::MissingOutputs)),
        };
        fields.push(match field_type {
            Some(field_type) => field.with_type(field_type)?,
            None => field,
        });
    }
    // The whole-plan rules are the constructors', so a parsed plan and a
    // hand-built one are refused alike.
    match context_field {
        Some(name) => Plan::with_context_field(name, fields),
        None => Plan::new_with(fields, resolver),
    }
}

/// Encrypt a record — or a batch of records — per a plan.
///
/// `source` is an [`FfiValue::Object`] of `{ field: value }` (one record),
/// or an [`FfiValue::Array`] of such objects (a batch). Every plan field
/// must be present in each record, and every record field must be named by
/// the plan — silently dropping a field on either side would lose data or
/// index nothing.
///
/// The source is checked and converted here, with no cipher: that is
/// [`check_source`], and it is where [`Error::Source`] comes from. What
/// comes back is the plan's [`Pending`], with every term
/// derived and every key request queued and nothing sent: one batched
/// `generate_keys` for every ciphertext leaf of every row when it is
/// awaited, however many rows and fields there are. Its failure is the
/// engine's [`Error`](crate::Error).
///
/// The result is per record a map of `field → { output-key → node }` (see
/// the [module docs](self#the-stored-record-is-wire-format)): `"c"` first,
/// then each term in the order the plan named its indexes. A batch is a
/// sequence of such maps.
///
/// # Examples
///
/// ```
/// use stack_encrypt::dynamic::{record, FfiValue, Scope};
/// use stack_encrypt::StackCipher;
/// use stack_encrypt::kms::FakeDataKeySource;
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// let cipher = StackCipher::builder()
///     .kms(FakeDataKeySource::new())
///     .init()
///     .await?;
/// let keyset = cipher.default_keyset();
///
/// // Seal `age` under users/age with an equality term beside it.
/// let plan = record::plan(FfiValue::Object(vec![(
///     "age".to_string(),
///     FfiValue::Object(vec![
///         (
///             "context".to_string(),
///             FfiValue::Array(vec![
///                 FfiValue::String("users".into()),
///                 FfiValue::String("age".into()),
///             ]),
///         ),
///         (
///             "outputs".to_string(),
///             FfiValue::Array(vec![
///                 FfiValue::String("c".into()),
///                 FfiValue::String("eq".into()),
///             ]),
///         ),
///         ("type".to_string(), FfiValue::String("uint32".into())),
///     ]),
/// )]))?;
///
/// let row = FfiValue::Object(vec![("age".to_string(), FfiValue::UInt32(34))]);
/// let sealed = record::encrypt(&keyset, row, &plan)?.await?;
///
/// // Only the ciphertext comes back; the term is one-way.
/// let opened = record::decrypt(Scope::Client(&cipher), sealed, &plan, None)?.await?;
/// let FfiValue::Object(fields) = opened else {
///     unreachable!("one record opens to one object");
/// };
/// assert!(matches!(&fields[..], [(name, FfiValue::UInt32(34))] if name == "age"));
/// # Ok::<(), stack_encrypt::dynamic::Error>(())
/// # }).unwrap();
/// ```
///
/// # Errors
///
/// [`Error::Source`] if the source does not fit the plan — a row that is
/// not an object, a field the plan does not name or one it names that the
/// row lacks, or a value of another kind than its field declares, which is
/// how a value no term is defined for is refused: every indexed field
/// declares its kind and the kind check comes first. Decided here, before
/// the pending exists. A failure of the pending itself is the engine's.
///
/// A plan with a target field needs the resolver that built it:
/// [`encrypt_with`]. This runs under [`NoTargets`], so such a plan is
/// refused ([`Error::Target`]).
pub fn encrypt<'a, K: 'static>(
    cipher: &'a KeysetCipher<'_, K>,
    source: FfiValue,
    plan: &Plan,
) -> Result<Pending<'a, StackCipherText, K>, Error> {
    encrypt_with(cipher, source, plan, &NoTargets)
}

/// [`encrypt`], running each target field's EQL type through `resolver`:
/// the type's own plan yields a [`Pending`] that is zipped into the
/// record's, so a record with target fields is still one ZeroKMS request.
/// A target field's value rides under [`EQL_KEY`] in the result.
///
/// # Errors
///
/// As [`encrypt`], plus [`Error::Target`] for a target value of another
/// kind than the type takes, or a name the resolver refuses.
pub fn encrypt_with<'a, K: 'static>(
    cipher: &'a KeysetCipher<'_, K>,
    source: FfiValue,
    plan: &Plan,
    resolver: &(impl TargetResolver + ?Sized),
) -> Result<Pending<'a, StackCipherText, K>, Error> {
    let rows = source_rows(source, plan)?;
    let lowered = plan.lower::<K>().map_err(|_| Error::Internal)?;
    let extend = plan.declared_context();
    let shape = plan.shape();
    // Every target field of every row, in row-major order, run by the
    // resolver; `all` merges their requests with the lowered plan's below.
    let mut pendings = Vec::new();
    let mut targets = |row: Row| -> Result<FieldValues, Error> {
        for (field, value) in plan.target_fields().zip(row.targets) {
            let name = field.target().unwrap_or_default();
            pendings.push(
                resolver
                    .encrypt(name, cipher, field.label(), value)
                    .map_err(|error| Error::Target(name_target(error, &field.name)))?,
            );
        }
        Ok(row.values)
    };
    Ok(match rows {
        Rows::One(row) => {
            let values = targets(row)?;
            let eql = Pending::all(cipher, pendings);
            Runs::<FieldValues, K>::pending(&lowered, cipher, &values, None, extend)
                .zip(eql)
                .try_map(move |(values, eql)| shape_record(values, eql, &shape))
        }
        Rows::Batch(rows) => {
            let values = rows
                .into_iter()
                .map(&mut targets)
                .collect::<Result<Vec<FieldValues>, Error>>()?;
            let eql = Pending::all(cipher, pendings);
            let per_row = plan.target_fields().count();
            Runs::<[FieldValues], K>::pending(&lowered, cipher, &values, None, extend)
                .zip(eql)
                .try_map(move |(rows, eql)| {
                    let mut eql = eql.into_iter();
                    rows.into_iter()
                        .map(|values| {
                            let own: Vec<Vec<u8>> = eql.by_ref().take(per_row).collect();
                            shape_record(values, own, &shape)
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .map(CipherText::Sequence)
                })
        }
    })
}

/// Derive the EQL query value of one target field for one plaintext: the
/// operand that matches stored values of the field, as JSON bytes, through
/// the type's own query plan. A query derives no data key, so the pending
/// settles without I/O; it is a [`Pending`] all the same, for one shape at
/// the call site.
///
/// # Errors
///
/// [`Error::Plan`] if the plan has no field `field` or it is not a target
/// field (a term of an indexed field is [`super::term`](super::term()));
/// [`Error::Source`] for a value of another kind than the field declares;
/// [`Error::Target`] for what the resolver refuses.
pub fn query<'a, K: 'static>(
    cipher: &'a KeysetCipher<'_, K>,
    plan: &Plan,
    field: &str,
    value: FfiValue,
    resolver: &(impl TargetResolver + ?Sized),
) -> Result<Pending<'a, Vec<u8>, K>, Error> {
    let field = plan
        .fields
        .iter()
        .find(|candidate| candidate.name == field)
        .ok_or_else(|| Error::Plan {
            field: Some(field.to_owned()),
            reason: Reason::NoSuchField,
        })?;
    let name = field.target().ok_or_else(|| Error::Plan {
        field: Some(field.name.clone()),
        reason: Reason::NotATarget,
    })?;
    check_field(&value, field)?;
    resolver
        .query(name, cipher, field.label(), value)
        .map_err(|error| Error::Target(name_target(error, &field.name)))
}

/// A resolver's refusal, with the field named where the resolver could not
/// name it: a resolver sees a type and a label, the lowering knows the
/// field.
fn name_target(error: TargetError, field: &str) -> TargetError {
    match error {
        TargetError::Column { label, reason, .. } => TargetError::Column {
            name: field.to_owned(),
            label,
            reason,
        },
        TargetError::Plaintext {
            target,
            expected,
            found,
            ..
        } => TargetError::Plaintext {
            name: field.to_owned(),
            target,
            expected,
            found,
        },
        TargetError::Stored { target, reason, .. } => TargetError::Stored {
            name: field.to_owned(),
            target,
            reason,
        },
        other => other,
    }
}

/// Decrypt a record — or a batch — produced by [`encrypt`] under the same
/// plan.
///
/// Only the `"c"` and `"passthrough"` outputs participate: terms are
/// one-way. The stored tree is checked and read here, with no cipher: that
/// is [`check_record`], and it is where [`Error::Record`] comes from. What
/// comes back is the plan's opener as a [`Pending`]: one batched
/// `retrieve_keys` for every ciphertext leaf when it is awaited and, when
/// opening through [`Scope::Client`], one per keyset the leaves were sealed
/// under. Its value is an [`FfiValue::Object`] per record holding the plan's
/// fields that come back, in plan order — or an [`FfiValue::Array`] of them
/// for a batch.
///
/// `expected` is the context the caller expects, for a plan with a
/// [context field](Plan::with_context_field): the chain's
/// `open(record).context(expected)`. Each record's stored context field is
/// checked against it before any key is requested, and a record that
/// names another context fails the pending with
/// [`Error::ContextMismatch`](crate::Error::ContextMismatch). `None`
/// opens each record under whatever context it stores. For a plan with a
/// context of its own there is nothing to expect: `Some` is refused as the
/// chain refuses it, with
/// [`PlanError::TwoContextSources`](crate::PlanError::TwoContextSources).
///
/// # Errors
///
/// [`Error::Record`] if the stored tree does not fit the plan, decided
/// here. A failure of the pending is the engine's: a wrong context, a wrong
/// key, a tampered ciphertext, a leaf from a keyset other than a
/// [`Scope::Keyset`]'s ([`Error::ForeignKeyset`](crate::Error::ForeignKeyset),
/// before any key is retrieved), a stored context field that is not the
/// one expected ([`Error::ContextMismatch`](crate::Error::ContextMismatch),
/// likewise before any key is retrieved), or a typed field that opens to a
/// value of another kind than it declares
/// ([`PlanError::FieldType`](crate::PlanError::FieldType) — the type tag
/// is inside the AEAD envelope, so only opening can see it).
///
/// A plan with a target field needs the resolver that built it:
/// [`decrypt_with`]. This runs under [`NoTargets`], so such a plan is
/// refused ([`Error::Target`]).
pub fn decrypt<'a, K: 'static>(
    scope: Scope<'a, K>,
    record: StackCipherText,
    plan: &Plan,
    expected: Option<Label>,
) -> Result<Pending<'a, FfiValue, K>, Error> {
    decrypt_with(scope, record, plan, expected, &NoTargets)
}

/// [`decrypt`], opening each target field's EQL value (the [`EQL_KEY`]
/// node) through `resolver`: the type's own decryption, under the field's
/// column, zipped into the record's pending and confined to the scope's
/// keyset as every other leaf is.
///
/// # Errors
///
/// As [`decrypt`], plus [`Error::Target`] for a stored value that is not
/// the type, or a name the resolver refuses.
pub fn decrypt_with<'a, K: 'static>(
    scope: Scope<'a, K>,
    record: StackCipherText,
    plan: &Plan,
    expected: Option<Label>,
    resolver: &(impl TargetResolver + ?Sized),
) -> Result<Pending<'a, FfiValue, K>, Error> {
    let rows = record_rows(record, plan)?;
    let lowered = plan.lower::<K>().map_err(|_| Error::Internal)?;
    let extend = plan.declared_context();
    let shape = plan.shape();
    let (cipher, keyset) = match &scope {
        Scope::Client(cipher) => (*cipher, None),
        Scope::Keyset(keyset) => (keyset.cipher(), Some(keyset.keyset_id())),
    };
    // Confine a pending to the scope's keyset, as the lowered plan's is:
    // a target value sealed under another keyset is refused before any key
    // is retrieved.
    let confine = move |pending: Pending<'a, FfiValue, K>| match keyset {
        Some(keyset) => pending.scoped_to(keyset),
        None => pending,
    };
    let mut pendings = Vec::new();
    let mut targets = |row: StoredRow| -> Result<FieldValues, Error> {
        for (field, stored) in plan.target_fields().zip(row.targets) {
            let name = field.target().unwrap_or_default();
            pendings.push(confine(
                resolver
                    .decrypt(name, cipher, field.label(), &stored)
                    .map_err(|error| Error::Target(name_target(error, &field.name)))?,
            ));
        }
        Ok(row.values)
    };
    Ok(match rows {
        Rows::One(row) => {
            let values = targets(row)?;
            let eql = Pending::all(cipher, pendings);
            run(
                scope,
                Opens::<FieldValues, K>::decryption(&lowered, values, expected, extend),
            )
            .zip(eql)
            .try_map(move |(values, eql)| open_record(values, eql, &shape))
        }
        Rows::Batch(rows) => {
            let values = rows
                .into_iter()
                .map(&mut targets)
                .collect::<Result<Vec<FieldValues>, Error>>()?;
            let eql = Pending::all(cipher, pendings);
            let per_row = plan.target_fields().count();
            run(
                scope,
                Opens::<Vec<FieldValues>, K>::decryption(&lowered, values, expected, extend),
            )
            .zip(eql)
            .try_map(move |(rows, eql)| {
                let mut eql = eql.into_iter();
                rows.into_iter()
                    .map(|values| {
                        let own: Vec<FfiValue> = eql.by_ref().take(per_row).collect();
                        open_record(values, own, &shape)
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(FfiValue::Array)
            })
        }
    })
}

/// Run an opener through the scope the caller chose: the client opens
/// leaves from any of its keysets, a keyset cipher refuses a foreign one
/// before any key is retrieved.
fn run<'a, K: 'static, T: 'static>(
    scope: Scope<'a, K>,
    decryption: Decryption<T, K>,
) -> Pending<'a, T, K> {
    match scope {
        Scope::Client(cipher) => cipher.run_decryption(decryption),
        Scope::Keyset(keyset) => keyset
            .cipher()
            .run_decryption(decryption)
            .scoped_to(keyset.keyset_id()),
    }
}

/// Check a source against a plan without encrypting it — everything
/// [`encrypt`] checks before it builds its pending.
///
/// A binding runs this at its boundary so a malformed call fails the same
/// way whether or not a cipher is available, and never costs a keyset load.
/// It is the same conversion [`encrypt`] runs, followed by the lowered
/// plan's own check of the value, so the two cannot disagree on what is
/// malformed.
///
/// # Errors
///
/// As [`encrypt`], minus the cipher.
pub fn check_source(source: FfiValue, plan: &Plan) -> Result<(), Error> {
    let rows = source_rows(source, plan)?;
    let lowered = plan.lower::<()>().map_err(|_| Error::Internal)?;
    let check = |row: &Row| {
        Runs::<FieldValues, ()>::check(&lowered, &row.values, None).map_err(|error| {
            let (field, reason) = refusal(error);
            Error::Source { field, reason }
        })
    };
    match &rows {
        Rows::One(row) => check(row),
        Rows::Batch(rows) => rows.iter().try_for_each(check),
    }
}

/// Check a stored record against a plan without opening it — everything
/// [`decrypt`] checks before it builds its pending. See [`check_source`].
///
/// A typed field's declared type is not among them: the type is the sealed
/// leaf's tag, inside the AEAD envelope, so only awaiting [`decrypt`] can
/// check it. A stored context field *is*: it is a passthrough, so the
/// check reads it and compares it with `expected`, as [`decrypt`] does
/// before any key is requested.
///
/// # Errors
///
/// As [`decrypt`], minus the cipher: [`Error::Record`] for a tree that
/// does not fit the plan, including a stored context field that is not
/// text or an `expected` given for a plan with a context of its own, and
/// [`Error::Cipher`] holding
/// [`Error::ContextMismatch`](crate::Error::ContextMismatch) for a stored
/// context that is not the one expected — the same error the pending
/// would fail with.
pub fn check_record(
    record: StackCipherText,
    plan: &Plan,
    expected: Option<&Label>,
) -> Result<(), Error> {
    let rows = record_rows(record, plan)?;
    let lowered = plan.lower::<()>().map_err(|_| Error::Internal)?;
    let check = |row: &StoredRow| {
        Opens::<FieldValues, ()>::check(&lowered, &row.values, expected).map_err(
            |error| match error {
                mismatch @ crate::Error::ContextMismatch { .. } => Error::Cipher(mismatch),
                error => {
                    let (field, reason) = refusal(error);
                    Error::Record { field, reason }
                }
            },
        )
    };
    match &rows {
        Rows::One(row) => check(row),
        Rows::Batch(rows) => rows.iter().try_for_each(check),
    }
}

// =============================================================================
// The two trees a record path reads
// =============================================================================

/// A tree that may carry a passthrough or a repeated map key somewhere
/// inside it: a source value ([`FfiValue`]) or a stored ciphertext
/// ([`StackCipherText`]), walked the one way the record rules need.
trait RecordTree: Sized {
    /// The error a tree that does not fit its plan reports, for the field
    /// at fault.
    fn misfit(field: &str, reason: Reason) -> Error;

    /// Whether this node is a passthrough.
    fn is_passthrough(&self) -> bool;

    /// The node's children, for a container.
    fn children(&self) -> Children<'_, Self>;
}

/// A node's children.
enum Children<'a, T> {
    Sequence(&'a [T]),
    Map(&'a [(String, T)]),
    None,
}

impl RecordTree for FfiValue {
    fn misfit(field: &str, reason: Reason) -> Error {
        Error::Source {
            field: Some(field.to_owned()),
            reason,
        }
    }

    fn is_passthrough(&self) -> bool {
        matches!(self, FfiValue::Passthrough(_))
    }

    fn children(&self) -> Children<'_, Self> {
        match self {
            FfiValue::Array(items) => Children::Sequence(items),
            FfiValue::Object(entries) => Children::Map(entries),
            _ => Children::None,
        }
    }
}

impl RecordTree for StackCipherText {
    fn misfit(field: &str, reason: Reason) -> Error {
        Error::Record {
            field: Some(field.to_owned()),
            reason,
        }
    }

    fn is_passthrough(&self) -> bool {
        matches!(self, CipherText::Passthrough(_))
    }

    // Exhaustive, so a variant added to `CipherText` has to say here whether
    // it can hide a passthrough.
    fn children(&self) -> Children<'_, Self> {
        match self {
            CipherText::Sequence(items) => Children::Sequence(items),
            CipherText::Map(entries) => Children::Map(entries),
            CipherText::Passthrough(_)
            | CipherText::Single(_)
            | CipherText::None(_)
            | CipherText::EmptySequence(_)
            | CipherText::EmptyMap(_) => Children::None,
        }
    }
}

/// The rows of a call, as the engine's records: one, or a batch, so the
/// result takes the shape the input had.
enum Rows<R> {
    One(R),
    Batch(Vec<R>),
}

/// One source row: the lowered plan's values, and each target field's
/// value in plan order, for the resolver.
struct Row {
    values: FieldValues,
    targets: Vec<FfiValue>,
}

/// One stored row: the lowered plan's ciphertexts, and each target field's
/// EQL bytes in plan order, for the resolver.
struct StoredRow {
    values: FieldValues,
    targets: Vec<Vec<u8>>,
}

/// Take the one entry named `name` out of a row, whatever order the row had
/// it in. `None` if the row has no such entry — or has it twice: the maps
/// this is used on (a row, a field's output map) are stripped here and never
/// reach the cipher's own duplicate-key refusal, so a first-match take would
/// quietly pick one of two `"c"` nodes for a field, and an attacker with
/// write access to the stored tree could append a stale-but-valid
/// ciphertext beside the current one and have it chosen.
fn take<T>(row: &mut Vec<(String, T)>, name: &str) -> Option<(String, T)> {
    let mut matches = row.iter().enumerate().filter(|(_, (n, _))| n == name);
    let (at, _) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(row.swap_remove(at))
}

/// Why [`take`] found no single `name` in `entries`: `repeated` if the key
/// is there more than once, `missing` if it is not there at all. Read before
/// anything is taken, so the count is the row's own.
fn absence<T>(entries: &[(String, T)], name: &str, missing: Reason, repeated: Reason) -> Reason {
    if entries.iter().any(|(key, _)| key == name) {
        repeated
    } else {
        missing
    }
}

/// Whether no key in `entries` repeats.
fn keys_are_unique<T>(entries: &[(String, T)]) -> bool {
    let mut seen = std::collections::HashSet::with_capacity(entries.len());
    entries.iter().all(|(key, _)| seen.insert(key.as_str()))
}

/// Reject a tree that contains a passthrough anywhere, or a map with a key
/// given twice anywhere.
///
/// The duplicate-key half keeps the preflight honest. The cipher refuses a
/// repeated key itself — at seal, because a map it cannot open must never
/// be produced, and at open, because a stale entry appended beside the
/// current one *verifies* under the same per-entry AAD — but it does so
/// only once the value reaches it, after the plan check has passed. A
/// `check_source`/`check_record` that let such a tree through would say
/// "well-formed" of a value the operation then refuses, so the walk refuses
/// it here, as the misfit it is.
///
/// The passthrough half is the invariant the
/// [module docs](self#the-stored-record-is-wire-format) call load-bearing:
/// on the encrypt side a passthrough inside a sealed field's value would
/// produce a `"c"` subtree whose bytes verify nothing; on the decrypt side a
/// passthrough under `"c"` would be handed back as if it had been opened.
fn check_tree<T: RecordTree>(tree: &T, field: &str) -> Result<(), Error> {
    if tree.is_passthrough() {
        return Err(T::misfit(field, Reason::Passthrough));
    }
    match tree.children() {
        Children::Sequence(items) => items.iter().try_for_each(|item| check_tree(item, field)),
        Children::Map(entries) => {
            if !keys_are_unique(entries) {
                return Err(T::misfit(field, Reason::RepeatedKey));
            }
            entries
                .iter()
                .try_for_each(|(_, node)| check_tree(node, field))
        }
        Children::None => Ok(()),
    }
}

// =============================================================================
// Encrypt side: the source as the engine's record
// =============================================================================

/// The rows of a record source, each as the [`FieldValues`] the lowered
/// plan runs over, with everything that can be checked without a cipher
/// checked: the source is one object or an array of objects, every plan
/// field is present exactly once in every row and no row carries a field
/// the plan does not name, and each value fits its field ([`check_field`]).
/// Each field is moved out of the source into its slot at the type its kind
/// lowers to; nothing else is copied.
fn source_rows(source: FfiValue, plan: &Plan) -> Result<Rows<Row>, Error> {
    match source {
        FfiValue::Object(row) => Ok(Rows::One(source_row(row, plan)?)),
        FfiValue::Array(items) => Ok(Rows::Batch(
            items
                .into_iter()
                .map(|item| match item {
                    FfiValue::Object(row) => source_row(row, plan),
                    _ => Err(Error::bad_source(Reason::NotAnObject)),
                })
                .collect::<Result<Vec<_>, _>>()?,
        )),
        _ => Err(Error::bad_source(Reason::NotAnObject)),
    }
}

fn source_row(mut row: Vec<(String, FfiValue)>, plan: &Plan) -> Result<Row, Error> {
    let mut values = FieldValues::new();
    let mut targets = Vec::new();
    for field in &plan.fields {
        let Some((_, value)) = take(&mut row, &field.name) else {
            return Err(FfiValue::misfit(
                &field.name,
                absence(
                    &row,
                    &field.name,
                    Reason::FieldMissing,
                    Reason::FieldRepeated,
                ),
            ));
        };
        check_field(&value, field)?;
        if field.is_target() {
            targets.push(value);
        } else {
            let _ = values.insert(&field.name, Value::new(value));
        }
    }
    // Every plan field is taken; anything left is a field the plan does not
    // name, which would otherwise be dropped unencrypted.
    if let Some((extra, _)) = row.first() {
        return Err(FfiValue::misfit(extra, Reason::UnknownField));
    }
    Ok(Row { values, targets })
}

/// A source value against its plan field: a typed field needs a value of
/// its type, every term output needs a scalar the scheme defines the term
/// for ([`IndexSpec::supports`]), and a ciphertext output refuses a
/// passthrough, or a repeated map key, anywhere in the value
/// ([`check_tree`]).
fn check_field(value: &FfiValue, field: &FieldPlan) -> Result<(), Error> {
    if let Some(declared) = field.field_type {
        if !declared.holds(value) {
            return Err(FfiValue::misfit(&field.name, Reason::FieldType));
        }
    }
    // A target field's value is sealed by the type's own plan, which
    // refuses a passthrough as any ciphertext does; the same walk here.
    if field.is_target() {
        check_tree(value, &field.name)?;
    }
    for output in &field.outputs {
        match output {
            Output::Ciphertext => check_tree(value, &field.name)?,
            Output::Term(kind) => {
                let scalar =
                    Scalar::of(value, kind).map_err(|error| error.in_field(&field.name))?;
                if !kind.supports(&scalar) {
                    return Err(Error::Term {
                        field: Some(field.name.clone()),
                        kind: kind.clone(),
                    });
                }
            }
            Output::Passthrough => {}
        }
    }
    Ok(())
}

// =============================================================================
// Output adapters: the engine's record as the stored shape, and back
// =============================================================================

/// What the adapters know of a field once the engine has run.
#[derive(Clone, Debug)]
struct FieldShape {
    name: String,
    verb: Verb,
    keys: Vec<&'static str>,
    kind: Option<ValueKind>,
}

/// A slot of the record the engine built from the plan, at the type the
/// plan's verb produces. A missing or mistyped slot is the engine answering
/// with a shape other than the one it was asked for — a bug here, never the
/// caller's input — so it is [`ResponseShape`](crate::Error::ResponseShape),
/// as a miscounted term list is, and not a plan refusal.
fn slot<T: std::any::Any>(values: &mut FieldValues, name: &str) -> Result<T, crate::Error> {
    values.take(name).map_err(|_| crate::Error::ResponseShape)
}

/// A term as the stored tree carries it: a passthrough byte node.
fn term_node(term: TermBytes) -> StackCipherText {
    CipherText::Passthrough(Box::new(FfiValue::Bytes(vitaminc_protected::Protected::new(
        term.into_bytes(),
    ))) as BoxedPassthrough)
}

/// The record the plan produced, in the stored shape: per field, in plan
/// order, its output map.
fn shape_record(
    mut values: FieldValues,
    eql: Vec<Vec<u8>>,
    shape: &[FieldShape],
) -> Result<StackCipherText, crate::Error> {
    let mut fields = Vec::with_capacity(shape.len());
    let mut eql = eql.into_iter();
    for field in shape {
        let outputs = match field.verb {
            Verb::Target => {
                // The resolver answered one value per target field, in plan
                // order; running short is the engine answering with a
                // different shape than it was asked.
                let value = eql.next().ok_or(crate::Error::ResponseShape)?;
                vec![(
                    EQL_KEY.to_string(),
                    CipherText::Passthrough(Box::new(FfiValue::Bytes(
                        vitaminc_protected::Protected::new(value),
                    )) as BoxedPassthrough),
                )]
            }
            Verb::Encrypt => {
                let ciphertext: StackCipherText = slot(&mut values, &field.name)?;
                vec![("c".to_string(), ciphertext)]
            }
            Verb::EncryptIndex => {
                let sealed: Encrypted<Vec<TermBytes>> = slot(&mut values, &field.name)?;
                let mut outputs = Vec::with_capacity(1 + field.keys.len());
                outputs.push(("c".to_string(), sealed.ciphertext));
                outputs.extend(keyed_terms(sealed.terms, &field.keys)?);
                outputs
            }
            Verb::Index => keyed_terms(slot(&mut values, &field.name)?, &field.keys)?,
            Verb::Passthrough => {
                let value = take_leaf(&mut values, &field.name)?;
                vec![(
                    "passthrough".to_string(),
                    CipherText::Passthrough(Box::new(value) as BoxedPassthrough),
                )]
            }
        };
        fields.push((field.name.clone(), CipherText::Map(outputs)));
    }
    Ok(CipherText::Map(fields))
}

/// Each term under its index key, in the order the plan named the indexes.
/// The counts cannot disagree: both come from the plan's indexes; if they
/// did, the engine answered with a different shape than it was asked.
fn keyed_terms(
    terms: Vec<TermBytes>,
    keys: &[&'static str],
) -> Result<Vec<(String, StackCipherText)>, crate::Error> {
    if terms.len() != keys.len() {
        return Err(crate::Error::ResponseShape);
    }
    Ok(keys
        .iter()
        .zip(terms)
        .map(|(key, term)| ((*key).to_string(), term_node(term)))
        .collect())
}

/// The field `name` out of the record, as the value it holds.
fn take_leaf(values: &mut FieldValues, name: &str) -> Result<FfiValue, crate::Error> {
    Ok(slot::<Value>(values, name)?.into_inner())
}

/// The record the plan opened, as a value: the fields that come back, in
/// plan order, each checked against its declared kind. The tag is
/// authenticated, so a mismatch is not tampering: the row was sealed as
/// another type than the plan now declares.
fn open_record(
    mut values: FieldValues,
    eql: Vec<FfiValue>,
    shape: &[FieldShape],
) -> Result<FfiValue, crate::Error> {
    let mut fields = Vec::with_capacity(shape.len());
    let mut eql = eql.into_iter();
    for field in shape.iter().filter(|field| field.verb != Verb::Index) {
        let value = if field.verb == Verb::Target {
            eql.next().ok_or(crate::Error::ResponseShape)?
        } else {
            take_leaf(&mut values, &field.name)?
        };
        if let Some(kind) = field.kind {
            if !kind.holds(&value) {
                return Err(crate::PlanError::FieldType {
                    field: field.name.clone(),
                    expected: kind.name(),
                }
                .into());
            }
        }
        fields.push((field.name.clone(), value));
    }
    Ok(FfiValue::Object(fields))
}

// =============================================================================
// Decrypt side: the stored tree as the engine's record
// =============================================================================

/// The rows of a stored record, each as the [`FieldValues`] the lowered
/// plan opens: the tree is one map or a sequence of maps; each sealed field
/// is present exactly once, is a map of outputs with exactly one `"c"`, and
/// that node has no passthrough and no repeated key in it ([`check_tree`]);
/// each passthrough field is present exactly once with exactly one
/// `"passthrough"` node carrying a value of the field's kind. Terms, and
/// entries the plan does not open, are ignored: comparands, not ciphertext.
fn record_rows(tree: StackCipherText, plan: &Plan) -> Result<Rows<StoredRow>, Error> {
    match tree {
        CipherText::Map(row) => Ok(Rows::One(record_row(row, plan)?)),
        CipherText::Sequence(items) => Ok(Rows::Batch(
            items
                .into_iter()
                .map(|item| match item {
                    CipherText::Map(row) => record_row(row, plan),
                    _ => Err(Error::bad_record(Reason::NotAnObject)),
                })
                .collect::<Result<Vec<_>, _>>()?,
        )),
        _ => Err(Error::bad_record(Reason::NotAnObject)),
    }
}

fn record_row(mut row: Vec<(String, StackCipherText)>, plan: &Plan) -> Result<StoredRow, Error> {
    let mut values = FieldValues::new();
    let mut targets = Vec::new();
    for field in plan.fields.iter().filter(|field| field.opens()) {
        let misfit = |reason| StackCipherText::misfit(&field.name, reason);
        let Some((_, node)) = take(&mut row, &field.name) else {
            return Err(misfit(absence(
                &row,
                &field.name,
                Reason::FieldMissing,
                Reason::FieldRepeated,
            )));
        };
        let CipherText::Map(mut outputs) = node else {
            return Err(misfit(Reason::OutputsNotMap));
        };
        // The one node under `key`, or why there is not exactly one.
        let mut node = |key: &str, missing: Reason| {
            take(&mut outputs, key)
                .map(|(_, node)| node)
                .ok_or_else(|| misfit(absence(&outputs, key, missing, Reason::RepeatedKey)))
        };
        match field.verb() {
            Verb::Target => {
                // The EQL value: a passthrough carrying bytes, exactly once.
                // What it opens to is the type's own decryption's to decide.
                let CipherText::Passthrough(payload) = node(EQL_KEY, Reason::NoEqlNode)? else {
                    return Err(misfit(Reason::NotPassthrough));
                };
                let value = *payload
                    .downcast::<FfiValue>()
                    .map_err(|_| misfit(Reason::NotPassthrough))?;
                let FfiValue::Bytes(bytes) = value else {
                    return Err(misfit(Reason::NotPassthrough));
                };
                targets.push(bytes.risky_unwrap());
            }
            Verb::Passthrough => {
                let CipherText::Passthrough(payload) =
                    node("passthrough", Reason::NoPassthroughNode)?
                else {
                    return Err(misfit(Reason::NotPassthrough));
                };
                let value = *payload
                    .downcast::<FfiValue>()
                    .map_err(|_| misfit(Reason::NotPassthrough))?;
                if field.field_type.is_some_and(|kind| !kind.holds(&value)) {
                    return Err(misfit(Reason::FieldType));
                }
                let _ = values.insert(&field.name, Value::new(value));
            }
            Verb::Encrypt | Verb::EncryptIndex | Verb::Index => {
                let ciphertext = node("c", Reason::NoCiphertextNode)?;
                check_tree(&ciphertext, &field.name)?;
                let _ = values.insert(&field.name, ciphertext);
            }
        }
    }
    Ok(StoredRow { values, targets })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use stack_kms::{
        DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyPayload,
        IdentifiedBy, IndexKey, IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
    };
    use uuid::Uuid;
    use vitaminc_protected::{Controlled, Protected};

    use crate::dynamic::{context, term};
    use crate::plan::pick;
    use crate::sem::EqualityTerm;
    use crate::target::{AeadContext, DecryptInto, EncryptFrom};
    use crate::{nonempty, Equality, PlanError, StackCipher};

    /// `FakeDataKeySource` with call counters, so the batching contract —
    /// one key request per invocation, none for a refused call — is
    /// asserted rather than trusted.
    #[derive(Default)]
    struct Counting {
        inner: FakeDataKeySource,
        generate_calls: AtomicUsize,
        retrieve_calls: AtomicUsize,
    }

    impl DataKeySource for Counting {
        async fn generate_keys(
            &self,
            payloads: Vec<GenerateKeyPayload<'_>>,
            keyset_id: Option<Uuid>,
            unverified_context: Option<Cow<'_, UnverifiedContext>>,
        ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
            let _ = self.generate_calls.fetch_add(1, Ordering::SeqCst);
            self.inner
                .generate_keys(payloads, keyset_id, unverified_context)
                .await
        }

        async fn retrieve_keys(
            &self,
            payloads: Vec<RetrieveKeyPayload<'_>>,
            keyset_id: Option<Uuid>,
            unverified_context: Option<&UnverifiedContext>,
        ) -> Result<Vec<DataKey>, stack_kms::Error> {
            let _ = self.retrieve_calls.fetch_add(1, Ordering::SeqCst);
            self.inner
                .retrieve_keys(payloads, keyset_id, unverified_context)
                .await
        }
    }

    impl IndexKeySource for Counting {
        async fn load_index_key(
            &self,
            keyset_id: Option<IdentifiedBy>,
        ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
            self.inner.load_index_key(keyset_id).await
        }
    }

    async fn cipher() -> StackCipher<Counting> {
        StackCipher::builder()
            .kms(Counting::default())
            .init()
            .await
            .expect("build cipher")
    }

    fn generates(cipher: &StackCipher<Counting>) -> usize {
        cipher.kms().generate_calls.load(Ordering::SeqCst)
    }

    fn retrieves(cipher: &StackCipher<Counting>) -> usize {
        cipher.kms().retrieve_calls.load(Ordering::SeqCst)
    }

    // ---- values, as a binding would decode them ----------------------------

    fn s(value: &str) -> FfiValue {
        FfiValue::String(value.into())
    }

    fn obj(entries: Vec<(&str, FfiValue)>) -> FfiValue {
        FfiValue::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    fn strings(items: &[&str]) -> FfiValue {
        FfiValue::Array(items.iter().map(|item| s(item)).collect())
    }

    /// The label `users/<field>`, as a binding spells a column.
    fn label(field: &str) -> FfiValue {
        strings(&["users", field])
    }

    fn spec(context: FfiValue, outputs: &[&str]) -> FfiValue {
        obj(vec![("context", context), ("outputs", strings(outputs))])
    }

    fn typed(context: FfiValue, outputs: &[&str], ty: &str) -> FfiValue {
        obj(vec![
            ("context", context),
            ("outputs", strings(outputs)),
            ("type", s(ty)),
        ])
    }

    /// The plan most tests share: `age` sealed and indexed for equality and
    /// order under `users/age`; `email` sealed alone under `users/email`;
    /// `nick` indexed for match only, never sealed; `id` carried through.
    fn plan_value() -> FfiValue {
        obj(vec![
            ("age", typed(label("age"), &["c", "eq", "ore"], "uint32")),
            ("email", spec(label("email"), &["c"])),
            ("nick", typed(label("nick"), &["match"], "string")),
            ("id", spec(label("id"), &["passthrough"])),
        ])
    }

    fn the_plan() -> Plan {
        plan(plan_value()).expect("the shared plan parses")
    }

    fn row(age: u32) -> FfiValue {
        obj(vec![
            ("age", FfiValue::UInt32(age)),
            ("email", s("a@x")),
            ("nick", s("al smith")),
            ("id", FfiValue::UInt64(7)),
        ])
    }

    // ---- running the lowering ---------------------------------------------

    async fn seal(
        keyset: &KeysetCipher<'_, Counting>,
        source: FfiValue,
        plan: &Plan,
    ) -> StackCipherText {
        encrypt(keyset, source, plan)
            .expect("the source fits the plan")
            .await
            .expect("encrypt")
    }

    async fn open(
        cipher: &StackCipher<Counting>,
        record: StackCipherText,
        plan: &Plan,
    ) -> FfiValue {
        decrypt(Scope::Client(cipher), record, plan, None)
            .expect("the record fits the plan")
            .await
            .expect("decrypt")
    }

    // ---- reading results back -----------------------------------------------

    fn map(tree: StackCipherText) -> Vec<(String, StackCipherText)> {
        match tree {
            CipherText::Map(entries) => entries,
            _ => panic!("expected a map node"),
        }
    }

    fn sequence(tree: StackCipherText) -> Vec<StackCipherText> {
        match tree {
            CipherText::Sequence(items) => items,
            _ => panic!("expected a sequence node"),
        }
    }

    fn object(value: FfiValue) -> Vec<(String, FfiValue)> {
        match value {
            FfiValue::Object(entries) => entries,
            _ => panic!("expected an object"),
        }
    }

    fn array(value: FfiValue) -> Vec<FfiValue> {
        match value {
            FfiValue::Array(items) => items,
            _ => panic!("expected an array"),
        }
    }

    fn keys<T>(entries: &[(String, T)]) -> Vec<&str> {
        entries.iter().map(|(k, _)| k.as_str()).collect()
    }

    fn node(entries: &mut Vec<(String, StackCipherText)>, key: &str) -> StackCipherText {
        take(entries, key)
            .unwrap_or_else(|| panic!("no {key} node"))
            .1
    }

    fn term_bytes(node: &StackCipherText) -> Vec<u8> {
        match node {
            CipherText::Passthrough(payload) => match (**payload).downcast_ref::<FfiValue>() {
                Some(FfiValue::Bytes(bytes)) => bytes.risky_ref().to_vec(),
                _ => panic!("a term rides as a passthrough byte node"),
            },
            _ => panic!("a term rides as a passthrough"),
        }
    }

    fn u32_of(value: &FfiValue) -> u32 {
        match value {
            FfiValue::UInt32(v) => *v,
            _ => panic!("expected a u32"),
        }
    }

    fn u64_of(value: &FfiValue) -> u64 {
        match value {
            FfiValue::UInt64(v) => *v,
            _ => panic!("expected a u64"),
        }
    }

    fn text_of(value: &FfiValue) -> String {
        match value {
            FfiValue::String(s) => String::from_utf8(s.risky_ref().to_vec()).expect("utf8"),
            _ => panic!("expected text"),
        }
    }

    fn forged(value: FfiValue) -> StackCipherText {
        CipherText::Passthrough(Box::new(value) as BoxedPassthrough)
    }

    fn plan_error(error: crate::Error) -> PlanError {
        match error {
            crate::Error::Plan(error) => error,
            other => panic!("expected a plan error, got {other:?}"),
        }
    }

    /// A table row: what is refused, the value that must be refused, and
    /// the error it must be refused with. `Error` is not `PartialEq`, so the
    /// expectation is a predicate.
    type Refused = (&'static str, FfiValue, fn(&Error) -> bool);

    /// The adapters read the record the engine built from the plan. A slot
    /// that is missing or of another type than the plan's verb produces is
    /// the engine's shape disagreeing with the plan's — this module's bug —
    /// and is reported as `ResponseShape`, which a binding maps to its
    /// internal status, never as a plan refusal the caller is told to fix.
    #[test]
    fn a_slot_the_engine_did_not_produce_is_a_response_shape_error() {
        let shape = the_plan().shape();
        let empty = FieldValues::new();
        assert!(
            matches!(
                shape_record(empty, Vec::new(), &shape),
                Err(crate::Error::ResponseShape)
            ),
            "a missing slot on the encrypt side"
        );
        let mut wrong = FieldValues::new();
        let _ = wrong.insert("age", 34u32);
        assert!(
            matches!(
                shape_record(wrong, Vec::new(), &shape),
                Err(crate::Error::ResponseShape)
            ),
            "a mistyped slot on the encrypt side"
        );
        let mut wrong = FieldValues::new();
        let _ = wrong.insert("age", 34u32);
        assert!(
            matches!(
                open_record(wrong, Vec::new(), &shape),
                Err(crate::Error::ResponseShape)
            ),
            "a mistyped slot on the decrypt side"
        );
        assert!(
            matches!(
                open_record(FieldValues::new(), Vec::new(), &shape),
                Err(crate::Error::ResponseShape)
            ),
            "a missing slot on the decrypt side"
        );
    }

    mod given_a_plan_value {
        use super::*;

        #[test]
        fn parses_each_field_in_order_with_its_label_and_outputs() {
            let plan = the_plan();
            assert_eq!(
                plan.fields()
                    .iter()
                    .map(FieldPlan::name)
                    .collect::<Vec<_>>(),
                ["age", "email", "nick", "id"],
                "fields keep the plan's order"
            );
            assert_eq!(
                plan.fields()[0].outputs(),
                [
                    Output::Ciphertext,
                    Output::Term(IndexSpec::Equality),
                    Output::Term(IndexSpec::Ore)
                ],
                "outputs keep their spelled order"
            );
            assert_eq!(
                plan.fields()[1].outputs(),
                [Output::Ciphertext],
                "a field can be sealed alone"
            );
            assert_eq!(
                plan.fields()[2].outputs(),
                [Output::Term(IndexSpec::Match(
                    crate::sem::MatchOptions::default()
                ))],
                "a field can be indexed and never sealed"
            );
            assert_eq!(
                plan.fields()[3].outputs(),
                [Output::Passthrough],
                "a field can be carried through"
            );
            assert!(
                plan.fields()[0].has_ciphertext()
                    && plan.fields()[1].has_ciphertext()
                    && !plan.fields()[2].has_ciphertext()
                    && !plan.fields()[3].has_ciphertext(),
                "has_ciphertext follows the outputs"
            );
            assert_eq!(
                plan.label().expect("a plan context").to_string(),
                "users",
                "the plan's one context"
            );
            assert!(plan.extension().is_empty(), "no extension was spelled");
            assert_eq!(
                plan.fields()[1].label().to_string(),
                "users/email",
                "a field's label is the one its spec spelled"
            );
            assert_eq!(plan.fields()[1].identity(), "email");
            assert_eq!(
                plan.fields()[1].context(),
                &context(label("email")).expect("context"),
                "a field's context is the one its spec spelled, read by `context`"
            );
        }

        #[test]
        fn refuses_a_malformed_plan_before_any_field_is_built() {
            let cases: Vec<Refused> = vec![
                ("a plan that is not an object", s("x"), |e| {
                    matches!(e, Error::Plan { .. })
                }),
                ("an empty plan", obj(vec![]), |e| {
                    matches!(e, Error::Plan { .. })
                }),
                (
                    "a field spec that is not an object",
                    obj(vec![("age", s("x"))]),
                    |e| matches!(e, Error::Plan { .. }),
                ),
                (
                    "a field spec with an unknown key",
                    obj(vec![(
                        "age",
                        obj(vec![
                            ("context", label("age")),
                            ("outputs", strings(&["c"])),
                            ("nullable", FfiValue::Bool(true)),
                        ]),
                    )]),
                    |e| matches!(e, Error::Plan { .. }),
                ),
                (
                    "a field spec with no context",
                    obj(vec![("age", obj(vec![("outputs", strings(&["c"]))]))]),
                    |e| matches!(e, Error::Plan { .. }),
                ),
                (
                    "a field spec with no outputs",
                    obj(vec![("age", obj(vec![("context", label("age"))]))]),
                    |e| matches!(e, Error::Plan { .. }),
                ),
                (
                    "outputs that are not a list",
                    obj(vec![("age", spec(label("age"), &[]))]),
                    |e| matches!(e, Error::Plan { .. }),
                ),
                (
                    "an output that is not a string",
                    obj(vec![(
                        "age",
                        obj(vec![
                            ("context", label("age")),
                            ("outputs", FfiValue::Array(vec![FfiValue::UInt32(1)])),
                        ]),
                    )]),
                    |e| matches!(e, Error::Plan { .. }),
                ),
                (
                    "an unknown output",
                    obj(vec![("age", spec(label("age"), &["c", "sum"]))]),
                    |e| matches!(e, Error::Plan { .. }),
                ),
                (
                    "an output named twice",
                    obj(vec![("age", spec(label("age"), &["c", "eq", "c"]))]),
                    |e| matches!(e, Error::Plan { .. }),
                ),
                (
                    "passthrough beside a ciphertext",
                    obj(vec![("age", spec(label("age"), &["passthrough", "c"]))]),
                    |e| matches!(e, Error::Plan { .. }),
                ),
                (
                    "passthrough beside an index",
                    obj(vec![("age", spec(label("age"), &["eq", "passthrough"]))]),
                    |e| matches!(e, Error::Plan { .. }),
                ),
                (
                    "a field named twice",
                    FfiValue::Object(vec![
                        ("age".to_string(), spec(label("age"), &["c"])),
                        ("age".to_string(), spec(label("age"), &["eq"])),
                    ]),
                    |e| matches!(e, Error::Plan { .. }),
                ),
                (
                    "a context given twice",
                    obj(vec![(
                        "age",
                        obj(vec![
                            ("context", label("age")),
                            ("outputs", strings(&["c"])),
                            ("context", label("other")),
                        ]),
                    )]),
                    |e| matches!(e, Error::Plan { .. }),
                ),
                (
                    "outputs given twice",
                    obj(vec![(
                        "age",
                        obj(vec![
                            ("context", label("age")),
                            ("outputs", strings(&["c"])),
                            ("outputs", strings(&["eq"])),
                        ]),
                    )]),
                    |e| matches!(e, Error::Plan { .. }),
                ),
                (
                    "a context that is not one",
                    obj(vec![("age", spec(FfiValue::Bool(true), &["c"]))]),
                    |e| matches!(e, Error::Context { .. }),
                ),
                (
                    "a context that renders empty",
                    obj(vec![("age", spec(s(""), &["c"]))]),
                    |e| matches!(e, Error::Context { .. }),
                ),
            ];
            for (label, value, expected) in cases {
                let err = plan(value).err();
                assert!(
                    err.as_ref().is_some_and(expected),
                    "{label} must be refused as the right error: {err:?}"
                );
            }
        }

        /// A field's context is its label, optionally extended, and nothing
        /// else: what a fields plan can give a field. The shapes refused here
        /// are contexts (`dynamic::context` reads them) that no `.fields()`
        /// chain could spell.
        #[test]
        fn refuses_a_field_context_that_is_not_a_label() {
            let refused = [
                ("one text part, however it reads", s("users/age")),
                ("a one-segment label", strings(&["users"])),
                ("a one-element list", FfiValue::Array(vec![s("users")])),
                ("an integer", FfiValue::UInt64(7)),
                ("bytes", FfiValue::Bytes(Protected::new(b"users".to_vec()))),
                (
                    "a one-segment label, extended",
                    FfiValue::Array(vec![s("users"), FfiValue::UInt64(7)]),
                ),
                (
                    "a segment that is not plain",
                    strings(&["users", "age/years"]),
                ),
                (
                    "a segment with a reserved prefix",
                    strings(&["users", "7age"]),
                ),
                (
                    "a list part as an extension",
                    FfiValue::Array(vec![label("age"), strings(&["eu", "west"])]),
                ),
            ];
            for (what, context) in refused {
                let result = plan(obj(vec![("age", spec(context, &["c"]))]));
                assert!(
                    matches!(result, Err(Error::Plan { .. })),
                    "{what}: {result:?}"
                );
            }
        }

        /// Every field sits under the plan's one context and carries the one
        /// extension, so two fields that disagree are not one plan.
        #[test]
        fn refuses_fields_under_different_contexts_or_extensions() {
            let parsed = plan(obj(vec![
                ("age", spec(label("age"), &["c"])),
                ("total", spec(strings(&["orders", "total"]), &["c"])),
            ]));
            assert!(
                matches!(parsed, Err(Error::Plan { .. })),
                "two contexts: {parsed:?}"
            );
            let parsed = plan(obj(vec![
                (
                    "age",
                    spec(
                        FfiValue::Array(vec![label("age"), FfiValue::UInt64(7)]),
                        &["c"],
                    ),
                ),
                ("email", spec(label("email"), &["c"])),
            ]));
            assert!(
                matches!(parsed, Err(Error::Plan { .. })),
                "one field extended, one not: {parsed:?}"
            );
            let parsed = plan(obj(vec![
                (
                    "age",
                    spec(
                        FfiValue::Array(vec![label("age"), FfiValue::UInt64(7)]),
                        &["c"],
                    ),
                ),
                (
                    "email",
                    spec(
                        FfiValue::Array(vec![label("email"), FfiValue::UInt64(8)]),
                        &["c"],
                    ),
                ),
            ]));
            assert!(
                matches!(parsed, Err(Error::Plan { .. })),
                "two extensions: {parsed:?}"
            );
            // The same prefix spelled deeper is still one context.
            let parsed = plan(obj(vec![
                ("age", spec(strings(&["app", "users", "age"]), &["c"])),
                ("email", spec(strings(&["app", "users", "email"]), &["c"])),
            ]))
            .expect("one two-segment context");
            assert_eq!(
                parsed.label().expect("a plan context").to_string(),
                "app/users"
            );
        }

        /// Two sealed fields keyed under one identity would have one context
        /// and interchangeable terms: the builder refuses it, so the plan does.
        #[test]
        fn refuses_two_fields_keyed_under_one_identity() {
            let parsed = plan(obj(vec![
                ("mail", typed(label("email"), &["c", "eq"], "string")),
                ("mail2", typed(label("email"), &["c", "eq"], "string")),
            ]));
            assert!(matches!(parsed, Err(Error::Plan { .. })), "{parsed:?}");
            // Two passthrough fields key nothing, so they may share a label.
            let parsed = plan(obj(vec![
                ("a", spec(label("meta"), &["passthrough"])),
                ("b", spec(label("meta"), &["passthrough"])),
            ]));
            assert!(parsed.is_ok(), "{parsed:?}");
        }

        /// A field whose label ends in a segment other than its name is keyed
        /// under that segment: the plan pins its identity.
        #[test]
        fn a_label_whose_last_segment_is_not_the_name_pins_the_identity() {
            let parsed = plan(obj(vec![(
                "nickname",
                spec(strings(&["users", "handle"]), &["c"]),
            )]))
            .expect("parses");
            assert_eq!(parsed.fields()[0].identity(), "handle");
            let lowered = parsed.lower::<()>().expect("lowers");
            let field = lowered.field("nickname").expect("the field");
            assert_eq!(field.identity(), "handle");
            assert_eq!(
                field.label().map(ToString::to_string),
                Some("users/handle".into())
            );
        }

        #[test]
        fn a_field_plan_refuses_no_outputs_and_a_repeated_output() {
            let ctx = context(label("age")).expect("context");
            assert!(
                matches!(
                    FieldPlan::new("age", ctx.clone(), vec![]),
                    Err(Error::Plan { .. })
                ),
                "a field must produce something"
            );
            assert!(
                matches!(
                    FieldPlan::new(
                        "age",
                        ctx.clone(),
                        vec![Output::Term(IndexSpec::Ore), Output::Term(IndexSpec::Ore)]
                    ),
                    Err(Error::Plan { .. })
                ),
                "an output cannot be produced twice under one key"
            );
            assert!(
                matches!(
                    FieldPlan::new(
                        "age",
                        ctx.clone(),
                        vec![Output::Passthrough, Output::Ciphertext]
                    ),
                    Err(Error::Plan { .. })
                ),
                "a passthrough field has no other output"
            );
            assert!(
                FieldPlan::new("age", ctx, vec![Output::Ciphertext]).is_ok(),
                "one output is a plan"
            );
        }

        /// A match index with non-default options is spelled in a plan as
        /// an object, parses to the index carrying them, and still rides
        /// under the `"match"` key; the bare key stays the defaults.
        #[test]
        fn a_match_index_with_options_parses_from_its_object_form() {
            let wide = obj(vec![(
                "match",
                obj(vec![
                    ("tokenizer", s("standard")),
                    ("downcase", FfiValue::Bool(false)),
                    ("k", FfiValue::UInt32(6)),
                    ("m", FfiValue::UInt32(1024)),
                ]),
            )]);
            let plan = plan(obj(vec![(
                "nick",
                obj(vec![
                    ("context", label("nick")),
                    ("outputs", FfiValue::Array(vec![s("c"), wide])),
                    ("type", s("string")),
                ]),
            )]))
            .expect("parses");
            let options = crate::sem::MatchOptions {
                tokenizer: crate::sem::Tokenizer::Standard,
                downcase: false,
                k: 6,
                m: 1024,
            };
            assert_eq!(
                plan.fields()[0].outputs(),
                [Output::Ciphertext, Output::Term(IndexSpec::Match(options))]
            );
            assert_eq!(plan.fields()[0].outputs()[1].key(), "match");
        }

        /// Two match indexes in one field would both ride under `"match"`,
        /// so a field names an output key once whatever the options.
        #[test]
        fn a_field_refuses_two_match_indexes_under_different_options() {
            let wide = obj(vec![("match", obj(vec![("k", FfiValue::UInt32(6))]))]);
            let parsed = plan(obj(vec![(
                "nick",
                obj(vec![
                    ("context", label("nick")),
                    ("outputs", FfiValue::Array(vec![s("match"), wide])),
                ]),
            )]));
            assert!(
                matches!(parsed, Err(Error::Plan { .. })),
                "two match outputs are one key twice"
            );
            let ctx = context(label("nick")).expect("context");
            let by_hand = FieldPlan::new(
                "nick",
                ctx,
                vec![
                    Output::Term(IndexSpec::Match(crate::sem::MatchOptions::default())),
                    Output::Term(IndexSpec::Match(crate::sem::MatchOptions {
                        k: 6,
                        ..crate::sem::MatchOptions::default()
                    })),
                ],
            );
            assert!(
                matches!(by_hand, Err(Error::Plan { .. })),
                "and by hand alike"
            );
        }

        /// An output list entry is `"c"`, `"passthrough"` or an index in its
        /// wire form, and nothing else; a malformed match object is a plan
        /// error.
        #[test]
        fn an_output_that_is_not_one_is_refused() {
            for (label_, output) in [
                ("an unknown key", s("cc")),
                ("a number", FfiValue::UInt32(1)),
                (
                    "an object for the ciphertext",
                    obj(vec![("c", obj(vec![]))]),
                ),
                (
                    "match options out of bounds",
                    obj(vec![("match", obj(vec![("k", FfiValue::UInt32(2))]))]),
                ),
            ] {
                let parsed = plan(obj(vec![(
                    "nick",
                    obj(vec![
                        ("context", label("nick")),
                        ("outputs", FfiValue::Array(vec![output])),
                    ]),
                )]));
                assert!(matches!(parsed, Err(Error::Plan { .. })), "{label_}");
            }
            assert_eq!(Output::parse("c"), Some(Output::Ciphertext));
            assert_eq!(Output::parse("passthrough"), Some(Output::Passthrough));
            assert_eq!(Output::parse("ore"), Some(Output::Term(IndexSpec::Ore)));
            assert_eq!(Output::parse("cc"), None);
            assert_eq!(Output::Passthrough.key(), "passthrough");
            assert_eq!(Output::Ciphertext.key(), "c");
        }

        /// The whole-plan rules hold for a plan built by hand, not only for
        /// a parsed one: a hand-built plan reaches the same `encrypt` and
        /// `check_source`, which rely on them.
        #[test]
        fn a_hand_built_plan_refuses_no_fields_and_a_repeated_name() {
            let field = |name: &str| {
                FieldPlan::new(
                    name,
                    context(label(name)).expect("context"),
                    vec![Output::Ciphertext],
                )
                .expect("field")
            };
            assert!(
                matches!(Plan::new(vec![]), Err(Error::Plan { .. })),
                "a plan must have a field"
            );
            assert!(
                matches!(
                    Plan::new(vec![field("age"), field("age")]),
                    Err(Error::Plan { .. })
                ),
                "a field cannot be planned twice"
            );
            let plan = Plan::new(vec![field("age"), field("email")]).expect("a plan");
            assert_eq!(
                plan.fields()
                    .iter()
                    .map(FieldPlan::name)
                    .collect::<Vec<_>>(),
                ["age", "email"],
                "the fields keep the order given"
            );
        }
    }

    /// The refusal names the indexed field that has no type. A typed indexed
    /// field, a sealed-only field and a passthrough field beside it are not
    /// what is refused.
    #[test]
    fn untyped_index_names_the_field_that_has_no_type() {
        let parsed = plan(obj(vec![
            ("age", typed(label("age"), &["c", "eq"], "uint32")),
            ("email", spec(label("email"), &["c"])),
            ("id", spec(label("id"), &["passthrough"])),
            ("nick", spec(label("nick"), &["match"])),
        ]));
        assert!(
            matches!(&parsed, Err(Error::UntypedIndex { field }) if field == "nick"),
            "{parsed:?}"
        );
    }

    /// An indexed field declares its type. A plan whose indexed field has
    /// none is refused when it is built, for every index kind, with no key
    /// request; a field that only seals or only carries its value through
    /// still builds without one, seals and opens.
    #[tokio::test]
    async fn an_indexed_field_without_a_type_is_refused_at_build() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        fn wide() -> FfiValue {
            IndexSpec::Match(crate::sem::MatchOptions {
                k: 6,
                ..crate::sem::MatchOptions::default()
            })
            .to_value()
        }
        // Each case is refused for the missing type and nothing else: the
        // refusal is the variant that names the field, and the same spec
        // parses once a kind that admits its outputs is declared. (An
        // `FfiValue` does not clone, so each case builds its outputs twice.)
        type Outputs = fn() -> Vec<FfiValue>;
        let cases: [(&str, Outputs, &str); 7] = [
            ("equality", || vec![s("c"), s("eq")], "uint32"),
            ("match", || vec![s("c"), s("match")], "string"),
            ("match with options", || vec![s("c"), wide()], "string"),
            ("ore", || vec![s("c"), s("ore")], "uint32"),
            ("ope", || vec![s("c"), s("ope")], "uint32"),
            ("an index alone", || vec![s("eq")], "uint32"),
            (
                "several indexes",
                || vec![s("c"), s("eq"), s("ore"), s("ope")],
                "uint32",
            ),
        ];
        for (what, outputs, kind) in cases {
            let parse = |ty: Option<&str>| {
                let mut spec = vec![
                    ("context", label("age")),
                    ("outputs", FfiValue::Array(outputs())),
                ];
                spec.extend(ty.map(|ty| ("type", s(ty))));
                plan(obj(vec![("age", obj(spec))]))
            };
            let refused = parse(None);
            assert!(
                matches!(&refused, Err(Error::UntypedIndex { field }) if field == "age"),
                "{what} with no type: {refused:?}"
            );
            assert!(
                parse(Some(kind)).is_ok(),
                "{what} typed {kind} is the same spec, accepted"
            );
        }
        // By hand alike: the rule is the plan's, not the parser's.
        let field = FieldPlan::new(
            "age",
            context(label("age")).expect("context"),
            vec![Output::Ciphertext, Output::Term(IndexSpec::Equality)],
        )
        .expect("a field plan");
        assert!(
            matches!(Plan::new(vec![field.clone()]), Err(Error::UntypedIndex { field }) if field == "age"),
            "an indexed field plan with no type does not make a plan"
        );
        let typed_field = field.with_type(ValueKind::UInt32).expect("admits equality");
        assert!(Plan::new(vec![typed_field]).is_ok());

        let untyped = plan(obj(vec![
            ("notes", spec(label("notes"), &["c"])),
            ("id", spec(label("id"), &["passthrough"])),
        ]))
        .expect("a sealed-only and a passthrough field need no type");
        let sealed = seal(
            &keyset,
            obj(vec![("notes", s("hi")), ("id", FfiValue::UInt64(7))]),
            &untyped,
        )
        .await;
        let opened = object(open(&cipher, sealed, &untyped).await);
        assert_eq!(text_of(&opened[0].1), "hi");
        assert_eq!(u64_of(&opened[1].1), 7);
        assert_eq!(
            generates(&cipher),
            1,
            "one key request, for the one sealed field"
        );
    }

    mod given_a_source_that_does_not_fit_the_plan {
        use super::*;

        /// `check_source` is the conversion `encrypt` runs, so a binding's
        /// boundary rejection and the operation's are the same error — and
        /// neither costs a key request.
        #[tokio::test]
        async fn encrypt_and_check_source_refuse_it_alike_with_no_key_request() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();
            let mut with_passthrough_in_a_list = object(row(1));
            with_passthrough_in_a_list[1].1 =
                FfiValue::Array(vec![s("a@x"), FfiValue::Passthrough(Box::new(s("b@x")))]);
            let cases: Vec<Refused> = vec![
                ("a source that is not an object", FfiValue::UInt32(1), |e| {
                    matches!(e, Error::Source { .. })
                }),
                (
                    "a batch with an item that is not an object",
                    FfiValue::Array(vec![row(1), FfiValue::UInt32(2)]),
                    |e| matches!(e, Error::Source { .. }),
                ),
                (
                    "a row missing a plan field",
                    obj(vec![
                        ("age", FfiValue::UInt32(1)),
                        ("email", s("a@x")),
                        ("nick", s("al")),
                    ]),
                    |e| matches!(e, Error::Source { .. }),
                ),
                (
                    "a row with a field the plan does not name",
                    {
                        let mut entries = object(row(1));
                        entries.push(("extra".to_string(), s("x")));
                        FfiValue::Object(entries)
                    },
                    |e| matches!(e, Error::Source { .. }),
                ),
                (
                    "a row with a field the plan does not name in place of one it does",
                    {
                        let mut entries = object(row(1));
                        entries[3].0 = "extra".to_string();
                        FfiValue::Object(entries)
                    },
                    |e| matches!(e, Error::Source { .. }),
                ),
                (
                    "a passthrough under a sealed field",
                    {
                        let mut entries = object(row(1));
                        entries[1].1 = FfiValue::Passthrough(Box::new(s("a@x")));
                        FfiValue::Object(entries)
                    },
                    |e| matches!(e, Error::Source { .. }),
                ),
                (
                    "a passthrough inside a list under a sealed field",
                    FfiValue::Object(with_passthrough_in_a_list),
                    |e| matches!(e, Error::Source { .. }),
                ),
                (
                    "a plan field given twice",
                    {
                        let mut entries = object(row(1));
                        let _ = take(&mut entries, "nick");
                        entries.push(("age".to_string(), FfiValue::UInt32(2)));
                        FfiValue::Object(entries)
                    },
                    |e| matches!(e, Error::Source { .. }),
                ),
                (
                    "a repeated key inside an object under a sealed field",
                    {
                        let mut entries = object(row(1));
                        entries[1].1 = obj(vec![("k", s("a@x")), ("k", s("b@x"))]);
                        FfiValue::Object(entries)
                    },
                    |e| matches!(e, Error::Source { .. }),
                ),
                (
                    "a container under an indexed field, which declares a scalar kind",
                    {
                        let mut entries = object(row(1));
                        entries[2].1 = FfiValue::Array(vec![s("al")]);
                        FfiValue::Object(entries)
                    },
                    |e| matches!(e, Error::Source { .. }),
                ),
                (
                    "a scalar of another kind under an indexed field",
                    {
                        let mut entries = object(row(1));
                        entries[2].1 = FfiValue::UInt32(3);
                        FfiValue::Object(entries)
                    },
                    |e| matches!(e, Error::Source { .. }),
                ),
            ];
            for (label_, source, expected) in cases {
                let err = check_source(source, &plan).err();
                assert!(
                    err.as_ref().is_some_and(expected),
                    "{label_}: check_source must refuse it as the right error: {err:?}"
                );
            }
            let missing = obj(vec![
                ("age", FfiValue::UInt32(1)),
                ("email", s("a@x")),
                ("nick", s("al")),
            ]);
            let err = encrypt(&keyset, missing, &plan).err();
            assert!(
                matches!(err, Some(Error::Source { .. })),
                "encrypt refuses a row missing a plan field: {err:?}"
            );
            let mut entries = object(row(1));
            entries[1].1 = FfiValue::Passthrough(Box::new(s("a@x")));
            let err = encrypt(&keyset, FfiValue::Object(entries), &plan).err();
            assert!(
                matches!(err, Some(Error::Source { .. })),
                "encrypt refuses a passthrough under a sealed field: {err:?}"
            );
            let mut entries = object(row(1));
            entries[2].1 = FfiValue::UInt32(3);
            let err = encrypt(&keyset, FfiValue::Object(entries), &plan).err();
            assert!(
                matches!(err, Some(Error::Source { .. })),
                "encrypt refuses a value of another kind than the indexed field declares: {err:?}"
            );
            assert_eq!(
                generates(&cipher),
                0,
                "a refused source costs no key request"
            );
        }

        /// A float cannot reach an equality index through a plan: a field
        /// declared `float64` is refused when the plan is built, and a field
        /// declared an integer refuses the float value as the wrong kind,
        /// before any key request. There is no untyped indexed field for a
        /// float to slip through.
        #[tokio::test]
        async fn a_float_asked_for_equality_is_refused_at_build_or_as_the_wrong_kind() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let as_float = plan(obj(vec![(
                "score",
                typed(label("score"), &["c", "eq"], "float64"),
            )]));
            assert!(
                matches!(as_float, Err(Error::Plan { .. })),
                "no PRF encoding exists for a float: {as_float:?}"
            );
            let as_u32 = plan(obj(vec![(
                "score",
                typed(label("score"), &["c", "eq"], "uint32"),
            )]))
            .expect("plan");
            let source = obj(vec![("score", FfiValue::Float64(1.5))]);
            let err = encrypt(&keyset, source, &as_u32).err();
            assert!(
                matches!(err, Some(Error::Source { .. })),
                "a float is not the declared kind: {err:?}"
            );
            assert_eq!(generates(&cipher), 0, "refused before any key request");
        }
    }

    mod given_one_record {
        use super::*;

        #[tokio::test]
        async fn seals_it_from_one_key_request_in_the_stored_shape() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();

            let pending = encrypt(&keyset, row(34), &plan).expect("fits");
            assert_eq!(
                generates(&cipher),
                0,
                "nothing is requested before the await"
            );
            let sealed = pending.await.expect("encrypt");
            assert_eq!(
                generates(&cipher),
                1,
                "every ciphertext leaf seals from one batched key request"
            );

            let mut fields = map(sealed);
            assert_eq!(
                keys(&fields),
                ["age", "email", "nick", "id"],
                "the result holds every plan field, in plan order"
            );
            let mut age = map(node(&mut fields, "age"));
            assert_eq!(
                keys(&age),
                ["c", "eq", "ore"],
                "a field's ciphertext rides first, then its terms in index order"
            );
            assert!(
                !matches!(node(&mut age, "c"), CipherText::Passthrough(_)),
                "the ciphertext is never a passthrough"
            );
            assert_eq!(
                term_bytes(&node(&mut age, "eq")).len(),
                32,
                "an equality term is the raw 32 PRF bytes"
            );
            let email = map(node(&mut fields, "email"));
            assert_eq!(
                keys(&email),
                ["c"],
                "a sealed-only field has just its ciphertext"
            );
            let nick = map(node(&mut fields, "nick"));
            assert_eq!(
                keys(&nick),
                ["match"],
                "an indexed-only field has just its term"
            );
            let mut id = map(node(&mut fields, "id"));
            assert_eq!(keys(&id), ["passthrough"]);
            let CipherText::Passthrough(payload) = node(&mut id, "passthrough") else {
                panic!("a passthrough field rides as a passthrough node");
            };
            assert_eq!(
                u64_of(payload.downcast_ref::<FfiValue>().expect("a value")),
                7,
                "carrying the value as it is"
            );
        }

        /// The terms a plan lists after the ciphertext ride in the order the
        /// plan named them, whichever order the spec spelled `"c"` in.
        #[tokio::test]
        async fn terms_ride_in_index_order_after_the_ciphertext() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = plan(obj(vec![(
                "age",
                typed(label("age"), &["ore", "c", "eq"], "uint32"),
            )]))
            .expect("plan");
            let sealed = seal(&keyset, obj(vec![("age", FfiValue::UInt32(1))]), &plan).await;
            let mut fields = map(sealed);
            let age = map(node(&mut fields, "age"));
            assert_eq!(keys(&age), ["c", "ore", "eq"]);
        }

        /// ADR-0004's property, pinned: the ciphertext opens under the plan
        /// label and under nothing else, and each term is the standalone
        /// derivation under that same label.
        #[tokio::test]
        async fn binds_the_ciphertext_and_every_term_under_the_one_field_label() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();
            let age_ctx = plan.fields()[0].context().clone();
            let nick_ctx = plan.fields()[2].context().clone();

            let mut fields = map(seal(&keyset, row(34), &plan).await);
            let mut age = map(node(&mut fields, "age"));
            let mut nick = map(node(&mut fields, "nick"));

            let opened: FfiValue = cipher
                .decrypt(node(&mut age, "c"), age_ctx.clone())
                .await
                .expect("the ciphertext opens under the field's label");
            assert_eq!(u32_of(&opened), 34, "and to the value that was sealed");
            let mut again = map(seal(&keyset, row(34), &plan).await);
            let mut again_age = map(node(&mut again, "age"));
            let under_label: FfiValue = cipher
                .decrypt(
                    node(&mut again_age, "c"),
                    Label::parse("users/age").expect("label"),
                )
                .await
                .expect("the field's context is the typed label");
            assert_eq!(u32_of(&under_label), 34);

            let mut email = map(node(&mut fields, "email"));
            let wrong: Result<FfiValue, _> =
                cipher.decrypt(node(&mut email, "c"), age_ctx.clone()).await;
            assert!(
                wrong.is_err(),
                "a field's ciphertext does not open under another field's context"
            );

            let eq = term(
                &keyset,
                Scalar::U32(34),
                &IndexSpec::Equality,
                age_ctx.clone(),
            )
            .await
            .expect("standalone equality term");
            assert_eq!(
                term_bytes(&node(&mut age, "eq")),
                eq,
                "the equality term is the standalone derivation under the field label"
            );
            let ore = term(&keyset, Scalar::U32(34), &IndexSpec::Ore, age_ctx)
                .await
                .expect("standalone ore term");
            assert_eq!(
                term_bytes(&node(&mut age, "ore")),
                ore,
                "the ore term is the standalone derivation under the field label"
            );
            let scalar = Scalar::of(
                &s("al smith"),
                &IndexSpec::Match(crate::sem::MatchOptions::default()),
            )
            .expect("text");
            let matched = term(
                &keyset,
                scalar,
                &IndexSpec::Match(crate::sem::MatchOptions::default()),
                nick_ctx,
            )
            .await
            .expect("standalone match term");
            assert_eq!(
                term_bytes(&node(&mut nick, "match")),
                matched,
                "the match term is the standalone derivation under the field label"
            );
        }

        /// A plan's match options reach the term: the stored `"match"`
        /// term is the derivation under those options, not the defaults.
        #[tokio::test]
        async fn a_match_term_derives_under_the_plan_options() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let options = crate::sem::MatchOptions {
                k: 6,
                m: 1024,
                ..crate::sem::MatchOptions::default()
            };
            let plan = plan(obj(vec![(
                "nick",
                obj(vec![
                    ("context", label("nick")),
                    (
                        "outputs",
                        FfiValue::Array(vec![IndexSpec::Match(options.clone()).to_value()]),
                    ),
                    ("type", s("string")),
                ]),
            )]))
            .expect("parses");
            let ctx = plan.fields()[0].context().clone();
            let row = obj(vec![("nick", s("al smith"))]);
            let mut fields = map(seal(&keyset, row, &plan).await);
            let mut nick = map(node(&mut fields, "nick"));
            let stored = term_bytes(&node(&mut nick, "match"));

            let kind = IndexSpec::Match(options);
            let scalar = Scalar::of(&s("al smith"), &kind).expect("text");
            let expected = term(&keyset, scalar.clone(), &kind, ctx.clone())
                .await
                .expect("standalone");
            assert_eq!(stored, expected, "the term is the plan options' derivation");
            let default = IndexSpec::Match(crate::sem::MatchOptions::default());
            let under_default = term(&keyset, scalar, &default, ctx).await.expect("default");
            assert_ne!(stored, under_default, "and not the defaults'");
        }

        #[tokio::test]
        async fn opens_back_to_the_fields_that_come_back_in_plan_order() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();
            let sealed = seal(&keyset, row(34), &plan).await;

            let pending = decrypt(Scope::Client(&cipher), sealed, &plan, None).expect("fits");
            assert_eq!(
                retrieves(&cipher),
                0,
                "nothing is retrieved before the await"
            );
            let opened = pending.await.expect("decrypt");
            assert_eq!(
                retrieves(&cipher),
                1,
                "every ciphertext leaf opens from one batched key request"
            );
            let fields = object(opened);
            assert_eq!(
                keys(&fields),
                ["age", "email", "id"],
                "sealed and passthrough fields come back, in plan order; terms are one-way"
            );
            assert_eq!(u32_of(&fields[0].1), 34, "the age round-trips");
            assert_eq!(text_of(&fields[1].1), "a@x", "the email round-trips");
            assert_eq!(u64_of(&fields[2].1), 7, "the passthrough round-trips");

            // Through the keyset it was sealed under, too.
            let sealed = seal(&keyset, row(35), &plan).await;
            let fields = object(
                decrypt(Scope::Keyset(keyset.clone()), sealed, &plan, None)
                    .expect("fits")
                    .await
                    .expect("decrypt through the keyset"),
            );
            assert_eq!(
                u32_of(&fields[0].1),
                35,
                "the age round-trips through its keyset"
            );
        }

        /// A sealed field can hold a whole object. The walk refuses a key
        /// given *twice*; an object whose keys are all distinct is
        /// well-formed on both sides of the round trip.
        #[tokio::test]
        async fn a_nested_object_with_distinct_keys_round_trips() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();
            let source = || {
                let mut entries = object(row(34));
                entries[1].1 = obj(vec![("home", s("a@x")), ("work", s("b@x"))]);
                FfiValue::Object(entries)
            };

            check_source(source(), &plan).expect("check_source accepts it");
            let sealed = seal(&keyset, source(), &plan).await;
            check_record(sealed, &plan, None).expect("check_record accepts it");

            let sealed = seal(&keyset, source(), &plan).await;
            let fields = object(open(&cipher, sealed, &plan).await);
            let email = object(fields.into_iter().nth(1).expect("the email field").1);
            assert_eq!(keys(&email), ["home", "work"]);
            assert_eq!(text_of(&email[0].1), "a@x");
            assert_eq!(text_of(&email[1].1), "b@x");
        }

        /// The lowering is the plan builder: the record a data plan seals is
        /// the record the chain seals under the same declaration over the
        /// same plaintext type, a [`Value`] per field — the same terms, and
        /// ciphertexts each side opens.
        #[tokio::test]
        async fn seals_what_the_chain_seals_under_the_same_declaration() {
            struct User {
                age: Value,
                email: Value,
                nick: Value,
                id: u64,
            }
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let user = User {
                age: Value::new(FfiValue::UInt32(34)),
                email: Value::new(s("a@x")),
                nick: Value::new(s("al smith")),
                id: 7,
            };
            let default_match = IndexSpec::Match(crate::sem::MatchOptions::default());
            let mut chain = cipher
                .encrypt(&user)
                .context("users")
                .fields()
                .encrypt_index(
                    pick("age", |u: &User| &u.age),
                    (IndexSpec::Equality, IndexSpec::Ore),
                )
                .encrypt(pick("email", |u: &User| &u.email))
                .index(pick("nick", |u: &User| &u.nick), default_match)
                .passthrough(pick("id", |u: &User| &u.id))
                .await
                .expect("the chain");
            let plan = plan(obj(vec![
                (
                    "age",
                    typed_spec(label("age"), &["c", "eq", "ore"], "uint32"),
                ),
                ("email", typed_spec(label("email"), &["c"], "string")),
                ("nick", typed_spec(label("nick"), &["match"], "string")),
                ("id", spec(label("id"), &["passthrough"])),
            ]))
            .expect("plan");
            let mut fields = map(seal(&keyset, row(34), &plan).await);

            let age: Encrypted<(TermBytes, TermBytes)> = chain.take("age").expect("age");
            let mut lowered_age = map(node(&mut fields, "age"));
            assert_eq!(
                term_bytes(&node(&mut lowered_age, "eq")),
                age.terms.0.as_bytes(),
                "the same equality term"
            );
            assert_eq!(
                term_bytes(&node(&mut lowered_age, "ore")),
                age.terms.1.as_bytes(),
                "the same ore term"
            );
            let nick: TermBytes = chain.take("nick").expect("nick");
            let mut lowered_nick = map(node(&mut fields, "nick"));
            assert_eq!(
                term_bytes(&node(&mut lowered_nick, "match")),
                nick.as_bytes(),
                "the same match terms"
            );

            // Each side's ciphertext opens through the other.
            let chain_opened: FfiValue = cipher
                .decrypt(
                    node(&mut lowered_age, "c"),
                    Label::parse("users/age").expect("label"),
                )
                .await
                .expect("the chain's reader opens the lowering's leaf");
            assert_eq!(u32_of(&chain_opened), 34);
            let email: StackCipherText = chain.take("email").expect("email");
            let stored = CipherText::Map(vec![
                (
                    "age".to_string(),
                    CipherText::Map(vec![("c".to_string(), age.ciphertext)]),
                ),
                (
                    "email".to_string(),
                    CipherText::Map(vec![("c".to_string(), email)]),
                ),
                (
                    "id".to_string(),
                    CipherText::Map(vec![(
                        "passthrough".to_string(),
                        forged(FfiValue::UInt64(7)),
                    )]),
                ),
            ]);
            let opened = object(open(&cipher, stored, &plan).await);
            assert_eq!(keys(&opened), ["age", "email", "id"]);
            assert_eq!(
                u32_of(&opened[0].1),
                34,
                "the lowering opens the chain's leaf"
            );
            assert_eq!(text_of(&opened[1].1), "a@x", "and its string");
            assert_eq!(u64_of(&opened[2].1), 7);
        }
    }

    fn typed_spec(context: FfiValue, outputs: &[&str], ty: &str) -> FfiValue {
        typed(context, outputs, ty)
    }

    mod given_an_extended_context {
        use super::*;

        fn extended(field: &str, parts: &[FfiValue]) -> FfiValue {
            parts.iter().fold(label(field), |context, part| {
                FfiValue::Array(vec![context, duplicate_scalar(part)])
            })
        }

        fn duplicate_scalar(part: &FfiValue) -> FfiValue {
            match part {
                FfiValue::UInt64(v) => FfiValue::UInt64(*v),
                FfiValue::String(t) => {
                    FfiValue::String(std::str::from_utf8(t.risky_ref()).expect("utf8").into())
                }
                _ => panic!("a scalar part"),
            }
        }

        /// A field's extension lowers to the chain's `.extend(..)`: the
        /// record is the typed chain's under the same extension, and the
        /// stored terms are the probes under the extended context, not the
        /// flat one.
        #[tokio::test]
        async fn a_one_part_extension_is_the_chains_extend() {
            struct Age {
                age: u32,
            }
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let parts = [FfiValue::UInt64(7)];
            let plan = plan(obj(vec![(
                "age",
                typed(extended("age", &parts), &["c", "eq"], "uint32"),
            )]))
            .expect("plan");
            assert_eq!(plan.extension().len(), 1);
            let mut fields =
                map(seal(&keyset, obj(vec![("age", FfiValue::UInt32(34))]), &plan).await);
            let mut age = map(node(&mut fields, "age"));

            let mut typed_record = cipher
                .encrypt(&Age { age: 34 })
                .context("users")
                .fields()
                .encrypt_index(pick("age", |a: &Age| &a.age), Equality)
                .extend(7u64)
                .await
                .expect("typed chain");
            let typed_age: Encrypted<EqualityTerm> = typed_record.take("age").expect("age");
            let stored = term_bytes(&node(&mut age, "eq"));
            assert_eq!(
                stored,
                typed_age.terms.to_bytes(),
                "the same term as the chain extended by the same part"
            );
            let native = nonempty!("users").with("age").with(7u64);
            let probe = keyset.equality_term(34u32, native).await.expect("probe");
            assert_eq!(stored, probe.to_bytes());
            let flat = keyset
                .equality_term(34u32, nonempty!("users").with("age"))
                .await
                .expect("probe");
            assert_ne!(
                stored,
                flat.to_bytes(),
                "the extension domain-separates from the flat label"
            );
            let opened: FfiValue = cipher
                .decrypt(node(&mut age, "c"), native)
                .await
                .expect("the leaf opens under the extended context");
            assert_eq!(u32_of(&opened), 34);
        }

        /// Several parts nest to the left, one at a time, as a binding
        /// extends them and as `NonEmpty::with` nests: `((label)/7)/eu`,
        /// never `(label)/(7/eu)`.
        #[tokio::test]
        async fn several_parts_nest_to_the_left() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let parts = [FfiValue::UInt64(7), s("eu")];
            let plan = plan(obj(vec![(
                "age",
                typed(extended("age", &parts), &["c", "eq"], "uint32"),
            )]))
            .expect("plan");
            assert_eq!(plan.extension().len(), 2);
            let mut fields =
                map(seal(&keyset, obj(vec![("age", FfiValue::UInt32(34))]), &plan).await);
            let mut age = map(node(&mut fields, "age"));
            let stored = term_bytes(&node(&mut age, "eq"));

            let nested = nonempty!("users").with("age").with(7u64).with("eu");
            let probe = keyset.equality_term(34u32, nested).await.expect("probe");
            assert_eq!(stored, probe.to_bytes(), "left-nested, part by part");
            let one_piece = nonempty!("users")
                .with("age")
                .with(NonEmpty::from(7u64).with("eu"));
            let probe = keyset.equality_term(34u32, one_piece).await.expect("probe");
            assert_ne!(stored, probe.to_bytes(), "not one two-part piece");

            let opened: FfiValue = cipher
                .decrypt(node(&mut age, "c"), nested)
                .await
                .expect("opens under the nested context");
            assert_eq!(u32_of(&opened), 34);

            // And the record opens through the plan, which carries the parts.
            let sealed = seal(&keyset, obj(vec![("age", FfiValue::UInt32(35))]), &plan).await;
            let opened = object(open(&cipher, sealed, &plan).await);
            assert_eq!(u32_of(&opened[0].1), 35);
        }

        /// `DeclaredContext::with` is what the lowering builds: one part is
        /// the context a `NonEmpty` extension always gave, and each further
        /// part nests to the left.
        #[test]
        fn declared_context_with_nests_like_nonempty_with() {
            use crate::IntoAad;
            let own = || nonempty!("users").with("age");
            let one = DeclaredContext::from(7u64).under(own());
            let with = DeclaredContext::default()
                .with(CallerContext::from(7u64))
                .under(own());
            assert_eq!(
                one.clone().into_aad().as_bytes(),
                with.into_aad().as_bytes(),
                "one part: `with` is `From<NonEmpty>`"
            );
            assert_eq!(
                one.into_aad().as_bytes(),
                own().with(7u64).into_aad().as_bytes()
            );
            let two = DeclaredContext::default()
                .with(CallerContext::from(7u64))
                .with(CallerContext::from(nonempty!("eu")))
                .under(own());
            assert_eq!(
                two.into_aad().as_bytes(),
                own().with(7u64).with("eu").into_aad().as_bytes(),
                "two parts nest to the left"
            );
            let none = DeclaredContext::default().under(own());
            assert_eq!(none.into_aad().as_bytes(), own().into_aad().as_bytes());
        }
    }

    mod given_a_batch {
        use super::*;

        #[tokio::test]
        async fn seals_every_row_from_one_key_request_and_opens_as_an_array() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();

            let sealed = seal(
                &keyset,
                FfiValue::Array(vec![row(1), row(2), row(3)]),
                &plan,
            )
            .await;
            assert_eq!(generates(&cipher), 1, "one key request for the whole batch");

            let rows = sequence(sealed);
            assert_eq!(rows.len(), 3, "a batch seals to a sequence of rows");
            let opened = open(&cipher, CipherText::Sequence(rows), &plan).await;
            assert_eq!(
                retrieves(&cipher),
                1,
                "one key request to open the whole batch"
            );
            let rows = array(opened);
            assert_eq!(
                rows.into_iter()
                    .map(|row| u32_of(&object(row)[0].1))
                    .collect::<Vec<_>>(),
                [1, 2, 3],
                "rows open in the order they were sealed"
            );
        }

        #[tokio::test]
        async fn an_empty_batch_is_an_empty_batch() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();
            let sealed = seal(&keyset, FfiValue::Array(vec![]), &plan).await;
            assert!(
                matches!(&sealed, CipherText::Sequence(rows) if rows.is_empty()),
                "an empty batch seals to an empty sequence"
            );
            let opened = open(&cipher, sealed, &plan).await;
            assert!(
                array(opened).is_empty(),
                "an empty sequence opens to an empty array"
            );
            assert_eq!(
                (generates(&cipher), retrieves(&cipher)),
                (0, 0),
                "nothing to seal or open costs no key request"
            );
        }
    }

    mod given_a_stored_record_that_does_not_fit_the_plan {
        use super::*;

        async fn sealed(keyset: &KeysetCipher<'_, Counting>) -> Vec<(String, StackCipherText)> {
            map(seal(keyset, row(34), &the_plan()).await)
        }

        /// The forged-plaintext case the module docs call load-bearing is
        /// in here: a passthrough under `"c"` must be refused, because
        /// opening it would hand its payload back as if opened.
        #[tokio::test]
        async fn decrypt_and_check_record_refuse_it_before_any_key_is_retrieved() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();

            let mut cases: Vec<(&str, StackCipherText)> = Vec::new();

            let mut fields = sealed(&keyset).await;
            let mut age = map(node(&mut fields, "age"));
            cases.push(("a record that is not a map", node(&mut age, "c")));

            let mut fields = sealed(&keyset).await;
            let mut age = map(node(&mut fields, "age"));
            cases.push((
                "a batch with a row that is not a map",
                CipherText::Sequence(vec![node(&mut age, "c")]),
            ));

            let mut fields = sealed(&keyset).await;
            let _ = node(&mut fields, "email");
            cases.push(("a record missing a sealed field", CipherText::Map(fields)));

            let mut fields = sealed(&keyset).await;
            let _ = node(&mut fields, "id");
            cases.push((
                "a record missing a passthrough field",
                CipherText::Map(fields),
            ));

            let mut fields = sealed(&keyset).await;
            let mut age = map(node(&mut fields, "age"));
            fields.push(("age".to_string(), node(&mut age, "c")));
            cases.push((
                "a sealed field that is not an output map",
                CipherText::Map(fields),
            ));

            let mut fields = sealed(&keyset).await;
            let mut age = map(node(&mut fields, "age"));
            let _ = node(&mut age, "c");
            fields.push(("age".to_string(), CipherText::Map(age)));
            cases.push((
                "a sealed field with no ciphertext output",
                CipherText::Map(fields),
            ));

            let mut fields = sealed(&keyset).await;
            let mut age = map(node(&mut fields, "age"));
            let _ = node(&mut age, "c");
            age.push(("c".to_string(), forged(FfiValue::UInt32(99))));
            fields.push(("age".to_string(), CipherText::Map(age)));
            cases.push((
                "a passthrough where the ciphertext should be",
                CipherText::Map(fields),
            ));

            let mut fields = sealed(&keyset).await;
            let mut age = map(node(&mut fields, "age"));
            let _ = node(&mut age, "c");
            age.push((
                "c".to_string(),
                CipherText::Map(vec![("v".to_string(), forged(FfiValue::UInt32(99)))]),
            ));
            fields.push(("age".to_string(), CipherText::Map(age)));
            cases.push((
                "a passthrough inside the ciphertext subtree",
                CipherText::Map(fields),
            ));

            let mut fields = sealed(&keyset).await;
            let mut id = map(node(&mut fields, "id"));
            let _ = node(&mut id, "passthrough");
            fields.push(("id".to_string(), CipherText::Map(id)));
            cases.push((
                "a passthrough field with no passthrough output",
                CipherText::Map(fields),
            ));

            let mut fields = sealed(&keyset).await;
            let mut id = map(node(&mut fields, "id"));
            let _ = node(&mut id, "passthrough");
            let mut stale = sealed(&keyset).await;
            let mut stale_age = map(node(&mut stale, "age"));
            id.push(("passthrough".to_string(), node(&mut stale_age, "c")));
            fields.push(("id".to_string(), CipherText::Map(id)));
            cases.push((
                "a passthrough field carrying a ciphertext",
                CipherText::Map(fields),
            ));

            // The three shapes where a first-match take would have picked
            // one of two valid ciphertexts: a second, stale-but-valid copy
            // of a field, of its `"c"` output, or of a key inside it.
            let mut fields = sealed(&keyset).await;
            let mut stale = sealed(&keyset).await;
            fields.push(("age".to_string(), node(&mut stale, "age")));
            cases.push(("a sealed field given twice", CipherText::Map(fields)));

            let mut fields = sealed(&keyset).await;
            let mut stale = sealed(&keyset).await;
            let mut age = map(node(&mut fields, "age"));
            let mut stale_age = map(node(&mut stale, "age"));
            age.push(("c".to_string(), node(&mut stale_age, "c")));
            fields.push(("age".to_string(), CipherText::Map(age)));
            cases.push(("a ciphertext output given twice", CipherText::Map(fields)));

            let mut fields = sealed(&keyset).await;
            let mut stale = sealed(&keyset).await;
            let mut age = map(node(&mut fields, "age"));
            let mut stale_age = map(node(&mut stale, "age"));
            let (current, older) = (node(&mut age, "c"), node(&mut stale_age, "c"));
            age.push((
                "c".to_string(),
                CipherText::Map(vec![("v".to_string(), current), ("v".to_string(), older)]),
            ));
            fields.push(("age".to_string(), CipherText::Map(age)));
            cases.push((
                "a repeated key inside the ciphertext subtree",
                CipherText::Map(fields),
            ));

            let before = retrieves(&cipher);
            for (label_, record) in cases {
                let err = decrypt(Scope::Client(&cipher), record, &plan, None).err();
                assert!(
                    matches!(err, Some(Error::Record { .. })),
                    "{label_}: decrypt must refuse it as a misfit record: {err:?}"
                );
            }
            assert_eq!(
                retrieves(&cipher),
                before,
                "a misfit record is refused before any key is retrieved"
            );

            // And the boundary parser agrees, on the load-bearing shape.
            let mut fields = sealed(&keyset).await;
            let mut age = map(node(&mut fields, "age"));
            let _ = node(&mut age, "c");
            age.push(("c".to_string(), forged(FfiValue::UInt32(99))));
            fields.push(("age".to_string(), CipherText::Map(age)));
            let err = check_record(CipherText::Map(fields), &plan, None).err();
            assert!(
                matches!(err, Some(Error::Record { .. })),
                "check_record refuses a forged ciphertext the same way: {err:?}"
            );
            let mut fields = sealed(&keyset).await;
            let mut stale = sealed(&keyset).await;
            let mut age = map(node(&mut fields, "age"));
            let mut stale_age = map(node(&mut stale, "age"));
            age.push(("c".to_string(), node(&mut stale_age, "c")));
            fields.push(("age".to_string(), CipherText::Map(age)));
            let err = check_record(CipherText::Map(fields), &plan, None).err();
            assert!(
                matches!(err, Some(Error::Record { .. })),
                "check_record refuses a twice-given ciphertext the same way: {err:?}"
            );
        }

        #[tokio::test]
        async fn ignores_terms_and_entries_the_plan_does_not_open() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();

            let mut fields = sealed(&keyset).await;
            // The indexed-only field can be absent, a term can be anything,
            // and an entry the plan does not name is not looked at.
            let _ = node(&mut fields, "nick");
            let mut age = map(node(&mut fields, "age"));
            let _ = node(&mut age, "eq");
            age.push(("eq".to_string(), forged(s("not a term"))));
            age.push(("zzz".to_string(), forged(s("not an output"))));
            fields.push(("age".to_string(), CipherText::Map(age)));
            fields.push(("extra".to_string(), forged(s("not a field"))));

            let opened = object(open(&cipher, CipherText::Map(fields), &plan).await);
            assert_eq!(
                keys(&opened),
                ["age", "email", "id"],
                "the fields that come back open"
            );
            assert_eq!(u32_of(&opened[0].1), 34, "to what was sealed");
        }
    }

    mod given_a_context_field {
        use super::*;

        /// A one-segment label: the field's identity alone, which is what a
        /// field's context is under a context field.
        fn identity(field: &str) -> FfiValue {
            strings(&[field])
        }

        /// The plan most of these tests share: the record's `tenant` field is
        /// its context, `age` is sealed and indexed for equality under
        /// `<tenant>/age`, and `id` is carried through.
        fn plan_value() -> FfiValue {
            obj(vec![
                ("context_field", s("tenant")),
                (
                    "tenant",
                    typed(identity("tenant"), &["passthrough"], "string"),
                ),
                ("age", typed(identity("age"), &["c", "eq"], "uint32")),
                ("id", typed(identity("id"), &["passthrough"], "uint64")),
            ])
        }

        fn the_plan() -> Plan {
            plan(plan_value()).expect("the context-field plan parses")
        }

        fn row(tenant: &str, age: u32) -> FfiValue {
            obj(vec![
                ("tenant", s(tenant)),
                ("age", FfiValue::UInt32(age)),
                ("id", FfiValue::UInt64(7)),
            ])
        }

        fn expected(label: &str) -> Option<Label> {
            Some(Label::parse(label).expect("a label"))
        }

        /// The error a pending failed with. `FfiValue` has no `Debug`, so
        /// `expect_err` cannot be used on an opened value.
        fn refused<T>(result: Result<T, crate::Error>) -> crate::Error {
            match result {
                Err(error) => error,
                Ok(_) => panic!("the operation was not refused"),
            }
        }

        fn keys_of(plan: &Plan) -> Vec<&str> {
            plan.fields().iter().map(FieldPlan::name).collect()
        }

        struct Age {
            age: u32,
        }

        /// The equality term the typed chain stores for `age` under
        /// `<context>/age`, extended by `parts`: what the lowering must
        /// derive when the context comes from the record.
        async fn chain_term(
            cipher: &StackCipher<Counting>,
            context: &str,
            age: u32,
            parts: &[u64],
        ) -> Vec<u8> {
            let value = Age { age };
            let chain = cipher
                .encrypt(&value)
                .context(context)
                .fields()
                .encrypt_index(pick("age", |a: &Age| &a.age), Equality);
            let mut record = match parts {
                [] => chain.await,
                [part] => chain.extend(*part).await,
                _ => panic!("one part at most"),
            }
            .expect("typed chain");
            let typed: Encrypted<EqualityTerm> = record.take("age").expect("age");
            typed.terms.to_bytes()
        }

        /// The stored record with its context field replaced by `tenant`,
        /// as an attacker with write access to the row would leave it.
        fn with_stored_context(sealed: StackCipherText, tenant: &str) -> StackCipherText {
            let mut fields = map(sealed);
            let _ = take(&mut fields, "tenant").expect("the tenant node");
            fields.push((
                "tenant".to_string(),
                CipherText::Map(vec![("passthrough".to_string(), forged(s(tenant)))]),
            ));
            CipherText::Map(fields)
        }

        #[test]
        fn parses_as_the_builders_context_field() {
            let plan = the_plan();
            assert_eq!(plan.context_field(), Some("tenant"));
            assert_eq!(plan.label(), None, "the plan has no context of its own");
            assert_eq!(
                keys_of(&plan),
                ["tenant", "age", "id"],
                "the context field is a field"
            );
            let tenant = &plan.fields()[0];
            assert_eq!(tenant.outputs(), [Output::Passthrough]);
            assert_eq!(tenant.field_type(), Some(ValueKind::String));
            assert_eq!(
                tenant.label().to_string(),
                "tenant",
                "its label is its identity"
            );
            assert_eq!(plan.fields()[1].label().to_string(), "age");
        }

        /// The context field needs no `"type"`: it is a string either way.
        #[test]
        fn an_untyped_context_field_is_a_string() {
            let plan = plan(obj(vec![
                ("context_field", s("tenant")),
                ("tenant", spec(identity("tenant"), &["passthrough"])),
                ("age", spec(identity("age"), &["c"])),
            ]))
            .expect("parses");
            assert_eq!(plan.fields()[0].field_type(), Some(ValueKind::String));
        }

        #[test]
        fn refuses_what_the_builder_and_the_grammar_refuse() {
            let refused = [
                (
                    "a context field the plan does not name",
                    obj(vec![
                        ("context_field", s("tenant")),
                        ("age", typed(identity("age"), &["c"], "uint32")),
                    ]),
                ),
                (
                    "a context_field key that is not a string",
                    obj(vec![
                        ("context_field", FfiValue::UInt64(7)),
                        ("age", typed(identity("age"), &["c"], "uint32")),
                    ]),
                ),
                (
                    "a context_field key given twice",
                    obj(vec![
                        ("context_field", s("tenant")),
                        ("context_field", s("tenant")),
                        ("tenant", spec(identity("tenant"), &["passthrough"])),
                        ("age", typed(identity("age"), &["c"], "uint32")),
                    ]),
                ),
                (
                    "a field named context_field",
                    obj(vec![(
                        "context_field",
                        spec(label("context_field"), &["passthrough"]),
                    )]),
                ),
                (
                    "a context field that is sealed",
                    obj(vec![
                        ("context_field", s("tenant")),
                        ("tenant", typed(identity("tenant"), &["c"], "string")),
                        ("age", typed(identity("age"), &["c"], "uint32")),
                    ]),
                ),
                (
                    "a context field that is indexed",
                    obj(vec![
                        ("context_field", s("tenant")),
                        ("tenant", typed(identity("tenant"), &["eq"], "string")),
                        ("age", typed(identity("age"), &["c"], "uint32")),
                    ]),
                ),
                (
                    "a context field typed as something other than a string",
                    obj(vec![
                        ("context_field", s("tenant")),
                        (
                            "tenant",
                            typed(identity("tenant"), &["passthrough"], "int64"),
                        ),
                        ("age", typed(identity("age"), &["c"], "uint32")),
                    ]),
                ),
                (
                    "a field under a context of its own beside the context field",
                    obj(vec![
                        ("context_field", s("tenant")),
                        ("tenant", spec(identity("tenant"), &["passthrough"])),
                        ("age", typed(label("age"), &["c"], "uint32")),
                    ]),
                ),
                (
                    "the context field itself under a two-segment label",
                    obj(vec![
                        ("context_field", s("tenant")),
                        ("tenant", spec(label("tenant"), &["passthrough"])),
                        ("age", typed(identity("age"), &["c"], "uint32")),
                    ]),
                ),
            ];
            for (what, value) in refused {
                let result = plan(value);
                assert!(
                    matches!(result, Err(Error::Plan { .. })),
                    "{what}: {result:?}"
                );
            }
        }

        /// The manual constructor holds the same rules, so a plan in hand
        /// holds them whichever way it was built.
        #[test]
        fn the_manual_constructor_refuses_the_same() {
            let field = |name: &str, ctx: FfiValue, outputs: &[&str]| {
                FieldPlan::new(
                    name,
                    context(ctx).expect("context"),
                    outputs
                        .iter()
                        .map(|o| Output::parse(o).expect("output"))
                        .collect(),
                )
                .expect("field")
            };
            let tenant = || field("tenant", identity("tenant"), &["passthrough"]);
            let age = || field("age", identity("age"), &["c"]);
            assert!(Plan::with_context_field("tenant", vec![tenant(), age()]).is_ok());
            assert!(
                matches!(
                    Plan::with_context_field("nope", vec![tenant(), age()]),
                    Err(Error::Plan { .. })
                ),
                "a field the plan does not name"
            );
            assert!(
                matches!(
                    Plan::with_context_field("age", vec![tenant(), age()]),
                    Err(Error::Plan { .. })
                ),
                "a sealed field as the context"
            );
            assert!(
                matches!(Plan::new(vec![tenant(), age()]), Err(Error::Plan { .. })),
                "one-segment labels need a context field"
            );
        }

        /// A plan with a context field holds the type rule too: an untyped
        /// indexed field beside the context field is refused, parsed or
        /// built by hand, and the refusal names it.
        #[test]
        fn an_untyped_indexed_field_beside_the_context_field_is_refused() {
            let parsed = plan(obj(vec![
                ("context_field", s("tenant")),
                ("tenant", spec(identity("tenant"), &["passthrough"])),
                ("age", spec(identity("age"), &["c", "eq"])),
            ]));
            assert!(
                matches!(&parsed, Err(Error::UntypedIndex { field }) if field == "age"),
                "{parsed:?}"
            );

            let field = |name: &str, outputs: &[&str]| {
                FieldPlan::new(
                    name,
                    context(identity(name)).expect("context"),
                    outputs
                        .iter()
                        .map(|o| Output::parse(o).expect("output"))
                        .collect(),
                )
                .expect("field")
            };
            let built = Plan::with_context_field(
                "tenant",
                vec![
                    field("tenant", &["passthrough"]),
                    field("age", &["c", "eq"]),
                ],
            );
            assert!(
                matches!(&built, Err(Error::UntypedIndex { field }) if field == "age"),
                "{built:?}"
            );
        }

        /// Two tenants in one batch: each record is sealed under the context
        /// its own field names, in one key request, and each opens back
        /// under the context it stores.
        #[tokio::test]
        async fn each_record_in_a_batch_is_sealed_under_its_own_context() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();
            let batch = FfiValue::Array(vec![row("tenants/acme", 34), row("tenants/globex", 34)]);

            let sealed = seal(&keyset, batch, &plan).await;
            assert_eq!(generates(&cipher), 1, "one key request for both tenants");

            // The stored term is the one derived under <tenant>/age: the
            // context came from the record, not from the plan.
            let mut rows = sequence(sealed);
            let mut acme = map(rows.remove(0));
            let mut globex = map(rows.remove(0));
            let acme_term = term_bytes(&node(&mut map(node(&mut acme, "age")), "eq"));
            let globex_term = term_bytes(&node(&mut map(node(&mut globex, "age")), "eq"));
            assert_eq!(
                acme_term,
                chain_term(&cipher, "tenants/acme", 34, &[]).await,
                "the chain's term under tenants/acme"
            );
            assert_eq!(
                globex_term,
                chain_term(&cipher, "tenants/globex", 34, &[]).await,
                "the chain's term under tenants/globex"
            );
            assert_ne!(
                acme_term, globex_term,
                "the same age, two tenants, two terms"
            );

            // The context field rides as a passthrough, so the record stores
            // its own context.
            let mut tenant = map(node(&mut acme, "tenant"));
            let CipherText::Passthrough(payload) = node(&mut tenant, "passthrough") else {
                panic!("the context field rides as a passthrough");
            };
            let FfiValue::String(stored) = *payload.downcast::<FfiValue>().expect("a value") else {
                panic!("the stored context is text");
            };
            assert_eq!(utf8(&stored), Some("tenants/acme"));

            // Each opens under what it stores, with no context named.
            let sealed = seal(
                &keyset,
                FfiValue::Array(vec![row("tenants/acme", 34), row("tenants/globex", 35)]),
                &plan,
            )
            .await;
            let mut opened = array(open(&cipher, sealed, &plan).await);
            let globex = object(opened.remove(1));
            let acme = object(opened.remove(0));
            assert_eq!(
                text_of(&acme[0].1),
                "tenants/acme",
                "the context field comes back"
            );
            assert_eq!(u32_of(&acme[1].1), 34);
            assert_eq!(text_of(&globex[0].1), "tenants/globex");
            assert_eq!(u32_of(&globex[1].1), 35);
        }

        /// The caller's expected context is checked against each record's
        /// stored one before any key is requested: the chain's
        /// `open(record).context(expected)`.
        #[tokio::test]
        async fn an_expected_context_refuses_a_record_stored_under_another() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();
            let retrieved = retrieves(&cipher);

            let sealed = seal(&keyset, row("tenants/acme", 34), &plan).await;
            let refused = decrypt(
                Scope::Client(&cipher),
                sealed,
                &plan,
                expected("tenants/globex"),
            )
            .expect("the shape fits")
            .await;
            match refused {
                Err(crate::Error::ContextMismatch { stored }) => {
                    assert_eq!(stored.to_string(), "tenants/acme")
                }
                Err(other) => panic!("expected ContextMismatch, got {other:?}"),
                Ok(_) => panic!("a record stored under another context opened"),
            }
            assert_eq!(
                retrieves(&cipher),
                retrieved,
                "refused before any key is retrieved"
            );

            // The preflight says the same, as the error the pending would
            // fail with.
            let sealed = seal(&keyset, row("tenants/acme", 34), &plan).await;
            let preflight = check_record(sealed, &plan, expected("tenants/globex").as_ref());
            assert!(
                matches!(
                    preflight,
                    Err(Error::Cipher(crate::Error::ContextMismatch { .. }))
                ),
                "{preflight:?}"
            );
            let sealed = seal(&keyset, row("tenants/acme", 34), &plan).await;
            check_record(sealed, &plan, expected("tenants/acme").as_ref())
                .expect("the expected context");
            let sealed = seal(&keyset, row("tenants/acme", 34), &plan).await;
            check_record(sealed, &plan, None).expect("no expectation");

            let sealed = seal(&keyset, row("tenants/acme", 34), &plan).await;
            let opened = object(
                decrypt(
                    Scope::Client(&cipher),
                    sealed,
                    &plan,
                    expected("tenants/acme"),
                )
                .expect("fits")
                .await
                .expect("the expected context opens"),
            );
            assert_eq!(u32_of(&opened[1].1), 34);

            // One wrong record refuses the whole batch, before any key.
            let batch = seal(
                &keyset,
                FfiValue::Array(vec![row("tenants/acme", 1), row("tenants/globex", 2)]),
                &plan,
            )
            .await;
            let retrieved = retrieves(&cipher);
            let refused = decrypt(
                Scope::Client(&cipher),
                batch,
                &plan,
                expected("tenants/acme"),
            )
            .expect("fits")
            .await;
            assert!(matches!(refused, Err(crate::Error::ContextMismatch { .. })));
            assert_eq!(retrieves(&cipher), retrieved);
        }

        /// A stored context changed in storage opens nothing: every field was
        /// sealed under the original, so the key source (or the AEAD) refuses
        /// it even with no expectation.
        #[tokio::test]
        async fn a_context_changed_in_storage_opens_nothing() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();
            let sealed = seal(&keyset, row("tenants/acme", 34), &plan).await;
            let result = decrypt(
                Scope::Client(&cipher),
                with_stored_context(sealed, "tenants/globex"),
                &plan,
                None,
            )
            .expect("the shape fits")
            .await;
            assert!(result.is_err(), "sealed under acme, opened under globex");
        }

        /// The context field's value is read as a label when the plan runs:
        /// a value that is not text is refused by the field's type, and text
        /// that is not a plain label by the label rules, both before any
        /// key request.
        #[tokio::test]
        async fn a_context_value_that_is_not_a_label_is_refused_before_any_key() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();
            let not_text = || {
                obj(vec![
                    ("tenant", FfiValue::UInt64(7)),
                    ("age", FfiValue::UInt32(34)),
                    ("id", FfiValue::UInt64(7)),
                ])
            };
            assert!(matches!(
                check_source(not_text(), &plan),
                Err(Error::Source { .. })
            ));
            assert!(matches!(
                encrypt(&keyset, not_text(), &plan),
                Err(Error::Source { .. })
            ));

            let not_a_label = || row("tenants/(acme)", 34);
            assert!(matches!(
                check_source(not_a_label(), &plan),
                Err(Error::Source { .. })
            ));
            let failed = encrypt(&keyset, not_a_label(), &plan)
                .expect("the source fits the plan's shape")
                .await;
            assert!(
                matches!(plan_error(refused(failed)), PlanError::ContextLabel(_)),
                "the label rule, when the plan runs"
            );
            assert_eq!(generates(&cipher), 0, "nothing was requested");

            // Stored text that is not a label is refused the same way on
            // open.
            let sealed = seal(&keyset, row("tenants/acme", 34), &plan).await;
            assert!(matches!(
                check_record(with_stored_context(sealed, "tenants/(acme)"), &plan, None),
                Err(Error::Record { .. })
            ));
            let sealed = seal(&keyset, row("tenants/acme", 34), &plan).await;
            let retrieved = retrieves(&cipher);
            let failed = decrypt(
                Scope::Client(&cipher),
                with_stored_context(sealed, "tenants/(acme)"),
                &plan,
                None,
            )
            .expect("the shape fits")
            .await;
            assert!(matches!(
                plan_error(refused(failed)),
                PlanError::ContextLabel(_)
            ));
            assert_eq!(retrieves(&cipher), retrieved);
        }

        /// An expected context is for a plan that takes its context from a
        /// field. For one with a context of its own it is a second source,
        /// refused as the chain refuses it.
        #[tokio::test]
        async fn an_expected_context_on_a_plan_with_its_own_is_two_sources() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = super::the_plan();
            let sealed = seal(&keyset, super::row(34), &plan).await;
            assert!(matches!(
                check_record(sealed, &plan, expected("users").as_ref()),
                Err(Error::Record { .. })
            ));
            let sealed = seal(&keyset, super::row(34), &plan).await;
            let failed = decrypt(Scope::Client(&cipher), sealed, &plan, expected("users"))
                .expect("the shape fits")
                .await;
            assert!(matches!(
                plan_error(refused(failed)),
                PlanError::TwoContextSources { .. }
            ));
        }

        /// `.extend(..)` extends the context the field supplies, as it
        /// extends a plan's own: the term is the probe under
        /// `<tenant>/age` then the part.
        #[tokio::test]
        async fn an_extension_extends_the_fields_context() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let extended =
                |field: &str| FfiValue::Array(vec![identity(field), FfiValue::UInt64(7)]);
            let plan = plan(obj(vec![
                ("context_field", s("tenant")),
                (
                    "tenant",
                    typed(extended("tenant"), &["passthrough"], "string"),
                ),
                ("age", typed(extended("age"), &["c", "eq"], "uint32")),
            ]))
            .expect("parses");
            assert_eq!(plan.extension().len(), 1);
            let source = || {
                obj(vec![
                    ("tenant", s("tenants/acme")),
                    ("age", FfiValue::UInt32(34)),
                ])
            };
            let mut fields = map(seal(&keyset, source(), &plan).await);
            let stored = term_bytes(&node(&mut map(node(&mut fields, "age")), "eq"));
            assert_eq!(
                stored,
                chain_term(&cipher, "tenants/acme", 34, &[7]).await,
                "the chain's term under tenants/acme, extended by 7"
            );
            let sealed = seal(&keyset, source(), &plan).await;
            let opened = object(open(&cipher, sealed, &plan).await);
            assert_eq!(
                u32_of(&opened[1].1),
                34,
                "and it opens under the extended context"
            );
        }
    }

    mod given_a_keyset_scope {
        use super::*;

        fn named(name: &str) -> IdentifiedBy {
            IdentifiedBy::Name(name.to_string().into())
        }

        #[tokio::test]
        async fn refuses_a_leaf_from_another_keyset_before_any_key_is_retrieved() {
            let cipher = cipher().await;
            let acme = cipher.keyset(named("acme")).await.expect("acme");
            let globex = cipher.keyset(named("globex")).await.expect("globex");
            let plan = the_plan();

            let sealed = seal(&acme, row(34), &plan).await;
            let err = decrypt(Scope::Keyset(globex.clone()), sealed, &plan, None)
                .expect("the record fits")
                .await
                .err();
            assert!(
                matches!(
                    err,
                    Some(crate::Error::ForeignKeyset { expected, found })
                        if expected == globex.keyset_id() && found == acme.keyset_id()
                ),
                "another tenant's keyset refuses the leaf, naming both keysets: {err:?}"
            );
            assert_eq!(
                retrieves(&cipher),
                0,
                "refused before any key was retrieved"
            );

            let sealed = seal(&acme, row(34), &plan).await;
            let opened = object(
                decrypt(Scope::Keyset(acme.clone()), sealed, &plan, None)
                    .expect("fits")
                    .await
                    .expect("its own keyset opens it"),
            );
            assert_eq!(u32_of(&opened[0].1), 34, "to what was sealed");

            let sealed = seal(&acme, row(34), &plan).await;
            let opened = object(open(&cipher, sealed, &plan).await);
            assert_eq!(
                u32_of(&opened[0].1),
                34,
                "the client opens a leaf from any of its keysets"
            );
        }

        #[tokio::test]
        async fn debug_names_the_cipher_it_opens_through() {
            let cipher = cipher().await;
            assert!(
                format!("{:?}", Scope::Client(&cipher)).starts_with("Client("),
                "the client scope says so"
            );
            assert!(
                format!("{:?}", Scope::Keyset(cipher.default_keyset())).starts_with("Keyset("),
                "the keyset scope says so"
            );
        }
    }

    /// The typed helper the tests lean on, pinned in passing: a field's
    /// list context and the typed label agree, so a test written against
    /// either is the same test.
    #[test]
    fn the_field_context_is_the_typed_label() {
        use crate::IntoAad;
        assert_eq!(
            the_plan().fields()[0]
                .context()
                .clone()
                .into_inner()
                .into_aad()
                .as_bytes(),
            Label::parse("users/age")
                .expect("label")
                .into_aad()
                .as_bytes(),
            "a field's list context is the label"
        );
    }

    mod given_a_typed_field {
        use super::*;

        fn age_plan(ty: &str) -> Plan {
            plan(obj(vec![(
                "age",
                typed(label("age"), &["c", "eq", "ore"], ty),
            )]))
            .expect("a typed plan parses")
        }

        #[test]
        fn the_plan_parses_the_type_and_an_untyped_field_has_none() {
            let parsed = plan(obj(vec![
                ("age", typed(label("age"), &["c", "ore"], "uint64")),
                ("bio", typed(label("bio"), &["c", "match"], "string")),
                ("notes", spec(label("notes"), &["c"])),
            ]))
            .expect("parses");
            let types: Vec<_> = parsed.fields().iter().map(FieldPlan::field_type).collect();
            assert_eq!(
                types,
                [Some(ValueKind::UInt64), Some(ValueKind::String), None]
            );
        }

        /// The parser applies `"type"` after it has read every key, so a
        /// spec that declares its type before its outputs is checked the
        /// same way: admitted when the type admits the indexes, refused
        /// when it does not.
        #[test]
        fn the_plan_reads_a_type_given_before_the_outputs() {
            let early = |ty: &str| {
                obj(vec![
                    ("type", s(ty)),
                    ("outputs", strings(&["c", "eq"])),
                    ("context", label("age")),
                ])
            };
            let parsed = plan(obj(vec![("age", early("uint64"))])).expect("parses");
            assert_eq!(parsed.fields()[0].field_type(), Some(ValueKind::UInt64));
            assert_eq!(
                parsed.fields()[0].outputs(),
                [Output::Ciphertext, Output::Term(IndexSpec::Equality)]
            );
            let refused = plan(obj(vec![("age", early("float64"))]));
            assert!(
                matches!(refused, Err(Error::Plan { .. })),
                "equality on a float is refused whatever the key order: {refused:?}"
            );
        }

        #[test]
        fn the_plan_refuses_an_unresolvable_type_or_one_that_does_not_admit_an_index() {
            let refused: [(&str, FfiValue); 8] = [
                ("an unknown type", typed(label("x"), &["c"], "u64")),
                (
                    "a type in the wrong case",
                    typed(label("x"), &["c"], "UInt64"),
                ),
                (
                    "a type that is not a string",
                    obj(vec![
                        ("context", label("x")),
                        ("outputs", strings(&["c"])),
                        ("type", FfiValue::UInt32(6)),
                    ]),
                ),
                (
                    "a type given twice",
                    obj(vec![
                        ("context", label("x")),
                        ("outputs", strings(&["c"])),
                        ("type", s("string")),
                        ("type", s("string")),
                    ]),
                ),
                (
                    "match on an integer",
                    typed(label("x"), &["c", "match"], "int64"),
                ),
                (
                    "equality on a float",
                    typed(label("x"), &["c", "eq"], "float64"),
                ),
                ("equality on a bool", typed(label("x"), &["eq"], "bool")),
                (
                    "order on a composite",
                    typed(label("x"), &["c", "ore"], "object"),
                ),
            ];
            for (label_, field) in refused {
                let result = plan(obj(vec![("x", field)]));
                assert!(
                    matches!(result, Err(Error::Plan { .. })),
                    "{label_}: {result:?}"
                );
            }
        }

        #[test]
        fn a_hand_built_field_takes_a_type_its_indexes_admit_and_refuses_one_they_do_not() {
            let field = FieldPlan::new(
                "age",
                context(label("age")).expect("context"),
                vec![Output::Ciphertext, Output::Term(IndexSpec::Equality)],
            )
            .expect("field");
            assert_eq!(field.field_type(), None, "untyped until declared");
            let typed = field
                .clone()
                .with_type(ValueKind::UInt32)
                .expect("equality admits a u32");
            assert_eq!(typed.field_type(), Some(ValueKind::UInt32));
            assert!(matches!(
                field.with_type(ValueKind::Float32),
                Err(Error::Plan { .. })
            ));
            let sealed_only = FieldPlan::new(
                "doc",
                context(label("doc")).expect("context"),
                vec![Output::Ciphertext],
            )
            .expect("field")
            .with_type(ValueKind::Object)
            .expect("a composite with no index is a plain sealed field");
            assert_eq!(sealed_only.field_type(), Some(ValueKind::Object));
        }

        /// The engine verifies the tag rather than trusting the binding: a
        /// `u32` is not a `uint64`, however small. Refused before any key
        /// is minted, by `check_source` alike — and for the two kinds that
        /// lower to a Rust leaf type as well.
        #[tokio::test]
        async fn encrypt_refuses_a_value_of_another_type_with_no_key_request() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let u64_plan = age_plan("uint64");
            let check = check_source(obj(vec![("age", FfiValue::UInt32(34))]), &u64_plan);
            assert!(
                matches!(check, Err(Error::Source { .. })),
                "check_source refuses it too"
            );
            for (label_, value) in [
                ("a u32 for a uint64 field", FfiValue::UInt32(34)),
                ("a float for a uint64 field", FfiValue::Float64(34.0)),
                ("null for a uint64 field", FfiValue::Null),
            ] {
                let result = encrypt(&keyset, obj(vec![("age", value)]), &u64_plan).err();
                assert!(
                    matches!(result, Some(Error::Source { .. })),
                    "{label_}: {result:?}"
                );
            }
            let as_u32 = age_plan("uint32");
            let result = encrypt(&keyset, obj(vec![("age", FfiValue::UInt64(34))]), &as_u32).err();
            assert!(
                matches!(result, Some(Error::Source { .. })),
                "a u64 for a uint32 field: {result:?}"
            );
            let as_string =
                plan(obj(vec![("age", typed(label("age"), &["c"], "string"))])).expect("plan");
            let result = encrypt(
                &keyset,
                obj(vec![("age", FfiValue::UInt32(34))]),
                &as_string,
            )
            .err();
            assert!(
                matches!(result, Some(Error::Source { .. })),
                "a u32 for a string field: {result:?}"
            );
            assert_eq!(generates(&cipher), 0, "refused before any key request");
        }

        #[tokio::test]
        async fn a_value_of_the_type_round_trips_and_its_terms_are_the_typed_terms() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = age_plan("uint64");
            let sealed = seal(&keyset, obj(vec![("age", FfiValue::UInt64(34))]), &plan).await;
            let mut row = map(sealed);
            let mut age = map(node(&mut row, "age"));
            let eq = term_bytes(&node(&mut age, "eq"));
            let typed = keyset
                .equality_term(34u64, nonempty!("users").with("age"))
                .await
                .expect("typed");
            assert_eq!(eq, typed.into_bytes().to_vec(), "the u64 term");

            let sealed = seal(&keyset, obj(vec![("age", FfiValue::UInt64(34))]), &plan).await;
            let opened = open(&cipher, sealed, &plan).await;
            let fields = object(opened);
            assert!(matches!(&fields[..], [(name, FfiValue::UInt64(34))] if name == "age"));
        }

        /// A row sealed as one type and read under a plan declaring another
        /// is refused, not handed back as the wrong type. The tag is inside
        /// the AEAD envelope, so this is a plan disagreeing with its data,
        /// never tampering, and it is caught once the leaf is open — which
        /// is the pending's failure, not the preflight's.
        #[tokio::test]
        async fn decrypt_refuses_a_value_that_opens_to_another_type() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let untyped = plan(obj(vec![("age", spec(label("age"), &["c"]))])).expect("plan");
            let sealed = seal(&keyset, obj(vec![("age", FfiValue::UInt64(34))]), &untyped).await;
            let as_int64 =
                plan(obj(vec![("age", typed(label("age"), &["c"], "int64"))])).expect("plan");
            let result = decrypt(Scope::Client(&cipher), sealed, &as_int64, None)
                .expect("the shape fits")
                .await;
            assert_eq!(
                plan_error(result.err().expect("refused")),
                PlanError::FieldType {
                    field: "age".into(),
                    expected: "int64",
                }
            );

            let sealed = seal(&keyset, obj(vec![("age", FfiValue::UInt64(34))]), &untyped).await;
            let as_uint64 =
                plan(obj(vec![("age", typed(label("age"), &["c"], "uint64"))])).expect("plan");
            let opened = open(&cipher, sealed, &as_uint64).await;
            assert_eq!(u64_of(&object(opened)[0].1), 34, "the declared type opens");
        }

        /// One row stored as another kind fails the whole batch, as the
        /// CHANGELOG says. The other rows are not returned.
        #[tokio::test]
        async fn decrypt_fails_a_batch_when_one_row_opens_to_another_type() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let untyped = plan(obj(vec![("age", spec(label("age"), &["c"]))])).expect("plan");
            let rows = FfiValue::Array(vec![
                obj(vec![("age", FfiValue::UInt64(34))]),
                obj(vec![("age", FfiValue::Float64(34.0))]),
            ]);
            let sealed = seal(&keyset, rows, &untyped).await;
            let as_uint64 =
                plan(obj(vec![("age", typed(label("age"), &["c"], "uint64"))])).expect("plan");
            let result = decrypt(Scope::Client(&cipher), sealed, &as_uint64, None)
                .expect("the shape fits")
                .await;
            assert_eq!(
                plan_error(result.err().expect("the batch is refused")),
                PlanError::FieldType {
                    field: "age".into(),
                    expected: "uint64",
                }
            );
        }

        /// The migration path the CHANGELOG gives for rows stored as
        /// another kind: a plan that gives the field only `"c"` and no
        /// `"type"` opens a row of any kind, whatever indexes it was sealed
        /// with, and the value, converted to the declared kind, seals again
        /// under the typed plan and opens there.
        #[tokio::test]
        async fn a_ciphertext_only_untyped_plan_reads_rows_of_any_kind() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let as_uint32 = seal(
                &keyset,
                obj(vec![("age", FfiValue::UInt32(34))]),
                &age_plan("uint32"),
            )
            .await;
            let as_int64 = seal(
                &keyset,
                obj(vec![("age", FfiValue::Int64(34))]),
                &age_plan("int64"),
            )
            .await;
            let read = plan(obj(vec![("age", spec(label("age"), &["c"]))])).expect("plan");

            let opened = object(open(&cipher, as_uint32, &read).await);
            assert!(
                matches!(opened[0].1, FfiValue::UInt32(34)),
                "a uint32 row opens as one"
            );
            let opened = object(open(&cipher, as_int64, &read).await);
            let FfiValue::Int64(value) = opened[0].1 else {
                panic!("an int64 row opens as one")
            };

            let converted = u32::try_from(value).expect("fits");
            let resealed = seal(
                &keyset,
                obj(vec![("age", FfiValue::UInt32(converted))]),
                &age_plan("uint32"),
            )
            .await;
            let reopened = object(open(&cipher, resealed, &age_plan("uint32")).await);
            assert_eq!(u32_of(&reopened[0].1), 34);
        }

        /// In a batch, each opened value is checked against its own field,
        /// not the first field's.
        #[tokio::test]
        async fn decrypt_checks_each_field_against_its_own_type() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = plan(obj(vec![
                ("age", typed(label("age"), &["c"], "uint64")),
                ("name", typed(label("name"), &["c"], "string")),
            ]))
            .expect("plan");
            let rows = FfiValue::Array(vec![
                obj(vec![("age", FfiValue::UInt64(1)), ("name", s("a"))]),
                obj(vec![("age", FfiValue::UInt64(2)), ("name", s("b"))]),
            ]);
            let sealed = seal(&keyset, rows, &plan).await;
            let opened = array(open(&cipher, sealed, &plan).await);
            assert_eq!(opened.len(), 2);
            let second = object(opened.into_iter().nth(1).expect("row"));
            assert_eq!(keys(&second), ["age", "name"]);
            assert_eq!(u64_of(&second[0].1), 2);
            assert_eq!(text_of(&second[1].1), "b");
        }

        /// The query side: a host's `34` (a float, from JavaScript) read as
        /// the field's type derives the term the field stores.
        #[tokio::test]
        async fn a_query_value_read_as_the_field_type_finds_the_stored_term() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = age_plan("uint64");
            let field = &plan.fields()[0];
            let sealed = seal(&keyset, obj(vec![("age", FfiValue::UInt64(34))]), &plan).await;
            let mut row = map(sealed);
            let mut age = map(node(&mut row, "age"));
            let stored = term_bytes(&node(&mut age, "eq"));

            let declared = field.field_type().expect("typed");
            let value =
                crate::dynamic::read(declared, FfiValue::Float64(34.0)).expect("an exact 34");
            let scalar = Scalar::of(&value, &IndexSpec::Equality).expect("scalar");
            let query = term(
                &keyset,
                scalar,
                &IndexSpec::Equality,
                field.context().clone(),
            )
            .await
            .expect("query term");
            assert_eq!(query, stored);
        }

        /// An index-only field has no ciphertext, so it is not among the
        /// opened values. The typed field after it is checked against its
        /// own type, not against the index-only field's.
        #[tokio::test]
        async fn decrypt_skips_an_index_only_field_when_it_checks_types() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = plan(obj(vec![
                ("age", typed(label("age"), &["eq"], "uint64")),
                ("name", typed(label("name"), &["c"], "string")),
            ]))
            .expect("plan");
            let sealed = seal(
                &keyset,
                obj(vec![("age", FfiValue::UInt64(34)), ("name", s("bob"))]),
                &plan,
            )
            .await;
            let opened = object(open(&cipher, sealed, &plan).await);
            assert_eq!(keys(&opened), ["name"]);
            assert_eq!(text_of(&opened[0].1), "bob");
        }

        /// A typed composite field opens as its declared kind, with its
        /// entries, including when it is empty: an empty `[]` that opened
        /// as `{}` would fail every read of an `"array"` field.
        #[tokio::test]
        async fn a_typed_composite_field_round_trips_even_when_empty() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            for (ty, value, len) in [
                ("object", obj(vec![("home", s("a@x"))]), 1),
                ("object", FfiValue::Object(vec![]), 0),
                (
                    "array",
                    FfiValue::Array(vec![s("a"), FfiValue::UInt32(1)]),
                    2,
                ),
                ("array", FfiValue::Array(vec![]), 0),
            ] {
                let plan = plan(obj(vec![("doc", typed(label("doc"), &["c"], ty))])).expect("plan");
                let sealed = seal(&keyset, obj(vec![("doc", value)]), &plan).await;
                let opened = open(&cipher, sealed, &plan).await;
                let (_, doc) = object(opened).into_iter().next().expect("doc");
                match (ty, doc) {
                    ("object", FfiValue::Object(entries)) => assert_eq!(entries.len(), len),
                    ("array", FfiValue::Array(items)) => assert_eq!(items.len(), len),
                    (ty, _) => panic!("a {ty} field opened as another kind"),
                }
            }
        }

        /// `check_record` does not open anything, so it cannot see a
        /// typed field's type: the tag is inside the AEAD envelope. A
        /// record sealed as another type passes it, and only awaiting
        /// `decrypt` refuses it.
        #[tokio::test]
        async fn check_record_accepts_a_record_sealed_as_another_type() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let untyped = plan(obj(vec![("age", spec(label("age"), &["c"]))])).expect("plan");
            let as_uint64 =
                plan(obj(vec![("age", typed(label("age"), &["c"], "uint64"))])).expect("plan");

            let sealed = seal(&keyset, obj(vec![("age", FfiValue::UInt32(34))]), &untyped).await;
            check_record(sealed, &as_uint64, None)
                .expect("the type is not visible without opening");

            let sealed = seal(&keyset, obj(vec![("age", FfiValue::UInt32(34))]), &untyped).await;
            let result = decrypt(Scope::Client(&cipher), sealed, &as_uint64, None)
                .expect("the shape fits")
                .await;
            assert!(
                matches!(result, Err(crate::Error::Plan(PlanError::FieldType { .. }))),
                "decrypt is where the type is checked: {:?}",
                result.err()
            );
        }

        /// Every index a typed field can declare stores the term a binding's
        /// probe derives under the field's context: ORE and OPE over a
        /// `uint32` and a `string`, and a match index under non-default
        /// options over a `string`, through the output key each rides under.
        #[tokio::test]
        async fn a_typed_field_stores_the_term_the_dynamic_probe_derives() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let wide = IndexSpec::Match(crate::sem::MatchOptions {
                k: 6,
                m: 1024,
                ..crate::sem::MatchOptions::default()
            });
            for (ty, kind) in [
                ("uint32", IndexSpec::Equality),
                ("uint32", IndexSpec::Ore),
                ("uint32", IndexSpec::Ope),
                ("string", IndexSpec::Equality),
                ("string", IndexSpec::Ore),
                ("string", IndexSpec::Ope),
                (
                    "string",
                    IndexSpec::Match(crate::sem::MatchOptions::default()),
                ),
                ("string", wide),
            ] {
                let value = || match ty {
                    "uint32" => FfiValue::UInt32(34),
                    _ => s("al smith"),
                };
                let plan = plan(obj(vec![(
                    "f",
                    obj(vec![
                        ("context", label("f")),
                        ("outputs", FfiValue::Array(vec![s("c"), kind.to_value()])),
                        ("type", s(ty)),
                    ]),
                )]))
                .expect("plan");
                let mut fields = map(seal(&keyset, obj(vec![("f", value())]), &plan).await);
                let mut f = map(node(&mut fields, "f"));
                let stored = term_bytes(&node(&mut f, kind.key()));
                let scalar = Scalar::of(&value(), &kind).expect("scalar");
                let probe = term(&keyset, scalar, &kind, plan.fields()[0].context().clone())
                    .await
                    .expect("probe");
                assert_eq!(stored, probe, "{ty} {kind}");
                assert!(!stored.is_empty(), "{ty} {kind}");
            }
        }

        /// A passthrough field with a declared type carries only values of
        /// that type, in and out.
        #[tokio::test]
        async fn a_typed_passthrough_field_is_checked_both_ways() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = plan(obj(vec![
                ("age", typed(label("age"), &["c"], "uint32")),
                ("id", typed(label("id"), &["passthrough"], "uint64")),
            ]))
            .expect("plan");
            let refused = encrypt(
                &keyset,
                obj(vec![
                    ("age", FfiValue::UInt32(1)),
                    ("id", FfiValue::UInt32(7)),
                ]),
                &plan,
            )
            .err();
            assert!(matches!(refused, Some(Error::Source { .. })), "{refused:?}");
            let sealed = seal(
                &keyset,
                obj(vec![
                    ("age", FfiValue::UInt32(1)),
                    ("id", FfiValue::UInt64(7)),
                ]),
                &plan,
            )
            .await;
            let mut fields = map(sealed);
            let age = node(&mut fields, "age");
            fields.push(("age".to_string(), age));
            let _ = node(&mut fields, "id");
            fields.push((
                "id".to_string(),
                CipherText::Map(vec![(
                    "passthrough".to_string(),
                    forged(FfiValue::UInt32(7)),
                )]),
            ));
            let refused =
                decrypt(Scope::Client(&cipher), CipherText::Map(fields), &plan, None).err();
            assert!(matches!(refused, Some(Error::Record { .. })), "{refused:?}");
        }
    }

    /// A resolver shaped like the EQL one, over this engine: it seals a
    /// string as one leaf under the field's label and writes it into a JSON
    /// envelope with the label as its `i`, opens it back checking that `i`,
    /// and derives an equality term for a query. What it proves is the
    /// lowering's half — the target field rides in the record's request,
    /// is stored under `"eql"`, opens through the resolver, and every
    /// refusal is decided before a key is touched — not EQL's envelope,
    /// which is `eql-bindings`' to prove.
    mod given_a_target_field {
        use super::*;
        use crate::dynamic::{NoTargets, TargetDescriptor, TargetError, TargetResolver};
        use crate::target::CallerContext;
        use crate::SealedValue;

        struct FakeEql;

        const TEXT_EQ: &str = "TextEq";

        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }

        fn unhex(text: &str) -> Option<Vec<u8>> {
            (0..text.len())
                .step_by(2)
                .map(|at| u8::from_str_radix(text.get(at..at + 2)?, 16).ok())
                .collect()
        }

        fn text_of_value(name: &str, value: FfiValue) -> Result<String, TargetError> {
            match value {
                FfiValue::String(text) => Ok(utf8(&text).unwrap_or_default().to_owned()),
                other => Err(TargetError::Plaintext {
                    name: String::new(),
                    target: name.to_owned(),
                    expected: Some(ValueKind::String),
                    found: other.kind(),
                }),
            }
        }

        fn column(name: &str, label: &Label) -> Result<NonEmpty<Label>, TargetError> {
            if label.segments().len() != 2 {
                return Err(TargetError::Column {
                    name: String::new(),
                    label: label.to_string(),
                    reason: format!("{name} is stored under a table and a column"),
                });
            }
            Ok(NonEmpty::from(label.clone()))
        }

        impl TargetResolver for FakeEql {
            fn targets(&self) -> Vec<TargetDescriptor> {
                vec![
                    TargetDescriptor::new(
                        TEXT_EQ,
                        "text",
                        "Eq",
                        Some(ValueKind::String),
                        "public.eql_v3_text_eq",
                        vec!["eq".to_string()],
                        Some("TextEqQuery".to_string()),
                        Some("eql_v3.query_text_eq".to_string()),
                        true,
                        None,
                    ),
                    TargetDescriptor::new(
                        "TextOrdOre",
                        "text",
                        "OrdOre",
                        Some(ValueKind::String),
                        "public.eql_v3_text_ord_ore",
                        vec!["eq".to_string(), "ore".to_string()],
                        Some("TextOrdOreQuery".to_string()),
                        Some("eql_v3.query_text_ord_ore".to_string()),
                        false,
                        Some("block ORE is not CLLW ORE".to_string()),
                    ),
                ]
            }

            fn encrypt<'a, K: 'static>(
                &self,
                name: &str,
                keyset: &'a KeysetCipher<'_, K>,
                label: &Label,
                plaintext: FfiValue,
            ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
                let _ = self.resolve(name)?;
                let text = text_of_value(name, plaintext)?;
                let column = column(name, label)?;
                let stored_label = label.to_string();
                Ok(keyset
                    .encrypt_as::<String, StackCipherText>(&text, AeadContext::from(column))
                    .try_map(move |sealed| {
                        let CipherText::Single(leaf) = sealed else {
                            return Err(crate::Error::UnsupportedShape);
                        };
                        serde_json::to_vec(&serde_json::json!({
                            "v": 3,
                            "i": stored_label,
                            "c": hex(&leaf.to_bytes()),
                        }))
                        .map_err(|e| crate::Error::Other(Box::new(e)))
                    }))
            }

            fn decrypt<'a, K: 'static>(
                &self,
                name: &str,
                cipher: &'a StackCipher<K>,
                label: &Label,
                stored: &[u8],
            ) -> Result<Pending<'a, FfiValue, K>, TargetError> {
                let _ = self.resolve(name)?;
                let column = column(name, label)?;
                let stored: serde_json::Value =
                    serde_json::from_slice(stored).map_err(|e| TargetError::Stored {
                        name: String::new(),
                        target: name.to_owned(),
                        reason: crate::diagnostic::describe_json_error(&e),
                    })?;
                let leaf = stored["c"]
                    .as_str()
                    .and_then(unhex)
                    .and_then(|bytes| SealedValue::from_bytes(&bytes).ok())
                    .ok_or_else(|| TargetError::Stored {
                        name: String::new(),
                        target: name.to_owned(),
                        reason: "no ciphertext".to_owned(),
                    })?;
                if stored["i"].as_str() != Some(&label.to_string()) {
                    return Ok(Pending::failed(
                        cipher,
                        crate::Error::Other("stored under another column".into()),
                    ));
                }
                let opening: Decryption<String, K> =
                    crate::target::open(CipherText::Single(leaf), AeadContext::from(column));
                Ok(cipher
                    .run_decryption(opening)
                    .map(|text| FfiValue::String(text.into())))
            }

            fn query<'a, K: 'static>(
                &self,
                name: &str,
                keyset: &'a KeysetCipher<'_, K>,
                label: &Label,
                plaintext: FfiValue,
            ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
                let _ = self.resolve(name)?;
                let text = text_of_value(name, plaintext)?;
                let column = column(name, label)?;
                let stored_label = label.to_string();
                Ok(keyset
                    .encrypt_as::<String, EqualityTerm>(&text, CallerContext::from(column))
                    .try_map(move |term| {
                        serde_json::to_vec(&serde_json::json!({
                            "v": 3,
                            "i": stored_label,
                            "hm": hex(term.as_bytes()),
                        }))
                        .map_err(|e| crate::Error::Other(Box::new(e)))
                    }))
            }
        }

        fn target_spec(context: FfiValue, target: &str) -> FfiValue {
            obj(vec![("context", context), ("target", s(target))])
        }

        /// `age` sealed and indexed by the lowered plan, `email` a target.
        fn mixed_plan_value() -> FfiValue {
            obj(vec![
                ("age", typed(label("age"), &["c", "eq"], "uint32")),
                ("email", target_spec(label("email"), TEXT_EQ)),
            ])
        }

        fn mixed_plan() -> Plan {
            plan_with(mixed_plan_value(), &FakeEql).expect("a plan with a target parses")
        }

        fn mixed_row(age: u32, email: &str) -> FfiValue {
            obj(vec![("age", FfiValue::UInt32(age)), ("email", s(email))])
        }

        fn eql_json(record: &mut Vec<(String, StackCipherText)>, field: &str) -> serde_json::Value {
            let CipherText::Map(mut outputs) = node(record, field) else {
                panic!("{field} is a map of outputs");
            };
            assert_eq!(keys(&outputs), [EQL_KEY], "{field}: one node, under eql");
            let CipherText::Passthrough(payload) = node(&mut outputs, EQL_KEY) else {
                panic!("the eql node is a passthrough");
            };
            let FfiValue::Bytes(bytes) = *payload.downcast::<FfiValue>().unwrap() else {
                panic!("the eql node carries bytes");
            };
            serde_json::from_slice(bytes.risky_ref()).expect("the eql node is JSON")
        }

        fn target_error(error: Error) -> TargetError {
            match error {
                Error::Target(error) => error,
                other => panic!("expected a target refusal, got {other:?}"),
            }
        }

        /// The refusal a call returned; a `Pending` has no `Debug`, so this
        /// stands in for `unwrap_err`.
        fn refused<T>(result: Result<T, Error>) -> Error {
            match result {
                Err(error) => error,
                Ok(_) => panic!("the call accepted what it should have refused"),
            }
        }

        async fn seal_mixed(
            keyset: &KeysetCipher<'_, Counting>,
            plan: &Plan,
        ) -> Vec<(String, StackCipherText)> {
            map(encrypt_with(keyset, mixed_row(1, "a@x"), plan, &FakeEql)
                .expect("fits")
                .await
                .expect("seals"))
        }

        #[tokio::test]
        async fn is_sealed_by_the_resolver_in_the_records_one_request() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = mixed_plan();
            assert_eq!(plan.fields()[1].target(), Some(TEXT_EQ));
            assert!(
                plan.fields()[1].outputs().is_empty(),
                "a target's outputs are the type's"
            );
            assert_eq!(
                plan.fields()[1].field_type(),
                Some(ValueKind::String),
                "an undeclared type is the target's plaintext kind"
            );

            let sealed = encrypt_with(&keyset, mixed_row(34, "a@x"), &plan, &FakeEql)
                .expect("the row fits")
                .await
                .expect("seals");
            assert_eq!(
                generates(&cipher),
                1,
                "the target leaf minted in the record's one request"
            );
            let mut record = map(sealed);
            assert_eq!(keys(&record), ["age", "email"], "plan order");
            let eql = eql_json(&mut record, "email");
            assert_eq!(eql["v"], 3);
            assert_eq!(
                eql["i"], "users/email",
                "the field's label is the stored column"
            );
            assert!(eql["c"].is_string());

            // `node` took the inspected entry out; a fresh record opens.
            let record = seal_mixed(&keyset, &plan).await;
            let opened = decrypt_with(
                Scope::Client(&cipher),
                CipherText::Map(record),
                &plan,
                None,
                &FakeEql,
            )
            .expect("the record fits")
            .await
            .expect("opens");
            assert_eq!(
                retrieves(&cipher),
                1,
                "the target leaf retrieved in the record's one request"
            );
            let fields = object(opened);
            assert_eq!(keys(&fields), ["age", "email"]);
            assert_eq!(u32_of(&fields[0].1), 1, "seal_mixed's age");
            assert_eq!(text_of(&fields[1].1), "a@x");

            // Through a keyset scope, the target's pending is confined to it
            // like every other leaf's.
            let record = seal_mixed(&keyset, &plan).await;
            let opened = decrypt_with(
                Scope::Keyset(cipher.default_keyset()),
                CipherText::Map(record),
                &plan,
                None,
                &FakeEql,
            )
            .expect("the record fits")
            .await
            .expect("opens under its own keyset");
            assert_eq!(text_of(&object(opened)[1].1), "a@x");
        }

        #[tokio::test]
        async fn a_batch_keeps_every_rows_target_in_order() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = mixed_plan();
            let rows = FfiValue::Array(vec![
                mixed_row(1, "one"),
                mixed_row(2, "two"),
                mixed_row(3, "three"),
            ]);
            let sealed = encrypt_with(&keyset, rows, &plan, &FakeEql)
                .expect("the rows fit")
                .await
                .expect("seals");
            assert_eq!(
                generates(&cipher),
                1,
                "three rows, two leaves each, one request"
            );
            let opened = decrypt_with(Scope::Client(&cipher), sealed, &plan, None, &FakeEql)
                .expect("the batch fits")
                .await
                .expect("opens");
            assert_eq!(retrieves(&cipher), 1);
            let rows = array(opened);
            let emails: Vec<String> = rows
                .into_iter()
                .map(|row| text_of(&object(row)[1].1))
                .collect();
            assert_eq!(
                emails,
                ["one", "two", "three"],
                "each row's target is its own"
            );
        }

        #[tokio::test]
        async fn a_plan_of_targets_alone_runs_with_no_lowered_field() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = plan_with(
                obj(vec![("email", target_spec(label("email"), TEXT_EQ))]),
                &FakeEql,
            )
            .expect("parses");
            let sealed = encrypt_with(&keyset, obj(vec![("email", s("a@x"))]), &plan, &FakeEql)
                .expect("fits")
                .await
                .expect("seals");
            assert_eq!(generates(&cipher), 1);
            let opened = decrypt_with(Scope::Client(&cipher), sealed, &plan, None, &FakeEql)
                .expect("fits")
                .await
                .expect("opens");
            assert_eq!(text_of(&object(opened)[0].1), "a@x");
        }

        #[test]
        fn is_refused_when_the_plan_is_built_without_a_resolver() {
            // The bare entry points are the build without EQL types.
            let error = target_error(plan(mixed_plan_value()).unwrap_err());
            assert!(
                matches!(&error, TargetError::NoTargets { name } if name == TEXT_EQ),
                "{error}"
            );
            let fields = vec![
                FieldPlan::new(
                    "age",
                    context(label("age")).unwrap(),
                    vec![Output::Ciphertext],
                )
                .unwrap(),
                FieldPlan::with_target("email", context(label("email")).unwrap(), TEXT_EQ).unwrap(),
            ];
            assert!(matches!(
                Plan::new(fields).unwrap_err(),
                Error::Target(TargetError::NoTargets { .. })
            ));
        }

        #[tokio::test]
        async fn a_plan_built_with_a_resolver_is_refused_by_the_bare_entry_points() {
            // Fail closed: a plan from the build with EQL types handed to the
            // build without them is refused, never half-sealed.
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = mixed_plan();
            let error = target_error(refused(encrypt(&keyset, mixed_row(1, "a@x"), &plan)));
            assert!(matches!(error, TargetError::NoTargets { .. }), "{error}");
            assert_eq!(generates(&cipher), 0, "nothing minted");
            let sealed = CipherText::Map(seal_mixed(&keyset, &plan).await);
            let error = target_error(refused(decrypt(
                Scope::Client(&cipher),
                sealed,
                &plan,
                None,
            )));
            assert!(matches!(error, TargetError::NoTargets { .. }), "{error}");
            assert_eq!(retrieves(&cipher), 0, "nothing retrieved");
        }

        #[test]
        fn a_name_the_build_cannot_run_is_refused_when_the_plan_is_built() {
            let refused = |target: &str| {
                target_error(
                    plan_with(
                        obj(vec![("email", target_spec(label("email"), target))]),
                        &FakeEql,
                    )
                    .unwrap_err(),
                )
            };
            assert!(matches!(refused("Nope"), TargetError::Unknown { name } if name == "Nope"));
            assert!(matches!(
                refused("TextOrdOre"),
                TargetError::Unproducible { name, reason } if name == "TextOrdOre" && reason.contains("CLLW")
            ));
            assert!(
                matches!(refused("texteq"), TargetError::Unknown { .. }),
                "exact names"
            );
        }

        /// The constructor's one bound on the label is "a label", the same
        /// as every field constructor's: how many segments it needs is the
        /// plan's rule, where the plan is built. A one-segment label is a
        /// field's identity under a context field, and under a plan with a
        /// context of its own it has nothing to sit under; the column rule
        /// — exactly two — is `Plan::new_with`'s (the test after this one).
        /// Pinned from both sides so the constructor's bound cannot drift:
        /// one segment accepted and then refused by the plan, two accepted,
        /// and three accepted intact.
        #[test]
        fn with_target_takes_any_label_and_the_plan_holds_the_segment_rules() {
            let ctx = |segments: &[&str]| context(strings(segments)).expect("a context value");
            let one = FieldPlan::with_target("email", ctx(&["users"]), TEXT_EQ)
                .expect("one segment is a label; the plan decides");
            assert!(
                matches!(Plan::new_with(vec![one], &FakeEql), Err(Error::Plan { .. })),
                "under a plan with a context of its own, one segment has nothing to sit under"
            );
            let two = FieldPlan::with_target("email", ctx(&["users", "email"]), TEXT_EQ)
                .expect("two segments: table and column");
            assert_eq!(two.label().to_string(), "users/email");
            let three =
                FieldPlan::with_target("email", ctx(&["tenant", "users", "email"]), TEXT_EQ)
                    .expect("three segments are a label; the column rule is the resolver's");
            assert_eq!(three.label().segments().count(), 3);
            assert_eq!(three.identity(), "email");
            assert_eq!(three.target(), Some(TEXT_EQ));
        }

        /// `context=app/users` with `email,encrypt_into=TextEq` in Go gives
        /// the label `app/users/email`: no column for it. Refused when the
        /// plan is built, so `se_plan_check` tells the generator before it
        /// writes the code, and no value ever reaches the resolver.
        #[tokio::test]
        async fn a_target_label_that_is_not_table_and_column_is_refused_when_the_plan_is_built() {
            let cipher = cipher().await;
            let value = obj(vec![(
                "email",
                target_spec(strings(&["app", "users", "email"]), TEXT_EQ),
            )]);
            let error = target_error(plan_with(value, &FakeEql).unwrap_err());
            assert!(
                matches!(&error, TargetError::Column { name, label, .. } if name == "email" && label == "app/users/email"),
                "{error}"
            );
            assert_eq!(
                error.to_string(),
                "email: the label app/users/email is not an EQL column: an EQL column is a \
                 two-segment label: table and column"
            );
            // A sealed field under the same three-segment label is fine: the
            // rule is the EQL column's, not the plan's.
            let value = obj(vec![(
                "email",
                spec(strings(&["app", "users", "email"]), &["c"]),
            )]);
            assert!(plan_with(value, &FakeEql).is_ok());
            assert_eq!(generates(&cipher), 0, "nothing minted");
        }

        /// The resolver opens a target value through the client, which opens
        /// every keyset's values; `confine` is what holds it to the scope's
        /// keyset. A plan of one target field, so no lowered leaf can cause
        /// the refusal instead: this fails if `confine` stops calling
        /// `scoped_to`, and one tenant's cipher opens another's column.
        #[tokio::test]
        async fn a_keyset_scope_refuses_a_target_value_from_another_keyset() {
            let cipher = cipher().await;
            let named = |n: &str| IdentifiedBy::Name(n.to_string().into());
            let acme = cipher.keyset(named("acme")).await.expect("acme");
            let globex = cipher.keyset(named("globex")).await.expect("globex");
            let plan = plan_with(
                obj(vec![("email", target_spec(label("email"), TEXT_EQ))]),
                &FakeEql,
            )
            .unwrap();
            let sealed = encrypt_with(&acme, obj(vec![("email", s("a@x"))]), &plan, &FakeEql)
                .unwrap()
                .await
                .unwrap();
            let result = decrypt_with(Scope::Keyset(globex), sealed, &plan, None, &FakeEql)
                .expect("the record fits")
                .await;
            match result {
                Err(crate::Error::ForeignKeyset { .. }) => {}
                Err(other) => panic!("refused, but not as a foreign keyset: {other}"),
                Ok(_) => panic!("globex opened acme's target value"),
            }
            assert_eq!(
                retrieves(&cipher),
                0,
                "refused before any key was retrieved"
            );
            // acme's own scope, and the client, still open it.
            let sealed = encrypt_with(&acme, obj(vec![("email", s("a@x"))]), &plan, &FakeEql)
                .unwrap()
                .await
                .unwrap();
            let opened = decrypt_with(Scope::Keyset(acme), sealed, &plan, None, &FakeEql)
                .unwrap()
                .await
                .expect("its own keyset opens it");
            assert_eq!(text_of(&object(opened)[0].1), "a@x");
        }

        /// The node under `"eql"` must be a passthrough: a ciphertext leaf
        /// there is a record the plan did not produce, refused before any
        /// key is retrieved. (The "misplaced" case in the test below puts
        /// the leaf under `"c"`, where `take` of `"eql"` fails first; this
        /// one reaches the node-shape refusal itself.)
        #[tokio::test]
        async fn a_non_passthrough_node_under_eql_is_refused() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = mixed_plan();
            let mut row = seal_mixed(&keyset, &plan).await;
            row.retain(|(k, _)| k != "email");
            row.push((
                "email".to_string(),
                CipherText::Map(vec![(EQL_KEY.to_string(), forged(s("x")))]),
            ));
            assert!(matches!(
                check_record(CipherText::Map(row), &plan, None),
                Err(Error::Record { .. })
            ));
            let mut row = seal_mixed(&keyset, &plan).await;
            row.retain(|(k, _)| k != "email");
            row.push((
                "email".to_string(),
                CipherText::Map(vec![(EQL_KEY.to_string(), forged(s("x")))]),
            ));
            let error = refused(decrypt_with(
                Scope::Client(&cipher),
                CipherText::Map(row),
                &plan,
                None,
                &FakeEql,
            ));
            assert!(matches!(error, Error::Record { .. }), "{error:?}");
            assert_eq!(retrieves(&cipher), 0);
        }

        /// The adapters trust the resolver to answer one value per target
        /// field; fewer is the engine's shape disagreeing with the plan's,
        /// reported as `ResponseShape` (a binding's internal status), never
        /// as a refusal the caller is told to fix.
        #[test]
        fn a_target_slot_the_resolver_did_not_answer_is_a_response_shape_error() {
            let plan = plan_with(
                obj(vec![("email", target_spec(label("email"), TEXT_EQ))]),
                &FakeEql,
            )
            .unwrap();
            let shape = plan.shape();
            assert!(
                matches!(
                    shape_record(FieldValues::new(), Vec::new(), &shape),
                    Err(crate::Error::ResponseShape)
                ),
                "a missing target value on the encrypt side"
            );
            assert!(
                matches!(
                    open_record(FieldValues::new(), Vec::new(), &shape),
                    Err(crate::Error::ResponseShape)
                ),
                "a missing target value on the decrypt side"
            );
        }

        #[test]
        fn the_target_and_output_forms_are_exclusive() {
            let both = obj(vec![
                ("context", label("email")),
                ("outputs", strings(&["c"])),
                ("target", s(TEXT_EQ)),
            ]);
            assert!(matches!(
                plan_with(obj(vec![("email", both)]), &FakeEql),
                Err(Error::Plan { .. })
            ));
            let neither = obj(vec![("context", label("email"))]);
            assert!(matches!(
                plan_with(obj(vec![("email", neither)]), &FakeEql),
                Err(Error::Plan { .. })
            ));
            let not_text = obj(vec![
                ("context", label("email")),
                ("target", FfiValue::UInt32(1)),
            ]);
            assert!(matches!(
                plan_with(obj(vec![("email", not_text)]), &FakeEql),
                Err(Error::Plan { .. })
            ));
            let empty = obj(vec![("context", label("email")), ("target", s(""))]);
            assert!(matches!(
                plan_with(obj(vec![("email", empty)]), &FakeEql),
                Err(Error::Plan { .. })
            ));
            let twice = obj(vec![
                ("context", label("email")),
                ("target", s(TEXT_EQ)),
                ("target", s(TEXT_EQ)),
            ]);
            assert!(matches!(
                plan_with(obj(vec![("email", twice)]), &FakeEql),
                Err(Error::Plan { .. })
            ));
        }

        #[tokio::test]
        async fn the_fields_type_is_the_targets_plaintext_kind() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            // Declared and agreeing: fine.
            let declared = obj(vec![
                ("context", label("email")),
                ("target", s(TEXT_EQ)),
                ("type", s("string")),
            ]);
            let plan = plan_with(obj(vec![("email", declared)]), &FakeEql).expect("agrees");
            assert_eq!(plan.fields()[0].field_type(), Some(ValueKind::String));
            // Declared and disagreeing: refused when the plan is built.
            let other = obj(vec![
                ("context", label("email")),
                ("target", s(TEXT_EQ)),
                ("type", s("uint64")),
            ]);
            let error = target_error(plan_with(obj(vec![("email", other)]), &FakeEql).unwrap_err());
            assert!(
                matches!(&error, TargetError::Kind { name, target, expected: Some(ValueKind::String), declared: ValueKind::UInt64 } if name == "email" && target == TEXT_EQ),
                "{error}"
            );
            // A value of another kind is refused before the resolver runs.
            let wrong = obj(vec![("email", FfiValue::UInt32(7))]);
            assert!(matches!(
                check_source(wrong, &plan),
                Err(Error::Source { .. })
            ));
            let wrong = obj(vec![("email", FfiValue::UInt32(7))]);
            assert!(matches!(
                refused(encrypt_with(&keyset, wrong, &plan, &FakeEql)),
                Error::Source { .. }
            ));
            // A passthrough is refused as it is for any sealed field.
            let forged = obj(vec![("email", FfiValue::Passthrough(Box::new(s("a@x"))))]);
            assert!(matches!(
                refused(encrypt_with(&keyset, forged, &plan, &FakeEql)),
                Error::Source { .. }
            ));
            assert_eq!(generates(&cipher), 0);
        }

        #[test]
        fn an_extended_plan_refuses_a_target_field_rather_than_dropping_the_extension() {
            let extended = |field: &str| FfiValue::Array(vec![label(field), FfiValue::UInt32(7)]);
            let value = obj(vec![
                ("age", spec(extended("age"), &["c"])),
                ("email", target_spec(extended("email"), TEXT_EQ)),
            ]);
            let error = target_error(plan_with(value, &FakeEql).unwrap_err());
            assert!(
                matches!(&error, TargetError::Extended { name, label } if name == "email" && label == "users/email"),
                "{error}"
            );
            // The same plan without the target field extends as before.
            let value = obj(vec![("age", spec(extended("age"), &["c"]))]);
            assert!(plan_with(value, &FakeEql).is_ok());
        }

        /// A plan with a context field has no table of its own: each
        /// record names one. An EQL value stores a table the declaration
        /// fixes, so a target field is refused there as it is in an extended
        /// plan, and before the resolver is asked.
        #[test]
        fn a_context_field_plan_refuses_a_target_field() {
            let identity = |field: &str| strings(&[field]);
            let value = obj(vec![
                ("context_field", s("tenant")),
                ("tenant", spec(identity("tenant"), &["passthrough"])),
                ("age", spec(identity("age"), &["c"])),
                ("email", target_spec(identity("email"), TEXT_EQ)),
            ]);
            let error = target_error(plan_with(value, &FakeEql).unwrap_err());
            assert!(
                matches!(&error, TargetError::ContextField { name, context_field } if name == "email" && context_field == "tenant"),
                "{error}"
            );
            // Refused by the plan, whatever the build holds: a build with
            // no EQL types says the same.
            let value = obj(vec![
                ("context_field", s("tenant")),
                ("tenant", spec(identity("tenant"), &["passthrough"])),
                ("email", target_spec(identity("email"), TEXT_EQ)),
            ]);
            assert!(matches!(
                target_error(plan(value).unwrap_err()),
                TargetError::ContextField { .. }
            ));
            // The same plan without the target field takes its context
            // from the field as before.
            let value = obj(vec![
                ("context_field", s("tenant")),
                ("tenant", spec(identity("tenant"), &["passthrough"])),
                ("age", spec(identity("age"), &["c"])),
            ]);
            assert_eq!(
                plan_with(value, &FakeEql).expect("parses").context_field(),
                Some("tenant")
            );
        }

        #[test]
        fn a_target_field_is_keyed_under_its_identity_like_a_sealed_one() {
            // Two fields under one label, one of them a target: the terms
            // and the EQL value would be interchangeable, so refused as two
            // sealed fields under one identity are.
            let fields = vec![
                FieldPlan::new(
                    "mail",
                    context(label("email")).unwrap(),
                    vec![Output::Ciphertext],
                )
                .unwrap(),
                FieldPlan::with_target("email", context(label("email")).unwrap(), TEXT_EQ).unwrap(),
            ];
            assert!(matches!(
                Plan::new_with(fields, &FakeEql),
                Err(Error::Plan { .. })
            ));
            let fields = vec![
                FieldPlan::with_target("email", context(label("email")).unwrap(), TEXT_EQ).unwrap(),
                FieldPlan::new(
                    "mail",
                    context(label("email")).unwrap(),
                    vec![Output::Ciphertext],
                )
                .unwrap(),
            ];
            assert!(matches!(
                Plan::new_with(fields, &FakeEql),
                Err(Error::Plan { .. })
            ));
            let fields = vec![
                FieldPlan::with_target("a", context(label("email")).unwrap(), TEXT_EQ).unwrap(),
                FieldPlan::with_target("b", context(label("email")).unwrap(), TEXT_EQ).unwrap(),
            ];
            assert!(matches!(
                Plan::new_with(fields, &FakeEql),
                Err(Error::Plan { .. })
            ));
        }

        #[tokio::test]
        async fn a_stored_eql_node_is_passthrough_bytes_exactly_once() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = mixed_plan();
            // A fresh record each time: a ciphertext tree is not `Clone`.
            let with_email = |mut row: Vec<(String, StackCipherText)>, node: StackCipherText| {
                row.retain(|(k, _)| k != "email");
                row.push(("email".to_string(), node));
                CipherText::Map(row)
            };
            let bytes_node = |bytes: &[u8]| {
                CipherText::Map(vec![(
                    EQL_KEY.to_string(),
                    CipherText::Passthrough(Box::new(FfiValue::Bytes(Protected::new(
                        bytes.to_vec(),
                    ))) as BoxedPassthrough),
                )])
            };
            // A ciphertext leaf where the EQL value should be.
            let misplaced = CipherText::Map(vec![("c".to_string(), forged(s("x")))]);
            let record = with_email(seal_mixed(&keyset, &plan).await, misplaced);
            assert!(matches!(
                check_record(record, &plan, None),
                Err(Error::Record { .. })
            ));
            // The node twice.
            let mut row = seal_mixed(&keyset, &plan).await;
            let CipherText::Map(mut outputs) = node(&mut row, "email") else {
                panic!("a map")
            };
            let CipherText::Map(again) = node(&mut seal_mixed(&keyset, &plan).await, "email")
            else {
                panic!("a map")
            };
            outputs.extend(again);
            row.push(("email".to_string(), CipherText::Map(outputs)));
            assert!(matches!(
                check_record(CipherText::Map(row), &plan, None),
                Err(Error::Record { .. })
            ));
            // A payload that is not bytes.
            let null = CipherText::Map(vec![(
                EQL_KEY.to_string(),
                CipherText::Passthrough(Box::new(FfiValue::Null) as BoxedPassthrough),
            )]);
            let record = with_email(seal_mixed(&keyset, &plan).await, null);
            assert!(matches!(
                check_record(record, &plan, None),
                Err(Error::Record { .. })
            ));
            // Bytes that are not the type: the shape fits, and the resolver
            // refuses them before any key is retrieved.
            let record = with_email(seal_mixed(&keyset, &plan).await, bytes_node(b"not json"));
            assert!(check_record(record, &plan, None).is_ok(), "the shape fits");
            let retrieved = retrieves(&cipher);
            let record = with_email(seal_mixed(&keyset, &plan).await, bytes_node(b"not json"));
            let error = target_error(refused(decrypt_with(
                Scope::Client(&cipher),
                record,
                &plan,
                None,
                &FakeEql,
            )));
            assert!(
                matches!(&error, TargetError::Stored { name, target, .. } if name == "email" && target == TEXT_EQ),
                "{error}"
            );
            assert_eq!(retrieves(&cipher), retrieved, "nothing retrieved");
            // An untouched record still opens.
            let record = CipherText::Map(seal_mixed(&keyset, &plan).await);
            let opened = decrypt_with(Scope::Client(&cipher), record, &plan, None, &FakeEql)
                .unwrap()
                .await
                .unwrap();
            assert_eq!(text_of(&object(opened)[1].1), "a@x");
        }

        #[tokio::test]
        async fn a_query_runs_the_targets_query_through_the_resolver() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = mixed_plan();
            let probe = query(&keyset, &plan, "email", s("a@x"), &FakeEql)
                .expect("a target field")
                .await
                .expect("derives");
            let probe: serde_json::Value = serde_json::from_slice(&probe).unwrap();
            assert_eq!(probe["i"], "users/email");
            let again = query(&keyset, &plan, "email", s("a@x"), &FakeEql)
                .unwrap()
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&again).unwrap()["hm"],
                probe["hm"],
                "deterministic"
            );
            assert_eq!(generates(&cipher), 0, "a query mints nothing");
            // Not a target field, no such field, the wrong kind, and the
            // bare build: each refused before the resolver runs.
            assert!(matches!(
                refused(query(&keyset, &plan, "age", s("x"), &FakeEql)),
                Error::Plan { .. }
            ));
            assert!(matches!(
                refused(query(&keyset, &plan, "nope", s("x"), &FakeEql)),
                Error::Plan { .. }
            ));
            assert!(matches!(
                refused(query(
                    &keyset,
                    &plan,
                    "email",
                    FfiValue::UInt32(1),
                    &FakeEql
                )),
                Error::Source { .. }
            ));
            assert!(matches!(
                refused(query(&keyset, &plan, "email", s("x"), &NoTargets)),
                Error::Target(TargetError::NoTargets { .. })
            ));
        }

        #[tokio::test]
        async fn a_resolver_refusal_names_the_field() {
            // The resolver sees a type and a label; the lowering names the
            // field the refusal was about.
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = plan_with(
                obj(vec![("email", target_spec(label("email"), TEXT_EQ))]),
                &FakeEql,
            )
            .unwrap();
            // A resolver that refuses the value as not its plaintext: the
            // lowering's own kind check runs first, so reach the resolver
            // with a kind it does not refuse here but the resolver does —
            // there is none for a string target, so use the stored side.
            let junk = CipherText::Map(vec![(
                "email".to_string(),
                CipherText::Map(vec![(
                    EQL_KEY.to_string(),
                    CipherText::Passthrough(Box::new(FfiValue::Bytes(Protected::new(
                        b"{}".to_vec(),
                    ))) as BoxedPassthrough),
                )]),
            )]);
            let error = target_error(refused(decrypt_with(
                Scope::Client(&cipher),
                junk,
                &plan,
                None,
                &FakeEql,
            )));
            match error {
                TargetError::Stored { name, .. } => assert_eq!(name, "email"),
                other => panic!("{other}"),
            }
            let _ = keyset;
        }
    }

    /// The leaf encoding, pinned: every field lowered from data seals the
    /// tagged `Value` leaf whatever its `"type"`, so a type declared later
    /// changes no bytes; a Rust field of a bare type shares a data field's
    /// terms and not its leaf, and the two leaves cannot be told apart by
    /// inspection, which is why the lowering never picks an encoding from
    /// the type.
    mod given_the_leaf_encoding {
        use super::*;

        #[derive(EncryptFrom, DecryptInto)]
        #[stash(plaintext = u32, crate = "crate")]
        struct Age {
            c: StackCipherText,
            hm: EqualityTerm,
        }

        /// A `uint32` field and a `string` field seal the tagged leaf, as an
        /// untyped field does: the leaf opens as a value, and a bare `u32`
        /// reader refuses the five bytes it finds.
        #[tokio::test]
        async fn every_field_seals_the_tagged_leaf_whatever_its_type() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let age_label = Label::parse("users/age").expect("label");
            for ty in [None, Some("uint32")] {
                let field = match ty {
                    Some(ty) => typed(label("age"), &["c"], ty),
                    None => spec(label("age"), &["c"]),
                };
                let plan = plan(obj(vec![("age", field)])).expect("plan");
                let mut fields =
                    map(seal(&keyset, obj(vec![("age", FfiValue::UInt32(34))]), &plan).await);
                let mut age = map(node(&mut fields, "age"));
                let as_value: FfiValue = cipher
                    .decrypt(node(&mut age, "c"), age_label.clone())
                    .await
                    .expect("the tagged leaf opens as a value");
                assert_eq!(u32_of(&as_value), 34, "type {ty:?}");
                let mut fields =
                    map(seal(&keyset, obj(vec![("age", FfiValue::UInt32(34))]), &plan).await);
                let mut age = map(node(&mut fields, "age"));
                let as_u32: Result<u32, _> =
                    cipher.decrypt(node(&mut age, "c"), age_label.clone()).await;
                assert!(
                    matches!(as_u32, Err(crate::Error::Aead)),
                    "five tagged bytes are not a bare u32, type {ty:?}: {as_u32:?}"
                );
            }
            let plan = plan(obj(vec![(
                "email",
                typed(label("email"), &["c"], "string"),
            )]))
            .expect("plan");
            let mut fields = map(seal(&keyset, obj(vec![("email", s("a@x"))]), &plan).await);
            let mut email = map(node(&mut fields, "email"));
            let as_value: FfiValue = cipher
                .decrypt(
                    node(&mut email, "c"),
                    Label::parse("users/email").expect("label"),
                )
                .await
                .expect("a tagged string leaf");
            assert_eq!(text_of(&as_value), "a@x");
        }

        /// Declaring a type on a field written without one, or dropping it,
        /// changes no bytes: the row opens to the value it held, exactly, in
        /// both directions. #1082 needs no re-encryption.
        #[tokio::test]
        async fn declaring_a_type_later_changes_no_bytes() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let untyped = plan(obj(vec![
                ("age", spec(label("age"), &["c"])),
                ("email", spec(label("email"), &["c"])),
            ]))
            .expect("plan");
            let typed_plan = plan(obj(vec![
                ("age", typed(label("age"), &["c"], "uint32")),
                ("email", typed(label("email"), &["c"], "string")),
            ]))
            .expect("plan");
            let source = || obj(vec![("age", FfiValue::UInt32(34)), ("email", s("alice"))]);

            let sealed_untyped = seal(&keyset, source(), &untyped).await;
            let opened = object(open(&cipher, sealed_untyped, &typed_plan).await);
            assert_eq!(
                u32_of(&opened[0].1),
                34,
                "an untyped row opens under a uint32 field"
            );
            assert_eq!(
                text_of(&opened[1].1),
                "alice",
                "an untyped row opens under a string field, with no leading byte"
            );

            let sealed_typed = seal(&keyset, source(), &typed_plan).await;
            let opened = object(open(&cipher, sealed_typed, &untyped).await);
            assert_eq!(
                u32_of(&opened[0].1),
                34,
                "a typed row opens under an untyped field"
            );
            assert_eq!(text_of(&opened[1].1), "alice");
        }

        /// A derived `plaintext = u32` record and a `uint32` data-plan field
        /// under one label derive the same term. Their leaves are different
        /// encodings, and neither reader opens the other's: the derive's bare
        /// four bytes carry no tag for the lowering, the lowering's five
        /// tagged bytes are not a `u32`. A Rust record that must interchange
        /// leaves with a data plan declares `Value` fields instead
        /// (`seals_what_the_chain_seals_under_the_same_declaration`).
        #[tokio::test]
        async fn the_derive_and_a_data_plan_share_terms_not_leaves() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let label_ = Label::parse("users/age").expect("label");
            let derived: Age = keyset
                .encrypt_as(&34u32, CallerContext::from(NonEmpty::from(label_.clone())))
                .await
                .expect("derive");

            let plan = plan(obj(vec![(
                "age",
                typed(label("age"), &["c", "eq"], "uint32"),
            )]))
            .expect("plan");
            let mut fields =
                map(seal(&keyset, obj(vec![("age", FfiValue::UInt32(34))]), &plan).await);
            let mut age = map(node(&mut fields, "age"));
            assert_eq!(
                term_bytes(&node(&mut age, "eq")),
                derived.hm.to_bytes(),
                "the same equality term"
            );

            let as_u32: Result<u32, _> = keyset
                .decrypt_as(
                    node(&mut age, "c"),
                    AeadContext::from(NonEmpty::from(label_.clone())),
                )
                .await;
            assert!(
                matches!(as_u32, Err(crate::Error::Aead)),
                "the derive does not open the lowering's leaf: {as_u32:?}"
            );
            let stored = CipherText::Map(vec![(
                "age".to_string(),
                CipherText::Map(vec![("c".to_string(), derived.c)]),
            )]);
            let result = decrypt(Scope::Client(&cipher), stored, &plan, None)
                .expect("the shape fits")
                .await;
            assert!(
                matches!(result, Err(crate::Error::Aead)),
                "the lowering does not open the derive's leaf: {:?}",
                result.err()
            );
        }

        /// The two encodings cannot be told apart by inspection: a bare
        /// `String` reader accepts a tagged string leaf, reading the tag as
        /// a line feed. Pinned so that it is known, never relied on: the
        /// lowering reads only its own encoding, and a Rust record that
        /// shares rows with a binding declares `Value` fields.
        #[tokio::test]
        async fn a_bare_string_reader_cannot_tell_a_tagged_leaf_apart() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = plan(obj(vec![("email", spec(label("email"), &["c"]))])).expect("plan");
            let mut fields = map(seal(&keyset, obj(vec![("email", s("alice"))]), &plan).await);
            let mut email = map(node(&mut fields, "email"));
            let bare: String = cipher
                .decrypt(
                    node(&mut email, "c"),
                    Label::parse("users/email").expect("label"),
                )
                .await
                .expect("valid UTF-8 either way");
            assert_eq!(bare, "\nalice", "the string tag, U+000A, read as text");
        }
    }

    /// Every refusal names the field it is about, where there is one, and
    /// says why with a [`Reason`]: the message, the accessors and the
    /// payload all carry the same two facts.
    mod every_refusal_names_its_field_and_reason {
        use super::*;
        use crate::ErrorPayload;

        /// The variant, the field and the reason an error must report.
        fn expect(error: &Error, variant: &str, field: Option<&str>, reason: Reason) {
            let actual = match error {
                Error::Context { .. } => "Context",
                Error::Plan { .. } => "Plan",
                Error::Source { .. } => "Source",
                Error::Record { .. } => "Record",
                other => panic!("expected a {variant} error, got {other:?}"),
            };
            assert_eq!(actual, variant, "{error}");
            assert_eq!(error.field(), field, "{error}");
            assert_eq!(error.reason(), Some(reason), "{error}");
            let fields = error.payload();
            assert_eq!(fields["reason"], reason.as_str(), "{error}");
            assert_eq!(
                fields.get("field").and_then(|f| f.as_str()),
                field,
                "{error}"
            );
            if let Some(field) = field {
                assert!(error.to_string().contains(field), "{error}");
            }
        }

        fn refused_plan(value: FfiValue) -> Error {
            plan(value).expect_err("the plan is refused")
        }

        fn age(spec: Vec<(&str, FfiValue)>) -> FfiValue {
            obj(vec![("age", obj(spec))])
        }

        #[test]
        fn a_malformed_plan() {
            use Reason::*;
            let cases: Vec<(&str, FfiValue, Option<&str>, Reason, &str)> = vec![
                ("not an object", s("x"), None, NotAnObject, "Plan"),
                ("no fields", obj(vec![]), None, NoFields, "Plan"),
                (
                    "a spec that is not an object",
                    obj(vec![("age", s("x"))]),
                    Some("age"),
                    NotAnObject,
                    "Plan",
                ),
                (
                    "an unknown key",
                    age(vec![
                        ("context", label("age")),
                        ("outputs", strings(&["c"])),
                        ("nullable", FfiValue::Bool(true)),
                    ]),
                    Some("age"),
                    UnknownKey,
                    "Plan",
                ),
                (
                    "a key given twice",
                    age(vec![
                        ("context", label("age")),
                        ("context", label("age")),
                        ("outputs", strings(&["c"])),
                    ]),
                    Some("age"),
                    RepeatedKey,
                    "Plan",
                ),
                (
                    "no context",
                    age(vec![("outputs", strings(&["c"]))]),
                    Some("age"),
                    MissingContext,
                    "Plan",
                ),
                (
                    "no outputs or target",
                    age(vec![("context", label("age"))]),
                    Some("age"),
                    MissingOutputs,
                    "Plan",
                ),
                (
                    "outputs and a target",
                    age(vec![
                        ("context", label("age")),
                        ("outputs", strings(&["c"])),
                        ("target", s("TextEq")),
                    ]),
                    Some("age"),
                    OutputsWithTarget,
                    "Plan",
                ),
                (
                    "outputs that are not a list",
                    age(vec![("context", label("age")), ("outputs", s("c"))]),
                    Some("age"),
                    OutputsNotList,
                    "Plan",
                ),
                (
                    "an output that is not one",
                    age(vec![
                        ("context", label("age")),
                        ("outputs", strings(&["c", "zz"])),
                    ]),
                    Some("age"),
                    UnknownOutput,
                    "Plan",
                ),
                (
                    "no outputs",
                    age(vec![("context", label("age")), ("outputs", strings(&[]))]),
                    Some("age"),
                    NoOutputs,
                    "Plan",
                ),
                (
                    "an output named twice",
                    age(vec![
                        ("context", label("age")),
                        ("outputs", strings(&["c", "c"])),
                    ]),
                    Some("age"),
                    DuplicateOutput,
                    "Plan",
                ),
                (
                    "passthrough beside another output",
                    age(vec![
                        ("context", label("age")),
                        ("outputs", strings(&["c", "passthrough"])),
                    ]),
                    Some("age"),
                    PassthroughWithOutputs,
                    "Plan",
                ),
                (
                    "a target that is not a string",
                    age(vec![
                        ("context", label("age")),
                        ("target", FfiValue::UInt32(1)),
                    ]),
                    Some("age"),
                    InvalidTarget,
                    "Plan",
                ),
                (
                    "a type that is not one",
                    age(vec![
                        ("context", label("age")),
                        ("outputs", strings(&["c"])),
                        ("type", s("decimal")),
                    ]),
                    Some("age"),
                    UnknownType,
                    "Plan",
                ),
                (
                    "an index the type has not",
                    age(vec![
                        ("context", label("age")),
                        ("outputs", strings(&["c", "match"])),
                        ("type", s("uint32")),
                    ]),
                    Some("age"),
                    IndexNotAdmitted,
                    "Plan",
                ),
                (
                    "a context that is not a label",
                    age(vec![("context", s("users")), ("outputs", strings(&["c"]))]),
                    Some("age"),
                    ContextNotLabel,
                    "Plan",
                ),
                (
                    "a context of a kind no context has",
                    age(vec![
                        ("context", FfiValue::Bool(true)),
                        ("outputs", strings(&["c"])),
                    ]),
                    Some("age"),
                    ContextKind,
                    "Context",
                ),
                (
                    "a field named twice",
                    FfiValue::Object(vec![
                        ("age".to_string(), spec(label("age"), &["c"])),
                        ("age".to_string(), spec(label("age"), &["c"])),
                    ]),
                    Some("age"),
                    DuplicateField,
                    "Plan",
                ),
                (
                    "fields under different contexts",
                    obj(vec![
                        ("age", spec(label("age"), &["c"])),
                        ("email", spec(strings(&["orders", "email"]), &["c"])),
                    ]),
                    Some("email"),
                    MixedContexts,
                    "Plan",
                ),
            ];
            for (what, value, field, reason, variant) in cases {
                let error = refused_plan(value);
                assert!(
                    !matches!(error, Error::UntypedIndex { .. }),
                    "{what}: {error}"
                );
                expect(&error, variant, field, reason);
            }
        }

        #[test]
        fn a_source_that_does_not_fit() {
            use Reason::*;
            let plan = the_plan();
            let without = |name: &str| {
                let mut entries = object(row(34));
                let _ = take(&mut entries, name);
                entries
            };
            let mut repeated = object(row(34));
            repeated.push(("age".to_string(), FfiValue::UInt32(2)));
            let mut extra = object(row(34));
            extra.push(("extra".to_string(), FfiValue::UInt32(2)));
            let mut mistyped = without("age");
            mistyped.push(("age".to_string(), s("old")));
            let mut forged = without("email");
            forged.push((
                "email".to_string(),
                FfiValue::Passthrough(Box::new(s("a@x"))),
            ));
            let cases: Vec<(&str, FfiValue, Option<&str>, Reason)> = vec![
                ("not an object", s("x"), None, NotAnObject),
                (
                    "a batch row that is not an object",
                    FfiValue::Array(vec![s("x")]),
                    None,
                    NotAnObject,
                ),
                (
                    "a field missing",
                    FfiValue::Object(without("email")),
                    Some("email"),
                    FieldMissing,
                ),
                (
                    "a field given twice",
                    FfiValue::Object(repeated),
                    Some("age"),
                    FieldRepeated,
                ),
                (
                    "a field the plan does not name",
                    FfiValue::Object(extra),
                    Some("extra"),
                    UnknownField,
                ),
                (
                    "a value of another type",
                    FfiValue::Object(mistyped),
                    Some("age"),
                    FieldType,
                ),
                (
                    "a passthrough under a sealed field",
                    FfiValue::Object(forged),
                    Some("email"),
                    Passthrough,
                ),
            ];
            for (what, source, field, reason) in cases {
                let error = check_source(source, &plan).expect_err(what);
                expect(&error, "Source", field, reason);
            }
        }

        #[tokio::test]
        async fn a_stored_record_that_does_not_fit() {
            use Reason::*;
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();
            let sealed = || async { map(seal(&keyset, row(34), &plan).await) };

            let mut cases: Vec<(&str, StackCipherText, Option<&str>, Reason)> = Vec::new();

            let mut fields = sealed().await;
            let _ = node(&mut fields, "email");
            cases.push((
                "a field missing",
                CipherText::Map(fields),
                Some("email"),
                FieldMissing,
            ));

            let mut fields = sealed().await;
            let email = node(&mut fields, "email");
            fields.push(("email".to_string(), forged(FfiValue::UInt32(1))));
            fields.push(("email".to_string(), email));
            cases.push((
                "a field given twice",
                CipherText::Map(fields),
                Some("email"),
                FieldRepeated,
            ));

            let mut fields = sealed().await;
            let _ = node(&mut fields, "email");
            fields.push(("email".to_string(), forged(FfiValue::UInt32(1))));
            cases.push((
                "a field that is not an output map",
                CipherText::Map(fields),
                Some("email"),
                OutputsNotMap,
            ));

            let mut fields = sealed().await;
            let mut email = map(node(&mut fields, "email"));
            let _ = node(&mut email, "c");
            fields.push(("email".to_string(), CipherText::Map(email)));
            cases.push((
                "no ciphertext node",
                CipherText::Map(fields),
                Some("email"),
                NoCiphertextNode,
            ));

            let mut fields = sealed().await;
            let mut email = map(node(&mut fields, "email"));
            let _ = node(&mut email, "c");
            email.push(("c".to_string(), forged(FfiValue::UInt32(1))));
            fields.push(("email".to_string(), CipherText::Map(email)));
            cases.push((
                "a passthrough under c",
                CipherText::Map(fields),
                Some("email"),
                Passthrough,
            ));

            let mut fields = sealed().await;
            let mut id = map(node(&mut fields, "id"));
            let _ = node(&mut id, "passthrough");
            fields.push(("id".to_string(), CipherText::Map(id)));
            cases.push((
                "no passthrough node",
                CipherText::Map(fields),
                Some("id"),
                NoPassthroughNode,
            ));

            let fields = sealed().await;
            let mut first = fields;
            let mut age = map(node(&mut first, "age"));
            cases.push(("not a map", node(&mut age, "c"), None, NotAnObject));

            for (what, record, field, reason) in cases {
                let error = check_record(record, &plan, None).expect_err(what);
                expect(&error, "Record", field, reason);
            }
        }

        /// A binding switches on `as_str`, so no two reasons share a name.
        #[test]
        fn every_reason_has_a_distinct_snake_case_name() {
            let names: std::collections::BTreeSet<&str> =
                Reason::ALL.iter().map(|reason| reason.as_str()).collect();
            assert_eq!(names.len(), Reason::ALL.len(), "names are distinct");
            for reason in Reason::ALL {
                let name = reason.as_str();
                assert!(
                    name.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                    "{name}"
                );
                assert!(!reason.to_string().is_empty(), "{name}");
            }
        }

        /// Each refusal from the plan builder maps to the field it names and
        /// the reason a binding reports: the lowering checks most of these
        /// first, so not every one is reachable through [`plan`].
        #[test]
        fn every_plan_refusal_maps_to_its_field_and_reason() {
            use crate::PlanError as P;
            use Reason::*;
            let field = || "age".to_string();
            let some = |name: &str| Some(name.to_string());
            let cases: Vec<(crate::Error, Option<String>, Reason)> = vec![
                (crate::Error::Aead, None, Refused),
                (
                    P::ContextLabel(crate::LabelError::Empty).into(),
                    None,
                    ContextNotLabel,
                ),
                (
                    P::FieldLabel {
                        field: field(),
                        source: crate::LabelError::Empty,
                    }
                    .into(),
                    some("age"),
                    ContextNotLabel,
                ),
                (
                    P::DuplicateField { field: field() }.into(),
                    some("age"),
                    DuplicateField,
                ),
                (
                    P::SharedIdentity {
                        identity: "age".into(),
                        first: "age".into(),
                        second: "years".into(),
                    }
                    .into(),
                    some("years"),
                    SharedIdentity,
                ),
                (
                    P::PassthroughIndexed { field: field() }.into(),
                    some("age"),
                    PassthroughWithOutputs,
                ),
                (
                    P::DuplicateIndex {
                        at: field(),
                        index: "eq",
                    }
                    .into(),
                    some("age"),
                    DuplicateOutput,
                ),
                (P::EmptyIndexes.into(), None, NoOutputs),
                (
                    P::NotInPlan { field: field() }.into(),
                    some("age"),
                    UnknownField,
                ),
                (
                    P::NotInValue { field: field() }.into(),
                    some("age"),
                    FieldMissing,
                ),
                (
                    P::FieldType {
                        field: field(),
                        expected: "int64",
                    }
                    .into(),
                    some("age"),
                    FieldType,
                ),
                (
                    P::NoSuchField { field: field() }.into(),
                    some("age"),
                    NoSuchField,
                ),
                (
                    P::TargetWithVerbs { field: field() }.into(),
                    some("age"),
                    OutputsWithTarget,
                ),
                (
                    P::IndexNotDeclared {
                        field: field(),
                        index: "ore",
                    }
                    .into(),
                    some("age"),
                    Refused,
                ),
                (
                    P::IndexOptions {
                        field: field(),
                        declared: IndexSpec::Equality,
                        asked: IndexSpec::Equality,
                    }
                    .into(),
                    some("age"),
                    Refused,
                ),
                (P::IdentityWithoutField.into(), None, Refused),
                (P::MixedCiphers.into(), None, Refused),
                (
                    P::TwoContextSources {
                        first: "the plan",
                        second: "the call",
                    }
                    .into(),
                    None,
                    Refused,
                ),
                (P::NoContext.into(), None, Refused),
            ];
            for (error, field, reason) in cases {
                let shown = format!("{error:?}");
                assert_eq!(refusal(error), (field, reason), "{shown}");
            }
        }

        /// `in_field` names the field only where none is named yet.
        #[test]
        fn in_field_fills_only_an_unnamed_field() {
            let named = Error::bad_source(Reason::FieldType).in_field("age");
            assert_eq!(named.field(), Some("age"));
            assert_eq!(named.in_field("email").field(), Some("age"));
            assert!(Error::Internal.in_field("age").field().is_none());
        }
    }
}
