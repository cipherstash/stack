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
//! an integer, bytes, a one-element list) is refused as a plan a fields plan
//! cannot express.
//!
//! # What a field's `"type"` decides, and what it does not
//!
//! Every field lowered from data is a [`Value`]: its plaintext type is the
//! runtime value itself, and it seals in vitaminc's self-describing tagged
//! leaf encoding (`[tag] ++ payload`) whatever its declared `"type"`. The
//! type decides which indexes the field admits ([`admits`]), which values it
//! seals and which it opens to (checked by kind, both ways), and nothing
//! about the bytes: declaring a type on a field written without one changes
//! no leaf, so a binding that starts sending `"type"` (#1082) re-encrypts
//! nothing. A field's terms dispatch on each value's own variant to the
//! typed term operation, so they are the bytes a Rust `u32` or `String`
//! field derives under the same label.
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
//! recorded against #1082, not something the lowering can take on its own.
//!
//! # The stored record is wire format
//!
//! A record is stored as `field → { output-key → node }`: `"c"` is the
//! field's ciphertext, each term rides under its index key (`"eq"`,
//! `"match"`, `"ore"`, `"ope"`) as a passthrough byte node, and a passthrough
//! field rides under `"passthrough"`. A row written under one spelling is
//! read under the same spelling or not at all, so the keys are fixed here
//! and every binding agrees on them by construction.
//!
//! Under `"c"` a passthrough is refused in both directions, and that is
//! load-bearing: opening a passthrough retrieves no key and opens no AEAD,
//! it hands the payload back — so without the decrypt-side refusal an
//! attacker with write access to the stored tree could replace a field's
//! `"c"` subtree with a passthrough carrying forged plaintext and have it
//! reported as a successful decrypt. The encrypt-side refusal is what makes
//! that a round-trip invariant rather than data loss.

use vitaminc_aead_value::{FfiValue, ValueKind};

use super::{admits, utf8, Error, Scalar, Scope, TermBytes, Value};
use crate::plan::{FieldValues, FieldsBuilder, Opens, Runs};
use crate::target::{CallerContext, DeclaredContext, Decryption, Encrypted, IndexSpec};
use crate::{
    BoxedPassthrough, CipherText, ContextPiece, KeysetCipher, Label, NonEmpty, Pending,
    StackCipherText,
};

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

/// The verb a field's outputs lower to: one of the plan builder's four.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Verb {
    Encrypt,
    EncryptIndex,
    Index,
    Passthrough,
}

/// One field of a record plan: what to call it, what label to seal it
/// under, what to produce for it, and, optionally, what type its values are.
///
/// A field with a declared type (a [`ValueKind`]) admits only the indexes
/// that kind is defined for ([`admits`], checked when the plan is built),
/// seals only values of that kind and opens only to one (checked per value),
/// so the engine verifies what a binding hands it rather than trusting the
/// binding's tagging. A field with no declared type is dispatched on each
/// value's own type; see the [module docs](self#what-a-fields-type-decides).
#[derive(Clone, Debug)]
pub struct FieldPlan {
    name: String,
    context: NonEmpty<ContextPiece<'static>>,
    label: Label,
    extension: Vec<ContextPiece<'static>>,
    outputs: Vec<Output>,
    field_type: Option<ValueKind>,
}

impl FieldPlan {
    /// A field plan.
    ///
    /// `context` is the field's whole context as a binding spells it: its
    /// label, a list of at least two plain segments, extended by zero or more
    /// scalar parts nested to the left (see the
    /// [module docs](self#what-a-fields-context-must-be)). Build one from a
    /// value with [`super::context`](super::context()).
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] if `outputs` is empty, names an output twice (two
    /// outputs with the same [key](Output::key) are the same output — two
    /// match indexes under different options would both ride under
    /// `"match"`), or names [`Output::Passthrough`] beside another output;
    /// or if `context` is not a label of at least two segments, optionally
    /// extended.
    pub fn new(
        name: impl Into<String>,
        context: NonEmpty<ContextPiece<'static>>,
        outputs: Vec<Output>,
    ) -> Result<Self, Error> {
        if outputs.is_empty() {
            return Err(Error::Plan);
        }
        for (at, output) in outputs.iter().enumerate() {
            if outputs[..at]
                .iter()
                .any(|prior| prior.key() == output.key())
            {
                return Err(Error::Plan);
            }
        }
        if outputs.contains(&Output::Passthrough) && outputs.len() > 1 {
            return Err(Error::Plan);
        }
        let (label, extension) = split_context(context.get())?;
        if label.segments().len() < 2 {
            return Err(Error::Plan);
        }
        Ok(Self {
            name: name.into(),
            context,
            label,
            extension,
            outputs,
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
                    return Err(Error::Plan);
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
    /// extension: the plan's context, then the field's identity.
    pub fn label(&self) -> &Label {
        &self.label
    }

    /// The label segment the field's data is keyed under: the last segment
    /// of its label.
    pub fn identity(&self) -> &str {
        // A label has at least two segments by construction (`new`), so
        // this never falls back.
        self.label.segments().last().unwrap_or("")
    }

    /// What the field produces.
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
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
        if self.outputs.contains(&Output::Passthrough) {
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
        Label::new(prefix).map_err(|_| Error::Plan)
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
/// A list of plain text segments is the label. A two-element list whose
/// second element is a scalar is a context extended by that part, nested to
/// the left, so the first element is taken apart in turn. Anything else — a
/// bare part, a one-element list, a list mixing segments and other parts, a
/// part that is itself a list — is not a context a fields plan can give a
/// field.
fn split_context(piece: &ContextPiece<'_>) -> Result<(Label, Vec<ContextPiece<'static>>), Error> {
    let ContextPiece::List(parts) = piece else {
        return Err(Error::Plan);
    };
    if let Some(segments) = parts.iter().map(text_of).collect::<Option<Vec<&str>>>() {
        if segments.len() >= 2 {
            let label = Label::new(segments).map_err(|_| Error::Plan)?;
            return Ok((label, Vec::new()));
        }
    }
    match parts.as_slice() {
        [inner, part] if !matches!(part, ContextPiece::List(_)) => {
            let (label, mut extension) = split_context(inner)?;
            extension.push(part.clone().into_owned());
            Ok((label, extension))
        }
        _ => Err(Error::Plan),
    }
}

/// A record plan: the fields a record has, each with what to call it, what
/// label to seal it under, and what to produce for it.
///
/// Opaque, because the operations over a plan rely on properties of the
/// whole that no single [`FieldPlan`] can carry: there is at least one
/// field, no two fields share a name, every field's label sits under the
/// one plan context and carries the one extension, and the whole lowers to
/// a [`Plan`](crate::Plan) that builds. Both the parser ([`plan`]) and the
/// manual constructor ([`Plan::new`]) go through the one check, so a plan in
/// hand is a plan that holds them, whichever way it was built.
#[derive(Clone, Debug)]
pub struct Plan {
    context: Label,
    extension: Vec<ContextPiece<'static>>,
    fields: Vec<FieldPlan>,
}

impl Plan {
    /// A plan over `fields`, in the order given — which is the order of the
    /// fields in every result.
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] if `fields` is empty, names a field twice, has
    /// fields whose labels sit under different contexts or carry different
    /// extensions, or does not build as a fields plan: two sealed or indexed
    /// fields keyed under one identity, for instance, whose terms would be
    /// interchangeable.
    pub fn new(fields: Vec<FieldPlan>) -> Result<Self, Error> {
        let Some(first) = fields.first() else {
            return Err(Error::Plan);
        };
        let context = first.prefix()?;
        let extension = first.extension.clone();
        for (at, field) in fields.iter().enumerate() {
            if fields[..at].iter().any(|prior| prior.name == field.name) {
                return Err(Error::Plan);
            }
            if field.prefix()? != context || field.extension != extension {
                return Err(Error::Plan);
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
        let _ = plan.lower::<()>().map_err(|_| Error::Plan)?;
        Ok(plan)
    }

    /// The plan's fields, in result order. Never empty, and no two share a
    /// name.
    pub fn fields(&self) -> &[FieldPlan] {
        &self.fields
    }

    /// The plan's one context: the label every field's label extends.
    pub fn label(&self) -> &Label {
        &self.context
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
    /// into.
    fn lower<K: 'static>(&self) -> Result<crate::Plan<FieldValues, K>, crate::Error> {
        let mut builder = crate::Plan::context(self.context.clone()).fields::<FieldValues, K>();
        for field in &self.fields {
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
    }
}

/// Read a record plan from a decoded value.
///
/// The plan is an [`FfiValue::Object`]:
///
/// ```text
/// { <field>: { "context": <context>, "outputs": [ "c" | "passthrough" | <index>, ... ], "type": <type> }, ... }
/// ```
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
/// `"type"` is optional, and names a [`ValueKind`] (`"int64"`, `"string"`,
/// …; see [`ValueKind::name`]): vitaminc's vocabulary, not one of this
/// crate's. Declared, it is checked against the field's outputs here
/// ([`admits`]) and against every value sealed into or opened
/// from the field, and it decides the field's leaf encoding (see the
/// [module docs](self#what-a-fields-type-decides)).
///
/// **An indexed field without `"type"` is dispatched on each value's own
/// tag**, so for that field the engine trusts the binding to tag every value
/// the same way: a `34` sent once as a `Float64` and once as an `Int64` under
/// one `"ore"` field is accepted both times and stores two different terms.
/// This is transitional. It keeps the plans the Go binding sends today, which
/// carry no `"type"`, valid until that binding fills `"type"` from its struct
/// types; then `"type"` becomes required on every field with a term output
/// (#1082).
///
/// `<context>` is read by [`super::context`](super::context()) and must be
/// the field's label, optionally extended; the
/// [module docs](self#what-a-fields-context-must-be) give the shape.
///
/// # Examples
///
/// ```
/// use stack_encrypt::dynamic::{record, FfiValue, Output};
/// use stack_encrypt::target::IndexSpec;
///
/// // As a binding would decode it from its caller: seal `age` under the
/// // label users/age and index it for equality.
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
///     ]),
/// )]))?;
///
/// assert_eq!(plan.fields().len(), 1);
/// assert_eq!(plan.fields()[0].name(), "age");
/// assert_eq!(plan.label().to_string(), "users");
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
/// `"context"`, `"outputs"` and `"type"` or with one given twice, missing
/// `"context"` or `"outputs"`, an output list that is not a list of outputs
/// (above), is empty, names an output key twice or names `"passthrough"`
/// beside another output, a `"type"` that is not a string naming a
/// [`ValueKind`], a type that does not admit one of the field's index
/// outputs, a context that is not a label of at least two segments
/// (optionally extended), fields under different contexts or extensions,
/// or a plan the builder refuses ([`Plan::new`]). [`Error::Context`] for a
/// `"context"` that is present but is not a context at all, or renders
/// empty.
///
/// The transport codec refuses duplicate object keys before a binding's
/// value reaches here, but an [`FfiValue`] can be built with them directly
/// and this is a public parser, so it refuses them itself rather than
/// letting the last one win.
pub fn plan(value: FfiValue) -> Result<Plan, Error> {
    let FfiValue::Object(entries) = value else {
        return Err(Error::Plan);
    };
    let mut fields: Vec<FieldPlan> = Vec::with_capacity(entries.len());
    for (name, spec) in entries {
        let FfiValue::Object(spec) = spec else {
            return Err(Error::Plan);
        };
        let mut context: Option<NonEmpty<ContextPiece<'static>>> = None;
        let mut outputs: Option<Vec<Output>> = None;
        let mut field_type: Option<ValueKind> = None;
        for (key, value) in spec {
            match key.as_str() {
                "context" if context.is_none() => context = Some(super::context(value)?),
                "outputs" if outputs.is_none() => {
                    let FfiValue::Array(items) = value else {
                        return Err(Error::Plan);
                    };
                    let parsed = items
                        .iter()
                        .map(Output::from_value)
                        .collect::<Result<Vec<_>, _>>()?;
                    outputs = Some(parsed);
                }
                "type" if field_type.is_none() => {
                    let FfiValue::String(s) = &value else {
                        return Err(Error::Plan);
                    };
                    let name = utf8(s).ok_or(Error::Plan)?;
                    field_type = Some(name.parse().map_err(|_| Error::Plan)?);
                }
                // An unknown key, or one of the three given twice.
                _ => return Err(Error::Plan),
            }
        }
        let field = FieldPlan::new(
            name,
            context.ok_or(Error::Plan)?,
            outputs.ok_or(Error::Plan)?,
        )?;
        fields.push(match field_type {
            Some(field_type) => field.with_type(field_type)?,
            None => field,
        });
    }
    // The whole-plan rules are `Plan::new`'s, so a parsed plan and a
    // hand-built one are refused alike.
    Plan::new(fields)
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
/// [`check_source`], and it is where [`Error::Source`] and [`Error::Term`]
/// come from. What comes back is the plan's [`Pending`], with every term
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
///     ]),
/// )]))?;
///
/// let row = FfiValue::Object(vec![("age".to_string(), FfiValue::UInt32(34))]);
/// let sealed = record::encrypt(&keyset, row, &plan)?.await?;
///
/// // Only the ciphertext comes back; the term is one-way.
/// let opened = record::decrypt(Scope::Client(&cipher), sealed, &plan)?.await?;
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
/// [`Error::Source`] if the source does not fit the plan; [`Error::Term`]
/// if a value has no term the plan asks for. Both are decided here, before
/// the pending exists. A failure of the pending itself is the engine's.
pub fn encrypt<'a, K: 'static>(
    cipher: &'a KeysetCipher<'_, K>,
    source: FfiValue,
    plan: &Plan,
) -> Result<Pending<'a, StackCipherText, K>, Error> {
    let rows = source_rows(source, plan)?;
    let lowered = plan.lower::<K>().map_err(|_| Error::Internal)?;
    let extend = plan.declared_context();
    let shape = plan.shape();
    Ok(match rows {
        Rows::One(values) => {
            Runs::<FieldValues, K>::pending(&lowered, cipher, &values, None, extend)
                .try_map(move |values| shape_record(values, &shape))
        }
        Rows::Batch(rows) => Runs::<[FieldValues], K>::pending(
            &lowered, cipher, &rows, None, extend,
        )
        .try_map(move |rows| {
            rows.into_iter()
                .map(|values| shape_record(values, &shape))
                .collect::<Result<Vec<_>, _>>()
                .map(CipherText::Sequence)
        }),
    })
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
/// # Errors
///
/// [`Error::Record`] if the stored tree does not fit the plan, decided
/// here. A failure of the pending is the engine's: a wrong context, a wrong
/// key, a tampered ciphertext, a leaf from a keyset other than a
/// [`Scope::Keyset`]'s ([`Error::ForeignKeyset`](crate::Error::ForeignKeyset),
/// before any key is retrieved), or a typed field that opens to a value of
/// another kind than it declares ([`PlanError::FieldType`](crate::PlanError::FieldType)
/// — the type tag is inside the AEAD envelope, so only opening can see it).
pub fn decrypt<'a, K: 'static>(
    scope: Scope<'a, K>,
    record: StackCipherText,
    plan: &Plan,
) -> Result<Pending<'a, FfiValue, K>, Error> {
    let rows = record_rows(record, plan)?;
    let lowered = plan.lower::<K>().map_err(|_| Error::Internal)?;
    let extend = plan.declared_context();
    let shape = plan.shape();
    Ok(match rows {
        Rows::One(values) => run(
            scope,
            Opens::<FieldValues, K>::decryption(&lowered, values, None, extend),
        )
        .try_map(move |values| open_record(values, &shape)),
        Rows::Batch(rows) => run(
            scope,
            Opens::<Vec<FieldValues>, K>::decryption(&lowered, rows, None, extend),
        )
        .try_map(move |rows| {
            rows.into_iter()
                .map(|values| open_record(values, &shape))
                .collect::<Result<Vec<_>, _>>()
                .map(FfiValue::Array)
        }),
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
    let check = |values: &FieldValues| {
        Runs::<FieldValues, ()>::check(&lowered, values, None).map_err(|_| Error::Source)
    };
    match &rows {
        Rows::One(values) => check(values),
        Rows::Batch(rows) => rows.iter().try_for_each(check),
    }
}

/// Check a stored record against a plan without opening it — everything
/// [`decrypt`] checks before it builds its pending. See [`check_source`].
///
/// A typed field's declared type is not among them: the type is the sealed
/// leaf's tag, inside the AEAD envelope, so only awaiting [`decrypt`] can
/// check it.
///
/// # Errors
///
/// As [`decrypt`], minus the cipher.
pub fn check_record(record: StackCipherText, plan: &Plan) -> Result<(), Error> {
    let rows = record_rows(record, plan)?;
    let lowered = plan.lower::<()>().map_err(|_| Error::Internal)?;
    let check = |values: &FieldValues| {
        Opens::<FieldValues, ()>::check(&lowered, values, None).map_err(|_| Error::Record)
    };
    match &rows {
        Rows::One(values) => check(values),
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
    /// The error a tree that does not fit its plan reports.
    const MISFIT: Error;

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
    const MISFIT: Error = Error::Source;

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
    const MISFIT: Error = Error::Record;

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
enum Rows {
    One(FieldValues),
    Batch(Vec<FieldValues>),
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
fn check_tree<T: RecordTree>(tree: &T) -> Result<(), Error> {
    if tree.is_passthrough() {
        return Err(T::MISFIT);
    }
    match tree.children() {
        Children::Sequence(items) => items.iter().try_for_each(check_tree),
        Children::Map(entries) => {
            if !keys_are_unique(entries) {
                return Err(T::MISFIT);
            }
            entries.iter().try_for_each(|(_, node)| check_tree(node))
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
fn source_rows(source: FfiValue, plan: &Plan) -> Result<Rows, Error> {
    match source {
        FfiValue::Object(row) => Ok(Rows::One(source_row(row, plan)?)),
        FfiValue::Array(items) => Ok(Rows::Batch(
            items
                .into_iter()
                .map(|item| match item {
                    FfiValue::Object(row) => source_row(row, plan),
                    _ => Err(Error::Source),
                })
                .collect::<Result<Vec<_>, _>>()?,
        )),
        _ => Err(Error::Source),
    }
}

fn source_row(mut row: Vec<(String, FfiValue)>, plan: &Plan) -> Result<FieldValues, Error> {
    if row.len() != plan.fields.len() {
        return Err(Error::Source);
    }
    let mut values = FieldValues::new();
    for field in &plan.fields {
        let (_, value) = take(&mut row, &field.name).ok_or(Error::Source)?;
        check_field(&value, field)?;
        let _ = values.insert(&field.name, Value::new(value));
    }
    Ok(values)
}

/// A source value against its plan field: a typed field needs a value of
/// its type, every term output needs a scalar the scheme defines the term
/// for ([`IndexSpec::supports`]), and a ciphertext output refuses a
/// passthrough, or a repeated map key, anywhere in the value
/// ([`check_tree`]).
fn check_field(value: &FfiValue, field: &FieldPlan) -> Result<(), Error> {
    if let Some(declared) = field.field_type {
        if !declared.holds(value) {
            return Err(Error::Source);
        }
    }
    for output in &field.outputs {
        match output {
            Output::Ciphertext => check_tree(value)?,
            Output::Term(kind) => {
                let scalar = Scalar::of(value, kind)?;
                if !kind.supports(&scalar) {
                    return Err(Error::Term { kind: kind.clone() });
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
    shape: &[FieldShape],
) -> Result<StackCipherText, crate::Error> {
    let mut fields = Vec::with_capacity(shape.len());
    for field in shape {
        let outputs = match field.verb {
            Verb::Encrypt => {
                let ciphertext: StackCipherText = values.take(&field.name)?;
                vec![("c".to_string(), ciphertext)]
            }
            Verb::EncryptIndex => {
                let sealed: Encrypted<Vec<TermBytes>> = values.take(&field.name)?;
                let mut outputs = Vec::with_capacity(1 + field.keys.len());
                outputs.push(("c".to_string(), sealed.ciphertext));
                outputs.extend(keyed_terms(sealed.terms, &field.keys)?);
                outputs
            }
            Verb::Index => keyed_terms(values.take(&field.name)?, &field.keys)?,
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
    Ok(values.take::<Value>(name)?.into_inner())
}

/// The record the plan opened, as a value: the fields that come back, in
/// plan order, each checked against its declared kind. The tag is
/// authenticated, so a mismatch is not tampering: the row was sealed as
/// another type than the plan now declares.
fn open_record(mut values: FieldValues, shape: &[FieldShape]) -> Result<FfiValue, crate::Error> {
    let mut fields = Vec::with_capacity(shape.len());
    for field in shape.iter().filter(|field| field.verb != Verb::Index) {
        let value = take_leaf(&mut values, &field.name)?;
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
fn record_rows(tree: StackCipherText, plan: &Plan) -> Result<Rows, Error> {
    match tree {
        CipherText::Map(row) => Ok(Rows::One(record_row(row, plan)?)),
        CipherText::Sequence(items) => Ok(Rows::Batch(
            items
                .into_iter()
                .map(|item| match item {
                    CipherText::Map(row) => record_row(row, plan),
                    _ => Err(Error::Record),
                })
                .collect::<Result<Vec<_>, _>>()?,
        )),
        _ => Err(Error::Record),
    }
}

fn record_row(mut row: Vec<(String, StackCipherText)>, plan: &Plan) -> Result<FieldValues, Error> {
    let mut values = FieldValues::new();
    for field in plan.fields.iter().filter(|field| field.opens()) {
        let (_, node) = take(&mut row, &field.name).ok_or(Error::Record)?;
        let CipherText::Map(mut outputs) = node else {
            return Err(Error::Record);
        };
        match field.verb() {
            Verb::Passthrough => {
                let (_, node) = take(&mut outputs, "passthrough").ok_or(Error::Record)?;
                let CipherText::Passthrough(payload) = node else {
                    return Err(Error::Record);
                };
                let value = *payload.downcast::<FfiValue>().map_err(|_| Error::Record)?;
                if field.field_type.is_some_and(|kind| !kind.holds(&value)) {
                    return Err(Error::Record);
                }
                let _ = values.insert(&field.name, Value::new(value));
            }
            Verb::Encrypt | Verb::EncryptIndex | Verb::Index => {
                let (_, ciphertext) = take(&mut outputs, "c").ok_or(Error::Record)?;
                check_tree(&ciphertext)?;
                let _ = values.insert(&field.name, ciphertext);
            }
        }
    }
    Ok(values)
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
            ("age", spec(label("age"), &["c", "eq", "ore"])),
            ("email", spec(label("email"), &["c"])),
            ("nick", spec(label("nick"), &["match"])),
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
        decrypt(Scope::Client(cipher), record, plan)
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
            assert_eq!(plan.label().to_string(), "users", "the plan's one context");
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
                    matches!(e, Error::Plan)
                }),
                ("an empty plan", obj(vec![]), |e| matches!(e, Error::Plan)),
                (
                    "a field spec that is not an object",
                    obj(vec![("age", s("x"))]),
                    |e| matches!(e, Error::Plan),
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
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "a field spec with no context",
                    obj(vec![("age", obj(vec![("outputs", strings(&["c"]))]))]),
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "a field spec with no outputs",
                    obj(vec![("age", obj(vec![("context", label("age"))]))]),
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "outputs that are not a list",
                    obj(vec![("age", spec(label("age"), &[]))]),
                    |e| matches!(e, Error::Plan),
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
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "an unknown output",
                    obj(vec![("age", spec(label("age"), &["c", "sum"]))]),
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "an output named twice",
                    obj(vec![("age", spec(label("age"), &["c", "eq", "c"]))]),
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "passthrough beside a ciphertext",
                    obj(vec![("age", spec(label("age"), &["passthrough", "c"]))]),
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "passthrough beside an index",
                    obj(vec![("age", spec(label("age"), &["eq", "passthrough"]))]),
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "a field named twice",
                    FfiValue::Object(vec![
                        ("age".to_string(), spec(label("age"), &["c"])),
                        ("age".to_string(), spec(label("age"), &["eq"])),
                    ]),
                    |e| matches!(e, Error::Plan),
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
                    |e| matches!(e, Error::Plan),
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
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "a context that is not one",
                    obj(vec![("age", spec(FfiValue::Bool(true), &["c"]))]),
                    |e| matches!(e, Error::Context),
                ),
                (
                    "a context that renders empty",
                    obj(vec![("age", spec(s(""), &["c"]))]),
                    |e| matches!(e, Error::Context),
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
                assert!(matches!(result, Err(Error::Plan)), "{what}: {result:?}");
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
                matches!(parsed, Err(Error::Plan)),
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
                matches!(parsed, Err(Error::Plan)),
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
                matches!(parsed, Err(Error::Plan)),
                "two extensions: {parsed:?}"
            );
            // The same prefix spelled deeper is still one context.
            let parsed = plan(obj(vec![
                ("age", spec(strings(&["app", "users", "age"]), &["c"])),
                ("email", spec(strings(&["app", "users", "email"]), &["c"])),
            ]))
            .expect("one two-segment context");
            assert_eq!(parsed.label().to_string(), "app/users");
        }

        /// Two sealed fields keyed under one identity would have one context
        /// and interchangeable terms: the builder refuses it, so the plan does.
        #[test]
        fn refuses_two_fields_keyed_under_one_identity() {
            let parsed = plan(obj(vec![
                ("mail", spec(label("email"), &["c", "eq"])),
                ("mail2", spec(label("email"), &["c", "eq"])),
            ]));
            assert!(matches!(parsed, Err(Error::Plan)), "{parsed:?}");
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
                matches!(FieldPlan::new("age", ctx.clone(), vec![]), Err(Error::Plan)),
                "a field must produce something"
            );
            assert!(
                matches!(
                    FieldPlan::new(
                        "age",
                        ctx.clone(),
                        vec![Output::Term(IndexSpec::Ore), Output::Term(IndexSpec::Ore)]
                    ),
                    Err(Error::Plan)
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
                    Err(Error::Plan)
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
                matches!(parsed, Err(Error::Plan)),
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
            assert!(matches!(by_hand, Err(Error::Plan)), "and by hand alike");
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
                assert!(matches!(parsed, Err(Error::Plan)), "{label_}");
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
                matches!(Plan::new(vec![]), Err(Error::Plan)),
                "a plan must have a field"
            );
            assert!(
                matches!(
                    Plan::new(vec![field("age"), field("age")]),
                    Err(Error::Plan)
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
                    matches!(e, Error::Source)
                }),
                (
                    "a batch with an item that is not an object",
                    FfiValue::Array(vec![row(1), FfiValue::UInt32(2)]),
                    |e| matches!(e, Error::Source),
                ),
                (
                    "a row missing a plan field",
                    obj(vec![
                        ("age", FfiValue::UInt32(1)),
                        ("email", s("a@x")),
                        ("nick", s("al")),
                    ]),
                    |e| matches!(e, Error::Source),
                ),
                (
                    "a row with a field the plan does not name",
                    {
                        let mut entries = object(row(1));
                        entries.push(("extra".to_string(), s("x")));
                        FfiValue::Object(entries)
                    },
                    |e| matches!(e, Error::Source),
                ),
                (
                    "a row with a field the plan does not name in place of one it does",
                    {
                        let mut entries = object(row(1));
                        entries[3].0 = "extra".to_string();
                        FfiValue::Object(entries)
                    },
                    |e| matches!(e, Error::Source),
                ),
                (
                    "a passthrough under a sealed field",
                    {
                        let mut entries = object(row(1));
                        entries[1].1 = FfiValue::Passthrough(Box::new(s("a@x")));
                        FfiValue::Object(entries)
                    },
                    |e| matches!(e, Error::Source),
                ),
                (
                    "a passthrough inside a list under a sealed field",
                    FfiValue::Object(with_passthrough_in_a_list),
                    |e| matches!(e, Error::Source),
                ),
                (
                    "a plan field given twice",
                    {
                        let mut entries = object(row(1));
                        let _ = take(&mut entries, "nick");
                        entries.push(("age".to_string(), FfiValue::UInt32(2)));
                        FfiValue::Object(entries)
                    },
                    |e| matches!(e, Error::Source),
                ),
                (
                    "a repeated key inside an object under a sealed field",
                    {
                        let mut entries = object(row(1));
                        entries[1].1 = obj(vec![("k", s("a@x")), ("k", s("b@x"))]);
                        FfiValue::Object(entries)
                    },
                    |e| matches!(e, Error::Source),
                ),
                (
                    "a container under an indexed field",
                    {
                        let mut entries = object(row(1));
                        entries[2].1 = FfiValue::Array(vec![s("al")]);
                        FfiValue::Object(entries)
                    },
                    |e| {
                        matches!(
                            e,
                            Error::Term {
                                kind: IndexSpec::Match(_)
                            }
                        )
                    },
                ),
                (
                    "a scalar the scheme has no such term for",
                    {
                        let mut entries = object(row(1));
                        entries[2].1 = FfiValue::UInt32(3);
                        FfiValue::Object(entries)
                    },
                    |e| {
                        matches!(
                            e,
                            Error::Term {
                                kind: IndexSpec::Match(_)
                            }
                        )
                    },
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
                matches!(err, Some(Error::Source)),
                "encrypt refuses a row missing a plan field: {err:?}"
            );
            let mut entries = object(row(1));
            entries[1].1 = FfiValue::Passthrough(Box::new(s("a@x")));
            let err = encrypt(&keyset, FfiValue::Object(entries), &plan).err();
            assert!(
                matches!(err, Some(Error::Source)),
                "encrypt refuses a passthrough under a sealed field: {err:?}"
            );
            let mut entries = object(row(1));
            entries[2].1 = FfiValue::UInt32(3);
            let err = encrypt(&keyset, FfiValue::Object(entries), &plan).err();
            assert!(
                matches!(
                    err,
                    Some(Error::Term {
                        kind: IndexSpec::Match(_)
                    })
                ),
                "encrypt refuses a value with no such term: {err:?}"
            );
            assert_eq!(
                generates(&cipher),
                0,
                "a refused source costs no key request"
            );
        }

        #[tokio::test]
        async fn a_float_asked_for_equality_is_refused_as_that_kind() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan =
                plan(obj(vec![("score", spec(label("score"), &["c", "eq"]))])).expect("plan");
            let source = obj(vec![("score", FfiValue::Float64(1.5))]);
            let err = encrypt(&keyset, source, &plan).err();
            assert!(
                matches!(
                    err,
                    Some(Error::Term {
                        kind: IndexSpec::Equality
                    })
                ),
                "no PRF encoding exists for a float: {err:?}"
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
            let plan =
                plan(obj(vec![("age", spec(label("age"), &["ore", "c", "eq"]))])).expect("plan");
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

            let pending = decrypt(Scope::Client(&cipher), sealed, &plan).expect("fits");
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
                decrypt(Scope::Keyset(keyset.clone()), sealed, &plan)
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
            check_record(sealed, &plan).expect("check_record accepts it");

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
                spec(extended("age", &parts), &["c", "eq"]),
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
                let err = decrypt(Scope::Client(&cipher), record, &plan).err();
                assert!(
                    matches!(err, Some(Error::Record)),
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
            let err = check_record(CipherText::Map(fields), &plan).err();
            assert!(
                matches!(err, Some(Error::Record)),
                "check_record refuses a forged ciphertext the same way: {err:?}"
            );
            let mut fields = sealed(&keyset).await;
            let mut stale = sealed(&keyset).await;
            let mut age = map(node(&mut fields, "age"));
            let mut stale_age = map(node(&mut stale, "age"));
            age.push(("c".to_string(), node(&mut stale_age, "c")));
            fields.push(("age".to_string(), CipherText::Map(age)));
            let err = check_record(CipherText::Map(fields), &plan).err();
            assert!(
                matches!(err, Some(Error::Record)),
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
            let err = decrypt(Scope::Keyset(globex.clone()), sealed, &plan)
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
                decrypt(Scope::Keyset(acme.clone()), sealed, &plan)
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
                matches!(refused, Err(Error::Plan)),
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
                assert!(matches!(result, Err(Error::Plan)), "{label_}: {result:?}");
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
                Err(Error::Plan)
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
                matches!(check, Err(Error::Source)),
                "check_source refuses it too"
            );
            for (label_, value) in [
                ("a u32 for a uint64 field", FfiValue::UInt32(34)),
                ("a float for a uint64 field", FfiValue::Float64(34.0)),
                ("null for a uint64 field", FfiValue::Null),
            ] {
                let result = encrypt(&keyset, obj(vec![("age", value)]), &u64_plan).err();
                assert!(
                    matches!(result, Some(Error::Source)),
                    "{label_}: {result:?}"
                );
            }
            let as_u32 = age_plan("uint32");
            let result = encrypt(&keyset, obj(vec![("age", FfiValue::UInt64(34))]), &as_u32).err();
            assert!(
                matches!(result, Some(Error::Source)),
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
                matches!(result, Some(Error::Source)),
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
            let result = decrypt(Scope::Client(&cipher), sealed, &as_int64)
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
            check_record(sealed, &as_uint64).expect("the type is not visible without opening");

            let sealed = seal(&keyset, obj(vec![("age", FfiValue::UInt32(34))]), &untyped).await;
            let result = decrypt(Scope::Client(&cipher), sealed, &as_uint64)
                .expect("the shape fits")
                .await;
            assert!(
                matches!(result, Err(crate::Error::Plan(PlanError::FieldType { .. }))),
                "decrypt is where the type is checked: {:?}",
                result.err()
            );
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
            assert!(matches!(refused, Some(Error::Source)), "{refused:?}");
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
            let refused = decrypt(Scope::Client(&cipher), CipherText::Map(fields), &plan).err();
            assert!(matches!(refused, Some(Error::Record)), "{refused:?}");
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
            let result = decrypt(Scope::Client(&cipher), stored, &plan)
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
}
