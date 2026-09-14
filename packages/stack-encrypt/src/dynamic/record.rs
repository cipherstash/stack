//! Records: the runtime form of `#[derive(EncryptFrom)]`.
//!
//! A *plan* says, per field, which encryption context to bind and which
//! outputs to produce; the source supplies the field values. That is the
//! same job the derive does from a struct definition, done from data — which
//! is all a binding has.
//!
//! However many rows and fields are in one call, all ciphertext leaves seal
//! from **one** batched `generate_keys`: the pendings are merged before
//! settling, exactly like the derive's `zip`/`all` composition. Index terms
//! are *not* in that batch — [`encrypt`] settles each term as it builds the
//! row, which under the local HMAC backend is no ZeroKMS traffic at all, and
//! under a backend that derives terms at ZeroKMS would be one round trip per
//! term until the term pendings are merged into the row's batch. That is a
//! change for this module when such a backend lands, not something the
//! record path promises today.
//!
//! # One context per field, both halves
//!
//! A field's context is proven [`NonEmpty`] once, when the plan is built,
//! and the same context drives the field's ciphertext and every one of its
//! terms. That is ADR-0004's property, held here by construction rather than
//! by a bound: [`encrypt`] never sees two contexts for one field, so it
//! cannot seal the value under one and index it under another.
//!
//! A plan context is the *whole* context of its field. There is no caller
//! context to extend it with, so the plan spells the extension itself: a
//! bare string matches a Rust record sealed with `encrypt_into` (no caller
//! context); a list matches one sealed with `encrypt_into_with_context` —
//! see [`super::context`](super::context()) for which list spells which Rust
//! context. Rows are readable across the two however they were sealed,
//! provided the plan names the context the row was sealed under.
//!
//! # Terms ride as passthrough
//!
//! A term is a comparand, not a ciphertext to open, and passthrough is its
//! honest encoding: the result tree carries each term as a
//! [`CipherText::Passthrough`] byte node beside the field's `"c"` subtree.
//! Under `"c"` itself a passthrough is refused in both directions, and that
//! is load-bearing: `decrypt_as` collects **zero** retrieve-requests for a
//! passthrough and returns its payload with no AEAD opened, so without the
//! decrypt-side refusal an attacker with write access to the stored tree
//! could replace a field's `"c"` subtree with a passthrough carrying forged
//! plaintext and have it reported as a successful decrypt.

use stack_kms::DataKeySource;
use vitaminc_aead_value::FfiValue;
use vitaminc_protected::Protected;

use super::{borrowed, term, utf8, Error, Opener, Scalar, TermKind};
use crate::target::Pending;
use crate::{
    AadPiece, BoxedPassthrough, CipherText, Encrypt, KeysetCipher, NonEmpty, StackCipherText,
};

/// What a plan field asks for.
///
/// The strings are wire format twice over: they are how a binding spells an
/// output, *and* the keys of the per-field output map in the stored result.
/// See the [module docs](super) on stability.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Output {
    /// `"c"` — the field's [`StackCipherText`].
    Ciphertext,
    /// An index term: `"eq"`, `"match"`, `"ore"` or `"ope"`.
    Term(TermKind),
}

impl Output {
    /// The output a key names, or `None` for a key that is not one.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "c" => Output::Ciphertext,
            "eq" => Output::Term(TermKind::Equality),
            "match" => Output::Term(TermKind::Match),
            "ore" => Output::Term(TermKind::Ore),
            "ope" => Output::Term(TermKind::Ope),
            _ => return None,
        })
    }

    /// The map key this output rides under.
    pub fn key(self) -> &'static str {
        match self {
            Output::Ciphertext => "c",
            Output::Term(kind) => kind.key(),
        }
    }
}

/// One field of a record plan: what to call it, what context to bind it
/// under, and what to produce for it.
#[derive(Clone, Debug)]
pub struct FieldPlan {
    name: String,
    context: NonEmpty<AadPiece<'static>>,
    outputs: Vec<Output>,
}

impl FieldPlan {
    /// A field plan.
    ///
    /// The context is a proven [`NonEmpty`] because that proof has to happen
    /// somewhere and here is the last place it can: the cipher-directed path
    /// [`encrypt`] seals through accepts any AAD, so nothing downstream
    /// would stop an empty context from being sealed under — and opening
    /// goes through `decrypt_as`, which would then never open it. Build one
    /// from a value with [`super::context`](super::context()).
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] if `outputs` is empty or names an output twice.
    pub fn new(
        name: impl Into<String>,
        context: NonEmpty<AadPiece<'static>>,
        outputs: Vec<Output>,
    ) -> Result<Self, Error> {
        if outputs.is_empty() {
            return Err(Error::Plan);
        }
        for (at, output) in outputs.iter().enumerate() {
            if outputs[..at].contains(output) {
                return Err(Error::Plan);
            }
        }
        Ok(Self {
            name: name.into(),
            context,
            outputs,
        })
    }

    /// The field's name — its key in the source and in the result.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The context this field binds under, on both halves.
    pub fn context(&self) -> &NonEmpty<AadPiece<'static>> {
        &self.context
    }

    /// What the field produces.
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    /// Whether the field has a ciphertext to seal and open.
    pub fn has_ciphertext(&self) -> bool {
        self.outputs.contains(&Output::Ciphertext)
    }

    /// A borrowed view of the context, so one proof serves every output of
    /// every row without copying the payloads.
    fn view(&self) -> Result<NonEmpty<AadPiece<'_>>, Error> {
        // The proof was made when the plan was built, so re-taking it over
        // the same tree cannot fail.
        NonEmpty::new(borrowed(self.context.get())).map_err(|_| Error::Internal)
    }
}

/// Read a record plan from a decoded value.
///
/// The plan is an [`FfiValue::Object`]:
///
/// ```text
/// { <field>: { "context": <context>, "outputs": [ "c" | "eq" | "match" | "ore" | "ope", ... ] }, ... }
/// ```
///
/// `<context>` is defined once, in [`super::context`](super::context()): a
/// string, bytes, an integer, or a list of those, with what each spells in
/// Rust and the emptiness rule.
///
/// # Errors
///
/// [`Error::Plan`] for an empty plan, a missing or malformed context, an
/// empty, unknown or duplicated output list, or an unknown key.
/// [`Error::Context`] for a context that is malformed or empty. Field names
/// are unique by construction — the transport codec rejects duplicate object
/// keys before this sees them.
pub fn plan(value: FfiValue) -> Result<Vec<FieldPlan>, Error> {
    let FfiValue::Object(entries) = value else {
        return Err(Error::Plan);
    };
    if entries.is_empty() {
        return Err(Error::Plan);
    }
    entries
        .into_iter()
        .map(|(name, spec)| {
            let FfiValue::Object(spec) = spec else {
                return Err(Error::Plan);
            };
            let mut context: Option<NonEmpty<AadPiece<'static>>> = None;
            let mut outputs: Option<Vec<Output>> = None;
            for (key, value) in spec {
                match key.as_str() {
                    "context" => context = Some(super::context(value)?),
                    "outputs" => {
                        let FfiValue::Array(items) = value else {
                            return Err(Error::Plan);
                        };
                        let mut parsed = Vec::with_capacity(items.len());
                        for item in &items {
                            let FfiValue::String(s) = item else {
                                return Err(Error::Plan);
                            };
                            let key = utf8(s).ok_or(Error::Plan)?;
                            parsed.push(Output::parse(key).ok_or(Error::Plan)?);
                        }
                        outputs = Some(parsed);
                    }
                    _ => return Err(Error::Plan),
                }
            }
            FieldPlan::new(
                name,
                context.ok_or(Error::Plan)?,
                outputs.ok_or(Error::Plan)?,
            )
        })
        .collect()
}

/// A row's assembled outputs, ciphertext slots still pending: the terms are
/// derived (locally), and each `None` is filled from the settled ciphertexts
/// in build order.
type RowSkeleton = Vec<(String, Vec<(&'static str, Option<Vec<u8>>)>)>;

/// Encrypt a record — or a batch of records — per a plan.
///
/// `source` is an [`FfiValue::Object`] of `{ field: scalar }` (one record),
/// or an [`FfiValue::Array`] of such objects (a batch). Every plan field
/// must be present in each record, and every record field must be named by
/// the plan — silently dropping a field on either side would lose data or
/// index nothing.
///
/// The result is per record a map of `field → { output-key → node }`, where
/// `"c"` is the field's sealed ciphertext subtree and each term rides as a
/// passthrough byte node. A batch is a sequence of such maps.
///
/// # Cross-language note
///
/// A `"c"` leaf seals the aead-value *tagged* plaintext encoding (`[type
/// tag] ++ payload`), because that tag table is the contract the bindings
/// share. A Rust `#[derive(EncryptFrom)]` over a plain primitive — a bare
/// `u32` — seals four untagged bytes instead, so a plain-primitive Rust
/// derive and a plan do **not** interchange ciphertexts for the same field
/// until the Rust side uses aead-value's tagged types too. This is by
/// design, not a defect in either side.
///
/// # Errors
///
/// [`Error::Source`] if the source does not fit the plan; [`Error::Term`]
/// if a value has no term the plan asks for; [`Error::Cipher`] if sealing
/// or deriving fails.
pub async fn encrypt<K>(
    cipher: &KeysetCipher<'_, K>,
    source: FfiValue,
    plan: &[FieldPlan],
) -> Result<StackCipherText, Error>
where
    K: DataKeySource + Sync,
{
    let (rows, batched) = source_rows(source, plan)?;

    // Build every row: terms derive now (local), ciphertexts queue their
    // data-key requests into one flat pending list.
    let mut pendings: Vec<Pending<'_, StackCipherText, K>> = Vec::new();
    let mut skeletons: Vec<RowSkeleton> = Vec::with_capacity(rows.len());
    for row in rows {
        skeletons.push(build_row(cipher, row, plan, &mut pendings).await?);
    }

    // The one batched key request for the whole invocation.
    let sealed = Pending::all(cipher, pendings).await?;
    let mut sealed = sealed.into_iter();

    // Fill the ciphertext slots back in, in build order.
    let mut row_nodes = Vec::with_capacity(skeletons.len());
    for skeleton in skeletons {
        let mut fields = Vec::with_capacity(skeleton.len());
        for (field, outputs) in skeleton {
            let mut nodes = Vec::with_capacity(outputs.len());
            for (key, slot) in outputs {
                let node = match slot {
                    Some(term) => CipherText::Passthrough(Box::new(FfiValue::Bytes(Protected::new(
                        term,
                    )))
                        as BoxedPassthrough),
                    None => sealed.next().ok_or(Error::Internal)?,
                };
                nodes.push((key.to_string(), node));
            }
            fields.push((field, CipherText::Map(nodes)));
        }
        row_nodes.push(CipherText::Map(fields));
    }
    if sealed.next().is_some() {
        return Err(Error::Internal);
    }

    if batched {
        Ok(CipherText::Sequence(row_nodes))
    } else {
        row_nodes.pop().ok_or(Error::Internal)
    }
}

/// Decrypt a record — or a batch — produced by [`encrypt`] under the same
/// plan.
///
/// Only the `"c"` outputs participate: terms are one-way. The result is an
/// [`FfiValue::Object`] per record holding the plan's ciphertext-bearing
/// fields, in plan order — or an [`FfiValue::Array`] of them for a batch.
/// One batched `retrieve_keys` per invocation and, when opening through
/// [`Opener::Any`], one per keyset the leaves were sealed under.
///
/// # Errors
///
/// [`Error::Record`] if the stored tree does not fit the plan;
/// [`Error::Cipher`] if opening fails — including the expected outcome for
/// a wrong context, a wrong key or a tampered ciphertext.
pub async fn decrypt<K>(
    opener: Opener<'_, K>,
    record: StackCipherText,
    plan: &[FieldPlan],
) -> Result<FfiValue, Error>
where
    K: DataKeySource + Sync + 'static,
{
    let (rows, batched) = record_leaves(record, plan)?;
    let contexts = plan
        .iter()
        .filter(|field| field.has_ciphertext())
        .map(FieldPlan::view)
        .collect::<Result<Vec<_>, Error>>()?;

    // Per row, per ciphertext-bearing plan field (in plan order, as
    // `record_leaves` lifted them): queue the "c" subtree's decrypt.
    let mut pendings: Vec<Pending<'_, FfiValue, K>> = Vec::new();
    let mut names: Vec<Vec<String>> = Vec::with_capacity(rows.len());
    for row in rows {
        if row.len() != contexts.len() {
            return Err(Error::Internal);
        }
        let mut row_names = Vec::with_capacity(row.len());
        for ((name, ct), context) in row.into_iter().zip(&contexts) {
            let context = context.clone();
            // The scope is the opener's, the declaration is the target's:
            // `decrypt_as` takes one context and drives both halves with it.
            pendings.push(match &opener {
                Opener::Any(cipher) => cipher.decrypt_as(ct, context.into()),
                Opener::Only(keyset) => keyset.decrypt_as(ct, context.into()),
            });
            row_names.push(name);
        }
        names.push(row_names);
    }

    // The one batched key request for the whole invocation.
    let values = match &opener {
        Opener::Any(cipher) => Pending::all(*cipher, pendings).await,
        Opener::Only(keyset) => Pending::all(keyset, pendings).await,
    }?;
    let mut values = values.into_iter();

    let mut row_values = Vec::with_capacity(names.len());
    for row_names in names {
        let mut entries = Vec::with_capacity(row_names.len());
        for name in row_names {
            entries.push((name, values.next().ok_or(Error::Internal)?));
        }
        row_values.push(FfiValue::Object(entries));
    }
    if values.next().is_some() {
        return Err(Error::Internal);
    }

    if batched {
        Ok(FfiValue::Array(row_values))
    } else {
        row_values.pop().ok_or(Error::Internal)
    }
}

/// Check a source against a plan without encrypting it — everything
/// [`encrypt`] checks before it consults the cipher.
///
/// A binding runs this at its boundary so a malformed call fails the same
/// way whether or not a cipher is available, and never costs a keyset load.
/// It is the same parser [`encrypt`] runs, so the two cannot disagree on
/// what is malformed.
///
/// # Errors
///
/// As [`encrypt`], minus the cipher.
pub fn check_source(source: FfiValue, plan: &[FieldPlan]) -> Result<(), Error> {
    source_rows(source, plan).map(drop)
}

/// Check a stored record against a plan without opening it — everything
/// [`decrypt`] checks before it consults the cipher. See [`check_source`].
///
/// # Errors
///
/// As [`decrypt`], minus the cipher.
pub fn check_record(record: StackCipherText, plan: &[FieldPlan]) -> Result<(), Error> {
    record_leaves(record, plan).map(drop)
}

/// The rows of a record source, each aligned to the plan's field order, with
/// everything that can be checked without a cipher checked: the source is
/// one object or an array of objects, every plan field is present in every
/// row and no row carries a field the plan does not name (silently dropping
/// a field on either side would lose data or index nothing), and each value
/// fits its field's outputs ([`check_field`]). The `bool` is whether the
/// source was a batch.
fn source_rows(source: FfiValue, plan: &[FieldPlan]) -> Result<(Vec<Vec<FfiValue>>, bool), Error> {
    let (rows, batched) = match source {
        FfiValue::Object(entries) => (vec![entries], false),
        FfiValue::Array(items) => {
            let rows = items
                .into_iter()
                .map(|item| match item {
                    FfiValue::Object(entries) => Ok(entries),
                    _ => Err(Error::Source),
                })
                .collect::<Result<Vec<_>, Error>>()?;
            (rows, true)
        }
        _ => return Err(Error::Source),
    };
    let rows = rows
        .into_iter()
        .map(|mut row| {
            if row.len() != plan.len() {
                return Err(Error::Source);
            }
            plan.iter()
                .map(|field| {
                    let at = row
                        .iter()
                        .position(|(name, _)| name == &field.name)
                        .ok_or(Error::Source)?;
                    let (_, value) = row.swap_remove(at);
                    check_field(&value, field)?;
                    Ok(value)
                })
                .collect::<Result<Vec<_>, Error>>()
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok((rows, batched))
}

/// A source value against its plan field: every term output needs a scalar
/// the scheme defines the term for ([`TermKind::supports`]), and a
/// ciphertext output refuses a passthrough anywhere in the value
/// ([`reject_passthrough_value`]).
fn check_field(value: &FfiValue, field: &FieldPlan) -> Result<(), Error> {
    for output in &field.outputs {
        match output {
            Output::Ciphertext => reject_passthrough_value(value)?,
            Output::Term(kind) => {
                let scalar = Scalar::of(value, *kind)?;
                if !kind.supports(&scalar) {
                    return Err(Error::Term { kind: *kind });
                }
            }
        }
    }
    Ok(())
}

/// The `"c"` subtrees a record tree holds for the plan's ciphertext-bearing
/// fields, per row in plan order, with the row's field name: the tree is one
/// map or a sequence of maps, each such field is present, is a map of
/// outputs with a `"c"` node, and that node is not a passthrough
/// ([`reject_passthrough_tree`]). Terms and fields the plan does not name
/// are ignored (comparands, not ciphertext). The `bool` is whether the tree
/// was a batch.
#[allow(clippy::type_complexity)]
fn record_leaves(
    tree: StackCipherText,
    plan: &[FieldPlan],
) -> Result<(Vec<Vec<(String, StackCipherText)>>, bool), Error> {
    let (rows, batched) = match tree {
        CipherText::Map(entries) => (vec![entries], false),
        CipherText::Sequence(items) => {
            let rows = items
                .into_iter()
                .map(|item| match item {
                    CipherText::Map(entries) => Ok(entries),
                    _ => Err(Error::Record),
                })
                .collect::<Result<Vec<_>, Error>>()?;
            (rows, true)
        }
        _ => return Err(Error::Record),
    };
    let rows = rows
        .into_iter()
        .map(|mut row| {
            plan.iter()
                .filter(|field| field.has_ciphertext())
                .map(|field| {
                    let at = row
                        .iter()
                        .position(|(name, _)| name == &field.name)
                        .ok_or(Error::Record)?;
                    let (name, node) = row.swap_remove(at);
                    let CipherText::Map(outputs) = node else {
                        return Err(Error::Record);
                    };
                    let ct = outputs
                        .into_iter()
                        .find_map(|(key, node)| (key == "c").then_some(node))
                        .ok_or(Error::Record)?;
                    reject_passthrough_tree(&ct)?;
                    Ok((name, ct))
                })
                .collect::<Result<Vec<_>, Error>>()
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok((rows, batched))
}

/// Build one record row: derive its terms and queue its ciphertext pendings,
/// returning the row skeleton. The plan drives the iteration so the output
/// field order is the plan's; the row arrives from [`source_rows`] already
/// in that order and checked against the plan.
async fn build_row<'c, K>(
    cipher: &'c KeysetCipher<'_, K>,
    row: Vec<FfiValue>,
    plan: &[FieldPlan],
    pendings: &mut Vec<Pending<'c, StackCipherText, K>>,
) -> Result<RowSkeleton, Error>
where
    K: DataKeySource + Sync,
{
    // A row `source_rows` did not align is a bug here, not caller input.
    if row.len() != plan.len() {
        return Err(Error::Internal);
    }
    let mut skeleton = Vec::with_capacity(plan.len());
    for (field, value) in plan.iter().zip(row) {
        let name = field.name.clone();
        // One borrowed view of the field's context, cloned per output: the
        // same context reaches the ciphertext and every term (ADR-0004).
        let context = field.view()?;

        // Terms first — they lift a copy of the scalar; the value itself is
        // consumed by the ciphertext path below. One lift serves every term
        // output: the kind only names which error a non-scalar reports.
        let scalar = field
            .outputs
            .iter()
            .find_map(|o| match o {
                Output::Term(kind) => Some(*kind),
                Output::Ciphertext => None,
            })
            .map(|kind| Scalar::of(&value, kind))
            .transpose()?;

        let mut outputs: Vec<(&'static str, Option<Vec<u8>>)> =
            Vec::with_capacity(field.outputs.len());
        for output in &field.outputs {
            let Output::Term(kind) = output else {
                outputs.push((output.key(), None));
                continue;
            };
            let scalar = scalar.clone().ok_or(Error::Internal)?;
            outputs.push((
                output.key(),
                Some(term(cipher, scalar, *kind, context.clone()).await?),
            ));
        }

        if field.has_ciphertext() {
            reject_passthrough_value(&value)?;
            let tree = value
                .encrypt_with_aad(cipher, context.clone())
                .map_err(|_| Error::Internal)?;
            pendings.push(tree.into_pending(cipher, context));
        }

        skeleton.push((name, outputs));
    }
    Ok(skeleton)
}

/// Reject a source field value that contains a passthrough anywhere, before
/// it reaches a `"c"` slot.
///
/// A passthrough node is *unauthenticated by definition* — on decrypt it
/// hands its payload back with no AEAD opened — so admitting one under a
/// field the plan declares ciphertext-bearing would quietly produce a slot
/// whose bytes verify nothing. Rejecting it here is what makes
/// [`reject_passthrough_tree`]'s mirror-image rejection a round-trip
/// invariant rather than data loss.
fn reject_passthrough_value(value: &FfiValue) -> Result<(), Error> {
    match value {
        FfiValue::Passthrough(_) => Err(Error::Source),
        FfiValue::Array(items) => items.iter().try_for_each(reject_passthrough_value),
        FfiValue::Object(entries) => entries
            .iter()
            .try_for_each(|(_, v)| reject_passthrough_value(v)),
        _ => Ok(()),
    }
}

/// Reject a `"c"` subtree that contains a passthrough anywhere.
///
/// This is the decrypt-side half of [`reject_passthrough_value`], and it is
/// load-bearing: `decrypt_as` collects **zero** retrieve-requests for a
/// passthrough and returns its payload with no AEAD opened, so an attacker
/// with write access to the stored tree could replace a field's `"c"`
/// subtree with a passthrough carrying forged plaintext, and this function's
/// absence would report it as a successful decrypt. [`encrypt`] never
/// produces a passthrough under `"c"`, so the shape is unconditionally an
/// error.
fn reject_passthrough_tree(tree: &StackCipherText) -> Result<(), Error> {
    match tree {
        CipherText::Passthrough(_) => Err(Error::Record),
        CipherText::Sequence(items) => items.iter().try_for_each(reject_passthrough_tree),
        CipherText::Map(entries) => entries
            .iter()
            .try_for_each(|(_, v)| reject_passthrough_tree(v)),
        CipherText::Single(_)
        | CipherText::None(_)
        | CipherText::EmptySequence(_)
        | CipherText::EmptyMap(_) => Ok(()),
    }
}
