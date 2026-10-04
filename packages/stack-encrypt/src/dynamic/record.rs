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
//! and one borrowed view of it — a single local in the row builder — drives
//! the field's ciphertext and every one of its terms. That is ADR-0004's
//! property. The typed path holds it with a type parameter threaded through
//! the declaration tree; this path has no tree to thread, sealing through
//! the cipher-directed `encrypt_with_aad` instead, so it holds it by one
//! variable: [`encrypt`] never has two contexts for a field in hand, so it
//! cannot seal the value under one and index it under another. That is
//! enforcement by shape rather than by type, and the tests here pin it — a
//! record's `"c"` opens under its plan context and its terms equal the
//! standalone derivation under that same context.
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

use super::{borrowed, term, utf8, Error, Scalar, Scope, TermKind};
use crate::target::Pending;
use crate::{
    BoxedPassthrough, CipherText, ContextPiece, Encrypt, KeysetCipher, NonEmpty, StackCipherText,
};

/// What a plan field asks for.
///
/// The strings are wire format twice over: they are how a binding spells an
/// output, *and* the keys of the per-field output map in the stored result.
/// That is why this enum is exhaustive — see the [module docs](super#stability).
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
    context: NonEmpty<ContextPiece<'static>>,
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
        context: NonEmpty<ContextPiece<'static>>,
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
    pub fn context(&self) -> &NonEmpty<ContextPiece<'static>> {
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
    fn view(&self) -> Result<NonEmpty<ContextPiece<'_>>, Error> {
        // The proof was made when the plan was built, so re-taking it over
        // the same tree cannot fail.
        NonEmpty::new(borrowed(self.context.get())).map_err(|_| Error::Internal)
    }
}

/// A record plan: the fields a record has, each with what to call it, what
/// context to bind it under, and what to produce for it.
///
/// Opaque, because the operations over a plan rely on two properties of the
/// whole that no single [`FieldPlan`] can carry: there is at least one
/// field, and no two fields share a name. With a repeated name the source
/// check would accept a row that names the field once, and [`encrypt`]
/// would write a map with the same key twice — a stored record no reader
/// can take apart. Both the parser ([`plan`]) and the manual constructor
/// ([`Plan::new`]) go through the one check, so a plan in hand is a plan
/// that holds them, whichever way it was built.
#[derive(Clone, Debug)]
pub struct Plan {
    fields: Vec<FieldPlan>,
}

impl Plan {
    /// A plan over `fields`, in the order given — which is the order of the
    /// fields in every result.
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] if `fields` is empty or names a field twice.
    pub fn new(fields: Vec<FieldPlan>) -> Result<Self, Error> {
        if fields.is_empty() {
            return Err(Error::Plan);
        }
        for (at, field) in fields.iter().enumerate() {
            if fields[..at].iter().any(|prior| prior.name == field.name) {
                return Err(Error::Plan);
            }
        }
        Ok(Self { fields })
    }

    /// The plan's fields, in result order. Never empty, and no two share a
    /// name.
    pub fn fields(&self) -> &[FieldPlan] {
        &self.fields
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
/// # Examples
///
/// ```
/// use stack_encrypt::dynamic::{record, FfiValue, Output, TermKind};
///
/// // As a binding would decode it from its caller: seal `age` under
/// // "users/age" and index it for equality.
/// let plan = record::plan(FfiValue::Object(vec![(
///     "age".to_string(),
///     FfiValue::Object(vec![
///         ("context".to_string(), FfiValue::String("users/age".into())),
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
/// assert_eq!(
///     plan.fields()[0].outputs(),
///     [Output::Ciphertext, Output::Term(TermKind::Equality)]
/// );
/// # Ok::<(), stack_encrypt::dynamic::Error>(())
/// ```
///
/// # Errors
///
/// [`Error::Plan`] for a plan that is not an object of field specs, an
/// empty plan, a field named twice, a spec with a key other than
/// `"context"` and `"outputs"` or with either given twice or missing, or
/// an output list that is not a list of known output names, is empty, or
/// names an output twice. [`Error::Context`] for a `"context"` that is
/// present but is not a context, or renders empty.
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
        for (key, value) in spec {
            match key.as_str() {
                "context" if context.is_none() => context = Some(super::context(value)?),
                "outputs" if outputs.is_none() => {
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
                // An unknown key, or one of the two given twice.
                _ => return Err(Error::Plan),
            }
        }
        fields.push(FieldPlan::new(
            name,
            context.ok_or(Error::Plan)?,
            outputs.ok_or(Error::Plan)?,
        )?);
    }
    // The whole-plan rules — non-empty, no name twice — are `Plan::new`'s,
    // so a parsed plan and a hand-built one are refused alike.
    Plan::new(fields)
}

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
/// // Seal `age` under "users/age" with an equality term beside it.
/// let plan = record::plan(FfiValue::Object(vec![(
///     "age".to_string(),
///     FfiValue::Object(vec![
///         ("context".to_string(), FfiValue::String("users/age".into())),
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
/// let sealed = record::encrypt(&keyset, row, &plan).await?;
///
/// // Only the ciphertext comes back; the term is one-way.
/// let opened = record::decrypt(Scope::Client(&cipher), sealed, &plan).await?;
/// let FfiValue::Object(fields) = opened else {
///     unreachable!("one record opens to one object");
/// };
/// assert!(matches!(&fields[..], [(name, FfiValue::UInt32(34))] if name == "age"));
/// # Ok::<(), stack_encrypt::dynamic::Error>(())
/// # }).unwrap();
/// ```
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
    plan: &Plan,
) -> Result<StackCipherText, Error>
where
    K: DataKeySource + Sync,
{
    let Rows { rows, batched } = source_rows(source, plan)?;

    // Build every row: terms derive now (local), ciphertexts queue their
    // data-key requests into one flat pending list.
    let mut pendings: Vec<Pending<'_, StackCipherText, K>> = Vec::new();
    let mut skeletons: Vec<Vec<FieldSkeleton>> = Vec::with_capacity(rows.len());
    for row in rows {
        skeletons.push(build_row(cipher, row, plan, &mut pendings).await?);
    }

    // The one batched key request for the whole invocation.
    let mut sealed = Settled::of(Pending::all(cipher, pendings).await?);

    // Fill the ciphertext slots back in, in build order.
    let row_nodes = skeletons
        .into_iter()
        .map(|skeleton| {
            let fields = skeleton
                .into_iter()
                .map(|field| {
                    let nodes = field
                        .outputs
                        .into_iter()
                        .map(|(key, slot)| {
                            let node = match slot {
                                Slot::Term(term) => CipherText::Passthrough(Box::new(
                                    FfiValue::Bytes(Protected::new(term)),
                                )
                                    as BoxedPassthrough),
                                Slot::Ciphertext => sealed.next()?,
                            };
                            Ok((key.to_string(), node))
                        })
                        .collect::<Result<Vec<_>, Error>>()?;
                    Ok((field.name, CipherText::Map(nodes)))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            Ok(CipherText::Map(fields))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    sealed.finish()?;

    Rows {
        rows: row_nodes,
        batched,
    }
    .reshape(CipherText::Sequence)
}

/// Decrypt a record — or a batch — produced by [`encrypt`] under the same
/// plan.
///
/// Only the `"c"` outputs participate: terms are one-way. The result is an
/// [`FfiValue::Object`] per record holding the plan's ciphertext-bearing
/// fields, in plan order — or an [`FfiValue::Array`] of them for a batch.
/// One batched `retrieve_keys` per invocation and, when opening through
/// [`Scope::Client`], one per keyset the leaves were sealed under.
///
/// # Errors
///
/// [`Error::Record`] if the stored tree does not fit the plan;
/// [`Error::Cipher`] if opening fails — including the expected outcome for
/// a wrong context, a wrong key, a tampered ciphertext, or a leaf from a
/// keyset other than a [`Scope::Keyset`]'s.
pub async fn decrypt<K>(
    scope: Scope<'_, K>,
    record: StackCipherText,
    plan: &Plan,
) -> Result<FfiValue, Error>
where
    K: DataKeySource + Sync + 'static,
{
    let Rows { rows, batched } = record_leaves(record, plan)?;
    let contexts = plan
        .fields
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
            // The scope is the caller's, the declaration is the target's:
            // `decrypt_as` takes one context and drives both halves with it.
            pendings.push(match &scope {
                Scope::Client(cipher) => cipher.decrypt_as(ct, context.into()),
                Scope::Keyset(keyset) => keyset.decrypt_as(ct, context.into()),
            });
            row_names.push(name);
        }
        names.push(row_names);
    }

    // The one batched key request for the whole invocation.
    let mut values = Settled::of(match &scope {
        Scope::Client(cipher) => Pending::all(*cipher, pendings).await,
        Scope::Keyset(keyset) => Pending::all(keyset, pendings).await,
    }?);

    let row_values = names
        .into_iter()
        .map(|row_names| {
            let entries = row_names
                .into_iter()
                .map(|name| Ok((name, values.next()?)))
                .collect::<Result<Vec<_>, Error>>()?;
            Ok(FfiValue::Object(entries))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    values.finish()?;

    Rows {
        rows: row_values,
        batched,
    }
    .reshape(FfiValue::Array)
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
pub fn check_source(source: FfiValue, plan: &Plan) -> Result<(), Error> {
    source_rows(source, plan).map(drop)
}

/// Check a stored record against a plan without opening it — everything
/// [`decrypt`] checks before it consults the cipher. See [`check_source`].
///
/// # Errors
///
/// As [`decrypt`], minus the cipher.
pub fn check_record(record: StackCipherText, plan: &Plan) -> Result<(), Error> {
    record_leaves(record, plan).map(drop)
}

// =============================================================================
// The two trees a record path walks
// =============================================================================

/// The two trees a record path walks — a source ([`FfiValue`]) and a stored
/// record ([`StackCipherText`]) — seen the one way the path needs to see
/// them: as one row (a map of named nodes) or a sequence of rows, and as a
/// tree that may carry a passthrough somewhere inside it.
trait RecordTree: Sized {
    /// The error a tree that does not fit its plan reports.
    const MISFIT: Error;

    /// The tree as a row's entries, a batch's rows, or neither.
    fn shape(self) -> Shape<Self>;

    /// Whether this node is a passthrough.
    fn is_passthrough(&self) -> bool;

    /// The node's children, for a container.
    fn children(&self) -> Children<'_, Self>;
}

/// A tree read as rows.
enum Shape<T> {
    /// One row: its named entries.
    Row(Vec<(String, T)>),
    /// A batch: its rows, each still to be read as one.
    Batch(Vec<T>),
    /// Neither.
    Other,
}

/// A node's children.
enum Children<'a, T> {
    Sequence(&'a [T]),
    Map(&'a [(String, T)]),
    None,
}

impl RecordTree for FfiValue {
    const MISFIT: Error = Error::Source;

    fn shape(self) -> Shape<Self> {
        match self {
            FfiValue::Object(entries) => Shape::Row(entries),
            FfiValue::Array(items) => Shape::Batch(items),
            _ => Shape::Other,
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
    const MISFIT: Error = Error::Record;

    fn shape(self) -> Shape<Self> {
        match self {
            CipherText::Map(entries) => Shape::Row(entries),
            CipherText::Sequence(items) => Shape::Batch(items),
            _ => Shape::Other,
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

/// The rows of a call — one record, or a batch of them — carried with
/// whether they came as a batch, so the result takes the shape the input
/// had.
struct Rows<T> {
    rows: Vec<T>,
    batched: bool,
}

/// Each row of `tree`, as its named entries: one row for a map, one per item
/// for a sequence of maps, and the tree's misfit error for anything else.
fn rows<V: RecordTree>(tree: V) -> Result<Rows<Vec<(String, V)>>, Error> {
    match tree.shape() {
        Shape::Row(entries) => Ok(Rows {
            rows: vec![entries],
            batched: false,
        }),
        Shape::Batch(items) => Ok(Rows {
            rows: items
                .into_iter()
                .map(|item| match item.shape() {
                    Shape::Row(entries) => Ok(entries),
                    _ => Err(V::MISFIT),
                })
                .collect::<Result<Vec<_>, Error>>()?,
            batched: true,
        }),
        Shape::Other => Err(V::MISFIT),
    }
}

impl<T> Rows<T> {
    fn try_map<U>(self, f: impl FnMut(T) -> Result<U, Error>) -> Result<Rows<U>, Error> {
        Ok(Rows {
            rows: self
                .rows
                .into_iter()
                .map(f)
                .collect::<Result<Vec<_>, Error>>()?,
            batched: self.batched,
        })
    }

    /// The rows in the shape the input had: `batch` over all of them for a
    /// batch, the one row bare otherwise.
    fn reshape(self, batch: impl FnOnce(Vec<T>) -> T) -> Result<T, Error> {
        let Rows { mut rows, batched } = self;
        if batched {
            Ok(batch(rows))
        } else {
            rows.pop().ok_or(Error::Internal)
        }
    }
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
/// only once the value reaches it: on the encrypt side that is after the
/// plan check has passed, where a failure reads as this module's own bug,
/// and on the decrypt side after the row's keys have been requested. A
/// `check_source`/`check_record` that let such a tree through would say
/// "well-formed" of a value the operation then refuses, so the walk refuses
/// it here, as the misfit it is.
///
/// On the passthrough half: on the encrypt side a source field value with one inside it must not
/// reach a `"c"` slot: a passthrough node is *unauthenticated by definition*
/// — on decrypt it hands its payload back with no AEAD opened — so admitting
/// one under a field the plan declares ciphertext-bearing would quietly
/// produce a slot whose bytes verify nothing. On the decrypt side a `"c"`
/// subtree with one inside it is the load-bearing half: `decrypt_as`
/// collects **zero** retrieve-requests for a passthrough and returns its
/// payload with no AEAD opened, so an attacker with write access to the
/// stored tree could replace a field's `"c"` subtree with a passthrough
/// carrying forged plaintext, and this check's absence would report it as a
/// successful decrypt. [`encrypt`] never produces a passthrough under `"c"`,
/// so the shape is unconditionally an error, and the encrypt-side check is
/// what makes that a round-trip invariant rather than data loss.
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
// Encrypt side
// =============================================================================

/// The rows of a record source, each aligned to the plan's field order, with
/// everything that can be checked without a cipher checked: the source is
/// one object or an array of objects, every plan field is present exactly
/// once in every row and no row carries a field the plan does not name
/// (silently dropping a field on either side would lose data or index
/// nothing), and each value fits its field's outputs ([`check_field`]).
fn source_rows(source: FfiValue, plan: &Plan) -> Result<Rows<Vec<FfiValue>>, Error> {
    rows(source)?.try_map(|mut row| {
        if row.len() != plan.fields.len() {
            return Err(Error::Source);
        }
        plan.fields
            .iter()
            .map(|field| {
                let (_, value) = take(&mut row, &field.name).ok_or(Error::Source)?;
                check_field(&value, field)?;
                Ok(value)
            })
            .collect()
    })
}

/// A source value against its plan field: every term output needs a scalar
/// the scheme defines the term for ([`TermKind::supports`]), and a
/// ciphertext output refuses a passthrough, or a repeated map key, anywhere
/// in the value ([`check_tree`]).
fn check_field(value: &FfiValue, field: &FieldPlan) -> Result<(), Error> {
    for output in &field.outputs {
        match output {
            Output::Ciphertext => check_tree(value)?,
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

/// One field of a built row: its name and, per output in plan order, the
/// key and what fills it.
struct FieldSkeleton {
    name: String,
    outputs: Vec<(&'static str, Slot)>,
}

/// What fills an output slot: a term, derived as the row was built, or the
/// ciphertext still pending in the row's batch, filled in build order once
/// the batch settles.
enum Slot {
    Term(Vec<u8>),
    Ciphertext,
}

/// The values a batch settled to, handed back one per slot in build order.
/// The count has to come out exact — a slot with no value, or a value with
/// no slot, means the merge miscounted, which is a bug here.
struct Settled<T>(std::vec::IntoIter<T>);

impl<T> Settled<T> {
    fn of(values: Vec<T>) -> Self {
        Self(values.into_iter())
    }

    fn next(&mut self) -> Result<T, Error> {
        self.0.next().ok_or(Error::Internal)
    }

    fn finish(mut self) -> Result<(), Error> {
        match self.0.next() {
            Some(_) => Err(Error::Internal),
            None => Ok(()),
        }
    }
}

/// Build one record row: derive its terms and queue its ciphertext pendings,
/// returning the row skeleton. The plan drives the iteration so the output
/// field order is the plan's; the row arrives from [`source_rows`] already
/// in that order and checked against the plan.
async fn build_row<'c, K>(
    cipher: &'c KeysetCipher<'_, K>,
    row: Vec<FfiValue>,
    plan: &Plan,
    pendings: &mut Vec<Pending<'c, StackCipherText, K>>,
) -> Result<Vec<FieldSkeleton>, Error>
where
    K: DataKeySource + Sync,
{
    // A row `source_rows` did not align is a bug here, not caller input.
    if row.len() != plan.fields.len() {
        return Err(Error::Internal);
    }
    let mut skeleton = Vec::with_capacity(plan.fields.len());
    for (field, value) in plan.fields.iter().zip(row) {
        let name = field.name.clone();
        // The one context this field has, cloned per output: this variable
        // is what reaches the ciphertext and every term (ADR-0004), and
        // there is no other.
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

        let mut outputs = Vec::with_capacity(field.outputs.len());
        for output in &field.outputs {
            let Output::Term(kind) = output else {
                outputs.push((output.key(), Slot::Ciphertext));
                continue;
            };
            let scalar = scalar.clone().ok_or(Error::Internal)?;
            outputs.push((
                output.key(),
                Slot::Term(term(cipher, scalar, *kind, context.clone()).await?),
            ));
        }

        if field.has_ciphertext() {
            // Re-checked here so this function's own contract does not rest
            // on its caller's: with the tree checked, the cipher's refusals
            // (a passthrough, a repeated key) cannot fire, and a failure
            // below is a bug here.
            check_tree(&value)?;
            let tree = value
                .encrypt_with_aad(cipher, context.clone())
                .map_err(|_| Error::Internal)?;
            pendings.push(tree.into_pending(cipher, context));
        }

        skeleton.push(FieldSkeleton { name, outputs });
    }
    Ok(skeleton)
}

// =============================================================================
// Decrypt side
// =============================================================================

/// The `"c"` subtrees a record tree holds for the plan's ciphertext-bearing
/// fields, per row in plan order, with the row's field name: the tree is one
/// map or a sequence of maps, each such field is present exactly once, is a
/// map of outputs with exactly one `"c"` node, and that node has no
/// passthrough and no repeated key in it ([`check_tree`]). Terms and fields
/// the plan does not name are ignored (comparands, not ciphertext).
#[allow(clippy::type_complexity)]
fn record_leaves(
    tree: StackCipherText,
    plan: &Plan,
) -> Result<Rows<Vec<(String, StackCipherText)>>, Error> {
    rows(tree)?.try_map(|mut row| {
        plan.fields
            .iter()
            .filter(|field| field.has_ciphertext())
            .map(|field| {
                let (name, node) = take(&mut row, &field.name).ok_or(Error::Record)?;
                let Shape::Row(mut outputs) = node.shape() else {
                    return Err(Error::Record);
                };
                let (_, ct) = take(&mut outputs, Output::Ciphertext.key()).ok_or(Error::Record)?;
                check_tree(&ct)?;
                Ok((name, ct))
            })
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use stack_kms::{
        DataKey, DataKeyWithTag, FakeDataKeySource, GenerateKeyPayload, IdentifiedBy, IndexKey,
        IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
    };
    use uuid::Uuid;
    use vitaminc_protected::Controlled;

    use crate::dynamic::context;
    use crate::{nonempty, StackCipher};

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

    fn spec(context: FfiValue, outputs: &[&str]) -> FfiValue {
        obj(vec![("context", context), ("outputs", strings(outputs))])
    }

    /// The plan most tests share: `age` sealed and indexed for equality and
    /// order under `"users/age"`; `email` sealed alone under an extended
    /// context; `nick` indexed for match only, never sealed.
    fn plan_value() -> FfiValue {
        obj(vec![
            ("age", spec(s("users/age"), &["c", "eq", "ore"])),
            (
                "email",
                spec(
                    FfiValue::Array(vec![s("users/email"), FfiValue::UInt64(7)]),
                    &["c"],
                ),
            ),
            ("nick", spec(s("users/nick"), &["match"])),
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
        ])
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

    fn text_of(value: &FfiValue) -> String {
        match value {
            FfiValue::String(s) => String::from_utf8(s.risky_ref().to_vec()).expect("utf8"),
            _ => panic!("expected text"),
        }
    }

    fn forged(value: FfiValue) -> StackCipherText {
        CipherText::Passthrough(Box::new(value) as BoxedPassthrough)
    }

    /// `Settled` is exact both ways: a slot with no value and a value with
    /// no slot are both the merge miscounting, reported as `Internal`.
    #[test]
    fn settled_values_must_match_their_slots_exactly() {
        let mut settled = Settled::of(vec![1]);
        assert!(matches!(settled.next(), Ok(1)));
        assert!(
            matches!(settled.next(), Err(Error::Internal)),
            "a slot with no value"
        );
        assert!(Settled::of(Vec::<u8>::new()).finish().is_ok());
        assert!(
            matches!(Settled::of(vec![1]).finish(), Err(Error::Internal)),
            "a value with no slot"
        );
    }

    /// A table row: what is refused, the value that must be refused, and
    /// the error it must be refused with. `Error` is not `PartialEq`, so the
    /// expectation is a predicate.
    type Refused = (&'static str, FfiValue, fn(&Error) -> bool);

    mod given_a_plan_value {
        use super::*;

        #[test]
        fn parses_each_field_in_order_with_its_context_and_outputs() {
            let plan = the_plan();
            assert_eq!(
                plan.fields()
                    .iter()
                    .map(FieldPlan::name)
                    .collect::<Vec<_>>(),
                ["age", "email", "nick"],
                "fields keep the plan's order"
            );
            assert_eq!(
                plan.fields()[0].outputs(),
                [
                    Output::Ciphertext,
                    Output::Term(TermKind::Equality),
                    Output::Term(TermKind::Ore)
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
                [Output::Term(TermKind::Match)],
                "a field can be indexed and never sealed"
            );
            assert!(
                plan.fields()[0].has_ciphertext()
                    && plan.fields()[1].has_ciphertext()
                    && !plan.fields()[2].has_ciphertext(),
                "has_ciphertext follows the outputs"
            );
            assert_eq!(
                plan.fields()[1].context(),
                &context(FfiValue::Array(vec![s("users/email"), FfiValue::UInt64(7)]))
                    .expect("context"),
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
                            ("context", s("users/age")),
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
                    obj(vec![("age", obj(vec![("context", s("users/age"))]))]),
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "outputs that are not a list",
                    obj(vec![("age", spec(s("users/age"), &[]))]),
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "an output that is not a string",
                    obj(vec![(
                        "age",
                        obj(vec![
                            ("context", s("users/age")),
                            ("outputs", FfiValue::Array(vec![FfiValue::UInt32(1)])),
                        ]),
                    )]),
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "an unknown output",
                    obj(vec![("age", spec(s("users/age"), &["c", "sum"]))]),
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "an output named twice",
                    obj(vec![("age", spec(s("users/age"), &["c", "eq", "c"]))]),
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "a field named twice",
                    FfiValue::Object(vec![
                        ("age".to_string(), spec(s("users/age"), &["c"])),
                        ("age".to_string(), spec(s("users/age"), &["eq"])),
                    ]),
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "a context given twice",
                    obj(vec![(
                        "age",
                        obj(vec![
                            ("context", s("users/age")),
                            ("outputs", strings(&["c"])),
                            ("context", s("users/other")),
                        ]),
                    )]),
                    |e| matches!(e, Error::Plan),
                ),
                (
                    "outputs given twice",
                    obj(vec![(
                        "age",
                        obj(vec![
                            ("context", s("users/age")),
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

        #[test]
        fn a_field_plan_refuses_no_outputs_and_a_repeated_output() {
            let ctx = context(s("users/age")).expect("context");
            assert!(
                matches!(FieldPlan::new("age", ctx.clone(), vec![]), Err(Error::Plan)),
                "a field must produce something"
            );
            assert!(
                matches!(
                    FieldPlan::new(
                        "age",
                        ctx.clone(),
                        vec![Output::Term(TermKind::Ore), Output::Term(TermKind::Ore)]
                    ),
                    Err(Error::Plan)
                ),
                "an output cannot be produced twice under one key"
            );
            assert!(
                FieldPlan::new("age", ctx, vec![Output::Ciphertext]).is_ok(),
                "one output is a plan"
            );
        }

        /// The whole-plan rules hold for a plan built by hand, not only for
        /// a parsed one: a hand-built plan reaches the same `encrypt` and
        /// `check_source`, which rely on them.
        #[test]
        fn a_hand_built_plan_refuses_no_fields_and_a_repeated_name() {
            let field = |name: &str| {
                FieldPlan::new(
                    name,
                    context(s("users/age")).expect("context"),
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

        /// `check_source` is the parser `encrypt` runs, so a binding's
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
                    obj(vec![("age", FfiValue::UInt32(1)), ("email", s("a@x"))]),
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
                                kind: TermKind::Match
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
                                kind: TermKind::Match
                            }
                        )
                    },
                ),
            ];
            // A value is consumed by the call that checks it, so the table
            // exercises the boundary parser and the operation is exercised
            // below on the shapes a caller is likeliest to get wrong.
            for (label, source, expected) in cases {
                let err = check_source(source, &plan).err();
                assert!(
                    err.as_ref().is_some_and(expected),
                    "{label}: check_source must refuse it as the right error: {err:?}"
                );
            }
            let missing = obj(vec![("age", FfiValue::UInt32(1)), ("email", s("a@x"))]);
            let err = encrypt(&keyset, missing, &plan).await.err();
            assert!(
                matches!(err, Some(Error::Source)),
                "encrypt refuses a row missing a plan field: {err:?}"
            );
            let mut entries = object(row(1));
            entries[1].1 = FfiValue::Passthrough(Box::new(s("a@x")));
            let err = encrypt(&keyset, FfiValue::Object(entries), &plan)
                .await
                .err();
            assert!(
                matches!(err, Some(Error::Source)),
                "encrypt refuses a passthrough under a sealed field: {err:?}"
            );
            let mut entries = object(row(1));
            entries[2].1 = FfiValue::UInt32(3);
            let err = encrypt(&keyset, FfiValue::Object(entries), &plan)
                .await
                .err();
            assert!(
                matches!(
                    err,
                    Some(Error::Term {
                        kind: TermKind::Match
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
                plan(obj(vec![("score", spec(s("users/score"), &["c", "eq"]))])).expect("plan");
            let source = obj(vec![("score", FfiValue::Float64(1.5))]);
            let err = encrypt(&keyset, source, &plan).await.err();
            assert!(
                matches!(
                    err,
                    Some(Error::Term {
                        kind: TermKind::Equality
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
        async fn seals_it_from_one_key_request_in_the_plan_shape() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();

            let sealed = encrypt(&keyset, row(34), &plan).await.expect("encrypt");
            assert_eq!(
                generates(&cipher),
                1,
                "every ciphertext leaf seals from one batched key request"
            );

            let mut fields = map(sealed);
            assert_eq!(
                keys(&fields),
                ["age", "email", "nick"],
                "the result holds every plan field, in plan order"
            );
            let mut age = map(node(&mut fields, "age"));
            assert_eq!(
                keys(&age),
                ["c", "eq", "ore"],
                "a field's outputs ride under their keys, in output order"
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
        }

        /// ADR-0004's property, pinned: the ciphertext opens under the plan
        /// context and under nothing else, and each term is the standalone
        /// derivation under that same context.
        #[tokio::test]
        async fn binds_the_ciphertext_and_every_term_under_the_one_plan_context() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();
            let age_ctx = plan.fields()[0].context().clone();
            let nick_ctx = plan.fields()[2].context().clone();

            let mut fields = map(encrypt(&keyset, row(34), &plan).await.expect("encrypt"));
            let mut age = map(node(&mut fields, "age"));
            let mut nick = map(node(&mut fields, "nick"));

            let opened: FfiValue = cipher
                .decrypt(node(&mut age, "c"), age_ctx.clone())
                .await
                .expect("the ciphertext opens under the plan context");
            assert_eq!(u32_of(&opened), 34, "and to the value that was sealed");

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
                TermKind::Equality,
                age_ctx.clone(),
            )
            .await
            .expect("standalone equality term");
            assert_eq!(
                term_bytes(&node(&mut age, "eq")),
                eq,
                "the equality term is the standalone derivation under the plan context"
            );
            let ore = term(&keyset, Scalar::U32(34), TermKind::Ore, age_ctx)
                .await
                .expect("standalone ore term");
            assert_eq!(
                term_bytes(&node(&mut age, "ore")),
                ore,
                "the ore term is the standalone derivation under the plan context"
            );
            let scalar = Scalar::of(&s("al smith"), TermKind::Match).expect("text");
            let matched = term(&keyset, scalar, TermKind::Match, nick_ctx)
                .await
                .expect("standalone match term");
            assert_eq!(
                term_bytes(&node(&mut nick, "match")),
                matched,
                "the match term is the standalone derivation under the plan context"
            );
        }

        #[tokio::test]
        async fn opens_back_to_its_ciphertext_bearing_fields_in_plan_order() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();
            let sealed = encrypt(&keyset, row(34), &plan).await.expect("encrypt");

            let opened = decrypt(Scope::Client(&cipher), sealed, &plan)
                .await
                .expect("decrypt");
            assert_eq!(
                retrieves(&cipher),
                1,
                "every ciphertext leaf opens from one batched key request"
            );
            let fields = object(opened);
            assert_eq!(
                keys(&fields),
                ["age", "email"],
                "only the sealed fields come back, in plan order; terms are one-way"
            );
            assert_eq!(u32_of(&fields[0].1), 34, "the age round-trips");
            assert_eq!(text_of(&fields[1].1), "a@x", "the email round-trips");

            // Through the keyset it was sealed under, too.
            let sealed = encrypt(&keyset, row(35), &plan).await.expect("encrypt");
            let fields = object(
                decrypt(Scope::Keyset(keyset.clone()), sealed, &plan)
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
            let sealed = encrypt(&keyset, source(), &plan).await.expect("encrypt");
            check_record(sealed, &plan).expect("check_record accepts it");

            let sealed = encrypt(&keyset, source(), &plan).await.expect("encrypt");
            let fields = object(
                decrypt(Scope::Client(&cipher), sealed, &plan)
                    .await
                    .expect("decrypt"),
            );
            let email = object(fields.into_iter().nth(1).expect("the email field").1);
            assert_eq!(keys(&email), ["home", "work"]);
            assert_eq!(text_of(&email[0].1), "a@x");
            assert_eq!(text_of(&email[1].1), "b@x");
        }
    }

    mod given_a_batch {
        use super::*;

        #[tokio::test]
        async fn seals_every_row_from_one_key_request_and_opens_as_an_array() {
            let cipher = cipher().await;
            let keyset = cipher.default_keyset();
            let plan = the_plan();

            let sealed = encrypt(
                &keyset,
                FfiValue::Array(vec![row(1), row(2), row(3)]),
                &plan,
            )
            .await
            .expect("encrypt");
            assert_eq!(generates(&cipher), 1, "one key request for the whole batch");

            let rows = sequence(sealed);
            assert_eq!(rows.len(), 3, "a batch seals to a sequence of rows");
            let opened = decrypt(Scope::Client(&cipher), CipherText::Sequence(rows), &plan)
                .await
                .expect("decrypt");
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
            let sealed = encrypt(&keyset, FfiValue::Array(vec![]), &plan)
                .await
                .expect("an empty batch seals");
            assert!(
                matches!(&sealed, CipherText::Sequence(rows) if rows.is_empty()),
                "an empty batch seals to an empty sequence"
            );
            let opened = decrypt(Scope::Client(&cipher), sealed, &plan)
                .await
                .expect("an empty batch opens");
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
            map(encrypt(keyset, row(34), &the_plan())
                .await
                .expect("encrypt"))
        }

        /// The forged-plaintext case the module docs call load-bearing is
        /// in here: a passthrough under `"c"` must be refused, because
        /// `decrypt_as` would otherwise hand its payload back as if opened.
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
            for (label, record) in cases {
                let err = decrypt(Scope::Client(&cipher), record, &plan).await.err();
                assert!(
                    matches!(err, Some(Error::Record)),
                    "{label}: decrypt must refuse it as a misfit record: {err:?}"
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

            let opened = object(
                decrypt(Scope::Client(&cipher), CipherText::Map(fields), &plan)
                    .await
                    .expect("decrypt"),
            );
            assert_eq!(keys(&opened), ["age", "email"], "the sealed fields open");
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

            let sealed = encrypt(&acme, row(34), &plan).await.expect("encrypt");
            let err = decrypt(Scope::Keyset(globex.clone()), sealed, &plan)
                .await
                .err();
            assert!(
                matches!(
                    err,
                    Some(Error::Cipher(crate::Error::ForeignKeyset { expected, found }))
                        if expected == globex.keyset_id() && found == acme.keyset_id()
                ),
                "another tenant's keyset refuses the leaf, naming both keysets: {err:?}"
            );
            assert_eq!(
                retrieves(&cipher),
                0,
                "refused before any key was retrieved"
            );

            let sealed = encrypt(&acme, row(34), &plan).await.expect("encrypt");
            let opened = object(
                decrypt(Scope::Keyset(acme.clone()), sealed, &plan)
                    .await
                    .expect("its own keyset opens it"),
            );
            assert_eq!(u32_of(&opened[0].1), 34, "to what was sealed");

            let sealed = encrypt(&acme, row(34), &plan).await.expect("encrypt");
            let opened = object(
                decrypt(Scope::Client(&cipher), sealed, &plan)
                    .await
                    .expect("the client opens a leaf from any of its keysets"),
            );
            assert_eq!(u32_of(&opened[0].1), 34, "to what was sealed");
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

    /// The typed helper the tests lean on, pinned in passing: `nonempty!`
    /// and `context` agree, so a test written against either is the same
    /// test.
    #[test]
    fn the_plan_context_is_the_typed_context() {
        use crate::IntoAad;
        assert_eq!(
            the_plan().fields()[0]
                .context()
                .clone()
                .into_inner()
                .into_aad()
                .as_bytes(),
            nonempty!("users/age").into_aad().as_bytes(),
            "a bare plan string is the typed literal"
        );
    }
}
