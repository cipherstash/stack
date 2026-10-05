//! Saved plans: the chain without the value, validated once at `build()`,
//! and how each lowers to the combinators in [`target`](crate::target).
use std::any::{type_name, TypeId};
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use super::values::{Field, Fields, Slot};
use super::{FieldValues, PlanError};
use crate::target::{
    ciphertext, indexed, inspect, open, passthrough, AeadContext, Borrowed, DeclaredContext,
    DecryptInto, Decryption, Encrypted, Encryption, IndexSpec, Indexes, Pending,
};
use crate::{Error, KeysetCipher, Label, LabelError, NonEmpty, StackCipherText};

/// A context a plan is declared under: a [`Label`], or text parsed as one.
///
/// A plan's context is a name, so it is a label of plain segments:
/// `"users"`, or `"documents/v2/body"`, which is three segments and renders
/// in the ZeroKMS log exactly as written. Text that is not a plain label is
/// kept and refused when the plan is built ([`PlanError::ContextLabel`]),
/// so a chain reads straight through and fails in one place.
pub trait IntoLabel {
    /// The label, or why the text is not one.
    fn into_label(self) -> Result<Label, LabelError>;
}
impl IntoLabel for Label {
    fn into_label(self) -> Result<Label, LabelError> {
        Ok(self)
    }
}
impl IntoLabel for &Label {
    fn into_label(self) -> Result<Label, LabelError> {
        Ok(self.clone())
    }
}
impl IntoLabel for &str {
    fn into_label(self) -> Result<Label, LabelError> {
        Label::parse(self)
    }
}
impl IntoLabel for String {
    fn into_label(self) -> Result<Label, LabelError> {
        Label::parse(&self)
    }
}

/// What a field of a fields plan does with its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FieldKind {
    /// Sealed, with no index: [`encrypt`](FieldsBuilder::encrypt).
    Encrypt,
    /// Sealed, with indexes beside the ciphertext:
    /// [`encrypt_index`](FieldsBuilder::encrypt_index).
    EncryptIndex,
    /// Indexes alone, no ciphertext: [`index`](FieldsBuilder::index).
    Index,
    /// Carried unsealed and unauthenticated:
    /// [`passthrough`](FieldsBuilder::passthrough).
    Passthrough,
}

/// One field of a built [`Plan`]: its name, the label it is sealed and
/// indexed under, and what it declares. What a query takes
/// ([`Plan::field`]), so a query is derived under exactly the label the
/// write used, and asking for an index the field never declared is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldPlan {
    name: Arc<str>,
    label: Label,
    kind: FieldKind,
    indexes: Vec<IndexSpec>,
    type_id: TypeId,
    type_name: &'static str,
}

impl FieldPlan {
    /// The field's name in the value and in the record.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The label the field is sealed and indexed under:
    /// `<context>/<identity>`.
    pub fn label(&self) -> &Label {
        &self.label
    }

    /// What the field does with its value.
    pub fn kind(&self) -> FieldKind {
        self.kind
    }

    /// The indexes the field declares, in order; empty for `encrypt` and
    /// `passthrough`.
    pub fn indexes(&self) -> &[IndexSpec] {
        &self.indexes
    }

    /// The field's plaintext type, by name.
    pub fn type_name(&self) -> &'static str {
        self.type_name
    }

    /// The label a query of `F` through `index` is derived under, or why
    /// the field cannot answer it: the query's plaintext is not the field's
    /// type, or the field never declared that index.
    pub(crate) fn query_label<F: 'static>(&self, index: &IndexSpec) -> Result<Label, PlanError> {
        if TypeId::of::<F>() != self.type_id {
            return Err(PlanError::FieldType {
                field: self.name.to_string(),
                expected: self.type_name,
            });
        }
        if !self.indexes.contains(index) {
            return Err(PlanError::IndexNotDeclared {
                field: self.name.to_string(),
                index: index.key(),
            });
        }
        Ok(self.label.clone())
    }
}

/// The start of a plan, and the namespace of a built fields plan.
///
/// [`Plan::context`] starts the chain without a value. A plan is the saved
/// tail of an encrypt call: run it with
/// [`using`](crate::plan::EncryptBuilder::using) on a value, a query or a
/// stored record, and every one of them derives under the same labels.
///
/// A built `Plan<S, K>` is a **fields plan** over values of type `S`, for a
/// cipher over the data-key source `K` (both are usually inferred from where
/// the plan is run). It is data: `Clone`, `Debug`, reusable, and each run
/// lowers it to a fresh [`Encryption`] (see [`encryption`](Self::encryption)).
/// A one-value plan is a [`ValuePlan`].
pub struct Plan<S: 'static, K: 'static> {
    inner: Arc<PlanInner<S, K>>,
}

struct PlanInner<S: 'static, K: 'static> {
    context: Label,
    names: Arc<[Arc<str>]>,
    fields: Vec<Built<S, K>>,
}

struct Built<S: 'static, K: 'static> {
    plan: FieldPlan,
    lower: Lower<S, K>,
    probe: Probe<S>,
    open: Option<Reader<K>>,
}

/// A field's description, produced afresh for each run: a description is
/// single-use, a plan is not. The phantom argument binds the lifetime the
/// description borrows its source for.
type Lower<S, K> = Arc<
    dyn for<'s> Fn(PhantomData<&'s ()>, &Label) -> Encryption<'s, S, Slot, K, DeclaredContext>
        + Send
        + Sync,
>;
/// A field's opening, from the stored value and the context it was sealed
/// under.
type Opener<K> =
    Arc<dyn Fn(&str, Slot, AeadContext) -> Result<Decryption<Slot, K>, PlanError> + Send + Sync>;
/// Whether a value produces a field at the plan's type: what the field's
/// lowering will find in it, asked before any keyset is loaded.
type Probe<S> = Arc<dyn Fn(&S) -> Result<(), Error> + Send + Sync>;
/// Whether a stored value is one a field's opening reads, or the type it
/// expects: the opening's own type check, asked before any keyset is
/// loaded.
type Holds = fn(&Slot) -> Result<(), &'static str>;

/// How a field comes back from a stored record. An index-only field has
/// none: its terms are one-way.
struct Reader<K> {
    holds: Holds,
    open: Opener<K>,
}

impl<K> Clone for Reader<K> {
    fn clone(&self) -> Self {
        Self {
            holds: self.holds,
            open: Arc::clone(&self.open),
        }
    }
}

/// A stored value read as exactly a `T`.
fn holds<T: 'static>(slot: &Slot) -> Result<(), &'static str> {
    if slot.is::<T>() {
        Ok(())
    } else {
        Err(type_name::<T>())
    }
}

impl<S: 'static, K: 'static> Clone for Plan<S, K> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S: 'static, K: 'static> fmt::Debug for Plan<S, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plan")
            .field("context", &self.inner.context.to_string())
            .field(
                "fields",
                &self
                    .inner
                    .fields
                    .iter()
                    .map(|field| &field.plan)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Plan<(), ()> {
    /// Start a plan under `context`, with no value: the saved form of
    /// `cipher.encrypt(&value).context(..)`. Follow it with
    /// [`fields`](PlanContext::fields) or [`with`](PlanContext::with), then
    /// `build()`.
    ///
    /// Anchored on `Plan<(), ()>` only so `Plan::context` resolves without
    /// naming a type; that plan is never built.
    pub fn context(context: impl IntoLabel) -> PlanContext {
        PlanContext {
            context: context.into_label(),
        }
    }
}

/// A plan with its context and nothing else yet: choose one value
/// ([`with`](Self::with)) or field by field ([`fields`](Self::fields)).
#[derive(Clone, Debug)]
pub struct PlanContext {
    context: Result<Label, LabelError>,
}

impl PlanContext {
    /// A context already parsed, for a chain that started from a value.
    pub(super) fn from_result(context: Result<Label, LabelError>) -> Self {
        Self { context }
    }

    /// Seal each top-level field of the value on its own, under
    /// `<context>/<field>`, as the field verbs that follow declare.
    pub fn fields<S: 'static, K: 'static>(self) -> FieldsBuilder<S, K> {
        FieldsBuilder {
            context: self.context,
            fields: Vec::new(),
            identity_without_field: false,
        }
    }

    /// One value, sealed under the context with `indexes` beside it: a
    /// one-value plan, whose output is an [`Encrypted<Terms>`].
    pub fn with<S, X: Indexes<S>>(self, indexes: X) -> ValuePlanBuilder<S, X> {
        ValuePlanBuilder {
            context: self.context,
            indexes,
            plaintext: PhantomData,
        }
    }
}

/// A one-value plan under construction; see [`ValuePlan`].
pub struct ValuePlanBuilder<S, X> {
    context: Result<Label, LabelError>,
    indexes: X,
    plaintext: PhantomData<fn(&S)>,
}

impl<S, X: fmt::Debug> fmt::Debug for ValuePlanBuilder<S, X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValuePlanBuilder")
            .field("context", &self.context)
            .field("indexes", &self.indexes)
            .finish()
    }
}

impl<S, X: Indexes<S>> ValuePlanBuilder<S, X> {
    /// Validate the plan: the context is a plain label and no index is named
    /// twice.
    ///
    /// # Errors
    ///
    /// [`PlanError::ContextLabel`] or [`PlanError::DuplicateIndex`], in
    /// [`Error::Plan`].
    pub fn build(self) -> Result<ValuePlan<S, X>, Error> {
        let context = self.checked_context()?;
        Ok(ValuePlan {
            context,
            indexes: self.indexes,
            plaintext: PhantomData,
        })
    }

    /// The context, once the plan has passed [`build`](Self::build)'s
    /// checks.
    fn checked_context(&self) -> Result<Label, Error> {
        let context = self.context.clone().map_err(PlanError::ContextLabel)?;
        check_indexes(&context.to_string(), &self.indexes.specs())?;
        Ok(context)
    }

    /// Validate the plan as [`build`](Self::build) does, without building
    /// it: what a chain asks before it loads a keyset.
    pub(super) fn check(&self) -> Result<(), Error> {
        self.checked_context().map(drop)
    }
}

/// A one-value plan: a context, and the indexes derived beside the
/// ciphertext of an `S`. Built from `Plan::context(..).with(..)`.
///
/// It carries its plaintext type, so decrypting through it yields an `S`,
/// and a query through it selects its index by type
/// ([`Indexes::select`]): asking for one it does not hold does not compile.
pub struct ValuePlan<S, X> {
    context: Label,
    indexes: X,
    plaintext: PhantomData<fn(&S)>,
}

impl<S, X: Clone> Clone for ValuePlan<S, X> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            indexes: self.indexes.clone(),
            plaintext: PhantomData,
        }
    }
}

impl<S, X: fmt::Debug> fmt::Debug for ValuePlan<S, X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValuePlan")
            .field("context", &self.context.to_string())
            .field("indexes", &self.indexes)
            .finish()
    }
}

impl<S, X> ValuePlan<S, X> {
    /// The label the value is sealed and indexed under.
    pub fn label(&self) -> &Label {
        &self.context
    }

    /// The index set.
    pub fn indexes(&self) -> &X {
        &self.indexes
    }

    /// The description one run of this plan executes:
    /// `indexed(indexes).under(context)`.
    pub fn encryption<'s, K: 'static>(
        &self,
    ) -> Encryption<'s, S, Encrypted<X::Terms>, K, DeclaredContext>
    where
        S: crate::Encrypt + Clone + 's,
        X: Indexes<S> + Clone,
    {
        indexed::<S, K, Borrowed, X>(self.indexes.clone())
            .under(NonEmpty::from(self.context.clone()))
    }
}

/// A fields plan under construction: the field verbs, then
/// [`build`](Self::build).
///
/// Each verb is generic over the field's plaintext type `F`. Rust cannot
/// learn a field's type from its name, so where the value has fields of
/// several types the type is named: `.encrypt_index::<u32>("age", (Equality,
/// Ore))`. An index that is not defined over `F` (`Match` on a `u32`) does
/// not compile, and neither does an empty index set.
pub struct FieldsBuilder<S: 'static, K: 'static> {
    context: Result<Label, LabelError>,
    fields: Vec<Declared<S, K>>,
    identity_without_field: bool,
}

struct Declared<S: 'static, K: 'static> {
    name: Arc<str>,
    identity: Option<Arc<str>>,
    kind: FieldKind,
    indexes: Vec<IndexSpec>,
    type_id: TypeId,
    type_name: &'static str,
    lower: Lower<S, K>,
    probe: Probe<S>,
    open: Option<Reader<K>>,
}

impl<S: 'static, K: 'static> fmt::Debug for FieldsBuilder<S, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldsBuilder")
            .field("context", &self.context)
            .field(
                "fields",
                &self
                    .fields
                    .iter()
                    .map(|field| (&*field.name, field.kind, &field.indexes))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// The type checks a description of `F` needs to sit in a field slot.
fn lower<S, K, L>(lower: L) -> Lower<S, K>
where
    L: for<'s> Fn(PhantomData<&'s ()>, &Label) -> Encryption<'s, S, Slot, K, DeclaredContext>
        + Send
        + Sync
        + 'static,
{
    Arc::new(lower)
}

/// The field `name` of `source` as an `F`. The plan has already checked
/// that the value names every field it declares (`check_value`, zipped
/// first, whose error wins), so a field that does not come back here is
/// one the value cannot produce at the plan's type.
fn pick<'b, S: Field<F>, F: 'static>(source: &'b S, name: &str) -> Result<&'b F, Error> {
    source.field(name).ok_or_else(|| {
        PlanError::FieldType {
            field: name.to_owned(),
            expected: type_name::<F>(),
        }
        .into()
    })
}

/// A stored value as `T`, or the plan's error naming the field.
fn stored<T: 'static>(field: &str, slot: Slot) -> Result<T, PlanError> {
    slot.downcast::<T>().map_err(|_| PlanError::FieldType {
        field: field.to_owned(),
        expected: type_name::<T>(),
    })
}

/// Open a sealed field's ciphertext as an `F`.
fn open_sealed<F, K>(ciphertext: StackCipherText, context: AeadContext) -> Decryption<Slot, K>
where
    F: crate::Decrypt<'static> + Send + 'static,
    K: 'static,
{
    open::<F, K>(ciphertext, context).map(Slot::new)
}

impl<S: 'static, K: 'static> FieldsBuilder<S, K> {
    fn declare<F: 'static>(
        mut self,
        name: &str,
        kind: FieldKind,
        indexes: Vec<IndexSpec>,
        lower: Lower<S, K>,
        open: Option<Reader<K>>,
    ) -> Self
    where
        S: Field<F>,
    {
        let field: Arc<str> = Arc::from(name);
        let probe: Probe<S> = Arc::new(move |source: &S| pick::<S, F>(source, &field).map(drop));
        self.fields.push(Declared {
            name: Arc::from(name),
            identity: None,
            kind,
            indexes,
            type_id: TypeId::of::<F>(),
            type_name: type_name::<F>(),
            lower,
            probe,
            open,
        });
        self
    }

    /// Seal the field `name` with no index: its ciphertext alone, under
    /// `<context>/<name>`. Lowers to [`ciphertext`]`().under(label)`.
    pub fn encrypt<F>(self, name: &str) -> Self
    where
        S: Field<F>,
        F: crate::Encrypt + crate::Decrypt<'static> + Clone + Send + 'static,
    {
        let field: Arc<str> = Arc::from(name);
        self.declare::<F>(
            name,
            FieldKind::Encrypt,
            Vec::new(),
            lower(move |_, label| {
                let field = Arc::clone(&field);
                ciphertext::<F, K, Borrowed>()
                    .under(NonEmpty::from(label.clone()))
                    .project_by(move |source: &S| pick::<S, F>(source, &field))
                    .map(Slot::new)
            }),
            Some(Reader {
                holds: holds::<StackCipherText>,
                open: Arc::new(|field, slot, context| {
                    Ok(open_sealed::<F, K>(stored(field, slot)?, context))
                }),
            }),
        )
    }

    /// Seal the field `name` with `indexes` beside its ciphertext, all under
    /// `<context>/<name>`: one index, or a tuple of two to four. The record
    /// holds an [`Encrypted<Terms>`]. Lowers to
    /// [`indexed`]`(indexes).under(label)`.
    pub fn encrypt_index<F>(
        self,
        name: &str,
        indexes: impl Indexes<F, Terms: Send> + Clone + Send + Sync + 'static,
    ) -> Self
    where
        S: Field<F>,
        F: crate::Encrypt + crate::Decrypt<'static> + Clone + Send + 'static,
    {
        self.encrypt_index_of(name, indexes)
    }

    fn encrypt_index_of<F, X>(self, name: &str, indexes: X) -> Self
    where
        S: Field<F>,
        F: crate::Encrypt + crate::Decrypt<'static> + Clone + Send + 'static,
        X: Indexes<F> + Clone + Send + Sync + 'static,
        X::Terms: Send,
    {
        let field: Arc<str> = Arc::from(name);
        let specs = indexes.specs();
        self.declare::<F>(
            name,
            FieldKind::EncryptIndex,
            specs,
            lower(move |_, label| {
                let field = Arc::clone(&field);
                indexed::<F, K, Borrowed, X>(indexes.clone())
                    .under(NonEmpty::from(label.clone()))
                    .project_by(move |source: &S| pick::<S, F>(source, &field))
                    .map(Slot::new)
            }),
            // A stored row may hold the whole `Encrypted<Terms>`, or only
            // its ciphertext: the terms are not needed to decrypt.
            Some(Reader {
                holds: |slot| match slot.is::<Encrypted<X::Terms>>() {
                    true => Ok(()),
                    false => holds::<StackCipherText>(slot),
                },
                open: Arc::new(|field, slot, context| {
                    let ciphertext = match slot.downcast::<Encrypted<X::Terms>>() {
                        Ok(encrypted) => encrypted.ciphertext,
                        Err(slot) => stored::<StackCipherText>(field, slot)?,
                    };
                    Ok(open_sealed::<F, K>(ciphertext, context))
                }),
            }),
        )
    }

    /// Derive `indexes` from the field `name` with no ciphertext beside
    /// them, under `<context>/<name>`. The field is written and searched,
    /// and does not come back from decrypt: a term is one-way. The record
    /// holds the terms. Lowers to [`Indexes::operations`]`().under(label)`.
    pub fn index<F>(
        self,
        name: &str,
        indexes: impl Indexes<F, Terms: Send> + Clone + Send + Sync + 'static,
    ) -> Self
    where
        S: Field<F>,
        F: Clone + Send + 'static,
    {
        self.index_of(name, indexes)
    }

    fn index_of<F, X>(self, name: &str, indexes: X) -> Self
    where
        S: Field<F>,
        F: Clone + Send + 'static,
        X: Indexes<F> + Clone + Send + Sync + 'static,
        X::Terms: Send,
    {
        let field: Arc<str> = Arc::from(name);
        let specs = indexes.specs();
        self.declare::<F>(
            name,
            FieldKind::Index,
            specs,
            lower(move |_, label| {
                let field = Arc::clone(&field);
                indexes
                    .operations::<K, Borrowed>()
                    .under(NonEmpty::from(label.clone()))
                    .project_by(move |source: &S| pick::<S, F>(source, &field))
                    .map(Slot::new)
            }),
            None,
        )
    }

    /// Carry the field `name` into the record as it is.
    ///
    /// A passthrough field is **not encrypted and not authenticated**:
    /// nothing binds it to the sealed fields beside it, so whoever can write
    /// the stored record can change it undetected. A field that must stay
    /// readable but be tamper-evident is not a passthrough: seal it with an
    /// [`Equality`](crate::Equality) index beside it. Lowers to
    /// [`passthrough`]`()`, which ignores the context.
    pub fn passthrough<F>(self, name: &str) -> Self
    where
        S: Field<F>,
        F: Clone + Send + 'static,
    {
        let field: Arc<str> = Arc::from(name);
        self.declare::<F>(
            name,
            FieldKind::Passthrough,
            Vec::new(),
            lower(move |_, _| {
                let field = Arc::clone(&field);
                passthrough::<F, K, Borrowed, DeclaredContext>()
                    .project_by(move |source: &S| pick::<S, F>(source, &field))
                    .map(Slot::new)
            }),
            Some(Reader {
                holds: holds::<F>,
                open: Arc::new(|field, slot, _| {
                    Ok(Decryption::ready(Slot::new(stored::<F>(field, slot)?)))
                }),
            }),
        )
    }

    /// Key the field just declared under `identity` rather than its name.
    ///
    /// A field's identity is the label segment its data is keyed under, and
    /// it never changes once data is written. It defaults to the field's
    /// name; pin it when a stored field is renamed, so the name moves and the
    /// key does not.
    pub fn identity(mut self, identity: &str) -> Self {
        match self.fields.last_mut() {
            Some(field) => field.identity = Some(Arc::from(identity)),
            None => self.identity_without_field = true,
        }
        self
    }

    /// Validate the whole plan and freeze it.
    ///
    /// # Errors
    ///
    /// In [`Error::Plan`], before any key is touched:
    ///
    /// - [`PlanError::ContextLabel`]: the context is not a plain label;
    /// - [`PlanError::IdentityWithoutField`]: `identity` came before any field;
    /// - [`PlanError::FieldLabel`]: a field name or identity is not a plain
    ///   segment;
    /// - [`PlanError::DuplicateIndex`]: a field names one index twice;
    /// - [`PlanError::PassthroughIndexed`]: a field is both passthrough and
    ///   indexed;
    /// - [`PlanError::DuplicateField`]: a field is named twice;
    /// - [`PlanError::SharedIdentity`]: two fields share one identity;
    /// - with a type [`schema`](Fields::schema):
    ///   [`PlanError::NotInValue`] for a field the type does not have,
    ///   [`PlanError::FieldType`] for one declared at the wrong type, and
    ///   [`PlanError::NotInPlan`] for a field of the type the plan leaves
    ///   unnamed.
    ///
    /// A value's fields are checked against the plan again whenever it
    /// runs, so a type with no schema is refused then.
    pub fn build(self) -> Result<Plan<S, K>, Error>
    where
        S: Fields,
    {
        self.freeze()
    }

    /// Validate the plan as [`build`](Self::build) does, without freezing
    /// it: what a chain asks before it loads a keyset.
    pub(super) fn check(&self) -> Result<(), Error>
    where
        S: Fields,
    {
        self.freeze().map(drop)
    }

    fn freeze(&self) -> Result<Plan<S, K>, Error>
    where
        S: Fields,
    {
        let context = self.context.clone().map_err(PlanError::ContextLabel)?;
        if self.identity_without_field {
            return Err(PlanError::IdentityWithoutField.into());
        }
        let mut fields = Vec::with_capacity(self.fields.len());
        for (at, field) in self.fields.iter().enumerate() {
            let identity = field.identity.as_deref().unwrap_or(&field.name);
            check_indexes(&field.name, &field.indexes)?;
            let label = Label::new(context.segments().chain([&*field.name]))
                .and_then(|_| Label::new(context.segments().chain([identity])))
                .map_err(|source| PlanError::FieldLabel {
                    field: field.name.to_string(),
                    source,
                })?;
            for earlier in &self.fields[..at] {
                check_pair(earlier, field)?;
            }
            fields.push(Built {
                plan: FieldPlan {
                    name: Arc::clone(&field.name),
                    label,
                    kind: field.kind,
                    indexes: field.indexes.clone(),
                    type_id: field.type_id,
                    type_name: field.type_name,
                },
                lower: Arc::clone(&field.lower),
                probe: Arc::clone(&field.probe),
                open: field.open.clone(),
            });
        }
        if let Some(schema) = S::schema() {
            check_schema(&schema, &fields)?;
        }
        Ok(Plan {
            inner: Arc::new(PlanInner {
                context,
                names: fields.iter().map(|f| Arc::clone(&f.plan.name)).collect(),
                fields,
            }),
        })
    }
}

/// No index named twice in one field or one-value plan. Two match indexes
/// with different options are still one index twice: a field has one term
/// per index kind.
fn check_indexes(at: &str, indexes: &[IndexSpec]) -> Result<(), PlanError> {
    for (i, index) in indexes.iter().enumerate() {
        if indexes[..i]
            .iter()
            .any(|earlier| earlier.key() == index.key())
        {
            return Err(PlanError::DuplicateIndex {
                at: at.to_owned(),
                index: index.key(),
            });
        }
    }
    Ok(())
}

/// The rules between two fields: one name each, and one identity each. A
/// name declared once as passthrough and once indexed is reported as that,
/// since it is the likelier mistake.
fn check_pair<S, K>(earlier: &Declared<S, K>, field: &Declared<S, K>) -> Result<(), PlanError> {
    if earlier.name == field.name {
        let passthrough = |f: &Declared<S, K>| f.kind == FieldKind::Passthrough;
        let indexed = |f: &Declared<S, K>| !f.indexes.is_empty();
        if (passthrough(earlier) && indexed(field)) || (indexed(earlier) && passthrough(field)) {
            return Err(PlanError::PassthroughIndexed {
                field: field.name.to_string(),
            });
        }
        return Err(PlanError::DuplicateField {
            field: field.name.to_string(),
        });
    }
    let identity =
        |f: &Declared<S, K>| -> Arc<str> { Arc::clone(f.identity.as_ref().unwrap_or(&f.name)) };
    if identity(earlier) == identity(field) {
        return Err(PlanError::SharedIdentity {
            identity: identity(field).to_string(),
            first: earlier.name.to_string(),
            second: field.name.to_string(),
        });
    }
    Ok(())
}

/// A plan against a type that fixes its fields: every plan field is one of
/// the type's, at the type the plan declares, and every field of the type
/// is named.
fn check_schema<S, K>(
    schema: &[super::FieldSchema],
    fields: &[Built<S, K>],
) -> Result<(), PlanError> {
    for field in fields {
        let Some(declared) = schema.iter().find(|s| s.name() == field.plan.name()) else {
            return Err(PlanError::NotInValue {
                field: field.plan.name().to_owned(),
            });
        };
        if declared.type_id() != field.plan.type_id {
            return Err(PlanError::FieldType {
                field: field.plan.name().to_owned(),
                expected: field.plan.type_name,
            });
        }
    }
    match schema
        .iter()
        .find(|s| !fields.iter().any(|f| f.plan.name() == s.name()))
    {
        Some(unnamed) => Err(PlanError::NotInPlan {
            field: unnamed.name().to_owned(),
        }),
        None => Ok(()),
    }
}

/// The value's fields against the plan's, both ways: what a fields plan
/// checks every time it runs.
fn check_value<S: Fields>(source: &S, names: &[Arc<str>]) -> Result<(), Error> {
    let have = source.field_names();
    if let Some(extra) = have.iter().find(|n| !names.iter().any(|p| &**p == **n)) {
        return Err(PlanError::NotInPlan {
            field: (*extra).to_owned(),
        }
        .into());
    }
    if let Some(missing) = names.iter().find(|p| !have.contains(&&***p)) {
        return Err(PlanError::NotInValue {
            field: missing.to_string(),
        }
        .into());
    }
    Ok(())
}

impl<S: 'static, K: 'static> Plan<S, K> {
    /// The plan's context.
    pub fn label(&self) -> &Label {
        &self.inner.context
    }

    /// The fields, in the order they were declared.
    pub fn fields(&self) -> impl ExactSizeIterator<Item = &FieldPlan> + '_ {
        self.inner.fields.iter().map(|field| &field.plan)
    }

    /// One field, for a query: `users_plan.field("email")?`.
    ///
    /// # Errors
    ///
    /// [`PlanError::NoSuchField`] if the plan has no field of that name.
    pub fn field(&self, name: &str) -> Result<FieldPlan, Error> {
        self.fields()
            .find(|field| field.name() == name)
            .cloned()
            .ok_or_else(|| {
                PlanError::NoSuchField {
                    field: name.to_owned(),
                }
                .into()
            })
    }

    /// The description one run of this plan executes over an `S`: a check
    /// that the value's fields are the plan's, then each field's description
    /// (picked out of the value by name, under its own label), zipped so
    /// every key request settles in one batch, and the record assembled.
    ///
    /// This is the lowering, not a second executor: run it with
    /// [`KeysetCipher::run`], or let the chain do so.
    pub fn encryption<'s>(&self) -> Encryption<'s, S, FieldValues, K, DeclaredContext>
    where
        S: Fields,
    {
        let names = Arc::clone(&self.inner.names);
        let mut record =
            inspect::<S, K, DeclaredContext, _>(move |source| check_value(source, &names))
                .map(|()| Vec::new());
        for field in &self.inner.fields {
            let name = Arc::clone(&field.plan.name);
            record = record
                .zip((field.lower)(PhantomData, &field.plan.label))
                .map(move |(mut slots, slot)| {
                    slots.push((name, slot));
                    slots
                });
        }
        record.map(FieldValues::from_slots)
    }

    /// A value against the plan, as running it checks it: the value's
    /// fields are the plan's, and each is of the type the plan declares.
    fn check_value(&self, source: &S) -> Result<(), Error>
    where
        S: Fields,
    {
        check_value(source, &self.inner.names)?;
        self.inner
            .fields
            .iter()
            .try_for_each(|field| (field.probe)(source))
    }

    /// A stored record against the plan, as opening it checks it: every
    /// field of the record is one the plan names, and every field the plan
    /// can return is in it, of a type its opening reads.
    fn check_record(&self, record: &FieldValues) -> Result<(), PlanError> {
        if let Some(extra) = record
            .names()
            .find(|name| !self.inner.names.iter().any(|p| &**p == *name))
        {
            return Err(PlanError::NotInPlan {
                field: extra.to_owned(),
            });
        }
        for field in &self.inner.fields {
            let Some(reader) = &field.open else {
                continue;
            };
            let name = field.plan.name();
            let Some(slot) = record.slot(name) else {
                return Err(PlanError::NotInValue {
                    field: name.to_owned(),
                });
            };
            (reader.holds)(slot).map_err(|expected| PlanError::FieldType {
                field: name.to_owned(),
                expected,
            })?;
        }
        Ok(())
    }

    /// The opening of a stored record: each sealed field opened under the
    /// context it was sealed under (its label, extended by `context`),
    /// passthrough fields carried back, index-only fields left out. Every
    /// field of the record must be one the plan names, and every field the
    /// plan can return must be in it.
    pub fn decryption(
        &self,
        mut row: FieldValues,
        context: DeclaredContext,
    ) -> Decryption<FieldValues, K> {
        if let Err(error) = self.check_record(&row) {
            return Decryption::failed(error.into());
        }
        let mut record = Decryption::ready(Vec::new());
        for field in &self.inner.fields {
            let slot = row.take_slot(field.plan.name());
            let Some(Reader { open, .. }) = &field.open else {
                continue;
            };
            let opening = match slot {
                None => Decryption::failed(
                    PlanError::NotInValue {
                        field: field.plan.name().to_owned(),
                    }
                    .into(),
                ),
                Some(slot) => {
                    let sealed_under = context
                        .clone()
                        .under(NonEmpty::from(field.plan.label.clone()));
                    open(field.plan.name(), slot, sealed_under.into())
                        .unwrap_or_else(|error| Decryption::failed(error.into()))
                }
            };
            let name = Arc::clone(&field.plan.name);
            record = record.zip(opening).map(move |(mut slots, slot)| {
                slots.push((name, slot));
                slots
            });
        }
        record.map(FieldValues::from_slots)
    }
}

/// A plan that can be run over a source of type `Src`, producing `Output`:
/// what [`using`](crate::plan::EncryptBuilder::using) asks of its plan.
///
/// Implemented for a fields plan over one value, a slice and a `Vec` of
/// them, and for a one-value plan likewise. A slice or a `Vec` runs one
/// description per item and settles all of them in one batch: one key
/// request for the whole collection.
pub trait Runs<Src: ?Sized, K> {
    /// What one run produces.
    type Output: 'static;
    /// Lower the plan and run it over `source` under `context`: the
    /// [`Pending`], with every term already derived and every key request
    /// queued, and nothing sent.
    fn pending<'p>(
        &self,
        keyset: &'p KeysetCipher<'_, K>,
        source: &Src,
        context: DeclaredContext,
    ) -> Pending<'p, Self::Output, K>;

    /// Whether `source` is one the plan can run over: the refusals
    /// [`pending`](Self::pending) would raise about the value, asked before
    /// a chain loads a keyset. A plan with nothing to check about a value
    /// keeps this default.
    ///
    /// # Errors
    ///
    /// The [`Error::Plan`] that running the plan over `source` would raise.
    fn check(&self, _source: &Src) -> Result<(), Error> {
        Ok(())
    }
}

/// A plan that can open a stored `R`, producing `Output`: what
/// [`using`](crate::plan::OpenBuilder::using) asks of its plan.
pub trait Opens<R, K> {
    /// What opening produces.
    type Output: 'static;
    /// The opening of `row` under `context`.
    fn decryption(&self, row: R, context: DeclaredContext) -> Decryption<Self::Output, K>;

    /// Whether `row` is one the plan can open: the refusals
    /// [`decryption`](Self::decryption) would raise about the record,
    /// asked before a chain loads a keyset. A plan with nothing to check
    /// about a record keeps this default.
    ///
    /// # Errors
    ///
    /// The [`Error::Plan`] that opening `row` would raise.
    fn check(&self, _row: &R) -> Result<(), Error> {
        Ok(())
    }
}

impl<S: Fields + 'static, K: 'static> Runs<S, K> for Plan<S, K> {
    type Output = FieldValues;
    fn pending<'p>(
        &self,
        keyset: &'p KeysetCipher<'_, K>,
        source: &S,
        context: DeclaredContext,
    ) -> Pending<'p, FieldValues, K> {
        keyset.run(self.encryption(), source, context)
    }

    fn check(&self, source: &S) -> Result<(), Error> {
        self.check_value(source)
    }
}

impl<S, X, K> Runs<S, K> for ValuePlan<S, X>
where
    S: crate::Encrypt + Clone,
    X: Indexes<S> + Clone,
    K: 'static,
{
    type Output = Encrypted<X::Terms>;
    fn pending<'p>(
        &self,
        keyset: &'p KeysetCipher<'_, K>,
        source: &S,
        context: DeclaredContext,
    ) -> Pending<'p, Self::Output, K> {
        keyset.run(self.encryption(), source, context)
    }
}

/// A collection of sources runs one description per item, merged into one
/// batch.
macro_rules! runs_over_collections {
    ($([$($generics:tt)*] $plan:ty => $item:ty where [$($bounds:tt)*];)+) => {$(
        impl<$($generics)*> Runs<[$item], K> for $plan where $($bounds)* {
            type Output = Vec<<Self as Runs<$item, K>>::Output>;
            fn pending<'p>(
                &self,
                keyset: &'p KeysetCipher<'_, K>,
                source: &[$item],
                context: DeclaredContext,
            ) -> Pending<'p, Self::Output, K> {
                Pending::all(
                    keyset,
                    source
                        .iter()
                        .map(|item| Runs::<$item, K>::pending(self, keyset, item, context.clone()))
                        .collect(),
                )
            }
            fn check(&self, source: &[$item]) -> Result<(), Error> {
                source
                    .iter()
                    .try_for_each(|item| Runs::<$item, K>::check(self, item))
            }
        }
        impl<$($generics)*> Runs<Vec<$item>, K> for $plan where $($bounds)* {
            type Output = Vec<<Self as Runs<$item, K>>::Output>;
            fn pending<'p>(
                &self,
                keyset: &'p KeysetCipher<'_, K>,
                source: &Vec<$item>,
                context: DeclaredContext,
            ) -> Pending<'p, Self::Output, K> {
                Runs::<[$item], K>::pending(self, keyset, source.as_slice(), context)
            }
            fn check(&self, source: &Vec<$item>) -> Result<(), Error> {
                Runs::<[$item], K>::check(self, source.as_slice())
            }
        }
    )+};
}
runs_over_collections! {
    [S, K] Plan<S, K> => S where [S: Fields + 'static, K: 'static];
    [S, X, K] ValuePlan<S, X> => S where [S: crate::Encrypt + Clone, X: Indexes<S> + Clone, K: 'static];
}

impl<S: 'static, K: 'static> Opens<FieldValues, K> for Plan<S, K> {
    type Output = FieldValues;
    fn decryption(&self, row: FieldValues, context: DeclaredContext) -> Decryption<FieldValues, K> {
        Plan::decryption(self, row, context)
    }
    fn check(&self, row: &FieldValues) -> Result<(), Error> {
        Ok(self.check_record(row)?)
    }
}

impl<S: 'static, K: 'static> Opens<Vec<FieldValues>, K> for Plan<S, K> {
    type Output = Vec<FieldValues>;
    fn decryption(
        &self,
        rows: Vec<FieldValues>,
        context: DeclaredContext,
    ) -> Decryption<Vec<FieldValues>, K> {
        Decryption::all(
            rows.into_iter()
                .map(|row| Plan::decryption(self, row, context.clone())),
        )
    }
    fn check(&self, rows: &Vec<FieldValues>) -> Result<(), Error> {
        rows.iter().try_for_each(|row| Ok(self.check_record(row)?))
    }
}

/// A one-value plan opens anything that recovers its plaintext from an
/// AEAD context: an [`Encrypted<Terms>`] or a bare [`StackCipherText`].
impl<S, X, R, K> Opens<R, K> for ValuePlan<S, X>
where
    S: 'static,
    R: DecryptInto<S, Context = AeadContext>,
    K: 'static,
{
    type Output = S;
    fn decryption(&self, row: R, context: DeclaredContext) -> Decryption<S, K> {
        row.decryption(context.under(NonEmpty::from(self.context.clone())).into())
    }
}
