//! Saved fields plans: the chain without the value, validated once at
//! `build()`, and how each lowers to the combinators in
//! [`target`](crate::target).
use std::any::{type_name, TypeId};
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use super::field_ref::{resolve, Access, FieldRef, FieldsOf, Reader};
use super::values::Slot;
use super::{FieldValues, PlanError};
use crate::target::{
    ciphertext, indexed, inspect, open, passthrough, AeadContext, Borrowed, CallerContext,
    DeclaredContext, DecryptField, Decryptable, Decryption, EncryptFrom, Encryption,
    ExpectedContext, IndexSpec, Indexes, Pending,
};
use crate::{Error, KeysetCipher, Label, LabelError, NonEmpty, StackCipherText};

/// A context a plan is declared under: a [`Label`], or text parsed as one.
///
/// A plan's context is a name, so it is a label of plain segments:
/// `"users"`, or `"documents/v2/body"`, which is three segments and renders
/// in the ZeroKMS log exactly as written. Text that is not a plain label is
/// kept and refused when the plan is built or run
/// ([`PlanError::ContextLabel`]), so a chain reads straight through and
/// fails in one place.
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
/// A context held in a `String` (a config value, say), borrowed:
/// `Plan::context(&name)`.
impl IntoLabel for &String {
    fn into_label(self) -> Result<Label, LabelError> {
        Label::parse(self)
    }
}

/// Who supplied a context, for [`PlanError::TwoContextSources`].
pub(crate) const FROM_PLAN: &str = "the plan";
pub(crate) const FROM_CALL: &str = "the call";
pub(crate) const FROM_FIELD: &str = "a context field";

/// The label a field is sealed under: the context, then its identity.
pub(crate) fn join(context: &Label, identity: &str) -> Result<Label, LabelError> {
    Label::new(context.segments().chain([identity]))
}

/// The one context of a plan that takes it from the plan or the call:
/// exactly one of the two.
pub(crate) fn resolve_context(
    plan: Option<&Label>,
    call: Option<Label>,
) -> Result<Label, PlanError> {
    match (plan, call) {
        (Some(plan), None) => Ok(plan.clone()),
        (None, Some(call)) => Ok(call),
        (Some(_), Some(_)) => Err(PlanError::TwoContextSources {
            first: FROM_PLAN,
            second: FROM_CALL,
        }),
        (None, None) => Err(PlanError::NoContext),
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
    /// Laid out by a target type's own `EncryptFrom`:
    /// [`encrypt_into`](FieldsBuilder::encrypt_into).
    EncryptInto,
    /// The plan's context, carried unsealed:
    /// [`context_field`](FieldsBuilder::context_field).
    ContextField,
}

/// One field of a built [`Plan`]: its name, the label it is sealed and
/// indexed under, and what it declares. What a query takes
/// ([`Plan::field`]), so a query is derived under exactly the label the
/// write used, and asking for an index the field never declared is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldPlan {
    name: Arc<str>,
    identity: Arc<str>,
    label: Option<Label>,
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

    /// The label segment the field is keyed under: its name, unless one
    /// was pinned with [`identity`](FieldsBuilder::identity).
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The label the field is sealed and indexed under,
    /// `<context>/<identity>`, when the plan was built with its context.
    /// `None` when the context comes from the call or from a context field
    /// (a query then names it with `.context(..)`), and for a passthrough or
    /// context field, which is neither sealed nor indexed, so its name need
    /// not be a label segment.
    pub fn label(&self) -> Option<&Label> {
        self.label.as_ref()
    }

    /// What the field does with its value.
    pub fn kind(&self) -> FieldKind {
        self.kind
    }

    /// The indexes the field declares, in order; empty for `encrypt` and
    /// `passthrough`. A typed field's are its target's
    /// ([`EncryptFrom::indexes`]).
    pub fn indexes(&self) -> &[IndexSpec] {
        &self.indexes
    }

    /// The field's plaintext type, by name.
    pub fn type_name(&self) -> &'static str {
        self.type_name
    }

    /// The label a query of `F` through `index` is derived under, given the
    /// context the query call names (if any), or why the field cannot
    /// answer it: the query's plaintext is not the field's type, the field
    /// never declared that index (or declared it with other options), or the
    /// context is missing or given twice.
    pub(crate) fn query_label<F: 'static>(
        &self,
        index: &IndexSpec,
        call: Option<Label>,
    ) -> Result<Label, PlanError> {
        if TypeId::of::<F>() != self.type_id {
            return Err(PlanError::FieldType {
                field: self.name.to_string(),
                expected: self.type_name,
            });
        }
        check_declared(&self.name, &self.indexes, index)?;
        match &self.label {
            Some(label) => resolve_context(Some(label), call),
            None => {
                let context = call.ok_or(PlanError::NoContext)?;
                join(&context, &self.identity).map_err(|source| PlanError::FieldLabel {
                    field: self.name.to_string(),
                    source,
                })
            }
        }
    }
}

/// `index` is one of `declared`, or the error naming how it is not.
pub(crate) fn check_declared(
    at: &str,
    declared: &[IndexSpec],
    index: &IndexSpec,
) -> Result<(), PlanError> {
    if declared.contains(index) {
        return Ok(());
    }
    match declared.iter().find(|have| have.key() == index.key()) {
        Some(have) => Err(PlanError::IndexOptions {
            field: at.to_owned(),
            declared: have.clone(),
            asked: index.clone(),
        }),
        None => Err(PlanError::IndexNotDeclared {
            field: at.to_owned(),
            index: index.key(),
        }),
    }
}

/// The start of a plan, and the namespace of a built fields plan.
///
/// A plan starts one of two ways, each with an optional context:
///
/// - [`Plan::fields`] (or [`Plan::context`]`(c).fields()`): field by field;
/// - [`Plan::value`] (or [`Plan::context`]`(c).with(..)`): one value.
///
/// A built `Plan<S, K>` is a **fields plan** over values of type `S`, for a
/// cipher over the data-key source `K` (both are usually inferred from where
/// the plan is run). It is data: `Clone`, `Debug`, reusable, and each run
/// lowers it to a fresh [`Encryption`] (see [`encryption`](Self::encryption)).
/// A one-value plan is a [`ValuePlan`](super::ValuePlan).
///
/// # Where the context comes from
///
/// Exactly one of three places:
///
/// 1. the plan, when it is built: `.context(c)`;
/// 2. the call that runs it, for a plan built without one:
///    `cipher.encrypt(&v).context(c).using(&plan)`;
/// 3. a field of the value: [`context_field`](FieldsBuilder::context_field).
///
/// Two of them is [`PlanError::TwoContextSources`], when the plan is built
/// or when it is run; none is [`PlanError::NoContext`], when it is run
/// (before any key is requested), since only the call can say. Every field
/// is sealed under `<context>/<identity>`, and `.extend(parts)` extends
/// whichever context the plan has.
///
/// ```
/// # use stack_encrypt::plan::pick;
/// # struct User { email: String, id: u64 }
/// # async fn example() -> Result<(), stack_encrypt::Error> {
/// use stack_encrypt::kms::FakeDataKeySource;
/// use stack_encrypt::{Equality, Plan, StackCipher};
///
/// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
/// let user = User { email: "bob@example.com".into(), id: 42 };
///
/// // Built without a context: each call names its own.
/// let users_plan = Plan::fields()
///     .encrypt_index(pick("email", |u: &User| &u.email), Equality)
///     .passthrough(pick("id", |u: &User| &u.id))
///     .build()?;
/// let record = cipher.encrypt(&user).context("tenants/acme/users").using(&users_plan).await?;
///
/// // A query and a read name the same context.
/// let email_plan = users_plan.field("email")?;
/// let query_value = cipher
///     .query("bob@example.com")
///     .context("tenants/acme/users")
///     .using(&email_plan)
///     .equality()
///     .await?;
/// # let _ = query_value;
/// let back = cipher.open(record).context("tenants/acme/users").using(&users_plan).await?;
/// assert_eq!(back.get::<String>("email").map(String::as_str), Some("bob@example.com"));
///
/// // Without one, the call is refused before any key is requested.
/// let refused = cipher.encrypt(&user).using(&users_plan).await;
/// assert!(matches!(
///     refused,
///     Err(stack_encrypt::Error::Plan(stack_encrypt::PlanError::NoContext))
/// ));
/// # Ok(())
/// # }
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
/// ```
pub struct Plan<S: 'static, K: 'static> {
    inner: Arc<PlanInner<S, K>>,
}

struct PlanInner<S: 'static, K: 'static> {
    source: Source<S>,
    names: Arc<[Arc<str>]>,
    fields: Vec<Built<S, K>>,
    fields_of: Option<FieldsOf<S>>,
}

/// Where a built fields plan takes its context from.
enum Source<S> {
    Plan(Label),
    Call,
    Field(ContextField<S>),
}

impl<S> Source<S> {
    fn what(&self) -> &'static str {
        match self {
            Source::Plan(_) => FROM_PLAN,
            Source::Call => FROM_CALL,
            Source::Field(_) => FROM_FIELD,
        }
    }
}

/// Read the context out of a value.
type OfValue<S> = Arc<dyn for<'b> Fn(&'b S) -> Result<Label, Error> + Send + Sync>;
/// Read the context out of a stored record's context field.
type OfStored = Arc<dyn Fn(&Slot) -> Result<Label, PlanError> + Send + Sync>;

/// A field of the value whose value is the plan's context: read from the
/// value to seal, and from the stored record to open.
struct ContextField<S> {
    name: Arc<str>,
    of_value: OfValue<S>,
    of_stored: OfStored,
}

impl<S> Clone for ContextField<S> {
    fn clone(&self) -> Self {
        Self {
            name: Arc::clone(&self.name),
            of_value: Arc::clone(&self.of_value),
            of_stored: Arc::clone(&self.of_stored),
        }
    }
}

impl<S> ContextField<S> {
    /// The context a stored record was sealed under, read from its context
    /// field and checked against what the caller expects, if anything,
    /// before any key is requested.
    fn stored(&self, record: &FieldValues, expected: Option<Label>) -> Result<Label, Error> {
        let slot = record
            .slot(&self.name)
            .ok_or_else(|| PlanError::NotInValue {
                field: self.name.to_string(),
            })?;
        let stored = (self.of_stored)(slot)?;
        let expected = match expected {
            Some(expected) => ExpectedContext::from(NonEmpty::from(expected)),
            None => ExpectedContext::default(),
        };
        expected.validate(stored).map(NonEmpty::into_inner)
    }
}

struct Built<S: 'static, K: 'static> {
    plan: FieldPlan,
    lower: Lower<S, K>,
    probe: Probe<S>,
    open: Option<FieldOpener<K>>,
}

/// A field's description, produced afresh for each run: a description is
/// single-use, a plan is not. It runs under the field's whole context (its
/// label, extended by the call's parts); the plan supplies that. The phantom
/// argument binds the lifetime the description borrows its source for.
type Lower<S, K> = Arc<
    dyn for<'s> Fn(PhantomData<&'s ()>) -> Encryption<'s, S, Slot, K, CallerContext> + Send + Sync,
>;
/// A field's opening, from the stored value and the whole context it was
/// sealed under.
type Opener<K> =
    Arc<dyn Fn(&str, Slot, CallerContext) -> Result<Decryption<Slot, K>, PlanError> + Send + Sync>;
/// Whether a value produces a field at the plan's type: what the field's
/// lowering will find in it, asked before any keyset is loaded.
type Probe<S> = Arc<dyn Fn(&S) -> Result<(), Error> + Send + Sync>;
/// Whether a stored value is one a field's opening reads, or the type it
/// expects: the opening's own type check, asked before any keyset is
/// loaded.
type Holds = fn(&Slot) -> Result<(), &'static str>;

/// How a field comes back from a stored record. A field that does not come
/// back (terms alone, which are one-way) has none.
struct FieldOpener<K> {
    holds: Holds,
    open: Opener<K>,
}

impl<K> Clone for FieldOpener<K> {
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
        let context = match &self.inner.source {
            Source::Plan(label) => label.to_string(),
            Source::Call => String::from("<from the call>"),
            Source::Field(field) => format!("<from field {:?}>", field.name),
        };
        f.debug_struct("Plan")
            .field("context", &context)
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
    /// `build()`. The common spelling of `Plan::fields().context(c)`.
    ///
    /// Anchored on `Plan<(), ()>` only so `Plan::context` resolves without
    /// naming a type; that plan is never built.
    pub fn context(context: impl IntoLabel) -> PlanContext {
        PlanContext {
            context: context.into_label(),
        }
    }

    /// Start a fields plan with no context yet: give it one with
    /// [`context`](FieldsBuilder::context) or
    /// [`context_field`](FieldsBuilder::context_field), or leave it for the
    /// call that runs it.
    pub fn fields<S: 'static, K: 'static>() -> FieldsBuilder<S, K> {
        FieldsBuilder {
            sources: Vec::new(),
            fields: Vec::new(),
            identity_without_field: false,
            fields_of: None,
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

    pub(super) fn into_result(self) -> Result<Label, LabelError> {
        self.context
    }

    /// Seal each top-level field of the value on its own, under
    /// `<context>/<field>`, as the field verbs that follow declare.
    pub fn fields<S: 'static, K: 'static>(self) -> FieldsBuilder<S, K> {
        let mut fields = Plan::fields();
        fields.sources.push(Declare::Plan(self.context));
        fields
    }
}

/// A context source as declared, before `build()` checks there is one.
enum Declare<S> {
    Plan(Result<Label, LabelError>),
    Field(ContextField<S>),
}

impl<S> fmt::Debug for Declare<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Declare::Plan(label) => label.fmt(f),
            Declare::Field(field) => f.debug_tuple("Field").field(&field.name).finish(),
        }
    }
}

impl<S> Declare<S> {
    fn what(&self) -> &'static str {
        match self {
            Declare::Plan(_) => FROM_PLAN,
            Declare::Field(_) => FROM_FIELD,
        }
    }
}

/// A fields plan under construction: the field verbs, then
/// [`build`](Self::build).
///
/// Each verb names its field with a [`FieldRef`]: a name, read through the
/// value's [`Field<F>`](super::Field), or a picker, a name with an accessor
/// ([`pick`](super::pick)). With a name, Rust cannot learn the field's type,
/// so where the value has fields of several types the type is named:
/// `.encrypt_index::<u32>("age", (Equality, Ore))`; a picker's accessor
/// names it. An index that is not defined over `F` (`Match` on a `u32`) does
/// not compile, and neither does an empty index set.
///
/// A field is either the data verbs (`encrypt`, `encrypt_index`, `index`,
/// `passthrough`) or one typed target (`encrypt_into`), never both.
pub struct FieldsBuilder<S: 'static, K: 'static> {
    sources: Vec<Declare<S>>,
    fields: Vec<Declared<S, K>>,
    identity_without_field: bool,
    fields_of: Option<FieldsOf<S>>,
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
    open: Option<FieldOpener<K>>,
}

impl<S: 'static, K: 'static> fmt::Debug for FieldsBuilder<S, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldsBuilder")
            .field("context", &self.sources)
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

/// A description of a field `F`, lifted to read it out of the value `S`
/// and to hold its output in a record slot.
fn lifted<'s, S, F, T, K>(
    operation: Encryption<'s, F, T, K, CallerContext>,
    name: &Arc<str>,
    read: &Reader<S, F>,
) -> Encryption<'s, S, Slot, K, CallerContext>
where
    S: 's,
    F: 'static,
    T: std::any::Any + Send + 'static,
    K: 'static,
{
    let name = Arc::clone(name);
    let read = Arc::clone(read);
    operation
        .project_by(move |source: &S| picked(&read, source, &name))
        .map(Slot::new)
}

/// The field `name` of `source` as an `F`. A plan that reads fields by name
/// has already checked that the value names every field it declares
/// (`check_value`, zipped first, whose error wins), so a field that does
/// not come back here is one the value cannot produce at the plan's type.
fn picked<'b, S, F: 'static>(
    read: &Reader<S, F>,
    source: &'b S,
    name: &str,
) -> Result<&'b F, Error> {
    read(source).ok_or_else(|| {
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
fn open_sealed<F, K>(ciphertext: StackCipherText, context: CallerContext) -> Decryption<Slot, K>
where
    F: crate::Decrypt<'static> + Send + 'static,
    K: 'static,
{
    open::<F, K>(ciphertext, AeadContext::from(context)).map(Slot::new)
}

impl<S: 'static, K: 'static> FieldsBuilder<S, K> {
    fn declare<F: 'static>(
        mut self,
        name: Arc<str>,
        access: &Access<S, F>,
        kind: FieldKind,
        indexes: Vec<IndexSpec>,
        lower: Lower<S, K>,
        open: Option<FieldOpener<K>>,
    ) -> Self {
        if let Some(fields) = access.fields {
            self.fields_of = Some(fields);
        }
        let read = Arc::clone(&access.read);
        let field = Arc::clone(&name);
        let probe: Probe<S> = Arc::new(move |source: &S| picked(&read, source, &field).map(drop));
        self.fields.push(Declared {
            name,
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

    /// Take the plan's context from `context`, given when the plan is
    /// built: every field is sealed under `<context>/<identity>`.
    /// `Plan::context(c).fields()` is the same.
    pub fn context(mut self, context: impl IntoLabel) -> Self {
        self.sources.push(Declare::Plan(context.into_label()));
        self
    }

    /// Take the plan's context from the field `field` of each value: its
    /// value is the context, and every other field is sealed under
    /// `<that value>/<identity>`.
    ///
    /// The field is carried into the record as it is, as a passthrough is
    /// (so **unsealed and unauthenticated**), so the record can be opened
    /// without being told its context. When it is opened, the stored value
    /// is the context each field is opened under, checked first against the
    /// context the caller expects, if it names one:
    /// `cipher.open(record).context(expected)` refuses a record whose
    /// context field says otherwise with
    /// [`Error::ContextMismatch`](crate::Error::ContextMismatch), before any
    /// key is requested. That is the derive's `#[stash(context_field)]`
    /// check ([`ExpectedContext`]). A context field changed in storage
    /// opens nothing either way: every field was sealed under the original.
    ///
    /// The field's value must be a plain label (`"tenants/acme"`), read
    /// through [`IntoLabel`]; one that is not is
    /// [`PlanError::ContextLabel`] when the plan runs.
    ///
    /// ```
    /// # use stack_encrypt::plan::pick;
    /// # struct Note { tenant: String, text: String }
    /// # async fn example() -> Result<(), stack_encrypt::Error> {
    /// use stack_encrypt::kms::FakeDataKeySource;
    /// use stack_encrypt::{Error, Plan, StackCipher};
    ///
    /// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
    /// let notes_plan = Plan::fields()
    ///     .context_field(pick("tenant", |n: &Note| &n.tenant))
    ///     .encrypt(pick("text", |n: &Note| &n.text))
    ///     .build()?;
    ///
    /// // `text` is sealed under `tenants/acme/text`.
    /// let note = Note { tenant: "tenants/acme".into(), text: "hello".into() };
    /// let record = cipher.encrypt(&note).using(&notes_plan).await?;
    ///
    /// // Opening checks the stored context against the one expected.
    /// let refused = cipher.open(record).context("tenants/globex").using(&notes_plan).await;
    /// assert!(matches!(refused, Err(Error::ContextMismatch { .. })));
    /// # Ok(())
    /// # }
    /// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
    /// ```
    pub fn context_field<F>(self, field: impl FieldRef<S, F>) -> Self
    where
        F: IntoLabel + Clone + Send + 'static,
    {
        let (name, access) = resolve(field);
        let read = Arc::clone(&access.read);
        let field_name = Arc::clone(&name);
        let stored_name = Arc::clone(&name);
        let context = ContextField {
            name: Arc::clone(&name),
            of_value: Arc::new(move |source: &S| {
                picked(&read, source, &field_name)?
                    .clone()
                    .into_label()
                    .map_err(|error| PlanError::ContextLabel(error).into())
            }),
            of_stored: Arc::new(move |slot: &Slot| {
                slot.downcast_ref::<F>()
                    .ok_or_else(|| PlanError::FieldType {
                        field: stored_name.to_string(),
                        expected: type_name::<F>(),
                    })?
                    .clone()
                    .into_label()
                    .map_err(PlanError::ContextLabel)
            }),
        };
        let mut plan = self.passthrough_as(name, access, FieldKind::ContextField);
        plan.sources.push(Declare::Field(context));
        plan
    }

    /// Seal the field `field` with no index: its ciphertext alone, under
    /// `<context>/<identity>`. Lowers to [`ciphertext`]`().under(label)`.
    pub fn encrypt<F>(self, field: impl FieldRef<S, F>) -> Self
    where
        F: crate::Encrypt + crate::Decrypt<'static> + Clone + Send + 'static,
    {
        let (name, access) = resolve(field);
        let read = Arc::clone(&access.read);
        let field = Arc::clone(&name);
        self.declare::<F>(
            name,
            &access,
            FieldKind::Encrypt,
            Vec::new(),
            Arc::new(move |_| {
                lifted(
                    ciphertext::<F, K, Borrowed>().accepting::<CallerContext>(),
                    &field,
                    &read,
                )
            }),
            Some(FieldOpener {
                holds: holds::<StackCipherText>,
                open: Arc::new(|field, slot, context| {
                    Ok(open_sealed::<F, K>(stored(field, slot)?, context))
                }),
            }),
        )
    }

    /// Seal the field `field` with `indexes` beside its ciphertext, all
    /// under `<context>/<identity>`: one index, or a tuple of two to five.
    /// The record holds an [`Encrypted<Terms>`](crate::Encrypted). Lowers to
    /// [`indexed`]`(indexes).under(label)`, which is also what
    /// `encrypt_into::<Encrypted<Terms>, _>` lowers to.
    pub fn encrypt_index<F>(
        self,
        field: impl FieldRef<S, F>,
        indexes: impl Indexes<F, Terms: Send> + Clone + Send + Sync + 'static,
    ) -> Self
    where
        F: crate::Encrypt + crate::Decrypt<'static> + Clone + Send + 'static,
    {
        self.encrypt_index_of(field, indexes)
    }

    fn encrypt_index_of<F, X>(self, field: impl FieldRef<S, F>, indexes: X) -> Self
    where
        F: crate::Encrypt + crate::Decrypt<'static> + Clone + Send + 'static,
        X: Indexes<F> + Clone + Send + Sync + 'static,
        X::Terms: Send,
    {
        let (name, access) = resolve(field);
        let read = Arc::clone(&access.read);
        let field = Arc::clone(&name);
        let specs = indexes.specs();
        self.declare::<F>(
            name,
            &access,
            FieldKind::EncryptIndex,
            specs,
            Arc::new(move |_| lifted(indexed::<F, K, Borrowed, X>(indexes.clone()), &field, &read)),
            // A stored record may hold the whole `Encrypted<Terms>`, or only
            // its ciphertext: the terms are not needed to decrypt.
            Some(FieldOpener {
                holds: |slot| match slot.is::<crate::Encrypted<X::Terms>>() {
                    true => Ok(()),
                    false => holds::<StackCipherText>(slot),
                },
                open: Arc::new(|field, slot, context| {
                    let ciphertext = match slot.downcast::<crate::Encrypted<X::Terms>>() {
                        Ok(encrypted) => encrypted.ciphertext,
                        Err(slot) => stored::<StackCipherText>(field, slot)?,
                    };
                    Ok(open_sealed::<F, K>(ciphertext, context))
                }),
            }),
        )
    }

    /// Derive `indexes` from the field `field` with no ciphertext beside
    /// them, under `<context>/<identity>`. The field is written and
    /// searched, and does not come back from decrypt: a term is one-way.
    /// The record holds the terms. Lowers to
    /// [`Indexes::operations`]`().under(label)`.
    pub fn index<F>(
        self,
        field: impl FieldRef<S, F>,
        indexes: impl Indexes<F, Terms: Send> + Clone + Send + Sync + 'static,
    ) -> Self
    where
        F: Clone + Send + 'static,
    {
        self.index_of(field, indexes)
    }

    fn index_of<F, X>(self, field: impl FieldRef<S, F>, indexes: X) -> Self
    where
        F: Clone + Send + 'static,
        X: Indexes<F> + Clone + Send + Sync + 'static,
        X::Terms: Send,
    {
        let (name, access) = resolve(field);
        let read = Arc::clone(&access.read);
        let field = Arc::clone(&name);
        let specs = indexes.specs();
        self.declare::<F>(
            name,
            &access,
            FieldKind::Index,
            specs,
            Arc::new(move |_| lifted(indexes.operations::<K, Borrowed>(), &field, &read)),
            None,
        )
    }

    /// Carry the field `field` into the record as it is.
    ///
    /// A passthrough field is **not encrypted and not authenticated**:
    /// nothing binds it to the sealed fields beside it, so whoever can write
    /// the stored record can change it undetected. A field that must stay
    /// readable but be tamper-evident is not a passthrough: seal it with an
    /// [`Equality`](crate::Equality) index beside it. Lowers to
    /// [`passthrough`]`()`, which ignores the context.
    ///
    /// A passthrough field is under no label, so its name may be any text
    /// (`"2fa_enabled"`, `"created(utc)"`): it is only the record key. An
    /// [`identity`](Self::identity) pinned on it keys nothing.
    pub fn passthrough<F>(self, field: impl FieldRef<S, F>) -> Self
    where
        F: Clone + Send + 'static,
    {
        let (name, access) = resolve(field);
        self.passthrough_as(name, access, FieldKind::Passthrough)
    }

    fn passthrough_as<F>(self, name: Arc<str>, access: Access<S, F>, kind: FieldKind) -> Self
    where
        F: Clone + Send + 'static,
    {
        let read = Arc::clone(&access.read);
        let field = Arc::clone(&name);
        self.declare::<F>(
            name,
            &access,
            kind,
            Vec::new(),
            Arc::new(move |_| {
                lifted(
                    passthrough::<F, K, Borrowed, CallerContext>(),
                    &field,
                    &read,
                )
            }),
            Some(FieldOpener {
                holds: holds::<F>,
                open: Arc::new(|field, slot, _| {
                    Ok(Decryption::ready(Slot::new(stored::<F>(field, slot)?)))
                }),
            }),
        )
    }

    /// Lay the field `field` out as the target `T` does: `T`'s own
    /// [`EncryptFrom<F>`] decides what is sealed and which terms sit beside
    /// it, all under `<context>/<identity>`, and the record holds a `T`.
    /// Lowers to `<T as EncryptFrom<F>>::encryption().under(label)`, as the
    /// derive composes a field of a record type.
    ///
    /// The target says which queries the field answers
    /// ([`EncryptFrom::indexes`]); any other is refused. It opens through
    /// `T`'s own decryption ([`DecryptField`], which a ciphertext, an
    /// [`Encrypted<Terms>`](crate::Encrypted), a tuple holding one and a
    /// derived record implement); a target with nothing to open
    /// ([`Decryptable::DECRYPTABLE`] false: terms alone) does not come back
    /// from `open`, like an [`index`](Self::index) field.
    ///
    /// Name the target and let the field's type be inferred, or name both:
    /// `.encrypt_into::<TextEq, _>("email")`,
    /// `.encrypt_into::<Encrypted<(EqualityTerm, MatchTerms)>, String>("email")`.
    /// With a picker the field's type is the accessor's.
    ///
    /// A field is either data verbs or one target: declaring the same field
    /// with both is [`PlanError::TargetWithVerbs`].
    ///
    /// ```
    /// # use stack_encrypt::plan::pick;
    /// # struct User { email: String }
    /// # async fn example() -> Result<(), stack_encrypt::Error> {
    /// use stack_encrypt::kms::FakeDataKeySource;
    /// use stack_encrypt::sem::{EqualityTerm, MatchTerms};
    /// use stack_encrypt::{Encrypted, Plan, StackCipher};
    ///
    /// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
    /// let users_plan = Plan::context("users")
    ///     .fields()
    ///     .encrypt_into::<Encrypted<(EqualityTerm, MatchTerms)>, _>(pick("email", |u: &User| &u.email))
    ///     .build()?;
    ///
    /// let user = User { email: "bob@example.com".into() };
    /// let mut record = cipher.encrypt(&user).using(&users_plan).await?;
    /// let email: Encrypted<(EqualityTerm, MatchTerms)> = record.take("email")?;
    ///
    /// // The target declares an equality index, so the field answers it.
    /// let query_value = cipher.query("bob@example.com").using(&users_plan.field("email")?).equality().await?;
    /// assert_eq!(query_value, email.terms.0);
    /// # Ok(())
    /// # }
    /// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
    /// ```
    pub fn encrypt_into<T, F>(self, field: impl FieldRef<S, F>) -> Self
    where
        F: Send + 'static,
        T: EncryptFrom<F> + Decryptable + DecryptField<F, CallerContext> + Send,
        CallerContext: Into<T::Context>,
    {
        let (name, access) = resolve(field);
        let read = Arc::clone(&access.read);
        let field = Arc::clone(&name);
        let open: Option<FieldOpener<K>> = if T::DECRYPTABLE {
            Some(FieldOpener {
                holds: holds::<T>,
                open: Arc::new(|field, slot, context| {
                    Ok(stored::<T>(field, slot)?
                        .decryption_field::<K>(context)
                        .map_or_else(
                            || Decryption::failed(Error::NotOpened),
                            |d| d.map(Slot::new),
                        ))
                }),
            })
        } else {
            None
        };
        self.declare::<F>(
            name,
            &access,
            FieldKind::EncryptInto,
            T::indexes(),
            Arc::new(move |_| {
                lifted(
                    T::encryption::<K>().accepting::<CallerContext>(),
                    &field,
                    &read,
                )
            }),
            open,
        )
    }

    /// Key the field just declared under `identity` rather than its name.
    ///
    /// A field's identity is the label segment its data is keyed under, and
    /// it never changes once data is written. It defaults to the field's
    /// name; pin it when a stored field is renamed, so the name moves and the
    /// key does not. Once pinned, the name is only the field's key in the
    /// value and the record, so it need not be a plain label segment
    /// (`"0"`, a tuple index, or `"2fa_secret"` keyed as `totp_secret`).
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
    /// - [`PlanError::TwoContextSources`]: the context is given twice
    ///   (`context` and `context_field`, or either twice);
    /// - [`PlanError::ContextLabel`]: the context is not a plain label;
    /// - [`PlanError::IdentityWithoutField`]: `identity` came before any field;
    /// - [`PlanError::FieldLabel`]: the identity of a sealed or indexed
    ///   field (its name, unless one is pinned) is not a plain segment (a
    ///   passthrough field's name may be any text: it is under no label);
    /// - [`PlanError::DuplicateIndex`]: a field names one index twice;
    /// - [`PlanError::TargetWithVerbs`]: a field is both a typed target and
    ///   data verbs;
    /// - [`PlanError::PassthroughIndexed`]: a field is both passthrough and
    ///   indexed;
    /// - [`PlanError::DuplicateField`]: a field is named twice;
    /// - [`PlanError::SharedIdentity`]: two sealed or indexed fields share
    ///   one identity;
    /// - with a type [`schema`](super::Fields::schema), when a field is named
    ///   by name: [`PlanError::NotInValue`] for a field the type does not
    ///   have, [`PlanError::FieldType`] for one declared at the wrong type,
    ///   and [`PlanError::NotInPlan`] for a field of the type the plan leaves
    ///   unnamed.
    ///
    /// A plan with no context at all builds: the call that runs it names
    /// one. A value's fields are checked against the plan again whenever it
    /// runs, so a type with no schema is refused then.
    pub fn build(self) -> Result<Plan<S, K>, Error> {
        self.freeze()
    }

    /// Validate the plan as [`build`](Self::build) does, without keeping
    /// it, and `source` against it as running it would: what a chain asks
    /// before it loads a keyset.
    pub(super) fn check(&self, source: &S) -> Result<(), Error> {
        Runs::<S, K>::check(&self.freeze()?, source, None)
    }

    fn freeze(&self) -> Result<Plan<S, K>, Error> {
        let mut sources = self.sources.iter();
        let source = match (sources.next(), sources.next()) {
            (None, _) => Source::Call,
            (Some(Declare::Plan(label)), None) => {
                Source::Plan(label.clone().map_err(PlanError::ContextLabel)?)
            }
            (Some(Declare::Field(field)), None) => Source::Field(field.clone()),
            (Some(first), Some(second)) => {
                return Err(PlanError::TwoContextSources {
                    first: first.what(),
                    second: second.what(),
                }
                .into())
            }
        };
        if self.identity_without_field {
            return Err(PlanError::IdentityWithoutField.into());
        }
        let mut fields = Vec::with_capacity(self.fields.len());
        for (at, field) in self.fields.iter().enumerate() {
            let identity = field.identity.as_ref().unwrap_or(&field.name);
            check_indexes(&field.name, &field.indexes)?;
            let label = match (&source, keys_nothing(field.kind)) {
                // Carried as it is, under no label: its name is only the
                // record key, so any text will do.
                (_, true) => Ok(None),
                (Source::Plan(context), false) => join(context, identity).map(Some),
                (_, false) => Label::new([&**identity]).map(|_| None),
            }
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
                    identity: Arc::clone(identity),
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
        if let Some(schema) = self.fields_of.and_then(|fields| (fields.schema)()) {
            check_schema(&schema, &fields)?;
        }
        Ok(Plan {
            inner: Arc::new(PlanInner {
                source,
                names: fields.iter().map(|f| Arc::clone(&f.plan.name)).collect(),
                fields,
                fields_of: self.fields_of,
            }),
        })
    }
}

/// No index named twice in one field or one-value plan. Two match indexes
/// with different options are still one index twice: a field has one term
/// per index kind.
pub(crate) fn check_indexes(at: &str, indexes: &[IndexSpec]) -> Result<(), PlanError> {
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
/// name declared once as a target and once with data verbs is reported as
/// that, and one declared once passthrough and once indexed likewise, since
/// those are the likelier mistakes.
fn check_pair<S, K>(earlier: &Declared<S, K>, field: &Declared<S, K>) -> Result<(), PlanError> {
    if earlier.name == field.name {
        let target = |f: &Declared<S, K>| matches!(f.kind, FieldKind::EncryptInto);
        if target(earlier) != target(field) {
            return Err(PlanError::TargetWithVerbs {
                field: field.name.to_string(),
            });
        }
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
    // A passthrough or context field keys nothing, so it shares no
    // identity.
    if keys_nothing(earlier.kind) || keys_nothing(field.kind) {
        return Ok(());
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
/// that reads any field by name checks every time it runs.
fn check_value(have: &[&str], names: &[Arc<str>]) -> Result<(), Error> {
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

/// The base context every field's label extends, for one run.
enum Base<S> {
    Label(Label),
    Field(OfValue<S>),
}

impl<S: 'static, K: 'static> Plan<S, K> {
    /// The plan's context, when it was built with one.
    pub fn label(&self) -> Option<&Label> {
        match &self.inner.source {
            Source::Plan(label) => Some(label),
            _ => None,
        }
    }

    /// The field the plan takes its context from, if it has one.
    pub fn context_field(&self) -> Option<&str> {
        match &self.inner.source {
            Source::Field(field) => Some(&field.name),
            _ => None,
        }
    }

    /// The fields, in the order they were declared.
    pub fn field_plans(&self) -> impl ExactSizeIterator<Item = &FieldPlan> + '_ {
        self.inner.fields.iter().map(|field| &field.plan)
    }

    /// One field, for a query: `users_plan.field("email")?`.
    ///
    /// # Errors
    ///
    /// [`PlanError::NoSuchField`] if the plan has no field of that name.
    pub fn field(&self, name: &str) -> Result<FieldPlan, Error> {
        self.field_plans()
            .find(|field| field.name() == name)
            .cloned()
            .ok_or_else(|| {
                PlanError::NoSuchField {
                    field: name.to_owned(),
                }
                .into()
            })
    }

    /// The description one run of this plan executes over an `S`, given
    /// the context the call names (for a plan built without one; `None`
    /// otherwise): a check that the value's fields are the plan's (when it
    /// reads any by name), then each field's description, picked out of the
    /// value under its own label, zipped so every key request settles in
    /// one batch, and the record assembled. A context missing or given twice
    /// is a description that fails without I/O.
    ///
    /// This is the lowering, not a second executor: run it with
    /// [`KeysetCipher::run`], or let the chain do so.
    pub fn encryption<'s>(
        &self,
        context: Option<Label>,
    ) -> Encryption<'s, S, FieldValues, K, DeclaredContext> {
        let base = match self.base(context) {
            Ok(base) => base,
            Err(error) => return Encryption::failed(error.into()),
        };
        let names = Arc::clone(&self.inner.names);
        let fields_of = self.inner.fields_of;
        let mut record = inspect::<S, K, DeclaredContext, _>(move |source| match fields_of {
            Some(fields) => check_value(&(fields.names)(source), &names),
            None => Ok(()),
        })
        .map(|()| Vec::new());
        for field in &self.inner.fields {
            let operation = (field.lower)(PhantomData);
            let identity = Arc::clone(&field.plan.identity);
            let name = Arc::clone(&field.plan.name);
            let operation = match &base {
                // Under no label of its own: it ignores the context, so it
                // is handed the base one.
                Base::Label(context) if keys_nothing(field.plan.kind) => {
                    operation.under(NonEmpty::from(context.clone()))
                }
                Base::Label(context) => match join(context, &identity) {
                    Ok(label) => operation.under(NonEmpty::from(label)),
                    Err(source) => Encryption::failed(field_label(&name, source)),
                },
                Base::Field(of_value) => {
                    let of_value = Arc::clone(of_value);
                    let name = Arc::clone(&name);
                    let keys_nothing = keys_nothing(field.plan.kind);
                    operation.under_by(move |source: &S| {
                        let context = of_value(source)?;
                        match keys_nothing {
                            true => Ok(context),
                            false => join(&context, &identity).map_err(|e| field_label(&name, e)),
                        }
                    })
                }
            };
            record = record.zip(operation).map(move |(mut slots, slot)| {
                slots.push((name, slot));
                slots
            });
        }
        record.map(FieldValues::from_slots)
    }

    /// The base context one run extends, from the plan's source and the
    /// context the call names: exactly one of them.
    fn base(&self, call: Option<Label>) -> Result<Base<S>, PlanError> {
        match (&self.inner.source, call) {
            (Source::Plan(label), None) => Ok(Base::Label(label.clone())),
            (Source::Call, Some(label)) => Ok(Base::Label(label)),
            (Source::Field(field), None) => Ok(Base::Field(Arc::clone(&field.of_value))),
            (Source::Call, None) => Err(PlanError::NoContext),
            (source, Some(_)) => Err(PlanError::TwoContextSources {
                first: source.what(),
                second: FROM_CALL,
            }),
        }
    }

    /// A value against the plan, as running it checks it under the context
    /// the call names: one context source, the value's fields are the
    /// plan's (when it reads any by name), each is of the type the plan
    /// declares, and a context field holds a plain label.
    fn check_value(&self, source: &S, call: Option<&Label>) -> Result<(), Error> {
        let base = self.base(call.cloned())?;
        if let Some(fields) = self.inner.fields_of {
            check_value(&(fields.names)(source), &self.inner.names)?;
        }
        self.inner
            .fields
            .iter()
            .try_for_each(|field| (field.probe)(source))?;
        match base {
            Base::Label(_) => Ok(()),
            Base::Field(of_value) => of_value(source).map(drop),
        }
    }

    /// A stored record against the plan, as opening it checks it under the
    /// context the call names: the record's fields (see
    /// [`check_record`](Self::check_record)), then the context it opens
    /// under, a context field's checked against what the caller expects.
    fn check_opening(&self, record: &FieldValues, call: Option<&Label>) -> Result<(), Error> {
        self.check_record(record)?;
        self.opening_base(record, call.cloned()).map(drop)
    }

    /// The context a stored record opens under.
    fn opening_base(&self, record: &FieldValues, call: Option<Label>) -> Result<Label, Error> {
        match (&self.inner.source, call) {
            (Source::Field(field), expected) => field.stored(record, expected),
            (Source::Plan(label), call) => Ok(resolve_context(Some(label), call)?),
            (Source::Call, call) => Ok(resolve_context(None, call)?),
        }
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
    /// context it was sealed under (its label, extended by `extend`),
    /// passthrough fields carried back, fields that are terms alone left
    /// out. Every field of the record must be one the plan names, and every
    /// field the plan can return must be in it.
    ///
    /// `context` is what the call names: the context, for a plan built
    /// without one; for a plan with a context field, the context the caller
    /// expects the record's field to hold, checked before any key is
    /// requested; and nothing for a plan built with one.
    pub fn decryption(
        &self,
        mut record: FieldValues,
        context: Option<Label>,
        extend: DeclaredContext,
    ) -> Decryption<FieldValues, K> {
        if let Err(error) = self.check_record(&record) {
            return Decryption::failed(error.into());
        }
        let base = match self.opening_base(&record, context) {
            Ok(base) => base,
            Err(error) => return Decryption::failed(error),
        };
        let mut opened = Decryption::ready(Vec::new());
        for field in &self.inner.fields {
            let slot = record.take_slot(field.plan.name());
            let Some(FieldOpener { open, .. }) = &field.open else {
                continue;
            };
            let label = match keys_nothing(field.plan.kind) {
                // Under no label of its own: its opening ignores the
                // context, so it is handed the base one.
                true => Ok(base.clone()),
                false => join(&base, &field.plan.identity),
            };
            let opening = match (slot, label) {
                (None, _) => Decryption::failed(
                    PlanError::NotInValue {
                        field: field.plan.name().to_owned(),
                    }
                    .into(),
                ),
                (Some(_), Err(source)) => Decryption::failed(field_label(&field.plan.name, source)),
                (Some(slot), Ok(label)) => {
                    let sealed_under = extend.clone().under(NonEmpty::from(label));
                    open(field.plan.name(), slot, sealed_under)
                        .unwrap_or_else(|error| Decryption::failed(error.into()))
                }
            };
            let name = Arc::clone(&field.plan.name);
            opened = opened.zip(opening).map(move |(mut slots, slot)| {
                slots.push((name, slot));
                slots
            });
        }
        opened.map(FieldValues::from_slots)
    }
}

/// Whether a field is carried under no label of its own: a passthrough or
/// a context field, whose name is only its record key.
fn keys_nothing(kind: FieldKind) -> bool {
    matches!(kind, FieldKind::Passthrough | FieldKind::ContextField)
}

fn field_label(field: &str, source: LabelError) -> Error {
    PlanError::FieldLabel {
        field: field.to_owned(),
        source,
    }
    .into()
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
    /// Lower the plan and run it over `source`, under the context the call
    /// names (if any) extended by `extend`: the [`Pending`], with every term
    /// already derived and every key request queued, and nothing sent.
    fn pending<'p>(
        &self,
        keyset: &'p KeysetCipher<'_, K>,
        source: &Src,
        context: Option<Label>,
        extend: DeclaredContext,
    ) -> Pending<'p, Self::Output, K>;

    /// Whether `source` is one the plan can run over under the context the
    /// call names (if any): the refusals [`pending`](Self::pending) would
    /// raise about the value and the context, asked before a chain loads a
    /// keyset. A plan with nothing to check keeps this default.
    ///
    /// # Errors
    ///
    /// The [`Error::Plan`] that running the plan over `source` would raise.
    fn check(&self, _source: &Src, _context: Option<&Label>) -> Result<(), Error> {
        Ok(())
    }
}

/// A plan that can open a stored `R`, producing `Output`: what
/// [`using`](crate::plan::OpenBuilder::using) asks of its plan.
pub trait Opens<R, K> {
    /// What opening produces.
    type Output: 'static;
    /// The opening of `record`, under the context the call names (if any;
    /// see [`Plan::decryption`]) extended by `extend`.
    fn decryption(
        &self,
        record: R,
        context: Option<Label>,
        extend: DeclaredContext,
    ) -> Decryption<Self::Output, K>;

    /// Whether `record` is one the plan can open under the context the
    /// call names (if any): the refusals
    /// [`decryption`](Self::decryption) would raise about the record and
    /// the context, asked before a chain loads a keyset. A plan with
    /// nothing to check keeps this default.
    ///
    /// # Errors
    ///
    /// The [`Error::Plan`] (or [`Error::ContextMismatch`]) that opening
    /// `record` would raise before any key request.
    fn check(&self, _record: &R, _context: Option<&Label>) -> Result<(), Error> {
        Ok(())
    }
}

impl<S: 'static, K: 'static> Runs<S, K> for Plan<S, K> {
    type Output = FieldValues;
    fn pending<'p>(
        &self,
        keyset: &'p KeysetCipher<'_, K>,
        source: &S,
        context: Option<Label>,
        extend: DeclaredContext,
    ) -> Pending<'p, FieldValues, K> {
        keyset.run(self.encryption(context), source, extend)
    }

    fn check(&self, source: &S, context: Option<&Label>) -> Result<(), Error> {
        self.check_value(source, context)
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
                context: Option<Label>,
                extend: DeclaredContext,
            ) -> Pending<'p, Self::Output, K> {
                Pending::all(
                    keyset,
                    source
                        .iter()
                        .map(|item| {
                            Runs::<$item, K>::pending(
                                self,
                                keyset,
                                item,
                                context.clone(),
                                extend.clone(),
                            )
                        })
                        .collect(),
                )
            }
            fn check(&self, source: &[$item], context: Option<&Label>) -> Result<(), Error> {
                source
                    .iter()
                    .try_for_each(|item| Runs::<$item, K>::check(self, item, context))
            }
        }
        impl<$($generics)*> Runs<Vec<$item>, K> for $plan where $($bounds)* {
            type Output = Vec<<Self as Runs<$item, K>>::Output>;
            fn pending<'p>(
                &self,
                keyset: &'p KeysetCipher<'_, K>,
                source: &Vec<$item>,
                context: Option<Label>,
                extend: DeclaredContext,
            ) -> Pending<'p, Self::Output, K> {
                Runs::<[$item], K>::pending(self, keyset, source.as_slice(), context, extend)
            }
            fn check(&self, source: &Vec<$item>, context: Option<&Label>) -> Result<(), Error> {
                Runs::<[$item], K>::check(self, source.as_slice(), context)
            }
        }
    )+};
}
pub(crate) use runs_over_collections;
runs_over_collections! {
    [S, K] Plan<S, K> => S where [S: 'static, K: 'static];
}

impl<S: 'static, K: 'static> Opens<FieldValues, K> for Plan<S, K> {
    type Output = FieldValues;
    fn decryption(
        &self,
        record: FieldValues,
        context: Option<Label>,
        extend: DeclaredContext,
    ) -> Decryption<FieldValues, K> {
        Plan::decryption(self, record, context, extend)
    }
    fn check(&self, record: &FieldValues, context: Option<&Label>) -> Result<(), Error> {
        self.check_opening(record, context)
    }
}

impl<S: 'static, K: 'static> Opens<Vec<FieldValues>, K> for Plan<S, K> {
    type Output = Vec<FieldValues>;
    fn decryption(
        &self,
        records: Vec<FieldValues>,
        context: Option<Label>,
        extend: DeclaredContext,
    ) -> Decryption<Vec<FieldValues>, K> {
        Decryption::all(
            records
                .into_iter()
                .map(|record| Plan::decryption(self, record, context.clone(), extend.clone())),
        )
    }
    fn check(&self, records: &Vec<FieldValues>, context: Option<&Label>) -> Result<(), Error> {
        records
            .iter()
            .try_for_each(|record| self.check_opening(record, context))
    }
}
