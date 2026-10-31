//! The chain on the cipher: `cipher.encrypt(&value)`, `cipher.query(&value)`
//! and `cipher.open(record)`, each finished by `.await`, and [`all`] for
//! several at once.
use std::future::IntoFuture;
use std::marker::PhantomData;

use stack_kms::{DataKeySource, IdentifiedBy, IndexKeySource, MaybeSend};
use uuid::Uuid;

use super::build::{FieldPlan, FieldsBuilder, IntoLabel, Opens, PlanContext, Runs};
use super::field_ref::FieldRef;
use super::value::{Indexed, Laid, Typed, ValueLayout, ValuePlan, ValueShape};
use super::PlanError;
use crate::op::{Answers, DefaultIndex, Input, LabelledTarget, Operator, QueryToken, Supports};
use crate::target::{
    ciphertext, Borrowed, CallerContext, DeclaredContext, DecryptField, Decryptable, EncryptFrom,
    Index, Indexes, Layout, Pending, PendingFuture, Select, Whole,
};
use crate::{Error, KeysetCipher, Label, LabelError, NonEmpty, StackCipher, StackCipherText};

/// What a cipher's data-key source must offer for a chain to run: data keys
/// to seal and open, index keys to load a keyset named in the chain, and,
/// on native targets, `Sync`, because the future holds the cipher across an
/// await (as awaiting a [`Pending`] does).
#[cfg(not(target_arch = "wasm32"))]
pub trait PlanKms: DataKeySource + IndexKeySource + Sync + 'static {}
#[cfg(not(target_arch = "wasm32"))]
impl<K: DataKeySource + IndexKeySource + Sync + 'static> PlanKms for K {}
/// See the native definition; the same minus `Sync`.
#[cfg(target_arch = "wasm32")]
pub trait PlanKms: DataKeySource + IndexKeySource + 'static {}
#[cfg(target_arch = "wasm32")]
impl<K: DataKeySource + IndexKeySource + 'static> PlanKms for K {}

/// The keyset a chain names with `.keyset(..)`: a [`KeysetCipher`] already
/// in hand, or a keyset by id or name, loaded when the chain is awaited (as
/// [`StackCipher::keyset`] would load it).
///
/// A chain that names no keyset encrypts under the client's default keyset,
/// and opens leaves from any keyset the client may use. Inside [`all`], a
/// chain that names none encrypts under the keyset the batch's other chains
/// name (or the default), and still opens leaves from any keyset.
pub enum KeysetChoice<'a, K> {
    /// A keyset already selected.
    Handle(KeysetCipher<'a, K>),
    /// A keyset to select when the chain runs.
    Named(IdentifiedBy),
}

impl<K> std::fmt::Debug for KeysetChoice<'_, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeysetChoice::Handle(keyset) => f.debug_tuple("Handle").field(keyset).finish(),
            KeysetChoice::Named(keyset) => f.debug_tuple("Named").field(keyset).finish(),
        }
    }
}

impl<'a, K> From<KeysetCipher<'a, K>> for KeysetChoice<'a, K> {
    fn from(keyset: KeysetCipher<'a, K>) -> Self {
        KeysetChoice::Handle(keyset)
    }
}
impl<'a, K> From<&KeysetCipher<'a, K>> for KeysetChoice<'a, K> {
    fn from(keyset: &KeysetCipher<'a, K>) -> Self {
        KeysetChoice::Handle(keyset.clone())
    }
}
impl<K> From<IdentifiedBy> for KeysetChoice<'_, K> {
    fn from(keyset: IdentifiedBy) -> Self {
        KeysetChoice::Named(keyset)
    }
}
impl<K> From<Uuid> for KeysetChoice<'_, K> {
    fn from(keyset: Uuid) -> Self {
        KeysetChoice::Named(IdentifiedBy::Uuid(keyset))
    }
}
impl<K> From<&str> for KeysetChoice<'_, K> {
    fn from(name: &str) -> Self {
        KeysetChoice::Named(IdentifiedBy::Name(name.to_owned().into()))
    }
}
impl<K> From<String> for KeysetChoice<'_, K> {
    fn from(name: String) -> Self {
        KeysetChoice::Named(IdentifiedBy::Name(name.into()))
    }
}
impl<K> From<&String> for KeysetChoice<'_, K> {
    fn from(name: &String) -> Self {
        Self::from(name.as_str())
    }
}

/// What every chain carries besides its value: the cipher, the keyset it
/// names, the context it names for a plan built without one, and the
/// caller's extension of the plan's contexts.
struct Common<'a, K> {
    cipher: &'a StackCipher<K>,
    keyset: Option<KeysetChoice<'a, K>>,
    context: Option<Result<Label, LabelError>>,
    extend: DeclaredContext,
}

impl<'a, K> Common<'a, K> {
    fn new(cipher: &'a StackCipher<K>) -> Self {
        Self {
            cipher,
            keyset: None,
            context: None,
            extend: DeclaredContext::default(),
        }
    }

    /// The context the call named, parsed, left in place: what a chain's
    /// [`check`](Operation::check) reads.
    fn peek_context(&self) -> Result<Option<&Label>, PlanError> {
        match &self.context {
            None => Ok(None),
            Some(Ok(label)) => Ok(Some(label)),
            Some(Err(error)) => Err(PlanError::ContextLabel(*error)),
        }
    }

    /// The context the call named, parsed.
    fn call_context(&mut self) -> Result<Option<Label>, PlanError> {
        self.context
            .take()
            .transpose()
            .map_err(PlanError::ContextLabel)
    }
}

mod sealed {
    pub trait Sealed {}
}

/// One finished chain: something `.await` settles, and [`all`] batches.
///
/// Sealed: the chains in this module are the operations. What the trait
/// shows is the shape the design promises: a chain is checked with no I/O
/// ([`check`](Self::check)), then yields a [`Pending`] synchronously
/// ([`prepare`](Self::prepare)), with every term derived and every key
/// request queued, and only awaiting it reaches ZeroKMS.
///
/// Awaiting a chain checks it before it loads a keyset it names, so a plan
/// that does not hold up is refused before any request to ZeroKMS, the
/// keyset lookup included.
pub trait Operation<'a, K: 'static>: sealed::Sealed + Sized {
    /// What the chain produces.
    type Output: MaybeSend + 'static;
    /// The cipher the chain was started on.
    fn cipher(&self) -> &'a StackCipher<K>;
    /// The keyset the chain names, if any, taken out of it.
    fn take_keyset(&mut self) -> Option<KeysetChoice<'a, K>>;
    /// The chain's plan, and the value or record it runs over, checked
    /// with no I/O and no keyset: the [`Error::Plan`] refusals
    /// [`prepare`](Self::prepare) would raise.
    ///
    /// # Errors
    ///
    /// The first refusal, as [`prepare`](Self::prepare) would report it.
    fn check(&self) -> Result<(), Error>;
    /// Lower the chain and build its [`Pending`] under `keyset`, with no
    /// I/O. `scoped` says whether this chain named `keyset`: an opening is
    /// then confined to it, and otherwise opens leaves from any keyset.
    fn prepare<'p>(
        self,
        keyset: &'p KeysetCipher<'a, K>,
        scoped: bool,
    ) -> Pending<'p, Self::Output, K>
    where
        'a: 'p;
}

/// The keyset a set of chains runs under: the one they name (all the same
/// one), or the client's default when none names one. The `bool` says
/// whether one was named.
async fn resolve<'a, K: PlanKms>(
    cipher: &'a StackCipher<K>,
    choices: Vec<Option<KeysetChoice<'a, K>>>,
) -> Result<(KeysetCipher<'a, K>, bool), Error> {
    let mut chosen: Option<KeysetCipher<'a, K>> = None;
    for choice in choices.into_iter().flatten() {
        let keyset = match choice {
            KeysetChoice::Handle(keyset) => keyset,
            KeysetChoice::Named(keyset) => cipher.keyset(keyset).await?,
        };
        match &chosen {
            Some(first) if first.keyset_id() != keyset.keyset_id() => {
                return Err(Error::KeysetMismatch {
                    left: first.keyset_id(),
                    right: keyset.keyset_id(),
                });
            }
            Some(_) => {}
            None => chosen = Some(keyset),
        }
    }
    Ok(match chosen {
        Some(keyset) => (keyset, true),
        None => (cipher.default_keyset(), false),
    })
}

/// Await one chain: resolve its keyset, prepare it, settle it.
fn settle<'a, K, O>(mut operation: O) -> PendingFuture<'a, O::Output>
where
    K: PlanKms,
    O: Operation<'a, K> + MaybeSend + 'a,
{
    Box::pin(async move {
        operation.check()?;
        let choice = operation.take_keyset();
        let (keyset, scoped) = resolve(operation.cipher(), vec![choice]).await?;
        operation.prepare(&keyset, scoped).settle().await
    })
}

/// `.keyset(..)` and `.extend(..)`, on every chain.
macro_rules! chain_options {
    ($([$($generics:tt)*] $chain:ty;)+) => {$(
        impl<$($generics)*> $chain {
            /// Run under this keyset: a [`KeysetCipher`] in hand, or a
            /// keyset id or name, loaded when the chain is awaited. With
            /// none, encryption uses the client's default keyset.
            pub fn keyset(mut self, keyset: impl Into<KeysetChoice<'a, K>>) -> Self {
                self.common.keyset = Some(keyset.into());
                self
            }
            /// Extend the plan's every context by `parts` for this call:
            /// each field's `<context>/<field>` becomes
            /// `(<context>/<field>)/<parts>`, as a derived record's caller
            /// context does. The same parts must be given to read it back.
            /// A second call replaces the first.
            pub fn extend(mut self, parts: impl Into<DeclaredContext>) -> Self {
                self.common.extend = parts.into();
                self
            }
        }
        impl<$($generics)*> sealed::Sealed for $chain {}
    )+};
}

/// `.await` on a finished chain.
macro_rules! settles {
    ($([$($generics:tt)*] $chain:ty;)+) => {$(
        impl<$($generics)*> IntoFuture for $chain
        where
            Self: Operation<'a, K> + MaybeSend + 'a,
            K: PlanKms,
        {
            type Output = Result<<Self as Operation<'a, K>>::Output, Error>;
            type IntoFuture = PendingFuture<'a, <Self as Operation<'a, K>>::Output>;
            fn into_future(self) -> Self::IntoFuture {
                settle(self)
            }
        }
    )+};
}

impl<K: 'static> StackCipher<K> {
    /// Start a chain that encrypts `value`.
    ///
    /// Finish it with a context ([`context`](EncryptBuilder::context)) or a
    /// saved plan ([`using`](EncryptBuilder::using)), then `.await`. Before
    /// the await nothing has touched a key. With no `.keyset(..)` the
    /// client's default keyset mints the data keys.
    ///
    /// This is the fluent spelling of the cipher-directed and
    /// target-directed entry points on [`KeysetCipher`]
    /// ([`encrypt`](KeysetCipher::encrypt), [`encrypt_as`](KeysetCipher::encrypt_as),
    /// [`run`](KeysetCipher::run)), which stay; see the [`plan`](crate::plan)
    /// module for the whole chain.
    pub fn encrypt<'a, S: ?Sized>(&'a self, value: &'a S) -> EncryptBuilder<'a, S, K> {
        EncryptBuilder {
            common: Common::new(self),
            source: value,
        }
    }

    /// Start a chain that derives the query term for the operator `op` over
    /// `value`, to match terms a plan wrote. Name the plan with
    /// [`on`](QueryBuilder::on): `cipher.query(op::Eq, "bob@example.com").on(&plan)`.
    /// The plan chooses the index that answers the operator there; an
    /// index the plan declares beside that one is named first, with
    /// [`via`](QueryBuilder::via).
    ///
    /// The value is what the operator takes ([`Input`]): one plaintext, or
    /// for `op::Between` a pair of them, `cipher.query(op::Between, &(18, 65))`.
    /// It is copied once (`to_owned`), so `query(op::Eq, "bob@example.com")`
    /// queries a `String` field.
    pub fn query<'a, Op, Q>(&'a self, op: Op, value: &Q) -> QueryBuilder<'a, Op, F<Q>, K>
    where
        Op: Operator,
        Q: ToOwned + ?Sized,
        F<Q>: Input<Op::Arity>,
    {
        let _: Op = op;
        QueryBuilder {
            common: Common::new(self),
            value: value.to_owned(),
            op: PhantomData,
        }
    }

    /// Start a chain that decrypts `record`, a record a plan wrote. Name the
    /// plan with [`using`](OpenBuilder::using), then `.await`.
    ///
    /// Named `open` rather than `decrypt`: [`StackCipher::decrypt`] is the
    /// cipher-directed decrypt and keeps its two-argument form.
    pub fn open<'a, R>(&'a self, record: R) -> OpenBuilder<'a, R, K> {
        OpenBuilder {
            common: Common::new(self),
            record,
        }
    }
}

/// A chain encrypting a value, before its context or plan is chosen.
pub struct EncryptBuilder<'a, S: ?Sized, K> {
    common: Common<'a, K>,
    source: &'a S,
}

impl<'a, S: ?Sized, K: 'static> EncryptBuilder<'a, S, K> {
    /// Encrypt under `context`: one tree, sealed under that label, as
    /// `keyset.encrypt(&value, label)` does. Text is parsed as a
    /// [`Label`] (`"documents/v2/body"` is three segments), and text that
    /// is not one is refused when the chain is awaited.
    pub fn context(self, context: impl IntoLabel) -> EncryptWithContext<'a, S, K> {
        EncryptWithContext {
            common: self.common,
            source: self.source,
            context: context.into_label(),
        }
    }

    /// Encrypt as the saved `plan` declares: a fields plan ([`Plan`](super::Plan)) or a
    /// one-value plan ([`ValuePlan`]), over one value, a slice or a `Vec` of
    /// them. A collection settles every key request in one batch. The plan
    /// must have a context of its own (built with one, or a context field);
    /// one without is given its context by
    /// [`context(..).using(..)`](EncryptWithContext::using).
    pub fn using<P: Runs<S, K>>(self, plan: &'a P) -> EncryptUsing<'a, S, P, K> {
        EncryptUsing {
            common: self.common,
            source: self.source,
            plan,
        }
    }
}

/// A chain encrypting a value under a context: awaited as it is, one tree;
/// or indexed ([`with`](Self::with)), or field by field
/// ([`fields`](Self::fields)).
pub struct EncryptWithContext<'a, S: ?Sized, K> {
    common: Common<'a, K>,
    source: &'a S,
    context: Result<Label, LabelError>,
}

impl<'a, S: ?Sized, K: 'static> EncryptWithContext<'a, S, K> {
    /// Encrypt as the saved `plan` declares, under this context: for a plan
    /// built without a context of its own, this call names it. A plan that
    /// has one (built with it, or from a context field) is refused with
    /// [`PlanError::TwoContextSources`] when awaited, before any key is
    /// requested.
    pub fn using<P: Runs<S, K>>(mut self, plan: &'a P) -> EncryptUsing<'a, S, P, K> {
        self.common.context = Some(self.context);
        EncryptUsing {
            common: self.common,
            source: self.source,
            plan,
        }
    }

    /// Seal the value with `indexes` beside it: one index or a tuple of
    /// two to five, each defined over the value's type. The output is an
    /// [`Encrypted<Terms>`](crate::Encrypted), terms read by destructuring.
    pub fn with<X: Indexes<S>>(self, indexes: X) -> EncryptIndexed<'a, S, X, K>
    where
        S: Sized,
    {
        EncryptIndexed {
            common: self.common,
            source: self.source,
            plan: PlanContext::from_result(self.context).with(indexes),
        }
    }

    /// Seal each top-level field on its own, under `<context>/<field>`, as
    /// the field verbs that follow declare. The output is a
    /// [`FieldValues`](super::FieldValues).
    pub fn fields(self) -> EncryptFields<'a, S, K>
    where
        S: Sized + 'static,
    {
        EncryptFields {
            common: self.common,
            source: self.source,
            plan: PlanContext::from_result(self.context).fields(),
        }
    }
}

impl<'a, S, K: 'static> Operation<'a, K> for EncryptWithContext<'a, S, K>
where
    S: crate::Encrypt + Clone,
{
    type Output = StackCipherText;
    fn cipher(&self) -> &'a StackCipher<K> {
        self.common.cipher
    }
    fn take_keyset(&mut self) -> Option<KeysetChoice<'a, K>> {
        self.common.keyset.take()
    }
    fn check(&self) -> Result<(), Error> {
        match &self.context {
            Ok(_) => Ok(()),
            Err(error) => Err(PlanError::ContextLabel(*error).into()),
        }
    }
    fn prepare<'p>(self, keyset: &'p KeysetCipher<'a, K>, _: bool) -> Pending<'p, Self::Output, K>
    where
        'a: 'p,
    {
        match self.context {
            Ok(label) => keyset.run(
                ciphertext::<S, K, Borrowed>().under(NonEmpty::from(label)),
                self.source,
                self.common.extend,
            ),
            Err(error) => Pending::failed(keyset, PlanError::ContextLabel(error).into()),
        }
    }
}

/// A chain encrypting one value with indexes beside it.
pub struct EncryptIndexed<'a, S, X, K> {
    common: Common<'a, K>,
    source: &'a S,
    plan: super::value::ValuePlanBuilder<S, Indexed<X>>,
}

impl<'a, S, X, K: 'static> Operation<'a, K> for EncryptIndexed<'a, S, X, K>
where
    S: crate::Encrypt + Clone,
    X: Indexes<S> + Clone,
    X::Terms: MaybeSend,
{
    type Output = crate::Encrypted<X::Terms>;
    fn cipher(&self) -> &'a StackCipher<K> {
        self.common.cipher
    }
    fn take_keyset(&mut self) -> Option<KeysetChoice<'a, K>> {
        self.common.keyset.take()
    }
    fn check(&self) -> Result<(), Error> {
        self.plan.check()
    }
    fn prepare<'p>(self, keyset: &'p KeysetCipher<'a, K>, _: bool) -> Pending<'p, Self::Output, K>
    where
        'a: 'p,
    {
        match self.plan.build() {
            Ok(plan) => plan.pending(keyset, self.source, None, self.common.extend),
            Err(error) => Pending::failed(keyset, error),
        }
    }
}

/// A chain encrypting a value field by field: the field verbs of
/// [`FieldsBuilder`], then `.await`. The plan is validated when it is
/// awaited, with the same errors as [`FieldsBuilder::build`].
pub struct EncryptFields<'a, S: 'static, K: 'static> {
    common: Common<'a, K>,
    source: &'a S,
    plan: FieldsBuilder<S, K>,
}

impl<'a, S: 'static, K: 'static> EncryptFields<'a, S, K> {
    /// [`FieldsBuilder::encrypt`].
    pub fn encrypt<F>(mut self, field: impl FieldRef<S, F>) -> Self
    where
        F: crate::Encrypt + crate::Decrypt + Clone + Send + 'static,
    {
        self.plan = self.plan.encrypt::<F>(field);
        self
    }
    /// [`FieldsBuilder::encrypt_index`].
    pub fn encrypt_index<F>(
        mut self,
        field: impl FieldRef<S, F>,
        indexes: impl Indexes<F, Terms: Send> + Clone + Send + Sync + 'static,
    ) -> Self
    where
        F: crate::Encrypt + crate::Decrypt + Clone + Send + 'static,
    {
        self.plan = self.plan.encrypt_index::<F>(field, indexes);
        self
    }
    /// [`FieldsBuilder::index`].
    pub fn index<F>(
        mut self,
        field: impl FieldRef<S, F>,
        indexes: impl Indexes<F, Terms: Send> + Clone + Send + Sync + 'static,
    ) -> Self
    where
        F: Clone + Send + 'static,
    {
        self.plan = self.plan.index::<F>(field, indexes);
        self
    }
    /// [`FieldsBuilder::passthrough`]: carried **unsealed and
    /// unauthenticated**.
    pub fn passthrough<F>(mut self, field: impl FieldRef<S, F>) -> Self
    where
        F: Clone + Send + 'static,
    {
        self.plan = self.plan.passthrough::<F>(field);
        self
    }
    /// [`FieldsBuilder::encrypt_into`].
    pub fn encrypt_into<T, F>(mut self, field: impl FieldRef<S, F>) -> Self
    where
        F: Send + 'static,
        T: EncryptFrom<F> + Decryptable + DecryptField<F, CallerContext> + Send,
        CallerContext: Into<T::Context>,
    {
        self.plan = self.plan.encrypt_into::<T, F>(field);
        self
    }
    /// [`FieldsBuilder::identity`].
    pub fn identity(mut self, identity: &str) -> Self {
        self.plan = self.plan.identity(identity);
        self
    }
}

impl<'a, S: 'static, K: 'static> Operation<'a, K> for EncryptFields<'a, S, K> {
    type Output = super::FieldValues;
    fn cipher(&self) -> &'a StackCipher<K> {
        self.common.cipher
    }
    fn take_keyset(&mut self) -> Option<KeysetChoice<'a, K>> {
        self.common.keyset.take()
    }
    fn check(&self) -> Result<(), Error> {
        self.plan.check(self.source)
    }
    fn prepare<'p>(self, keyset: &'p KeysetCipher<'a, K>, _: bool) -> Pending<'p, Self::Output, K>
    where
        'a: 'p,
    {
        match self.plan.build() {
            Ok(plan) => plan.pending(keyset, self.source, None, self.common.extend),
            Err(error) => Pending::failed(keyset, error),
        }
    }
}

/// A chain encrypting a value, a slice or a `Vec` as a saved plan declares.
pub struct EncryptUsing<'a, S: ?Sized, P, K> {
    common: Common<'a, K>,
    source: &'a S,
    plan: &'a P,
}

impl<'a, S: ?Sized, P: Runs<S, K>, K: 'static> Operation<'a, K> for EncryptUsing<'a, S, P, K>
where
    P::Output: MaybeSend,
{
    type Output = P::Output;
    fn cipher(&self) -> &'a StackCipher<K> {
        self.common.cipher
    }
    fn take_keyset(&mut self) -> Option<KeysetChoice<'a, K>> {
        self.common.keyset.take()
    }
    fn check(&self) -> Result<(), Error> {
        self.plan.check(self.source, self.common.peek_context()?)
    }
    fn prepare<'p>(
        mut self,
        keyset: &'p KeysetCipher<'a, K>,
        _: bool,
    ) -> Pending<'p, Self::Output, K>
    where
        'a: 'p,
    {
        match self.common.call_context() {
            Ok(context) => self
                .plan
                .pending(keyset, self.source, context, self.common.extend),
            Err(error) => Pending::failed(keyset, error.into()),
        }
    }
}

/// The owned form of a queried value: `String` for a `str` query.
type F<Q> = <Q as ToOwned>::Owned;

/// A chain deriving the query term for an operator, before its plan is
/// named.
pub struct QueryBuilder<'a, Op, F, K> {
    common: Common<'a, K>,
    value: F,
    op: PhantomData<fn() -> Op>,
}

impl<'a, Op: Operator, F: Input<Op::Arity>, K: 'static> QueryBuilder<'a, Op, F, K> {
    /// Name the context the term is derived under, for a plan built
    /// without one: the context the write's call named, or for a plan with
    /// a context field, the value that field held. A plan built with its
    /// context refuses this ([`PlanError::TwoContextSources`]).
    pub fn context(mut self, context: impl IntoLabel) -> Self {
        self.common.context = Some(context.into_label());
        self
    }

    /// Answer the operator through `index` rather than the index the plan
    /// chooses for it ([`Chooses`]): a match index with its own
    /// configuration, an OPE index where ORE is the default, or an index
    /// of a target type that has no [`Answers`] impl for the operator. The
    /// plan named next must declare it, as [`on`](Self::on) says.
    pub fn via<I: Supports<Op, F>>(self, index: I) -> QueryVia<'a, Op, F, I, K> {
        QueryVia {
            common: self.common,
            value: self.value,
            op: self.op,
            index,
        }
    }

    /// Query on `plan`: a field of a fields plan
    /// ([`Plan::field`](super::Plan::field)), or a one-value plan
    /// ([`ValuePlan`]). The plan chooses the index that answers the
    /// operator ([`Chooses`]), and the term is derived under exactly the
    /// label the write used.
    ///
    /// What the plan's type can see is checked here: an operator it does
    /// not answer, a value that is not what the operator takes over the
    /// plan's plaintext, or a one-value plan without the index, does not
    /// compile. A field of a fields plan is data, so there an index the
    /// field does not declare, or declares with other options, is refused
    /// when the query is awaited ([`PlanError::IndexNotDeclared`],
    /// [`PlanError::IndexOptions`]), before any key is requested.
    pub fn on<P, At>(self, plan: &P) -> QueryOp<'a, F, Op, P::Via, K>
    where
        P: Chooses<Op, F, At>,
    {
        let QueryBuilder { common, value, op } = self;
        QueryOp::resolve(
            common,
            value,
            op,
            (),
            |()| P::Via::default(),
            |(), call| plan.choose(call),
        )
    }
}

/// A chain deriving the query term for an operator through a named index,
/// before its plan is named.
pub struct QueryVia<'a, Op, F, I, K> {
    common: Common<'a, K>,
    value: F,
    op: PhantomData<fn() -> Op>,
    index: I,
}

impl<'a, Op, F, I, K: 'static> QueryVia<'a, Op, F, I, K>
where
    Op: Operator,
    F: Input<Op::Arity>,
    I: Supports<Op, F>,
{
    /// Name the context the term is derived under, as
    /// [`QueryBuilder::context`], before or after the index.
    pub fn context(mut self, context: impl IntoLabel) -> Self {
        self.common.context = Some(context.into_label());
        self
    }

    /// Query on `plan` through the named index, which the plan must
    /// declare ([`Resolves`]): a one-value plan without it does not
    /// compile; a field of a fields plan without it is refused when the
    /// query is awaited. A one-value plan built `with` indexes uses its
    /// own index of that type, so the named index says only which.
    pub fn on<P, At>(self, plan: &P) -> QueryOp<'a, F, Op, I, K>
    where
        P: Resolves<F::Plaintext, I, At>,
    {
        let QueryVia {
            common,
            value,
            op,
            index,
        } = self;
        QueryOp::resolve(
            common,
            value,
            op,
            index,
            |index| index,
            |index, call| plan.resolve(index, call),
        )
    }
}

/// A plan a query for the operator `Op`, given `In`, runs on, and the
/// index it answers the operator with. Sealed: the three plan shapes
/// implement it.
///
/// A field of a fields plan and a one-value plan built `with` indexes
/// answer through the operator's [`DefaultIndex`]; a one-value plan for a
/// target type answers through the type's [`Answers`] impl, when the type
/// is a [`LabelledTarget`], whose stored terms were derived under the
/// context the plan's label names. Such a plan is queried through the
/// indexes the type declares ([`ValueLayout`]) even when the type cannot be
/// encrypted through it, as an EQL type sealed under its column cannot.
/// The plan's
/// plaintext is the input's ([`Input::Plaintext`]): `S` for a query given
/// an `S`, and for a `Between` given an `(S, S)`. `At` is the position of
/// that index in a plan built `with` several, and is inferred.
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not answer `{Op}` given `{In}`",
    label = "no index answers this operator on this plan",
    note = "a field of a fields plan or a plan built `with` indexes answers an operator through its default index (`op::Eq`: `Equality`; `op::Matches`: `Match` with the default configuration, case-insensitive and over text only; `op::Lt`, `Lte`, `Gt`, `Gte` and `Between`: `Ore` over an integer, `Between` given a pair); a typed plan answers the operators its target type implements `Answers` for; `.via(index)` names an index the plan declares"
)]
pub trait Chooses<Op: Operator, In: Input<Op::Arity>, At>: plan_sealed::Sealed {
    /// The index that answers `Op` on this plan.
    type Via: Supports<Op, In> + Default;
    /// The index the query runs through on this plan, and the label the
    /// write used, or why the plan refuses the query, as
    /// [`Resolves::resolve`] says. `call` is the context the call named, if
    /// any.
    fn choose(&self, call: Option<Label>) -> (Self::Via, Result<Label, PlanError>);
}

impl<Op: DefaultIndex<In>, In: Input<Op::Arity>> Chooses<Op, In, Whole> for FieldPlan {
    type Via = Op::Via;
    fn choose(&self, call: Option<Label>) -> (Op::Via, Result<Label, PlanError>) {
        Resolves::<In::Plaintext, Op::Via, Whole>::resolve(self, Op::Via::default(), call)
    }
}

impl<Op, S, In, X, At> Chooses<Op, In, At> for ValuePlan<S, Indexed<X>>
where
    Op: DefaultIndex<In>,
    Op::Via: Clone,
    In: Input<Op::Arity, Plaintext = S>,
    S: 'static,
    X: Indexes<S> + Select<Op::Via, At>,
{
    type Via = Op::Via;
    fn choose(&self, call: Option<Label>) -> (Op::Via, Result<Label, PlanError>) {
        Resolves::<S, Op::Via, At>::resolve(self, Op::Via::default(), call)
    }
}

impl<Op, S, In, T> Chooses<Op, In, Whole> for ValuePlan<S, Typed<T>>
where
    Op: Operator,
    In: Input<Op::Arity, Plaintext = S>,
    S: 'static,
    T: Answers<Op, In> + LabelledTarget,
    Typed<T>: ValueLayout<S>,
{
    type Via = T::Via;
    fn choose(&self, call: Option<Label>) -> (T::Via, Result<Label, PlanError>) {
        let index = T::Via::default();
        let label = self.query_label(&index.spec(), call);
        (index, label)
    }
}

/// A plan laid out by value answers the operators its layout's index
/// supports, through that index, under the plan's options.
impl<Op, S, In, X, T> Chooses<Op, In, Whole> for ValuePlan<S, Laid<X, T>>
where
    Op: Operator,
    In: Input<Op::Arity, Plaintext = S>,
    S: 'static,
    X: Layout<S, Target = T>,
    X::Index: Supports<Op, In> + Default,
    Laid<X, T>: ValueShape<S>,
{
    type Via = X::Index;
    fn choose(&self, call: Option<Label>) -> (X::Index, Result<Label, PlanError>) {
        Resolves::<S, X::Index, Whole>::resolve(self, X::Index::default(), call)
    }
}

mod plan_sealed {
    use super::{FieldPlan, Indexed, Laid, Typed, ValuePlan};
    pub trait Sealed {}
    impl Sealed for FieldPlan {}
    impl<F, X> Sealed for ValuePlan<F, Indexed<X>> {}
    impl<F, T> Sealed for ValuePlan<F, Typed<T>> {}
    impl<F, X, T> Sealed for ValuePlan<F, Laid<X, T>> {}
}

/// A plan the index `I` over the plaintext `S` can be queried on. Sealed:
/// the three plan shapes implement it, and each finds the label the write
/// used.
///
/// A field of a fields plan ([`Plan::field`](super::Plan::field)) and a
/// one-value plan for a target type take the index as given, and refuse
/// one the plan does not declare when the query is awaited
/// ([`PlanError::IndexNotDeclared`]). A one-value plan for a target type
/// takes a named index only when the type is sealed under the label
/// ([`ValueShape`]): a type that answers through its [`Answers`] impls
/// alone, as an EQL type does, cannot have another index named on its
/// plan, which would send a term the type's SQL does not take. A one-value plan built `with`
/// indexes selects its own index of that type ([`Indexes::select`]), at
/// the position `At`, which is inferred; a plan without that index does
/// not compile.
#[diagnostic::on_unimplemented(
    message = "`{Self}` cannot be queried through `{I}` over `{S}`",
    label = "this plan does not declare the index, or is not a plan a query runs on",
    note = "query on a field of a fields plan (`plan.field(..)`) or on a one-value plan; a plan built `with` indexes must hold one of this type"
)]
pub trait Resolves<S, I, At>: plan_sealed::Sealed {
    /// The index the query runs through on this plan, and the label the
    /// write used, or why the plan refuses the query. `call` is the context
    /// the call named, if any.
    fn resolve(&self, index: I, call: Option<Label>) -> (I, Result<Label, PlanError>);
}

impl<S: 'static, I: Index<S>> Resolves<S, I, Whole> for FieldPlan {
    fn resolve(&self, index: I, call: Option<Label>) -> (I, Result<Label, PlanError>) {
        let label = self.query_label::<S>(&index.spec(), call);
        (index, label)
    }
}

impl<S: 'static, X, I, At> Resolves<S, I, At> for ValuePlan<S, Indexed<X>>
where
    X: Indexes<S> + Select<I, At>,
    I: Index<S> + Clone,
{
    fn resolve(&self, _: I, call: Option<Label>) -> (I, Result<Label, PlanError>) {
        let index = self.indexes().select::<I, At>().clone();
        (index, self.resolve(call))
    }
}

impl<S: 'static, T, I: Index<S>> Resolves<S, I, Whole> for ValuePlan<S, Typed<T>>
where
    Typed<T>: ValueShape<S>,
{
    fn resolve(&self, index: I, call: Option<Label>) -> (I, Result<Label, PlanError>) {
        let label = self.query_label(&index.spec(), call);
        (index, label)
    }
}

/// A plan laid out by value uses its layout's own index, with its
/// options, so the index named says only which; as a plan built `with`
/// indexes does.
impl<S: 'static, X, T> Resolves<S, X::Index, Whole> for ValuePlan<S, Laid<X, T>>
where
    X: Layout<S, Target = T>,
    Laid<X, T>: ValueShape<S>,
{
    fn resolve(&self, _: X::Index, call: Option<Label>) -> (X::Index, Result<Label, PlanError>) {
        (self.layout().index().clone(), self.resolve(call))
    }
}

/// A chain deriving one query term for an operator, ready to await. It
/// resolves to the [`QueryTerm`](crate::op::QueryTerm) the index sends for
/// the operator ([`Supports::Query`]).
pub struct QueryOp<'a, F, Op, I, K> {
    common: Common<'a, K>,
    value: F,
    index: I,
    label: Result<Label, PlanError>,
    op: PhantomData<fn() -> Op>,
}

impl<'a, F, Op, I, K> QueryOp<'a, F, Op, I, K> {
    /// The chain for a query on a plan: the index the plan resolves for the
    /// context the call named, and the label the write used, or why the
    /// plan refuses it. A call context that is not a label is that refusal,
    /// with `fallback`'s index, which is never used to derive a term. `seed`
    /// is what either is built from: the named index for [`QueryVia::on`],
    /// nothing for [`QueryBuilder::on`]. The one path from both.
    fn resolve<X>(
        mut common: Common<'a, K>,
        value: F,
        op: PhantomData<fn() -> Op>,
        seed: X,
        fallback: impl FnOnce(X) -> I,
        resolve: impl FnOnce(X, Option<Label>) -> (I, Result<Label, PlanError>),
    ) -> Self {
        let (index, label) = match common.call_context() {
            Ok(call) => resolve(seed, call),
            Err(error) => (fallback(seed), Err(error)),
        };
        QueryOp {
            common,
            value,
            index,
            label,
            op,
        }
    }
}

impl<'a, F, Op, I, K: 'static> Operation<'a, K> for QueryOp<'a, F, Op, I, K>
where
    Op: Operator,
    F: Input<Op::Arity>,
    I: Supports<Op, F> + 'static,
    I::Term: MaybeSend,
    F::Terms<I::Term>: MaybeSend,
    I::Query: MaybeSend + 'static,
{
    type Output = I::Query;
    fn cipher(&self) -> &'a StackCipher<K> {
        self.common.cipher
    }
    fn take_keyset(&mut self) -> Option<KeysetChoice<'a, K>> {
        self.common.keyset.take()
    }
    fn check(&self) -> Result<(), Error> {
        let label = self.label.as_ref().map_err(|error| error.clone())?;
        self.index
            .check_label(label, self.common.extend.is_extended())?;
        self.index.check(&self.value)
    }
    fn prepare<'p>(self, keyset: &'p KeysetCipher<'a, K>, _: bool) -> Pending<'p, Self::Output, K>
    where
        'a: 'p,
    {
        let label = match self.label {
            Ok(label) => label,
            Err(error) => return Pending::failed(keyset, error.into()),
        };
        // `check` ran before any keyset was resolved; a chain prepared on
        // its own is held to the same refusals, so no term is derived under
        // a context or from a value the index refuses. `admit` checks and
        // takes the verifier in one pass over the value.
        let extended = self.common.extend.is_extended();
        let verifier = match self
            .index
            .check_label(&label, extended)
            .and_then(|()| self.index.admit(&self.value))
        {
            Ok(verifier) => verifier,
            Err(error) => return Pending::failed(keyset, error),
        };
        let token = QueryToken::new(label.clone(), extended);
        self.value
            .derive(&self.index, keyset, label, self.common.extend)
            .map(move |terms| I::query(verifier, terms, token))
    }
}

/// A chain decrypting a stored record, before its plan is named.
pub struct OpenBuilder<'a, R, K> {
    common: Common<'a, K>,
    record: R,
}

impl<'a, R, K: 'static> OpenBuilder<'a, R, K> {
    /// Name the context: for a plan built without one, the context the
    /// write's call named; for a plan with a context field, the context the
    /// caller expects the record to hold, so a record whose field says
    /// otherwise is [`Error::ContextMismatch`] before any key is requested.
    /// A plan built with its context refuses this
    /// ([`PlanError::TwoContextSources`]).
    pub fn context(mut self, context: impl IntoLabel) -> Self {
        self.common.context = Some(context.into_label());
        self
    }

    /// Decrypt as `plan` declares: the fields that can come back (sealed
    /// and passthrough fields, not index-only ones) for a fields plan, the
    /// plaintext for a one-value plan.
    pub fn using<P: Opens<R, K>>(self, plan: &'a P) -> OpenUsing<'a, R, P, K> {
        OpenUsing {
            common: self.common,
            record: self.record,
            plan,
        }
    }
}

/// A chain decrypting a stored record through a plan, ready to await.
pub struct OpenUsing<'a, R, P, K> {
    common: Common<'a, K>,
    record: R,
    plan: &'a P,
}

impl<'a, R, P: Opens<R, K>, K: 'static> Operation<'a, K> for OpenUsing<'a, R, P, K>
where
    P::Output: MaybeSend,
{
    type Output = P::Output;
    fn cipher(&self) -> &'a StackCipher<K> {
        self.common.cipher
    }
    fn take_keyset(&mut self) -> Option<KeysetChoice<'a, K>> {
        self.common.keyset.take()
    }
    fn check(&self) -> Result<(), Error> {
        self.plan.check(&self.record, self.common.peek_context()?)
    }
    fn prepare<'p>(
        mut self,
        keyset: &'p KeysetCipher<'a, K>,
        scoped: bool,
    ) -> Pending<'p, Self::Output, K>
    where
        'a: 'p,
    {
        let opening = match self.common.call_context() {
            Ok(context) => self
                .plan
                .decryption(self.record, context, self.common.extend),
            Err(error) => crate::target::Decryption::failed(error.into()),
        };
        if scoped {
            keyset.run_decryption(opening)
        } else {
            keyset.cipher().run_decryption(opening)
        }
    }
}

chain_options! {
    ['a, S: ?Sized, K: 'static] EncryptBuilder<'a, S, K>;
    ['a, S: ?Sized, K: 'static] EncryptWithContext<'a, S, K>;
    ['a, S, X, K: 'static] EncryptIndexed<'a, S, X, K>;
    ['a, S: 'static, K: 'static] EncryptFields<'a, S, K>;
    ['a, S: ?Sized, P, K: 'static] EncryptUsing<'a, S, P, K>;
    ['a, Op, F, K: 'static] QueryBuilder<'a, Op, F, K>;
    ['a, Op, F, I, K: 'static] QueryVia<'a, Op, F, I, K>;
    ['a, F, Op, I, K: 'static] QueryOp<'a, F, Op, I, K>;
    ['a, R, K: 'static] OpenBuilder<'a, R, K>;
    ['a, R, P, K: 'static] OpenUsing<'a, R, P, K>;
}

settles! {
    ['a, S: ?Sized, K] EncryptWithContext<'a, S, K>;
    ['a, S, X, K] EncryptIndexed<'a, S, X, K>;
    ['a, S: 'static, K: 'static] EncryptFields<'a, S, K>;
    ['a, S: ?Sized, P, K] EncryptUsing<'a, S, P, K>;
    ['a, F, Op, I, K] QueryOp<'a, F, Op, I, K>;
    ['a, R, P, K] OpenUsing<'a, R, P, K>;
}

/// Each chain's `Debug` names the chain and nothing it holds: the value
/// is plaintext.
macro_rules! opaque_debug {
    ($([$($generics:tt)*] $chain:ty, $name:literal;)+) => {$(
        impl<$($generics)*> std::fmt::Debug for $chain {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct($name).finish_non_exhaustive()
            }
        }
    )+};
}
opaque_debug! {
    ['a, S: ?Sized, K] EncryptBuilder<'a, S, K>, "EncryptBuilder";
    ['a, S: ?Sized, K] EncryptWithContext<'a, S, K>, "EncryptWithContext";
    ['a, S, X, K] EncryptIndexed<'a, S, X, K>, "EncryptIndexed";
    ['a, S: 'static, K: 'static] EncryptFields<'a, S, K>, "EncryptFields";
    ['a, S: ?Sized, P, K] EncryptUsing<'a, S, P, K>, "EncryptUsing";
    ['a, Op, F, K] QueryBuilder<'a, Op, F, K>, "QueryBuilder";
    ['a, Op, F, I, K] QueryVia<'a, Op, F, I, K>, "QueryVia";
    ['a, F, Op, I, K] QueryOp<'a, F, Op, I, K>, "QueryOp";
    ['a, R, K] OpenBuilder<'a, R, K>, "OpenBuilder";
    ['a, R, P, K] OpenUsing<'a, R, P, K>, "OpenUsing";
}

/// Several chains settled together: one ZeroKMS request per request kind
/// for all of them, under one keyset. Built by [`all`].
pub struct All<'a, K, T> {
    operations: T,
    scope: PhantomData<Scope<'a, K>>,
}

/// The lifetime and data-key source a batch runs under, carried only in
/// the type.
type Scope<'a, K> = (&'a (), fn() -> K);

impl<K, T> std::fmt::Debug for All<'_, K, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("All").finish_non_exhaustive()
    }
}

/// Settle several chains in one ZeroKMS request: a tuple of two to four
/// chains, awaited together, resolving to the tuple of their outputs.
///
/// Every chain is prepared under one keyset (the one they name, which must
/// be the same for all, or the client's default) and their [`Pending`]s
/// are zipped, so however many there are, awaiting makes one `generate`
/// call and one `retrieve` call per keyset at most. A chain that names no
/// keyset encrypts and queries under that batch keyset. An opening that
/// names none still opens leaves from any keyset, as it does alone: the
/// batch settles those openings beside it, in one more `retrieve` call per
/// keyset they read.
///
/// Every chain is checked ([`Operation::check`]) before any keyset is
/// loaded, so one chain whose plan does not hold up fails the batch with no
/// request at all. Chains started on different ciphers are
/// [`PlanError::MixedCiphers`], and chains naming different keysets are
/// [`Error::KeysetMismatch`], both before any key request.
///
/// ```
/// # async fn example() -> Result<(), stack_encrypt::Error> {
/// use stack_encrypt::kms::FakeDataKeySource;
/// use stack_encrypt::{op, Equality, Plan, StackCipher};
///
/// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
/// let email_plan = Plan::context("users/email").with(Equality).build()?;
///
/// let email = String::from("bob@example.com");
/// let (written, query_value) = stack_encrypt::all((
///     cipher.encrypt(&email).using(&email_plan),
///     cipher.query(op::Eq, "bob@example.com").on(&email_plan),
/// ))
/// .await?;
/// assert_eq!(written.terms, query_value);
/// # Ok(())
/// # }
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
/// ```
pub fn all<'a, K: 'static, T: Batch<'a, K>>(operations: T) -> All<'a, K, T> {
    All {
        operations,
        scope: PhantomData,
    }
}

/// A tuple of two to four chains [`all`] can settle together. Sealed.
pub trait Batch<'a, K: 'static>: sealed::Sealed {}

/// One chain's pending, routed to the group it settles in: the batch,
/// under the batch keyset, or, for an opening that named no keyset and has
/// not failed, the openings that read from any keyset. The other group
/// holds an empty place for it, so a failure always lands in the batch and
/// stops it before any I/O.
fn route<'p, T, K>(
    cipher: &'p StackCipher<K>,
    pending: Pending<'p, T, K>,
) -> (Pending<'p, Option<T>, K>, Pending<'p, Option<T>, K>)
where
    T: MaybeSend + 'p,
{
    if pending.opens_any_keyset() {
        (Pending::ready(cipher, Ok(None)), pending.map(Some))
    } else {
        (pending.map(Some), Pending::ready(cipher, Ok(None)))
    }
}

/// A chain's output, from whichever group it was routed to.
fn placed<T>(batch: Option<T>, any: Option<T>) -> Result<T, Error> {
    batch.or(any).ok_or(Error::ResponseShape)
}

/// `all` over a tuple: each entry is the chain's type, its value, whether
/// it named a keyset, and its places in the batch and in the openings
/// group; the patterns undo the nested `zip` of each group.
macro_rules! all_of {
    ($((
        $first:ident $fop:ident $fnamed:ident $fbatch:ident $fany:ident
        $(, $rest:ident $rop:ident $rnamed:ident $rbatch:ident $rany:ident)+
    ) => ($batch:pat, $any:pat),)+) => {$(
        impl<$first, $($rest),+> sealed::Sealed for ($first, $($rest),+) {}
        impl<'a, K: 'static, $first: Operation<'a, K>, $($rest: Operation<'a, K>),+> Batch<'a, K>
            for ($first, $($rest),+)
        {
        }
        impl<'a, K: PlanKms, $first, $($rest),+> IntoFuture for All<'a, K, ($first, $($rest),+)>
        where
            $first: Operation<'a, K> + MaybeSend + 'a,
            $($rest: Operation<'a, K> + MaybeSend + 'a,)+
        {
            type Output = Result<($first::Output, $($rest::Output),+), Error>;
            type IntoFuture = PendingFuture<'a, ($first::Output, $($rest::Output),+)>;
            fn into_future(self) -> Self::IntoFuture {
                let (mut $fop, $(mut $rop),+) = self.operations;
                Box::pin(async move {
                    $fop.check()?;
                    $($rop.check()?;)+
                    let cipher = $fop.cipher();
                    if $(!std::ptr::eq($rop.cipher(), cipher))||+ {
                        return Err(PlanError::MixedCiphers.into());
                    }
                    let ($fnamed, $($rnamed),+) = ($fop.take_keyset(), $($rop.take_keyset()),+);
                    let named = ($fnamed.is_some(), $($rnamed.is_some()),+);
                    let (keyset, _) = resolve(cipher, vec![$fnamed, $($rnamed),+]).await?;
                    let ($fnamed, $($rnamed),+) = named;
                    let ($fbatch, $fany) = route(cipher, $fop.prepare(&keyset, $fnamed));
                    $(let ($rbatch, $rany) = route(cipher, $rop.prepare(&keyset, $rnamed));)+
                    let ($fbatch, $($rbatch),+) = $fbatch
                        $(.zip($rbatch))+
                        .map(|$batch| ($fbatch, $($rbatch),+))
                        .settle()
                        .await?;
                    let ($fany, $($rany),+) = $fany
                        $(.zip($rany))+
                        .map(|$any| ($fany, $($rany),+))
                        .settle()
                        .await?;
                    Ok((placed($fbatch, $fany)?, $(placed($rbatch, $rany)?),+))
                })
            }
        }
    )+};
}
all_of! {
    (A a a_named a_batch a_any, B b b_named b_batch b_any)
        => ((a_batch, b_batch), (a_any, b_any)),
    (A a a_named a_batch a_any, B b b_named b_batch b_any, C c c_named c_batch c_any)
        => (((a_batch, b_batch), c_batch), ((a_any, b_any), c_any)),
    (
        A a a_named a_batch a_any,
        B b b_named b_batch b_any,
        C c c_named c_batch c_any,
        D d d_named d_batch d_any
    ) => (
        (((a_batch, b_batch), c_batch), d_batch),
        (((a_any, b_any), c_any), d_any)
    ),
}
