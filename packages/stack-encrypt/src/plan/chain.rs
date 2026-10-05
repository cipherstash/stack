//! The chain on the cipher: `cipher.encrypt(&value)`, `cipher.query(&value)`
//! and `cipher.open(row)`, each finished by `.await`, and [`all`] for
//! several at once.
use std::future::IntoFuture;
use std::marker::PhantomData;

use stack_kms::{DataKeySource, IdentifiedBy, IndexKeySource, MaybeSend};
use uuid::Uuid;

use super::build::{FieldPlan, FieldsBuilder, IntoLabel, Opens, PlanContext, Runs, ValuePlan};
use super::values::{Field, Fields};
use super::PlanError;
use crate::target::{
    ciphertext, Borrowed, DeclaredContext, Equality, Index, Indexes, Owned, Pending, PendingFuture,
    Select,
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

/// What every chain carries besides its value: the cipher, the keyset it
/// names, and the caller's extension of the plan's contexts.
struct Common<'a, K> {
    cipher: &'a StackCipher<K>,
    keyset: Option<KeysetChoice<'a, K>>,
    context: DeclaredContext,
}

impl<'a, K> Common<'a, K> {
    fn new(cipher: &'a StackCipher<K>) -> Self {
        Self {
            cipher,
            keyset: None,
            context: DeclaredContext::default(),
        }
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
                self.common.context = parts.into();
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

    /// Start a chain that derives a query term for `value`, to match terms
    /// a plan wrote. Name the plan with [`using`](QueryBuilder::using) and
    /// the index with `equality()` or `index(..)`.
    ///
    /// The value is copied once (`to_owned`), so `query("bob@example.com")`
    /// queries a `String` field.
    pub fn query<'a, Q>(&'a self, value: &Q) -> QueryBuilder<'a, Q::Owned, K>
    where
        Q: ToOwned + ?Sized,
    {
        QueryBuilder {
            common: Common::new(self),
            value: value.to_owned(),
        }
    }

    /// Start a chain that decrypts `row`, a record a plan wrote. Name the
    /// plan with [`using`](OpenBuilder::using), then `.await`.
    ///
    /// Named `open` rather than `decrypt`: [`StackCipher::decrypt`] is the
    /// cipher-directed decrypt and keeps its two-argument form.
    pub fn open<'a, R>(&'a self, row: R) -> OpenBuilder<'a, R, K> {
        OpenBuilder {
            common: Common::new(self),
            row,
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
    /// them. A collection settles every key request in one batch.
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
    /// Seal the value with `indexes` beside it: one index or a tuple of
    /// two to four, each defined over the value's type. The output is an
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
                self.common.context,
            ),
            Err(error) => Pending::failed(keyset, PlanError::ContextLabel(error).into()),
        }
    }
}

/// A chain encrypting one value with indexes beside it.
pub struct EncryptIndexed<'a, S, X, K> {
    common: Common<'a, K>,
    source: &'a S,
    plan: super::build::ValuePlanBuilder<S, X>,
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
            Ok(plan) => plan.pending(keyset, self.source, self.common.context),
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
    pub fn encrypt<F>(mut self, name: &str) -> Self
    where
        S: Field<F>,
        F: crate::Encrypt + crate::Decrypt<'static> + Clone + Send + 'static,
    {
        self.plan = self.plan.encrypt::<F>(name);
        self
    }
    /// [`FieldsBuilder::encrypt_index`].
    pub fn encrypt_index<F>(
        mut self,
        name: &str,
        indexes: impl Indexes<F, Terms: Send> + Clone + Send + Sync + 'static,
    ) -> Self
    where
        S: Field<F>,
        F: crate::Encrypt + crate::Decrypt<'static> + Clone + Send + 'static,
    {
        self.plan = self.plan.encrypt_index::<F>(name, indexes);
        self
    }
    /// [`FieldsBuilder::index`].
    pub fn index<F>(
        mut self,
        name: &str,
        indexes: impl Indexes<F, Terms: Send> + Clone + Send + Sync + 'static,
    ) -> Self
    where
        S: Field<F>,
        F: Clone + Send + 'static,
    {
        self.plan = self.plan.index::<F>(name, indexes);
        self
    }
    /// [`FieldsBuilder::passthrough`]: carried **unsealed and
    /// unauthenticated**.
    pub fn passthrough<F>(mut self, name: &str) -> Self
    where
        S: Field<F>,
        F: Clone + Send + 'static,
    {
        self.plan = self.plan.passthrough::<F>(name);
        self
    }
    /// [`FieldsBuilder::identity`].
    pub fn identity(mut self, identity: &str) -> Self {
        self.plan = self.plan.identity(identity);
        self
    }
}

impl<'a, S: Fields + 'static, K: 'static> Operation<'a, K> for EncryptFields<'a, S, K> {
    type Output = super::FieldValues;
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
            Ok(plan) => plan.pending(keyset, self.source, self.common.context),
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
        self.plan.check(self.source)
    }
    fn prepare<'p>(self, keyset: &'p KeysetCipher<'a, K>, _: bool) -> Pending<'p, Self::Output, K>
    where
        'a: 'p,
    {
        self.plan.pending(keyset, self.source, self.common.context)
    }
}

/// A chain deriving a query term, before its plan is named.
pub struct QueryBuilder<'a, F, K> {
    common: Common<'a, K>,
    value: F,
}

impl<'a, F, K: 'static> QueryBuilder<'a, F, K> {
    /// Query through `plan`: a field of a fields plan
    /// ([`Plan::field`](super::Plan::field)), or a one-value plan ([`ValuePlan`]). The term is
    /// derived under exactly the label the write used.
    pub fn using<P>(self, plan: &'a P) -> QueryUsing<'a, F, P, K> {
        QueryUsing {
            common: self.common,
            value: self.value,
            plan,
        }
    }
}

/// A chain deriving a query term through a plan, before its index is
/// chosen.
pub struct QueryUsing<'a, F, P, K> {
    common: Common<'a, K>,
    value: F,
    plan: &'a P,
}

impl<'a, F: 'static, K: 'static> QueryUsing<'a, F, FieldPlan, K> {
    /// The equality term: sugar for `index(Equality)`.
    pub fn equality(self) -> QueryIndex<'a, F, Equality, K>
    where
        Equality: Index<F>,
    {
        self.index(Equality)
    }

    /// The term of `index`. The field must have declared it, and the query's
    /// plaintext must be the field's type; otherwise awaiting is
    /// [`PlanError::IndexNotDeclared`] or [`PlanError::FieldType`], never a
    /// term that matches nothing.
    pub fn index<I: Index<F>>(self, index: I) -> QueryIndex<'a, F, I, K> {
        let label = self.plan.query_label::<F>(&index.spec());
        QueryIndex {
            common: self.common,
            value: self.value,
            index,
            label,
        }
    }
}

impl<'a, F: 'static, X: Indexes<F>, K: 'static> QueryUsing<'a, F, ValuePlan<F, X>, K> {
    /// The equality term, selected from the plan's indexes by type: a plan
    /// with no `Equality` index does not compile here.
    pub fn equality<At>(self) -> QueryIndex<'a, F, Equality, K>
    where
        Equality: Index<F>,
        X: Select<Equality, At>,
    {
        self.index::<Equality, At>()
    }

    /// The term of the plan's index of type `I`, selected by type
    /// ([`Indexes::select`]); `At` is inferred: `.index::<Ore, _>()`.
    pub fn index<I, At>(self) -> QueryIndex<'a, F, I, K>
    where
        I: Index<F> + Clone,
        X: Select<I, At>,
    {
        let index = self.plan.indexes().select::<I, At>().clone();
        QueryIndex {
            common: self.common,
            value: self.value,
            index,
            label: Ok(self.plan.label().clone()),
        }
    }
}

/// A chain deriving one query term, ready to await.
pub struct QueryIndex<'a, F, I, K> {
    common: Common<'a, K>,
    value: F,
    index: I,
    label: Result<Label, PlanError>,
}

impl<'a, F: 'static, I: Index<F>, K: 'static> Operation<'a, K> for QueryIndex<'a, F, I, K>
where
    I::Term: MaybeSend,
{
    type Output = I::Term;
    fn cipher(&self) -> &'a StackCipher<K> {
        self.common.cipher
    }
    fn take_keyset(&mut self) -> Option<KeysetChoice<'a, K>> {
        self.common.keyset.take()
    }
    fn check(&self) -> Result<(), Error> {
        match &self.label {
            Ok(_) => Ok(()),
            Err(error) => Err(error.clone().into()),
        }
    }
    fn prepare<'p>(self, keyset: &'p KeysetCipher<'a, K>, _: bool) -> Pending<'p, Self::Output, K>
    where
        'a: 'p,
    {
        match self.label {
            Ok(label) => keyset.run(
                self.index
                    .operation::<K, Owned>()
                    .under(NonEmpty::from(label)),
                self.value,
                self.common.context,
            ),
            Err(error) => Pending::failed(keyset, error.into()),
        }
    }
}

/// A chain decrypting a stored record, before its plan is named.
pub struct OpenBuilder<'a, R, K> {
    common: Common<'a, K>,
    row: R,
}

impl<'a, R, K: 'static> OpenBuilder<'a, R, K> {
    /// Decrypt as `plan` declares: the fields that can come back (sealed
    /// and passthrough fields, not index-only ones) for a fields plan, the
    /// plaintext for a one-value plan.
    pub fn using<P: Opens<R, K>>(self, plan: &'a P) -> OpenUsing<'a, R, P, K> {
        OpenUsing {
            common: self.common,
            row: self.row,
            plan,
        }
    }
}

/// A chain decrypting a stored record through a plan, ready to await.
pub struct OpenUsing<'a, R, P, K> {
    common: Common<'a, K>,
    row: R,
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
        self.plan.check(&self.row)
    }
    fn prepare<'p>(
        self,
        keyset: &'p KeysetCipher<'a, K>,
        scoped: bool,
    ) -> Pending<'p, Self::Output, K>
    where
        'a: 'p,
    {
        let opening = self.plan.decryption(self.row, self.common.context);
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
    ['a, F, K: 'static] QueryBuilder<'a, F, K>;
    ['a, F, P, K: 'static] QueryUsing<'a, F, P, K>;
    ['a, F, I, K: 'static] QueryIndex<'a, F, I, K>;
    ['a, R, K: 'static] OpenBuilder<'a, R, K>;
    ['a, R, P, K: 'static] OpenUsing<'a, R, P, K>;
}

settles! {
    ['a, S: ?Sized, K] EncryptWithContext<'a, S, K>;
    ['a, S, X, K] EncryptIndexed<'a, S, X, K>;
    ['a, S: 'static, K: 'static] EncryptFields<'a, S, K>;
    ['a, S: ?Sized, P, K] EncryptUsing<'a, S, P, K>;
    ['a, F, I, K] QueryIndex<'a, F, I, K>;
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
    ['a, F, K] QueryBuilder<'a, F, K>, "QueryBuilder";
    ['a, F, P, K] QueryUsing<'a, F, P, K>, "QueryUsing";
    ['a, F, I, K] QueryIndex<'a, F, I, K>, "QueryIndex";
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
/// use stack_encrypt::{Equality, Plan, StackCipher};
///
/// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
/// let email_plan = Plan::context("users/email").with(Equality).build()?;
///
/// let email = String::from("bob@example.com");
/// let (written, probe) = stack_encrypt::all((
///     cipher.encrypt(&email).using(&email_plan),
///     cipher.query("bob@example.com").using(&email_plan).equality(),
/// ))
/// .await?;
/// assert_eq!(written.terms, probe);
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
