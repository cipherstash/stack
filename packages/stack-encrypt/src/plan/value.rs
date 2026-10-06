//! One-value plans: one plaintext, sealed with its indexes beside it
//! ([`with`](ValueStart::with)) or laid out by a target type
//! ([`encrypt_into`](ValueStart::encrypt_into)).
use std::fmt;
use std::marker::PhantomData;

use super::build::{
    check_declared, check_indexes, resolve_context, runs_over_collections, IntoLabel, Opens,
    PlanContext, Runs, FROM_CALL, FROM_FIELD, FROM_PLAN,
};
use super::PlanError;
use crate::registry::{KeysetRegistry, NoRegistry};
use crate::target::{
    indexed, Borrowed, CallerContext, DeclaredContext, DecryptInto, Decryption, EncryptFrom,
    Encrypted, Encryption, ExpectedContext, IndexSpec, Indexes, Pending,
};
use crate::{
    Error, IntoContext, KeysetCipher, Label, LabelError, MaybeEmpty, NonEmpty, Plan,
    StackCipherText,
};
use vitaminc_kms::provider::MaybeSend;

impl Plan<(), NoRegistry> {
    /// Start a one-value plan over plaintext `S`, with no context yet: give
    /// it one with [`context`](ValueStart::context), or leave it for the
    /// call that runs it. Then [`with`](ValueStart::with) its indexes or
    /// [`encrypt_into`](ValueStart::encrypt_into) a target, and `build()`.
    ///
    /// ```
    /// # async fn example() -> Result<(), stack_encrypt::Error> {
    /// use stack_encrypt::registry::fake::FakeKeysetRegistry;
    /// use stack_encrypt::StackCipherBuilder;
    /// use stack_encrypt::sem::EqualityTerm;
    /// use stack_encrypt::{Equality, Ore, Plan, StackCipher, StackCipherText};
    ///
    /// let cipher = StackCipherBuilder::new().registry(FakeKeysetRegistry::new()).init().await?;
    ///
    /// // With its context and indexes.
    /// let age_plan = Plan::value::<u32>().context("users/age").with((Equality, Ore)).build()?;
    /// let age = cipher.encrypt(&34u32).using(&age_plan).await?;
    /// let back: u32 = cipher.open(age).using(&age_plan).await?;
    /// assert_eq!(back, 34);
    ///
    /// // Laid out by a tuple of targets, its context named by each call:
    /// // a `plaintext = String` record without the struct.
    /// let email_plan = Plan::value::<String>()
    ///     .encrypt_into::<(StackCipherText, EqualityTerm)>()
    ///     .build()?;
    /// let email = String::from("bob@example.com");
    /// let (c, eq) = cipher.encrypt(&email).context("users/email").using(&email_plan).await?;
    /// let query_value = cipher
    ///     .query("bob@example.com")
    ///     .context("users/email")
    ///     .using(&email_plan)
    ///     .equality()
    ///     .await?;
    /// assert_eq!(query_value, eq);
    /// let back = cipher.open((c, eq)).context("users/email").using(&email_plan).await?;
    /// assert_eq!(back, email);
    /// # Ok(())
    /// # }
    /// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
    /// ```
    pub fn value<S>() -> ValueStart<S> {
        ValueStart {
            sources: Vec::new(),
            plaintext: PhantomData,
        }
    }
}

/// A one-value plan before its layout is chosen; see [`Plan::value`].
pub struct ValueStart<S> {
    sources: Vec<Result<Label, LabelError>>,
    plaintext: PhantomData<fn(&S)>,
}

impl<S> fmt::Debug for ValueStart<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValueStart")
            .field("context", &self.sources)
            .finish()
    }
}

impl<S> ValueStart<S> {
    /// Seal the value under `context`, given when the plan is built.
    pub fn context(mut self, context: impl IntoLabel) -> Self {
        self.sources.push(context.into_label());
        self
    }

    /// Seal the value with `indexes` beside it: one index, or a tuple of
    /// two to five. The output is an [`Encrypted<Terms>`]. The data spelling
    /// of `encrypt_into::<Encrypted<Terms>>()`: both lower to
    /// [`indexed`].
    pub fn with<X: Indexes<S>>(self, indexes: X) -> ValuePlanBuilder<S, Indexed<X>> {
        ValuePlanBuilder {
            sources: self.sources,
            shape: Indexed(indexes),
            plaintext: PhantomData,
        }
    }

    /// Lay the value out as the target `T` does: `T`'s own
    /// [`EncryptFrom<S>`] decides what is sealed and which terms sit beside
    /// it. A tuple of targets, `encrypt_into::<(StackCipherText,
    /// EqualityTerm)>()`, derives each element from the value under the one
    /// context, which is what a `plaintext = S` derive's record is. Lowers
    /// to `<T as EncryptFrom<S>>::encryption().under(context)`.
    ///
    /// A tuple target holding no ciphertext (terms only) builds, but `open`
    /// on it fails with [`Error::NotOpened`](crate::Error::NotOpened): a
    /// target of terms alone is a query-only plan, as a record deriving
    /// `EncryptFrom` alone is.
    pub fn encrypt_into<T>(self) -> ValuePlanBuilder<S, Typed<T>>
    where
        T: EncryptFrom<S>,
    {
        ValuePlanBuilder {
            sources: self.sources,
            shape: Typed(PhantomData),
            plaintext: PhantomData,
        }
    }
}

impl<S> ValueStart<S> {
    /// Take the plan's context from the call, and carry it out beside the
    /// output, typed `C`: the one-value form of a fields plan's
    /// [`context_field`](super::FieldsBuilder::context_field), and what a
    /// `plaintext = S` derive with `#[stash(context_field)]` is.
    ///
    /// The call hands the context over as a `NonEmpty<C>`; the output is
    /// `(C, T)`, the context as given beside the target's layout. The
    /// stored context is **unsealed and unauthenticated**, as a passthrough
    /// is: what protects the record is that the target was sealed under it.
    /// When the record is opened
    /// ([`decryption_with_context`](ValuePlan::decryption_with_context)), the
    /// stored context is checked first against the one the caller expects
    /// ([`ExpectedContext`]): a mismatch is
    /// [`Error::ContextMismatch`](crate::Error::ContextMismatch), before any
    /// key is requested.
    ///
    /// A context field is the plan's one context source, so a build-time
    /// [`context`](Self::context) beside it is
    /// [`PlanError::TwoContextSources`] at `build()`.
    ///
    /// Unlike a fields plan's context field, the context here is a `C`, not
    /// a [`Label`], so the plan does not run through the chain:
    /// `cipher.encrypt(..).using`, `cipher.open(..).using` and
    /// `cipher.query(..).using` do not take it (it is neither
    /// [`Runs`](super::Runs) nor [`Opens`](super::Opens)), and it has no
    /// query path. Run it as the derive does, with its two descriptions:
    /// `keyset.run(plan.encryption_with_context(), &value, context)` and
    /// `keyset.run_decryption(plan.decryption_with_context(record,
    /// expected))`.
    pub fn context_field<C>(self) -> ContextFieldStart<S, C> {
        ContextFieldStart {
            sources: self.sources,
            plaintext: PhantomData,
        }
    }
}

/// A one-value plan whose context is carried out beside its output, before
/// its layout is chosen; see [`ValueStart::context_field`].
pub struct ContextFieldStart<S, C> {
    sources: Vec<Result<Label, LabelError>>,
    plaintext: PhantomData<fn(&S) -> C>,
}

impl<S, C> fmt::Debug for ContextFieldStart<S, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContextFieldStart")
            .field("context", &self.sources)
            .field("stored", &std::any::type_name::<C>())
            .finish()
    }
}

impl<S, C> ContextFieldStart<S, C> {
    /// Lay the value out as the target `T` does, under the call's context,
    /// and carry that context out beside it: the output is `(C, T)`.
    pub fn encrypt_into<T>(self) -> ValuePlanBuilder<S, Stored<C, T>>
    where
        T: EncryptFrom<S>,
    {
        ValuePlanBuilder {
            sources: self.sources,
            shape: Stored(PhantomData),
            plaintext: PhantomData,
        }
    }
}

/// A one-value plan's layout when its context is carried out beside its
/// target `T` ([`ValueStart::context_field`]): its output is `(C, T)`. Run
/// through [`ValuePlan::encryption_with_context`] and
/// [`ValuePlan::decryption_with_context`] only; see
/// [`context_field`](ValueStart::context_field).
pub struct Stored<C, T>(PhantomData<fn() -> (C, T)>);

impl<C, T> Clone for Stored<C, T> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}
impl<C, T> fmt::Debug for Stored<C, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Stored<{}, {}>",
            std::any::type_name::<C>(),
            std::any::type_name::<T>()
        )
    }
}

impl<S, C, T: EncryptFrom<S>> ValuePlanBuilder<S, Stored<C, T>> {
    /// Validate the plan: no build-time context beside the context field,
    /// and no index named twice.
    ///
    /// # Errors
    ///
    /// [`PlanError::TwoContextSources`] or [`PlanError::DuplicateIndex`],
    /// in [`Error::Plan`].
    pub fn build(self) -> Result<ValuePlan<S, Stored<C, T>>, Error> {
        if !self.sources.is_empty() {
            return Err(PlanError::TwoContextSources {
                first: FROM_PLAN,
                second: FROM_FIELD,
            }
            .into());
        }
        check_indexes("the value", &T::indexes())?;
        Ok(ValuePlan {
            context: None,
            shape: self.shape,
            plaintext: PhantomData,
        })
    }
}

impl<S, C, T> ValuePlan<S, Stored<C, T>> {
    /// The description of one run: `T`'s layout under the context the call
    /// hands over, which is carried out beside it as the record's `C`.
    /// Run it with [`KeysetCipher::run`] and a `NonEmpty<C>`.
    pub fn encryption_with_context<'s, K: KeysetRegistry + 'static>(
        &self,
    ) -> Encryption<'s, S, (C, T), K, NonEmpty<C>>
    where
        S: 's,
        T: EncryptFrom<S>,
        CallerContext: Into<T::Context>,
        NonEmpty<C>: Into<CallerContext>,
        C: Clone + MaybeSend + 'static,
    {
        T::encryption()
            .accepting::<CallerContext>()
            .accepting::<NonEmpty<C>>()
            .map_with_context(|target, context: NonEmpty<C>| (context.into_inner(), target))
    }

    /// The opening of a stored `(C, T)`: the stored context checked against
    /// `expected` (which [`ExpectedContext::default`] leaves unchecked beyond
    /// being nonempty), before any key is requested, then `T` opened under
    /// it through its own [`DecryptInto`].
    pub fn decryption_with_context<K: KeysetRegistry + 'static>(
        &self,
        record: (C, T),
        expected: ExpectedContext<C>,
    ) -> Decryption<S, K>
    where
        S: 'static,
        T: DecryptInto<S>,
        NonEmpty<C>: Into<T::Context>,
        C: MaybeEmpty + PartialEq + IntoContext<'static>,
    {
        let (stored, target) = record;
        match expected.validate(stored) {
            Ok(context) => target.decryption(context.into()),
            Err(error) => Decryption::failed(error),
        }
    }
}

impl PlanContext {
    /// One value, sealed under the context with `indexes` beside it: a
    /// one-value plan, whose output is an [`Encrypted<Terms>`].
    pub fn with<S, X: Indexes<S>>(self, indexes: X) -> ValuePlanBuilder<S, Indexed<X>> {
        ValuePlanBuilder {
            sources: vec![self.into_result()],
            shape: Indexed(indexes),
            plaintext: PhantomData,
        }
    }
}

/// A one-value plan's layout when it was given its indexes
/// ([`with`](ValueStart::with)): its output is an [`Encrypted<Terms>`],
/// and a query selects its index by type.
#[derive(Clone, Debug)]
pub struct Indexed<X>(X);

/// A one-value plan's layout when it names a target
/// ([`encrypt_into`](ValueStart::encrypt_into)): its output is a `T`, and a
/// query may ask for the indexes `T` declares ([`EncryptFrom::indexes`]).
pub struct Typed<T>(PhantomData<fn() -> T>);

impl<T> Clone for Typed<T> {
    fn clone(&self) -> Self {
        Self(PhantomData)
    }
}
impl<T> fmt::Debug for Typed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Typed<{}>", std::any::type_name::<T>())
    }
}

mod sealed {
    pub trait Sealed {}
    impl<X> Sealed for super::Indexed<X> {}
    impl<T> Sealed for super::Typed<T> {}
}

/// What a one-value plan's layout says before it runs: what one run
/// produces, and the indexes it declares. Enough to build the plan
/// ([`ValuePlanBuilder::build`]), which checks those indexes; running it
/// under a [`Label`] asks for [`ValueShape`]. Sealed.
///
/// A [`Typed`] layout is one for every target, whatever context the target
/// takes; it is a [`ValueShape`] only when a [`CallerContext`] converts
/// into that context. A target whose context is, say, a `NonEmpty<u64>`
/// builds, and runs through
/// [`encryption_with_context`](ValuePlan::encryption_with_context).
pub trait ValueLayout<S>: sealed::Sealed + Clone {
    /// What one run produces.
    type Output: 'static;
    /// The indexes the value is searchable by, as data.
    fn specs(&self) -> Vec<IndexSpec>;
}

/// How a one-value plan lays its value out under a [`Label`]: [`Indexed`]
/// or [`Typed`]. What [`ValuePlan::encryption`], `cipher.encrypt(..).using`
/// and a query through the plan ask. Sealed.
pub trait ValueShape<S>: ValueLayout<S> {
    /// The description of one value, run under its whole context.
    fn lower<'s, K: KeysetRegistry + 'static>(
        &self,
    ) -> Encryption<'s, S, Self::Output, K, CallerContext>
    where
        S: 's;
}

impl<S, X> ValueLayout<S> for Indexed<X>
where
    S: crate::Encrypt + Clone,
    X: Indexes<S> + Clone,
{
    type Output = Encrypted<X::Terms>;
    fn specs(&self) -> Vec<IndexSpec> {
        self.0.specs()
    }
}

impl<S, X> ValueShape<S> for Indexed<X>
where
    S: crate::Encrypt + Clone,
    X: Indexes<S> + Clone,
{
    fn lower<'s, K: KeysetRegistry + 'static>(
        &self,
    ) -> Encryption<'s, S, Self::Output, K, CallerContext>
    where
        S: 's,
    {
        indexed::<S, K, Borrowed, X>(self.0.clone())
    }
}

impl<S, T> ValueLayout<S> for Typed<T>
where
    T: EncryptFrom<S>,
{
    type Output = T;
    fn specs(&self) -> Vec<IndexSpec> {
        T::indexes()
    }
}

impl<S, T> ValueShape<S> for Typed<T>
where
    T: EncryptFrom<S>,
    CallerContext: Into<T::Context>,
{
    fn lower<'s, K: KeysetRegistry + 'static>(&self) -> Encryption<'s, S, T, K, CallerContext>
    where
        S: 's,
    {
        T::encryption().accepting::<CallerContext>()
    }
}

/// A one-value plan under construction; see [`ValuePlan`].
pub struct ValuePlanBuilder<S, X> {
    sources: Vec<Result<Label, LabelError>>,
    shape: X,
    plaintext: PhantomData<fn(&S)>,
}

impl<S, X: fmt::Debug> fmt::Debug for ValuePlanBuilder<S, X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValuePlanBuilder")
            .field("context", &self.sources)
            .field("shape", &self.shape)
            .finish()
    }
}

impl<S, X: ValueLayout<S>> ValuePlanBuilder<S, X> {
    /// Validate the plan: at most one context, a plain label, and no index
    /// named twice. A plan with no context builds; each call names one.
    ///
    /// # Errors
    ///
    /// [`PlanError::TwoContextSources`], [`PlanError::ContextLabel`] or
    /// [`PlanError::DuplicateIndex`], in [`Error::Plan`].
    pub fn build(self) -> Result<ValuePlan<S, X>, Error> {
        let context = self.checked_context()?;
        Ok(ValuePlan {
            context,
            shape: self.shape,
            plaintext: PhantomData,
        })
    }

    /// Validate the plan as [`build`](Self::build) does, without building
    /// it: what a chain asks before it loads a keyset.
    pub(super) fn check(&self) -> Result<(), Error> {
        self.checked_context().map(drop)
    }

    /// The context, if any, once the plan has passed
    /// [`build`](Self::build)'s checks.
    fn checked_context(&self) -> Result<Option<Label>, Error> {
        let mut sources = self.sources.iter().cloned();
        let context = match (sources.next(), sources.next()) {
            (None, _) => None,
            (Some(context), None) => Some(context.map_err(PlanError::ContextLabel)?),
            (Some(_), Some(_)) => {
                return Err(PlanError::TwoContextSources {
                    first: FROM_PLAN,
                    second: FROM_PLAN,
                }
                .into())
            }
        };
        let at = context
            .as_ref()
            .map_or_else(|| String::from("the value"), Label::to_string);
        check_indexes(&at, &self.shape.specs())?;
        Ok(context)
    }
}

/// A one-value plan: a context (or none, for the call to name), and how the
/// value is laid out: its indexes ([`Indexed`], from `with`) or a target
/// ([`Typed`], from `encrypt_into`). Built from [`Plan::value`] or
/// `Plan::context(..).with(..)`.
///
/// It carries its plaintext type, so decrypting through it yields an `S`.
/// A query through an [`Indexed`] plan selects its index by type
/// ([`Indexes::select`]): asking for one it does not hold does not compile.
/// Through a [`Typed`] plan, asking for an index the target does not declare
/// is [`PlanError::IndexNotDeclared`].
pub struct ValuePlan<S, X> {
    context: Option<Label>,
    shape: X,
    plaintext: PhantomData<fn(&S)>,
}

impl<S, X: Clone> Clone for ValuePlan<S, X> {
    fn clone(&self) -> Self {
        Self {
            context: self.context.clone(),
            shape: self.shape.clone(),
            plaintext: PhantomData,
        }
    }
}

impl<S, X: fmt::Debug> fmt::Debug for ValuePlan<S, X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValuePlan")
            .field("context", &self.context.as_ref().map(Label::to_string))
            .field("shape", &self.shape)
            .finish()
    }
}

impl<S, X> ValuePlan<S, X> {
    /// The label the value is sealed and indexed under, when the plan was
    /// built with one.
    pub fn label(&self) -> Option<&Label> {
        self.context.as_ref()
    }

    /// The label one run uses, given the context the call names.
    pub(crate) fn resolve(&self, call: Option<Label>) -> Result<Label, PlanError> {
        resolve_context(self.context.as_ref(), call)
    }

    /// The context the call names against the plan's own: exactly one of
    /// them, which is all a one-value plan checks before a run or an
    /// opening.
    fn check_call(&self, call: Option<&Label>) -> Result<(), Error> {
        Ok(self.resolve(call.cloned()).map(drop)?)
    }

    /// The description one run of this plan executes, given the context the
    /// call names (for a plan built without one; `None` otherwise):
    /// the layout `.under(context)`. A context missing or given twice is a
    /// description that fails without I/O.
    pub fn encryption<'s, K: KeysetRegistry + 'static>(
        &self,
        context: Option<Label>,
    ) -> Encryption<'s, S, X::Output, K, DeclaredContext>
    where
        S: 's,
        X: ValueShape<S>,
    {
        match self.resolve(context) {
            Ok(label) => self.shape.lower().under(NonEmpty::from(label)),
            Err(error) => Encryption::failed(error.into()),
        }
    }
}

impl<S, X> ValuePlan<S, Indexed<X>> {
    /// The index set.
    pub fn indexes(&self) -> &X {
        &self.shape.0
    }
}

impl<S, T> ValuePlan<S, Typed<T>>
where
    Typed<T>: ValueShape<S>,
{
    /// The label a query through `index` is derived under, or why the plan
    /// cannot answer it.
    pub(crate) fn query_label(
        &self,
        index: &IndexSpec,
        call: Option<Label>,
    ) -> Result<Label, PlanError> {
        let label = self.resolve(call)?;
        check_declared(&label.to_string(), &self.shape.specs(), index)?;
        Ok(label)
    }
}

impl<S, T> ValuePlan<S, Typed<T>> {
    /// The description of one run under a context the caller hands over
    /// whole, of any type `C` the target accepts: `T`'s layout,
    /// `.accepting::<C>()`. This is how a derived `plaintext = S` record
    /// runs its plan, so a caller's context reaches every output exactly as
    /// it was given (a `NonEmpty<_>` of any context type, an integer, or an
    /// [`AeadContext`](crate::target::AeadContext) for a target of
    /// ciphertexts alone), not parsed into a [`Label`] first.
    ///
    /// For a plan built without a context; one built with its own fails
    /// with [`PlanError::TwoContextSources`], without I/O.
    pub fn encryption_with_context<'s, K: KeysetRegistry + 'static, C>(
        &self,
    ) -> Encryption<'s, S, T, K, C>
    where
        S: 's,
        T: EncryptFrom<S>,
        C: Into<T::Context> + 's,
    {
        match self.context {
            None => T::encryption().accepting::<C>(),
            Some(_) => Encryption::failed(
                PlanError::TwoContextSources {
                    first: FROM_PLAN,
                    second: FROM_CALL,
                }
                .into(),
            ),
        }
    }
}

impl<S, X, K: KeysetRegistry> Runs<S, K> for ValuePlan<S, X>
where
    X: ValueShape<S>,
    K: KeysetRegistry + 'static,
{
    type Output = X::Output;
    fn pending<'p>(
        &self,
        keyset: &'p KeysetCipher<'_, K>,
        source: &S,
        context: Option<Label>,
        extend: DeclaredContext,
    ) -> Pending<'p, Self::Output, K> {
        keyset.run(self.encryption(context), source, extend)
    }

    fn check(&self, _source: &S, context: Option<&Label>) -> Result<(), Error> {
        self.check_call(context)
    }
}

runs_over_collections! {
    [S, X, K: KeysetRegistry] ValuePlan<S, X> => S where [X: ValueShape<S>, K: KeysetRegistry + 'static] check_call;
}

impl<S, X> ValuePlan<S, X> {
    /// Open one stored `R` under the plan's context (or the call's),
    /// extended by `extend`.
    fn open_one<R, K>(
        &self,
        record: R,
        context: Option<Label>,
        extend: DeclaredContext,
    ) -> Decryption<S, K>
    where
        R: DecryptInto<S>,
        CallerContext: Into<R::Context>,
        S: 'static,
        K: KeysetRegistry + 'static,
    {
        match self.resolve(context) {
            Ok(label) => record.decryption(extend.under(NonEmpty::from(label)).into()),
            Err(error) => Decryption::failed(error.into()),
        }
    }

    /// Open every stored `R` in one batch: one key request.
    fn open_all<R, K>(
        &self,
        records: Vec<R>,
        context: Option<Label>,
        extend: DeclaredContext,
    ) -> Decryption<Vec<S>, K>
    where
        R: DecryptInto<S>,
        CallerContext: Into<R::Context>,
        S: 'static,
        K: KeysetRegistry + 'static,
    {
        Decryption::all(
            records
                .into_iter()
                .map(|record| self.open_one(record, context.clone(), extend.clone())),
        )
    }
}

/// An [`Indexed`] plan opens what it wrote, an [`Encrypted<Terms>`], or its
/// ciphertext alone, one or a `Vec` of them.
macro_rules! indexed_opens {
    ($([$($generics:tt)*] $record:ty;)+) => {$(
        impl<S, X, K: KeysetRegistry, $($generics)*> Opens<$record, K> for ValuePlan<S, Indexed<X>>
        where
            S: crate::Decrypt<'static> + 'static,
            K: KeysetRegistry + 'static,
        {
            type Output = S;
            fn decryption(
                &self,
                record: $record,
                context: Option<Label>,
                extend: DeclaredContext,
            ) -> Decryption<S, K> {
                self.open_one(record, context, extend)
            }
            fn check(&self, _: &$record, context: Option<&Label>) -> Result<(), Error> {
                self.check_call(context)
            }
        }
        impl<S, X, K: KeysetRegistry, $($generics)*> Opens<Vec<$record>, K> for ValuePlan<S, Indexed<X>>
        where
            S: crate::Decrypt<'static> + 'static,
            K: KeysetRegistry + 'static,
        {
            type Output = Vec<S>;
            fn decryption(
                &self,
                records: Vec<$record>,
                context: Option<Label>,
                extend: DeclaredContext,
            ) -> Decryption<Vec<S>, K> {
                self.open_all(records, context, extend)
            }
            fn check(&self, _: &Vec<$record>, context: Option<&Label>) -> Result<(), Error> {
                self.check_call(context)
            }
        }
    )+};
}
indexed_opens! {
    [Terms] Encrypted<Terms>;
    [] StackCipherText;
}

/// A [`Typed`] plan opens its target, one or a `Vec` of them, through the
/// target's own [`DecryptInto`].
impl<S, T, K: KeysetRegistry> Opens<T, K> for ValuePlan<S, Typed<T>>
where
    T: DecryptInto<S>,
    CallerContext: Into<T::Context>,
    S: 'static,
    K: KeysetRegistry + 'static,
{
    type Output = S;
    fn decryption(
        &self,
        record: T,
        context: Option<Label>,
        extend: DeclaredContext,
    ) -> Decryption<S, K> {
        self.open_one(record, context, extend)
    }
    fn check(&self, _: &T, context: Option<&Label>) -> Result<(), Error> {
        self.check_call(context)
    }
}

impl<S, T, K: KeysetRegistry> Opens<Vec<T>, K> for ValuePlan<S, Typed<T>>
where
    T: DecryptInto<S>,
    CallerContext: Into<T::Context>,
    S: 'static,
    K: KeysetRegistry + 'static,
{
    type Output = Vec<S>;
    fn decryption(
        &self,
        records: Vec<T>,
        context: Option<Label>,
        extend: DeclaredContext,
    ) -> Decryption<Vec<S>, K> {
        self.open_all(records, context, extend)
    }
    fn check(&self, _: &Vec<T>, context: Option<&Label>) -> Result<(), Error> {
        self.check_call(context)
    }
}
