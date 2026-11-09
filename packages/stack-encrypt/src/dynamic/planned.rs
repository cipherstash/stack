//! A value under a plan that is data: [`Planned`], a target in the owned
//! API's sense, and the query plans and field handles a program whose
//! declaration is data queries through.
//!
//! A [`Plan`] says how a record is stored. [`Planned::new`] pairs it with
//! one record, or one query value, so that the owned entry points run it:
//! `encrypt_into` for a record, `decrypt_from` for a stored row, and the
//! same for a query value under a [`QueryPlan`]. The caller's scopes and
//! bindings come as the one context argument, built from
//! [`Scope`](crate::target::Scope) and [`Bind`](crate::target::Bind), and
//! a query takes scopes only: a binding on a query is refused before any
//! key is requested ([`PlanError::BindInQuery`]).
//!
//! ```
//! use stack_encrypt::dynamic::{record, Op, Planned, QueryTerm, ValueFrame};
//! use stack_encrypt::kms::FakeDataKeySource;
//! use stack_encrypt::target::Scope;
//! use stack_encrypt::{AsProtectedRef, DecryptFrom, EncryptInto, StackCipher, StackCipherText};
//! use vitaminc_aead_frame::serde::to_vec;
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! let keyset = cipher.default_keyset();
//! let declaration = to_vec(&serde_json::json!({
//!     "email": { "context": ["users", "email"], "outputs": ["c", "eq"], "type": "string" },
//!     "age": { "context": ["users", "age"], "outputs": ["c", "ore"], "type": "uint64" },
//! }))?;
//! let plan = record::plan(declaration.as_protected_ref())?;
//! let values = ValueFrame::from_bytes(
//!     to_vec(&serde_json::json!({"email": "ada@example.com", "age": 36}))?.as_protected_ref(),
//! )?;
//!
//! // A record under the plan, bound to its row.
//! let row: StackCipherText = Planned::new(&plan, values.clone())
//!     .encrypt_into_with_context(&keyset, Scope::new(42u64).bind(9u128))
//!     .await?;
//! let opened = ValueFrame::decrypt_from_with_context(
//!     Planned::new(&plan, row),
//!     &keyset,
//!     Scope::new(42u64).bind(9u128),
//! )
//! .await?;
//! assert_eq!(opened, values);
//!
//! // A query value under a query plan, by the scope alone.
//! let by_email = plan.query("email", Op::Eq)?;
//! let probe = ValueFrame::from_bytes(to_vec("ada@example.com")?.as_protected_ref())?;
//! let term: QueryTerm = Planned::new(&by_email, probe.clone())
//!     .encrypt_into_with_context(&keyset, Scope::new(42u64))
//!     .await?;
//! assert_eq!(term.operator(), Op::Eq);
//!
//! // Or through the field handle, checked against the plan where it is made.
//! let same: QueryTerm = plan
//!     .field("email")?
//!     .eq(probe)?
//!     .scope(Scope::new(42u64))
//!     .encrypt(&keyset)
//!     .await?;
//! assert_eq!(same, term);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # }).unwrap();
//! ```
use std::borrow::Cow;
use std::fmt;

use zeroize::Zeroize;

use super::query::{field_operators, find, query_term, QueryTerm};
use super::record::{self, Plan};
use super::target::{NoTargets, TargetResolver};
use super::value_frame::ValueFrame;
use super::{Error, Op, Reason, Scope};
use crate::contexts::{self, CallerShape, Contexts, LeafContext, Placeholder};
use crate::target::{
    CallerContext, DeclaredContext, DecryptSource, Decryption, EncryptTarget, Encryption,
    OptionalContext, Owned, Pending,
};
use crate::{Encrypt, KeysetCipher, PlanError, StackCipherText};

/// The resolver of a build without EQL types, for [`Plan::field`].
static NO_TARGETS: NoTargets = NoTargets;

/// One value under one plan: a record under a [`Plan`], or a query value
/// under a [`QueryPlan`], each a [`ValueFrame`], the dynamic interface's
/// value; or a stored row under a [`Plan`]. A target in the owned API's
/// sense: the stored row implements `EncryptTarget<Planned<Plan,
/// ValueFrame>>`, a query term implements `EncryptTarget<Planned<QueryPlan,
/// ValueFrame>>`, and `Planned<Plan, StackCipherText>` implements
/// `DecryptSource<ValueFrame>`. The resolver `R` runs the EQL type a field
/// names; [`new`](Self::new) takes none, [`with_resolver`](Self::with_resolver)
/// one.
///
/// A `ValueFrame` is plaintext in a protected buffer: the borrowed form
/// reads it in place, the owned form consumes it, and the buffer is wiped
/// as it is dropped. `Planned` prints neither the value nor the plan.
pub struct Planned<'p, P, V, R = NoTargets> {
    plan: &'p P,
    value: V,
    resolver: R,
}

impl<'p, P, V> Planned<'p, P, V> {
    /// `value` under `plan`, with no EQL types: a plan whose field names
    /// one is refused when it runs.
    pub fn new(plan: &'p P, value: V) -> Self {
        Self {
            plan,
            value,
            resolver: NoTargets,
        }
    }
}

impl<'p, P, V, R> Planned<'p, P, V, R> {
    /// `value` under `plan`, with `resolver` for the EQL types its fields
    /// name.
    pub fn with_resolver(plan: &'p P, value: V, resolver: R) -> Self {
        Self {
            plan,
            value,
            resolver,
        }
    }

    /// The plan.
    pub fn plan(&self) -> &'p P {
        self.plan
    }
}

impl<'p, V, R> Planned<'p, Plan, V, R> {
    /// The contexts every field of the plan is sealed and indexed under,
    /// after the plan's own parts and with a placeholder for the caller's
    /// scope and for the caller's binding, before the value is encrypted.
    /// No key is requested.
    ///
    /// # Errors
    ///
    /// As [`Plan::contexts`].
    pub fn contexts(&self) -> Result<Contexts, crate::Error> {
        Ok(contexts::resolve(
            self.plan.caller_shapes()?,
            CallerShape::both(caller_scope(), caller_bind()),
        ))
    }
}

impl<'p, V, R> Planned<'p, QueryPlan, V, R> {
    /// The query context and the stored context of the field the query
    /// plan names, with a placeholder for the caller's scope:
    /// [`QueryPlan::contexts`].
    ///
    /// # Errors
    ///
    /// As [`QueryPlan::contexts`].
    pub fn contexts(&self) -> Result<LeafContext, crate::Error> {
        self.plan.contexts()
    }
}

/// The placeholder for the scope a `Planned` record's or query's caller
/// may supply.
fn caller_scope() -> Placeholder {
    Placeholder::optional("scope", "CallerContext")
}

/// The placeholder for the binding a `Planned` record's caller may supply.
fn caller_bind() -> Placeholder {
    Placeholder::optional("bind", "CallerContext").as_bind()
}

impl<'p, P, V, R> fmt::Debug for Planned<'p, P, V, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Planned").finish_non_exhaustive()
    }
}

impl<'p, P, V: Zeroize, R> Zeroize for Planned<'p, P, V, R> {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

/// Replace the frame's bytes with none. The protected buffer that held
/// them wipes them as it is dropped.
impl Zeroize for ValueFrame {
    fn zeroize(&mut self) {
        *self = ValueFrame::empty();
    }
}

/// A dynamic refusal as the owned path reports it. A cipher error is
/// already the crate's and passes through, so a refused term keeps its
/// kind. A binding on a query is the crate's own refusal,
/// [`PlanError::BindInQuery`], as the typed query reports it. Every other
/// dynamic refusal is boxed as [`crate::Error::Other`], with its message.
fn wrap(error: Error) -> crate::Error {
    match error {
        Error::Cipher(error) => error,
        Error::Plan {
            reason: Reason::BindInQuery,
            ..
        } => PlanError::BindInQuery.into(),
        other => crate::Error::Other(Box::new(other)),
    }
}

impl Plan {
    /// This plan under the caller's context: its scope as one more part of
    /// every field's context, then its bindings after the plan's own.
    /// `None` leaves the plan as it is, borrowed: nothing is copied for a
    /// call with no caller context.
    fn under_caller(&self, context: Option<CallerContext>) -> Result<Cow<'_, Self>, Error> {
        let Some(context) = context else {
            return Ok(Cow::Borrowed(self));
        };
        let (scopes, bindings) = context.checked()?.pieces();
        let plan = self.clone().with_scopes(scopes)?;
        if bindings.is_empty() {
            return Ok(Cow::Owned(plan));
        }
        let mut all = plan.bindings().to_vec();
        all.extend(bindings);
        plan.with_bindings(all).map(Cow::Owned)
    }

    /// This plan under a query's scopes, which hold no binding. No scope
    /// leaves the plan as it is, borrowed.
    fn under_scopes<'p>(
        &'p self,
        scopes: &DeclaredContext,
        field: &str,
    ) -> Result<Cow<'p, Self>, Error> {
        if scopes.has_bindings() {
            return Err(Error::Plan {
                field: Some(field.to_owned()),
                reason: Reason::BindInQuery,
            });
        }
        if !scopes.is_extended() {
            return Ok(Cow::Borrowed(self));
        }
        let pieces = scopes.parts().iter().filter_map(|part| part.pieces().0);
        self.clone().with_scopes(pieces).map(Cow::Owned)
    }

    /// A query plan for `field` and `operator`, with no EQL types: refused
    /// here, before any value exists, when no index of the field answers
    /// the operator.
    ///
    /// # Errors
    ///
    /// As [`query_with`](Self::query_with).
    pub fn query(&self, field: &str, operator: Op) -> Result<QueryPlan, Error> {
        self.query_with(field, operator, &NoTargets)
    }

    /// A query plan for `field` and `operator`, with `resolver` for an EQL
    /// type the field names.
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] with [`Reason::NoSuchField`] for a field the plan
    /// does not have; [`Error::Source`] with [`Reason::OperatorNotAnswered`]
    /// when no index of the field answers the operator; [`Error::Target`]
    /// for a type the resolver refuses.
    pub fn query_with(
        &self,
        field: &str,
        operator: Op,
        resolver: &(impl TargetResolver + ?Sized),
    ) -> Result<QueryPlan, Error> {
        let answered = field_operators(self, field, resolver)?
            .into_iter()
            .any(|(op, _)| op == operator);
        if !answered {
            return Err(Error::Source {
                field: Some(field.to_owned()),
                reason: Reason::OperatorNotAnswered,
            });
        }
        Ok(QueryPlan {
            plan: self.clone(),
            field: field.to_owned(),
            operator,
        })
    }

    /// The handle of `field`, whose operator methods are each checked
    /// against this plan where they are called, with no EQL types: a field
    /// that names one is refused at the operator.
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] with [`Reason::NoSuchField`].
    pub fn field<'p>(&'p self, name: &str) -> Result<FieldHandle<'p>, Error> {
        self.field_with(name, &NO_TARGETS)
    }

    /// The handle of `field`, with `resolver` for an EQL type the field
    /// names: each operator is checked through it, and the query runs the
    /// type through it.
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] with [`Reason::NoSuchField`].
    pub fn field_with<'p, R: TargetResolver + ?Sized>(
        &'p self,
        name: &str,
        resolver: &'p R,
    ) -> Result<FieldHandle<'p, R>, Error> {
        let _ = find(self, name)?;
        Ok(FieldHandle {
            plan: self,
            name: name.to_owned(),
            resolver,
        })
    }
}

/// A record under a plan encrypts to the stored row, as
/// [`record::encrypt_with`] produces it: every field under its own context,
/// the caller's scope and then its bindings after the plan's own. The
/// borrowed form reads the frame in place; the owned form consumes it.
impl<'p, R> EncryptTarget<Planned<'p, Plan, ValueFrame, R>> for StackCipherText
where
    R: TargetResolver + 'p,
{
    type ContextInput = OptionalContext<CallerContext>;
    fn encryption<'s, K: 'static>(
    ) -> Encryption<'s, Planned<'p, Plan, ValueFrame, R>, Self, K, Self::ContextInput>
    where
        Planned<'p, Plan, ValueFrame, R>: 's,
    {
        Encryption::from_build(
            contexts::caller_leaf(),
            move |source: &Planned<'p, Plan, ValueFrame, R>,
                  cipher,
                  context: Self::ContextInput| {
                encrypt_record(
                    cipher,
                    source.plan,
                    &source.value,
                    &source.resolver,
                    context,
                )
            },
        )
    }
    fn owned_encryption<'s, K: 'static>(
    ) -> Encryption<'s, Planned<'p, Plan, ValueFrame, R>, Self, K, Self::ContextInput, Owned>
    where
        Planned<'p, Plan, ValueFrame, R>: 's,
    {
        Encryption::from_build(
            contexts::caller_leaf(),
            move |source: Planned<'p, Plan, ValueFrame, R>, cipher, context: Self::ContextInput| {
                let Planned {
                    plan,
                    value,
                    resolver,
                } = source;
                encrypt_record(cipher, plan, value, &resolver, context)
            },
        )
    }
}

/// [`record::encrypt_with`] under the plan extended by the caller's
/// context, or the refusal.
fn encrypt_record<'a, K: 'static>(
    cipher: &'a KeysetCipher<'_, K>,
    plan: &Plan,
    value: impl Encrypt,
    resolver: &(impl TargetResolver + ?Sized),
    context: OptionalContext<CallerContext>,
) -> Pending<'a, StackCipherText, K> {
    let plan = match plan.under_caller(context.into_inner()) {
        Ok(plan) => plan,
        Err(error) => return Pending::failed(cipher, wrap(error)),
    };
    match record::encrypt_with(cipher, value, &plan, resolver) {
        Ok(pending) => pending,
        Err(error) => Pending::failed(cipher, wrap(error)),
    }
}

/// A stored row under a plan decrypts to its values, as
/// [`record::decrypt_with`] opens it, under the caller's scope and
/// bindings. A row from another keyset than the one the call names is
/// refused before any key is retrieved. The opening is a closure the
/// cipher runs later, which owns the plan, the row and the resolver, so
/// the resolver is `Send + Sync + 'static` here where the encrypt side
/// borrows it.
impl<'p, R> DecryptSource<ValueFrame> for Planned<'p, Plan, StackCipherText, R>
where
    R: TargetResolver + Send + Sync + 'static,
{
    type ContextInput = OptionalContext<CallerContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<ValueFrame, K> {
        // The opening is a closure the cipher runs later, so it owns its
        // plan: one copy, with the caller's parts applied.
        let plan = match self.plan.under_caller(context.into_inner()) {
            Ok(plan) => plan.into_owned(),
            Err(error) => return Decryption::failed(wrap(error)),
        };
        let Planned {
            value, resolver, ..
        } = self;
        Decryption::from_open(move |cipher| {
            match record::decrypt_with(Scope::Client(cipher), value, &plan, None, &resolver) {
                Ok(pending) => pending,
                Err(error) => Pending::failed(cipher, wrap(error)),
            }
        })
    }
}

/// A record plan narrowed to one field and one operator: what a query
/// value runs under. Made by [`Plan::query`], which refuses a field no
/// index of which answers the operator, so a query plan in hand is one the
/// engine derives a term for.
#[derive(Clone, Debug)]
pub struct QueryPlan {
    plan: Plan,
    field: String,
    operator: Op,
}

impl QueryPlan {
    /// The record plan the query runs under.
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// The field the query is about.
    pub fn field(&self) -> &str {
        &self.field
    }

    /// The operator.
    pub fn operator(&self) -> Op {
        self.operator
    }

    /// The query context and the stored context of the field, after the
    /// record plan's own parts and with a placeholder for the scope the
    /// caller adds.
    ///
    /// # Errors
    ///
    /// As [`Plan::contexts`].
    pub fn contexts(&self) -> Result<LeafContext, crate::Error> {
        let contexts = contexts::resolve(
            self.plan.caller_shapes()?,
            CallerShape::scope(caller_scope()),
        );
        contexts.get(&self.field).cloned().ok_or_else(|| {
            wrap(Error::Plan {
                field: Some(self.field.clone()),
                reason: Reason::NoSuchField,
            })
        })
    }

    /// [`query_term`] under the plan extended by `scopes`, or the refusal.
    fn term<'a, K: 'static>(
        &self,
        cipher: &'a KeysetCipher<'_, K>,
        value: impl Encrypt,
        scopes: &DeclaredContext,
        resolver: &(impl TargetResolver + ?Sized),
    ) -> Pending<'a, QueryTerm, K> {
        let plan = match self.plan.under_scopes(scopes, &self.field) {
            Ok(plan) => plan,
            Err(error) => return Pending::failed(cipher, wrap(error)),
        };
        match query_term(cipher, &plan, &self.field, self.operator, value, resolver) {
            Ok(pending) => pending,
            Err(error) => Pending::failed(cipher, wrap(error)),
        }
    }
}

/// A query value under a query plan encrypts to the query term, as
/// [`query_term`] derives it: the operand bytes and the SQL type they bind
/// as. The caller's context is its scope alone; a binding is refused
/// before any key is requested ([`PlanError::BindInQuery`]).
impl<'p, R> EncryptTarget<Planned<'p, QueryPlan, ValueFrame, R>> for QueryTerm
where
    R: TargetResolver + 'p,
{
    type ContextInput = OptionalContext<CallerContext>;
    fn encryption<'s, K: 'static>(
    ) -> Encryption<'s, Planned<'p, QueryPlan, ValueFrame, R>, Self, K, Self::ContextInput>
    where
        Planned<'p, QueryPlan, ValueFrame, R>: 's,
    {
        Encryption::from_build(
            contexts::caller_leaf(),
            move |source: &Planned<'p, QueryPlan, ValueFrame, R>,
                  cipher,
                  context: Self::ContextInput| {
                let scopes = context
                    .into_inner()
                    .map(DeclaredContext::from)
                    .unwrap_or_default();
                source
                    .plan
                    .term(cipher, &source.value, &scopes, &source.resolver)
            },
        )
    }
    fn owned_encryption<'s, K: 'static>(
    ) -> Encryption<'s, Planned<'p, QueryPlan, ValueFrame, R>, Self, K, Self::ContextInput, Owned>
    where
        Planned<'p, QueryPlan, ValueFrame, R>: 's,
    {
        Encryption::from_build(
            contexts::caller_leaf(),
            move |source: Planned<'p, QueryPlan, ValueFrame, R>,
                  cipher,
                  context: Self::ContextInput| {
                let scopes = context
                    .into_inner()
                    .map(DeclaredContext::from)
                    .unwrap_or_default();
                let Planned {
                    plan,
                    value,
                    resolver,
                } = source;
                plan.term(cipher, value, &scopes, &resolver)
            },
        )
    }
}

/// One field of a plan that is data, for a query: one method per operator,
/// each checked against the plan where it is called ([`Plan::query_with`]),
/// so a field none of whose indexes answers the operator is refused there.
/// The handle has no `bind` method: a binding is in no query context. Made
/// by [`Plan::field`], with no EQL types, or [`Plan::field_with`], with
/// the resolver that runs the type the field names.
pub struct FieldHandle<'p, R: ?Sized = NoTargets> {
    plan: &'p Plan,
    name: String,
    resolver: &'p R,
}

impl<'p, R: ?Sized> Clone for FieldHandle<'p, R> {
    fn clone(&self) -> Self {
        Self {
            plan: self.plan,
            name: self.name.clone(),
            resolver: self.resolver,
        }
    }
}

impl<'p, R: ?Sized> fmt::Debug for FieldHandle<'p, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldHandle")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// One method per scalar operator, each [`op`](FieldHandle::op) with it.
macro_rules! handle_methods {
    ($($(#[$doc:meta])* $method:ident => $op:ident;)+) => {$(
        impl<'p, R: TargetResolver + ?Sized> FieldHandle<'p, R> {
            $(#[$doc])*
            ///
            /// # Errors
            ///
            /// As [`Plan::query_with`].
            pub fn $method(self, value: ValueFrame) -> Result<DynamicQuery<'p, R>, Error> {
                self.op(Op::$op, value)
            }
        }
    )+};
}
handle_methods! {
    /// Rows whose value equals `value` (`eq`).
    eq => Eq;
    /// Rows whose value is below `value` (`lt`).
    lt => Lt;
    /// Rows whose value is at or below `value` (`lte`).
    lte => Lte;
    /// Rows whose value is above `value` (`gt`).
    gt => Gt;
    /// Rows whose value is at or above `value` (`gte`).
    gte => Gte;
    /// Rows whose text holds `value` (`matches`), a probabilistic answer.
    matches => Matches;
    /// Rows whose value is between the two bounds of `value`, a list of
    /// two values, low then high (`between`).
    between => Between;
}

impl<'p, R: TargetResolver + ?Sized> FieldHandle<'p, R> {
    /// The query for any operator, the JSON ones included, with `value` as
    /// [`query_term`] reads the operator's input: what the named methods
    /// are each one of.
    ///
    /// # Errors
    ///
    /// As [`Plan::query_with`].
    pub fn op(self, operator: Op, value: ValueFrame) -> Result<DynamicQuery<'p, R>, Error> {
        Ok(DynamicQuery {
            plan: self.plan.query_with(&self.name, operator, self.resolver)?,
            value,
            scopes: DeclaredContext::default(),
            resolver: self.resolver,
        })
    }

    /// The field's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The plan the field belongs to.
    pub fn plan(&self) -> &'p Plan {
        self.plan
    }
}

/// A query from a [`FieldHandle`], ready for the caller's scopes and the
/// keyset. It has no `bind` method: a binding is in no query context. The
/// value is a frame, a protected buffer wiped when the query is dropped.
pub struct DynamicQuery<'p, R: ?Sized = NoTargets> {
    plan: QueryPlan,
    value: ValueFrame,
    scopes: DeclaredContext,
    resolver: &'p R,
}

impl<'p, R: ?Sized> fmt::Debug for DynamicQuery<'p, R> {
    /// Names the field and the operator; the value is plaintext.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicQuery")
            .field("field", &self.plan.field)
            .field("operator", &self.plan.operator)
            .finish_non_exhaustive()
    }
}

impl<'p, R: ?Sized> DynamicQuery<'p, R> {
    /// Add a scope the stored values were written under. A `Scope`, a
    /// `NonEmpty` or a bare integer converts; a `Bind` does not, and a
    /// context with a binding inside it is refused when the query runs
    /// ([`PlanError::BindInQuery`]).
    pub fn scope(mut self, part: impl Into<DeclaredContext>) -> Self {
        self.scopes.append(part.into());
        self
    }

    /// The query plan this query runs under.
    pub fn plan(&self) -> &QueryPlan {
        &self.plan
    }
}

impl<'p, R: TargetResolver + ?Sized> DynamicQuery<'p, R> {
    /// Derive the query term under `keyset`: [`query_term`] for the plan,
    /// extended by the scopes. Nothing is requested until the pending is
    /// awaited.
    pub fn encrypt<'a, K: 'static>(
        self,
        keyset: &'a KeysetCipher<'_, K>,
    ) -> Pending<'a, QueryTerm, K> {
        self.plan
            .term(keyset, self.value, &self.scopes, self.resolver)
    }
}
