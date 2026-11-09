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
//! key is requested ([`Reason::BindInQuery`]).
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
use std::fmt;

use zeroize::Zeroize;

use super::query::{field_operators, find, query_term, QueryTerm};
use super::record::{self, Plan};
use super::target::{NoTargets, TargetResolver};
use super::value_frame::ValueFrame;
use super::{Error, Op, Reason, Scope};
use crate::contexts::{self, Contexts, LeafContext};
use crate::target::{
    CallerContext, DeclaredContext, DecryptSource, Decryption, EncryptTarget, Encryption,
    OptionalContext, Owned, Pending,
};
use crate::{Encrypt, KeysetCipher, StackCipherText};

/// One value under one plan: a record under a [`Plan`], or a query value
/// under a [`QueryPlan`]. A target in the owned API's sense: the stored row
/// implements `EncryptTarget<Planned<Plan, V>>`, a query term implements
/// `EncryptTarget<Planned<QueryPlan, V>>`, and `Planned<Plan,
/// StackCipherText>` implements `DecryptSource<ValueFrame>`. The resolver
/// `R` runs the EQL type a field names; [`new`](Self::new) takes none,
/// [`with_resolver`](Self::with_resolver) one.
///
/// The value is plaintext, so `Planned` wipes it when it is dropped through
/// the owned entry points, as every source is, and prints neither it nor
/// the plan.
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
    /// with a placeholder for the parts the caller supplies, before the
    /// value is encrypted. No key is requested.
    ///
    /// # Errors
    ///
    /// As [`Plan::contexts`].
    pub fn contexts(&self) -> Result<Contexts, crate::Error> {
        let shapes = self.plan.caller_shapes()?;
        Ok(contexts::resolve(
            shapes,
            <OptionalContext<CallerContext> as crate::SuppliedContext>::supplies(),
        ))
    }
}

impl<'p, V, R> Planned<'p, QueryPlan, V, R> {
    /// The query context and the stored context of the field the query
    /// plan names: [`QueryPlan::contexts`].
    ///
    /// # Errors
    ///
    /// As [`QueryPlan::contexts`].
    pub fn contexts(&self) -> Result<LeafContext, crate::Error> {
        self.plan.contexts()
    }
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

fn wrap(error: Error) -> crate::Error {
    crate::Error::Other(Box::new(error))
}

impl Plan {
    /// This plan under the caller's context: its scope as one more part of
    /// every field's context, then its bindings after the plan's own.
    /// `None` leaves the plan as it is.
    fn under_caller(self, context: Option<CallerContext>) -> Result<Self, Error> {
        let Some(context) = context else {
            return Ok(self);
        };
        let (scopes, bindings) = context.checked()?.pieces();
        let plan = self.with_scopes(scopes)?;
        if bindings.is_empty() {
            return Ok(plan);
        }
        let mut all = plan.bindings().to_vec();
        all.extend(bindings);
        plan.with_bindings(all)
    }

    /// This plan under a query's scopes, which hold no binding.
    fn under_scopes(self, scopes: &DeclaredContext, field: &str) -> Result<Self, Error> {
        if scopes.has_bindings() {
            return Err(Error::Plan {
                field: Some(field.to_owned()),
                reason: Reason::BindInQuery,
            });
        }
        let pieces = scopes.parts().iter().filter_map(|part| part.pieces().0);
        self.with_scopes(pieces)
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
    /// against this plan where they are called.
    ///
    /// # Errors
    ///
    /// [`Error::Plan`] with [`Reason::NoSuchField`].
    pub fn field<'p>(&'p self, name: &str) -> Result<FieldHandle<'p>, Error> {
        let _ = find(self, name)?;
        Ok(FieldHandle {
            plan: self,
            name: name.to_owned(),
        })
    }
}

/// A record under a plan encrypts to the stored row, as
/// [`record::encrypt_with`] produces it: every field under its own context,
/// the caller's scope and then its bindings after the plan's own. The
/// borrowed form reads a copy of the value; the owned form consumes it.
impl<'p, V, R> EncryptTarget<Planned<'p, Plan, V, R>> for StackCipherText
where
    V: Encrypt + Clone + Zeroize + 'p,
    R: TargetResolver + 'p,
{
    type ContextInput = OptionalContext<CallerContext>;
    fn encryption<'s, K: 'static>(
    ) -> Encryption<'s, Planned<'p, Plan, V, R>, Self, K, Self::ContextInput>
    where
        Planned<'p, Plan, V, R>: 's,
    {
        Encryption::from_build(
            contexts::caller_leaf(),
            move |source: &Planned<'p, Plan, V, R>, cipher, context: Self::ContextInput| {
                encrypt_record(
                    cipher,
                    source.plan,
                    source.value.clone(),
                    &source.resolver,
                    context,
                )
            },
        )
    }
    fn owned_encryption<'s, K: 'static>(
    ) -> Encryption<'s, Planned<'p, Plan, V, R>, Self, K, Self::ContextInput, Owned>
    where
        Planned<'p, Plan, V, R>: 's,
    {
        Encryption::from_build(
            contexts::caller_leaf(),
            move |source: Planned<'p, Plan, V, R>, cipher, context: Self::ContextInput| {
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
    let plan = match plan.clone().under_caller(context.into_inner()) {
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
/// refused before any key is retrieved.
impl<'p, R> DecryptSource<ValueFrame> for Planned<'p, Plan, StackCipherText, R>
where
    R: TargetResolver + Send + Sync + 'static,
{
    type ContextInput = OptionalContext<CallerContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<ValueFrame, K> {
        let plan = match self.plan.clone().under_caller(context.into_inner()) {
            Ok(plan) => plan,
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

    /// The query context and the stored context of the field, before any
    /// scope the caller adds: the record plan's entry for it.
    ///
    /// # Errors
    ///
    /// As [`Plan::contexts`].
    pub fn contexts(&self) -> Result<LeafContext, crate::Error> {
        let contexts = self.plan.contexts()?;
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
        let plan = match self.plan.clone().under_scopes(scopes, &self.field) {
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
/// before any key is requested ([`Reason::BindInQuery`]).
impl<'p, V, R> EncryptTarget<Planned<'p, QueryPlan, V, R>> for QueryTerm
where
    V: Encrypt + Clone + Zeroize + 'p,
    R: TargetResolver + 'p,
{
    type ContextInput = OptionalContext<CallerContext>;
    fn encryption<'s, K: 'static>(
    ) -> Encryption<'s, Planned<'p, QueryPlan, V, R>, Self, K, Self::ContextInput>
    where
        Planned<'p, QueryPlan, V, R>: 's,
    {
        Encryption::from_build(
            contexts::caller_leaf(),
            move |source: &Planned<'p, QueryPlan, V, R>, cipher, context: Self::ContextInput| {
                let scopes = context
                    .into_inner()
                    .map(DeclaredContext::from)
                    .unwrap_or_default();
                source
                    .plan
                    .term(cipher, source.value.clone(), &scopes, &source.resolver)
            },
        )
    }
    fn owned_encryption<'s, K: 'static>(
    ) -> Encryption<'s, Planned<'p, QueryPlan, V, R>, Self, K, Self::ContextInput, Owned>
    where
        Planned<'p, QueryPlan, V, R>: 's,
    {
        Encryption::from_build(
            contexts::caller_leaf(),
            move |source: Planned<'p, QueryPlan, V, R>, cipher, context: Self::ContextInput| {
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
/// each checked against the plan where it is called ([`Plan::query`]), so
/// a field no index of which answers the operator is refused there. The
/// handle has no `bind` method: a binding is in no query context.
#[derive(Clone, Debug)]
pub struct FieldHandle<'p> {
    plan: &'p Plan,
    name: String,
}

/// One method per operator, each a [`Plan::query`] with the value.
macro_rules! handle_methods {
    ($($(#[$doc:meta])* $method:ident => $op:ident;)+) => {$(
        impl<'p> FieldHandle<'p> {
            $(#[$doc])*
            ///
            /// # Errors
            ///
            /// As [`Plan::query`].
            pub fn $method<V>(self, value: V) -> Result<DynamicQuery<V>, Error> {
                Ok(DynamicQuery {
                    plan: self.plan.query(&self.name, Op::$op)?,
                    value,
                    scopes: DeclaredContext::default(),
                    resolver: NoTargets,
                })
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

impl<'p> FieldHandle<'p> {
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
/// keyset. It has no `bind` method: a binding is in no query context.
pub struct DynamicQuery<V, R = NoTargets> {
    plan: QueryPlan,
    value: V,
    scopes: DeclaredContext,
    resolver: R,
}

impl<V, R> fmt::Debug for DynamicQuery<V, R> {
    /// Names the field and the operator; the value is plaintext.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicQuery")
            .field("field", &self.plan.field)
            .field("operator", &self.plan.operator)
            .finish_non_exhaustive()
    }
}

impl<V, R> DynamicQuery<V, R> {
    /// Add a scope the stored values were written under. A `Scope` or a
    /// `NonEmpty` converts; a `Bind` does not, and a context with a binding
    /// inside it is refused when the query runs ([`Reason::BindInQuery`]).
    pub fn scope(mut self, part: impl Into<DeclaredContext>) -> Self {
        self.scopes.append(part.into());
        self
    }

    /// Run the EQL type the field names through `resolver`.
    pub fn with_resolver<R2>(self, resolver: R2) -> DynamicQuery<V, R2> {
        DynamicQuery {
            plan: self.plan,
            value: self.value,
            scopes: self.scopes,
            resolver,
        }
    }

    /// The query plan this query runs under.
    pub fn plan(&self) -> &QueryPlan {
        &self.plan
    }
}

impl<V: Encrypt, R: TargetResolver> DynamicQuery<V, R> {
    /// Derive the query term under `keyset`: [`query_term`] for the plan,
    /// extended by the scopes. Nothing is requested until the pending is
    /// awaited.
    pub fn encrypt<'a, K: 'static>(
        self,
        keyset: &'a KeysetCipher<'_, K>,
    ) -> Pending<'a, QueryTerm, K> {
        self.plan
            .term(keyset, self.value, &self.scopes, &self.resolver)
    }
}
