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
//! use stack_encrypt::dynamic::{record, Op, Planned, QueryTerm, frame::OwnedFrame};
//! use stack_encrypt::target::Scope;
//! use stack_encrypt::{AsProtectedRef, DecryptFrom, EncryptInto, StackCipher, StackCipherText};
//! use std::collections::BTreeMap;
//! use recipher_frame::serde::to_vec;
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
//! // the environment, or from the profile that `npx stash auth login` writes.
//! let cipher = StackCipher::builder()
//! #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
//!     .init()
//!     .await?;
//! let keyset = cipher.default_keyset();
//! let declaration = to_vec(&serde_json::json!({
//!     "email": { "context": ["users", "email"], "outputs": ["c", "eq"], "type": "string" },
//!     "age": { "context": ["users", "age"], "outputs": ["c", "ore"], "type": "uint64" },
//! }))?;
//! let plan = record::plan(declaration.as_protected_ref())?;
//!
//! // Each value goes straight into a frame, which keeps its bytes under
//! // `Protected` and wipes them when it is dropped. A row is a map of them.
//! let row = || -> Result<OwnedFrame, Box<dyn std::error::Error>> {
//!     let fields = BTreeMap::from([
//!         ("email", OwnedFrame::of("ada@example.com")?),
//!         ("age", OwnedFrame::of(36u64)?),
//!     ]);
//!     Ok(OwnedFrame::of(&fields)?)
//! };
//!
//! // A record under the plan, bound to its row. The values are moved in:
//! // a frame is not `Clone`.
//! let stored: StackCipherText = Planned::new(&plan, row()?)
//!     .encrypt_into_with_context(&keyset, Scope::new(42u64).bind(9u128))
//!     .await?;
//! let opened = OwnedFrame::decrypt_from_with_context(
//!     Planned::new(&plan, stored),
//!     &keyset,
//!     Scope::new(42u64).bind(9u128),
//! )
//! .await?;
//! assert_eq!(opened.frame(), row()?.frame());
//!
//! // A query value under a query plan, by the scope alone.
//! let by_email = plan.query("email", Op::Eq)?;
//! let term: QueryTerm = Planned::new(&by_email, OwnedFrame::of("ada@example.com")?)
//!     .encrypt_into_with_context(&keyset, Scope::new(42u64))
//!     .await?;
//! assert_eq!(term.operator(), Op::Eq);
//!
//! // Or through the field handle, checked against the plan where it is made.
//! let same: QueryTerm = plan
//!     .field("email")?
//!     .eq(OwnedFrame::of("ada@example.com")?)?
//!     .scope(Scope::new(42u64))
//!     .encrypt(&keyset)
//!     .await?;
//! assert_eq!(same, term);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # }).unwrap();
//! ```
use std::any::type_name;
use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use zeroize::Zeroize;

use super::query::{field_operators, find, query_term, QueryTerm};
use super::record::{
    self, name_target, open_record, shape_record, write_record, Absent, Context, FieldPlan, Plan,
    Rows, Verb,
};
use super::target::{NoTargets, TargetResolver};
use super::{Error, Op, Reason, TermBytes};
use crate::contexts::{self, CallerShape, Contexts, LeafContext, Placeholder};
use crate::kms::MaybeSend;
use crate::plan::{field_label, join, FieldValues, IntoLabel, Slot, FROM_CALL, FROM_PLAN};
use crate::target::{
    ciphertext, indexed, inspect, open, AeadContext, Borrowed, CallerContext, DeclaredContext,
    DecryptSource, Decryption, EncryptTarget, Encrypted, Encryption, ExpectedContext, IndexSpec,
    Indexes, OptionalContext, Owned, Pending,
};
use crate::target::{Step, YIELD_EVERY};
use crate::{
    CipherRef, CipherText, Encrypt, KeysetCipher, Label, NonEmpty, PlanError, StackCipherText,
};
use vitaminc_aead::frame::{Frame, OwnedFrame};

/// The resolver of a build without EQL types, for [`Plan::field`].
static NO_TARGETS: NoTargets = NoTargets;

/// One value under one plan: a record under a [`Plan`], or a query value
/// under a [`QueryPlan`], each an [`OwnedFrame`], the dynamic interface's
/// value; or a stored row under a [`Plan`]. A target in the owned API's
/// sense: the stored row implements `EncryptTarget<Planned<Plan,
/// OwnedFrame>>`, a query term implements `EncryptTarget<Planned<QueryPlan,
/// OwnedFrame>>`, and `Planned<Plan, StackCipherText>` implements
/// `DecryptSource<OwnedFrame>`. The resolver `R` runs the EQL type a field
/// names; [`new`](Self::new) takes none, [`with_resolver`](Self::with_resolver)
/// one.
///
/// An `OwnedFrame` is plaintext in a protected buffer: the borrowed form
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

/// Wipes the owned frame the plan holds.
impl<'p, P, R> Zeroize for Planned<'p, P, OwnedFrame, R> {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

/// Wipes nothing: a borrowed frame holds no bytes of its own, and the
/// buffer it borrows is wiped by its owner. A `Planned` is wiped when the
/// owned form of an encryption takes it, which for a borrowed frame lets
/// the borrow go.
impl<'p, P, R> Zeroize for Planned<'p, P, Frame<'_>, R> {
    fn zeroize(&mut self) {}
}

/// A dynamic refusal as the owned path reports it. A binding on a query is
/// the crate's own refusal, [`PlanError::BindInQuery`], as the typed query
/// reports it. Every other refusal is as [`Error::into_crate`] reports it: a
/// cipher error passes through, and a refusal of the input is
/// [`crate::Error::Input`].
fn wrap(error: Error) -> crate::Error {
    match error {
        Error::Plan {
            reason: Reason::BindInQuery,
            ..
        } => PlanError::BindInQuery.into(),
        other => other.into_crate(),
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
                found: None,
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
                found: None,
                row: None,
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

/// A record under a plan encrypts to the stored row: every field under its
/// own context, the caller's scope and then its bindings after the plan's
/// own. The value is an [`OwnedFrame`], or a [`Frame`] borrowed from bytes
/// the caller keeps. The borrowed form reads the frame in place; the owned
/// form consumes it.
impl<'p, V, R> EncryptTarget<Planned<'p, Plan, V, R>> for StackCipherText
where
    V: Encrypt + 'p,
    for<'x> &'x V: Encrypt,
    Planned<'p, Plan, V, R>: Zeroize,
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
                    &source.value,
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
        Encryption::from_owned_build(
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

/// The record lowered under the plan extended by the caller's context, or
/// the refusal.
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
    match Planned::with_resolver(&*plan, value, resolver).run_encrypt(cipher) {
        Ok(pending) => pending,
        Err(error) => Pending::failed(cipher, wrap(error)),
    }
}

/// A stored row under a plan decrypts to its values, under the caller's
/// scope and bindings. A row from another keyset than the one the call
/// names is refused before any key is retrieved. The opening is a closure
/// the cipher runs later, which owns the plan, the row and the resolver,
/// so the resolver is `Send + Sync + 'static` here where the encrypt side
/// borrows it.
impl<'p, R> DecryptSource<OwnedFrame> for Planned<'p, Plan, StackCipherText, R>
where
    R: TargetResolver + Send + Sync + 'static,
{
    type ContextInput = OptionalContext<CallerContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<OwnedFrame, K> {
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
            match Planned::with_resolver(&plan, value, &resolver).run_decrypt(cipher, None) {
                Ok(pending) => pending,
                Err(error) => Pending::failed(cipher, wrap(error)),
            }
        })
    }
}

impl<'p, 'r, V, R> Planned<'p, Plan, V, &'r R>
where
    V: Encrypt,
    R: TargetResolver + ?Sized,
{
    /// Lower the plan and run it over the value: a record, or a batch of
    /// records, checked against the plan here, before any key is requested
    /// ([`Error::Source`]), and each target field's EQL type run through the
    /// resolver. Every term is derived and every key request queued in the
    /// one [`Pending`], so awaiting it is one batched `generate_keys` for
    /// every ciphertext leaf of every row and every target field.
    ///
    /// A batch's rows are lowered and run a chunk at a time
    /// ([`built_in_chunks`]): in a wasm guest when the pending settles, with
    /// a yield between two chunks. Everything that refuses the call before
    /// the pending exists still runs here, and so do the target fields:
    /// every row's target fields run through the resolver before the first
    /// chunk, which for an EQL type derives all of its terms. The target
    /// fields are not built in chunks.
    ///
    /// # Errors
    ///
    /// As [`record::encrypt_with`].
    pub(super) fn run_encrypt<'a, K: 'static>(
        self,
        cipher: &'a KeysetCipher<'_, K>,
    ) -> Result<Pending<'a, StackCipherText, K>, Error> {
        let Planned {
            plan,
            value,
            resolver,
        } = self;
        let rows = record::source_rows(value, plan)?;
        let extend = plan.declared_context();
        let shape = plan.shape();
        // Every target field of every row, in row-major order, run by the
        // resolver; `all` merges their requests with the lowered plan's
        // below. A row runs the target fields it does not leave out, so each
        // row's count is its own.
        let mut pendings = Vec::new();
        let mut targets = |row: record::Row| -> Result<(Absent, FieldValues, usize), Error> {
            let fields = plan
                .target_fields()
                .filter(|field| !row.absent.contains(field.name()));
            let mut count = 0;
            for (field, value) in fields.zip(row.targets) {
                let name = field.target().unwrap_or_default();
                pendings.push(
                    resolver
                        .encrypt(
                            name,
                            field.target_options(),
                            cipher,
                            field.label(),
                            &extend,
                            value.frame(),
                        )
                        .map_err(|error| Error::Target(name_target(error, field.name())))?,
                );
                count += 1;
            }
            Ok((row.absent, row.values, count))
        };
        Ok(match rows {
            Rows::One(row) => {
                let (absent, values, _) = targets(row)?;
                let description = compose::<K>(plan, &absent).map_err(|_| Error::Internal)?;
                let eql = Pending::all(cipher, pendings);
                cipher
                    .run(description, values, extend)
                    .zip(eql)
                    .try_map(move |(values, eql)| shape_record(values, eql, &shape, &absent))
            }
            Rows::Batch(rows) => {
                let rows = rows
                    .into_iter()
                    .map(&mut targets)
                    .collect::<Result<Vec<_>, Error>>()?;
                let len = rows.len();
                let mut per_row = Vec::with_capacity(len);
                let groups = by_absent(
                    rows.into_iter()
                        .map(|(absent, values, count)| {
                            per_row.push((absent.clone(), count));
                            (absent, values)
                        })
                        .collect(),
                );
                // One lowered plan per group of rows that leave out the same
                // fields, every group's requests merged into the one call.
                // Each row lowers its own when it is built. Lowering depends
                // on the plan and the group alone, so a group whose plan
                // does not lower is refused here, before the pending exists.
                for (absent, _, _) in &groups {
                    let _ = compose::<K>(plan, absent).map_err(|_| Error::Internal)?;
                }
                let (groups, positions) = BatchRows::new(groups);
                let plan = plan.clone();
                let row =
                    move |absent: &Absent, values: FieldValues| match compose::<K>(&plan, absent) {
                        Ok(description) => cipher.run(description, values, extend.clone()),
                        // Not reached: lowering depends on the plan and the
                        // group alone, and every group lowered above. Each
                        // row composes its own because a description runs
                        // once.
                        Err(_) => Pending::failed(cipher, wrap(Error::Internal)),
                    };
                let eql = Pending::all(cipher, pendings);
                let finish = move |groups: Vec<Vec<Pending<'a, FieldValues, K>>>| {
                    let runs = groups
                        .into_iter()
                        .map(|rows| Pending::all(cipher, rows))
                        .collect();
                    Pending::all(cipher, runs)
                        .zip(eql)
                        .try_map(move |(groups, eql)| {
                            let rows = in_row_order(len, positions.into_iter().zip(groups))?;
                            let mut eql = eql.into_iter();
                            rows.into_iter()
                                .zip(per_row)
                                .map(|(values, (absent, count))| {
                                    let own: Vec<Vec<u8>> = eql.by_ref().take(count).collect();
                                    shape_record(values, own, &shape, &absent)
                                })
                                .collect::<Result<Vec<_>, _>>()
                                .map(CipherText::Sequence)
                        })
                };
                built_in_chunks(cipher, groups, row, finish)
            }
        })
    }
}

impl<'p, 'r, R> Planned<'p, Plan, StackCipherText, &'r R>
where
    R: TargetResolver + ?Sized,
{
    /// Lower the plan and open the stored row, or batch of rows, through
    /// it: the stored tree checked against the plan here, before any key is
    /// requested ([`Error::Record`]), and each target field's EQL value
    /// opened through the resolver. Every leaf, the target fields' included,
    /// is confined to the keyset `cipher_ref` names when it names one, so a
    /// leaf from another keyset is refused before any key is retrieved.
    ///
    /// `expected` is the context the caller expects a plan that takes its
    /// context from a field to find there, checked against each row before
    /// any key is requested; `None` opens each row under the context it
    /// stores. The owned entry point passes `None`.
    ///
    /// A batch's rows are opened a chunk at a time, as
    /// [`run_encrypt`](Self::run_encrypt)'s are lowered. The target fields
    /// are not: every row's target fields are opened through the resolver
    /// here, before the first chunk.
    ///
    /// # Errors
    ///
    /// As [`record::decrypt_with`].
    pub(super) fn run_decrypt<'a, K: 'static>(
        self,
        cipher_ref: impl Into<CipherRef<'a, K>>,
        expected: Option<Label>,
    ) -> Result<Pending<'a, OwnedFrame, K>, Error> {
        let Planned {
            plan,
            value,
            resolver,
        } = self;
        let cipher_ref: CipherRef<'a, K> = cipher_ref.into();
        let rows = record::record_rows(value, plan)?;
        let extend = plan.declared_context();
        let shape = plan.shape();
        let cipher = cipher_ref.cipher();
        let mut pendings = Vec::new();
        let mut targets = |row: record::StoredRow| -> Result<(Absent, FieldValues, usize), Error> {
            let fields = plan
                .target_fields()
                .filter(|field| !row.absent.contains(field.name()));
            let mut count = 0;
            for (field, stored) in fields.zip(row.targets) {
                let name = field.target().unwrap_or_default();
                // Confined to the caller's keyset, as the lowered plan's
                // leaves are: a target value sealed under another keyset is
                // refused before any key is retrieved.
                pendings.push(confine(
                    resolver
                        .decrypt(name, cipher, field.label(), &extend, &stored)
                        .map_err(|error| Error::Target(name_target(error, field.name())))?,
                    &cipher_ref,
                ));
                count += 1;
            }
            Ok((row.absent, row.values, count))
        };
        Ok(match rows {
            Rows::One(row) => {
                let (absent, values, _) = targets(row)?;
                let eql = Pending::all(cipher, pendings);
                confine(
                    cipher.run_decryption(opening::<K>(plan, values, expected, extend, &absent)),
                    &cipher_ref,
                )
                .zip(eql)
                .try_map(move |(values, eql)| {
                    write_record(Rows::One(open_record(values, eql, &shape, &absent)?))
                })
            }
            Rows::Batch(rows) => {
                let rows = rows
                    .into_iter()
                    .map(&mut targets)
                    .collect::<Result<Vec<_>, Error>>()?;
                let len = rows.len();
                let mut per_row = Vec::with_capacity(len);
                let groups = by_absent(
                    rows.into_iter()
                        .map(|(absent, values, count)| {
                            per_row.push((absent.clone(), count));
                            (absent, values)
                        })
                        .collect(),
                );
                let (groups, positions) = BatchRows::new(groups);
                let plan = plan.clone();
                let row = move |absent: &Absent, values: FieldValues| {
                    cipher.run_decryption(opening::<K>(
                        &plan,
                        values,
                        expected.clone(),
                        extend.clone(),
                        absent,
                    ))
                };
                let eql = Pending::all(cipher, pendings);
                let caller = cipher_ref.clone();
                let finish = move |groups: Vec<Vec<Pending<'a, FieldValues, K>>>| {
                    let opens = groups
                        .into_iter()
                        .map(|rows| confine(Pending::collect(cipher, rows), &caller))
                        .collect();
                    Pending::all(cipher, opens)
                        .zip(eql)
                        .try_map(move |(groups, eql)| {
                            let rows = in_row_order(len, positions.into_iter().zip(groups))?;
                            let mut eql = eql.into_iter();
                            let rows = rows
                                .into_iter()
                                .zip(per_row)
                                .map(|(values, (absent, count))| {
                                    let own: Vec<OwnedFrame> = eql.by_ref().take(count).collect();
                                    open_record(values, own, &shape, &absent)
                                })
                                .collect::<Result<Vec<_>, _>>()?;
                            write_record(Rows::Batch(rows))
                        })
                };
                built_in_chunks(cipher_ref, groups, row, finish)
            }
        })
    }
}

/// A pending the client built, confined to the keyset the caller ran it
/// through, when the caller ran it through one: the client opens leaves
/// from any of its keysets, and a keyset cipher refuses a foreign one
/// before any key is retrieved.
fn confine<'a, T: 'a, K>(
    pending: Pending<'a, T, K>,
    cipher_ref: &CipherRef<'a, K>,
) -> Pending<'a, T, K> {
    pending.confined_to(cipher_ref.keyset())
}

/// Every row of a batch, in its [`RowGroup`], each row built into its own
/// pending a chunk at a time ([`build`](Self::build)).
struct BatchRows<'a, R, T: 'a, K> {
    groups: Vec<RowGroup<'a, R, T, K>>,
}

/// The rows of a batch that leave out the same fields ([`by_absent`]): the
/// rows still to build, and the pendings built for the rows before them.
struct RowGroup<'a, R, T: 'a, K> {
    absent: Absent,
    rows: std::vec::IntoIter<R>,
    built: Vec<Pending<'a, T, K>>,
}

impl<'a, R, T: 'a, K> BatchRows<'a, R, T, K> {
    /// The groups [`by_absent`] makes, to build, and the positions of each
    /// group's rows in the batch.
    fn new(groups: Vec<(Absent, Vec<usize>, Vec<R>)>) -> (Self, Vec<Vec<usize>>) {
        let mut positions = Vec::with_capacity(groups.len());
        let groups = groups
            .into_iter()
            .map(|(absent, at, rows)| {
                positions.push(at);
                RowGroup {
                    absent,
                    built: Vec::with_capacity(rows.len()),
                    rows: rows.into_iter(),
                }
            })
            .collect();
        (Self { groups }, positions)
    }

    /// Build rows in order through `row`, until the rows this call built
    /// make `budget` requests or more ([`Pending::key_count`]: one per
    /// data key, and one per keyset loaded), as a column weighs its items
    /// between yields ([`YIELD_EVERY`]). A row that makes none weighs
    /// one, so a batch of rows with no data key is chunked too. Returns
    /// whether rows are left to build.
    ///
    /// A row whose pending already failed ends the build: the batch fails
    /// with the first such row, as a column stops at it, so the rows after
    /// it are dropped unbuilt.
    fn build(
        &mut self,
        budget: usize,
        row: &mut impl FnMut(&Absent, R) -> Pending<'a, T, K>,
    ) -> bool {
        let mut weight = 0;
        let mut failed = false;
        // A group whose rows are all built yields none, so each chunk
        // starts where the last one stopped.
        'build: for group in &mut self.groups {
            for next in group.rows.by_ref() {
                let pending = row(&group.absent, next);
                failed = pending.has_failed();
                weight += pending.key_count().max(1);
                group.built.push(pending);
                if failed || weight >= budget {
                    break 'build;
                }
            }
        }
        if failed {
            for group in &mut self.groups {
                group.rows.by_ref().for_each(drop);
            }
        }
        self.groups.iter().any(|group| group.rows.len() > 0)
    }

    /// Whether the batch has no row, built or to build.
    fn is_empty(&self) -> bool {
        self.groups
            .iter()
            .all(|group| group.rows.len() == 0 && group.built.is_empty())
    }

    /// The pendings built for each group's rows.
    fn into_built(self) -> Vec<Vec<Pending<'a, T, K>>> {
        self.groups.into_iter().map(|group| group.built).collect()
    }
}

/// The pendings `row` builds for `rows`, handed to `finish` to merge.
///
/// In a wasm guest the rows are built when the pending settles
/// ([`in_chunks`]), [`YIELD_EVERY`] data keys' worth at a time with
/// a yield between two chunks, so a host that cannot preempt the guest
/// (the Go SDK, whose garbage collector waits for a running guest call)
/// gets control back while a large batch is built. Natively they are all
/// built now, in one pass with no yield: a step would hold `row`, which
/// holds the cipher, across the yield, and a native step must be `Send`,
/// which would ask the key source to be `Sync`.
///
/// The rows are built in the same order, into the same pendings, either
/// way, and nothing is requested until every row is built.
fn built_in_chunks<'a, R: 'a, T: 'a, U: 'a, K: 'a>(
    cipher_ref: impl Into<CipherRef<'a, K>>,
    rows: BatchRows<'a, R, T, K>,
    row: impl FnMut(&Absent, R) -> Pending<'a, T, K> + 'a,
    finish: impl FnOnce(Vec<Vec<Pending<'a, T, K>>>) -> Pending<'a, U, K> + 'a,
) -> Pending<'a, U, K> {
    #[cfg(target_arch = "wasm32")]
    {
        in_chunks(cipher_ref, rows, row, finish)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = cipher_ref.into();
        let (mut rows, mut row) = (rows, row);
        // No budget: every row, or every row up to a failed one.
        let _ = rows.build(usize::MAX, &mut row);
        finish(rows.into_built())
    }
}

/// [`built_in_chunks`] in a wasm guest: a pending whose rows are built
/// [`chunk`] by chunk when it settles ([`Pending::in_steps`]).
///
/// A batch with no row has no chunk to build, so its pending is built now,
/// as it is natively. Built in steps, it would be confined to the keyset of
/// `cipher_ref`, and settling it would load that keyset, which a native
/// decrypt of an empty batch does not do.
///
/// Natively only the tests build a batch through it, since a native step
/// must be `Send`.
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn in_chunks<'a, R: 'a, T: 'a, U: 'a, K: 'a>(
    cipher_ref: impl Into<CipherRef<'a, K>>,
    rows: BatchRows<'a, R, T, K>,
    row: impl FnMut(&Absent, R) -> Pending<'a, T, K> + MaybeSend + 'a,
    finish: impl FnOnce(Vec<Vec<Pending<'a, T, K>>>) -> Pending<'a, U, K> + MaybeSend + 'a,
) -> Pending<'a, U, K>
where
    BatchRows<'a, R, T, K>: MaybeSend,
{
    if rows.is_empty() {
        return finish(rows.into_built());
    }
    Pending::in_steps(cipher_ref, move |_| chunk(rows, row, finish))
}

/// One chunk of [`in_chunks`], and the rest after it: the step of a
/// [`Pending::in_steps`].
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn chunk<'a, R: 'a, T: 'a, U: 'a, K: 'a>(
    mut rows: BatchRows<'a, R, T, K>,
    mut row: impl FnMut(&Absent, R) -> Pending<'a, T, K> + MaybeSend + 'a,
    finish: impl FnOnce(Vec<Vec<Pending<'a, T, K>>>) -> Pending<'a, U, K> + MaybeSend + 'a,
) -> Step<'a, U, K>
where
    BatchRows<'a, R, T, K>: MaybeSend,
{
    if rows.build(YIELD_EVERY, &mut row) {
        Step::More(Box::new(move |_| chunk(rows, row, finish)))
    } else {
        Step::Built(finish(rows.into_built()))
    }
}

/// The rows of a batch grouped by the fields they leave out, each group
/// with the positions of its rows in the batch, in the order each group
/// first appears: one composed description runs each group ([`compose`]).
/// A batch with no `"null": "sql"` field is one group.
fn by_absent<R>(rows: Vec<(Absent, R)>) -> Vec<(Absent, Vec<usize>, Vec<R>)> {
    let mut groups: Vec<(Absent, Vec<usize>, Vec<R>)> = Vec::new();
    for (at, (absent, row)) in rows.into_iter().enumerate() {
        match groups.iter_mut().find(|(seen, _, _)| *seen == absent) {
            Some((_, positions, members)) => {
                positions.push(at);
                members.push(row);
            }
            None => groups.push((absent, vec![at], vec![row])),
        }
    }
    groups
}

/// Each group's results back in batch order, the inverse of [`by_absent`].
/// A group that answers with another count than it was given is the engine
/// answering with another shape than it was asked.
fn in_row_order<T>(
    len: usize,
    groups: impl IntoIterator<Item = (Vec<usize>, Vec<T>)>,
) -> Result<Vec<T>, crate::Error> {
    let mut rows: Vec<Option<T>> = std::iter::repeat_with(|| None).take(len).collect();
    for (positions, results) in groups {
        if positions.len() != results.len() {
            return Err(crate::Error::ResponseShape);
        }
        for (at, result) in positions.into_iter().zip(results) {
            let slot = rows.get_mut(at).ok_or(crate::Error::ResponseShape)?;
            *slot = Some(result);
        }
    }
    rows.into_iter()
        .map(|row| row.ok_or(crate::Error::ResponseShape))
        .collect()
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
                found: None,
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
/// as. The value is an [`OwnedFrame`] or a borrowed [`Frame`]. The caller's
/// context is its scope alone; a binding is refused before any key is
/// requested ([`PlanError::BindInQuery`]).
impl<'p, V, R> EncryptTarget<Planned<'p, QueryPlan, V, R>> for QueryTerm
where
    V: Encrypt + 'p,
    for<'x> &'x V: Encrypt,
    Planned<'p, QueryPlan, V, R>: Zeroize,
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
                    .term(cipher, &source.value, &scopes, &source.resolver)
            },
        )
    }
    fn owned_encryption<'s, K: 'static>(
    ) -> Encryption<'s, Planned<'p, QueryPlan, V, R>, Self, K, Self::ContextInput, Owned>
    where
        Planned<'p, QueryPlan, V, R>: 's,
    {
        Encryption::from_owned_build(
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
            pub fn $method<V: QueryValue>(self, value: V) -> Result<DynamicQuery<'p, R, V>, Error> {
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
    pub fn op<V: QueryValue>(
        self,
        operator: Op,
        value: V,
    ) -> Result<DynamicQuery<'p, R, V>, Error> {
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

/// A value a [`FieldHandle`] query can hold: an [`OwnedFrame`], wiped when
/// the query is dropped, or a [`Frame`] or `&OwnedFrame` borrowed from bytes
/// the caller keeps and wipes.
///
/// The trait is sealed. A query holds its plaintext until the term is
/// derived, so it accepts only a value whose bytes are wiped. To query with
/// a Rust value, write it into a frame first with [`OwnedFrame::of`].
pub trait QueryValue: Encrypt + sealed::Sealed {}

mod sealed {
    pub trait Sealed {}
}

impl sealed::Sealed for OwnedFrame {}
impl QueryValue for OwnedFrame {}
impl sealed::Sealed for &OwnedFrame {}
impl QueryValue for &OwnedFrame {}
impl sealed::Sealed for Frame<'_> {}
impl QueryValue for Frame<'_> {}

/// A query from a [`FieldHandle`], ready for the caller's scopes and the
/// keyset. It has no `bind` method: a binding is in no query context. The
/// value is a [`QueryValue`], read when the term is derived.
pub struct DynamicQuery<'p, R: ?Sized = NoTargets, V = OwnedFrame> {
    plan: QueryPlan,
    value: V,
    scopes: DeclaredContext,
    resolver: &'p R,
}

impl<'p, R: ?Sized, V> fmt::Debug for DynamicQuery<'p, R, V> {
    /// Names the field and the operator; the value is plaintext.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynamicQuery")
            .field("field", &self.plan.field)
            .field("operator", &self.plan.operator)
            .finish_non_exhaustive()
    }
}

impl<'p, R: ?Sized, V> DynamicQuery<'p, R, V> {
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

impl<'p, R: TargetResolver + ?Sized, V: QueryValue> DynamicQuery<'p, R, V> {
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

// =============================================================================
// The lowering: a data plan composed from the combinators
// =============================================================================

/// The description one run of `plan` executes over a record's values,
/// without the fields in `absent`: a check that the values' fields are the
/// plan's, then each field's verb as its combinator, read out of the
/// record by name, under the field's label, zipped so every key request
/// settles in one batch, and the record assembled. The description is
/// handed the values themselves. Every sealed or indexed field reads its
/// value in place, and then each passthrough field's value is moved into the
/// output, so no value is copied. The values left over are dropped, and a
/// frame wipes itself when it drops. This is the one
/// lowering of a data plan, as the derive's generated code is of a typed
/// record: [`Planned`] and `contexts()` run it. The
/// checks a binding asks without a cipher ([`check_values`],
/// [`check_stored`], [`opening_base`]) are a second statement of the rules
/// the description enforces through `inspect`, `lift` and `under_by`, and
/// the two are kept in step by the tests in this module.
///
/// # Errors
///
/// A field's label that is not plain ([`PlanError::FieldLabel`]), which the
/// plan's parser refuses first, so a parsed plan never fails here.
pub(super) fn compose<'s, K: 'static>(
    plan: &Plan,
    absent: &Absent,
) -> Result<Encryption<'s, FieldValues, FieldValues, K, DeclaredContext, Owned>, crate::Error> {
    let names = lowered_names(plan, absent);
    // The passthrough fields, whose values are moved into the output.
    let mut carried: Vec<Arc<str>> = Vec::new();
    let mut record: Encryption<'s, FieldValues, Vec<(Arc<str>, Slot)>, K, DeclaredContext> =
        inspect::<FieldValues, K, DeclaredContext, _>(move |values| check_names(values, &names))
            .map(|()| Vec::new());
    for field in lowered_fields(plan, absent) {
        let name: Arc<str> = Arc::from(field.name());
        let identity = field.identity().to_owned();
        let Some(operation) = operation_of::<K>(field, &name) else {
            continue;
        };
        // A passthrough is sealed under nothing, so its label is only its
        // record key: a context field's value is read as the context it is.
        let keys_nothing = keys_nothing(field);
        let operation = match plan.context_source() {
            Context::Label(context) => match join(context, &identity) {
                Ok(label) => operation.under(NonEmpty::from(label)),
                Err(source) => return Err(field_label(field.name(), source)),
            },
            Context::Field(of) => {
                let label_field = of.clone();
                let field_name = field.name().to_owned();
                let joined = (!keys_nothing).then(|| identity.clone());
                operation.under_by(of, joined.as_deref(), move |values: &FieldValues| {
                    let context = context_of(values, &label_field)?;
                    if keys_nothing {
                        Ok(context)
                    } else {
                        join(&context, &identity).map_err(|source| field_label(&field_name, source))
                    }
                })
            }
        }
        .named(&name);
        if keys_nothing {
            carried.push(Arc::clone(&name));
        }
        record = record.zip(operation).map(
            move |(mut slots, slot): (Vec<(Arc<str>, Slot)>, Option<Slot>)| {
                slots.extend(slot.map(|slot| (name, slot)));
                slots
            },
        );
    }
    // The record's checks have read the values by now, so a passthrough
    // field that is missing has already failed the record.
    let moved = Encryption::from_owned_build(
        Vec::new(),
        move |mut values: FieldValues, cipher, _: DeclaredContext| {
            let slots: Vec<(Arc<str>, Slot)> = carried
                .into_iter()
                .filter_map(|name| values.take_slot(&name).map(|slot| (name, slot)))
                .collect();
            Pending::ready(cipher, Ok(slots))
        },
    );
    // The output's slots are read by name, so their order does not matter.
    Ok(moved.zip(record).map(|(moved, mut slots)| {
        slots.extend(moved);
        FieldValues::from_slots(slots)
    }))
}

/// The opening of a stored record's values under `plan`, without the
/// fields in `absent`: each sealed field opened under the context it was
/// sealed under (its label, extended by `extend`), passthrough fields
/// carried back, fields that are terms alone left out. `expected` is the
/// context the caller expects a context field to hold, checked before any
/// key is requested; a plan with a context of its own refuses one.
pub(super) fn opening<K: 'static>(
    plan: &Plan,
    mut values: FieldValues,
    expected: Option<Label>,
    extend: DeclaredContext,
    absent: &Absent,
) -> Decryption<FieldValues, K> {
    if let Err(error) = check_stored(plan, &values, absent) {
        return Decryption::failed(error);
    }
    let base = match opening_base(plan, &values, expected) {
        Ok(base) => base,
        Err(error) => return Decryption::failed(error),
    };
    let mut opened: Decryption<Vec<(Arc<str>, Slot)>, K> = Decryption::ready(Vec::new());
    for field in lowered_fields(plan, absent).filter(|field| field.opens()) {
        let name: Arc<str> = Arc::from(field.name());
        let Some(slot) = values.take_slot(field.name()) else {
            return Decryption::failed(not_in_value(field.name()));
        };
        let opening: Decryption<Slot, K> = if keys_nothing(field) {
            Decryption::ready(slot)
        } else {
            let label = match join(&base, field.identity()) {
                Ok(label) => label,
                Err(source) => return Decryption::failed(field_label(field.name(), source)),
            };
            let ciphertext = match sealed_of(slot) {
                Ok(ciphertext) => ciphertext,
                Err(()) => {
                    return Decryption::failed(field_type(
                        field.name(),
                        type_name::<StackCipherText>(),
                    ))
                }
            };
            let sealed_under = extend.clone().under(NonEmpty::from(label));
            open::<OwnedFrame, K>(ciphertext, AeadContext::from(sealed_under)).map(Slot::new)
        };
        opened =
            opened
                .zip(opening)
                .map(move |(mut slots, slot): (Vec<(Arc<str>, Slot)>, Slot)| {
                    slots.push((name, slot));
                    slots
                });
    }
    opened.map(FieldValues::from_slots)
}

/// Whether a field is carried in the clear, under no label of its own: a
/// passthrough, which the field a context-field plan reads its context
/// from always is ([`Plan::with_context_field`] requires it). Its name is
/// only its record key, so a stored one is handed back as it is.
fn keys_nothing(field: &FieldPlan) -> bool {
    field.verb() == Verb::Passthrough
}

/// The names of the fields the lowering runs, in plan order.
fn lowered_names(plan: &Plan, absent: &Absent) -> Vec<String> {
    lowered_fields(plan, absent)
        .map(|field| field.name().to_owned())
        .collect()
}

/// One field's verb as its combinator over the field's value, lifted to
/// read the field out of the record. `None` for a target field, which the
/// resolver runs and the lowering never sees.
///
/// A passthrough field's combinator only checks that the record has the
/// field, and yields no slot: its value is moved into the output afterwards
/// ([`compose`]), not copied here.
fn operation_of<'s, K: 'static>(
    field: &FieldPlan,
    name: &Arc<str>,
) -> Option<Encryption<'s, FieldValues, Option<Slot>, K, CallerContext>> {
    let indexes = field.indexes();
    Some(match field.verb() {
        Verb::Encrypt => lift(
            ciphertext::<OwnedFrame, K, Borrowed>().accepting::<CallerContext>(),
            name,
        ),
        Verb::EncryptIndex => lift(
            indexed::<OwnedFrame, K, Borrowed, Vec<IndexSpec>>(indexes),
            name,
        ),
        Verb::Index => lift(indexes.operations::<K, Borrowed>(), name),
        Verb::Passthrough => {
            let name = Arc::clone(name);
            inspect::<FieldValues, K, CallerContext, _>(move |values| {
                values
                    .get::<OwnedFrame>(&name)
                    .map(drop)
                    .ok_or_else(|| field_type(&name, type_name::<OwnedFrame>()))
            })
            .map(|()| None)
        }
        Verb::Target => return None,
    })
}

/// The fields the lowering runs: every field but a target's, which the
/// resolver runs, and the ones the row leaves out.
fn lowered_fields<'p>(plan: &'p Plan, absent: &'p Absent) -> impl Iterator<Item = &'p FieldPlan> {
    plan.fields()
        .iter()
        .filter(move |field| !field.is_target() && !absent.contains(field.name()))
}

/// A description over one field's value, lifted to read that field out of
/// the record by name and to hold its output in a slot.
fn lift<'s, T, K>(
    operation: Encryption<'s, OwnedFrame, T, K, CallerContext>,
    name: &Arc<str>,
) -> Encryption<'s, FieldValues, Option<Slot>, K, CallerContext>
where
    T: std::any::Any + Send + 'static,
    K: 'static,
{
    let name = Arc::clone(name);
    operation
        .project_by(move |values: &FieldValues| {
            values
                .get::<OwnedFrame>(&name)
                .ok_or_else(|| field_type(&name, type_name::<OwnedFrame>()))
        })
        .map(|output| Some(Slot::new(output)))
}

/// The values' fields against the plan's, both ways, and each at the type
/// the plan reads: what running the plan checks before any key is
/// requested, and what [`check_source`](super::record::check_source) asks
/// without a cipher.
pub(super) fn check_values(
    plan: &Plan,
    values: &FieldValues,
    absent: &Absent,
) -> Result<(), crate::Error> {
    check_names(values, &lowered_names(plan, absent))?;
    for field in lowered_fields(plan, absent) {
        if values.get::<OwnedFrame>(field.name()).is_none() {
            return Err(field_type(field.name(), type_name::<OwnedFrame>()));
        }
    }
    if let Context::Field(of) = plan.context_source() {
        let _ = context_of(values, of)?;
    }
    Ok(())
}

/// A stored record's values against the plan, as opening checks them:
/// every field of the record is one the plan names, and every field the
/// plan can return is in it, of a type its opening reads.
pub(super) fn check_stored(
    plan: &Plan,
    values: &FieldValues,
    absent: &Absent,
) -> Result<(), crate::Error> {
    let names = lowered_names(plan, absent);
    if let Some(extra) = values.names().find(|name| !names.iter().any(|n| n == name)) {
        return Err(PlanError::NotInPlan {
            field: extra.to_owned(),
        }
        .into());
    }
    for field in lowered_fields(plan, absent).filter(|field| field.opens()) {
        let Some(slot) = values.slot(field.name()) else {
            return Err(not_in_value(field.name()));
        };
        let keys_nothing = keys_nothing(field);
        let holds = if keys_nothing {
            slot.is::<OwnedFrame>()
        } else {
            slot.is::<StackCipherText>() || slot.is::<Encrypted<Vec<TermBytes>>>()
        };
        if !holds {
            let expected = if keys_nothing {
                type_name::<OwnedFrame>()
            } else {
                type_name::<StackCipherText>()
            };
            return Err(field_type(field.name(), expected));
        }
    }
    Ok(())
}

/// The context a stored record opens under: the plan's own label, which
/// an `expected` context contradicts, or the record's context field,
/// checked against `expected` before any key is requested.
pub(super) fn opening_base(
    plan: &Plan,
    values: &FieldValues,
    expected: Option<Label>,
) -> Result<Label, crate::Error> {
    match (plan.context_source(), expected) {
        (Context::Label(label), None) => Ok(label.clone()),
        (Context::Label(_), Some(_)) => Err(PlanError::TwoContextSources {
            first: FROM_PLAN,
            second: FROM_CALL,
        }
        .into()),
        (Context::Field(of), expected) => {
            let stored = context_of(values, of)?;
            let expected = match expected {
                Some(expected) => ExpectedContext::from(NonEmpty::from(expected)),
                None => ExpectedContext::default(),
            };
            expected.validate(stored).map(NonEmpty::into_inner)
        }
    }
}

/// The values' fields against the plan's, both ways.
fn check_names(values: &FieldValues, names: &[String]) -> Result<(), crate::Error> {
    if let Some(extra) = values
        .names()
        .find(|have| !names.iter().any(|name| name == have))
    {
        return Err(PlanError::NotInPlan {
            field: extra.to_owned(),
        }
        .into());
    }
    if let Some(missing) = names.iter().find(|name| !values.contains(name)) {
        return Err(not_in_value(missing));
    }
    Ok(())
}

/// The context a record's context field holds, read in place: each sealed
/// field's closure reads it once per row, a parse of a short text, and
/// copies nothing for it.
fn context_of(values: &FieldValues, field: &str) -> Result<Label, crate::Error> {
    values
        .get::<OwnedFrame>(field)
        .ok_or_else(|| field_type(field, type_name::<OwnedFrame>()))?
        .into_label()
        .map_err(|error| PlanError::ContextLabel(error).into())
}

/// A stored sealed field: its ciphertext, whether the slot holds the
/// ciphertext alone, as a stored record does, or the whole
/// `Encrypted<Vec<TermBytes>>` a caller of [`opening`] may hand it, as the
/// typed plan's opener took either.
fn sealed_of(slot: Slot) -> Result<StackCipherText, ()> {
    let slot = match slot.downcast::<StackCipherText>() {
        Ok(ciphertext) => return Ok(ciphertext),
        Err(slot) => slot,
    };
    match slot.downcast::<Encrypted<Vec<TermBytes>>>() {
        Ok(encrypted) => Ok(encrypted.ciphertext),
        Err(_) => Err(()),
    }
}

fn field_type(field: &str, expected: &'static str) -> crate::Error {
    PlanError::FieldType {
        field: field.to_owned(),
        expected,
    }
    .into()
}

fn not_in_value(field: &str) -> crate::Error {
    PlanError::NotInValue {
        field: field.to_owned(),
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::test_frame::{frame_of, Tree};
    use crate::StackCipher;
    use stack_kms::FakeDataKeySource;
    use vitaminc_protected::AsProtectedRef as _;

    fn s(value: &str) -> Tree {
        Tree::String(value.into())
    }
    fn obj(entries: Vec<(&str, Tree)>) -> Tree {
        Tree::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }
    fn strings(items: &[&str]) -> Tree {
        Tree::Array(items.iter().map(|item| s(item)).collect())
    }
    fn field<'a>(name: &'a str, outputs: &[&str], ty: &str) -> (&'a str, Tree) {
        (
            name,
            obj(vec![
                ("context", strings(&["users", name])),
                ("outputs", strings(outputs)),
                ("type", s(ty)),
            ]),
        )
    }
    /// A sealed field and a passthrough, both typed.
    fn the_plan() -> Plan {
        let value = obj(vec![
            field("age", &["c", "eq"], "uint32"),
            field("id", &["passthrough"], "uint64"),
        ]);
        record::plan(frame_of(&value).as_protected_ref().as_deref()).expect("parses")
    }
    /// Two sealed fields, so a row that leaves out neither asks for two
    /// data keys.
    fn two_sealed() -> Plan {
        let value = obj(vec![
            field("age", &["c", "eq"], "uint32"),
            field("id", &["c"], "uint64"),
        ]);
        record::plan(frame_of(&value).as_protected_ref().as_deref()).expect("parses")
    }
    async fn cipher() -> StackCipher<FakeDataKeySource> {
        StackCipher::builder()
            .kms(FakeDataKeySource::new())
            .init()
            .await
            .expect("build cipher")
    }
    fn frame(value: Tree) -> OwnedFrame {
        OwnedFrame::of(&value).expect("a frame")
    }
    fn values(age: Option<Tree>, id: Option<Tree>) -> FieldValues {
        let mut values = FieldValues::new();
        if let Some(age) = age {
            let _ = values.insert("age", frame(age));
        }
        if let Some(id) = id {
            let _ = values.insert("id", frame(id));
        }
        values
    }
    fn reason(error: crate::Error) -> PlanError {
        match error {
            crate::Error::Plan(error) => error,
            other => panic!("not a plan refusal: {other:?}"),
        }
    }

    /// Build `rows` a chunk at a time, as a wasm guest does, and say how
    /// many rows were built once each chunk was. A build that never says it
    /// is done fails here instead of hanging the test.
    fn chunks<'a, R, T: 'a, K>(
        rows: &mut BatchRows<'a, R, T, K>,
        row: &mut impl FnMut(&Absent, R) -> Pending<'a, T, K>,
    ) -> Vec<usize> {
        let mut built = Vec::new();
        for _ in 0..1_000 {
            let more = rows.build(YIELD_EVERY, row);
            built.push(rows.groups.iter().map(|group| group.built.len()).sum());
            if !more {
                return built;
            }
        }
        panic!(
            "the build still had rows to build after {} chunks",
            built.len()
        );
    }

    /// A batch's rows are built a chunk at a time, each chunk ending once
    /// its rows ask for [`YIELD_EVERY`] data keys: the rows of the shared
    /// plan seal one value each, so 200 rows are built 64 at a time, and a
    /// wasm guest yields three times while it builds them. The rows come
    /// back in order, each group's apart, and settle as one call.
    #[tokio::test]
    async fn a_batch_is_built_a_chunk_of_yield_every_keys_at_a_time() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = the_plan();
        let extend = plan.declared_context();
        let row = |i: u32| values(Some(Tree::UInt32(i)), Some(Tree::UInt64(i.into())));
        let mut no_id = Absent::new();
        let _ = no_id.insert("id".to_owned());
        // Two groups: 150 whole rows, then 50 that leave out `id`.
        let (mut rows, positions) = BatchRows::new(vec![
            (
                Absent::new(),
                (0..150).collect(),
                (0..150).map(row).collect(),
            ),
            (
                no_id,
                (150..200).collect(),
                (150..200)
                    .map(|i| values(Some(Tree::UInt32(i)), None))
                    .collect(),
            ),
        ]);
        assert_eq!(positions[1], (150..200).collect::<Vec<usize>>());
        let mut build = |absent: &Absent, values: FieldValues| {
            let description = compose::<FakeDataKeySource>(&plan, absent).expect("lowers");
            keyset.run(description, values, extend.clone())
        };
        let chunks = chunks(&mut rows, &mut build);
        assert_eq!(chunks, [64, 128, 192, 200]);
        let yields = chunks.len() - 1;
        assert_eq!(yields, 200 / YIELD_EVERY, "a yield between each two chunks");

        let groups = rows.into_built();
        assert_eq!(groups.iter().map(Vec::len).collect::<Vec<_>>(), [150, 50]);
        let runs = groups
            .into_iter()
            .map(|rows| Pending::all(&keyset, rows))
            .collect();
        let sealed = Pending::all(&keyset, runs).await.expect("seals");
        assert_eq!(sealed[0].len() + sealed[1].len(), 200);
    }

    /// A chunk is weighed in data keys, not rows: rows that seal two values
    /// each are built 32 at a time.
    #[tokio::test]
    async fn a_chunk_ends_at_yield_every_keys_whatever_each_row_asks_for() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = two_sealed();
        let extend = plan.declared_context();
        let (mut rows, _) = BatchRows::new(vec![(
            Absent::new(),
            (0..100).collect(),
            (0..100u32)
                .map(|i| values(Some(Tree::UInt32(i)), Some(Tree::UInt64(i.into()))))
                .collect(),
        )]);
        let mut build = |absent: &Absent, values: FieldValues| {
            let description = compose::<FakeDataKeySource>(&plan, absent).expect("lowers");
            let pending = keyset.run(description, values, extend.clone());
            assert_eq!(
                pending.key_count(),
                2,
                "a row asks for a key per sealed value"
            );
            pending
        };
        assert_eq!(chunks(&mut rows, &mut build), [32, 64, 96, 100]);
    }

    /// A batch that ends on a chunk's boundary is done with that chunk: no
    /// empty chunk, so no yield, after it.
    #[tokio::test]
    async fn a_batch_that_fills_its_last_chunk_is_done_with_it() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let mut build = |_: &Absent, i: usize| Pending::ready(&keyset, Ok(i));
        let (mut rows, _) = BatchRows::new(vec![
            (Absent::new(), (0..100).collect(), (0..100).collect()),
            (Absent::new(), (100..128).collect(), (100..128).collect()),
        ]);
        assert_eq!(chunks(&mut rows, &mut build), [64, 128]);
    }

    /// A row with no data key weighs one, so a batch that seals nothing is
    /// chunked too; and a row that failed ends the build, with the rows
    /// after it never built, as a column stops at it.
    #[tokio::test]
    async fn a_batch_build_weighs_a_row_with_no_key_and_stops_at_a_failed_row() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let built = std::cell::Cell::new(0);
        let mut build = |_: &Absent, i: usize| {
            built.set(built.get() + 1);
            if i == 100 {
                Pending::failed(&keyset, crate::Error::ResponseShape)
            } else {
                Pending::ready(&keyset, Ok(i))
            }
        };
        let (mut rows, _) = BatchRows::new(vec![(
            Absent::new(),
            (0..200).collect(),
            (0..200).collect(),
        )]);
        assert!(
            rows.build(YIELD_EVERY, &mut build),
            "64 rows that weigh one each"
        );
        assert_eq!(built.get(), 64);
        assert!(
            !rows.build(YIELD_EVERY, &mut build),
            "the failed row ends the build"
        );
        assert_eq!(built.get(), 101, "no row after the failed one is built");
        let column = Pending::all(&keyset, rows.into_built().remove(0)).await;
        assert!(matches!(column, Err(crate::Error::ResponseShape)));
    }

    /// A batch built in steps through [`in_chunks`], as a wasm guest builds it:
    /// no row is built before the pending settles, each step builds a chunk
    /// of [`YIELD_EVERY`] data keys' worth of rows and then yields, and the
    /// rows settle in order, each group apart. A row of the first group
    /// seals two values and a row of the second group one, so the 111 rows
    /// are built 32, then 32, then the last 47.
    #[tokio::test]
    async fn a_batch_built_in_steps_yields_between_chunks_and_settles_in_row_order() {
        use std::future::IntoFuture as _;
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use std::task::{Context, Poll, Waker};

        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = two_sealed();
        let extend = plan.declared_context();
        let mut no_id = Absent::new();
        let _ = no_id.insert("id".to_owned());
        // Every third row leaves out `id`, so the two groups interleave.
        let (whole, part): (Vec<usize>, Vec<usize>) = (0..111).partition(|i| i % 3 != 2);
        let input = |at: &[usize], id: bool| -> Vec<(usize, FieldValues)> {
            at.iter()
                .map(|&i| {
                    let age = Tree::UInt32(u32::try_from(i).expect("small"));
                    let id = id.then(|| Tree::UInt64(u64::try_from(i).expect("small")));
                    (i, values(Some(age), id))
                })
                .collect()
        };
        let (rows, positions) = BatchRows::new(vec![
            (Absent::new(), whole.clone(), input(&whole, true)),
            (no_id.clone(), part.clone(), input(&part, false)),
        ]);
        assert_eq!(positions, [whole.clone(), part.clone()]);

        let built = Arc::new(AtomicUsize::new(0));
        let row = {
            let (plan, extend, built, keyset) =
                (plan.clone(), extend.clone(), built.clone(), &keyset);
            move |absent: &Absent, (at, values): (usize, FieldValues)| {
                let _ = built.fetch_add(1, SeqCst);
                let description = compose::<FakeDataKeySource>(&plan, absent).expect("lowers");
                let pending = keyset.run(description, values, extend.clone());
                pending.map(move |sealed| (at, sealed))
            }
        };
        let finish = {
            let keyset = &keyset;
            move |groups: Vec<Vec<_>>| {
                let runs = groups
                    .into_iter()
                    .map(|rows| Pending::all(keyset, rows))
                    .collect();
                Pending::all(keyset, runs)
            }
        };
        let pending = in_chunks(&keyset, rows, row, finish);
        assert_eq!(built.load(SeqCst), 0, "no row is built before it settles");

        // Settled by hand: each time the future is not ready is a yield
        // between two chunks. A build that never ends fails here instead of
        // hanging the test.
        let mut settle = pending.into_future();
        let mut cx = Context::from_waker(Waker::noop());
        let mut chunks = Vec::new();
        let groups = loop {
            match settle.as_mut().poll(&mut cx) {
                Poll::Ready(groups) => break groups.expect("seals"),
                Poll::Pending => {
                    chunks.push(built.load(SeqCst));
                    assert!(chunks.len() < 1_000, "the build never ended");
                }
            }
        };
        chunks.push(built.load(SeqCst));
        assert_eq!(chunks, [32, 64, 111]);

        let order = |group: &[(usize, FieldValues)]| -> Vec<usize> {
            group.iter().map(|(at, _)| *at).collect()
        };
        assert_eq!(groups.len(), 2);
        assert_eq!(order(&groups[0]), whole);
        assert_eq!(order(&groups[1]), part);
        // Each sealed row opens to its own row's values.
        for (absent, group) in [Absent::new(), no_id].iter().zip(groups) {
            for (at, sealed) in group {
                let opened = keyset
                    .run_decryption(opening::<FakeDataKeySource>(
                        &plan,
                        sealed,
                        None,
                        extend.clone(),
                        absent,
                    ))
                    .await
                    .expect("opens");
                let age = Tree::UInt32(u32::try_from(at).expect("small"));
                assert_eq!(
                    opened.get::<OwnedFrame>("age").map(OwnedFrame::frame),
                    Some(frame(age).frame())
                );
                let id = (!absent.contains("id"))
                    .then(|| frame(Tree::UInt64(u64::try_from(at).expect("small"))));
                assert_eq!(
                    opened.get::<OwnedFrame>("id").map(OwnedFrame::frame),
                    id.as_ref().map(OwnedFrame::frame)
                );
            }
        }
    }

    /// An empty batch built in chunks, as a wasm guest builds a batch, asks
    /// for nothing, as it does natively: through a keyset handle that is not
    /// loaded yet, the keyset stays unloaded. A decrypt confines each group
    /// of rows to the caller's keyset, and an empty batch has no group.
    #[tokio::test]
    async fn an_empty_batch_built_in_chunks_loads_no_keyset() {
        let cipher = cipher().await;
        let handle = cipher.keyset(stack_kms::IdentifiedBy::Name("acme".to_string().into()));
        let (rows, positions) = BatchRows::new(Vec::new());
        assert!(positions.is_empty());
        let (cipher, handle) = (&cipher, &handle);
        let finish = move |groups: Vec<Vec<_>>| {
            let groups = groups
                .into_iter()
                .map(|rows| Pending::all(handle, rows))
                .collect();
            Pending::all(cipher, groups)
        };
        let row = move |_: &Absent, at: usize| Pending::ready(handle, Ok(at));
        let batch = in_chunks(handle, rows, row, finish).await;
        assert!(batch.expect("settles").is_empty());
        assert!(handle.loaded_state().is_none(), "the keyset is not loaded");
    }

    /// What `check_source` asks without a cipher refuses what the
    /// description refuses: a field the plan does not name, a field the
    /// plan names that the values leave out, and a field at another type.
    #[test]
    fn the_values_are_checked_against_the_plan_both_ways() {
        let plan = the_plan();
        let absent = Absent::new();
        let full = || values(Some(Tree::UInt32(34)), Some(Tree::UInt64(7)));
        assert!(check_values(&plan, &full(), &absent).is_ok());

        let mut extra = full();
        let _ = extra.insert("name", frame(s("ada")));
        assert!(matches!(
            reason(check_values(&plan, &extra, &absent).unwrap_err()),
            PlanError::NotInPlan { field } if field == "name"
        ));

        let missing = values(Some(Tree::UInt32(34)), None);
        assert!(matches!(
            reason(check_values(&plan, &missing, &absent).unwrap_err()),
            PlanError::NotInValue { field } if field == "id"
        ));

        let mut typed = values(None, Some(Tree::UInt64(7)));
        let _ = typed.insert("age", 34u32);
        assert!(matches!(
            reason(check_values(&plan, &typed, &absent).unwrap_err()),
            PlanError::FieldType { field, expected, .. }
                if field == "age" && expected == type_name::<OwnedFrame>()
        ));

        // A field the row leaves out is not expected.
        let mut absent_id = Absent::new();
        let _ = absent_id.insert("id".to_owned());
        assert!(check_values(&plan, &missing, &absent_id).is_ok());
    }

    /// A stored record's values are checked at the types the opening reads:
    /// a ciphertext for a sealed field, a frame for a passthrough. A sealed
    /// slot may hold the ciphertext alone, as a stored record does, or the
    /// whole `Encrypted` with its terms, and either opens.
    #[tokio::test]
    async fn the_stored_values_are_checked_against_the_plan() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = the_plan();
        let absent = Absent::new();
        let seal = || async {
            let description = compose::<FakeDataKeySource>(&plan, &absent).expect("composes");
            keyset
                .run(
                    description,
                    values(Some(Tree::UInt32(34)), Some(Tree::UInt64(7))),
                    DeclaredContext::default(),
                )
                .await
                .expect("seals")
        };
        let mut sealed = seal().await;
        assert!(check_stored(&plan, &sealed, &absent).is_ok());

        let encrypted: Encrypted<Vec<TermBytes>> = sealed.take("age").expect("the age");
        let ciphertext = seal()
            .await
            .take::<Encrypted<Vec<TermBytes>>>("age")
            .expect("the age")
            .ciphertext;
        let stored = |age: Slot| {
            FieldValues::from_slots(vec![
                (Arc::from("age"), age),
                (Arc::from("id"), Slot::new(frame(Tree::UInt64(7)))),
            ])
        };
        let whole = stored(Slot::new(encrypted));
        assert!(check_stored(&plan, &whole, &absent).is_ok());
        let opened = cipher
            .run_decryption(opening::<FakeDataKeySource>(
                &plan,
                whole,
                None,
                DeclaredContext::default(),
                &absent,
            ))
            .await
            .expect("opens");
        assert_eq!(
            opened.get::<OwnedFrame>("age").map(OwnedFrame::frame),
            Some(frame(Tree::UInt32(34)).frame())
        );

        // A sealed field holding a frame, an extra field, a missing field.
        let swapped = stored(Slot::new(frame(Tree::UInt32(34))));
        assert!(matches!(
            reason(check_stored(&plan, &swapped, &absent).unwrap_err()),
            PlanError::FieldType { field, expected, .. }
                if field == "age" && expected == type_name::<StackCipherText>()
        ));
        let mut extra = stored(Slot::new(ciphertext));
        let _ = extra.insert("name", frame(s("ada")));
        assert!(matches!(
            reason(check_stored(&plan, &extra, &absent).unwrap_err()),
            PlanError::NotInPlan { field } if field == "name"
        ));
        let missing =
            FieldValues::from_slots(vec![(Arc::from("id"), Slot::new(frame(Tree::UInt64(7))))]);
        assert!(matches!(
            reason(check_stored(&plan, &missing, &absent).unwrap_err()),
            PlanError::NotInValue { field } if field == "age"
        ));
    }

    /// Zeroizing a planned value wipes the value it holds: the frame's bytes
    /// are wiped and it is left holding the plain null.
    #[test]
    fn zeroizing_a_planned_value_leaves_a_null() {
        let plan = the_plan();
        let mut planned = Planned::new(&plan, frame(obj(vec![("age", Tree::UInt32(34))])));
        assert!(!planned.value.frame().is_null());
        planned.zeroize();
        assert!(planned.value.frame().is_null());
        assert_eq!(planned.value.frame(), OwnedFrame::null().frame());
    }

    /// `Debug` names the wrapper and the handle's field, and shows no value.
    #[test]
    fn debug_names_the_wrapper_and_the_field_but_no_value() {
        let plan = the_plan();
        let shown = format!(
            "{:?}",
            Planned::new(&plan, frame(obj(vec![("age", Tree::UInt32(34))])))
        );
        assert!(shown.starts_with("Planned"), "{shown}");
        assert!(!shown.contains("34"), "{shown}");
        let handle = plan.field("age").expect("the field");
        let shown = format!("{handle:?}");
        assert!(shown.starts_with("FieldHandle"), "{shown}");
        assert!(shown.contains("age"), "{shown}");
    }
}
