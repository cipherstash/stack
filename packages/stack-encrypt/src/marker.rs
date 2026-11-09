//! Field markers: the value a typed query of a record field starts from.
//!
//! `#[derive(EncryptTarget)]` on a `struct = ..` record emits one marker
//! per derived field, as an associated constant named after the field in
//! upper case: `EncryptedUser::EMAIL` for a field `email`. A marker names
//! the field, the context the derive sealed it under (the record's scope,
//! then the field's identity), and the field's target type, whose
//! [`Answers`] impls say which operators the field's indexes answer. So a
//! query from a marker uses the declaration the derive wrote, and never a
//! plan written by hand beside it: the query term and the stored term come
//! from one source.
//!
//! A marker has one method per operator the field's indexes answer, checked
//! at compile time through [`Answers`]: a field of `Encrypted<EqualityTerm>`
//! has [`eq`](Marker::eq) and no `gt`, and the error names the index. The
//! query takes the caller's scopes with [`scope`](MarkedQuery::scope), and
//! no binding: a binding is in no query context, and the query type has no
//! `bind` method. It ends with [`encrypt`](MarkedQuery::encrypt), whose
//! output is the query term the field's index sends for the operator
//! ([`Supports::Query`]).
//!
//! ```
//! use stack_encrypt::kms::FakeDataKeySource;
//! use stack_encrypt::sem::{EqualityTerm, OreTerm};
//! use stack_encrypt::target::{EncryptTarget, Scope};
//! use stack_encrypt::{EncryptInto, Encrypted, StackCipher};
//! use zeroize::Zeroize;
//!
//! #[derive(Clone, Zeroize)]
//! struct User {
//!     email: String,
//!     age: u32,
//! }
//!
//! #[derive(EncryptTarget)]
//! #[stash(struct = User, scope = "users", scope(tenant: u64))]
//! struct EncryptedUser {
//!     email: Encrypted<EqualityTerm>,
//!     age: Encrypted<OreTerm<u32>>,
//! }
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
//! let keyset = cipher.default_keyset();
//! let user = User { email: "ada@example.com".into(), age: 36 };
//! let stored: EncryptedUser = user.encrypt_into_with_context(&keyset, Scope::new(42u64)).await?;
//!
//! // The query from the marker, under the same scope, is the stored term.
//! let by_email = EncryptedUser::EMAIL
//!     .eq("ada@example.com")
//!     .scope(Scope::new(42u64))
//!     .encrypt(&keyset)
//!     .await?;
//! assert_eq!(by_email, stored.email.terms);
//! let adults = EncryptedUser::AGE
//!     .between(&18u32, &36)
//!     .scope(Scope::new(42u64))
//!     .encrypt(&keyset)
//!     .await?;
//! assert_eq!(adults.hi(), &stored.age.terms);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # }).unwrap();
//! ```
//!
//! `EncryptedUser::EMAIL.gt("x")` does not compile: `Encrypted<EqualityTerm>`
//! answers no ordering (`tests/ui/marker_operator_not_answered.rs`). Nor
//! does `.bind(..)` on the query (`tests/ui/marker_query_has_no_bind.rs`).
use std::marker::PhantomData;

use stack_kms::MaybeSend;

use crate::contexts::Contexts;
use crate::op::{
    Answers, Between, Eq, Gt, Gte, Input, LabelledTarget, Lt, Lte, Matches, Operator, QueryToken,
    Supports,
};
use crate::target::{DeclaredContext, Pending};
use crate::{Error, KeysetCipher, Label, PlanError};

/// A field of a derived record, as a value: the field's name, the context
/// the derive sealed it under, and its target type `T`. See the [module
/// docs](self).
pub struct Marker<T> {
    name: &'static str,
    scope: &'static str,
    identity: &'static str,
    contexts: fn() -> Contexts,
    target: PhantomData<fn() -> T>,
}

impl<T> Clone for Marker<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T> Copy for Marker<T> {}
impl<T> std::fmt::Debug for Marker<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Marker")
            .field("name", &self.name)
            .field("scope", &self.scope)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl<T> Marker<T> {
    /// A marker for the field `name`, sealed under `scope` then `identity`
    /// by the record whose `contexts` function this is. The derive emits
    /// the call; a record's markers are its associated constants.
    #[doc(hidden)]
    pub const fn new(
        name: &'static str,
        scope: &'static str,
        identity: &'static str,
        contexts: fn() -> Contexts,
    ) -> Self {
        Self {
            name,
            scope,
            identity,
            contexts,
            target: PhantomData,
        }
    }

    /// The field's name in the record.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The context the field is sealed and indexed under before any part
    /// the caller supplies: the record's scope, then the field's identity,
    /// `users/email`.
    pub fn label(&self) -> Label {
        Label::new([self.scope, self.identity]).unwrap_or_else(|_| {
            unreachable!("the derive refused a scope or identity that is not a plain segment")
        })
    }

    /// The contexts the field is sealed and indexed under, with a
    /// placeholder for each part the caller supplies: the record's
    /// [`contexts()`](Contexts), narrowed to this field. One unnamed
    /// context for a field that is a value; one per inner field for a
    /// field that is itself a record. No key is requested.
    pub fn contexts(&self) -> Contexts {
        (self.contexts)().narrowed(self.name)
    }

    fn query<Op: Operator, In: Input<Op::Arity>>(self, value: In) -> MarkedQuery<T, Op, In> {
        MarkedQuery {
            label: self.label(),
            value,
            scopes: DeclaredContext::default(),
            marker: PhantomData,
        }
    }
}

/// One method per operator. Each exists only where the field's target type
/// answers the operator ([`Answers`]), so a missing one is a compile error
/// that names the field's indexes.
macro_rules! operator_methods {
    ($($(#[$doc:meta])* $method:ident => $op:ident;)+) => {$(
        impl<T> Marker<T> {
            $(#[$doc])*
            pub fn $method<Q>(self, value: &Q) -> MarkedQuery<T, $op, Q::Owned>
            where
                Q: ?Sized + ToOwned,
                Q::Owned: 'static,
                T: Answers<$op, Q::Owned> + LabelledTarget,
            {
                self.query(value.to_owned())
            }
        }
    )+};
}
operator_methods! {
    /// Rows whose value equals `value` ([`op::Eq`](struct@Eq)).
    eq => Eq;
    /// Rows whose value is below `value` ([`op::Lt`](Lt)).
    lt => Lt;
    /// Rows whose value is at or below `value` ([`op::Lte`](Lte)).
    lte => Lte;
    /// Rows whose value is above `value` ([`op::Gt`](Gt)).
    gt => Gt;
    /// Rows whose value is at or above `value` ([`op::Gte`](Gte)).
    gte => Gte;
    /// Rows whose text holds `value`, as the field's match index cuts both
    /// ([`op::Matches`](struct@Matches)). The query term is probabilistic:
    /// verify each decrypted row with it.
    matches => Matches;
}

impl<T> Marker<T> {
    /// Rows whose value is between `lo` and `hi`, inclusive
    /// ([`op::Between`](Between)): one term carrying both bounds, derived
    /// under one context.
    pub fn between<Q>(self, lo: &Q, hi: &Q) -> MarkedQuery<T, Between, (Q::Owned, Q::Owned)>
    where
        Q: ?Sized + ToOwned,
        Q::Owned: 'static,
        T: Answers<Between, (Q::Owned, Q::Owned)> + LabelledTarget,
    {
        self.query((lo.to_owned(), hi.to_owned()))
    }
}

/// A query from a [`Marker`], for the operator `Op` with the input `In`,
/// ready for the caller's scopes and the keyset. It has no `bind` method:
/// a binding is in no query context.
pub struct MarkedQuery<T, Op, In> {
    label: Label,
    value: In,
    scopes: DeclaredContext,
    marker: PhantomData<fn() -> (T, Op)>,
}

impl<T, Op, In> std::fmt::Debug for MarkedQuery<T, Op, In> {
    /// Names the query and its label; the value is plaintext.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarkedQuery")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl<T, Op, In> MarkedQuery<T, Op, In>
where
    Op: Operator,
    In: Input<Op::Arity>,
    T: Answers<Op, In>,
{
    /// Add a scope the stored values were written under: the tenant a
    /// record was encrypted with `Scope::new(tenant)`. Further scopes
    /// nest after it, in order. A `Scope` or a `NonEmpty` converts; a
    /// `Bind` does not, and a context that reaches the query with a
    /// binding inside it is refused when the query runs
    /// ([`PlanError::BindInQuery`]).
    pub fn scope(mut self, part: impl Into<DeclaredContext>) -> Self {
        self.scopes.append(part.into());
        self
    }

    /// Derive the query term under `keyset`: the term the field's index
    /// sends for the operator, derived under the marker's label extended
    /// by the scopes. The query is prepared ([`Supports::prepare`]) before
    /// any key is requested, so a refused query costs no request.
    pub fn encrypt<'a, K: 'static>(
        self,
        keyset: &'a KeysetCipher<'_, K>,
    ) -> Pending<'a, <T::Via as Supports<Op, In>>::Query, K>
    where
        <T::Via as crate::target::Index<In::Plaintext>>::Term: MaybeSend,
        In::Terms<<T::Via as crate::target::Index<In::Plaintext>>::Term>: MaybeSend,
        <T::Via as Supports<Op, In>>::Query: MaybeSend + 'static,
    {
        if self.scopes.has_bindings() {
            return Pending::failed(keyset, Error::from(PlanError::BindInQuery));
        }
        let index = T::Via::default();
        let extended = self.scopes.is_extended();
        let verifier = match index
            .check_label(&self.label, extended)
            .and_then(|()| index.prepare(&self.value))
        {
            Ok(verifier) => verifier,
            Err(error) => return Pending::failed(keyset, error),
        };
        let token = QueryToken::new(self.label.clone(), extended);
        self.value
            .derive(&index, keyset, self.label, self.scopes)
            .map(move |terms| T::Via::query(verifier, terms, token))
    }
}
