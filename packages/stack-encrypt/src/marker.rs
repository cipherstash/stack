//! Field markers: the value a typed query of a record field starts from.
//!
//! `#[derive(EncryptTarget)]` on a `struct = ..` record emits one marker
//! per derived field, as an associated constant named after the field in
//! upper case: `EncryptedUser::EMAIL` for a field `email`. A marker names
//! the field, the context the derive sealed it under (the record's scope,
//! then the field's identity), the field's target type, whose [`Answers`]
//! impls say which operators the field's indexes answer, and the scope the
//! record's caller supplies, if it lists one. So a query from a marker uses
//! the declaration the derive wrote, and never a plan written by hand
//! beside it: the query term and the stored term come from one source.
//!
//! A marker has one method per operator the field's indexes answer, checked
//! at compile time through [`Answers`]: a field of `Encrypted<EqualityTerm>`
//! has [`eq`](Marker::eq) and no `gt`, and the error names the index. A
//! record that lists a caller scope, `scope(tenant: u64)`, gives its
//! markers that scope's type, and the query has no
//! [`encrypt`](MarkedQuery::encrypt) until [`scope`](MarkedQuery::scope) is
//! given exactly once, with a value of that type. A record that lists none
//! gives a query that is ready at once and takes no scope. A binding is in
//! no query context, so the query type has no `bind` method. The query ends
//! with `encrypt`, whose output is the query term the field's index sends
//! for the operator ([`Supports::Query`]).
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
//!     .between(18u32, 36)
//!     .scope(Scope::new(42u64))
//!     .encrypt(&keyset)
//!     .await?;
//! assert_eq!(adults.hi(), &stored.age.terms);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! # }).unwrap();
//! ```
//!
//! These do not compile: `EncryptedUser::EMAIL.gt("x")`, since
//! `Encrypted<EqualityTerm>` answers no ordering
//! (`tests/ui/marker_operator_not_answered.rs`); `.encrypt(&keyset)` with
//! no scope, `.scope(Scope::new("42"))` for a `u64` tenant, and a second
//! `.scope(..)` (`tests/ui/marker_query_needs_its_scope.rs`); and
//! `.bind(..)` on the query (`tests/ui/marker_query_has_no_bind.rs`).
//!
//! # What a marker does not check
//!
//! An equality marker takes a value of any type that the equality index
//! accepts: `EMAIL.eq(42u64)` compiles on a text field and matches
//! nothing, because the derive sees the record's field types and not the
//! plaintext struct's. An order marker fixes the type, since `OreTerm<S>`
//! names it. A field whose type is several indexes, such as
//! `Encrypted<(EqualityTerm, MatchTerms)>`, or an `Option<..>` field, has a
//! marker with no operator method yet, since [`Answers`] is implemented for
//! one index (#1596); the query chain still queries them.
//!
//! A marker on a field that is itself a record (`EncryptedAccount::ADDRESS`)
//! names the record's context, and [`contexts`](Marker::contexts) lists the
//! inner fields under it. It has no operator methods, and does not reach
//! the inner record's markers: the inner record's own markers derive under
//! its own scope, not the outer field's.
use std::marker::PhantomData;

use stack_kms::MaybeSend;
use zeroize::Zeroize;

use crate::contexts::Contexts;
use crate::op::{
    Answers, Between, Eq, Gt, Gte, Input, LabelledTarget, Lt, Lte, Matches, Operator, QueryToken,
    Supports,
};
use crate::target::{DeclaredContext, NoScope, Pending, Scope};
use crate::{KeysetCipher, Label};

/// A field of a derived record, as a value: the field's name, the context
/// the derive sealed it under, its target type `T`, and the type `C` of the
/// scope the record's caller supplies: `Scope<u64>` for `scope(tenant:
/// u64)`, [`NoScope`] for a record that lists none. See the [module
/// docs](self).
pub struct Marker<T, C = NoScope> {
    name: &'static str,
    scope: &'static str,
    identity: &'static str,
    contexts: fn() -> Contexts,
    target: PhantomData<fn() -> (T, C)>,
}

impl<T, C> Clone for Marker<T, C> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T, C> Copy for Marker<T, C> {}
impl<T, C> std::fmt::Debug for Marker<T, C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Marker")
            .field("name", &self.name)
            .field("scope", &self.scope)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl<T, C> Marker<T, C> {
    /// A marker for the field `name`, sealed under `scope` then `identity`
    /// by the record whose `contexts` function this is. For generated code:
    /// the derive emits the call with the segments it has checked to be
    /// plain, and a record's markers are its associated constants. A marker
    /// built by hand states nothing about any stored value, and
    /// [`label`](Self::label) panics on a segment that is not plain.
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

    /// The field's name in the record, as `contexts()` names it.
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

    fn query<Op, In>(self, value: In, wipe: fn(In)) -> MarkedQuery<T, Op, In, C::Start>
    where
        Op: Operator,
        In: Input<Op::Arity>,
        C: ScopeInput,
    {
        MarkedQuery {
            label: self.label(),
            value: Some(value),
            wipe,
            scopes: DeclaredContext::default(),
            marker: PhantomData,
        }
    }
}

/// Wipe one owned query value.
fn wipe_one<S: Zeroize>(mut value: S) {
    value.zeroize();
}

/// Wipe both bounds of a range.
fn wipe_pair<S: Zeroize>((mut lo, mut hi): (S, S)) {
    lo.zeroize();
    hi.zeroize();
}

/// What a marker's operator methods take: an owned scalar, moved into the
/// query, or a borrowed text or byte string, copied into it. A number is
/// given by value, `AGE.between(18, 65)`, and a string literal as it is,
/// `EMAIL.eq("ada@example.com")`. The query holds the owned value and
/// wipes it when it is derived, refused or dropped. The scalars are the
/// ones the indexes accept: the booleans, the integers, the floats, text,
/// bytes, the [`value`](crate::value) types, and an `Option` of each.
pub trait QueryInput {
    /// The owned value the query holds.
    type Value: Zeroize + 'static;
    /// The value, owned.
    fn into_value(self) -> Self::Value;
}
macro_rules! owned_query_inputs {
    ($($ty:ty),+ $(,)?) => {$(
        impl QueryInput for $ty {
            type Value = $ty;
            fn into_value(self) -> $ty {
                self
            }
        }
    )+};
}
owned_query_inputs!(
    bool,
    u8,
    u16,
    u32,
    u64,
    u128,
    i8,
    i16,
    i32,
    i64,
    i128,
    f32,
    f64,
    String,
    Vec<u8>,
    crate::value::Date,
    crate::value::Timestamp,
    crate::value::Decimal,
);
impl<V: QueryInput> QueryInput for Option<V> {
    type Value = Option<V::Value>;
    fn into_value(self) -> Self::Value {
        self.map(V::into_value)
    }
}
impl QueryInput for &str {
    type Value = String;
    fn into_value(self) -> String {
        self.to_owned()
    }
}
impl QueryInput for &String {
    type Value = String;
    fn into_value(self) -> String {
        self.clone()
    }
}
impl QueryInput for &[u8] {
    type Value = Vec<u8>;
    fn into_value(self) -> Vec<u8> {
        self.to_vec()
    }
}
impl QueryInput for &Vec<u8> {
    type Value = Vec<u8>;
    fn into_value(self) -> Vec<u8> {
        self.clone()
    }
}

/// One method per operator. Each exists only where the field's target type
/// answers the operator ([`Answers`]), so a missing one is a compile error
/// that names the field's indexes. The value is moved or copied into the
/// query ([`QueryInput`]), and wiped when the query is derived, refused or
/// dropped.
macro_rules! operator_methods {
    ($($(#[$doc:meta])* $method:ident => $op:ident;)+) => {$(
        impl<T, C: ScopeInput> Marker<T, C> {
            $(#[$doc])*
            pub fn $method<Q>(self, value: Q) -> MarkedQuery<T, $op, Q::Value, C::Start>
            where
                Q: QueryInput,
                T: Answers<$op, Q::Value> + LabelledTarget,
            {
                self.query(value.into_value(), wipe_one)
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

impl<T, C: ScopeInput> Marker<T, C> {
    /// Rows whose value is between `lo` and `hi`, inclusive
    /// ([`op::Between`](Between)): one term carrying both bounds, derived
    /// under one context.
    pub fn between<Q>(self, lo: Q, hi: Q) -> BetweenQuery<T, Q::Value, C::Start>
    where
        Q: QueryInput,
        T: Answers<Between, (Q::Value, Q::Value)> + LabelledTarget,
    {
        self.query((lo.into_value(), hi.into_value()), wipe_pair)
    }
}

/// A query for [`Between`] from a [`Marker`]: the input is the two bounds,
/// low then high, of one type.
pub type BetweenQuery<T, In, S = Ready> = MarkedQuery<T, Between, (In, In), S>;

/// The types a query is tagged with, and holds none of: its target, its
/// operator and its state.
type Tags<T, Op, S> = PhantomData<fn() -> (T, Op, S)>;

/// The scope a record's caller supplies, as a marker's type parameter:
/// what state a query from the marker starts in. Sealed: the two inputs
/// are [`NoScope`] and [`Scope<U>`].
pub trait ScopeInput: scope_sealed::Sealed {
    /// [`Ready`] for a record with no caller scope; [`Needs<Self>`] for a
    /// record whose caller supplies one.
    type Start;
}
mod scope_sealed {
    pub trait Sealed {}
}
impl scope_sealed::Sealed for NoScope {}
impl ScopeInput for NoScope {
    type Start = Ready;
}
impl<U> scope_sealed::Sealed for Scope<U> {}
impl<U> ScopeInput for Scope<U> {
    type Start = Needs<Scope<U>>;
}

/// The state of a query whose record lists a caller scope of type `C`
/// that has not been given yet: [`scope`](MarkedQuery::scope) takes it and
/// makes the query [`Ready`].
pub struct Needs<C>(PhantomData<fn() -> C>);

/// The state of a query that can be encrypted: its record lists no caller
/// scope, or the scope has been given.
pub struct Ready;

/// A query from a [`Marker`], for the operator `Op` with the input `In`, in
/// the state `S`: [`Needs`] its scope, or [`Ready`] for the keyset. It has
/// no `bind` method: a binding is in no query context. The value is wiped
/// when the query is derived, refused or dropped.
pub struct MarkedQuery<T, Op, In, S = Ready> {
    label: Label,
    value: Option<In>,
    wipe: fn(In),
    scopes: DeclaredContext,
    marker: Tags<T, Op, S>,
}

impl<T, Op, In, S> Drop for MarkedQuery<T, Op, In, S> {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            (self.wipe)(value);
        }
    }
}

impl<T, Op, In, S> std::fmt::Debug for MarkedQuery<T, Op, In, S> {
    /// Names the query and its label; the value is plaintext.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarkedQuery")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

impl<T, Op, In, C> MarkedQuery<T, Op, In, Needs<C>>
where
    C: Into<DeclaredContext>,
{
    /// Give the scope the record's caller supplies: the tenant a record
    /// was encrypted with `Scope::new(tenant)`, of the type the record
    /// lists. An empty scope is refused when the query runs. The query is
    /// then [`Ready`]; there is no second `scope`.
    pub fn scope(mut self, scope: C) -> MarkedQuery<T, Op, In, Ready> {
        let mut scopes = std::mem::take(&mut self.scopes);
        scopes.append(scope.into());
        MarkedQuery {
            label: self.label.clone(),
            value: self.value.take(),
            wipe: self.wipe,
            scopes,
            marker: PhantomData,
        }
    }
}

impl<T, Op, In> MarkedQuery<T, Op, In, Ready>
where
    Op: Operator,
    In: Input<Op::Arity>,
    T: Answers<Op, In>,
{
    /// Derive the query term under `keyset`: the term the field's index
    /// sends for the operator, derived under the marker's label extended
    /// by the scope. The query is prepared ([`Supports::prepare`]) before
    /// any key is requested, so a refused query costs no request, and its
    /// value is wiped.
    pub fn encrypt<'a, K: 'static>(
        mut self,
        keyset: &'a KeysetCipher<'_, K>,
    ) -> Pending<'a, <T::Via as Supports<Op, In>>::Query, K>
    where
        <T::Via as crate::target::Index<In::Plaintext>>::Term: MaybeSend,
        In::Terms<<T::Via as crate::target::Index<In::Plaintext>>::Term>: MaybeSend,
        <T::Via as Supports<Op, In>>::Query: MaybeSend + 'static,
    {
        let Some(value) = self.value.take() else {
            unreachable!("a query holds its value until it is encrypted or dropped")
        };
        let index = T::Via::default();
        let extended = self.scopes.is_extended();
        let verifier = match index
            .check_label(&self.label, extended)
            .and_then(|()| index.prepare(&value))
        {
            Ok(verifier) => verifier,
            Err(error) => {
                (self.wipe)(value);
                return Pending::failed(keyset, error);
            }
        };
        let token = QueryToken::new(self.label.clone(), extended);
        let scopes = std::mem::take(&mut self.scopes);
        value
            .derive(&index, keyset, self.label.clone(), scopes)
            .map(move |terms| T::Via::query(verifier, terms, token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// A query value that counts how many times it was wiped.
    struct Spy(Arc<AtomicUsize>);

    impl Zeroize for Spy {
        fn zeroize(&mut self) {
            let _ = self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn query<In>(value: In, wipe: fn(In)) -> MarkedQuery<(), (), In> {
        MarkedQuery {
            label: Label::parse("users/age").expect("a label"),
            value: Some(value),
            wipe,
            scopes: DeclaredContext::default(),
            marker: PhantomData,
        }
    }

    /// A query dropped before it is derived wipes the value it copied.
    #[test]
    fn a_dropped_query_wipes_its_value() {
        let wipes = Arc::new(AtomicUsize::new(0));
        let query = query(Spy(Arc::clone(&wipes)), wipe_one::<Spy>);
        assert_eq!(wipes.load(Ordering::SeqCst), 0, "held, not wiped");
        drop(query);
        assert_eq!(wipes.load(Ordering::SeqCst), 1, "wiped once on drop");
    }

    /// A range query wipes both of its bounds.
    #[test]
    fn a_dropped_range_query_wipes_both_bounds() {
        let lo = Arc::new(AtomicUsize::new(0));
        let hi = Arc::new(AtomicUsize::new(0));
        let query = query(
            (Spy(Arc::clone(&lo)), Spy(Arc::clone(&hi))),
            wipe_pair::<Spy>,
        );
        drop(query);
        assert_eq!(lo.load(Ordering::SeqCst), 1);
        assert_eq!(hi.load(Ordering::SeqCst), 1);
    }

    /// A query whose value was taken, as deriving it does, wipes nothing
    /// twice: the taken value is the derivation's to wipe.
    #[test]
    fn a_taken_value_is_not_wiped_by_the_drop() {
        let wipes = Arc::new(AtomicUsize::new(0));
        let mut query = query(Spy(Arc::clone(&wipes)), wipe_one::<Spy>);
        let taken = query.value.take().expect("the value");
        drop(query);
        assert_eq!(wipes.load(Ordering::SeqCst), 0, "nothing left to wipe");
        drop(taken);
    }

    /// An owned scalar is the query's as it is, for each scalar the
    /// indexes accept; a borrowed text or byte string is copied into an
    /// owned one.
    #[test]
    fn a_query_input_is_owned_or_copied_in() {
        use crate::value::{Date, Decimal, Timestamp};
        macro_rules! owned_as_it_is {
            ($($value:expr),+ $(,)?) => {$(
                assert_eq!($value.into_value(), $value);
                assert_eq!(Some($value).into_value(), Some($value));
            )+};
        }
        owned_as_it_is!(
            true,
            7u8,
            7u16,
            7u32,
            7u64,
            7u128,
            -7i8,
            -7i16,
            -7i32,
            -7i64,
            -7i128,
            0.5f32,
            0.5f64,
            String::from("ada"),
            b"ada".to_vec(),
        );
        let date = Date::from_days_since_epoch(7).unwrap();
        assert_eq!(date.into_value().days_since_epoch(), 7);
        let instant = Timestamp::new(7, 9).unwrap();
        let instant = instant.into_value();
        assert_eq!((instant.seconds(), instant.nanoseconds()), (7, 9));
        let decimal = Decimal::new(75, 1).unwrap();
        let decimal = decimal.into_value();
        assert_eq!((decimal.mantissa(), decimal.scale()), (75, 1));

        assert_eq!("ada".into_value(), String::from("ada"));
        assert_eq!((&String::from("ada")).into_value(), String::from("ada"));
        assert_eq!(b"ada"[..].into_value(), b"ada".to_vec());
        assert_eq!((&b"ada".to_vec()).into_value(), b"ada".to_vec());
    }
}
