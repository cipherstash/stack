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
//! field of several indexes, `Encrypted<(EqualityTerm, MatchTerms)>`, has
//! a method for each operator one of its indexes answers. A nullable field,
//! `Option<Encrypted<EqualityTerm>>`, has the methods a present value has.
//!
//! A record that lists a caller scope, `scope(tenant: u64)`, gives its
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
//! # A field that is a record
//!
//! A field whose type is itself a record, `address: EncryptedAddress`, is
//! sealed under the outer field's context: each inner field's context is
//! its own, `addresses/street`, then the outer field's, `accounts/address`,
//! then the outer record's caller scope. The marker of the outer field
//! reaches the inner record's markers with that context applied:
//!
//! ```text
//! EncryptedAccount::ADDRESS.field(EncryptedAddress::STREET).eq("Main St")
//! ```
//!
//! [`field`](Marker::field) takes a marker of the record the field holds,
//! and no other, so a marker of another record does not compile
//! (`tests/ui/marker_field_of_another_record.rs`). The result is a marker
//! of the inner field, with the outer record's caller scope, and its
//! [`contexts`](Marker::contexts) are the outer record's, narrowed to the
//! inner field. A record three deep is reached one step at a time:
//! `Outer::ACCOUNT.field(EncryptedAccount::ADDRESS).field(EncryptedAddress::STREET)`.
//! The inner record must list no scope of its own, stored or supplied: a
//! query of it would take two scopes, and `field` takes a marker whose
//! scope is [`NoScope`] ([`NestedScope`]).
//!
//! # The type a query takes
//!
//! An equality marker takes a value of any type that the equality index
//! accepts: `EMAIL.eq(42u64)` compiles on a text field and matches
//! nothing, because the derive sees the record's field types and not the
//! plaintext struct's. A field states its type with
//! `#[stash(query = String)]`. Then each of its marker's methods takes that
//! type alone ([`Takes`]), and the derive checks it against the plaintext
//! struct's field, which is that type or an `Option` of it. An order marker
//! fixes the type without the attribute, since `OreTerm<S>` names it.
//!
//! A nullable field's marker without the attribute also takes an `Option`,
//! since the equality index accepts one. `NICK.eq(None::<String>)`
//! compiles and derives a term that no stored row holds: a `None` field
//! stores no term, and a marker query is never `IS NULL`. Mark the field
//! `#[stash(query = String)]` to refuse it.
use std::marker::PhantomData;

use stack_kms::MaybeSend;
use zeroize::Zeroize;

use crate::contexts::Contexts;
use crate::op::{
    Answers, Between, Eq, Gt, Gte, Input, LabelledTarget, Lt, Lte, Matches, Operator, QueryToken,
    Supports,
};
use crate::target::{DeclaredContext, NoScope, Pending, Scope};
use crate::{KeysetCipher, Label, NonEmpty};

/// A field of a derived record, as a value: the field's name, the context
/// the derive sealed it under, its target type `T`, the type `C` of the
/// scope the record's caller supplies (`Scope<u64>` for `scope(tenant:
/// u64)`, [`NoScope`] for a record that lists none), and the type `P` a
/// query of it takes ([`TakesAny`], or [`Takes<String>`] for a field marked
/// `#[stash(query = String)]`).
///
/// `W` is where the field sits: [`Root<R>`] for a field of the record `R`,
/// which is every marker the derive emits, and [`Nested<W>`] for a field of
/// a record that is itself a field, reached with [`field`](Self::field).
/// See the [module docs](self).
pub struct Marker<W, T, C = NoScope, P = TakesAny> {
    name: &'static str,
    scope: &'static str,
    identity: &'static str,
    contexts: fn() -> Contexts,
    place: W,
    target: FieldTags<T, C, P>,
}

/// The types a marker is tagged with, and holds none of: the field's
/// target, its record's caller scope and its query type.
type FieldTags<T, C, P> = PhantomData<fn() -> (T, C, P)>;

impl<W: Copy, T, C, P> Clone for Marker<W, T, C, P> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<W: Copy, T, C, P> Copy for Marker<W, T, C, P> {}
impl<W: Place, T, C, P> std::fmt::Debug for Marker<W, T, C, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Marker")
            .field("name", &self.name)
            .field("scope", &self.scope)
            .field("identity", &self.identity)
            .field("within", &outers(&self.place))
            .finish_non_exhaustive()
    }
}

impl<R, T, C, P> Marker<Root<R>, T, C, P> {
    /// A marker for the field `name` of the record `R`, sealed under
    /// `scope` then `identity` by the record whose `contexts` function this
    /// is. For generated code: the derive emits the call with the segments
    /// it has checked to be plain, and a record's markers are its
    /// associated constants. A marker built by hand states nothing about
    /// any stored value, and [`label`](Self::label) panics on a segment
    /// that is not plain.
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
            place: Root(PhantomData),
            target: PhantomData,
        }
    }
}

impl<W: Place, T, C, P> Marker<W, T, C, P> {
    /// The field's name in its record, as `contexts()` names it.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The field's own context, before any part the caller supplies: the
    /// record's scope, then the field's identity, `users/email`. A field
    /// of a nested record is then extended by the outer fields' contexts,
    /// which [`contexts`](Self::contexts) shows.
    pub fn label(&self) -> Label {
        label(self.scope, self.identity)
    }

    /// The contexts the field is sealed and indexed under, with a
    /// placeholder for each part the caller supplies: the outermost
    /// record's [`contexts()`](Contexts), narrowed to this field. One
    /// unnamed context for a field that is a value; one per inner field for
    /// a field that is itself a record. No key is requested.
    pub fn contexts(&self) -> Contexts {
        self.place.narrow((self.contexts)()).narrowed(self.name)
    }

    /// The marker of a field of the record this field holds, with this
    /// field's context applied: `EncryptedAccount::ADDRESS.field(EncryptedAddress::STREET)`.
    /// A query from it derives under the inner field's own context, then
    /// this field's, then the outer record's caller scope, as the derive
    /// sealed the inner field. It takes this marker's scope, and the inner
    /// marker's query type.
    ///
    /// `inner` must be a marker of the record `T` this field holds, so a
    /// marker of another record does not compile. That record must list no
    /// scope of its own ([`NestedScope`]): a query of it would take two
    /// scopes.
    pub fn field<U, C2: NestedScope, Q>(
        self,
        inner: Marker<Root<T>, U, C2, Q>,
    ) -> Marker<Nested<W>, U, C, Q> {
        Marker {
            name: inner.name,
            scope: inner.scope,
            identity: inner.identity,
            contexts: self.contexts,
            place: Nested {
                name: self.name,
                scope: self.scope,
                identity: self.identity,
                outer: self.place,
            },
            target: PhantomData,
        }
    }

    fn query<Op, In>(self, value: In, wipe: fn(In)) -> MarkedQuery<T, Op, In, C::Start>
    where
        Op: Operator,
        In: Input<Op::Arity>,
        C: ScopeInput,
    {
        MarkedQuery {
            label: self.label(),
            outers: outers(&self.place),
            value: Some(value),
            wipe,
            scopes: DeclaredContext::default(),
            marker: PhantomData,
        }
    }
}

/// The label of a field the derive emitted a marker for: its record's
/// scope, then its identity.
fn label(scope: &'static str, identity: &'static str) -> Label {
    Label::new([scope, identity]).unwrap_or_else(|_| {
        unreachable!("the derive refused a scope or identity that is not a plain segment")
    })
}

/// The labels of the record fields that hold a field at `place`,
/// outermost first: empty for a field of the record itself.
fn outers(place: &impl Place) -> Vec<Label> {
    let mut outers = Vec::new();
    place.push_outers(&mut outers);
    outers
}

/// The scope a record lists for its own caller, where the record is the
/// type of another record's field: [`NoScope`] alone. A query of a field of
/// a record with its own scope would take that scope and the outer
/// record's.
#[diagnostic::on_unimplemented(
    message = "`field` takes a marker of a record that lists no scope of its own, not `{Self}`",
    label = "a query of this field would take two scopes",
    note = "the inner record's fields are reached by `field` only when the inner record has no `scope(..)` of its own, stored or supplied"
)]
pub trait NestedScope: nested_sealed::Sealed {}
mod nested_sealed {
    pub trait Sealed {}
}
impl nested_sealed::Sealed for NoScope {}
impl NestedScope for NoScope {}

/// Where a marked field sits: [`Root`] for a field of the record the
/// derive emitted the marker for, [`Nested`] for one that
/// [`Marker::field`] reached through a record field. Sealed.
pub trait Place: Copy + place_sealed::Sealed {
    /// The outermost record's contexts, narrowed to the record that holds
    /// the field.
    fn narrow(&self, contexts: Contexts) -> Contexts;
    /// Push the labels of the record fields that hold the field, outermost
    /// first: none for a field of the record itself.
    fn push_outers(&self, outers: &mut Vec<Label>);
}
mod place_sealed {
    pub trait Sealed {}
}

/// A field of the record `R` itself: where every marker the derive emits
/// sits. [`Marker::field`] checks a marker's record through it.
pub struct Root<R>(PhantomData<fn() -> R>);
impl<R> Clone for Root<R> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<R> Copy for Root<R> {}
impl<R> place_sealed::Sealed for Root<R> {}
impl<R> Place for Root<R> {
    fn narrow(&self, contexts: Contexts) -> Contexts {
        contexts
    }
    fn push_outers(&self, _: &mut Vec<Label>) {}
}

/// A field of a record that is itself the field named here, which sits at
/// `W`: what [`Marker::field`] makes.
#[derive(Clone, Copy)]
pub struct Nested<W> {
    name: &'static str,
    scope: &'static str,
    identity: &'static str,
    outer: W,
}
impl<W> place_sealed::Sealed for Nested<W> {}
impl<W: Place> Place for Nested<W> {
    fn narrow(&self, contexts: Contexts) -> Contexts {
        self.outer.narrow(contexts).narrowed(self.name)
    }
    fn push_outers(&self, outers: &mut Vec<Label>) {
        self.outer.push_outers(outers);
        outers.push(label(self.scope, self.identity));
    }
}

/// The type a marker's queries take: [`TakesAny`], any type the field's
/// index accepts, or [`Takes<V>`], `V` alone. A field marked
/// `#[stash(query = V)]` is `Takes<V>`. Sealed, for every `V`.
pub trait QueryValue<V>: value_sealed::Sealed<V> {}
mod value_sealed {
    pub trait Sealed<V> {}
}

/// A marker whose queries take any type the field's index accepts: the
/// default, where the record does not state the field's query type.
#[derive(Debug)]
pub enum TakesAny {}
impl<V> value_sealed::Sealed<V> for TakesAny {}
impl<V> QueryValue<V> for TakesAny {}

/// A marker whose queries take `V` alone: a field marked
/// `#[stash(query = V)]`. A query value is copied from its borrowed form,
/// so a marker of `Takes<String>` accepts `"ada"` as well as a `&String`.
///
/// A value of another type is refused at compile time. Since `V` is the one
/// type the marker accepts, the compiler reports it as a mismatch of the
/// value's query form: "type mismatch resolving `<u64 as QueryInput>::Value
/// == String`".
pub struct Takes<V>(PhantomData<fn() -> V>);
impl<V> value_sealed::Sealed<V> for Takes<V> {}
impl<V> QueryValue<V> for Takes<V> {}

/// A plaintext field whose queries take `V`: `V` itself, or `Option<V>`
/// for a nullable field. The derive checks a field's `#[stash(query = V)]`
/// against the plaintext struct's field with it.
#[doc(hidden)]
#[diagnostic::on_unimplemented(
    message = "the plaintext field is `{Self}`, which `query = {V}` does not name",
    label = "the plaintext field's type",
    note = "`#[stash(query = T)]` names the plaintext field's type, or the type inside its `Option`"
)]
pub trait QueryField<V> {}
impl<V> QueryField<V> for V {}
impl<V> QueryField<V> for Option<V> {}

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
/// that names the field's indexes, and only for the field's query type
/// ([`QueryValue`]). The value is moved or copied into the query
/// ([`QueryInput`]), and wiped when the query is derived, refused or
/// dropped.
macro_rules! operator_methods {
    ($($(#[$doc:meta])* $method:ident => $op:ident;)+) => {$(
        impl<W: Place, T, C: ScopeInput, P> Marker<W, T, C, P> {
            $(#[$doc])*
            pub fn $method<Q>(self, value: Q) -> MarkedQuery<T, $op, Q::Value, C::Start>
            where
                Q: QueryInput,
                P: QueryValue<Q::Value>,
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

impl<W: Place, T, C: ScopeInput, P> Marker<W, T, C, P> {
    /// Rows whose value is between `lo` and `hi`, inclusive
    /// ([`op::Between`](Between)): one term carrying both bounds, derived
    /// under one context.
    pub fn between<Q>(self, lo: Q, hi: Q) -> BetweenQuery<T, Q::Value, C::Start>
    where
        Q: QueryInput,
        P: QueryValue<Q::Value>,
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
    /// The labels of the record fields that hold the field, outermost
    /// first.
    outers: Vec<Label>,
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
    /// Names the query, its label and the fields that hold it; the value
    /// is plaintext.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarkedQuery")
            .field("label", &self.label)
            .field("within", &self.outers)
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
            outers: std::mem::take(&mut self.outers),
            value: self.value.take(),
            wipe: self.wipe,
            scopes,
            marker: PhantomData,
        }
    }
}

impl<T, Op, In, S> MarkedQuery<T, Op, In, S> {
    /// The parts the field's own label is extended by: the caller's scope
    /// under each record field that holds the field, outermost first, as
    /// the derive seals a nested record's fields. Each outer field's
    /// context is one part of the next one in, so a field of a field is
    /// `(addresses/street) / ((accounts/address) / tenant)`.
    fn extension(&mut self) -> DeclaredContext {
        let scopes = std::mem::take(&mut self.scopes);
        self.outers.drain(..).fold(scopes, |scopes, outer| {
            DeclaredContext::from(scopes.under(NonEmpty::from(outer)))
        })
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
    /// by the outer fields' contexts and the scope. The query is prepared
    /// ([`Supports::prepare`]) before any key is requested, so a refused
    /// query costs no request, and its value is wiped.
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
        let scopes = self.extension();
        let extended = scopes.is_extended();
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
            outers: Vec::new(),
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
