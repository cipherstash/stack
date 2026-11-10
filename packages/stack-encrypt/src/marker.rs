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
//! A record that lists a scope gives its markers that scope's type. The
//! scope may be one the caller supplies, `scope(tenant: u64)`, or one the
//! row stores, `scope(field = "tenant")`: a query cannot read a row, so it
//! takes either kind from its caller. The query has no
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
//! then the outer record's scope, if it lists one. The marker of the outer
//! field reaches the inner record's markers with that context applied:
//!
//! ```text
//! EncryptedAccount::ADDRESS.field(EncryptedAddress::STREET).eq("Main St")
//! ```
//!
//! [`field`](Marker::field) takes a marker of the record the field holds,
//! and no other, so a marker of another record does not compile
//! (`tests/ui/marker_field_of_another_record.rs`). The result is a marker
//! of the inner field, and its [`contexts`](Marker::contexts) are the outer
//! record's, narrowed to the inner field. A record three deep is reached
//! one step at a time:
//! `Outer::ACCOUNT.field(EncryptedAccount::ADDRESS).field(EncryptedAddress::STREET)`.
//!
//! A nullable record field, `address: Option<EncryptedAddress>`, has the
//! same `field` ([`Holds`]). A row whose field is `None` stores nothing,
//! so no query matches it.
//!
//! ## An inner record with a scope of its own
//!
//! An inner record may list a scope of its own, such as
//! `scope(field = "tenant")`. A query of one of its fields then takes one
//! scope for each record that lists one, and [`scope`](MarkedQuery::scope)
//! takes them together, outermost first ([`JoinScope`]):
//!
//! ```text
//! EncryptedCompany::OFFICE
//!     .field(EncryptedOffice::STREET)
//!     .eq("1 Main St")
//!     .scope((Scope::new(company_tenant), Scope::new(office_tenant)))
//! ```
//!
//! Where only one of the records lists a scope, `scope` takes that one
//! scope alone. A missing scope, a scope of the wrong type, and scopes in
//! the wrong order do not compile
//! (`tests/ui/marker_nested_query_needs_each_scope.rs`). A query takes at
//! most three scopes, so a fourth record with a scope of its own does not
//! compile either (`tests/ui/marker_nested_query_takes_three_scopes.rs`).
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
/// scopes a query of it takes, and the type `P` a query of it takes
/// ([`TakesAny`], or [`Takes<String>`] for a field marked
/// `#[stash(query = String)]`).
///
/// `C` is [`NoScope`] for a record that lists no scope, and `Scope<u64>`
/// for one that lists `scope(tenant: u64)` or `scope(field = "tenant")`
/// over a `u64`. For a field reached with [`field`](Self::field), it is
/// each record's scope, outermost first ([`JoinScope`]): one `Scope<U>`,
/// or a tuple of two or three.
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
            .field("within", &labels(&holders(&self.place)))
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
    /// the inner record's scope if it lists one, then this field's
    /// context, then the outer record's scope, as the derive sealed the
    /// inner field. It takes the inner marker's query type.
    ///
    /// `inner` must be a marker of the record `R` this field holds, or
    /// holds an `Option` of ([`Holds`]), so a marker of another record
    /// does not compile.
    ///
    /// The query takes this marker's scope, then the inner record's
    /// ([`JoinScope`]): `.scope((outer, inner))` where both records list
    /// one, and the one scope alone where one record does.
    pub fn field<R, U, C2, Q>(
        self,
        inner: Marker<Root<R>, U, C2, Q>,
    ) -> Marker<Nested<W>, U, C::Joined, Q>
    where
        T: Holds<R>,
        C: JoinScope<C2>,
        C2: ScopeInput,
    {
        Marker {
            name: inner.name,
            scope: inner.scope,
            identity: inner.identity,
            contexts: self.contexts,
            place: Nested {
                name: self.name,
                scope: self.scope,
                identity: self.identity,
                scoped: C2::COUNT > 0,
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
        let holders = holders(&self.place);
        let nested = holders.iter().filter(|holder| holder.scoped).count();
        MarkedQuery {
            label: self.label(),
            // Each scope the marker takes is one record's. The records
            // that are fields list theirs in `holders`; any scope left over
            // is the outermost record's.
            root_scoped: C::COUNT > nested,
            holders,
            value: Some(value),
            wipe,
            scopes: Vec::new(),
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

/// A record field that holds a marked field: the outer field's label, and
/// whether the record it holds lists a scope of its own. Opaque: a
/// [`Place`] lists them for a query.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct Holder {
    label: Label,
    scoped: bool,
}

/// The record fields that hold a field at `place`, outermost first: empty
/// for a field of the record itself.
fn holders(place: &impl Place) -> Vec<Holder> {
    let mut holders = Vec::new();
    place.push_holders(&mut holders);
    holders
}

/// The labels of the record fields that hold a field, outermost first.
fn labels(holders: &[Holder]) -> Vec<&Label> {
    holders.iter().map(|holder| &holder.label).collect()
}

/// A field type that holds the record `R`: `R` itself, or `Option<R>` for
/// a nullable record field. [`Marker::field`] takes a marker of `R`.
#[diagnostic::on_unimplemented(
    message = "`field` takes a marker of the record this field holds, and `{Self}` does not hold `{R}`",
    label = "a marker of another record",
    note = "a field of type `T` or `Option<T>` takes a marker of the record `T`, such as `T::STREET`"
)]
pub trait Holds<R>: holds_sealed::Sealed<R> {}
mod holds_sealed {
    pub trait Sealed<R> {}
}
impl<R> holds_sealed::Sealed<R> for R {}
impl<R> Holds<R> for R {}
impl<R> holds_sealed::Sealed<R> for Option<R> {}
impl<R> Holds<R> for Option<R> {}

/// The scope a query takes when a field of a record with the scope `Self`
/// holds a record with the scope `Inner`: what [`Marker::field`] gives its
/// result.
///
/// - Where the inner record lists none, the outer record's scope.
/// - Where only the inner record lists one, that scope.
/// - Where both do, both, outermost first: `(Scope<A>, Scope<B>)`.
///
/// A query takes at most three scopes: a fourth does not compile, and the
/// error says so. Sealed.
#[diagnostic::on_unimplemented(
    message = "`field` takes a marker of a record, whose scope is `NoScope` or one `Scope<T>`, not `{Inner}`",
    label = "not the scope of one record"
)]
pub trait JoinScope<Inner>: join_sealed::Sealed<Inner> {
    /// The scope the query takes.
    type Joined: ScopeInput;
}
mod join_sealed {
    pub trait Sealed<Inner> {}

    /// The scope of a fourth record, which a query cannot take. It bounds
    /// the one [`JoinScope`](super::JoinScope) implementation that would
    /// add a fourth scope.
    ///
    /// Without that implementation, the compiler sees one way to join a
    /// fourth scope, `JoinScope<NoScope>`. It then decides that the inner
    /// record lists no scope, and reports a type mismatch that says so.
    /// With it, the compiler takes the inner record's scope from the
    /// marker it is given, and reports this trait's message.
    ///
    /// Its one implementation is for [`Unnameable`], so that the compiler
    /// cannot rule the bound out before it knows the inner scope. No
    /// marker has that scope.
    #[diagnostic::on_unimplemented(
        message = "a query takes at most three scopes, and this field would take a fourth, `{Self}`",
        label = "a fourth record with a scope of its own",
        note = "the dynamic interface queries a field under more than three scopes"
    )]
    pub trait FourthScope {}
    impl FourthScope for super::Scope<Unnameable> {}

    /// A type outside this module cannot name. See [`FourthScope`].
    pub enum Unnameable {}
}
impl<C: ScopeInput> join_sealed::Sealed<NoScope> for C {}
impl<C: ScopeInput> JoinScope<NoScope> for C {
    type Joined = C;
}
impl<B> join_sealed::Sealed<Scope<B>> for NoScope {}
impl<B> JoinScope<Scope<B>> for NoScope {
    type Joined = Scope<B>;
}
impl<A, B> join_sealed::Sealed<Scope<B>> for Scope<A> {}
impl<A, B> JoinScope<Scope<B>> for Scope<A> {
    type Joined = (Scope<A>, Scope<B>);
}
impl<A, B, D> join_sealed::Sealed<Scope<D>> for (Scope<A>, Scope<B>) {}
impl<A, B, D> JoinScope<Scope<D>> for (Scope<A>, Scope<B>) {
    type Joined = (Scope<A>, Scope<B>, Scope<D>);
}
impl<A, B, D, E> join_sealed::Sealed<Scope<E>> for (Scope<A>, Scope<B>, Scope<D>) {}
/// Met by no marker: see `join_sealed::FourthScope`.
impl<A, B, D, E> JoinScope<Scope<E>> for (Scope<A>, Scope<B>, Scope<D>)
where
    Scope<E>: join_sealed::FourthScope,
{
    type Joined = Self;
}

/// Where a marked field sits: [`Root`] for a field of the record the
/// derive emitted the marker for, [`Nested`] for one that
/// [`Marker::field`] reached through a record field. Sealed.
pub trait Place: Copy + place_sealed::Sealed {
    /// The outermost record's contexts, narrowed to the record that holds
    /// the field.
    fn narrow(&self, contexts: Contexts) -> Contexts;
    /// Push the record fields that hold the field, outermost first: none
    /// for a field of the record itself.
    #[doc(hidden)]
    fn push_holders(&self, holders: &mut Vec<Holder>);
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
    fn push_holders(&self, _: &mut Vec<Holder>) {}
}

/// A field of a record that is itself the field named here, which sits at
/// `W`: what [`Marker::field`] makes.
#[derive(Clone, Copy)]
pub struct Nested<W> {
    name: &'static str,
    scope: &'static str,
    identity: &'static str,
    /// Whether the record this field holds lists a scope of its own.
    scoped: bool,
    outer: W,
}
impl<W> place_sealed::Sealed for Nested<W> {}
impl<W: Place> Place for Nested<W> {
    fn narrow(&self, contexts: Contexts) -> Contexts {
        self.outer.narrow(contexts).narrowed(self.name)
    }
    fn push_holders(&self, holders: &mut Vec<Holder>) {
        self.outer.push_holders(holders);
        holders.push(Holder {
            label: label(self.scope, self.identity),
            scoped: self.scoped,
        });
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

/// The scopes a query from a marker takes, as the marker's type
/// parameter: what state the query starts in. Sealed: the inputs are
/// [`NoScope`], [`Scope<U>`], and a tuple of two or three scopes for a
/// field of a record that lists a scope of its own ([`JoinScope`]).
pub trait ScopeInput: scope_sealed::Sealed {
    /// [`Ready`] for a query that takes no scope; [`Needs<Self>`] for one
    /// that takes any.
    type Start;
    /// How many scopes the query takes.
    #[doc(hidden)]
    const COUNT: usize;
}
mod scope_sealed {
    pub trait Sealed {}
}
impl scope_sealed::Sealed for NoScope {}
impl ScopeInput for NoScope {
    type Start = Ready;
    const COUNT: usize = 0;
}
impl<U> scope_sealed::Sealed for Scope<U> {}
impl<U> ScopeInput for Scope<U> {
    type Start = Needs<Scope<U>>;
    const COUNT: usize = 1;
}
impl<A, B> scope_sealed::Sealed for (Scope<A>, Scope<B>) {}
impl<A, B> ScopeInput for (Scope<A>, Scope<B>) {
    type Start = Needs<Self>;
    const COUNT: usize = 2;
}
impl<A, B, D> scope_sealed::Sealed for (Scope<A>, Scope<B>, Scope<D>) {}
impl<A, B, D> ScopeInput for (Scope<A>, Scope<B>, Scope<D>) {
    type Start = Needs<Self>;
    const COUNT: usize = 3;
}

/// The scopes [`scope`](MarkedQuery::scope) is given: one [`Scope<U>`], or
/// a tuple of them, outermost record first. Sealed.
pub trait GivenScopes: given_sealed::Sealed {
    /// Push each scope, outermost record first.
    #[doc(hidden)]
    fn push_scopes(self, scopes: &mut Vec<DeclaredContext>);
}
mod given_sealed {
    pub trait Sealed {}
}
impl<U> given_sealed::Sealed for Scope<U> where Scope<U>: Into<DeclaredContext> {}
impl<U> GivenScopes for Scope<U>
where
    Scope<U>: Into<DeclaredContext>,
{
    fn push_scopes(self, scopes: &mut Vec<DeclaredContext>) {
        scopes.push(self.into());
    }
}
impl<A, B> given_sealed::Sealed for (Scope<A>, Scope<B>) {}
impl<A, B> GivenScopes for (Scope<A>, Scope<B>)
where
    Scope<A>: GivenScopes,
    Scope<B>: GivenScopes,
{
    fn push_scopes(self, scopes: &mut Vec<DeclaredContext>) {
        self.0.push_scopes(scopes);
        self.1.push_scopes(scopes);
    }
}
impl<A, B, D> given_sealed::Sealed for (Scope<A>, Scope<B>, Scope<D>) {}
impl<A, B, D> GivenScopes for (Scope<A>, Scope<B>, Scope<D>)
where
    Scope<A>: GivenScopes,
    Scope<B>: GivenScopes,
    Scope<D>: GivenScopes,
{
    fn push_scopes(self, scopes: &mut Vec<DeclaredContext>) {
        self.0.push_scopes(scopes);
        self.1.push_scopes(scopes);
        self.2.push_scopes(scopes);
    }
}

/// The state of a query that takes the scopes `C`, which have not been
/// given yet: [`scope`](MarkedQuery::scope) takes them and makes the query
/// [`Ready`]. `C` is one [`Scope<U>`], or a tuple of them for a field of a
/// record that lists a scope of its own.
pub struct Needs<C>(PhantomData<fn() -> C>);

/// The state of a query that can be encrypted: it takes no scope, or its
/// scopes have been given.
pub struct Ready;

/// A query from a [`Marker`], for the operator `Op` with the input `In`, in
/// the state `S`: [`Needs`] its scope, or [`Ready`] for the keyset. It has
/// no `bind` method: a binding is in no query context. The value is wiped
/// when the query is derived, refused or dropped.
pub struct MarkedQuery<T, Op, In, S = Ready> {
    label: Label,
    /// The record fields that hold the field, outermost first.
    holders: Vec<Holder>,
    /// Whether the outermost record lists a scope.
    root_scoped: bool,
    value: Option<In>,
    wipe: fn(In),
    /// The scopes given, one for each record that lists one, outermost
    /// first.
    scopes: Vec<DeclaredContext>,
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
            .field("within", &labels(&self.holders))
            .finish_non_exhaustive()
    }
}

impl<T, Op, In, C> MarkedQuery<T, Op, In, Needs<C>>
where
    C: GivenScopes,
{
    /// Give the scopes the query takes: the tenant a record was encrypted
    /// with `Scope::new(tenant)`, of the type the record lists. A field of
    /// a record that lists a scope of its own takes one scope for each
    /// record, as a tuple, outermost first. An empty scope is refused when
    /// the query runs. The query is then [`Ready`]; there is no second
    /// `scope`.
    pub fn scope(mut self, scope: C) -> MarkedQuery<T, Op, In, Ready> {
        let mut scopes = Vec::new();
        scope.push_scopes(&mut scopes);
        MarkedQuery {
            label: self.label.clone(),
            holders: std::mem::take(&mut self.holders),
            root_scoped: self.root_scoped,
            value: self.value.take(),
            wipe: self.wipe,
            scopes,
            marker: PhantomData,
        }
    }
}

impl<T, Op, In, S> MarkedQuery<T, Op, In, S> {
    /// The parts the field's own label is extended by, as the derive seals
    /// a nested record's fields. The build starts with the outermost
    /// record's scope. For each record field that holds the field,
    /// outermost first, the parts so far extend that field's label. The
    /// record that field holds then puts its own scope, if it lists one,
    /// before the result. So a field of a field is
    /// `(addresses/street) / ((accounts/address) / tenant)`, and where the
    /// inner record lists a scope, that scope extends the field's label
    /// first.
    fn extension(&mut self) -> DeclaredContext {
        // The types give one scope for each record that lists one. A
        // wrong count would derive a term no row stores, with no error.
        debug_assert_eq!(
            self.scopes.len(),
            usize::from(self.root_scoped)
                + self.holders.iter().filter(|holder| holder.scoped).count(),
            "a query has one scope for each record that lists one",
        );
        let mut given = std::mem::take(&mut self.scopes).into_iter();
        let mut next = |scoped: bool| match scoped {
            true => given.next().unwrap_or_default(),
            false => DeclaredContext::default(),
        };
        let root = next(self.root_scoped);
        self.holders.drain(..).fold(root, |outer, holder| {
            let mut context = next(holder.scoped);
            context.append(DeclaredContext::from(
                outer.under(NonEmpty::from(holder.label)),
            ));
            context
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
    /// by the outer fields' contexts and the scopes. The query is prepared
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
            holders: Vec::new(),
            root_scoped: false,
            value: Some(value),
            wipe,
            scopes: Vec::new(),
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
