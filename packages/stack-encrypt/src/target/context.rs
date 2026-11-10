//! The contexts a target declares, and the parts a caller supplies.
//!
//! Every part of a context is a **scope** or a **binding**. The declaration
//! supplies the first scopes: the record's name, then the field's name. The
//! caller supplies the rest.
//!
//! - The **query context** is all the scopes: the declared ones, then the
//!   caller's. Search terms derive under it. A query supplies the same
//!   scopes, and matches every row stored under the same query context.
//! - The **stored context** is the query context followed by the bindings.
//!   The data key and the AAD derive under it. A binding ties a ciphertext
//!   to one row, such as a row ID. A query does not know it, so a binding
//!   does not narrow a query.
//!
//! The kind of a part is not in any derivation. Only the values and their
//! order are. So a record with no binding stores exactly the bytes it
//! stored before bindings existed.
//!
//! A caller passes its parts as [`Scope::new(..)`](Scope::new),
//! [`Bind::new(..)`](Bind::new), or [`Scope::new(..).bind(..)`](Scope::bind).
//! A declaration lists the parts the caller must supply, with kind and
//! type, as its context input: `RequiredContext<Parts<Scope<u64>, Bind<u128>>>`
//! for a tenant scope and a row binding. A part the declaration does not
//! list does not compile.
//!
//! The types here are the core-owned ones: each holds the parts view of a
//! context, the one tree both the AEAD and the PRF encode from, so the
//! structured identity of its descriptor survives the trip into a boxed
//! operation description. A record that stores its own identifier declares
//! `NonEmpty<T>` instead.
use crate::{ContextPiece, Descriptor, Error, IntoContext, MaybeEmpty, NonEmpty};

/// Prove a context nonempty at the point it is used. The core-owned types
/// are nonempty by construction, so for them this cannot fail; the one
/// helper keeps the error mapping in one place.
pub(super) fn nonempty<T: MaybeEmpty>(value: T) -> Result<NonEmpty<T>, Error> {
    NonEmpty::new(value).map_err(|e| Error::Other(Box::new(e)))
}

/// A part the caller passed that is empty: an empty text or byte string.
/// Refused before any key is requested, as an empty context is, with an
/// error a caller can match on.
fn refuse_empty_part() -> Error {
    crate::plan::PlanError::EmptyPart.into()
}

/// Nest `tail` under `head`, as [`NonEmpty::with`] nests: `(head, tail)`.
fn nest(head: ContextPiece<'static>, tail: ContextPiece<'static>) -> ContextPiece<'static> {
    ContextPiece::List(vec![head, tail])
}

/// An owned, validated context for a target that accepts any Vitamin C
/// context and derives both ciphertext and terms from it.
///
/// A caller context holds the caller's scopes and bindings apart, so the
/// terms can derive under the [query context](Self::query) and the key and
/// the AAD under the [stored context](Self::stored). Built from a
/// `NonEmpty<T>`, a bare integer, or the caller's [`Scope`], [`Bind`] and
/// [`Parts`]. Concrete records declare their own context type instead.
#[derive(Clone, Debug)]
pub struct CallerContext {
    /// The scopes, as one tree, or none for a caller who passed only
    /// bindings.
    scopes: Option<ContextPiece<'static>>,
    /// The bindings, in order.
    bindings: Vec<ContextPiece<'static>>,
    /// Whether a part the caller passed through [`Scope`] or [`Bind`] is
    /// empty. The leaf that runs under this context refuses it. A part a
    /// binding spelled as data ([`from_piece`](Self::from_piece)) is not
    /// checked here: the dynamic grammar allows an empty extension part.
    empty_part: bool,
}
impl<'c, T> From<NonEmpty<T>> for CallerContext
where
    T: IntoContext<'c>,
{
    fn from(context: NonEmpty<T>) -> Self {
        Self::scopes(context.into_context().into_owned())
    }
}
/// A borrowed context: a write and a query can share one `NonEmpty`
/// without the caller moving it. The parts are cloned into the call, so
/// `T` is `Clone`.
impl<'c, T> From<&NonEmpty<T>> for CallerContext
where
    T: Clone + IntoContext<'c>,
{
    fn from(context: &NonEmpty<T>) -> Self {
        Self::from(context.clone())
    }
}
impl<S: ScopePart, B: BindPart> From<Parts<S, B>> for CallerContext {
    fn from(parts: Parts<S, B>) -> Self {
        let (scopes, empty_scope) = parts.scope.into_piece();
        let (binding, empty_bind) = parts.bind.into_piece();
        Self {
            scopes,
            bindings: binding.into_iter().collect(),
            empty_part: empty_scope || empty_bind,
        }
    }
}
impl<'c, T: IntoContext<'c> + MaybeEmpty> From<Scope<T>> for CallerContext {
    fn from(scope: Scope<T>) -> Self {
        Self::from(Parts {
            scope,
            bind: NoBind,
        })
    }
}
impl<'c, T: IntoContext<'c> + MaybeEmpty> From<Bind<T>> for CallerContext {
    fn from(bind: Bind<T>) -> Self {
        Self::from(Parts {
            scope: NoScope,
            bind,
        })
    }
}
/// Empty when the query context is: a context with no scope derives no
/// term.
impl MaybeEmpty for CallerContext {
    fn is_empty(&self) -> bool {
        self.scopes.as_ref().is_none_or(MaybeEmpty::is_empty)
    }
}
// `CallerContext` is deliberately not an `IntoContext`: a context with a
// binding is two contexts, and a PRF or AEAD API handed one whole would
// have to pick. A leaf takes `query()` or `stored()` by name.
impl CallerContext {
    fn scopes(piece: ContextPiece<'static>) -> Self {
        Self {
            scopes: Some(piece),
            bindings: Vec::new(),
            empty_part: false,
        }
    }
    /// Refuse an empty part. A context with no scope passes: a record
    /// whose fields have contexts of their own takes a binding alone.
    pub(crate) fn checked(self) -> Result<Self, Error> {
        if self.empty_part {
            return Err(refuse_empty_part());
        }
        Ok(self)
    }
    /// Prove the query context nonempty, and refuse an empty part, before
    /// a term is derived.
    pub(crate) fn validated(self) -> Result<NonEmpty<Self>, Error> {
        let this = self.checked()?;
        nonempty(this)
    }
    /// The query context: the scopes, as one tree. The unit context when
    /// the caller passed no scope.
    pub fn query(&self) -> ContextPiece<'static> {
        self.scopes.clone().unwrap_or(ContextPiece::Unit)
    }
    /// The stored context: the scopes, then each binding in order, nesting
    /// to the left: `((scopes, b1), b2)`.
    pub fn stored(&self) -> ContextPiece<'static> {
        let mut stored = self.scopes.clone();
        for binding in &self.bindings {
            stored = Some(match stored {
                Some(head) => nest(head, binding.clone()),
                None => binding.clone(),
            });
        }
        stored.unwrap_or(ContextPiece::Unit)
    }
    /// Whether the caller passed a binding.
    pub fn has_bindings(&self) -> bool {
        !self.bindings.is_empty()
    }
    /// The query context, proven nonempty, for a term. Called on a
    /// validated context, whose query context is nonempty.
    pub(crate) fn query_nonempty(validated: NonEmpty<Self>) -> NonEmpty<ContextPiece<'static>> {
        let query = validated.into_inner().query();
        // `validated` proved the scopes nonempty, which is what `query` is.
        NonEmpty::new(query).unwrap_or_else(|_| unreachable!("a validated context has a scope"))
    }
    /// Both contexts, proven nonempty, for a leaf that derives terms and
    /// seals: the query context first, the stored context second. Called
    /// on a validated context, whose scopes are nonempty, so the stored
    /// context, which starts with them, is nonempty too.
    pub(crate) fn both_nonempty(
        validated: NonEmpty<Self>,
    ) -> (
        NonEmpty<ContextPiece<'static>>,
        NonEmpty<ContextPiece<'static>>,
    ) {
        let context = validated.into_inner();
        let (query, stored) = (context.query(), context.stored());
        (
            NonEmpty::new(query)
                .unwrap_or_else(|_| unreachable!("a validated context has a scope")),
            NonEmpty::new(stored)
                .unwrap_or_else(|_| unreachable!("a validated context has a scope")),
        )
    }
    /// A caller context from a context part as a binding spelled it, with
    /// no emptiness proof: what a plan lowered from data extends a field's
    /// context by. An empty part extends a nonempty context to a nonempty
    /// one, so the proof it skips is the whole tree's, which
    /// [`DeclaredContext::under`] re-establishes when it runs.
    #[cfg(feature = "dynamic")]
    pub(crate) fn from_piece(piece: ContextPiece<'static>) -> Self {
        Self::scopes(piece)
    }
    /// A caller context of one binding, as a binding spelled it, with no
    /// emptiness proof, as [`from_piece`](Self::from_piece).
    #[cfg(feature = "dynamic")]
    pub(crate) fn bind_piece(piece: ContextPiece<'static>) -> Self {
        Self {
            scopes: None,
            bindings: vec![piece],
            empty_part: false,
        }
    }
    /// The parts a record stores in its row, as the caller context the
    /// record runs its fields under: the stored scope, then the stored
    /// binding. For generated code.
    #[doc(hidden)]
    pub fn from_stored(stored: StoredParts) -> Self {
        Self {
            scopes: stored.scope,
            bindings: stored.bind.into_iter().collect(),
            empty_part: stored.empty_part,
        }
    }
    /// The own context `own`, extended by this caller context: the field's
    /// own context is the prefix, the caller's scopes extend it, and the
    /// bindings follow, exactly as a `struct = T` derive composes them.
    /// `(("users", "age"), tenant)` is the query context under a tenant
    /// scope, and `((("users", "age"), tenant), row)` the stored context
    /// under a row binding too. The own context is never discarded.
    pub fn extend<'c, O: IntoContext<'c>>(self, own: NonEmpty<O>) -> Self {
        let own = own.into_context().into_owned();
        Self {
            scopes: Some(match self.scopes {
                Some(scopes) => nest(own, scopes),
                None => own,
            }),
            bindings: self.bindings,
            empty_part: self.empty_part,
        }
    }
    /// This context, extended by the scopes and bindings of `part`: the
    /// scopes nest to the left, and the bindings follow those already
    /// given.
    fn then(mut self, part: CallerContext) -> Self {
        if let Some(scopes) = part.scopes {
            self.scopes = Some(match self.scopes.take() {
                Some(head) => nest(head, scopes),
                None => scopes,
            });
        }
        self.bindings.extend(part.bindings);
        self.empty_part |= part.empty_part;
        self
    }
    /// The scopes and the bindings, for [`Contexts`](crate::Contexts).
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    pub(crate) fn pieces(&self) -> (Option<ContextPiece<'static>>, Vec<ContextPiece<'static>>) {
        (self.scopes.clone(), self.bindings.clone())
    }
}

/// An owned nonempty context for ciphertext-only operations.
///
/// Since vitaminc 0.5 every context type implements one trait,
/// [`IntoContext`], and the AEAD and PRF derivations are both blankets over
/// it, so this type accepts exactly the contexts a [`CallerContext`] does.
/// It is kept as a distinct declaration because it says something a
/// `CallerContext` does not: the record it is declared on derives no terms.
/// A derived record whose fields are all ciphertexts declares it with
/// `#[stash(context_type = AeadContext)]`, and then accepts the same
/// contexts the canonical [`StackCipherText`](crate::StackCipherText) path
/// does. Built from a caller context, it is the stored context: the scopes,
/// then the bindings. It keeps the two apart until it is used, so
/// [`extend`](Self::extend) nests them as [`CallerContext::extend`] does.
#[derive(Clone, Debug)]
pub struct AeadContext {
    inner: CallerContext,
}
impl<'a, T: IntoContext<'a>> From<NonEmpty<T>> for AeadContext {
    fn from(value: NonEmpty<T>) -> Self {
        Self {
            inner: CallerContext::from(value),
        }
    }
}
/// A borrowed context, as for [`CallerContext`].
impl<'a, T: Clone + IntoContext<'a>> From<&NonEmpty<T>> for AeadContext {
    fn from(value: &NonEmpty<T>) -> Self {
        Self::from(value.clone())
    }
}
impl From<CallerContext> for AeadContext {
    fn from(value: CallerContext) -> Self {
        Self { inner: value }
    }
}
impl<S: ScopePart, B: BindPart> From<Parts<S, B>> for AeadContext {
    fn from(parts: Parts<S, B>) -> Self {
        CallerContext::from(parts).into()
    }
}
impl<'c, T: IntoContext<'c> + MaybeEmpty> From<Scope<T>> for AeadContext {
    fn from(scope: Scope<T>) -> Self {
        CallerContext::from(scope).into()
    }
}
impl<'c, T: IntoContext<'c> + MaybeEmpty> From<Bind<T>> for AeadContext {
    fn from(bind: Bind<T>) -> Self {
        CallerContext::from(bind).into()
    }
}
impl MaybeEmpty for AeadContext {
    fn is_empty(&self) -> bool {
        self.inner.stored().is_empty()
    }
}
/// The stored context: the scopes, then the bindings.
impl<'a> IntoContext<'a> for AeadContext {
    fn into_context(self) -> ContextPiece<'a> {
        self.inner.stored()
    }
}
impl AeadContext {
    /// The query context: the scopes alone. What a JSON document's
    /// selectors and token chain derive under, so a query under the scopes
    /// finds a document bound to its row.
    pub(crate) fn query(&self) -> ContextPiece<'static> {
        self.inner.query()
    }
    pub(super) fn validated(self) -> Result<NonEmpty<Self>, Error> {
        if self.inner.empty_part {
            return Err(refuse_empty_part());
        }
        nonempty(self)
    }
    /// [`validated`](Self::validated), and also check that the descriptor
    /// of this context fits in a ZeroKMS request.
    ///
    /// [`ciphertext`](super::ciphertext) runs this check before it takes the
    /// plaintext. So when the context is refused, no copy of the plaintext
    /// has been made.
    pub(super) fn sealable(self) -> Result<NonEmpty<Self>, Error> {
        Descriptor::from_piece(&self.piece()).check()?;
        self.validated()
    }
    /// The parts of this context: the stored context.
    pub(crate) fn piece(&self) -> ContextPiece<'static> {
        self.inner.stored()
    }
    /// The own context `own`, extended by this caller context, exactly as
    /// [`CallerContext::extend`] does for a record that derives terms: the
    /// field's own context is the prefix, the scopes extend it, and the
    /// bindings follow. The same input seals under the same context
    /// through either type.
    pub fn extend<'c, O: IntoContext<'c>>(self, own: NonEmpty<O>) -> Self {
        Self {
            inner: self.inner.extend(own),
        }
    }
}

/// A caller's context of either kind, extending a field's own context: what
/// [`Encryption::extend`](super::Encryption::extend) asks of the context a
/// subtree is run under. An own context is a `NonEmpty<_>` — the derive emits
/// `nonempty!(..)` for a literal and `nonempty!(prefix).with(column)` for the
/// pair it infers — so an empty one is refused at compile time, and extending
/// cannot fail.
///
/// Sealed: the two core-owned types are the two kinds, and a context that
/// extends is one whose encodings the core built.
pub trait Extends: sealed::Sealed + Sized {
    /// The own context `own`, extended by this one.
    fn extend<'c, O: IntoContext<'c>>(self, own: NonEmpty<O>) -> Self;
}
mod sealed {
    pub trait Sealed {}
    impl Sealed for super::CallerContext {}
    impl Sealed for super::AeadContext {}
    impl Sealed for super::NoScope {}
    impl Sealed for super::NoBind {}
    impl<T> Sealed for super::Scope<T> {}
    impl<T> Sealed for super::Bind<T> {}
    impl<T> Sealed for Option<super::Scope<T>> {}
    impl<T> Sealed for Option<super::Bind<T>> {}
}
impl Extends for CallerContext {
    fn extend<'c, O: IntoContext<'c>>(self, own: NonEmpty<O>) -> Self {
        CallerContext::extend(self, own)
    }
}
impl Extends for AeadContext {
    fn extend<'c, O: IntoContext<'c>>(self, own: NonEmpty<O>) -> Self {
        AeadContext::extend(self, own)
    }
}

/// A scope the caller supplies: a part a query can supply too, such as a
/// tenant. A scope narrows the data, and the queries over it.
///
/// `Scope::new(tenant)` is the caller's input where a declaration lists
/// `scope(tenant: u64)`. [`bind`](Self::bind) adds a binding after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope<T>(T);
impl<T> Scope<T> {
    /// A scope of `value`.
    pub fn new(value: T) -> Self {
        Self(value)
    }
    /// This scope, then the binding `value`: the input where a declaration
    /// lists a scope and a binding. A binding comes after every scope, so
    /// there is no method that adds a scope after a binding.
    pub fn bind<U>(self, value: U) -> Parts<Scope<T>, Bind<U>> {
        Parts {
            scope: self,
            bind: Bind(value),
        }
    }
    /// This scope, then the scope `value` of a record nested inside: the
    /// input for a query on a field of a nested record, where both
    /// records list a scope. See [`Scopes`].
    pub fn scope<U>(self, value: U) -> Scopes<Scope<T>, Scope<U>> {
        Scopes {
            outer: self,
            inner: Scope(value),
        }
    }
    /// The value.
    pub fn get(&self) -> &T {
        &self.0
    }
    /// The value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// The scopes of nested records, outermost record first.
///
/// A query on a field of a nested record needs one scope for each record
/// that lists a scope. Build the value by chaining
/// [`Scope::scope`], starting with the outermost record's scope:
///
/// ```
/// use stack_encrypt::target::Scope;
///
/// let company_tenant = 7u64;
/// let office_tenant = 42u64;
/// let scopes = Scope::new(company_tenant).scope(office_tenant);
/// // A third record's scope follows in the same way.
/// let scopes = scopes.scope("floor-3");
/// # let _ = scopes;
/// ```
///
/// Pass the result to
/// [`MarkedQuery::scope`](crate::marker::MarkedQuery::scope). You do not
/// need to write this type's name: `Outer` is a [`Scope`] or another
/// `Scopes`, and `Inner` is the [`Scope`] of the innermost record.
///
/// `Scopes` is different from a scope with several parts, such as
/// `Scope::new(("eu", 42u64))`. That value is the scope of one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scopes<Outer, Inner> {
    outer: Outer,
    inner: Inner,
}
impl<Outer, Inner> Scopes<Outer, Inner> {
    /// These scopes, then the scope `value` of a record nested one level
    /// further in.
    pub fn scope<U>(self, value: U) -> Scopes<Self, Scope<U>> {
        Scopes {
            outer: self,
            inner: Scope(value),
        }
    }
    /// The outer scopes and the innermost scope.
    pub(crate) fn into_parts(self) -> (Outer, Inner) {
        (self.outer, self.inner)
    }
}

/// A binding the caller supplies: a part that ties a ciphertext to one row,
/// such as a row ID. A query does not know it, so a binding does not narrow
/// a query.
///
/// `Bind::new(row)` is the caller's input where a declaration lists
/// `bind(row: u128)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bind<T>(T);
impl<T> Bind<T> {
    /// A binding of `value`.
    pub fn new(value: T) -> Self {
        Self(value)
    }
    /// The value.
    pub fn get(&self) -> &T {
        &self.0
    }
    /// The value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// No caller scope: the scope slot of a declaration that lists none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoScope;
/// No caller binding: the binding slot of a declaration that lists none.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoBind;

/// The caller's scope and binding together, as a declaration lists them:
/// `Parts<Scope<u64>, Bind<u128>>` for a tenant scope and a row binding.
/// The scope slot `S` is [`NoScope`], a [`Scope`], or, on the decrypt side
/// of a record that stores its scope, an `Option<Scope<T>>` the caller may
/// pass to check the stored one. The binding slot `B` is the same with
/// [`NoBind`] and [`Bind`].
///
/// A caller rarely names this type: [`Scope::new`], [`Bind::new`] and
/// [`Scope::bind`] build the input, and it converts to the slots the
/// declaration lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Parts<S, B> {
    scope: S,
    bind: B,
}
impl<S, B> Parts<S, B> {
    /// The scope slot.
    pub fn scope(&self) -> &S {
        &self.scope
    }
    /// The binding slot.
    pub fn bind(&self) -> &B {
        &self.bind
    }
}

/// What a scope slot holds. Sealed: the slots are [`NoScope`], [`Scope`],
/// and `Option<Scope<T>>`.
pub trait ScopePart: sealed::Sealed {
    /// The scope as a context part, and whether it is empty.
    fn into_piece(self) -> (Option<ContextPiece<'static>>, bool);
    /// The placeholder's type name, for [`Contexts`](crate::Contexts):
    /// `None` for no scope.
    fn type_name() -> Option<String>;
}
/// What a binding slot holds. Sealed: the slots are [`NoBind`], [`Bind`],
/// and `Option<Bind<T>>`.
pub trait BindPart: sealed::Sealed {
    /// The binding as a context part, and whether it is empty.
    fn into_piece(self) -> (Option<ContextPiece<'static>>, bool);
    /// The placeholder's type name, for [`Contexts`](crate::Contexts):
    /// `None` for no binding.
    fn type_name() -> Option<String>;
}
fn part_of<'c, T: IntoContext<'c> + MaybeEmpty>(value: T) -> (Option<ContextPiece<'static>>, bool) {
    let empty = value.is_empty();
    (Some(value.into_context().into_owned()), empty)
}
impl ScopePart for NoScope {
    fn into_piece(self) -> (Option<ContextPiece<'static>>, bool) {
        (None, false)
    }
    fn type_name() -> Option<String> {
        None
    }
}
impl<'c, T: IntoContext<'c> + MaybeEmpty> ScopePart for Scope<T> {
    fn into_piece(self) -> (Option<ContextPiece<'static>>, bool) {
        part_of(self.0)
    }
    fn type_name() -> Option<String> {
        Some(crate::contexts::short_type_name::<T>())
    }
}
impl<'c, T: IntoContext<'c> + MaybeEmpty> ScopePart for Option<Scope<T>> {
    fn into_piece(self) -> (Option<ContextPiece<'static>>, bool) {
        self.map_or((None, false), ScopePart::into_piece)
    }
    fn type_name() -> Option<String> {
        Some(crate::contexts::short_type_name::<T>())
    }
}
impl BindPart for NoBind {
    fn into_piece(self) -> (Option<ContextPiece<'static>>, bool) {
        (None, false)
    }
    fn type_name() -> Option<String> {
        None
    }
}
impl<'c, T: IntoContext<'c> + MaybeEmpty> BindPart for Bind<T> {
    fn into_piece(self) -> (Option<ContextPiece<'static>>, bool) {
        part_of(self.0)
    }
    fn type_name() -> Option<String> {
        Some(crate::contexts::short_type_name::<T>())
    }
}
impl<'c, T: IntoContext<'c> + MaybeEmpty> BindPart for Option<Bind<T>> {
    fn into_piece(self) -> (Option<ContextPiece<'static>>, bool) {
        self.map_or((None, false), BindPart::into_piece)
    }
    fn type_name() -> Option<String> {
        Some(crate::contexts::short_type_name::<T>())
    }
}

// The caller's input converts to the slots the declaration lists. A scope
// alone fills a `NoBind` or an `Option<Bind<_>>` slot; a binding alone fills
// a `NoScope` or an `Option<Scope<_>>` slot; both fill the optional slots of
// a record that stores one of them.
macro_rules! parts_conversions {
    ($([$($generics:ident),*] $from:ty => $scope:ty, $bind:ty, |$v:ident| $body:expr;)*) => {$(
        impl<$($generics),*> From<$from> for Parts<$scope, $bind> {
            fn from($v: $from) -> Self {
                $body
            }
        }
    )*};
}
parts_conversions! {
    [T] Scope<T> => Scope<T>, NoBind, |scope| Parts { scope, bind: NoBind };
    [T] Scope<T> => Option<Scope<T>>, NoBind, |scope| Parts { scope: Some(scope), bind: NoBind };
    [T, U] Scope<T> => Scope<T>, Option<Bind<U>>, |scope| Parts { scope, bind: None };
    [T, U] Scope<T> => Option<Scope<T>>, Option<Bind<U>>, |scope| Parts { scope: Some(scope), bind: None };
    [U] Bind<U> => NoScope, Bind<U>, |bind| Parts { scope: NoScope, bind };
    [U] Bind<U> => NoScope, Option<Bind<U>>, |bind| Parts { scope: NoScope, bind: Some(bind) };
    [T, U] Bind<U> => Option<Scope<T>>, Bind<U>, |bind| Parts { scope: None, bind };
    [T, U] Bind<U> => Option<Scope<T>>, Option<Bind<U>>, |bind| Parts { scope: None, bind: Some(bind) };
    [T, U] Parts<Scope<T>, Bind<U>> => Option<Scope<T>>, Bind<U>, |parts| Parts { scope: Some(parts.scope), bind: parts.bind };
    [T, U] Parts<Scope<T>, Bind<U>> => Scope<T>, Option<Bind<U>>, |parts| Parts { scope: parts.scope, bind: Some(parts.bind) };
    [T, U] Parts<Scope<T>, Bind<U>> => Option<Scope<T>>, Option<Bind<U>>, |parts| Parts { scope: Some(parts.scope), bind: Some(parts.bind) };
}

/// The caller's parts, as the required input of a record that lists them.
impl<S: ScopePart, B: BindPart> From<Parts<S, B>> for super::input::RequiredContext<Parts<S, B>> {
    fn from(parts: Parts<S, B>) -> Self {
        use super::input::AcceptsContext as _;
        Self::supplied(parts)
    }
}
/// The caller's parts, as the optional input of a record that stores them.
impl<S: ScopePart, B: BindPart> From<Parts<S, B>> for super::input::OptionalContext<Parts<S, B>> {
    fn from(parts: Parts<S, B>) -> Self {
        use super::input::AcceptsContext as _;
        Self::supplied(parts)
    }
}
/// A record's fields run under the declared context the caller's parts
/// extend: what `accepting` converts the record's input into.
impl<S: ScopePart, B: BindPart> From<super::input::RequiredContext<Parts<S, B>>>
    for DeclaredContext
{
    fn from(input: super::input::RequiredContext<Parts<S, B>>) -> Self {
        Self(vec![input.into_inner().into()])
    }
}

/// The parts a record stores in its row: a stored scope, a stored binding,
/// or both. Read from the plaintext on encrypt, and from the row on
/// decrypt. For generated code.
#[doc(hidden)]
#[derive(Clone, Debug, Default)]
pub struct StoredParts {
    scope: Option<ContextPiece<'static>>,
    bind: Option<ContextPiece<'static>>,
    empty_part: bool,
}
impl StoredParts {
    /// No stored part.
    pub fn none() -> Self {
        Self::default()
    }
    /// The stored scope.
    pub fn scope<'c>(mut self, value: impl IntoContext<'c> + MaybeEmpty) -> Self {
        let (piece, empty) = part_of(value);
        self.scope = piece;
        self.empty_part |= empty;
        self
    }
    /// The stored binding.
    pub fn bind<'c>(mut self, value: impl IntoContext<'c> + MaybeEmpty) -> Self {
        let (piece, empty) = part_of(value);
        self.bind = piece;
        self.empty_part |= empty;
        self
    }
    fn mismatch(stored: &ContextPiece<'static>) -> Error {
        Error::ContextMismatch {
            stored: Descriptor::from_piece(stored),
        }
    }
    /// Check the caller's `parts` against the stored ones, and build the
    /// context the record opens under: the stored parts, then the caller's
    /// parts that are not stored.
    ///
    /// A caller's part that a slot stores is a check: it must equal the
    /// stored one. A caller's part that no slot stores is the caller's own,
    /// and is added after the stored ones, as on encrypt.
    ///
    /// # Errors
    ///
    /// [`Error::ContextMismatch`] when a passed part differs from the stored
    /// one. The error carries the stored part's descriptor. The check runs
    /// before any key is requested.
    pub fn checked<S: ScopePart, B: BindPart>(
        self,
        parts: Option<Parts<S, B>>,
    ) -> Result<DeclaredContext, Error> {
        let mut context = DeclaredContext::default();
        let stored = CallerContext::from_stored(self.clone());
        if stored.scopes.is_some() || !stored.bindings.is_empty() {
            context = context.with(stored);
        }
        let Some(parts) = parts else {
            return Ok(context);
        };
        let (scope, empty_scope) = parts.scope.into_piece();
        let (bind, empty_bind) = parts.bind.into_piece();
        let mut caller = CallerContext {
            scopes: None,
            bindings: Vec::new(),
            empty_part: empty_scope || empty_bind,
        };
        match (&self.scope, scope) {
            (Some(stored), Some(passed)) if *stored != passed => {
                return Err(Self::mismatch(stored))
            }
            (Some(_), _) => {}
            (None, passed) => caller.scopes = passed,
        }
        match (&self.bind, bind) {
            (Some(stored), Some(passed)) if *stored != passed => {
                return Err(Self::mismatch(stored))
            }
            (Some(_), _) => {}
            (None, Some(passed)) => caller.bindings.push(passed),
            (None, None) => {}
        }
        if caller.scopes.is_some() || !caller.bindings.is_empty() || caller.empty_part {
            context = context.with(caller);
        }
        Ok(context)
    }
}

/// The decrypt-side inputs a record with stored parts takes, checked
/// against the parts it stores. For generated code. Sealed: the three
/// inputs below implement it.
#[doc(hidden)]
pub trait CheckedInput: super::input::ContextInput + checked_sealed::Sealed {
    /// The context the record opens under: [`StoredParts::checked`].
    ///
    /// # Errors
    ///
    /// As [`StoredParts::checked`].
    fn checked(self, stored: StoredParts) -> Result<DeclaredContext, Error>;
}
impl<S: ScopePart, B: BindPart> CheckedInput for super::input::RequiredContext<Parts<S, B>> {
    fn checked(self, stored: StoredParts) -> Result<DeclaredContext, Error> {
        stored.checked(Some(self.into_inner()))
    }
}
impl<S: ScopePart, B: BindPart> CheckedInput for super::input::OptionalContext<Parts<S, B>> {
    fn checked(self, stored: StoredParts) -> Result<DeclaredContext, Error> {
        stored.checked(self.into_inner())
    }
}
mod checked_sealed {
    pub trait Sealed {}
    impl<S, B> Sealed for crate::target::RequiredContext<super::Parts<S, B>> {}
    impl<S, B> Sealed for crate::target::OptionalContext<super::Parts<S, B>> {}
    impl Sealed for crate::target::DeclaredScopes {}
}
impl CheckedInput for super::input::DeclaredScopes {
    fn checked(self, stored: StoredParts) -> Result<DeclaredContext, Error> {
        let mut context = stored.checked(None::<Parts<NoScope, NoBind>>)?;
        context.append(self.into());
        Ok(context)
    }
}

/// The optional extension a record whose fields already declare their own
/// contexts accepts from its caller.
///
/// `()` (the default) leaves the declared contexts as they are; a nonempty
/// value extends each of them, the way a caller's context extends a field's
/// own. This is what a `struct = T` derive without a `context_field`
/// declares.
///
/// An extension is one part or several, applied in order and nesting to the
/// left, as [`NonEmpty::with`] nests: a field's `users/age` extended by `7`
/// and then `"eu"` ([`with`](Self::with) twice) is `((users/age)/7u64)/eu`,
/// the context a binding whose caller extends part by part spells. One
/// `NonEmpty` holding both parts is a different context, `(users/age)/(7u64/eu)`.
///
/// A part's bindings follow every part's scopes: the field's own context,
/// extended by the scopes in order, is the query context; the bindings in
/// order follow it in the stored context.
#[derive(Clone, Debug, Default)]
pub struct DeclaredContext(Vec<CallerContext>);
impl From<()> for DeclaredContext {
    fn from(_: ()) -> Self {
        Self::default()
    }
}
impl From<CallerContext> for DeclaredContext {
    fn from(value: CallerContext) -> Self {
        Self(vec![value])
    }
}
impl<'a, T: IntoContext<'a>> From<NonEmpty<T>> for DeclaredContext {
    fn from(value: NonEmpty<T>) -> Self {
        Self(vec![value.into()])
    }
}
/// A borrowed context, as for [`CallerContext`].
impl<'a, T: Clone + IntoContext<'a>> From<&NonEmpty<T>> for DeclaredContext {
    fn from(value: &NonEmpty<T>) -> Self {
        Self(vec![value.into()])
    }
}
/// A scope the call adds. A query takes a scope and no binding, so this is
/// the one conversion from a caller's part: a `Bind` does not convert, and
/// a query chain's `.extend(Bind::new(..))` does not compile.
impl<'c, T: IntoContext<'c> + MaybeEmpty> From<Scope<T>> for DeclaredContext {
    fn from(scope: Scope<T>) -> Self {
        Self(vec![scope.into()])
    }
}
impl DeclaredContext {
    /// Whether any part extends the field's own context.
    pub(crate) fn is_extended(&self) -> bool {
        !self.0.is_empty()
    }

    /// The parts, in order, for [`Contexts`](crate::Contexts).
    #[cfg_attr(not(feature = "dynamic"), allow(dead_code))]
    pub(crate) fn parts(&self) -> &[CallerContext] {
        &self.0
    }

    /// Whether any part carries a binding. A query refuses such a context
    /// before any key is requested: a binding is in no query context.
    pub(crate) fn has_bindings(&self) -> bool {
        self.0.iter().any(CallerContext::has_bindings)
    }

    /// Extend by one more part, after any already given: the field's own
    /// context, extended by every part so far, is extended by `part`.
    pub fn with(mut self, part: impl Into<CallerContext>) -> Self {
        self.0.push(part.into());
        self
    }

    /// Append the caller's parts, preserving each part's grouping.
    pub(crate) fn append(&mut self, other: Self) {
        self.0.extend(other.0);
    }

    /// The context one field is derived under: its own `own`, extended by
    /// the caller's context if one was given — `("users", "age")` as it is
    /// under `()`, `(("users", "age"), id)` under a caller's `id`, and
    /// `((("users", "age"), id), region)` under `id` then `region`. The
    /// bindings of every part follow the scopes, in order.
    pub fn under<'c, O: IntoContext<'c>>(self, own: NonEmpty<O>) -> CallerContext {
        self.0
            .into_iter()
            .fold(CallerContext::from(own), CallerContext::then)
    }

    /// [`under`](Self::under), refusing a part the caller passed empty.
    ///
    /// # Errors
    ///
    /// An empty scope or binding, before any key is requested.
    pub(crate) fn checked_under<'c, O: IntoContext<'c>>(
        self,
        own: NonEmpty<O>,
    ) -> Result<CallerContext, Error> {
        let context = self.under(own);
        if context.empty_part {
            return Err(refuse_empty_part());
        }
        Ok(context)
    }
}

/// What a caller may assert about a record that stores its context.
///
/// A `#[stash(context_field)]` record carries its identifier in storage, and
/// decryption reads the context from there. The default asks only that the
/// stored value be nonempty; a `NonEmpty<T>` asks that it also equal the
/// destination the caller believes it is opening. Either way the check runs
/// before any key is retrieved.
///
/// # The default accepts whatever the record stores
///
/// That is deliberate, and the reason is the column migration flow — add
/// `email_encrypted`, migrate, drop `email`, rename `email_encrypted` to
/// `email`. Every row written before the rename still stores the old
/// identifier, so a strict check would reject all of them at the first read
/// afterwards.
///
/// The consequence is worth stating rather than discovering: an identifier
/// that must survive renames cannot also enforce placement. A whole,
/// self-consistent record moved from one column to another opens cleanly — a
/// confused deputy, to be caught by the caller passing the identifier it
/// expects, not by this type's default. What is *not* at risk is the key: the
/// descriptor is HMAC'd into the tag, so altering a stored identifier makes
/// the retrieve fail rather than succeed, and nobody reaches a key they are
/// not entitled to.
// Hidden here, on the definition, and not only on the re-export. rustc
// reads this attribute when it lists the types that implement a trait in a
// compile error, and rustdoc reads it when another crate's docs name the
// type. On the re-export alone, the type still showed in both.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct ExpectedContext<T>(Option<NonEmpty<T>>);
impl<T> Default for ExpectedContext<T> {
    fn default() -> Self {
        Self(None)
    }
}
impl<T> From<()> for ExpectedContext<T> {
    fn from(_: ()) -> Self {
        Self::default()
    }
}
impl<T> From<NonEmpty<T>> for ExpectedContext<T> {
    fn from(value: NonEmpty<T>) -> Self {
        Self(Some(value))
    }
}
impl<'c, T: MaybeEmpty + PartialEq + IntoContext<'c>> ExpectedContext<T> {
    /// Check the stored context against this expectation and prove it
    /// nonempty, yielding the context the record is opened under.
    ///
    /// # Errors
    ///
    /// [`Error::ContextMismatch`] if an expected context was given and the
    /// stored one differs from it; the error carries the stored context's
    /// descriptor. Otherwise fails if the stored context is empty. A stored
    /// context is data the record was handed, not something the cipher has
    /// authenticated yet: both checks happen before any key is requested.
    pub fn validate(self, stored: T) -> Result<NonEmpty<T>, Error> {
        if let Some(expected) = self.0 {
            if expected.into_inner() != stored {
                let stored = Descriptor::from_piece(&stored.into_context());
                return Err(Error::ContextMismatch { stored });
            }
        }
        nonempty(stored)
    }
}

macro_rules! integer_contexts {
    ($($ty:ty),*) => {$ (
        impl From<$ty> for CallerContext {
            fn from(value: $ty) -> Self { Self::from(NonEmpty::<$ty>::from(value)) }
        }
        impl From<$ty> for AeadContext {
            fn from(value: $ty) -> Self { Self::from(NonEmpty::<$ty>::from(value)) }
        }
        impl From<$ty> for DeclaredContext {
            fn from(value: $ty) -> Self { Self::from(NonEmpty::<$ty>::from(value)) }
        }
    )*};
}
// A bare integer is a context in its own right (see `CONTEXT.md`): it needs
// no `NonEmpty` proof, so it converts directly.
integer_contexts!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonempty;

    fn text(value: &str) -> ContextPiece<'static> {
        ContextPiece::Text(std::borrow::Cow::Owned(value.to_owned()))
    }

    /// The same parts seal under the same stored context through either
    /// type: `AeadContext` keeps the scopes and the bindings apart until
    /// it is used, so a binding follows the extended scopes rather than
    /// nesting beside them.
    #[test]
    fn an_aead_context_extends_as_a_caller_context_does() {
        let own = || nonempty!("users").with("email");
        let parts = || Scope::new(7u64).bind(9u128);
        let caller = CallerContext::from(parts()).extend(own());
        let aead = AeadContext::from(parts()).extend(own());
        assert_eq!(aead.piece(), caller.stored());
        assert_eq!(
            aead.into_context(),
            nest(
                nest(own().into_context().into_owned(), ContextPiece::U64(7)),
                ContextPiece::U128(9)
            )
        );
        // With no binding the two agreed before, and still do.
        let scope = CallerContext::from(Scope::new(7u64)).extend(own());
        assert_eq!(
            AeadContext::from(Scope::new(7u64)).extend(own()).piece(),
            scope.stored()
        );
    }

    #[test]
    fn a_declared_context_knows_whether_it_carries_a_binding() {
        assert!(!DeclaredContext::from(Scope::new(7u64)).has_bindings());
        assert!(DeclaredContext::default()
            .with(CallerContext::from(Scope::new(7u64).bind(9u128)))
            .has_bindings());
        assert!(DeclaredContext::default()
            .with(Bind::new(9u128))
            .has_bindings());
    }

    /// A borrowed `NonEmpty` converts to the same declared context as the
    /// owned one, and extends the field's own context by it: the
    /// conversion is not an empty declaration.
    #[test]
    fn a_borrowed_nonempty_is_the_same_declared_context_as_the_owned_one() {
        let parts = NonEmpty::from(7u64).with("eu");
        let own = || nonempty!("users").with("age");
        let borrowed = DeclaredContext::from(&parts);
        let owned = DeclaredContext::from(parts);
        assert!(borrowed.is_extended());
        assert_eq!(borrowed.under(own()).stored(), owned.under(own()).stored());
        assert_ne!(
            DeclaredContext::from(&parts).under(own()).stored(),
            DeclaredContext::default().under(own()).stored()
        );
        let caller = CallerContext::from(&parts);
        assert_eq!(caller.stored(), parts.into_context().into_owned());
        assert_eq!(caller.query(), caller.stored());
    }

    /// The refusal of an empty part names what it refuses.
    #[test]
    fn an_empty_part_is_refused_by_name() {
        assert_eq!(
            refuse_empty_part().to_string(),
            "a scope or binding is empty"
        );
        let refused = CallerContext::from(Scope::new(String::new()))
            .validated()
            .unwrap_err();
        assert_eq!(refused.to_string(), "a scope or binding is empty");
    }

    #[test]
    fn a_scope_alone_is_the_query_and_the_stored_context() {
        let context = CallerContext::from(Scope::new(7u64));
        assert_eq!(context.query(), ContextPiece::U64(7));
        assert_eq!(context.stored(), ContextPiece::U64(7));
        assert!(!context.has_bindings());
    }

    #[test]
    fn a_binding_is_in_the_stored_context_and_not_in_the_query_context() {
        let context = CallerContext::from(Scope::new(7u64).bind(9u128));
        assert_eq!(context.query(), ContextPiece::U64(7));
        assert_eq!(
            context.stored(),
            nest(ContextPiece::U64(7), ContextPiece::U128(9))
        );
        let bind_only = CallerContext::from(Bind::new(9u128));
        assert_eq!(bind_only.query(), ContextPiece::Unit);
        assert_eq!(bind_only.stored(), ContextPiece::U128(9));
        assert!(bind_only.is_empty(), "no scope: no term derives");
    }

    #[test]
    fn a_declared_context_nests_scopes_then_bindings() {
        let own = nonempty!("users").with("email");
        let context = DeclaredContext::default()
            .with(Scope::new(7u64).bind(9u128))
            .with(Scope::new("eu"))
            .under(own);
        let own_piece = nest(text("users"), text("email"));
        let query = nest(nest(own_piece.clone(), ContextPiece::U64(7)), text("eu"));
        assert_eq!(context.query(), query);
        assert_eq!(context.stored(), nest(query, ContextPiece::U128(9)));
    }

    #[test]
    fn a_record_with_no_binding_composes_as_it_always_did() {
        let own = nonempty!("users").with("age");
        let before = nest(
            nest(nest(text("users"), text("age")), ContextPiece::U64(7)),
            text("eu"),
        );
        let context = DeclaredContext::default()
            .with(7u64)
            .with(nonempty!("eu"))
            .under(own);
        assert_eq!(context.query(), before);
        assert_eq!(context.stored(), before);
    }

    #[test]
    fn an_empty_part_is_refused_before_a_term_derives() {
        let empty = CallerContext::from(Scope::new("").bind(1u64));
        assert!(empty.validated().is_err());
        let bound_empty = CallerContext::from(Scope::new("acme").bind(Vec::<u8>::new()));
        assert!(bound_empty.clone().validated().is_err());
        assert!(AeadContext::from(bound_empty).validated().is_err());
        let under = DeclaredContext::default()
            .with(Scope::new(""))
            .checked_under(nonempty!("users").with("age"));
        assert!(under.is_err());
        assert!(CallerContext::from(Scope::new("acme")).validated().is_ok());
    }

    #[test]
    fn stored_parts_are_checked_against_the_callers() {
        let stored = StoredParts::none().scope(7u64).bind(9u128);
        // Nothing passed: the stored parts alone.
        let context = stored
            .clone()
            .checked(None::<Parts<NoScope, NoBind>>)
            .unwrap();
        let under = context.under(nonempty!("users").with("email"));
        assert_eq!(
            under.query(),
            nest(nest(text("users"), text("email")), ContextPiece::U64(7))
        );
        assert!(under.has_bindings());
        // The same parts passed: accepted.
        let same: Parts<Option<Scope<u64>>, Option<Bind<u128>>> =
            Scope::new(7u64).bind(9u128).into();
        assert!(stored.clone().checked(Some(same)).is_ok());
        // A different scope: refused with the stored descriptor.
        let other: Parts<Option<Scope<u64>>, Option<Bind<u128>>> = Scope::new(8u64).into();
        match stored.clone().checked(Some(other)) {
            Err(Error::ContextMismatch { stored }) => assert_eq!(stored.as_str(), "7u64"),
            other => panic!("expected a mismatch, got {other:?}"),
        }
        // A caller binding that is not stored is added after the stored parts.
        let scope_only = StoredParts::none().scope(7u64);
        let parts: Parts<Option<Scope<u64>>, Bind<u128>> = Bind::new(3u128).into();
        let context = scope_only.checked(Some(parts)).unwrap();
        let under = context.under(nonempty!("users").with("email"));
        assert_eq!(
            under.query(),
            nest(nest(text("users"), text("email")), ContextPiece::U64(7))
        );
        assert_eq!(under.stored(), nest(under.query(), ContextPiece::U128(3)));
    }
}

#[cfg(test)]
mod part_tests {
    use super::*;
    use crate::target::input::DeclaredScopes;

    /// An AEAD context with neither scope nor binding is empty, and seals
    /// nothing; one with a binding alone is not, since the binding is in
    /// the stored context.
    #[test]
    fn an_aead_context_with_no_part_is_empty() {
        let none = AeadContext::from(CallerContext::from_stored(StoredParts::none()));
        assert!(MaybeEmpty::is_empty(&none));
        assert!(none.validated().is_err());
        assert!(!MaybeEmpty::is_empty(&AeadContext::from(Bind::new(9u128))));
        assert!(!MaybeEmpty::is_empty(&AeadContext::from(Scope::new(1u64))));
        assert!(AeadContext::from(Scope::new(1u64)).validated().is_ok());
    }

    /// A stored binding slot that may be left out names the binding's
    /// type, as the required slot does.
    #[test]
    fn an_optional_bind_slot_names_its_type() {
        assert_eq!(
            <Option<Bind<u128>> as BindPart>::type_name(),
            <Bind<u128> as BindPart>::type_name()
        );
        assert_eq!(
            <Option<Bind<u128>> as BindPart>::type_name().as_deref(),
            Some("u128")
        );
    }

    /// An empty stored part is refused whichever part it is, and whichever
    /// part came first: the flags accumulate into the part the record
    /// opens under, which the leaf refuses before any key is requested.
    #[test]
    fn an_empty_stored_part_is_refused_in_either_slot() {
        let none = || None::<Parts<NoScope, NoBind>>;
        let part = |stored: StoredParts| stored.checked(none()).unwrap().parts()[0].clone();
        assert!(part(StoredParts::none().scope("").bind(7u64))
            .validated()
            .is_err());
        assert!(part(StoredParts::none().scope(7u64).bind(""))
            .validated()
            .is_err());
        assert!(part(StoredParts::none().bind("").scope(7u64))
            .validated()
            .is_err());
        assert!(part(StoredParts::none().scope(7u64).bind(9u128))
            .validated()
            .is_ok());
    }

    /// An empty part the caller passes is refused whichever part it is.
    #[test]
    fn an_empty_passed_part_is_refused_in_either_slot() {
        fn part<S: ScopePart, B: BindPart>(parts: Parts<S, B>) -> CallerContext {
            StoredParts::none().checked(Some(parts)).unwrap().parts()[0].clone()
        }
        assert!(part(Scope::new("").bind(9u128)).validated().is_err());
        assert!(part(Scope::new(1u64).bind("")).validated().is_err());
        assert!(part(Scope::new(1u64).bind(9u128)).validated().is_ok());
    }

    /// A record whose parts are all stored takes no caller part, and its
    /// declared scopes carry the stored parts: the stored scope is in the
    /// context the record opens under.
    #[test]
    fn declared_scopes_carry_the_stored_parts() {
        let context = DeclaredScopes::default()
            .checked(StoredParts::none().scope(7u64))
            .unwrap();
        assert!(context.is_extended());
        let (scopes, bindings) = context.parts()[0].pieces();
        assert_eq!(scopes, Some(ContextPiece::U64(7)));
        assert!(bindings.is_empty());
        let empty = DeclaredScopes::default()
            .checked(StoredParts::none())
            .unwrap();
        assert!(!empty.is_extended());
    }
}
