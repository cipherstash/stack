//! Core-owned operation descriptions: what a target declares, and the cipher
//! executes. No constructor here accepts a plaintext-and-cipher callback; a
//! description selects core operations and converts their completed output,
//! nothing more.
//!
//! No constructor takes a context either. The context reaches every operation
//! by being threaded through the tree that composes them, as a type parameter
//! of [`Encryption`] (ADR-0004): a target cannot route the context it is
//! handed to one operation and something else to another, because there is
//! no argument to route. What a subtree may do is take a context of its own,
//! by name, with [`Encryption::under`] or [`Encryption::extend`].
use super::context::{AeadContext, CallerContext, DeclaredContext, Extends};
use super::core::{encrypt_native, open_native, Term};
use super::{CipherScope, Pending};
use crate::{Error, KeysetCipher, NonEmpty, StackCipher, StackCipherText};
use stack_kms::MaybeSend;
use std::fmt;

/// Declaration that an encrypted target is produced from `S`.
///
/// The derive supplies it; a hand-written implementation composes the
/// constructors in this module ([`ciphertext`], [`equality`], [`matching`],
/// [`ore`], [`ope`]) and converts their output with [`Encryption::map`] or
/// [`Encryption::transcode`]. Nothing here receives the plaintext or a
/// cipher: the returned [`Encryption`]'s execution is private, so a target
/// can choose operations and build its output but cannot replace encryption.
pub trait EncryptFrom<S>: Sized + 'static {
    /// The context this target still needs when it is run — what a caller
    /// supplies alongside the plaintext: a [`CallerContext`] for a target
    /// that derives terms, an [`AeadContext`] for one that only seals, a
    /// `NonEmpty<T>` for a record that stores its identifier, or a
    /// [`DeclaredContext`] — which `()` satisfies — for a record whose fields
    /// name their own.
    type Context;
    /// The description the cipher executes for one value of `S`. The context
    /// is supplied when the description is run, not here, so every operation
    /// beneath it receives the same one (ADR-0004).
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's;
}
/// Declaration of how a stored target recovers `P`.
///
/// Inspection sees no cipher: the implementation selects the recoverable
/// ciphertext and its context, and [`open`] describes the rest. A query-only
/// target (terms alone) has no implementation.
pub trait DecryptInto<P>: Sized {
    /// What a caller supplies to open the target. For a record that stores
    /// its context this is an [`ExpectedContext`](super::ExpectedContext),
    /// which may name the destination the caller believes it is opening.
    type Context;
    /// The description the cipher executes to recover `P`.
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<P, K>;
}

#[cfg(not(target_arch = "wasm32"))]
type Build<'s, S, T, K, Ctx> =
    Box<dyn for<'a, 'k> FnOnce(&S, &'a KeysetCipher<'k, K>, Ctx) -> Pending<'a, T, K> + Send + 's>;
#[cfg(target_arch = "wasm32")]
type Build<'s, S, T, K, Ctx> =
    Box<dyn for<'a, 'k> FnOnce(&S, &'a KeysetCipher<'k, K>, Ctx) -> Pending<'a, T, K> + 's>;
#[cfg(not(target_arch = "wasm32"))]
type Open<T, K> = Box<dyn for<'a> FnOnce(&'a StackCipher<K>) -> Pending<'a, T, K> + Send>;
#[cfg(target_arch = "wasm32")]
type Open<T, K> = Box<dyn for<'a> FnOnce(&'a StackCipher<K>) -> Pending<'a, T, K>>;

/// A composable description of how `T` is encrypted from `S`, under the
/// `Ctx` it is handed when it runs.
///
/// Built from the constructors in this module and the combinators below;
/// executed only by [`KeysetCipher::encrypt_as`]. Nothing runs, and no key is
/// requested, until then.
///
/// `Ctx` is the context this description still needs. It is a type parameter,
/// not a stored value, and that is what makes two rules hold at compile time
/// rather than by discipline (ADR-0004):
///
/// - **One context per target.** [`zip`](Self::zip) requires both sides to
///   need the same `Ctx` and hands them the same value, so a target has no
///   way to route what it is handed to one side and something else to the
///   other. A ciphertext beside a term takes the term's context through
///   [`accepting`](Self::accepting): the [`AeadContext`] it seals under is
///   the AEAD half of that one value. A side given a context of its own,
///   with [`under`](Self::under) or [`extend`](Self::extend), says so in the
///   declaration; that is how a record names its fields' contexts, and the
///   tree does not tell a record's fields from a target's halves.
/// - **A leaf still cannot be reached without a context.** An operation needs
///   a real one. [`under`](Self::under) and [`extend`](Self::extend) are the
///   only ways to change the context a subtree runs under, and only `under`
///   discharges the requirement into a [`DeclaredContext`], which is what
///   `()` may satisfy.
#[must_use = "an encryption description does nothing until a keyset cipher executes it"]
pub struct Encryption<'s, S, T, K, Ctx> {
    build: Build<'s, S, T, K, Ctx>,
}
/// A composable description of how `T` is recovered from a stored target.
///
/// Built from [`open`] and the combinators below; executed only by
/// `decrypt_as`. Nothing runs, and no key is retrieved, until then.
#[must_use = "a decryption description does nothing until a cipher executes it"]
pub struct Decryption<T, K> {
    inner: Opening<T, K>,
}
/// A declaration either failed while it was being built, or has an opening
/// to execute. A failure is held as a value rather than a closure that
/// yields it, so a combinator can see it without executing anything: that
/// is what lets [`Decryption::all`] stop at the first failed item.
enum Opening<T, K> {
    Failed(Error),
    Open(Open<T, K>),
}
impl<S, T, K, Ctx> fmt::Debug for Encryption<'_, S, T, K, Ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encryption").finish_non_exhaustive()
    }
}
impl<T, K> fmt::Debug for Decryption<T, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("Decryption");
        if let Opening::Failed(error) = &self.inner {
            let _ = debug.field("failed", error);
        }
        debug.finish_non_exhaustive()
    }
}

impl<'s, S: 's, T: 'static, K: 'static, Ctx: 's> Encryption<'s, S, T, K, Ctx> {
    /// A description whose output is already known — metadata a record
    /// carries, or a declaration rejected before any key request.
    pub fn ready(result: Result<T, Error>) -> Self
    where
        T: MaybeSend,
    {
        Self {
            build: Box::new(move |_, cipher, _| Pending::ready(cipher, result)),
        }
    }
    /// Reject the declaration: execution yields `error` without I/O, and any
    /// description this is zipped into fails with it.
    pub fn failed(error: Error) -> Self {
        Self {
            build: Box::new(move |_, cipher, _| Pending::failed(cipher, error)),
        }
    }
    /// Build the destination from the completed output. `f` sees ciphertext
    /// and terms, never the plaintext.
    pub fn map<U: 'static, F>(self, f: F) -> Encryption<'s, S, U, K, Ctx>
    where
        F: FnOnce(T) -> U + MaybeSend + 'static,
    {
        Encryption {
            build: Box::new(move |source, cipher, cx| (self.build)(source, cipher, cx).map(f)),
        }
    }
    /// [`map`](Self::map) for a conversion that can fail, such as reading
    /// native output into a destination that does not accept every shape.
    pub fn try_map<U: 'static, F>(self, f: F) -> Encryption<'s, S, U, K, Ctx>
    where
        F: FnOnce(T) -> Result<U, Error> + MaybeSend + 'static,
    {
        Encryption {
            build: Box::new(move |source, cipher, cx| (self.build)(source, cipher, cx).try_map(f)),
        }
    }
    /// Drive the destination's [`Visitor`](super::transcode::Visitor) from
    /// this operation's native output, moving leaves and markers across
    /// without an intermediate tree.
    pub fn transcode<U: super::transcode::Transcode + 'static>(self) -> Encryption<'s, S, U, K, Ctx>
    where
        T: super::transcode::Reader,
    {
        self.try_map(|output| super::transcode::Reader::read(output, U::visitor()))
    }
    /// Run both descriptions over the same source, under the one context this
    /// description is handed, settling their key requests in one batch.
    ///
    /// Both sides must need the same `Ctx`, and both receive the same value:
    /// there is no second context to pass. A side may still have taken a
    /// context of its own with [`under`](Self::under) or
    /// [`extend`](Self::extend) before it got here — that is how a record
    /// composes fields with different contexts — and `zip` cannot tell that
    /// from a target's two halves (ADR-0004, decision 1).
    pub fn zip<U: 'static>(
        self,
        other: Encryption<'s, S, U, K, Ctx>,
    ) -> Encryption<'s, S, (T, U), K, Ctx>
    where
        Ctx: Clone,
    {
        Encryption {
            build: Box::new(move |source, cipher, cx| {
                (self.build)(source, cipher, cx.clone()).zip((other.build)(source, cipher, cx))
            }),
        }
    }
    /// Take a different context type, converting on the way in.
    ///
    /// A ciphertext seals under an [`AeadContext`] while the term beside it
    /// derives under a [`CallerContext`]: `accepting` lets the ciphertext
    /// take the term's context, of which its own is the AEAD half, so the two
    /// zip under one value. Likewise a record declares the context its
    /// *caller* supplies, which need not be the type its operations need — a
    /// record storing its own context declares `NonEmpty<T>` while its
    /// operations want a `CallerContext` — and this adapts the one to the
    /// other once, at the root.
    pub fn accepting<C2>(self) -> Encryption<'s, S, T, K, C2>
    where
        C2: Into<Ctx> + 's,
    {
        self.needing(Into::into)
    }
    /// Need a different context, derived from the one supplied by `derive`
    /// at the root of this subtree. The one place a context changes on its
    /// way down; every public way of doing so is a closure handed here.
    fn needing<C2, F>(self, derive: F) -> Encryption<'s, S, T, K, C2>
    where
        C2: 's,
        F: FnOnce(C2) -> Ctx + MaybeSend + 's,
    {
        Encryption {
            build: Box::new(move |source, cipher, cx| (self.build)(source, cipher, derive(cx))),
        }
    }
    /// Run this whole subtree under `own`, extended by the surrounding
    /// context if there is one.
    ///
    /// A record names each field once here rather than handing a context to
    /// every operation separately. It is also what discharges the context an
    /// operation needs, which is why a leaf that is never given a context of
    /// its own cannot be run under `()`. Available wherever a
    /// [`CallerContext`] can become what the subtree needs: a leaf of either
    /// kind, or a record whose own contexts a caller's extends.
    pub fn under(self, own: NonEmpty<&'static str>) -> Encryption<'s, S, T, K, DeclaredContext>
    where
        Ctx: From<CallerContext>,
    {
        self.needing(move |cx: DeclaredContext| cx.under(own).into())
    }
    /// Run this whole subtree under `own`, extended by the surrounding
    /// context `C` — which is still required.
    ///
    /// The sibling of [`under`](Self::under), for a record that cannot make
    /// the caller's context optional because some *other* field of it is a
    /// bare leaf. `C` is the caller's context type — a [`CallerContext`], or
    /// an [`AeadContext`] for a record that only seals — and the same one
    /// context reaches every operation beneath; the difference from `under`
    /// is only whether `()` can satisfy the result.
    pub fn extend<C>(self, own: NonEmpty<&'static str>) -> Encryption<'s, S, T, K, C>
    where
        C: Extends + 's,
        Ctx: From<C>,
    {
        self.needing(move |cx: C| cx.extend(own).into())
    }
    /// Lift a description of a field to a description of the struct that
    /// holds it, which is how a `struct = T` derive composes its fields.
    ///
    /// The selector is a plain function pointer over a borrow: it captures
    /// nothing, so it cannot reach a cipher, and what it returns is encrypted
    /// under `S`'s own Vitamin C contract. It is a place to pick a field, not
    /// to re-encode one.
    pub fn project<P: 's>(
        self,
        select: for<'borrow> fn(&'borrow P) -> &'borrow S,
    ) -> Encryption<'s, P, T, K, Ctx> {
        Encryption {
            build: Box::new(move |source, cipher, cx| (self.build)(select(source), cipher, cx)),
        }
    }
}

impl<'s, S: 's, T: 'static, K: 'static, Ctx: 's + Clone + MaybeSend + 'static>
    Encryption<'s, S, T, K, Ctx>
{
    /// Build the output from the completed operations *and* the context they
    /// ran under.
    ///
    /// For a record that stores its own context in a field
    /// (`#[stash(context_field)]`): the context is supplied when the
    /// description runs, so the field it populates is filled there too.
    pub fn map_with_context<U: 'static, F>(self, f: F) -> Encryption<'s, S, U, K, Ctx>
    where
        F: FnOnce(T, Ctx) -> U + MaybeSend + 'static,
    {
        Encryption {
            build: Box::new(move |source, cipher, cx: Ctx| {
                let carried = cx.clone();
                (self.build)(source, cipher, cx).map(move |value| f(value, carried))
            }),
        }
    }
}

/// The canonical ciphertext operation: seal `S`, under the [`AeadContext`]
/// the tree hands it, through its own Vitamin C `Encrypt` implementation,
/// into the native [`StackCipherText`] tree. There is no Serde fallback; a
/// plaintext without `Encrypt` does not compile.
///
/// Sealing needs only the AEAD encoding of a context, so this needs an
/// `AeadContext` where a term needs a [`CallerContext`]. Beside a term,
/// [`accepting`](Encryption::accepting) lets it take the term's context —
/// the AEAD half of the same value — so the two zip under one context.
pub fn ciphertext<'s, S: crate::Encrypt + Clone + 's, K: 'static>(
) -> Encryption<'s, S, StackCipherText, K, AeadContext> {
    Encryption {
        build: Box::new(
            move |source, cipher, cx: AeadContext| match cx.validated() {
                Ok(ctx) => encrypt_native(source, cipher, ctx),
                Err(e) => Pending::failed(cipher, e),
            },
        ),
    }
}
/// A term operation: `$function` produces `$output` from any `S` satisfying
/// the bounds, under the [`CallerContext`] the tree hands it.
macro_rules! term_operation {
    (
        $(#[$doc:meta])*
        $function:ident, $output:ty, [$($generics:tt)*], [$($bounds:tt)*]
    ) => {
        $(#[$doc])*
        pub fn $function<'s, S, K: 'static, $($generics)*>(
        ) -> Encryption<'s, S, $output, K, CallerContext>
        where
            S: 's,
            $($bounds)*
        {
            Encryption {
                build: Box::new(move |source, cipher, cx: CallerContext| match cx.validated() {
                    Ok(ctx) => <$output as Term<S, K, _>>::encrypt_from(source, cipher, ctx),
                    Err(e) => Pending::failed(cipher, e),
                }),
            }
        }
    };
}
term_operation!(
    /// The equality term of `S` under the context the tree hands it. Requires
    /// only `S`'s PRF contract, not recoverable encryption.
    equality, crate::sem::EqualityTerm, [], [S: vitaminc_prf::PrfValue + Clone]
);
term_operation!(
    /// The match term of any text `S` under the context the tree hands it,
    /// tokenised and hashed as `O` declares.
    matching, crate::sem::MatchTerm<O>, [O: crate::sem::MatchConfig + 'static], [S: AsRef<str>]
);
term_operation!(
    /// The order-revealing term of `S` under the context the tree hands it.
    /// The bounds are the leaf's own: they say which `S` the CLLW ORE scheme
    /// can order.
    ore, crate::sem::OreTerm<S>, [],
    [S: cllw_ore::CllwOreEncrypt + Clone + Send + 'static, S::Output: Send + 'static]
);
term_operation!(
    /// The order-preserving term of `S` under the context the tree hands it,
    /// with the same bounds as [`ore`].
    ope, crate::sem::OpeTerm<S>, [],
    [S: cllw_ore::CllwOpeEncrypt + Clone + Send + 'static, S::Output: Send + 'static]
);

impl<T: 'static, K: 'static> Decryption<T, K> {
    /// Reject the opening: execution yields `error` without I/O, any
    /// description this is zipped into fails with it, and a collection
    /// ([`all`](Self::all)) stops at it. The derives use it when a stored
    /// context fails validation.
    pub fn failed(error: Error) -> Self {
        Self {
            inner: Opening::Failed(error),
        }
    }
    fn open(open: Open<T, K>) -> Self {
        Self {
            inner: Opening::Open(open),
        }
    }
    /// A description whose output is already known: a defaulted field, or
    /// an absent optional.
    pub fn ready(value: T) -> Self
    where
        T: MaybeSend,
    {
        Self::open(Box::new(move |cipher| Pending::ready(cipher, Ok(value))))
    }
    /// Convert the recovered value.
    pub fn map<U: 'static, F>(self, f: F) -> Decryption<U, K>
    where
        F: FnOnce(T) -> U + MaybeSend + 'static,
    {
        match self.inner {
            Opening::Failed(error) => Decryption::failed(error),
            Opening::Open(open) => Decryption::open(Box::new(move |cipher| open(cipher).map(f))),
        }
    }
    /// Open both, retrieving their keys in one batch. A failed side fails
    /// the pair, the left one first, without executing the other.
    pub fn zip<U: 'static>(self, other: Decryption<U, K>) -> Decryption<(T, U), K> {
        match (self.inner, other.inner) {
            (Opening::Failed(error), _) | (_, Opening::Failed(error)) => Decryption::failed(error),
            (Opening::Open(left), Opening::Open(right)) => {
                Decryption::open(Box::new(move |cipher| left(cipher).zip(right(cipher))))
            }
        }
    }
    /// Open every description, retrieving all their keys in one batch, and
    /// collect the results in order.
    ///
    /// `items` is consumed only as far as its first failed description: the
    /// column fails with that error, and the descriptions after it are never
    /// built. A `Vec<T>` whose rows validate a stored context does not go on
    /// validating rows once one has been refused.
    pub fn all<I>(items: I) -> Decryption<Vec<T>, K>
    where
        I: IntoIterator<Item = Self>,
    {
        let mut opens = Vec::new();
        for item in items {
            match item.inner {
                Opening::Failed(error) => return Decryption::failed(error),
                Opening::Open(open) => opens.push(open),
            }
        }
        Decryption::open(Box::new(move |cipher| {
            Pending::collect(cipher, opens.into_iter().map(|open| open(cipher)))
        }))
    }
    /// An absent item recovers as `None` without I/O.
    fn optional(item: Option<Self>) -> Decryption<Option<T>, K>
    where
        T: MaybeSend,
    {
        match item {
            Some(item) => item.map(Some),
            None => Decryption::ready(None),
        }
    }
    /// Execute under a scope. A [`KeysetCipher`] scope refuses a leaf from any
    /// other keyset; a [`StackCipher`] scope opens leaves from any.
    fn open_in<'a>(self, scope: impl CipherScope<'a, K>) -> Pending<'a, T, K> {
        let pending = match self.inner {
            Opening::Failed(error) => return Pending::failed(scope, error),
            Opening::Open(open) => open(scope.cipher()),
        };
        match scope.keyset() {
            Some(id) => pending.scoped_to(id),
            None => pending,
        }
    }
}
/// The canonical opening operation: retrieve the tree's keys and decode `P`
/// through its own Vitamin C `Decrypt` implementation, under `context`.
pub fn open<P: crate::Decrypt<'static> + 'static, K: 'static>(
    tree: StackCipherText,
    context: impl Into<AeadContext>,
) -> Decryption<P, K> {
    let context = context.into();
    Decryption::open(Box::new(move |cipher| match context.validated() {
        Ok(ctx) => open_native(tree, cipher, ctx),
        Err(e) => Pending::failed(cipher, e),
    }))
}

impl<K: 'static> KeysetCipher<'_, K> {
    /// Encrypt `source` into `T` under this keyset, as `T`'s declaration
    /// describes. The returned [`Pending`] settles every key request the
    /// declaration made in one batch.
    pub fn encrypt_as<'a, S, T>(&'a self, source: &S, context: T::Context) -> Pending<'a, T, K>
    where
        T: EncryptFrom<S>,
    {
        (T::encryption().build)(source, self, context)
    }
    /// Recover `P` from `source`, as its declaration describes. A leaf sealed
    /// under another keyset is refused ([`Error::ForeignKeyset`]) before any
    /// key is retrieved.
    pub fn decrypt_as<'a, P: 'static, T>(
        &'a self,
        source: T,
        context: T::Context,
    ) -> Pending<'a, P, K>
    where
        T: DecryptInto<P>,
    {
        source.decryption(context).open_in(self)
    }
}
impl<K: 'static> StackCipher<K> {
    /// Recover `P` from `source`, as its declaration describes. Leaves from
    /// any of the client's keysets open here.
    pub fn decrypt_as<'a, P: 'static, T>(
        &'a self,
        source: T,
        context: T::Context,
    ) -> Pending<'a, P, K>
    where
        T: DecryptInto<P>,
    {
        source.decryption(context).open_in(self)
    }
}

/// Source-side call syntax for [`KeysetCipher::encrypt_as`], implemented for
/// every type: `value.encrypt_into(&keyset)`. Targets implement
/// [`EncryptFrom`], never these methods.
pub trait EncryptInto: Sized {
    /// Encrypt into `T` with its default context — `()` for a declaration
    /// that carries its own contexts.
    fn encrypt_into<'a, T, K: 'static>(&self, cipher: &'a KeysetCipher<'_, K>) -> Pending<'a, T, K>
    where
        T: EncryptFrom<Self>,
        T::Context: Default,
    {
        cipher.encrypt_as(self, Default::default())
    }
    /// Encrypt into `T` under `context`, accepting anything that converts
    /// into `T`'s context — a `nonempty!` literal, say.
    fn encrypt_into_with_context<'a, T, K: 'static>(
        &self,
        cipher: &'a KeysetCipher<'_, K>,
        context: impl Into<T::Context>,
    ) -> Pending<'a, T, K>
    where
        T: EncryptFrom<Self>,
    {
        cipher.encrypt_as(self, context.into())
    }
    /// [`encrypt_into_with_context`](Self::encrypt_into_with_context) named
    /// from the target's side: `Target::encrypt_from(&value, &keyset, ctx)`.
    fn encrypt_from<'a, S, K: 'static>(
        source: &S,
        cipher: &'a KeysetCipher<'_, K>,
        context: impl Into<<Self as EncryptFrom<S>>::Context>,
    ) -> Pending<'a, Self, K>
    where
        Self: EncryptFrom<S>,
    {
        cipher.encrypt_as(source, context.into())
    }
}
impl<T> EncryptInto for T {}
/// Source-side call syntax for `decrypt_as`, implemented for every type:
/// `stored.decrypt_into(&cipher, ctx)`. Targets implement [`DecryptInto`],
/// never these methods.
pub trait DecryptFrom: Sized + 'static {
    /// Recover `P` through `cipher`, which may be a [`KeysetCipher`] (refusing
    /// foreign leaves) or a [`StackCipher`] (opening any).
    fn decrypt_into<'a, P: 'static, K: 'static>(
        self,
        cipher: impl CipherScope<'a, K>,
        context: impl Into<<Self as DecryptInto<P>>::Context>,
    ) -> Pending<'a, P, K>
    where
        Self: DecryptInto<P>,
    {
        self.decryption(context.into()).open_in(cipher)
    }
    /// Recover `Self` from `source` with its default context — the plain
    /// "read the stored context and validate it" for a record that stores
    /// one.
    fn decrypt_from<'a, S, K: 'static>(
        source: S,
        cipher: impl CipherScope<'a, K>,
    ) -> Pending<'a, Self, K>
    where
        S: DecryptInto<Self> + 'static,
        S::Context: Default,
    {
        source.decrypt_into(cipher, S::Context::default())
    }
    /// Recover `Self` from `source` under `context`.
    fn decrypt_from_with_context<'a, S, K: 'static>(
        source: S,
        cipher: impl CipherScope<'a, K>,
        context: impl Into<S::Context>,
    ) -> Pending<'a, Self, K>
    where
        S: DecryptInto<Self> + 'static,
    {
        source.decrypt_into(cipher, context.into())
    }
}
impl<T: 'static> DecryptFrom for T {}

impl<S: crate::Encrypt + Clone> EncryptFrom<S> for StackCipherText {
    type Context = AeadContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        ciphertext()
    }
}
impl<P: crate::Decrypt<'static> + 'static> DecryptInto<P> for StackCipherText {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<P, K> {
        open(self, context)
    }
}
impl<S: vitaminc_prf::PrfValue + Clone> EncryptFrom<S> for crate::sem::EqualityTerm {
    type Context = CallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        equality()
    }
}
impl<S: AsRef<str>, O: crate::sem::MatchConfig + 'static> EncryptFrom<S>
    for crate::sem::MatchTerm<O>
{
    type Context = CallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        matching()
    }
}
impl<S> EncryptFrom<S> for crate::sem::OreTerm<S>
where
    S: cllw_ore::CllwOreEncrypt + Clone + Send + 'static,
    S::Output: Send + 'static,
{
    type Context = CallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        ore()
    }
}
impl<S> EncryptFrom<S> for crate::sem::OpeTerm<S>
where
    S: cllw_ore::CllwOpeEncrypt + Clone + Send + 'static,
    S::Output: Send + 'static,
{
    type Context = CallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        ope()
    }
}

// A `Vec<Target>` is a row per item, each encrypted independently under the
// same context and settled in one batch; an `Option<Target>` is one row or
// nothing, without I/O. (A plaintext `Vec`/`Option` sealed into a
// `StackCipherText` is a different thing: Vitamin C's native sequence and
// option, with their authenticated markers.)
impl<S, T: EncryptFrom<S>> EncryptFrom<Vec<S>> for Vec<T>
where
    T::Context: Clone + 'static + MaybeSend,
{
    type Context = T::Context;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Vec<S>, Self, K, Self::Context>
    where
        S: 's,
    {
        Encryption {
            build: Box::new(move |source, cipher, cx: T::Context| {
                Pending::collect(
                    cipher,
                    source
                        .iter()
                        .map(|item| cipher.encrypt_as(item, cx.clone())),
                )
            }),
        }
    }
}
impl<S, T: EncryptFrom<S> + MaybeSend> EncryptFrom<Option<S>> for Option<T>
where
    T::Context: 'static + MaybeSend,
{
    type Context = T::Context;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Option<S>, Self, K, Self::Context>
    where
        S: 's,
    {
        Encryption {
            build: Box::new(move |source, cipher, cx: T::Context| match source {
                Some(item) => cipher.encrypt_as(item, cx).map(Some),
                None => Pending::ready(cipher, Ok(None)),
            }),
        }
    }
}
impl<P: 'static, T: DecryptInto<P> + 'static> DecryptInto<Vec<P>> for Vec<T>
where
    T::Context: Clone + 'static,
{
    type Context = T::Context;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Vec<P>, K> {
        Decryption::all(
            self.into_iter()
                .map(|item| item.decryption(context.clone())),
        )
    }
}
impl<P: 'static + MaybeSend, T: DecryptInto<P> + 'static> DecryptInto<Option<P>> for Option<T> {
    type Context = T::Context;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Option<P>, K> {
        Decryption::optional(self.map(|item| item.decryption(context)))
    }
}

/// How a derive finds the one recoverable field of a record among its terms.
///
/// A term returns `None`: it is one-way. A ciphertext field returns its
/// opening description. Neither sees a cipher. Implemented for every leaf
/// type and for `Vec`/`Option` of them; a hand-written leaf that wraps a
/// [`StackCipherText`] implements it alongside [`Decryptable`].
pub trait DecryptField<P, Ctx>: Sized {
    /// The opening description, if this field holds recoverable ciphertext.
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>>;
}
impl<P: 'static, Ctx> DecryptField<P, Ctx> for StackCipherText
where
    Self: DecryptInto<P>,
    Ctx: Into<<Self as DecryptInto<P>>::Context>,
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
        Some(self.decryption(context.into()))
    }
}
impl<P: 'static, T: 'static + Decryptable + DecryptField<P, Ctx>, Ctx: Clone + 'static>
    DecryptField<Vec<P>, Ctx> for Vec<T>
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<Vec<P>, K>> {
        if !T::DECRYPTABLE {
            return None;
        }
        Some(Decryption::all(self.into_iter().map(|item| {
            item.decryption_field(context.clone())
                .unwrap_or_else(|| Decryption::failed(Error::NotOpened))
        })))
    }
}
impl<P: 'static + MaybeSend, T: 'static + Decryptable + DecryptField<P, Ctx>, Ctx: 'static>
    DecryptField<Option<P>, Ctx> for Option<T>
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<Option<P>, K>> {
        if !T::DECRYPTABLE {
            return None;
        }
        Some(Decryption::optional(self.map(|item| {
            item.decryption_field(context)
                .unwrap_or_else(|| Decryption::failed(Error::NotOpened))
        })))
    }
}

/// Whether a field type holds recoverable ciphertext. The derives require
/// exactly one such field per plaintext value; a term is never one.
pub trait Decryptable {
    /// `true` for ciphertext, `false` for a term.
    const DECRYPTABLE: bool;
}
impl Decryptable for StackCipherText {
    const DECRYPTABLE: bool = true;
}
impl<T: Decryptable> Decryptable for Vec<T> {
    const DECRYPTABLE: bool = T::DECRYPTABLE;
}
impl<T: Decryptable> Decryptable for Option<T> {
    const DECRYPTABLE: bool = T::DECRYPTABLE;
}
