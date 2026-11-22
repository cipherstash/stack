//! Core-owned operation descriptions: what a target declares, and the cipher
//! executes. No constructor here accepts a plaintext-and-cipher callback; a
//! description selects core operations and converts their completed output,
//! nothing more.
//!
//! No constructor takes a context either. The context reaches every operation
//! by being threaded through the tree that composes them, as a type parameter
//! of [`Encryption`]: a target cannot route the context it is
//! handed to one operation and something else to another, because there is
//! no argument to route. What a subtree may do is take a context of its own,
//! by name, with [`Encryption::under`] or [`Encryption::extend`]. A subtree
//! can also read its context from a named field of the plaintext, with
//! [`Encryption::context_from`].

// One context per target, threaded through the declaration tree:
// packages/stack-encrypt/docs/adr/0004-one-context-per-target-threaded-through-the-declaration-tree.md.
use super::context::{
    AeadContext, CallerContext, DeclaredContext, Extends, StoredContext, StoredParts,
};
use super::conversion::{DecryptSource, EncryptTarget};
use super::core::{encrypt_native, open_native, Term};
use super::input::{AcceptsContext, NoCallerContext, RequiredContext};
use super::source::{
    Borrowed, ConsumeSource, Guarded, Held, Owned, Source, SourceMode, WipeSource,
};
use super::{CipherRef, Pending};
use crate::contexts::{self, Contexts, Placeholder, Shape, Shapes, SuppliedContext};
use crate::json::{JsonDocument, JsonOptions, JsonPlaintext, JsonTerms};
use crate::{Error, IntoContext, KeysetCipher, MaybeEmpty, NonEmpty, StackCipher, StackCipherText};
use stack_kms::MaybeSend;
use std::fmt;
use std::marker::PhantomData;
use vitaminc_aead::EncryptRef;

// What a description is handed is a `Source`: a borrow in the default
// `Borrowed` mode, the value itself in `Owned` mode (see `SourceMode`). The
// borrow's lifetime is the closure's own, so one owned value can be lent to
// a description and then handed to another.
#[cfg(not(target_arch = "wasm32"))]
type Build<'s, S, T, K, Ctx> = Box<
    dyn for<'a, 'k, 'b> FnOnce(Source<'b, S>, &'a KeysetCipher<'k, K>, Ctx) -> Pending<'a, T, K>
        + Send
        + 's,
>;
#[cfg(target_arch = "wasm32")]
type Build<'s, S, T, K, Ctx> = Box<
    dyn for<'a, 'k, 'b> FnOnce(Source<'b, S>, &'a KeysetCipher<'k, K>, Ctx) -> Pending<'a, T, K>
        + 's,
>;
#[cfg(not(target_arch = "wasm32"))]
type Open<T, K> = Box<dyn for<'a> FnOnce(&'a StackCipher<K>) -> Pending<'a, T, K> + Send>;
#[cfg(target_arch = "wasm32")]
type Open<T, K> = Box<dyn for<'a> FnOnce(&'a StackCipher<K>) -> Pending<'a, T, K>>;

/// A composable description of how `T` is encrypted from `S`, under the
/// `Ctx` it is handed when it runs.
///
/// Built from the constructors in this module and the combinators below;
/// executed only by a keyset cipher: [`EncryptInto`](super::EncryptInto) runs
/// a target's declaration, and [`KeysetCipher::run`] runs a description held
/// in a variable. Nothing runs, and no key is requested, until then.
///
/// `Ctx` is the context this description still needs. It is a type parameter,
/// not a stored value, and that is what makes two rules hold at compile time
/// rather than by discipline:
///
/// - **One context per target.** [`zip`](Self::zip) requires both sides to
///   need the same `Ctx` and hands them the same value, so a target has no
///   way to route what it is handed to one side and something else to the
///   other. A ciphertext beside a term takes the term's context through
///   [`accepting`](Self::accepting): the [`AeadContext`] it seals under is
///   the AEAD half of that one value. A side given a context of its own,
///   with [`under`](Self::under), [`extend`](Self::extend), or
///   [`context_from`](Self::context_from), says so in the declaration; that
///   is how a record names its fields' contexts, and the tree does not tell a
///   record's fields from a target's halves.
/// - **A leaf still cannot be reached without a context.** An operation needs
///   a real one. [`under`](Self::under) and [`extend`](Self::extend) change
///   the context that a subtree runs under. `under` discharges the
///   requirement into a [`DeclaredContext`], and `()` may satisfy that.
///   [`context_from`](Self::context_from) also discharges the requirement,
///   into [`NoCallerContext`], with the context read from a named field of
///   the plaintext.
///
/// `M` is how the description is handed its plaintext ([`SourceMode`]):
/// by reference in the default [`Borrowed`] mode, which a declaration that
/// takes a field out of a borrowed struct runs in, or by value in
/// [`Owned`] mode, which [`EncryptInto`](super::EncryptInto) runs. Every
/// operation reads the plaintext in place, so in neither mode does `S` need
/// to be `Clone`. In owned mode the operation handed the value wipes it.
#[must_use = "an encryption description does nothing until a keyset cipher executes it"]
pub struct Encryption<'s, S: 's, T, K, Ctx, M: SourceMode<'s, S> = Borrowed> {
    build: Build<'s, S, T, K, Ctx>,
    /// The context of each leaf, in terms of the context this description
    /// is handed. Kept beside the closure by every combinator, so
    /// [`contexts`](Self::contexts) shows what the closure will do.
    shapes: Shapes,
    /// Which of the two a [`Source`] this description is handed holds.
    mode: PhantomData<fn() -> M>,
}
/// A composable description of how `T` is recovered from a stored target.
///
/// Built from [`open`] and the combinators below; executed only by a
/// cipher: [`DecryptFrom`](super::DecryptFrom) runs a stored target's
/// declaration, and `run_decryption` runs a description held in a variable.
/// Nothing runs, and no key is retrieved, until then.
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
impl<'s, S: 's, T, K, Ctx, M: SourceMode<'s, S>> fmt::Debug for Encryption<'s, S, T, K, Ctx, M> {
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

impl<'s, S: 's, T: 'static, K: 'static, Ctx: 's, M: SourceMode<'s, S>>
    Encryption<'s, S, T, K, Ctx, M>
{
    /// The shapes of this description's leaves, for a description that runs
    /// this one inside its closure.
    pub(crate) fn shapes(&self) -> Shapes {
        self.shapes.clone()
    }
    /// The contexts this description uses, one for each field that is
    /// sealed or indexed, with a [`Placeholder`] for every part the caller
    /// supplies. No key is requested.
    ///
    /// The derives emit `contexts()` on every record, which calls this.
    /// See [`Contexts`].
    pub fn contexts(&self) -> Contexts
    where
        Ctx: SuppliedContext,
    {
        contexts::resolve(self.shapes.clone(), Ctx::supplies())
    }
    /// Name every leaf after the field of a record the leaves belong to. A
    /// leaf a nested record already named becomes `<name>.<its name>`. The
    /// derives emit it after each field's [`under`](Self::under). Hidden:
    /// generated code calls it.
    #[doc(hidden)]
    pub fn named(mut self, name: &str) -> Self {
        self.shapes = contexts::name(self.shapes, name);
        self
    }
    /// A description whose output is already known — metadata a record
    /// carries, or a declaration rejected before any key request.
    pub fn ready(result: Result<T, Error>) -> Self
    where
        T: MaybeSend,
    {
        Self {
            build: Box::new(move |_, cipher, _| Pending::ready(cipher, result)),
            shapes: Vec::new(),
            mode: PhantomData,
        }
    }
    /// Reject the declaration: execution yields `error` without I/O, and any
    /// description this is zipped into fails with it.
    pub fn failed(error: Error) -> Self {
        Self {
            build: Box::new(move |_, cipher, _| Pending::failed(cipher, error)),
            shapes: Vec::new(),
            mode: PhantomData,
        }
    }
    /// Reject this declaration as [`failed`](Self::failed) does, but keep
    /// the contexts of its leaves. [`contexts`](Self::contexts) then still
    /// shows each field the declaration names, and running it yields
    /// `error` without I/O. A set of indexes that is refused (two indexes
    /// for one operator, say) uses this, so its field does not disappear
    /// from `contexts()`. Hidden: generated code calls it.
    #[doc(hidden)]
    pub fn refused(self, error: Error) -> Self {
        Self {
            build: Box::new(move |_, cipher, _| Pending::failed(cipher, error)),
            shapes: self.shapes,
            mode: PhantomData,
        }
    }
    /// Build the destination from the completed output. `f` sees ciphertext
    /// and terms, never the plaintext.
    pub fn map<U: 'static, F>(self, f: F) -> Encryption<'s, S, U, K, Ctx, M>
    where
        F: FnOnce(T) -> U + MaybeSend + 'static,
    {
        let Self { build, shapes, .. } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx| build(source, cipher, cx).map(f)),
            shapes,
            mode: PhantomData,
        }
    }
    /// [`map`](Self::map) for a conversion that can fail, such as reading
    /// native output into a destination that does not accept every shape.
    pub fn try_map<U: 'static, F>(self, f: F) -> Encryption<'s, S, U, K, Ctx, M>
    where
        F: FnOnce(T) -> Result<U, Error> + MaybeSend + 'static,
    {
        let Self { build, shapes, .. } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx| build(source, cipher, cx).try_map(f)),
            shapes,
            mode: PhantomData,
        }
    }
    /// Drive the destination's [`Visitor`](super::transcode::Visitor) from
    /// this operation's native output, moving leaves and markers across
    /// without an intermediate tree.
    pub fn transcode<U: super::transcode::Transcode + 'static>(
        self,
    ) -> Encryption<'s, S, U, K, Ctx, M>
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
    /// from a target's two halves.
    ///
    /// Both sides read the same plaintext, and neither needs a copy of it.
    /// `other` is a [`Borrowed`] description: it reads the plaintext in place,
    /// and runs first. Then this description is handed what it would be
    /// handed alone: the same borrow in [`Borrowed`] mode, or the value itself
    /// in [`Owned`] mode. So several operations over one owned value put the
    /// one that takes the value first, and the ones that only read it after.
    /// The outputs are in the order written.
    ///
    /// While `other` reads an owned value, the value is held in a guard. If
    /// `other` panics, the value is wiped as the stack unwinds
    /// ([`WipeSource`]).
    pub fn zip<U: 'static>(
        self,
        other: Encryption<'s, S, U, K, Ctx>,
    ) -> Encryption<'s, S, (T, U), K, Ctx, M>
    where
        Ctx: Clone,
        M: WipeSource<'s, S>,
    {
        let Self {
            build, mut shapes, ..
        } = self;
        let Encryption {
            build: other_build,
            shapes: other_shapes,
            ..
        } = other;
        shapes.extend(other_shapes);
        Encryption {
            build: Box::new(move |source, cipher, cx| {
                let guarded = Guarded::<M, S>::new(source);
                let theirs = other_build(guarded.source().lend(), cipher, cx.clone());
                build(guarded.take(), cipher, cx).zip(theirs)
            }),
            shapes,
            mode: PhantomData,
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
    pub fn accepting<C2>(self) -> Encryption<'s, S, T, K, C2, M>
    where
        C2: Into<Ctx> + 's,
    {
        self.needing(Into::into)
    }
    /// Need a different context, derived from the one supplied by `derive`
    /// at the root of this subtree. The one place a context changes on its
    /// way down; every public way of doing so is a closure handed here.
    fn needing<C2, F>(self, derive: F) -> Encryption<'s, S, T, K, C2, M>
    where
        C2: 's,
        F: FnOnce(C2) -> Ctx + MaybeSend + 's,
    {
        let Self { build, shapes, .. } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx| build(source, cipher, derive(cx))),
            shapes,
            mode: PhantomData,
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
    ///
    /// A part the caller passed empty is refused here, before the subtree
    /// runs. In [`Owned`] mode that refusal drops the plaintext without
    /// wiping it, because `S` need not be `Zeroize`. A derived record wipes
    /// it instead.
    pub fn under(
        self,
        own: NonEmpty<impl IntoContext<'static> + MaybeSend + 's>,
    ) -> Encryption<'s, S, T, K, DeclaredContext, M>
    where
        Ctx: From<CallerContext>,
    {
        self.under_refusing(own, |source| drop(source))
    }
    /// [`under`](Self::under), for a field of a derived `struct = ..`
    /// record. A context that is refused here wipes a plaintext that was
    /// passed by value. `under` drops it as it is.
    ///
    /// **This method is for generated code.** The derive emits it for each
    /// sealed field, in the borrowed form and in the owned form. The
    /// plaintext is `Zeroize`, as the source of every
    /// [`EncryptTarget`] is.
    #[doc(hidden)]
    pub fn under_field(
        self,
        own: NonEmpty<impl IntoContext<'static> + MaybeSend + 's>,
    ) -> Encryption<'s, S, T, K, DeclaredContext, M>
    where
        Ctx: From<CallerContext>,
        S: zeroize::Zeroize,
    {
        self.under_refusing(own, |source| {
            source.release(|value| drop(vitaminc_protected::Protected::new(value)))
        })
    }
    /// The body of [`under`](Self::under). `refused` is given the source
    /// when the context is refused, before the subtree has seen it. The
    /// JSON index's query passes one that wipes a document through its own
    /// guard.
    pub(crate) fn under_refusing(
        mut self,
        own: NonEmpty<impl IntoContext<'static> + MaybeSend + 's>,
        refused: for<'b> fn(Source<'b, S>),
    ) -> Encryption<'s, S, T, K, DeclaredContext, M>
    where
        Ctx: From<CallerContext>,
    {
        let own = contexts::piece_of(own);
        self.shapes = contexts::substitute(self.shapes, &Shape::under(own.get().clone()));
        let Self { build, shapes, .. } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx: DeclaredContext| {
                match cx.checked_under(own) {
                    Ok(context) => build(source, cipher, context.into()),
                    Err(error) => {
                        refused(source);
                        Pending::failed(cipher, error)
                    }
                }
            }),
            shapes,
            mode: PhantomData,
        }
    }
    /// Run this whole subtree under the parts the plaintext stores, then the
    /// caller's parts. `read` reads the stored scope and binding out of the
    /// plaintext. `scope` and `bind` name them, for
    /// [`contexts`](Self::contexts). The caller's input `C` is the parts the
    /// record lists, converted into the declared context the subtree runs
    /// under.
    ///
    /// **This method is for generated code.** A `struct = ..` record with a
    /// `scope(field = ..)` or `bind(field = ..)` attribute emits it at its
    /// root, in place of [`accepting`](Self::accepting). `read` is a plain
    /// function pointer: it captures nothing, so it cannot reach a cipher,
    /// and it only copies the fields it names.
    #[doc(hidden)]
    pub fn parts_from<C>(
        self,
        read: for<'b> fn(&'b S) -> StoredParts,
        scope: Option<(&'static str, String)>,
        bind: Option<(&'static str, String)>,
    ) -> Encryption<'s, S, T, K, C, M>
    where
        Ctx: From<DeclaredContext>,
        C: Into<DeclaredContext> + 's,
    {
        let Self { build, shapes, .. } = self;
        let shapes = contexts::substitute(shapes, &Shape::stored_parts(scope, bind));
        Encryption {
            build: Box::new(move |source, cipher, caller: C| {
                let stored = read(source.view());
                let mut context = DeclaredContext::from(CallerContext::from_stored(stored));
                context.append(caller.into());
                build(source, cipher, context.into())
            }),
            shapes,
            mode: PhantomData,
        }
    }
    /// Name the caller's parts, for [`contexts`](Self::contexts): the
    /// `scope(tenant: u64)` and `bind(row: u128)` a record lists. The types
    /// come from the record's context input; this adds the names.
    ///
    /// **This method is for generated code.**
    #[doc(hidden)]
    pub fn caller_names(mut self, scope: Option<&'static str>, bind: Option<&'static str>) -> Self {
        self.shapes = contexts::substitute(self.shapes, &Shape::named_caller(scope, bind));
        self
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
    pub fn extend<C>(
        mut self,
        own: NonEmpty<impl IntoContext<'static> + MaybeSend + 's>,
    ) -> Encryption<'s, S, T, K, C, M>
    where
        C: Extends + 's,
        Ctx: From<C>,
    {
        let own = contexts::piece_of(own);
        self.shapes = contexts::substitute(self.shapes, &Shape::under(own.get().clone()));
        self.needing(move |cx: C| cx.extend(own).into())
    }
    /// [`refused`](Self::refused), for the owned form of a derived record.
    /// A description refused here wipes a plaintext that was passed by value.
    /// `refused` drops it as it is, because `S` need not be `Zeroize`.
    ///
    /// **This method is for generated code.** The derive emits it when a
    /// record's indexes are refused, in the owned form of a record that
    /// moves its plaintext into its one field.
    #[doc(hidden)]
    pub fn refused_wiping(self, error: Error) -> Self
    where
        S: zeroize::Zeroize,
    {
        Self {
            build: Box::new(move |source, cipher, _| {
                source.release(|value| drop(vitaminc_protected::Protected::new(value)));
                Pending::failed(cipher, error)
            }),
            shapes: self.shapes,
            mode: PhantomData,
        }
    }
    /// The body of [`storing`](Encryption::storing). `refused` is given the
    /// source when the context cannot be stored, before the description has
    /// seen it.
    fn storing_refusing<C, U: 'static, F>(
        self,
        store: F,
        refused: for<'b> fn(Source<'b, S>),
    ) -> Encryption<'s, S, U, K, StoredContext<C>, M>
    where
        Ctx: From<CallerContext>,
        C: MaybeSend + 'static,
        F: FnOnce(T, C) -> U + MaybeSend + 'static,
    {
        let Self { build, shapes, .. } = self;
        Encryption {
            build: Box::new(
                move |source, cipher, cx: StoredContext<C>| match cx.into_parts() {
                    Ok((stored, context)) => {
                        build(source, cipher, context.into()).map(move |value| store(value, stored))
                    }
                    Err(error) => {
                        refused(source);
                        Pending::failed(cipher, error)
                    }
                },
            ),
            shapes,
            mode: PhantomData,
        }
    }
}

impl<'s, S: 's, T: 'static, K: 'static, Ctx: 's> Encryption<'s, S, T, K, Ctx> {
    /// A description built from its execution closure. This constructor is
    /// crate-internal, because it gives a closure the source and the cipher
    /// together, and the public constructors never do that. The collection
    /// declarations use it to run an element's description once for each
    /// element.
    ///
    /// `shapes` is the context of each leaf the closure will run, in terms
    /// of the context it is handed. A closure that runs another
    /// description passes that description's [`shapes`](Self::shapes).
    pub(crate) fn from_build<F>(shapes: Shapes, build: F) -> Self
    where
        F: for<'a, 'k, 'b> FnOnce(&'b S, &'a KeysetCipher<'k, K>, Ctx) -> Pending<'a, T, K>
            + MaybeSend
            + 's,
    {
        Self {
            build: Box::new(move |source, cipher, cx| build(source.borrowed(), cipher, cx)),
            shapes,
            mode: PhantomData,
        }
    }
    /// Lift a description of a field to a description of the struct that
    /// holds it, which is how a `struct = T` derive composes its fields.
    ///
    /// The selector is a plain function pointer over a borrow: it captures
    /// nothing, so it cannot reach a cipher, and what it returns is encrypted
    /// under `S`'s own Vitamin C contract. It is a place to pick a field, not
    /// to re-encode one.
    ///
    /// A field is picked out of a borrowed struct, so this is a
    /// [`Borrowed`]-mode combinator: a field whose operations consume it is
    /// cloned, as it always was, and the struct itself never is.
    pub fn project<P: 's>(
        self,
        select: for<'borrow> fn(&'borrow P) -> &'borrow S,
    ) -> Encryption<'s, P, T, K, Ctx> {
        let Self { build, shapes, .. } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx| {
                build(Source::lent(select(source.borrowed())), cipher, cx)
            }),
            shapes,
            mode: PhantomData,
        }
    }
    /// Store the context this description runs under, for a record that
    /// writes its context into the row (`#[stash(context_field)]`).
    ///
    /// The result takes a [`StoredContext`]: the context to store, and the
    /// context to run under. `store` builds the output from this
    /// description's output and the context to store.
    ///
    /// - On its own, the record stores the context the caller passes, and
    ///   runs under it.
    /// - As a field of a `struct = ..` record, it stores the field's own
    ///   context, and runs under the scopes and bindings of the record too.
    ///
    /// A field whose type cannot store the field's own context fails here,
    /// before any key is requested
    /// ([`PlanError::ContextNotStorable`](crate::PlanError::ContextNotStorable)).
    /// The plaintext is borrowed, so the refusal drops no plaintext. The
    /// [`Owned`] form of this method wipes the plaintext it is handed when
    /// the context is refused.
    ///
    /// **This method is for generated code.** The derive emits it at the
    /// root of a `#[stash(context_field)]` record.
    #[doc(hidden)]
    pub fn storing<C, U: 'static, F>(self, store: F) -> Encryption<'s, S, U, K, StoredContext<C>>
    where
        Ctx: From<CallerContext>,
        C: MaybeSend + 'static,
        F: FnOnce(T, C) -> U + MaybeSend + 'static,
    {
        self.storing_refusing(store, |source| drop(source))
    }
    /// Takes the context from a field of the plaintext. The caller then
    /// supplies no context.
    ///
    /// Use it for a value that arrives together with its context. For example,
    /// a value decrypted from an older format comes with the column it was
    /// stored in. A type that wraps the target names the field that contains
    /// the context, once. Callers of that type then encrypt without a context
    /// argument.
    ///
    /// The target must store its context in the row. In the types, its context
    /// input must be a typed context, `NonEmpty<C>`. A record with a
    /// `#[stash(context_field)]` has such an input. An EQL type has one too,
    /// and stores its column in `i`. So the context is read from the plaintext
    /// on the way in, and from the row on the way out.
    ///
    /// Opening a value never needs its plaintext.
    ///
    /// `pick` returns a reference to a field of the plaintext. So `pick` can
    /// only pass on a value that the plaintext contains. It cannot compute a
    /// context from the plaintext. `pick` is a plain function pointer, like the
    /// selector of [`project`](Self::project), so it cannot reach a cipher.
    ///
    /// The context must not be empty. If it is empty, the description fails.
    /// No key is requested.
    ///
    /// # Security
    ///
    /// The picked field is not secret. ZeroKMS receives it as the descriptor
    /// of the data key. A target that stores its context also writes it in
    /// the clear.
    ///
    /// Pick a field that says where the value belongs, such as its column.
    /// Never pick a field that is also sealed: its plaintext would then be
    /// stored outside the ciphertext. The compiler refuses that mistake when
    /// the context type differs from the type of the sealed value, as
    /// `Identifier` differs from `String`.
    ///
    /// ```
    /// use stack_encrypt::sem::EqualityTerm;
    /// use stack_encrypt::target::{EncryptTarget, Encryption, NoCallerContext};
    /// use stack_encrypt::{EncryptInto, NonEmpty, StackCipher};
    /// use zeroize::Zeroize;
    ///
    /// /// A value and the column it belongs to.
    /// struct Placed {
    ///     column: String,
    ///     value: String,
    /// }
    /// impl Zeroize for Placed {
    ///     // The column is not secret.
    ///     fn zeroize(&mut self) {
    ///         self.value.zeroize();
    ///     }
    /// }
    ///
    /// /// The stored form: the column in the clear, and the term of the value.
    /// #[derive(EncryptTarget)]
    /// #[stash(plaintext = String)]
    /// struct Stored {
    ///     #[stash(context_field)]
    ///     column: String,
    ///     hm: EqualityTerm,
    /// }
    ///
    /// /// `Stored`, encrypted from a `Placed`, under the column in the `Placed`.
    /// struct FromPlaced(Stored);
    /// impl EncryptTarget<Placed> for FromPlaced {
    ///     type ContextInput = NoCallerContext;
    ///     fn encryption<'s, K: 'static>() -> Encryption<'s, Placed, Self, K, NoCallerContext> {
    ///         <Stored as EncryptTarget<String>>::encryption()
    ///             .project(|placed: &Placed| &placed.value)
    ///             .context_from(|placed: &Placed| &placed.column)
    ///             .map(FromPlaced)
    ///     }
    /// }
    ///
    /// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
    /// // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
    /// // the environment, or from the profile that `npx stash auth login` writes.
    /// let cipher = StackCipher::builder()
    /// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
    ///     .init()
    ///     .await?;
    /// let keyset = cipher.default_keyset();
    /// let placed = Placed { column: "users/email".into(), value: "ada@example.com".into() };
    /// // No context argument: the context comes from `placed.column`.
    /// let FromPlaced(stored) = placed.encrypt_into(&keyset).await?;
    /// assert_eq!(stored.column, "users/email");
    ///
    /// // The same term as passing the column as the context.
    /// let direct: Stored = "ada@example.com"
    ///     .to_owned()
    ///     .encrypt_into_with_context(&keyset, NonEmpty::new("users/email".to_owned())?)
    ///     .await?;
    /// assert_eq!(stored.hm, direct.hm);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// # }).unwrap();
    /// ```
    ///
    /// `context_from` works in the [`Borrowed`] mode. Every
    /// `EncryptTarget::encryption` runs in that mode. The owned form of such a
    /// target wraps the plaintext and runs the borrowed form, so the owned
    /// form needs nothing more.
    pub fn context_from<C>(
        self,
        pick: for<'borrow> fn(&'borrow S) -> &'borrow C,
    ) -> Encryption<'s, S, T, K, NoCallerContext>
    where
        Ctx: AcceptsContext<Value = NonEmpty<C>>,
        C: Clone + MaybeEmpty + 's,
    {
        let Self { build, shapes, .. } = self;
        let shapes = contexts::substitute(
            shapes,
            &Shape::Placeholder(Placeholder::from_plaintext(
                "context",
                contexts::short_type_name::<NonEmpty<C>>(),
            )),
        );
        Encryption {
            build: Box::new(
                move |source, cipher, _: NoCallerContext| match super::context::nonempty(
                    pick(source.view()).clone(),
                ) {
                    Ok(context) => build(source, cipher, Ctx::supplied(context)),
                    Err(error) => Pending::failed(cipher, error),
                },
            ),
            shapes,
            mode: PhantomData,
        }
    }
    /// [`under`](Encryption::under) for a context read out of the source
    /// itself, as a plan whose context is a field of the value does: `own`
    /// reads the label from the borrowed source, or fails, in which case the
    /// description yields that error without I/O.
    ///
    /// Crate-internal: the data plan's lowering
    /// (`dynamic::planned::compose`) is its caller.
    ///
    /// `field` names the field of the source the label is read from, and
    /// `identity` the segment `own` joins to it, for
    /// [`contexts`](Self::contexts).
    #[cfg(feature = "dynamic")]
    pub(crate) fn under_by<G>(
        self,
        field: &str,
        identity: Option<&str>,
        own: G,
    ) -> Encryption<'s, S, T, K, DeclaredContext>
    where
        Ctx: From<CallerContext>,
        G: for<'b> FnOnce(&'b S) -> Result<crate::Label, Error> + MaybeSend + 's,
    {
        let Self { build, shapes, .. } = self;
        let shapes = contexts::substitute(
            shapes,
            &Shape::under_label(
                Placeholder::from_plaintext(field.to_owned(), "Label"),
                identity,
            ),
        );
        Encryption {
            build: Box::new(
                move |source, cipher, cx: DeclaredContext| match own(source.view()) {
                    Ok(label) => build(source, cipher, cx.under(NonEmpty::from(label)).into()),
                    Err(error) => Pending::failed(cipher, error),
                },
            ),
            shapes,
            mode: PhantomData,
        }
    }
    /// [`project`](Self::project) for a field picked by name at run time, as
    /// a data plan does: `select` may capture the name, and may fail
    /// (the value has no such field, or not of this type), in which case the
    /// description yields that error without I/O.
    ///
    /// Crate-internal: the data plan's lowering is its caller, and what
    /// `select` captures is a field name. The public combinator stays the
    /// capture-free `project`.
    #[cfg(feature = "dynamic")]
    pub(crate) fn project_by<P: 's, G>(self, select: G) -> Encryption<'s, P, T, K, Ctx>
    where
        G: for<'b> FnOnce(&'b P) -> Result<&'b S, Error> + MaybeSend + 's,
    {
        let Self { build, shapes, .. } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx| match select(source.borrowed()) {
                Ok(field) => build(Source::lent(field), cipher, cx),
                Err(error) => Pending::failed(cipher, error),
            }),
            shapes,
            mode: PhantomData,
        }
    }
}

impl<'s, S: 's, T: 'static, K: 'static, Ctx: 's> Encryption<'s, S, T, K, Ctx, Owned> {
    /// A description built from its execution closure, which is handed the
    /// plaintext by value. Crate-internal, as
    /// [`from_build`](Encryption::from_build) is, and for the same reason.
    /// The closure is responsible for wiping what it does not move into the
    /// output.
    pub(crate) fn from_owned_build<F>(shapes: Shapes, build: F) -> Self
    where
        F: for<'a, 'k> FnOnce(S, &'a KeysetCipher<'k, K>, Ctx) -> Pending<'a, T, K>
            + MaybeSend
            + 's,
    {
        Self {
            build: Box::new(move |source, cipher, cx| build(source.owned(), cipher, cx)),
            shapes,
            mode: PhantomData,
        }
    }
    /// [`project`](Self::project) for a plaintext passed by value. It turns a
    /// description of one field into a description of the struct that contains
    /// the field. `select` moves that field out of the struct.
    ///
    /// **This method is for generated code.** It is public because the derive
    /// emits it, and it is hidden from the docs. The derive calls it only when
    /// the plaintext has one field. Its pattern names every field of the
    /// plaintext, so no other field is left to drop.
    ///
    /// **The other fields of the struct are dropped without being wiped.** Use
    /// `project_owned` only for a struct whose other fields contain nothing
    /// secret. To encrypt a struct with more than one field, divide it with
    /// [`split`](Self::split). `split` passes every field on to a description.
    ///
    /// `select` is a plain function pointer, as the selector of `project` is.
    /// The function captures nothing, so it cannot reach a cipher. It can only
    /// move values.
    #[doc(hidden)]
    pub fn project_owned<P: 's>(self, select: fn(P) -> S) -> Encryption<'s, P, T, K, Ctx, Owned> {
        let Self { build, shapes, .. } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx| {
                build(Source::given(select(source.owned())), cipher, cx)
            }),
            shapes,
            mode: PhantomData,
        }
    }
    /// [`storing`](Encryption::storing) for a plaintext passed by value.
    ///
    /// A context that cannot be stored is refused before the description
    /// runs, as in the borrowed form. The refusal wipes the plaintext. That
    /// is why `S` must be `Zeroize`: a `serde_json::Value` cannot be the
    /// source here. Convert it to a [`JsonPlaintext`] first, with
    /// [`over_json_plaintext`](Encryption::over_json_plaintext).
    ///
    /// **This method is for generated and binding code.** The derive emits
    /// it at the root of the owned form of a `#[stash(context_field)]`
    /// record with one field, and `eql-bindings` seals a JSON tree document
    /// through it.
    #[doc(hidden)]
    pub fn storing<C, U: 'static, F>(
        self,
        store: F,
    ) -> Encryption<'s, S, U, K, StoredContext<C>, Owned>
    where
        Ctx: From<CallerContext>,
        C: MaybeSend + 'static,
        F: FnOnce(T, C) -> U + MaybeSend + 'static,
        S: zeroize::Zeroize,
    {
        self.storing_refusing(store, |source| {
            source.release(|value| drop(vitaminc_protected::Protected::new(value)))
        })
    }
    /// Divide a plaintext passed by value between two descriptions, under the
    /// one context this description is given. The key requests of both
    /// descriptions are made in one batch. This is the owned form of
    /// [`zip`](Self::zip), for two descriptions over two *different* parts of
    /// one value.
    ///
    /// `divide` is a plain function pointer. It destructures `P` into the part
    /// that `self` takes and the part that `other` takes. A record's
    /// `owned_encryption` divides the struct into its fields this way, with
    /// one `split` for each field.
    ///
    /// So a passthrough field is moved into the output and never copied.
    /// Each sealed field is guarded by its own
    /// target's description. Nothing is cloned, so `P` does not need to
    /// implement `Clone`.
    ///
    /// `self` runs first, while the part for `other` waits. If the description
    /// of `self` panics before `other` receives its part, that part is passed
    /// to `wipe` during the unwind. Without `wipe`, the part would be dropped
    /// as it is.
    ///
    /// `wipe` must wipe what `other` seals, and leave what `other` stores in
    /// the clear. So a part with only passthrough fields takes `|_| {}`. A
    /// part that is not sealed needs no `Zeroize` bound. Once `other` has its
    /// part, `other` is responsible for wiping it, as it is for any owned
    /// source.
    pub fn split<P: 's, U: 's, V: 'static>(
        self,
        other: Encryption<'s, U, V, K, Ctx, Owned>,
        divide: fn(P) -> (S, U),
        wipe: fn(&mut U),
    ) -> Encryption<'s, P, (T, V), K, Ctx, Owned>
    where
        Ctx: Clone,
    {
        let Self {
            build, mut shapes, ..
        } = self;
        let Encryption {
            build: other_build,
            shapes: other_shapes,
            ..
        } = other;
        shapes.extend(other_shapes);
        Encryption {
            build: Box::new(move |source, cipher, cx: Ctx| {
                let first_cx = cx.clone();
                let (mine, theirs) = divide(source.owned());
                let waiting = Waiting {
                    part: Some(theirs),
                    wipe,
                };
                let first = build(Source::given(mine), cipher, first_cx);
                first.zip(other_build(Source::given(waiting.hand_over()), cipher, cx))
            }),
            shapes,
            mode: PhantomData,
        }
    }
}

impl<'s, T: 'static, K: 'static, Ctx: 's> Encryption<'s, serde_json::Value, T, K, Ctx, Owned> {
    /// The same description, over a [`JsonPlaintext`] passed by value. The
    /// document is moved out of the `JsonPlaintext` and handed to this
    /// description, with no copy. This description then owns the document,
    /// and must wipe it: [`json_document`] and [`json_terms`] do.
    ///
    /// Nothing here returns the document to the caller, so no caller can
    /// take an unwiped `serde_json::Value` out of a `JsonPlaintext`.
    ///
    /// **This method is for generated and binding code.** `eql-bindings`
    /// seals a JSON tree document through it. A JSON target in this crate
    /// moves its document in the same way.
    #[doc(hidden)]
    pub fn over_json_plaintext(self) -> Encryption<'s, JsonPlaintext, T, K, Ctx, Owned> {
        self.project_owned(JsonPlaintext::into_value)
    }
}

/// The part of a [`split`](Encryption::split) value that waits while the
/// description of the other part runs. If it is dropped before
/// [`hand_over`](Self::hand_over), because that description unwound, it passes
/// the part to `wipe`.
struct Waiting<U> {
    part: Option<U>,
    wipe: fn(&mut U),
}

impl<U> Waiting<U> {
    /// The first description returned, so the part goes to its own
    /// description.
    fn hand_over(mut self) -> U {
        self.part
            .take()
            .unwrap_or_else(|| unreachable!("a waiting part is handed over once"))
    }
}

impl<U> Drop for Waiting<U> {
    fn drop(&mut self) {
        if let Some(part) = self.part.as_mut() {
            (self.wipe)(part);
        }
    }
}

/// A description whose operation is chosen by the value it is handed, at
/// the moment it runs: `choose` sees the source, the keyset cipher and the
/// context, and returns the pending of whichever typed operation applies.
///
/// Crate-internal, and deliberately so: this is the one constructor that
/// hands a closure the plaintext and the cipher together, which the public
/// constructors never do. Its one caller is the `dynamic` module, where a
/// value's type is known only at run time and the step that stays dynamic
/// is dispatching a runtime scalar to the typed term operation a Rust
/// caller would have named. Everything else about the field (its context,
/// its place in the record, its batching) is the engine's, as for any other
/// description.
#[cfg(feature = "dynamic")]
pub(crate) fn chosen<'s, S: 's, T: 'static, K: 'static, Ctx: 's, M: SourceMode<'s, S>, G>(
    choose: G,
) -> Encryption<'s, S, T, K, Ctx, M>
where
    G: for<'a, 'k, 'b> FnOnce(Source<'b, S>, &'a KeysetCipher<'k, K>, Ctx) -> Pending<'a, T, K>
        + MaybeSend
        + 's,
{
    Encryption {
        build: Box::new(choose),
        shapes: contexts::caller_leaf(),
        mode: PhantomData,
    }
}

/// A description that only checks the borrowed source, yielding `()` or the
/// error without I/O. Zipped beside a record's fields, a failed check fails
/// the whole record before any key is requested. Crate-internal: the data
/// plan's lowering uses it to refuse a value whose fields the plan does not
/// match.
#[cfg(feature = "dynamic")]
pub(crate) fn inspect<'s, S: 's, K: 'static, Ctx: 's, C>(check: C) -> Encryption<'s, S, (), K, Ctx>
where
    C: FnOnce(&S) -> Result<(), Error> + MaybeSend + 's,
{
    Encryption {
        build: Box::new(move |source, cipher, _| Pending::ready(cipher, check(source.view()))),
        shapes: Vec::new(),
        mode: PhantomData,
    }
}

impl<'s, S: 's, T: 'static, K: 'static, Ctx: 's + Clone + MaybeSend + 'static, M>
    Encryption<'s, S, T, K, Ctx, M>
where
    M: SourceMode<'s, S>,
{
    /// Build the output from the completed operations *and* the context they
    /// ran under.
    ///
    /// For a record that stores its own context in a field
    /// (`#[stash(context_field)]`): the context is supplied when the
    /// description runs, so the field it populates is filled there too.
    pub fn map_with_context<U: 'static, F>(self, f: F) -> Encryption<'s, S, U, K, Ctx, M>
    where
        F: FnOnce(T, Ctx) -> U + MaybeSend + 'static,
    {
        let Self { build, shapes, .. } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx: Ctx| {
                let carried = cx.clone();
                build(source, cipher, cx).map(move |value| f(value, carried))
            }),
            shapes,
            mode: PhantomData,
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
///
/// The plaintext is read in place and never copied. In the default
/// [`Borrowed`] mode it is walked as a borrow, and it stays with the caller.
/// In [`Owned`] mode it is walked by value, so Vitamin C wipes what the value
/// owns when the walk is done. A source is `Encrypt` both by value and by
/// reference, which is what the two bounds ask.
///
/// The context is checked before the plaintext is read. In [`Owned`] mode
/// a refused context wipes the value, so there `S` is `Zeroize`
/// ([`WipeSource`]).
pub fn ciphertext<'s, S, K: 'static, M: WipeSource<'s, S>>(
) -> Encryption<'s, S, StackCipherText, K, AeadContext, M>
where
    S: crate::Encrypt + EncryptRef + 's,
{
    Encryption {
        build: Box::new(move |source, cipher, cx: AeadContext| match cx.sealable() {
            Ok(ctx) => match source.into_held() {
                Held::Lent(source) => encrypt_native(source.lend(), cipher, ctx),
                Held::Given(source) => encrypt_native(source, cipher, ctx),
            },
            Err(e) => {
                M::wipe(source);
                Pending::failed(cipher, e)
            }
        }),
        shapes: contexts::caller_leaf(),
        mode: PhantomData,
    }
}
/// Encrypt a supported scalar, or an [`OpaqueBlob`](crate::OpaqueBlob), as
/// one opaque ciphertext, permitting empty context.
///
/// This operation borrows its source. The owned [`EncryptInto`](super::EncryptInto)
/// conversions supply a [`Protected`](vitaminc_protected::Protected) owner and
/// wipe it after planning. Calling [`KeysetCipher::run`] directly leaves source
/// cleanup with the caller; this operation alone does not wipe that borrow.
/// A blob is encoded here too, synchronously, so an encoding refusal is the
/// pending's result and no plaintext outlives this call in the pending.
/// Mapping the encrypted output preserves the scalar's optional-context policy;
/// it does not turn this into an EQL ciphertext or term operation. A wrapper may
/// require caller context with [`RequiredContext`](super::RequiredContext), or
/// declare a nonempty context with [`Encryption::under`].
pub fn scalar_ciphertext<'s, S: crate::OpaqueEncode, K: 'static>(
) -> Encryption<'s, S, crate::Ciphertext, K, super::OptionalContext<super::ScalarContext>> {
    Encryption {
        build: Box::new(
            move |source, cipher, context: super::OptionalContext<super::ScalarContext>| {
                let piece = context.piece();
                crate::scalar::sealed::Encode::seal(source.borrowed(), cipher, piece.clone())
                    .under_context(piece.clone(), piece)
            },
        ),
        shapes: contexts::caller_leaf(),
        mode: PhantomData,
    }
}

/// Carry the plaintext through unchanged: the output is the source itself,
/// and the context the description is handed is ignored.
///
/// This is a field that is present in a record's output so the record is
/// whole, and is **not encrypted and not authenticated**: nothing binds it
/// to the ciphertexts beside it, so whoever can write the stored record can
/// change it undetected. A field that must stay readable but be
/// tamper-evident is not a passthrough: seal it, with an equality index
/// beside it for lookup ([`indexed`](super::indexed) with
/// [`Equality`](super::Equality)).
///
/// In [`Owned`] mode the value is moved through. In the default
/// [`Borrowed`] mode the value is the caller's, so the output is a copy of
/// it, and `S` must be `Clone`. That is what `M: ConsumeSource<'s, S>` asks,
/// and no other operation asks for it. `Ctx` is whatever the surrounding tree
/// hands its fields, so a passthrough zips beside any of them.
pub fn passthrough<'s, S, K, M, Ctx>() -> Encryption<'s, S, S, K, Ctx, M>
where
    S: MaybeSend + 'static,
    K: 'static,
    M: ConsumeSource<'s, S>,
    Ctx: 's,
{
    Encryption {
        build: Box::new(move |source, cipher, _| Pending::ready(cipher, Ok(M::take(source)))),
        shapes: Vec::new(),
        mode: PhantomData,
    }
}
/// A term operation: `$function` produces `$output` from any `S` satisfying
/// the bounds, under the [`CallerContext`] the tree hands it.
///
/// Every term reads the plaintext in place, so it runs in either mode
/// without a copy. `$lend` is how a borrow of `S` becomes the source its
/// scheme reads. In [`Owned`] mode a `wipe` term hands the value to its
/// scheme, which wipes it. A `view` term (match) reads a borrow in either
/// mode through `$derive`, called as `Term::encrypt_from` is, and then
/// wipes a value it was handed. Either kind wipes a value it was handed
/// when the context is refused ([`WipeSource`]).
macro_rules! term_operation {
    (
        $(#[$doc:meta])*
        $function:ident, $output:ty, wipe($lend:expr), [$($generics:tt)*], [$($bounds:tt)*]
    ) => {
        $(#[$doc])*
        pub fn $function<'s, S, K: 'static, M: WipeSource<'s, S>, $($generics)*>(
        ) -> Encryption<'s, S, $output, K, CallerContext, M>
        where
            S: 's,
            $($bounds)*
        {
            Encryption {
                build: Box::new(move |source, cipher, cx: CallerContext| {
                    let (query, stored) = (cx.query(), cx.stored());
                    match cx.validated() {
                        Ok(ctx) => {
                            let context = CallerContext::query_nonempty(ctx);
                            match source.into_held() {
                                Held::Lent(source) => <$output as Term<_, K, _>>::encrypt_from(
                                    $lend(source),
                                    cipher,
                                    context,
                                ),
                                Held::Given(source) => <$output as Term<S, K, _>>::encrypt_from(
                                    source, cipher, context,
                                ),
                            }
                            .under_context(query, stored)
                        }
                        Err(e) => {
                            M::wipe(source);
                            Pending::failed(cipher, e)
                        }
                    }
                }),
                shapes: contexts::caller_leaf(),
                mode: PhantomData,
            }
        }
    };
    (
        $(#[$doc:meta])*
        $function:ident, $output:ty, view($derive:expr), [$($generics:tt)*], [$($bounds:tt)*]
    ) => {
        $(#[$doc])*
        pub fn $function<'s, S, K: 'static, M: WipeSource<'s, S>, $($generics)*>(
        ) -> Encryption<'s, S, $output, K, CallerContext, M>
        where
            S: 's,
            $($bounds)*
        {
            Encryption {
                build: Box::new(move |source, cipher, cx: CallerContext| {
                    // Wiped when the guard drops: after the read, and if
                    // the read panics.
                    let guarded = Guarded::<M, S>::new(source);
                    let (query, stored) = (cx.query(), cx.stored());
                    match cx.validated() {
                        Ok(ctx) => ($derive)(
                            guarded.source().view(),
                            cipher,
                            CallerContext::query_nonempty(ctx),
                        )
                        .under_context(query, stored),
                        Err(e) => Pending::failed(cipher, e),
                    }
                }),
                shapes: contexts::caller_leaf(),
                mode: PhantomData,
            }
        }
    };
}
term_operation!(
    /// The equality term of `S` under the context the tree hands it. Requires
    /// only that `S` describes itself (`Encrypt`), as one scalar with an
    /// equality domain; not recoverable encryption.
    equality, crate::sem::EqualityTerm, wipe(EncryptRef::lend), [], [S: crate::Encrypt + EncryptRef]
);
term_operation!(
    /// The match term of any text `S` under the context the tree hands it,
    /// tokenised and hashed as `O` declares: a stored value's filter, which
    /// holds every token the text cuts.
    matching, crate::sem::MatchTerms<O>,
    view(<crate::sem::MatchTerms<O> as Term<&S, K, _>>::encrypt_from),
    [O: crate::sem::MatchConfig + 'static], [S: AsRef<str>]
);
term_operation!(
    /// The match term a query of the text `S` sends, under the context the
    /// tree hands it: the filter of the tokens the query keeps, which a
    /// stored filter holds when the row holds them. With
    /// [`short_words`](crate::sem::MatchOptions::short_words) on, a query's
    /// short words are tokens of the filter only when it cuts no n-gram:
    /// "Ng" asks for the word `ng`, and "Mike Ng" for its trigrams alone, so
    /// it finds "Mike Nguyen" as well as "Mike Ng". With the option off it
    /// is [`matching`]'s term.
    ///
    /// What a field query of a match index derives
    /// ([`Index::query_operation`](super::Index::query_operation)). It
    /// refuses nothing [`matching`] does not: a query is prepared first
    /// ([`Supports::prepare`](crate::op::Supports::prepare)), which refuses
    /// text that cuts no token.
    matching_query, crate::sem::MatchTerms<O>,
    view(crate::sem::match_query),
    [O: crate::sem::MatchConfig + 'static], [S: AsRef<str>]
);
term_operation!(
    /// The order-revealing term of `S` under the context the tree hands it.
    /// The bound is the leaf's own: it says which `S` has an order target.
    ore, crate::sem::OreTerm<S>, wipe(std::convert::identity), [],
    [S: crate::Orderable + EncryptRef + 'static]
);
term_operation!(
    /// The order-preserving term of `S` under the context the tree hands it,
    /// with the same bounds as [`ore`].
    ope, crate::sem::OpeTerm<S>, wipe(std::convert::identity), [],
    [S: crate::Orderable + EncryptRef + 'static]
);
term_operation!(
    /// The block ORE term of `S` under the context the tree hands it, with
    /// the same bounds as [`ore`].
    ore_block, crate::sem::OreBlockTerm<S>, wipe(std::convert::identity), [],
    [S: crate::Orderable + EncryptRef + 'static]
);

/// The JSON index's terms of a document under the context the tree hands
/// it: every node's selectors, the chain tokens and the grouping
/// ([`JsonTerms`]), derived locally. No key is requested, and the document
/// is only read, so this runs in any source mode without a copy. What
/// [`Json`](struct@super::Json)'s [`Index::operation`](super::Index::operation)
/// is, and what a query derives.
pub fn json_terms<'s, K: 'static, M: SourceMode<'s, serde_json::Value>>(
    options: JsonOptions,
) -> Encryption<'s, serde_json::Value, JsonTerms, K, CallerContext, M> {
    Encryption {
        shapes: contexts::caller_leaf(),
        build: Box::new(move |source, cipher, cx: CallerContext| {
            let (query, stored) = (cx.query(), cx.stored());
            let pending = match cx.validated() {
                Ok(ctx) => crate::json::terms_pending(
                    source.view(),
                    &options,
                    cipher,
                    CallerContext::query_nonempty(ctx),
                )
                .under_context(query, stored),
                Err(e) => Pending::failed(cipher, e),
            };
            // The terms are derived by now; a document this description
            // owns (the one a query asks about) is wiped rather than dropped.
            source.release(|value| drop(crate::json::PlainJson::protect(value)));
            pending
        }),
        mode: PhantomData,
    }
}

/// The JSON index's one sealing operation: flatten the document, derive
/// its terms, request one data key under the context's descriptor and seal
/// every node under it, into a [`JsonDocument`]. The stored form of a JSON
/// field; what [`JsonDocument`]'s own [`EncryptTarget<JsonPlaintext>`] runs. The
/// document is read in place. In [`Owned`] mode it is wiped once it is
/// sealed, and when the context is refused. In [`Borrowed`] mode it is
/// copied only when the keyset is not loaded yet: the sealing then keeps
/// its own copy until the keyset arrives, and wipes it.
pub fn json_document<'s, K: 'static, M: SourceMode<'s, serde_json::Value>>(
    options: JsonOptions,
) -> Encryption<'s, serde_json::Value, JsonDocument, K, CallerContext, M> {
    Encryption {
        build: Box::new(move |source, cipher, cx: CallerContext| {
            let (query, stored) = (cx.query(), cx.stored());
            match cx.validated() {
                Ok(ctx) => {
                    let (query_context, stored_context) = CallerContext::both_nonempty(ctx);
                    // The sealing wipes a document it is given.
                    crate::json::seal_pending(
                        source,
                        &options,
                        cipher,
                        query_context,
                        stored_context,
                    )
                    .under_context(query, stored)
                }
                Err(e) => {
                    source.release(|value| drop(crate::json::PlainJson::protect(value)));
                    Pending::failed(cipher, e)
                }
            }
        }),
        shapes: contexts::caller_leaf(),
        mode: PhantomData,
    }
}

/// A [`JsonPlaintext`] seals into a document as the JSON index lays it out
/// under the default options, and declares that index.
///
/// The context is required. It is the column the document is stored in,
/// and every selector is derived under it:
///
/// ```
/// # async fn example() -> Result<(), stack_encrypt::Error> {
/// use serde_json::json;
/// use stack_encrypt::json::{JsonDocument, JsonPlaintext};
/// use stack_encrypt::kms::FakeDataKeySource;
/// use stack_encrypt::{nonempty, DecryptFrom, EncryptInto, StackCipher};
///
/// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
/// let column = nonempty!("users").with("profile");
///
/// let profile = JsonPlaintext::from(json!({"name": "Ada", "age": 35}));
/// let document: JsonDocument = profile
///     .encrypt_into_with_context(&cipher.default_keyset(), column.clone())
///     .await?;
///
/// let opened = JsonPlaintext::decrypt_from_with_context(document, &cipher, column).await?;
/// assert_eq!(opened.value()["name"], "Ada");
/// # Ok(())
/// # }
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
/// ```
///
/// The plaintext is wiped when the document has been sealed, and when the
/// context is refused. `encrypt_into` moves the document into the sealing,
/// and the sealing reads it in place. A borrowed document is read in place
/// too. It is copied only when the keyset is not loaded yet: the sealing
/// then keeps one copy until the keyset arrives, and wipes it.
impl EncryptTarget<JsonPlaintext> for JsonDocument {
    type ContextInput = RequiredContext<CallerContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, JsonPlaintext, Self, K, Self::ContextInput>
    where
        JsonPlaintext: 's,
    {
        json_document(JsonOptions::default())
            .project(JsonPlaintext::value)
            .accepting()
    }
    fn owned_encryption<'s, K: 'static>(
    ) -> Encryption<'s, JsonPlaintext, Self, K, Self::ContextInput, Owned>
    where
        JsonPlaintext: 's,
    {
        json_document::<K, Owned>(JsonOptions::default())
            .over_json_plaintext()
            .accepting()
    }
    fn indexes() -> Vec<super::IndexSpec> {
        vec![super::IndexSpec::Json(JsonOptions::default())]
    }
}

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
    /// A description whose opening is `open`: a crate-internal target
    /// that builds its own key requests (the JSON index's documents) runs
    /// through here, as [`open`] does for a native tree.
    ///
    /// The output is recovered plaintext, so the pending is marked as one
    /// that can be wiped, as [`open`]'s is. A [`zip`](Self::zip) or an
    /// [`all`](Self::all) this description is part of then wipes the output
    /// when a later item fails.
    pub(crate) fn from_open<F>(open: F) -> Self
    where
        F: for<'a> FnOnce(&'a StackCipher<K>) -> Pending<'a, T, K> + MaybeSend + 'static,
        T: zeroize::Zeroize,
    {
        Self::open(Box::new(move |cipher| open(cipher).wiping()))
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
    ///
    /// When the right side fails after the left side recovered plaintext,
    /// the left side's plaintext is wiped before the error is returned, if
    /// the left side is an [`open`] or a target's own decryption. A
    /// description built with [`ready`](Self::ready) or [`map`](Self::map)
    /// is not wiped: its output is dropped as it is.
    pub fn zip<U: 'static>(self, other: Decryption<U, K>) -> Decryption<(T, U), K> {
        match (self.inner, other.inner) {
            (Opening::Failed(error), _) | (_, Opening::Failed(error)) => Decryption::failed(error),
            (Opening::Open(left), Opening::Open(right)) => {
                Decryption::open(Box::new(move |cipher| left(cipher).zip(right(cipher))))
            }
        }
    }
    /// [`zip`](Self::zip) for recovered plaintext. The right side can fail
    /// after its key arrives, or panic in its conversion. The plaintext that
    /// the left side recovered is then wiped, not dropped as it is. A record
    /// that derives `DecryptSource` opens its fields through this method. So a
    /// field opened before a later field is refused is wiped when the refusal
    /// is returned.
    pub fn zip_wiping<U: 'static>(self, other: Decryption<U, K>) -> Decryption<(T, U), K>
    where
        T: zeroize::Zeroize,
    {
        match (self.inner, other.inner) {
            (Opening::Failed(error), _) | (_, Opening::Failed(error)) => Decryption::failed(error),
            (Opening::Open(left), Opening::Open(right)) => {
                Decryption::open(Box::new(move |cipher| {
                    left(cipher).zip_wiping(right(cipher))
                }))
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
    ///
    /// When an item fails after the items before it recovered plaintext,
    /// each of those items that is an [`open`] or a target's own decryption
    /// is wiped before the error is returned, as [`zip`](Self::zip) does for
    /// its left side.
    pub fn all<I>(items: I) -> Decryption<Vec<T>, K>
    where
        I: IntoIterator<Item = Self>,
    {
        match Self::openings(items) {
            Err(error) => Decryption::failed(error),
            Ok(opens) => Decryption::open(Box::new(move |cipher| {
                Pending::collect(cipher, opens.into_iter().map(|open| open(cipher)))
            })),
        }
    }
    /// The same as [`all`](Self::all), but for recovered plaintext. When an
    /// item fails after its key arrived, `all` drops the items recovered
    /// before it. This function wipes them. The owned `Vec<S>` conversions
    /// decrypt through this function.
    pub(crate) fn all_wiping<I>(items: I) -> Decryption<Vec<T>, K>
    where
        I: IntoIterator<Item = Self>,
        T: zeroize::Zeroize,
    {
        match Self::openings(items) {
            Err(error) => Decryption::failed(error),
            Ok(opens) => Decryption::open(Box::new(move |cipher| {
                Pending::collect_wiping(cipher, opens.into_iter().map(|open| open(cipher)))
            })),
        }
    }
    /// The openings of `items`, up to the first description that fails. If a
    /// description fails, this returns its error, and the descriptions after
    /// it are never built.
    fn openings<I>(items: I) -> Result<Vec<Open<T, K>>, Error>
    where
        I: IntoIterator<Item = Self>,
    {
        let mut opens = Vec::new();
        for item in items {
            match item.inner {
                Opening::Failed(error) => return Err(error),
                Opening::Open(open) => opens.push(open),
            }
        }
        Ok(opens)
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
    /// Run this opening through `cipher_ref`. Through a [`KeysetCipher`],
    /// a leaf from any other keyset is refused. Through a [`StackCipher`],
    /// leaves from any keyset are opened.
    ///
    /// The opening builds its pending through the client, which opens
    /// leaves from any keyset. So the pending is then confined to the
    /// keyset of `cipher_ref`, when it has one.
    pub(super) fn open_in<'a>(self, cipher_ref: impl Into<CipherRef<'a, K>>) -> Pending<'a, T, K> {
        let cipher_ref: CipherRef<'a, K> = cipher_ref.into();
        let pending = match self.inner {
            Opening::Failed(error) => return Pending::failed(cipher_ref, error),
            Opening::Open(open) => open(cipher_ref.cipher()),
        };
        pending.confined_to(cipher_ref.keyset())
    }
}
/// The canonical opening operation: retrieve the tree's keys and decode `P`
/// through its own Vitamin C `Decrypt` implementation, under `context`.
///
/// `P` is recovered plaintext, so it must be `Zeroize`: a
/// [`Decryption::zip`] or [`Decryption::all`] that holds this opening wipes
/// its output when a later item fails after this one's key arrived.
pub fn open<P: crate::Decrypt + zeroize::Zeroize + Send + 'static, K: 'static>(
    tree: StackCipherText,
    context: impl Into<AeadContext>,
) -> Decryption<P, K> {
    let context = context.into();
    Decryption::open(Box::new(move |cipher| match context.validated() {
        Ok(ctx) => open_native(tree, cipher, ctx).wiping(),
        Err(e) => Pending::failed(cipher, e),
    }))
}

impl<K: 'static> KeysetCipher<'_, K> {
    /// Run a description held in a variable over `source`, under `context`.
    ///
    /// `source` is what the description's mode hands its operations: `&S`
    /// for a [`Borrowed`]-mode description (the default), or `S` itself for
    /// an [`Owned`]-mode one. Neither mode copies the plaintext. In owned
    /// mode the description takes the value, and wipes it once it is read.
    /// A caller that keeps the value after the call runs it borrowed.
    ///
    /// ```
    /// # async fn example() -> Result<(), stack_encrypt::Error> {
    /// use stack_encrypt::target::{self, AeadContext, Owned};
    /// use stack_encrypt::{nonempty, StackCipher, StackCipherText};
    /// use vitaminc_protected::Protected;
    ///
    /// // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
    /// // the environment, or from the profile that `npx stash auth login` writes.
    /// let cipher = StackCipher::builder()
    /// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
    ///     .init()
    ///     .await?;
    /// let keyset = cipher.default_keyset();
    /// // `Protected<String>` is deliberately not `Clone`: it is moved in, and
    /// // the one copy is wiped once it is sealed.
    /// let card = Protected::new(String::from("4111 1111 1111 1111"));
    /// let sealed: StackCipherText = keyset
    ///     .run(
    ///         target::ciphertext::<_, _, Owned>(),
    ///         card,
    ///         AeadContext::from(nonempty!("cards/number")),
    ///     )
    ///     .await?;
    /// # let _ = sealed;
    /// # Ok(())
    /// # }
    /// # tokio_test_block_on(example()).unwrap();
    /// # fn tokio_test_block_on<F: std::future::Future>(f: F) -> F::Output {
    /// #     tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
    /// # }
    /// ```
    ///
    /// The opening side is [`run_decryption`](Self::run_decryption): an
    /// [`Encryption`] is run with its source and context, a [`Decryption`]
    /// already holds both. Either is single-use; a saved plan builds a fresh
    /// one per call.
    ///
    /// A borrowed source is `&'s S`, tied to the description's own lifetime
    /// `'s`, so a description fixed at one `'s` can only run over sources
    /// that live that long. A boxed, reusable description must therefore
    /// keep `'s` higher-ranked or be created per call. Creating a fresh
    /// description for each call is the simpler choice.
    pub fn run<'a, 's, S: 's, T: 'static, Ctx, M: SourceMode<'s, S>>(
        &'a self,
        encryption: Encryption<'s, S, T, K, Ctx, M>,
        source: M::Source,
        context: Ctx,
    ) -> Pending<'a, T, K> {
        (encryption.build)(M::source(source), self, context)
    }
    /// Run a [`Decryption`] held in a variable under this keyset: the
    /// counterpart of [`run`](Self::run), and what
    /// [`DecryptFrom`](super::DecryptFrom) does with a type's declaration. A
    /// leaf sealed under another keyset is refused
    /// ([`Error::ForeignKeyset`]) before any key is retrieved.
    ///
    /// ```
    /// # async fn example() -> Result<(), stack_encrypt::Error> {
    /// use stack_encrypt::target::{self, AeadContext, Decryption};
    /// use stack_encrypt::{nonempty, EncryptInto, StackCipher, StackCipherText};
    ///
    /// // With no `.kms(..)`, the cipher uses ZeroKMS. It reads credentials from
    /// // the environment, or from the profile that `npx stash auth login` writes.
    /// let cipher = StackCipher::builder()
    /// #     .kms(stack_encrypt::kms::FakeDataKeySource::new())
    ///     .init()
    ///     .await?;
    /// let keyset = cipher.default_keyset();
    /// let context = || AeadContext::from(nonempty!("users/email"));
    /// let sealed: StackCipherText = "bob@example.com"
    ///     .to_string()
    ///     .encrypt_into_with_context(&keyset, context())
    ///     .await?;
    ///
    /// let opening: Decryption<String, _> = target::open(sealed, context());
    /// assert_eq!(keyset.run_decryption(opening).await?, "bob@example.com");
    /// # Ok(())
    /// # }
    /// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
    /// ```
    pub fn run_decryption<'a, P: 'static>(
        &'a self,
        decryption: Decryption<P, K>,
    ) -> Pending<'a, P, K> {
        decryption.open_in(self)
    }
}
impl<K: 'static> StackCipher<K> {
    /// Run a [`Decryption`] held in a variable through the client: leaves
    /// from any of its keysets open here. See
    /// [`KeysetCipher::run_decryption`], which refuses a foreign one.
    pub fn run_decryption<'a, P: 'static>(
        &'a self,
        decryption: Decryption<P, K>,
    ) -> Pending<'a, P, K> {
        decryption.open_in(self)
    }
}

// The owned declarations of the same leaves. Each one requires the context its
// operation needs, as the caller's required input: a ciphertext needs an
// `AeadContext`, and a term needs a `CallerContext`. A call cannot leave the
// context out, because a structural leaf takes no empty context. `Default`
// does not change that.
//
// The borrowed form of a ciphertext reads the plaintext in place, as the
// structural declaration does. The owned form of a ciphertext is handed the
// value and seals it. When the context is refused, it wipes the value.
//
// The owned term targets keep the default owned form. It guards the value and
// runs the borrowed form over it, so each term reads the value in place. A
// term derives no descriptor, so no context is refused there.
impl<S: crate::Encrypt + EncryptRef + zeroize::Zeroize> EncryptTarget<S> for StackCipherText {
    type ContextInput = RequiredContext<AeadContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
    where
        S: 's,
    {
        ciphertext().accepting()
    }
    fn owned_encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput, Owned>
    where
        S: 's,
    {
        ciphertext().accepting()
    }
}
impl<P: crate::Decrypt + zeroize::Zeroize + Send + 'static> DecryptSource<P> for StackCipherText {
    type ContextInput = RequiredContext<AeadContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<P, K> {
        open(self, context.into_inner())
    }
}
impl<S: crate::Encrypt + EncryptRef + zeroize::Zeroize> EncryptTarget<S>
    for crate::sem::EqualityTerm
{
    type ContextInput = RequiredContext<CallerContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
    where
        S: 's,
    {
        equality().accepting()
    }
    fn indexes() -> Vec<super::IndexSpec> {
        vec![super::IndexSpec::Equality]
    }
}
impl<S: AsRef<str> + zeroize::Zeroize, O: crate::sem::MatchConfig + 'static> EncryptTarget<S>
    for crate::sem::MatchTerms<O>
{
    type ContextInput = RequiredContext<CallerContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
    where
        S: 's,
    {
        matching().accepting()
    }
    fn indexes() -> Vec<super::IndexSpec> {
        vec![super::IndexSpec::Match(O::options())]
    }
}
macro_rules! owned_order_term {
    ($($ty:ident, $operation:ident, $spec:ident;)+) => {$(
        impl<S: crate::Orderable + EncryptRef + zeroize::Zeroize + 'static> EncryptTarget<S>
            for crate::sem::$ty<S>
        {
            type ContextInput = RequiredContext<CallerContext>;
            fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
            where
                S: 's,
            {
                $operation().accepting()
            }
            fn indexes() -> Vec<super::IndexSpec> {
                vec![super::IndexSpec::$spec]
            }
        }
    )+};
}
owned_order_term! {
    OreTerm, ore, Ore;
    OpeTerm, ope, Ope;
    OreBlockTerm, ore_block, OreBlock;
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
impl<P: zeroize::Zeroize + 'static, Ctx> DecryptField<P, Ctx> for StackCipherText
where
    Self: DecryptSource<P>,
    Ctx: Into<<Self as DecryptSource<P>>::ContextInput>,
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<P, K>> {
        Some(<Self as DecryptSource<P>>::decryption(self, context.into()))
    }
}
impl<
        P: zeroize::Zeroize + 'static,
        T: 'static + Decryptable + DecryptField<P, Ctx>,
        Ctx: Clone + 'static,
    > DecryptField<Vec<P>, Ctx> for Vec<T>
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<Vec<P>, K>> {
        if !T::DECRYPTABLE {
            return None;
        }
        Some(Decryption::all_wiping(self.into_iter().map(|item| {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{nonempty, sem::EqualityTerm, EncryptInto};
    use stack_kms::FakeDataKeySource;

    #[tokio::test]
    async fn an_optional_ciphertext_field_recovers_present_and_absent_values() {
        let cipher = StackCipher::builder()
            .kms(FakeDataKeySource::new())
            .init()
            .await
            .unwrap();
        let keyset = cipher.default_keyset();
        let context = || AeadContext::from(nonempty!("users/nickname"));

        for expected in [Some("secret nickname".to_string()), None] {
            let sealed: Option<StackCipherText> = match &expected {
                Some(value) => Some(
                    value
                        .clone()
                        .encrypt_into_with_context(&keyset, context())
                        .await
                        .unwrap(),
                ),
                None => None,
            };
            let opening: Decryption<Option<String>, FakeDataKeySource> = sealed
                .decryption_field(context())
                .expect("an optional ciphertext is a recoverable field even when absent");
            assert_eq!(
                opening.open_in(&keyset).await.unwrap(),
                expected,
                "opening should recover the value that was sealed, or its absence"
            );
        }
    }

    #[test]
    fn an_optional_term_is_never_a_recoverable_field() {
        for term in [Some(EqualityTerm::from_bytes([7; 32])), None] {
            let opening: Option<Decryption<Option<String>, FakeDataKeySource>> =
                term.decryption_field(CallerContext::from(nonempty!("users/nickname")));
            assert!(opening.is_none(), "a term cannot recover plaintext");
        }
    }

    #[test]
    fn operation_debug_describes_the_operation_without_its_captured_value() {
        let encryption: Encryption<'_, (), _, (), ()> = Encryption::ready(Ok("secret metadata"));
        assert_eq!(
            format!("{encryption:?}"),
            "Encryption { .. }",
            "a ready encryption should not print its captured value"
        );

        let decryption = Decryption::<_, ()>::ready("secret plaintext");
        assert_eq!(
            format!("{decryption:?}"),
            "Decryption { .. }",
            "a ready decryption should not print its plaintext"
        );
        let failure = Decryption::<(), ()>::failed(Error::NotOpened);
        assert_eq!(
            format!("{failure:?}"),
            "Decryption { failed: NotOpened, .. }",
            "a failed decryption should name its error and nothing else"
        );
    }
}
