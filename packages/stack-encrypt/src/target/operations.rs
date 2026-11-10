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
//! by name, with [`Encryption::under`] or [`Encryption::extend`]. A subtree
//! can also read its context from a named field of the plaintext, with
//! [`Encryption::context_from`].
use super::context::{AeadContext, CallerContext, DeclaredContext, Extends};
use super::conversion::{DecryptSource, EncryptTarget};
use super::core::{encrypt_native, open_native, Term};
use super::index::{Index, IndexSpec, Json};
use super::input::{AcceptsContext, NoCallerContext, RequiredContext};
use super::source::{Borrowed, ConsumeSource, Owned, ShareSource, SourceMode};
use super::{CipherScope, Pending};
use crate::contexts::{self, Contexts, Placeholder, Shape, Shapes, SuppliedContext};
use crate::json::{JsonDocument, JsonOptions, JsonTerms};
use crate::{Error, IntoContext, KeysetCipher, MaybeEmpty, NonEmpty, StackCipher, StackCipherText};
use stack_kms::MaybeSend;
use std::fmt;

/// Declaration that an encrypted target is produced from `S`.
///
/// The derive supplies it; a hand-written implementation composes the
/// constructors in this module ([`ciphertext`], [`equality`], [`matching`],
/// [`ore`], [`ope`], [`ore_block`]) and converts their output with [`Encryption::map`] or
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
    /// The indexes this target's terms answer queries by, as data, under
    /// the context the target is run under: what a plan field typed with
    /// this target ([`encrypt_into`](crate::plan::FieldsBuilder::encrypt_into))
    /// lets a query ask for. A query for any other index is refused rather
    /// than derived, since it would match nothing.
    ///
    /// The default is none, which is right for a ciphertext and for a record
    /// whose fields sit under contexts of their own; a term, an
    /// [`Encrypted<Terms>`](super::Encrypted) and a tuple of targets name
    /// theirs.
    fn indexes() -> Vec<super::IndexSpec> {
        vec![]
    }
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

// What the description is handed is `M::Source`: `&'s S` in the default
// `Borrowed` mode, `S` itself in `Owned` mode (see `SourceMode`).
#[cfg(not(target_arch = "wasm32"))]
type Build<'s, S, T, K, Ctx, M> = Box<
    dyn for<'a, 'k> FnOnce(
            <M as SourceMode<'s, S>>::Source,
            &'a KeysetCipher<'k, K>,
            Ctx,
        ) -> Pending<'a, T, K>
        + Send
        + 's,
>;
#[cfg(target_arch = "wasm32")]
type Build<'s, S, T, K, Ctx, M> = Box<
    dyn for<'a, 'k> FnOnce(
            <M as SourceMode<'s, S>>::Source,
            &'a KeysetCipher<'k, K>,
            Ctx,
        ) -> Pending<'a, T, K>
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
/// by reference in the default [`Borrowed`] mode, which every
/// [`EncryptFrom`] declaration runs in, or by value in
/// [`Owned`] mode, run with [`KeysetCipher::run`]. In owned mode
/// a single operation consumes the plaintext without copying it, so `S` need
/// not be `Clone`; [`zip`](Self::zip) is the one place that asks for it.
#[must_use = "an encryption description does nothing until a keyset cipher executes it"]
pub struct Encryption<'s, S: 's, T, K, Ctx, M: SourceMode<'s, S> = Borrowed> {
    build: Build<'s, S, T, K, Ctx, M>,
    /// The context of each leaf, in terms of the context this description
    /// is handed. Kept beside the closure by every combinator, so
    /// [`contexts`](Self::contexts) shows what the closure will do.
    shapes: Shapes,
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
        F: for<'a, 'k> FnOnce(M::Source, &'a KeysetCipher<'k, K>, Ctx) -> Pending<'a, T, K>
            + MaybeSend
            + 's,
    {
        Self {
            build: Box::new(build),
            shapes,
        }
    }
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
        contexts::resolve(self.shapes.clone(), Ctx::placeholder())
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
        }
    }
    /// Reject the declaration: execution yields `error` without I/O, and any
    /// description this is zipped into fails with it.
    pub fn failed(error: Error) -> Self {
        Self {
            build: Box::new(move |_, cipher, _| Pending::failed(cipher, error)),
            shapes: Vec::new(),
        }
    }
    /// Build the destination from the completed output. `f` sees ciphertext
    /// and terms, never the plaintext.
    pub fn map<U: 'static, F>(self, f: F) -> Encryption<'s, S, U, K, Ctx, M>
    where
        F: FnOnce(T) -> U + MaybeSend + 'static,
    {
        let Self { build, shapes } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx| build(source, cipher, cx).map(f)),
            shapes,
        }
    }
    /// [`map`](Self::map) for a conversion that can fail, such as reading
    /// native output into a destination that does not accept every shape.
    pub fn try_map<U: 'static, F>(self, f: F) -> Encryption<'s, S, U, K, Ctx, M>
    where
        F: FnOnce(T) -> Result<U, Error> + MaybeSend + 'static,
    {
        let Self { build, shapes } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx| build(source, cipher, cx).try_map(f)),
            shapes,
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
    /// from a target's two halves (ADR-0004, decision 1).
    ///
    /// Both sides also receive the same plaintext. In the default
    /// [`Borrowed`] mode that is the same reference, and costs nothing. In
    /// [`Owned`] mode this side gets a clone and `other` takes
    /// ownership, so a chain of `n` operations makes `n - 1` copies rather
    /// than `n`, and only here does an owned plaintext need to be `Clone`.
    /// In Owned mode, a match term next to an operation that consumes the
    /// value still needs `S: Clone`.
    pub fn zip<U: 'static>(
        self,
        other: Encryption<'s, S, U, K, Ctx, M>,
    ) -> Encryption<'s, S, (T, U), K, Ctx, M>
    where
        Ctx: Clone,
        M: ShareSource<'s, S>,
    {
        let Self { build, mut shapes } = self;
        let Encryption {
            build: other_build,
            shapes: other_shapes,
        } = other;
        shapes.extend(other_shapes);
        Encryption {
            build: Box::new(move |source, cipher, cx| {
                let (mine, theirs) = M::share(source);
                build(mine, cipher, cx.clone()).zip(other_build(theirs, cipher, cx))
            }),
            shapes,
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
        let Self { build, shapes } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx| build(source, cipher, derive(cx))),
            shapes,
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
    pub fn under(
        mut self,
        own: NonEmpty<impl IntoContext<'static> + MaybeSend + 's>,
    ) -> Encryption<'s, S, T, K, DeclaredContext, M>
    where
        Ctx: From<CallerContext>,
    {
        let own = contexts::piece_of(own);
        self.shapes = contexts::substitute(self.shapes, &Shape::under(own.get().clone()));
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
}

impl<'s, S: 's, T: 'static, K: 'static, Ctx: 's> Encryption<'s, S, T, K, Ctx> {
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
        let Self { build, shapes } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx| build(select(source), cipher, cx)),
            shapes,
        }
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
    /// use stack_encrypt::kms::FakeDataKeySource;
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
    /// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
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
        let Self { build, shapes } = self;
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
                    pick(source).clone(),
                ) {
                    Ok(context) => build(source, cipher, Ctx::supplied(context)),
                    Err(error) => Pending::failed(cipher, error),
                },
            ),
            shapes,
        }
    }
    /// [`under`](Encryption::under) for a context read out of the source
    /// itself, as a plan whose context is a field of the value does: `own`
    /// reads the label from the borrowed source, or fails, in which case the
    /// description yields that error without I/O.
    ///
    /// Crate-internal: the plan builder is its one caller.
    ///
    /// `field` names the field of the source the label is read from, and
    /// `identity` the segment `own` joins to it, for
    /// [`contexts`](Self::contexts).
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
        let Self { build, shapes } = self;
        let shapes = contexts::substitute(
            shapes,
            &Shape::under_label(
                Placeholder::from_plaintext(field.to_owned(), "Label"),
                identity,
            ),
        );
        Encryption {
            build: Box::new(
                move |source, cipher, cx: DeclaredContext| match own(source) {
                    Ok(label) => build(source, cipher, cx.under(NonEmpty::from(label)).into()),
                    Err(error) => Pending::failed(cipher, error),
                },
            ),
            shapes,
        }
    }
    /// [`under`](Encryption::under) for a context the call names, which a
    /// plan built without one takes. The description fails with `error`
    /// if it runs, and shows the call's context as a placeholder.
    ///
    /// Crate-internal: the plan builder is its one caller, for
    /// [`contexts`](Self::contexts) on such a plan.
    pub(crate) fn under_call(
        self,
        identity: Option<&str>,
        error: Error,
    ) -> Encryption<'s, S, T, K, DeclaredContext>
    where
        Ctx: From<CallerContext>,
    {
        let shapes = contexts::substitute(
            self.shapes,
            &Shape::under_label(Placeholder::required("context", "Label"), identity),
        );
        Encryption {
            build: Box::new(move |_, cipher, _: DeclaredContext| Pending::failed(cipher, error)),
            shapes,
        }
    }
    /// [`project`](Self::project) for a field picked by name at run time, as
    /// a plan's `fields()` does: `select` may capture the name, and may fail
    /// (the value has no such field, or not of this type), in which case the
    /// description yields that error without I/O.
    ///
    /// Crate-internal: the plan builder is its one caller, and what `select`
    /// captures is a field name. The public combinator stays the
    /// capture-free `project`.
    pub(crate) fn project_by<P: 's, G>(self, select: G) -> Encryption<'s, P, T, K, Ctx>
    where
        G: for<'b> FnOnce(&'b P) -> Result<&'b S, Error> + MaybeSend + 's,
    {
        let Self { build, shapes } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx| match select(source) {
                Ok(field) => build(field, cipher, cx),
                Err(error) => Pending::failed(cipher, error),
            }),
            shapes,
        }
    }
}

impl<'s, S: 's, T: 'static, K: 'static, Ctx: 's> Encryption<'s, S, T, K, Ctx, Owned> {
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
        let Self { build, shapes } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx| build(select(source), cipher, cx)),
            shapes,
        }
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
        let Self { build, mut shapes } = self;
        let Encryption {
            build: other_build,
            shapes: other_shapes,
        } = other;
        shapes.extend(other_shapes);
        Encryption {
            build: Box::new(move |source, cipher, cx: Ctx| {
                let first_cx = cx.clone();
                let (mine, theirs) = divide(source);
                let waiting = Waiting {
                    part: Some(theirs),
                    wipe,
                };
                let first = build(mine, cipher, first_cx);
                first.zip(other_build(waiting.hand_over(), cipher, cx))
            }),
            shapes,
        }
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
    G: for<'a, 'k> FnOnce(M::Source, &'a KeysetCipher<'k, K>, Ctx) -> Pending<'a, T, K>
        + MaybeSend
        + 's,
{
    Encryption::from_build(contexts::caller_leaf(), choose)
}

/// A description that only checks the borrowed source, yielding `()` or the
/// error without I/O. Zipped beside a record's fields, a failed check fails
/// the whole record before any key is requested. Crate-internal: the plan
/// builder uses it to refuse a value whose fields the plan does not match.
pub(crate) fn inspect<'s, S: 's, K: 'static, Ctx: 's, C>(check: C) -> Encryption<'s, S, (), K, Ctx>
where
    C: FnOnce(&S) -> Result<(), Error> + MaybeSend + 's,
{
    Encryption {
        build: Box::new(move |source, cipher, _| Pending::ready(cipher, check(source))),
        shapes: Vec::new(),
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
        let Self { build, shapes } = self;
        Encryption {
            build: Box::new(move |source, cipher, cx: Ctx| {
                let carried = cx.clone();
                build(source, cipher, cx).map(move |value| f(value, carried))
            }),
            shapes,
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
/// `Encrypt` consumes the plaintext. In [`Owned`] mode it is
/// handed over, so `S` need not be `Clone`; in the default [`Borrowed`] mode
/// it is cloned once, which is what `M: ConsumeSource<'s, S>` asks.
///
/// The context is checked before the plaintext is taken. So in [`Borrowed`]
/// mode a refused context makes no copy. In [`Owned`] mode a refused context
/// drops the value without wiping it, because `S` need not be `Zeroize`. The
/// owned declarations of this crate's leaves wipe it instead.
pub fn ciphertext<'s, S: crate::Encrypt + 's, K: 'static, M: ConsumeSource<'s, S>>(
) -> Encryption<'s, S, StackCipherText, K, AeadContext, M> {
    sealing(drop)
}
/// [`ciphertext`] for a plaintext that is wiped when the context is refused.
/// The owned declarations of [`StackCipherText`] and
/// [`Encrypted`](crate::Encrypted) run this form.
pub(crate) fn wiping_ciphertext<'s, S, K: 'static, M: ConsumeSource<'s, S>>(
) -> Encryption<'s, S, StackCipherText, K, AeadContext, M>
where
    S: crate::Encrypt + zeroize::Zeroize + 's,
{
    sealing(|source| {
        M::release(source, |value| {
            drop(vitaminc_protected::Protected::new(value))
        })
    })
}
/// The body of [`ciphertext`]. `refused` is given the source when the context
/// is refused. The check runs before [`ConsumeSource::take`], so a refused
/// context never makes a copy of the plaintext.
fn sealing<'s, S: crate::Encrypt + 's, K: 'static, M: ConsumeSource<'s, S>>(
    refused: fn(M::Source),
) -> Encryption<'s, S, StackCipherText, K, AeadContext, M> {
    Encryption {
        build: Box::new(move |source, cipher, cx: AeadContext| match cx.sealable() {
            Ok(ctx) => encrypt_native(M::take(source), cipher, ctx),
            Err(e) => {
                refused(source);
                Pending::failed(cipher, e)
            }
        }),
        shapes: contexts::caller_leaf(),
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
                crate::scalar::sealed::Encode::seal(source, cipher, piece.clone())
                    .under_context(piece)
            },
        ),
        shapes: contexts::caller_leaf(),
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
/// In [`Owned`] mode the value is moved through; in the
/// default [`Borrowed`] mode it is cloned once, which is what
/// `M: ConsumeSource<'s, S>` asks. `Ctx` is whatever the surrounding tree
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
    }
}
/// A term operation: `$function` produces `$output` from any `S` satisfying
/// the bounds, under the [`CallerContext`] the tree hands it.
///
/// `consume` terms (equality, ORE, OPE) take the plaintext by value, as their
/// scheme does, so they ask the same `M: ConsumeSource<'s, S>` as
/// [`ciphertext`]. A `view` term (match) only reads it, so it works in any
/// mode and never clones.
macro_rules! term_operation {
    (
        $(#[$doc:meta])*
        $function:ident, $output:ty, consume, [$($generics:tt)*], [$($bounds:tt)*]
    ) => {
        $(#[$doc])*
        pub fn $function<'s, S, K: 'static, M: ConsumeSource<'s, S>, $($generics)*>(
        ) -> Encryption<'s, S, $output, K, CallerContext, M>
        where
            S: 's,
            $($bounds)*
        {
            Encryption {
                build: Box::new(move |source, cipher, cx: CallerContext| {
                    let piece = cx.piece().clone();
                    match cx.validated() {
                        Ok(ctx) => <$output as Term<S, K, _>>::encrypt_from(M::take(source), cipher, ctx)
                            .under_context(piece),
                        Err(e) => Pending::failed(cipher, e),
                    }
                }),
                shapes: contexts::caller_leaf(),
            }
        }
    };
    (
        $(#[$doc:meta])*
        $function:ident, $output:ty, view, [$($generics:tt)*], [$($bounds:tt)*]
    ) => {
        $(#[$doc])*
        pub fn $function<'s, S, K: 'static, M: SourceMode<'s, S>, $($generics)*>(
        ) -> Encryption<'s, S, $output, K, CallerContext, M>
        where
            S: 's,
            $($bounds)*
        {
            Encryption {
                build: Box::new(move |source, cipher, cx: CallerContext| {
                    let piece = cx.piece().clone();
                    match cx.validated() {
                        Ok(ctx) => <$output as Term<&S, K, _>>::encrypt_from(M::view(&source), cipher, ctx)
                            .under_context(piece),
                        Err(e) => Pending::failed(cipher, e),
                    }
                }),
                shapes: contexts::caller_leaf(),
            }
        }
    };
}
term_operation!(
    /// The equality term of `S` under the context the tree hands it. Requires
    /// only that `S` describes itself (`Encrypt`), as one scalar with an
    /// equality domain; not recoverable encryption.
    equality, crate::sem::EqualityTerm, consume, [], [S: crate::Encrypt]
);
term_operation!(
    /// The match term of any text `S` under the context the tree hands it,
    /// tokenised and hashed as `O` declares.
    matching, crate::sem::MatchTerms<O>, view, [O: crate::sem::MatchConfig + 'static], [S: AsRef<str>]
);
term_operation!(
    /// The order-revealing term of `S` under the context the tree hands it.
    /// The bound is the leaf's own: it says which `S` has an order target.
    ore, crate::sem::OreTerm<S>, consume, [],
    [S: crate::sem::Orderable]
);
term_operation!(
    /// The order-preserving term of `S` under the context the tree hands it,
    /// with the same bounds as [`ore`].
    ope, crate::sem::OpeTerm<S>, consume, [],
    [S: crate::sem::Orderable]
);
term_operation!(
    /// The block ORE term of `S` under the context the tree hands it, with
    /// the same bounds as [`ore`].
    ore_block, crate::sem::OreBlockTerm<S>, consume, [],
    [S: crate::sem::Orderable]
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
            let piece = cx.piece().clone();
            let pending = match cx.validated() {
                Ok(ctx) => crate::json::terms_pending(M::view(&source), &options, cipher, ctx)
                    .under_context(piece),
                Err(e) => Pending::failed(cipher, e),
            };
            // The terms are derived by now; a document this description
            // owns (the one a query asks about) is wiped rather than dropped.
            M::release(source, |value| drop(crate::json::PlainJson::protect(value)));
            pending
        }),
    }
}

/// The JSON index's one sealing operation: flatten the document, derive
/// its terms, request one data key under the context's descriptor and seal
/// every node under it, into a [`JsonDocument`]. The stored form of a JSON
/// field; what [`JsonDocument`]'s own [`EncryptFrom<Value>`] runs. The
/// document is consumed, so in the default [`Borrowed`] mode it is cloned
/// once, as [`ciphertext`] clones its plaintext.
pub fn json_document<'s, K: 'static, M: ConsumeSource<'s, serde_json::Value>>(
    options: JsonOptions,
) -> Encryption<'s, serde_json::Value, JsonDocument, K, CallerContext, M> {
    Encryption {
        build: Box::new(move |source, cipher, cx: CallerContext| {
            let piece = cx.piece().clone();
            match cx.validated() {
                Ok(ctx) => crate::json::seal_pending(M::take(source), &options, cipher, ctx)
                    .under_context(piece),
                Err(e) => Pending::failed(cipher, e),
            }
        }),
        shapes: contexts::caller_leaf(),
    }
}

/// A target's layout, chosen by value rather than by type.
///
/// Most targets have one layout, fixed by their type: the type's
/// [`EncryptFrom`] says what is sealed and which terms sit beside it, and
/// a plan uses it with
/// [`encrypt_into::<T>()`](crate::plan::ValueStart::encrypt_into). A
/// target that takes options needs more than a type, and a layout is the
/// value that carries them.
///
/// The JSON index is the layout this crate provides. `Json::new(options)`
/// seals the same [`JsonDocument`] as `encrypt_into::<JsonDocument>()`,
/// but under `options` instead of the defaults: for example, with the
/// leaves at `$.age` ordered, so that a query can compare them.
///
/// A plan takes a layout with
/// [`encrypt_with_layout`](crate::plan::ValueStart::encrypt_with_layout).
/// A query through that plan uses the layout's index ([`Layout::index`]),
/// so it derives under the same options without naming them again.
///
/// ```
/// # async fn example() -> Result<(), stack_encrypt::Error> {
/// use serde_json::json;
/// use stack_encrypt::json::{JsonDocument, JsonOptions};
/// use stack_encrypt::kms::FakeDataKeySource;
/// use stack_encrypt::sem::TermError;
/// use stack_encrypt::target::Json;
/// use stack_encrypt::{op, Error, Plan, StackCipher};
///
/// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
/// let profile = json!({"name": "Bob", "age": 34});
///
/// // By value: the JSON index with `$.age` ordered.
/// let options = JsonOptions::default().ordering(["$.age"])?;
/// let ordered = Plan::value::<serde_json::Value>()
///     .context("users/profile")
///     .encrypt_with_layout(Json::new(options))
///     .build()?;
/// let doc: JsonDocument = cipher.encrypt(&profile).using(&ordered).await?;
/// // The leaf at `$.age` carries an ordering term...
/// assert_eq!(doc.entries().iter().filter(|e| e.ordering_term().is_some()).count(), 1);
/// // ...and a query through the plan derives under the same options.
/// let _adults = cipher.query(op::AtPath(op::Gte), &("$.age", 18)).on(&ordered).await?;
///
/// // By type: the same target under the default options, which order no
/// // path, so the same query is refused.
/// let unordered = Plan::value::<serde_json::Value>()
///     .context("users/profile")
///     .encrypt_into::<JsonDocument>()
///     .build()?;
/// let refused = cipher.query(op::AtPath(op::Gte), &("$.age", 18)).on(&unordered).await;
/// assert!(matches!(refused, Err(Error::Term(TermError::JsonPathNotOrdered))));
/// # Ok(())
/// # }
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(example()).unwrap();
/// ```
///
/// A layout belongs to a plan. The cipher's
/// [`encrypt_as`](crate::KeysetCipher::encrypt_as) is a different layer:
/// it seals one value as a target type's own `EncryptFrom` does, with no
/// plan and no options.
pub trait Layout<S>: Clone + fmt::Debug + 'static {
    /// What a run produces: the target the layout seals a value into.
    type Target: EncryptFrom<S>;
    /// The index a query through the plan runs through: the layout
    /// itself, for an index with options.
    type Index: Index<S> + Clone;
    /// The description the cipher executes for one value of `S`, under
    /// this layout's options.
    fn encryption<'s, K: 'static>(
        &self,
    ) -> Encryption<'s, S, Self::Target, K, <Self::Target as EncryptFrom<S>>::Context>
    where
        S: 's;
    /// The index, with its options.
    fn index(&self) -> &Self::Index;
    /// The indexes the plan declares, as data: the index's.
    fn specs(&self) -> Vec<IndexSpec> {
        vec![self.index().spec()]
    }
}

/// The JSON index seals a [`JsonDocument`] under its options, and is the
/// index a query through the plan runs through.
impl Layout<serde_json::Value> for Json {
    type Target = JsonDocument;
    type Index = Json;
    fn encryption<'s, K: 'static>(
        &self,
    ) -> Encryption<'s, serde_json::Value, JsonDocument, K, CallerContext>
    where
        serde_json::Value: 's,
    {
        json_document(self.options.clone())
    }
    fn index(&self) -> &Json {
        self
    }
}

/// A JSON document seals as the JSON index lays it out under the default
/// options, and declares that index: a plan typed with it answers
/// containment and the accessors through [`Json`](struct@super::Json).
impl EncryptFrom<serde_json::Value> for JsonDocument {
    type Context = CallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, serde_json::Value, Self, K, Self::Context>
    where
        serde_json::Value: 's,
    {
        json_document(JsonOptions::default())
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
    pub(crate) fn from_open<F>(open: F) -> Self
    where
        F: for<'a> FnOnce(&'a StackCipher<K>) -> Pending<'a, T, K> + MaybeSend + 'static,
    {
        Self::open(Box::new(open))
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
    /// Execute under a scope. A [`KeysetCipher`] scope refuses a leaf from any
    /// other keyset; a [`StackCipher`] scope opens leaves from any.
    pub(super) fn open_in<'a>(self, scope: impl CipherScope<'a, K>) -> Pending<'a, T, K> {
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
pub fn open<P: crate::Decrypt + Send + 'static, K: 'static>(
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
    /// Run a description held in a variable over `source`, under `context`.
    ///
    /// `source` is what the description's mode hands its operations: `&S`
    /// for a [`Borrowed`]-mode description (the default, and what
    /// [`encrypt_as`](Self::encrypt_as) runs for a type), or `S` itself for
    /// an [`Owned`]-mode one. Owned mode is how a plaintext
    /// that is not `Clone` reaches an operation: a single operation consumes
    /// it without a copy.
    ///
    /// ```
    /// # async fn example() -> Result<(), stack_encrypt::Error> {
    /// use stack_encrypt::kms::FakeDataKeySource;
    /// use stack_encrypt::target::{self, AeadContext, Owned};
    /// use stack_encrypt::{nonempty, StackCipher, StackCipherText};
    /// use vitaminc_protected::Protected;
    ///
    /// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
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
    /// keep `'s` higher-ranked (as `plan::Lower` does, with a phantom
    /// `PhantomData<&'s ()>` argument) or be created per call.
    pub fn run<'a, 's, S: 's, T: 'static, Ctx, M: SourceMode<'s, S>>(
        &'a self,
        encryption: Encryption<'s, S, T, K, Ctx, M>,
        source: M::Source,
        context: Ctx,
    ) -> Pending<'a, T, K> {
        (encryption.build)(source, self, context)
    }
    /// Run a [`Decryption`] held in a variable under this keyset: the
    /// counterpart of [`run`](Self::run), and what
    /// [`decrypt_as`](Self::decrypt_as) does with a type's declaration. A
    /// leaf sealed under another keyset is refused
    /// ([`Error::ForeignKeyset`]) before any key is retrieved.
    ///
    /// ```
    /// # async fn example() -> Result<(), stack_encrypt::Error> {
    /// use stack_encrypt::kms::FakeDataKeySource;
    /// use stack_encrypt::target::{self, AeadContext, Decryption};
    /// use stack_encrypt::{nonempty, StackCipher, StackCipherText};
    ///
    /// let cipher = StackCipher::builder().kms(FakeDataKeySource::new()).init().await?;
    /// let keyset = cipher.default_keyset();
    /// let context = || AeadContext::from(nonempty!("users/email"));
    /// let sealed: StackCipherText = keyset.encrypt_as(&"bob@example.com".to_string(), context()).await?;
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
    /// Run a [`Decryption`] held in a variable through the client: leaves
    /// from any of its keysets open here. See
    /// [`KeysetCipher::run_decryption`], which refuses a foreign one.
    pub fn run_decryption<'a, P: 'static>(
        &'a self,
        decryption: Decryption<P, K>,
    ) -> Pending<'a, P, K> {
        decryption.open_in(self)
    }
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
pub trait LegacyEncryptInto: Sized {
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
impl<T> LegacyEncryptInto for T {}
/// Source-side call syntax for `decrypt_as`, implemented for every type:
/// `stored.decrypt_into(&cipher, ctx)`. Targets implement [`DecryptInto`],
/// never these methods.
pub trait LegacyDecryptFrom: Sized + 'static {
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
impl<T: 'static> LegacyDecryptFrom for T {}

// The leaf declarations below keep `Clone` on purpose. An `EncryptFrom`
// declaration runs in the `Borrowed` mode (`encrypt_as` hands it `&S`), and an
// operation that consumes a borrowed plaintext must clone it: the bound is
// `Borrowed: ConsumeSource<'s, S>`, spelled out. The constructors themselves
// (`ciphertext`, `equality`, `ore`, `ope`) ask only for the scheme's own
// capability, and run a non-`Clone` plaintext in `Owned` mode.
impl<S: crate::Encrypt + Clone> EncryptFrom<S> for StackCipherText {
    type Context = AeadContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        ciphertext()
    }
}
impl<P: crate::Decrypt + Send + 'static> DecryptInto<P> for StackCipherText {
    type Context = AeadContext;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<P, K> {
        open(self, context)
    }
}
impl<S: crate::Encrypt + Clone> EncryptFrom<S> for crate::sem::EqualityTerm {
    type Context = CallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        equality()
    }
    fn indexes() -> Vec<super::IndexSpec> {
        vec![super::IndexSpec::Equality]
    }
}
impl<S: AsRef<str>, O: crate::sem::MatchConfig + 'static> EncryptFrom<S>
    for crate::sem::MatchTerms<O>
{
    type Context = CallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        matching()
    }
    fn indexes() -> Vec<super::IndexSpec> {
        vec![super::IndexSpec::Match(O::options())]
    }
}
impl<S> EncryptFrom<S> for crate::sem::OreTerm<S>
where
    S: crate::sem::Orderable + Clone,
{
    type Context = CallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        ore()
    }
    fn indexes() -> Vec<super::IndexSpec> {
        vec![super::IndexSpec::Ore]
    }
}
impl<S> EncryptFrom<S> for crate::sem::OpeTerm<S>
where
    S: crate::sem::Orderable + Clone,
{
    type Context = CallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        ope()
    }
    fn indexes() -> Vec<super::IndexSpec> {
        vec![super::IndexSpec::Ope]
    }
}
impl<S> EncryptFrom<S> for crate::sem::OreBlockTerm<S>
where
    S: crate::sem::Orderable + Clone,
{
    type Context = CallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::Context>
    where
        S: 's,
    {
        ore_block()
    }
    fn indexes() -> Vec<super::IndexSpec> {
        vec![super::IndexSpec::OreBlock]
    }
}

// The owned declarations of the same leaves. Each one requires the context its
// operation needs, as the caller's required input: a ciphertext needs an
// `AeadContext`, and a term needs a `CallerContext`. A call cannot leave the
// context out, because a structural leaf takes no empty context. `Default`
// does not change that.
//
// The borrowed form of a ciphertext clones the plaintext, as the structural
// declaration does. It checks the context first, so a refused context makes no
// copy. The owned form of a ciphertext is handed the value and seals it without
// a copy. When the context is refused, it wipes the value.
//
// The owned term targets keep the default owned form. It guards the value and
// runs the borrowed form over it, so each term takes a copy. A term derives no
// descriptor, so no context is refused there. Each term scheme consumes its
// copy.
impl<S: crate::Encrypt + Clone + zeroize::Zeroize> EncryptTarget<S> for StackCipherText {
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
        wiping_ciphertext().accepting()
    }
}
impl<P: crate::Decrypt + zeroize::Zeroize + Send + 'static> DecryptSource<P> for StackCipherText {
    type ContextInput = RequiredContext<AeadContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<P, K> {
        open(self, context.into_inner())
    }
}
impl<S: crate::Encrypt + Clone + zeroize::Zeroize> EncryptTarget<S> for crate::sem::EqualityTerm {
    type ContextInput = RequiredContext<CallerContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
    where
        S: 's,
    {
        equality().accepting()
    }
    fn indexes() -> Vec<super::IndexSpec> {
        <Self as EncryptFrom<S>>::indexes()
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
        <Self as EncryptFrom<S>>::indexes()
    }
}
macro_rules! owned_order_term {
    ($($ty:ident, $operation:ident;)+) => {$(
        impl<S: crate::sem::Orderable + Clone + zeroize::Zeroize> EncryptTarget<S> for crate::sem::$ty<S> {
            type ContextInput = RequiredContext<CallerContext>;
            fn encryption<'s, K: 'static>() -> Encryption<'s, S, Self, K, Self::ContextInput>
            where
                S: 's,
            {
                $operation().accepting()
            }
            fn indexes() -> Vec<super::IndexSpec> {
                <Self as EncryptFrom<S>>::indexes()
            }
        }
    )+};
}
owned_order_term! {
    OreTerm, ore;
    OpeTerm, ope;
    OreBlockTerm, ore_block;
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
            shapes: T::encryption::<K>().shapes(),
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
            shapes: T::encryption::<K>().shapes(),
            build: Box::new(move |source, cipher, cx: T::Context| match source {
                Some(item) => cipher.encrypt_as(item, cx).map(Some),
                None => Pending::ready(cipher, Ok(None)),
            }),
        }
    }
}
// Opened through `all_wiping`, as the owned `Vec<T>` is. If an element fails
// after its key arrives, the column fails, and the elements recovered before
// it are wiped. That is why `P` must implement `Zeroize`. Every plaintext the
// engine decrypts into already implements it.
impl<P: zeroize::Zeroize + 'static, T: DecryptInto<P> + 'static> DecryptInto<Vec<P>> for Vec<T>
where
    T::Context: Clone + 'static,
{
    type Context = T::Context;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Vec<P>, K> {
        Decryption::all_wiping(
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
        Some(<Self as DecryptInto<P>>::decryption(self, context.into()))
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
    use crate::{nonempty, sem::EqualityTerm};
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
                Some(value) => Some(keyset.encrypt_as(value, context()).await.unwrap()),
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
