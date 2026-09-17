//! Core-owned operation descriptions: what a target declares, and the cipher
//! executes. No constructor here accepts a plaintext-and-cipher callback; a
//! description selects core operations and converts their completed output,
//! nothing more.
use super::context::{AeadContext, CallerContext};
use super::core::{encrypt_native, open_native, Term};
use super::{CipherScope, Pending};
use crate::{Error, KeysetCipher, StackCipher, StackCipherText};
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
    /// What a caller supplies alongside the plaintext: a [`CallerContext`] or
    /// [`AeadContext`] for a generic target, a `NonEmpty<T>` for a record that
    /// stores its identifier, or `()` when the declaration carries every
    /// context it needs.
    type Context;
    /// The description the cipher executes for one value of `S`.
    fn encryption<'s, K: 'static>(context: Self::Context) -> Encryption<'s, S, Self, K>
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
type Build<'s, S, T, K> =
    Box<dyn for<'a, 'k> FnOnce(&S, &'a KeysetCipher<'k, K>) -> Pending<'a, T, K> + Send + 's>;
#[cfg(target_arch = "wasm32")]
type Build<'s, S, T, K> =
    Box<dyn for<'a, 'k> FnOnce(&S, &'a KeysetCipher<'k, K>) -> Pending<'a, T, K> + 's>;
#[cfg(not(target_arch = "wasm32"))]
type Open<T, K> = Box<dyn for<'a> FnOnce(&'a StackCipher<K>) -> Pending<'a, T, K> + Send>;
#[cfg(target_arch = "wasm32")]
type Open<T, K> = Box<dyn for<'a> FnOnce(&'a StackCipher<K>) -> Pending<'a, T, K>>;

/// A composable description of how `T` is encrypted from `S`.
///
/// Built from the constructors in this module and the combinators below;
/// executed only by [`KeysetCipher::encrypt_as`]. Nothing runs, and no key is
/// requested, until then.
#[must_use = "an encryption description does nothing until a keyset cipher executes it"]
pub struct Encryption<'s, S, T, K> {
    build: Build<'s, S, T, K>,
}
/// A composable description of how `T` is recovered from a stored target.
///
/// Built from [`open`] and the combinators below; executed only by
/// `decrypt_as`. Nothing runs, and no key is retrieved, until then.
#[must_use = "a decryption description does nothing until a cipher executes it"]
pub struct Decryption<T, K> {
    open: Open<T, K>,
}
impl<S, T, K> fmt::Debug for Encryption<'_, S, T, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encryption").finish_non_exhaustive()
    }
}
impl<T, K> fmt::Debug for Decryption<T, K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decryption").finish_non_exhaustive()
    }
}

impl<'s, S: 's, T: 'static, K: 'static> Encryption<'s, S, T, K> {
    /// A description whose output is already known — metadata a record
    /// carries, or a declaration rejected before any key request.
    pub fn ready(result: Result<T, Error>) -> Self
    where
        T: MaybeSend,
    {
        Self {
            build: Box::new(move |_, cipher| Pending::ready(cipher, result)),
        }
    }
    /// Reject the declaration: execution yields `error` without I/O, and any
    /// description this is zipped into fails with it.
    pub fn failed(error: Error) -> Self {
        Self {
            build: Box::new(move |_, cipher| Pending::failed(cipher, error)),
        }
    }
    /// Build the destination from the completed output. `f` sees ciphertext
    /// and terms, never the plaintext.
    pub fn map<U: 'static, F>(self, f: F) -> Encryption<'s, S, U, K>
    where
        F: FnOnce(T) -> U + MaybeSend + 'static,
    {
        Encryption {
            build: Box::new(move |source, cipher| (self.build)(source, cipher).map(f)),
        }
    }
    /// [`map`](Self::map) for a conversion that can fail, such as reading
    /// native output into a destination that does not accept every shape.
    pub fn try_map<U: 'static, F>(self, f: F) -> Encryption<'s, S, U, K>
    where
        F: FnOnce(T) -> Result<U, Error> + MaybeSend + 'static,
    {
        Encryption {
            build: Box::new(move |source, cipher| (self.build)(source, cipher).try_map(f)),
        }
    }
    /// Drive the destination's [`Visitor`](super::transcode::Visitor) from
    /// this operation's native output, moving leaves and markers across
    /// without an intermediate tree.
    pub fn transcode<U: super::transcode::Transcode + 'static>(self) -> Encryption<'s, S, U, K>
    where
        T: super::transcode::Reader,
    {
        self.try_map(|output| super::transcode::Reader::read(output, U::visitor()))
    }
    /// Run both descriptions over the same source, settling their key
    /// requests in one batch.
    pub fn zip<U: 'static>(self, other: Encryption<'s, S, U, K>) -> Encryption<'s, S, (T, U), K> {
        Encryption {
            build: Box::new(move |source, cipher| {
                (self.build)(source, cipher).zip((other.build)(source, cipher))
            }),
        }
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
    ) -> Encryption<'s, P, T, K> {
        Encryption {
            build: Box::new(move |source, cipher| (self.build)(select(source), cipher)),
        }
    }
}

/// The canonical ciphertext operation: seal `S` under `context` through its
/// own Vitamin C `Encrypt` implementation, into the native
/// [`StackCipherText`] tree. There is no Serde fallback; a plaintext without
/// `Encrypt` does not compile.
pub fn ciphertext<'s, S: crate::Encrypt + Clone + 's, K: 'static>(
    context: impl Into<AeadContext>,
) -> Encryption<'s, S, StackCipherText, K> {
    let context = context.into();
    Encryption {
        build: Box::new(move |source, cipher| match context.validated() {
            Ok(ctx) => encrypt_native(source, cipher, ctx),
            Err(e) => Pending::failed(cipher, e),
        }),
    }
}
macro_rules! term_operation {
    (
        $(#[$doc:meta])*
        $function:ident, $output:ty, [$($generics:tt)*], [$($bounds:tt)*]
    ) => {
        $(#[$doc])*
        pub fn $function<'s, S, K: 'static, $($generics)*>(
            context: impl Into<CallerContext>,
        ) -> Encryption<'s, S, $output, K>
        where
            S: 's,
            $($bounds)*
        {
            let context = context.into();
            Encryption {
                build: Box::new(move |source, cipher| match context.validated() {
                    Ok(ctx) => <$output as Term<S, K, _>>::encrypt_from(source, cipher, ctx),
                    Err(e) => Pending::failed(cipher, e),
                }),
            }
        }
    };
}
term_operation!(
    /// The equality term of `S` under `context`. Requires only `S`'s PRF
    /// contract, not recoverable encryption.
    equality, crate::sem::EqualityTerm, [], [S: vitaminc_prf::PrfValue + Clone]
);
term_operation!(
    /// The match term of any text `S` under `context`, tokenised and hashed
    /// as `O` declares.
    matching, crate::sem::MatchTerm<O>, [O: crate::sem::MatchConfig + 'static], [S: AsRef<str>]
);
term_operation!(
    /// The order-revealing term of `S` under `context`. The bounds are the
    /// leaf's own: they say which `S` the CLLW ORE scheme can order.
    ore, crate::sem::OreTerm<S>, [],
    [S: cllw_ore::CllwOreEncrypt + Clone + Send + 'static, S::Output: Send + 'static]
);
term_operation!(
    /// The order-preserving term of `S` under `context`, with the same
    /// bounds as [`ore`].
    ope, crate::sem::OpeTerm<S>, [],
    [S: cllw_ore::CllwOpeEncrypt + Clone + Send + 'static, S::Output: Send + 'static]
);

impl<T: 'static, K: 'static> Decryption<T, K> {
    /// Reject the opening: execution yields `error` without I/O, and any
    /// description this is zipped into fails with it. The derives use it
    /// when a stored context fails validation.
    pub fn failed(error: Error) -> Self {
        Self {
            open: Box::new(move |cipher| Pending::failed(cipher, error)),
        }
    }
    /// A description whose output is already known: a defaulted field, or
    /// an absent optional.
    pub fn ready(value: T) -> Self
    where
        T: MaybeSend,
    {
        Self {
            open: Box::new(move |cipher| Pending::ready(cipher, Ok(value))),
        }
    }
    /// Convert the recovered value.
    pub fn map<U: 'static, F>(self, f: F) -> Decryption<U, K>
    where
        F: FnOnce(T) -> U + MaybeSend + 'static,
    {
        Decryption {
            open: Box::new(move |cipher| (self.open)(cipher).map(f)),
        }
    }
    /// Open both, retrieving their keys in one batch.
    pub fn zip<U: 'static>(self, other: Decryption<U, K>) -> Decryption<(T, U), K> {
        Decryption {
            open: Box::new(move |cipher| (self.open)(cipher).zip((other.open)(cipher))),
        }
    }
    /// Open every description, retrieving all their keys in one batch, and
    /// collect the results in order.
    pub fn all<I>(items: I) -> Decryption<Vec<T>, K>
    where
        I: IntoIterator<Item = Self>,
    {
        let items: Vec<Self> = items.into_iter().collect();
        Decryption {
            open: Box::new(move |cipher| {
                Pending::collect(cipher, items.into_iter().map(|item| (item.open)(cipher)))
            }),
        }
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
        let pending = (self.open)(scope.cipher());
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
    Decryption {
        open: Box::new(move |cipher| match context.validated() {
            Ok(ctx) => open_native(tree, cipher, ctx),
            Err(e) => Pending::failed(cipher, e),
        }),
    }
}

impl<K: 'static> KeysetCipher<'_, K> {
    /// Encrypt `source` into `T` under this keyset, as `T`'s declaration
    /// describes. The returned [`Pending`] settles every key request the
    /// declaration made in one batch.
    pub fn encrypt_as<'a, S, T>(&'a self, source: &S, context: T::Context) -> Pending<'a, T, K>
    where
        T: EncryptFrom<S>,
    {
        (T::encryption(context).build)(source, self)
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
    fn encryption<'s, K: 'static>(context: Self::Context) -> Encryption<'s, S, Self, K>
    where
        S: 's,
    {
        ciphertext(context)
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
    fn encryption<'s, K: 'static>(context: Self::Context) -> Encryption<'s, S, Self, K>
    where
        S: 's,
    {
        equality(context)
    }
}
impl<S: AsRef<str>, O: crate::sem::MatchConfig + 'static> EncryptFrom<S>
    for crate::sem::MatchTerm<O>
{
    type Context = CallerContext;
    fn encryption<'s, K: 'static>(context: Self::Context) -> Encryption<'s, S, Self, K>
    where
        S: 's,
    {
        matching(context)
    }
}
impl<S> EncryptFrom<S> for crate::sem::OreTerm<S>
where
    S: cllw_ore::CllwOreEncrypt + Clone + Send + 'static,
    S::Output: Send + 'static,
{
    type Context = CallerContext;
    fn encryption<'s, K: 'static>(context: Self::Context) -> Encryption<'s, S, Self, K>
    where
        S: 's,
    {
        ore(context)
    }
}
impl<S> EncryptFrom<S> for crate::sem::OpeTerm<S>
where
    S: cllw_ore::CllwOpeEncrypt + Clone + Send + 'static,
    S::Output: Send + 'static,
{
    type Context = CallerContext;
    fn encryption<'s, K: 'static>(context: Self::Context) -> Encryption<'s, S, Self, K>
    where
        S: 's,
    {
        ope(context)
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
    fn encryption<'s, K: 'static>(context: Self::Context) -> Encryption<'s, Vec<S>, Self, K>
    where
        S: 's,
    {
        Encryption {
            build: Box::new(move |source, cipher| {
                Pending::collect(
                    cipher,
                    source
                        .iter()
                        .map(|item| cipher.encrypt_as(item, context.clone())),
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
    fn encryption<'s, K: 'static>(context: Self::Context) -> Encryption<'s, Option<S>, Self, K>
    where
        S: 's,
    {
        Encryption {
            build: Box::new(move |source, cipher| match source {
                Some(item) => cipher.encrypt_as(item, context).map(Some),
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
