//! Core-owned operation descriptions. Constructors never accept a plaintext/cipher callback.
use super::core::{encrypt_native, open_native, Term};
use super::{CipherScope, Pending};
use crate::{
    Aad, AadPiece, Error, IntoAad, IntoPrfContext, KeysetCipher, MaybeEmpty, NonEmpty, PrfContext,
    StackCipher, StackCipherText,
};
use stack_kms::MaybeSend;

/// Owned, validated context for targets that accept any Vitamin C context.
/// Concrete records can instead declare their own associated context type.
/// Both encodings and the descriptor's structured identity are preserved.
#[derive(Clone, Debug)]
pub struct CallerContext {
    aad: AadPiece<'static>,
    prf: PrfContext<'static>,
}
impl<'c, T> From<NonEmpty<T>> for CallerContext
where
    T: IntoAad<'c> + IntoPrfContext<'c> + Clone,
{
    fn from(context: NonEmpty<T>) -> Self {
        Self {
            aad: context.clone().into_aad_piece().into_owned(),
            prf: context.into_prf_context().into_owned(),
        }
    }
}
impl MaybeEmpty for CallerContext {
    fn is_empty(&self) -> bool {
        false
    }
}
impl<'a> IntoAad<'a> for CallerContext {
    fn into_aad(self) -> Aad<'a> {
        self.aad.into_aad()
    }
    fn into_aad_piece(self) -> AadPiece<'a> {
        self.aad
    }
}
impl<'a> IntoPrfContext<'a> for CallerContext {
    fn into_prf_context(self) -> PrfContext<'a> {
        self.prf
    }
}
impl CallerContext {
    fn validated(self) -> Result<NonEmpty<Self>, Error> {
        NonEmpty::new(self).map_err(|e| Error::Other(Box::new(e)))
    }
    /// Extend a field's own context with this caller context.
    pub fn under(self, field: &'static str) -> Result<Self, Error> {
        let prefix = NonEmpty::new(field).map_err(|e| Error::Other(Box::new(e)))?;
        Ok(prefix.with(self.validated()?).into())
    }
}

/// Declaration of how an encrypted target is produced from `S`.
/// The returned description has private execution machinery: implementations can
/// select core operations and construct outputs, but cannot replace encryption.
pub trait EncryptFrom<S>: Sized + 'static {
    type Context;
    fn encryption<'s, K: 'static>(context: Self::Context) -> Encryption<'s, S, Self, K>
    where
        S: 's;
}
/// Declaration of how a stored target recovers `P`. Inspection sees no cipher.
pub trait DecryptInto<P>: Sized {
    type Context;
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

/// A composable encryption description, executed only by the cipher.
pub struct Encryption<'s, S, T, K> {
    build: Build<'s, S, T, K>,
}
/// A composable decryption description, executed only by the cipher.
pub struct Decryption<T, K> {
    open: Open<T, K>,
}

impl<'s, S: 's, T: 'static, K: 'static> Encryption<'s, S, T, K> {
    /// Construct metadata or reject a declaration before any key request.
    pub fn ready(result: Result<T, Error>) -> Self
    where
        T: MaybeSend,
    {
        Self {
            build: Box::new(move |_, cipher| Pending::ready(cipher, result)),
        }
    }
    pub fn failed(error: Error) -> Self {
        Self {
            build: Box::new(move |_, cipher| Pending::failed(cipher, error)),
        }
    }
    /// Construct the destination from completed outputs, without access to plaintext.
    pub fn map<U: 'static, F>(self, f: F) -> Encryption<'s, S, U, K>
    where
        F: FnOnce(T) -> U + MaybeSend + 'static,
    {
        Encryption {
            build: Box::new(move |source, cipher| (self.build)(source, cipher).map(f)),
        }
    }
    /// Fallible output conversion, including native ciphertext transcoding.
    pub fn try_map<U: 'static, F>(self, f: F) -> Encryption<'s, S, U, K>
    where
        F: FnOnce(T) -> Result<U, Error> + MaybeSend + 'static,
    {
        Encryption {
            build: Box::new(move |source, cipher| (self.build)(source, cipher).try_map(f)),
        }
    }
    /// Drive a destination visitor directly from this operation's native output.
    pub fn transcode<U: super::transcode::Transcode + 'static>(self) -> Encryption<'s, S, U, K>
    where
        T: super::transcode::Reader,
    {
        self.try_map(|output| super::transcode::Reader::read(output, U::visitor()))
    }
    /// Compose operations over the same source in one key request batch.
    pub fn zip<U: 'static>(self, other: Encryption<'s, S, U, K>) -> Encryption<'s, S, (T, U), K> {
        Encryption {
            build: Box::new(move |source, cipher| {
                (self.build)(source, cipher).zip((other.build)(source, cipher))
            }),
        }
    }
    /// Select a borrowed plaintext field. The selector cannot supply a new owned
    /// serialization of that field; its selected type drives the core operation.
    pub fn project<P: 's>(
        self,
        select: for<'borrow> fn(&'borrow P) -> &'borrow S,
    ) -> Encryption<'s, P, T, K> {
        Encryption {
            build: Box::new(move |source, cipher| (self.build)(select(source), cipher)),
        }
    }
}

/// Canonical ciphertext operation. Source encoding belongs to Vitamin C.
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
    ($function:ident, $output:ty, [$($extra:tt)*], $($bounds:tt)*) => {
        pub fn $function<'s,S,K:'static,$($extra)*>(context: impl Into<CallerContext>)->Encryption<'s,S,$output,K>
        where S: 's + $($bounds)* {
            let context=context.into();
            Encryption { build:Box::new(move |source,cipher| match context.validated() {
                Ok(ctx) => <$output as Term<S, K, _>>::encrypt_from(source,cipher,ctx),
                Err(e) => Pending::failed(cipher,e),
            }) }
        }
    };
}
term_operation!(
    equality,
    crate::sem::EqualityTerm,
    [],
    vitaminc_prf::PrfValue + Clone
);
term_operation!(matching, crate::sem::MatchTerm<O>, [O:crate::sem::MatchConfig+'static,], AsRef<str>);
// Ordering output bounds are part of the primitive's contract.
pub fn ore<'s, S, K: 'static>(
    context: impl Into<CallerContext>,
) -> Encryption<'s, S, crate::sem::OreTerm<S>, K>
where
    S: cllw_ore::CllwOreEncrypt + Clone + Send + 'static,
    S::Output: Send + 'static,
{
    let context = context.into();
    Encryption {
        build: Box::new(move |source, cipher| match context.validated() {
            Ok(ctx) => <crate::sem::OreTerm<S> as Term<S, K, _>>::encrypt_from(source, cipher, ctx),
            Err(e) => Pending::failed(cipher, e),
        }),
    }
}
pub fn ope<'s, S, K: 'static>(
    context: impl Into<CallerContext>,
) -> Encryption<'s, S, crate::sem::OpeTerm<S>, K>
where
    S: cllw_ore::CllwOpeEncrypt + Clone + Send + 'static,
    S::Output: Send + 'static,
{
    let context = context.into();
    Encryption {
        build: Box::new(move |source, cipher| match context.validated() {
            Ok(ctx) => <crate::sem::OpeTerm<S> as Term<S, K, _>>::encrypt_from(source, cipher, ctx),
            Err(e) => Pending::failed(cipher, e),
        }),
    }
}

impl<T: 'static, K: 'static> Decryption<T, K> {
    pub fn failed(error: Error) -> Self {
        Self {
            open: Box::new(move |cipher| Pending::failed(cipher, error)),
        }
    }
    pub fn ready(value: T) -> Self
    where
        T: MaybeSend,
    {
        Self {
            open: Box::new(move |cipher| Pending::ready(cipher, Ok(value))),
        }
    }
    pub fn map<U: 'static, F>(self, f: F) -> Decryption<U, K>
    where
        F: FnOnce(T) -> U + MaybeSend + 'static,
    {
        Decryption {
            open: Box::new(move |cipher| (self.open)(cipher).map(f)),
        }
    }
    pub fn zip<U: 'static>(self, other: Decryption<U, K>) -> Decryption<(T, U), K> {
        Decryption {
            open: Box::new(move |cipher| (self.open)(cipher).zip((other.open)(cipher))),
        }
    }
}
/// Open the native ciphertext through Vitamin C's requested plaintext decoder.
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
    pub fn encrypt_as<'a, S, T>(&'a self, source: &S, context: T::Context) -> Pending<'a, T, K>
    where
        T: EncryptFrom<S>,
    {
        (T::encryption(context).build)(source, self)
    }
    pub fn decrypt_as<'a, P: 'static, T>(
        &'a self,
        source: T,
        context: T::Context,
    ) -> Pending<'a, P, K>
    where
        T: DecryptInto<P>,
    {
        (source.decryption(context).open)(self.cipher()).scoped_to(self.keyset_id())
    }
}
impl<K: 'static> StackCipher<K> {
    pub fn decrypt_as<'a, P: 'static, T>(
        &'a self,
        source: T,
        context: T::Context,
    ) -> Pending<'a, P, K>
    where
        T: DecryptInto<P>,
    {
        (source.decryption(context).open)(self)
    }
}

/// Blanket call-site convenience; targets implement the declaration, not these methods.
pub trait EncryptInto: Sized {
    fn encrypt_into<'a, T, K: 'static>(&self, cipher: &'a KeysetCipher<'_, K>) -> Pending<'a, T, K>
    where
        T: EncryptFrom<Self>,
        T::Context: Default,
    {
        cipher.encrypt_as(self, Default::default())
    }
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
/// Blanket decrypt call-site convenience; there is no overridable target execution method.
pub trait DecryptFrom: Sized + 'static {
    fn decrypt_into<'a, P: 'static, K: 'static>(
        self,
        cipher: impl CipherScope<'a, K>,
        context: impl Into<<Self as DecryptInto<P>>::Context>,
    ) -> Pending<'a, P, K>
    where
        Self: DecryptInto<P>,
    {
        let pending = (self.decryption(context.into()).open)(cipher.cipher());
        match cipher.keyset() {
            Some(id) => pending.scoped_to(id),
            None => pending,
        }
    }
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
    T: MaybeSend,
    T::Context: MaybeSend,
{
    type Context = T::Context;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Vec<P>, K> {
        Decryption {
            open: Box::new(move |cipher| {
                Pending::collect(
                    cipher,
                    self.into_iter()
                        .map(|item| cipher.decrypt_as(item, context.clone())),
                )
            }),
        }
    }
}
impl<P: 'static + MaybeSend, T: DecryptInto<P> + 'static + MaybeSend> DecryptInto<Option<P>>
    for Option<T>
where
    T::Context: 'static + MaybeSend,
{
    type Context = T::Context;
    fn decryption<K: 'static>(self, context: Self::Context) -> Decryption<Option<P>, K> {
        Decryption {
            open: Box::new(move |cipher| match self {
                Some(item) => cipher.decrypt_as(item, context).map(Some),
                None => Pending::ready(cipher, Ok(None)),
            }),
        }
    }
}

/// Optional extension for records whose fields already declare their base contexts.
/// `()` selects the declared contexts unchanged; a nonempty value extends them.
#[derive(Clone, Debug, Default)]
pub struct DeclaredContext(Option<CallerContext>);
impl From<()> for DeclaredContext {
    fn from(_: ()) -> Self {
        Self::default()
    }
}
impl From<CallerContext> for DeclaredContext {
    fn from(value: CallerContext) -> Self {
        Self(Some(value))
    }
}
impl<'a, T: IntoAad<'a> + IntoPrfContext<'a> + Clone> From<NonEmpty<T>> for DeclaredContext {
    fn from(value: NonEmpty<T>) -> Self {
        Self(Some(value.into()))
    }
}
impl DeclaredContext {
    pub fn field(self, field: &'static str) -> Result<CallerContext, Error> {
        match self.0 {
            Some(context) => context.under(field),
            None => NonEmpty::new(field)
                .map(Into::into)
                .map_err(|e| Error::Other(Box::new(e))),
        }
    }
}
/// Optional destination validation for a record carrying its context in storage.
/// Even without an expected value, the stored context must pass `NonEmpty::new`.
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
impl<T: MaybeEmpty + PartialEq> ExpectedContext<T> {
    pub fn validate(self, stored: T) -> Result<NonEmpty<T>, Error> {
        if self
            .0
            .is_some_and(|expected| expected.into_inner() != stored)
        {
            return Err(Error::Other(
                "stored context does not match the expected context".into(),
            ));
        }
        NonEmpty::new(stored).map_err(|e| Error::Other(Box::new(e)))
    }
}
/// Declaration used by derives to select the one recoverable field. Terms return
/// `None`; ciphertext fields return an opening description. No cipher is exposed.
pub trait DecryptField<P, Ctx>: Sized {
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
impl<P, Ctx> DecryptField<P, Ctx> for crate::sem::EqualityTerm {
    fn decryption_field<K: 'static>(self, _: Ctx) -> Option<Decryption<P, K>> {
        None
    }
}
impl<P, Ctx, O: crate::sem::MatchConfig> DecryptField<P, Ctx> for crate::sem::MatchTerm<O> {
    fn decryption_field<K: 'static>(self, _: Ctx) -> Option<Decryption<P, K>> {
        None
    }
}
impl<P, Ctx, T: cllw_ore::CllwOreEncrypt> DecryptField<P, Ctx> for crate::sem::OreTerm<T> {
    fn decryption_field<K: 'static>(self, _: Ctx) -> Option<Decryption<P, K>> {
        None
    }
}
impl<P, Ctx, T: cllw_ore::CllwOpeEncrypt> DecryptField<P, Ctx> for crate::sem::OpeTerm<T> {
    fn decryption_field<K: 'static>(self, _: Ctx) -> Option<Decryption<P, K>> {
        None
    }
}
impl<
        P: 'static,
        T: 'static + super::Decryptable + DecryptField<P, Ctx> + MaybeSend,
        Ctx: Clone + 'static + MaybeSend,
    > DecryptField<Vec<P>, Ctx> for Vec<T>
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<Vec<P>, K>> {
        if !T::DECRYPTABLE {
            return None;
        }
        Some(Decryption {
            open: Box::new(move |cipher| {
                Pending::collect(
                    cipher,
                    self.into_iter().map(|item| {
                        let plan = item
                            .decryption_field(context.clone())
                            .unwrap_or_else(|| Decryption::failed(Error::NotOpened));
                        (plan.open)(cipher)
                    }),
                )
            }),
        })
    }
}
impl<
        P: 'static + MaybeSend,
        T: 'static + super::Decryptable + DecryptField<P, Ctx> + MaybeSend,
        Ctx: 'static + MaybeSend,
    > DecryptField<Option<P>, Ctx> for Option<T>
{
    fn decryption_field<K: 'static>(self, context: Ctx) -> Option<Decryption<Option<P>, K>> {
        if !T::DECRYPTABLE {
            return None;
        }
        Some(match self {
            Some(item) => item
                .decryption_field(context)
                .unwrap_or_else(|| Decryption::failed(Error::NotOpened))
                .map(Some),
            None => Decryption::ready(None),
        })
    }
}

/// Owned nonempty context for ciphertext-only operations. These do not require a
/// PRF encoding; a type that implements only `IntoAad` remains sufficient.
#[derive(Clone, Debug)]
pub struct AeadContext(AadPiece<'static>);
impl<'a, T: IntoAad<'a>> From<NonEmpty<T>> for AeadContext {
    fn from(value: NonEmpty<T>) -> Self {
        Self(value.into_aad_piece().into_owned())
    }
}
impl From<CallerContext> for AeadContext {
    fn from(value: CallerContext) -> Self {
        Self(value.aad)
    }
}
impl MaybeEmpty for AeadContext {
    fn is_empty(&self) -> bool {
        false
    }
}
impl<'a> IntoAad<'a> for AeadContext {
    fn into_aad(self) -> Aad<'a> {
        self.0.into_aad()
    }
    fn into_aad_piece(self) -> AadPiece<'a> {
        self.0
    }
}
impl AeadContext {
    fn validated(self) -> Result<NonEmpty<Self>, Error> {
        NonEmpty::new(self).map_err(|e| Error::Other(Box::new(e)))
    }
}
macro_rules! integer_contexts {
    ($($ty:ty),*) => {$ (
        impl From<$ty> for CallerContext {
            fn from(value:$ty)->Self { Self::from(NonEmpty::<$ty>::from(value)) }
        }
        impl From<$ty> for AeadContext {
            fn from(value:$ty)->Self { Self::from(NonEmpty::<$ty>::from(value)) }
        }
        impl From<$ty> for DeclaredContext {
            fn from(value:$ty)->Self { Self::from(NonEmpty::<$ty>::from(value)) }
        }
    )*};
}
integer_contexts!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

/// Whether a field contains recoverable ciphertext. Derives assert exactly one
/// such field per plaintext value; query terms are never recovery candidates.
pub trait Decryptable {
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
