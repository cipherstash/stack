//! The contexts a target declares.
//!
//! A target's associated `Context` is what a caller hands `encrypt_as` and
//! `decrypt_as` alongside the value. The types here are the core-owned ones:
//! each holds Vitamin C's encodings of a nonempty context, so the structured
//! identity of its descriptor survives the trip into a boxed operation
//! description. A record that stores its own identifier declares
//! `NonEmpty<T>` instead, and a target whose declaration carries every
//! context it needs declares `()`.
use crate::{
    Aad, AadPiece, Descriptor, Error, IntoAad, IntoPrfContext, MaybeEmpty, NonEmpty, PrfContext,
};

/// Prove a context nonempty at the point it is used. The core-owned types
/// are nonempty by construction, so for them this cannot fail; the one
/// helper keeps the error mapping in one place.
pub(super) fn nonempty<T: MaybeEmpty>(value: T) -> Result<NonEmpty<T>, Error> {
    NonEmpty::new(value).map_err(|e| Error::Other(Box::new(e)))
}

/// An owned, validated context for a target that accepts any Vitamin C
/// context and derives both ciphertext and terms from it.
///
/// Built from a `NonEmpty<T>` (or a bare integer), it holds the AEAD and PRF
/// encodings of that context, so the descriptor's structured identity is
/// preserved. Concrete records declare their own context type instead.
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
    pub(super) fn validated(self) -> Result<NonEmpty<Self>, Error> {
        nonempty(self)
    }
    /// Extend a field's own context with this caller context: the field's
    /// literal becomes the prefix, this context the extension, exactly as a
    /// `struct = T` derive composes them.
    ///
    /// # Errors
    ///
    /// Fails if `field` is empty; a field's own context is a literal the
    /// derive has already checked, so a hand-written caller is the only one
    /// that can hit this.
    pub fn under(self, field: &'static str) -> Result<Self, Error> {
        let prefix = nonempty(field)?;
        Ok(prefix.with(self.validated()?).into())
    }
}

/// An owned nonempty context for ciphertext-only operations.
///
/// Sealing needs only the AEAD encoding, so a type that implements `IntoAad`
/// without `IntoPrfContext` is enough here where it would not be for a
/// [`CallerContext`].
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
    pub(super) fn validated(self) -> Result<NonEmpty<Self>, Error> {
        nonempty(self)
    }
}

/// The optional extension a record whose fields already declare their own
/// contexts accepts from its caller.
///
/// `()` (the default) leaves the declared contexts as they are; a nonempty
/// value extends each of them, the way a caller's context extends a field's
/// own. This is what a `struct = T` derive without a `context_field`
/// declares.
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
    /// The context one field is derived under: its own literal, extended by
    /// the caller's context if one was given.
    ///
    /// # Errors
    ///
    /// Fails if `field` is empty. The derive checks its literals at compile
    /// time, so only a hand-written caller can hit this.
    pub fn field(self, field: &'static str) -> Result<CallerContext, Error> {
        match self.0 {
            Some(context) => context.under(field),
            None => nonempty(field).map(Into::into),
        }
    }
}

/// What a caller may assert about a record that stores its context.
///
/// A `#[stash(context_field)]` record carries its identifier in storage, and
/// decryption reads the context from there. The default asks only that the
/// stored value be nonempty; a `NonEmpty<T>` asks that it also equal the
/// destination the caller believes it is opening. Either way the check runs
/// before any key is retrieved.
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
impl<'c, T: MaybeEmpty + PartialEq + IntoAad<'c>> ExpectedContext<T> {
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
                let stored = Descriptor::from_piece(&stored.into_aad_piece());
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
