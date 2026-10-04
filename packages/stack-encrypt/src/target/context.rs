//! The contexts a target declares.
//!
//! A target's associated `Context` is what a caller hands `encrypt_as` and
//! `decrypt_as` alongside the value. The types here are the core-owned ones:
//! each holds the parts view of a nonempty context — the one tree both the
//! AEAD and the PRF encode from — so the structured identity of its
//! descriptor survives the trip into a boxed operation description. A
//! record that stores its own identifier declares `NonEmpty<T>` instead,
//! and a target whose declaration carries every context it needs declares
//! `()`.
use crate::{ContextPiece, Descriptor, Error, IntoContext, MaybeEmpty, NonEmpty};

/// Prove a context nonempty at the point it is used. The core-owned types
/// are nonempty by construction, so for them this cannot fail; the one
/// helper keeps the error mapping in one place.
pub(super) fn nonempty<T: MaybeEmpty>(value: T) -> Result<NonEmpty<T>, Error> {
    NonEmpty::new(value).map_err(|e| Error::Other(Box::new(e)))
}

/// An owned, validated context for a target that accepts any Vitamin C
/// context and derives both ciphertext and terms from it.
///
/// Built from a `NonEmpty<T>` (or a bare integer), it holds the parts view
/// of that context. The AEAD and the PRF encode the same tree to the same
/// bytes, so one tree serves both derivations and the descriptor's
/// structured identity is preserved. Concrete records declare their own
/// context type instead.
#[derive(Clone, Debug)]
pub struct CallerContext(ContextPiece<'static>);
impl<'c, T> From<NonEmpty<T>> for CallerContext
where
    T: IntoContext<'c>,
{
    fn from(context: NonEmpty<T>) -> Self {
        Self(context.into_context().into_owned())
    }
}
impl MaybeEmpty for CallerContext {
    fn is_empty(&self) -> bool {
        false
    }
}
impl<'a> IntoContext<'a> for CallerContext {
    fn into_context(self) -> ContextPiece<'a> {
        self.0
    }
}
impl CallerContext {
    pub(super) fn validated(self) -> Result<NonEmpty<Self>, Error> {
        nonempty(self)
    }
    /// The own context `own`, extended by this caller context: the field's
    /// own context is the prefix, this context the extension, exactly as a
    /// `struct = T` derive composes them — `(("users", "age"), id)`. The own
    /// context is never discarded.
    pub fn extend<'c, O: IntoContext<'c>>(self, own: NonEmpty<O>) -> Self {
        own.with(self).into()
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
/// does.
#[derive(Clone, Debug)]
pub struct AeadContext(ContextPiece<'static>);
impl<'a, T: IntoContext<'a>> From<NonEmpty<T>> for AeadContext {
    fn from(value: NonEmpty<T>) -> Self {
        Self(value.into_context().into_owned())
    }
}
impl From<CallerContext> for AeadContext {
    fn from(value: CallerContext) -> Self {
        Self(value.0)
    }
}
impl MaybeEmpty for AeadContext {
    fn is_empty(&self) -> bool {
        false
    }
}
impl<'a> IntoContext<'a> for AeadContext {
    fn into_context(self) -> ContextPiece<'a> {
        self.0
    }
}
impl AeadContext {
    pub(super) fn validated(self) -> Result<NonEmpty<Self>, Error> {
        nonempty(self)
    }
    /// The own context `own`, extended by this caller context, as
    /// [`CallerContext::extend`] does for a record that derives terms: the
    /// field's own context is the prefix, this context the extension.
    pub fn extend<'c, O: IntoContext<'c>>(self, own: NonEmpty<O>) -> Self {
        own.with(self).into()
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
impl<'a, T: IntoContext<'a>> From<NonEmpty<T>> for DeclaredContext {
    fn from(value: NonEmpty<T>) -> Self {
        Self(Some(value.into()))
    }
}
impl DeclaredContext {
    /// The context one field is derived under: its own `own`, extended by
    /// the caller's context if one was given — `("users", "age")` as it is
    /// under `()`, `(("users", "age"), id)` under a caller's `id`.
    pub fn under<'c, O: IntoContext<'c>>(self, own: NonEmpty<O>) -> CallerContext {
        match self.0 {
            Some(caller) => caller.extend(own),
            None => own.into(),
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
/// not entitled to. See ADR-0004.
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
