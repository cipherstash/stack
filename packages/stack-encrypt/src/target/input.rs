//! Explicit caller-context capabilities. `Default` never grants permission to omit context.
//!
//! | Input | Omitted | Supplied | Meaning |
//! |---|---|---|---|
//! | [`NoCallerContext`] | allowed | refused | the declaration derives every context itself |
//! | [`RequiredContext<C>`] | refused | `C` | the caller supplies the context, or the part the declaration selects |
//! | [`OptionalContext<C>`] | allowed | `C` | for an opaque scalar: omission is the empty context |
//! | [`ContextExtension<C>`] | allowed | `C` | omission keeps the declared contexts; supply extends each of them |
//! | [`ExpectedContext<T>`](super::ExpectedContext) | allowed | `NonEmpty<T>` | omission opens under the stored context; supply also checks it |
//!
//! Whether a method is available is a trait bound ([`AllowsNoContext`],
//! [`AcceptsContext`]), never inferred from `C: Default`: a
//! `RequiredContext<u64>` stays required although `u64` defaults to zero.

use super::context::{CallerContext, DeclaredContext, ExpectedContext};
use crate::{ContextPiece, IntoContext, NonEmpty};

mod sealed {
    pub trait Sealed {}
}

/// A library-owned description of what context a caller may supply.
pub trait ContextInput: sealed::Sealed {}

/// A declaration permits omitting caller context.
pub trait AllowsNoContext: ContextInput + Sized {
    /// Construct the explicitly omitted input.
    fn omitted() -> Self;
}

/// A declaration accepts a context argument.
pub trait AcceptsContext: ContextInput + Sized {
    /// The caller's value, before the presence wrapper is added.
    type Value;
    /// Record that the caller supplied a value.
    fn supplied(value: Self::Value) -> Self;
}

/// The declaration supplies all context itself; a caller cannot add any.
#[derive(Clone, Copy, Debug)]
pub struct NoCallerContext;
impl sealed::Sealed for NoCallerContext {}
impl ContextInput for NoCallerContext {}
impl AllowsNoContext for NoCallerContext {
    fn omitted() -> Self {
        Self
    }
}

/// Caller context is required, even when `C` implements `Default`.
#[derive(Clone, Debug)]
pub struct RequiredContext<C>(C);
impl<C> RequiredContext<C> {
    /// Take the caller's required value when interpreting a declaration.
    pub fn into_inner(self) -> C {
        self.0
    }
}
impl<C> sealed::Sealed for RequiredContext<C> {}
impl<C> ContextInput for RequiredContext<C> {}
impl<C> AcceptsContext for RequiredContext<C> {
    type Value = C;
    fn supplied(value: C) -> Self {
        Self(value)
    }
}

/// Caller context may be omitted. Absence is distinct from a supplied value.
#[derive(Clone, Debug)]
pub struct OptionalContext<C>(Option<C>);
impl<C> OptionalContext<C> {
    /// Inspect presence when interpreting a declaration.
    pub fn into_inner(self) -> Option<C> {
        self.0
    }
}
impl<C> sealed::Sealed for OptionalContext<C> {}
impl<C> ContextInput for OptionalContext<C> {}
impl<C> AllowsNoContext for OptionalContext<C> {
    fn omitted() -> Self {
        Self(None)
    }
}
impl<C> AcceptsContext for OptionalContext<C> {
    type Value = C;
    fn supplied(value: C) -> Self {
        Self(Some(value))
    }
}

/// Caller context may extend the contexts a declaration carries itself.
///
/// What a derived record whose fields each sit under their own pair
/// (`("users", "name")`) accepts: omitted, the declared contexts stand as
/// they are; supplied, every one of them is extended by the value — `7u64`
/// makes the field `(("users", "name"), 7u64)`. Omission appends nothing, not
/// an empty part. Decrypting a record sealed under an extension needs the
/// same extension; the omitted method's availability is not a promise that
/// it opens every stored record of the type.
#[derive(Clone, Debug)]
pub struct ContextExtension<C>(Option<C>);
impl<C> ContextExtension<C> {
    /// Inspect presence when interpreting a declaration.
    pub fn into_inner(self) -> Option<C> {
        self.0
    }
}
impl<C> sealed::Sealed for ContextExtension<C> {}
impl<C> ContextInput for ContextExtension<C> {}
impl<C> AllowsNoContext for ContextExtension<C> {
    fn omitted() -> Self {
        Self(None)
    }
}
impl<C> AcceptsContext for ContextExtension<C> {
    type Value = C;
    fn supplied(value: C) -> Self {
        Self(Some(value))
    }
}
// What a record's declaration tree runs under: its fields' own contexts,
// extended by the caller's part if one was given.
impl<C: Into<DeclaredContext>> From<ContextExtension<C>> for DeclaredContext {
    fn from(extension: ContextExtension<C>) -> Self {
        extension.0.map_or_else(Self::default, Into::into)
    }
}
// A legacy `DeclaredContext` caller (a plan, a `struct = ..` derive) hands
// its extension to an owned record field through here.
impl From<DeclaredContext> for ContextExtension<DeclaredContext> {
    fn from(extension: DeclaredContext) -> Self {
        if extension.is_extended() {
            Self::supplied(extension)
        } else {
            Self::omitted()
        }
    }
}
// A record field is handed its own pair extended by the caller's context
// (`Encryption::under`): a nested record takes that as its extension.
impl<C: From<CallerContext>> From<CallerContext> for ContextExtension<C> {
    fn from(context: CallerContext) -> Self {
        Self::supplied(C::from(context))
    }
}
// A field whose target requires a caller context is given the record's pair,
// extended by the caller's part: a `RequiredContext<CallerContext>` or
// `RequiredContext<AeadContext>` field sits under a `struct = ..` record.
impl<C: From<CallerContext>> From<CallerContext> for RequiredContext<C> {
    fn from(context: CallerContext) -> Self {
        Self::supplied(C::from(context))
    }
}
// A record that derives terms hands its ciphertext-only fields the AEAD
// half of the context it requires.
impl From<RequiredContext<CallerContext>> for RequiredContext<super::AeadContext> {
    fn from(context: RequiredContext<CallerContext>) -> Self {
        Self::supplied(context.into_inner().into())
    }
}
// A record that stores its context (`context_field`) requires the
// `NonEmpty<T>` it stores and runs its fields under the caller context
// built from it.
impl<'c, T: IntoContext<'c>> From<RequiredContext<NonEmpty<T>>> for RequiredContext<CallerContext> {
    fn from(context: RequiredContext<NonEmpty<T>>) -> Self {
        Self::supplied(context.into_inner().into())
    }
}
impl<'c, T: IntoContext<'c>> From<RequiredContext<NonEmpty<T>>>
    for RequiredContext<super::AeadContext>
{
    fn from(context: RequiredContext<NonEmpty<T>>) -> Self {
        Self::supplied(context.into_inner().into())
    }
}
// A record that stores its context takes the `NonEmpty<T>` it stores from
// its structural bridge as the required input.
impl<T> From<NonEmpty<T>> for RequiredContext<NonEmpty<T>> {
    fn from(context: NonEmpty<T>) -> Self {
        Self::supplied(context)
    }
}
// The legacy declarations' contexts, wrapped as the required input of the
// owned leaf that replaces each: what a plan or a legacy record hands an
// owned field.
impl From<super::AeadContext> for RequiredContext<super::AeadContext> {
    fn from(context: super::AeadContext) -> Self {
        Self::supplied(context)
    }
}
// The core operations take the context the input carries, with no wrapper
// of their own: `ciphertext()` under a `RequiredContext<AeadContext>`,
// a term under a `RequiredContext<CallerContext>`.
impl<C: Into<super::AeadContext>> From<RequiredContext<C>> for super::AeadContext {
    fn from(context: RequiredContext<C>) -> Self {
        context.into_inner().into()
    }
}
impl<C: Into<CallerContext>> From<RequiredContext<C>> for CallerContext {
    fn from(context: RequiredContext<C>) -> Self {
        context.into_inner().into()
    }
}

/// A record that stores its context accepts an expectation of it, or none.
///
/// Omitted, the record opens under whatever context it stores, after
/// checking that it is nonempty; supplied, the stored context must also
/// equal the `NonEmpty<T>` the caller names, and a mismatch is refused
/// before any key is retrieved ([`ExpectedContext::validate`]).
impl<T> sealed::Sealed for ExpectedContext<T> {}
impl<T> ContextInput for ExpectedContext<T> {}
impl<T> AllowsNoContext for ExpectedContext<T> {
    fn omitted() -> Self {
        Self::default()
    }
}
impl<T> AcceptsContext for ExpectedContext<T> {
    type Value = NonEmpty<T>;
    fn supplied(value: NonEmpty<T>) -> Self {
        Self::from(value)
    }
}

/// Owned AEAD context for an opaque scalar. Empty context is valid.
///
/// Contexts use the existing canonical encoding. No extra tuple, prefix or
/// presence marker is added to AAD. Convert ordinary contexts with `Into`;
/// the conversion methods do this automatically.
///
/// Keep an owned context when the same value is needed for sealing and opening:
///
/// ```no_run
/// use stack_encrypt::{Ciphertext, DecryptFrom, EncryptInto, target::ScalarContext};
/// # async fn example<K: stack_encrypt::kms::DataKeySource + stack_encrypt::kms::IndexKeySource + Sync + 'static>(cipher: &stack_encrypt::StackCipher<K>) -> Result<(), stack_encrypt::Error> {
/// let context = ScalarContext::from(("users", "age"));
/// let encrypted: Ciphertext = 42i32
///     .encrypt_into_with_context(&cipher.default_keyset(), context.clone())
///     .await?;
/// let age = i32::decrypt_from_with_context(encrypted, cipher, context).await?;
/// assert_eq!(age, 42);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct ScalarContext(ContextPiece<'static>);
impl<'c, C: IntoContext<'c>> From<C> for ScalarContext {
    fn from(value: C) -> Self {
        Self(value.into_context().into_owned())
    }
}
impl OptionalContext<ScalarContext> {
    pub(crate) fn piece(self) -> ContextPiece<'static> {
        self.0
            .map_or_else(|| ().into_context(), |context| context.0)
    }
}

// A required input can drive the scalar operation without weakening the
// declaration's caller-facing requirement.
impl<C: Into<ScalarContext>> From<RequiredContext<C>> for OptionalContext<ScalarContext> {
    fn from(context: RequiredContext<C>) -> Self {
        Self::supplied(context.into_inner().into())
    }
}

// `Encryption::under` supplies the declared nonempty context to the scalar
// operation. The caller's omitted input must not extend it with an empty tuple.
impl From<super::CallerContext> for OptionalContext<ScalarContext> {
    fn from(context: super::CallerContext) -> Self {
        Self::supplied(context.into())
    }
}
impl From<NoCallerContext> for super::DeclaredContext {
    fn from(_: NoCallerContext) -> Self {
        Self::default()
    }
}
