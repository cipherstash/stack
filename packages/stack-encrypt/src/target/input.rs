//! Explicit caller-context capabilities. `Default` never grants permission to omit context.
//!
//! | Input | Context left out | Context passed | What the input means |
//! |---|---|---|---|
//! | [`NoCallerContext`] | Allowed | Refused | The declaration builds every context itself. |
//! | [`RequiredContext<C>`] | Refused | `C` | The caller supplies the context, or the part of it that the declaration selects. |
//! | [`OptionalContext<C>`] | Allowed | `C` | For an opaque scalar. A context left out is the empty context. |
//! | [`DeclaredScopes`] | Allowed | Refused | A derived `struct = ..` record. Each field has its own context. A record that contains it, or a plan, passes that field's context. |
//! | [`ExpectedContext<T>`](super::ExpectedContext) | Allowed | `NonEmpty<T>` | A context left out opens under the stored context, unchecked. A context passed is checked against the stored one. |
//!
//! A trait bound decides whether a method is available ([`AllowsNoContext`]
//! or [`AcceptsContext`]). It is never inferred from `C: Default`. For
//! example, `RequiredContext<u64>` stays required, although `u64` has a
//! default of zero.

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

/// The input of a derived `struct = ..` record: the caller passes no context.
///
/// Each field of the record has its own context, such as `("users", "name")`.
/// The record's name is the first scope, and the field's name is the next.
/// So the caller has nothing to add, and `encrypt_into_with_context` does not
/// compile for the record. A part that the caller supplies, such as a tenant
/// scope or a row binding, must be declared on the record first. The
/// declaration attributes for those parts are not built yet.
///
/// Only the library passes this input a value:
///
/// - A record that is a field of another record is given that field's
///   context, which then extends each of its own fields' contexts.
/// - A plan or a structural record passes its declared context the same
///   way.
#[derive(Clone, Debug, Default)]
pub struct DeclaredScopes(DeclaredContext);
impl sealed::Sealed for DeclaredScopes {}
impl ContextInput for DeclaredScopes {}
impl AllowsNoContext for DeclaredScopes {
    fn omitted() -> Self {
        Self::default()
    }
}
// The context a record's declaration tree runs under: each field's own
// context, extended by the context of the record that contains it, if any.
impl From<DeclaredScopes> for DeclaredContext {
    fn from(scopes: DeclaredScopes) -> Self {
        scopes.0
    }
}
// A structural caller with a `DeclaredContext`, such as a plan or a `struct =
// ..` structural derive, passes its context to an owned record field through
// this conversion.
impl From<DeclaredContext> for DeclaredScopes {
    fn from(context: DeclaredContext) -> Self {
        Self(context)
    }
}
// A record field is given its own context (`Encryption::under`). A nested
// record takes that context as the one its own fields extend.
impl From<CallerContext> for DeclaredScopes {
    fn from(context: CallerContext) -> Self {
        Self(context.into())
    }
}
// A field whose target requires a caller context is given the record's context
// for that field, extended by the caller's context. So a
// `RequiredContext<CallerContext>` field or a `RequiredContext<AeadContext>`
// field can be a field of a `struct = ..` record.
impl<C: From<CallerContext>> From<CallerContext> for RequiredContext<C> {
    fn from(context: CallerContext) -> Self {
        Self::supplied(C::from(context))
    }
}
// A record that derives terms gives its ciphertext fields the AEAD part of the
// context it requires.
impl From<RequiredContext<CallerContext>> for RequiredContext<super::AeadContext> {
    fn from(context: RequiredContext<CallerContext>) -> Self {
        Self::supplied(context.into_inner().into())
    }
}
// A record that stores its context (`context_field`) requires the
// `NonEmpty<T>` it stores. It runs its fields under the caller context built
// from that value.
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
// A record that stores its context takes the `NonEmpty<T>` it stores from its
// structural trait as the required input.
impl<T> From<NonEmpty<T>> for RequiredContext<NonEmpty<T>> {
    fn from(context: NonEmpty<T>) -> Self {
        Self::supplied(context)
    }
}
// The contexts of the structural declarations, wrapped as the required input
// of the owned leaf that replaces each one. A plan or a structural record
// gives an owned field its context this way.
impl From<super::AeadContext> for RequiredContext<super::AeadContext> {
    fn from(context: super::AeadContext) -> Self {
        Self::supplied(context)
    }
}
// The core operations take the context the input contains, with no wrapper of
// their own. For example, `ciphertext()` takes a
// `RequiredContext<AeadContext>`, and a term takes a
// `RequiredContext<CallerContext>`.
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

/// The input of a record that stores its context: the context the caller
/// expects, or none.
///
/// - If the caller passes a `NonEmpty<T>`, the stored context must equal it. A
///   different stored context is refused before any key is retrieved
///   ([`ExpectedContext::validate`]).
/// - If the caller leaves the context out, the record opens under whatever
///   context it stores, after a check that the context is not empty.
///
/// The stored context is not authenticated. A ciphertext moved together with
/// its stored context opens in its new place, unless the caller passes the
/// context it expects.
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
/// A scalar operation seals and derives no term, so a caller context runs
/// it under the stored context.
impl From<super::CallerContext> for ScalarContext {
    fn from(value: super::CallerContext) -> Self {
        Self(value.stored())
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
// operation. The caller's omitted input must not extend it with an empty
// tuple. A scalar operation seals and derives no term, so it runs under
// the stored context.
impl From<super::CallerContext> for OptionalContext<ScalarContext> {
    fn from(context: super::CallerContext) -> Self {
        Self::supplied(ScalarContext(context.stored()))
    }
}
impl From<NoCallerContext> for super::DeclaredContext {
    fn from(_: NoCallerContext) -> Self {
        Self::default()
    }
}
