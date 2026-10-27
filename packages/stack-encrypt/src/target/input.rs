//! Explicit caller-context capabilities. `Default` never grants permission to omit context.

use crate::{ContextPiece, IntoContext};

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

/// Owned AEAD context for an opaque scalar. Empty context is valid.
///
/// Contexts use the existing canonical encoding. No extra tuple, prefix or
/// presence marker is added to AAD. Convert ordinary contexts with `Into`;
/// the conversion methods do this automatically.
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
