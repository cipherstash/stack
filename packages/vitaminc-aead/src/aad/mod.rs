//! Associated data, as a view of a context.
//!
//! The bytes an AEAD authenticates for a context are the context's canonical
//! encoding, owned by [`vitaminc_context`]. This module adds nothing to that
//! encoding: [`IntoAad`] is a blanket over [`IntoContext`], so a context type
//! implements `IntoContext` once and gets `IntoAad` (and the PRF crate's
//! `IntoPrfContext`) for free, with byte-identical results on both sides.

pub use vitaminc_context::{Context, ContextPiece, IntoContext};

/// The associated data a context is authenticated as. Kept as a name for
/// the transition; it is [`Context`].
#[deprecated(
    since = "0.5.0",
    note = "renamed to `Context`, re-exported here from `vitaminc_context`"
)]
pub type Aad<'a> = Context<'a>;

/// The parts view of a context. Kept as a name for the transition; it is
/// [`ContextPiece`].
#[deprecated(
    since = "0.5.0",
    note = "renamed to `ContextPiece`, re-exported here from `vitaminc_context`"
)]
pub type AadPiece<'a> = ContextPiece<'a>;

/// Types that can be used as the associated data of an AEAD call.
///
/// This is the AEAD's view of a context. It is implemented for every type
/// that implements [`IntoContext`], and only through that blanket, so the
/// bytes the AEAD authenticates are always the context's canonical encoding
/// and always equal to what a PRF derives under for the same value. There
/// is nothing to implement here: give a type of your own an `IntoContext`
/// impl and it is an `IntoAad`.
///
/// ```rust
/// use vitaminc_aead::{ContextPiece, IntoAad, IntoContext};
///
/// struct TenantId(u64);
///
/// impl<'a> IntoContext<'a> for TenantId {
///     fn into_context(self) -> ContextPiece<'a> {
///         ("tenant", self.0).into_context()
///     }
/// }
///
/// assert_eq!(
///     TenantId(7).into_aad().as_bytes(),
///     ("tenant", 7u64).into_aad().as_bytes(),
/// );
/// ```
pub trait IntoAad<'a>: IntoContext<'a> {
    /// The bytes the AEAD authenticates: the canonical encoding of
    /// [`into_context`](IntoContext::into_context).
    fn into_aad(self) -> Context<'a>;
}

impl<'a, T> IntoAad<'a> for T
where
    T: IntoContext<'a>,
{
    fn into_aad(self) -> Context<'a> {
        self.into_context().encode()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;
    use vitaminc_prf::IntoPrfContext;

    /// The acceptance criterion of #339: for every tree this crate can be
    /// handed, the AEAD and the PRF see the same bytes.
    #[quickcheck]
    fn the_aad_and_the_prf_context_are_the_same_bytes(tree: ContextPiece<'static>) -> bool {
        tree.clone().into_aad().as_bytes() == tree.into_prf_context().as_bytes()
    }

    #[test]
    fn a_context_is_its_own_aad() {
        let ctx = ("users/email", 7u64).into_aad();
        assert_eq!(
            ctx.clone().into_aad(),
            ctx,
            "an encoded context re-encodes to itself"
        );
    }
}
