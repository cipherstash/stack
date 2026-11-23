//! The two kinds of strategy, and the trait that keeps a type to one of
//! them.
//!
//! This is a module of its own because the crate root re-exports
//! `stack_profile::diagnostic`. There, that name hides the compiler's
//! `#[diagnostic::..]` attributes.

use crate::AuthStrategy;
// Named in the docs only.
#[cfg(doc)]
use crate::{CredentialAuthStrategy, CredentialPerCall};

/// The identity of a strategy, or of a key source, that has one of its own:
/// an access key, a saved login, or a provider that names the caller.
///
/// Every request it makes is made as that identity, so a call through it
/// takes no credential. It is the [`Kind`](StrategyKind::Kind) of every
/// [`AuthStrategy`]. The other kind is [`CredentialPerCall`].
///
/// You rarely name this type. The compiler works it out from the strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnIdentity;

mod kind {
    /// The two kinds of strategy, and no other. It is `pub` in a private
    /// module, so that it can bound a public associated type and still not
    /// be implemented outside this crate.
    #[allow(unreachable_pub)]
    pub trait Sealed {}
    impl Sealed for super::OwnIdentity {}
    impl Sealed for crate::CredentialPerCall {}
}

/// Which of the two kinds a strategy is.
///
/// A strategy makes every request as itself, or as the caller whose
/// credential comes with the call. It is never both: a strategy that had
/// both would make a call that forgot its credential as itself, and nobody
/// would know. This trait is what stops a type from being both. A type
/// implements it once, so it has one [`Kind`](Self::Kind):
///
/// - [`OwnIdentity`], for a strategy with an identity of its own. Every
///   [`AuthStrategy`] has this kind already. You do not implement
///   `StrategyKind` for one.
/// - [`CredentialPerCall`], for a strategy that takes a credential with
///   each call. [`CredentialAuthStrategy`] requires this kind, so you
///   implement `StrategyKind` beside it.
///
/// Code built on a strategy, such as Stack KMS and Stack Encrypt, reads the
/// kind from which of the two traits the strategy has. It adds no rule of
/// its own.
///
/// # Example
///
/// A strategy of your own that takes a credential with each call:
///
/// ```
/// use stack_auth::{
///     AuthError, CredentialAuthStrategy, CredentialPerCall, SecretToken, ServiceToken,
///     StrategyKind,
/// };
///
/// struct Exchange;
///
/// impl StrategyKind for &Exchange {
///     type Kind = CredentialPerCall;
/// }
///
/// impl CredentialAuthStrategy for &Exchange {
///     async fn get_token_with_credential(
///         self,
///         credential: SecretToken,
///     ) -> Result<ServiceToken, AuthError> {
///         // A real strategy exchanges `credential` for a token of its own.
///         Ok(ServiceToken::new(credential))
///     }
/// }
///
/// # async fn example() -> Result<(), AuthError> {
/// let strategy = Exchange;
/// let token = (&strategy)
///     .get_token_with_credential(SecretToken::new("header.payload.signature"))
///     .await?;
/// # drop(token);
/// # Ok(())
/// # }
/// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(example()).unwrap();
/// ```
///
/// A type that is both kinds does not compile. The second impl collides
/// with the one every `AuthStrategy` has:
///
/// ```compile_fail,E0119
/// use stack_auth::{
///     AuthError, AuthStrategy, CredentialAuthStrategy, CredentialPerCall, SecretToken,
///     ServiceToken, StrategyKind,
/// };
///
/// struct Both;
///
/// impl AuthStrategy for &Both {
///     async fn get_token(self) -> Result<ServiceToken, AuthError> {
///         Ok(ServiceToken::new(SecretToken::new("its.own.token")))
///     }
/// }
///
/// impl StrategyKind for &Both {
///     type Kind = CredentialPerCall;
/// }
///
/// impl CredentialAuthStrategy for &Both {
///     async fn get_token_with_credential(
///         self,
///         credential: SecretToken,
///     ) -> Result<ServiceToken, AuthError> {
///         Ok(ServiceToken::new(credential))
///     }
/// }
/// ```
#[diagnostic::on_unimplemented(
    message = "`{Self}` does not say which kind of strategy it is",
    label = "this strategy has no `StrategyKind`",
    note = "a strategy that takes a credential with each call implements `StrategyKind` with `type Kind = CredentialPerCall`, beside `CredentialAuthStrategy`",
    note = "a strategy with an identity of its own implements `AuthStrategy`, which gives it `Kind = OwnIdentity`. It does not implement `CredentialAuthStrategy`"
)]
pub trait StrategyKind {
    /// [`OwnIdentity`] or [`CredentialPerCall`].
    type Kind: kind::Sealed;
}

/// Every [`AuthStrategy`] has an identity of its own.
impl<T: AuthStrategy> StrategyKind for T {
    type Kind = OwnIdentity;
}
