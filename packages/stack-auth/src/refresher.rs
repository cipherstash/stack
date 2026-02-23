use std::future::Future;

use crate::{AuthError, Token};

/// Internal trait defining how to refresh or re-authenticate to obtain a new [`Token`].
///
/// [`AutoRefresh<R>`](crate::auto_refresh::AutoRefresh) delegates the type-specific
/// parts of token refresh to the `Refresher` implementation while handling the
/// concurrency orchestration (cascade prevention, two-tier locking) generically.
pub(crate) trait Refresher: Send + Sync {
    /// The credential extracted from the current token before a refresh attempt.
    type Credential: Send;

    /// Persist a token after a successful refresh. Best-effort — implementations
    /// should log on failure rather than returning an error.
    fn save(&self, token: &Token);

    /// Extract a credential for refreshing.
    ///
    /// `token` is `None` on cold start (no cached token). Returns `None` if
    /// this refresher can't produce a token without a prior one (e.g. OAuth
    /// needs a refresh token).
    fn try_credential(&self, token: Option<&mut Token>) -> Option<Self::Credential>;

    /// Restore state after a failed refresh attempt (e.g. put the refresh token
    /// back so the next caller can retry).
    fn restore(&self, token: &mut Token, credential: Self::Credential);

    /// Perform the HTTP refresh or authentication call.
    fn refresh(
        &self,
        credential: &Self::Credential,
    ) -> impl Future<Output = Result<Token, AuthError>> + Send;
}
