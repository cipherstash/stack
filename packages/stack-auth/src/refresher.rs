use std::future::Future;

use crate::{AuthError, Token};

/// Internal trait defining how to refresh or re-authenticate to obtain a new [`Token`].
///
/// [`AutoRefresh<R>`](crate::auto_refresh::AutoRefresh) delegates the type-specific
/// parts of token refresh to the `Refresher` implementation while handling the
/// concurrency orchestration (cascade prevention, two-tier locking) generically.
///
/// On native targets the trait carries `Send + Sync` bounds so refreshers can
/// drive `tokio::spawn` background work. On wasm32 the bounds are dropped —
/// reqwest's fetch-backed futures are not `Send` (they reference JS handles
/// via `Rc<RefCell<...>>`) and edge runtimes are single-threaded anyway.
#[cfg(not(target_arch = "wasm32"))]
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

#[cfg(target_arch = "wasm32")]
pub(crate) trait Refresher {
    /// The credential extracted from the current token before a refresh attempt.
    type Credential;

    /// Persist a token after a successful refresh. Best-effort — implementations
    /// should log on failure rather than returning an error.
    ///
    /// On wasm32 persistence is typically a no-op (no filesystem) — token
    /// caching is in-memory and short-lived.
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
    ///
    /// The returned future is not `Send` — reqwest's wasm32 fetch backend
    /// holds JS handles via `Rc<RefCell<...>>` and edge runtimes are
    /// single-threaded anyway.
    fn refresh(
        &self,
        credential: &Self::Credential,
    ) -> impl Future<Output = Result<Token, AuthError>>;
}
