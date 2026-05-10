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
    type Credential: Send;
    fn save(&self, token: &Token);
    fn try_credential(&self, token: Option<&mut Token>) -> Option<Self::Credential>;
    fn restore(&self, token: &mut Token, credential: Self::Credential);
    fn refresh(
        &self,
        credential: &Self::Credential,
    ) -> impl Future<Output = Result<Token, AuthError>> + Send;
}

#[cfg(target_arch = "wasm32")]
pub(crate) trait Refresher {
    type Credential;
    fn save(&self, token: &Token);
    fn try_credential(&self, token: Option<&mut Token>) -> Option<Self::Credential>;
    fn restore(&self, token: &mut Token, credential: Self::Credential);
    fn refresh(
        &self,
        credential: &Self::Credential,
    ) -> impl Future<Output = Result<Token, AuthError>>;
}
