use url::Url;

use crate::access_key_refresher::AccessKeyRefresher;
use crate::auto_refresh::AutoRefresh;
use crate::{AuthError, AuthStrategy, SecretToken};

/// An [`AuthStrategy`] that uses a static access key to authenticate.
///
/// The first call to [`get_token`](AuthStrategy::get_token) authenticates with
/// the server. Subsequent calls return the cached token until it expires, at
/// which point re-authentication happens automatically.
pub struct AccessKeyStrategy {
    inner: AutoRefresh<AccessKeyRefresher>,
}

impl AccessKeyStrategy {
    /// Create a new `AccessKeyStrategy`.
    pub fn new(access_key: SecretToken, base_url: Url, audience: Option<String>) -> Self {
        let refresher = AccessKeyRefresher::new(access_key, base_url, audience);
        Self {
            inner: AutoRefresh::new(refresher),
        }
    }
}

impl AuthStrategy for &AccessKeyStrategy {
    async fn get_token(self) -> Result<SecretToken, AuthError> {
        Ok(self.inner.get_token().await?)
    }
}
