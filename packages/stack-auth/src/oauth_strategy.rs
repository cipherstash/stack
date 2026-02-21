use url::Url;

use crate::auto_refresh::AutoRefresh;
use crate::oauth_refresher::OAuthRefresher;
use crate::token_store::{TokenStore, TokenStoreError};
use crate::{AuthError, AuthStrategy, SecretToken};

/// An [`AuthStrategy`] that uses OAuth refresh tokens to maintain a valid access token.
///
/// Wraps a [`TokenStore`] for persistence and handles token refresh via the
/// OAuth `/oauth/token` endpoint.
///
/// # Construction
///
/// Requires a pre-existing token on disk (from a prior device code flow).
/// Returns [`TokenStoreError::NotFound`] if no token has been saved yet.
pub struct OAuthStrategy {
    inner: AutoRefresh<OAuthRefresher>,
}

impl OAuthStrategy {
    /// Create a new `OAuthStrategy` by loading a token from the given store.
    ///
    /// Returns an error if the token file is missing or unreadable.
    pub fn new(
        store: TokenStore,
        base_url: Url,
        client_id: impl Into<String>,
    ) -> Result<Self, TokenStoreError> {
        let token = store.load()?.ok_or(TokenStoreError::NotFound)?;
        let refresher = OAuthRefresher::new(store, base_url, client_id);
        Ok(Self {
            inner: AutoRefresh::with_token(refresher, token),
        })
    }
}

impl AuthStrategy for &OAuthStrategy {
    async fn get_token(self) -> Result<SecretToken, AuthError> {
        Ok(self.inner.get_token().await?)
    }
}
