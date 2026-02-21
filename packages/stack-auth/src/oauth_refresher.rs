use url::Url;

use crate::refresher::Refresher;
use crate::token_store::TokenStore;
use crate::{AuthError, SecretToken, Token};

/// Implements [`Refresher`] using OAuth refresh tokens.
///
/// Owns a [`TokenStore`] for persisting refreshed tokens to disk.
pub(crate) struct OAuthRefresher {
    store: TokenStore,
    base_url: Url,
    client_id: String,
}

impl OAuthRefresher {
    pub(crate) fn new(store: TokenStore, base_url: Url, client_id: impl Into<String>) -> Self {
        Self {
            store,
            base_url,
            client_id: client_id.into(),
        }
    }
}

impl Refresher for OAuthRefresher {
    type Credential = SecretToken;

    fn save(&self, token: &Token) {
        match self.store.save(token) {
            Ok(()) => tracing::debug!("refreshed token saved to disk"),
            Err(err) => tracing::warn!(%err, "failed to save refreshed token to disk"),
        }
    }

    fn try_credential(&self, token: Option<&mut Token>) -> Option<Self::Credential> {
        token.and_then(|t| t.take_refresh_token())
    }

    fn restore(&self, token: &mut Token, credential: Self::Credential) {
        token.refresh_token = Some(credential);
    }

    async fn refresh(&self, credential: &Self::Credential) -> Result<Token, AuthError> {
        Token::refresh(credential, &self.base_url, &self.client_id).await
    }
}
