use url::Url;

use stack_profile::ProfileStore;

use crate::refresher::Refresher;
use crate::{AuthError, SecretToken, Token};

/// Implements [`Refresher`] using OAuth refresh tokens.
///
/// Optionally owns a [`ProfileStore`] for persisting refreshed tokens to disk.
/// When the store is `None`, tokens are cached in memory only.
pub(crate) struct OAuthRefresher {
    store: Option<ProfileStore>,
    base_url: Url,
    client_id: String,
    region: String,
    device_instance_id: Option<String>,
}

impl OAuthRefresher {
    pub(crate) fn new(
        store: Option<ProfileStore>,
        base_url: Url,
        client_id: impl Into<String>,
        region: impl Into<String>,
        device_instance_id: Option<String>,
    ) -> Self {
        Self {
            store,
            base_url,
            client_id: client_id.into(),
            region: region.into(),
            device_instance_id,
        }
    }
}

impl Refresher for OAuthRefresher {
    type Credential = SecretToken;

    fn save(&self, token: &Token) {
        if let Some(store) = &self.store {
            match store.save_profile(token) {
                Ok(()) => tracing::debug!("refreshed token saved to disk"),
                Err(err) => tracing::warn!(%err, "failed to save refreshed token to disk"),
            }
        }
    }

    fn try_credential(&self, token: Option<&mut Token>) -> Option<Self::Credential> {
        token.and_then(|t| t.take_refresh_token())
    }

    fn restore(&self, token: &mut Token, credential: Self::Credential) {
        token.refresh_token = Some(credential);
    }

    async fn refresh(&self, credential: &Self::Credential) -> Result<Token, AuthError> {
        let mut token = Token::refresh(
            credential,
            &self.base_url,
            &self.client_id,
            self.device_instance_id.as_deref(),
        )
        .await?;
        token.set_region(&self.region);
        token.set_client_id(&self.client_id);
        if let Some(ref id) = self.device_instance_id {
            token.set_device_instance_id(id);
        }
        Ok(token)
    }
}
