use cts_common::Crn;

use crate::access_key_strategy::AccessKeyStrategy;
use crate::oauth_strategy::OAuthStrategy;
use crate::token_store::TokenStore;
use crate::{AuthError, AuthStrategy, SecretToken};

/// An [`AuthStrategy`] that automatically detects available credentials
/// and delegates to the appropriate inner strategy.
///
/// # Detection order
///
/// 1. If the `CS_CLIENT_ACCESS_KEY` environment variable is set, an
///    [`AccessKeyStrategy`] is created. The region is extracted from the
///    `CS_WORKSPACE_CRN` environment variable.
/// 2. If a token store file exists at the default location
///    (`~/.cipherstash/auth.json`), an [`OAuthStrategy`] is created from it.
/// 3. Otherwise, [`AuthError::NotAuthenticated`] is returned.
pub enum AutoStrategy {
    /// Authenticated via a static access key.
    AccessKey(AccessKeyStrategy),
    /// Authenticated via OAuth tokens persisted on disk.
    OAuth(OAuthStrategy),
}

impl AutoStrategy {
    /// Detect available credentials and build the appropriate strategy.
    ///
    /// See the [type-level docs](AutoStrategy) for the detection order.
    pub fn new() -> Result<Self, AuthError> {
        // 1. Access key from environment
        if let Ok(access_key) = std::env::var("CS_CLIENT_ACCESS_KEY") {
            let crn_str =
                std::env::var("CS_WORKSPACE_CRN").map_err(|_| AuthError::NotAuthenticated)?;
            let crn: Crn = crn_str.parse().map_err(AuthError::InvalidCrn)?;
            let strategy = AccessKeyStrategy::new(crn.region, SecretToken::new(access_key))?;
            return Ok(Self::AccessKey(strategy));
        }

        // 2. OAuth token from disk
        if let Ok(store) = TokenStore::new_default() {
            if store.path().exists() {
                let strategy = OAuthStrategy::using_store(store)?;
                return Ok(Self::OAuth(strategy));
            }
        }

        // 3. No credentials found
        Err(AuthError::NotAuthenticated)
    }
}

impl AuthStrategy for &AutoStrategy {
    async fn get_token(self) -> Result<SecretToken, AuthError> {
        match self {
            AutoStrategy::AccessKey(inner) => inner.get_token().await,
            AutoStrategy::OAuth(inner) => inner.get_token().await,
        }
    }
}
