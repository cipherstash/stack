use cts_common::Crn;

use crate::access_key_strategy::AccessKeyStrategy;
use crate::oauth_strategy::OAuthStrategy;
use stack_profile::ProfileStore;

use crate::{AuthError, AuthStrategy, SecretToken, Token};

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
///
/// # Example
///
/// ```no_run
/// use stack_auth::{AuthStrategy, AutoStrategy};
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let strategy = AutoStrategy::new()?;
/// let token = (&strategy).get_token().await?;
/// println!("Authenticated! token={:?}", token);
/// # Ok(())
/// # }
/// ```
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
        let access_key = std::env::var("CS_CLIENT_ACCESS_KEY").ok();
        let crn = std::env::var("CS_WORKSPACE_CRN").ok();
        let store = Some(ProfileStore::resolve(None)?);
        Self::detect(access_key, crn, store)
    }

    /// Core detection logic, separated for testability.
    ///
    /// Takes pre-resolved inputs rather than reading from the environment
    /// or filesystem directly.
    fn detect(
        access_key: Option<String>,
        crn: Option<String>,
        store: Option<ProfileStore>,
    ) -> Result<Self, AuthError> {
        // 1. Access key from environment
        if let Some(access_key) = access_key {
            let crn_str = crn.ok_or(AuthError::NotAuthenticated)?;
            let crn: Crn = crn_str.parse().map_err(AuthError::InvalidCrn)?;
            let key: crate::AccessKey = access_key.parse()?;
            let strategy = AccessKeyStrategy::new_with_crn(crn, key)?;
            return Ok(Self::AccessKey(strategy));
        }

        // 2. OAuth token from disk
        if let Some(store) = store {
            if store.exists_profile::<Token>() {
                let strategy = OAuthStrategy::with_profile(store).build()?;
                return Ok(Self::OAuth(strategy));
            }
        }

        // 3. No credentials found
        Err(AuthError::NotAuthenticated)
    }
}

impl AutoStrategy {
    /// Return the workspace CRN from the inner strategy.
    ///
    /// For [`AccessKeyStrategy`], this is the CRN parsed from the `CS_WORKSPACE_CRN`
    /// environment variable. For [`OAuthStrategy`], this is extracted from the stored
    /// token's claims.
    pub fn workspace_crn(&self) -> Result<Crn, AuthError> {
        match self {
            AutoStrategy::AccessKey(inner) => inner
                .workspace_crn()
                .cloned()
                .ok_or(AuthError::NotAuthenticated),
            AutoStrategy::OAuth(inner) => inner
                .workspace_crn()
                .cloned()
                .ok_or(AuthError::NotAuthenticated),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const VALID_CRN: &str = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY";

    fn make_oauth_token() -> Token {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = serde_json::json!({
            "iss": "https://cts.example.com/",
            "sub": "CS|test-user",
            "aud": "test-audience",
            "iat": now,
            "exp": now + 3600,
            "workspace": "ZVATKW3VHMFG27DY",
            "scope": "",
        });

        let key = jsonwebtoken::EncodingKey::from_secret(b"test-secret");
        let jwt = jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, &key).unwrap();

        Token {
            access_token: SecretToken::new(jwt),
            token_type: "Bearer".to_string(),
            expires_at: now + 3600,
            refresh_token: Some(SecretToken::new("test-refresh-token")),
            region: Some("ap-southeast-2.aws".to_string()),
            client_id: Some("test-client-id".to_string()),
            device_instance_id: None,
        }
    }

    fn write_token_store(dir: &std::path::Path) -> ProfileStore {
        let store = ProfileStore::new(dir);
        store.save_profile(&make_oauth_token()).unwrap();
        store
    }

    #[test]
    fn access_key_with_valid_crn() {
        let result = AutoStrategy::detect(
            Some("CSAKtestKeyId.testKeySecret".into()),
            Some(VALID_CRN.into()),
            None,
        );

        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), AutoStrategy::AccessKey(_)));
    }

    #[test]
    fn access_key_without_crn_returns_not_authenticated() {
        let result = AutoStrategy::detect(Some("CSAKtestKeyId.testKeySecret".into()), None, None);

        assert!(matches!(result, Err(AuthError::NotAuthenticated)));
    }

    #[test]
    fn access_key_with_invalid_crn_returns_invalid_crn() {
        let result = AutoStrategy::detect(
            Some("CSAKtestKeyId.testKeySecret".into()),
            Some("not-a-crn".into()),
            None,
        );

        assert!(matches!(result, Err(AuthError::InvalidCrn(_))));
    }

    #[test]
    fn oauth_store_with_valid_token() {
        let dir = tempfile::tempdir().unwrap();
        let store = write_token_store(dir.path());

        let result = AutoStrategy::detect(None, None, Some(store));

        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), AutoStrategy::OAuth(_)));
    }

    #[test]
    fn oauth_store_without_token_file_returns_not_authenticated() {
        let dir = tempfile::tempdir().unwrap();
        let store = ProfileStore::new(dir.path());

        let result = AutoStrategy::detect(None, None, Some(store));

        assert!(matches!(result, Err(AuthError::NotAuthenticated)));
    }

    #[test]
    fn no_credentials_returns_not_authenticated() {
        let result = AutoStrategy::detect(None, None, None);

        assert!(matches!(result, Err(AuthError::NotAuthenticated)));
    }

    #[test]
    fn access_key_takes_priority_over_oauth_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = write_token_store(dir.path());

        let result = AutoStrategy::detect(
            Some("CSAKtestKeyId.testKeySecret".into()),
            Some(VALID_CRN.into()),
            Some(store),
        );

        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), AutoStrategy::AccessKey(_)));
    }
}
