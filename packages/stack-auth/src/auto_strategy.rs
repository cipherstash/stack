use cts_common::{Crn, Region};

use crate::access_key_strategy::AccessKeyStrategy;
use crate::oauth_strategy::OAuthStrategy;
use stack_profile::ProfileStore;

use crate::{AuthError, AuthStrategy, ServiceToken, Token};

/// An [`AuthStrategy`] that automatically detects available credentials
/// and delegates to the appropriate inner strategy.
///
/// # Detection order
///
/// 1. If the `CS_CLIENT_ACCESS_KEY` environment variable is set, an
///    [`AccessKeyStrategy`] is created. The region is resolved from the
///    `CS_REGION` environment variable, falling back to `CS_WORKSPACE_CRN`.
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
        let region = match std::env::var("CS_REGION").ok() {
            Some(r) => Some(r),
            None => std::env::var("CS_WORKSPACE_CRN")
                .ok()
                .map(|s| {
                    s.parse::<Crn>()
                        .map(|crn| crn.region.identifier())
                        .map_err(AuthError::InvalidCrn)
                })
                .transpose()?,
        };
        let store = Some(ProfileStore::resolve(None)?);
        Self::detect(access_key, region, store)
    }

    /// Core detection logic, separated for testability.
    ///
    /// Takes pre-resolved inputs rather than reading from the environment
    /// or filesystem directly.
    fn detect(
        access_key: Option<String>,
        region: Option<String>,
        store: Option<ProfileStore>,
    ) -> Result<Self, AuthError> {
        // 1. Access key from environment
        if let Some(access_key) = access_key {
            let region_str = region.ok_or(AuthError::NotAuthenticated)?;
            let region = Region::new(&region_str)?;
            let key: crate::AccessKey = access_key.parse()?;
            let strategy = AccessKeyStrategy::new(region, key)?;
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

impl AuthStrategy for &AutoStrategy {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
        match self {
            AutoStrategy::AccessKey(inner) => inner.get_token().await,
            AutoStrategy::OAuth(inner) => inner.get_token().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SecretToken, Token};
    use std::time::{SystemTime, UNIX_EPOCH};

    const VALID_REGION: &str = "ap-southeast-2.aws";

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
    fn access_key_with_valid_region() {
        let result = AutoStrategy::detect(
            Some("CSAKtestKeyId.testKeySecret".into()),
            Some(VALID_REGION.into()),
            None,
        );

        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), AutoStrategy::AccessKey(_)));
    }

    #[test]
    fn access_key_without_region_returns_not_authenticated() {
        let result = AutoStrategy::detect(Some("CSAKtestKeyId.testKeySecret".into()), None, None);

        assert!(matches!(result, Err(AuthError::NotAuthenticated)));
    }

    #[test]
    fn invalid_access_key_format_returns_invalid_access_key() {
        let result = AutoStrategy::detect(
            Some("not-a-valid-key".into()),
            Some(VALID_REGION.into()),
            None,
        );

        assert!(matches!(result, Err(AuthError::InvalidAccessKey(_))));
    }

    #[test]
    fn access_key_with_invalid_region_returns_error() {
        let result = AutoStrategy::detect(
            Some("CSAKtestKeyId.testKeySecret".into()),
            Some("not-a-region".into()),
            None,
        );

        assert!(matches!(result, Err(AuthError::Region(_))));
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
            Some(VALID_REGION.into()),
            Some(store),
        );

        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), AutoStrategy::AccessKey(_)));
    }
}
