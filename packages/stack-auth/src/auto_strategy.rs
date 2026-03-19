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
///    [`AccessKeyStrategy`] is created. The region is extracted from the
///    `CS_WORKSPACE_CRN` environment variable.
/// 2. If a token store file exists at the default location
///    (`~/.cipherstash/auth.json`), an [`OAuthStrategy`] is created from it.
/// 3. Otherwise, [`AuthError::NotAuthenticated`] is returned.
///
/// # Examples
///
/// ```no_run
/// use stack_auth::{AuthStrategy, AutoStrategy};
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// // Auto-detect from env vars + profile store
/// let strategy = AutoStrategy::detect()?;
/// let token = (&strategy).get_token().await?;
/// println!("Authenticated! token={:?}", token);
/// # Ok(())
/// # }
/// ```
///
/// ```no_run
/// use stack_auth::AutoStrategy;
///
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// // Provide explicit values with env/profile fallback
/// let strategy = AutoStrategy::builder()
///     .with_access_key("CSAK...")
///     .detect()?;
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
    /// Create a builder for configuring credential resolution.
    ///
    /// The builder lets callers provide explicit values (access key, region)
    /// that take precedence over environment variables and the profile store.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use stack_auth::AutoStrategy;
    /// use cts_common::Region;
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let strategy = AutoStrategy::builder()
    ///     .with_access_key("CSAKmyKeyId.myKeySecret")
    ///     .with_region(Region::aws("ap-southeast-2")?)
    ///     .detect()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> AutoStrategyBuilder {
        AutoStrategyBuilder {
            access_key: None,
            region: None,
        }
    }

    /// Detect credentials from environment variables and profile store.
    ///
    /// Equivalent to `AutoStrategy::builder().detect()`.
    ///
    /// Resolution order:
    /// 1. `CS_CLIENT_ACCESS_KEY` env var → [`AccessKeyStrategy`]
    /// 2. `~/.cipherstash/auth.json` → [`OAuthStrategy`]
    /// 3. [`AuthError::NotAuthenticated`]
    pub fn detect() -> Result<Self, AuthError> {
        Self::builder().detect()
    }

    /// Core detection logic, separated for testability.
    ///
    /// Takes pre-resolved inputs rather than reading from the environment
    /// or filesystem directly.
    fn detect_inner(
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

/// Builder for configuring credential resolution before calling [`detect()`](AutoStrategyBuilder::detect).
///
/// Explicit values provided via builder methods take precedence over environment variables.
/// Environment variables take precedence over the profile store.
///
/// # Example
///
/// ```no_run
/// use stack_auth::AutoStrategy;
///
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// // Provide access key explicitly, region from CS_WORKSPACE_CRN env var
/// let strategy = AutoStrategy::builder()
///     .with_access_key("CSAKmyKeyId.myKeySecret")
///     .detect()?;
/// # Ok(())
/// # }
/// ```
pub struct AutoStrategyBuilder {
    access_key: Option<String>,
    region: Option<Region>,
}

impl AutoStrategyBuilder {
    /// Provide an explicit access key. Takes precedence over env vars.
    pub fn with_access_key(mut self, access_key: impl Into<String>) -> Self {
        self.access_key = Some(access_key.into());
        self
    }

    /// Provide an explicit region. Takes precedence over env vars.
    pub fn with_region(mut self, region: impl Into<Region>) -> Self {
        self.region = Some(region.into());
        self
    }

    /// Resolve the auth strategy.
    ///
    /// Resolution order:
    /// 1. Explicit values provided via builder methods
    /// 2. Environment variables (`CS_CLIENT_ACCESS_KEY`, `CS_WORKSPACE_CRN` for region)
    /// 3. Profile store (`~/.cipherstash/auth.json` for OAuth)
    /// 4. [`AuthError::NotAuthenticated`]
    pub fn detect(self) -> Result<AutoStrategy, AuthError> {
        // Merge explicit values with env vars (explicit wins)
        let access_key = self
            .access_key
            .or_else(|| std::env::var("CS_CLIENT_ACCESS_KEY").ok());

        let region = self.region.map(|r| r.identifier()).or_else(|| {
            std::env::var("CS_WORKSPACE_CRN")
                .ok()
                .and_then(|s| s.parse::<Crn>().ok())
                .map(|crn| crn.region.identifier())
        });

        let store = ProfileStore::resolve(None).ok();

        AutoStrategy::detect_inner(access_key, region, store)
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

    mod detect_inner {
        use super::*;

        #[test]
        fn access_key_with_valid_region() {
            let result = AutoStrategy::detect_inner(
                Some("CSAKtestKeyId.testKeySecret".into()),
                Some(VALID_REGION.into()),
                None,
            );

            assert!(result.is_ok());
            assert!(matches!(result.unwrap(), AutoStrategy::AccessKey(_)));
        }

        #[test]
        fn access_key_without_region_returns_not_authenticated() {
            let result =
                AutoStrategy::detect_inner(Some("CSAKtestKeyId.testKeySecret".into()), None, None);

            assert!(matches!(result, Err(AuthError::NotAuthenticated)));
        }

        #[test]
        fn invalid_access_key_format_returns_invalid_access_key() {
            let result = AutoStrategy::detect_inner(
                Some("not-a-valid-key".into()),
                Some(VALID_REGION.into()),
                None,
            );

            assert!(matches!(result, Err(AuthError::InvalidAccessKey(_))));
        }

        #[test]
        fn access_key_with_invalid_region_returns_error() {
            let result = AutoStrategy::detect_inner(
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

            let result = AutoStrategy::detect_inner(None, None, Some(store));

            assert!(result.is_ok());
            assert!(matches!(result.unwrap(), AutoStrategy::OAuth(_)));
        }

        #[test]
        fn oauth_store_without_token_file_returns_not_authenticated() {
            let dir = tempfile::tempdir().unwrap();
            let store = ProfileStore::new(dir.path());

            let result = AutoStrategy::detect_inner(None, None, Some(store));

            assert!(matches!(result, Err(AuthError::NotAuthenticated)));
        }

        #[test]
        fn no_credentials_returns_not_authenticated() {
            let result = AutoStrategy::detect_inner(None, None, None);

            assert!(matches!(result, Err(AuthError::NotAuthenticated)));
        }

        #[test]
        fn access_key_takes_priority_over_oauth_store() {
            let dir = tempfile::tempdir().unwrap();
            let store = write_token_store(dir.path());

            let result = AutoStrategy::detect_inner(
                Some("CSAKtestKeyId.testKeySecret".into()),
                Some(VALID_REGION.into()),
                Some(store),
            );

            assert!(result.is_ok());
            assert!(matches!(result.unwrap(), AutoStrategy::AccessKey(_)));
        }
    }

    mod builder {
        use super::*;

        #[test]
        fn explicit_access_key_and_region() {
            let result = AutoStrategy::builder()
                .with_access_key("CSAKtestKeyId.testKeySecret")
                .with_region(Region::new(VALID_REGION).unwrap())
                .detect();

            assert!(result.is_ok());
            assert!(matches!(result.unwrap(), AutoStrategy::AccessKey(_)));
        }

        #[test]
        fn explicit_access_key_without_region_and_no_env_returns_not_authenticated() {
            // Save and clear env to ensure no fallback
            let saved_crn = std::env::var("CS_WORKSPACE_CRN").ok();
            std::env::remove_var("CS_WORKSPACE_CRN");

            let result = AutoStrategy::builder()
                .with_access_key("CSAKtestKeyId.testKeySecret")
                .detect();

            // Restore env
            if let Some(val) = saved_crn {
                std::env::set_var("CS_WORKSPACE_CRN", val);
            }

            assert!(matches!(result, Err(AuthError::NotAuthenticated)));
        }

        #[test]
        fn invalid_explicit_access_key_returns_invalid_access_key() {
            let result = AutoStrategy::builder()
                .with_access_key("not-a-valid-key")
                .with_region(Region::new(VALID_REGION).unwrap())
                .detect();

            assert!(matches!(result, Err(AuthError::InvalidAccessKey(_))));
        }
    }
}
