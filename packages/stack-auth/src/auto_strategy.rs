use cts_common::Crn;

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
    /// The builder lets callers provide explicit values (access key, workspace CRN)
    /// that take precedence over environment variables and the profile store.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use stack_auth::AutoStrategy;
    /// use cts_common::Crn;
    ///
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// let crn: Crn = "crn:ap-southeast-2.aws:workspace-id".parse()?;
    /// let strategy = AutoStrategy::builder()
    ///     .with_access_key("CSAKmyKeyId.myKeySecret")
    ///     .with_workspace_crn(crn)
    ///     .detect()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> AutoStrategyBuilder {
        AutoStrategyBuilder {
            access_key: None,
            crn: None,
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
        crn: Option<Crn>,
        store: Option<ProfileStore>,
    ) -> Result<Self, AuthError> {
        // 1. Access key from environment
        if let Some(access_key) = access_key {
            let region = crn
                .map(|c| c.region)
                .ok_or(AuthError::MissingWorkspaceCrn)?;
            let key: crate::AccessKey = access_key.parse()?;
            let strategy = AccessKeyStrategy::new(region, key)?;
            return Ok(Self::AccessKey(strategy));
        }

        // 2. OAuth token from disk (in the current workspace directory)
        if let Some(store) = store {
            let has_token = store
                .current_workspace_store()
                .map(|ws| ws.exists_profile::<Token>())
                .unwrap_or(false);
            if has_token {
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
    crn: Option<Crn>,
}

impl AutoStrategyBuilder {
    /// Provide an explicit access key. Takes precedence over env vars.
    pub fn with_access_key(mut self, access_key: impl Into<String>) -> Self {
        self.access_key = Some(access_key.into());
        self
    }

    /// Provide an explicit workspace CRN. Takes precedence over env vars.
    pub fn with_workspace_crn(mut self, crn: Crn) -> Self {
        self.crn = Some(crn);
        self
    }

    /// Resolve the auth strategy.
    ///
    /// Resolution order:
    /// 1. Explicit values provided via builder methods
    /// 2. Environment variables (`CS_CLIENT_ACCESS_KEY`, `CS_WORKSPACE_CRN`)
    /// 3. Profile store (`~/.cipherstash/auth.json` for OAuth)
    /// 4. [`AuthError::NotAuthenticated`]
    pub fn detect(self) -> Result<AutoStrategy, AuthError> {
        // Merge explicit values with env vars (explicit wins)
        let access_key = self
            .access_key
            .or_else(|| std::env::var("CS_CLIENT_ACCESS_KEY").ok());

        let crn = match self.crn {
            Some(crn) => Some(crn),
            None => std::env::var("CS_WORKSPACE_CRN")
                .ok()
                .map(|s| s.parse::<Crn>().map_err(AuthError::InvalidCrn))
                .transpose()?,
        };

        // Resolve errors (e.g. missing profile directory) are intentionally
        // swallowed here so that env-var-only setups don't need a profile dir.
        // If no credentials are found at all, NotAuthenticated is returned.
        let store = ProfileStore::resolve(None).ok();

        AutoStrategy::detect_inner(access_key, crn, store)
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

    const VALID_CRN: &str = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY";

    fn valid_crn() -> Crn {
        VALID_CRN.parse().unwrap()
    }

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
        store.init_workspace("ZVATKW3VHMFG27DY").unwrap();
        let ws_store = store.current_workspace_store().unwrap();
        ws_store.save_profile(&make_oauth_token()).unwrap();
        store
    }

    mod detect_inner {
        use super::*;

        #[test]
        fn access_key_with_valid_crn() {
            let result = AutoStrategy::detect_inner(
                Some("CSAKtestKeyId.testKeySecret".into()),
                Some(valid_crn()),
                None,
            );

            assert!(result.is_ok());
            assert!(matches!(result.unwrap(), AutoStrategy::AccessKey(_)));
        }

        #[test]
        fn access_key_without_crn_returns_missing_workspace_crn() {
            let result =
                AutoStrategy::detect_inner(Some("CSAKtestKeyId.testKeySecret".into()), None, None);

            assert!(matches!(result, Err(AuthError::MissingWorkspaceCrn)));
        }

        #[test]
        fn invalid_access_key_format_returns_invalid_access_key() {
            let result =
                AutoStrategy::detect_inner(Some("not-a-valid-key".into()), Some(valid_crn()), None);

            assert!(matches!(result, Err(AuthError::InvalidAccessKey(_))));
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
                Some(valid_crn()),
                Some(store),
            );

            assert!(result.is_ok());
            assert!(matches!(result.unwrap(), AutoStrategy::AccessKey(_)));
        }
    }

    mod builder {
        use super::*;

        #[test]
        fn explicit_access_key_and_crn() {
            let result = AutoStrategy::builder()
                .with_access_key("CSAKtestKeyId.testKeySecret")
                .with_workspace_crn(valid_crn())
                .detect();

            assert!(result.is_ok());
            assert!(matches!(result.unwrap(), AutoStrategy::AccessKey(_)));
        }

        #[test]
        fn explicit_access_key_without_crn_and_no_env_returns_missing_workspace_crn() {
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

            assert!(matches!(result, Err(AuthError::MissingWorkspaceCrn)));
        }

        #[test]
        fn invalid_crn_env_var_returns_invalid_crn() {
            let saved_crn = std::env::var("CS_WORKSPACE_CRN").ok();
            std::env::set_var("CS_WORKSPACE_CRN", "not-a-crn");

            let result = AutoStrategy::builder()
                .with_access_key("CSAKtestKeyId.testKeySecret")
                .detect();

            // Restore env
            match saved_crn {
                Some(val) => std::env::set_var("CS_WORKSPACE_CRN", val),
                None => std::env::remove_var("CS_WORKSPACE_CRN"),
            }

            assert!(matches!(result, Err(AuthError::InvalidCrn(_))));
        }

        #[test]
        fn invalid_explicit_access_key_returns_invalid_access_key() {
            let result = AutoStrategy::builder()
                .with_access_key("not-a-valid-key")
                .with_workspace_crn(valid_crn())
                .detect();

            assert!(matches!(result, Err(AuthError::InvalidAccessKey(_))));
        }
    }
}
