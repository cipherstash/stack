use cts_common::Crn;

use crate::access_key_strategy::AccessKeyStrategy;
use crate::device_session_strategy::DeviceSessionStrategy;
use stack_profile::ProfileStore;

use crate::transport::{self, SharedTransport};
use crate::HttpTransport;
use crate::Token;
use crate::{AuthError, AuthStrategy, SecretToken, ServiceToken};

/// An [`AuthStrategy`] that automatically detects available credentials
/// and delegates to the appropriate inner strategy.
///
/// # Detection order
///
/// 1. If the `CS_CLIENT_ACCESS_KEY` environment variable is set, an
///    [`AccessKeyStrategy`] is created. The workspace CRN is parsed from
///    `CS_WORKSPACE_CRN` (or the explicit
///    [`with_workspace_crn`](AutoStrategyBuilder::with_workspace_crn) value);
///    its region drives service discovery and its workspace ID is used
///    to verify every issued token.
/// 2. If a token store file exists at the default location
///    (`~/.cipherstash/auth.json`), a [`DeviceSessionStrategy`] is created from it.
///    If a workspace CRN is supplied, the session of that workspace is used
///    (not the CLI's current one) and every token is verified against it.
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
    DeviceSession(DeviceSessionStrategy),
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
            transport: None,
        }
    }

    /// Detect credentials from environment variables and profile store.
    ///
    /// Equivalent to `AutoStrategy::builder().detect()`.
    ///
    /// Resolution order:
    /// 1. `CS_CLIENT_ACCESS_KEY` env var → [`AccessKeyStrategy`]
    /// 2. `~/.cipherstash/auth.json` → [`DeviceSessionStrategy`] (the workspace
    ///    named by `CS_WORKSPACE_CRN` if set, otherwise the current one)
    /// 3. [`AuthError::NotAuthenticated`]
    pub fn detect() -> Result<Self, AuthError> {
        Self::builder().detect()
    }

    /// The workspace CRN that [`detect`](Self::detect) resolves, without
    /// building a strategy.
    ///
    /// A strategy constructed by hand takes a CRN —
    /// [`OidcFederationStrategy::new(crn, provider)`](crate::OidcFederationStrategy::new),
    /// [`AccessKeyStrategy::new(crn, key)`](crate::AccessKeyStrategy::new) —
    /// and this finds the one configured for the process, in the order
    /// `detect` looks:
    ///
    /// 1. `CS_WORKSPACE_CRN`, if it is set. The CRN is returned as written,
    ///    region included.
    /// 2. Otherwise, if `CS_CLIENT_ACCESS_KEY` is set, nothing: `detect`
    ///    refuses an access key without a CRN, and so does this. Only the
    ///    variable's presence is checked.
    /// 3. Otherwise the session `npx stash auth login` saved for the CLI's
    ///    current workspace (`auth.json` in the profile directory,
    ///    `~/.cipherstash` unless `CS_CONFIG_PATH` names another). The CRN
    ///    is that session's region and workspace.
    ///
    /// Nothing falls back to a default workspace, and the profile directory
    /// is not looked at when either variable is set. On wasm32 there is no
    /// profile, so `CS_WORKSPACE_CRN` is the only source.
    ///
    /// When `CS_WORKSPACE_CRN` is set and `detect` finds a CLI session rather
    /// than an access key, the strategy `detect` builds checks only the
    /// workspace id of its tokens against the variable, and sends its
    /// requests to the region the session records. The two agree whenever
    /// the variable names the region the session was created in; this
    /// function cannot tell when they do not, since it returns the variable
    /// unchanged.
    ///
    /// # Errors
    ///
    /// - [`AuthError::InvalidCrn`] if `CS_WORKSPACE_CRN` is set but is not a
    ///   CRN. The profile is not tried in its place.
    /// - [`AuthError::MissingWorkspaceCrn`] if `CS_CLIENT_ACCESS_KEY` is set
    ///   and `CS_WORKSPACE_CRN` is not.
    /// - [`AuthError::NotAuthenticated`] if neither variable is set and the
    ///   CLI's current workspace has no saved session (or there is no
    ///   profile directory, or no current workspace), or the saved session
    ///   records no region. Set `CS_WORKSPACE_CRN`, or log in with
    ///   `npx stash auth login`.
    /// - [`AuthError::Store`] if the saved session exists but cannot be read
    ///   or parsed.
    /// - [`AuthError::InvalidToken`] if the saved session's token is not a
    ///   JWT with a `workspace` claim.
    /// - [`AuthError::Server`] if the region the saved session records is not
    ///   one this crate knows.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use stack_auth::{AuthError, AutoStrategy, OidcFederationStrategy, OidcProviderFn, SecretToken};
    ///
    /// # fn run() -> Result<(), AuthError> {
    /// let crn = AutoStrategy::detect_workspace_crn()?;
    /// let provider = OidcProviderFn::new(|| async {
    ///     // The JWT of the user behind the current request.
    ///     Ok::<_, AuthError>(SecretToken::new("header.payload.signature".to_string()))
    /// });
    /// let strategy = OidcFederationStrategy::new(crn, provider)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn detect_workspace_crn() -> Result<Crn, AuthError> {
        let env_crn = std::env::var("CS_WORKSPACE_CRN").ok();
        // Presence only. Read through the same wrapper `detect` uses, so the
        // copy read is wiped when it is dropped.
        let has_access_key = access_key_from_env(std::env::var("CS_CLIENT_ACCESS_KEY")).is_some();
        #[cfg(not(target_arch = "wasm32"))]
        let store = resolve_profile_store;
        // wasm32 has no profile directory: the variable is the only source.
        #[cfg(target_arch = "wasm32")]
        let store = || None;
        Self::workspace_crn_inner(env_crn.as_deref(), has_access_key, store)
    }

    /// Core of [`detect_workspace_crn`](Self::detect_workspace_crn), over
    /// pre-read variables. `store` is called only when neither variable
    /// decides the answer.
    fn workspace_crn_inner(
        env_crn: Option<&str>,
        has_access_key: bool,
        store: impl FnOnce() -> Option<ProfileStore>,
    ) -> Result<Crn, AuthError> {
        if let Some(crn) = env_crn {
            return crn.parse::<Crn>().map_err(AuthError::from);
        }
        if has_access_key {
            return Err(AuthError::MissingWorkspaceCrn(
                crate::error::MissingWorkspaceCrn,
            ));
        }
        // The same session `detect` would build a `DeviceSessionStrategy`
        // from: the current workspace's, and only if it has a token.
        let session = store()
            .and_then(|store| store.current_workspace_store().ok())
            .filter(|ws| ws.exists_profile::<Token>())
            .ok_or(AuthError::NotAuthenticated(crate::error::NotAuthenticated))?;
        session.load_profile::<Token>()?.workspace_crn()
    }

    /// Core detection logic, separated for testability.
    ///
    /// Takes pre-resolved inputs rather than reading from the environment
    /// or filesystem directly. On wasm32 the profile-store fallback is
    /// unreachable (no filesystem) — callers must supply an access key.
    #[cfg(not(target_arch = "wasm32"))]
    fn detect_inner(
        access_key: Option<&str>,
        crn: Option<Crn>,
        store: Option<ProfileStore>,
        transport: Option<SharedTransport>,
    ) -> Result<Self, AuthError> {
        // 1. Access key from environment
        if let Some(access_key) = access_key {
            let workspace_crn = crn.ok_or(AuthError::MissingWorkspaceCrn(
                crate::error::MissingWorkspaceCrn,
            ))?;
            let key: crate::AccessKey = access_key.parse()?;
            let strategy = AccessKeyStrategy::builder(workspace_crn, key)
                .maybe_transport(transport)
                .build()?;
            return Ok(Self::AccessKey(strategy));
        }

        // 2. OAuth token from disk. A supplied CRN pins the workspace, so the
        //    CLI's current workspace is irrelevant; without one, use it.
        if let Some(store) = store {
            let ws_store = match &crn {
                Some(crn) => store.workspace_store(crn.workspace_id.as_str()),
                None => store.current_workspace_store(),
            };
            let has_token = ws_store
                .map(|ws| ws.exists_profile::<Token>())
                .unwrap_or(false);
            if has_token {
                let mut builder = DeviceSessionStrategy::with_profile(store);
                if let Some(crn) = &crn {
                    builder = builder.workspace_crn(crn);
                }
                let strategy = builder.maybe_transport(transport).build()?;
                return Ok(Self::DeviceSession(strategy));
            }
        }

        // 3. No credentials found
        Err(AuthError::NotAuthenticated(crate::error::NotAuthenticated))
    }

    #[cfg(target_arch = "wasm32")]
    fn detect_inner(
        access_key: Option<&str>,
        crn: Option<Crn>,
        transport: Option<SharedTransport>,
    ) -> Result<Self, AuthError> {
        if let Some(access_key) = access_key {
            let workspace_crn = crn.ok_or(AuthError::MissingWorkspaceCrn(
                crate::error::MissingWorkspaceCrn,
            ))?;
            let key: crate::AccessKey = access_key.parse()?;
            let strategy = AccessKeyStrategy::builder(workspace_crn, key)
                .maybe_transport(transport)
                .build()?;
            return Ok(Self::AccessKey(strategy));
        }
        Err(AuthError::NotAuthenticated(crate::error::NotAuthenticated))
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
    /// A [`SecretToken`] so the key is wiped on drop and masked in `Debug`.
    access_key: Option<SecretToken>,
    crn: Option<Crn>,
    transport: Option<SharedTransport>,
}

impl AutoStrategyBuilder {
    /// Send the detected strategy's requests through `transport` instead of
    /// the bundled `reqwest` client. Required without the `http` feature.
    pub fn transport(mut self, transport: impl HttpTransport) -> Self {
        self.transport = Some(transport::share(transport));
        self
    }

    /// Provide an explicit access key. Takes precedence over env vars.
    pub fn with_access_key(mut self, access_key: impl Into<String>) -> Self {
        self.access_key = Some(SecretToken::new(access_key));
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
        // Wrapped as soon as it is read, so this copy is wiped on drop. The
        // process environment keeps its own copy, which is beyond our reach.
        let access_key = self
            .access_key
            .or_else(|| access_key_from_env(std::env::var("CS_CLIENT_ACCESS_KEY")));

        let crn = match self.crn {
            Some(crn) => Some(crn),
            None => std::env::var("CS_WORKSPACE_CRN")
                .ok()
                .map(|s| s.parse::<Crn>().map_err(AuthError::from))
                .transpose()?,
        };

        #[cfg(not(target_arch = "wasm32"))]
        {
            let store = resolve_profile_store();
            AutoStrategy::detect_inner(
                access_key.as_ref().map(SecretToken::as_str),
                crn,
                store,
                self.transport,
            )
        }
        #[cfg(target_arch = "wasm32")]
        {
            AutoStrategy::detect_inner(
                access_key.as_ref().map(SecretToken::as_str),
                crn,
                self.transport,
            )
        }
    }
}

impl AuthStrategy for &AutoStrategy {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
        match self {
            AutoStrategy::AccessKey(inner) => inner.get_token().await,
            AutoStrategy::DeviceSession(inner) => inner.get_token().await,
        }
    }
}

/// The CLI's profile directory, if one can be resolved.
///
/// A resolve error (no home directory, say) is not an error for detection:
/// env-var-only setups have no profile directory. If no credentials are
/// found at all, the caller reports that instead.
#[cfg(not(target_arch = "wasm32"))]
fn resolve_profile_store() -> Option<ProfileStore> {
    match ProfileStore::resolve(None) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::info!(error = %e, "could not resolve profile store; continuing without it");
            None
        }
    }
}

/// Wrap an access key read from the environment, wiping it if it is unusable.
///
/// A value that is not valid UTF-8 comes back as [`VarError::NotUnicode`],
/// which owns the whole key. It cannot be a valid access key, so it is
/// treated as unset, as before; but it is wiped first rather than dropped,
/// since it is still a credential.
///
/// [`VarError::NotUnicode`]: std::env::VarError::NotUnicode
fn access_key_from_env(value: Result<String, std::env::VarError>) -> Option<SecretToken> {
    match value {
        Ok(key) => Some(SecretToken::new(key)),
        Err(std::env::VarError::NotUnicode(key)) => {
            drop(zeroize::Zeroizing::new(key.into_encoded_bytes()));
            None
        }
        Err(std::env::VarError::NotPresent) => None,
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
            "org_id": "org_test_default",
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
            federated_from: None,
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
        #[cfg(feature = "http")] // builds a strategy with no transport of its own
        fn access_key_with_valid_crn() {
            let result = AutoStrategy::detect_inner(
                Some("CSAKtestKeyId.testKeySecret"),
                Some(valid_crn()),
                None,
                None,
            );

            assert!(result.is_ok());
            assert!(matches!(result.unwrap(), AutoStrategy::AccessKey(_)));
        }

        #[test]
        fn access_key_without_crn_returns_missing_workspace_crn() {
            let result =
                AutoStrategy::detect_inner(Some("CSAKtestKeyId.testKeySecret"), None, None, None);

            assert!(matches!(result, Err(AuthError::MissingWorkspaceCrn(_))));
        }

        #[test]
        fn invalid_access_key_format_returns_invalid_access_key() {
            let result =
                AutoStrategy::detect_inner(Some("not-a-valid-key"), Some(valid_crn()), None, None);

            assert!(matches!(result, Err(AuthError::InvalidAccessKey(_))));
        }

        #[test]
        #[cfg(feature = "http")] // builds a strategy with no transport of its own
        fn oauth_store_with_valid_token() {
            let dir = tempfile::tempdir().unwrap();
            let store = write_token_store(dir.path());

            let result = AutoStrategy::detect_inner(None, None, Some(store), None);

            assert!(result.is_ok());
            assert!(matches!(result.unwrap(), AutoStrategy::DeviceSession(_)));
        }

        #[test]
        #[cfg(feature = "http")] // builds a strategy with no transport of its own
        fn crn_selects_that_workspaces_session_over_the_current_one() {
            let dir = tempfile::tempdir().unwrap();
            let store = write_token_store(dir.path());
            // The CLI user switches to another workspace with no session.
            store.init_workspace("AAAAAAAAAAAAAAAA").unwrap();

            let result = AutoStrategy::detect_inner(None, Some(valid_crn()), Some(store), None);

            assert!(matches!(result, Ok(AutoStrategy::DeviceSession(_))));
        }

        #[test]
        #[cfg(feature = "http")] // builds a strategy with no transport of its own
        fn crn_matching_the_current_workspace_builds_a_device_session() {
            let dir = tempfile::tempdir().unwrap();
            let store = write_token_store(dir.path());

            let result = AutoStrategy::detect_inner(None, Some(valid_crn()), Some(store), None);

            assert!(matches!(result, Ok(AutoStrategy::DeviceSession(_))));
        }

        #[test]
        #[cfg(feature = "http")] // saves a token, so the fallback would build a strategy
        fn crn_without_a_session_for_that_workspace_is_not_authenticated() {
            let dir = tempfile::tempdir().unwrap();
            // The current workspace has a token; the CRN names another.
            let store = write_token_store(dir.path());
            let crn: Crn = "crn:ap-southeast-2.aws:AAAAAAAAAAAAAAAA".parse().unwrap();

            let result = AutoStrategy::detect_inner(None, Some(crn), Some(store), None);

            assert!(matches!(result, Err(AuthError::NotAuthenticated(_))));
        }

        #[test]
        fn oauth_store_without_token_file_returns_not_authenticated() {
            let dir = tempfile::tempdir().unwrap();
            let store = ProfileStore::new(dir.path());

            let result = AutoStrategy::detect_inner(None, None, Some(store), None);

            assert!(matches!(result, Err(AuthError::NotAuthenticated(_))));
        }

        #[test]
        fn no_credentials_returns_not_authenticated() {
            let result = AutoStrategy::detect_inner(None, None, None, None);

            assert!(matches!(result, Err(AuthError::NotAuthenticated(_))));
        }

        #[test]
        #[cfg(feature = "http")] // builds a strategy with no transport of its own
        fn access_key_takes_priority_over_oauth_store() {
            let dir = tempfile::tempdir().unwrap();
            let store = write_token_store(dir.path());

            let result = AutoStrategy::detect_inner(
                Some("CSAKtestKeyId.testKeySecret"),
                Some(valid_crn()),
                Some(store),
                None,
            );

            assert!(result.is_ok());
            assert!(matches!(result.unwrap(), AutoStrategy::AccessKey(_)));
        }
    }

    mod builder {
        use super::*;

        #[test]
        #[cfg(feature = "http")] // builds a strategy with no transport of its own
        fn explicit_access_key_and_crn() {
            let result = AutoStrategy::builder()
                .with_access_key("CSAKtestKeyId.testKeySecret")
                .with_workspace_crn(valid_crn())
                .detect();

            assert!(result.is_ok());
            assert!(matches!(result.unwrap(), AutoStrategy::AccessKey(_)));
        }

        // Both tests below set process environment. `temp_env` serialises
        // them (and restores the variable afterwards), which matters under
        // plain `cargo test`, where tests share one process.
        #[test]
        fn explicit_access_key_without_crn_and_no_env_returns_missing_workspace_crn() {
            let result = temp_env::with_var_unset("CS_WORKSPACE_CRN", || {
                AutoStrategy::builder()
                    .with_access_key("CSAKtestKeyId.testKeySecret")
                    .detect()
            });

            assert!(matches!(result, Err(AuthError::MissingWorkspaceCrn(_))));
        }

        #[test]
        fn invalid_crn_env_var_returns_invalid_crn() {
            let result = temp_env::with_var("CS_WORKSPACE_CRN", Some("not-a-crn"), || {
                AutoStrategy::builder()
                    .with_access_key("CSAKtestKeyId.testKeySecret")
                    .detect()
            });

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

    mod workspace_crn_inner {
        use super::*;

        const OTHER_CRN: &str = "crn:us-east-1.aws:AAAAAAAAAAAAAAAA";

        /// A profile source for a case that must not reach the profile.
        fn unreachable_store() -> Option<ProfileStore> {
            panic!("the profile directory must not be resolved")
        }

        mod given_cs_workspace_crn {
            use super::*;

            #[test]
            fn returns_it_without_resolving_the_profile() {
                let crn =
                    AutoStrategy::workspace_crn_inner(Some(OTHER_CRN), false, unreachable_store)
                        .unwrap();

                assert_eq!(crn.to_string(), OTHER_CRN, "the variable's CRN is returned");
            }

            #[test]
            fn returns_it_with_an_access_key_too() {
                let crn =
                    AutoStrategy::workspace_crn_inner(Some(OTHER_CRN), true, unreachable_store)
                        .unwrap();

                assert_eq!(
                    crn.to_string(),
                    OTHER_CRN,
                    "an access key with a CRN is the CRN"
                );
            }

            #[test]
            fn that_is_not_a_crn_is_invalid_crn_not_the_profiles() {
                let result =
                    AutoStrategy::workspace_crn_inner(Some("not-a-crn"), false, unreachable_store);

                assert!(
                    matches!(result, Err(AuthError::InvalidCrn(_))),
                    "expected InvalidCrn, got: {result:?}"
                );
            }
        }

        mod given_an_access_key_and_no_cs_workspace_crn {
            use super::*;

            #[test]
            fn is_missing_workspace_crn_as_detect_is() {
                let result = AutoStrategy::workspace_crn_inner(None, true, unreachable_store);

                assert!(
                    matches!(result, Err(AuthError::MissingWorkspaceCrn(_))),
                    "an access key without a CRN must not fall back to the profile, got: {result:?}"
                );
            }
        }

        mod given_neither_variable {
            use super::*;

            #[test]
            fn returns_the_crn_of_the_current_workspaces_session() {
                let dir = tempfile::tempdir().unwrap();
                let store = write_token_store(dir.path());

                let crn = AutoStrategy::workspace_crn_inner(None, false, || Some(store)).unwrap();

                assert_eq!(
                    crn,
                    valid_crn(),
                    "the session's region and workspace make the CRN"
                );
            }

            #[test]
            fn a_current_workspace_without_a_session_is_not_authenticated() {
                let dir = tempfile::tempdir().unwrap();
                let store = write_token_store(dir.path());
                // The CLI user switches to another workspace with no session.
                store.init_workspace("AAAAAAAAAAAAAAAA").unwrap();

                let result = AutoStrategy::workspace_crn_inner(None, false, || Some(store));

                assert!(
                    matches!(result, Err(AuthError::NotAuthenticated(_))),
                    "another workspace's session must not be used, got: {result:?}"
                );
            }

            #[test]
            fn a_profile_with_no_current_workspace_is_not_authenticated() {
                let dir = tempfile::tempdir().unwrap();
                let store = ProfileStore::new(dir.path());

                let result = AutoStrategy::workspace_crn_inner(None, false, || Some(store));

                assert!(
                    matches!(result, Err(AuthError::NotAuthenticated(_))),
                    "expected NotAuthenticated, got: {result:?}"
                );
            }

            #[test]
            fn no_profile_is_not_authenticated() {
                let result = AutoStrategy::workspace_crn_inner(None, false, || None);

                assert!(
                    matches!(result, Err(AuthError::NotAuthenticated(_))),
                    "expected NotAuthenticated, got: {result:?}"
                );
            }
        }
    }

    // These set process environment, so `temp_env` serialises them and
    // restores the variables afterwards (plain `cargo test` shares one
    // process). `CS_CONFIG_PATH` always names a temporary directory, so the
    // developer's own profile is never read.
    mod detect_workspace_crn {
        use super::*;

        fn detect_with(
            workspace_crn: Option<&str>,
            access_key: Option<&str>,
            profile: &std::path::Path,
        ) -> Result<Crn, AuthError> {
            temp_env::with_vars(
                [
                    ("CS_WORKSPACE_CRN", workspace_crn),
                    ("CS_CLIENT_ACCESS_KEY", access_key),
                    ("CS_CONFIG_PATH", profile.to_str()),
                ],
                AutoStrategy::detect_workspace_crn,
            )
        }

        #[test]
        fn reads_cs_workspace_crn() {
            let dir = tempfile::tempdir().unwrap();
            let crn = "crn:us-east-1.aws:AAAAAAAAAAAAAAAA";

            let result = detect_with(Some(crn), None, dir.path()).unwrap();

            assert_eq!(result.to_string(), crn, "the variable's CRN is returned");
        }

        #[test]
        fn falls_back_to_the_profile_cs_config_path_names() {
            let dir = tempfile::tempdir().unwrap();
            write_token_store(dir.path());

            let result = detect_with(None, None, dir.path()).unwrap();

            assert_eq!(result, valid_crn(), "the profile session's CRN is returned");
        }

        #[test]
        fn reads_cs_client_access_key_and_refuses_it_without_a_crn() {
            let dir = tempfile::tempdir().unwrap();
            // A session that would answer, were the access key ignored.
            write_token_store(dir.path());

            let result = detect_with(None, Some("CSAKtestKeyId.testKeySecret"), dir.path());

            assert!(
                matches!(result, Err(AuthError::MissingWorkspaceCrn(_))),
                "expected MissingWorkspaceCrn, got: {result:?}"
            );
        }

        #[test]
        fn with_neither_is_not_authenticated() {
            let dir = tempfile::tempdir().unwrap();

            let result = detect_with(None, None, dir.path());

            assert!(
                matches!(result, Err(AuthError::NotAuthenticated(_))),
                "nothing configured must be an error, got: {result:?}"
            );
        }
    }

    mod access_key_from_env {
        use super::super::access_key_from_env;
        use std::env::VarError;

        #[test]
        fn wraps_a_set_value() {
            let key = access_key_from_env(Ok("CSAKid.secret".to_string())).unwrap();
            assert_eq!(key.as_str(), "CSAKid.secret");
        }

        #[test]
        fn treats_an_unset_value_as_absent() {
            assert!(access_key_from_env(Err(VarError::NotPresent)).is_none());
        }

        #[test]
        fn treats_a_non_utf8_value_as_absent() {
            let value = std::ffi::OsString::from("CSAKid.secret");
            assert!(access_key_from_env(Err(VarError::NotUnicode(value))).is_none());
        }
    }
}
