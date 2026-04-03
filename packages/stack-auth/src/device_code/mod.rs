mod protocol;

use cts_common::{CtsServiceDiscovery, Region, ServiceDiscovery};
use url::Url;

use std::time::{SystemTime, UNIX_EPOCH};

use std::path::PathBuf;

use stack_profile::ProfileStore;

use crate::{ensure_trailing_slash, http_client, AuthError, DeviceIdentity, Token};
use protocol::{
    DeviceCode, DeviceCodeRequest, DeviceCodeResponse, ErrorResponse, TokenRequest, TokenResponse,
};

#[cfg(test)]
mod tests;

/// Authenticates with CipherStash using the
/// [device code flow (RFC 8628)](https://datatracker.ietf.org/doc/html/rfc8628).
///
/// This is the primary entry point for CLI and browserless authentication.
/// Create a strategy with [`DeviceCodeStrategy::new`], then call
/// [`begin`](DeviceCodeStrategy::begin) to start the flow.
///
/// # Example
///
/// ```
/// use stack_auth::DeviceCodeStrategy;
/// use cts_common::Region;
///
/// let region = Region::aws("ap-southeast-2").unwrap();
/// let strategy = DeviceCodeStrategy::new(region, "my-client-id").unwrap();
/// ```
pub struct DeviceCodeStrategy {
    region: Region,
    base_url: Url,
    client_id: String,
    profile_dir: Option<PathBuf>,
    device_identity: Option<DeviceIdentity>,
}

impl DeviceCodeStrategy {
    /// Create a new strategy for the given CipherStash region and OAuth client ID.
    ///
    /// The auth endpoint is resolved automatically via service discovery.
    ///
    /// # Example
    ///
    /// ```
    /// use stack_auth::DeviceCodeStrategy;
    /// use cts_common::Region;
    ///
    /// let strategy = DeviceCodeStrategy::new(
    ///     Region::aws("ap-southeast-2").unwrap(),
    ///     "my-client-id",
    /// ).unwrap();
    /// ```
    pub fn new(region: Region, client_id: impl Into<String>) -> Result<Self, AuthError> {
        Self::builder(region, client_id).build()
    }

    /// Return a builder for configuring a `DeviceCodeStrategy` before construction.
    pub fn builder(region: Region, client_id: impl Into<String>) -> DeviceCodeStrategyBuilder {
        DeviceCodeStrategyBuilder {
            region,
            client_id: client_id.into(),
            base_url_override: None,
            profile_dir: None,
            device_identity: None,
        }
    }

    /// Start the device code flow.
    ///
    /// Requests a device code from the CipherStash auth server and returns a
    /// [`PendingDeviceCode`] with the user-facing codes and URIs. Show these
    /// to the user, then call [`PendingDeviceCode::poll_for_token`] to wait
    /// for authorization.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidClient`] if the client ID is not recognized,
    /// or [`AuthError::Request`] if the server is unreachable.
    pub async fn begin(&self) -> Result<PendingDeviceCode, AuthError> {
        let client = http_client();

        let code_url = self.base_url.join("oauth/device/code")?;

        tracing::debug!(url = %code_url, client_id = %self.client_id, "requesting device code");

        let device_instance_id = self
            .device_identity
            .as_ref()
            .map(|d| d.device_instance_id.to_string());

        let code_resp = client
            .post(code_url)
            .form(&DeviceCodeRequest {
                client_id: &self.client_id,
                device_instance_id: device_instance_id.as_deref(),
                device_name: self
                    .device_identity
                    .as_ref()
                    .map(|d| d.device_name.as_str()),
            })
            .send()
            .await?;

        if !code_resp.status().is_success() {
            let err: ErrorResponse = code_resp.json().await?;
            tracing::debug!(error = %err.error, "device code request failed");
            return Err(match err.error.as_str() {
                "invalid_client" => AuthError::InvalidClient,
                _ => AuthError::Server(err.error_description),
            });
        }

        let code: DeviceCodeResponse = code_resp.json().await?;

        let token_url = self.base_url.join("oauth/device/token")?;

        tracing::debug!(
            user_code = %code.user_code,
            expires_in = code.expires_in,
            "device code received"
        );

        Ok(PendingDeviceCode {
            token_url,
            region: self.region,
            client_id: self.client_id.clone(),
            device_code: code.device_code,
            user_code: code.user_code,
            verification_uri: code.verification_uri,
            verification_uri_complete: code.verification_uri_complete,
            expires_in: code.expires_in,
            profile_dir: self.profile_dir.clone(),
            device_identity: self.device_identity.clone(),
        })
    }
}

/// Builder for [`DeviceCodeStrategy`].
///
/// Created via [`DeviceCodeStrategy::builder`].
pub struct DeviceCodeStrategyBuilder {
    region: Region,
    client_id: String,
    base_url_override: Option<Url>,
    profile_dir: Option<PathBuf>,
    device_identity: Option<DeviceIdentity>,
}

impl DeviceCodeStrategyBuilder {
    /// Override the base URL resolved by service discovery.
    ///
    /// Useful for pointing at a local or mock CTS instance during testing.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn base_url(mut self, url: Url) -> Self {
        self.base_url_override = Some(url);
        self
    }

    /// Override the profile directory used to persist the token.
    ///
    /// By default tokens are saved to `~/.cipherstash/auth.json`. Use this in
    /// tests to redirect writes to a temporary directory.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn profile_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.profile_dir = Some(dir.into());
        self
    }

    /// Set the device identity for this strategy.
    ///
    /// When set, the device instance ID and name are sent to the auth server
    /// during the device code flow and persisted in the token.
    pub fn device_identity(mut self, identity: DeviceIdentity) -> Self {
        self.device_identity = Some(identity);
        self
    }

    /// Build the [`DeviceCodeStrategy`].
    ///
    /// Resolves the base URL via service discovery unless overridden with
    /// `base_url` (available when the `test-utils` feature is enabled).
    pub fn build(self) -> Result<DeviceCodeStrategy, AuthError> {
        let base_url = match self.base_url_override {
            Some(url) => url,
            None => crate::cts_base_url_from_env()?
                .unwrap_or(CtsServiceDiscovery::endpoint(self.region)?),
        };
        Ok(DeviceCodeStrategy {
            region: self.region,
            base_url: ensure_trailing_slash(base_url),
            client_id: self.client_id,
            profile_dir: self.profile_dir,
            device_identity: self.device_identity,
        })
    }
}

/// A device code flow that is waiting for the user to authorize.
///
/// Returned by [`DeviceCodeStrategy::begin`]. Display the
/// [`user_code`](Self::user_code) and
/// [`verification_uri_complete`](Self::verification_uri_complete) to the user
/// (or call [`open_in_browser`](Self::open_in_browser)), then call
/// [`poll_for_token`](Self::poll_for_token) to wait for authorization.
///
/// # Example
///
/// ```no_run
/// # use stack_auth::DeviceCodeStrategy;
/// # use cts_common::Region;
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// # let strategy = DeviceCodeStrategy::new(Region::aws("ap-southeast-2")?, "cli")?;
/// let pending = strategy.begin().await?;
///
/// println!("Go to: {}", pending.verification_uri_complete());
/// println!("Enter code: {}", pending.user_code());
///
/// let token = pending.poll_for_token().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct PendingDeviceCode {
    token_url: Url,
    region: Region,
    client_id: String,
    device_code: DeviceCode,
    /// The short code the user must enter to authorize this device.
    user_code: String,
    /// The base verification URI (without the user code embedded).
    verification_uri: String,
    /// The full verification URI with the user code pre-filled.
    verification_uri_complete: String,
    /// How many seconds the device code remains valid.
    expires_in: u64,
    /// Profile directory override. Falls back to `~/.cipherstash`.
    profile_dir: Option<PathBuf>,
    /// Device identity to associate with the token.
    device_identity: Option<DeviceIdentity>,
}

impl PendingDeviceCode {
    /// The short code the user must enter to authorize this device.
    pub fn user_code(&self) -> &str {
        &self.user_code
    }

    /// The base verification URI (without the user code embedded).
    pub fn verification_uri(&self) -> &str {
        &self.verification_uri
    }

    /// The full verification URI with the user code pre-filled.
    pub fn verification_uri_complete(&self) -> &str {
        &self.verification_uri_complete
    }

    /// How many seconds the device code remains valid.
    pub fn expires_in(&self) -> u64 {
        self.expires_in
    }

    /// Open the verification URI in the user's default browser.
    ///
    /// Returns `true` if the browser was opened successfully.
    pub fn open_in_browser(&self) -> bool {
        open::that(&self.verification_uri_complete).is_ok()
    }

    /// Poll the auth server until the user authorizes (or the code expires).
    ///
    /// This method consumes `self` and blocks asynchronously, polling at a
    /// server-controlled interval (starting at 5 seconds). It returns a
    /// [`Token`] on success.
    ///
    /// # Errors
    ///
    /// - [`AuthError::AccessDenied`] — the user rejected the request.
    /// - [`AuthError::TokenExpired`] — the device code expired before the user
    ///   authorized.
    /// - [`AuthError::Request`] — a network error occurred while polling.
    pub async fn poll_for_token(self) -> Result<Token, AuthError> {
        let client = http_client();
        let mut interval = tokio::time::Duration::from_secs(5);
        let deadline =
            tokio::time::Instant::now() + tokio::time::Duration::from_secs(self.expires_in);

        tracing::debug!(
            url = %self.token_url,
            expires_in = self.expires_in,
            "polling for token"
        );

        loop {
            if tokio::time::Instant::now() >= deadline {
                tracing::debug!("device code expired while polling");
                return Err(AuthError::TokenExpired);
            }

            let resp = client
                .post(self.token_url.clone())
                .form(&TokenRequest {
                    client_id: &self.client_id,
                    device_code: &self.device_code,
                    grant_type: "urn:ietf:params:oauth:grant-type:device_code",
                })
                .send()
                .await?;

            if resp.status().is_success() {
                tracing::debug!("token received");
                let token_resp: TokenResponse = resp.json().await?;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let mut token = Token {
                    access_token: token_resp.access_token,
                    token_type: token_resp.token_type,
                    expires_at: now + token_resp.expires_in,
                    refresh_token: token_resp.refresh_token,
                    region: None,
                    client_id: None,
                    device_instance_id: None,
                };
                token.set_region(self.region.identifier());
                token.set_client_id(&self.client_id);
                if let Some(ref identity) = self.device_identity {
                    token.set_device_instance_id(identity.device_instance_id.to_string());
                }

                let store = match &self.profile_dir {
                    Some(dir) => ProfileStore::new(dir),
                    None => ProfileStore::resolve(None)?,
                };
                let workspace_id = token.workspace_id()?;
                store.init_workspace(workspace_id.as_str())?;
                store
                    .workspace_store(workspace_id.as_str())?
                    .save_profile(&token)?;
                tracing::debug!(
                    workspace = workspace_id.as_str(),
                    "token saved to workspace directory"
                );

                return Ok(token);
            }

            let err: ErrorResponse = resp.json().await?;
            match err.error.as_str() {
                "authorization_pending" => {
                    tracing::debug!("authorization pending, retrying");
                }
                "slow_down" => {
                    interval += tokio::time::Duration::from_secs(5);
                    tracing::debug!(interval_secs = interval.as_secs(), "slowing down");
                }
                "expired_token" => return Err(AuthError::TokenExpired),
                "access_denied" => return Err(AuthError::AccessDenied),
                "invalid_grant" => return Err(AuthError::InvalidGrant),
                "invalid_client" => return Err(AuthError::InvalidClient),
                _ => return Err(AuthError::Server(err.error_description)),
            }

            tokio::time::sleep(interval).await;
        }
    }
}
