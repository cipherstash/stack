//! Workload identity federation: a federated token from a file, exchanged
//! at the Entra ID token endpoint. Native only.

use std::fmt;
use std::path::PathBuf;

use stack_kms_vendor::VendorTransport;
use zeroize::Zeroizing;

use super::client_secret::{EntraApp, JWT_BEARER_ASSERTION_TYPE};
use super::{AccessToken, AuthError, TokenProvider};
use crate::time::{system_clock, Clock};

/// A federated token (for example the service account token that AKS
/// workload identity projects at `AZURE_FEDERATED_TOKEN_FILE`), exchanged at
/// the Entra ID token endpoint as a client assertion. The file is read on
/// each login, because the platform rotates it. Wrap it in a
/// [`CachedToken`](super::CachedToken). Native only.
pub struct WorkloadIdentityLogin<T> {
    app: EntraApp,
    token_file: PathBuf,
    transport: T,
    clock: Clock,
}

impl<T> fmt::Debug for WorkloadIdentityLogin<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkloadIdentityLogin")
            .field("tenant_id", &self.app.tenant_id())
            .field("client_id", &self.app.client_id())
            .field("token_file", &self.token_file)
            .finish_non_exhaustive()
    }
}

impl<T> WorkloadIdentityLogin<T> {
    /// Log in as `client_id` of `tenant_id` with the federated token in
    /// `token_file`, through `transport`.
    pub fn new(
        tenant_id: &str,
        client_id: &str,
        token_file: impl Into<PathBuf>,
        transport: T,
    ) -> Result<Self, AuthError> {
        Ok(Self {
            app: EntraApp::new(tenant_id, client_id)?,
            token_file: token_file.into(),
            transport,
            clock: system_clock(),
        })
    }

    /// Post to the Entra ID host `host` instead of
    /// [`DEFAULT_AUTHORITY_HOST`](super::DEFAULT_AUTHORITY_HOST).
    pub fn with_authority_host(mut self, host: impl Into<String>) -> Result<Self, AuthError> {
        self.app = self.app.with_authority_host(host.into())?;
        Ok(self)
    }

    /// Read the time from `clock`.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The token endpoint URL.
    pub fn token_url(&self) -> String {
        self.app.token_url()
    }

    /// The transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: VendorTransport + Send + Sync> TokenProvider for WorkloadIdentityLogin<T> {
    async fn token(&self, scope: &str) -> Result<AccessToken, AuthError> {
        let assertion =
            Zeroizing::new(std::fs::read_to_string(&self.token_file).map_err(|_| {
                AuthError::access_denied(format!(
                    "cannot read the federated token file {}",
                    self.token_file.display()
                ))
            })?);
        let assertion = assertion.trim();
        if assertion.is_empty() {
            return Err(AuthError::access_denied(
                "the federated token file is empty",
            ));
        }
        self.app
            .post(
                &self.transport,
                &self.clock,
                "the workload identity login",
                scope,
                &[
                    ("client_assertion_type", JWT_BEARER_ASSERTION_TYPE),
                    ("client_assertion", assertion),
                ],
            )
            .await
    }
}
