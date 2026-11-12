//! Microsoft Entra ID (Azure AD) access tokens for Key Vault and Managed
//! HSM, and the credentials that get them.
//!
//! [`TokenProvider`] is the seam: the client asks it for an [`AccessToken`]
//! for a scope (`https://vault.azure.net/.default` or
//! `https://managedhsm.azure.net/.default`) before each request. This crate
//! provides:
//!
//! * [`AccessToken`] itself: a static token, for example from
//!   `az account get-access-token --resource https://vault.azure.net`.
//!   Everywhere. It is used for every scope until Azure refuses it.
//! * [`ClientSecretLogin`]: a service principal's client secret, exchanged
//!   at the Entra ID token endpoint (OAuth 2.0 client credentials).
//!   Everywhere.
//! * [`WorkloadIdentityLogin`]: a federated token from a file (AKS
//!   workload identity, `AZURE_FEDERATED_TOKEN_FILE`), exchanged as a
//!   client assertion. **Native only.**
//! * [`ManagedIdentityLogin`]: the managed identity of an Azure VM, VM scale
//!   set, AKS node or container instance (IMDS), or of an App Service or
//!   Functions app (`IDENTITY_ENDPOINT`). **Native only.**
//! * [`CachedToken`]: keeps the token of each scope and gets a new one
//!   before it expires.
//! * [`DefaultCredentials`] (native): picks one from the environment.
//!
//! In the WASI guest the host supplies the token (ADR-0014): the guest
//! implements [`TokenProvider`] over a host import.
//!
//! **Not supported:** client certificate credentials
//! (`AZURE_CLIENT_CERTIFICATE_PATH`). They sign a JWT with the service
//! principal's RSA key, and the only pure-Rust RSA crate has an open timing
//! advisory (RUSTSEC-2023-0071). Use a client secret, workload identity or a
//! managed identity. Also not supported: Azure CLI credentials, Azure Arc
//! and Service Fabric managed identity.

use std::future::Future;
use std::time::Duration;

use serde::Deserialize;
use stack_kms::{BackendErrorKind, MaybeSend};
use stack_kms_vendor::{
    classify_status, CredentialError, CredentialKind, FetchCredential, VendorResponse,
};
use web_time::SystemTime;

#[cfg(not(target_arch = "wasm32"))]
use crate::config::EnvLookup;
use crate::time::unix_seconds;

mod client_secret;
#[cfg(not(target_arch = "wasm32"))]
mod managed_identity;
#[cfg(not(target_arch = "wasm32"))]
mod workload_identity;

pub use client_secret::{
    is_tenant_id, ClientSecretLogin, DEFAULT_AUTHORITY_HOST, JWT_BEARER_ASSERTION_TYPE,
};
#[cfg(not(target_arch = "wasm32"))]
pub use managed_identity::{
    ManagedIdentityLogin, APP_SERVICE_API_VERSION, IMDS_API_VERSION, IMDS_TOKEN_URL,
};
#[cfg(not(target_arch = "wasm32"))]
pub use workload_identity::WorkloadIdentityLogin;

/// The environment variable of a static access token. Azure has no
/// standard name for one; this one is ours.
pub const ACCESS_TOKEN_VARIABLE: &str = "AZURE_KEY_VAULT_ACCESS_TOKEN";

pub use stack_kms_vendor::{AccessToken, DEFAULT_REFRESH_BEFORE_EXPIRY};

/// The credential kind of this crate: an Entra ID [`AccessToken`], one for
/// each scope. It names [`AuthError`] and [`CachedToken`].
#[derive(Debug)]
pub enum AzureCredentials {}

impl CredentialKind for AzureCredentials {
    const LABEL: &'static str = "Azure credentials";
    type Key = String;
    type Credential = AccessToken;
}

/// A token could not be got. The message starts with "Azure credentials".
pub type AuthError = CredentialError<AzureCredentials>;

/// Where a client gets its access tokens. The client asks before each
/// request, so a provider that logs in should cache ([`CachedToken`]).
///
/// The returned future is bounded by [`MaybeSend`]: `Send` on native
/// targets, unbounded on wasm32.
pub trait TokenProvider: Send + Sync {
    /// A token for `scope` (`https://vault.azure.net/.default`). A managed
    /// identity asks for the resource, the scope without `/.default`.
    fn token(
        &self,
        scope: &str,
    ) -> impl Future<Output = Result<AccessToken, AuthError>> + MaybeSend;

    /// Azure refused a token (HTTP 401). A caching provider drops its
    /// tokens, so that the next request gets a new one. The default does
    /// nothing.
    fn invalidate(&self) {}
}

impl TokenProvider for AccessToken {
    fn token(
        &self,
        _scope: &str,
    ) -> impl Future<Output = Result<AccessToken, AuthError>> + MaybeSend {
        std::future::ready(Ok(self.clone()))
    }
}

/// The resource of a scope: the scope without `/.default`.
pub fn resource_of(scope: &str) -> &str {
    scope.strip_suffix("/.default").unwrap_or(scope)
}

/// An integer of a JSON response that may be a number or a string (IMDS and
/// App Service send strings).
fn read_u64(value: Option<&serde_json::Value>) -> Option<u64> {
    match value? {
        serde_json::Value::String(text) => text.trim().parse().ok(),
        serde_json::Value::Number(number) => number.as_u64(),
        _ => None,
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    expires_in: Option<serde_json::Value>,
    expires_on: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct TokenErrorBody {
    error: Option<serde_json::Value>,
    error_description: Option<String>,
}

/// The access token of a token endpoint or managed identity response, read
/// at `now`. `source` names it in errors.
///
/// The life is `expires_in` (seconds, a number or a string), else
/// `expires_on` (Unix seconds) less `now`.
pub(crate) fn read_token_response(
    source: &str,
    response: &VendorResponse,
    now: SystemTime,
) -> Result<AccessToken, AuthError> {
    if let Some(kind) = classify_status(response.status) {
        // A refused grant is HTTP 400 or 401 (`invalid_client`); IMDS
        // answers 400 or 404 for an identity it does not have. None of these
        // is a missing key or a damaged ciphertext. IMDS answers 410 while
        // it updates, which a later try fixes.
        let kind = match (response.status, kind) {
            (410, _) => BackendErrorKind::Unavailable,
            (_, BackendErrorKind::InvalidCiphertext | BackendErrorKind::NotFound) => {
                BackendErrorKind::AccessDenied
            }
            (_, kind) => kind,
        };
        let detail = serde_json::from_slice::<TokenErrorBody>(&response.body)
            .ok()
            .map(|body| {
                let error = match body.error {
                    Some(serde_json::Value::String(text)) => text,
                    Some(serde_json::Value::Object(object)) => object
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or_default()
                        .to_owned(),
                    _ => String::new(),
                };
                match body.error_description {
                    Some(description) => format!("{error}: {description}"),
                    None => error,
                }
            })
            .unwrap_or_default();
        return Err(AuthError::new(
            kind,
            format!("{source} failed with HTTP {}: {detail}", response.status),
        ));
    }
    let parsed: TokenResponse = serde_json::from_slice(&response.body).map_err(|_| {
        AuthError::unavailable(format!("{source} returned a response that is not JSON"))
    })?;
    let token = AccessToken::new(
        parsed
            .access_token
            .filter(|token| !token.is_empty())
            .ok_or_else(|| AuthError::unavailable(format!("{source} returned no access token")))?,
    );
    let life = match read_u64(parsed.expires_in.as_ref()) {
        Some(seconds) => Some(seconds),
        None => {
            read_u64(parsed.expires_on.as_ref()).map(|end| end.saturating_sub(unix_seconds(now)))
        }
    };
    Ok(match life {
        None | Some(0) => token,
        Some(seconds) => token.with_expires_in(Duration::from_secs(seconds)),
    })
}

/// Keeps the token `inner` returns for each scope, and gets a new one when
/// it is near its expiry: [`DEFAULT_REFRESH_BEFORE_EXPIRY`] before, or a
/// third of its life before when it lives less than three times that.
///
/// One fetch runs at a time: callers that arrive during a fetch wait for it.
/// If a fetch fails while the cached token has not expired, the cached
/// token is still returned. A token with no expiry is kept until Azure
/// refuses it ([`TokenProvider::invalidate`], which drops every scope's).
pub type CachedToken<P> = stack_kms_vendor::CachedToken<P, AzureCredentials>;

impl<P: TokenProvider> FetchCredential<P> for AzureCredentials {
    fn fetch<'a>(
        provider: &'a P,
        scope: &'a String,
    ) -> impl Future<Output = Result<AccessToken, AuthError>> + MaybeSend + 'a {
        provider.token(scope)
    }

    fn invalidate(provider: &P) {
        provider.invalidate();
    }
}

impl<P: TokenProvider> TokenProvider for CachedToken<P> {
    fn token(
        &self,
        scope: &str,
    ) -> impl Future<Output = Result<AccessToken, AuthError>> + MaybeSend {
        self.get(scope)
    }

    fn invalidate(&self) {
        stack_kms_vendor::CachedToken::invalidate(self);
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod default {
    use stack_kms_vendor::VendorTransport;

    use super::*;
    use crate::config::process_env;

    /// The credentials [`DefaultCredentials::from_env`] picks.
    #[derive(Debug)]
    pub enum DefaultCredentials<T> {
        /// [`ACCESS_TOKEN_VARIABLE`].
        Token(AccessToken),
        /// `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`.
        ClientSecret(CachedToken<ClientSecretLogin<T>>),
        /// `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
        /// `AZURE_FEDERATED_TOKEN_FILE`.
        WorkloadIdentity(CachedToken<WorkloadIdentityLogin<T>>),
        /// A managed identity: App Service (`IDENTITY_ENDPOINT`) or IMDS.
        ManagedIdentity(CachedToken<ManagedIdentityLogin<T>>),
    }

    impl<T: VendorTransport + Send + Sync> DefaultCredentials<T> {
        /// Pick credentials from the environment, in this order (the order
        /// of the Azure SDKs' `DefaultAzureCredential`, less the ones this
        /// crate does not support):
        ///
        /// 1. [`ACCESS_TOKEN_VARIABLE`]: a static access token.
        /// 2. `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`:
        ///    a client secret. `AZURE_CLIENT_CERTIFICATE_PATH` with no
        ///    secret is refused (not supported).
        /// 3. `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
        ///    `AZURE_FEDERATED_TOKEN_FILE`: workload identity.
        /// 4. Otherwise a managed identity: App Service when
        ///    `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` are set, else IMDS.
        ///    `AZURE_CLIENT_ID`, if set, names a user-assigned identity.
        ///
        /// `AZURE_AUTHORITY_HOST` changes the Entra ID host (for a national
        /// cloud). The logins send through `transport` and are cached.
        pub fn from_env(transport: T) -> Result<Self, AuthError> {
            Self::from_env_lookup(transport, &process_env())
        }

        /// As [`from_env`](Self::from_env), reading the variables with `env`.
        pub fn from_env_lookup(transport: T, env: &EnvLookup) -> Result<Self, AuthError> {
            if let Some(token) = env(ACCESS_TOKEN_VARIABLE).map(AccessToken::new) {
                return Ok(Self::Token(token));
            }
            let tenant = env("AZURE_TENANT_ID");
            let client = env("AZURE_CLIENT_ID");
            if let (Some(tenant), Some(client)) = (&tenant, &client) {
                if let Some(secret) = env("AZURE_CLIENT_SECRET") {
                    let login = ClientSecretLogin::new(tenant, client, secret, transport)?;
                    let login = match env("AZURE_AUTHORITY_HOST") {
                        Some(host) => login.with_authority_host(host)?,
                        None => login,
                    };
                    return Ok(Self::ClientSecret(CachedToken::new(login)));
                }
                if env("AZURE_CLIENT_CERTIFICATE_PATH").is_some() {
                    return Err(AuthError::access_denied(
                        "client certificate credentials (AZURE_CLIENT_CERTIFICATE_PATH) are \
                         not supported; use a client secret, workload identity or a managed \
                         identity",
                    ));
                }
                if let Some(file) = env("AZURE_FEDERATED_TOKEN_FILE") {
                    let login = WorkloadIdentityLogin::new(tenant, client, file, transport)?;
                    let login = match env("AZURE_AUTHORITY_HOST") {
                        Some(host) => login.with_authority_host(host)?,
                        None => login,
                    };
                    return Ok(Self::WorkloadIdentity(CachedToken::new(login)));
                }
            }
            Ok(Self::ManagedIdentity(CachedToken::new(
                ManagedIdentityLogin::from_env_lookup(transport, env)?,
            )))
        }
    }

    impl<T: VendorTransport + Send + Sync> TokenProvider for DefaultCredentials<T> {
        async fn token(&self, scope: &str) -> Result<AccessToken, AuthError> {
            match self {
                Self::Token(token) => Ok(token.clone()),
                Self::ClientSecret(login) => login.token(scope).await,
                Self::WorkloadIdentity(login) => login.token(scope).await,
                Self::ManagedIdentity(login) => login.token(scope).await,
            }
        }

        fn invalidate(&self) {
            match self {
                Self::Token(_) => {}
                Self::ClientSecret(login) => login.invalidate(),
                Self::WorkloadIdentity(login) => login.invalidate(),
                Self::ManagedIdentity(login) => login.invalidate(),
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use default::DefaultCredentials;

#[cfg(test)]
mod tests {
    use web_time::UNIX_EPOCH;

    use super::*;

    #[test]
    fn the_resource_is_the_scope_without_default() {
        assert_eq!(
            resource_of("https://vault.azure.net/.default"),
            "https://vault.azure.net"
        );
        assert_eq!(resource_of("https://x"), "https://x");
    }

    #[test]
    fn token_responses_are_read_and_failures_classified() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000_000);
        for (body, life) in [
            (
                &br#"{"token_type":"Bearer","expires_in":3599,"access_token":"t"}"#[..],
                Some(3599),
            ),
            (br#"{"access_token":"t","expires_in":"86399"}"#, Some(86399)),
            (
                br#"{"access_token":"t","expires_on":"1003600"}"#,
                Some(3600),
            ),
            (br#"{"access_token":"t","expires_on":1000060}"#, Some(60)),
            (br#"{"access_token":"t","expires_on":"999999"}"#, None),
            (br#"{"access_token":"t"}"#, None),
        ] {
            let token =
                read_token_response("x", &VendorResponse::new(200, body.to_vec()), now).unwrap();
            assert_eq!(token.token(), "t");
            assert_eq!(token.expires_in(), life.map(Duration::from_secs));
        }
        for (status, body, kind) in [
            (
                400,
                &br#"{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}"#[..],
                BackendErrorKind::AccessDenied,
            ),
            (401, b"{}", BackendErrorKind::AccessDenied),
            (404, b"not found", BackendErrorKind::AccessDenied),
            (410, b"", BackendErrorKind::Unavailable),
            (429, b"", BackendErrorKind::Throttled),
            (503, b"", BackendErrorKind::Unavailable),
            (200, b"not json", BackendErrorKind::Unavailable),
            (
                200,
                br#"{"access_token":""}"#,
                BackendErrorKind::Unavailable,
            ),
        ] {
            let error =
                read_token_response("x", &VendorResponse::new(status, body.to_vec()), now)
                    .unwrap_err();
            assert_eq!(error.kind(), kind, "{status}");
        }
        let error = read_token_response(
            "the token endpoint",
            &VendorResponse::new(
                401,
                br#"{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided."}"#
                    .to_vec(),
            ),
            now,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Azure credentials: the token endpoint failed with HTTP 401: \
             invalid_client: AADSTS7000215: Invalid client secret provided."
        );
    }
}
