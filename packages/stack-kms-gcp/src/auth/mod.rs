//! OAuth 2.0 access tokens for Cloud KMS, and the credentials that get them.
//!
//! [`TokenProvider`] is the seam: the client asks it for an [`AccessToken`]
//! before each request. This crate provides:
//!
//! * [`AccessToken`] itself: a static token, for example from
//!   `gcloud auth print-access-token`. Everywhere. It is used until Google
//!   refuses it.
//! * [`ServiceAccountLogin`]: a service account key (the JSON file Google
//!   issues, [`ServiceAccountKey`]) signs a JWT with RS256 and exchanges it
//!   at the token endpoint (RFC 7523). Everywhere: the key can come from
//!   bytes. Feature `service-account` (on by default).
//! * [`MetadataServerLogin`]: the token of the attached service account,
//!   from the metadata server of Compute Engine, GKE, Cloud Run and Cloud
//!   Functions. **Native only.**
//! * [`CachedToken`]: keeps the token a login returns and gets a new one
//!   before it expires.
//! * [`DefaultCredentials`] (native, feature `service-account`): picks one
//!   from the environment.
//!
//! In the WASI guest the host supplies the token (ADR-0014): the guest
//! implements [`TokenProvider`] over a host import.
//!
//! **Not supported:** the `authorized_user` file that
//! `gcloud auth application-default login` writes, `external_account`
//! (workload identity federation) files, and service account
//! impersonation. Use a service account key, the metadata server, or a
//! static token.

use std::future::Future;
#[cfg(any(feature = "service-account", not(target_arch = "wasm32")))]
use std::time::Duration;

#[cfg(any(feature = "service-account", not(target_arch = "wasm32")))]
use serde::Deserialize;
#[cfg(any(feature = "service-account", not(target_arch = "wasm32")))]
use stack_kms::BackendErrorKind;
use stack_kms::MaybeSend;
#[cfg(any(feature = "service-account", not(target_arch = "wasm32")))]
use stack_kms_vendor::{classify_status, VendorResponse};
use stack_kms_vendor::{CredentialError, CredentialKind, FetchCredential};

#[cfg(all(feature = "service-account", not(target_arch = "wasm32")))]
use crate::config::EnvLookup;

#[cfg(not(target_arch = "wasm32"))]
mod metadata;
#[cfg(feature = "service-account")]
mod service_account;

#[cfg(not(target_arch = "wasm32"))]
pub use metadata::{MetadataServerLogin, DEFAULT_METADATA_HOST, METADATA_TOKEN_PATH};
#[cfg(feature = "service-account")]
pub use service_account::{
    ServiceAccountKey, ServiceAccountLogin, ASSERTION_LIFETIME, DEFAULT_TOKEN_URI,
    JWT_BEARER_GRANT_TYPE,
};

/// The OAuth scope of Cloud KMS.
pub const CLOUD_KMS_SCOPE: &str = "https://www.googleapis.com/auth/cloudkms";

pub use stack_kms_vendor::{AccessToken, DEFAULT_REFRESH_BEFORE_EXPIRY};

/// The environment variable of a static access token.
pub const ACCESS_TOKEN_VARIABLE: &str = "GOOGLE_OAUTH_ACCESS_TOKEN";

/// The credential kind of this crate: an [`AccessToken`], one for the
/// client (Cloud KMS has one scope). It names [`AuthError`] and
/// [`CachedToken`].
#[derive(Debug)]
pub enum GoogleCredentials {}

impl CredentialKind for GoogleCredentials {
    const LABEL: &'static str = "Google credentials";
    type Key = ();
    type Credential = AccessToken;
}

/// A token could not be got. The message starts with "Google
/// credentials".
pub type AuthError = CredentialError<GoogleCredentials>;

/// Where a client gets its access token. The client asks before each
/// request, so a provider that logs in should cache ([`CachedToken`]).
///
/// The returned future is bounded by [`MaybeSend`]: `Send` on native
/// targets, unbounded on wasm32.
pub trait TokenProvider: Send + Sync {
    /// The current token.
    fn token(&self) -> impl Future<Output = Result<AccessToken, AuthError>> + MaybeSend;

    /// Google refused the current token (HTTP 401). A caching provider
    /// drops it, so that the next request gets a new one. The default does
    /// nothing.
    fn invalidate(&self) {}
}

impl TokenProvider for AccessToken {
    fn token(&self) -> impl Future<Output = Result<AccessToken, AuthError>> + MaybeSend {
        std::future::ready(Ok(self.clone()))
    }
}

#[cfg(any(feature = "service-account", not(target_arch = "wasm32")))]
#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    #[serde(default)]
    expires_in: u64,
}

#[cfg(any(feature = "service-account", not(target_arch = "wasm32")))]
#[derive(Deserialize)]
struct TokenErrorBody {
    error: Option<serde_json::Value>,
    error_description: Option<String>,
}

/// The access token of a token endpoint or metadata server response.
/// `source` names it in errors.
#[cfg(any(feature = "service-account", not(target_arch = "wasm32")))]
pub(crate) fn read_token_response(
    source: &str,
    response: &VendorResponse,
) -> Result<AccessToken, AuthError> {
    if let Some(kind) = classify_status(response.status) {
        // A refused grant is HTTP 400 (`invalid_grant`); a metadata server
        // with no service account answers 404. Neither is a missing key or
        // a damaged ciphertext.
        let kind = match kind {
            BackendErrorKind::InvalidCiphertext | BackendErrorKind::NotFound => {
                BackendErrorKind::AccessDenied
            }
            kind => kind,
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
    Ok(match parsed.expires_in {
        0 => token,
        seconds => token.with_expires_in(Duration::from_secs(seconds)),
    })
}

/// Keeps the token `inner` returns, and gets a new one when it is near its
/// expiry: [`DEFAULT_REFRESH_BEFORE_EXPIRY`] before, or a third of its life
/// before when it lives less than three times that.
///
/// One fetch runs at a time: callers that arrive during a fetch wait for it
/// and share its result. If a fetch fails while the cached token has not
/// expired, the cached token is still returned. A token with no expiry is
/// kept until Google refuses it ([`TokenProvider::invalidate`]).
pub type CachedToken<P> = stack_kms_vendor::CachedToken<P, GoogleCredentials>;

impl<P: TokenProvider> FetchCredential<P> for GoogleCredentials {
    fn fetch<'a>(
        provider: &'a P,
        _key: &'a (),
    ) -> impl Future<Output = Result<AccessToken, AuthError>> + MaybeSend + 'a {
        provider.token()
    }

    fn invalidate(provider: &P) {
        provider.invalidate();
    }
}

impl<P: TokenProvider> TokenProvider for CachedToken<P> {
    fn token(&self) -> impl Future<Output = Result<AccessToken, AuthError>> + MaybeSend {
        self.get(&())
    }

    fn invalidate(&self) {
        stack_kms_vendor::CachedToken::invalidate(self);
    }
}

#[cfg(all(feature = "service-account", not(target_arch = "wasm32")))]
mod default {
    use stack_kms_vendor::VendorTransport;

    use super::*;
    use crate::config::process_env;

    /// The credentials [`DefaultCredentials::from_env`] picks.
    #[derive(Debug)]
    pub enum DefaultCredentials<T> {
        /// [`ACCESS_TOKEN_VARIABLE`].
        Token(AccessToken),
        /// The service account key file at `GOOGLE_APPLICATION_CREDENTIALS`.
        ServiceAccount(Box<CachedToken<ServiceAccountLogin<T>>>),
        /// The metadata server.
        MetadataServer(CachedToken<MetadataServerLogin<T>>),
    }

    impl<T: VendorTransport + Send + Sync> DefaultCredentials<T> {
        /// Pick credentials from the environment, in this order:
        ///
        /// 1. [`ACCESS_TOKEN_VARIABLE`] (`GOOGLE_OAUTH_ACCESS_TOKEN`): a
        ///    static access token.
        /// 2. `GOOGLE_APPLICATION_CREDENTIALS`: the path of a service
        ///    account key file. A file of another type (an
        ///    `authorized_user` or `external_account` file) is refused.
        /// 3. Otherwise the metadata server, at `GCE_METADATA_HOST` if set.
        ///
        /// The logins send through `transport` and are cached.
        pub fn from_env(transport: T) -> Result<Self, AuthError> {
            Self::from_env_lookup(transport, &process_env())
        }

        /// As [`from_env`](Self::from_env), reading the variables with `env`.
        pub fn from_env_lookup(transport: T, env: &EnvLookup) -> Result<Self, AuthError> {
            if let Some(token) = env(ACCESS_TOKEN_VARIABLE).map(AccessToken::new) {
                return Ok(Self::Token(token));
            }
            if let Some(path) = env("GOOGLE_APPLICATION_CREDENTIALS") {
                let key = ServiceAccountKey::from_file(path)?;
                return Ok(Self::ServiceAccount(Box::new(CachedToken::new(
                    ServiceAccountLogin::new(key, transport),
                ))));
            }
            Ok(Self::MetadataServer(CachedToken::new(
                MetadataServerLogin::from_env_lookup(transport, env)?,
            )))
        }
    }

    impl<T: VendorTransport + Send + Sync> TokenProvider for DefaultCredentials<T> {
        async fn token(&self) -> Result<AccessToken, AuthError> {
            match self {
                Self::Token(token) => Ok(token.clone()),
                Self::ServiceAccount(login) => login.token().await,
                Self::MetadataServer(login) => login.token().await,
            }
        }

        fn invalidate(&self) {
            match self {
                Self::Token(_) => {}
                Self::ServiceAccount(login) => login.invalidate(),
                Self::MetadataServer(login) => login.invalidate(),
            }
        }
    }
}

#[cfg(all(feature = "service-account", not(target_arch = "wasm32")))]
pub use default::DefaultCredentials;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_responses_are_read_and_failures_classified() {
        let ok = VendorResponse::new(
            200,
            br#"{"access_token":"t","expires_in":3599,"token_type":"Bearer"}"#.to_vec(),
        );
        let token = read_token_response("x", &ok).unwrap();
        assert_eq!(token.token(), "t");
        assert_eq!(token.expires_in(), Some(Duration::from_secs(3599)));
        for (status, body, kind) in [
            (
                400,
                &br#"{"error":"invalid_grant","error_description":"Invalid JWT Signature."}"#[..],
                BackendErrorKind::AccessDenied,
            ),
            (401, b"{}", BackendErrorKind::AccessDenied),
            (404, b"not found", BackendErrorKind::AccessDenied),
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
                read_token_response("x", &VendorResponse::new(status, body.to_vec())).unwrap_err();
            assert_eq!(error.kind(), kind, "{status}");
        }
        let error = read_token_response(
            "the token endpoint",
            &VendorResponse::new(
                400,
                br#"{"error":"invalid_grant","error_description":"Invalid JWT Signature."}"#
                    .to_vec(),
            ),
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Google credentials: the token endpoint failed with HTTP 400: \
             invalid_grant: Invalid JWT Signature."
        );
    }
}
