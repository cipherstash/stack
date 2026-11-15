//! The metadata server's token for the attached service account. Native
//! only.

use std::fmt;

use stack_kms_vendor::{VendorRequest, VendorTransport};

use super::{read_token_response, AccessToken, AuthError, TokenProvider};
use crate::config::EnvLookup;

/// The host of the metadata server on Google Cloud.
pub const DEFAULT_METADATA_HOST: &str = "metadata.google.internal";

/// The path of the default service account's access token.
pub const METADATA_TOKEN_PATH: &str = "/computeMetadata/v1/instance/service-accounts/default/token";

/// The access token of the service account attached to the Compute Engine
/// instance, GKE workload (Workload Identity), Cloud Run service or Cloud
/// Functions function, from the metadata server. The request carries
/// `Metadata-Flavor: Google`. Native only. Wrap it in a
/// [`CachedToken`](super::CachedToken): the server caches the token too and
/// says how long it has left.
///
/// The token has the scopes of the attached service account (on Compute
/// Engine, the instance's access scopes must include Cloud KMS or
/// `cloud-platform`).
pub struct MetadataServerLogin<T> {
    transport: T,
    host: String,
}

impl<T> fmt::Debug for MetadataServerLogin<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetadataServerLogin")
            .field("host", &self.host)
            .finish_non_exhaustive()
    }
}

/// A host, with an optional port: `[A-Za-z0-9.-]` and at most one `:`
/// before digits. Nothing that could change the request path.
fn is_host(text: &str) -> bool {
    let (host, port) = match text.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (text, None),
    };
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        && port.is_none_or(|port| {
            !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit())
        })
}

impl<T> MetadataServerLogin<T> {
    /// Ask the metadata server at [`DEFAULT_METADATA_HOST`] through
    /// `transport`.
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            host: DEFAULT_METADATA_HOST.to_owned(),
        }
    }

    /// Ask the metadata server at `GCE_METADATA_HOST` (`host` or
    /// `host:port`, the name the Google SDKs read) if it is set.
    pub fn from_env_lookup(transport: T, env: &EnvLookup) -> Result<Self, AuthError> {
        let login = Self::new(transport);
        match env("GCE_METADATA_HOST") {
            Some(host) => login.with_host(host),
            None => Ok(login),
        }
    }

    /// Ask the metadata server at `host` (`host` or `host:port`) instead.
    pub fn with_host(mut self, host: impl Into<String>) -> Result<Self, AuthError> {
        let host = host.into();
        if !is_host(&host) {
            return Err(AuthError::access_denied(format!(
                "{host:?} is not a metadata server host"
            )));
        }
        self.host = host;
        Ok(self)
    }

    /// The URL of the token.
    pub fn url(&self) -> String {
        format!("http://{}{METADATA_TOKEN_PATH}", self.host)
    }

    /// The transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: VendorTransport + Send + Sync> TokenProvider for MetadataServerLogin<T> {
    async fn token(&self) -> Result<AccessToken, AuthError> {
        let request = VendorRequest::new("GET", self.url()).header("metadata-flavor", "Google");
        let response = self.transport.send(request).await.map_err(|error| {
            AuthError::unavailable(format!(
                "the metadata server got no response (not on Google Cloud?): {error}"
            ))
        })?;
        read_token_response("the metadata server", &response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_are_checked() {
        for good in [
            "metadata.google.internal",
            "169.254.169.254",
            "127.0.0.1:8080",
        ] {
            assert!(is_host(good), "{good}");
        }
        for bad in [
            "",
            "a/b",
            "a:b",
            "a:",
            "a:123456",
            "user@host",
            "a b",
            "a?b",
        ] {
            assert!(!is_host(bad), "{bad:?}");
        }
    }
}
