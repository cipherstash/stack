//! The managed identity of an Azure resource: IMDS, or the App Service
//! identity endpoint. Native only.

use std::fmt;

use stack_kms_vendor::{VendorRequest, VendorTransport};
use zeroize::Zeroizing;

use super::{read_token_response, resource_of, AccessToken, AuthError, TokenProvider};
use crate::config::EnvLookup;
use crate::time::{system_clock, Clock};

/// The token URL of the Azure Instance Metadata Service.
pub const IMDS_TOKEN_URL: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
/// The IMDS API version of a token request.
pub const IMDS_API_VERSION: &str = "2018-02-01";
/// The API version of an App Service (and Functions) identity endpoint
/// request.
pub const APP_SERVICE_API_VERSION: &str = "2019-08-01";

/// Where the managed identity's token comes from.
enum Source {
    /// IMDS: Azure VMs, VM scale sets, AKS nodes and container instances.
    Imds,
    /// App Service and Functions: `IDENTITY_ENDPOINT`, with
    /// `IDENTITY_HEADER` in `X-IDENTITY-HEADER`.
    AppService {
        endpoint: String,
        header: Zeroizing<String>,
    },
}

/// The token of the managed identity of the Azure resource this process
/// runs on. Native only. Wrap it in a [`CachedToken`](super::CachedToken).
///
/// With a client id it asks for that user-assigned identity; without one,
/// for the system-assigned identity.
pub struct ManagedIdentityLogin<T> {
    source: Source,
    client_id: Option<String>,
    transport: T,
    clock: Clock,
}

impl<T> fmt::Debug for ManagedIdentityLogin<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = match &self.source {
            Source::Imds => "imds".to_owned(),
            Source::AppService { endpoint, .. } => format!("app service at {endpoint}"),
        };
        f.debug_struct("ManagedIdentityLogin")
            .field("source", &source)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// An App Service identity endpoint: HTTP to a loopback host (App Service
/// serves it on `127.0.0.1`), or HTTPS, with no query, fragment or
/// credentials. The identity header is sent there, so it must not be
/// anywhere else.
fn is_identity_endpoint(endpoint: &str) -> bool {
    let Ok(parsed) = url::Url::parse(endpoint) else {
        return false;
    };
    let loopback = match parsed.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => return false,
    };
    (parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback))
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.username().is_empty()
        && parsed.password().is_none()
}

impl<T> ManagedIdentityLogin<T> {
    /// The system-assigned identity, from IMDS, through `transport`.
    pub fn imds(transport: T) -> Self {
        Self {
            source: Source::Imds,
            client_id: None,
            transport,
            clock: system_clock(),
        }
    }

    /// The identity of an App Service or Functions app, from `endpoint`
    /// (`IDENTITY_ENDPOINT`) with `header` (`IDENTITY_HEADER`).
    pub fn app_service(
        endpoint: impl Into<String>,
        header: impl Into<String>,
        transport: T,
    ) -> Result<Self, AuthError> {
        let endpoint = endpoint.into();
        if !is_identity_endpoint(&endpoint) {
            return Err(AuthError::access_denied(format!(
                "{endpoint:?} is not an App Service identity endpoint (HTTP to a loopback \
                 host, or HTTPS, with no query)"
            )));
        }
        let header = Zeroizing::new(header.into());
        if header.is_empty() || header.contains(['\r', '\n']) {
            return Err(AuthError::access_denied(
                "IDENTITY_HEADER is empty or holds a line break",
            ));
        }
        Ok(Self {
            source: Source::AppService { endpoint, header },
            client_id: None,
            transport,
            clock: system_clock(),
        })
    }

    /// App Service when `IDENTITY_ENDPOINT` and `IDENTITY_HEADER` are set,
    /// else IMDS. `AZURE_CLIENT_ID`, if set, names a user-assigned identity.
    pub fn from_env_lookup(transport: T, env: &EnvLookup) -> Result<Self, AuthError> {
        let login = match (env("IDENTITY_ENDPOINT"), env("IDENTITY_HEADER")) {
            (Some(endpoint), Some(header)) => Self::app_service(endpoint, header, transport)?,
            _ => Self::imds(transport),
        };
        Ok(match env("AZURE_CLIENT_ID") {
            Some(client_id) => login.with_client_id(client_id),
            None => login,
        })
    }

    /// Ask for the user-assigned identity with `client_id`.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Read the time from `clock` (App Service answers with `expires_on`).
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The token URL for `scope`.
    pub fn url(&self, scope: &str) -> String {
        let (base, api_version) = match &self.source {
            Source::Imds => (IMDS_TOKEN_URL, IMDS_API_VERSION),
            Source::AppService { endpoint, .. } => (endpoint.as_str(), APP_SERVICE_API_VERSION),
        };
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        let _ = query
            .append_pair("api-version", api_version)
            .append_pair("resource", resource_of(scope));
        if let Some(client_id) = &self.client_id {
            let _ = query.append_pair("client_id", client_id);
        }
        format!("{base}?{}", query.finish())
    }

    /// The transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: VendorTransport + Send + Sync> TokenProvider for ManagedIdentityLogin<T> {
    async fn token(&self, scope: &str) -> Result<AccessToken, AuthError> {
        let request = VendorRequest::new("GET", self.url(scope));
        let (request, source) = match &self.source {
            Source::Imds => (request.header("metadata", "true"), "IMDS"),
            Source::AppService { header, .. } => (
                request.header("x-identity-header", header.as_str()),
                "the App Service identity endpoint",
            ),
        };
        let response = self.transport.send(request).await.map_err(|error| {
            AuthError::unavailable(format!("{source} got no response (not on Azure?): {error}"))
        })?;
        read_token_response(source, &response, (self.clock)())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_endpoints_are_checked() {
        for good in [
            "http://127.0.0.1:41056/msi/token",
            "http://localhost:8081/msi/token/",
            "http://[::1]:80/token",
            "https://identity.example/token",
        ] {
            assert!(is_identity_endpoint(good), "{good}");
        }
        for bad in [
            "http://169.254.169.254/token",
            "http://evil.example/token",
            "http://127.0.0.1/token?x=1",
            "http://user@127.0.0.1/token",
            "file:///etc/passwd",
            "not a url",
        ] {
            assert!(!is_identity_endpoint(bad), "{bad}");
        }
    }

    #[test]
    fn urls_name_the_resource_and_the_identity() {
        let login = ManagedIdentityLogin::imds(());
        assert_eq!(
            login.url("https://vault.azure.net/.default"),
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01\
             &resource=https%3A%2F%2Fvault.azure.net"
        );
        let login = ManagedIdentityLogin::app_service("http://127.0.0.1:41056/msi/token", "h", ())
            .unwrap()
            .with_client_id("c-1");
        assert_eq!(
            login.url("https://managedhsm.azure.net/.default"),
            "http://127.0.0.1:41056/msi/token?api-version=2019-08-01\
             &resource=https%3A%2F%2Fmanagedhsm.azure.net&client_id=c-1"
        );
        assert!(!format!("{login:?}").contains("\"h\""));
        assert!(ManagedIdentityLogin::app_service("http://127.0.0.1/t", "a\nb", ()).is_err());
    }
}
