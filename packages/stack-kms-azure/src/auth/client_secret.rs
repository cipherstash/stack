//! The Entra ID token endpoint: a service principal's client secret
//! (OAuth 2.0 client credentials), and the shared request of every login
//! that posts to it.

use std::fmt;

use stack_kms_vendor::{VendorRequest, VendorTransport};
use zeroize::Zeroizing;

use super::{read_token_response, AccessToken, AuthError, TokenProvider};
use crate::time::{system_clock, Clock};

/// The Entra ID host of the public cloud. `AZURE_AUTHORITY_HOST` (the Azure
/// SDK name) changes it, for example to `https://login.chinacloudapi.cn`.
pub const DEFAULT_AUTHORITY_HOST: &str = "https://login.microsoftonline.com";

/// The `client_assertion_type` of a federated token (RFC 7523).
pub const JWT_BEARER_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// A tenant id: a GUID or a domain name, `[A-Za-z0-9.-]`, so that it cannot
/// change the token endpoint path.
pub fn is_tenant_id(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 256
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        && !text.starts_with('.')
}

/// An Entra ID application: the tenant, the client id and the authority
/// host. Shared by the logins that post to the token endpoint.
#[derive(Clone, Debug)]
pub(crate) struct EntraApp {
    tenant_id: String,
    client_id: String,
    authority_host: String,
}

impl EntraApp {
    pub(crate) fn new(tenant_id: &str, client_id: &str) -> Result<Self, AuthError> {
        if !is_tenant_id(tenant_id) {
            return Err(AuthError::access_denied(format!(
                "{tenant_id:?} is not an Entra ID tenant id"
            )));
        }
        if client_id.is_empty() {
            return Err(AuthError::access_denied("the client id is empty"));
        }
        Ok(Self {
            tenant_id: tenant_id.to_owned(),
            client_id: client_id.to_owned(),
            authority_host: DEFAULT_AUTHORITY_HOST.to_owned(),
        })
    }

    pub(crate) fn with_authority_host(mut self, host: String) -> Result<Self, AuthError> {
        let parsed = url::Url::parse(&host).map_err(|_| {
            AuthError::access_denied(format!("{host:?} is not an authority host URL"))
        })?;
        if parsed.scheme() != "https"
            || parsed.host().is_none()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(AuthError::access_denied(format!(
                "{host:?} is not an HTTPS authority host with no path"
            )));
        }
        self.authority_host = parsed.as_str().trim_end_matches('/').to_owned();
        Ok(self)
    }

    pub(crate) fn client_id(&self) -> &str {
        &self.client_id
    }

    pub(crate) fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub(crate) fn token_url(&self) -> String {
        format!(
            "{}/{}/oauth2/v2.0/token",
            self.authority_host, self.tenant_id
        )
    }

    /// Post the client credentials form `extra` (after `grant_type`,
    /// `client_id` and `scope`) and read the token. `source` names the login
    /// in errors.
    pub(crate) async fn post<T: VendorTransport>(
        &self,
        transport: &T,
        clock: &Clock,
        source: &str,
        scope: &str,
        extra: &[(&str, &str)],
    ) -> Result<AccessToken, AuthError> {
        let body = {
            let mut form = url::form_urlencoded::Serializer::new(String::new());
            let _ = form
                .append_pair("grant_type", "client_credentials")
                .append_pair("client_id", &self.client_id)
                .append_pair("scope", scope);
            for (name, value) in extra {
                let _ = form.append_pair(name, value);
            }
            Zeroizing::new(form.finish().into_bytes())
        };
        let mut request = VendorRequest::new("POST", self.token_url())
            .header("content-type", "application/x-www-form-urlencoded");
        request.body = body;
        let response = transport.send(request).await.map_err(|error| {
            AuthError::unavailable(format!(
                "the Entra ID token endpoint got no response: {error}"
            ))
        })?;
        read_token_response(source, &response, clock())
    }
}

/// A service principal's client secret, exchanged at the Entra ID token
/// endpoint for an access token (OAuth 2.0 client credentials). Entra ID
/// issues the token for about an hour. Wrap it in a
/// [`CachedToken`](super::CachedToken).
///
/// The secret is wiped on drop and never printed. Everywhere: the WASI guest
/// can use it if the host passes the secret, but ADR-0014 has the host
/// supply the token.
pub struct ClientSecretLogin<T> {
    app: EntraApp,
    secret: Zeroizing<String>,
    transport: T,
    clock: Clock,
}

impl<T> fmt::Debug for ClientSecretLogin<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientSecretLogin")
            .field("tenant_id", &self.app.tenant_id())
            .field("client_id", &self.app.client_id())
            .field("client_secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl<T> ClientSecretLogin<T> {
    /// Log in as `client_id` of `tenant_id` with `secret`, through
    /// `transport`. Refuses a tenant id that is not a GUID or domain name.
    pub fn new(
        tenant_id: &str,
        client_id: &str,
        secret: impl Into<String>,
        transport: T,
    ) -> Result<Self, AuthError> {
        let secret = Zeroizing::new(secret.into());
        if secret.is_empty() {
            return Err(AuthError::access_denied("the client secret is empty"));
        }
        Ok(Self {
            app: EntraApp::new(tenant_id, client_id)?,
            secret,
            transport,
            clock: system_clock(),
        })
    }

    /// Post to the Entra ID host `host` (`https://login.microsoftonline.us`)
    /// instead of [`DEFAULT_AUTHORITY_HOST`].
    pub fn with_authority_host(mut self, host: impl Into<String>) -> Result<Self, AuthError> {
        self.app = self.app.with_authority_host(host.into())?;
        Ok(self)
    }

    /// Read the time from `clock` (for an `expires_on` response).
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

impl<T: VendorTransport + Send + Sync> TokenProvider for ClientSecretLogin<T> {
    async fn token(&self, scope: &str) -> Result<AccessToken, AuthError> {
        self.app
            .post(
                &self.transport,
                &self.clock,
                "the client secret login",
                scope,
                &[("client_secret", self.secret.as_str())],
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_ids_are_checked() {
        for good in [
            "00000000-0000-0000-0000-000000000000",
            "contoso.onmicrosoft.com",
            "organizations",
        ] {
            assert!(is_tenant_id(good), "{good}");
        }
        for bad in ["", "a/b", "a?b", "a b", ".", "..", "a%2fb", "a#b"] {
            assert!(!is_tenant_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_login_is_checked_and_hides_the_secret() {
        let login = ClientSecretLogin::new("tenant", "client", "the-secret", ()).unwrap();
        assert_eq!(
            login.token_url(),
            "https://login.microsoftonline.com/tenant/oauth2/v2.0/token"
        );
        assert!(!format!("{login:?}").contains("the-secret"));
        let login = login
            .with_authority_host("https://login.microsoftonline.us/")
            .unwrap();
        assert_eq!(
            login.token_url(),
            "https://login.microsoftonline.us/tenant/oauth2/v2.0/token"
        );
        for bad in [
            "http://login.microsoftonline.com",
            "https://login.microsoftonline.com/x",
            "https://login.microsoftonline.com/?a=b",
            "not a url",
        ] {
            let login = ClientSecretLogin::new("tenant", "client", "s", ()).unwrap();
            assert!(login.with_authority_host(bad).is_err(), "{bad}");
        }
        assert!(ClientSecretLogin::new("a/b", "client", "s", ()).is_err());
        assert!(ClientSecretLogin::new("tenant", "", "s", ()).is_err());
        assert!(ClientSecretLogin::new("tenant", "client", "", ()).is_err());
    }
}
