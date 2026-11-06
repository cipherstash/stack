//! Service account keys and the JWT bearer token exchange (RFC 7523).

use std::fmt;
use std::time::Duration;

use base64ct::{Base64UrlUnpadded, Encoding};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use stack_kms_vendor::{VendorRequest, VendorTransport};
use web_time::SystemTime;
use zeroize::Zeroizing;

use super::{read_token_response, AccessToken, AuthError, TokenProvider, CLOUD_KMS_SCOPE};
use crate::time::{system_clock, unix_seconds, Clock};

/// Google's OAuth 2.0 token endpoint, the `token_uri` of every service
/// account key Google issues.
pub const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// The `grant_type` of the JWT bearer token exchange (RFC 7523).
pub const JWT_BEARER_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// How long a signed assertion is valid: one hour, the most Google accepts.
pub const ASSERTION_LIFETIME: Duration = Duration::from_secs(3600);

/// A service account key: the JSON file Google issues for a service
/// account (`"type": "service_account"`).
///
/// The private key is wiped on drop and never printed. Only the fields the
/// token exchange needs are read: `client_email`, `private_key`,
/// `private_key_id` and `token_uri`.
pub struct ServiceAccountKey {
    client_email: String,
    private_key_id: Option<String>,
    token_uri: String,
    signing_key: SigningKey<Sha256>,
}

impl fmt::Debug for ServiceAccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountKey")
            .field("client_email", &self.client_email)
            .field("private_key_id", &self.private_key_id)
            .field("token_uri", &self.token_uri)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

#[derive(Deserialize)]
struct KeyFile {
    #[serde(rename = "type")]
    kind: Option<String>,
    client_email: Option<String>,
    private_key: Option<String>,
    private_key_id: Option<String>,
    token_uri: Option<String>,
}

#[derive(Serialize)]
struct Header<'a> {
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    typ: &'static str,
}

#[derive(Serialize)]
struct Claims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: u64,
    exp: u64,
}

impl ServiceAccountKey {
    /// Read a service account key from the bytes of its JSON file. Refuses
    /// another type of credentials file, a key that is not an RSA PKCS #8
    /// PEM key, and a `token_uri` that is not HTTPS.
    pub fn from_json(json: &[u8]) -> Result<Self, AuthError> {
        let file: KeyFile = serde_json::from_slice(json)
            .map_err(|_| AuthError::access_denied("the service account key is not JSON"))?;
        match file.kind.as_deref() {
            Some("service_account") => {}
            Some(other) => {
                return Err(AuthError::access_denied(format!(
                    "a credentials file of type {other:?} is not supported: \
                     use a service account key (\"service_account\")"
                )))
            }
            None => {
                return Err(AuthError::access_denied(
                    "the credentials file has no \"type\"",
                ))
            }
        }
        let client_email = file
            .client_email
            .filter(|email| !email.is_empty())
            .ok_or_else(|| {
                AuthError::access_denied("the service account key has no client_email")
            })?;
        let pem = Zeroizing::new(file.private_key.ok_or_else(|| {
            AuthError::access_denied("the service account key has no private_key")
        })?);
        let private_key = RsaPrivateKey::from_pkcs8_pem(&pem).map_err(|_| {
            AuthError::access_denied("the private_key is not an RSA PKCS #8 PEM key")
        })?;
        let token_uri = file
            .token_uri
            .unwrap_or_else(|| DEFAULT_TOKEN_URI.to_owned());
        let parsed = url::Url::parse(&token_uri)
            .map_err(|_| AuthError::access_denied("the token_uri is not a URL"))?;
        if parsed.scheme() != "https" || parsed.host().is_none() {
            return Err(AuthError::access_denied(
                "the token_uri is not an HTTPS URL",
            ));
        }
        Ok(Self {
            client_email,
            private_key_id: file.private_key_id.filter(|id| !id.is_empty()),
            token_uri,
            signing_key: SigningKey::<Sha256>::new(private_key),
        })
    }

    /// Read a service account key file. Native only.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, AuthError> {
        let path = path.as_ref();
        let json = Zeroizing::new(std::fs::read(path).map_err(|error| {
            AuthError::access_denied(format!(
                "cannot read the service account key at {}: {}",
                path.display(),
                error.kind()
            ))
        })?);
        Self::from_json(&json)
    }

    /// The service account's email address.
    pub fn client_email(&self) -> &str {
        &self.client_email
    }

    /// The id of the key, if the file names one. It is the `kid` of the
    /// JWT header.
    pub fn private_key_id(&self) -> Option<&str> {
        self.private_key_id.as_deref()
    }

    /// The token endpoint.
    pub fn token_uri(&self) -> &str {
        &self.token_uri
    }

    /// The signed JWT assertion for `scope`, issued at `issued_at` and
    /// valid for [`ASSERTION_LIFETIME`]: `{"alg":"RS256","kid":…,"typ":"JWT"}`
    /// and `{"iss":…,"scope":…,"aud":<token_uri>,"iat":…,"exp":…}`, signed
    /// with RSASSA-PKCS1-v1_5 and SHA-256 (RS256). The signature is
    /// deterministic; the private key operation is blinded.
    pub fn assertion(
        &self,
        scope: &str,
        issued_at: SystemTime,
    ) -> Result<Zeroizing<String>, AuthError> {
        let iat = unix_seconds(issued_at);
        let header = serde_json::to_vec(&Header {
            alg: "RS256",
            kid: self.private_key_id.as_deref(),
            typ: "JWT",
        })
        .map_err(|_| AuthError::access_denied("the JWT header"))?;
        let claims = serde_json::to_vec(&Claims {
            iss: &self.client_email,
            scope,
            aud: &self.token_uri,
            iat,
            exp: iat + ASSERTION_LIFETIME.as_secs(),
        })
        .map_err(|_| AuthError::access_denied("the JWT claims"))?;
        let mut jwt = Zeroizing::new(format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(&header),
            Base64UrlUnpadded::encode_string(&claims)
        ));
        let signature = self
            .signing_key
            .try_sign_with_rng(&mut rand_core::OsRng, jwt.as_bytes())
            .map_err(|_| AuthError::unavailable("the JWT could not be signed"))?;
        jwt.push('.');
        jwt.push_str(&Base64UrlUnpadded::encode_string(&signature.to_bytes()));
        Ok(jwt)
    }
}

/// A service account key's token: a signed JWT assertion exchanged at the
/// key's `token_uri` for an access token (RFC 7523), with the Cloud KMS
/// scope. Google issues the token for one hour. Wrap it in a
/// [`CachedToken`](super::CachedToken).
pub struct ServiceAccountLogin<T> {
    key: ServiceAccountKey,
    transport: T,
    scope: String,
    clock: Clock,
}

impl<T> fmt::Debug for ServiceAccountLogin<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceAccountLogin")
            .field("key", &self.key)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl<T> ServiceAccountLogin<T> {
    /// Exchange assertions signed by `key` through `transport`, for
    /// [`CLOUD_KMS_SCOPE`].
    pub fn new(key: ServiceAccountKey, transport: T) -> Self {
        Self {
            key,
            transport,
            scope: CLOUD_KMS_SCOPE.to_owned(),
            clock: system_clock(),
        }
    }

    /// Ask for `scope` instead (space-separated scopes), for example
    /// `https://www.googleapis.com/auth/cloud-platform`.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = scope.into();
        self
    }

    /// Read the issue time of each assertion from `clock`.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The key.
    pub fn key(&self) -> &ServiceAccountKey {
        &self.key
    }

    /// The transport.
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: VendorTransport + Send + Sync> TokenProvider for ServiceAccountLogin<T> {
    async fn token(&self) -> Result<AccessToken, AuthError> {
        let assertion = self.key.assertion(&self.scope, (self.clock)())?;
        // The assertion is base64url and dots, so it needs no form escape.
        let body = Zeroizing::new(
            format!(
                "grant_type={}&assertion={}",
                url::form_urlencoded::byte_serialize(JWT_BEARER_GRANT_TYPE.as_bytes())
                    .collect::<String>(),
                assertion.as_str()
            )
            .into_bytes(),
        );
        let mut request = VendorRequest::new("POST", self.key.token_uri())
            .header("content-type", "application/x-www-form-urlencoded");
        request.body = body;
        let response = self.transport.send(request).await.map_err(|error| {
            AuthError::unavailable(format!("the token endpoint got no response: {error}"))
        })?;
        read_token_response("the service account token exchange", &response)
    }
}
