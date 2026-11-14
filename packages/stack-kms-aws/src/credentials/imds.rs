//! Credentials from the EC2 instance metadata service, IMDSv2.

use stack_kms_vendor::{classify_status, VendorRequest, VendorTransport};
use zeroize::Zeroizing;

use super::response::{json_credentials, status_failure};
use super::{Credentials, CredentialsError, CredentialsProvider, EnvLookup};

/// The IMDS endpoint when `AWS_EC2_METADATA_SERVICE_ENDPOINT` is not set.
pub const DEFAULT_IMDS_ENDPOINT: &str = "http://169.254.169.254";
/// The lifetime asked for a session token, in seconds (six hours, the
/// maximum).
const TOKEN_TTL_SECONDS: &str = "21600";
const CREDENTIALS_PATH: &str = "/latest/meta-data/iam/security-credentials/";

/// Credentials of the EC2 instance profile, from the instance metadata
/// service with IMDSv2 session tokens. IMDSv1 is not used.
///
/// Each fetch gets a session token (`PUT /latest/api/token`), the role
/// name, and the role's credentials. Wrap it in
/// [`CachedCredentials`](super::CachedCredentials). Off EC2 the endpoint
/// does not answer, so give the transport a short connect timeout. Native
/// only.
pub struct ImdsCredentials<T> {
    transport: T,
    endpoint: String,
}

impl<T> std::fmt::Debug for ImdsCredentials<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImdsCredentials")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl<T: VendorTransport> ImdsCredentials<T> {
    /// IMDS at `endpoint` (`http://169.254.169.254`, no trailing slash
    /// needed).
    pub fn new(transport: T, endpoint: impl Into<String>) -> Self {
        Self {
            transport,
            endpoint: endpoint.into().trim_end_matches('/').to_owned(),
        }
    }

    /// IMDS at `AWS_EC2_METADATA_SERVICE_ENDPOINT`, else the default
    /// endpoint. `None` when `AWS_EC2_METADATA_DISABLED` is `true`.
    pub fn from_env_lookup(env: &EnvLookup, transport: T) -> Option<Self> {
        if env("AWS_EC2_METADATA_DISABLED").is_some_and(|value| value.eq_ignore_ascii_case("true"))
        {
            return None;
        }
        let endpoint = env("AWS_EC2_METADATA_SERVICE_ENDPOINT")
            .unwrap_or_else(|| DEFAULT_IMDS_ENDPOINT.to_owned());
        Some(Self::new(transport, endpoint))
    }

    async fn send(&self, request: VendorRequest) -> Result<Zeroizing<Vec<u8>>, CredentialsError> {
        let response = self.transport.send(request).await.map_err(|error| {
            CredentialsError::unavailable(format!("IMDS did not answer: {error}"))
        })?;
        if classify_status(response.status).is_some() {
            return Err(status_failure("IMDS", &response));
        }
        Ok(response.body)
    }
}

impl<T: VendorTransport + Send + Sync> CredentialsProvider for ImdsCredentials<T> {
    async fn credentials(&self) -> Result<Credentials, CredentialsError> {
        let token = self
            .send(
                VendorRequest::new("PUT", format!("{}/latest/api/token", self.endpoint))
                    .header("x-aws-ec2-metadata-token-ttl-seconds", TOKEN_TTL_SECONDS),
            )
            .await?;
        let token = Zeroizing::new(
            String::from_utf8(token.to_vec())
                .map_err(|_| CredentialsError::unavailable("IMDS returned an invalid token"))?,
        );
        let roles = self
            .send(
                VendorRequest::new("GET", format!("{}{CREDENTIALS_PATH}", self.endpoint))
                    .header("x-aws-ec2-metadata-token", token.as_str()),
            )
            .await?;
        let role = std::str::from_utf8(&roles)
            .ok()
            .and_then(|roles| roles.lines().map(str::trim).find(|line| !line.is_empty()))
            .map(str::to_owned)
            .ok_or_else(|| {
                CredentialsError::access_denied("the instance has no IAM instance profile")
            })?;
        let request = VendorRequest::new(
            "GET",
            format!(
                "{}{CREDENTIALS_PATH}{}",
                self.endpoint,
                crate::sigv4::uri_encode(role.as_bytes())
            ),
        )
        .header("x-aws-ec2-metadata-token", token.as_str());
        let response = self.transport.send(request).await.map_err(|error| {
            CredentialsError::unavailable(format!("IMDS did not answer: {error}"))
        })?;
        json_credentials("IMDS", &response)
    }
}
