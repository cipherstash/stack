//! IRSA: credentials from STS `AssumeRoleWithWebIdentity`.

use std::path::PathBuf;

use stack_kms_vendor::{VendorRequest, VendorTransport};

use super::response::sts_credentials;
use super::{Credentials, CredentialsError, CredentialsProvider, EnvLookup};
use crate::sigv4::uri_encode;

/// The STS API version.
const STS_VERSION: &str = "2011-06-15";
/// The session name when `AWS_ROLE_SESSION_NAME` is not set.
const DEFAULT_SESSION_NAME: &str = "stack-kms-aws";

/// Credentials for an IAM role, assumed with a web identity token: IAM
/// Roles for Service Accounts (IRSA) on EKS, or any OIDC token file.
///
/// Each fetch reads the token file again (the platform rotates it) and
/// calls STS `AssumeRoleWithWebIdentity`, which needs no AWS credentials.
/// Wrap it in [`CachedCredentials`](super::CachedCredentials). Native only.
pub struct WebIdentityCredentials<T> {
    transport: T,
    role_arn: String,
    token_file: PathBuf,
    session_name: String,
    sts_endpoint: String,
}

impl<T> std::fmt::Debug for WebIdentityCredentials<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebIdentityCredentials")
            .field("role_arn", &self.role_arn)
            .field("token_file", &self.token_file)
            .field("session_name", &self.session_name)
            .field("sts_endpoint", &self.sts_endpoint)
            .finish_non_exhaustive()
    }
}

impl<T: VendorTransport> WebIdentityCredentials<T> {
    /// Assume `role_arn` with the token in `token_file`, through the STS
    /// endpoint of `region` (the global endpoint for `None`).
    pub fn new(
        transport: T,
        role_arn: impl Into<String>,
        token_file: impl Into<PathBuf>,
        region: Option<&str>,
    ) -> Self {
        Self {
            transport,
            role_arn: role_arn.into(),
            token_file: token_file.into(),
            session_name: DEFAULT_SESSION_NAME.to_owned(),
            sts_endpoint: sts_endpoint(region),
        }
    }

    /// From `AWS_WEB_IDENTITY_TOKEN_FILE`, `AWS_ROLE_ARN` and (optional)
    /// `AWS_ROLE_SESSION_NAME`. `None` unless the first two are set.
    pub fn from_env_lookup(env: &EnvLookup, transport: T, region: Option<&str>) -> Option<Self> {
        let token_file = env("AWS_WEB_IDENTITY_TOKEN_FILE")?;
        let role_arn = env("AWS_ROLE_ARN")?;
        let mut provider = Self::new(transport, role_arn, token_file, region);
        if let Some(name) = env("AWS_ROLE_SESSION_NAME") {
            provider.session_name = name;
        }
        Some(provider)
    }

    /// Use `endpoint` for STS (a full URL).
    pub fn with_sts_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.sts_endpoint = endpoint.into();
        self
    }

    /// Use `name` as the role session name.
    pub fn with_session_name(mut self, name: impl Into<String>) -> Self {
        self.session_name = name.into();
        self
    }
}

/// The STS endpoint of `region`.
pub(super) fn sts_endpoint(region: Option<&str>) -> String {
    match region {
        Some(region) => format!(
            "https://sts.{region}.{}/",
            crate::config::dns_suffix(region)
        ),
        None => "https://sts.amazonaws.com/".to_owned(),
    }
}

impl<T: VendorTransport + Send + Sync> CredentialsProvider for WebIdentityCredentials<T> {
    async fn credentials(&self) -> Result<Credentials, CredentialsError> {
        let token = zeroize::Zeroizing::new(std::fs::read_to_string(&self.token_file).map_err(
            |error| {
                CredentialsError::access_denied(format!(
                    "the web identity token file {} could not be read: {error}",
                    self.token_file.display()
                ))
            },
        )?);
        let body = zeroize::Zeroizing::new(format!(
            "Action=AssumeRoleWithWebIdentity&RoleArn={}&RoleSessionName={}&Version={STS_VERSION}&WebIdentityToken={}",
            uri_encode(self.role_arn.as_bytes()),
            uri_encode(self.session_name.as_bytes()),
            uri_encode(token.trim().as_bytes()),
        ));
        let request = VendorRequest::new("POST", self.sts_endpoint.as_str())
            .header(
                "content-type",
                "application/x-www-form-urlencoded; charset=utf-8",
            )
            .body(body.as_bytes().to_vec());
        let response = self.transport.send(request).await.map_err(|error| {
            CredentialsError::unavailable(format!("STS did not answer: {error}"))
        })?;
        sts_credentials(&response)
    }
}
