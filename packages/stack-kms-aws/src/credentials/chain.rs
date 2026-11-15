//! The default credential chain.

use stack_kms_vendor::VendorTransport;

use super::{
    CachedCredentials, Credentials, CredentialsError, CredentialsProvider, EcsCredentials,
    EnvLookup, ImdsCredentials, WebIdentityCredentials,
};

/// The credentials source the environment names, chosen once, in the order
/// the AWS SDKs use:
///
/// 1. static credentials: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`;
/// 2. IRSA: `AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_ROLE_ARN`;
/// 3. the container endpoint: `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or
///    `AWS_CONTAINER_CREDENTIALS_FULL_URI`;
/// 4. IMDSv2, unless `AWS_EC2_METADATA_DISABLED=true`.
///
/// The shared config and credentials files (`~/.aws/config`) and SSO are
/// not read. Native only.
#[derive(Debug)]
pub enum DefaultCredentialsSource<T> {
    /// Static credentials from the environment.
    Static(Credentials),
    /// IRSA.
    WebIdentity(WebIdentityCredentials<T>),
    /// The container endpoint.
    Ecs(EcsCredentials<T>),
    /// IMDSv2.
    Imds(ImdsCredentials<T>),
}

/// The default credential chain, cached.
pub type DefaultCredentials<T> = CachedCredentials<DefaultCredentialsSource<T>>;

impl<T: VendorTransport + Send + Sync> DefaultCredentialsSource<T> {
    /// Choose the source from the variables `env` reads. `region` is the
    /// STS region for IRSA. Fails when no source is configured (IMDS
    /// disabled and nothing else set) or a container URI is refused.
    pub fn from_env_lookup(
        env: &EnvLookup,
        transport: T,
        region: Option<&str>,
    ) -> Result<Self, CredentialsError> {
        if let Some(credentials) = Credentials::from_env_lookup(env) {
            return Ok(Self::Static(credentials));
        }
        if env("AWS_WEB_IDENTITY_TOKEN_FILE").is_some() && env("AWS_ROLE_ARN").is_some() {
            return WebIdentityCredentials::from_env_lookup(env, transport, region)
                .map(Self::WebIdentity)
                .ok_or_else(|| CredentialsError::access_denied("IRSA is not configured"));
        }
        if env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").is_some()
            || env("AWS_CONTAINER_CREDENTIALS_FULL_URI").is_some()
        {
            return EcsCredentials::from_env_lookup(env, transport)?
                .map(Self::Ecs)
                .ok_or_else(|| {
                    CredentialsError::access_denied("the container endpoint is not configured")
                });
        }
        ImdsCredentials::from_env_lookup(env, transport)
            .map(Self::Imds)
            .ok_or_else(|| {
                CredentialsError::access_denied(
                    "no AWS credentials are configured: set AWS_ACCESS_KEY_ID and \
                     AWS_SECRET_ACCESS_KEY, IRSA, a container endpoint, or enable IMDS",
                )
            })
    }

    /// Choose the source from the process environment, and cache it.
    pub fn cached_from_env(
        transport: T,
        region: Option<&str>,
    ) -> Result<DefaultCredentials<T>, CredentialsError> {
        Self::from_env_lookup(&super::process_env(), transport, region).map(CachedCredentials::new)
    }
}

impl<T: VendorTransport + Send + Sync> CredentialsProvider for DefaultCredentialsSource<T> {
    async fn credentials(&self) -> Result<Credentials, CredentialsError> {
        match self {
            Self::Static(credentials) => credentials.credentials().await,
            Self::WebIdentity(provider) => provider.credentials().await,
            Self::Ecs(provider) => provider.credentials().await,
            Self::Imds(provider) => provider.credentials().await,
        }
    }
}
