//! Credentials from the ECS container endpoint (and EKS Pod Identity).

use stack_kms_vendor::{VendorRequest, VendorTransport};
use zeroize::Zeroizing;

use super::response::json_credentials;
use super::{Credentials, CredentialsError, CredentialsProvider, EnvLookup};

/// The ECS task credentials host, for `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.
const ECS_HOST: &str = "http://169.254.170.2";

/// Where the authorization token of the container endpoint comes from.
#[derive(Clone, Debug)]
enum AuthToken {
    None,
    /// `AWS_CONTAINER_AUTHORIZATION_TOKEN`.
    Value(Zeroizing<String>),
    /// `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, read on each fetch (EKS
    /// Pod Identity rotates it).
    File(std::path::PathBuf),
}

/// Credentials from the container credentials endpoint: ECS task roles
/// (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`) and EKS Pod Identity or any
/// other `AWS_CONTAINER_CREDENTIALS_FULL_URI`.
///
/// Wrap it in [`CachedCredentials`](super::CachedCredentials). Native only.
pub struct EcsCredentials<T> {
    transport: T,
    uri: String,
    token: AuthToken,
}

impl<T> std::fmt::Debug for EcsCredentials<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcsCredentials")
            .field("uri", &self.uri)
            .finish_non_exhaustive()
    }
}

impl<T: VendorTransport> EcsCredentials<T> {
    /// From `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, else
    /// `AWS_CONTAINER_CREDENTIALS_FULL_URI`, with the token from
    /// `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` or
    /// `AWS_CONTAINER_AUTHORIZATION_TOKEN`. `Ok(None)` when neither URI is
    /// set.
    ///
    /// A full URI must be HTTPS, or plain HTTP to a loopback address or to
    /// one of the ECS and EKS link-local hosts, as the AWS SDKs require:
    /// the credentials must not cross a network in the clear.
    pub fn from_env_lookup(
        env: &EnvLookup,
        transport: T,
    ) -> Result<Option<Self>, CredentialsError> {
        let uri = if let Some(relative) = env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
            format!("{ECS_HOST}{relative}")
        } else if let Some(full) = env("AWS_CONTAINER_CREDENTIALS_FULL_URI") {
            check_full_uri(&full)?;
            full
        } else {
            return Ok(None);
        };
        let token = if let Some(file) = env("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
            AuthToken::File(file.into())
        } else if let Some(value) = env("AWS_CONTAINER_AUTHORIZATION_TOKEN") {
            AuthToken::Value(Zeroizing::new(value))
        } else {
            AuthToken::None
        };
        Ok(Some(Self {
            transport,
            uri,
            token,
        }))
    }
}

/// Refuse a full URI that would send credentials in the clear over a
/// network.
fn check_full_uri(uri: &str) -> Result<(), CredentialsError> {
    let parsed = url::Url::parse(uri).map_err(|_| {
        CredentialsError::access_denied("AWS_CONTAINER_CREDENTIALS_FULL_URI is not a valid URL")
    })?;
    let allowed = match parsed.scheme() {
        "https" => true,
        "http" => match parsed.host() {
            Some(url::Host::Ipv4(ip)) => {
                ip.is_loopback()
                    || ip.octets() == [169, 254, 170, 2]
                    || ip.octets() == [169, 254, 170, 23]
            }
            Some(url::Host::Ipv6(ip)) => {
                ip.is_loopback() || ip.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x23]
            }
            Some(url::Host::Domain(domain)) => domain == "localhost",
            None => false,
        },
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(CredentialsError::access_denied(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI must be HTTPS, or HTTP to a loopback or ECS/EKS link-local host",
        ))
    }
}

impl<T: VendorTransport + Send + Sync> CredentialsProvider for EcsCredentials<T> {
    async fn credentials(&self) -> Result<Credentials, CredentialsError> {
        let mut request = VendorRequest::new("GET", self.uri.as_str());
        let token = match &self.token {
            AuthToken::None => None,
            AuthToken::Value(value) => Some(value.clone()),
            AuthToken::File(path) => Some(Zeroizing::new(
                std::fs::read_to_string(path)
                    .map_err(|error| {
                        CredentialsError::access_denied(format!(
                            "the container authorization token file {} could not be read: {error}",
                            path.display()
                        ))
                    })?
                    .trim()
                    .to_owned(),
            )),
        };
        if let Some(token) = token {
            request = request.header("authorization", token.as_str());
        }
        let response = self.transport.send(request).await.map_err(|error| {
            CredentialsError::unavailable(format!("the container endpoint did not answer: {error}"))
        })?;
        json_credentials("the container endpoint", &response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_uris_must_not_cross_a_network_in_the_clear() {
        for allowed in [
            "https://example.com/creds",
            "http://127.0.0.1:8080/creds",
            "http://localhost/creds",
            "http://169.254.170.2/v2/credentials",
            "http://169.254.170.23/v1/credentials",
            "http://[fd00:ec2::23]/v1/credentials",
            "http://[::1]/creds",
        ] {
            assert!(check_full_uri(allowed).is_ok(), "{allowed}");
        }
        for refused in [
            "http://example.com/creds",
            "http://10.0.0.1/creds",
            "ftp://127.0.0.1/creds",
            "not a url",
        ] {
            assert!(check_full_uri(refused).is_err(), "{refused}");
        }
    }
}
