//! The trust boundary for ZeroKMS endpoints read from unverified claims.

use cts_common::{Region, ZeroKmsServiceDiscovery};
use url::Url;

/// A ZeroKMS claim URL outside the supported CipherStash-hosted service.
///
/// The message never includes the untrusted URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the token must name a supported CipherStash-hosted ZeroKMS endpoint")]
pub struct InvalidHostedZeroKmsEndpoint;

/// A validated CipherStash-hosted ZeroKMS endpoint and its region.
///
/// Claims may select HTTPS on the default port at the root path of
/// `<region>.<provider>.viturhosted.net` or
/// `<region>.<provider>.zerokms.cipherstashmanaged.net`. The region must be
/// known to this build's `cts-common`; future regions and staging hosts
/// require an SDK upgrade or an explicitly configured KMS endpoint.
///
/// This validates the destination, not the token's signature or authority.
///
/// ```
/// use stack_auth::HostedZeroKmsEndpoint;
/// let endpoint = HostedZeroKmsEndpoint::new(
///     "https://us-east-1.aws.zerokms.cipherstashmanaged.net/".parse()?,
/// )?;
/// assert_eq!(endpoint.region().identifier(), "us-east-1.aws");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedZeroKmsEndpoint {
    url: Url,
    region: Region,
}

impl HostedZeroKmsEndpoint {
    /// Validate an endpoint from an unverified service claim.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHostedZeroKmsEndpoint`] for any other destination,
    /// including userinfo, query strings and fragments.
    pub fn new(url: Url) -> Result<Self, InvalidHostedZeroKmsEndpoint> {
        if url.scheme() != "https"
            || url.port().is_some()
            || url.path() != "/"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(InvalidHostedZeroKmsEndpoint);
        }
        let host = url.host_str().ok_or(InvalidHostedZeroKmsEndpoint)?;
        if !host.ends_with(".viturhosted.net") && !host.ends_with(".zerokms.cipherstashmanaged.net")
        {
            return Err(InvalidHostedZeroKmsEndpoint);
        }
        // cts-common owns region extraction but currently knows only the
        // legacy domain. Normalize the one additional trusted suffix before
        // delegating, retaining its exact-label and region checks.
        let legacy_host = host
            .strip_suffix(".zerokms.cipherstashmanaged.net")
            .map(|prefix| format!("{prefix}.viturhosted.net"));
        let region =
            ZeroKmsServiceDiscovery::region_from_host_fqdn(legacy_host.as_deref().unwrap_or(host))
                .map_err(|_| InvalidHostedZeroKmsEndpoint)?;
        Ok(Self { url, region })
    }

    /// The validated HTTPS URL.
    pub fn as_url(&self) -> &Url {
        &self.url
    }

    /// The service's region, independent of its hosted domain.
    pub fn region(&self) -> Region {
        self.region
    }
}
