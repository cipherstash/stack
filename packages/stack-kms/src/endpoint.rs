use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use url::Url;

/// Why a URL was rejected as a [`ZeroKmsEndpoint`].
///
/// No message repeats the URL it refused: [`NoHost`](Self::NoHost) and
/// [`QueryOrFragment`](Self::QueryOrFragment) are checked before
/// [`Userinfo`](Self::Userinfo), so the URL they hold can still carry
/// credentials, and a query string can carry anything. A
/// [`NotHosted`](Self::NotHosted) URL came from an unverified token claim, so
/// it can carry whatever its author chose. The URL stays in the variant for a
/// caller in this process.
#[derive(Debug, Error, PartialEq, Eq, miette::Diagnostic)]
pub enum InvalidEndpoint {
    /// The value did not parse as a URL at all.
    #[error("not a valid URL: {0}")]
    #[diagnostic(code(stack_kms::endpoint_not_url))]
    Parse(#[from] url::ParseError),

    /// The URL parsed but has no authority — `localhost:8080` parses as scheme
    /// `localhost`, path `8080` — so no request path could ever be joined to it.
    #[error("the URL has no host; is the `http://` or `https://` prefix missing?")]
    #[diagnostic(code(stack_kms::endpoint_no_host))]
    NoHost(String),

    /// Only `http` and `https` can reach ZeroKMS.
    #[error("unsupported scheme `{0}`; expected `http` or `https`")]
    #[diagnostic(code(stack_kms::endpoint_scheme))]
    Scheme(String),

    /// Request URLs are built by joining an endpoint path onto the base, which
    /// discards any query or fragment — so accepting one would silently drop it.
    #[error("query strings and fragments are not supported on a ZeroKMS endpoint")]
    #[diagnostic(code(stack_kms::endpoint_query_or_fragment))]
    QueryOrFragment(String),

    /// Credentials belong in the bearer token, never in the URL.
    #[error("userinfo is not supported on a ZeroKMS endpoint")]
    #[diagnostic(
        code(stack_kms::endpoint_userinfo),
        help("Remove the user and password from the URL: ZeroKMS takes the credential as a bearer token.")
    )]
    Userinfo,

    /// A token's `services` claim named an endpoint that is not a
    /// CipherStash-hosted ZeroKMS. The claim is read from a token whose
    /// signature this client does not verify, so it may only choose between
    /// CipherStash's own regional endpoints; anything else must be configured
    /// explicitly by the operator.
    #[error(
        "the token's services claim may only name a CipherStash-hosted ZeroKMS endpoint (`https://<region>.<provider>.viturhosted.net`)"
    )]
    #[diagnostic(
        code(stack_kms::endpoint_not_hosted),
        help("To use any other ZeroKMS endpoint, configure it explicitly (`CS_ZEROKMS_HOST` or `with_base_url`).")
    )]
    NotHosted(String),

    /// A token's `services` claim named a different ZeroKMS endpoint from the
    /// one this client resolved from an earlier token. The client refuses to
    /// send the token anywhere but the endpoint it already uses, and refuses
    /// to move to the new one.
    #[error("the token names a different ZeroKMS endpoint from the one this client already uses")]
    #[diagnostic(
        code(stack_kms::endpoint_mismatch),
        help("A client resolves its ZeroKMS endpoint from the first token it holds. Use a separate client for each region's credentials, or configure the endpoint explicitly (`CS_ZEROKMS_HOST`).")
    )]
    Mismatch,
}

impl stack_auth::ErrorPayload for InvalidEndpoint {
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match self {
            Self::Scheme(scheme) => {
                stack_auth::diagnostic::payload([("scheme", scheme.as_str().into())])
            }
            Self::Parse(_)
            | Self::NoHost(_)
            | Self::QueryOrFragment(_)
            | Self::Userinfo
            | Self::NotHosted(_)
            | Self::Mismatch => serde_json::Map::new(),
        }
    }
}

/// A validated ZeroKMS base URL.
///
/// Construction is the one place URL hygiene happens, so everything downstream
/// (the HTTP connection, the builder, the token's `services` claim) works with a
/// value that is already known to be usable:
///
/// * scheme is `http` or `https` and the URL has a host
/// * no userinfo, query or fragment (they would be dropped or leak)
/// * the path ends in `/`, so [`request_url`](Self::request_url) *appends*
///   an endpoint path (`https://gw.example/zerokms` + `retrieve-data-key` →
///   `https://gw.example/zerokms/retrieve-data-key`) instead of replacing the
///   last segment as `Url::join` would
///
/// ```
/// use stack_kms::ZeroKmsEndpoint;
///
/// let endpoint: ZeroKmsEndpoint = "https://gateway.example/zerokms".parse()?;
/// assert_eq!(endpoint.as_str(), "https://gateway.example/zerokms/");
/// assert_eq!(
///     endpoint.request_url("retrieve-data-key").as_str(),
///     "https://gateway.example/zerokms/retrieve-data-key"
/// );
///
/// assert!("localhost:3002".parse::<ZeroKmsEndpoint>().is_err());
/// # Ok::<(), stack_kms::InvalidEndpoint>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeroKmsEndpoint(Url);

impl ZeroKmsEndpoint {
    /// Validate and normalise a parsed [`Url`].
    pub fn new(mut url: Url) -> Result<Self, InvalidEndpoint> {
        if url.cannot_be_a_base() || url.host_str().is_none() {
            return Err(InvalidEndpoint::NoHost(url.into()));
        }
        if !matches!(url.scheme(), "http" | "https") {
            return Err(InvalidEndpoint::Scheme(url.scheme().to_string()));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(InvalidEndpoint::QueryOrFragment(url.into()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(InvalidEndpoint::Userinfo);
        }
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        Ok(Self(url))
    }

    /// Validate an endpoint named by an access token's `services` claim.
    ///
    /// The claim comes from a token whose signature this crate never checks,
    /// and a [`TokenStore`](stack_auth::TokenStore) can hand back a token
    /// someone else wrote. So on top of [`new`](Self::new)'s hygiene, a
    /// claimed endpoint must be a CipherStash-hosted ZeroKMS:
    ///
    /// * scheme `https`, on the default port
    /// * host `<region>.<provider>.viturhosted.net`, for a region CipherStash
    ///   runs (`cts_common::Region`) — the form CTS issues
    ///
    /// Any other endpoint (a gateway, a local ZeroKMS, plain `http`) is
    /// accepted only from explicit configuration: `CS_ZEROKMS_HOST` or the
    /// builder's `with_base_url`.
    ///
    /// # Errors
    ///
    /// Whatever [`new`](Self::new) refuses, and
    /// [`InvalidEndpoint::NotHosted`] for a usable URL on any other host.
    pub(crate) fn from_services_claim(url: Url) -> Result<Self, InvalidEndpoint> {
        let endpoint = Self::new(url)?;
        let url = endpoint.as_url();
        let hosted = url.scheme() == "https"
            && url.port().is_none()
            && url.host_str().is_some_and(|host| {
                cts_common::ZeroKmsServiceDiscovery::region_from_host_fqdn(host).is_ok()
            });
        if hosted {
            Ok(endpoint)
        } else {
            Err(InvalidEndpoint::NotHosted(endpoint.0.into()))
        }
    }

    /// The URL for a request path (a `ViturRequest::ENDPOINT`), appended to
    /// the base. Infallible: the base is known to be http(s) with a
    /// slash-terminated path, and the endpoint paths are relative constants.
    pub fn request_url(&self, endpoint: &str) -> Url {
        let mut url = self.0.clone();
        let path = format!("{}{}", self.0.path(), endpoint);
        url.set_path(&path);
        url
    }

    /// The normalised base URL as a string (always slash-terminated).
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Borrow the underlying [`Url`].
    pub fn as_url(&self) -> &Url {
        &self.0
    }
}

impl TryFrom<Url> for ZeroKmsEndpoint {
    type Error = InvalidEndpoint;

    fn try_from(url: Url) -> Result<Self, Self::Error> {
        Self::new(url)
    }
}

impl FromStr for ZeroKmsEndpoint {
    type Err = InvalidEndpoint;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(Url::parse(s)?)
    }
}

impl fmt::Display for ZeroKmsEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl From<ZeroKmsEndpoint> for Url {
    fn from(endpoint: ZeroKmsEndpoint) -> Self {
        endpoint.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(s: &str) -> ZeroKmsEndpoint {
        s.parse().unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    mod accepts {
        use super::*;

        #[test]
        fn a_bare_host() {
            assert_eq!(endpoint("https://a.example").as_str(), "https://a.example/");
        }

        #[test]
        fn a_host_with_port_over_http() {
            assert_eq!(
                endpoint("http://localhost:3002").as_str(),
                "http://localhost:3002/"
            );
        }

        #[test]
        fn a_path_prefix_and_terminates_it_with_a_slash() {
            assert_eq!(
                endpoint("https://gateway.example/zerokms").as_str(),
                "https://gateway.example/zerokms/"
            );
        }

        #[test]
        fn an_already_slash_terminated_url_unchanged() {
            for s in [
                "https://a.example/",
                "https://a.example/zerokms/",
                "http://localhost:3002/",
            ] {
                assert_eq!(endpoint(s).as_str(), s, "{s} should be left as-is");
            }
        }
    }

    mod request_url {
        use super::*;

        #[test]
        fn appends_to_a_path_prefix() {
            assert_eq!(
                endpoint("https://gateway.example/zerokms")
                    .request_url("retrieve-data-key")
                    .as_str(),
                "https://gateway.example/zerokms/retrieve-data-key"
            );
        }

        #[test]
        fn appends_to_a_bare_host() {
            assert_eq!(
                endpoint("https://a.example")
                    .request_url("generate-data-key")
                    .as_str(),
                "https://a.example/generate-data-key"
            );
        }

        #[test]
        fn matches_url_join_for_every_protocol_endpoint() {
            // `Url::join` is what the connection used before this type existed;
            // the infallible `set_path` construction must agree with it.
            let base = endpoint("https://gateway.example/zerokms/v1");
            for path in [
                "generate-data-key",
                "retrieve-data-key",
                "retrieve-data-key-fallible",
            ] {
                assert_eq!(
                    base.request_url(path),
                    base.as_url().join(path).unwrap(),
                    "{path}"
                );
            }
        }
    }

    mod rejects {
        use super::*;

        #[test]
        fn a_scheme_less_host_and_port() {
            // `Url::parse` accepts this — scheme `localhost`, opaque path
            // `8080` — but nothing could ever be joined onto it.
            assert!(matches!(
                "localhost:8080".parse::<ZeroKmsEndpoint>(),
                Err(InvalidEndpoint::NoHost(_))
            ));
        }

        #[test]
        fn a_non_http_scheme() {
            assert!(matches!(
                "ftp://a.example".parse::<ZeroKmsEndpoint>(),
                Err(InvalidEndpoint::Scheme(s)) if s == "ftp"
            ));
        }

        #[test]
        fn a_query_string() {
            assert!(matches!(
                "https://gw.example/zerokms?apikey=abc".parse::<ZeroKmsEndpoint>(),
                Err(InvalidEndpoint::QueryOrFragment(_))
            ));
        }

        #[test]
        fn a_fragment() {
            assert!(matches!(
                "https://gw.example/zerokms#frag".parse::<ZeroKmsEndpoint>(),
                Err(InvalidEndpoint::QueryOrFragment(_))
            ));
        }

        #[test]
        fn userinfo() {
            assert!(matches!(
                "https://user:pw@gw.example".parse::<ZeroKmsEndpoint>(),
                Err(InvalidEndpoint::Userinfo)
            ));
        }

        #[test]
        fn garbage() {
            assert!(matches!(
                "not a url".parse::<ZeroKmsEndpoint>(),
                Err(InvalidEndpoint::Parse(_))
            ));
        }

        #[test]
        fn nothing_with_a_message_that_repeats_a_claimed_url() {
            let err = claimed("https://marker.example/").unwrap_err();
            assert!(!err.to_string().contains("marker"), "{err}");
        }
    }

    fn claimed(s: &str) -> Result<ZeroKmsEndpoint, InvalidEndpoint> {
        ZeroKmsEndpoint::from_services_claim(Url::parse(s).unwrap())
    }

    /// The endpoint a token's `services` claim may name: only CipherStash's
    /// own regional ZeroKMS, whatever the explicit-config path accepts.
    mod from_services_claim {
        use super::*;

        #[test]
        fn accepts_every_region_cipherstash_runs() {
            for region in cts_common::Region::all() {
                let s = format!("https://{}.viturhosted.net/", region.identifier());
                assert_eq!(claimed(&s).map(|e| e.to_string()), Ok(s.clone()), "{s}");
            }
        }

        #[test]
        fn accepts_a_hosted_endpoint_without_a_trailing_slash() {
            assert_eq!(
                claimed("https://ap-southeast-2.aws.viturhosted.net")
                    .unwrap()
                    .as_str(),
                "https://ap-southeast-2.aws.viturhosted.net/"
            );
        }

        #[test]
        fn accepts_an_explicit_default_port() {
            // `Url` drops `:443` on https, so it is the same endpoint.
            assert!(claimed("https://us-east-1.aws.viturhosted.net:443/").is_ok());
        }

        #[test]
        fn rejects_hosts_outside_cipherstash() {
            for s in [
                "https://evil.example/",
                "https://zerokms.example.com/",
                "https://localhost:3002/",
                "https://127.0.0.1/",
                "https://viturhosted.net/",
                "https://aws.viturhosted.net/",
                "https://us-east-1.aws.viturhosted.net.evil.example/",
                "https://evil.us-east-1.aws.viturhosted.net/",
                "https://us-east-1.aws.viturhosted.net.",
                "https://us-east-1-aws.viturhosted.net/",
                "https://xviturhosted.net/",
            ] {
                assert!(
                    matches!(claimed(s), Err(InvalidEndpoint::NotHosted(_))),
                    "{s}: {:?}",
                    claimed(s)
                );
            }
        }

        #[test]
        fn rejects_a_region_cipherstash_does_not_run() {
            assert!(matches!(
                claimed("https://mars-north-1.aws.viturhosted.net/"),
                Err(InvalidEndpoint::NotHosted(_))
            ));
            assert!(matches!(
                claimed("https://us-east-1.gcp.viturhosted.net/"),
                Err(InvalidEndpoint::NotHosted(_))
            ));
        }

        #[test]
        fn rejects_plain_http_to_a_hosted_name() {
            assert!(matches!(
                claimed("http://us-east-1.aws.viturhosted.net/"),
                Err(InvalidEndpoint::NotHosted(_))
            ));
        }

        #[test]
        fn rejects_a_non_default_port() {
            assert!(matches!(
                claimed("https://us-east-1.aws.viturhosted.net:8443/"),
                Err(InvalidEndpoint::NotHosted(_))
            ));
        }

        #[test]
        fn still_applies_the_hygiene_rules_first() {
            assert!(matches!(
                claimed("https://user:pw@us-east-1.aws.viturhosted.net/"),
                Err(InvalidEndpoint::Userinfo)
            ));
            assert!(matches!(
                claimed("https://us-east-1.aws.viturhosted.net/?q=1"),
                Err(InvalidEndpoint::QueryOrFragment(_))
            ));
        }
    }
}
