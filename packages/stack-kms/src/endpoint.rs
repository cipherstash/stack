use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use url::Url;

/// Why a URL was rejected as a [`ZeroKmsEndpoint`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum InvalidEndpoint {
    /// The value did not parse as a URL at all.
    #[error("not a valid URL: {0}")]
    Parse(#[from] url::ParseError),

    /// The URL parsed but has no authority — `localhost:8080` parses as scheme
    /// `localhost`, path `8080` — so no request path could ever be joined to it.
    #[error("`{0}` has no host; is the `http://` or `https://` prefix missing?")]
    NoHost(String),

    /// Only `http` and `https` can reach ZeroKMS.
    #[error("unsupported scheme `{0}`; expected `http` or `https`")]
    Scheme(String),

    /// Request URLs are built by joining an endpoint path onto the base, which
    /// discards any query or fragment — so accepting one would silently drop it.
    #[error("query strings and fragments are not supported on a ZeroKMS endpoint: `{0}`")]
    QueryOrFragment(String),

    /// Credentials belong in the bearer token, never in the URL.
    #[error("userinfo is not supported on a ZeroKMS endpoint")]
    Userinfo,
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
    }
}
