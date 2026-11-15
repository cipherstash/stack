//! AWS Signature Version 4, in-crate.
//!
//! The AWS SDKs and the `aws-sigv4` crate are not used: the SDKs need tokio
//! and hyper, and this crate must build for wasm32-wasip1 (ADR-0015).
//! Signing is a few HMAC-SHA256 calls, so it is written here and tested
//! against the AWS SigV4 test suite.
//!
//! [`sign`] adds `host` (when the request has none), `x-amz-date`,
//! `x-amz-security-token` (for temporary credentials) and `authorization`
//! to a [`VendorRequest`]. It signs every header the request carries.
//!
//! See <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html>.

use std::fmt::Write as _;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use stack_kms_vendor::VendorRequest;
use web_time::SystemTime;
use zeroize::Zeroizing;

use crate::credentials::Credentials;
use crate::time::amz_date;

/// The signing algorithm name.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// A request could not be signed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SigningError {
    /// The request URL does not parse or has no host.
    #[error("the request URL is not a valid absolute URL with a host")]
    InvalidUrl,
}

/// What a signature is made with, apart from the request.
#[derive(Clone, Copy, Debug)]
pub struct SigningParams<'a> {
    /// The credentials.
    pub credentials: &'a Credentials,
    /// The AWS region (`us-east-1`).
    pub region: &'a str,
    /// The service signing name (`kms`, `sts`).
    pub service: &'a str,
    /// The signing time.
    pub time: SystemTime,
}

/// Sign `request` in place (see the module docs).
pub fn sign(request: &mut VendorRequest, params: &SigningParams<'_>) -> Result<(), SigningError> {
    let url = url::Url::parse(&request.url).map_err(|_| SigningError::InvalidUrl)?;
    let host = url.host_str().ok_or(SigningError::InvalidUrl)?;
    let host = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    let (date, timestamp) = amz_date(params.time);
    if request.header_value("host").is_none() {
        request.headers.push(("host".to_owned(), host));
    }
    request
        .headers
        .push(("x-amz-date".to_owned(), timestamp.clone()));
    if let Some(token) = params.credentials.session_token() {
        request
            .headers
            .push(("x-amz-security-token".to_owned(), token.to_owned()));
    }

    let (canonical, signed_headers) = canonical_request(request, &url);
    let scope = format!("{date}/{}/{}/aws4_request", params.region, params.service);
    let string_to_sign = format!(
        "{ALGORITHM}\n{timestamp}\n{scope}\n{}",
        hex(&Sha256::digest(canonical.as_bytes()))
    );
    let key = signing_key(
        params.credentials.secret_access_key(),
        &date,
        params.region,
        params.service,
    );
    let signature = hex(&hmac(key.as_slice(), string_to_sign.as_bytes()));
    request.headers.push((
        "authorization".to_owned(),
        format!(
            "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            params.credentials.access_key_id()
        ),
    ));
    Ok(())
}

/// The canonical request of `request` and its signed header list.
fn canonical_request(request: &VendorRequest, url: &url::Url) -> (String, String) {
    let mut headers: Vec<(String, String)> = Vec::new();
    for (name, value) in &request.headers {
        let name = name.to_ascii_lowercase();
        let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        match headers.iter_mut().find(|(n, _)| *n == name) {
            Some((_, joined)) => {
                joined.push(',');
                joined.push_str(&value);
            }
            None => headers.push((name, value)),
        }
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));
    let signed_headers = headers
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let mut canonical = String::new();
    canonical.push_str(&request.method);
    canonical.push('\n');
    canonical.push_str(&canonical_uri(url.path()));
    canonical.push('\n');
    canonical.push_str(&canonical_query(url.query().unwrap_or("")));
    canonical.push('\n');
    for (name, value) in &headers {
        let _ = writeln!(canonical, "{name}:{value}");
    }
    canonical.push('\n');
    canonical.push_str(&signed_headers);
    canonical.push('\n');
    canonical.push_str(&hex(&Sha256::digest(request.body.as_slice())));
    (canonical, signed_headers)
}

/// Each path segment decoded and encoded again with the SigV4 rules.
fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        return "/".to_owned();
    }
    path.split('/')
        .map(|segment| uri_encode(&percent_decode(segment)))
        .collect::<Vec<_>>()
        .join("/")
}

/// The query pairs decoded, encoded again with the SigV4 rules, and sorted
/// by name, then value.
fn canonical_query(query: &str) -> String {
    let mut pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (
                uri_encode(&percent_decode(name)),
                uri_encode(&percent_decode(value)),
            )
        })
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encode every byte except the RFC 3986 unreserved characters.
pub(crate) fn uri_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// Decode `%XX` escapes. An escape that is not two hex digits is kept as
/// it is.
fn percent_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let decoded = (bytes[i] == b'%')
            .then(|| bytes.get(i + 1..i + 3))
            .flatten()
            .and_then(|hex| std::str::from_utf8(hex).ok())
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        match decoded {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    out
}

/// The SigV4 signing key: `HMAC` chained over the date, region, service and
/// `aws4_request`, from `AWS4` + the secret.
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Zeroizing<Vec<u8>> {
    let initial = Zeroizing::new(format!("AWS4{secret}"));
    let k_date = Zeroizing::new(hmac(initial.as_bytes(), date.as_bytes()));
    let k_region = Zeroizing::new(hmac(&k_date, region.as_bytes()));
    let k_service = Zeroizing::new(hmac(&k_region, service.as_bytes()));
    Zeroizing::new(hmac(&k_service, b"aws4_request"))
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    // HMAC takes a key of any length.
    #[allow(clippy::expect_used)]
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    //! Vectors from the AWS SigV4 test suite (`aws-sig-v4-test-suite`, as
    //! shipped in botocore and the AWS SDKs). Every case uses the access key
    //! `AKIDEXAMPLE`, the secret `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`,
    //! region `us-east-1`, service `service` and the time
    //! `20150830T123600Z`, except the IAM example from the AWS SigV4
    //! documentation (service `iam`).

    use std::time::Duration;

    use web_time::UNIX_EPOCH;

    use super::*;

    const ACCESS_KEY: &str = "AKIDEXAMPLE";
    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    fn suite_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_440_938_160)
    }

    fn signed(mut request: VendorRequest, service: &str) -> VendorRequest {
        let credentials = Credentials::new(ACCESS_KEY, SECRET, None);
        sign(
            &mut request,
            &SigningParams {
                credentials: &credentials,
                region: "us-east-1",
                service,
                time: suite_time(),
            },
        )
        .unwrap();
        request
    }

    fn canonical(request: &VendorRequest) -> String {
        canonical_request(request, &url::Url::parse(&request.url).unwrap()).0
    }

    fn authorization(request: &VendorRequest) -> &str {
        request.header_value("authorization").unwrap()
    }

    #[test]
    fn get_vanilla() {
        let request = signed(
            VendorRequest::new("GET", "https://example.amazonaws.com/"),
            "service",
        );
        assert_eq!(
            canonical(&request.clone().without_authorization()),
            "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            authorization(&request),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    #[test]
    fn post_vanilla() {
        let request = signed(
            VendorRequest::new("POST", "https://example.amazonaws.com/"),
            "service",
        );
        assert_eq!(
            authorization(&request),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"
        );
    }

    #[test]
    fn get_vanilla_query_order_key_case() {
        let request = signed(
            VendorRequest::new(
                "GET",
                "https://example.amazonaws.com/?Param2=value2&Param1=value1",
            ),
            "service",
        );
        assert_eq!(
            authorization(&request),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=host;x-amz-date, \
             Signature=b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"
        );
    }

    #[test]
    fn post_x_www_form_urlencoded() {
        let request = signed(
            VendorRequest::new("POST", "https://example.amazonaws.com/")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(b"Param1=value1".to_vec()),
            "service",
        );
        assert_eq!(
            authorization(&request),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"
        );
    }

    /// The worked example in the AWS SigV4 documentation: IAM `ListUsers`.
    #[test]
    fn the_documented_iam_example() {
        let request = signed(
            VendorRequest::new(
                "GET",
                "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08",
            )
            .header(
                "Content-Type",
                "application/x-www-form-urlencoded; charset=utf-8",
            ),
            "iam",
        );
        let canonical = canonical(&request.clone().without_authorization());
        assert_eq!(
            hex(&Sha256::digest(canonical.as_bytes())),
            "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        );
        assert_eq!(
            authorization(&request),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date, \
             Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn a_session_token_is_sent_and_signed() {
        let credentials = Credentials::new(ACCESS_KEY, SECRET, Some("session-token".to_owned()));
        let mut request = VendorRequest::new("POST", "https://kms.us-east-1.amazonaws.com/");
        sign(
            &mut request,
            &SigningParams {
                credentials: &credentials,
                region: "us-east-1",
                service: "kms",
                time: suite_time(),
            },
        )
        .unwrap();
        assert_eq!(
            request.header_value("x-amz-security-token"),
            Some("session-token")
        );
        assert!(
            authorization(&request).contains("SignedHeaders=host;x-amz-date;x-amz-security-token,")
        );
    }

    #[test]
    fn a_port_is_part_of_the_host() {
        let request = signed(VendorRequest::new("POST", "http://localhost:4566/"), "kms");
        assert_eq!(request.header_value("host"), Some("localhost:4566"));
        let request = signed(
            VendorRequest::new("POST", "https://kms.us-east-1.amazonaws.com:443/"),
            "kms",
        );
        assert_eq!(
            request.header_value("host"),
            Some("kms.us-east-1.amazonaws.com")
        );
    }

    #[test]
    fn an_invalid_url_is_refused() {
        let credentials = Credentials::new(ACCESS_KEY, SECRET, None);
        let params = SigningParams {
            credentials: &credentials,
            region: "us-east-1",
            service: "kms",
            time: suite_time(),
        };
        for url in ["not a url", "data:text/plain,hello"] {
            assert_eq!(
                sign(&mut VendorRequest::new("GET", url), &params),
                Err(SigningError::InvalidUrl)
            );
        }
    }

    #[test]
    fn paths_and_queries_canonicalise() {
        assert_eq!(canonical_uri(""), "/");
        assert_eq!(canonical_uri("/example%20space/"), "/example%20space/");
        assert_eq!(canonical_uri("/a~b/%7e"), "/a~b/~");
        assert_eq!(canonical_query("b=2&a=1&a=0"), "a=0&a=1&b=2");
        assert_eq!(canonical_query("Param=a%20b&x"), "Param=a%20b&x=");
        assert_eq!(canonical_query("k=%zz"), "k=%25zz");
        assert_eq!(canonical_query(""), "");
    }

    trait WithoutAuthorization {
        fn without_authorization(self) -> Self;
    }

    impl WithoutAuthorization for VendorRequest {
        fn without_authorization(mut self) -> Self {
            self.headers.retain(|(name, _)| name != "authorization");
            self
        }
    }
}
