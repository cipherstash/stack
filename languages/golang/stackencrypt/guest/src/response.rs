//! Pure response-mapping logic for the host transport, mirroring the
//! reference `HttpConnection` in `stack-kms/src/connection/http.rs`:
//! status-code → [`ViturRequestErrorKind`] mapping and the content-type
//! validation performed before deserializing a success body. Kept free of
//! any wasm ABI concerns so it compiles — and its unit tests run — on the
//! native host target. (Ported from the #2099 spike's `response.rs`,
//! re-based on stack-kms's connection rather than `cipherstash-client`'s.)

use std::fmt;

use serde::de::DeserializeOwned;
use zerokms_protocol::{ViturRequestError, ViturRequestErrorKind};

/// The host reported it could not perform the HTTP call at all (negative
/// status). The body carries the host's error text.
#[derive(Debug)]
pub struct TransportFailure(pub String);

impl fmt::Display for TransportFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "host transport failed: {}", self.0)
    }
}

impl std::error::Error for TransportFailure {}

/// A non-2xx ZeroKMS response.
#[derive(Debug)]
pub struct FailureResponse {
    pub status: i32,
    pub body: String,
}

impl fmt::Display for FailureResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Status: {}, Body: {}", self.status, self.body)
    }
}

impl std::error::Error for FailureResponse {}

/// A 2xx response whose Content-Type is not JSON — typically a proxy or load
/// balancer answering with an HTML error page.
#[derive(Debug)]
pub struct UnexpectedContentType {
    pub received: Option<String>,
    pub expected: &'static str,
    pub body: String,
}

impl fmt::Display for UnexpectedContentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Received '{:?}', expected '{}', Body: {}",
            self.received, self.expected, self.body
        )
    }
}

impl std::error::Error for UnexpectedContentType {}

/// `true` if a `content-type` header value denotes JSON, ignoring any
/// parameters (`application/json; charset=utf-8`) and ASCII case — the same
/// tolerance as the reference `HttpConnection` (proxies and API gateways
/// commonly normalise the header that way).
fn is_json_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|media_type| media_type.eq_ignore_ascii_case("application/json"))
}

/// Map a host transport result onto the ZeroKMS protocol contract.
///
/// `status` is the HTTP status code, or negative for a transport-level
/// failure (in which case `body` carries the host's error text).
/// `content_type` is the response Content-Type header, if any.
///
/// The error bodies captured into [`FailureResponse`] /
/// [`UnexpectedContentType`] are non-2xx (or non-JSON) server error text,
/// not key material — the only payload that carries wrapped keys is a 2xx
/// JSON body, which is consumed by deserialization and wiped by the caller.
pub fn map_response<T: DeserializeOwned>(
    status: i32,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<T, ViturRequestError> {
    match status {
        s if s < 0 => Err(ViturRequestError::send(
            "Host transport reported a failure",
            TransportFailure(String::from_utf8_lossy(body).into_owned()),
        )),
        200..=299 => {
            let expected = "application/json";
            if !content_type.is_some_and(is_json_content_type) {
                return Err(ViturRequestError::parse(
                    "Invalid content type header",
                    UnexpectedContentType {
                        received: content_type.map(|ct| ct.to_owned()),
                        expected,
                        body: String::from_utf8_lossy(body).into_owned(),
                    },
                ));
            }
            serde_json::from_slice(body)
                .map_err(|e| ViturRequestError::parse("Failed to deserialize response body", e))
        }
        status => {
            let failure = FailureResponse {
                status,
                body: String::from_utf8_lossy(body).into_owned(),
            };
            Err(match status {
                404 => ViturRequestError::new(
                    ViturRequestErrorKind::NotFound,
                    "Resource not found",
                    failure,
                ),
                401 => ViturRequestError::new(
                    ViturRequestErrorKind::Unauthorized,
                    "Request unauthorized",
                    failure,
                ),
                403 => ViturRequestError::new(
                    ViturRequestErrorKind::Forbidden,
                    "Request forbidden",
                    failure,
                ),
                409 => ViturRequestError::new(
                    ViturRequestErrorKind::Conflict,
                    "Resource conflict",
                    failure,
                ),
                _ => ViturRequestError::other("Server returned failure response", failure),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerokms_protocol::Keyset;

    fn kind_of(result: Result<Vec<Keyset>, ViturRequestError>) -> ViturRequestErrorKind {
        result.expect_err("expected an error").kind
    }

    const KEYSETS_JSON: &[u8] = br#"[
        {"id":"6a70bd18-99ac-4650-b104-37eec3a15b09","name":"alpha","description":"","is_disabled":false,"is_default":true}
    ]"#;

    #[test]
    fn success_with_json_content_type_deserializes() {
        let keysets: Vec<Keyset> =
            map_response(200, Some("application/json"), KEYSETS_JSON).expect("deserializes");
        assert_eq!(keysets.len(), 1);
        assert_eq!(keysets[0].name, "alpha");
    }

    #[test]
    fn json_content_type_tolerates_parameters_and_case() {
        // Same tolerance as the reference `HttpConnection`.
        let keysets: Vec<Keyset> =
            map_response(200, Some("Application/JSON; charset=utf-8"), KEYSETS_JSON)
                .expect("deserializes");
        assert_eq!(keysets.len(), 1);
    }

    #[test]
    fn success_without_json_content_type_is_parse_error() {
        assert!(matches!(
            kind_of(map_response(200, None, KEYSETS_JSON)),
            ViturRequestErrorKind::ParseResponse
        ));
        // A proxy or load balancer answering 200 with an HTML error page.
        assert!(matches!(
            kind_of(map_response(
                200,
                Some("text/html"),
                b"<html>gateway error</html>"
            )),
            ViturRequestErrorKind::ParseResponse
        ));
    }

    #[test]
    fn success_with_invalid_json_is_parse_error() {
        assert!(matches!(
            kind_of(map_response(200, Some("application/json"), b"not json")),
            ViturRequestErrorKind::ParseResponse
        ));
    }

    #[test]
    fn transport_failure_is_send_error() {
        assert!(matches!(
            kind_of(map_response(-1, None, b"connection refused")),
            ViturRequestErrorKind::SendRequest
        ));
    }

    #[test]
    fn error_statuses_map_to_their_kinds() {
        assert!(matches!(
            kind_of(map_response(401, None, b"nope")),
            ViturRequestErrorKind::Unauthorized
        ));
        assert!(matches!(
            kind_of(map_response(403, None, b"Not permitted")),
            ViturRequestErrorKind::Forbidden
        ));
        assert!(matches!(
            kind_of(map_response(404, None, b"missing")),
            ViturRequestErrorKind::NotFound
        ));
        assert!(matches!(
            kind_of(map_response(409, None, b"exists")),
            ViturRequestErrorKind::Conflict
        ));
        assert!(matches!(
            kind_of(map_response(500, None, b"boom")),
            ViturRequestErrorKind::Other
        ));
    }
}
