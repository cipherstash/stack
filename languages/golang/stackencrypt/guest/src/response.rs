//! The host transport's one piece of response logic that is *not* shared with
//! the reference `HttpConnection`: turning the import's `i32` return into
//! either a transport failure or an HTTP status.
//!
//! Everything past that — the 2xx content-type check, JSON deserialization,
//! and the 404/401/403/409 → [`ViturRequestErrorKind`] table — is
//! [`stack_kms::classify_response`], which lives outside the `http` feature
//! gate precisely so this guest and `HttpConnection` cannot drift apart. Kept
//! free of any wasm ABI concerns so it compiles — and its unit tests run — on
//! the native host target.
//!
//! [`ViturRequestErrorKind`]: zerokms_protocol::ViturRequestErrorKind

use std::collections::HashMap;
use std::fmt;

use serde::de::DeserializeOwned;
use stack_kms::classify_response;
use zerokms_protocol::ViturRequestError;

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

/// Map a host transport result onto the ZeroKMS protocol contract.
///
/// `status` is the HTTP status code, or negative for a transport-level
/// failure (in which case `body` carries the host's error text).
/// `content_type` is the response Content-Type header, if any.
///
/// A status outside the `u16` range is a host that is not honouring the
/// import contract; it is treated as a transport failure rather than being
/// truncated into some unrelated code.
pub fn map_response<T: DeserializeOwned>(
    status: i32,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<T, ViturRequestError> {
    let Ok(status) = u16::try_from(status) else {
        return Err(ViturRequestError::send(
            "Host transport reported a failure",
            TransportFailure(String::from_utf8_lossy(body).into_owned()),
        ));
    };
    // The guest does not carry the response headers into the error payloads:
    // it has already read the only one it needs (content-type), and the rest
    // would be an extra copy of attacker-influenced bytes for a Display
    // string nothing reads.
    classify_response(status, content_type, Some(body), HashMap::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerokms_protocol::{Keyset, ViturRequestErrorKind};

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
        // Same tolerance as the reference `HttpConnection` — literally the
        // same predicate now.
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
        // A status the import contract cannot mean is a transport failure
        // too, never a truncated code.
        assert!(matches!(
            kind_of(map_response(70_000, None, b"nonsense")),
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
