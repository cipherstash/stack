//! Response classification, shared by every [`ZeroKMSConnection`] regardless
//! of transport.
//!
//! Whether the bytes arrived over reqwest ([`HttpConnection`]) or over a wasm
//! host import (the WASI guest's connection), a ZeroKMS response is classified
//! the same way: 2xx must be JSON and deserialize, and 404/401/403/409 carry
//! specific [`ViturRequestErrorKind`]s so callers can tell a bad token from a
//! missing keyset without parsing strings. That table lives here, once, free
//! of any feature gate — a guest built without the `http` feature still gets
//! the same verdicts as the default transport.
//!
//! [`ZeroKMSConnection`]: crate::ZeroKMSConnection
//! [`HttpConnection`]: crate::HttpConnection

use std::collections::HashMap;

use serde::de::DeserializeOwned;
use serde_json::from_slice;
use thiserror::Error;
use zerokms_protocol::{ViturRequestError, ViturRequestErrorKind};

/// No ZeroKMS base URL is known: none was configured, and none was resolved
/// from the access token's `services` claim.
///
/// Classified as a request-*preparation* error, never an authentication
/// failure — a caller that read it as a 401 would refresh its token and retry
/// forever against what is really a configuration problem.
#[derive(Debug, Error)]
#[error("ZeroKMS base URL was not resolved from the token's `services` claim")]
pub struct BaseUrlUnresolved;

/// A 2xx response whose `Content-Type` is not JSON — typically a proxy or load
/// balancer answering with an HTML error page.
///
/// `Display` carries only what was received and expected: the body and headers
/// are attacker-influenced and unbounded, and this type's `Display` reaches
/// logs. They stay available through `Debug` for structured inspection.
#[derive(Debug, Error)]
#[error("Received '{received:?}', expected '{expected}'")]
#[non_exhaustive]
pub struct UnexpectedContentType {
    pub received: Option<String>,
    pub expected: &'static str,
    pub body: Option<String>,
    pub headers: HashMap<String, String>,
}

/// A non-2xx ZeroKMS response.
///
/// `Display` is the status alone, for the same reason as
/// [`UnexpectedContentType`]: body and headers are unbounded server text that
/// must not be pulled into a log line. `Debug` still carries them.
#[derive(Debug, Error)]
#[error("Status: {status}")]
#[non_exhaustive]
pub struct FailureResponse {
    pub status: u16,
    pub body: Option<String>,
    pub headers: HashMap<String, String>,
}

/// `true` if a `content-type` header value denotes JSON, ignoring any
/// parameters (`application/json; charset=utf-8`) and ASCII case — proxies and
/// API gateways commonly normalise the header that way.
pub fn is_json_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|media_type| media_type.eq_ignore_ascii_case("application/json"))
}

/// Classify one ZeroKMS response.
///
/// `status` is the HTTP status code, `content_type` the response
/// `Content-Type` if the transport could read one, `body` the response body
/// (`None` when the transport read it and failed), and `headers` whatever the
/// transport can cheaply supply for the error payloads — an empty map is fine
/// for transports that do not surface them.
///
/// The error bodies captured into [`FailureResponse`] /
/// [`UnexpectedContentType`] are non-2xx (or non-JSON) server error text, not
/// key material: the only payload that carries wrapped keys is a 2xx JSON
/// body, which is consumed by deserialization here and wiped by the caller.
pub fn classify_response<T: DeserializeOwned>(
    status: u16,
    content_type: Option<&str>,
    body: Option<&[u8]>,
    headers: HashMap<String, String>,
) -> Result<T, ViturRequestError> {
    let text = || body.map(|b| String::from_utf8_lossy(b).into_owned());

    if (200..=299).contains(&status) {
        let expected = "application/json";
        if !content_type.is_some_and(is_json_content_type) {
            return Err(ViturRequestError::parse(
                "Invalid content type header",
                UnexpectedContentType {
                    received: content_type.map(|ct| ct.to_owned()),
                    expected,
                    body: text(),
                    headers,
                },
            ));
        }
        let body = body.ok_or_else(|| {
            ViturRequestError::parse(
                "Failed to deserialize response body",
                FailureResponse {
                    status,
                    body: None,
                    headers: headers.clone(),
                },
            )
        })?;
        return from_slice(body)
            .map_err(|e| ViturRequestError::parse("Failed to deserialize response body", e));
    }

    let failure = FailureResponse {
        status,
        body: text(),
        headers,
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

#[cfg(test)]
mod tests {
    use super::*;
    use zerokms_protocol::Keyset;

    const KEYSETS_JSON: &[u8] = br#"[
        {"id":"6a70bd18-99ac-4650-b104-37eec3a15b09","name":"alpha","description":"","is_disabled":false,"is_default":true}
    ]"#;

    fn classify(
        status: u16,
        content_type: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Vec<Keyset>, ViturRequestError> {
        classify_response(status, content_type, body, HashMap::new())
    }

    fn kind_of(result: Result<Vec<Keyset>, ViturRequestError>) -> ViturRequestErrorKind {
        result.expect_err("expected an error").kind
    }

    #[test]
    fn accepts_json_with_or_without_parameters_and_ignoring_case() {
        for value in [
            "application/json",
            "application/json; charset=utf-8",
            "application/json;charset=UTF-8",
            "  Application/JSON ; charset=utf-8",
        ] {
            assert!(is_json_content_type(value), "{value:?} should be accepted");
        }
    }

    #[test]
    fn rejects_other_media_types() {
        for value in [
            "text/html",
            "application/jsonx",
            "text/json",
            "",
            "; charset=utf-8",
        ] {
            assert!(!is_json_content_type(value), "{value:?} should be rejected");
        }
    }

    #[test]
    fn success_with_json_content_type_deserializes() {
        let keysets =
            classify(200, Some("application/json"), Some(KEYSETS_JSON)).expect("deserializes");
        assert_eq!(keysets.len(), 1);
        assert_eq!(keysets[0].name, "alpha");

        let keysets = classify(
            200,
            Some("Application/JSON; charset=utf-8"),
            Some(KEYSETS_JSON),
        )
        .expect("deserializes");
        assert_eq!(keysets.len(), 1);
    }

    #[test]
    fn success_without_json_content_type_is_a_parse_error() {
        assert!(matches!(
            kind_of(classify(200, None, Some(KEYSETS_JSON))),
            ViturRequestErrorKind::ParseResponse
        ));
        // A proxy or load balancer answering 200 with an HTML error page.
        assert!(matches!(
            kind_of(classify(
                200,
                Some("text/html"),
                Some(b"<html>gateway error</html>")
            )),
            ViturRequestErrorKind::ParseResponse
        ));
        // A 2xx whose body could not be read at all.
        assert!(matches!(
            kind_of(classify(200, Some("application/json"), None)),
            ViturRequestErrorKind::ParseResponse
        ));
        assert!(matches!(
            kind_of(classify(200, Some("application/json"), Some(b"not json"))),
            ViturRequestErrorKind::ParseResponse
        ));
    }

    #[test]
    fn error_statuses_map_to_their_kinds() {
        for (status, expected) in [
            (401, ViturRequestErrorKind::Unauthorized),
            (403, ViturRequestErrorKind::Forbidden),
            (404, ViturRequestErrorKind::NotFound),
            (409, ViturRequestErrorKind::Conflict),
            (500, ViturRequestErrorKind::Other),
        ] {
            assert_eq!(
                std::mem::discriminant(&kind_of(classify(status, None, Some(b"nope")))),
                std::mem::discriminant(&expected),
                "status {status}"
            );
        }
    }
}
