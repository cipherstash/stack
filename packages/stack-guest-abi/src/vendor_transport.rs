//! The guest's [`VendorTransport`]: a key vendor backend's HTTP requests
//! sent through the `transport_send` host import (ADR-0011).
//!
//! The vendor client signs each request inside the guest and the host only
//! carries the bytes, as for ZeroKMS. The conversions between the import's
//! form (a status that is negative for a transport failure, headers in the
//! [`crate::headers`] line format) and [`VendorResponse`] are pure, and are
//! tested on the native target. [`HostVendorTransport`] itself calls the
//! import and so exists on wasm32 only.
//!
//! Only the transport is here. Which vendor the guest builds, and where its
//! credentials come from, is the guest's own wiring.

use stack_kms_vendor::{TransportError, VendorResponse};
use zeroize::Zeroizing;

/// Encode request headers in the import's line format.
///
/// A header name or value with a line break cannot be carried: it would
/// split into two lines (or inject a header). It is refused.
pub fn encode_request_headers(
    headers: &[(String, String)],
) -> Result<Zeroizing<Vec<u8>>, TransportError> {
    let has_break = |text: &str| text.contains(['\n', '\r']);
    if let Some((name, _)) = headers
        .iter()
        .find(|(name, value)| has_break(name) || has_break(value) || name.contains(':'))
    {
        return Err(TransportError(format!(
            "the header {name:?} cannot be sent: a name or value has a line break or a name has a colon"
        )));
    }
    let pairs: Vec<(&str, &str)> = headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    // The headers can hold a credential (a session token): wipe on drop.
    Ok(Zeroizing::new(crate::headers::encode_headers(&pairs)))
}

/// Decode response headers from the import's line format. Malformed lines
/// are skipped, as [`crate::headers::header_value`] does.
pub fn decode_response_headers(buffer: &[u8]) -> Vec<(String, String)> {
    buffer
        .split(|&byte| byte == b'\n')
        .filter_map(|line| {
            let line = std::str::from_utf8(line).ok()?;
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect()
}

/// Turn what the import returned into a [`VendorResponse`].
///
/// A negative status is a transport failure, and the body is then the
/// host's error text. A status above 999 cannot be an HTTP status and is a
/// transport failure too.
pub fn response_from_host(
    status: i32,
    headers: &[u8],
    body: Zeroizing<Vec<u8>>,
) -> Result<VendorResponse, TransportError> {
    if status < 0 {
        return Err(TransportError(format!(
            "the host could not send the request: {}",
            String::from_utf8_lossy(&body)
        )));
    }
    let status = u16::try_from(status)
        .ok()
        .filter(|status| (100..=999).contains(status))
        .ok_or_else(|| TransportError(format!("the host returned the status {status}")))?;
    Ok(VendorResponse {
        status,
        headers: decode_response_headers(headers),
        body,
    })
}

#[cfg(target_arch = "wasm32")]
pub use host::HostVendorTransport;

#[cfg(target_arch = "wasm32")]
mod host {
    use std::time::Duration;

    use stack_kms_vendor::{TransportError, VendorRequest, VendorResponse, VendorTransport};

    use super::{encode_request_headers, response_from_host};
    use crate::transport;

    /// A [`VendorTransport`] whose HTTP client is the host's, through the
    /// `transport_send` import.
    ///
    /// The import is synchronous from the guest's side, so `send` resolves
    /// at once. `sleep` blocks the instance with `std::thread::sleep`, which
    /// wasm32-wasip1 implements with a `poll_oneoff` clock subscription.
    /// That is correct here: the guest runs one call at a time and has
    /// nothing else to do while it backs off.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct HostVendorTransport;

    impl VendorTransport for HostVendorTransport {
        async fn send(&self, request: VendorRequest) -> Result<VendorResponse, TransportError> {
            let headers = encode_request_headers(&request.headers)?;
            let response = transport::send(&request.method, &request.url, &headers, &request.body)
                .map_err(|error| TransportError(error.to_string()))?;
            let transport::Response {
                status,
                headers,
                body,
                ..
            } = response;
            response_from_host(status, &headers, body)
        }

        async fn sleep(&self, duration: Duration) {
            std::thread::sleep(duration);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_headers_encode_in_the_line_format() {
        let headers = vec![
            ("host".to_owned(), "kms.us-east-1.amazonaws.com".to_owned()),
            ("x-amz-target".to_owned(), "TrentService.Decrypt".to_owned()),
        ];
        assert_eq!(
            encode_request_headers(&headers).unwrap().as_slice(),
            b"host: kms.us-east-1.amazonaws.com\nx-amz-target: TrentService.Decrypt"
        );
    }

    #[test]
    fn a_header_with_a_line_break_or_a_colon_in_its_name_is_refused() {
        for (name, value) in [
            ("x-a", "1\nx-b: 2"),
            ("x-a", "1\r"),
            ("x-a\n", "1"),
            ("x:a", "1"),
        ] {
            let headers = vec![(name.to_owned(), value.to_owned())];
            assert!(encode_request_headers(&headers).is_err(), "{name:?}");
        }
        let headers = vec![("x-a".to_owned(), "a:b".to_owned())];
        assert!(encode_request_headers(&headers).is_ok());
    }

    #[test]
    fn response_headers_decode_and_skip_malformed_lines() {
        assert_eq!(
            decode_response_headers(b"Content-Type: application/json\nbad line\nx-a:  b:c "),
            vec![
                ("Content-Type".to_owned(), "application/json".to_owned()),
                ("x-a".to_owned(), "b:c".to_owned()),
            ]
        );
        assert!(decode_response_headers(b"").is_empty());
        assert!(decode_response_headers(&[0xff, b':', b'a']).is_empty());
    }

    #[test]
    fn a_host_status_becomes_a_response_or_a_transport_error() {
        let response = response_from_host(
            400,
            b"x-amzn-errortype: ThrottlingException",
            Zeroizing::new(b"{}".to_vec()),
        )
        .unwrap();
        assert_eq!(response.status, 400);
        assert_eq!(
            response.header_value("X-Amzn-ErrorType"),
            Some("ThrottlingException")
        );
        assert_eq!(response.body.as_slice(), b"{}");

        let error =
            response_from_host(-1, b"", Zeroizing::new(b"dial tcp: refused".to_vec())).unwrap_err();
        assert!(error.0.contains("dial tcp: refused"));
        assert!(response_from_host(99, b"", Zeroizing::new(vec![])).is_err());
        assert!(response_from_host(1000, b"", Zeroizing::new(vec![])).is_err());
        assert!(response_from_host(100, b"", Zeroizing::new(vec![])).is_ok());
        assert!(response_from_host(999, b"", Zeroizing::new(vec![])).is_ok());
    }
}
