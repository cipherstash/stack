//! The HTTP seam a vendor client sends through.
//!
//! The official vendor SDKs need tokio and hyper and do not build for
//! wasm32-wasip1 (ADR-0011). Each vendor client is therefore a small REST
//! client that signs its own requests and sends them through
//! [`VendorTransport`]. Native Rust implements it over an HTTP client; the
//! WASI guest implements it over its `transport_send` host import. The
//! vendor code is the same on both.

use std::future::Future;
use std::time::Duration;

use stack_kms::{BackendErrorKind, MaybeSend};

/// One signed HTTP request to a vendor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VendorRequest {
    /// The HTTP method, upper case (`POST`).
    pub method: String,
    /// The full URL.
    pub url: String,
    /// The headers, signature included, in the order they are sent.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// A vendor's HTTP response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VendorResponse {
    /// The HTTP status.
    pub status: u16,
    /// The headers.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// The request did not get a response: the transport failed (DNS, TLS,
/// connection, timeout).
#[derive(Debug, thiserror::Error)]
#[error("the vendor request got no response: {0}")]
pub struct TransportError(pub String);

/// The HTTP seam a vendor client sends through, of the same shape as
/// [`ZeroKMSConnection`](stack_kms::ZeroKMSConnection).
///
/// The returned futures are bounded by [`MaybeSend`]: `Send` on native
/// targets, unbounded on wasm32. A transport gives the request no meaning:
/// it sends the bytes and returns the response. The vendor client signs
/// the request before, and classifies the response after
/// ([`classify_status`]).
pub trait VendorTransport {
    /// Send `request` and return the response, whatever its status.
    fn send(
        &self,
        request: VendorRequest,
    ) -> impl Future<Output = Result<VendorResponse, TransportError>> + MaybeSend;

    /// Wait for `duration`. A key vendor backend uses it to back off after
    /// a rate limit ([`KeyVendorBackend::sleep`](crate::KeyVendorBackend::sleep)).
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + MaybeSend;
}

/// The failure kind of an HTTP status that is not a success, in terms that
/// hold for every vendor. `None` for a 2xx status.
///
/// A vendor client may refine it from the response body (for example AWS
/// returns 400 for both a damaged ciphertext and a throttle).
pub fn classify_status(status: u16) -> Option<BackendErrorKind> {
    match status {
        200..=299 => None,
        401 | 403 => Some(BackendErrorKind::AccessDenied),
        404 => Some(BackendErrorKind::NotFound),
        429 => Some(BackendErrorKind::Throttled),
        500..=599 => Some(BackendErrorKind::Unavailable),
        _ => Some(BackendErrorKind::InvalidCiphertext),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// A transport that answers from a script, as the vendor crates' tests
    /// will over recorded fixtures.
    struct Scripted {
        responses: Mutex<Vec<VendorResponse>>,
        sent: Mutex<Vec<VendorRequest>>,
    }

    impl VendorTransport for Scripted {
        async fn send(&self, request: VendorRequest) -> Result<VendorResponse, TransportError> {
            self.sent.lock().unwrap().push(request);
            self.responses
                .lock()
                .unwrap()
                .pop()
                .ok_or_else(|| TransportError("no response".into()))
        }

        async fn sleep(&self, _duration: Duration) {}
    }

    #[tokio::test]
    async fn a_transport_sends_bytes_and_returns_the_response() {
        let transport = Scripted {
            responses: Mutex::new(vec![VendorResponse {
                status: 200,
                headers: vec![],
                body: b"{}".to_vec(),
            }]),
            sent: Mutex::new(vec![]),
        };
        let request = VendorRequest {
            method: "POST".into(),
            url: "https://kms.example/".into(),
            headers: vec![("x-amz-target".into(), "TrentService.Decrypt".into())],
            body: b"{}".to_vec(),
        };
        let response = transport.send(request.clone()).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(
            *transport.sent.lock().unwrap(),
            std::slice::from_ref(&request)
        );
        assert!(transport.send(request).await.is_err());
    }

    #[test]
    fn statuses_classify_the_same_for_every_vendor() {
        assert_eq!(classify_status(200), None);
        assert_eq!(classify_status(204), None);
        assert_eq!(classify_status(401), Some(BackendErrorKind::AccessDenied));
        assert_eq!(classify_status(403), Some(BackendErrorKind::AccessDenied));
        assert_eq!(classify_status(404), Some(BackendErrorKind::NotFound));
        assert_eq!(classify_status(429), Some(BackendErrorKind::Throttled));
        assert_eq!(classify_status(500), Some(BackendErrorKind::Unavailable));
        assert_eq!(classify_status(503), Some(BackendErrorKind::Unavailable));
        assert_eq!(
            classify_status(400),
            Some(BackendErrorKind::InvalidCiphertext)
        );
    }
}
