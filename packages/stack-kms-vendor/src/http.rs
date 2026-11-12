//! The native [`VendorTransport`]: HTTPS through reqwest.
//!
//! It uses the same HTTP client and TLS configuration as stack-kms's
//! ZeroKMS transport: reqwest with rustls, and the platform verifier with
//! the compromised-CA blocklist (`stack_auth::tls::client_config`). Native
//! only. The WASI guest sends through its `transport_send` host import.

use std::time::Duration;

use zeroize::Zeroizing;

use crate::transport::{TransportError, VendorRequest, VendorResponse, VendorTransport};

/// The default time limit for one request, connection included.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The native [`VendorTransport`]: HTTPS (or plain HTTP, for a local
/// emulator or an instance metadata service) through reqwest.
///
/// Clone it freely: clones share one connection pool.
#[derive(Clone, Debug)]
pub struct HttpVendorTransport {
    client: reqwest::Client,
}

/// Options for [`HttpVendorTransport`].
#[derive(Clone, Debug)]
pub struct HttpVendorTransportOptions {
    /// The time limit for one request, connection included. Default
    /// [`DEFAULT_REQUEST_TIMEOUT`].
    pub timeout: Duration,
    /// The time limit to open a connection. `None` keeps the operating
    /// system's limit. Set a short one for an instance metadata service,
    /// which does not answer off the cloud.
    pub connect_timeout: Option<Duration>,
}

impl Default for HttpVendorTransportOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: None,
        }
    }
}

impl HttpVendorTransport {
    /// A transport with the default options.
    pub fn new() -> Result<Self, TransportError> {
        Self::with_options(HttpVendorTransportOptions::default())
    }

    /// A transport with `options`.
    pub fn with_options(options: HttpVendorTransportOptions) -> Result<Self, TransportError> {
        let tls = stack_auth::tls::client_config(false)
            .map_err(|error| TransportError(format!("TLS configuration failed: {error}")))?;
        let mut builder = reqwest::ClientBuilder::new()
            .user_agent(concat!("stack-kms-vendor/", env!("CARGO_PKG_VERSION")))
            .tls_backend_preconfigured(tls)
            .timeout(options.timeout);
        if let Some(connect_timeout) = options.connect_timeout {
            builder = builder.connect_timeout(connect_timeout);
        }
        let client = builder
            .build()
            .map_err(|error| TransportError(format!("HTTP client failed to build: {error}")))?;
        Ok(Self { client })
    }
}

impl VendorTransport for HttpVendorTransport {
    async fn send(&self, request: VendorRequest) -> Result<VendorResponse, TransportError> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|_| TransportError(format!("invalid HTTP method {:?}", request.method)))?;
        let mut builder = self.client.request(method, request.url.as_str());
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        // reqwest takes the body by value: the copy it holds is not wiped.
        // The `Zeroizing` copy in `request` is wiped when it drops.
        let response = builder
            .body(request.body.to_vec())
            .send()
            .await
            .map_err(|error| TransportError(transport_failure(&error)))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect();
        let body = response
            .bytes()
            .await
            .map_err(|error| TransportError(transport_failure(&error)))?;
        Ok(VendorResponse {
            status,
            headers,
            body: Zeroizing::new(body.to_vec()),
        })
    }

    async fn sleep(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}

/// The text of a reqwest failure, without the URL: a URL can hold a
/// credential in its query.
fn transport_failure(error: &reqwest::Error) -> String {
    let kind = if error.is_timeout() {
        "timed out"
    } else if error.is_connect() {
        "could not connect"
    } else if error.is_body() || error.is_decode() {
        "could not read the response"
    } else {
        "failed"
    };
    let mut text = format!("the request {kind}");
    // reqwest's own text names the URL; only its causes are kept.
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// One HTTP/1.1 exchange on a local socket: read the request, answer
    /// with `response`, return what was read.
    async fn serve_once(listener: TcpListener, response: &'static [u8]) -> String {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let n = socket.read(&mut buffer).await.unwrap();
            received.extend_from_slice(&buffer[..n]);
            let text = String::from_utf8_lossy(&received);
            if let Some(end) = text.find("\r\n\r\n") {
                let length = text[..end]
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                if received.len() >= end + 4 + length {
                    break;
                }
            }
        }
        socket.write_all(response).await.unwrap();
        socket.shutdown().await.unwrap();
        String::from_utf8(received).unwrap()
    }

    #[tokio::test]
    async fn sends_the_request_and_returns_any_status() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_once(
            listener,
            b"HTTP/1.1 400 Bad Request\r\ncontent-type: application/x-amz-json-1.1\r\ncontent-length: 2\r\n\r\n{}",
        ));
        let transport = HttpVendorTransport::new().unwrap();
        let response = transport
            .send(
                VendorRequest::new("POST", format!("http://{address}/"))
                    .header("x-amz-target", "TrentService.Decrypt")
                    .body(b"{\"a\":1}".to_vec()),
            )
            .await
            .unwrap();
        assert_eq!(response.status, 400);
        assert_eq!(
            response.header_value("content-type"),
            Some("application/x-amz-json-1.1")
        );
        assert_eq!(response.body.as_slice(), b"{}");
        let received = server.await.unwrap();
        assert!(received.starts_with("POST / HTTP/1.1\r\n"));
        assert!(received.contains("x-amz-target: TrentService.Decrypt\r\n"));
        assert!(received.ends_with("{\"a\":1}"));
    }

    #[tokio::test]
    async fn a_refused_connection_is_a_transport_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let transport = HttpVendorTransport::with_options(HttpVendorTransportOptions {
            connect_timeout: Some(Duration::from_secs(1)),
            ..HttpVendorTransportOptions::default()
        })
        .unwrap();
        let error = transport
            .send(VendorRequest::new(
                "GET",
                format!("http://{address}/?secret=1"),
            ))
            .await
            .unwrap_err();
        assert!(error.0.contains("could not connect"), "{}", error.0);
        assert!(!error.0.contains("secret"), "{}", error.0);
    }

    #[tokio::test]
    async fn an_invalid_method_is_refused() {
        let transport = HttpVendorTransport::new().unwrap();
        let error = transport
            .send(VendorRequest::new("BAD METHOD", "http://127.0.0.1:1/"))
            .await
            .unwrap_err();
        assert!(error.0.contains("invalid HTTP method"));
    }

    #[tokio::test]
    async fn sleep_waits() {
        let transport = HttpVendorTransport::new().unwrap();
        let start = std::time::Instant::now();
        transport.sleep(Duration::from_millis(20)).await;
        assert!(start.elapsed() >= Duration::from_millis(20));
    }
}
