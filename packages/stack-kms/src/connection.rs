use crate::user_agent::get_user_agent;
use reqwest::{header::HeaderMap, Response, StatusCode};
use serde_json::{from_reader, to_vec};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
use std::{collections::HashMap, future::Future, sync::OnceLock};
use thiserror::Error;
use url::Url;
use zerokms_protocol::{ViturRequest, ViturRequestError, ViturRequestErrorKind};

#[cfg(not(target_arch = "wasm32"))]
const REQUEST_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Error)]
#[error("Failed to initialize HTTP connection: {0}")]
pub struct ConnectionInitError(#[from] reqwest::Error);

#[derive(Debug, Error)]
#[error("ZeroKMS base URL was not resolved from the token's `services` claim")]
struct BaseUrlUnresolved;

pub struct HttpConnectionOpts {
    base_url: Option<Url>,
    request_timeout: Option<u64>,
    connect_timeout: Option<u64>,
    pool_idle_timeout: Option<u64>,
}

impl HttpConnectionOpts {
    pub fn new(base_url: Option<Url>) -> Self {
        Self {
            base_url,
            request_timeout: None,
            connect_timeout: None,
            pool_idle_timeout: None,
        }
    }

    /// Set the **total request timeout** in seconds — covers connect + TLS
    /// handshake + body send + body receive together. If not set, defaults
    /// to 10 seconds.
    ///
    /// Set this larger when calling endpoints whose server-side processing
    /// time scales with payload size (e.g. `generate-data-key` with large
    /// `keys.len()`), or when running over high-latency / variable-quality
    /// networks. See [`with_connect_timeout`](Self::with_connect_timeout)
    /// to bound the connect phase separately.
    ///
    /// Ignored on wasm32 — reqwest's fetch-backed `ClientBuilder` doesn't
    /// expose `.timeout()` and the host runtime (e.g. Supabase Edge, Cloudflare
    /// Workers) owns request lifetime there.
    pub fn with_request_timeout(mut self, timeout_secs: u64) -> Self {
        self.request_timeout = Some(timeout_secs);
        self
    }

    /// Set the **connect timeout** in seconds — bound on TCP connect + TLS
    /// handshake only, separate from the total request timeout. If not set,
    /// reqwest falls back to the OS-level connect timeout (~75 s on most
    /// platforms), so the only ceiling on a stuck connect is whatever the
    /// total request timeout is.
    ///
    /// Useful for fast-fail behaviour on broken networks: a value like 5
    /// seconds gives the connect phase plenty of room without forcing the
    /// total request timeout to absorb both connect *and* response time.
    ///
    /// Ignored on wasm32 for the same reason as
    /// [`with_request_timeout`](Self::with_request_timeout): the host
    /// runtime owns connection lifetime under fetch.
    pub fn with_connect_timeout(mut self, timeout_secs: u64) -> Self {
        self.connect_timeout = Some(timeout_secs);
        self
    }

    /// Set the **pool idle timeout** in seconds — how long the underlying
    /// reqwest client keeps an idle keep-alive connection in its pool
    /// before closing it. If not set, reqwest's default of 90 s applies.
    ///
    /// Long-lived processes (bulk ingest, daemons) benefit from raising
    /// this so warm TLS connections survive idle gaps between batches.
    ///
    /// Ignored on wasm32 — connection pooling is owned by the host
    /// runtime under fetch.
    pub fn with_pool_idle_timeout(mut self, timeout_secs: u64) -> Self {
        self.pool_idle_timeout = Some(timeout_secs);
        self
    }
}

pub trait ZeroKMSConnectionInit {
    type ConnectionOpts;
    type Error: std::error::Error + Send + Sync + 'static;

    fn init(opts: Self::ConnectionOpts) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

/// On native targets the returned future is `Send` so callers can drive it on
/// a multi-threaded runtime. On wasm32 the bound is dropped — reqwest's
/// fetch-backed response futures aren't `Send`, and edge runtimes are
/// single-threaded anyway.
#[cfg(not(target_arch = "wasm32"))]
pub trait ZeroKMSConnection: ZeroKMSConnectionInit {
    fn send<Request: ViturRequest>(
        &self,
        request: Request,
        access_token: &str,
    ) -> impl Future<Output = Result<Request::Response, ViturRequestError>> + Send;
}

#[cfg(target_arch = "wasm32")]
pub trait ZeroKMSConnection: ZeroKMSConnectionInit {
    fn send<Request: ViturRequest>(
        &self,
        request: Request,
        access_token: &str,
    ) -> impl Future<Output = Result<Request::Response, ViturRequestError>>;
}

pub struct HttpConnection {
    base_url: OnceLock<Url>,
    client: reqwest::Client,
}

#[derive(Debug, Error)]
#[error("Received '{received:?}', expected '{expected}', Body: {body:?}, Headers: {headers:?}")]
struct UnexpectedError {
    received: Option<String>,
    expected: &'static str,
    body: Option<String>,
    headers: HashMap<String, String>,
}

#[derive(Debug, Error)]
#[error("Status: {status}, Body: {body:?}, Headers: {headers:?}")]
struct FailureResponse {
    status: StatusCode,
    body: Option<String>,
    headers: HashMap<String, String>,
}

impl FailureResponse {
    async fn from_response(response: Response) -> Self {
        let status = response.status();
        let headers = header_map_to_hash(response.headers());
        let body = response.text().await.ok();

        Self {
            status,
            body,
            headers,
        }
    }

    fn into_vitur_error(
        self,
        error_kind: ViturRequestErrorKind,
        message: &'static str,
    ) -> ViturRequestError {
        ViturRequestError::new(error_kind, message, self)
    }
}

fn header_map_to_hash(map: &HeaderMap) -> HashMap<String, String> {
    map.iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .map(|x| x.to_string())
                .ok()
                .map(|v| (k.to_string(), v))
        })
        .collect()
}

impl HttpConnection {
    /// Set the base URL if it has not already been set.
    ///
    /// This is a no-op if the URL was already provided at init time or by a
    /// previous call to this method.
    pub fn ensure_base_url(&self, url: Url) {
        // OnceLock::set returns Err if already set — that's fine, we keep the first value.
        let _ = self.base_url.set(url);
    }

    /// Returns `true` if the base URL has been resolved (either at init time
    /// or via [`ensure_base_url`](Self::ensure_base_url)).
    pub fn has_base_url(&self) -> bool {
        self.base_url.get().is_some()
    }
}

impl ZeroKMSConnectionInit for HttpConnection {
    type ConnectionOpts = HttpConnectionOpts;
    type Error = ConnectionInitError;

    fn init(opts: Self::ConnectionOpts) -> Result<Self, Self::Error> {
        let builder = reqwest::ClientBuilder::new().user_agent(get_user_agent());
        // wasm32 reqwest uses `fetch` and doesn't expose `.timeout()`,
        // `.connect_timeout()` or `.pool_idle_timeout()` — the host runtime
        // owns request lifetime and connection pooling. The corresponding
        // `with_*` builder methods are documented as no-ops on wasm32.
        #[cfg(not(target_arch = "wasm32"))]
        let builder = {
            let mut b = builder.timeout(Duration::from_secs(
                opts.request_timeout.unwrap_or(REQUEST_TIMEOUT_SECS),
            ));
            if let Some(connect_timeout) = opts.connect_timeout {
                b = b.connect_timeout(Duration::from_secs(connect_timeout));
            }
            if let Some(pool_idle_timeout) = opts.pool_idle_timeout {
                b = b.pool_idle_timeout(Duration::from_secs(pool_idle_timeout));
            }
            b
        };
        #[cfg(target_arch = "wasm32")]
        let _ = (
            opts.request_timeout,
            opts.connect_timeout,
            opts.pool_idle_timeout,
        );

        let client = builder.build()?;

        let base_url = OnceLock::new();
        if let Some(url) = opts.base_url {
            // Pre-fill when an explicit URL was provided at build time.
            let _ = base_url.set(url);
        }

        Ok(Self { base_url, client })
    }
}

impl ZeroKMSConnection for HttpConnection {
    async fn send<Request: ViturRequest>(
        &self,
        request: Request,
        access_token: &str,
    ) -> Result<Request::Response, ViturRequestError> {
        let body = to_vec(&request)
            .map_err(|e| ViturRequestError::prepare("Failed to serialize request", e))?;

        let base_url = self.base_url.get().ok_or_else(|| {
            // A missing base URL is a client-side configuration problem (the
            // token carried no ZeroKMS `services` claim and none was set
            // explicitly), not an authentication failure — classify it as a
            // request-preparation error so callers don't mistake it for a 401
            // and trigger a token refresh/reauth loop.
            ViturRequestError::prepare(
                "ZeroKMS base URL was not resolved from the token's services claim",
                BaseUrlUnresolved,
            )
        })?;

        let url = base_url
            .join(Request::ENDPOINT)
            .map_err(|e| ViturRequestError::prepare("Failed to construct request URL", e))?;

        let response = self
            .client
            .post(url.as_str())
            .body(body)
            .header("content-type", "application/json")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| ViturRequestError::send("Failed to send request", e))?;

        let status = response.status();

        if status.is_success() {
            // Ok response
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|x| x.to_str().ok());

            let expected = "application/json";

            if content_type != Some(expected) {
                return Err(ViturRequestError::parse(
                    "Invalid content type header",
                    UnexpectedError {
                        received: content_type.map(|x| x.into()),
                        expected,
                        headers: header_map_to_hash(response.headers()),
                        body: response.text().await.ok(),
                    },
                ));
            }

            let response_bytes = response.bytes().await.map_err(|e| {
                ViturRequestError::parse("Failed to read response body as bytes", e)
            })?;

            from_reader(&response_bytes[..])
                .map_err(|e| ViturRequestError::parse("Failed to deserialize response body", e))
        } else {
            // Error handling
            let failure = FailureResponse::from_response(response).await;

            let err = match status {
                StatusCode::NOT_FOUND => {
                    failure.into_vitur_error(ViturRequestErrorKind::NotFound, "Resource not found")
                }
                StatusCode::UNAUTHORIZED => failure
                    .into_vitur_error(ViturRequestErrorKind::Unauthorized, "Request unauthorized"),
                StatusCode::FORBIDDEN => {
                    failure.into_vitur_error(ViturRequestErrorKind::Forbidden, "Request forbidden")
                }
                StatusCode::CONFLICT => {
                    failure.into_vitur_error(ViturRequestErrorKind::Conflict, "Resource conflict")
                }
                _ => ViturRequestError::other("Server returned failure response", failure),
            };

            Err(err)
        }
    }
}

#[cfg(test)]
mod base_url_tests {
    use super::*;

    fn conn(base_url: Option<Url>) -> HttpConnection {
        HttpConnection::init(HttpConnectionOpts::new(base_url)).unwrap()
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn is_unset_until_ensured() {
        let c = conn(None);
        assert!(!c.has_base_url());

        c.ensure_base_url(url("https://a.example"));

        assert!(c.has_base_url());
        assert_eq!(c.base_url.get().unwrap().as_str(), "https://a.example/");
    }

    #[test]
    fn the_first_ensured_url_wins() {
        let c = conn(None);
        c.ensure_base_url(url("https://first.example"));
        c.ensure_base_url(url("https://second.example"));

        assert_eq!(c.base_url.get().unwrap().as_str(), "https://first.example/");
    }

    #[test]
    fn a_url_given_at_init_is_kept_over_a_later_ensure() {
        let c = conn(Some(url("https://init.example")));
        assert!(c.has_base_url());

        c.ensure_base_url(url("https://other.example"));

        assert_eq!(c.base_url.get().unwrap().as_str(), "https://init.example/");
    }

    #[tokio::test]
    async fn send_without_a_base_url_is_a_prepare_error_not_an_auth_error() {
        use zerokms_protocol::{GenerateKeyRequest, ViturRequestErrorKind};

        let c = conn(None);
        let req = GenerateKeyRequest {
            client_id: uuid::Uuid::nil(),
            keyset_id: None,
            keys: std::borrow::Cow::Owned(vec![]),
            unverified_context: Default::default(),
        };

        let err = c.send(req, "token").await.unwrap_err();

        assert!(
            matches!(err.kind, ViturRequestErrorKind::PrepareRequest),
            "a missing base URL must not look like a 401 (and trigger a reauth loop), got: {err:?}"
        );
    }
}
