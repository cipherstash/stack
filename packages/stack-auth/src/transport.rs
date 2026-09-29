//! The HTTP seam: how a strategy's requests reach the network.
//!
//! Every exchange this crate makes has one shape — post a body to a URL,
//! read the status and body back — and that is the whole of
//! [`HttpTransport`]. Its request and response are the ones the Go
//! binding's guest already carries across its `transport_send` host
//! import: method, URL, headers and body in; status, headers and body out;
//! all bytes, no streaming. So a host with its own HTTP client implements
//! the trait, and the strategies run unchanged over it — inside a wasm
//! module with no TLS stack of its own, or anywhere else `reqwest` is the
//! wrong choice.
//!
//! With the `http` feature, [`ReqwestTransport`] is the implementation
//! every builder uses unless told otherwise, so native callers see no
//! difference. Without it, a builder must be handed a transport.
//!
//! Bodies and header values are wiped on drop on both halves: a request
//! carries an access key or a refresh token and a bearer credential, and a
//! response carries the token that was minted. Neither type prints any of
//! that: `Debug` reports the method, URL, header names and body length.
//! The wipe covers this crate's buffers; what an HTTP client copies into
//! its own is that client's, and [`ReqwestTransport`] says what it does.

use std::fmt;
use std::future::Future;
use std::sync::{Arc, OnceLock};

use url::Url;
use zeroize::Zeroizing;

use crate::error::RequestError;
use crate::AuthError;

/// One HTTP request, as a transport receives it.
///
/// The shape is the guest host import's, deliberately: a transport that
/// can carry this can carry every request the crate makes, and nothing the
/// crate makes needs more.
pub struct HttpRequest {
    method: &'static str,
    url: Url,
    headers: Zeroizing<Vec<(String, String)>>,
    body: Zeroizing<Vec<u8>>,
}

impl HttpRequest {
    /// A request. `method` is upper-case (`"POST"`); header names are
    /// lower-case. This is what the crate builds internally; a transport
    /// implementation outside the crate needs it only to test itself.
    pub fn new(
        method: &'static str,
        url: Url,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            method,
            url,
            headers: Zeroizing::new(headers),
            body: Zeroizing::new(body),
        }
    }

    /// The HTTP method, upper-case (`"POST"`).
    pub fn method(&self) -> &str {
        self.method
    }

    /// The absolute URL to send to.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The request headers, in order. Names are lower-case. Values are
    /// wiped when the request is dropped: one of them is the bearer
    /// credential.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// The request body. Wiped when the request is dropped.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Names only: a request or response carries credentials in its body and
/// its header values, and `{:?}` in a log line is how those leak.
impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url.as_str())
            .field("headers", &HeaderNames(&self.headers))
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// One HTTP response, as a transport returns it.
pub struct HttpResponse {
    status: u16,
    headers: Zeroizing<Vec<(String, String)>>,
    body: Zeroizing<Vec<u8>>,
}

impl HttpResponse {
    /// A response with `status`, `headers` and `body`. The body and the
    /// header values are wiped when the response is dropped.
    pub fn new(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: Zeroizing::new(headers),
            body: Zeroizing::new(body),
        }
    }

    /// The HTTP status code.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The response headers, in order.
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// The response body.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The body as text, for logging and for the error classifiers.
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The body decoded as JSON. A body that does not decode is reported as
    /// a request failure, as it was when the HTTP client did the decoding.
    pub(crate) fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, RequestError> {
        serde_json::from_slice(&self.body).map_err(|e| RequestError(Box::new(e)))
    }
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &HeaderNames(&self.headers))
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The names of a header list, for the `Debug` impls above.
struct HeaderNames<'a>(&'a [(String, String)]);

impl fmt::Debug for HeaderNames<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(name, _)| name))
            .finish()
    }
}

/// Carries one HTTP request and returns its response.
///
/// On native targets the trait carries `Send + Sync` bounds so a strategy
/// holding a transport can be driven from `tokio::spawn` background work.
/// On wasm32 the bounds are dropped — a fetch-backed future is not `Send`
/// and edge runtimes are single-threaded anyway — matching every other
/// async trait in this crate.
///
/// A failure to get any response at all (the host is unreachable, the
/// connection dropped) is a [`RequestError`]. A response with an error
/// status is not a failure of the transport: return it, and the strategy
/// classifies it.
#[cfg(not(target_arch = "wasm32"))]
pub trait HttpTransport: Send + Sync + 'static {
    /// Send `request` and return the response.
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, RequestError>> + Send;
}

/// Wasm32 variant of [`HttpTransport`] — drops the `Send + Sync` bounds.
#[cfg(target_arch = "wasm32")]
pub trait HttpTransport: 'static {
    /// Send `request` and return the response.
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, RequestError>>;
}

/// One transport can serve several strategies: hand each an `Arc` of it.
#[cfg(not(target_arch = "wasm32"))]
impl<T: HttpTransport> HttpTransport for Arc<T> {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, RequestError>> + Send {
        (**self).send(request)
    }
}

/// One transport can serve several strategies: hand each an `Arc` of it.
#[cfg(target_arch = "wasm32")]
impl<T: HttpTransport> HttpTransport for Arc<T> {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, RequestError>> {
        (**self).send(request)
    }
}

// ---------------------------------------------------------------------------
// The crate-internal, object-safe view.
//
// `HttpTransport` returns `impl Future`, which is the crate's convention and
// the easiest thing to implement — and not object-safe. The strategies want
// one concrete type for "whatever transport was configured" rather than a
// type parameter on every public strategy, so this adapter boxes the future
// once, at construction, and nothing else in the crate names the transport's
// concrete type again.
// ---------------------------------------------------------------------------

#[cfg(not(target_arch = "wasm32"))]
pub(crate) trait DynTransport: Send + Sync {
    fn send_dyn<'a>(
        &'a self,
        request: HttpRequest,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<HttpResponse, RequestError>> + Send + 'a>>;
}

#[cfg(not(target_arch = "wasm32"))]
impl<T: HttpTransport> DynTransport for T {
    fn send_dyn<'a>(
        &'a self,
        request: HttpRequest,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<HttpResponse, RequestError>> + Send + 'a>>
    {
        Box::pin(self.send(request))
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) trait DynTransport {
    fn send_dyn<'a>(
        &'a self,
        request: HttpRequest,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<HttpResponse, RequestError>> + 'a>>;
}

#[cfg(target_arch = "wasm32")]
impl<T: HttpTransport> DynTransport for T {
    fn send_dyn<'a>(
        &'a self,
        request: HttpRequest,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<HttpResponse, RequestError>> + 'a>> {
        Box::pin(self.send(request))
    }
}

/// The transport a strategy holds: whichever implementation it was built
/// with, behind one type.
pub(crate) type SharedTransport = Arc<dyn DynTransport>;

/// Box `transport` once, for the strategies to share.
pub(crate) fn share(transport: impl HttpTransport) -> SharedTransport {
    Arc::new(transport)
}

/// The transport a builder ends up with: the one it was given, else the
/// bundled `reqwest` client, else an error — a strategy cannot exist
/// without a way to send.
pub(crate) fn resolve(configured: Option<SharedTransport>) -> Result<SharedTransport, AuthError> {
    match configured {
        Some(transport) => Ok(transport),
        #[cfg(feature = "http")]
        None => Ok(default_transport()),
        #[cfg(not(feature = "http"))]
        None => Err(AuthError::Request(RequestError(Box::new(NoTransport)))),
    }
}

/// No transport was configured and the crate was built without `http`.
#[cfg(not(feature = "http"))]
#[derive(Debug)]
pub(crate) struct NoTransport;

#[cfg(not(feature = "http"))]
impl std::fmt::Display for NoTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "no HTTP transport: this build of stack-auth has no `http` feature, \
             so the strategy must be given one with `.transport(..)`",
        )
    }
}

#[cfg(not(feature = "http"))]
impl std::error::Error for NoTransport {}

// ---------------------------------------------------------------------------
// The two request shapes the crate makes.
// ---------------------------------------------------------------------------

/// The `user-agent` every request this crate builds carries:
/// `stack-auth/<version> (<os> <arch>)`.
///
/// Not cosmetic. The edge in front of production CTS answers a request whose
/// `user-agent` is a runtime's generic default (Go's `Go-http-client/1.1`)
/// with a bare nginx 403 that never reaches CTS. Natively, reqwest sends no
/// `user-agent` of its own, which that edge happens to let through; a host
/// transport whose HTTP client fills one in when the request has none (the
/// Go binding's) was refused on every exchange. So the crate names itself
/// on every request rather than leaving the header to whatever client
/// carries it. A host transport may replace the value with one naming
/// itself (the Go guest sends `stack-auth/<version> (Go)`), but it is never
/// absent.
pub(crate) fn user_agent() -> &'static str {
    static USER_AGENT: OnceLock<String> = OnceLock::new();
    USER_AGENT.get_or_init(|| {
        format!(
            "stack-auth/{} ({} {})",
            crate::VERSION,
            std::env::consts::OS,
            std::env::consts::ARCH,
        )
    })
}

/// `POST` a JSON body.
pub(crate) async fn post_json<B: serde::Serialize>(
    transport: &SharedTransport,
    url: Url,
    body: &B,
) -> Result<HttpResponse, RequestError> {
    let body = Zeroizing::new(serde_json::to_vec(body).map_err(|e| RequestError(Box::new(e)))?);
    post(transport, url, "application/json", Vec::new(), body).await
}

/// `POST` a form (`application/x-www-form-urlencoded`) body.
pub(crate) async fn post_form<B: serde::Serialize>(
    transport: &SharedTransport,
    url: Url,
    body: &B,
) -> Result<HttpResponse, RequestError> {
    let body = Zeroizing::new(
        serde_urlencoded::to_string(body)
            .map_err(|e| RequestError(Box::new(e)))?
            .into_bytes(),
    );
    post(
        transport,
        url,
        "application/x-www-form-urlencoded",
        Vec::new(),
        body,
    )
    .await
}

/// `POST` `body` as `content_type`, with `extra` headers first and then
/// `content-type` and [`user_agent`]. A failure
/// here is the transport's (or the encoder's); the caller lifts it into
/// its own error type, which for a strategy is `AuthError::Request`.
pub(crate) async fn post(
    transport: &SharedTransport,
    url: Url,
    content_type: &str,
    mut extra: Vec<(String, String)>,
    body: Zeroizing<Vec<u8>>,
) -> Result<HttpResponse, RequestError> {
    extra.push(("content-type".to_string(), content_type.to_string()));
    extra.push(("user-agent".to_string(), user_agent().to_string()));
    let request = HttpRequest {
        method: "POST",
        url,
        headers: Zeroizing::new(extra),
        body,
    };
    transport.send_dyn(request).await
}

// ---------------------------------------------------------------------------
// The bundled implementation.
// ---------------------------------------------------------------------------

/// [`HttpTransport`] over a [`reqwest::Client`]: what every strategy uses
/// unless a builder is given something else.
///
/// [`Default`] builds the client with the crate's standard timeouts and
/// pool settings; [`ReqwestTransport::new`] takes a client configured by
/// the caller.
///
/// What it does with the secrets it is handed: the request body is given
/// to reqwest as a buffer this crate still owns, so it is wiped when reqwest
/// is done with it rather than copied into an ordinary allocation; the
/// `authorization` header is marked sensitive, so reqwest's and hyper's
/// own `Debug` output redact it. What it cannot do: reach the buffers
/// reqwest and hyper allocate for themselves while sending and receiving.
/// Those are theirs, and this crate's wipe guarantee stops at its own.
#[cfg(feature = "http")]
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

#[cfg(feature = "http")]
impl ReqwestTransport {
    /// A transport over `client`.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[cfg(feature = "http")]
impl Default for ReqwestTransport {
    fn default() -> Self {
        Self::new(http_client())
    }
}

#[cfg(feature = "http")]
impl HttpTransport for ReqwestTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, RequestError> {
        use reqwest::header::HeaderValue;

        let HttpRequest {
            method,
            url,
            headers,
            body,
        } = request;
        let method = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|e| RequestError(Box::new(e)))?;
        let mut builder = self.client.request(method, url);
        for (name, value) in headers.iter() {
            let mut value = HeaderValue::from_str(value).map_err(|e| RequestError(Box::new(e)))?;
            if name.eq_ignore_ascii_case("authorization") {
                value.set_sensitive(true);
            }
            builder = builder.header(name.as_str(), value);
        }
        // `from_owner` lends reqwest the buffer instead of copying it: the
        // `Zeroizing` is dropped, and wiped, when the body is.
        let response = builder.body(bytes::Bytes::from_owner(body)).send().await?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = response.bytes().await?.to_vec();
        Ok(HttpResponse::new(status, headers, body))
    }
}

/// The bundled transport, boxed for the strategies.
#[cfg(feature = "http")]
pub(crate) fn default_transport() -> SharedTransport {
    share(ReqwestTransport::default())
}

/// Create a [`reqwest::Client`] with standard timeouts.
///
/// In test builds, timeouts are omitted so that `tokio::test(start_paused = true)`
/// does not auto-advance time past the connect timeout before the mock server
/// can respond. On wasm32, reqwest's fetch backend doesn't expose
/// `connect_timeout`/`pool_*` — the host runtime owns those concerns.
#[cfg(all(feature = "http", any(test, feature = "test-utils")))]
fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(all(
    feature = "http",
    not(any(test, feature = "test-utils")),
    not(target_arch = "wasm32")
))]
fn http_client() -> reqwest::Client {
    use std::time::Duration;

    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(10)
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(all(
    feature = "http",
    not(any(test, feature = "test-utils")),
    target_arch = "wasm32"
))]
fn http_client() -> reqwest::Client {
    // Wasm32 reqwest uses the host's `fetch`; timeouts and pooling are owned
    // by the runtime, so `ClientBuilder` doesn't expose them here.
    reqwest::Client::builder()
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::access_key_refresher::AccessKeyRefresher;
    use crate::oidc_refresher::{OidcProviderFn, OidcRefresher};
    use crate::refresher::Refresher;
    use crate::{SecretToken, Token};

    /// What the stub saw: method, URL, headers, body.
    type Seen = (String, String, Vec<(String, String)>, Vec<u8>);

    /// A transport that answers every request with one canned response and
    /// remembers what it was asked, so a test can pin the wire shape without
    /// an HTTP client in the build.
    struct Stub {
        response: Result<(u16, &'static str), &'static str>,
        seen: Mutex<Vec<Seen>>,
    }

    impl Stub {
        fn replying(status: u16, body: &'static str) -> Self {
            Self {
                response: Ok((status, body)),
                seen: Mutex::new(Vec::new()),
            }
        }

        fn failing(message: &'static str) -> Self {
            Self {
                response: Err(message),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpTransport for Stub {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, RequestError> {
            self.seen.lock().unwrap().push((
                request.method().to_string(),
                request.url().to_string(),
                request.headers().to_vec(),
                request.body().to_vec(),
            ));
            match self.response {
                Ok((status, body)) => Ok(HttpResponse::new(status, Vec::new(), body.into())),
                Err(message) => Err(RequestError(Box::new(std::io::Error::other(message)))),
            }
        }
    }

    fn base_url() -> Url {
        "https://cts.example.com/".parse().unwrap()
    }

    fn workspace_id() -> cts_common::WorkspaceId {
        "ZVATKW3VHMFG27DY".parse().unwrap()
    }

    fn seen(stub: &Arc<Stub>) -> Seen {
        stub.seen.lock().unwrap().remove(0)
    }

    /// The crate itself reads a response through `text()`/`json()`; the
    /// public accessors are what a host transport's own tests (and the FFI
    /// bindings) read, so they must hand back exactly what was built.
    #[test]
    fn a_response_reads_back_what_it_was_built_with() {
        let headers = vec![("content-type".to_string(), "application/json".to_string())];
        let response = HttpResponse::new(201, headers.clone(), b"{\"ok\":true}".to_vec());

        assert_eq!(response.status(), 201, "response should retain its status");
        assert_eq!(
            response.headers(),
            headers.as_slice(),
            "response should retain its headers"
        );
        assert_eq!(
            response.body(),
            b"{\"ok\":true}",
            "response should retain its body"
        );
    }

    #[test]
    fn debug_output_names_headers_and_never_prints_a_secret() {
        let request = HttpRequest::new(
            "POST",
            base_url(),
            vec![
                ("authorization".into(), "Bearer SECRET-TOKEN".into()),
                ("content-type".into(), "application/json".into()),
            ],
            br#"{"accessKey":"CSAK-SECRET"}"#.to_vec(),
        );
        let shown = format!("{request:?}");
        assert!(
            shown.contains("authorization") && shown.contains("content-type"),
            "{shown}"
        );
        assert!(shown.contains("body_len: 27"), "{shown}");
        assert!(!shown.contains("SECRET"), "{shown}");

        let response = HttpResponse::new(
            200,
            vec![("set-cookie".into(), "session=SECRET".into())],
            br#"{"accessToken":"SECRET"}"#.to_vec(),
        );
        let shown = format!("{response:?}");
        assert!(
            shown.contains("status: 200") && shown.contains("set-cookie"),
            "{shown}"
        );
        assert!(!shown.contains("SECRET"), "{shown}");
    }

    #[tokio::test]
    async fn a_shared_transport_serves_more_than_one_strategy() {
        let stub = Arc::new(Stub::replying(
            200,
            r#"{"accessToken":"svc","expiry":4102444800}"#,
        ));
        let one: SharedTransport = share(Arc::clone(&stub));
        let two: SharedTransport = share(stub.clone());
        for transport in [one, two] {
            let refresher = AccessKeyRefresher::new(
                SecretToken::new("CSAKid.secret"),
                base_url(),
                None,
                transport,
            );
            let _ = refresher.refresh(&()).await;
        }
        assert_eq!(
            stub.seen.lock().unwrap().len(),
            2,
            "both strategies reached the one transport"
        );
    }

    /// The `user-agent` the crate's requests must carry, spelled out rather
    /// than read back from [`user_agent`], so a change to it is a test
    /// change.
    fn expected_user_agent() -> String {
        format!(
            "stack-auth/{} ({} {})",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
            std::env::consts::ARCH,
        )
    }

    /// The `user-agent` values in `headers`: there must be exactly one.
    fn user_agents(headers: &[(String, String)]) -> Vec<&str> {
        headers
            .iter()
            .filter(|(name, _)| name == "user-agent")
            .map(|(_, value)| value.as_str())
            .collect()
    }

    /// The edge in front of production CTS refuses a request whose
    /// `user-agent` is a runtime's generic default with a bare 403, and a
    /// host transport's HTTP client fills one in when the request carries
    /// none. Both request shapes the crate makes name the crate themselves.
    #[tokio::test]
    async fn every_request_identifies_itself() {
        let stub = Arc::new(Stub::replying(200, "{}"));
        let transport: SharedTransport = stub.clone();

        post_json(&transport, base_url(), &serde_json::json!({"a": 1}))
            .await
            .unwrap();
        post_form(&transport, base_url(), &[("a", "1")])
            .await
            .unwrap();
        post(
            &transport,
            base_url(),
            "application/json",
            vec![("authorization".into(), "Bearer tok".into())],
            Zeroizing::new(Vec::new()),
        )
        .await
        .unwrap();

        let expected = expected_user_agent();
        for (shape, content_type) in [
            ("post_json", "application/json"),
            ("post_form", "application/x-www-form-urlencoded"),
            ("post with extra headers", "application/json"),
        ] {
            let (_, _, headers, _) = seen(&stub);
            assert_eq!(
                user_agents(&headers),
                vec![expected.as_str()],
                "{shape}: exactly one user-agent, naming the crate, version and platform"
            );
            assert!(
                headers.contains(&("content-type".to_string(), content_type.to_string())),
                "{shape}: the content type travels with the user-agent: {headers:?}"
            );
        }
    }

    #[test]
    fn the_user_agent_names_the_crate_version_and_platform() {
        assert_eq!(user_agent(), expected_user_agent());
        assert_eq!(crate::VERSION, env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn refresh_posts_a_form_and_reads_the_token() {
        let stub = Arc::new(Stub::replying(
            200,
            r#"{"access_token":"new","token_type":"Bearer","expires_in":3600,"refresh_token":"rotated"}"#,
        ));
        let transport: SharedTransport = stub.clone();

        let token = Token::refresh_with(
            &transport,
            &SecretToken::new("rt"),
            &base_url(),
            "cli",
            None,
        )
        .await
        .unwrap();

        assert_eq!(token.access_token().as_str(), "new");
        assert_eq!(token.refresh_token().unwrap().as_str(), "rotated");
        let (method, url, headers, body) = seen(&stub);
        assert_eq!(method, "POST");
        assert_eq!(url, "https://cts.example.com/oauth/token");
        assert!(headers.contains(&(
            "content-type".to_string(),
            "application/x-www-form-urlencoded".to_string()
        )));
        assert_eq!(
            user_agents(&headers),
            vec![expected_user_agent().as_str()],
            "the device-session refresh identifies the crate"
        );
        assert_eq!(
            body, b"grant_type=refresh_token&client_id=cli&refresh_token=rt",
            "an absent device id is omitted, not sent empty"
        );
    }

    #[tokio::test]
    async fn refresh_classifies_the_oauth_error_body() {
        for (error, check) in [
            (
                "invalid_grant",
                (|e| matches!(e, AuthError::InvalidGrant(_))) as fn(&AuthError) -> bool,
            ),
            ("invalid_client", |e| {
                matches!(e, AuthError::InvalidClient(_))
            }),
            ("access_denied", |e| matches!(e, AuthError::AccessDenied(_))),
        ] {
            let body: &'static str = match error {
                "invalid_grant" => r#"{"error":"invalid_grant"}"#,
                "invalid_client" => r#"{"error":"invalid_client"}"#,
                _ => r#"{"error":"access_denied"}"#,
            };
            let transport: SharedTransport = Arc::new(Stub::replying(400, body));
            let err = Token::refresh_with(
                &transport,
                &SecretToken::new("rt"),
                &base_url(),
                "cli",
                None,
            )
            .await
            .unwrap_err();
            assert!(check(&err), "{error}: {err:?}");
        }
    }

    #[tokio::test]
    async fn access_key_posts_json_and_maps_the_response() {
        let stub = Arc::new(Stub::replying(
            200,
            r#"{"accessToken":"svc","expiry":4102444800}"#,
        ));
        let refresher = AccessKeyRefresher::new(
            SecretToken::new("CSAKid.secret"),
            base_url(),
            Some("aud".into()),
            stub.clone(),
        );

        let token = refresher.refresh(&()).await.unwrap();

        assert_eq!(token.access_token().as_str(), "svc");
        let (method, url, headers, body) = seen(&stub);
        assert_eq!(method, "POST");
        assert_eq!(url, "https://cts.example.com/api/authorise");
        assert!(headers.contains(&("content-type".to_string(), "application/json".to_string())));
        assert_eq!(
            user_agents(&headers),
            vec![expected_user_agent().as_str()],
            "the access-key exchange identifies the crate"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            serde_json::json!({"accessKey": "CSAKid.secret", "audience": "aud"})
        );
    }

    #[tokio::test]
    async fn oidc_federation_posts_json_and_identifies_the_crate() {
        let stub = Arc::new(Stub::replying(
            200,
            r#"{"accessToken":"svc","expiry":4102444800}"#,
        ));
        let provider = OidcProviderFn::new(|| async { Ok(SecretToken::new("h.p.s")) });
        let refresher = OidcRefresher::new(provider, workspace_id(), base_url(), stub.clone());

        let _ = refresher.refresh(&()).await;

        let (method, url, headers, _) = seen(&stub);
        assert_eq!(method, "POST");
        assert_eq!(url, "https://cts.example.com/api/authorise");
        assert_eq!(
            user_agents(&headers),
            vec![expected_user_agent().as_str()],
            "the OIDC federation exchange identifies the crate"
        );
    }

    #[tokio::test]
    async fn a_bare_402_is_a_usage_limit_on_every_exchange() {
        let transport: SharedTransport = Arc::new(Stub::replying(402, ""));
        let refresher = AccessKeyRefresher::new(
            SecretToken::new("CSAKid.secret"),
            base_url(),
            None,
            transport,
        );
        let err = refresher.refresh(&()).await.unwrap_err();
        assert!(matches!(err, AuthError::UsageLimitExceeded(_)), "{err:?}");

        let transport: SharedTransport = Arc::new(Stub::replying(402, ""));
        let provider = OidcProviderFn::new(|| async { Ok(SecretToken::new("h.p.s")) });
        let refresher = OidcRefresher::new(provider, workspace_id(), base_url(), transport);
        let err = refresher.refresh(&()).await.unwrap_err();
        assert!(matches!(err, AuthError::UsageLimitExceeded(_)), "{err:?}");

        let transport: SharedTransport = Arc::new(Stub::replying(402, ""));
        let err = Token::refresh_with(
            &transport,
            &SecretToken::new("rt"),
            &base_url(),
            "cli",
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AuthError::UsageLimitExceeded(_)), "{err:?}");
    }

    #[tokio::test]
    async fn an_unclassified_failure_is_a_server_error_with_the_body() {
        let transport: SharedTransport = Arc::new(Stub::replying(500, "boom"));
        let refresher = AccessKeyRefresher::new(
            SecretToken::new("CSAKid.secret"),
            base_url(),
            None,
            transport,
        );
        let err = refresher.refresh(&()).await.unwrap_err();
        match err {
            AuthError::Server(e) => {
                assert!(e.to_string().contains("500") && e.to_string().contains("boom"))
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_transport_failure_is_a_request_error() {
        let transport: SharedTransport = Arc::new(Stub::failing("connection refused"));
        let refresher = AccessKeyRefresher::new(
            SecretToken::new("CSAKid.secret"),
            base_url(),
            None,
            transport,
        );
        let err = refresher.refresh(&()).await.unwrap_err();
        match err {
            AuthError::Request(e) => assert!(e.to_string().contains("connection refused")),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn an_undecodable_success_body_is_a_request_error() {
        let transport: SharedTransport = Arc::new(Stub::replying(200, "not json"));
        let refresher = AccessKeyRefresher::new(
            SecretToken::new("CSAKid.secret"),
            base_url(),
            None,
            transport,
        );
        let err = refresher.refresh(&()).await.unwrap_err();
        assert!(matches!(err, AuthError::Request(_)), "{err:?}");
    }

    #[cfg(not(feature = "http"))]
    #[test]
    fn a_builder_without_a_transport_is_refused_when_there_is_no_bundled_one() {
        let crn: cts_common::Crn = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY".parse().unwrap();
        let key: crate::AccessKey = "CSAKtestKeyId.testKeySecret".parse().unwrap();
        let Err(err) = crate::AccessKeyStrategy::new(crn, key) else {
            panic!("built a strategy with nothing to send through");
        };
        assert!(matches!(err, AuthError::Request(_)), "{err:?}");
        assert!(err.to_string().contains("`.transport(..)`"), "{err}");
    }

    #[cfg(not(feature = "http"))]
    #[test]
    fn a_builder_with_a_transport_builds_without_the_bundled_one() {
        let crn: cts_common::Crn = "crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY".parse().unwrap();
        let key: crate::AccessKey = "CSAKtestKeyId.testKeySecret".parse().unwrap();
        assert!(crate::AccessKeyStrategy::builder(crn, key)
            .transport(Stub::replying(200, ""))
            .build()
            .is_ok());
    }
}
