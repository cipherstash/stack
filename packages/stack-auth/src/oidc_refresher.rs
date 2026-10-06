use std::future::Future;
use std::sync::Arc;

use cts_common::WorkspaceId;
use sha2::{Digest, Sha256};
use url::Url;

use crate::authorize_dto::AuthoriseResponse;
use crate::refresher::Refresher;
use crate::transport::{self, SharedTransport};
use crate::{AuthError, SecretToken, Token};

/// Asynchronously supplies the third-party OIDC JWT of the caller a request
/// is for.
///
/// [`OidcFederationStrategy`](crate::OidcFederationStrategy) calls this on
/// **every** [`get_token`](crate::AuthStrategy::get_token): the JWT it returns
/// is how the strategy tells one user from another, so a server that serves
/// many users through one client must return the JWT of the user behind the
/// *current* request (read from the request's context, session, or
/// `Authorization` header), never a value captured once. The strategy then
/// re-federates only when that JWT has no cached, unexpired CTS token, so the
/// call is cheap on the hot path as long as the implementation is: provider
/// SDKs (`clerk.session.getToken()`, `supabase.auth.getSession()`) cache their
/// session locally and are fine to call per request. Implementations typically
/// wrap such an SDK call, an FFI callback, or a test double.
///
/// On native targets the trait carries `Send + Sync` bounds so the provider
/// can be driven from `tokio::spawn` background work. On wasm32 the bounds
/// are dropped — reqwest's fetch-backed futures are not `Send` and edge
/// runtimes are single-threaded anyway.
#[cfg(not(target_arch = "wasm32"))]
pub trait OidcProvider: Send + Sync {
    /// Fetch the third-party OIDC JWT of the caller this request is for.
    fn fetch(&self) -> impl Future<Output = Result<SecretToken, AuthError>> + Send;
}

/// Wasm32 variant of [`OidcProvider`] — drops the `Send + Sync` bounds.
#[cfg(target_arch = "wasm32")]
pub trait OidcProvider {
    /// Fetch the third-party OIDC JWT of the caller this request is for.
    fn fetch(&self) -> impl Future<Output = Result<SecretToken, AuthError>>;
}

/// [`OidcProvider`] backed by a user-supplied async closure.
///
/// The closure fires on every [`get_token`](crate::AuthStrategy::get_token),
/// so it must return the *current* caller's JWT each time, not a value
/// captured once. The point of the closure is to defer to the provider's own
/// session machinery on every call: a provider SDK (`clerk.session.getToken()`,
/// `supabase.auth.getSession()`) hands back a freshly-minted short-lived JWT,
/// transparently refreshing its own session as needed. Capturing a single
/// token up front would instead pin one user's JWT, which expires and can
/// never be renewed — and would make every caller that user.
///
/// # Example
///
/// ```no_run
/// use stack_auth::{AuthError, OidcProviderFn, SecretToken};
///
/// # async fn clerk_session_get_token() -> Result<String, AuthError> { Ok(String::new()) }
/// // Each call asks the provider SDK for the *current* session token, so an
/// // expired JWT is refreshed upstream rather than reused.
/// let provider = OidcProviderFn::new(|| async {
///     let jwt = clerk_session_get_token().await?;
///     Ok::<_, AuthError>(SecretToken::new(jwt))
/// });
/// ```
pub struct OidcProviderFn<F> {
    fetch: F,
}

impl<F> OidcProviderFn<F> {
    /// Build an `OidcProviderFn` from an async closure returning the current JWT.
    pub fn new(fetch: F) -> Self {
        Self { fetch }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl<F, Fut> OidcProvider for OidcProviderFn<F>
where
    F: Fn() -> Fut + Send + Sync,
    Fut: Future<Output = Result<SecretToken, AuthError>> + Send,
{
    fn fetch(&self) -> impl Future<Output = Result<SecretToken, AuthError>> + Send {
        (self.fetch)()
    }
}

#[cfg(target_arch = "wasm32")]
impl<F, Fut> OidcProvider for OidcProviderFn<F>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<SecretToken, AuthError>>,
{
    fn fetch(&self) -> impl Future<Output = Result<SecretToken, AuthError>> {
        (self.fetch)()
    }
}

/// The identity of a provider JWT inside
/// [`OidcFederationStrategy`](crate::OidcFederationStrategy): the SHA-256 of
/// the whole token.
///
/// The strategy keys its per-user cache on this, and stamps it (as hex, see
/// [`Token::federated_from`]) on every token it federates, so a stored token
/// is served only to the JWT that produced it.
///
/// It is deliberately the *whole JWT*, not the `iss`/`sub` claims read from
/// it. The client cannot verify a JWT's signature, so a cache keyed on claims
/// would hand a forged JWT carrying a victim's `sub` the victim's cached CTS
/// token without CTS ever seeing it. Keyed on the bytes, a forged JWT gets
/// its own entry and is refused by CTS. The cost is one exchange each time
/// the identity provider rotates a user's JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct JwtDigest([u8; 32]);

impl JwtDigest {
    pub(crate) fn of(jwt: &SecretToken) -> Self {
        Self(Sha256::digest(jwt.as_str().as_bytes()).into())
    }

    /// Lowercase hex, the form [`Token::federated_from`] carries.
    pub(crate) fn to_hex(self) -> String {
        self.0.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Whether `hex`, as read back from [`Token::federated_from`], is this
    /// digest.
    pub(crate) fn matches_hex(self, hex: &str) -> bool {
        hex == self.to_hex()
    }
}

/// The CTS endpoint a strategy federates against: `POST /api/authorise` on
/// one base URL, for one workspace, over one transport.
///
/// The exchange is stateless. `/api/authorise` issues no CTS refresh token, so
/// keeping a federated token fresh means federating again with a current
/// provider JWT — which [`JwtRefresher`] does, one refresher per JWT. The
/// *upstream* OIDC provider that issues the JWT is typically not stateless: it
/// relies on its own session machinery (cookies, a session store, a refresh
/// token) to mint the short-lived JWT that [`OidcProvider::fetch`] returns.
pub(crate) struct OidcFederation {
    workspace_id: WorkspaceId,
    base_url: Url,
    transport: SharedTransport,
}

impl OidcFederation {
    pub(crate) fn new(
        workspace_id: WorkspaceId,
        base_url: Url,
        transport: SharedTransport,
    ) -> Self {
        Self {
            workspace_id,
            base_url,
            transport,
        }
    }

    /// Exchange `jwt` for a CTS service token.
    pub(crate) async fn federate(&self, jwt: &SecretToken) -> Result<Token, AuthError> {
        let url = self.base_url.join("api/authorise")?;
        tracing::debug!(url = %url, "federating OIDC token");

        let resp = transport::post_json(
            &self.transport,
            url,
            &OidcAuthoriseRequest {
                oidc_token: jwt.as_str(),
                workspace_id: self.workspace_id.as_str(),
            },
        )
        .await?;

        if !resp.is_success() {
            let status = resp.status();
            let body = resp.text();
            tracing::debug!(%status, %body, "OIDC federation failed");
            if let Some(err) = crate::error::classify_issuance_failure(status, &body) {
                return Err(err);
            }
            return Err(AuthError::Server(crate::error::ServerError(format!(
                "{status}: {body}"
            ))));
        }

        let auth_resp: AuthoriseResponse = resp.json()?;

        // The response → Token mapping (including the absolute-epoch `expiry`
        // handling that CIP-3233 fixed) lives on `From<AuthoriseResponse>`.
        Ok(auth_resp.into())
    }
}

/// A [`Refresher`] for **one** provider JWT: every refresh federates that
/// same JWT again.
///
/// [`OidcFederationStrategy`](crate::OidcFederationStrategy) keeps one of
/// these, inside its own [`AutoRefresh`](crate::auto_refresh::AutoRefresh),
/// per distinct JWT its provider has returned. Re-federating the held JWT is
/// right because the JWT *is* the cache key: while a caller keeps presenting
/// it, it is still what that caller has, and a CTS token that expires before
/// the JWT does (CTS tokens last about 15 minutes) is renewed from it. Once
/// the provider rotates the JWT, callers land on a different refresher and
/// this one ages out of the cache. A JWT that has itself expired is refused
/// by CTS, and that refusal is the caller's answer.
///
/// `try_credential` always yields and `restore` is a no-op, like
/// [`AccessKeyRefresher`](crate::access_key_refresher::AccessKeyRefresher):
/// the credential is always to hand.
pub(crate) struct JwtRefresher {
    jwt: SecretToken,
    digest: JwtDigest,
    federation: Arc<OidcFederation>,
}

impl JwtRefresher {
    pub(crate) fn new(jwt: SecretToken, federation: Arc<OidcFederation>) -> Self {
        let digest = JwtDigest::of(&jwt);
        Self {
            jwt,
            digest,
            federation,
        }
    }

    /// The digest of the JWT this refresher federates.
    pub(crate) fn digest(&self) -> JwtDigest {
        self.digest
    }
}

impl Refresher for JwtRefresher {
    type Credential = ();

    fn save(&self, _token: &Token) {
        // Federated tokens are ephemeral — no per-refresher persistence.
    }

    fn try_credential(&self, _token: Option<&mut Token>) -> Option<Self::Credential> {
        // The JWT is held, so federation can always be attempted — including
        // on cold start (initial auth).
        Some(())
    }

    fn restore(&self, _token: &mut Token, _credential: Self::Credential) {
        // Nothing to restore — the JWT is still held.
    }

    async fn refresh(&self, _credential: &Self::Credential) -> Result<Token, AuthError> {
        let mut token = self.federation.federate(&self.jwt).await?;
        // Stamp the token with the JWT it came from, so a `TokenStore` that
        // persists it can tell the strategy, on a later cold start, which
        // caller it belongs to.
        token.federated_from = Some(self.digest.to_hex());
        Ok(token)
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OidcAuthoriseRequest<'a> {
    oidc_token: &'a str,
    workspace_id: &'a str,
}

#[cfg(test)]
mod digest_tests {
    use super::*;

    /// The hex form is what lands in a persisted token (and so in a
    /// customer's cookie), so pin it to an independently computed vector:
    /// `printf '%s' header.payload.signature | shasum -a 256`.
    #[test]
    fn digest_hex_is_sha256_of_the_whole_jwt() {
        let digest = JwtDigest::of(&SecretToken::new("header.payload.signature"));
        assert_eq!(
            digest.to_hex(),
            "256d04db4e5e4ac308751ed0885b722b758630567c53a7125ed9fbd068e5c3f6"
        );
    }

    #[test]
    fn different_jwts_have_different_digests() {
        let a = JwtDigest::of(&SecretToken::new("jwt-a"));
        let b = JwtDigest::of(&SecretToken::new("jwt-b"));
        assert_ne!(a, b);
        assert_eq!(a, JwtDigest::of(&SecretToken::new("jwt-a")));
    }
}

#[cfg(test)]
#[cfg(feature = "http")]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::transport::default_transport;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use mocktail::prelude::*;

    use super::*;
    use crate::auto_refresh::{AutoRefresh, AutoRefreshError};

    const WORKSPACE_ID: &str = "ZVATKW3VHMFG27DY";

    fn workspace_id() -> WorkspaceId {
        WORKSPACE_ID.parse().unwrap()
    }

    /// Build a mock `/api/authorise` response. CTS returns `expiry` as an
    /// ABSOLUTE Unix epoch (the JWT `exp` claim), so model that faithfully: the
    /// token is valid for `expires_in_secs` from now.
    fn auth_response_json(access: &str, expires_in_secs: u64) -> serde_json::Value {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        serde_json::json!({
            "accessToken": access,
            "expiry": now + expires_in_secs
        })
    }

    async fn start_server(mocks: MockSet) -> MockServer {
        let server = MockServer::new_http("oidc-refresher-test").with_mocks(mocks);
        server.start().await.unwrap();
        server
    }

    fn federation(server: &MockServer) -> Arc<OidcFederation> {
        Arc::new(OidcFederation::new(
            workspace_id(),
            server.url(""),
            default_transport(),
        ))
    }

    fn refresher_for(server: &MockServer, jwt: &str) -> JwtRefresher {
        JwtRefresher::new(SecretToken::new(jwt), federation(server))
    }

    /// The request body `/api/authorise` receives for `jwt` in this workspace.
    fn exchange_of(jwt: &str) -> serde_json::Value {
        serde_json::json!({ "oidcToken": jwt, "workspaceId": WORKSPACE_ID })
    }

    // ---- Regression: CTS `expiry` is an absolute epoch (CIP-3233) ----

    /// CTS `/api/authorise` returns `expiry` as an ABSOLUTE Unix epoch (the JWT
    /// `exp` claim), not a relative duration — identical to the access-key path
    /// fixed in CIP-3233. The federation step must use it as-is.
    ///
    /// Pre-fix (`expires_at = now + expiry`), this token's `expires_at` lands
    /// ~decades in the future, so `is_expired()` is never true — the federated
    /// token never re-federates and silently dies at its real ~15-minute `exp`.
    /// The assertion below fails under the pre-fix arithmetic (`expires_in()` ≈
    /// 1.7e9) and passes with the fix (`expires_in()` ≈ 900). See CIP-3233.
    #[tokio::test]
    async fn oidc_expiry_is_absolute_epoch_not_relative() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let absolute_expiry = now + 900; // a 15-minute token, as an absolute epoch

        let mut mocks = MockSet::new();
        mocks.mock(move |when, then| {
            when.post().path("/api/authorise");
            then.json(serde_json::json!({
                "accessToken": "tok",
                "expiry": absolute_expiry
            }));
        });
        let server = start_server(mocks).await;

        let token = federation(&server)
            .federate(&SecretToken::new("jwt-0"))
            .await
            .unwrap();

        assert!(
            token.expires_in() <= 1000,
            "expires_in should be ~900s (absolute `expiry` used as-is); got {} \
             — pre-fix `now + expiry` yields ~1.7e9",
            token.expires_in()
        );
        assert!(
            !token.is_expired(),
            "a freshly federated 15-minute token must not be reported as already expired"
        );
    }

    /// The federation step sends exactly the JWT it was given, and nothing it
    /// mints is stamped — stamping is the refresher's job, so a token that
    /// came straight from the endpoint is not mistaken for a cached one.
    #[tokio::test]
    async fn federate_sends_the_given_jwt_and_leaves_the_token_unstamped() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post()
                .path("/api/authorise")
                .json(exchange_of("the-jwt"));
            then.json(auth_response_json("cts-token", 3600));
        });
        let server = start_server(mocks).await;

        let token = federation(&server)
            .federate(&SecretToken::new("the-jwt"))
            .await
            .expect("a body carrying exactly the JWT and workspace is what the mock matched");

        assert_eq!(token.access_token().as_str(), "cts-token");
        assert!(token.federated_from().is_none());
    }

    /// The refresher federates the one JWT it holds, and stamps the result
    /// with that JWT's digest so a store can bind it.
    #[tokio::test]
    async fn refresh_federates_the_held_jwt_and_stamps_its_digest() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post()
                .path("/api/authorise")
                .json(exchange_of("held-jwt"));
            then.json(auth_response_json("cts-token", 3600));
        });
        let server = start_server(mocks).await;
        let refresher = refresher_for(&server, "held-jwt");

        let token = refresher.refresh(&()).await.unwrap();

        assert_eq!(token.access_token().as_str(), "cts-token");
        assert_eq!(
            token.federated_from(),
            Some(
                JwtDigest::of(&SecretToken::new("held-jwt"))
                    .to_hex()
                    .as_str()
            )
        );
    }

    #[test]
    fn test_request_serialization() {
        let body = serde_json::to_value(OidcAuthoriseRequest {
            oidc_token: "the-jwt",
            workspace_id: WORKSPACE_ID,
        })
        .unwrap();
        assert_eq!(
            body,
            exchange_of("the-jwt"),
            "request body should carry exactly the OIDC token and workspace ID"
        );
    }

    /// Under `AutoRefresh`, one refresher caches its token and re-federates the
    /// same JWT when that token expires — the per-user engine the strategy
    /// builds on.
    #[tokio::test]
    async fn under_auto_refresh_the_same_jwt_is_federated_again_on_expiry() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post()
                .path("/api/authorise")
                .json(exchange_of("held-jwt"));
            then.json(auth_response_json("first", 0));
        });
        let server = start_server(mocks).await;
        let engine = AutoRefresh::with_store(refresher_for(&server, "held-jwt"), crate::NoStore);

        assert_eq!(engine.get_token().await.unwrap().as_str(), "first");

        // The first token is already expired, so the next call must federate
        // again — with the same JWT, which is all the second mock accepts.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post()
                .path("/api/authorise")
                .json(exchange_of("held-jwt"));
            then.json(auth_response_json("second", 3600));
        });
        assert_eq!(engine.get_token().await.unwrap().as_str(), "second");

        // Now cached: a federation call would fail loudly.
        server.mocks().clear();
        server.mocks().mock(|when, then| {
            when.post().path("/api/authorise");
            then.internal_server_error()
                .json(serde_json::json!({"error": "should not be called"}));
        });
        assert_eq!(engine.get_token().await.unwrap().as_str(), "second");
    }

    #[tokio::test]
    async fn test_server_rejection_propagates() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.internal_server_error()
                .json(serde_json::json!({"error": "workspace mismatch"}));
        });
        let server = start_server(mocks).await;
        let engine = AutoRefresh::with_store(refresher_for(&server, "jwt-0"), crate::NoStore);

        let err = engine.get_token().await.unwrap_err();
        assert!(
            matches!(err, AutoRefreshError::Auth(AuthError::Server(_))),
            "a 500 from /api/authorise should surface as a server error, got: {err:?}"
        );
    }

    /// The OIDC federation path is the third caller of
    /// `classify_issuance_failure`. The other two are covered; without this
    /// the claim that all three cannot drift apart is untested here.
    #[tokio::test]
    async fn usage_limit_402_is_typed_not_server_error() {
        let mut mocks = MockSet::new();
        mocks.mock(|when, then| {
            when.post().path("/api/authorise");
            then.status(reqwest::StatusCode::PAYMENT_REQUIRED)
                .json(serde_json::json!({
                    "error": "access_denied",
                    "cs_code": "USAGE_LIMIT_EXCEEDED",
                    "error_description": "Workspace has exceeded its usage limit",
                }));
        });
        let server = start_server(mocks).await;
        let engine = AutoRefresh::with_store(refresher_for(&server, "jwt-0"), crate::NoStore);

        let AutoRefreshError::Auth(err) = engine.get_token().await.unwrap_err() else {
            panic!("expected a typed auth error");
        };

        assert_eq!(
            err.error_code(),
            crate::error::codes::USAGE_LIMIT_EXCEEDED,
            "a usage limit must not be flattened into SERVER_ERROR",
        );
    }
}
