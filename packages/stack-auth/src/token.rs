use cts_common::claims::ClientClaims;
use cts_common::{Crn, Region, WorkspaceId};
use url::Url;

use crate::transport::{self, SharedTransport};
use crate::{AuthError, SecretToken};

#[cfg(not(target_arch = "wasm32"))]
impl stack_profile::ProfileData for Token {
    const FILENAME: &'static str = "auth.json";
    const MODE: Option<u32> = Some(0o600);
}

/// How many seconds before expiry [`Token::is_expired`] returns `true`.
///
/// This leeway triggers preemptive refresh well before the token becomes
/// unusable, giving the HTTP refresh call time to complete while concurrent
/// callers can still use the current token.
const EXPIRY_LEEWAY_SECS: u64 = 90;

/// The current Unix time in whole seconds, from the system wall clock.
///
/// Delegates to [`SystemClock`](crate::clock::SystemClock) so the crate has a
/// single definition of "now"; the `*_at` methods take an explicit `now` for
/// tests that drive a [`Clock`](crate::clock::Clock).
fn now_unix_secs() -> u64 {
    use crate::clock::{Clock, SystemClock};
    SystemClock.now_unix_secs()
}

/// An access token returned by a successful authentication flow.
///
/// The token contains a [`SecretToken`] (the bearer credential), a token type
/// (typically `"Bearer"`), and an absolute expiry timestamp.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub(crate) access_token: SecretToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) refresh_token: Option<SecretToken>,
    pub(crate) token_type: String,
    pub(crate) expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) device_instance_id: Option<String>,
}

impl Token {
    /// Returns a reference to the access token credential.
    ///
    /// The returned [`SecretToken`] is opaque — its [`Debug`] output is masked.
    /// Pass it to API clients that need the raw bearer token.
    pub fn access_token(&self) -> &SecretToken {
        &self.access_token
    }

    /// The token type (e.g. `"Bearer"`).
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    /// The absolute epoch timestamp when the token expires.
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// How many seconds until the token expires (computed from the current time).
    pub fn expires_in(&self) -> u64 {
        self.expires_at.saturating_sub(now_unix_secs())
    }

    /// Returns `true` if the token has expired (with 90 seconds of leeway).
    ///
    /// The 90-second leeway triggers preemptive refresh well before the token
    /// becomes unusable, giving the HTTP refresh call plenty of time to complete
    /// while the current token is still valid for concurrent callers.
    ///
    /// For checking whether the token is still usable as a bearer credential,
    /// use [`is_usable`](Self::is_usable) instead.
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(now_unix_secs())
    }

    /// [`is_expired`](Self::is_expired) evaluated against an explicit `now`
    /// (seconds since the Unix epoch) rather than the wall clock.
    ///
    /// Used internally so [`AutoRefresh`](crate::auto_refresh::AutoRefresh) can
    /// drive expiry from an injected [`Clock`](crate::clock::Clock).
    pub(crate) fn is_expired_at(&self, now: u64) -> bool {
        now.saturating_add(EXPIRY_LEEWAY_SECS) >= self.expires_at
    }

    /// Returns `true` if the token is still usable (before the actual expiry timestamp).
    ///
    /// Unlike [`is_expired`](Self::is_expired) which includes 90s leeway for preemptive
    /// refresh, this only returns `false` when the token has genuinely expired.
    pub fn is_usable(&self) -> bool {
        self.is_usable_at(now_unix_secs())
    }

    /// [`is_usable`](Self::is_usable) evaluated against an explicit `now`
    /// (seconds since the Unix epoch) rather than the wall clock.
    pub(crate) fn is_usable_at(&self, now: u64) -> bool {
        now < self.expires_at
    }

    /// Returns a reference to the refresh token, if one was provided.
    pub fn refresh_token(&self) -> Option<&SecretToken> {
        self.refresh_token.as_ref()
    }

    /// Takes the refresh token out, leaving `None` in its place.
    pub fn take_refresh_token(&mut self) -> Option<SecretToken> {
        self.refresh_token.take()
    }

    /// Returns the stored region identifier, if any.
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    /// Returns the stored client ID, if any.
    pub fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    /// Set the region identifier on this token.
    pub(crate) fn set_region(&mut self, region: impl Into<String>) {
        self.region = Some(region.into());
    }

    /// Set the client ID on this token.
    pub(crate) fn set_client_id(&mut self, client_id: impl Into<String>) {
        self.client_id = Some(client_id.into());
    }

    /// Returns the stored device instance ID, if any.
    pub fn device_instance_id(&self) -> Option<&str> {
        self.device_instance_id.as_deref()
    }

    /// Set the device instance ID on this token.
    pub(crate) fn set_device_instance_id(&mut self, id: impl Into<String>) {
        self.device_instance_id = Some(id.into());
    }

    /// Returns the workspace ID from the JWT claims.
    ///
    /// The access token is decoded (without signature verification) to extract
    /// the `workspace` claim.
    pub fn workspace_id(&self) -> Result<WorkspaceId, AuthError> {
        self.decode_claims().map(|c| c.workspace)
    }

    /// Returns the workspace CRN derived from the token's region and workspace ID.
    ///
    /// The region is set during the device code flow, and the workspace ID is
    /// extracted from the JWT `workspace` claim.
    pub fn workspace_crn(&self) -> Result<Crn, AuthError> {
        let workspace_id = self.workspace_id()?;
        let region: Region = self
            .region()
            .ok_or(AuthError::NotAuthenticated(crate::error::NotAuthenticated))?
            .parse()
            .map_err(|e: cts_common::RegionError| {
                AuthError::Server(crate::error::ServerError(e.to_string()))
            })?;
        Ok(Crn::new(region, workspace_id))
    }

    /// Returns the issuer URL from the JWT claims.
    ///
    /// The `iss` claim in CipherStash tokens is the CTS host URL for the
    /// workspace, so this can be used directly as the CTS base URL.
    pub fn issuer(&self) -> Result<Url, AuthError> {
        let claims = self.decode_claims()?;
        claims.iss.parse().map_err(AuthError::from)
    }

    /// Decode the JWT payload into [`ClientClaims`] without verifying the
    /// signature.
    ///
    /// This is safe because we already possess the token — we just need to read
    /// the claims it contains. See [`crate::decode_jwt_payload`] for why we parse
    /// by hand rather than through `jsonwebtoken`.
    ///
    /// Decodes [`ClientClaims`], not [`cts_common::claims::Claims`]: the server's
    /// view requires every claim it enforces (`org_id` among them), and failing
    /// an unverified client-side read of `workspace`/`iss` over a claim we never
    /// look at would turn a server-side rejection into a total client outage.
    fn decode_claims(&self) -> Result<ClientClaims, AuthError> {
        crate::decode_jwt_payload(self.access_token.as_str())
    }

    /// Fuzz-only entry point: run the JWT claims decode (`Token::decode_claims`)
    /// over an arbitrary string, discarding the claims and keeping only whether it
    /// succeeded. Gated on the `fuzz` feature so it never appears in normal builds.
    /// Reading claims from a token we already hold must never panic on a malformed
    /// token — only return `Err`. See `packages/stack-auth/fuzz`.
    ///
    /// `#[doc(hidden)]`: the `doc:stack-auth` task builds with `--all-features`,
    /// which enables `fuzz` — this keeps the shim out of the generated public docs.
    #[cfg(feature = "fuzz")]
    #[doc(hidden)]
    pub fn fuzz_decode_claims(token: &str) -> Result<(), AuthError> {
        Token {
            access_token: SecretToken::new(token),
            token_type: String::new(),
            expires_at: 0,
            refresh_token: None,
            region: None,
            client_id: None,
            device_instance_id: None,
        }
        .decode_claims()
        .map(|_| ())
    }

    /// Exchange a refresh token for a new [`Token`] via the `/oauth/token`
    /// endpoint.
    ///
    /// This is a static constructor — it takes a bare [`SecretToken`] (the
    /// refresh token) rather than operating on an existing `Token`. This
    /// allows callers to manage the refresh token lifecycle independently
    /// (e.g. taking it out of a cached token for cascade prevention and
    /// restoring it on failure).
    ///
    /// # Errors
    ///
    /// - [`AuthError::InvalidGrant`] — the refresh token was revoked or expired.
    /// - [`AuthError::InvalidClient`] — the client ID is not recognized.
    /// - [`AuthError::Request`] — a network error occurred.
    #[cfg(feature = "http")]
    pub async fn refresh(
        refresh_token: &SecretToken,
        base_url: &Url,
        client_id: &str,
        device_instance_id: Option<&str>,
    ) -> Result<Token, AuthError> {
        Self::refresh_with(
            &transport::default_transport(),
            refresh_token,
            base_url,
            client_id,
            device_instance_id,
        )
        .await
    }

    /// [`refresh`](Self::refresh) over a given transport: the form every
    /// build has, and the one the device-session refresher calls.
    pub(crate) async fn refresh_with(
        transport: &SharedTransport,
        refresh_token: &SecretToken,
        base_url: &Url,
        client_id: &str,
        device_instance_id: Option<&str>,
    ) -> Result<Token, AuthError> {
        let token_url = base_url.join("oauth/token")?;

        tracing::debug!(url = %token_url, "refreshing token");

        let resp = transport::post_form(
            transport,
            token_url,
            &RefreshRequest {
                grant_type: "refresh_token",
                client_id,
                refresh_token: refresh_token.as_str(),
                device_instance_id,
            },
        )
        .await?;

        if !resp.is_success() {
            let status = resp.status();

            // Read the body once as text and offer it to the shared classifier
            // before parsing. Two reasons this order matters: `resp.json()`
            // would turn a bodyless or non-JSON 402 into a decode error rather
            // than the usage limit it is, and routing every issuance path
            // through one classifier is what stops `/oauth/token` — the path
            // `DeviceSessionRefresher` delegates to — from disagreeing with
            // `/api/authorize` about what the same response means.
            let body = resp.text();
            tracing::debug!(%status, %body, "token refresh failed");

            if let Some(err) = crate::error::classify_issuance_failure(status, &body) {
                return Err(err);
            }

            let err: RefreshErrorResponse = serde_json::from_str(&body).map_err(|e| {
                AuthError::Server(crate::error::ServerError(format!(
                    "{status}: unparseable error body: {e}"
                )))
            })?;

            return Err(match err.error.as_str() {
                "invalid_grant" => AuthError::InvalidGrant(crate::error::InvalidGrant),
                "invalid_client" => AuthError::InvalidClient(crate::error::InvalidClient),
                "access_denied" => AuthError::AccessDenied(crate::error::AccessDenied),
                _ => AuthError::Server(crate::error::ServerError(err.error_description)),
            });
        }

        let token_resp: RefreshResponse = resp.json()?;

        Ok(Token {
            access_token: token_resp.access_token,
            token_type: token_resp.token_type,
            expires_at: now_unix_secs() + token_resp.expires_in,
            refresh_token: token_resp.refresh_token,
            region: None,
            client_id: None,
            // TODO(CIP-2793): The server should include device_instance_id in the
            // refresh response. Until then, callers (e.g. DeviceSessionRefresher) must
            // re-attach it manually after refresh.
            device_instance_id: None,
        })
    }
}

#[derive(serde::Serialize)]
struct RefreshRequest<'a> {
    grant_type: &'a str,
    client_id: &'a str,
    refresh_token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_instance_id: Option<&'a str>,
}

#[derive(serde::Deserialize)]
struct RefreshResponse {
    access_token: SecretToken,
    token_type: String,
    expires_in: u64,
    #[serde(default)]
    refresh_token: Option<SecretToken>,
}

/// The RFC 6749 error body, for failures the shared classifier declines.
///
/// `cs_code` is deliberately absent: `classify_issuance_failure` inspects it
/// on the raw body before this type is ever constructed, so duplicating the
/// field here would create a second place for the two to disagree.
#[derive(serde::Deserialize)]
struct RefreshErrorResponse {
    error: String,
    #[serde(default)]
    error_description: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{claims_with_workspace, jwt_token, raw_token};
    use crate::AuthError;

    fn make_token(expires_in: u64, refresh: bool) -> Token {
        Token {
            access_token: SecretToken::new("test-access-token"),
            token_type: "Bearer".to_string(),
            expires_at: now_unix_secs() + expires_in,
            refresh_token: if refresh {
                Some(SecretToken::new("test-refresh-token"))
            } else {
                None
            },
            region: None,
            client_id: None,
            device_instance_id: None,
        }
    }

    #[test]
    fn test_secret_token_debug_does_not_leak() {
        let token = SecretToken("super_secret_value".to_string());
        let debug = format!("{:?}", token);
        assert!(
            !debug.contains("super_secret_value"),
            "SecretToken Debug should not contain the secret, got: {debug}"
        );
    }

    // ---- is_expired_at / is_usable_at boundary tests ----

    /// A token with an explicit absolute `expires_at`, for driving the `*_at`
    /// predicates against precise boundary values (unlike `make_token`, which is
    /// relative to the wall clock).
    fn token_expiring_at(expires_at: u64) -> Token {
        Token {
            access_token: SecretToken::new("t"),
            token_type: "Bearer".to_string(),
            expires_at,
            refresh_token: None,
            region: None,
            client_id: None,
            device_instance_id: None,
        }
    }

    #[test]
    fn is_usable_at_boundary() {
        let t = token_expiring_at(1000);
        assert!(t.is_usable_at(999), "before expiry → usable");
        assert!(!t.is_usable_at(1000), "exactly at expiry → not usable");
        assert!(!t.is_usable_at(1001), "past expiry → not usable");
    }

    #[test]
    fn is_expired_at_leeway_window() {
        // EXPIRY_LEEWAY_SECS == 90: `is_expired_at` flips to true 90s ahead of
        // the real expiry timestamp so refresh is triggered preemptively.
        let t = token_expiring_at(1000);
        assert!(
            !t.is_expired_at(909),
            "just outside the 90s leeway → not expired"
        );
        assert!(t.is_expired_at(910), "exactly at the leeway edge → expired");
        // Inside the leeway window the token reads as "expired" (so a refresh is
        // triggered) yet is still usable — this is the expired-but-usable state
        // that drives AutoRefresh's non-blocking refresh path.
        assert!(
            t.is_expired_at(950) && t.is_usable_at(950),
            "inside the leeway: expired but still usable"
        );
    }

    /// The public, wall-clock predicates are what a caller holding a `Token`
    /// actually consults, so each is pinned on both sides of its edge — an
    /// hour either way of now, far outside the 90s leeway and any clock skew
    /// within one test.
    #[test]
    fn wall_clock_predicates_refuse_an_expired_token() {
        let expired = token_expiring_at(now_unix_secs() - 3600);
        assert!(expired.is_expired(), "an hour past expiry → expired");
        assert!(!expired.is_usable(), "an hour past expiry → not usable");

        let fresh = make_token(3600, false);
        assert!(!fresh.is_expired(), "an hour before expiry → not expired");
        assert!(fresh.is_usable(), "an hour before expiry → usable");
    }

    #[test]
    fn is_expired_at_saturates_near_u64_max() {
        // `is_expired_at` computes `now + EXPIRY_LEEWAY_SECS`; a plain add would
        // overflow and panic in debug builds. `test_support::raw_token` mints
        // tokens with `expires_at == u64::MAX`, so the saturating add must hold.
        let t = token_expiring_at(u64::MAX);
        assert!(
            t.is_expired_at(u64::MAX),
            "saturating_add must not overflow at the u64 ceiling"
        );
    }

    // ---- refresh() tests ----
    //
    // Grouped under one feature gate rather than one per item: every helper
    // and test below drives `Token::refresh` against a mock server, and both
    // only exist with `http`. `make_token` and
    // `test_refresh_debug_does_not_leak_tokens` deliberately stay outside —
    // `Debug` must not leak secrets in any build.
    #[cfg(feature = "http")]
    mod refresh_tests {
        use super::*;
        use mocktail::prelude::*;

        fn refresh_response_json() -> serde_json::Value {
            serde_json::json!({
                "access_token": "new-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "new-refresh-token"
            })
        }

        fn error_json(error: &str) -> serde_json::Value {
            serde_json::json!({
                "error": error,
                "error_description": format!("{error} occurred")
            })
        }

        async fn start_server(mocks: MockSet) -> MockServer {
            let server = MockServer::new_http("token-refresh-test").with_mocks(mocks);
            server.start().await.unwrap();
            server
        }

        #[tokio::test]
        async fn test_refresh_success() {
            let mut mocks = MockSet::new();
            mocks.mock(|when, then| {
                when.post().path("/oauth/token");
                then.json(refresh_response_json());
            });
            let server = start_server(mocks).await;
            let base_url = server.url("");

            let refresh_token = SecretToken::new("test-refresh-token");
            let refreshed = Token::refresh(&refresh_token, &base_url, "cli", None)
                .await
                .unwrap();

            assert_eq!(refreshed.access_token().as_str(), "new-access-token");
            assert_eq!(refreshed.token_type(), "Bearer");
            assert_eq!(
                refreshed.refresh_token().unwrap().as_str(),
                "new-refresh-token"
            );
            assert!(!refreshed.is_expired());
            assert!((3598..=3600).contains(&refreshed.expires_in()));
        }

        #[tokio::test]
        async fn test_refresh_invalid_grant() {
            let mut mocks = MockSet::new();
            mocks.mock(|when, then| {
                when.post().path("/oauth/token");
                then.bad_request().json(error_json("invalid_grant"));
            });
            let server = start_server(mocks).await;
            let base_url = server.url("");

            let refresh_token = SecretToken::new("test-refresh-token");
            let err = Token::refresh(&refresh_token, &base_url, "cli", None)
                .await
                .unwrap_err();

            assert!(matches!(err, AuthError::InvalidGrant(_)));
        }

        #[tokio::test]
        async fn test_refresh_invalid_client() {
            let mut mocks = MockSet::new();
            mocks.mock(|when, then| {
                when.post().path("/oauth/token");
                then.bad_request().json(error_json("invalid_client"));
            });
            let server = start_server(mocks).await;
            let base_url = server.url("");

            let refresh_token = SecretToken::new("test-refresh-token");
            let err = Token::refresh(&refresh_token, &base_url, "cli", None)
                .await
                .unwrap_err();

            assert!(matches!(err, AuthError::InvalidClient(_)));
        }

        #[tokio::test]
        async fn test_refresh_access_denied() {
            let mut mocks = MockSet::new();
            mocks.mock(|when, then| {
                when.post().path("/oauth/token");
                then.bad_request().json(error_json("access_denied"));
            });
            let server = start_server(mocks).await;
            let base_url = server.url("");

            let refresh_token = SecretToken::new("test-refresh-token");
            let err = Token::refresh(&refresh_token, &base_url, "cli", None)
                .await
                .unwrap_err();

            assert!(matches!(err, AuthError::AccessDenied(_)));
        }

        // ---- Usage-limit classification on the refresh path ----
        //
        // `/oauth/token` is the path `DeviceSessionRefresher` delegates to, so
        // these cases cover CLI login and dashboard refresh as well. They must
        // agree with `classify_issuance_failure`, which the other two issuance
        // paths use — the whole point of a shared classifier is that the same
        // server response cannot mean different things depending on which
        // refresher the caller happened to use.

        async fn refresh_against(
            status: reqwest::StatusCode,
            body: serde_json::Value,
        ) -> AuthError {
            let mut mocks = MockSet::new();
            mocks.mock(move |when, then| {
                when.post().path("/oauth/token");
                then.status(status).json(body.clone());
            });
            let server = start_server(mocks).await;
            let refresh_token = SecretToken::new("test-refresh-token");
            Token::refresh(&refresh_token, &server.url(""), "cli", None)
                .await
                .expect_err("a non-2xx refresh must fail")
        }

        #[tokio::test]
        async fn refresh_402_with_cs_code_is_usage_limit() {
            let err = refresh_against(
                reqwest::StatusCode::PAYMENT_REQUIRED,
                serde_json::json!({
                    "error": "access_denied",
                    "error_description": "Workspace has exceeded its usage limit",
                    "cs_code": "USAGE_LIMIT_EXCEEDED",
                }),
            )
            .await;

            assert_eq!(
                err.error_code(),
                crate::error::codes::USAGE_LIMIT_EXCEEDED,
                "cs_code must win over the registered access_denied code, or a usage \
                 limit reads as a permissions failure the user cannot act on",
            );
            assert!(
                err.to_string().contains("exceeded its usage limit"),
                "the server's description should survive verbatim, got {err}",
            );
        }

        #[tokio::test]
        async fn refresh_402_access_denied_without_cs_code_is_usage_limit() {
            let err = refresh_against(
                reqwest::StatusCode::PAYMENT_REQUIRED,
                serde_json::json!({"error": "access_denied"}),
            )
            .await;

            assert_eq!(
                err.error_code(),
                crate::error::codes::USAGE_LIMIT_EXCEEDED,
                "a CTS deployment predating cs_code still means usage limit at 402",
            );
        }

        /// Guards arm ORDER: `access_denied` only means "usage limit" at 402.
        #[tokio::test]
        async fn refresh_403_access_denied_is_still_access_denied() {
            let err = refresh_against(
                reqwest::StatusCode::FORBIDDEN,
                serde_json::json!({"error": "access_denied"}),
            )
            .await;

            assert!(
                matches!(err, AuthError::AccessDenied(_)),
                "a non-402 access_denied is a real authorization refusal, got {err:?}",
            );
        }

        /// Regression: this path used to parse the body as JSON *before* looking at
        /// the status, so a bodyless 402 surfaced as a reqwest decode error while
        /// the other two issuance paths classified it as a usage limit. Same server
        /// response, two different client errors.
        #[tokio::test]
        async fn refresh_402_with_empty_body_is_usage_limit() {
            let mut mocks = MockSet::new();
            mocks.mock(|when, then| {
                when.post().path("/oauth/token");
                then.status(reqwest::StatusCode::PAYMENT_REQUIRED);
            });
            let server = start_server(mocks).await;
            let refresh_token = SecretToken::new("test-refresh-token");

            let err = Token::refresh(&refresh_token, &server.url(""), "cli", None)
                .await
                .expect_err("a 402 must fail");

            assert_eq!(
                err.error_code(),
                crate::error::codes::USAGE_LIMIT_EXCEEDED,
                "must agree with classify_issuance_failure's bare-402 handling, got {err:?}",
            );
        }

        /// A 402 whose `cs_code` we cannot read must not claim a usage limit —
        /// mirrors `unreadable_cs_code_declines_to_classify` on the shared path.
        #[tokio::test]
        async fn refresh_402_with_unknown_cs_code_does_not_claim_usage_limit() {
            let err = refresh_against(
                reqwest::StatusCode::PAYMENT_REQUIRED,
                serde_json::json!({"error": "access_denied", "cs_code": "SOMETHING_ELSE"}),
            )
            .await;

            assert_ne!(
                err.error_code(),
                crate::error::codes::USAGE_LIMIT_EXCEEDED,
                "an unrecognised cs_code must not inherit the usage-limit classification",
            );
        }

        #[tokio::test]
        async fn test_refresh_unknown_error() {
            let mut mocks = MockSet::new();
            mocks.mock(|when, then| {
                when.post().path("/oauth/token");
                then.bad_request().json(error_json("something_unexpected"));
            });
            let server = start_server(mocks).await;
            let base_url = server.url("");

            let refresh_token = SecretToken::new("test-refresh-token");
            let err = Token::refresh(&refresh_token, &base_url, "cli", None)
                .await
                .unwrap_err();

            assert!(
                matches!(&err, AuthError::Server(crate::error::ServerError(desc)) if desc == "something_unexpected occurred")
            );
        }

        #[tokio::test]
        async fn test_refresh_response_without_new_refresh_token() {
            let mut mocks = MockSet::new();
            mocks.mock(|when, then| {
                when.post().path("/oauth/token");
                then.json(serde_json::json!({
                    "access_token": "new-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }));
            });
            let server = start_server(mocks).await;
            let base_url = server.url("");

            let refresh_token = SecretToken::new("test-refresh-token");
            let refreshed = Token::refresh(&refresh_token, &base_url, "cli", None)
                .await
                .unwrap();

            assert_eq!(refreshed.access_token().as_str(), "new-access-token");
            assert!(refreshed.refresh_token().is_none());
        }
    }

    // Deliberately not http-gated: `Debug` must not leak the secrets in any
    // build, including the no-default-features shape the WASI guest ships.
    #[tokio::test]
    async fn test_refresh_debug_does_not_leak_tokens() {
        let token = make_token(3600, true);
        let debug = format!("{:?}", token);
        assert!(
            !debug.contains("test-access-token"),
            "Debug output should not contain access token, got: {debug}"
        );
        assert!(
            !debug.contains("test-refresh-token"),
            "Debug output should not contain refresh token, got: {debug}"
        );
    }

    // ---- decode_claims / workspace_id / issuer tests ----

    fn valid_claims_json() -> serde_json::Value {
        claims_with_workspace("7366ITCXSAPCH5TN")
    }

    #[test]
    fn test_workspace_id_extracts_from_jwt() {
        let token = jwt_token(valid_claims_json());
        let ws = token.workspace_id().expect("should extract workspace ID");
        assert_eq!(ws.to_string(), "7366ITCXSAPCH5TN");
    }

    #[test]
    fn test_issuer_extracts_url_from_jwt() {
        let token = jwt_token(valid_claims_json());
        let issuer = token.issuer().expect("should extract issuer");
        assert_eq!(issuer.as_str(), "https://cts.example.com/");
    }

    #[test]
    fn test_workspace_id_fails_on_invalid_jwt() {
        let token = raw_token("not-a-jwt");
        let err = token.workspace_id().unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    #[test]
    fn test_issuer_fails_on_missing_claims() {
        let token = jwt_token(serde_json::json!({"sub": "user-123"}));
        let err = token.issuer().unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)));
    }

    /// The fuzz shim is the claim decoder, not a stub: the harness only
    /// checks it never panics, so this pins that it still reports the
    /// decoder's verdict both ways.
    #[cfg(feature = "fuzz")]
    #[test]
    fn fuzz_decode_claims_reports_the_decoders_verdict() {
        let valid = jwt_token(valid_claims_json());
        assert!(Token::fuzz_decode_claims(valid.access_token().as_str()).is_ok());
        assert!(matches!(
            Token::fuzz_decode_claims("not.a.jwt"),
            Err(AuthError::InvalidToken(_))
        ));
    }

    #[test]
    fn test_workspace_crn_derives_from_region_and_workspace() {
        let mut token = jwt_token(valid_claims_json());
        // Assign the field directly: `set_region` is http-only (the device-code
        // flow), but `workspace_crn` itself must stay covered without `http`.
        token.region = Some("ap-southeast-2.aws".into());
        let crn = token.workspace_crn().expect("should derive workspace CRN");
        assert_eq!(crn.to_string(), "crn:ap-southeast-2.aws:7366ITCXSAPCH5TN");
    }

    #[test]
    fn test_workspace_crn_fails_without_region() {
        let token = jwt_token(valid_claims_json());
        let err = token.workspace_crn().unwrap_err();
        assert!(matches!(err, AuthError::NotAuthenticated(_)));
    }

    #[test]
    fn test_workspace_crn_fails_with_invalid_region() {
        let mut token = jwt_token(valid_claims_json());
        token.region = Some("invalid-region".into());
        let err = token.workspace_crn().unwrap_err();
        assert!(matches!(err, AuthError::Server(_)));
    }

    /// `org_id` is required *server-side*, where the signature is verified
    /// first. This decode path verifies nothing and reads only `workspace` and
    /// `iss`, so a token minted before `org_id` existed — or by a CTS rolled
    /// back past the commit that added it — must still resolve both.
    #[test]
    fn workspace_id_and_issuer_resolve_without_org_id() {
        let mut claims = valid_claims_json();
        claims
            .as_object_mut()
            .expect("claims fixture is a JSON object")
            .remove("org_id");
        let token = jwt_token(claims);

        assert_eq!(
            token
                .workspace_id()
                .expect("workspace must decode without org_id")
                .to_string(),
            "7366ITCXSAPCH5TN"
        );
        assert_eq!(
            token
                .issuer()
                .expect("iss must decode without org_id")
                .as_str(),
            "https://cts.example.com/"
        );
    }
}
