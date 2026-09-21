#![doc(html_favicon_url = "https://cipherstash.com/favicon.ico")]
// The README is the crate's front page, but nearly all of it — the strategy
// table, the quick-start examples, the links — is about the bundled HTTP
// strategies, which only exist with `http`. Including it unconditionally would
// leave a no-http build documenting (and doctesting) an API it does not have.
#![cfg_attr(feature = "http", doc = include_str!("../README.md"))]
#![cfg_attr(
    not(feature = "http"),
    doc = "Authentication strategies for [CipherStash](https://cipherstash.com) services."
)]
#![cfg_attr(
    not(feature = "http"),
    doc = "\nWithout the `http` feature this crate has no HTTP client of its own: the\
 strategies (`AutoStrategy`, `AccessKeyStrategy`, `DeviceSessionStrategy`,\
 `OidcFederationStrategy`) and the refresh engine are all here, and each\
 builder must be given an [`HttpTransport`] — how a host with its own\
 transport (a wasm module, say) runs them. [`AuthStrategyFn`] and\
 [`TokenStoreFn`] remain the escape hatches for acquisition and persistence\
 done entirely on the host's side. Enable the `http` feature for the bundled\
 `ReqwestTransport`, the native device-code flow, and the crate's full\
 documentation."
)]
// Security lints
#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]
#![warn(clippy::panic)]
// Prevent mem::forget from bypassing ZeroizeOnDrop
#![warn(clippy::mem_forget)]
// Prevent accidental data leaks via output
#![warn(clippy::print_stdout)]
#![warn(clippy::print_stderr)]
#![warn(clippy::dbg_macro)]
// Code quality
#![warn(unreachable_pub)]
#![warn(unused_results)]
#![warn(clippy::todo)]
#![warn(clippy::unimplemented)]
// Without `http` the crate has no HTTP client, not no strategies: `http` is
// the bundled `ReqwestTransport` and the two native flows that use it
// unconditionally (device binding, device code). Everything that needs
// reqwest by name carries its own `#[cfg(feature = "http")]` gate rather
// than a crate-wide `allow(dead_code)`, so the compiler verifies the
// partition in both directions.
// Relax in tests
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]
#![cfg_attr(test, allow(clippy::panic))]
#![cfg_attr(test, allow(unused_results))]

use std::future::Future;
use vitaminc::protected::OpaqueDebug;
use zeroize::ZeroizeOnDrop;

mod access_key;
mod auth_strategy_fn;
mod clock;
mod error;
mod service_token;
mod token;
mod token_store;
mod transport;

// The strategies that acquire and refresh tokens over HTTP, and the refresh
// engine they share. In every build: they send through whatever
// `HttpTransport` their builder was given, and only the bundled
// `ReqwestTransport` (their default) is behind the `http` feature.
mod access_key_refresher;
mod access_key_strategy;
mod authorize_dto;
mod auto_refresh;
mod auto_strategy;
mod device_session_refresher;
mod device_session_strategy;
mod oidc_federation_strategy;
mod oidc_refresher;
mod refresher;

#[cfg(not(target_arch = "wasm32"))]
pub use error::StoreError;
pub use error::{
    AccessDenied, AlreadyConsumed, AuthError, AuthErrorKind, CustomError, InternalError,
    InvalidAccessKeyError, InvalidClient, InvalidCrn, InvalidGrant, InvalidToken, InvalidUrl,
    InvalidWorkspaceId, MissingWorkspaceCrn, NotAuthenticated, OrgNotProvisioned, RequestError,
    ServerError, TokenExpired, UnsupportedRegion, UsageLimitExceeded, WorkspaceMismatch,
};

// Filesystem-backed device identity and the interactive device-code flow are
// native-only — both pull `stack-profile` (which uses `dirs` + `gethostname`)
// and the device-code flow launches a browser via `open::that`. Wasm consumers
// use `DeviceSessionStrategy::with_token` or `AccessKeyStrategy`.
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
mod device_client;
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
mod device_code;

#[cfg(any(test, feature = "test-utils"))]
mod static_token_strategy;

#[cfg(test)]
mod test_support;

pub use access_key::{AccessKey, InvalidAccessKey};
pub use access_key_strategy::{AccessKeyStrategy, AccessKeyStrategyBuilder};
pub use auth_strategy_fn::AuthStrategyFn;
pub use auto_strategy::{AutoStrategy, AutoStrategyBuilder};
pub use device_session_strategy::{DeviceSessionStrategy, DeviceSessionStrategyBuilder};
pub use oidc_federation_strategy::{OidcFederationStrategy, OidcFederationStrategyBuilder};
pub use oidc_refresher::{OidcProvider, OidcProviderFn};
pub use service_token::ServiceToken;
#[cfg(any(test, feature = "test-utils"))]
pub use static_token_strategy::StaticTokenStrategy;
pub use token::Token;
pub use token_store::{InMemoryTokenStore, NoStore, TokenStore, TokenStoreFn};
#[cfg(feature = "http")]
pub use transport::ReqwestTransport;
pub use transport::{HttpRequest, HttpResponse, HttpTransport};

/// Deprecated alias for [`DeviceSessionStrategy`].
///
/// Renamed to make the *renewal* (existing CTS session) vs *federation*
/// ([`OidcFederationStrategy`]) distinction explicit. The old name still
/// resolves so existing code keeps compiling; it will be removed in a future
/// major release.
#[deprecated(since = "0.36.0", note = "renamed to `DeviceSessionStrategy`")]
pub type OAuthStrategy = DeviceSessionStrategy;

/// Deprecated alias for [`DeviceSessionStrategyBuilder`].
#[deprecated(since = "0.36.0", note = "renamed to `DeviceSessionStrategyBuilder`")]
pub type OAuthStrategyBuilder = DeviceSessionStrategyBuilder;

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use device_client::{bind_client_device, DeviceClientError};
#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
pub use device_code::{DeviceCodeStrategy, DeviceCodeStrategyBuilder, PendingDeviceCode};

// Re-exports from stack-profile for backward compatibility.
#[cfg(not(target_arch = "wasm32"))]
pub use stack_profile::DeviceIdentity;

/// The workspace CRN every strategy is bound to, re-exported from
/// `cts-common`.
///
/// A strategy built by hand takes one — `AccessKeyStrategy::new(crn, key)`,
/// `OidcFederationStrategy::new(crn, provider)` — so a caller that names its
/// own strategy needs this type and nothing else from `cts-common`. Its
/// region drives service discovery and its workspace id verifies every
/// token issued.
pub use cts_common::Crn;

/// Token *acquisition* — strategies that produce a [`ServiceToken`].
///
/// Use [`AuthStrategy`] as the consumer-facing trait (e.g. when wiring
/// strategies into `cipherstash-client`). [`AuthStrategyFn`] is the
/// closure-shaped impl for callers that source tokens externally
/// (FFI, custom IPC).
///
/// For the *persistence layer* — pluggable storage that slots into an
/// existing strategy — see [`crate::store`].
///
/// All items in this module are also re-exported at the crate root.
pub mod auth {
    pub use crate::{
        AccessKey, AuthError, AuthStrategy, AuthStrategyBounds, AuthStrategyFn, HttpRequest,
        HttpResponse, HttpTransport, InvalidAccessKey, SecretToken, ServiceToken,
    };

    #[cfg(feature = "http")]
    pub use crate::ReqwestTransport;

    pub use crate::{
        AccessKeyStrategy, AccessKeyStrategyBuilder, AutoStrategy, AutoStrategyBuilder,
        DeviceSessionStrategy, DeviceSessionStrategyBuilder, OidcFederationStrategy,
        OidcFederationStrategyBuilder, OidcProvider, OidcProviderFn,
    };

    #[cfg(not(target_arch = "wasm32"))]
    pub use crate::DeviceIdentity;

    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    pub use crate::{
        bind_client_device, DeviceClientError, DeviceCodeStrategy, DeviceCodeStrategyBuilder,
        PendingDeviceCode,
    };

    #[cfg(any(test, feature = "test-utils"))]
    pub use crate::StaticTokenStrategy;

    // Deprecated aliases, re-exported here too so `stack_auth::auth::OAuthStrategy`
    // consumers keep compiling alongside the crate-root aliases. See the
    // `OAuthStrategy` / `OAuthStrategyBuilder` definitions at the crate root.
    #[allow(deprecated)]
    pub use crate::{OAuthStrategy, OAuthStrategyBuilder};
}

/// Token *persistence* — pluggable backends for the service-token cache.
///
/// Use [`TokenStore`] as the trait, [`TokenStoreFn`] for closure-shaped
/// impls (cookies, KV blobs, Redis), and [`InMemoryTokenStore`] / [`NoStore`]
/// for ready-made implementations.
///
/// A `TokenStore` plugs into a concrete strategy via that strategy's
/// builder — it does *not* replace the strategy. For full token acquisition
/// (custom fetcher, FFI-hosted strategy), see [`crate::auth`].
///
/// For example, [`AccessKeyStrategyBuilder::with_token_store`](crate::AccessKeyStrategyBuilder::with_token_store).
///
/// All items in this module are also re-exported at the crate root.
pub mod store {
    pub use crate::{InMemoryTokenStore, NoStore, Token, TokenStore, TokenStoreFn};
}

/// A strategy for obtaining access tokens.
///
/// Implementations handle all details of authentication, token caching, and
/// refresh. Callers just call [`get_token`](AuthStrategy::get_token) whenever
/// they need a valid token.
///
/// The trait is designed to be implemented for `&T`, so that callers can use
/// shared references (e.g. `&DeviceSessionStrategy`) without consuming the strategy.
///
/// # Token refresh
///
/// All strategies that cache tokens ([`AccessKeyStrategy`], [`DeviceSessionStrategy`],
/// [`AutoStrategy`]) share the same internal refresh engine. Understanding the
/// refresh model helps predict how [`get_token`](AuthStrategy::get_token)
/// behaves under concurrent access.
///
/// ## Expiry vs usability
///
/// A token has two time thresholds:
///
/// - **Expired** — the token is within **90 seconds** of its `expires_at`
///   timestamp. This triggers a preemptive refresh attempt.
/// - **Usable** — the token has **not yet reached** its `expires_at` timestamp.
///   A token can be "expired" (in the preemptive sense) but still "usable"
///   (the server will still accept it).
///
/// ## Concurrent refresh strategies
///
/// The gap between "expired" and "unusable" enables two refresh modes:
///
/// 1. **Expiring but still usable** — The first caller triggers a background
///    refresh. Concurrent callers receive the current (still-valid) token
///    immediately without blocking.
/// 2. **Fully expired** — The first caller blocks while refreshing. Concurrent
///    callers wait until the refresh completes, then all receive the new token.
///
/// Only one refresh runs at a time, regardless of how many callers request a
/// token concurrently.
///
/// ## Flow diagram
///
/// ```mermaid
/// flowchart TD
///     Start["get_token()"] --> Lock["Acquire lock"]
///     Lock --> Cached{Token cached?}
///     Cached -- No --> InitAuth["Authenticate
///     (lock held)"]
///     InitAuth -- OK --> ReturnNew["Return new token"]
///     InitAuth -- NotFound --> ErrNotFound["NotAuthenticated"]
///     InitAuth -- Err --> ErrAuth["Return error"]
///     Cached -- Yes --> CheckRefresh{Expired?}
///
///     CheckRefresh -- "No (fresh)" --> ReturnOk["Return cached token"]
///
///     CheckRefresh -- "Yes (needs refresh)" --> InProgress{Refresh in progress?}
///     InProgress -- Yes --> WaitOrReturn["Return token if usable,
///     else wait for refresh"]
///     WaitOrReturn -- OK --> ReturnOk
///     WaitOrReturn -- "refresh failed" --> ErrExpired["TokenExpired"]
///
///     InProgress -- No --> HasCred{Refresh credential?}
///     HasCred -- None --> CheckUsable["Return token if usable,
///     else TokenExpired"]
///
///     HasCred -- Yes --> Usable{Still usable?}
///
///     Usable -- "Yes (preemptive)" --> NonBlocking["Refresh in background
///     (lock released)"]
///     NonBlocking --> ReturnOld["Return current token"]
///
///     Usable -- "No (fully expired)" --> Blocking["Refresh
///     (lock held)"]
///     Blocking -- OK --> ReturnNew2["Return new token"]
///     Blocking -- Err --> ErrExpired["TokenExpired"]
/// ```
#[cfg_attr(doc, aquamarine::aquamarine)]
#[cfg(not(target_arch = "wasm32"))]
pub trait AuthStrategy: Send {
    /// Retrieve a valid access token, refreshing or re-authenticating as needed.
    fn get_token(self) -> impl Future<Output = Result<ServiceToken, AuthError>> + Send;
}

/// Wasm32 variant of [`AuthStrategy`] — drops the `Send` bounds because
/// reqwest's fetch-backed futures aren't `Send` and edge runtimes are
/// single-threaded.
#[cfg(target_arch = "wasm32")]
pub trait AuthStrategy {
    /// Retrieve a valid access token, refreshing or re-authenticating as needed.
    fn get_token(self) -> impl Future<Output = Result<ServiceToken, AuthError>>;
}

/// Marker trait alias for the bounds an owned `AuthStrategy`-providing
/// credential type `C` must satisfy when held inside a long-lived client
/// (e.g. `cipherstash_client::ZeroKMS<C>` shared across requests).
///
/// - On native targets `C` must be `Send + Sync + 'static` so the client
///   can be carried across tokio task / `reqwest` worker boundaries.
/// - On `wasm32` the runtime is single-threaded and the typical credential
///   backing (a JS callable held by a `JsValue`) cannot cross threads
///   even in principle, so the `Send + Sync` requirement is dropped and
///   only `'static` remains.
///
/// Implemented via a blanket impl — any type satisfying the per-target
/// bounds automatically implements `AuthStrategyBounds`. Callers don't
/// implement it directly.
///
/// Mirrors the `cfg`-split already in place on [`AuthStrategy`] itself,
/// one layer up. Wasm consumers (e.g. `@cipherstash/protect-ffi` on
/// `wasm32-unknown-unknown`) can hold a `!Send + !Sync` credential type
/// without declaring `unsafe impl Send` / `Sync`.
#[cfg(not(target_arch = "wasm32"))]
pub trait AuthStrategyBounds: Send + Sync + 'static {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send + Sync + 'static> AuthStrategyBounds for T {}

#[cfg(target_arch = "wasm32")]
pub trait AuthStrategyBounds: 'static {}
#[cfg(target_arch = "wasm32")]
impl<T: 'static> AuthStrategyBounds for T {}

/// A sensitive token string that is zeroized on drop and hidden from debug output.
///
/// `SecretToken` wraps a `String` and enforces two invariants:
///
/// - **Zeroized on drop**: the backing memory is overwritten with zeros when
///   the token goes out of scope, preventing it from lingering in memory.
/// - **Opaque debug**: the [`Debug`] implementation prints `"***"` instead of
///   the actual value, so tokens won't leak into logs or error messages.
///
/// Use [`SecretToken::new`] to wrap a string value (e.g. an access key
/// loaded from configuration or an environment variable).
#[derive(Clone, OpaqueDebug, ZeroizeOnDrop, serde::Deserialize, serde::Serialize)]
#[serde(transparent)]
pub struct SecretToken(String);

impl SecretToken {
    /// Create a new `SecretToken` from a string value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Expose the inner token string for FFI boundaries.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Read the `CS_CTS_HOST` environment variable and parse it as a URL.
///
/// Returns `Ok(None)` if the variable is not set or empty.
/// Returns `Ok(Some(url))` if the variable is set and valid.
/// Returns `Err(_)` if the variable is set but not a valid URL.
pub(crate) fn cts_base_url_from_env() -> Result<Option<url::Url>, AuthError> {
    match std::env::var("CS_CTS_HOST") {
        Ok(val) if !val.is_empty() => Ok(Some(val.parse()?)),
        _ => Ok(None),
    }
}

/// Ensure a URL has a trailing slash so that `Url::join` with relative paths
/// appends to the path rather than replacing the last segment.
pub(crate) fn ensure_trailing_slash(mut url: url::Url) -> url::Url {
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    url
}

/// Decode a JWT payload by splitting on `.`, base64-decoding the middle
/// segment, and deserializing the JSON. Signatures are **not** verified — we
/// only ever read claims from a token we already hold.
///
/// This is the single decode path on every target. It deliberately avoids
/// `jsonwebtoken`: on wasm32 that crate pulls `ring` (which won't build), and on
/// native, `jsonwebtoken` 10 rejects any token whose header carries a non-string
/// field (e.g. Clerk's `srf: true`) before it even looks at the claims.
pub(crate) fn decode_jwt_payload<C>(token: &str) -> Result<C, AuthError>
where
    C: serde::de::DeserializeOwned,
{
    use base64::Engine;
    let segments: Vec<&str> = token.split('.').collect();
    if segments.len() != 3 {
        return Err(AuthError::InvalidToken(error::InvalidToken(
            "JWT must have three segments".to_string(),
        )));
    }
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segments[1])
        .map_err(|e| {
            AuthError::InvalidToken(error::InvalidToken(format!("base64 decode failed: {e}")))
        })?;
    serde_json::from_slice(&payload).map_err(|e| {
        AuthError::InvalidToken(error::InvalidToken(format!(
            "failed to decode JWT claims: {e}"
        )))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `error_code` strings are a stable contract surfaced across FFI
    /// (JS `Error.code`, Node-API codes), so pin every variant's code. If a
    /// new variant is added without a code, `error_code`'s exhaustive `kind()`
    /// dispatch fails to compile, so the contract can't silently drift.
    ///
    /// Also pins [`AuthError::ERROR_CODES`] against what `error_code` actually
    /// returns: every constructed variant's code must be declared there, and
    /// `ERROR_CODES` must hold exactly those codes. So the list can't grow
    /// stale entries or omit a real one — which is what the binding crates'
    /// union tests trust.
    #[test]
    #[allow(clippy::unwrap_used)]
    fn auth_error_code_is_stable_for_every_variant() {
        use std::collections::BTreeSet;

        let workspace = "ZVATKW3VHMFG27DY"
            .parse::<cts_common::WorkspaceId>()
            .unwrap();

        let cases: Vec<(AuthError, &str)> = vec![
            (
                AuthError::AccessDenied(crate::error::AccessDenied),
                "ACCESS_DENIED",
            ),
            (
                AuthError::TokenExpired(crate::error::TokenExpired),
                "EXPIRED_TOKEN",
            ),
            (
                AuthError::InvalidGrant(crate::error::InvalidGrant),
                "INVALID_GRANT",
            ),
            (
                AuthError::InvalidClient(crate::error::InvalidClient),
                "INVALID_CLIENT",
            ),
            (
                AuthError::NotAuthenticated(crate::error::NotAuthenticated),
                "NOT_AUTHENTICATED",
            ),
            (
                AuthError::MissingWorkspaceCrn(crate::error::MissingWorkspaceCrn),
                "MISSING_WORKSPACE_CRN",
            ),
            (
                AuthError::AlreadyConsumed(crate::error::AlreadyConsumed),
                "ALREADY_CONSUMED",
            ),
            (
                AuthError::Server(crate::error::ServerError("boom".into())),
                "SERVER_ERROR",
            ),
            (
                AuthError::Internal(crate::error::InternalError("boom".into())),
                "INTERNAL_ERROR",
            ),
            (
                AuthError::InvalidToken(crate::error::InvalidToken("malformed".into())),
                "INVALID_TOKEN",
            ),
            (
                AuthError::OrgNotProvisioned(crate::error::OrgNotProvisioned(
                    "not provisioned".into(),
                )),
                "ORG_NOT_PROVISIONED",
            ),
            (
                AuthError::UsageLimitExceeded(crate::error::UsageLimitExceeded(
                    "over limit".into(),
                )),
                "USAGE_LIMIT_EXCEEDED",
            ),
            (
                AuthError::Custom(crate::error::CustomError("boom".into())),
                "CUSTOM",
            ),
            (
                AuthError::Request(crate::error::RequestError(Box::new(std::io::Error::other(
                    "connection refused",
                )))),
                "REQUEST_ERROR",
            ),
            (
                AuthError::from("not a url".parse::<url::Url>().unwrap_err()),
                "INVALID_URL",
            ),
            (
                AuthError::from("not-a-region".parse::<cts_common::Region>().unwrap_err()),
                "INVALID_REGION",
            ),
            (
                AuthError::from("not-a-crn".parse::<cts_common::Crn>().unwrap_err()),
                "INVALID_CRN",
            ),
            (
                AuthError::from("!".parse::<cts_common::WorkspaceId>().unwrap_err()),
                "INVALID_WORKSPACE_ID",
            ),
            (
                AuthError::from("".parse::<crate::access_key::AccessKey>().unwrap_err()),
                "INVALID_ACCESS_KEY",
            ),
            (
                AuthError::WorkspaceMismatch(crate::error::WorkspaceMismatch {
                    expected_workspace: workspace,
                    token_workspace: workspace,
                }),
                "WORKSPACE_MISMATCH",
            ),
            #[cfg(not(target_arch = "wasm32"))]
            (
                AuthError::from(stack_profile::ProfileError::HomeDirNotFound),
                "STORE_ERROR",
            ),
        ];

        let declared: BTreeSet<&str> = AuthError::ERROR_CODES.iter().copied().collect();

        let mut from_variants: BTreeSet<&str> = BTreeSet::new();
        for (err, expected) in cases {
            assert_eq!(err.error_code(), expected, "error_code for {err:?}");
            assert!(
                declared.contains(expected),
                "{expected} is returned by error_code() but missing from AuthError::ERROR_CODES",
            );
            from_variants.insert(expected);
        }

        assert_eq!(
            declared, from_variants,
            "AuthError::ERROR_CODES drifted from the codes error_code() returns",
        );
    }

    /// `from_error_code` reconstructs the fixed-message unit variants and
    /// `WORKSPACE_MISMATCH` (from its payload) to their own code, and everything
    /// else — message-carrying, foreign-wrapping, or unrecognised codes — to
    /// `Custom`, preserving the message verbatim.
    #[test]
    fn from_error_code_maps_known_codes_and_falls_back_to_custom() {
        use crate::AuthErrorKind;

        let empty = serde_json::Map::new();

        for code in [
            "NOT_AUTHENTICATED",
            "EXPIRED_TOKEN",
            "ACCESS_DENIED",
            "INVALID_GRANT",
            "INVALID_CLIENT",
            "MISSING_WORKSPACE_CRN",
            "ALREADY_CONSUMED",
        ] {
            let err = AuthError::from_error_code(code, "unused for unit variants", &empty);
            assert_eq!(err.error_code(), code, "unit code should round-trip");
            assert!(
                !matches!(err, AuthError::Custom(_)),
                "{code} should map to its typed variant, not Custom",
            );
        }

        // WORKSPACE_MISMATCH rebuilds from the exact `payload()` it serialized
        // with — round-tripping the code (message is re-derived from the fields).
        let workspace = "ZVATKW3VHMFG27DY"
            .parse::<cts_common::WorkspaceId>()
            .unwrap();
        let payload = crate::error::WorkspaceMismatch {
            expected_workspace: workspace,
            token_workspace: workspace,
        }
        .payload();
        let err = AuthError::from_error_code("WORKSPACE_MISMATCH", "unused", &payload);
        assert_eq!(err.error_code(), "WORKSPACE_MISMATCH");
        assert!(!matches!(err, AuthError::Custom(_)));

        // A message-carrying variant, a foreign-wrapping one, WORKSPACE_MISMATCH
        // with no usable payload, and an unrecognised code all collapse to Custom
        // with the message kept as-is (no double-applied `Display` prefix).
        for code in [
            "SERVER_ERROR",
            "REQUEST_ERROR",
            "WORKSPACE_MISMATCH",
            "SOME_UNRECOGNISED_CODE",
        ] {
            let err = AuthError::from_error_code(code, "Server error: boom", &empty);
            assert_eq!(err.error_code(), "CUSTOM", "{code} should map to Custom");
            assert_eq!(
                err.to_string(),
                "Server error: boom",
                "Custom preserves the wire message verbatim",
            );
        }
    }

    /// Every variant annotated with `#[diagnostic(help(..))]` must surface that
    /// help through `miette::Diagnostic` — it's what the CLI renders below the
    /// error message. Unlike `error_code`'s exhaustive match, `help` is optional
    /// and silently compiles if dropped, so pin all six (and a couple of
    /// un-annotated variants that must stay `None`) explicitly.
    #[test]
    fn annotated_variants_expose_diagnostic_help() {
        use miette::Diagnostic;

        let workspace = "ZVATKW3VHMFG27DY"
            .parse::<cts_common::WorkspaceId>()
            .unwrap();

        // (variant, substring its help must contain) — one row per annotation.
        let with_help: Vec<(AuthError, &str)> = vec![
            (
                AuthError::from("not-a-region".parse::<cts_common::Region>().unwrap_err()),
                "supported region",
            ),
            (
                AuthError::from("not-a-crn".parse::<cts_common::Crn>().unwrap_err()),
                "crn:<region>:<workspace-id>",
            ),
            (
                AuthError::WorkspaceMismatch(crate::error::WorkspaceMismatch {
                    expected_workspace: workspace,
                    token_workspace: workspace,
                }),
                "different workspace",
            ),
            (
                AuthError::MissingWorkspaceCrn(crate::error::MissingWorkspaceCrn),
                "CS_WORKSPACE_CRN",
            ),
            (
                AuthError::NotAuthenticated(crate::error::NotAuthenticated),
                "stash login",
            ),
            (
                AuthError::from("".parse::<crate::access_key::AccessKey>().unwrap_err()),
                "CSAK<key-id>.<secret>",
            ),
        ];

        for (err, substring) in with_help {
            let help = err.help().map(|h| h.to_string());
            assert!(
                help.as_deref().is_some_and(|h| h.contains(substring)),
                "{err:?} should carry help containing {substring:?}, got: {help:?}",
            );
        }

        // Un-annotated variants must report no help — keeps the contract
        // symmetric so a stray annotation doesn't slip in unnoticed.
        for err in [
            AuthError::TokenExpired(crate::error::TokenExpired),
            AuthError::InvalidToken(crate::error::InvalidToken("malformed".to_string())),
        ] {
            assert!(
                err.help().is_none(),
                "{err:?} has no #[diagnostic(help)] and should report None",
            );
        }
    }
}
