//! Authentication error types.
//!
//! [`AuthError`] is the single canonical error enum. Each variant wraps a
//! dedicated struct that owns its `Display` message, `miette` diagnostic
//! (`help`/`url`) and machine-readable code, plus any structured payload — so
//! per-error logic lives with the error rather than in one central function.
//!
//! The enum is a thin dispatcher: `Display`/`Diagnostic` delegate to the inner
//! struct via `transparent`, and [`AuthError::error_code`] / the `Serialize`
//! impl delegate through `AuthError::kind`. Ergonomic `From<Foreign>` impls
//! keep `?` working at call sites that lift a foreign error directly.

use std::convert::Infallible;

use crate::access_key;

/// Behaviour shared by every concrete error wrapped in an [`AuthError`] variant.
///
/// Implemented by the per-error structs so each owns its FFI code and any
/// structured payload; [`AuthError`] dispatches to it via `AuthError::kind`.
pub trait AuthErrorKind: std::error::Error + miette::Diagnostic {
    /// Stable machine-readable identifier surfaced across FFI boundaries
    /// (e.g. JS `Error.code`). Named `error_code` to avoid colliding with
    /// `miette::Diagnostic::code`, inherited via the `Diagnostic` supertrait.
    fn error_code(&self) -> &'static str;

    /// Extra structured fields for the FFI/TS failure payload, beyond the
    /// `type`/`message`/`help`/`url` the enum emits generically. None by default.
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        serde_json::Map::new()
    }
}

/// The stable machine-readable error codes surfaced across FFI (JS `Error.code`,
/// the `AuthFailure` TS unions). Defined once here so each
/// [`AuthErrorKind::error_code`] impl and the [`AuthError::ERROR_CODES`] list
/// reference the same constant rather than repeating a magic string; a code
/// only ever changes in one place. `auth_error_code_is_stable_for_every_variant`
/// pins that every variant maps to one of these and that the list is exhaustive.
pub(crate) mod codes {
    pub(crate) const REQUEST_ERROR: &str = "REQUEST_ERROR";
    pub(crate) const ACCESS_DENIED: &str = "ACCESS_DENIED";
    pub(crate) const INVALID_GRANT: &str = "INVALID_GRANT";
    pub(crate) const INVALID_CLIENT: &str = "INVALID_CLIENT";
    pub(crate) const INVALID_URL: &str = "INVALID_URL";
    pub(crate) const INVALID_REGION: &str = "INVALID_REGION";
    pub(crate) const INVALID_CRN: &str = "INVALID_CRN";
    pub(crate) const WORKSPACE_MISMATCH: &str = "WORKSPACE_MISMATCH";
    pub(crate) const INVALID_WORKSPACE_ID: &str = "INVALID_WORKSPACE_ID";
    pub(crate) const MISSING_WORKSPACE_CRN: &str = "MISSING_WORKSPACE_CRN";
    pub(crate) const NOT_AUTHENTICATED: &str = "NOT_AUTHENTICATED";
    pub(crate) const EXPIRED_TOKEN: &str = "EXPIRED_TOKEN";
    pub(crate) const INVALID_ACCESS_KEY: &str = "INVALID_ACCESS_KEY";
    pub(crate) const INVALID_TOKEN: &str = "INVALID_TOKEN";
    pub(crate) const SERVER_ERROR: &str = "SERVER_ERROR";
    pub(crate) const ALREADY_CONSUMED: &str = "ALREADY_CONSUMED";
    pub(crate) const INTERNAL_ERROR: &str = "INTERNAL_ERROR";
    pub(crate) const CUSTOM: &str = "CUSTOM";
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) const STORE_ERROR: &str = "STORE_ERROR";
}

// ---------------------------------------------------------------------------
// Per-error structs
// ---------------------------------------------------------------------------

/// The HTTP request to the auth server failed (network error, timeout, etc.).
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("HTTP request failed: {0}")]
pub struct RequestError(pub reqwest::Error);
impl AuthErrorKind for RequestError {
    fn error_code(&self) -> &'static str {
        codes::REQUEST_ERROR
    }
}

/// The user denied the authorization request.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Authorization was denied")]
pub struct AccessDenied;
impl AuthErrorKind for AccessDenied {
    fn error_code(&self) -> &'static str {
        codes::ACCESS_DENIED
    }
}

/// The grant type was rejected by the server.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Invalid grant")]
pub struct InvalidGrant;
impl AuthErrorKind for InvalidGrant {
    fn error_code(&self) -> &'static str {
        codes::INVALID_GRANT
    }
}

/// The client ID is not recognized.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Invalid client")]
pub struct InvalidClient;
impl AuthErrorKind for InvalidClient {
    fn error_code(&self) -> &'static str {
        codes::INVALID_CLIENT
    }
}

/// A URL could not be parsed.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Invalid URL: {0}")]
pub struct InvalidUrl(pub url::ParseError);
impl AuthErrorKind for InvalidUrl {
    fn error_code(&self) -> &'static str {
        codes::INVALID_URL
    }
}

/// The requested region is not supported.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Unsupported region: {0}")]
#[diagnostic(help("Use a supported region, e.g. `ap-southeast-2.aws`."))]
pub struct UnsupportedRegion(pub cts_common::RegionError);
impl AuthErrorKind for UnsupportedRegion {
    fn error_code(&self) -> &'static str {
        codes::INVALID_REGION
    }
}

/// The workspace CRN could not be parsed.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Invalid workspace CRN: {0}")]
#[diagnostic(help(
    "A workspace CRN looks like `crn:<region>:<workspace-id>`, e.g. `crn:ap-southeast-2.aws:ZVATKW3VHMFG27DY`."
))]
pub struct InvalidCrn(pub cts_common::InvalidCrn);
impl AuthErrorKind for InvalidCrn {
    fn error_code(&self) -> &'static str {
        codes::INVALID_CRN
    }
}

/// The token issued by the auth server is for a different workspace than the
/// one configured on the strategy. Surfaces when the access key was minted for
/// a different workspace, or when the wrong CRN was passed.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Workspace mismatch: token issued for {token_workspace}, but strategy is configured for {expected_workspace}")]
#[diagnostic(help(
    "The access key or workspace CRN is scoped to a different workspace than the one requested — check which workspace the credential belongs to."
))]
pub struct WorkspaceMismatch {
    /// The workspace the strategy was configured for (from the CRN).
    pub expected_workspace: cts_common::WorkspaceId,
    /// The workspace the auth server's token actually carries.
    pub token_workspace: cts_common::WorkspaceId,
}
impl AuthErrorKind for WorkspaceMismatch {
    fn error_code(&self) -> &'static str {
        codes::WORKSPACE_MISMATCH
    }
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        [
            (
                "expected".to_string(),
                self.expected_workspace.to_string().into(),
            ),
            (
                "actual".to_string(),
                self.token_workspace.to_string().into(),
            ),
        ]
        .into_iter()
        .collect()
    }
}

/// The workspace ID could not be parsed.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Invalid workspace ID: {0}")]
pub struct InvalidWorkspaceId(pub cts_common::InvalidWorkspaceId);
impl AuthErrorKind for InvalidWorkspaceId {
    fn error_code(&self) -> &'static str {
        codes::INVALID_WORKSPACE_ID
    }
}

/// An access key was provided but the workspace CRN is missing.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error(
    "Workspace CRN is required when using an access key — set CS_WORKSPACE_CRN or call AutoStrategyBuilder::with_workspace_crn"
)]
#[diagnostic(help(
    "Most strategies need a workspace CRN — set the `CS_WORKSPACE_CRN` environment variable, or pass it explicitly, e.g. `AutoStrategyBuilder::with_workspace_crn`."
))]
pub struct MissingWorkspaceCrn;
impl AuthErrorKind for MissingWorkspaceCrn {
    fn error_code(&self) -> &'static str {
        codes::MISSING_WORKSPACE_CRN
    }
}

/// No credentials are available (e.g. not logged in, no access key configured).
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Not authenticated")]
#[diagnostic(help(
    "Log in with `stash login`, or set `CS_CLIENT_ACCESS_KEY` for service-to-service auth."
))]
pub struct NotAuthenticated;
impl AuthErrorKind for NotAuthenticated {
    fn error_code(&self) -> &'static str {
        codes::NOT_AUTHENTICATED
    }
}

/// A token (access token or device code) has expired.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Token expired")]
pub struct TokenExpired;
impl AuthErrorKind for TokenExpired {
    fn error_code(&self) -> &'static str {
        codes::EXPIRED_TOKEN
    }
}

/// The access key string is malformed (e.g. missing `CSAK` prefix or `.`).
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Invalid access key: {0}")]
#[diagnostic(help("Access keys have the form `CSAK<key-id>.<secret>`."))]
pub struct InvalidAccessKeyError(pub access_key::InvalidAccessKey);
impl AuthErrorKind for InvalidAccessKeyError {
    fn error_code(&self) -> &'static str {
        codes::INVALID_ACCESS_KEY
    }
}

/// The JWT could not be decoded or its claims are malformed.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Invalid token: {0}")]
pub struct InvalidToken(pub String);
impl AuthErrorKind for InvalidToken {
    fn error_code(&self) -> &'static str {
        codes::INVALID_TOKEN
    }
}

/// An unexpected error was returned by the auth server.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Server error: {0}")]
pub struct ServerError(pub String);
impl AuthErrorKind for ServerError {
    fn error_code(&self) -> &'static str {
        codes::SERVER_ERROR
    }
}

/// A consumable handle (e.g. a device-code poll) was used after it had already
/// been consumed. A caller bug rather than an auth outcome, but surfaced as an
/// `AuthError` so it flows through the `Result` contract rather than throwing
/// across the FFI boundary.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Handle already consumed")]
pub struct AlreadyConsumed;
impl AuthErrorKind for AlreadyConsumed {
    fn error_code(&self) -> &'static str {
        codes::ALREADY_CONSUMED
    }
}

/// An internal invariant was violated (e.g. a poisoned lock). Should not occur
/// in correct usage; surfaced rather than panicking so it crosses the FFI
/// boundary as a `Result` failure.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Internal error: {0}")]
pub struct InternalError(pub String);
impl AuthErrorKind for InternalError {
    fn error_code(&self) -> &'static str {
        codes::INTERNAL_ERROR
    }
}

/// An auth failure that doesn't correspond to a specific [`AuthError`] variant.
///
/// The catch-all for an error outside the standard set — a custom
/// [`AuthStrategy`](crate::AuthStrategy) surfacing its own failure, or an FFI
/// adaptor reconstructing a failure whose `type` code it can't rebuild into a
/// typed variant (a variant that wraps a foreign error, or an unrecognised
/// code). Mirrors serde's `Error::custom`: it carries the already-rendered
/// message verbatim (its `Display` is that message, with no added prefix), so
/// a reconstructed error reads exactly as it did on the far side of the
/// boundary. It serializes as `{ type: "CUSTOM", ... }`, so consumers switching
/// on the failure code must handle it.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("{0}")]
pub struct CustomError(pub String);
impl AuthErrorKind for CustomError {
    fn error_code(&self) -> &'static str {
        codes::CUSTOM
    }
}

/// A token store operation failed.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Token store error: {0}")]
pub struct StoreError(pub stack_profile::ProfileError);
#[cfg(not(target_arch = "wasm32"))]
impl AuthErrorKind for StoreError {
    fn error_code(&self) -> &'static str {
        codes::STORE_ERROR
    }
}

// ---------------------------------------------------------------------------
// The canonical enum
// ---------------------------------------------------------------------------

/// Errors that can occur during an authentication flow.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[non_exhaustive]
pub enum AuthError {
    #[error(transparent)]
    #[diagnostic(transparent)]
    Request(#[from] RequestError),
    #[error(transparent)]
    #[diagnostic(transparent)]
    AccessDenied(#[from] AccessDenied),
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidGrant(#[from] InvalidGrant),
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidClient(#[from] InvalidClient),
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidUrl(#[from] InvalidUrl),
    #[error(transparent)]
    #[diagnostic(transparent)]
    Region(#[from] UnsupportedRegion),
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidCrn(#[from] InvalidCrn),
    #[error(transparent)]
    #[diagnostic(transparent)]
    WorkspaceMismatch(#[from] WorkspaceMismatch),
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidWorkspaceId(#[from] InvalidWorkspaceId),
    #[error(transparent)]
    #[diagnostic(transparent)]
    MissingWorkspaceCrn(#[from] MissingWorkspaceCrn),
    #[error(transparent)]
    #[diagnostic(transparent)]
    NotAuthenticated(#[from] NotAuthenticated),
    #[error(transparent)]
    #[diagnostic(transparent)]
    TokenExpired(#[from] TokenExpired),
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidAccessKey(#[from] InvalidAccessKeyError),
    #[error(transparent)]
    #[diagnostic(transparent)]
    InvalidToken(#[from] InvalidToken),
    #[error(transparent)]
    #[diagnostic(transparent)]
    Server(#[from] ServerError),
    #[error(transparent)]
    #[diagnostic(transparent)]
    AlreadyConsumed(#[from] AlreadyConsumed),
    #[error(transparent)]
    #[diagnostic(transparent)]
    Internal(#[from] InternalError),
    #[error(transparent)]
    #[diagnostic(transparent)]
    Custom(#[from] CustomError),
    #[cfg(not(target_arch = "wasm32"))]
    #[error(transparent)]
    #[diagnostic(transparent)]
    Store(#[from] StoreError),
}

impl AuthError {
    /// The complete set of codes [`AuthError::error_code`] can return — the
    /// stable, machine-readable contract surfaced across FFI (JS `Error.code`,
    /// Node-API codes, the `index.d.ts` / `wasm-inline.d.ts` `AuthFailure`
    /// unions). The bindings derive their expected union from this constant
    /// rather than re-scraping the per-error [`AuthErrorKind::error_code`] impls,
    /// and `auth_error_code_is_stable_for_every_variant` pins that it stays in
    /// lockstep with what `error_code` actually returns.
    pub const ERROR_CODES: &'static [&'static str] = &[
        codes::REQUEST_ERROR,
        codes::ACCESS_DENIED,
        codes::INVALID_GRANT,
        codes::INVALID_CLIENT,
        codes::INVALID_URL,
        codes::INVALID_REGION,
        codes::INVALID_CRN,
        codes::WORKSPACE_MISMATCH,
        codes::INVALID_WORKSPACE_ID,
        codes::MISSING_WORKSPACE_CRN,
        codes::NOT_AUTHENTICATED,
        codes::EXPIRED_TOKEN,
        codes::INVALID_ACCESS_KEY,
        codes::INVALID_TOKEN,
        codes::SERVER_ERROR,
        codes::ALREADY_CONSUMED,
        codes::INTERNAL_ERROR,
        codes::CUSTOM,
        // `Store` (and its code) only exists off-wasm — see the enum above.
        #[cfg(not(target_arch = "wasm32"))]
        codes::STORE_ERROR,
    ];

    /// Dispatch to the wrapped concrete error as a trait object.
    fn kind(&self) -> &dyn AuthErrorKind {
        match self {
            Self::Request(e) => e,
            Self::AccessDenied(e) => e,
            Self::InvalidGrant(e) => e,
            Self::InvalidClient(e) => e,
            Self::InvalidUrl(e) => e,
            Self::Region(e) => e,
            Self::InvalidCrn(e) => e,
            Self::WorkspaceMismatch(e) => e,
            Self::InvalidWorkspaceId(e) => e,
            Self::MissingWorkspaceCrn(e) => e,
            Self::NotAuthenticated(e) => e,
            Self::TokenExpired(e) => e,
            Self::InvalidAccessKey(e) => e,
            Self::InvalidToken(e) => e,
            Self::Server(e) => e,
            Self::AlreadyConsumed(e) => e,
            Self::Internal(e) => e,
            Self::Custom(e) => e,
            #[cfg(not(target_arch = "wasm32"))]
            Self::Store(e) => e,
        }
    }

    /// Stable machine-readable identifier for surfacing across FFI boundaries
    /// (e.g. JS `Error.code`, Node-API error codes). Delegates to the wrapped
    /// error's [`AuthErrorKind::error_code`]; every value it can return is
    /// listed in [`AuthError::ERROR_CODES`].
    pub fn error_code(&self) -> &'static str {
        self.kind().error_code()
    }

    /// Reconstruct an `AuthError` from its stable FFI wire form — the `type`
    /// code, rendered `message`, and structured `payload` a serialized
    /// [`AuthError`] carries across the boundary (e.g. the `{ failure }` a
    /// JS-supplied auth strategy returns; `payload` is the extra fields
    /// [`AuthErrorKind::payload`] emits alongside `type`/`message`).
    ///
    /// This is the inverse an adaptor needs so that failures cross back into
    /// Rust as real `AuthError`s rather than being flattened to a single opaque
    /// variant:
    ///
    /// - the fixed-message unit codes map straight back to their variant;
    /// - `WORKSPACE_MISMATCH` rebuilds from its `expected`/`actual` payload;
    /// - every other code maps to [`AuthError::Custom`] (mirrors serde's
    ///   `Error::custom`), because the variants that wrap a foreign error
    ///   (`RequestError`, `InvalidUrl`, `UnsupportedRegion`, …) have no
    ///   constructor from a string, and `message` is the rendered `Display`
    ///   (e.g. `"Server error: …"`) — re-wrapping it in a prefixing variant
    ///   would double the prefix.
    ///
    /// `Custom` stores the message verbatim, so a reconstructed error still
    /// reads exactly as it did on the far side. `error_code()` round-trips
    /// exactly for the mapped codes and is `CUSTOM` otherwise. Pass an empty map
    /// for `payload` when there are no structured fields.
    pub fn from_error_code(
        code: &str,
        message: impl Into<String>,
        payload: &serde_json::Map<String, serde_json::Value>,
    ) -> Self {
        match code {
            codes::NOT_AUTHENTICATED => NotAuthenticated.into(),
            codes::EXPIRED_TOKEN => TokenExpired.into(),
            codes::ACCESS_DENIED => AccessDenied.into(),
            codes::INVALID_GRANT => InvalidGrant.into(),
            codes::INVALID_CLIENT => InvalidClient.into(),
            codes::MISSING_WORKSPACE_CRN => MissingWorkspaceCrn.into(),
            codes::ALREADY_CONSUMED => AlreadyConsumed.into(),
            codes::WORKSPACE_MISMATCH => workspace_mismatch_from_payload(payload)
                .unwrap_or_else(|| CustomError(message.into()).into()),
            _ => CustomError(message.into()).into(),
        }
    }
}

/// Rebuild a [`WorkspaceMismatch`] from the `expected`/`actual` fields
/// [`WorkspaceMismatch::payload`] emits. Returns `None` if either field is
/// absent or not a parseable workspace ID, so the caller can fall back to
/// [`AuthError::Custom`].
fn workspace_mismatch_from_payload(
    payload: &serde_json::Map<String, serde_json::Value>,
) -> Option<AuthError> {
    let parse =
        |key: &str| -> Option<cts_common::WorkspaceId> { payload.get(key)?.as_str()?.parse().ok() };
    Some(
        WorkspaceMismatch {
            expected_workspace: parse("expected")?,
            token_workspace: parse("actual")?,
        }
        .into(),
    )
}

/// Serialize an `AuthError` into the flat, FFI-facing shape consumed by the
/// Node and Wasm bindings: `{ type, message, help?, url?, ...payload }`.
///
/// `type`/`message` come from the canonical code and `Display`; `help`/`url`
/// are captured generically from the `miette::Diagnostic` surface (so
/// per-variant help stays colocated on the struct); extra structured fields
/// come from [`AuthErrorKind::payload`].
///
/// `serialize_map` lets the wasm binding render this as a plain JS object via
/// `Serializer::serialize_maps_as_objects(true)`; serde_json renders a JSON
/// object directly.
impl serde::Serialize for AuthError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use miette::Diagnostic;
        use serde::ser::SerializeMap;

        let kind = self.kind();
        let mut map = serializer.serialize_map(None)?;
        // Emit the per-variant payload first, then the fixed diagnostic fields —
        // so if a future `payload()` key ever collided with `type`/`message`/
        // `help`/`url`, the diagnostic field (written last) wins rather than being
        // clobbered. Mirrors the JS side's `{ ...payload, type, error }`.
        for (key, value) in kind.payload() {
            map.serialize_entry(&key, &value)?;
        }
        map.serialize_entry("type", kind.error_code())?;
        map.serialize_entry("message", &self.to_string())?;
        if let Some(help) = self.help() {
            map.serialize_entry("help", &help.to_string())?;
        }
        if let Some(url) = self.url() {
            map.serialize_entry("url", &url.to_string())?;
        }
        map.end()
    }
}

// ---------------------------------------------------------------------------
// Ergonomic `From<Foreign>` impls — keep `?` working where call sites lift a
// foreign error straight into `AuthError` (the per-struct wrapping is internal).
// ---------------------------------------------------------------------------

impl From<reqwest::Error> for AuthError {
    fn from(e: reqwest::Error) -> Self {
        Self::Request(RequestError(e))
    }
}

impl From<url::ParseError> for AuthError {
    fn from(e: url::ParseError) -> Self {
        Self::InvalidUrl(InvalidUrl(e))
    }
}

impl From<cts_common::RegionError> for AuthError {
    fn from(e: cts_common::RegionError) -> Self {
        Self::Region(UnsupportedRegion(e))
    }
}

impl From<cts_common::InvalidCrn> for AuthError {
    fn from(e: cts_common::InvalidCrn) -> Self {
        Self::InvalidCrn(InvalidCrn(e))
    }
}

impl From<cts_common::InvalidWorkspaceId> for AuthError {
    fn from(e: cts_common::InvalidWorkspaceId) -> Self {
        Self::InvalidWorkspaceId(InvalidWorkspaceId(e))
    }
}

impl From<access_key::InvalidAccessKey> for AuthError {
    fn from(e: access_key::InvalidAccessKey) -> Self {
        Self::InvalidAccessKey(InvalidAccessKeyError(e))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<stack_profile::ProfileError> for AuthError {
    fn from(e: stack_profile::ProfileError) -> Self {
        Self::Store(StoreError(e))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<crate::DeviceClientError> for AuthError {
    fn from(e: crate::DeviceClientError) -> Self {
        use crate::DeviceClientError as E;
        match e {
            // Every non-`Auth` variant has a canonical `AuthError` equivalent —
            // route through it so `bind_client_device` failures carry the same
            // code/help/payload as every other path. `Auth` already is one.
            E::Profile(e) => e.into(),
            E::Auth(e) => e,
            E::Request(e) => e.into(),
            E::InvalidUrl(e) => e.into(),
            E::Server { status, body } => {
                Self::Server(ServerError(format!("ZeroKMS returned {status}: {body}")))
            }
        }
    }
}

impl From<Infallible> for AuthError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_emits_type_message_help_and_payload() {
        let expected: cts_common::WorkspaceId = "ZVATKW3VHMFG27DY".parse().unwrap();
        let actual: cts_common::WorkspaceId = "AAAAAAAAAAAAAAAA".parse().unwrap();
        let (expected_s, actual_s) = (expected.to_string(), actual.to_string());

        let err = AuthError::WorkspaceMismatch(WorkspaceMismatch {
            expected_workspace: expected,
            token_workspace: actual,
        });
        let json = serde_json::to_value(&err).unwrap();

        // Generic fields the enum emits for every variant.
        assert_eq!(json["type"], "WORKSPACE_MISMATCH");
        assert_eq!(json["message"], err.to_string());
        // `help` comes from the miette diagnostic (present on this variant).
        assert!(json.get("help").is_some(), "help should be serialized");
        // Structured payload from `AuthErrorKind::payload`.
        assert_eq!(json["expected"], expected_s);
        assert_eq!(json["actual"], actual_s);
    }

    #[test]
    fn serialize_variant_without_payload_emits_only_generic_fields() {
        let err = AuthError::MissingWorkspaceCrn(MissingWorkspaceCrn);
        let json = serde_json::to_value(&err).unwrap();

        assert_eq!(json["type"], "MISSING_WORKSPACE_CRN");
        assert_eq!(json["message"], err.to_string());
        // No per-variant payload keys — the payload loop contributes nothing.
        assert!(json.get("expected").is_none());
        assert!(json.get("actual").is_none());
    }

    /// Every constructable `DeviceClientError` variant maps to its canonical
    /// `AuthError` code so `bind_client_device` failures share the one envelope
    /// path. (`Request` wraps a `reqwest::Error`, which has no public
    /// constructor, so it can't be built here — the same gap the exhaustive
    /// `error_code` test documents.)
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn device_client_error_maps_to_canonical_auth_error() {
        use crate::DeviceClientError as E;

        // `Auth` unwraps to the inner error unchanged.
        assert_eq!(
            AuthError::from(E::Auth(AuthError::AccessDenied(AccessDenied))).error_code(),
            codes::ACCESS_DENIED,
        );
        // Non-`Auth` variants route to their canonical `AuthError` equivalent.
        assert_eq!(
            AuthError::from(E::Profile(stack_profile::ProfileError::HomeDirNotFound)).error_code(),
            codes::STORE_ERROR,
        );
        assert_eq!(
            AuthError::from(E::InvalidUrl("not a url".parse::<url::Url>().unwrap_err()))
                .error_code(),
            codes::INVALID_URL,
        );
        let server = AuthError::from(E::Server {
            status: 500,
            body: "boom".to_string(),
        });
        assert_eq!(server.error_code(), codes::SERVER_ERROR);
        assert!(
            server.to_string().contains("ZeroKMS returned 500: boom"),
            "server error should preserve the status/body detail: {server}"
        );
    }
}
