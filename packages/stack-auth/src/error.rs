//! Authentication error types.
//!
//! [`AuthError`] is the single canonical error enum. Each variant wraps a
//! dedicated struct that owns its `Display` message, `miette` diagnostic
//! (`help`/`url`) and machine-readable code, plus any structured payload — so
//! per-error logic lives with the error rather than in one central function.
//!
//! The enum is a thin dispatcher: `Display`/`Diagnostic` delegate to the inner
//! struct via `transparent`, and [`AuthError::error_code`] / the `Serialize`
//! impl delegate through [`AuthError::kind`]. Ergonomic `From<Foreign>` impls
//! keep `?` working at call sites that lift a foreign error directly.

use std::convert::Infallible;

use crate::access_key;

/// Behaviour shared by every concrete error wrapped in an [`AuthError`] variant.
///
/// Implemented by the per-error structs so each owns its FFI code and any
/// structured payload; [`AuthError`] dispatches to it via [`AuthError::kind`].
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

// ---------------------------------------------------------------------------
// Per-error structs
// ---------------------------------------------------------------------------

/// The HTTP request to the auth server failed (network error, timeout, etc.).
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("HTTP request failed: {0}")]
pub struct RequestError(pub reqwest::Error);
impl AuthErrorKind for RequestError {
    fn error_code(&self) -> &'static str {
        "REQUEST_ERROR"
    }
}

/// The user denied the authorization request.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Authorization was denied")]
pub struct AccessDenied;
impl AuthErrorKind for AccessDenied {
    fn error_code(&self) -> &'static str {
        "ACCESS_DENIED"
    }
}

/// The grant type was rejected by the server.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Invalid grant")]
pub struct InvalidGrant;
impl AuthErrorKind for InvalidGrant {
    fn error_code(&self) -> &'static str {
        "INVALID_GRANT"
    }
}

/// The client ID is not recognized.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Invalid client")]
pub struct InvalidClient;
impl AuthErrorKind for InvalidClient {
    fn error_code(&self) -> &'static str {
        "INVALID_CLIENT"
    }
}

/// A URL could not be parsed.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Invalid URL: {0}")]
pub struct InvalidUrl(pub url::ParseError);
impl AuthErrorKind for InvalidUrl {
    fn error_code(&self) -> &'static str {
        "INVALID_URL"
    }
}

/// The requested region is not supported.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Unsupported region: {0}")]
#[diagnostic(help("Use a supported region, e.g. `ap-southeast-2.aws`."))]
pub struct UnsupportedRegion(pub cts_common::RegionError);
impl AuthErrorKind for UnsupportedRegion {
    fn error_code(&self) -> &'static str {
        "INVALID_REGION"
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
        "INVALID_CRN"
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
        "WORKSPACE_MISMATCH"
    }
    fn payload(&self) -> serde_json::Map<String, serde_json::Value> {
        match serde_json::json!({
            "expected": self.expected_workspace.to_string(),
            "actual": self.token_workspace.to_string(),
        }) {
            serde_json::Value::Object(map) => map,
            _ => serde_json::Map::new(),
        }
    }
}

/// The workspace ID could not be parsed.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Invalid workspace ID: {0}")]
pub struct InvalidWorkspaceId(pub cts_common::InvalidWorkspaceId);
impl AuthErrorKind for InvalidWorkspaceId {
    fn error_code(&self) -> &'static str {
        "INVALID_WORKSPACE_ID"
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
        "MISSING_WORKSPACE_CRN"
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
        "NOT_AUTHENTICATED"
    }
}

/// A token (access token or device code) has expired.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Token expired")]
pub struct TokenExpired;
impl AuthErrorKind for TokenExpired {
    fn error_code(&self) -> &'static str {
        "EXPIRED_TOKEN"
    }
}

/// The access key string is malformed (e.g. missing `CSAK` prefix or `.`).
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Invalid access key: {0}")]
#[diagnostic(help("Access keys have the form `CSAK<key-id>.<secret>`."))]
pub struct InvalidAccessKeyError(pub access_key::InvalidAccessKey);
impl AuthErrorKind for InvalidAccessKeyError {
    fn error_code(&self) -> &'static str {
        "INVALID_ACCESS_KEY"
    }
}

/// The JWT could not be decoded or its claims are malformed.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Invalid token: {0}")]
pub struct InvalidToken(pub String);
impl AuthErrorKind for InvalidToken {
    fn error_code(&self) -> &'static str {
        "INVALID_TOKEN"
    }
}

/// An unexpected error was returned by the auth server.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Server error: {0}")]
pub struct ServerError(pub String);
impl AuthErrorKind for ServerError {
    fn error_code(&self) -> &'static str {
        "SERVER_ERROR"
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
        "ALREADY_CONSUMED"
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
        "INTERNAL_ERROR"
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
        "STORE_ERROR"
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
    #[cfg(not(target_arch = "wasm32"))]
    #[error(transparent)]
    #[diagnostic(transparent)]
    Store(#[from] StoreError),
}

impl AuthError {
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
            #[cfg(not(target_arch = "wasm32"))]
            Self::Store(e) => e,
        }
    }

    /// Stable machine-readable identifier for surfacing across FFI boundaries
    /// (e.g. JS `Error.code`, Node-API error codes). Delegates to the wrapped
    /// error's [`AuthErrorKind::error_code`].
    pub fn error_code(&self) -> &'static str {
        self.kind().error_code()
    }
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
        map.serialize_entry("type", kind.error_code())?;
        map.serialize_entry("message", &self.to_string())?;
        if let Some(help) = self.help() {
            map.serialize_entry("help", &help.to_string())?;
        }
        if let Some(url) = self.url() {
            map.serialize_entry("url", &url.to_string())?;
        }
        for (key, value) in kind.payload() {
            map.serialize_entry(&key, &value)?;
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

impl From<Infallible> for AuthError {
    fn from(never: Infallible) -> Self {
        match never {}
    }
}
