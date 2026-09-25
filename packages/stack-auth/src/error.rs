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

use cts_common::protocol::{CS_CODE_ORG_NOT_PROVISIONED, CS_CODE_USAGE_LIMIT_EXCEEDED};

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
    // Aliased rather than re-declared: `CS_CODE_USAGE_LIMIT_EXCEEDED` /
    // `CS_CODE_ORG_NOT_PROVISIONED` are the wire values CTS actually sends
    // (`classify_issuance_failure` matches against them directly), and
    // `StickyDenial` round-trips through these FFI codes via `error_code()`
    // / `from_error_code`. A second, independent literal here would let the
    // two drift — editing one without the other silently breaks either the
    // wire classification or denial replay.
    pub(crate) const USAGE_LIMIT_EXCEEDED: &str = super::CS_CODE_USAGE_LIMIT_EXCEEDED;
    pub(crate) const ORG_NOT_PROVISIONED: &str = super::CS_CODE_ORG_NOT_PROVISIONED;
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

/// The request to the auth server failed (network error, timeout, etc.).
///
/// The payload is always boxed, never a concrete `reqwest::Error`: Cargo
/// features are additive, so a type whose shape changes with `http` breaks any
/// no-http consumer the moment something else in the graph turns the feature
/// on. The box holds whatever the [`HttpTransport`](crate::HttpTransport) in
/// use reported — the bundled one's `reqwest::Error`, or a host transport's
/// own — or the encoder's or decoder's error for a body that did not
/// serialize or parse.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("Request to the auth server failed: {0}")]
pub struct RequestError(pub Box<dyn std::error::Error + Send + Sync + 'static>);
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

/// The organisation has exhausted its usage allowance, so CTS declined to
/// issue a credential.
///
/// Distinct from [`AccessDenied`] and [`ServerError`] because it is neither a
/// permissions problem nor a transient one: retrying cannot succeed until the
/// plan changes. A client that backs off and retries on `SERVER_ERROR` — the
/// reasonable default — would otherwise spin indefinitely against a condition
/// only a human with a credit card can clear.
///
/// Carries the server's `error_description` verbatim so the operator-facing
/// wording stays owned by CTS rather than duplicated here.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("{0}")]
#[diagnostic(
    help(
        "The organisation has used its allowance for the current billing period. Upgrade the plan from the CipherStash dashboard, then retry."
    ),
    url("https://dashboard.cipherstash.com/billing")
)]
pub struct UsageLimitExceeded(pub String);

impl UsageLimitExceeded {
    /// Fallback message for a 402 whose body carried no usable description.
    pub const DEFAULT_MESSAGE: &'static str =
        "Workspace has exceeded its usage limit and cannot issue an access token";
}

/// The organisation is not a known customer in the usage system.
///
/// Distinct from [`UsageLimitExceeded`] because the remedy is different and
/// the two are not interchangeable: there is no plan to upgrade, so telling
/// the caller to upgrade one sends them somewhere that cannot help.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("{0}")]
#[diagnostic(
    help(
        "The organisation is not set up for usage tracking. Contact CipherStash support — retrying and upgrading the plan will both fail."
    ),
    url("https://cipherstash.com/support")
)]
pub struct OrgNotProvisioned(pub String);

impl OrgNotProvisioned {
    /// Fallback message for a 402 whose body carried no usable description.
    pub const DEFAULT_MESSAGE: &'static str =
        "Organisation is not provisioned in the usage system and cannot issue an access token";
}

impl AuthErrorKind for OrgNotProvisioned {
    fn error_code(&self) -> &'static str {
        codes::ORG_NOT_PROVISIONED
    }
}

impl AuthErrorKind for UsageLimitExceeded {
    fn error_code(&self) -> &'static str {
        codes::USAGE_LIMIT_EXCEEDED
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
    UsageLimitExceeded(#[from] UsageLimitExceeded),
    #[error(transparent)]
    #[diagnostic(transparent)]
    OrgNotProvisioned(#[from] OrgNotProvisioned),
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
    /// True when the *credential itself* was refused — an expired, invalid or
    /// consumed token, key or grant — so obtaining a fresh credential and
    /// retrying is a sensible response. False for everything else:
    /// authenticated-but-forbidden, server faults, and configuration or
    /// transport problems that no amount of refreshing can fix.
    ///
    /// This classification lives here, next to the variants, because
    /// `AuthError` is `#[non_exhaustive]`: a downstream `match` needs a `_`
    /// arm, which silently mis-classifies every variant added later. Inside
    /// this crate the match *is* exhaustive — adding a variant is a compile
    /// error until it is classified. FFI front-ends (the wasm guest's status
    /// mapping) key their "refresh the token and retry" signal off this.
    pub fn is_credential_rejection(&self) -> bool {
        match self {
            AuthError::NotAuthenticated(_)
            | AuthError::TokenExpired(_)
            | AuthError::InvalidGrant(_)
            | AuthError::InvalidClient(_)
            | AuthError::InvalidAccessKey(_)
            | AuthError::AlreadyConsumed(_) => true,
            AuthError::Request(_)
            | AuthError::AccessDenied(_)
            | AuthError::InvalidUrl(_)
            | AuthError::Region(_)
            | AuthError::InvalidCrn(_)
            | AuthError::WorkspaceMismatch(_)
            | AuthError::InvalidWorkspaceId(_)
            | AuthError::MissingWorkspaceCrn(_)
            | AuthError::InvalidToken(_)
            | AuthError::UsageLimitExceeded(_)
            | AuthError::OrgNotProvisioned(_)
            | AuthError::Server(_)
            | AuthError::Internal(_)
            | AuthError::Custom(_) => false,
            #[cfg(not(target_arch = "wasm32"))]
            AuthError::Store(_) => false,
        }
    }

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
        codes::USAGE_LIMIT_EXCEEDED,
        codes::ORG_NOT_PROVISIONED,
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
            Self::UsageLimitExceeded(e) => e,
            Self::OrgNotProvisioned(e) => e,
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

    /// Whether re-issuing the same request could plausibly succeed.
    ///
    /// Transport failures and server faults are worth retrying. Everything
    /// else returns the same answer until something outside this client
    /// changes — a plan upgrade, a corrected config, a fresh login — so a
    /// caller that retries on them only multiplies load against a decision
    /// that has already been made.
    ///
    /// Matched exhaustively so a new variant has to state which side it is on.
    /// Where a code's nature is genuinely unclear the answer is `true`:
    /// wrongly treating a transient failure as permanent locks a client out,
    /// which is worse than a retry that fails again.
    pub fn is_retryable(&self) -> bool {
        match self {
            // Transient by nature — the network or the far side may recover.
            Self::Request(_) | Self::Server(_) => true,
            // Ours to fix rather than the caller's to retry, but an internal
            // fault may be non-deterministic.
            Self::Internal(_) => true,
            // Opaque by construction: a reconstructed or user-supplied error
            // whose cause we cannot classify.
            Self::Custom(_) => true,
            // Local persistence (cookie, KV, keychain) can fail transiently.
            #[cfg(not(target_arch = "wasm32"))]
            Self::Store(_) => true,

            // Settled answers. Retrying re-asks a question already answered.
            Self::AccessDenied(_)
            | Self::InvalidGrant(_)
            | Self::InvalidClient(_)
            | Self::InvalidUrl(_)
            | Self::Region(_)
            | Self::InvalidCrn(_)
            | Self::WorkspaceMismatch(_)
            | Self::InvalidWorkspaceId(_)
            | Self::MissingWorkspaceCrn(_)
            | Self::NotAuthenticated(_)
            | Self::TokenExpired(_)
            | Self::InvalidAccessKey(_)
            | Self::InvalidToken(_)
            | Self::UsageLimitExceeded(_)
            | Self::OrgNotProvisioned(_)
            | Self::AlreadyConsumed(_) => false,
        }
    }

    /// Whether this failure refuses the *account* — as opposed to the
    /// credential presented — and is therefore safe to negatively-cache
    /// across separate `get_token` calls until something outside the client
    /// changes (a plan upgrade, provisioning).
    ///
    /// Deliberately narrower than [`is_retryable`](Self::is_retryable): most
    /// non-retryable failures (`invalid_grant`, `invalid_client`, ...) are
    /// verdicts on the *credential*, and a refresher restores that credential
    /// precisely so a later attempt can succeed once the caller supplies a
    /// good one — caching those would defeat the restore path. Only a
    /// verdict on the account itself is safe to replay without re-asking.
    ///
    /// Matched exhaustively, like `is_retryable`, so a new variant has to
    /// declare which side of this boundary it's on rather than silently not
    /// being cached.
    pub(crate) fn is_account_refusal(&self) -> bool {
        match self {
            Self::UsageLimitExceeded(_) | Self::OrgNotProvisioned(_) => true,

            Self::Request(_)
            | Self::AccessDenied(_)
            | Self::InvalidGrant(_)
            | Self::InvalidClient(_)
            | Self::InvalidUrl(_)
            | Self::Region(_)
            | Self::InvalidCrn(_)
            | Self::WorkspaceMismatch(_)
            | Self::InvalidWorkspaceId(_)
            | Self::MissingWorkspaceCrn(_)
            | Self::NotAuthenticated(_)
            | Self::TokenExpired(_)
            | Self::InvalidAccessKey(_)
            | Self::InvalidToken(_)
            | Self::Server(_)
            | Self::AlreadyConsumed(_)
            | Self::Internal(_)
            | Self::Custom(_) => false,
            #[cfg(not(target_arch = "wasm32"))]
            Self::Store(_) => false,
        }
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
            // Round-trips with its message, unlike the fixed-message unit
            // codes above: the description is CTS's wording, not ours. Falls
            // back to the same default the classifier uses, so an empty
            // message never produces a blank `Display`.
            codes::USAGE_LIMIT_EXCEEDED => UsageLimitExceeded(default_if_blank(
                message,
                UsageLimitExceeded::DEFAULT_MESSAGE,
            ))
            .into(),
            codes::ORG_NOT_PROVISIONED => OrgNotProvisioned(default_if_blank(
                message,
                OrgNotProvisioned::DEFAULT_MESSAGE,
            ))
            .into(),
            codes::WORKSPACE_MISMATCH => workspace_mismatch_from_payload(payload)
                .unwrap_or_else(|| CustomError(message.into()).into()),
            _ => CustomError(message.into()).into(),
        }
    }
}

/// `message.trim()`, or `default` if that's blank — the shared fallback for
/// the account-refusal codes in [`AuthError::from_error_code`], so an empty
/// message never produces a blank `Display` and the two codes can't drift
/// apart in how they apply that fallback.
fn default_if_blank(message: impl Into<String>, default: &str) -> String {
    let message = message.into();
    match message.trim() {
        "" => default.to_string(),
        _ => message,
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

/// Classify a failed CTS credential-issuance response.
///
/// Returns `Some` only for conditions with a typed variant; `None` means the
/// caller should fall back to its own generic handling. Every issuance path
/// (`/api/authorize`, OIDC federation, `/oauth/token`) routes through here so
/// they cannot drift apart in how they classify the same server response.
///
/// `402` is the discriminator. The OAuth paths must send
/// `error: "access_denied"` to stay RFC 6749-compliant, which is
/// indistinguishable from a genuine authorization refusal — so the status, not
/// the body, decides. `cs_code` is checked when present so that a future 402
/// with a different meaning does not silently inherit this classification.
pub(crate) fn classify_issuance_failure(status: u16, body: &str) -> Option<AuthError> {
    if status != 402 {
        return None;
    }

    // An empty body is the one shape a 402 from CTS itself can take without
    // being JSON: pre-`cs_code` deployments sent no body at all for a usage
    // limit, so that remains the reading for a bare 402.
    if body.trim().is_empty() {
        return Some(UsageLimitExceeded(UsageLimitExceeded::DEFAULT_MESSAGE.to_string()).into());
    }

    // Anything else has to actually parse as a JSON object to be CTS-shaped —
    // a non-empty body that isn't valid JSON, or that parses to a JSON value
    // that isn't an object (an array, a bare string, `null`, ...), is not a
    // response CTS ever sends. That's a 402 from something else entirely —
    // a proxy, a WAF, a gateway in front of CTS — and reporting it as a usage
    // limit would sticky-cache a permanent, non-retryable refusal for a
    // condition that may well be transient. Declining sends the caller down
    // its own generic, retryable handling instead.
    let parsed = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .filter(serde_json::Value::is_object)?;

    let field = |name: &str| -> Option<String> {
        parsed
            .get(name)?
            .as_str()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };

    // Presence is decided on the raw value, not on a string projection of it.
    // Reading `cs_code` through `as_str()` would make a non-string value
    // indistinguishable from an absent one, so `{"cs_code": 42}` would skip
    // this guard entirely and be classified — the exact inversion of what the
    // guard is for. Anything present but not recognised declines, which sends
    // the caller down the generic path rather than asserting a remedy on the
    // strength of a body we could not read.
    //
    // Compared explicitly with `==` rather than matched as patterns. Neither
    // footgun that phrasing might suggest actually applies here: these names
    // are brought into scope by `use`, so as bare-identifier patterns they'd
    // correctly resolve to the consts and compare (not bind) — an unqualified
    // identifier only binds when it fails to resolve to a const/unit-variant
    // at all — and a *qualified* path that fails to resolve is a compile
    // error (E0531), never a silent binding. `==` is simply the more obviously
    // correct form, not a workaround for either.
    let recognised = |code: &str| {
        if code == CS_CODE_USAGE_LIMIT_EXCEEDED {
            Some(Refusal::UsageLimit)
        } else if code == CS_CODE_ORG_NOT_PROVISIONED {
            Some(Refusal::NotProvisioned)
        } else {
            None
        }
    };

    let refusal = match parsed.get("cs_code") {
        Some(value) => recognised(value.as_str().map(str::trim).unwrap_or_default())?,
        // Absent: pre-`cs_code` deployments only ever sent 402 for a usage
        // limit, so that remains the reading for a bare 402.
        None => Refusal::UsageLimit,
    };

    let description = field("error_description");

    Some(match refusal {
        Refusal::UsageLimit => UsageLimitExceeded(
            description.unwrap_or_else(|| UsageLimitExceeded::DEFAULT_MESSAGE.to_string()),
        )
        .into(),
        Refusal::NotProvisioned => OrgNotProvisioned(
            description.unwrap_or_else(|| OrgNotProvisioned::DEFAULT_MESSAGE.to_string()),
        )
        .into(),
    })
}

/// Which account-level refusal a 402 body describes.
enum Refusal {
    UsageLimit,
    NotProvisioned,
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

#[cfg(feature = "http")]
impl From<reqwest::Error> for RequestError {
    fn from(e: reqwest::Error) -> Self {
        Self(Box::new(e))
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

#[cfg(all(feature = "http", not(target_arch = "wasm32")))]
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
#[cfg(feature = "http")]
mod classify_issuance_failure_tests {
    use super::*;

    const OAUTH_402: &str = r#"{
        "error": "access_denied",
        "error_description": "Workspace has exceeded its usage limit and cannot issue an access token",
        "cs_code": "USAGE_LIMIT_EXCEEDED"
    }"#;

    const AUTHORIZE_402: &str = r#"{
        "error": "usage_limit_exceeded",
        "error_description": "Workspace has exceeded its usage limit and cannot issue an access token"
    }"#;

    fn code_of(err: Option<AuthError>) -> Option<&'static str> {
        err.map(|e| e.error_code())
    }

    #[test]
    fn oauth_body_is_usage_limit_despite_access_denied_code() {
        let err = classify_issuance_failure(402, OAUTH_402).expect("402 must classify");
        assert_eq!(err.error_code(), codes::USAGE_LIMIT_EXCEEDED);
        assert!(err.to_string().contains("exceeded its usage limit"));
    }

    #[test]
    fn authorize_body_is_usage_limit() {
        assert_eq!(
            code_of(classify_issuance_failure(402, AUTHORIZE_402)),
            Some(codes::USAGE_LIMIT_EXCEEDED),
        );
    }

    /// Older CTS deployments predate `cs_code`; the status still carries the
    /// meaning, so classification must not depend on the body.
    #[test]
    fn bare_402_without_body_still_classifies() {
        let err = classify_issuance_failure(402, "").expect("402 must classify");
        assert_eq!(err.error_code(), codes::USAGE_LIMIT_EXCEEDED);
        assert_eq!(err.to_string(), UsageLimitExceeded::DEFAULT_MESSAGE);
    }

    /// A future 402 meaning something else must not silently inherit the
    /// usage-limit classification.
    #[test]
    fn unknown_cs_code_declines_to_classify() {
        let body = r#"{"error": "access_denied", "cs_code": "SOMETHING_ELSE"}"#;
        assert!(classify_issuance_failure(402, body).is_none());
    }

    #[test]
    fn non_402_statuses_are_left_alone() {
        for status in [400, 401, 403, 404, 500, 503] {
            assert!(
                classify_issuance_failure(status, OAUTH_402).is_none(),
                "status {status} must not be classified as a usage limit",
            );
        }
    }

    /// Regression: a `cs_code` we cannot read is not a `cs_code` we recognise.
    ///
    /// The first implementation projected the field through `.as_str()`, so a
    /// non-string value read as *absent* and fell through to classification —
    /// inverting the guard's whole purpose. Misclassifying here is the
    /// expensive direction: it tells a caller to go buy something on the
    /// strength of a body we failed to parse.
    #[test]
    fn unreadable_cs_code_declines_to_classify() {
        for body in [
            r#"{"cs_code": 42}"#,
            r#"{"cs_code": null}"#,
            r#"{"cs_code": {}}"#,
            r#"{"cs_code": []}"#,
            r#"{"cs_code": true}"#,
            r#"{"cs_code": ""}"#,
            r#"{"cs_code": "   "}"#,
        ] {
            assert!(
                classify_issuance_failure(402, body).is_none(),
                "a 402 carrying an unreadable cs_code must fall back, not claim a usage limit: {body}",
            );
        }
    }

    /// A 402 from something that is not CTS — a proxy, WAF, or payment gateway
    /// in front of it — must not panic or be reported as a usage limit if it
    /// carries a `cs_code` we do not recognise.
    #[test]
    fn non_object_and_non_json_bodies_are_handled() {
        for body in [
            "<html>502 Bad Gateway</html>",
            "[]",
            "null",
            "7",
            "\"a string\"",
            "",
            "   ",
            "{",
        ] {
            // No `cs_code` is discoverable in any of these, so the documented
            // bare-402 fallback applies; the contract is that it does not panic
            // and always yields a usable message.
            if let Some(err) = classify_issuance_failure(402, body) {
                assert!(
                    !err.to_string().trim().is_empty(),
                    "classified error must carry a usable message for body: {body:?}",
                );
            }
        }
    }

    /// A non-empty body that isn't CTS-shaped JSON — an HTML error page, a
    /// bare JSON array/string/number, or outright invalid JSON — must decline
    /// to classify rather than falling back to a usage limit. CTS itself
    /// either sends no body at all (the legacy bare-402 case, still handled)
    /// or a JSON object; anything else is a 402 from something in front of
    /// CTS (a proxy, a WAF, a gateway), and sticky-caching a permanent,
    /// non-retryable refusal for it would misdiagnose what could be a
    /// transient condition.
    #[test]
    fn non_cts_shaped_bodies_decline_to_classify() {
        for body in [
            "<html>502 Bad Gateway</html>",
            "[]",
            "null",
            "7",
            "\"a string\"",
            "{",
            "not json at all",
        ] {
            assert!(
                classify_issuance_failure(402, body).is_none(),
                "a 402 whose body is not CTS-shaped JSON must not be classified \
                 as a usage limit: {body:?}",
            );
        }
    }

    mod properties {
        use super::*;
        use proptest::prelude::*;

        /// Bodies with the structure the classifier actually inspects.
        ///
        /// A bare `".*"` strategy essentially never produces parseable JSON,
        /// so it exercises only the unparseable-body path and leaves the two
        /// branches that carry logic — the `cs_code` guard and the description
        /// extraction — with no property coverage at all.
        fn issuance_body() -> impl Strategy<Value = String> {
            let cs_code = prop_oneof![
                Just(None),
                Just(Some(serde_json::json!(CS_CODE_USAGE_LIMIT_EXCEEDED))),
                "[A-Z_]{1,20}".prop_map(|s| Some(serde_json::json!(s))),
                Just(Some(serde_json::json!(42))),
                Just(Some(serde_json::json!(null))),
                Just(Some(serde_json::json!({}))),
                Just(Some(serde_json::json!("   "))),
            ];
            let description = prop_oneof![
                Just(None),
                Just(Some("   ".to_string())),
                "\\PC{1,64}".prop_map(Some),
            ];

            let structured = (cs_code, description).prop_map(|(cs, desc)| {
                let mut obj = serde_json::Map::new();
                obj.insert("error".into(), serde_json::json!("access_denied"));
                if let Some(cs) = cs {
                    obj.insert("cs_code".into(), cs);
                }
                if let Some(desc) = desc {
                    obj.insert("error_description".into(), serde_json::json!(desc));
                }
                serde_json::Value::Object(obj).to_string()
            });

            prop_oneof![
                Just(String::new()),
                Just("{".to_string()),
                "\\PC{0,64}",
                structured,
            ]
        }

        /// Whether a body permits classification, derived independently of
        /// the implementation: an empty body always does (the legacy bare-402
        /// reading); a non-empty body only does if it parses as a JSON object
        /// whose `cs_code` (if present at all) matches the usage-limit code.
        fn cs_code_permits(body: &str) -> bool {
            if body.trim().is_empty() {
                return true;
            }
            let Ok(serde_json::Value::Object(obj)) =
                serde_json::from_str::<serde_json::Value>(body)
            else {
                return false;
            };
            obj.get("cs_code")
                .is_none_or(|v| v.as_str().map(str::trim) == Some(CS_CODE_USAGE_LIMIT_EXCEEDED))
        }

        /// Statuses to classify against.
        ///
        /// 402 is drawn explicitly rather than left to chance. Over
        /// `100..600`, 256 uniform draws miss 402 entirely about 60% of the
        /// time — which would leave the positive direction of the equality
        /// below untested in most runs, the same vacuity this replaces.
        fn issuance_status() -> impl Strategy<Value = u16> {
            prop_oneof![Just(402u16), 100u16..600]
        }

        proptest! {
            // Keep the case count modest so this stays a fast unit test.
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Classification happens exactly on the 402-with-compatible-cs_code
            /// branch — no more, and importantly no less.
            ///
            /// Stated as an equality rather than "non-402 never classifies", so
            /// a `classify_issuance_failure` that simply returned `None` fails
            /// here. Asserting only the negative direction passes vacuously.
            #[test]
            fn classification_is_exactly_the_402_branch(
                status in issuance_status(),
                body in issuance_body(),
            ) {
                prop_assert_eq!(
                    classify_issuance_failure(status, &body).is_some(),
                    status == 402 && cs_code_permits(&body),
                );
            }

            /// A classified usage limit always carries a usable message. An
            /// empty one would reach the user as a blank "upgrade your plan".
            ///
            /// Guarded by `cs_code_permits` and then `expect`ed, rather than
            /// wrapped in `if let Some`: a conditional body would hold however
            /// little the classifier actually classified.
            #[test]
            fn classified_errors_always_carry_a_message(body in issuance_body()) {
                prop_assume!(cs_code_permits(&body));
                let err = classify_issuance_failure(402, &body)
                    .expect("a 402 with a compatible cs_code must classify");
                prop_assert!(!err.to_string().trim().is_empty());
                prop_assert_eq!(err.error_code(), codes::USAGE_LIMIT_EXCEEDED);
            }

            /// The message is either the body's own description or the
            /// documented fallback — never anything invented in between.
            #[test]
            fn the_message_comes_from_the_body_or_the_default(body in issuance_body()) {
                prop_assume!(cs_code_permits(&body));
                let err = classify_issuance_failure(402, &body)
                    .expect("a 402 with a compatible cs_code must classify");

                let described = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| {
                        v.get("error_description")?.as_str().map(str::trim).map(str::to_string)
                    })
                    .filter(|s| !s.is_empty());
                let rendered = err.to_string();

                prop_assert!(
                    rendered == UsageLimitExceeded::DEFAULT_MESSAGE
                        || Some(&rendered) == described.as_ref(),
                    "message {rendered:?} came from neither the body nor the default",
                );
            }

            /// A classified usage limit is never retryable. This is the
            /// property the whole taxonomy exists to deliver.
            #[test]
            fn a_classified_usage_limit_is_never_retryable(body in issuance_body()) {
                prop_assume!(cs_code_permits(&body));
                let err = classify_issuance_failure(402, &body)
                    .expect("a 402 with a compatible cs_code must classify");
                prop_assert!(!err.is_retryable());
            }
        }
    }

    /// Every code states which side of the retry boundary it is on, so adding
    /// one to `ERROR_CODES` without deciding fails here rather than silently
    /// inheriting a default.
    #[test]
    fn retryability_is_pinned_for_every_error_code() {
        const RETRYABLE: &[&str] = &[
            codes::REQUEST_ERROR,
            codes::SERVER_ERROR,
            codes::INTERNAL_ERROR,
            codes::CUSTOM,
            #[cfg(not(target_arch = "wasm32"))]
            codes::STORE_ERROR,
        ];

        let payload = serde_json::Map::new();
        for code in AuthError::ERROR_CODES {
            // `from_error_code` degrades unmapped codes to `Custom`, which is
            // retryable — so drive the check from a real instance where the
            // code round-trips, and skip where it cannot be reconstructed.
            let err = AuthError::from_error_code(code, "message", &payload);
            if err.error_code() != *code {
                continue;
            }
            assert_eq!(
                err.is_retryable(),
                RETRYABLE.contains(code),
                "{code} is on the wrong side of the retry boundary",
            );
        }
    }

    /// Same contract as `retryability_is_pinned_for_every_error_code`, for the
    /// account-refusal axis: every code states whether it's safe to
    /// negatively-cache across `get_token` calls, so a new variant can't
    /// silently fall out of storm suppression (or, worse, silently start
    /// caching a credential-scoped failure that should have gone through the
    /// restore path instead).
    #[test]
    fn account_refusal_is_pinned_for_every_error_code() {
        const ACCOUNT_REFUSAL: &[&str] = &[codes::USAGE_LIMIT_EXCEEDED, codes::ORG_NOT_PROVISIONED];

        let payload = serde_json::Map::new();
        for code in AuthError::ERROR_CODES {
            let err = AuthError::from_error_code(code, "message", &payload);
            if err.error_code() != *code {
                continue;
            }
            assert_eq!(
                err.is_account_refusal(),
                ACCOUNT_REFUSAL.contains(code),
                "{code} is on the wrong side of the account-refusal boundary",
            );
        }
    }

    /// An org the usage system has never heard of must not be told to upgrade
    /// a plan it does not have. Both refusals travel as `access_denied` on a
    /// 402, so `cs_code` is the only thing separating them.
    #[test]
    fn not_provisioned_is_not_reported_as_a_usage_limit() {
        let body = r#"{"error":"access_denied","cs_code":"ORG_NOT_PROVISIONED",
                       "error_description":"Organisation is not provisioned"}"#;

        let err = classify_issuance_failure(402, body).expect("402 must classify");

        assert_eq!(err.error_code(), codes::ORG_NOT_PROVISIONED);
        assert!(
            !err.to_string().to_lowercase().contains("upgrade"),
            "there is no plan to upgrade: {err}",
        );
    }

    /// The remedies differ, so the help text has to differ too — that text is
    /// the whole reason for keeping the two codes apart.
    #[test]
    fn the_two_account_refusals_advise_differently() {
        use miette::Diagnostic;

        let limit: AuthError = UsageLimitExceeded("over".into()).into();
        let missing: AuthError = OrgNotProvisioned("absent".into()).into();

        let help = |e: &AuthError| e.help().map(|h| h.to_string()).unwrap_or_default();

        assert!(help(&limit).to_lowercase().contains("upgrade"));
        assert!(help(&missing).to_lowercase().contains("support"));
        assert_ne!(help(&limit), help(&missing));
    }

    /// `help()` says what to do; `url()` says where — a caller building a UI
    /// around this should be able to render an actual link, not just prose.
    #[test]
    fn the_two_account_refusals_link_to_where_to_act() {
        use miette::Diagnostic;

        let limit: AuthError = UsageLimitExceeded("over".into()).into();
        let missing: AuthError = OrgNotProvisioned("absent".into()).into();

        let url = |e: &AuthError| e.url().map(|u| u.to_string());

        assert_eq!(
            url(&limit).as_deref(),
            Some("https://dashboard.cipherstash.com/billing"),
        );
        assert_eq!(
            url(&missing).as_deref(),
            Some("https://cipherstash.com/support"),
        );
    }

    /// Neither clears by asking again.
    #[test]
    fn both_account_refusals_are_non_retryable() {
        let limit: AuthError = UsageLimitExceeded("over".into()).into();
        let missing: AuthError = OrgNotProvisioned("absent".into()).into();

        assert!(!limit.is_retryable());
        assert!(!missing.is_retryable());
    }

    #[test]
    fn not_provisioned_round_trips_through_error_code() {
        let err =
            AuthError::from_error_code(codes::ORG_NOT_PROVISIONED, "msg", &serde_json::Map::new());
        assert_eq!(err.error_code(), codes::ORG_NOT_PROVISIONED);
        assert_eq!(err.to_string(), "msg");
    }

    /// A blank description must fall back rather than surfacing an empty
    /// message to the user.
    #[test]
    fn blank_description_falls_back_to_default() {
        let body = r#"{"error": "access_denied", "error_description": "   "}"#;
        let err = classify_issuance_failure(402, body).expect("402 must classify");
        assert_eq!(err.to_string(), UsageLimitExceeded::DEFAULT_MESSAGE);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The typed variant must survive the FFI round-trip; degrading to `CUSTOM`
    /// would put clients back to string-matching the message.
    #[test]
    fn usage_limit_round_trips_through_error_code() {
        let original = AuthError::UsageLimitExceeded(UsageLimitExceeded("over limit".into()));
        let json = serde_json::to_value(&original).unwrap();
        assert_eq!(json["type"], "USAGE_LIMIT_EXCEEDED");
        assert!(
            json.get("help").is_some(),
            "the remedy should cross the boundary with the error",
        );

        let rebuilt = AuthError::from_error_code(
            json["type"].as_str().unwrap(),
            json["message"].as_str().unwrap(),
            &serde_json::Map::new(),
        );
        assert_eq!(rebuilt.error_code(), codes::USAGE_LIMIT_EXCEEDED);
        assert_eq!(rebuilt.to_string(), original.to_string());
    }

    /// Same contract as `retryability_is_pinned_for_every_error_code`, for
    /// the "refresh the credential and retry" axis the FFI front-ends key
    /// off: a credential verdict must say so, and an account, authorisation
    /// or transport failure must not send the caller round a refresh loop
    /// that cannot fix it.
    #[test]
    fn credential_rejection_is_pinned_for_every_error_code() {
        const CREDENTIAL_REJECTION: &[&str] = &[
            codes::NOT_AUTHENTICATED,
            codes::EXPIRED_TOKEN,
            codes::INVALID_GRANT,
            codes::INVALID_CLIENT,
            codes::INVALID_ACCESS_KEY,
            codes::ALREADY_CONSUMED,
        ];

        let payload = serde_json::Map::new();
        let mut rejected_credentials = 0;
        let mut other_errors = 0;
        for code in AuthError::ERROR_CODES {
            let err = AuthError::from_error_code(code, "message", &payload);
            if err.error_code() != *code {
                continue;
            }
            let expected = CREDENTIAL_REJECTION.contains(code);
            assert_eq!(
                err.is_credential_rejection(),
                expected,
                "{code} is on the wrong side of the credential-rejection boundary",
            );
            if expected {
                rejected_credentials += 1;
            } else {
                other_errors += 1;
            }
        }
        assert!(
            rejected_credentials > 0 && other_errors > 0,
            "both sides of the boundary must be exercised: {rejected_credentials} credential rejections, {other_errors} other errors",
        );

        // `INVALID_ACCESS_KEY` does not round-trip through `from_error_code`,
        // so build it the way a malformed key does.
        let malformed_key =
            AuthError::from("".parse::<crate::access_key::AccessKey>().unwrap_err());
        assert_eq!(
            malformed_key.error_code(),
            codes::INVALID_ACCESS_KEY,
            "malformed access key should retain its error code"
        );
        assert!(
            malformed_key.is_credential_rejection(),
            "malformed access key should be a credential rejection: {malformed_key:?}"
        );
    }

    /// The account-refusal codes carry CTS's wording across the boundary,
    /// but a blank one falls back to the default rather than rendering an
    /// empty `Display`; a real message is kept exactly as given.
    #[test]
    fn from_error_code_falls_back_on_a_blank_account_refusal_message() {
        let payload = serde_json::Map::new();
        for (code, default) in [
            (
                codes::USAGE_LIMIT_EXCEEDED,
                UsageLimitExceeded::DEFAULT_MESSAGE,
            ),
            (
                codes::ORG_NOT_PROVISIONED,
                OrgNotProvisioned::DEFAULT_MESSAGE,
            ),
        ] {
            for blank in ["", "  \t"] {
                let err = AuthError::from_error_code(code, blank, &payload);
                assert_eq!(err.error_code(), code, "blank message should retain {code}");
                assert_eq!(err.to_string(), default, "{code} with {blank:?}");
            }
            let err = AuthError::from_error_code(code, " as sent ", &payload);
            assert_eq!(err.to_string(), " as sent ", "{code} keeps its message");
        }
    }

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

    /// Every `DeviceClientError` variant maps to its canonical `AuthError`
    /// code so `bind_client_device` failures share the one envelope path.
    #[cfg(all(feature = "http", not(target_arch = "wasm32")))]
    #[test]
    fn device_client_error_maps_to_canonical_auth_error() {
        use crate::DeviceClientError as E;

        // `Auth` unwraps to the inner error unchanged.
        assert_eq!(
            AuthError::from(E::Auth(AuthError::AccessDenied(AccessDenied))).error_code(),
            codes::ACCESS_DENIED,
        );
        // `Request` carries the transport's error through as `REQUEST_ERROR`.
        let request = AuthError::from(E::Request(RequestError(Box::new(std::io::Error::other(
            "connection refused",
        )))));
        assert_eq!(request.error_code(), codes::REQUEST_ERROR);
        assert!(
            request.to_string().contains("connection refused"),
            "{request}"
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
