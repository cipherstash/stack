use std::sync::Mutex;

use stack_auth::{AuthError, DeviceCodeStrategy, PendingDeviceCode};
use cts_common::Region;
use napi::bindgen_prelude::*;
use napi_derive::napi;

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

fn error_code(err: &AuthError) -> &'static str {
    match err {
        AuthError::Request(_) => "REQUEST_ERROR",
        AuthError::AccessDenied => "ACCESS_DENIED",
        AuthError::ExpiredToken => "EXPIRED_TOKEN",
        AuthError::InvalidGrant => "INVALID_GRANT",
        AuthError::InvalidClient => "INVALID_CLIENT",
        AuthError::InvalidUrl(_) => "INVALID_URL",
        AuthError::Region(_) => "INVALID_REGION",
        AuthError::Server(_) => "SERVER_ERROR",
        _ => "UNKNOWN_ERROR",
    }
}

fn to_napi_error(err: AuthError) -> napi::Error {
    let code = error_code(&err);
    napi::Error::new(Status::GenericFailure, format!("{code}: {err}"))
}

// ---------------------------------------------------------------------------
// TokenResult — plain data object
// ---------------------------------------------------------------------------

#[napi(object)]
pub struct TokenResult {
    /// The OAuth access token.
    pub access_token: String,
    /// Token type, typically `"Bearer"`.
    pub token_type: String,
    /// Number of seconds before the token expires.
    pub expires_in: f64,
}

// ---------------------------------------------------------------------------
// DeviceCodeResult — class with methods
// ---------------------------------------------------------------------------

#[napi]
pub struct DeviceCodeResult {
    /// The short code the user must enter to authorize this device.
    user_code: String,
    /// The base verification URI (without the user code embedded).
    verification_uri: String,
    /// The full verification URI with the user code pre-filled.
    verification_uri_complete: String,
    /// How many seconds the device code remains valid.
    expires_in: f64,
    /// The pending device code handle (consumed by `pollForToken`).
    pending: Mutex<Option<PendingDeviceCode>>,
}

#[napi]
impl DeviceCodeResult {
    #[napi(getter)]
    pub fn user_code(&self) -> String {
        self.user_code.clone()
    }

    #[napi(getter)]
    pub fn verification_uri(&self) -> String {
        self.verification_uri.clone()
    }

    #[napi(getter, js_name = "verificationUriComplete")]
    pub fn verification_uri_complete(&self) -> String {
        self.verification_uri_complete.clone()
    }

    #[napi(getter)]
    pub fn expires_in(&self) -> f64 {
        self.expires_in
    }

    /// Poll the auth server until the user completes authorization.
    ///
    /// **Consumes** the internal handle — it cannot be reused after this call.
    /// If you need to open the browser, call `openInBrowser` *before*
    /// `pollForToken`.
    #[napi]
    pub async fn poll_for_token(&self) -> Result<TokenResult> {
        let pending = self
            .pending
            .lock()
            .map_err(|_| napi::Error::new(Status::GenericFailure, "Lock poisoned"))?
            .take()
            .ok_or_else(|| {
                napi::Error::new(
                    Status::GenericFailure,
                    "Device code handle has already been consumed",
                )
            })?;

        let token = pending.poll_for_token().await.map_err(to_napi_error)?;

        Ok(TokenResult {
            access_token: token.access_token().as_str().to_string(),
            token_type: token.token_type().to_string(),
            expires_in: token.expires_in() as f64,
        })
    }

    /// Open the verification URI in the user's default browser.
    ///
    /// Does **not** consume the handle — you can still call `pollForToken`
    /// afterwards.
    #[napi]
    pub fn open_in_browser(&self) -> Result<bool> {
        let guard = self
            .pending
            .lock()
            .map_err(|_| napi::Error::new(Status::GenericFailure, "Lock poisoned"))?;

        match guard.as_ref() {
            Some(pending) => Ok(pending.open_in_browser()),
            None => Err(napi::Error::new(
                Status::GenericFailure,
                "Device code handle has already been consumed",
            )),
        }
    }
}

impl DeviceCodeResult {
    fn from_pending(pending: PendingDeviceCode) -> Self {
        Self {
            user_code: pending.user_code().to_string(),
            verification_uri: pending.verification_uri().to_string(),
            verification_uri_complete: pending.verification_uri_complete().to_string(),
            expires_in: pending.expires_in() as f64,
            pending: Mutex::new(Some(pending)),
        }
    }
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/// Begin the OAuth 2.0 Device Authorization flow.
#[napi]
pub async fn begin_device_code_flow(
    region: String,
    client_id: String,
) -> Result<DeviceCodeResult> {
    let region = Region::new(&region).map_err(|e| to_napi_error(AuthError::from(e)))?;
    let strategy = DeviceCodeStrategy::new(region, client_id).map_err(to_napi_error)?;
    let pending = strategy.begin().await.map_err(to_napi_error)?;
    Ok(DeviceCodeResult::from_pending(pending))
}

/// Variant of `beginDeviceCodeFlow` that targets a custom auth server URL.
///
/// Intended for **testing only** — requires the crate to be built with the
/// `test-utils` Cargo feature.
#[cfg(feature = "test-utils")]
#[napi]
pub async fn begin_device_code_flow_with_base_url(
    region: String,
    client_id: String,
    base_url: String,
) -> Result<DeviceCodeResult> {
    let region = Region::new(&region).map_err(|e| to_napi_error(AuthError::from(e)))?;
    let parsed_url: url::Url = base_url
        .parse()
        .map_err(|e: url::ParseError| to_napi_error(AuthError::from(e)))?;
    let strategy = DeviceCodeStrategy::new(region, client_id)
        .map_err(to_napi_error)?
        .with_base_url(parsed_url)
        .map_err(to_napi_error)?;
    let pending = strategy.begin().await.map_err(to_napi_error)?;
    Ok(DeviceCodeResult::from_pending(pending))
}
