use serde::{Deserialize, Serialize};
use vitaminc::protected::OpaqueDebug;
use zeroize::ZeroizeOnDrop;

use crate::SecretToken;

/// A device code issued by the auth server, exchanged for an access token
/// once the user authorizes.
#[derive(OpaqueDebug, ZeroizeOnDrop, Deserialize, Serialize)]
#[serde(transparent)]
pub(super) struct DeviceCode(String);

#[derive(Deserialize)]
pub(super) struct DeviceCodeResponse {
    pub device_code: DeviceCode,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: u64,
}

#[derive(Deserialize)]
pub(super) struct TokenResponse {
    pub access_token: SecretToken,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(default)]
    pub refresh_token: Option<SecretToken>,
}

#[derive(Deserialize)]
pub(super) struct ErrorResponse {
    pub error: String,
    #[serde(default)]
    pub error_description: String,
}

#[derive(Serialize)]
pub(super) struct DeviceCodeRequest<'a> {
    pub client_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_instance_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<&'a str>,
}

#[derive(Serialize)]
pub(super) struct TokenRequest<'a> {
    pub client_id: &'a str,
    pub device_code: &'a DeviceCode,
    pub grant_type: &'a str,
}
