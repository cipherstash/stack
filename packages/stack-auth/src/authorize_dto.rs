//! Shared DTO for the CTS `POST /api/authorise` endpoint.
//!
//! Both [`AccessKeyRefresher`](crate::access_key_refresher::AccessKeyRefresher)
//! and [`OidcRefresher`](crate::oidc_refresher::OidcRefresher) exchange a
//! credential for a CTS
//! service token at the same endpoint; the success response is identical, so
//! the wire contract lives here in one place. The request bodies differ
//! (different credential fields) and stay private to each refresher.

use crate::SecretToken;

/// Success response from `POST /api/authorise`.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthoriseResponse {
    pub(crate) access_token: SecretToken,
    pub(crate) expiry: u64,
}
