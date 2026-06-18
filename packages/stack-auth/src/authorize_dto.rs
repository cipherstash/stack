//! Shared DTO for the CTS `POST /api/authorise` endpoint.
//!
//! Both [`AccessKeyRefresher`](crate::access_key_refresher::AccessKeyRefresher)
//! and [`OidcRefresher`](crate::oidc_refresher::OidcRefresher) exchange a
//! credential for a CTS
//! service token at the same endpoint; the success response is identical, so
//! the wire contract lives here in one place. The request bodies differ
//! (different credential fields) and stay private to each refresher.

use crate::{SecretToken, Token};

/// Success response from `POST /api/authorise`.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthoriseResponse {
    pub(crate) access_token: SecretToken,
    pub(crate) expiry: u64,
}

/// A `/api/authorise` success response *is* a complete CTS service token. Both
/// the access-key and OIDC federation flows hit the same endpoint and mint the
/// same kind of token, so the response → [`Token`] mapping lives here once
/// rather than being duplicated in each refresher — duplication is exactly how
/// the CIP-3233 expiry bug survived in the OIDC refresher after being fixed for
/// access keys.
impl From<AuthoriseResponse> for Token {
    fn from(resp: AuthoriseResponse) -> Self {
        Token {
            access_token: resp.access_token,
            token_type: "Bearer".to_string(),
            // CTS `/api/authorise` returns `expiry` as an ABSOLUTE Unix epoch (it is
            // the JWT `exp` claim), NOT a relative duration. Adding `now` here would
            // push the local expiry decades into the future, so `AutoRefresh` would
            // never consider the token expired and never refresh it — the token would
            // then silently die at its real (~15 min) `exp` and every request would
            // fail until the process restarted. Use the value as-is. See CIP-3233.
            expires_at: resp.expiry,
            // `/api/authorise` issues no refresh token and carries no region / client
            // / device metadata; those are populated only by the OAuth device flow.
            refresh_token: None,
            region: None,
            client_id: None,
            device_instance_id: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The single source of truth for the response → `Token` mapping: CTS
    /// `expiry` is an ABSOLUTE Unix epoch and must be used verbatim. Pre-fix the
    /// refreshers did `now + expiry`; the regression in CIP-3233 (and its OIDC
    /// sibling) now cannot recur in only one flow because there is only one flow.
    #[test]
    fn authorise_response_maps_expiry_as_absolute_epoch() {
        let resp = AuthoriseResponse {
            access_token: SecretToken::new("cts-token"),
            expiry: 1_900_000_000, // an absolute Unix epoch, not a duration
        };

        let token = Token::from(resp);

        assert_eq!(
            token.expires_at(),
            1_900_000_000,
            "expiry must be carried through as-is, never offset by `now`"
        );
        assert_eq!(token.token_type(), "Bearer");
        assert_eq!(token.access_token().as_str(), "cts-token");
        assert!(
            token.refresh_token.is_none(),
            "/api/authorise issues no refresh token"
        );
    }
}
