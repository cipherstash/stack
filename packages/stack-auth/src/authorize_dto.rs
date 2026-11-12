//! Shared DTO for the CTS `POST /api/authorise` endpoint.
//!
//! Both [`AccessKeyRefresher`](crate::access_key_refresher::AccessKeyRefresher)
//! and [`OidcFederation`](crate::oidc_refresher::OidcFederation) exchange a
//! credential for a CTS
//! service token at the same endpoint; the success response is identical, so
//! the wire contract lives here in one place. The request bodies differ
//! (different credential fields) and stay private to each exchange.

use crate::token::cap_expires_at;
use crate::{SecretToken, Token};

/// Success response from `POST /api/authorise`.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthoriseResponse {
    pub(crate) access_token: SecretToken,
    pub(crate) expiry: u64,
}

impl AuthoriseResponse {
    /// A `/api/authorise` success response *is* a complete CTS service token.
    /// Both the access-key and OIDC federation flows hit the same endpoint and
    /// mint the same kind of token, so the response → [`Token`] mapping lives
    /// here once rather than being duplicated in each refresher — duplication
    /// is exactly how the CIP-3233 expiry bug survived in the OIDC refresher
    /// after being fixed for access keys.
    ///
    /// `now` is the current Unix time, used only to cap the server's expiry.
    pub(crate) fn into_token(self, now: u64) -> Token {
        Token {
            access_token: self.access_token,
            token_type: "Bearer".to_string(),
            // CTS `/api/authorise` returns `expiry` as an ABSOLUTE Unix epoch (it is
            // the JWT `exp` claim), NOT a relative duration. Adding `now` here would
            // push the local expiry decades into the future, so `AutoRefresh` would
            // never consider the token expired and never refresh it — the token would
            // then silently die at its real (~15 min) `exp` and every request would
            // fail until the process restarted. Use the value as-is (see CIP-3233),
            // capped at 30 days from now so an absurd value cannot do the same.
            expires_at: cap_expires_at(now, self.expiry),
            // `/api/authorise` issues no refresh token and carries no region / client
            // / device metadata; those are populated only by the OAuth device flow.
            refresh_token: None,
            region: None,
            client_id: None,
            device_instance_id: None,
            federated_from: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::MAX_TOKEN_LIFETIME_SECS;

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

        let token = resp.into_token(1_899_999_100);

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

    /// An `expiry` more than 30 days after `now` is cut back to `now` plus 30
    /// days, however large it is.
    #[test]
    fn authorise_response_caps_expiry_at_thirty_days_from_now() {
        let now = 1_900_000_000;
        for expiry in [now + MAX_TOKEN_LIFETIME_SECS + 1, u64::MAX] {
            let resp = AuthoriseResponse {
                access_token: SecretToken::new("cts-token"),
                expiry,
            };
            assert_eq!(
                resp.into_token(now).expires_at(),
                now + MAX_TOKEN_LIFETIME_SECS
            );
        }
    }

    /// An `expiry` exactly 30 days out is kept, and so is one already past.
    #[test]
    fn authorise_response_keeps_an_expiry_within_the_cap() {
        let now = 1_900_000_000;
        for expiry in [now + MAX_TOKEN_LIFETIME_SECS, now - 1] {
            let resp = AuthoriseResponse {
                access_token: SecretToken::new("cts-token"),
                expiry,
            };
            assert_eq!(resp.into_token(now).expires_at(), expiry);
        }
    }
}
