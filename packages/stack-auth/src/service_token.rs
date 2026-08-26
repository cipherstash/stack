use cts_common::claims::{ServiceType, Services};
use cts_common::WorkspaceId;
use url::Url;
use vitaminc::protected::OpaqueDebug;
use zeroize::ZeroizeOnDrop;

use crate::{AuthError, SecretToken};

/// A CipherStash service token returned by an [`AuthStrategy`](crate::AuthStrategy).
///
/// Wraps a bearer credential ([`SecretToken`]) together with eagerly decoded
/// JWT claims that are used for service discovery. The JWT is decoded (but
/// **not** signature-verified) using [`cts_common::claims::ClientClaims`], so
/// only CipherStash-issued service tokens (from CTS or the access-key exchange)
/// will have their claims resolved.
///
/// # Decoded claims
///
/// * `subject()` — the `sub` claim (e.g. `"CS|auth0|user123"`).
/// * `workspace_id()` — the workspace identifier from the token.
/// * `issuer()` — the `iss` URL, i.e. the CTS host for this workspace.
/// * `zerokms_url()` — the ZeroKMS endpoint from the `services` claim.
///
/// For non-JWT tokens (e.g. static test tokens) or JWTs that don't match
/// the CipherStash claims schema, these methods return
/// `Err(AuthError::InvalidToken)`.
///
/// # Security
///
/// Like [`SecretToken`], this is zeroized on drop and hidden from [`Debug`]
/// output.
#[derive(Clone, OpaqueDebug, ZeroizeOnDrop)]
pub struct ServiceToken {
    secret: SecretToken,
    #[zeroize(skip)]
    decoded: Result<DecodedClaims, String>,
}

#[derive(Clone, Debug)]
struct DecodedClaims {
    subject: String,
    workspace: WorkspaceId,
    issuer: Url,
    services: Services,
}

impl ServiceToken {
    /// Create a `ServiceToken` from a [`SecretToken`].
    ///
    /// If the token string is a valid JWT with `iss` and `services` claims,
    /// they are decoded eagerly. If decoding fails (not a JWT, missing claims,
    /// etc.) the token is still usable as a bearer credential — `issuer()` and
    /// `zerokms_url()` will simply return an error.
    pub fn new(secret: SecretToken) -> Self {
        let decoded = Self::try_decode(&secret);
        Self { secret, decoded }
    }

    /// Expose the inner token string for use as a bearer credential.
    pub fn as_str(&self) -> &str {
        self.secret.as_str()
    }

    /// Return the `sub` (subject) claim from the JWT.
    ///
    /// In CipherStash tokens the subject encodes the principal identity,
    /// e.g. `"CS|auth0|user123"` for a user or `"CS|CSAKkeyId"` for an
    /// access key.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidToken`] if the token is not a valid JWT or
    /// the claims could not be decoded.
    pub fn subject(&self) -> Result<&str, AuthError> {
        self.decoded
            .as_ref()
            .map(|d| d.subject.as_str())
            .map_err(|reason| AuthError::InvalidToken(crate::error::InvalidToken(reason.clone())))
    }

    /// Return the workspace identifier from the JWT claims.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidToken`] if the token is not a valid JWT or
    /// the claims could not be decoded.
    pub fn workspace_id(&self) -> Result<&WorkspaceId, AuthError> {
        self.decoded
            .as_ref()
            .map(|d| &d.workspace)
            .map_err(|reason| AuthError::InvalidToken(crate::error::InvalidToken(reason.clone())))
    }

    /// Verify the token's `workspace` claim matches `expected`, returning the
    /// token unchanged on a match.
    ///
    /// This is the shared post-auth check that every strategy bound to a
    /// workspace CRN ([`AccessKeyStrategy`](crate::AccessKeyStrategy),
    /// [`OidcFederationStrategy`](crate::OidcFederationStrategy)) runs on each
    /// [`get_token`](crate::AuthStrategy::get_token), so a token CTS minted for
    /// a different workspace (or loaded from a poisoned shared cache) is never
    /// handed back.
    ///
    /// # Errors
    ///
    /// - [`AuthError::WorkspaceMismatch`] if the token's `workspace` claim is a
    ///   different workspace than `expected`.
    /// - [`AuthError::InvalidToken`] if the token is not a valid JWT or its
    ///   `workspace` claim could not be decoded, so verification can't run.
    pub(crate) fn verify_workspace(self, expected: WorkspaceId) -> Result<Self, AuthError> {
        let token_workspace = *self.workspace_id()?;
        if token_workspace != expected {
            return Err(AuthError::WorkspaceMismatch(
                crate::error::WorkspaceMismatch {
                    expected_workspace: expected,
                    token_workspace,
                },
            ));
        }
        Ok(self)
    }

    /// Return the `iss` (issuer) URL from the JWT claims.
    ///
    /// In CipherStash tokens the issuer is the CTS host URL for the workspace.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidToken`] if the token is not a valid JWT or
    /// the `iss` claim could not be parsed as a URL.
    pub fn issuer(&self) -> Result<&Url, AuthError> {
        self.decoded
            .as_ref()
            .map(|d| &d.issuer)
            .map_err(|reason| AuthError::InvalidToken(crate::error::InvalidToken(reason.clone())))
    }

    /// Return the decoded services map from the JWT claims.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidToken`] if the token is not a valid JWT or
    /// the claims could not be decoded.
    pub fn services(&self) -> Result<&Services, AuthError> {
        self.decoded
            .as_ref()
            .map(|d| &d.services)
            .map_err(|reason| AuthError::InvalidToken(crate::error::InvalidToken(reason.clone())))
    }

    /// Return the ZeroKMS endpoint URL from the `services` claim.
    ///
    /// CTS-issued JWTs include a `services` claim containing a map of service
    /// type to endpoint URL. This method looks up the `zerokms` entry.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidToken`] if the token is not a valid JWT or
    /// the `services` claim does not include a ZeroKMS endpoint.
    pub fn zerokms_url(&self) -> Result<Url, AuthError> {
        self.services()?
            .get(ServiceType::ZeroKms)
            .cloned()
            .ok_or_else(|| {
                AuthError::InvalidToken(crate::error::InvalidToken(
                    "Token does not include a ZeroKMS endpoint in the services claim".into(),
                ))
            })
    }

    /// Attempt to decode the JWT claims from the token string.
    ///
    /// NOTE: This does not verify the token signature or validate any claims,
    /// it only decodes the claims if the token is a well-formed JWT.
    fn try_decode(secret: &SecretToken) -> Result<DecodedClaims, String> {
        let claims = decode_claims(secret.as_str())?;
        let issuer: Url = claims
            .iss
            .parse()
            .map_err(|e| format!("iss claim is not a valid URL: {e}"))?;

        Ok(DecodedClaims {
            subject: claims.sub,
            workspace: claims.workspace,
            issuer,
            services: claims.services,
        })
    }
}

/// Decode the JWT payload into
/// [`ClientClaims`](cts_common::claims::ClientClaims) without verifying the
/// signature — we only read claims from a token we already hold. See
/// [`crate::decode_jwt_payload`] for why we parse by hand.
///
/// Deliberately *not* `cts_common::claims::Claims`: that is the server's view,
/// where every claim is required so an unauthorised token is rejected. Reading
/// discovery claims out of a token we already hold enforces nothing, so it must
/// not fail over a claim it never reads — `org_id` in particular, whose absence
/// is for ZeroKMS and CTS to reject once they have verified the signature.
fn decode_claims(token_str: &str) -> Result<cts_common::claims::ClientClaims, String> {
    // Strip the `AuthError::InvalidToken` prefix — callers re-wrap this string
    // in `AuthError::InvalidToken(reason)`, and we don't want "Invalid token:
    // Invalid token: ..." in the final message.
    crate::decode_jwt_payload(token_str).map_err(|e| match e {
        crate::AuthError::InvalidToken(crate::error::InvalidToken(reason)) => reason,
        other => other.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn claims_json(iss: &str, services: Option<BTreeMap<&str, &str>>) -> serde_json::Value {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut claims = serde_json::json!({
            "iss": iss,
            "sub": "CS|test-user",
            "aud": "legacy-aud-value",
            "iat": now,
            "exp": now + 3600,
            "workspace": "ZVATKW3VHMFG27DY",
            "org_id": "org_test_default",
            "scope": "",
        });

        if let Some(svc) = services {
            claims["services"] = serde_json::to_value(svc).unwrap();
        }

        claims
    }

    fn encode_claims(claims: serde_json::Value) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap()
    }

    fn make_jwt(iss: &str, services: Option<BTreeMap<&str, &str>>) -> String {
        encode_claims(claims_json(iss, services))
    }

    /// A JWT carrying every claim [`make_jwt`] mints *except* `org_id` — i.e. a
    /// token from a CTS that predates the claim, or one rolled back past it.
    fn make_jwt_without_org_id(iss: &str, services: Option<BTreeMap<&str, &str>>) -> String {
        let mut claims = claims_json(iss, services);
        claims.as_object_mut().unwrap().remove("org_id");
        encode_claims(claims)
    }

    fn services_with_zerokms(url: &str) -> Option<BTreeMap<&str, &str>> {
        Some(BTreeMap::from([("zerokms", url)]))
    }

    #[test]
    fn jwt_token_provides_issuer() {
        let jwt = make_jwt(
            "https://cts.example.com/",
            services_with_zerokms("https://zerokms.example.com/"),
        );
        let token = ServiceToken::new(SecretToken::new(jwt.clone()));

        assert_eq!(token.as_str(), jwt);
        assert_eq!(token.issuer().unwrap().as_str(), "https://cts.example.com/");
    }

    #[test]
    fn non_jwt_token_returns_errors_with_reason() {
        let token = ServiceToken::new(SecretToken::new("not-a-jwt"));

        assert_eq!(token.as_str(), "not-a-jwt");

        let err = token.issuer().unwrap_err().to_string();
        assert!(
            err.contains("three segments"),
            "expected specific decode error, got: {err}"
        );
    }

    #[test]
    fn zerokms_url_from_services_claim() {
        let jwt = make_jwt(
            "https://cts.example.com/",
            services_with_zerokms("https://zerokms.example.com/"),
        );
        let token = ServiceToken::new(SecretToken::new(jwt));
        assert_eq!(
            token.zerokms_url().unwrap().as_str(),
            "https://zerokms.example.com/"
        );
    }

    #[test]
    fn zerokms_url_from_services_claim_localhost() {
        let jwt = make_jwt(
            "https://cts.example.com/",
            services_with_zerokms("http://localhost:3002/"),
        );
        let token = ServiceToken::new(SecretToken::new(jwt));
        assert_eq!(
            token.zerokms_url().unwrap().as_str(),
            "http://localhost:3002/"
        );
    }

    #[test]
    fn zerokms_url_errors_when_services_claim_missing() {
        let jwt = make_jwt("https://cts.example.com/", None);
        let token = ServiceToken::new(SecretToken::new(jwt));
        let err = token.zerokms_url().unwrap_err().to_string();
        assert!(
            err.contains("services claim"),
            "expected services claim error, got: {err}"
        );
    }

    #[test]
    fn zerokms_url_errors_for_non_jwt() {
        let token = ServiceToken::new(SecretToken::new("not-a-jwt"));
        assert!(token.zerokms_url().is_err());
    }

    #[test]
    fn services_returns_map_for_valid_jwt() {
        let jwt = make_jwt(
            "https://cts.example.com/",
            services_with_zerokms("https://zerokms.example.com/"),
        );
        let token = ServiceToken::new(SecretToken::new(jwt));
        let services = token.services().unwrap();
        assert_eq!(
            services
                .get(cts_common::claims::ServiceType::ZeroKms)
                .map(|u| u.as_str()),
            Some("https://zerokms.example.com/")
        );
    }

    #[test]
    fn services_returns_empty_map_when_claim_missing() {
        let jwt = make_jwt("https://cts.example.com/", None);
        let token = ServiceToken::new(SecretToken::new(jwt));
        let services = token.services().unwrap();
        assert!(services.is_empty());
    }

    #[test]
    fn services_errors_for_non_jwt() {
        let token = ServiceToken::new(SecretToken::new("not-a-jwt"));
        let err = token.services().unwrap_err().to_string();
        assert!(
            err.contains("three segments"),
            "expected specific decode error, got: {err}"
        );
    }

    #[test]
    fn subject_from_valid_jwt() {
        let jwt = make_jwt(
            "https://cts.example.com/",
            services_with_zerokms("https://zerokms.example.com/"),
        );
        let token = ServiceToken::new(SecretToken::new(jwt));
        assert_eq!(
            token.subject().unwrap(),
            "CS|test-user",
            "subject should match JWT sub claim"
        );
    }

    #[test]
    fn subject_errors_for_non_jwt() {
        let token = ServiceToken::new(SecretToken::new("not-a-jwt"));
        assert!(
            token.subject().is_err(),
            "subject should error for non-JWT token"
        );
    }

    #[test]
    fn workspace_id_from_valid_jwt() {
        let jwt = make_jwt(
            "https://cts.example.com/",
            services_with_zerokms("https://zerokms.example.com/"),
        );
        let token = ServiceToken::new(SecretToken::new(jwt));
        assert_eq!(
            token.workspace_id().unwrap().to_string(),
            "ZVATKW3VHMFG27DY",
            "workspace_id should match JWT workspace claim"
        );
    }

    #[test]
    fn workspace_id_errors_for_non_jwt() {
        let token = ServiceToken::new(SecretToken::new("not-a-jwt"));
        assert!(
            token.workspace_id().is_err(),
            "workspace_id should error for non-JWT token"
        );
    }

    #[test]
    fn verify_workspace_returns_token_when_workspace_matches() {
        let jwt = make_jwt(
            "https://cts.example.com/",
            services_with_zerokms("https://zerokms.example.com/"),
        );
        let token = ServiceToken::new(SecretToken::new(jwt));
        let expected: WorkspaceId = "ZVATKW3VHMFG27DY".parse().unwrap();

        let verified = token
            .verify_workspace(expected)
            .expect("matching workspace should pass verification");
        assert_eq!(
            verified.workspace_id().unwrap().to_string(),
            "ZVATKW3VHMFG27DY",
            "verified token should still carry its workspace claim",
        );
    }

    #[test]
    fn verify_workspace_errors_with_mismatch_when_workspace_differs() {
        // make_jwt mints a token for workspace ZVATKW3VHMFG27DY.
        let jwt = make_jwt(
            "https://cts.example.com/",
            services_with_zerokms("https://zerokms.example.com/"),
        );
        let token = ServiceToken::new(SecretToken::new(jwt));
        let expected: WorkspaceId = "AAAAAAAAAAAAAAAA".parse().unwrap();

        let err = token
            .verify_workspace(expected)
            .expect_err("a different expected workspace must be rejected");
        match err {
            AuthError::WorkspaceMismatch(crate::error::WorkspaceMismatch {
                expected_workspace,
                token_workspace,
            }) => {
                assert_eq!(expected_workspace.to_string(), "AAAAAAAAAAAAAAAA");
                assert_eq!(token_workspace.to_string(), "ZVATKW3VHMFG27DY");
            }
            other => panic!("expected WorkspaceMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_workspace_errors_with_invalid_token_for_non_jwt() {
        // A non-JWT can't be decoded, so verification can't run.
        let token = ServiceToken::new(SecretToken::new("not-a-jwt"));
        let expected: WorkspaceId = "ZVATKW3VHMFG27DY".parse().unwrap();

        let err = token
            .verify_workspace(expected)
            .expect_err("a non-JWT token must surface InvalidToken");
        assert!(
            matches!(err, AuthError::InvalidToken(_)),
            "expected InvalidToken, got {err:?}",
        );
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let jwt = make_jwt(
            "https://cts.example.com/",
            services_with_zerokms("https://zerokms.example.com/"),
        );
        let token = ServiceToken::new(SecretToken::new(jwt.clone()));
        let debug = format!("{:?}", token);
        assert!(!debug.contains(&jwt));
    }

    /// `org_id` is a *server-side* requirement: ZeroKMS and CTS reject a token
    /// without it, after verifying the signature. This decode path verifies
    /// nothing and reads only `sub`/`workspace`/`iss`/`services`, so a claim it
    /// never looks at must not be able to break service discovery — otherwise a
    /// CTS rolled back past the commit that started minting `org_id` takes every
    /// SDK and CLI down with it, not just billing.
    #[test]
    fn resolves_discovery_claims_without_org_id() {
        let jwt = make_jwt_without_org_id(
            "https://cts.example.com/",
            services_with_zerokms("https://zerokms.example.com/"),
        );
        let token = ServiceToken::new(SecretToken::new(jwt));

        assert_eq!(token.subject().unwrap(), "CS|test-user");
        assert_eq!(
            token.workspace_id().unwrap().to_string(),
            "ZVATKW3VHMFG27DY"
        );
        assert_eq!(token.issuer().unwrap().as_str(), "https://cts.example.com/");
        assert_eq!(
            token.zerokms_url().unwrap().as_str(),
            "https://zerokms.example.com/"
        );
    }
}
