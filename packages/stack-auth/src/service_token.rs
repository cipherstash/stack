use cts_common::claims::Audience;
use url::Url;
use vitaminc::protected::OpaqueDebug;
use zeroize::ZeroizeOnDrop;

use crate::{AuthError, SecretToken};

/// A CipherStash service token returned by an [`AuthStrategy`](crate::AuthStrategy).
///
/// Wraps a bearer credential ([`SecretToken`]) together with eagerly decoded
/// JWT claims that are used for service discovery. The JWT is decoded (but
/// **not** signature-verified) using [`cts_common::claims::Claims`], so only
/// CipherStash-issued service tokens (from CTS or the access-key exchange)
/// will have their claims resolved.
///
/// # Decoded claims
///
/// * `issuer()` — the `iss` URL, i.e. the CTS host for this workspace.
/// * `audience()` — the `aud` claim, typically the ZeroKMS endpoint.
///
/// For non-JWT tokens (e.g. static test tokens) or JWTs that don't match
/// the CipherStash claims schema, both methods return
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
    decoded: Option<DecodedClaims>,
}

#[derive(Clone, Debug)]
struct DecodedClaims {
    issuer: Url,
    audience: Audience,
}

impl ServiceToken {
    /// Create a `ServiceToken` from a [`SecretToken`].
    ///
    /// If the token string is a valid JWT with `iss` and `aud` claims, they
    /// are decoded eagerly. If decoding fails (not a JWT, missing claims, etc.)
    /// the token is still usable as a bearer credential — `issuer()` and
    /// `audience()` will simply return an error.
    pub fn new(secret: SecretToken) -> Self {
        let decoded = Self::try_decode(&secret);
        Self { secret, decoded }
    }

    /// Expose the inner token string for use as a bearer credential.
    pub fn as_str(&self) -> &str {
        self.secret.as_str()
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
            .ok_or_else(|| AuthError::InvalidToken("token is not a valid JWT".into()))
    }

    /// Return the `aud` (audience) from the JWT claims.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::InvalidToken`] if the token is not a valid JWT.
    pub fn audience(&self) -> Result<&Audience, AuthError> {
        self.decoded
            .as_ref()
            .map(|d| &d.audience)
            .ok_or_else(|| AuthError::InvalidToken("token is not a valid JWT".into()))
    }

    /// Attempt to decode the JWT claims from the token string.
    /// NOTE: This does not verify the token signature or validate any claims, it only decodes the claims if the token is a well-formed JWT.
    fn try_decode(secret: &SecretToken) -> Option<DecodedClaims> {
        use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
        use std::collections::HashSet;

        let token_str = secret.as_str();
        let header = decode_header(token_str).ok()?;

        let dummy_key = DecodingKey::from_secret(&[]);
        let mut validation = Validation::new(header.alg);
        validation.validate_exp = false;
        validation.validate_aud = false;
        validation.required_spec_claims = HashSet::new();
        validation.insecure_disable_signature_validation();

        let data: jsonwebtoken::TokenData<cts_common::claims::Claims> =
            decode(token_str, &dummy_key, &validation).ok()?;

        let issuer: Url = data.claims.iss.parse().ok()?;

        Some(DecodedClaims {
            issuer,
            audience: data.claims.aud,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jwt(iss: &str, aud: &str) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = serde_json::json!({
            "iss": iss,
            "sub": "CS|test-user",
            "aud": aud,
            "iat": now,
            "exp": now + 3600,
            "workspace": "ZVATKW3VHMFG27DY",
            "scope": "",
        });

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap()
    }

    #[test]
    fn jwt_token_provides_issuer_and_audience() {
        let jwt = make_jwt("https://cts.example.com/", "https://zerokms.example.com/");
        let token = ServiceToken::new(SecretToken::new(jwt.clone()));

        assert_eq!(token.as_str(), jwt);
        assert_eq!(token.issuer().unwrap().as_str(), "https://cts.example.com/");
        assert!(token.audience().is_ok());
    }

    #[test]
    fn non_jwt_token_returns_errors() {
        let token = ServiceToken::new(SecretToken::new("not-a-jwt"));

        assert_eq!(token.as_str(), "not-a-jwt");
        assert!(token.issuer().is_err());
        assert!(token.audience().is_err());
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let jwt = make_jwt("https://cts.example.com/", "https://zerokms.example.com/");
        let token = ServiceToken::new(SecretToken::new(jwt.clone()));
        let debug = format!("{:?}", token);
        assert!(!debug.contains(&jwt));
    }
}
