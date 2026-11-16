//! Verification of the access tokens CTS issues, before a strategy hands one
//! out.
//!
//! Without it the client trusts whatever `authorize` returned: whoever
//! controls the auth URL (an injected `CS_CTS_HOST`, a compromised
//! dependency, a poisoned token store) can hand the client a token naming
//! any scopes, any issuer and any ZeroKMS endpoint, and the client sends key
//! requests where that token says.
//!
//! A [`TokenVerifier`] checks every token against a **trusted issuer that is
//! pinned separately from the auth URL**: by default the CTS host that
//! service discovery names for the workspace's region, or one set
//! explicitly with a builder's `trusted_issuer`. The base URL override and
//! `CS_CTS_HOST` change where tokens are *requested*; they never change which
//! issuer is *trusted*. For each token it checks, in this order:
//!
//! 1. the header names `RS256` (what CTS signs with) — nothing else,
//!    `none` and the HMAC algorithms in particular, is accepted;
//! 2. `iss` is the trusted issuer;
//! 3. `exp` has not passed (with [`LEEWAY_SECS`] of clock skew allowed);
//! 4. `aud` contains the expected audience, when the strategy requested one;
//! 5. the signature verifies under a key from the trusted issuer's JWKS
//!    (`<issuer>/.well-known/jwks.json`), never from a URL the token names.
//!
//! A token that fails any check is refused with one opaque
//! [`AuthError::InvalidToken`]; which check failed is logged at `warn`, and
//! nothing from the token itself is.
//!
//! The JWKS is cached for [`KEYS_TTL_SECS`]. A token signed by a key the
//! cache does not hold triggers an early refetch, so a rotated key works
//! immediately. Fetches, successful or failed, are at most one every
//! [`MIN_REFETCH_SECS`], so neither a run of forged `kid`s nor a CTS outage
//! turns every call into a request to CTS.

use std::fmt;

use cts_common::claims::Audience;
use cts_common::{CtsServiceDiscovery, Region, ServiceDiscovery};
use url::Url;

use crate::clock::{system_clock, SharedClock};
use crate::error::{InvalidToken, ServerError};
use crate::transport::{self, SharedTransport};
use crate::{AuthError, ServiceToken};

/// Clock skew allowed on `exp`, matching what ZeroKMS allows.
pub(crate) const LEEWAY_SECS: u64 = 60;

/// How long a fetched JWKS is used before it is fetched again.
pub(crate) const KEYS_TTL_SECS: u64 = 60 * 60;

/// The shortest interval between two fetches of the JWKS.
pub(crate) const MIN_REFETCH_SECS: u64 = 60;

/// The only signing algorithm accepted: CTS signs with RSASSA-PKCS1-v1_5 and
/// SHA-256.
const ALGORITHM: &str = "RS256";

/// The message every refused token gets. Which check failed is logged, not
/// returned (see the module docs).
const REFUSED: &str =
    "the access token could not be verified against the trusted CTS issuer's signing keys";

/// What a strategy builder was asked to do about verification.
///
/// Resolved into a [`TokenVerifier`] at `build`, once the builder knows the
/// region and the transport.
#[derive(Clone, Debug, Default)]
pub(crate) enum Verification {
    /// Tokens are not verified (the default, for now).
    #[default]
    Off,
    /// Verify against the CTS that service discovery names for the region.
    RegionIssuer,
    /// Verify against this issuer.
    Issuer(Url),
}

impl Verification {
    /// Verify against the region's CTS, unless an issuer is already pinned.
    pub(crate) fn enable(self) -> Self {
        match self {
            Verification::Off => Verification::RegionIssuer,
            pinned => pinned,
        }
    }

    /// The verifier this setting asks for, or `None` when it is off.
    ///
    /// `region` is asked for only when the issuer comes from it, so a
    /// strategy with verification off fails in no new way.
    pub(crate) fn resolve(
        self,
        region: impl FnOnce() -> Result<Region, AuthError>,
        audience: Option<String>,
        transport: &SharedTransport,
    ) -> Result<Option<TokenVerifier>, AuthError> {
        let issuer = match self {
            Verification::Off => return Ok(None),
            Verification::RegionIssuer => CtsServiceDiscovery::endpoint(region()?)?,
            Verification::Issuer(issuer) => issuer,
        };
        TokenVerifier::new(issuer, audience, transport.clone(), system_clock()).map(Some)
    }
}

/// `token`, verified by `verifier` when there is one.
pub(crate) async fn verify_if(
    verifier: Option<&TokenVerifier>,
    token: ServiceToken,
) -> Result<ServiceToken, AuthError> {
    match verifier {
        Some(verifier) => verifier.verify(token).await,
        None => Ok(token),
    }
}

/// Verifies CTS access tokens against a pinned issuer's signing keys. See the
/// module docs.
pub(crate) struct TokenVerifier {
    issuer: Url,
    jwks_url: Url,
    audience: Option<String>,
    transport: SharedTransport,
    clock: SharedClock,
    keys: tokio::sync::Mutex<KeyCache>,
}

#[derive(Default)]
struct KeyCache {
    keys: Vec<SigningKey>,
    /// When the keys were last fetched; `None` before the first fetch.
    fetched_at: Option<u64>,
    /// When a fetch was last attempted, successful or not.
    attempted_at: Option<u64>,
    /// Whether that attempt failed.
    attempt_failed: bool,
}

/// One RSA public key from the JWKS, as big-endian modulus and exponent.
#[derive(Clone)]
struct SigningKey {
    kid: Option<String>,
    n: Vec<u8>,
    e: Vec<u8>,
}

impl TokenVerifier {
    pub(crate) fn new(
        issuer: Url,
        audience: Option<String>,
        transport: SharedTransport,
        clock: SharedClock,
    ) -> Result<Self, AuthError> {
        let issuer = crate::ensure_trailing_slash(issuer);
        let jwks_url = cts_common::oidc::jwks_url(issuer.as_str())?;
        Ok(Self {
            issuer,
            jwks_url,
            audience,
            transport,
            clock,
            keys: tokio::sync::Mutex::new(KeyCache::default()),
        })
    }

    /// Return `token` if it verifies, else [`AuthError::InvalidToken`].
    ///
    /// A failure to fetch the signing keys is the transport's or the
    /// server's error ([`AuthError::Request`] or [`AuthError::Server`]), not
    /// the token's: it says nothing about whether the token is genuine.
    pub(crate) async fn verify(&self, token: ServiceToken) -> Result<ServiceToken, AuthError> {
        match self.check(token.as_str()).await? {
            Ok(()) => Ok(token),
            Err(rejection) => {
                tracing::warn!(
                    issuer = %self.issuer,
                    %rejection,
                    "refused an access token that did not verify"
                );
                Err(AuthError::InvalidToken(InvalidToken(REFUSED.to_string())))
            }
        }
    }

    /// The outer `Result` is a failure to fetch the keys; the inner one is
    /// the verdict on the token.
    async fn check(&self, token: &str) -> Result<Result<(), Rejection>, AuthError> {
        let parts = match Parts::split(token) {
            Ok(parts) => parts,
            Err(rejection) => return Ok(Err(rejection)),
        };
        if let Err(rejection) = self.check_claims(&parts) {
            return Ok(Err(rejection));
        }
        let Some(key) = self.key_for(parts.header.kid.as_deref()).await? else {
            return Ok(Err(Rejection::UnknownKey));
        };
        if rs256::verify(&key, parts.signed.as_bytes(), &parts.signature) {
            Ok(Ok(()))
        } else {
            Ok(Err(Rejection::Signature))
        }
    }

    fn check_claims(&self, parts: &Parts<'_>) -> Result<(), Rejection> {
        if parts.header.alg != ALGORITHM {
            return Err(Rejection::Algorithm);
        }
        let claims = &parts.claims;
        let issuer = Url::parse(&claims.iss)
            .map(crate::ensure_trailing_slash)
            .map_err(|_| Rejection::Issuer)?;
        if issuer != self.issuer {
            return Err(Rejection::Issuer);
        }
        if claims.exp.saturating_add(LEEWAY_SECS) <= self.clock.now_unix_secs() {
            return Err(Rejection::Expired);
        }
        if let Some(expected) = &self.audience {
            if !claims
                .aud
                .as_ref()
                .is_some_and(|aud| aud.contains(expected))
            {
                return Err(Rejection::Audience);
            }
        }
        Ok(())
    }

    /// The key `kid` names, fetching the JWKS when the cache is empty or
    /// stale, or when it lacks that key.
    ///
    /// No more than one fetch is attempted every [`MIN_REFETCH_SECS`],
    /// whether the last one succeeded or failed, so neither a run of forged
    /// `kid`s nor a CTS outage turns every call into a request. While a fetch
    /// cannot be made or has failed, a key already in the cache is still
    /// used, even past [`KEYS_TTL_SECS`]: the keys are public, and a short
    /// outage of CTS's JWKS should not refuse tokens they verify.
    ///
    /// The lock is held across the fetch, so concurrent callers wait for one
    /// request rather than each sending their own.
    async fn key_for(&self, kid: Option<&str>) -> Result<Option<SigningKey>, AuthError> {
        let mut cache = self.keys.lock().await;
        let now = self.clock.now_unix_secs();
        let fresh = cache
            .fetched_at
            .is_some_and(|at| now.saturating_sub(at) < KEYS_TTL_SECS);
        let cached = cache.find(kid);
        if fresh && cached.is_some() {
            return Ok(cached);
        }
        let tried_recently = cache
            .attempted_at
            .is_some_and(|at| now.saturating_sub(at) < MIN_REFETCH_SECS);
        if tried_recently {
            return match cached {
                Some(key) => Ok(Some(key)),
                None if cache.attempt_failed => Err(keys_unavailable()),
                None => Ok(None),
            };
        }
        cache.attempted_at = Some(now);
        match self.fetch_keys().await {
            Ok(keys) => {
                cache.keys = keys;
                cache.fetched_at = Some(now);
                cache.attempt_failed = false;
                Ok(cache.find(kid))
            }
            Err(err) => {
                cache.attempt_failed = true;
                match cached {
                    Some(key) => {
                        tracing::warn!(
                            url = %self.jwks_url,
                            error = %err,
                            "could not refresh CTS's signing keys; using the cached ones"
                        );
                        Ok(Some(key))
                    }
                    None => Err(err),
                }
            }
        }
    }

    async fn fetch_keys(&self) -> Result<Vec<SigningKey>, AuthError> {
        tracing::debug!(url = %self.jwks_url, "fetching CTS signing keys");
        let response =
            transport::get(&self.transport, self.jwks_url.clone(), "application/json").await?;
        if !response.is_success() {
            return Err(AuthError::Server(ServerError::refused(
                response.status(),
                &response.text(),
            )));
        }
        // An unreadable JWKS is the server's fault, not the token's.
        let jwks: Jwks = response.json()?;
        Ok(jwks.keys.into_iter().filter_map(Jwk::into_key).collect())
    }
}

impl KeyCache {
    /// The key named `kid`. A token with no `kid` may only use a JWKS that
    /// holds exactly one key, so the choice is never a guess.
    fn find(&self, kid: Option<&str>) -> Option<SigningKey> {
        match kid {
            Some(kid) => self
                .keys
                .iter()
                .find(|key| key.kid.as_deref() == Some(kid))
                .cloned(),
            None => match self.keys.as_slice() {
                [only] => Some(only.clone()),
                _ => None,
            },
        }
    }
}

/// The last fetch of the signing keys failed, and it is too soon to try
/// again.
fn keys_unavailable() -> AuthError {
    AuthError::Request(crate::error::RequestError(Box::new(std::io::Error::other(
        "CTS's signing keys could not be fetched; retrying at most once a minute",
    ))))
}

/// Why a token was refused. Logged, never returned.
#[derive(Debug)]
enum Rejection {
    Malformed,
    Algorithm,
    Issuer,
    Expired,
    Audience,
    UnknownKey,
    Signature,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rejection::Malformed => f.write_str("the token is not a well-formed JWT"),
            Rejection::Algorithm => f.write_str("the token is not signed with RS256"),
            Rejection::Issuer => f.write_str("the token's issuer is not the trusted issuer"),
            Rejection::Expired => f.write_str("the token has expired"),
            Rejection::Audience => f.write_str("the token is not for the expected audience"),
            Rejection::UnknownKey => {
                f.write_str("the token's signing key is not one the trusted issuer publishes")
            }
            Rejection::Signature => f.write_str("the token's signature does not verify"),
        }
    }
}

/// A JWT split into what verification needs. Its header and claims are
/// read before the signature is checked, and are named for it.
struct Parts<'a> {
    header: UnverifiedHeader,
    claims: UnverifiedClaims,
    /// `header.claims`, the bytes the signature covers.
    signed: &'a str,
    signature: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct UnverifiedHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// The claims verification checks, as the token states them. The rest are
/// read, unverified, by [`ServiceToken`]; once every check has passed they
/// are the issuer's.
#[derive(serde::Deserialize)]
struct UnverifiedClaims {
    iss: String,
    exp: u64,
    #[serde(default)]
    aud: Option<Audience>,
}

impl<'a> Parts<'a> {
    fn split(token: &'a str) -> Result<Self, Rejection> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let (signed, signature) = token.rsplit_once('.').ok_or(Rejection::Malformed)?;
        let (header, claims) = signed.split_once('.').ok_or(Rejection::Malformed)?;
        let decode = |segment: &str| {
            URL_SAFE_NO_PAD
                .decode(segment)
                .map_err(|_| Rejection::Malformed)
        };
        let header = serde_json::from_slice(&decode(header)?).map_err(|_| Rejection::Malformed)?;
        let claims = serde_json::from_slice(&decode(claims)?).map_err(|_| Rejection::Malformed)?;
        Ok(Self {
            header,
            claims,
            signed,
            signature: decode(signature)?,
        })
    }
}

#[derive(serde::Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

/// One entry of a JWKS. Only RSA signing keys are kept; anything else in the
/// set is ignored rather than failing the whole set.
#[derive(serde::Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default, rename = "use")]
    key_use: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
}

impl Jwk {
    fn into_key(self) -> Option<SigningKey> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        if self.kty != "RSA"
            || self.alg.as_deref().is_some_and(|alg| alg != ALGORITHM)
            || self
                .key_use
                .as_deref()
                .is_some_and(|key_use| key_use != "sig")
        {
            return None;
        }
        Some(SigningKey {
            kid: self.kid,
            n: URL_SAFE_NO_PAD.decode(self.n?).ok()?,
            e: URL_SAFE_NO_PAD.decode(self.e?).ok()?,
        })
    }
}

/// RSASSA-PKCS1-v1_5 with SHA-256 over a key from the JWKS.
///
/// aws-lc-rs where it builds; RustCrypto's `rsa` on wasm32, where it does
/// not. Not vitaminc, the first choice for crypto here: it has no RSA
/// signature verification. Both refuse a modulus under 2048 bits. The RustCrypto backend is also
/// compiled into the host's tests, so both are run against the same vectors.
mod rs256 {
    use super::SigningKey;

    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn verify(key: &SigningKey, message: &[u8], signature: &[u8]) -> bool {
        aws_lc::verify(key, message, signature)
    }

    #[cfg(target_arch = "wasm32")]
    pub(super) fn verify(key: &SigningKey, message: &[u8], signature: &[u8]) -> bool {
        rust_crypto::verify(key, message, signature)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(super) mod aws_lc {
        use super::SigningKey;
        use aws_lc_rs::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};

        pub(in super::super) fn verify(key: &SigningKey, message: &[u8], signature: &[u8]) -> bool {
            RsaPublicKeyComponents {
                n: &key.n,
                e: &key.e,
            }
            .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
            .is_ok()
        }
    }

    #[cfg(any(target_arch = "wasm32", test))]
    pub(super) mod rust_crypto {
        use super::SigningKey;
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use rsa::signature::Verifier;
        use rsa::{BigUint, RsaPublicKey};

        const MIN_MODULUS_BITS: usize = 2048;

        pub(in super::super) fn verify(key: &SigningKey, message: &[u8], signature: &[u8]) -> bool {
            let n = BigUint::from_bytes_be(&key.n);
            if n.bits() < MIN_MODULUS_BITS {
                return false;
            }
            let Ok(public) = RsaPublicKey::new(n, BigUint::from_bytes_be(&key.e)) else {
                return false;
            };
            let Ok(signature) = Signature::try_from(signature) else {
                return false;
            };
            VerifyingKey::<sha2::Sha256>::new(public)
                .verify(message, &signature)
                .is_ok()
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests;
