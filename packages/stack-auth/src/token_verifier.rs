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
//! pinned separately from the auth URL**: the CTS host that service
//! discovery names for the workspace's region. The base URL override and
//! `CS_CTS_HOST` change where tokens are *requested*; they never change which
//! issuer is *trusted*. For each token it checks, in this order:
//!
//! 1. the header names `RS256` (what CTS signs with) — nothing else,
//!    `none` and the HMAC algorithms in particular, is accepted;
//! 2. `iss` is the trusted issuer;
//! 3. `exp` has not passed and `nbf`, when present, has (with
//!    [`LEEWAY_SECS`] of clock skew allowed on each);
//! 4. `aud` contains the expected audience, when the strategy requested one;
//! 5. the signature verifies under a key from the trusted issuer's JWKS
//!    (`<issuer>/.well-known/jwks.json`), never from a URL the token names.
//!
//! A token that fails any check is refused with one opaque
//! [`AuthError::InvalidToken`]; which check failed is logged at `warn`, and
//! nothing from the token itself is.
//!
//! A strategy hands out the same cached token on every call until it is
//! refreshed, so the last token to verify is remembered (as a protected
//! SHA-256 digest, compared in constant time) and only its `exp` and `nbf`
//! are checked again. A new token is verified in full.
//!
//! The JWKS is cached for [`KEYS_TTL_SECS`]. A token signed by a key the
//! cache does not hold triggers an early refetch, so a rotated key works as
//! soon as one is allowed. Fetches, successful or failed, are at most one
//! every [`MIN_REFETCH_SECS`], so neither a run of forged `kid`s nor a CTS
//! outage turns every call into a request to CTS; a token signed by a key
//! published within that interval of the last fetch is refused.

use std::fmt;

use cts_common::claims::Audience;
use cts_common::{CtsServiceDiscovery, Region, ServiceDiscovery};
use url::Url;
use vitaminc_protected::{Equatable, Protected, ProtectedDigest};

use crate::auto_refresh::AutoRefresh;
use crate::clock::{system_clock, SharedClock};
use crate::error::{InvalidToken, ServerError};
use crate::transport::{self, SharedTransport};
use crate::{AuthError, ServiceToken};

/// Clock skew allowed on `exp` and `nbf`, matching what ZeroKMS allows.
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

/// The verifier a strategy builder asks for at `build`: one trusting the
/// CTS that service discovery names for `region`, or `None` when the builder
/// was not asked to [`verify_tokens`](crate::AccessKeyStrategyBuilder::verify_tokens).
///
/// `region` is asked for only when verifying, so a strategy with
/// verification off fails in no new way.
pub(crate) fn resolve(
    verify_tokens: bool,
    region: impl FnOnce() -> Result<Region, AuthError>,
    audience: Option<String>,
    transport: &SharedTransport,
) -> Result<Option<TokenVerifier>, AuthError> {
    if !verify_tokens {
        return Ok(None);
    }
    let issuer = CtsServiceDiscovery::endpoint(region()?)?;
    TokenVerifier::new(issuer, audience, transport.clone(), system_clock()).map(Some)
}

/// `token`, which `engine` handed out, verified by `verifier` when there is
/// one.
///
/// A refused token is expired in `engine`'s cache, so the next call fetches
/// a new one rather than refusing the same token until it expires.
pub(crate) async fn verify_cached<R, S>(
    verifier: Option<&TokenVerifier>,
    engine: &AutoRefresh<R, S>,
    token: ServiceToken,
) -> Result<ServiceToken, AuthError> {
    let Some(verifier) = verifier else {
        return Ok(token);
    };
    match verifier.verify(token.clone()).await {
        Err(err @ AuthError::InvalidToken(_)) => {
            engine.expire(&token).await;
            Err(err)
        }
        result => result,
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
    keys: std::sync::Mutex<KeyCache>,
    /// Held while the JWKS is fetched, so only one fetch runs at a time.
    fetching: tokio::sync::Mutex<()>,
    /// The last token to verify. The same bytes need only their times
    /// checked again.
    last_verified: std::sync::Mutex<Option<Verified>>,
}

/// A token that verified: a SHA-256 digest of it, not the token itself, and
/// its times. The digest is wiped when it is replaced or dropped.
struct Verified {
    digest: TokenDigest,
    times: Times,
}

/// The SHA-256 of a bearer token, compared only in constant time.
type TokenDigest = Equatable<Protected<[u8; 32]>>;

fn digest(token: &ServiceToken) -> TokenDigest {
    let mut digest: ProtectedDigest<sha2_v011::Sha256> = ProtectedDigest::new();
    digest.update(&Protected::new(token.as_str().as_bytes().to_vec()));
    let mut out = Protected::new([0u8; 32]);
    digest.finalize_into(&mut out);
    out.into()
}

/// When a token is valid: until `exp`, and from `nbf` when it has one.
#[derive(Clone, Copy)]
struct Times {
    exp: u64,
    nbf: Option<u64>,
}

/// What [`TokenVerifier::cached_key`] found.
enum Lookup {
    /// The answer, with no fetch due.
    Done(Result<Option<SigningKey>, AuthError>),
    /// A fetch is due. Holds the cached key for the `kid`, which is stale,
    /// if there is one.
    Fetch(Option<SigningKey>),
}

#[derive(Default)]
struct KeyCache {
    keys: Vec<SigningKey>,
    /// When the keys were last fetched; `None` before the first fetch.
    fetched_at: Option<u64>,
    /// When a fetch was last attempted, successful or not. The attempt
    /// failed when this is not also when the keys were last fetched.
    attempted_at: Option<u64>,
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
            keys: std::sync::Mutex::new(KeyCache::default()),
            fetching: tokio::sync::Mutex::new(()),
            last_verified: std::sync::Mutex::new(None),
        })
    }

    /// Return `token` if it verifies, else [`AuthError::InvalidToken`].
    ///
    /// A failure to fetch the signing keys is the transport's or the
    /// server's error ([`AuthError::Request`] or [`AuthError::Server`]), not
    /// the token's: it says nothing about whether the token is genuine.
    pub(crate) async fn verify(&self, token: ServiceToken) -> Result<ServiceToken, AuthError> {
        let digest = digest(&token);
        let result = match self.verified_times(&digest) {
            Some(times) => self.check_times(times),
            None => self.check(token.as_str()).await.map(|times| {
                self.remember(Verified { digest, times });
            }),
        };
        match result {
            Ok(()) => Ok(token),
            Err(Failure::Keys(err)) => Err(err),
            Err(Failure::Rejected(rejection)) => {
                tracing::warn!(
                    issuer = %self.issuer,
                    %rejection,
                    "refused an access token that did not verify"
                );
                Err(AuthError::InvalidToken(InvalidToken(REFUSED.to_string())))
            }
        }
    }

    /// The times of the last token to verify, if `digest` is that token's.
    fn verified_times(&self, digest: &TokenDigest) -> Option<Times> {
        let last = self.last_verified.lock().unwrap_or_else(|e| e.into_inner());
        last.as_ref()
            .filter(|verified| verified.digest.constant_time_eq(digest))
            .map(|verified| verified.times)
    }

    fn remember(&self, verified: Verified) {
        *self.last_verified.lock().unwrap_or_else(|e| e.into_inner()) = Some(verified);
    }

    /// Every check, returning the token's times when they all pass.
    async fn check(&self, token: &str) -> Result<Times, Failure> {
        let parts = Parts::split(token)?;
        self.check_claims(&parts)?;
        let key = self
            .key_for(parts.header.kid.as_deref())
            .await?
            .ok_or(Rejection::UnknownKey)?;
        // Fetching the keys can take long enough for the token to expire.
        let times = parts.claims.times();
        self.check_times(times)?;
        if !rs256::verify(&key, parts.signed.as_bytes(), &parts.signature) {
            return Err(Rejection::Signature.into());
        }
        Ok(times)
    }

    fn check_times(&self, times: Times) -> Result<(), Failure> {
        let now = self.clock.now_unix_secs();
        if times.exp.saturating_add(LEEWAY_SECS) <= now {
            return Err(Rejection::Expired.into());
        }
        if times
            .nbf
            .is_some_and(|nbf| nbf > now.saturating_add(LEEWAY_SECS))
        {
            return Err(Rejection::NotYetValid.into());
        }
        Ok(())
    }

    fn check_claims(&self, parts: &Parts<'_>) -> Result<(), Failure> {
        if parts.header.alg != ALGORITHM {
            return Err(Rejection::Algorithm.into());
        }
        let claims = &parts.claims;
        let issuer = Url::parse(&claims.iss)
            .map(crate::ensure_trailing_slash)
            .map_err(|_| Rejection::Issuer)?;
        if issuer != self.issuer {
            return Err(Rejection::Issuer.into());
        }
        self.check_times(claims.times())?;
        if let Some(expected) = &self.audience {
            if !claims
                .aud
                .as_ref()
                .is_some_and(|aud| aud.contains(expected))
            {
                return Err(Rejection::Audience.into());
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
    /// One fetch runs at a time, and the cache is not locked while it runs.
    /// A caller that needs a key the cache does not hold waits for that
    /// fetch; a caller whose key is only stale uses it straight away, so a
    /// slow JWKS endpoint holds up at most the one caller fetching.
    async fn key_for(&self, kid: Option<&str>) -> Result<Option<SigningKey>, AuthError> {
        let stale = match self.cached_key(kid) {
            Lookup::Done(Ok(Some(key))) => return Ok(Some(key)),
            // No key, perhaps because a fetch is still running: wait for it
            // below, then look again.
            Lookup::Done(_) => None,
            Lookup::Fetch(stale) => stale,
        };
        let _fetching = match stale {
            Some(key) => match self.fetching.try_lock() {
                Ok(fetching) => fetching,
                Err(_) => return Ok(Some(key)),
            },
            None => self.fetching.lock().await,
        };
        // The fetch this caller waited for may already have answered.
        let stale = match self.cached_key(kid) {
            Lookup::Done(result) => return result,
            Lookup::Fetch(stale) => stale,
        };
        let now = self.clock.now_unix_secs();
        self.cache().attempted_at = Some(now);
        let fetched = self.fetch_keys().await;
        let mut cache = self.cache();
        match fetched {
            Ok(keys) => {
                cache.keys = keys;
                cache.fetched_at = Some(now);
                Ok(cache.find(kid))
            }
            Err(err) => match stale {
                Some(key) => {
                    tracing::warn!(
                        url = %self.jwks_url,
                        error = %err,
                        "could not refresh CTS's signing keys; using the cached ones"
                    );
                    Ok(Some(key))
                }
                None => Err(err),
            },
        }
    }

    /// What the cache can answer without a fetch.
    fn cached_key(&self, kid: Option<&str>) -> Lookup {
        let cache = self.cache();
        let now = self.clock.now_unix_secs();
        let fresh = cache
            .fetched_at
            .is_some_and(|at| now.saturating_sub(at) < KEYS_TTL_SECS);
        let cached = cache.find(kid);
        if fresh && cached.is_some() {
            return Lookup::Done(Ok(cached));
        }
        let tried_recently = cache
            .attempted_at
            .is_some_and(|at| now.saturating_sub(at) < MIN_REFETCH_SECS);
        if tried_recently {
            return Lookup::Done(match cached {
                Some(key) => Ok(Some(key)),
                None if cache.attempted_at != cache.fetched_at => Err(keys_unavailable()),
                None => Ok(None),
            });
        }
        Lookup::Fetch(cached)
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, KeyCache> {
        self.keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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

/// Why [`TokenVerifier::check`] did not pass a token.
enum Failure {
    /// The signing keys could not be fetched. This says nothing about the
    /// token, and is returned as it is.
    Keys(AuthError),
    /// The token was refused.
    Rejected(Rejection),
}

impl From<AuthError> for Failure {
    fn from(err: AuthError) -> Self {
        Failure::Keys(err)
    }
}

impl From<Rejection> for Failure {
    fn from(rejection: Rejection) -> Self {
        Failure::Rejected(rejection)
    }
}

/// Why a token was refused. Logged, never returned.
#[derive(Debug)]
enum Rejection {
    Malformed,
    Algorithm,
    Issuer,
    Expired,
    NotYetValid,
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
            Rejection::NotYetValid => f.write_str("the token is not valid yet"),
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
    nbf: Option<u64>,
    #[serde(default)]
    aud: Option<Audience>,
}

impl UnverifiedClaims {
    fn times(&self) -> Times {
        Times {
            exp: self.exp,
            nbf: self.nbf,
        }
    }
}

impl<'a> Parts<'a> {
    fn split(token: &'a str) -> Result<Self, Rejection> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let [header, claims, signature] = crate::jwt_segments(token).ok_or(Rejection::Malformed)?;
        let signed = &token[..header.len() + 1 + claims.len()];
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
        use rsa::sha2::Sha256;
        use rsa::signature::Verifier;
        use rsa::{BoxedUint, PublicKey};

        const MIN_MODULUS_BITS: usize = 2048;

        pub(in super::super) fn verify(key: &SigningKey, message: &[u8], signature: &[u8]) -> bool {
            let n = BoxedUint::from_be_slice_vartime(&key.n);
            if (n.bit_width() as usize) < MIN_MODULUS_BITS {
                return false;
            }
            let Ok(public) = PublicKey::new(n, BoxedUint::from_be_slice_vartime(&key.e)) else {
                return false;
            };
            let Ok(signature) = Signature::try_from(signature) else {
                return false;
            };
            VerifyingKey::<Sha256>::new(public)
                .verify(message, &signature)
                .is_ok()
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests;
