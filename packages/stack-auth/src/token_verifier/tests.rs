use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::*;
use crate::clock::Clock;
use crate::error::RequestError;
use crate::test_support::signing::{TestKey, KEY_A, KEY_B};
use crate::transport::{HttpRequest, HttpResponse, HttpTransport};
use crate::SecretToken;

const ISSUER: &str = "https://ap-southeast-2.aws.cts.cipherstashmanaged.net/";
const NOW: u64 = 1_800_000_000;

fn signing_key(key: &TestKey) -> SigningKey {
    let public = key.components();
    SigningKey {
        kid: Some(key.kid.to_string()),
        n: public.n,
        e: public.e,
    }
}

fn claims() -> serde_json::Value {
    serde_json::json!({
        "iss": ISSUER,
        "sub": "CS|CSAKkeyId",
        "aud": "ap-southeast-2.aws.viturhosted.net",
        "iat": NOW - 10,
        "exp": NOW + 3600,
        "workspace": "ZVATKW3VHMFG27DY",
        "scope": "",
        "services": {"zerokms": "https://ap-southeast-2.aws.viturhosted.net/"},
    })
}

fn with(mut claims: serde_json::Value, key: &str, value: serde_json::Value) -> serde_json::Value {
    claims[key] = value;
    claims
}

fn token(jwt: String) -> ServiceToken {
    ServiceToken::new(SecretToken::new(jwt))
}

fn jwks(keys: &[&TestKey]) -> String {
    crate::test_support::signing::jwks(keys)
}

/// A CTS that serves a JWKS and records each URL it is asked for.
struct FakeCts {
    status: AtomicU64,
    jwks: Mutex<String>,
    fail: bool,
    requests: Mutex<Vec<(String, String)>>,
}

impl FakeCts {
    fn serving(jwks: String) -> Arc<Self> {
        Arc::new(Self {
            status: AtomicU64::new(200),
            jwks: Mutex::new(jwks),
            fail: false,
            requests: Mutex::new(Vec::new()),
        })
    }

    fn unreachable() -> Arc<Self> {
        Arc::new(Self {
            status: AtomicU64::new(200),
            jwks: Mutex::new(String::new()),
            fail: true,
            requests: Mutex::new(Vec::new()),
        })
    }

    fn rotate_to(&self, jwks: String) {
        *self.jwks.lock().unwrap() = jwks;
    }

    fn requests(&self) -> Vec<(String, String)> {
        self.requests.lock().unwrap().clone()
    }
}

impl HttpTransport for FakeCts {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, RequestError> {
        self.requests
            .lock()
            .unwrap()
            .push((request.method().to_string(), request.url().to_string()));
        if self.fail {
            return Err(RequestError(Box::new(std::io::Error::other("unreachable"))));
        }
        let status = self.status.load(Ordering::SeqCst) as u16;
        let body = self.jwks.lock().unwrap().clone().into_bytes();
        Ok(HttpResponse::new(status, Vec::new(), body))
    }
}

/// A clock the test moves by hand.
struct ManualClock(AtomicU64);

impl ManualClock {
    fn at(now: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(now)))
    }

    fn advance(&self, secs: u64) {
        let _ = self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_unix_secs(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn verifier(cts: &Arc<FakeCts>, clock: &Arc<ManualClock>) -> TokenVerifier {
    verifier_for(cts, clock, None)
}

fn verifier_for(
    cts: &Arc<FakeCts>,
    clock: &Arc<ManualClock>,
    audience: Option<&str>,
) -> TokenVerifier {
    TokenVerifier::new(
        ISSUER.parse().unwrap(),
        audience.map(str::to_string),
        transport::share(Arc::clone(cts)),
        clock.clone(),
    )
    .unwrap()
}

/// The verdict: `Ok` with the token back, or the refusal's message.
async fn verdict(verifier: &TokenVerifier, jwt: String) -> Result<(), String> {
    match verifier.verify(token(jwt.clone())).await {
        Ok(token) => {
            assert_eq!(token.as_str(), jwt, "a verified token comes back unchanged");
            Ok(())
        }
        Err(AuthError::InvalidToken(InvalidToken(message))) => {
            assert!(
                !message.contains(&jwt),
                "a refusal must not quote the token, got: {message}"
            );
            Err(message)
        }
        Err(other) => panic!("expected InvalidToken, got {other:?}"),
    }
}

mod given_a_token_signed_by_the_trusted_issuer {
    use super::*;

    #[tokio::test]
    async fn it_is_accepted() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));

        assert_eq!(verdict(&verifier, KEY_A.jwt(claims())).await, Ok(()));
    }

    #[tokio::test]
    async fn the_keys_come_from_the_pinned_issuers_jwks() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));

        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();

        assert_eq!(
            cts.requests(),
            vec![("GET".to_string(), format!("{ISSUER}.well-known/jwks.json"))],
        );
    }

    #[tokio::test]
    async fn an_issuer_differing_only_by_a_trailing_slash_is_the_same_issuer() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));
        let iss = ISSUER.trim_end_matches('/');

        let accepted = verdict(&verifier, KEY_A.jwt(with(claims(), "iss", iss.into()))).await;

        assert_eq!(accepted, Ok(()));
    }

    #[tokio::test]
    async fn a_header_carrying_non_string_fields_is_accepted() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));
        let header = serde_json::json!({"alg": "RS256", "kid": "key-a", "srf": true});

        let accepted = verdict(&verifier, KEY_A.jwt_with_header(header, claims())).await;

        assert_eq!(accepted, Ok(()));
    }

    #[tokio::test]
    async fn a_token_without_a_kid_uses_the_only_key() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));
        let header = serde_json::json!({"alg": "RS256"});

        let accepted = verdict(&verifier, KEY_A.jwt_with_header(header, claims())).await;

        assert_eq!(accepted, Ok(()));
    }

    #[tokio::test]
    async fn a_token_without_a_kid_is_refused_when_the_jwks_holds_several_keys() {
        let cts = FakeCts::serving(jwks(&[&KEY_A, &KEY_B]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));
        let header = serde_json::json!({"alg": "RS256"});

        let refused = verdict(&verifier, KEY_A.jwt_with_header(header, claims())).await;

        assert!(refused.is_err(), "the key would be a guess");
    }
}

mod given_a_forged_or_altered_token {
    use super::*;

    #[tokio::test]
    async fn altered_claims_are_refused() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));
        let genuine = KEY_A.jwt(claims());
        let mut segments: Vec<&str> = genuine.split('.').collect();
        let forged_claims = URL_SAFE_NO_PAD.encode(
            with(
                claims(),
                "services",
                serde_json::json!({"zerokms": "https://rogue.example/"}),
            )
            .to_string(),
        );
        segments[1] = &forged_claims;

        let refused = verdict(&verifier, segments.join(".")).await;

        assert!(
            refused.is_err(),
            "a re-pointed services claim must not verify"
        );
    }

    #[tokio::test]
    async fn a_token_signed_by_a_key_the_issuer_does_not_publish_is_refused() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));
        // Claims to be key-a, but is signed by key-b.
        let header = serde_json::json!({"alg": "RS256", "kid": "key-a"});

        let refused = verdict(&verifier, KEY_B.jwt_with_header(header, claims())).await;

        assert!(refused.is_err());
    }

    #[tokio::test]
    async fn an_hmac_token_is_refused_before_any_key_is_fetched() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));
        let hs256 = encode(
            &Header::default(),
            &claims(),
            &EncodingKey::from_secret(b"anyone-can-sign-this"),
        )
        .unwrap();

        let refused = verdict(&verifier, hs256).await;

        assert!(refused.is_err());
        assert!(
            cts.requests().is_empty(),
            "no key fetch for a token that cannot pass"
        );
    }

    #[tokio::test]
    async fn an_unsigned_token_is_refused() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));
        let unsigned = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(claims().to_string()),
        );

        assert!(verdict(&verifier, unsigned).await.is_err());
    }

    #[tokio::test]
    async fn a_token_that_is_not_a_jwt_is_refused() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));

        assert!(verdict(&verifier, "not-a-jwt".to_string()).await.is_err());
    }
}

mod given_a_token_from_another_issuer {
    use super::*;

    #[tokio::test]
    async fn it_is_refused_without_fetching_the_issuers_keys() {
        // A rogue auth server signing with its own key and publishing its
        // own JWKS: the token is internally consistent, but not the trusted
        // issuer's.
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));
        let rogue = with(claims(), "iss", "https://rogue.example/".into());

        let refused = verdict(&verifier, KEY_A.jwt(rogue)).await;

        assert!(refused.is_err());
        assert!(
            cts.requests().is_empty(),
            "the rogue issuer's JWKS is never asked for"
        );
    }

    #[tokio::test]
    async fn an_issuer_that_only_shares_a_prefix_is_refused() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));
        let lookalike = format!("{}evil/", ISSUER);

        let refused = verdict(
            &verifier,
            KEY_A.jwt(with(claims(), "iss", lookalike.into())),
        )
        .await;

        assert!(refused.is_err());
    }
}

mod given_the_tokens_expiry {
    use super::*;

    #[tokio::test]
    async fn a_token_past_its_expiry_and_the_leeway_is_refused() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));
        let expired = with(claims(), "exp", (NOW - LEEWAY_SECS).into());

        assert!(verdict(&verifier, KEY_A.jwt(expired)).await.is_err());
    }

    #[tokio::test]
    async fn a_token_expired_within_the_leeway_is_accepted() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));
        let skewed = with(claims(), "exp", (NOW - LEEWAY_SECS + 1).into());

        assert_eq!(verdict(&verifier, KEY_A.jwt(skewed)).await, Ok(()));
    }

    #[tokio::test]
    async fn a_token_without_an_expiry_is_refused() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier(&cts, &ManualClock::at(NOW));
        let mut claims = claims();
        let _ = claims.as_object_mut().unwrap().remove("exp");

        assert!(verdict(&verifier, KEY_A.jwt(claims)).await.is_err());
    }
}

mod given_an_expected_audience {
    use super::*;

    const AUDIENCE: &str = "ap-southeast-2.aws.viturhosted.net";

    #[tokio::test]
    async fn a_token_for_that_audience_is_accepted() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier_for(&cts, &ManualClock::at(NOW), Some(AUDIENCE));

        assert_eq!(verdict(&verifier, KEY_A.jwt(claims())).await, Ok(()));
    }

    #[tokio::test]
    async fn an_audience_list_containing_it_is_accepted() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier_for(&cts, &ManualClock::at(NOW), Some(AUDIENCE));
        let listed = with(claims(), "aud", serde_json::json!(["other", AUDIENCE]));

        assert_eq!(verdict(&verifier, KEY_A.jwt(listed)).await, Ok(()));
    }

    #[tokio::test]
    async fn a_token_for_another_audience_is_refused() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier_for(&cts, &ManualClock::at(NOW), Some(AUDIENCE));
        let other = with(claims(), "aud", "us-east-1.aws.viturhosted.net".into());

        assert!(verdict(&verifier, KEY_A.jwt(other)).await.is_err());
    }

    #[tokio::test]
    async fn a_token_without_an_audience_is_refused() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier_for(&cts, &ManualClock::at(NOW), Some(AUDIENCE));
        let mut claims = claims();
        let _ = claims.as_object_mut().unwrap().remove("aud");

        assert!(verdict(&verifier, KEY_A.jwt(claims)).await.is_err());
    }
}

mod given_the_key_cache {
    use super::*;

    #[tokio::test]
    async fn the_jwks_is_fetched_once_while_fresh() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let clock = ManualClock::at(NOW);
        let verifier = verifier(&cts, &clock);

        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();
        clock.advance(KEYS_TTL_SECS - 1);
        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();

        assert_eq!(cts.requests().len(), 1);
    }

    #[tokio::test]
    async fn the_jwks_is_fetched_again_once_stale() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let clock = ManualClock::at(NOW);
        let verifier = verifier(&cts, &clock);

        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();
        clock.advance(KEYS_TTL_SECS);
        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();

        assert_eq!(cts.requests().len(), 2);
    }

    #[tokio::test]
    async fn a_rotated_key_is_fetched_as_soon_as_the_rate_limit_allows() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let clock = ManualClock::at(NOW);
        let verifier = verifier(&cts, &clock);
        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();

        cts.rotate_to(jwks(&[&KEY_A, &KEY_B]));
        clock.advance(MIN_REFETCH_SECS);

        assert_eq!(verdict(&verifier, KEY_B.jwt(claims())).await, Ok(()));
        assert_eq!(cts.requests().len(), 2);
    }

    #[tokio::test]
    async fn unknown_keys_do_not_refetch_more_than_once_per_interval() {
        let cts = FakeCts::serving(jwks(&[&KEY_A]));
        let clock = ManualClock::at(NOW);
        let verifier = verifier(&cts, &clock);
        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();

        clock.advance(MIN_REFETCH_SECS - 1);
        for _ in 0..3 {
            assert!(verdict(&verifier, KEY_B.jwt(claims())).await.is_err());
        }

        assert_eq!(
            cts.requests().len(),
            1,
            "a run of unknown kids must not hammer CTS"
        );
    }

    #[tokio::test]
    async fn non_rsa_and_non_signing_keys_in_the_jwks_are_ignored() {
        let mut encryption_key = KEY_B.jwk();
        encryption_key["use"] = "enc".into();
        let jwks = serde_json::json!({"keys": [
            {"kty": "EC", "kid": "ec", "crv": "P-256", "x": "AA", "y": "AA"},
            encryption_key,
            KEY_A.jwk(),
        ]})
        .to_string();
        let cts = FakeCts::serving(jwks);
        let verifier = verifier(&cts, &ManualClock::at(NOW));

        assert_eq!(verdict(&verifier, KEY_A.jwt(claims())).await, Ok(()));
        assert!(
            verdict(&verifier, KEY_B.jwt(claims())).await.is_err(),
            "a key published for encryption must not verify a signature"
        );
    }
}

mod given_the_keys_cannot_be_fetched {
    use super::*;

    #[tokio::test]
    async fn an_unreachable_cts_is_a_request_error() {
        let cts = FakeCts::unreachable();
        let verifier = verifier(&cts, &ManualClock::at(NOW));

        let err = verifier
            .verify(token(KEY_A.jwt(claims())))
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::Request(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn an_error_status_is_a_server_error() {
        let cts = FakeCts::serving("{}".to_string());
        cts.status.store(503, Ordering::SeqCst);
        let verifier = verifier(&cts, &ManualClock::at(NOW));

        let err = verifier
            .verify(token(KEY_A.jwt(claims())))
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::Server(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn an_unreadable_jwks_refuses_the_token() {
        let cts = FakeCts::serving("<html>".to_string());
        let verifier = verifier(&cts, &ManualClock::at(NOW));

        let err = verifier
            .verify(token(KEY_A.jwt(claims())))
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::InvalidToken(_)), "got {err:?}");
    }
}

mod given_the_verification_setting {
    use super::*;

    fn region() -> Region {
        Region::aws("ap-southeast-2").unwrap()
    }

    #[test]
    fn off_builds_no_verifier() {
        let cts = transport::share(FakeCts::serving(String::new()));
        let resolved = Verification::Off
            .resolve(|| Ok(region()), None, &cts)
            .unwrap();
        assert!(resolved.is_none());
    }

    #[test]
    fn the_region_issuer_is_the_regions_cts() {
        let cts = transport::share(FakeCts::serving(String::new()));
        let verifier = Verification::RegionIssuer
            .resolve(|| Ok(region()), None, &cts)
            .unwrap()
            .expect("a verifier");
        assert_eq!(verifier.issuer.as_str(), ISSUER);
        assert_eq!(
            verifier.jwks_url.as_str(),
            format!("{ISSUER}.well-known/jwks.json")
        );
    }

    #[test]
    fn an_explicit_issuer_keeps_its_path() {
        let cts = transport::share(FakeCts::serving(String::new()));
        let verifier = Verification::Issuer("https://cts.example.com/staging".parse().unwrap())
            .resolve(|| Ok(region()), None, &cts)
            .unwrap()
            .expect("a verifier");
        assert_eq!(verifier.issuer.as_str(), "https://cts.example.com/staging/");
        assert_eq!(
            verifier.jwks_url.as_str(),
            "https://cts.example.com/staging/.well-known/jwks.json"
        );
    }
}

/// Both RS256 backends, against the same vectors: the host runs aws-lc-rs,
/// wasm32 runs RustCrypto's `rsa`, and only the host runs tests.
mod given_each_rs256_backend {
    use super::*;

    type Backend = fn(&SigningKey, &[u8], &[u8]) -> bool;

    const BACKENDS: [(&str, Backend); 2] = [
        ("aws-lc-rs", rs256::aws_lc::verify),
        ("rsa", rs256::rust_crypto::verify),
    ];

    #[test]
    fn a_valid_signature_verifies() {
        let signature = KEY_A.sign(b"message");
        for (name, verify) in BACKENDS {
            assert!(
                verify(&signing_key(&KEY_A), b"message", &signature),
                "{name}"
            );
        }
    }

    #[test]
    fn a_signature_over_other_bytes_does_not() {
        let signature = KEY_A.sign(b"message");
        for (name, verify) in BACKENDS {
            assert!(
                !verify(&signing_key(&KEY_A), b"massage", &signature),
                "{name}"
            );
        }
    }

    #[test]
    fn another_keys_signature_does_not() {
        let signature = KEY_B.sign(b"message");
        for (name, verify) in BACKENDS {
            assert!(
                !verify(&signing_key(&KEY_A), b"message", &signature),
                "{name}"
            );
        }
    }

    #[test]
    fn a_truncated_signature_does_not() {
        let signature = KEY_A.sign(b"message");
        for (name, verify) in BACKENDS {
            assert!(
                !verify(&signing_key(&KEY_A), b"message", &signature[1..]),
                "{name}"
            );
        }
    }

    #[test]
    fn a_modulus_under_2048_bits_is_refused() {
        // Keep key-a's exponent but shorten the modulus: whatever the
        // signature, a key this small is not accepted.
        let mut short = signing_key(&KEY_A);
        short.n.truncate(128);
        let signature = KEY_A.sign(b"message");
        for (name, verify) in BACKENDS {
            assert!(!verify(&short, b"message", &signature[..128]), "{name}");
        }
    }
}

/// Each strategy builder's `verify_tokens` / `trusted_issuer`, end to end
/// through a stub CTS.
mod given_a_strategy_that_verifies_tokens {
    use super::*;
    use crate::test_support::signing::{claims as cts_claims, StubCts};
    use crate::{
        AccessKey, AccessKeyStrategy, AuthStrategy, AutoStrategy, DeviceSessionStrategy,
        OidcFederationStrategy, OidcProviderFn,
    };
    use cts_common::Crn;

    const WORKSPACE: &str = "ZVATKW3VHMFG27DY";
    /// Where the strategies are told to request tokens. Not the issuer.
    const AUTH_URL: &str = "https://auth.example.com/";

    fn crn() -> Crn {
        format!("crn:ap-southeast-2.aws:{WORKSPACE}")
            .parse()
            .unwrap()
    }

    fn key() -> AccessKey {
        "CSAKkeyId.keySecret".parse().unwrap()
    }

    fn genuine() -> String {
        KEY_A.jwt(cts_claims(ISSUER, WORKSPACE))
    }

    /// Signed by a key the trusted issuer does not publish, naming a rogue
    /// issuer: what an attacker who controls the auth URL would mint.
    fn forged() -> String {
        KEY_B.jwt(cts_claims("https://rogue.example/", WORKSPACE))
    }

    fn cts(token: String) -> Arc<StubCts> {
        Arc::new(StubCts::new(token, jwks(&[&KEY_A])))
    }

    async fn access_key(cts: &Arc<StubCts>, pin: bool) -> Result<ServiceToken, AuthError> {
        let builder = AccessKeyStrategy::builder(crn(), key())
            .base_url(AUTH_URL.parse().unwrap())
            .transport(Arc::clone(cts));
        let builder = if pin {
            builder.trusted_issuer(ISSUER.parse().unwrap())
        } else {
            builder.verify_tokens()
        };
        builder.build().unwrap().get_token().await
    }

    #[tokio::test]
    async fn the_access_key_strategy_returns_a_genuine_token() {
        let cts = cts(genuine());
        assert!(access_key(&cts, true).await.is_ok());
    }

    #[tokio::test]
    async fn the_access_key_strategy_refuses_a_forged_token() {
        let cts = cts(forged());
        let err = access_key(&cts, true).await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn verify_tokens_trusts_the_regions_cts_not_the_auth_url() {
        // The auth URL is overridden, as `CS_CTS_HOST` or `base_url` would;
        // the issuer the strategy trusts is still the region's CTS, and that
        // is where it asks for keys. The token names the region's CTS too,
        // so it verifies.
        let cts = cts(genuine());

        assert!(access_key(&cts, false).await.is_ok());
        assert_eq!(
            cts.jwks_requests(),
            vec![format!("{ISSUER}.well-known/jwks.json")]
        );
    }

    #[tokio::test]
    async fn verify_tokens_refuses_a_token_from_the_overridden_auth_url() {
        let cts = cts(KEY_A.jwt(cts_claims(AUTH_URL, WORKSPACE)));

        let err = access_key(&cts, false).await.unwrap_err();

        assert!(matches!(err, AuthError::InvalidToken(_)), "got {err:?}");
        assert!(cts.jwks_requests().is_empty());
    }

    #[tokio::test]
    async fn the_access_key_strategy_checks_the_requested_audience() {
        let cts = cts(genuine());
        let strategy = AccessKeyStrategy::builder(crn(), key())
            .base_url(AUTH_URL.parse().unwrap())
            .transport(Arc::clone(&cts))
            .audience("ap-southeast-2.aws.viturhosted.net")
            .verify_tokens()
            .build()
            .unwrap();

        // `cts_claims` mints `aud: "test-audience"`.
        let err = strategy.get_token().await.unwrap_err();

        assert!(matches!(err, AuthError::InvalidToken(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn without_verification_no_keys_are_fetched() {
        let cts = cts(forged());
        let strategy = AccessKeyStrategy::builder(crn(), key())
            .base_url(AUTH_URL.parse().unwrap())
            .transport(Arc::clone(&cts))
            .build()
            .unwrap();

        assert!(strategy.get_token().await.is_ok(), "verification is opt-in");
        assert!(cts.jwks_requests().is_empty());
    }

    async fn oidc(cts: &Arc<StubCts>) -> Result<ServiceToken, AuthError> {
        let provider = OidcProviderFn::new(|| async { Ok(SecretToken::new("provider.jwt.value")) });
        OidcFederationStrategy::builder(crn(), provider)
            .base_url(AUTH_URL.parse().unwrap())
            .transport(Arc::clone(cts))
            .verify_tokens()
            .build()
            .unwrap()
            .get_token()
            .await
    }

    #[tokio::test]
    async fn the_oidc_federation_strategy_returns_a_genuine_token() {
        assert!(oidc(&cts(genuine())).await.is_ok());
    }

    #[tokio::test]
    async fn the_oidc_federation_strategy_refuses_a_forged_token() {
        let err = oidc(&cts(forged())).await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)), "got {err:?}");
    }

    async fn device_session(cts: &Arc<StubCts>, jwt: &str) -> Result<ServiceToken, AuthError> {
        let region = Region::aws("ap-southeast-2").unwrap();
        DeviceSessionStrategy::with_token(region, "client-id", crate::test_support::raw_token(jwt))
            .base_url(AUTH_URL.parse().unwrap())
            .transport(Arc::clone(cts))
            .verify_tokens()
            .build()
            .unwrap()
            .get_token()
            .await
    }

    #[tokio::test]
    async fn the_device_session_strategy_returns_a_genuine_token() {
        let cts = cts(String::new());
        assert!(device_session(&cts, &genuine()).await.is_ok());
    }

    #[tokio::test]
    async fn the_device_session_strategy_refuses_a_forged_saved_token() {
        let cts = cts(String::new());
        let err = device_session(&cts, &forged()).await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)), "got {err:?}");
    }

    /// A saved session names its own issuer, which is what is being checked,
    /// so the trusted issuer comes from the region saved alongside it.
    async fn saved_session(region: &str) -> (Arc<StubCts>, Result<ServiceToken, AuthError>) {
        let dir = tempfile::tempdir().unwrap();
        let store = stack_profile::ProfileStore::new(dir.path());
        let ws_store = store.workspace_store(WORKSPACE).unwrap();
        let mut saved = crate::test_support::raw_token(&genuine());
        saved.set_region(region);
        saved.set_client_id("client-id");
        ws_store.save_profile(&saved).unwrap();
        let cts = cts(String::new());
        let result = DeviceSessionStrategy::with_workspace_store(ws_store)
            .transport(Arc::clone(&cts))
            .verify_tokens()
            .build()
            .unwrap()
            .get_token()
            .await;
        (cts, result)
    }

    #[tokio::test]
    async fn a_saved_device_session_is_verified_against_its_saved_regions_cts() {
        let (cts, result) = saved_session("ap-southeast-2.aws").await;

        assert!(result.is_ok(), "got {result:?}");
        assert_eq!(
            cts.jwks_requests(),
            vec![format!("{ISSUER}.well-known/jwks.json")]
        );
    }

    #[tokio::test]
    async fn a_saved_device_session_from_another_regions_cts_is_refused() {
        // Signed by the Sydney CTS's key and naming it, but saved as a
        // Virginia session: the issuer is not the one the region trusts.
        let (_, result) = saved_session("us-east-1.aws").await;

        let err = result.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn the_auto_strategy_hands_verification_to_the_strategy_it_detects() {
        let cts = cts(forged());
        let strategy = AutoStrategy::builder()
            .with_access_key("CSAKkeyId.keySecret")
            .with_workspace_crn(crn())
            .transport(Arc::clone(&cts))
            .trusted_issuer(ISSUER.parse().unwrap())
            .detect()
            .unwrap();

        let err = strategy.get_token().await.unwrap_err();

        assert!(matches!(err, AuthError::InvalidToken(_)), "got {err:?}");
    }
}
