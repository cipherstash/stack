use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use super::*;
use crate::clock::TestClock;
use crate::test_support::signing::{jwks, StubCts, TestKey, KEY_A, KEY_B};
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

/// A second genuine token, so a test can tell a token the verifier has
/// already passed from a new one. (RS256 signatures are deterministic, so
/// `KEY_A.jwt(claims())` twice is the same token.)
fn another_token() -> String {
    KEY_A.jwt(with(claims(), "iat", (NOW - 5).into()))
}

fn with(mut claims: serde_json::Value, key: &str, value: serde_json::Value) -> serde_json::Value {
    claims[key] = value;
    claims
}

fn token(jwt: String) -> ServiceToken {
    ServiceToken::new(SecretToken::new(jwt))
}

fn verifier(cts: &Arc<StubCts>, clock: &TestClock) -> TokenVerifier {
    verifier_for(cts, clock, None)
}

fn verifier_for(cts: &Arc<StubCts>, clock: &TestClock, audience: Option<&str>) -> TokenVerifier {
    TokenVerifier::new(
        ISSUER.parse().unwrap(),
        audience.map(str::to_string),
        transport::share(Arc::clone(cts)),
        clock.shared(),
    )
    .unwrap()
}

/// A verifier for [`ISSUER`] at [`NOW`], whose CTS publishes key-a.
fn serving_key_a() -> (Arc<StubCts>, TokenVerifier) {
    let cts = StubCts::serving(jwks(&[&KEY_A]));
    let verifier = verifier(&cts, &TestClock::new(NOW));
    (cts, verifier)
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
        let (_, verifier) = serving_key_a();

        assert_eq!(
            verdict(&verifier, KEY_A.jwt(claims())).await,
            Ok(()),
            "a token the trusted issuer signed should be accepted"
        );
    }

    #[tokio::test]
    async fn the_keys_come_from_the_pinned_issuers_jwks() {
        let (cts, verifier) = serving_key_a();

        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();

        assert_eq!(
            cts.requests(),
            vec![("GET".to_string(), format!("{ISSUER}.well-known/jwks.json"))],
            "the keys should be fetched once, from the pinned issuer's JWKS",
        );
    }

    #[tokio::test]
    async fn an_issuer_differing_only_by_a_trailing_slash_is_the_same_issuer() {
        let (_, verifier) = serving_key_a();
        let iss = ISSUER.trim_end_matches('/');

        let accepted = verdict(&verifier, KEY_A.jwt(with(claims(), "iss", iss.into()))).await;

        assert_eq!(
            accepted,
            Ok(()),
            "a trailing slash should not change the issuer"
        );
    }

    #[tokio::test]
    async fn a_header_carrying_non_string_fields_is_accepted() {
        let (_, verifier) = serving_key_a();
        let header = serde_json::json!({"alg": "RS256", "kid": "key-a", "srf": true});

        let accepted = verdict(&verifier, KEY_A.jwt_with_header(header, claims())).await;

        assert_eq!(
            accepted,
            Ok(()),
            "a header field that is not a string should not refuse the token"
        );
    }

    #[tokio::test]
    async fn a_token_without_a_kid_uses_the_only_key() {
        let (_, verifier) = serving_key_a();
        let header = serde_json::json!({"alg": "RS256"});

        let accepted = verdict(&verifier, KEY_A.jwt_with_header(header, claims())).await;

        assert_eq!(
            accepted,
            Ok(()),
            "a token without a kid should use the JWKS's only key"
        );
    }

    #[tokio::test]
    async fn a_token_without_a_kid_is_refused_when_the_jwks_holds_several_keys() {
        let cts = StubCts::serving(jwks(&[&KEY_A, &KEY_B]));
        let verifier = verifier(&cts, &TestClock::new(NOW));
        let header = serde_json::json!({"alg": "RS256"});

        let refused = verdict(&verifier, KEY_A.jwt_with_header(header, claims())).await;

        assert!(refused.is_err(), "the key would be a guess");
    }
}

mod given_a_forged_or_altered_token {
    use super::*;

    #[tokio::test]
    async fn altered_claims_are_refused() {
        let (_, verifier) = serving_key_a();
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
        let (_, verifier) = serving_key_a();
        // Claims to be key-a, but is signed by key-b.
        let header = serde_json::json!({"alg": "RS256", "kid": "key-a"});

        let refused = verdict(&verifier, KEY_B.jwt_with_header(header, claims())).await;

        assert!(
            refused.is_err(),
            "a key the issuer does not publish should not verify, got {refused:?}"
        );
    }

    #[tokio::test]
    async fn an_hmac_token_is_refused_before_any_key_is_fetched() {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let (cts, verifier) = serving_key_a();
        let hs256 = encode(
            &Header::default(),
            &claims(),
            &EncodingKey::from_secret(b"anyone-can-sign-this"),
        )
        .unwrap();

        let refused = verdict(&verifier, hs256).await;

        assert!(
            refused.is_err(),
            "an HMAC token should be refused, got {refused:?}"
        );
        assert!(
            cts.requests().is_empty(),
            "no key fetch for a token that cannot pass"
        );
    }

    #[tokio::test]
    async fn an_unsigned_token_is_refused() {
        let (_, verifier) = serving_key_a();
        let unsigned = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(claims().to_string()),
        );

        assert!(
            verdict(&verifier, unsigned).await.is_err(),
            "an unsigned token should be refused"
        );
    }

    #[tokio::test]
    async fn a_token_that_is_not_a_jwt_is_refused() {
        let (_, verifier) = serving_key_a();

        assert!(
            verdict(&verifier, "not-a-jwt".to_string()).await.is_err(),
            "a string that is not a JWT should be refused"
        );
    }
}

mod given_a_token_from_another_issuer {
    use super::*;

    #[tokio::test]
    async fn it_is_refused_without_fetching_the_issuers_keys() {
        // A rogue auth server signing with its own key and publishing its
        // own JWKS: the token is internally consistent, but not the trusted
        // issuer's.
        let (cts, verifier) = serving_key_a();
        let rogue = with(claims(), "iss", "https://rogue.example/".into());

        let refused = verdict(&verifier, KEY_A.jwt(rogue)).await;

        assert!(
            refused.is_err(),
            "a token from another issuer should be refused, got {refused:?}"
        );
        assert!(
            cts.requests().is_empty(),
            "the rogue issuer's JWKS is never asked for"
        );
    }

    #[tokio::test]
    async fn an_issuer_that_only_shares_a_prefix_is_refused() {
        let (_, verifier) = serving_key_a();
        let lookalike = format!("{}evil/", ISSUER);

        let refused = verdict(
            &verifier,
            KEY_A.jwt(with(claims(), "iss", lookalike.into())),
        )
        .await;

        assert!(
            refused.is_err(),
            "an issuer that only shares a prefix should be refused, got {refused:?}"
        );
    }
}

mod given_the_tokens_expiry {
    use super::*;
    use crate::error::RequestError;
    use crate::transport::{HttpRequest, HttpResponse, HttpTransport};

    /// A CTS so slow to serve its keys that `clock` moves on by `secs`.
    struct Slow {
        cts: Arc<StubCts>,
        clock: TestClock,
        secs: u64,
    }

    impl HttpTransport for Slow {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, RequestError> {
            self.clock.advance(self.secs);
            self.cts.send(request).await
        }
    }

    #[tokio::test]
    async fn a_token_that_expires_while_the_keys_are_fetched_is_refused() {
        let clock = TestClock::new(NOW);
        let slow = Slow {
            cts: StubCts::serving(jwks(&[&KEY_A])),
            clock: clock.clone(),
            secs: 3600 + LEEWAY_SECS,
        };
        let verifier = TokenVerifier::new(
            ISSUER.parse().unwrap(),
            None,
            transport::share(slow),
            clock.shared(),
        )
        .unwrap();

        assert!(
            verdict(&verifier, KEY_A.jwt(claims())).await.is_err(),
            "a token that expired during the key fetch should be refused"
        );
    }

    #[tokio::test]
    async fn a_token_past_its_expiry_and_the_leeway_is_refused() {
        let (_, verifier) = serving_key_a();
        let expired = with(claims(), "exp", (NOW - LEEWAY_SECS).into());

        assert!(
            verdict(&verifier, KEY_A.jwt(expired)).await.is_err(),
            "a token past its expiry and the leeway should be refused"
        );
    }

    #[tokio::test]
    async fn a_token_expired_within_the_leeway_is_accepted() {
        let (_, verifier) = serving_key_a();
        let skewed = with(claims(), "exp", (NOW - LEEWAY_SECS + 1).into());

        assert_eq!(
            verdict(&verifier, KEY_A.jwt(skewed)).await,
            Ok(()),
            "a token expired within the leeway should be accepted"
        );
    }

    #[tokio::test]
    async fn a_token_without_an_expiry_is_refused() {
        let (_, verifier) = serving_key_a();
        let mut claims = claims();
        let _ = claims.as_object_mut().unwrap().remove("exp");

        assert!(
            verdict(&verifier, KEY_A.jwt(claims)).await.is_err(),
            "a token without exp should be refused"
        );
    }
}

mod given_a_not_before_time {
    use super::*;

    #[tokio::test]
    async fn a_token_not_yet_valid_is_refused() {
        let (_, verifier) = serving_key_a();

        let jwt = KEY_A.jwt(with(claims(), "nbf", (NOW + 600).into()));

        assert!(
            verdict(&verifier, jwt).await.is_err(),
            "a token whose nbf is in the future should be refused"
        );
    }

    /// The same clock skew is allowed as for `exp`.
    #[tokio::test]
    async fn a_token_valid_within_the_leeway_is_accepted() {
        let (_, verifier) = serving_key_a();

        let jwt = KEY_A.jwt(with(claims(), "nbf", (NOW + LEEWAY_SECS).into()));

        assert_eq!(
            verdict(&verifier, jwt).await,
            Ok(()),
            "a token whose nbf is within the leeway should be accepted"
        );
    }

    #[tokio::test]
    async fn a_token_valid_just_past_the_leeway_is_refused() {
        let (_, verifier) = serving_key_a();

        let jwt = KEY_A.jwt(with(claims(), "nbf", (NOW + LEEWAY_SECS + 1).into()));

        assert!(
            verdict(&verifier, jwt).await.is_err(),
            "a token whose nbf is just past the leeway should be refused"
        );
    }

    #[tokio::test]
    async fn a_token_already_valid_is_accepted() {
        let (_, verifier) = serving_key_a();

        let jwt = KEY_A.jwt(with(claims(), "nbf", (NOW - 10).into()));

        assert_eq!(
            verdict(&verifier, jwt).await,
            Ok(()),
            "a token whose nbf has passed should be accepted"
        );
    }

    /// A token that verified is checked again on its times alone, so a clock
    /// that steps back before its `nbf` refuses it.
    #[tokio::test]
    async fn a_verified_token_is_refused_after_the_clock_steps_back() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let clock = TestClock::new(NOW);
        let verifier = verifier(&cts, &clock);
        let jwt = KEY_A.jwt(with(claims(), "nbf", NOW.into()));
        verdict(&verifier, jwt.clone()).await.unwrap();

        clock.set(NOW - LEEWAY_SECS - 1);

        assert!(
            verdict(&verifier, jwt).await.is_err(),
            "a remembered token should be refused once the clock is before its nbf"
        );
    }
}

mod given_an_expected_subject {
    use super::*;

    const SUBJECT: &str = "CS|CSAKkeyId";

    fn verifier() -> TokenVerifier {
        serving_key_a().1.with_subject(Some(SUBJECT.to_string()))
    }

    #[tokio::test]
    async fn a_token_for_that_subject_is_accepted() {
        let jwt = KEY_A.jwt(with(claims(), "sub", SUBJECT.into()));

        assert_eq!(
            verdict(&verifier(), jwt).await,
            Ok(()),
            "a token for the expected subject should be accepted"
        );
    }

    #[tokio::test]
    async fn a_token_for_another_subject_is_refused() {
        let jwt = KEY_A.jwt(with(claims(), "sub", "CS|CSAKanotherKeyId".into()));

        assert!(
            verdict(&verifier(), jwt).await.is_err(),
            "a token for another subject should be refused"
        );
    }

    #[tokio::test]
    async fn a_token_with_no_subject_is_refused() {
        let mut claims = claims();
        claims.as_object_mut().unwrap().remove("sub");

        assert!(
            verdict(&verifier(), KEY_A.jwt(claims)).await.is_err(),
            "a token without sub should be refused"
        );
    }
}

mod given_an_expected_audience {
    use super::*;

    const AUDIENCE: &str = "ap-southeast-2.aws.viturhosted.net";

    #[tokio::test]
    async fn a_token_for_that_audience_is_accepted() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier_for(&cts, &TestClock::new(NOW), Some(AUDIENCE));

        assert_eq!(
            verdict(&verifier, KEY_A.jwt(claims())).await,
            Ok(()),
            "a token for the expected audience should be accepted"
        );
    }

    #[tokio::test]
    async fn an_audience_list_containing_it_is_accepted() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier_for(&cts, &TestClock::new(NOW), Some(AUDIENCE));
        let listed = with(claims(), "aud", serde_json::json!(["other", AUDIENCE]));

        assert_eq!(
            verdict(&verifier, KEY_A.jwt(listed)).await,
            Ok(()),
            "an audience list containing the expected audience should be accepted"
        );
    }

    #[tokio::test]
    async fn a_token_for_another_audience_is_refused() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier_for(&cts, &TestClock::new(NOW), Some(AUDIENCE));
        let other = with(claims(), "aud", "us-east-1.aws.viturhosted.net".into());

        assert!(
            verdict(&verifier, KEY_A.jwt(other)).await.is_err(),
            "a token for another audience should be refused"
        );
    }

    #[tokio::test]
    async fn a_token_without_an_audience_is_refused() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let verifier = verifier_for(&cts, &TestClock::new(NOW), Some(AUDIENCE));
        let mut claims = claims();
        let _ = claims.as_object_mut().unwrap().remove("aud");

        assert!(
            verdict(&verifier, KEY_A.jwt(claims)).await.is_err(),
            "a token without aud should be refused"
        );
    }
}

mod given_the_key_cache {
    use super::*;
    use crate::error::RequestError;
    use crate::transport::{HttpRequest, HttpResponse, HttpTransport};
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A CTS that serves its keys once, then never answers again.
    struct AnswersOnce {
        cts: Arc<StubCts>,
        answered: AtomicBool,
    }

    impl HttpTransport for AnswersOnce {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, RequestError> {
            if self.answered.swap(true, Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            self.cts.send(request).await
        }
    }

    #[tokio::test]
    async fn a_slow_refresh_does_not_hold_up_callers_with_a_stale_key() {
        let clock = TestClock::new(NOW);
        let verifier = TokenVerifier::new(
            ISSUER.parse().unwrap(),
            None,
            transport::share(AnswersOnce {
                cts: StubCts::serving(jwks(&[&KEY_A])),
                answered: AtomicBool::new(false),
            }),
            clock.shared(),
        )
        .unwrap();
        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();
        clock.advance(KEYS_TTL_SECS);

        // This caller starts the refresh, which never finishes.
        let refreshing = verifier.verify(token(another_token()));
        tokio::pin!(refreshing);
        tokio::select! {
            _ = &mut refreshing => panic!("the refresh should still be running"),
            () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
        }

        let third = KEY_A.jwt(with(claims(), "iat", (NOW - 1).into()));
        let verified =
            tokio::time::timeout(std::time::Duration::from_secs(5), verdict(&verifier, third))
                .await
                .expect("a caller with a stale key must not wait for the refresh");
        assert_eq!(
            verified,
            Ok(()),
            "a caller with a stale key should verify while the refresh runs"
        );
    }

    #[tokio::test]
    async fn concurrent_callers_without_a_key_share_one_fetch() {
        let (cts, verifier) = serving_key_a();

        let (first, second) = tokio::join!(
            verdict(&verifier, KEY_A.jwt(claims())),
            verdict(&verifier, another_token()),
        );

        assert_eq!(
            (first, second),
            (Ok(()), Ok(())),
            "both concurrent callers should be accepted"
        );
        assert_eq!(
            cts.requests().len(),
            1,
            "concurrent callers should share one fetch"
        );
    }

    /// A CTS that serves its keys only once `open` is notified.
    struct Gated {
        cts: Arc<StubCts>,
        open: Arc<tokio::sync::Notify>,
    }

    impl HttpTransport for Gated {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, RequestError> {
            self.open.notified().await;
            self.cts.send(request).await
        }
    }

    /// The second caller arrives after the first has started fetching, so
    /// it finds a fetch attempted moments ago and no key yet. That is a
    /// fetch still running, not one that failed.
    #[tokio::test]
    async fn a_caller_without_a_key_waits_for_a_fetch_already_running() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let open = Arc::new(tokio::sync::Notify::new());
        let verifier = TokenVerifier::new(
            ISSUER.parse().unwrap(),
            None,
            transport::share(Gated {
                cts: cts.clone(),
                open: open.clone(),
            }),
            TestClock::new(NOW).shared(),
        )
        .unwrap();

        let (first, second, ()) = tokio::join!(
            verdict(&verifier, KEY_A.jwt(claims())),
            verdict(&verifier, another_token()),
            async {
                for _ in 0..10 {
                    tokio::task::yield_now().await;
                }
                open.notify_one();
            },
        );

        assert_eq!(
            (first, second),
            (Ok(()), Ok(())),
            "both callers should be accepted"
        );
        assert_eq!(
            cts.requests().len(),
            1,
            "the second caller should wait for the running fetch, not start another"
        );
    }

    #[tokio::test]
    async fn the_jwks_is_fetched_once_while_fresh() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let clock = TestClock::new(NOW);
        let verifier = verifier(&cts, &clock);

        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();
        clock.advance(KEYS_TTL_SECS - 1);
        verdict(&verifier, another_token()).await.unwrap();

        assert_eq!(
            cts.requests().len(),
            1,
            "a fresh JWKS should not be fetched again"
        );
    }

    /// Each filter on its own: the key carries key-b's RSA modulus and
    /// exponent, so only the named field keeps it out.
    #[tokio::test]
    async fn a_key_not_typed_rsa_or_not_for_rs256_is_ignored() {
        for (field, value) in [("kty", "EC"), ("alg", "RS512"), ("use", "enc")] {
            let mut key = KEY_B.jwk();
            key[field] = value.into();
            let jwks = serde_json::json!({"keys": [KEY_A.jwk(), key]}).to_string();
            let cts = StubCts::serving(jwks);
            let verifier = verifier(&cts, &TestClock::new(NOW));

            assert!(
                verdict(&verifier, KEY_B.jwt(claims())).await.is_err(),
                "a key with {field} {value:?} must not verify an RS256 signature"
            );
        }
    }

    /// Written in minutes rather than with `KEYS_TTL_SECS`, so it pins the
    /// lifetime itself.
    #[tokio::test]
    async fn the_jwks_is_reused_for_an_hour() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let clock = TestClock::new(NOW);
        let verifier = verifier(&cts, &clock);

        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();
        clock.advance(59 * 60);
        verdict(&verifier, another_token()).await.unwrap();

        assert_eq!(
            cts.requests().len(),
            1,
            "a 59-minute-old JWKS is still fresh"
        );
    }

    #[tokio::test]
    async fn the_jwks_is_fetched_again_once_stale() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let clock = TestClock::new(NOW);
        let verifier = verifier(&cts, &clock);

        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();
        clock.advance(KEYS_TTL_SECS);
        verdict(&verifier, another_token()).await.unwrap();

        assert_eq!(
            cts.requests().len(),
            2,
            "a stale JWKS should be fetched again"
        );
    }

    #[tokio::test]
    async fn a_rotated_key_is_fetched_as_soon_as_the_rate_limit_allows() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let clock = TestClock::new(NOW);
        let verifier = verifier(&cts, &clock);
        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();

        cts.rotate_to(jwks(&[&KEY_A, &KEY_B]));
        clock.advance(MIN_REFETCH_SECS);

        assert_eq!(
            verdict(&verifier, KEY_B.jwt(claims())).await,
            Ok(()),
            "a rotated-in key should verify once a refetch is allowed"
        );
        assert_eq!(
            cts.requests().len(),
            2,
            "the rotated key should cost one refetch"
        );
    }

    #[tokio::test]
    async fn unknown_keys_do_not_refetch_more_than_once_per_interval() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let clock = TestClock::new(NOW);
        let verifier = verifier(&cts, &clock);
        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();

        clock.advance(MIN_REFETCH_SECS - 1);
        for _ in 0..3 {
            assert!(
                verdict(&verifier, KEY_B.jwt(claims())).await.is_err(),
                "a key not in the JWKS should be refused"
            );
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
        let cts = StubCts::serving(jwks);
        let verifier = verifier(&cts, &TestClock::new(NOW));

        assert_eq!(
            verdict(&verifier, KEY_A.jwt(claims())).await,
            Ok(()),
            "a key in the JWKS should verify alongside keys that are ignored"
        );
        assert!(
            verdict(&verifier, KEY_B.jwt(claims())).await.is_err(),
            "a key published for encryption must not verify a signature"
        );
    }
}

mod given_a_token_that_has_already_verified {
    use super::*;

    #[tokio::test]
    async fn it_is_not_checked_against_the_keys_again() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let clock = TestClock::new(NOW);
        let verifier = verifier(&cts, &clock);
        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();

        // The keys are stale and CTS is down: a full check would fetch them.
        cts.set_status(503);
        clock.advance(KEYS_TTL_SECS);

        assert_eq!(
            verdict(&verifier, KEY_A.jwt(claims())).await,
            Ok(()),
            "a remembered token should verify without the keys"
        );
        assert_eq!(cts.requests().len(), 1, "the keys were not fetched again");
    }

    #[tokio::test]
    async fn it_is_refused_once_it_expires() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let clock = TestClock::new(NOW);
        let verifier = verifier(&cts, &clock);
        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();

        clock.advance(3600 + LEEWAY_SECS);

        assert!(
            verdict(&verifier, KEY_A.jwt(claims())).await.is_err(),
            "a remembered token should be refused once it expires"
        );
    }

    #[tokio::test]
    async fn a_different_token_is_checked_in_full() {
        let (_, verifier) = serving_key_a();
        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();

        assert!(
            verdict(&verifier, KEY_B.jwt(claims())).await.is_err(),
            "a token not remembered should be checked in full and refused"
        );
    }

    /// An OIDC federation strategy shares one verifier across its users'
    /// engines, so two users' cached tokens alternate. Each should be
    /// remembered, not only the last one to verify.
    #[tokio::test]
    async fn two_alternating_tokens_are_not_checked_against_the_keys_again() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let clock = TestClock::new(NOW);
        let verifier = verifier(&cts, &clock);
        let (first, second) = (KEY_A.jwt(claims()), another_token());
        verdict(&verifier, first.clone()).await.unwrap();
        verdict(&verifier, second.clone()).await.unwrap();

        // The keys are stale: a full check would fetch them.
        clock.advance(KEYS_TTL_SECS);
        verdict(&verifier, first).await.unwrap();
        verdict(&verifier, second).await.unwrap();

        assert_eq!(
            cts.requests().len(),
            1,
            "both tokens had verified, so neither should be checked in full again"
        );
    }
}

mod given_the_keys_cannot_be_fetched {
    use super::*;
    use crate::error::RequestError;
    use crate::transport::{HttpRequest, HttpResponse, HttpTransport};

    /// A CTS that never answers.
    struct Hanging;

    impl HttpTransport for Hanging {
        async fn send(&self, _: HttpRequest) -> Result<HttpResponse, RequestError> {
            std::future::pending().await
        }
    }

    /// An abandoned fetch is forgotten, not counted as a failure: the next
    /// keyless caller is neither told the keys are unavailable nor refused
    /// as signed by an unknown key. It fetches again.
    #[tokio::test]
    async fn a_fetch_abandoned_part_way_is_not_counted_as_failed() {
        let verifier = TokenVerifier::new(
            ISSUER.parse().unwrap(),
            None,
            transport::share(Hanging),
            TestClock::new(NOW).shared(),
        )
        .unwrap();
        let abandoned = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            verifier.verify(token(KEY_A.jwt(claims()))),
        )
        .await;
        assert!(abandoned.is_err(), "the fetch should still be pending");

        // The hanging CTS never answers, so a caller that fetches again is
        // still waiting. One answered from the cache would not be.
        let next = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            verifier.verify(token(KEY_A.jwt(claims()))),
        )
        .await;
        assert!(
            next.is_err(),
            "the next caller should fetch again, got an answer: {next:?}"
        );
    }

    /// A CTS that hangs on the first fetch and answers every later one.
    struct HangsFirst {
        cts: Arc<StubCts>,
        hung: std::sync::atomic::AtomicBool,
    }

    impl HttpTransport for HangsFirst {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, RequestError> {
            if !self.hung.swap(true, std::sync::atomic::Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            self.cts.send(request).await
        }
    }

    /// A caller that gives up on its fetch (a timeout, a dropped request)
    /// has not seen the keys fail: the next caller fetches them, rather than
    /// every keyless caller being told the keys are unavailable for
    /// `MIN_REFETCH_SECS`.
    #[tokio::test]
    async fn a_fetch_abandoned_part_way_does_not_hold_off_the_next_fetch() {
        let verifier = TokenVerifier::new(
            ISSUER.parse().unwrap(),
            None,
            transport::share(HangsFirst {
                cts: StubCts::serving(jwks(&[&KEY_A])),
                hung: std::sync::atomic::AtomicBool::new(false),
            }),
            TestClock::new(NOW).shared(),
        )
        .unwrap();
        let abandoned = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            verifier.verify(token(KEY_A.jwt(claims()))),
        )
        .await;
        assert!(
            abandoned.is_err(),
            "the first fetch should still be pending"
        );

        let verified = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            verifier.verify(token(KEY_A.jwt(claims()))),
        )
        .await
        .expect("the second fetch is answered");

        assert!(
            verified.is_ok(),
            "an abandoned fetch is not a failed one, got: {verified:?}"
        );
    }

    #[tokio::test]
    async fn an_unreachable_cts_is_a_request_error() {
        let cts = StubCts::unreachable();
        let verifier = verifier(&cts, &TestClock::new(NOW));

        let err = verifier
            .verify(token(KEY_A.jwt(claims())))
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::Request(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_failed_fetch_is_not_retried_more_than_once_per_interval() {
        let cts = StubCts::unreachable();
        let clock = TestClock::new(NOW);
        let verifier = verifier(&cts, &clock);

        for _ in 0..3 {
            let err = verifier
                .verify(token(KEY_A.jwt(claims())))
                .await
                .unwrap_err();
            assert!(matches!(err, AuthError::Request(_)), "got {err:?}");
        }
        assert_eq!(
            cts.requests().len(),
            1,
            "an outage must not turn every call into a fetch"
        );

        clock.advance(MIN_REFETCH_SECS);
        let _ = verifier.verify(token(KEY_A.jwt(claims()))).await;
        assert_eq!(
            cts.requests().len(),
            2,
            "the fetch is retried after the interval"
        );
    }

    #[tokio::test]
    async fn an_error_status_is_a_server_error() {
        let cts = StubCts::serving("{}".to_string());
        cts.set_status(503);
        let verifier = verifier(&cts, &TestClock::new(NOW));

        let err = verifier
            .verify(token(KEY_A.jwt(claims())))
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::Server(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn an_unreadable_jwks_is_a_request_error_not_the_tokens() {
        let cts = StubCts::serving("<html>".to_string());
        let verifier = verifier(&cts, &TestClock::new(NOW));

        let err = verifier
            .verify(token(KEY_A.jwt(claims())))
            .await
            .unwrap_err();

        assert!(matches!(err, AuthError::Request(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn cached_keys_still_verify_when_a_refresh_fails() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let clock = TestClock::new(NOW);
        let verifier = verifier(&cts, &clock);
        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();

        cts.set_status(503);
        clock.advance(KEYS_TTL_SECS);

        assert_eq!(
            verdict(&verifier, another_token()).await,
            Ok(()),
            "a JWKS outage must not refuse a token the cached keys verify"
        );
        assert_eq!(cts.requests().len(), 2, "the refresh was attempted");
    }

    #[tokio::test]
    async fn an_unknown_key_during_an_outage_is_not_accepted() {
        let cts = StubCts::serving(jwks(&[&KEY_A]));
        let clock = TestClock::new(NOW);
        let verifier = verifier(&cts, &clock);
        verdict(&verifier, KEY_A.jwt(claims())).await.unwrap();

        cts.set_status(503);
        clock.advance(MIN_REFETCH_SECS);

        let err = verifier
            .verify(token(KEY_B.jwt(claims())))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Server(_)), "got {err:?}");
    }
}

mod given_the_verification_setting {
    use super::*;

    fn region() -> Region {
        Region::aws("ap-southeast-2").unwrap()
    }

    #[test]
    fn off_builds_no_verifier() {
        let cts = transport::share(StubCts::serving(String::new()));
        let resolved = resolve(false, || panic!("region asked for"), None, &cts).unwrap();
        assert!(
            resolved.is_none(),
            "verification off should build no verifier"
        );
    }

    #[test]
    fn the_issuer_is_the_regions_cts() {
        let cts = transport::share(StubCts::serving(String::new()));
        let verifier = resolve(true, || Ok(region()), None, &cts)
            .unwrap()
            .expect("a verifier");
        assert_eq!(
            verifier.issuer.as_str(),
            ISSUER,
            "the issuer should be the region's CTS"
        );
        assert_eq!(
            verifier.jwks_url.as_str(),
            format!("{ISSUER}.well-known/jwks.json"),
            "the JWKS should be the issuer's"
        );
    }

    #[test]
    fn an_issuer_with_a_path_keeps_it() {
        let verifier = TokenVerifier::new(
            "https://cts.example.com/staging".parse().unwrap(),
            None,
            transport::share(StubCts::serving(String::new())),
            system_clock(),
        )
        .unwrap();
        assert_eq!(
            verifier.issuer.as_str(),
            "https://cts.example.com/staging/",
            "an issuer's path should be kept"
        );
        assert_eq!(
            verifier.jwks_url.as_str(),
            "https://cts.example.com/staging/.well-known/jwks.json",
            "the JWKS should be under the issuer's path"
        );
    }
}

mod given_a_refusal {
    use super::*;

    /// The log line is the only place a refusal's reason appears, so each
    /// one must say something, and something different.
    #[test]
    fn each_reason_describes_itself() {
        let reasons: Vec<String> = [
            Rejection::Malformed,
            Rejection::Algorithm,
            Rejection::Issuer,
            Rejection::Expired,
            Rejection::Audience,
            Rejection::UnknownKey,
            Rejection::Signature,
        ]
        .iter()
        .map(ToString::to_string)
        .collect();

        let distinct: std::collections::HashSet<&String> = reasons.iter().collect();
        assert!(reasons.iter().all(|r| !r.is_empty()), "got {reasons:?}");
        assert_eq!(distinct.len(), reasons.len(), "got {reasons:?}");
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
    fn a_4096_bit_key_verifies() {
        let key = TestKey::generate_with_size("key-4096", aws_lc_rs::rsa::KeySize::Rsa4096);
        let signature = key.sign(b"message");
        for (name, verify) in BACKENDS {
            assert!(verify(&signing_key(&key), b"message", &signature), "{name}");
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

/// Each strategy builder's `verify_tokens`, end to end
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

    /// The `sub` CTS gives a token issued for [`key`].
    const KEY_SUBJECT: &str = "CS|CSAKkeyId";

    /// CTS's claims for a token issued to [`key`].
    fn key_claims(iss: &str, workspace: &str) -> serde_json::Value {
        with(cts_claims(iss, workspace), "sub", KEY_SUBJECT.into())
    }

    fn genuine() -> String {
        KEY_A.jwt(key_claims(ISSUER, WORKSPACE))
    }

    /// Signed by a key the trusted issuer does not publish, naming a rogue
    /// issuer: what an attacker who controls the auth URL would mint.
    fn forged() -> String {
        KEY_B.jwt(key_claims("https://rogue.example/", WORKSPACE))
    }

    fn cts(token: String) -> Arc<StubCts> {
        Arc::new(StubCts::new(token, jwks(&[&KEY_A])))
    }

    async fn access_key(cts: &Arc<StubCts>) -> Result<ServiceToken, AuthError> {
        AccessKeyStrategy::builder(crn(), key())
            .base_url(AUTH_URL.parse().unwrap())
            .transport(Arc::clone(cts))
            .verify_tokens()
            .build()
            .unwrap()
            .get_token()
            .await
    }

    #[tokio::test]
    async fn the_access_key_strategy_returns_a_genuine_token() {
        let cts = cts(genuine());
        assert!(
            access_key(&cts).await.is_ok(),
            "the access key strategy should return a genuine token"
        );
    }

    #[tokio::test]
    async fn the_access_key_strategy_refuses_a_forged_token() {
        let cts = cts(forged());
        let err = access_key(&cts).await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn verify_tokens_trusts_the_regions_cts_not_the_auth_url() {
        // The auth URL is overridden, as `CS_CTS_HOST` or `base_url` would;
        // the issuer the strategy trusts is still the region's CTS, and that
        // is where it asks for keys. The token names the region's CTS too,
        // so it verifies.
        let cts = cts(genuine());

        assert!(
            access_key(&cts).await.is_ok(),
            "a genuine token should verify despite the overridden auth URL"
        );
        assert_eq!(
            cts.jwks_requests(),
            vec![format!("{ISSUER}.well-known/jwks.json")],
            "the keys should come from the region's CTS, not the auth URL"
        );
    }

    #[tokio::test]
    async fn verify_tokens_refuses_a_token_from_the_overridden_auth_url() {
        let cts = cts(KEY_A.jwt(cts_claims(AUTH_URL, WORKSPACE)));

        let err = access_key(&cts).await.unwrap_err();

        assert!(matches!(err, AuthError::InvalidToken(_)), "got {err:?}");
        assert!(
            cts.jwks_requests().is_empty(),
            "a token naming the auth URL as issuer should be refused before any key fetch"
        );
    }

    /// A real token CTS issued to another access key in the workspace, which
    /// whoever controls the auth URL could hand over in place of this key's.
    #[tokio::test]
    async fn the_access_key_strategy_refuses_a_genuine_token_for_another_key() {
        let cts = cts(KEY_A.jwt(with(
            cts_claims(ISSUER, WORKSPACE),
            "sub",
            "CS|CSAKanotherKeyId".into(),
        )));

        let err = access_key(&cts).await.unwrap_err();

        assert!(matches!(err, AuthError::InvalidToken(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn the_access_key_strategy_refuses_a_genuine_token_for_another_workspace() {
        let cts = cts(KEY_A.jwt(key_claims(ISSUER, "AAAAAAAAAAAAAAAA")));

        let err = access_key(&cts).await.unwrap_err();

        assert!(
            matches!(err, AuthError::WorkspaceMismatch(_)),
            "got {err:?}"
        );
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

    /// Once CTS issues good tokens again, the next call gets one: a refused
    /// token is not cached until it expires.
    #[tokio::test]
    async fn the_access_key_strategy_replaces_a_refused_token_on_the_next_call() {
        let cts = cts(forged());
        let strategy = AccessKeyStrategy::builder(crn(), key())
            .base_url(AUTH_URL.parse().unwrap())
            .transport(Arc::clone(&cts))
            .verify_tokens()
            .build()
            .unwrap();
        assert!(
            strategy.get_token().await.is_err(),
            "the forged token should be refused"
        );

        cts.set_token(genuine());

        assert!(
            strategy.get_token().await.is_ok(),
            "the next call should get the new, genuine token"
        );
    }

    /// A token CTS keeps issuing and the verifier keeps refusing (here a
    /// `sub` that never matches, as a wrong setting would cause) must not
    /// turn every `get_token` into a token request to CTS.
    #[tokio::test]
    async fn a_token_refused_again_and_again_is_not_requested_on_every_call() {
        let cts = cts(KEY_A.jwt(with(
            cts_claims(ISSUER, WORKSPACE),
            "sub",
            "CS|CSAKanotherKeyId".into(),
        )));
        let strategy = AccessKeyStrategy::builder(crn(), key())
            .base_url(AUTH_URL.parse().unwrap())
            .transport(Arc::clone(&cts))
            .verify_tokens()
            .build()
            .unwrap();

        for _ in 0..4 {
            let err = strategy.get_token().await.unwrap_err();
            assert!(
                matches!(err, AuthError::InvalidToken(_)),
                "each call should be refused, got {err:?}"
            );
        }

        let token_requests = cts
            .requests()
            .into_iter()
            .filter(|(method, _)| method == "POST")
            .count();
        assert!(
            token_requests <= 2,
            "a refusal that keeps happening must back off, got {token_requests} token requests"
        );
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
        assert!(
            cts.jwks_requests().is_empty(),
            "no keys should be fetched when verification is off"
        );
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
        assert!(
            oidc(&cts(genuine())).await.is_ok(),
            "the OIDC federation strategy should return a genuine token"
        );
    }

    #[tokio::test]
    async fn the_oidc_federation_strategy_refuses_a_forged_token() {
        let err = oidc(&cts(forged())).await.unwrap_err();
        assert!(matches!(err, AuthError::InvalidToken(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn the_oidc_federation_strategy_replaces_a_refused_token_on_the_next_call() {
        let cts = cts(forged());
        let provider = OidcProviderFn::new(|| async { Ok(SecretToken::new("provider.jwt.value")) });
        let strategy = OidcFederationStrategy::builder(crn(), provider)
            .base_url(AUTH_URL.parse().unwrap())
            .transport(Arc::clone(&cts))
            .verify_tokens()
            .build()
            .unwrap();
        assert!(
            strategy.get_token().await.is_err(),
            "the forged token should be refused"
        );

        cts.set_token(genuine());

        assert!(
            strategy.get_token().await.is_ok(),
            "the next call should get the new, genuine token"
        );
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
        assert!(
            device_session(&cts, &genuine()).await.is_ok(),
            "the device session strategy should return a genuine token"
        );
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
            vec![format!("{ISSUER}.well-known/jwks.json")],
            "the keys should come from the saved region's CTS"
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
            .verify_tokens()
            .detect()
            .unwrap();

        let err = strategy.get_token().await.unwrap_err();

        assert!(matches!(err, AuthError::InvalidToken(_)), "got {err:?}");
    }
}
