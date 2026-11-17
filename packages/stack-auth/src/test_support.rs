//! Shared, crate-internal test helpers for minting [`Token`]s.
//!
//! Several test modules need a token carrying specific JWT claims, or a token
//! with an arbitrary raw access-token string. Keeping one definition here avoids
//! the fixture drift that comes from copy-pasting the `Token { .. }` literal and
//! the unsigned-JWT mint into every test module.

#[cfg(feature = "http")]
use cts_common::Crn;

use crate::{SecretToken, Token};

/// A [`Token`] with the given raw access-token string and a far-future expiry,
/// so it reads as valid. The access token need not be a JWT — pass any string to
/// exercise the not-a-JWT paths.
pub(crate) fn raw_token(access_token: &str) -> Token {
    Token {
        access_token: SecretToken::new(access_token),
        token_type: "Bearer".to_string(),
        expires_at: u64::MAX,
        refresh_token: Some(SecretToken::new("refresh-token")),
        region: None,
        client_id: None,
        device_instance_id: None,
        federated_from: None,
    }
}

/// A [`Token`] whose access token is a real (unsigned) JWT carrying `claims`.
pub(crate) fn jwt_token(claims: serde_json::Value) -> Token {
    use jsonwebtoken::{encode, EncodingKey, Header};
    let jwt = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(b"test-secret"),
    )
    .expect("encode JWT");
    raw_token(&jwt)
}

/// Standard CTS JWT claims for `workspace`, with the other required claims
/// (`iss`/`sub`/`aud`/`iat`/`exp`/`org_id`/`scope`) filled in with valid placeholders.
///
/// NOTE: `exp` is a fixed *past* epoch, so the token reads as expired — use
/// [`jwt_with_workspace`] instead when a currently-valid token is needed.
pub(crate) fn claims_with_workspace(workspace: &str) -> serde_json::Value {
    serde_json::json!({
        "workspace": workspace,
        "iss": "https://cts.example.com",
        "sub": "user-123",
        "aud": "https://cts.example.com",
        "iat": 1_700_000_000u64,
        "exp": 1_700_003_600u64,
        "org_id": "org_test_default",
        "scope": "dataset:create",
    })
}

/// A workspace [`Crn`] in the standard test region (`ap-southeast-2.aws`)
/// carrying the given `workspace` ID.
///
/// Only the mock-server tests, which need the bundled transport, mint one.
#[cfg(feature = "http")]
pub(crate) fn crn_with_workspace(workspace: &str) -> Crn {
    format!("crn:ap-southeast-2.aws:{workspace}")
        .parse()
        .expect("test CRN parses")
}

/// A real (unsigned) JWT *string* carrying the given `workspace` claim and a
/// currently-valid (`now + 1h`) expiry — for exercising the post-auth
/// workspace verification that CRN-bound strategies run. Unlike
/// [`claims_with_workspace`], whose `exp` is a fixed past epoch, the token this
/// mints reads as valid.
///
/// Only the mock-server tests, which need the bundled transport, mint one.
#[cfg(feature = "http")]
pub(crate) fn jwt_with_workspace(workspace: &str) -> String {
    jwt_for_principal(workspace, "CS|test-principal")
}

/// [`jwt_with_workspace`] for a named principal (`sub`), so a test with
/// several callers can tell whose CTS token it was handed.
#[cfg(feature = "http")]
pub(crate) fn jwt_for_principal(workspace: &str, sub: &str) -> String {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let claims = serde_json::json!({
        "iss": "https://cts.example.com/",
        "sub": sub,
        "aud": "test-audience",
        "iat": now,
        "exp": now + 3600,
        "workspace": workspace,
        "org_id": "org_test_default",
        "scope": "",
    });
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(b"test-secret"),
    )
    .expect("JWT encode")
}

/// RS256 keys and a stub CTS that signs with them, for exercising token
/// verification (`token_verifier`) without a real CTS.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod signing {
    use std::sync::atomic::{AtomicU16, Ordering};
    use std::sync::{Arc, LazyLock, Mutex};

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::{KeyPair, KeySize, PublicKeyComponents};
    use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    use crate::error::RequestError;
    use crate::transport::{HttpRequest, HttpResponse, HttpTransport};

    /// RSA keys are slow to generate, so each test borrows these.
    pub(crate) static KEY_A: LazyLock<TestKey> = LazyLock::new(|| TestKey::generate("key-a"));
    pub(crate) static KEY_B: LazyLock<TestKey> = LazyLock::new(|| TestKey::generate("key-b"));

    pub(crate) struct TestKey {
        pub(crate) kid: &'static str,
        pair: KeyPair,
    }

    impl TestKey {
        pub(crate) fn generate(kid: &'static str) -> Self {
            Self::generate_with_size(kid, KeySize::Rsa2048)
        }

        pub(crate) fn generate_with_size(kid: &'static str, size: KeySize) -> Self {
            Self {
                kid,
                pair: KeyPair::generate(size).unwrap(),
            }
        }

        pub(crate) fn components(&self) -> PublicKeyComponents<Vec<u8>> {
            PublicKeyComponents::from(self.pair.public_key())
        }

        pub(crate) fn jwk(&self) -> serde_json::Value {
            let public = self.components();
            serde_json::json!({
                "kty": "RSA",
                "kid": self.kid,
                "alg": "RS256",
                "use": "sig",
                "n": URL_SAFE_NO_PAD.encode(&public.n),
                "e": URL_SAFE_NO_PAD.encode(&public.e),
            })
        }

        pub(crate) fn sign(&self, message: &[u8]) -> Vec<u8> {
            let mut signature = vec![0; self.pair.public_modulus_len()];
            self.pair
                .sign(
                    &RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    message,
                    &mut signature,
                )
                .unwrap();
            signature
        }

        /// A compact JWT over `header` and `claims`, signed with this key.
        pub(crate) fn jwt_with_header(
            &self,
            header: serde_json::Value,
            claims: serde_json::Value,
        ) -> String {
            let signed = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header.to_string()),
                URL_SAFE_NO_PAD.encode(claims.to_string()),
            );
            let signature = self.sign(signed.as_bytes());
            format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature))
        }

        pub(crate) fn jwt(&self, claims: serde_json::Value) -> String {
            self.jwt_with_header(
                serde_json::json!({"alg": "RS256", "typ": "JWT", "kid": self.kid}),
                claims,
            )
        }
    }

    /// A JWKS publishing `keys`.
    pub(crate) fn jwks(keys: &[&TestKey]) -> String {
        serde_json::json!({ "keys": keys.iter().map(|key| key.jwk()).collect::<Vec<_>>() })
            .to_string()
    }

    /// A stub CTS: `POST .../api/authorise` returns `token`, and
    /// `GET .../.well-known/jwks.json` returns `jwks` with the status set by
    /// [`set_status`](Self::set_status), whatever the host. It records each
    /// `(method, url)` it is sent.
    pub(crate) struct StubCts {
        token: String,
        jwks: Mutex<String>,
        status: AtomicU16,
        unreachable: bool,
        seen: Mutex<Vec<(String, String)>>,
    }

    impl StubCts {
        pub(crate) fn new(token: String, jwks: String) -> Self {
            Self {
                token,
                jwks: Mutex::new(jwks),
                status: AtomicU16::new(200),
                unreachable: false,
                seen: Mutex::new(Vec::new()),
            }
        }

        /// A CTS that only serves `jwks`.
        pub(crate) fn serving(jwks: String) -> Arc<Self> {
            Arc::new(Self::new(String::new(), jwks))
        }

        /// A CTS every request to fails.
        pub(crate) fn unreachable() -> Arc<Self> {
            Arc::new(Self {
                unreachable: true,
                ..Self::new(String::new(), String::new())
            })
        }

        /// Publish `jwks` from now on.
        pub(crate) fn rotate_to(&self, jwks: String) {
            *self.jwks.lock().unwrap() = jwks;
        }

        /// Answer JWKS requests with `status` from now on.
        pub(crate) fn set_status(&self, status: u16) {
            self.status.store(status, Ordering::SeqCst);
        }

        /// Every `(method, url)` the stub has been sent.
        pub(crate) fn requests(&self) -> Vec<(String, String)> {
            self.seen.lock().unwrap().clone()
        }

        /// The URLs of the JWKS requests the stub has seen.
        pub(crate) fn jwks_requests(&self) -> Vec<String> {
            self.seen
                .lock()
                .unwrap()
                .iter()
                .filter(|(method, _)| method == "GET")
                .map(|(_, url)| url.clone())
                .collect()
        }
    }

    impl HttpTransport for StubCts {
        async fn send(&self, request: HttpRequest) -> Result<HttpResponse, RequestError> {
            let url = request.url().clone();
            self.seen
                .lock()
                .unwrap()
                .push((request.method().to_string(), url.to_string()));
            if self.unreachable {
                return Err(RequestError(Box::new(std::io::Error::other("unreachable"))));
            }
            let (status, body) = match (request.method(), url.path()) {
                ("GET", path) if path.ends_with("/.well-known/jwks.json") => (
                    self.status.load(Ordering::SeqCst),
                    self.jwks.lock().unwrap().clone(),
                ),
                ("POST", path) if path.ends_with("/api/authorise") => (
                    200,
                    serde_json::json!({
                        "accessToken": self.token,
                        "expiry": u64::from(u32::MAX),
                    })
                    .to_string(),
                ),
                _ => return Ok(HttpResponse::new(404, Vec::new(), Vec::new())),
            };
            Ok(HttpResponse::new(status, Vec::new(), body.into_bytes()))
        }
    }

    /// CTS claims for `workspace`, issued by `iss`, valid for an hour.
    pub(crate) fn claims(iss: &str, workspace: &str) -> serde_json::Value {
        let now = web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        serde_json::json!({
            "iss": iss,
            "sub": "CS|test-principal",
            "aud": "test-audience",
            "iat": now,
            "exp": now + 3600,
            "workspace": workspace,
            "org_id": "org_test_default",
            "scope": "",
        })
    }
}
