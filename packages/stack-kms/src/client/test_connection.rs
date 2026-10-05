//! In-memory [`ZeroKMSConnection`] used by unit tests to stub ZeroKMS
//! responses without touching the network, plus the fixtures every unit
//! test built on it needs (a client key, a client over the stub, and the
//! key material ZeroKMS would return).
//!
//! Shared by `client.rs`'s own tests and by `provider.rs`, which drives the
//! key-provider implementation over the same stub — and, behind the
//! `test-support` feature, by `stack-encrypt`, whose
//! `impl KeysetRegistry for Arc<StackKms>` cannot be tested from this crate
//! (the trait is not ours) and cannot be tested without a connection.

// Test scaffolding, compiled into the library only behind `test-support`. The
// crate's production lints are relaxed here for the same reason they are
// relaxed under `cfg(test)`: a fixture that cannot build its own stub has
// nothing useful to return, and a panic is the right answer to a test that
// asked for an endpoint it never stubbed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// `client` is a private module, so these `pub` items are only reachable
// through the `test-support` re-export in `lib.rs`. With the feature off and
// `cfg(test)` on — `wasm:no-http-test` runs the tests that way — nothing
// re-exports them and `unreachable_pub` is right to say so; they are
// crate-internal in that configuration, and `pub` is harmless.
#![cfg_attr(not(feature = "test-support"), allow(unreachable_pub))]

use async_mutex::Mutex;
use uuid::uuid;
use zerokms_protocol::{
    GeneratedKey, Keyset, LoadKeysetResponse, RetrievedKey, ViturKeyMaterial, ViturRequest,
    ViturRequestError,
};

use recipher::keyset::{EncryptionKeySet, ProxyKeySet};

use crate::client::{Client, ClientOpts};
use crate::connection::{ZeroKMSConnection, ZeroKMSConnectionInit};
use crate::key::{ClientKey, V1KeySet};

/// A fresh, random [`ClientKey`]. Data and index keys are derived from it,
/// so a test that compares derived material must reuse one value (reach it
/// through `StackKms::client_key`) rather than call this twice.
pub fn random_client_key() -> ClientKey {
    let domain_key = EncryptionKeySet::generate().unwrap();
    let authority_key = EncryptionKeySet::generate().unwrap();
    let keyset = ProxyKeySet::generate(&authority_key, &domain_key);

    ClientKey {
        key_id: uuid!("00000000-0000-0000-0000-000000000000"),
        keyset: V1KeySet(keyset),
    }
}

/// A low-level [`Client`] over a stub connection the callback configures.
pub fn build_client(
    callback: impl FnOnce(TestConnectionBuilder) -> TestConnectionBuilder,
) -> Client<TestConnection> {
    let builder = callback(TestConnectionBuilder::new());
    let client_opts = ClientOpts::new(builder)
        .with_max_keys_per_req(10)
        .unwrap()
        .with_max_concurrent_reqs(5)
        .unwrap();
    Client::init_opts(client_opts).expect("Failed to initialize test client")
}

/// 528 bytes is the size of the key material returned by ZeroKMS for the
/// recipher proxy re-encryption scheme.
pub fn key_material() -> ViturKeyMaterial {
    ViturKeyMaterial::from(vec![7u8; 528])
}

/// The keyset id [`load_keyset_response`] resolves to.
pub const TEST_KEYSET_ID: uuid::Uuid = uuid!("11111111-1111-1111-1111-111111111111");

/// The `load_keyset` response `ZeroKmsKeyset::new` consumes: the keyset it
/// resolves to, plus the partial key material its index key derives from.
pub fn load_keyset_response() -> LoadKeysetResponse {
    LoadKeysetResponse {
        partial_index_key: RetrievedKey {
            key_material: key_material(),
        },
        keyset: Keyset {
            id: TEST_KEYSET_ID,
            name: "default".to_string(),
            description: String::new(),
            is_disabled: false,
            is_default: true,
        },
    }
}

pub fn generated_key(tag: Vec<u8>) -> GeneratedKey {
    GeneratedKey {
        key_material: key_material(),
        tag,
        decryption_policy: None,
    }
}

type EffectHandlers = Vec<(String, Box<dyn FnOnce(&str) + Send>)>;
type RequestHandlers = Vec<(String, Result<String, ViturRequestError>)>;

pub struct TestConnectionBuilder {
    handlers: RequestHandlers,
    effects: EffectHandlers,
}

impl TestConnectionBuilder {
    pub fn new() -> Self {
        Self {
            handlers: vec![],
            effects: vec![],
        }
    }

    /// Add a matcher for a particular request, returning a success message.
    ///
    /// The matcher is only run once.
    pub fn add_success_response<R: ViturRequest>(mut self, response: R::Response) -> Self {
        self.handlers.push((
            R::ENDPOINT.to_string(),
            Ok(serde_json::to_string(&response)
                .expect("Failed to serialise success response. This shouldn't happen.")),
        ));
        self
    }

    /// Add a matcher for a particular request, returning a [`ViturRequestError`].
    ///
    /// The matcher is only run once.
    pub fn add_failed_response<R: ViturRequest>(mut self, error: ViturRequestError) -> Self {
        self.handlers.push((R::ENDPOINT.to_string(), Err(error)));
        self
    }

    /// Add a matcher for a particular request, running an effect on the body of the request.
    ///
    /// This matcher is only run once.
    pub fn add_effect<R: ViturRequest, H: FnOnce(R) + Send + 'static>(
        mut self,
        handler: H,
    ) -> Self {
        let endpoint = R::ENDPOINT;

        self.effects.push((
            endpoint.to_string(),
            Box::new(move |message| {
                handler(serde_json::from_str(message).expect(
                    "Failed to parse request from message in test effect. This shouldn't happen.",
                ))
            }),
        ));

        self
    }

    pub fn build(self) -> TestConnection {
        TestConnection {
            handlers: Mutex::new(self.handlers),
            effects: Mutex::new(self.effects),
        }
    }
}

impl Default for TestConnectionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct TestConnection {
    handlers: Mutex<RequestHandlers>,
    effects: Mutex<EffectHandlers>,
}

impl ZeroKMSConnectionInit for TestConnection {
    type ConnectionOpts = TestConnectionBuilder;
    type Error = std::convert::Infallible;

    fn init(builder: Self::ConnectionOpts) -> Result<Self, Self::Error> {
        Ok(builder.build())
    }
}

impl ZeroKMSConnection for TestConnection {
    // The stub has no URL to resolve — it dispatches on the request's endpoint
    // name — so the trait's defaults (no-op `ensure_base_url`, `has_base_url`
    // of `true`) are exactly right here.
    async fn send<Request: ViturRequest>(
        &self,
        request: Request,
        _access_token: &str,
    ) -> Result<Request::Response, ViturRequestError> {
        let endpoint = Request::ENDPOINT;

        let mut effect_guard = self.effects.lock().await;

        let effect_position = effect_guard.iter().position(|(x, _)| x == endpoint);

        let body = serde_json::to_string(&request)
            .expect("Failed to serialise request body in test connection");

        if let Some(index) = effect_position {
            let (_, effect) = effect_guard.remove(index);
            effect(&body);
        }

        let mut handler_guard = self.handlers.lock().await;

        let index = handler_guard
            .iter()
            .position(|(x, _)| x == endpoint)
            .unwrap_or_else(|| panic!("No handler defined for request: {endpoint}"));

        let (_, body) = handler_guard.remove(index);

        body.map(|x| {
            serde_json::from_str(&x)
                .expect("Failed to parse response body from handler in test connection")
        })
    }
}
