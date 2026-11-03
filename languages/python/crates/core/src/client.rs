//! The one engine client a process shares, and the runtime it runs on.
//!
//! Every `Cipher` in the process uses the same `StackCipher`. It is built on
//! the first operation that needs it, by whichever thread gets there first,
//! and never rebuilt: credentials are read once, and the default keyset is
//! loaded once (the spec in #1341, "Operations"). Beside it is one
//! multi-thread tokio runtime. An operation hands its future to that runtime
//! and blocks its own thread, with the GIL released, so calls from several
//! Python threads run inside the engine at the same time.
//!
//! The client is built over a ZeroKMS connection that counts every request
//! it sends, and the keyset loads among them that succeeded. The count is for the tests: the spec's request rules (one key
//! request per 500 values, one keyset load per process) are observed
//! through it, not assumed.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use stack_auth::AutoStrategy;
use stack_encrypt::kms::{
    ClientOpts, ConnectionInitError, EnvKeyProvider, FallbackKeyProvider, HttpConnection,
    HttpConnectionOpts, KeyProvider, KeyProviderError, ProfileStore, StackKms,
    StackKmsBuilderError, ZeroKMSConnection, ZeroKMSConnectionInit, ZeroKmsEndpoint,
};
use stack_encrypt::StackCipher;
use zerokms_protocol::{LoadKeysetRequest, ViturRequest, ViturRequestError};

use crate::credentials;
use crate::refusal::Refusal;

/// The ZeroKMS client the shared cipher is built over.
pub type Kms = StackKms<AutoStrategy, Counting>;

/// The shared engine client with its runtime.
pub struct Client {
    cipher: StackCipher<Kms>,
    runtime: tokio::runtime::Runtime,
}

static CLIENT: OnceLock<Client> = OnceLock::new();
// Serialises the build, so two threads making their first call at once build
// one client and load the keyset once. `OnceLock::get_or_init` would do the
// same, but it cannot fail, and a failed build must not be cached: the user
// fixes the credentials and calls again.
static BUILDING: Mutex<()> = Mutex::new(());
static BUILDS: AtomicU64 = AtomicU64::new(0);
static REQUESTS: AtomicU64 = AtomicU64::new(0);
static KEYSET_LOADS: AtomicU64 = AtomicU64::new(0);

/// The shared client, built on the first call.
///
/// # Errors
///
/// The refusal of whatever failed: the credentials (`stack_auth_*`), the
/// client key or the ZeroKMS client (`stack_kms_*`), or the keyset load
/// (`stack_encrypt_*`). Nothing is cached on failure.
pub fn shared() -> Result<&'static Client, Refusal> {
    #[cfg(feature = "deterministic-kms")]
    refuse_after_switch()?;
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    let _building = BUILDING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Again under the lock: a switch can finish while this thread waits for
    // it, and the live client must then not be built.
    #[cfg(feature = "deterministic-kms")]
    refuse_after_switch()?;
    if let Some(client) = CLIENT.get() {
        return Ok(client);
    }
    let client = build()?;
    BUILDS.fetch_add(1, Ordering::Relaxed);
    Ok(CLIENT.get_or_init(|| client))
}

/// Run an operation's future on the process's client, and return its result.
///
/// `run!(|cipher| future)` names the `StackCipher` the body builds its future
/// from. The body is written once and compiled for each client: the live
/// one, and in the test build the deterministic one, which takes its place
/// after the switch. The two have different key source types, so a function
/// that returned "the current client" would still leave each operation to
/// write a branch per client.
macro_rules! run {
    (|$cipher:ident| $future:expr) => {{
        #[cfg(feature = "deterministic-kms")]
        if let Some((cipher, runtime)) = $crate::client::deterministic() {
            let $cipher = cipher;
            return runtime.block_on($future);
        }
        let client = $crate::client::shared()?;
        let $cipher = client.cipher();
        client.block_on($future)
    }};
}
pub(crate) use run;

/// The client of the `deterministic-kms` test build, with its own runtime.
#[cfg(feature = "deterministic-kms")]
pub type Deterministic = (
    StackCipher<stack_kms::DeterministicSource>,
    tokio::runtime::Runtime,
);

#[cfg(feature = "deterministic-kms")]
static DETERMINISTIC: OnceLock<Deterministic> = OnceLock::new();

/// In the test build, an operation that asks for the live client after the
/// switch has not checked for the deterministic client, and would send
/// requests to ZeroKMS from a test process. Refuse it, so a new operation
/// that skips the check fails its test instead.
#[cfg(feature = "deterministic-kms")]
fn refuse_after_switch() -> Result<(), Refusal> {
    if DETERMINISTIC.get().is_none() {
        return Ok(());
    }
    Err(Refusal {
        code: "stack_test_build".to_owned(),
        message: "this operation asked for the live client after the switch to the \
                  deterministic one; call client::deterministic() first"
            .to_owned(),
        field: None,
        reason: None,
    })
}

/// Make every later operation in the process use a client whose keys come
/// from `seed` through `DeterministicSource`, not from ZeroKMS. For the
/// `deterministic-kms` test build only: rows sealed under the same seed open
/// in any process, the Go SDK's frozen rows among them.
///
/// # Errors
///
/// A refusal when the live client is already built, when a deterministic
/// client is already in place, or when the client does not build.
#[cfg(feature = "deterministic-kms")]
pub fn use_deterministic(seed: [u8; 32]) -> Result<(), Refusal> {
    let refused = |message: String| Refusal {
        code: "stack_test_build".to_owned(),
        message,
        field: None,
        reason: None,
    };
    // The lock `shared` builds under: a live build in flight on another
    // thread finishes before this checks, so the two never both exist.
    let _building = BUILDING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if CLIENT.get().is_some() || DETERMINISTIC.get().is_some() {
        return Err(refused(
            "the process already has a client; call this before any operation".to_owned(),
        ));
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| refused(format!("the runtime could not start: {error}")))?;
    let cipher = runtime
        .block_on(
            StackCipher::builder()
                .kms(stack_kms::DeterministicSource::new(seed))
                .init(),
        )
        .map_err(|error| Refusal::of(&error))?;
    DETERMINISTIC
        .set((cipher, runtime))
        .map_err(|_| refused("a deterministic client is already in place".to_owned()))
}

/// The deterministic client, once `use_deterministic` has made one.
#[cfg(feature = "deterministic-kms")]
pub fn deterministic() -> Option<&'static Deterministic> {
    DETERMINISTIC.get()
}

/// How many times the shared client has been built in this process: 0
/// before the first operation, 1 after it. For the tests.
pub fn build_count() -> u64 {
    BUILDS.load(Ordering::Relaxed)
}

/// How many requests the shared client has sent to ZeroKMS in this process,
/// the keyset load included. For the tests.
pub fn request_count() -> u64 {
    REQUESTS.load(Ordering::Relaxed)
}

/// How many keyset loads succeeded: 1 after the first operation, however
/// many threads made it at once. A failed load is not counted. For the
/// tests.
pub fn keyset_load_count() -> u64 {
    KEYSET_LOADS.load(Ordering::Relaxed)
}

impl Client {
    /// The cipher itself.
    pub fn cipher(&self) -> &StackCipher<Kms> {
        &self.cipher
    }

    /// Run `future` to completion on the shared runtime, blocking this
    /// thread. The caller releases the GIL around this.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }
}

fn build() -> Result<Client, Refusal> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| Refusal {
            code: "stack_runtime".to_owned(),
            message: format!("the engine's runtime could not start: {error}"),
            field: None,
            reason: None,
        })?;
    let cipher = runtime.block_on(init())?;
    Ok(Client { cipher, runtime })
}

/// What `StackCipher::builder().init()` does, with the counting connection
/// in place of the plain one: the credentials from `AutoStrategy`, the
/// client key from the environment or the profile, one ZeroKMS client, and
/// the default keyset loaded.
async fn init() -> Result<StackCipher<Kms>, Refusal> {
    // First: it reads one variable and sends nothing, so a bad value is
    // refused before the credentials are read.
    let endpoint = endpoint_from_env()?;
    let credentials = AutoStrategy::detect().map_err(|error| credentials::refusal(&error))?;
    let client_key = FallbackKeyProvider::new(
        EnvKeyProvider,
        ProfileClientKey(ProfileStore::resolve(None).ok()),
    )
    .client_key()
    .await
    .map_err(|error| Refusal::of(&error))?;
    // Requests go out one at a time, as the spec states the request count:
    // ceil(values / 500) key requests "in sequence". The Go guest sets the
    // same.
    let options = ClientOpts::new(HttpConnectionOpts::new(endpoint))
        .with_max_concurrent_reqs(1)
        .map_err(|error| Refusal::of(&error))?;
    let kms =
        Kms::connect(options, credentials, client_key).map_err(|error| Refusal::of(&error))?;
    StackCipher::builder()
        .kms(kms)
        .init()
        .await
        .map_err(|error| Refusal::of(&error))
}

/// The ZeroKMS endpoint override, as `StackKmsBuilder` reads it: the first
/// of `CS_ZEROKMS_HOST` and the legacy `CS_VITUR_HOST` that is set. `None`
/// leaves the endpoint to the token's services claim, as every other SDK
/// does. `init` builds the client itself to count its requests, so it reads
/// the variable here; the builder's own reader is private.
fn endpoint_from_env() -> Result<Option<ZeroKmsEndpoint>, Refusal> {
    for env_var in stack_encrypt::kms::vars::CS_ZEROKMS_HOST {
        if let Ok(value) = std::env::var(env_var) {
            return value.parse().map(Some).map_err(|source| {
                Refusal::of(&StackKmsBuilderError::InvalidEndpoint { env_var, source })
            });
        }
    }
    Ok(None)
}

/// The CLI's profile as a key provider, where it resolves. Where it does
/// not, the error says what to do, as stack-encrypt's own provider does.
struct ProfileClientKey(Option<ProfileStore>);

impl KeyProvider for ProfileClientKey {
    async fn client_key(&self) -> Result<stack_encrypt::kms::ClientKey, KeyProviderError> {
        match &self.0 {
            Some(store) => store.client_key().await,
            None => Err(KeyProviderError::NotConfigured(
                "no client key: set CS_CLIENT_ID and CS_CLIENT_KEY, or log in with `stash auth login`"
                    .into(),
            )),
        }
    }
}

/// The HTTP connection, counting every request it sends.
pub struct Counting(HttpConnection);

impl ZeroKMSConnectionInit for Counting {
    type ConnectionOpts = HttpConnectionOpts;
    type Error = ConnectionInitError;

    fn init(opts: Self::ConnectionOpts) -> Result<Self, Self::Error> {
        HttpConnection::init(opts).map(Self)
    }
}

impl ZeroKMSConnection for Counting {
    async fn send<Request: ViturRequest>(
        &self,
        request: Request,
        access_token: &str,
    ) -> Result<Request::Response, ViturRequestError> {
        REQUESTS.fetch_add(1, Ordering::Relaxed);
        let response = self.0.send(request, access_token).await;
        // A load that fails caches nothing, and the next call loads again:
        // only a load that succeeded is the one the contract counts.
        if Request::ENDPOINT == LoadKeysetRequest::ENDPOINT && response.is_ok() {
            KEYSET_LOADS.fetch_add(1, Ordering::Relaxed);
        }
        response
    }

    // Both forwarded: the trait's defaults would tell the client the base
    // URL is set when the connection underneath has none.
    fn ensure_base_url(&self, url: ZeroKmsEndpoint) {
        self.0.ensure_base_url(url);
    }

    fn has_base_url(&self) -> bool {
        self.0.has_base_url()
    }
}
