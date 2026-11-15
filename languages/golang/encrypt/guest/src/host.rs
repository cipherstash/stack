//! The guest's connections to its host: [`WasiHostConnection`] (a
//! [`ZeroKMSConnection`] whose requests the host performs, through the step
//! loop), [`HostTokenStrategy`] (an [`AuthStrategy`] that asks the host for
//! the bearer token) and [`StepCredentialImport`] (a key vendor backend's
//! short-lived credentials, asked for through the step loop, see
//! [`crate::vendor`]). wasm32-only — the token is an imported function, and
//! a step's future is not `Send`.
//!
//! # Requests
//!
//! The guest never waits on the network. A ZeroKMS request is recorded for
//! the step being run (`stack_guest_abi::step::request`) and the export
//! returns to the host with it, paused; the host performs it and resumes the
//! operation with the response ([`crate::io`] has the wire form). So a host
//! whose HTTP client cannot block — `fetch` on the edge — can run the guest,
//! and the guest is never running while a request is in flight. A key
//! vendor backend's requests, its credentials and its backoff waits pause
//! the operation the same way (`stack_guest_abi::vendor_transport`,
//! [`StepCredentialImport`]).
//!
//! # Import contract (module `cipherstash_transport`)
//!
//! All pointers are offsets into guest linear memory; the host allocates
//! guest buffers with `se_alloc` and the guest reclaims them through the
//! shared registry (`stack_guest_abi::buffers`).
//!
//! - `token_get(token_out) -> status` — hand over the current bearer token
//!   (Phase-1 auth: minting and refresh stay on the host, which holds a
//!   fresh token before each step, so this never waits). `token_out` is a
//!   `(ptr_out, len_out)` slot pair filled with an `se_alloc`'d buffer;
//!   status `0` is success, anything else a host-side failure. This
//!   guest's own: the credential guest supplies tokens rather than asking
//!   for them.
//!
//! What crosses the boundary per ZeroKMS call is exactly what would cross
//! TLS anyway: the URL, the bearer token, and the serialized protocol
//! bytes. Key material derived from a response never crosses back — the
//! derivation runs inside the guest ([`stack_kms`]'s client, unmodified).
//!
//! A key vendor backend does **not** keep that property. A vendor request
//! crosses as the signed HTTP request the vendor would receive over TLS,
//! and the host does the TLS. So the host, and any RoundTripper the Go
//! caller gives it, see the vendor traffic in plaintext: the key a wrap
//! request sends, and the key that an unwrap response returns (AWS
//! `Decrypt`, Google Cloud KMS and Vault `decrypt`, Azure `unwrapkey`).
//! That is a keyset's root key. Unlike a ZeroKMS response,
//! it is usable alone. The host wipes the request and response bodies it
//! holds once they are in guest memory, but not the buffers of net/http,
//! TLS or the RoundTripper. Keys the guest derives from it (index keys,
//! derived data keys) never cross back.
//!
//! What crosses *in* for a credential step is the credential the host's
//! source returns, which the guest uses to sign and then drops. It is
//! short-lived when the source is a role or token chain, and long-lived
//! when the source returns fixed keys (Go's `AWSCredentialsFromEnv` with no
//! session token, a fixed Vault token). A `StaticKey` backend's key crosses
//! once, in the guest config.
//!
//! Request bodies and response bodies can carry key-material contexts and
//! wrapped keys, so both are wiped on drop here; the buffers the host wrote
//! are reclaimed via the registry (which the ABI's `se_dealloc` also wipes).

use std::convert::Infallible;
use std::sync::Mutex;

use stack_auth::{AuthError, AuthStrategy, CustomError, SecretToken, ServiceToken};
use stack_guest_abi::buffers;
use stack_guest_abi::headers::header_value;
use stack_guest_abi::step;
use stack_kms::{BackendErrorKind, KeyVendor};
use stack_kms::{BaseUrlUnresolved, ZeroKMSConnection, ZeroKMSConnectionInit, ZeroKmsEndpoint};
use zeroize::Zeroizing;
use zerokms_protocol::{ViturRequest, ViturRequestError};

use crate::headers::request_headers;
use crate::response::map_response;
use crate::vendor::{CredentialError, CredentialImport};

#[link(wasm_import_module = "cipherstash_transport")]
extern "C" {
    fn token_get(token_ptr_out: *mut u32, token_len_out: *mut u32) -> i32;
}

/// A [`ZeroKMSConnection`] whose requests the host performs: `send` records
/// its request for the step being run and resolves when the host resumes the
/// operation with the response (see the [module docs](self)).
///
/// The endpoint is pinned at init when the cipher config named one;
/// otherwise it is discovered by `StackKms` from the access token's
/// `services` claim through [`ensure_base_url`](Self::ensure_base_url) —
/// the first value wins, per the trait's contract.
pub struct WasiHostConnection {
    base: Mutex<Option<ZeroKmsEndpoint>>,
}

impl WasiHostConnection {
    fn base(&self) -> std::sync::MutexGuard<'_, Option<ZeroKmsEndpoint>> {
        // Wasm is single-threaded: a poisoned lock can only mean a previous
        // panic already aborted the instance, so this is unreachable —
        // recover rather than add a second panic path.
        self.base
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl ZeroKMSConnectionInit for WasiHostConnection {
    type ConnectionOpts = Option<ZeroKmsEndpoint>;
    type Error = Infallible;

    fn init(opts: Self::ConnectionOpts) -> Result<Self, Infallible> {
        Ok(Self {
            base: Mutex::new(opts),
        })
    }
}

impl ZeroKMSConnection for WasiHostConnection {
    fn ensure_base_url(&self, url: ZeroKmsEndpoint) {
        let mut base = self.base();
        if base.is_none() {
            *base = Some(url);
        }
    }

    fn has_base_url(&self) -> bool {
        self.base().is_some()
    }

    async fn send<Request: ViturRequest>(
        &self,
        request: Request,
        access_token: &str,
    ) -> Result<Request::Response, ViturRequestError> {
        // Defence in depth, shared verbatim with `HttpConnection`:
        // `StackKms::get_token` resolves the endpoint (or fails with
        // `AuthError::InvalidToken`, which the status layer reports as
        // `STATUS_KMS_TRANSPORT`) before any caller reaches here, so on the
        // client's own paths this is unreachable. `send` is public trait API
        // though, and a *prepare* error is the answer that keeps a direct
        // caller from mistaking a missing endpoint for a 401 and refreshing
        // in a loop.
        let url = self
            .base()
            .as_ref()
            .map(|base| base.request_url(Request::ENDPOINT))
            .ok_or_else(|| {
                ViturRequestError::prepare(
                    "ZeroKMS base URL was not resolved from the token's services claim",
                    BaseUrlUnresolved,
                )
            })?;

        // Request bodies can reference key-material contexts; wipe on drop.
        let body = Zeroizing::new(
            serde_json::to_vec(&request)
                .map_err(|e| ViturRequestError::prepare("Failed to serialize request", e))?,
        );
        // The bearer token is a credential; wipe the header buffer on drop.
        let auth = Zeroizing::new(format!("Bearer {access_token}"));
        let headers = Zeroizing::new(request_headers(auth.as_str()));

        // The request's headers and body wipe on drop, and so does the
        // response's body: it carries wrapped key material.
        let request = step::Request::new("POST", url.to_string(), headers, body);
        let response = step::request(request)
            .await
            .map_err(|e| ViturRequestError::prepare("The host was not asked for the request", e))?;

        let content_type = header_value(&response.headers, "content-type");
        map_response(response.status, content_type, &response.body)
    }
}

/// An [`AuthStrategy`] that fetches the bearer token from the host on every
/// request via `token_get`. Refresh policy stays host-side (Phase-1 auth):
/// whatever token the host hands over is presented as-is, so the host can
/// rotate tokens without re-initialising the cipher.
pub struct HostTokenStrategy;

impl AuthStrategy for &HostTokenStrategy {
    async fn get_token(self) -> Result<ServiceToken, AuthError> {
        let mut token_ptr: u32 = 0;
        let mut token_len: u32 = 0;
        // SAFETY: the out-slots are stack locals the host writes once.
        let status = unsafe { token_get(&mut token_ptr, &mut token_len) };
        // Reclaim before judging the status: a host that allocated the token
        // buffer *and then* reported a failure would otherwise leave a live
        // credential registered, unfreed and unwiped.
        //
        // SAFETY: the pointer comes from the host's `se_alloc` call; the
        // registry validates it before any Vec is rebuilt.
        let bytes =
            unsafe { buffers::take(token_ptr as *mut u8, token_len as usize) }.map(Zeroizing::new);
        if status != 0 {
            return Err(AuthError::Custom(CustomError(format!(
                "host token_get failed with status {status}"
            ))));
        }
        let bytes = bytes.ok_or_else(|| {
            AuthError::Custom(CustomError(
                "host token buffer failed validation".to_string(),
            ))
        })?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| AuthError::Custom(CustomError("host token is not UTF-8".to_string())))?
            // A host that read the token from a file or a subprocess hands it
            // over with the trailing newline still attached; left in place it
            // would break the `name: value\n` header buffer in `send`, and no
            // bearer token has meaningful surrounding whitespace anyway.
            .trim();
        if text.is_empty() {
            return Err(AuthError::Custom(CustomError(
                "host token is empty".to_string(),
            )));
        }
        // Trim handles the *surrounding* whitespace case above; an *interior*
        // control character would survive it and land in the `name: value\n`
        // header buffer, where a newline splits the authorization line in
        // two — header injection into the host transport (or a silently
        // truncated credential and a confusing 401). No bearer token contains
        // control characters, so reject rather than sanitise.
        if text.chars().any(char::is_control) {
            return Err(AuthError::Custom(CustomError(
                "host token contains control characters".to_string(),
            )));
        }
        // `SecretToken` wipes on drop; `bytes` (the only other copy) wipes
        // via its `Zeroizing` wrapper above.
        Ok(ServiceToken::new(SecretToken::new(text)))
    }
}

/// A key vendor backend's [`CredentialImport`] through the step loop: the
/// operation pauses with a credential request for the vendor and scope, and
/// the host answers it from its credential source between steps, outside
/// the client's lock, where a source may wait on the network. The guest asks
/// before each vendor request and keeps nothing, so the host decides when a
/// credential is refreshed.
pub struct StepCredentialImport;

impl CredentialImport for StepCredentialImport {
    async fn credential(
        &self,
        vendor: KeyVendor,
        scope: &str,
    ) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
        let failed = |message: String| CredentialError {
            kind: BackendErrorKind::Unavailable,
            message,
        };
        let response = step::request(step::Request::credential(vendor.byte(), scope))
            .await
            .map_err(|e| failed(e.to_string()))?;
        if response.status != 0 {
            // The body is the host's error text: the credential source's
            // reason, never a credential.
            return Err(failed(format!(
                "the host has no {} credential: {}",
                vendor.name(),
                String::from_utf8_lossy(&response.body)
            )));
        }
        Ok(response.body)
    }
}
