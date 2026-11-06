//! The host imports and the types built over them: [`WasiHostConnection`]
//! (a [`ZeroKMSConnection`] whose transport is the host's HTTP client),
//! [`HostTokenStrategy`] (an [`AuthStrategy`] that asks the host for the
//! bearer token) and [`HostCredentialImport`] (the key vendor backend's
//! short-lived credentials, see [`crate::vendor`]). wasm32-only — everything
//! here calls an imported function.
//!
//! # Import contract (module `cipherstash_transport`)
//!
//! All pointers are offsets into guest linear memory; the host allocates
//! guest buffers with `se_alloc` and the guest reclaims them through the
//! shared registry (`stack_guest_abi::buffers`).
//!
//! - `transport_send(..)` — perform one HTTP request. The import and its
//!   contract are `stack_guest_abi::transport`'s, shared with every guest;
//!   this module only builds ZeroKMS requests over it.
//! - `token_get(token_out) -> status` — hand over the current bearer token
//!   (Phase-1 auth: minting and refresh stay on the host). `token_out` is a
//!   `(ptr_out, len_out)` slot pair filled with an `se_alloc`'d buffer;
//!   status `0` is success, anything else a host-side failure. This
//!   guest's own: the credential guest supplies tokens rather than asking
//!   for them.
//! - `vendor_credential_get(vendor, scope_ptr, scope_len, cred_out) ->
//!   status` — hand over one short-lived credential of the configured key
//!   vendor backend (ADR-0011). `vendor` is the `KeyVendor` byte (1 AWS,
//!   2 Google Cloud, 3 Azure, 4 Vault); `scope` (UTF-8, borrowed for the
//!   call) is the OAuth scope for Google Cloud and Azure and empty for AWS
//!   and Vault. `cred_out` is a `(ptr_out, len_out)` slot pair filled with
//!   an `se_alloc`'d buffer holding one value in the transport codec (its
//!   keys are in [`crate::vendor`]). Status `0` is success, anything else a
//!   host-side failure. Same shape as `token_get`. The host fills it from
//!   the vendor's own Go credential chain; only ready-to-use credentials
//!   cross (AWS credentials, an access token, a Vault token), never a
//!   signing key, so the guest does no RSA and reads no service account
//!   key. They are short-lived unless the Go source returns fixed ones. The import is referenced only by the
//!   vendor clients: a guest built with no vendor client would not import it.
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
//! request sends, and the key that an unwrap or generate response returns
//! (AWS `Decrypt` and `GenerateDataKey`, Google Cloud KMS and Vault
//! `decrypt`, Azure `unwrapkey`). That is a root key under derived data
//! keys, or a data key under wrapped data keys. Unlike a ZeroKMS response,
//! it is usable alone. The host wipes the request and response bodies it
//! holds once they are in guest memory, but not the buffers of net/http,
//! TLS or the RoundTripper. Keys the guest derives from it (index keys,
//! derived data keys) never cross back.
//!
//! What crosses *in* through `vendor_credential_get` is the credential the
//! host's source returns, which the guest uses to sign and then drops. It is
//! short-lived when the source is a role or token chain, and long-lived when
//! the source returns fixed keys (Go's `AWSCredentialsFromEnv` with no
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
use stack_guest_abi::transport;
use stack_kms::{BackendErrorKind, KeyVendor};
use stack_kms::{BaseUrlUnresolved, ZeroKMSConnection, ZeroKMSConnectionInit, ZeroKmsEndpoint};
use zeroize::Zeroizing;
use zerokms_protocol::{ViturRequest, ViturRequestError};

use crate::headers::request_headers;
use crate::response::map_response;
use crate::vendor::{CredentialError, CredentialImport};
use vitaminc_aead_value::transport as codec;
use vitaminc_aead_value::FfiValue;

#[link(wasm_import_module = "cipherstash_transport")]
extern "C" {
    fn token_get(token_ptr_out: *mut u32, token_len_out: *mut u32) -> i32;
    fn vendor_credential_get(
        vendor: u32,
        scope_ptr: *const u8,
        scope_len: u32,
        cred_ptr_out: *mut u32,
        cred_len_out: *mut u32,
    ) -> i32;
}

/// A [`ZeroKMSConnection`] whose transport is the `transport_send` host
/// import. The host call is synchronous from the guest's perspective, so
/// `send` resolves immediately — `block_on` in the ABI layer never parks.
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

        // The shared import reclaims both response slots before judging
        // either, and the body it hands back wipes on drop (it carries
        // wrapped key material).
        let response = transport::send("POST", url.as_str(), &headers, &body)
            .map_err(|e| ViturRequestError::parse("Host response buffer failed validation", e))?;

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

/// The `vendor_credential_get` import as a [`CredentialImport`]: the key
/// vendor backend's short-lived credential, asked of the host before each
/// vendor request.
#[derive(Clone, Copy, Debug, Default)]
pub struct HostCredentialImport;

impl CredentialImport for HostCredentialImport {
    fn credential(&self, vendor: KeyVendor, scope: &str) -> Result<FfiValue, CredentialError> {
        let failed = |message: String| CredentialError {
            kind: BackendErrorKind::Unavailable,
            message,
        };
        let mut ptr: u32 = 0;
        let mut len: u32 = 0;
        let scope_len = u32::try_from(scope.len())
            .map_err(|_| failed("the credential scope is too long".to_owned()))?;
        // SAFETY: `scope` is borrowed for the call; the out-slots are stack
        // locals the host writes once.
        let status = unsafe {
            vendor_credential_get(
                u32::from(vendor.byte()),
                scope.as_ptr(),
                scope_len,
                &mut ptr,
                &mut len,
            )
        };
        // Reclaim before judging the status, as `token_get` does: a host
        // that placed the credential and then failed must not leave it
        // registered and unwiped.
        //
        // SAFETY: the pointer comes from the host's `se_alloc` call; the
        // registry validates it before any Vec is rebuilt.
        let bytes = unsafe { buffers::take(ptr as *mut u8, len as usize) }.map(Zeroizing::new);
        if status != 0 {
            return Err(failed(format!(
                "the host's {} credential source failed with status {status}",
                vendor.name()
            )));
        }
        let bytes = bytes
            .ok_or_else(|| failed("the host credential buffer failed validation".to_owned()))?;
        // The decoded strings are `Protected` and wipe on drop; `bytes`
        // wipes through its `Zeroizing` wrapper.
        codec::decode_value(&mut codec::Reader::new(&bytes)).map_err(|_| CredentialError {
            kind: BackendErrorKind::AccessDenied,
            message: format!(
                "the host's {} credential is not a value in the transport codec",
                vendor.name()
            ),
        })
    }
}
