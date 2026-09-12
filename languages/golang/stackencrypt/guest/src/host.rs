//! The host imports and the types built over them: [`WasiHostConnection`]
//! (a [`ZeroKMSConnection`] whose transport is the host's HTTP client) and
//! [`HostTokenStrategy`] (an [`AuthStrategy`] that asks the host for the
//! bearer token). wasm32-only — everything here calls an imported function.
//!
//! # Import contract (module `cipherstash_transport`)
//!
//! All pointers are offsets into guest linear memory; the host allocates
//! guest buffers with `se_alloc` and the guest reclaims them through its
//! registry (`crate::buffers`).
//!
//! - `transport_send(method, url, headers, body, resp_headers_out,
//!   resp_body_out) -> status` — perform one HTTP request. Each of the four
//!   inputs is a `(ptr, len)` pair borrowed for the duration of the call;
//!   `headers` is the `name: value` line format of [`crate::headers`]. The
//!   two outputs are `(ptr_out, len_out)` slot pairs the host fills with
//!   `se_alloc`'d buffers (response headers, response body). The return
//!   value is the HTTP status code, or negative for a transport-level
//!   failure — then the body carries the host's error text and headers are
//!   empty. This is #2099's ZeroKMS-shaped import generalised to a plain
//!   HTTP request (method + URL + headers), so `stack-auth`'s refreshers
//!   can reuse it later and a future `wasi:http` implementation can replace
//!   it without changing the connection seam.
//! - `token_get(token_out) -> status` — hand over the current bearer token
//!   (Phase-1 auth: minting and refresh stay on the host). `token_out` is a
//!   `(ptr_out, len_out)` slot pair filled the same way; status `0` is
//!   success, anything else a host-side failure.
//!
//! What crosses the boundary per ZeroKMS call is exactly what would cross
//! TLS anyway: the URL, the bearer token, and the serialized protocol
//! bytes. Key material derived from a response never crosses back — the
//! derivation runs inside the guest ([`stack_kms`]'s client, unmodified).
//!
//! Request bodies and response bodies can carry key-material contexts and
//! wrapped keys, so both are wiped on drop here; the buffers the host wrote
//! are reclaimed via the registry (which the ABI's `se_dealloc` also wipes).

use std::convert::Infallible;
use std::fmt;
use std::sync::Mutex;

use stack_auth::{AuthError, AuthStrategy, CustomError, SecretToken, ServiceToken};
use stack_kms::{BaseUrlUnresolved, ZeroKMSConnection, ZeroKMSConnectionInit, ZeroKmsEndpoint};
use zeroize::Zeroizing;
use zerokms_protocol::{ViturRequest, ViturRequestError};

use crate::buffers;
use crate::headers::{encode_headers, header_value};
use crate::response::map_response;

#[link(wasm_import_module = "cipherstash_transport")]
extern "C" {
    fn transport_send(
        method_ptr: *const u8,
        method_len: u32,
        url_ptr: *const u8,
        url_len: u32,
        headers_ptr: *const u8,
        headers_len: u32,
        body_ptr: *const u8,
        body_len: u32,
        resp_headers_ptr_out: *mut u32,
        resp_headers_len_out: *mut u32,
        resp_body_ptr_out: *mut u32,
        resp_body_len_out: *mut u32,
    ) -> i32;

    fn token_get(token_ptr_out: *mut u32, token_len_out: *mut u32) -> i32;
}

/// The host stored an out-slot pointer the guest's buffer registry does not
/// know (or with a mismatched length) — a host-side bookkeeping bug.
#[derive(Debug)]
struct HostBufferError;

impl fmt::Display for HostBufferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "host returned an unregistered or mismatched buffer")
    }
}

impl std::error::Error for HostBufferError {}

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
        let headers = Zeroizing::new(encode_headers(&[
            ("authorization", auth.as_str()),
            ("content-type", "application/json"),
        ]));

        let method = b"POST";
        let mut resp_headers_ptr: u32 = 0;
        let mut resp_headers_len: u32 = 0;
        let mut resp_body_ptr: u32 = 0;
        let mut resp_body_len: u32 = 0;

        // SAFETY: every input pair names a live guest allocation borrowed
        // for the call; the out-slots are stack locals the host writes once.
        let status = unsafe {
            transport_send(
                method.as_ptr(),
                method.len() as u32,
                url.as_str().as_ptr(),
                url.as_str().len() as u32,
                headers.as_ptr(),
                headers.len() as u32,
                body.as_ptr(),
                body.len() as u32,
                &mut resp_headers_ptr,
                &mut resp_headers_len,
                &mut resp_body_ptr,
                &mut resp_body_len,
            )
        };

        // Reclaim *both* slots before judging either. A `?` on the headers
        // slot would otherwise strand the body buffer — a 2xx JSON body full
        // of wrapped data keys — registered, unfreed and unwiped for the life
        // of the instance.
        //
        // SAFETY: pointers come from the host's `se_alloc` calls; the
        // registry validates them before any Vec is rebuilt.
        let resp_headers =
            unsafe { buffers::take(resp_headers_ptr as *mut u8, resp_headers_len as usize) };
        // Response bodies carry wrapped key material — wipe on drop.
        let resp_body = unsafe { buffers::take(resp_body_ptr as *mut u8, resp_body_len as usize) }
            .map(Zeroizing::new);

        let unregistered =
            || ViturRequestError::parse("Host response buffer failed validation", HostBufferError);
        let resp_headers = resp_headers.ok_or_else(unregistered)?;
        let resp_body = resp_body.ok_or_else(unregistered)?;

        let content_type = header_value(&resp_headers, "content-type");
        map_response(status, content_type, &resp_body)
    }
}

/// An [`AuthStrategy`] that fetches the bearer token from the host on every
/// request via `token_get`. Refresh policy stays host-side (Phase-1 auth):
/// whatever token the host hands over is presented as-is, so the host can
/// rotate tokens without re-initialising the cipher handle.
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
