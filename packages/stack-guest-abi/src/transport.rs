//! The `cipherstash_transport::transport_send` host import: one HTTP
//! request performed by the host on the guest's behalf. wasm32-only —
//! everything here calls an imported function.
//!
//! # Import contract (module `cipherstash_transport`)
//!
//! All pointers are offsets into guest linear memory; the host allocates
//! guest buffers with `se_alloc` and the guest reclaims them through its
//! registry ([`crate::buffers`]).
//!
//! `transport_send(method, url, headers, body, resp_headers_out,
//! resp_body_out) -> status` — perform one HTTP request. Each of the four
//! inputs is a `(ptr, len)` pair borrowed for the duration of the call;
//! `headers` is the `name: value` line format of [`crate::headers`]. The
//! two outputs are `(ptr_out, len_out)` slot pairs the host fills with
//! `se_alloc`'d buffers (response headers, response body). The return value
//! is the HTTP status code, or negative for a transport-level failure —
//! then the body carries the host's error text and headers are empty.
//!
//! This is #2099's ZeroKMS-shaped import generalised to a plain HTTP
//! request (method + URL + headers), which is why `stack-auth`'s refreshers
//! can run over it too, and a future `wasi:http` implementation can replace
//! it without changing the callers.
//!
//! What crosses the boundary per call is what would cross TLS anyway: the
//! URL, the headers (a bearer credential among them), and the serialized
//! request. Response bodies can carry wrapped keys or tokens, so a
//! [`Response`] wipes its body on drop; the buffers the host wrote are
//! reclaimed via the registry, which the ABI's `se_dealloc` also wipes.

use vitaminc_protected::OpaqueDebug;
use zeroize::Zeroizing;

use crate::buffers;

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
}

/// The host stored an out-slot pointer the guest's buffer registry does not
/// know (or with a mismatched length) — a host-side bookkeeping bug.
#[derive(Debug, thiserror::Error)]
#[error("host returned an unregistered or mismatched buffer")]
pub struct HostBufferError;

/// What the host handed back for one request, both buffers reclaimed.
///
/// Only [`send`] builds one, and `Debug` shows the status alone: the body
/// can carry wrapped key material or a credential, and the headers are
/// treated the same way rather than audited per name.
#[derive(OpaqueDebug)]
#[non_exhaustive]
pub struct Response {
    /// The HTTP status code, or negative for a transport-level failure —
    /// then `body` is the host's error text. Kept as the import returns it:
    /// the sign convention is the wire contract with the Go host, and each
    /// guest maps it onto its own library's response type.
    #[non_sensitive]
    pub status: i32,
    /// The response headers in the [`crate::headers`] line format.
    pub headers: Vec<u8>,
    /// The response body. Wiped on drop: it can carry wrapped key material
    /// or a credential.
    pub body: Zeroizing<Vec<u8>>,
}

/// Perform one HTTP request through the host.
///
/// The host call is synchronous from the guest's perspective. The two
/// response slots are reclaimed *before* either is judged: a `?` on the
/// headers slot would otherwise strand the body buffer — a 2xx JSON body
/// full of wrapped data keys — registered, unfreed and unwiped for the life
/// of the instance. A slot the host did not fill (or filled with a pointer
/// the registry does not know) is [`HostBufferError`].
pub fn send(
    method: &str,
    url: &str,
    headers: &[u8],
    body: &[u8],
) -> Result<Response, HostBufferError> {
    let mut resp_headers_ptr: u32 = 0;
    let mut resp_headers_len: u32 = 0;
    let mut resp_body_ptr: u32 = 0;
    let mut resp_body_len: u32 = 0;

    // SAFETY: every input pair names a live guest allocation borrowed for
    // the call; the out-slots are stack locals the host writes once.
    let status = unsafe {
        transport_send(
            method.as_ptr(),
            method.len() as u32,
            url.as_ptr(),
            url.len() as u32,
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

    // SAFETY: pointers come from the host's `se_alloc` calls; the registry
    // validates them before any Vec is rebuilt.
    let resp_headers =
        unsafe { buffers::take(resp_headers_ptr as *mut u8, resp_headers_len as usize) };
    let resp_body = unsafe { buffers::take(resp_body_ptr as *mut u8, resp_body_len as usize) }
        .map(Zeroizing::new);

    let headers = resp_headers.ok_or(HostBufferError)?;
    let body = resp_body.ok_or(HostBufferError)?;
    Ok(Response {
        status,
        headers,
        body,
    })
}
