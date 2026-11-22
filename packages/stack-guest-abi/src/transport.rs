//! The `cipherstash_transport::transport_send` host import: one HTTP
//! request performed by the host on the guest's behalf. The import and
//! [`send`] are wasm32-only. Reclaiming the two buffers the host hands back
//! ([`reclaim`]) has no wasm in it, so it builds natively and runs under
//! Miri.
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

#[cfg(target_arch = "wasm32")]
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
/// The host call is synchronous from the guest's perspective. The response
/// buffers are reclaimed by [`reclaim`], which takes both before judging
/// either.
#[cfg(target_arch = "wasm32")]
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

    // SAFETY: the slots are what the host wrote: addresses of buffers it
    // obtained from `se_alloc`, or anything at all from a broken host. The
    // registry validates each before a Vec is rebuilt.
    unsafe {
        reclaim(
            status,
            (resp_headers_ptr as *mut u8, resp_headers_len as usize),
            (resp_body_ptr as *mut u8, resp_body_len as usize),
        )
    }
}

/// Reclaim the two response buffers the host filled, then judge them.
///
/// Both slots are taken back from the registry *before* either is judged:
/// a `?` on the headers slot would otherwise strand the body buffer (a 2xx
/// JSON body full of wrapped data keys) registered, unfreed and unwiped for
/// the life of the instance. A slot the host did not fill, or filled with a
/// pointer the registry does not know or a length it does not hold, is
/// [`HostBufferError`].
///
/// # Safety
///
/// As for [`buffers::take`]: each pointer should be one the registry handed
/// out. Any other pointer is refused rather than undefined behaviour,
/// unless it aliases a different live registered buffer of the same length.
pub unsafe fn reclaim(
    status: i32,
    headers: (*mut u8, usize),
    body: (*mut u8, usize),
) -> Result<Response, HostBufferError> {
    // SAFETY: the caller's contract; the registry validates each pair.
    let resp_headers = unsafe { buffers::take(headers.0, headers.1) };
    // SAFETY: as above.
    let resp_body = unsafe { buffers::take(body.0, body.1) }.map(Zeroizing::new);

    let headers = resp_headers.ok_or(HostBufferError)?;
    let body = resp_body.ok_or(HostBufferError)?;
    Ok(Response {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A buffer as the host fills one: allocated through the registry and
    /// written.
    fn host_filled(bytes: &[u8]) -> (*mut u8, usize) {
        let ptr = buffers::alloc(bytes.len());
        // SAFETY: `alloc` returned a live, registered buffer of this length.
        unsafe { std::slice::from_raw_parts_mut(ptr, bytes.len()) }.copy_from_slice(bytes);
        (ptr, bytes.len())
    }

    #[test]
    fn both_buffers_come_back_and_leave_the_registry() {
        let headers = host_filled(b"content-type: application/json\n");
        let body = host_filled(b"{}");
        // SAFETY: both were handed out by the registry.
        let response = unsafe { reclaim(200, headers, body) }.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.headers, b"content-type: application/json\n");
        assert_eq!(&response.body[..], b"{}");
        assert_eq!(buffers::live(), (0, 0));
    }

    #[test]
    fn empty_slots_are_empty_buffers() {
        // SAFETY: a null pointer with zero length is the canonical empty.
        let response =
            unsafe { reclaim(-1, (std::ptr::null_mut(), 0), (std::ptr::null_mut(), 0)) }.unwrap();
        assert!(response.headers.is_empty() && response.body.is_empty());
    }

    /// A broken headers slot does not strand the body: it is reclaimed (and
    /// wiped on drop) before the error is returned.
    #[test]
    fn an_unknown_headers_slot_still_reclaims_the_body() {
        let body = host_filled(b"wrapped key material");
        let stray = std::ptr::without_provenance_mut::<u8>(0x40);
        // SAFETY: `stray` is not registered, so it is refused, not read.
        let result = unsafe { reclaim(200, (stray, 4), body) };
        assert!(result.is_err());
        assert_eq!(buffers::live(), (0, 0));
    }

    /// A length the registry does not hold is refused, and the buffer stays
    /// registered for the host's `se_dealloc`, as the registry does.
    #[test]
    fn a_mismatched_length_is_refused_and_left_registered() {
        let headers = host_filled(b"x: y\n");
        let body = host_filled(b"body");
        // SAFETY: both were handed out by the registry.
        let result = unsafe { reclaim(200, headers, (body.0, body.1 + 1)) };
        assert!(result.is_err());
        assert_eq!(buffers::live(), (1, 0));
        // SAFETY: the registered pointer and its true length.
        unsafe { buffers::dealloc(body.0, body.1) };
        assert_eq!(buffers::live(), (0, 0));
    }

    /// Reclaiming the same slot twice yields it once.
    #[test]
    fn a_slot_is_reclaimed_once() {
        let headers = host_filled(b"a: b\n");
        let body = host_filled(b"c");
        // SAFETY: both were handed out by the registry.
        let first = unsafe { reclaim(200, headers, body) };
        assert!(first.is_ok());
        // SAFETY: both are now unknown to the registry, so refused.
        let second = unsafe { reclaim(200, headers, body) };
        assert!(second.is_err());
    }
}
