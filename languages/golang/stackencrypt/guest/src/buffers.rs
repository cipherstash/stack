//! The guest-owned buffer registry behind `se_alloc` / `se_dealloc`,
//! following the vitaminc guest's conventions (see `vcencrypt/guest/src/
//! abi.rs`; sharing one implementation from a common vitaminc crate is a
//! planned follow-up in that repository):
//!
//! - Every buffer the guest hands out — from [`alloc`] and from packed
//!   results — is recorded here keyed by start address, holding the true
//!   length. [`dealloc`] consults the registry instead of trusting the
//!   host: an unknown pointer (including a double-free) is a no-op, a
//!   length mismatch refuses to free, and the zeroizing wipe always covers
//!   the true allocation.
//! - [`take`] is the extra move this guest needs beyond vitaminc's: the
//!   host *returns* buffers to the guest (the transport response, the
//!   token) by writing into `se_alloc`'d memory and handing back the
//!   pointer; `take` reclaims ownership under the same registry discipline.
//!
//! Wasm is single-threaded, so a thread-local `RefCell` is a plain owner of
//! the map — no `Send`/`Sync` bounds required.

use std::cell::RefCell;
use std::collections::HashMap;

use zeroize::Zeroize;

thread_local! {
    static BUFFERS: RefCell<HashMap<usize, usize>> = RefCell::new(HashMap::new());
}

/// Allocate `len` bytes of guest memory for the host to write into.
/// Returns a pointer valid until reclaimed by [`dealloc`] or [`take`], or
/// null if the allocation fails. The null branch is real: allocation goes
/// through `try_reserve_exact`, not the aborting global-allocator error
/// path, so an oversized request is a recoverable host-side error instead
/// of a trap that poisons the instance.
pub(crate) fn alloc(len: usize) -> *mut u8 {
    let mut buf: Vec<u8> = Vec::new();
    if buf.try_reserve_exact(len).is_err() {
        return core::ptr::null_mut();
    }
    buf.resize(len, 0);
    register(buf)
}

/// Register a buffer and leak it to a raw pointer for the host. The
/// registry entry is what makes the matching [`dealloc`] / [`take`] sound.
pub(crate) fn register(buf: Vec<u8>) -> *mut u8 {
    let boxed = buf.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    BUFFERS.with(|b| b.borrow_mut().insert(ptr as usize, len));
    ptr
}

/// Zeroize and free a buffer previously handed out. The registry supplies
/// the true length; `len` is cross-checked but never trusted. An unknown
/// pointer (including a double-free) is a no-op; a length mismatch means
/// the host's bookkeeping has desynced from ours, so the buffer is kept
/// live and registered rather than freed out from under a confused host.
///
/// # Safety
///
/// `ptr` should be a pointer this module handed out. The registry makes any
/// other pointer (or a stale one) a no-op rather than undefined behaviour,
/// but a pointer that happens to alias a *different* live registered buffer
/// of the same length would free that buffer.
pub(crate) unsafe fn dealloc(ptr: *mut u8, len: usize) {
    if let Some(mut buf) = unsafe { reclaim(ptr, len) } {
        buf.zeroize();
    }
}

/// Take ownership of a buffer the host filled via [`alloc`] and handed back
/// (a transport response, a token). Same registry discipline as
/// [`dealloc`]; returns `None` for an unknown pointer or a length mismatch.
/// A null pointer with zero length is an empty buffer.
///
/// # Safety
///
/// As for [`dealloc`].
pub(crate) unsafe fn take(ptr: *mut u8, len: usize) -> Option<Vec<u8>> {
    if ptr.is_null() && len == 0 {
        return Some(Vec::new());
    }
    unsafe { reclaim(ptr, len) }
}

unsafe fn reclaim(ptr: *mut u8, len: usize) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    let real_len = BUFFERS.with(|b| b.borrow_mut().remove(&(ptr as usize)))?;
    if real_len != len {
        BUFFERS.with(|b| b.borrow_mut().insert(ptr as usize, real_len));
        return None;
    }
    // SAFETY: the registry guarantees `(ptr, real_len)` is exactly one live
    // allocation this module handed out via `register` (len == capacity by
    // `into_boxed_slice`), and the entry has just been removed so it cannot
    // be reclaimed twice.
    Some(unsafe { Vec::from_raw_parts(ptr, real_len, real_len) })
}
