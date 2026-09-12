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

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use zeroize::Zeroize;

thread_local! {
    static BUFFERS: RefCell<HashMap<usize, usize>> = RefCell::new(HashMap::new());
    /// Live zero-length buffers, counted rather than keyed: every empty
    /// `Vec` leaks to the *same* dangling pointer (alignment, so `0x1`), and
    /// a pointer-keyed map entry would be overwritten by the second empty
    /// allocation — the first reclaim would then remove the only entry and
    /// the second would fail validation. A host holding an empty response
    /// header buffer and an empty body buffer at once is contract-compliant,
    /// so empties get identity-free accounting.
    static EMPTY_BUFFERS: Cell<usize> = const { Cell::new(0) };
}

/// The pointer every zero-length buffer presents to the host: non-null (null
/// still unambiguously means "allocation failed") and identical for all of
/// them, which is exactly what `Box<[u8]>` produces for an empty slice.
fn empty_ptr() -> *mut u8 {
    std::ptr::NonNull::<u8>::dangling().as_ptr()
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
    if buf.is_empty() {
        // See `EMPTY_BUFFERS`: empties share one pointer, so they are
        // counted, not keyed. Nothing leaks — an empty `Vec` owns no heap.
        EMPTY_BUFFERS.with(|c| c.set(c.get() + 1));
        return empty_ptr();
    }
    let boxed = buf.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    // A fresh allocation can't already be registered; the returned previous
    // entry is the invariant, checked in debug builds.
    let previous = BUFFERS.with(|b| b.borrow_mut().insert(ptr as usize, len));
    debug_assert!(previous.is_none());
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

/// Wipe and free every buffer the registry still holds — what `se_shutdown`
/// does after dropping the cipher, so a host that tears the instance down
/// without releasing an output first still leaves no plaintext behind.
/// Empties carry no bytes; their count is simply reset.
pub(crate) fn wipe_all() {
    let live: Vec<(usize, usize)> = BUFFERS.with(|b| b.borrow_mut().drain().collect());
    for (ptr, len) in live {
        // SAFETY: every entry was registered by `register`, which leaked a
        // boxed slice of exactly `len` bytes at `ptr`, and it was removed
        // above so nothing else can reclaim it.
        let mut buf = unsafe { Vec::from_raw_parts(ptr as *mut u8, len, len) };
        buf.zeroize();
    }
    EMPTY_BUFFERS.with(|c| c.set(0));
}

unsafe fn reclaim(ptr: *mut u8, len: usize) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    if len == 0 && ptr == empty_ptr() {
        // An empty reclaim spends one unit of the empty count; over-reclaim
        // (a double-free of an empty) fails validation like any other
        // unknown pointer. A *real* buffer can never live at the dangling
        // address, and a zero `len` can only ever refer to an empty, so the
        // two accounting schemes cannot cross.
        return EMPTY_BUFFERS.with(|c| {
            let live = c.get();
            (live > 0).then(|| {
                c.set(live - 1);
                Vec::new()
            })
        });
    }
    let real_len = BUFFERS.with(|b| b.borrow_mut().remove(&(ptr as usize)))?;
    if real_len != len {
        // Put the entry back exactly as it was; it was just removed, so
        // nothing can be there to displace.
        let previous = BUFFERS.with(|b| b.borrow_mut().insert(ptr as usize, real_len));
        debug_assert!(previous.is_none());
        return None;
    }
    // SAFETY: the registry guarantees `(ptr, real_len)` is exactly one live
    // allocation this module handed out via `register` (len == capacity by
    // `into_boxed_slice`), and the entry has just been removed so it cannot
    // be reclaimed twice.
    Some(unsafe { Vec::from_raw_parts(ptr, real_len, real_len) })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each libtest thread gets its own thread-locals, so tests are isolated.

    #[test]
    fn two_live_empty_buffers_reclaim_independently() {
        // The regression this pins: both empties present the same dangling
        // pointer, and keyed accounting would let the second registration
        // clobber the first — making one of these `take`s fail.
        let a = alloc(0);
        let b = alloc(0);
        assert!(!a.is_null() && !b.is_null());
        assert_eq!(unsafe { take(a, 0) }, Some(Vec::new()));
        assert_eq!(unsafe { take(b, 0) }, Some(Vec::new()));
        // Both spent: a third reclaim is a double-free and must fail.
        assert_eq!(unsafe { take(b, 0) }, None);
    }

    #[test]
    fn empty_and_sized_buffers_do_not_cross_accounts() {
        let empty = alloc(0);
        let sized = alloc(3);
        // A zero-length reclaim of the sized pointer is a length mismatch,
        // not a withdrawal from the empty count.
        assert_eq!(unsafe { take(sized, 0) }, None);
        assert_eq!(unsafe { take(empty, 0) }, Some(Vec::new()));
        assert_eq!(unsafe { take(sized, 3) }, Some(vec![0, 0, 0]));
    }

    /// Shutdown's invariant: after `wipe_all`, nothing the registry handed
    /// out is live — sized or empty — so a host that forgot to release an
    /// output cannot reclaim it, and the bytes were zeroized on the way
    /// out.
    #[test]
    fn wipe_all_leaves_no_live_buffer() {
        let sized = register(vec![7, 7, 7]);
        let host_written = alloc(2);
        let empty = alloc(0);

        wipe_all();

        assert_eq!(unsafe { take(sized, 3) }, None);
        assert_eq!(unsafe { take(host_written, 2) }, None);
        assert_eq!(unsafe { take(empty, 0) }, None);
        // The registry is usable afterwards: a fresh allocation is tracked
        // as before.
        let again = alloc(1);
        assert_eq!(unsafe { take(again, 1) }, Some(vec![0]));
    }

    #[test]
    fn a_null_pointer_with_zero_length_is_the_canonical_empty() {
        assert_eq!(unsafe { take(core::ptr::null_mut(), 0) }, Some(Vec::new()));
    }

    #[test]
    fn dealloc_of_an_empty_buffer_is_balanced() {
        let a = alloc(0);
        unsafe { dealloc(a, 0) };
        // The dealloc spent the only live empty; a take now finds none.
        assert_eq!(unsafe { take(a, 0) }, None);
    }
}
