//! The guest-owned buffer registry behind `se_alloc` / `se_dealloc`,
//! following the vitaminc guest's conventions (see `vcencrypt/guest/src/
//! abi.rs`). Shared by every guest under `bindings/go`, so the registry
//! discipline is written once:
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
//! the map — no `Send`/`Sync` bounds required. That premise is the one
//! thing in this crate a native cdylib backend (CIP-3997's original scope,
//! deferred) could not keep: a library called from several host threads
//! would register on one thread and release on another, and a release the
//! registry does not know is a silent no-op that never wipes. The backend
//! replaces this owner with a `Mutex`-guarded table; the entry points and
//! their discipline stay as they are.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

use zeroize::Zeroize;

thread_local! {
    /// Live sized buffers, keyed by the pointer itself (hashed and compared
    /// by address) rather than by `ptr as usize`: the value handed back to
    /// `Vec::from_raw_parts` must be the pointer that came out of
    /// `Box::into_raw`, provenance intact. Rebuilding it from an integer is
    /// an exposed-provenance round trip that strict-provenance Miri
    /// (`miri:stack-guest-abi`) rejects, and it would hide a stale entry
    /// behind a pointer Miri could no longer check.
    static BUFFERS: RefCell<HashMap<*mut u8, usize>> = RefCell::new(HashMap::new());
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
pub fn alloc(len: usize) -> *mut u8 {
    let mut buf: Vec<u8> = Vec::new();
    if buf.try_reserve_exact(len).is_err() {
        return core::ptr::null_mut();
    }
    buf.resize(len, 0);
    register(buf)
}

/// Register a buffer and leak it to a raw pointer for the host. The
/// registry entry is what makes the matching [`dealloc`] / [`take`] sound.
pub fn register(buf: Vec<u8>) -> *mut u8 {
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
    let previous = BUFFERS.with(|b| b.borrow_mut().insert(ptr, len));
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
pub unsafe fn dealloc(ptr: *mut u8, len: usize) {
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
pub unsafe fn take(ptr: *mut u8, len: usize) -> Option<Vec<u8>> {
    if ptr.is_null() && len == 0 {
        return Some(Vec::new());
    }
    unsafe { reclaim(ptr, len) }
}

/// Wipe and free every buffer the registry still holds — what a guest's
/// shutdown export does after dropping its state, so a host that tears the
/// instance down without releasing an output first still leaves no
/// plaintext behind.
/// Empties carry no bytes; their count is simply reset.
///
/// This path allocates nothing: the registry is moved out whole (an empty
/// `HashMap` does not allocate) and walked in place, so a shutdown under
/// linear-memory pressure cannot fail before the wipe on an allocation the
/// wipe itself made.
pub fn wipe_all() {
    let live = BUFFERS.with(|b| core::mem::take(&mut *b.borrow_mut()));
    for (ptr, len) in live {
        // SAFETY: every entry was registered by `register`, which leaked a
        // boxed slice of exactly `len` bytes at `ptr`, and it was removed
        // above so nothing else can reclaim it.
        let mut buf = unsafe { Vec::from_raw_parts(ptr, len, len) };
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
    // The entry's own key is what the buffer is rebuilt from, not the host's
    // copy of the address: the key is the pointer `register` leaked, so it is
    // the one with provenance over the allocation. The host's `ptr` only
    // selects the entry (pointers hash and compare by address).
    let (ptr, real_len) = BUFFERS.with(|b| b.borrow_mut().remove_entry(&ptr))?;
    if real_len != len {
        // Put the entry back exactly as it was; it was just removed, so
        // nothing can be there to displace.
        let previous = BUFFERS.with(|b| b.borrow_mut().insert(ptr, real_len));
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

/// The registry against a model of what the host holds, over random
/// interleavings of every entry point. The unit tests above each pin one
/// rule; this is where the rules are checked together — a length mismatch
/// that leaves the buffer live, a double reclaim that fails, an empty
/// count that cannot be spent on a sized pointer, a wipe that leaves
/// nothing reclaimable — on sequences no one wrote by hand. Under Miri
/// (`miri:stack-guest-abi`) every `from_raw_parts` round trip in those
/// sequences is checked for undefined behaviour as well.
#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;

    /// One host action. `which` selects among the live buffers by modulus,
    /// so a shrunk sequence stays meaningful; `len_delta` is the host's
    /// error in the length it reports.
    #[derive(Debug, Clone)]
    enum Op {
        /// `se_alloc`, then the host writes a pattern into the buffer.
        Alloc(usize),
        /// A guest output packed for the host.
        Register(Vec<u8>),
        Take {
            which: usize,
            len_delta: i8,
        },
        Dealloc {
            which: usize,
            len_delta: i8,
        },
        /// A reclaim of memory the registry never handed out.
        TakeForeign(usize),
        WipeAll,
    }

    fn op() -> impl Strategy<Value = Op> {
        prop_oneof![
            (0usize..=48).prop_map(Op::Alloc),
            proptest::collection::vec(any::<u8>(), 0..48).prop_map(Op::Register),
            (any::<usize>(), -2i8..=2).prop_map(|(which, len_delta)| Op::Take { which, len_delta }),
            (any::<usize>(), -2i8..=2)
                .prop_map(|(which, len_delta)| Op::Dealloc { which, len_delta }),
            (0usize..=8).prop_map(Op::TakeForeign),
            Just(Op::WipeAll),
        ]
    }

    /// What the host holds: a pointer it was handed, the length it was
    /// told, and the bytes it expects back. Empties all share one pointer
    /// and appear once per live empty, which is the count the registry
    /// keeps.
    #[derive(Debug)]
    struct Held {
        ptr: *mut u8,
        len: usize,
        contents: Vec<u8>,
    }

    /// The length the host reports: its true length plus its error, never
    /// negative.
    fn reported(len: usize, delta: i8) -> usize {
        len.saturating_add_signed(delta as isize)
    }

    /// Nothing the host holds is reclaimable: every pointer, at its true
    /// length, is refused. Called only right after the buffers were
    /// released, before any allocation could reuse an address.
    fn assert_none_reclaimable(held: &[Held]) -> Result<(), TestCaseError> {
        for h in held {
            prop_assert_eq!(unsafe { take(h.ptr, h.len) }, None);
        }
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            // Miri runs each case a few hundred times slower; the shape of
            // the sequences matters more than their number there.
            cases: if cfg!(miri) { 24 } else { 256 },
            // No regression file: the test runs under Miri's isolation.
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn the_registry_matches_the_model(ops in proptest::collection::vec(op(), 1..40)) {
            let mut held: Vec<Held> = Vec::new();

            for op in ops {
                match op {
                    Op::Alloc(len) => {
                        let ptr = alloc(len);
                        prop_assert!(!ptr.is_null());
                        let contents: Vec<u8> =
                            (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
                        if len == 0 {
                            prop_assert_eq!(ptr, empty_ptr());
                        } else {
                            // A fresh sized buffer never aliases a live one.
                            prop_assert!(held.iter().all(|h| h.ptr != ptr));
                            // The host writes its input.
                            unsafe { std::slice::from_raw_parts_mut(ptr, len) }
                                .copy_from_slice(&contents);
                        }
                        held.push(Held { ptr, len, contents });
                    }
                    Op::Register(bytes) => {
                        let len = bytes.len();
                        let ptr = register(bytes.clone());
                        prop_assert!(!ptr.is_null());
                        if len == 0 {
                            prop_assert_eq!(ptr, empty_ptr());
                        } else {
                            prop_assert!(held.iter().all(|h| h.ptr != ptr));
                        }
                        held.push(Held { ptr, len, contents: bytes });
                    }
                    Op::Take { which, len_delta } => {
                        if held.is_empty() {
                            // With nothing live, the shared empty pointer is
                            // as unknown as any other.
                            prop_assert_eq!(unsafe { take(empty_ptr(), 0) }, None);
                            continue;
                        }
                        let i = which % held.len();
                        let len = reported(held[i].len, len_delta);
                        let got = unsafe { take(held[i].ptr, len) };
                        if len == held[i].len {
                            let h = held.swap_remove(i);
                            prop_assert_eq!(got, Some(h.contents));
                        } else {
                            // Refused, and still live: the true length
                            // reclaims it next.
                            prop_assert_eq!(got, None);
                        }
                    }
                    Op::Dealloc { which, len_delta } => {
                        if held.is_empty() {
                            unsafe { dealloc(empty_ptr(), 0) };
                            prop_assert_eq!(unsafe { take(empty_ptr(), 0) }, None);
                            continue;
                        }
                        let i = which % held.len();
                        let len = reported(held[i].len, len_delta);
                        unsafe { dealloc(held[i].ptr, len) };
                        if len == held[i].len {
                            let h = held.swap_remove(i);
                            // Freed: a second release at the true length is
                            // a double-free the registry refuses. Checked
                            // before anything can reuse the address.
                            if h.len > 0 || !held.iter().any(|o| o.len == 0) {
                                prop_assert_eq!(unsafe { take(h.ptr, h.len) }, None);
                            }
                        } else {
                            // A mismatch frees nothing.
                            let h = &held[i];
                            prop_assert_eq!(unsafe { take(h.ptr, h.len) }, Some(h.contents.clone()));
                            held.swap_remove(i);
                        }
                    }
                    Op::TakeForeign(len) => {
                        // Memory the registry never saw: refused, and left
                        // exactly as it was (Miri would report the free).
                        let mut foreign = vec![0xA5u8; len + 1];
                        prop_assert_eq!(unsafe { take(foreign.as_mut_ptr(), len + 1) }, None);
                        prop_assert_eq!(unsafe { take(foreign.as_mut_ptr(), 0) }, None);
                        prop_assert!(foreign.iter().all(|&b| b == 0xA5));
                    }
                    Op::WipeAll => {
                        wipe_all();
                        assert_none_reclaimable(&held)?;
                        held.clear();
                        // Usable afterwards.
                        let again = alloc(1);
                        prop_assert_eq!(unsafe { take(again, 1) }, Some(vec![0]));
                    }
                }
            }

            // Shutdown: everything the host still holds is released, and
            // nothing leaks (Miri checks that too).
            wipe_all();
            assert_none_reclaimable(&held)?;
        }

        /// A null pointer with zero length is the canonical empty whatever
        /// else is live, and null with a length is never a buffer.
        #[test]
        fn null_is_only_ever_the_canonical_empty(len in 1usize..64) {
            prop_assert_eq!(unsafe { take(core::ptr::null_mut(), 0) }, Some(Vec::new()));
            prop_assert_eq!(unsafe { take(core::ptr::null_mut(), len) }, None);
        }
    }
}
