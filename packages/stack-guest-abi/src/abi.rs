//! The part of the wasm export surface every guest has, and the helpers a
//! guest's own exports are written with. Same conventions as the vitaminc
//! guest (`vc_*`), under the `se_` prefix:
//!
//! - The host owns all buffer lifecycles. It writes inputs into guest
//!   memory obtained from [`se_alloc`] and releases every buffer — its own
//!   inputs and the guest's outputs — with [`se_dealloc`], which **zeroizes
//!   before freeing**. The guest keeps a registry of every buffer it hands
//!   out ([`crate::buffers`]), so `se_dealloc` never trusts the host's
//!   length.
//! - An export handed plaintext wipes that buffer in place before it
//!   returns ([`take_plaintext`]), rather than leaving it for `se_dealloc`:
//!   the host's plaintext then lives no longer than the call. A host must
//!   not read such a buffer back after the call, or pass it to two calls.
//! - Output buffers that contain plaintext are the host's to copy out and
//!   immediately `se_dealloc`.
//! - During an export the host's imported functions may re-enter the guest
//!   **only** through `se_alloc` (to place a response); calling any other
//!   export from inside a host import is undefined behaviour of the
//!   embedding, not of this crate.
//!
//! # Result encoding
//!
//! Every fallible export returns a single `u64` split into a high and a low
//! 32-bit field:
//!
//! - **success** — the high 32 bits are non-zero: an output pointer with
//!   the low 32 bits its length ([`ok_buffer`]).
//! - **error** — the high 32 bits are zero and the low 32 bits are a
//!   [`crate::status`] code ([`err_status`]). A valid pointer is never zero,
//!   so the two spaces never collide.
//!
//! # Hostile-input posture
//!
//! As the vitaminc guest: every export validates its pointer/length pairs
//! against linear memory before any unsafe construction ([`input`]; null
//! with nonzero length rejected), and invalid input yields `STATUS_ENCODING`
//! rather than a trap. A guest wraps each of its *own* exports in a
//! `catch_unwind`, belt-and-braces for a hypothetical unwind build —
//! wasm32-wasip1 aborts on panic; the two exports here need none, since
//! neither has a panic path (allocation goes through `try_reserve_exact`
//! and release through the registry). A failure is a status number, and
//! `se_last_error` has the error behind it, encoded under the rule on
//! `stack-profile`'s `ErrorPayload` ([`last_error`]): no plaintext, key,
//! token, ciphertext or context value is ever in it.
//!
//! Wasm modules are single-threaded; the host must serialize calls into one
//! instance.
//!
//! These exports are `#[no_mangle]` in a library crate: a cdylib that links
//! this crate exports them, so every guest gets `se_alloc` and `se_dealloc`
//! by depending on it and defines only the exports that are its own.

use zeroize::{Zeroize, Zeroizing};

use crate::buffers;
use crate::call;
use crate::last_error;

/// Run an export's body through [`call::run`] — clear the last error, run
/// `f` (a panic is an internal failure), clear it again on success or make
/// sure one is recorded on failure — and pack the result. Every guest export
/// that returns a packed result goes through here, so "every export clears
/// the last error when it starts and sets it when it fails" is written once,
/// in [`call`], where it is tested natively.
pub fn export(f: impl FnOnce() -> Result<Vec<u8>, u32>) -> u64 {
    match call::run(f) {
        Ok(out) => ok_buffer(out),
        Err(status) => err_status(status),
    }
}

/// The full error behind the most recent failed export, as a packed buffer
/// result: a transport-codec object of `code`, `message`, `help`, `url`
/// (when set), `severity`, `fields` and `causes` (see
/// [`last_error::encode`]). Zero when there is none — no export has failed
/// since the last success, or the error was already handed over.
///
/// The host calls it only after a non-zero status, copies the buffer out
/// and releases it with [`se_dealloc`], like any output. Handing the buffer
/// over empties the slot, so a second call returns zero
/// ([`call::pack_last_error`]). It reads the last error and does not clear
/// it first, so it is the one export that is not run through [`export`].
#[no_mangle]
pub extern "C" fn se_last_error() -> u64 {
    call::pack_last_error(address)
}

/// Allocate `len` bytes of guest memory for the host to write into. Returns
/// null if the allocation fails (recoverable host-side; never a trap).
#[no_mangle]
pub extern "C" fn se_alloc(len: u32) -> *mut u8 {
    buffers::alloc(len as usize)
}

/// Zeroize and free a buffer previously handed out by [`se_alloc`] or
/// packed into a result. See [`buffers::dealloc`] for the registry
/// discipline (unknown pointer: no-op; length mismatch: refused).
///
/// # Safety
///
/// `ptr` should be a pointer this crate handed out; the registry makes
/// anything else a no-op rather than undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn se_dealloc(ptr: *mut u8, len: u32) {
    unsafe { buffers::dealloc(ptr, len as usize) }
}

/// Pack a buffer result: `ptr << 32 | len` ([`call::pack_buffer`]). The
/// buffer is registered so the host's eventual [`se_dealloc`] wipes and
/// frees exactly what was allocated.
pub fn ok_buffer(out: Vec<u8>) -> u64 {
    let len = out.len() as u32;
    call::pack_buffer(address(buffers::register(out)), len)
}

/// Pack an error: the status in the low 32 bits, high bits zero
/// ([`call::pack_status`]).
pub fn err_status(status: u32) -> u64 {
    call::pack_status(status)
}

/// A pointer's wasm32 address: the whole pointer, since `usize` is 32 bits
/// here.
fn address(ptr: *mut u8) -> u32 {
    ptr as usize as u32
}

/// Current linear-memory size in bytes. `u64` because a full 4 GiB memory
/// (65536 pages) overflows a 32-bit `usize`.
fn linear_memory_bytes() -> u64 {
    core::arch::wasm32::memory_size::<0>() as u64 * 65536
}

/// Borrow a host-supplied `(ptr, len)` pair, validating before any slice
/// exists: null-with-nonzero-length is rejected (treating it as empty would
/// silently drop whatever bytes the host meant to pass), the length must be
/// under `isize::MAX`, and the whole range must lie inside the current
/// linear memory. A pair that fails validation yields `STATUS_ENCODING`; a
/// pair that passes can still name the wrong bytes — the host owns its
/// pointers — but can never fault or over-read past linear memory.
///
/// # Safety
///
/// The bounds check is what keeps the read inside linear memory; it cannot
/// see who owns the range or for how long, and that is what the caller
/// promises. `ptr`/`len` must name a buffer the host wrote and still owns
/// (one it obtained from [`se_alloc`], or an empty range), and that buffer
/// must stay allocated and unwritten for the whole of `'a` — in practice,
/// the borrow must end before the export returns and before any wipe of an
/// overlapping range ([`wipe_input`], [`take_plaintext`]). The lifetime is
/// otherwise unconstrained, so a caller choosing `'static` over a range it
/// is about to free would read freed memory: that is the promise, not a
/// property this function can check.
pub unsafe fn input<'a>(ptr: *const u8, len: u32) -> Result<&'a [u8], u32> {
    let refuse = || last_error::malformed("a pointer/length pair is outside guest memory");
    let len = len as usize;
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() || len > isize::MAX as usize {
        return Err(refuse());
    }
    let end = (ptr as usize).checked_add(len).ok_or_else(refuse)?;
    if end as u64 > linear_memory_bytes() {
        return Err(refuse());
    }
    // SAFETY: non-null, in-bounds of linear memory, and under `isize::MAX`;
    // wasm linear memory is fully initialized (fresh pages are zero), so
    // reading the range as bytes is defined. That it stays allocated and
    // unwritten for `'a` is the caller's contract, above.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Zeroize a validated input range in place (without freeing it — the host
/// still owns the buffer and will `se_dealloc` it after the call).
///
/// # Safety
///
/// The range must have passed [`input`] validation and carry no outstanding
/// borrows.
pub unsafe fn wipe_input(ptr: *mut u8, len: u32) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe { std::slice::from_raw_parts_mut(ptr, len as usize) }.zeroize();
}

/// Take a plaintext input out of the host's buffer and wipe the buffer.
///
/// An export that holds its decoded value across a host round trip would
/// otherwise keep the borrow of the host buffer alive for the whole call.
/// Copying into a `Zeroizing` first lets the original be wiped immediately:
/// the plaintext then exists for the duration of the call and no longer,
/// instead of sitting in linear memory until the host gets round to
/// `se_dealloc`.
///
/// Call it before any other buffer is borrowed, deliberately. The wipe
/// writes through `&mut`, so no other `&[u8]` into linear memory may be
/// live — and a host that aliases its value range onto another argument
/// therefore reads zeros there, which that argument's parser rejects.
///
/// # Safety
///
/// `ptr`/`len` must name a host buffer the caller is done with; it is zeroed
/// before this returns.
pub unsafe fn take_plaintext(ptr: *mut u8, len: u32) -> Result<Zeroizing<Vec<u8>>, u32> {
    // SAFETY: the borrow lives only for the copy on this line, inside the
    // call, over a buffer the caller has promised is the host's and live.
    let taken = Zeroizing::new(unsafe { input(ptr, len)? }.to_vec());
    unsafe { wipe_input(ptr, len) };
    Ok(taken)
}
