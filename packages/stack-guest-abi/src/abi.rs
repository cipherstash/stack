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
//! with nonzero length rejected), invalid input yields `STATUS_ENCODING`
//! rather than a trap, and a `catch_unwind` at each export is
//! belt-and-braces for a hypothetical unwind build — wasm32-wasip1 aborts on
//! panic. Statuses are the only detail leaked.
//!
//! Wasm modules are single-threaded; the host must serialize calls into one
//! instance.
//!
//! These exports are `#[no_mangle]` in a library crate: a cdylib that links
//! this crate exports them, so every guest gets `se_alloc` and `se_dealloc`
//! by depending on it and defines only the exports that are its own.

use zeroize::{Zeroize, Zeroizing};

use crate::buffers;
use crate::status::STATUS_ENCODING;

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

/// Pack a buffer result: `ptr << 32 | len`. The buffer is registered so the
/// host's eventual [`se_dealloc`] wipes and frees exactly what was
/// allocated.
pub fn ok_buffer(out: Vec<u8>) -> u64 {
    let len = out.len() as u64;
    let ptr = buffers::register(out) as usize as u64;
    (ptr << 32) | len
}

/// Pack an error: the status in the low 32 bits, high bits zero.
pub fn err_status(status: u32) -> u64 {
    status as u64
}

/// Current linear-memory size in bytes. `u64` because a full 4 GiB memory
/// (65536 pages) overflows a 32-bit `usize`.
pub fn linear_memory_bytes() -> u64 {
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
/// Safe to call with any pointer, which is the point: the validation above
/// is what a caller would otherwise have to promise, so the function is not
/// `unsafe` and the lint that asks for it is answered here rather than at
/// every export.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn input<'a>(ptr: *const u8, len: u32) -> Result<&'a [u8], u32> {
    let len = len as usize;
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() || len > isize::MAX as usize {
        return Err(STATUS_ENCODING);
    }
    let end = (ptr as usize).checked_add(len).ok_or(STATUS_ENCODING)?;
    if end as u64 > linear_memory_bytes() {
        return Err(STATUS_ENCODING);
    }
    // SAFETY: non-null, in-bounds of linear memory, and under `isize::MAX`;
    // wasm linear memory is fully initialized (fresh pages are zero), so
    // reading the range as bytes is defined.
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
    let taken = Zeroizing::new(input(ptr, len)?.to_vec());
    unsafe { wipe_input(ptr, len) };
    Ok(taken)
}
