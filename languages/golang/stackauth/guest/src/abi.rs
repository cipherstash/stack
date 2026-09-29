//! This guest's wasm export surface, under the `sa_` prefix, over the
//! conventions every guest shares (`stack_guest_abi::abi`: `se_alloc` /
//! `se_dealloc`, the buffer registry, the packed `u64` result encoding, the
//! hostile-input validation of every `(ptr, len)` pair).
//!
//! # The mount
//!
//! The host mounts the profile root at [`GUEST_ROOT`] and names a store's
//! directory on every call: the root itself, or a workspace directory
//! [`sa_workspace_dir`] returned. There is no init export and no handle:
//! the mount is the whole configuration, and a store is a directory.
//!
//! # Exports
//!
//! Every export takes UTF-8 strings as `(ptr, len)` pairs and returns a
//! packed result: a string, an FFI-codec value, or an empty buffer for an
//! operation with nothing to return. See [`crate::ops`] for each one's
//! meaning and encoding; the export is the validated, unwinding-safe
//! wrapper. [`sa_shutdown`] is the one lifetime call: it wipes every
//! buffer the registry still holds, so a host that tears the instance down
//! without releasing an output — a token, a key — leaves nothing behind.
//!
//! Wasm modules are single-threaded; the host must serialize calls into one
//! instance.

use std::panic::{catch_unwind, AssertUnwindSafe};

use stack_guest_abi::abi::{err_status, input, ok_buffer};
use stack_guest_abi::buffers;
use stack_guest_abi::status::STATUS_INTERNAL;

use crate::{auth, ops};

/// Where the host mounts the profile root. The Go side mounts exactly one
/// directory here and constructs every store directory under it; nothing
/// in this module composes a path from anything else.
pub const GUEST_ROOT: &str = "/profile";

/// An operation over one validated input.
type Op1 = fn(&[u8]) -> Result<Vec<u8>, u32>;
/// An operation over two validated inputs.
type Op2 = fn(&[u8], &[u8]) -> Result<Vec<u8>, u32>;

/// Run a two-input operation as an export: validate both pairs, run,
/// pack. A panic is `STATUS_INTERNAL` (wasm32-wasip1 aborts on panic; the
/// catch is belt-and-braces for an unwinding build).
fn export2(a_ptr: *const u8, a_len: u32, b_ptr: *const u8, b_len: u32, op: Op2) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // when `op` returns, inside the call, and nothing here writes to
        // linear memory while they are live.
        let a = unsafe { input(a_ptr, a_len)? };
        let b = unsafe { input(b_ptr, b_len)? };
        op(a, b)
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

/// [`export2`] for a one-input operation.
fn export1(a_ptr: *const u8, a_len: u32, op: Op1) -> u64 {
    // SAFETY: as in `export2`.
    catch_unwind(AssertUnwindSafe(|| op(unsafe { input(a_ptr, a_len)? })))
        .unwrap_or(Err(STATUS_INTERNAL))
        .map_or_else(err_status, ok_buffer)
}

/// The current workspace id of the store at `dir`. See
/// [`ops::current_workspace`].
///
/// # Safety
///
/// `dir_ptr`/`dir_len` should name a buffer the host wrote via `se_alloc`;
/// the range is bounds-checked against linear memory (a bad pair returns
/// `STATUS_ENCODING` instead of faulting).
#[no_mangle]
pub unsafe extern "C" fn sa_current_workspace(dir_ptr: *const u8, dir_len: u32) -> u64 {
    export1(dir_ptr, dir_len, ops::current_workspace)
}

/// Set the current workspace of the store at `dir`. See
/// [`ops::set_current_workspace`].
///
/// # Safety
///
/// As for [`sa_current_workspace`].
#[no_mangle]
pub unsafe extern "C" fn sa_set_current_workspace(
    dir_ptr: *const u8,
    dir_len: u32,
    id_ptr: *const u8,
    id_len: u32,
) -> u64 {
    export2(dir_ptr, dir_len, id_ptr, id_len, ops::set_current_workspace)
}

/// Clear the current workspace of the store at `dir`. See
/// [`ops::clear_current_workspace`].
///
/// # Safety
///
/// As for [`sa_current_workspace`].
#[no_mangle]
pub unsafe extern "C" fn sa_clear_current_workspace(dir_ptr: *const u8, dir_len: u32) -> u64 {
    export1(dir_ptr, dir_len, ops::clear_current_workspace)
}

/// The workspace ids under the store at `dir`. See
/// [`ops::list_workspaces`].
///
/// # Safety
///
/// As for [`sa_current_workspace`].
#[no_mangle]
pub unsafe extern "C" fn sa_list_workspaces(dir_ptr: *const u8, dir_len: u32) -> u64 {
    export1(dir_ptr, dir_len, ops::list_workspaces)
}

/// The directory of the workspace store `id` under the store at `dir`.
/// See [`ops::workspace_dir`].
///
/// # Safety
///
/// As for [`sa_current_workspace`].
#[no_mangle]
pub unsafe extern "C" fn sa_workspace_dir(
    dir_ptr: *const u8,
    dir_len: u32,
    id_ptr: *const u8,
    id_len: u32,
) -> u64 {
    export2(dir_ptr, dir_len, id_ptr, id_len, ops::workspace_dir)
}

/// The lock file path for `filename` in the store at `dir`. See
/// [`ops::lock_path`].
///
/// # Safety
///
/// As for [`sa_current_workspace`].
#[no_mangle]
pub unsafe extern "C" fn sa_lock_path(
    dir_ptr: *const u8,
    dir_len: u32,
    name_ptr: *const u8,
    name_len: u32,
) -> u64 {
    export2(dir_ptr, dir_len, name_ptr, name_len, ops::lock_path)
}

/// `secretkey.json` in the store at `dir`. See [`ops::secret_key`]. The
/// output carries the client key; the host copies it into its opaque
/// type and releases the buffer at once.
///
/// # Safety
///
/// As for [`sa_current_workspace`].
#[no_mangle]
pub unsafe extern "C" fn sa_secret_key(dir_ptr: *const u8, dir_len: u32) -> u64 {
    export1(dir_ptr, dir_len, ops::secret_key)
}

/// `auth.json` in the store at `dir`. See [`ops::token`]. The output
/// carries the access token; the host releases the buffer once it has
/// read it.
///
/// # Safety
///
/// As for [`sa_current_workspace`].
#[no_mangle]
pub unsafe extern "C" fn sa_token(dir_ptr: *const u8, dir_len: u32) -> u64 {
    export1(dir_ptr, dir_len, ops::token)
}

/// Whether this workspace has auth.json, without parsing its content.
/// # Safety
/// As for [`sa_current_workspace`].
#[no_mangle]
pub unsafe extern "C" fn sa_has_token(dir_ptr: *const u8, dir_len: u32) -> u64 {
    export1(dir_ptr, dir_len, ops::has_token)
}

/// `device.json` in the store at `dir`, read-only. See
/// [`ops::device_identity`].
///
/// # Safety
///
/// As for [`sa_current_workspace`].
#[no_mangle]
pub unsafe extern "C" fn sa_device_identity(dir_ptr: *const u8, dir_len: u32) -> u64 {
    export1(dir_ptr, dir_len, ops::device_identity)
}

/// Construct an auth strategy from a tagged JSON config. Returns its handle.
/// The access key, when present, stays in the guest and is dropped on free.
/// # Safety
/// The input pair is validated against guest linear memory.
#[no_mangle]
pub unsafe extern "C" fn sa_auth_new(ptr: *const u8, len: u32) -> u64 {
    export1(ptr, len, auth::create)
}

/// Validate a workspace CRN using the same Rust parser as AutoStrategy.
/// # Safety
/// The input pair is validated against guest linear memory.
#[no_mangle]
pub unsafe extern "C" fn sa_auth_validate_crn(ptr: *const u8, len: u32) -> u64 {
    export1(ptr, len, auth::validate_crn)
}

/// Get a service token from a strategy. A device session returns
/// `STATUS_AUTH_REFRESH_REQUIRED` when it enters the refresh window;
/// this export never refreshes a device session or needs its file lock.
/// # Safety
/// The input pair is validated against guest linear memory.
#[no_mangle]
pub unsafe extern "C" fn sa_auth_token(ptr: *const u8, len: u32) -> u64 {
    export1(ptr, len, auth::token)
}

/// Refresh a device session. The Go host must hold the workspace's
/// auth.json lock across this whole call, including the disk re-read and save.
/// # Safety
/// The input pair is validated against guest linear memory.
#[no_mangle]
pub unsafe extern "C" fn sa_auth_refresh(ptr: *const u8, len: u32) -> u64 {
    export1(ptr, len, auth::refresh)
}

/// Drop one strategy and its cached credential.
/// # Safety
/// The input pair is validated against guest linear memory.
#[no_mangle]
pub unsafe extern "C" fn sa_auth_free(ptr: *const u8, len: u32) -> u64 {
    export1(ptr, len, auth::free)
}

/// Tear the instance down: wipe every buffer the registry still holds.
/// This guest keeps no other state. Idempotent; `se_alloc` and
/// `se_dealloc` keep working so the host can still free what it holds.
#[no_mangle]
pub extern "C" fn sa_shutdown() {
    let _ = catch_unwind(AssertUnwindSafe(auth::clear));
    let _ = catch_unwind(AssertUnwindSafe(buffers::wipe_all));
}
