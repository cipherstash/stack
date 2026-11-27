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
//!
//! # Token exports step
//!
//! [`sa_auth_token`] and [`sa_auth_refresh`] never wait on the network.
//! Each runs its work as a step operation ([`crate::auth`]): done, it
//! returns the token as always. Waiting on a request to CTS, or parked
//! behind another caller's exchange, it returns `STATUS_NEEDS_IO` instead.
//! The host takes the step with [`sa_auth_io`] before it calls any other
//! export, and then:
//!
//! - for requests, performs them outside the guest and hands the responses
//!   to [`sa_auth_resume`], which returns the same three ways;
//! - for a parked operation, waits until [`sa_auth_runnable`] lists its
//!   handle, then resumes it with no responses. The host asks
//!   [`sa_auth_runnable`] after every step, resume and abort: one waiter
//!   running can be what makes the next one runnable;
//! - or gives up with [`sa_auth_abort`]. A host aborts a parked operation
//!   freely. It does not abort one whose request is in flight: it resumes
//!   it with the response, or with the transport failure, so a rotated
//!   refresh token is never dropped.
//!
//! [`crate::io`] has the wire form. Several operations may be paused at
//! once, each under its own handle, up to `stack_guest_abi::step::MAX_OPEN`.

use std::panic::{catch_unwind, AssertUnwindSafe};

use stack_guest_abi::abi::{export, input, take_plaintext};
use stack_guest_abi::call;
use stack_guest_abi::status::STATUS_NEEDS_IO;
use stack_guest_abi::step::{self, Operation, Step};
use stack_guest_abi::{buffers, last_error};
use vitaminc_protected::Controlled as _;

use crate::{auth, io, ops};

/// Where the host mounts the profile root. The Go side mounts exactly one
/// directory here and constructs every store directory under it; nothing
/// in this module composes a path from anything else.
pub const GUEST_ROOT: &str = "/profile";

/// An operation over one validated input.
type Op1 = fn(&[u8]) -> Result<Vec<u8>, u32>;
/// An operation over two validated inputs.
type Op2 = fn(&[u8], &[u8]) -> Result<Vec<u8>, u32>;

/// Run a two-input operation as an export: validate both pairs, run,
/// pack, through the shared [`export`] wrapper — which clears the last
/// error first, records one for any failure, and makes a panic
/// `STATUS_INTERNAL` (wasm32-wasip1 aborts on panic; the catch is
/// belt-and-braces for an unwinding build).
fn export2(a_ptr: *const u8, a_len: u32, b_ptr: *const u8, b_len: u32, op: Op2) -> u64 {
    export(|| {
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // when `op` returns, inside the call, and nothing here writes to
        // linear memory while they are live.
        let a = unsafe { input(a_ptr, a_len)? };
        let b = unsafe { input(b_ptr, b_len)? };
        op(a, b)
    })
}

/// [`export2`] for a one-input operation.
fn export1(a_ptr: *const u8, a_len: u32, op: Op1) -> u64 {
    // SAFETY: as in `export2`.
    export(|| op(unsafe { input(a_ptr, a_len)? }))
}

/// Turn what came of an operation's step into an export's result: the
/// output when done, `STATUS_NEEDS_IO` with the step registered for
/// [`sa_auth_io`] when paused or parked, the status when failed.
fn deliver(step: Result<Step, u32>) -> Result<Vec<u8>, u32> {
    let (handle, parked, requests) = match step? {
        Step::Done(out) => return Ok(out),
        Step::NeedsIo { handle, requests } => (handle, false, requests),
        Step::Parked { handle } => (handle, true, Vec::new()),
    };
    let encoded = io::encode_step(handle, parked, &requests);
    drop(requests);
    let encoded = encoded.inspect_err(|_| {
        let _ = step::abort(handle);
    })?;
    step::set_pending(encoded);
    Err(STATUS_NEEDS_IO)
}

/// Start a token operation built from one validated input, as an export.
fn start1(a_ptr: *const u8, a_len: u32, build: fn(&[u8]) -> Result<Operation, u32>) -> u64 {
    // SAFETY: as in `export2`.
    export(|| {
        deliver(step::start_parkable(build(unsafe {
            input(a_ptr, a_len)?
        })?))
    })
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

/// The CRN of the current workspace's saved session, for the store at
/// `dir`. See [`ops::session_crn`].
///
/// # Safety
///
/// As for [`sa_current_workspace`].
#[no_mangle]
pub unsafe extern "C" fn sa_session_crn(dir_ptr: *const u8, dir_len: u32) -> u64 {
    export1(dir_ptr, dir_len, ops::session_crn)
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

/// Get a service token from a strategy, as a step operation (see
/// [Token exports step](self#token-exports-step)). A device session returns
/// `STATUS_AUTH_REFRESH_REQUIRED` when it enters the refresh window;
/// this export never refreshes a device session or needs its file lock.
/// # Safety
/// The input pair is validated against guest linear memory.
#[no_mangle]
pub unsafe extern "C" fn sa_auth_token(ptr: *const u8, len: u32) -> u64 {
    start1(ptr, len, auth::token)
}

/// Refresh a device session, as a step operation. The Go host must hold
/// the workspace's auth.json lock across every step of it, from this call
/// to the step that finishes it, including the disk re-read and save.
/// # Safety
/// The input pair is validated against guest linear memory.
#[no_mangle]
pub unsafe extern "C" fn sa_auth_refresh(ptr: *const u8, len: u32) -> u64 {
    start1(ptr, len, auth::refresh)
}

/// The step a paused token export left: its handle, whether it is parked,
/// and the requests it waits on, as a packed buffer ([`crate::io`]), handed
/// over once: a second call returns zero, as does a call with no step
/// waiting. The host calls it after `STATUS_NEEDS_IO`, before any other
/// export, and releases the buffer with `se_dealloc`, which wipes it: a
/// request carries a credential.
#[no_mangle]
pub extern "C" fn sa_auth_io() -> u64 {
    match step::take_pending() {
        Some((ptr, len)) => call::pack_buffer(ptr as usize as u32, len as u32),
        None => 0,
    }
}

/// Hand a paused token operation the responses to the requests its last
/// step asked for ([`crate::io`] has the frame), or none for a parked one,
/// and run its next step. Returns as the export that started it does. The
/// responses buffer carries tokens and is wiped in place. A handle that
/// names no paused operation is `STATUS_STATE`; responses that do not
/// decode, or are not one per request, are `STATUS_ENCODING`, and the
/// operation is dropped.
///
/// # Safety
///
/// The responses pair is validated against guest linear memory.
#[no_mangle]
pub unsafe extern "C" fn sa_auth_resume(handle: u64, resp_ptr: *mut u8, resp_len: u32) -> u64 {
    export(|| {
        // SAFETY: a host-owned range the export was handed; it is copied
        // out and wiped in place before this returns.
        let bytes = unsafe { take_plaintext(resp_ptr, resp_len) };
        let responses = bytes.and_then(|bytes| io::decode_responses(bytes.risky_ref()));
        let responses = responses.inspect_err(|_| {
            let _ = step::abort(handle);
        })?;
        deliver(step::resume(handle, responses))
    })
}

/// Give up on a paused or parked token operation: drop it, wiping what it
/// held. An empty output; `STATUS_STATE` for a handle that names no paused
/// operation. Dropping an operation that held a strategy's lock can make
/// another runnable: the host asks [`sa_auth_runnable`] after it.
#[no_mangle]
pub extern "C" fn sa_auth_abort(handle: u64) -> u64 {
    export(|| step::abort(handle).map(|()| Vec::new()))
}

/// The parked token operations the host may resume now, with no
/// responses: a frame holding a list of handles ([`crate::io`]).
#[no_mangle]
pub extern "C" fn sa_auth_runnable() -> u64 {
    export(|| io::encode_runnable(&step::runnable()))
}

/// Drop one strategy and its cached credential.
/// # Safety
/// The input pair is validated against guest linear memory.
#[no_mangle]
pub unsafe extern "C" fn sa_auth_free(ptr: *const u8, len: u32) -> u64 {
    export1(ptr, len, auth::free)
}

/// Tear the instance down: drop every paused token operation and every
/// strategy, and wipe every buffer the registry still holds. Idempotent; `se_alloc` and
/// `se_dealloc` keep working so the host can still free what it holds.
#[no_mangle]
pub extern "C" fn sa_shutdown() {
    // The paused operations first: each holds its strategy, which then
    // drops with the registry.
    let _ = catch_unwind(AssertUnwindSafe(step::drop_all));
    let _ = catch_unwind(AssertUnwindSafe(auth::clear));
    let _ = catch_unwind(AssertUnwindSafe(last_error::clear));
    let _ = catch_unwind(AssertUnwindSafe(buffers::wipe_all));
}
