//! The wasm export surface. Same conventions as the vitaminc guest
//! (`vc_*`), under the `se_` prefix:
//!
//! - The host owns all buffer lifecycles. It writes inputs into guest
//!   memory obtained from [`se_alloc`] and releases every buffer — its own
//!   inputs and the guest's outputs — with [`se_dealloc`], which **zeroizes
//!   before freeing**. The guest keeps a registry of every buffer it hands
//!   out ([`crate::buffers`]), so `se_dealloc` never trusts the host's
//!   length. Two entry points additionally wipe their *input* buffer in
//!   place before returning: [`se_cipher_init`] (the config carries the
//!   client key) and [`se_decrypt`]'s output is plaintext the host must
//!   copy out and immediately `se_dealloc`.
//! - A cipher is a **handle**: [`se_cipher_init`] builds a
//!   `StackCipher<StackKms<HostTokenStrategy, WasiHostConnection>>` (one
//!   `load-keyset` round trip through the host transport — the index key
//!   then lives in the guest), and [`se_cipher_free`] drops it (client key
//!   and index key wiped by their own `ZeroizeOnDrop`). Handle ids are
//!   never reused; at exhaustion `se_cipher_init` fails with
//!   `STATUS_INTERNAL` rather than aliasing a live handle.
//! - During an entry-point call the host's imported functions may re-enter
//!   the guest **only** through `se_alloc` (to place the transport response
//!   / token); calling any other export from inside a host import is
//!   undefined behaviour of the embedding, not of this module.
//!
//! # Result encoding
//!
//! Every fallible export returns a single `u64` split into a high and a low
//! 32-bit field:
//!
//! - **success** — the high 32 bits are non-zero: an output pointer with
//!   the low 32 bits its length, or (for [`se_cipher_init`]) the handle
//!   with the low bits unused.
//! - **error** — the high 32 bits are zero and the low 32 bits are a
//!   [`crate::status`] code. A valid pointer / handle is never zero, so
//!   the two spaces never collide.
//!
//! # Hostile-input posture
//!
//! As the vitaminc guest: every export validates its pointer/length pairs
//! against linear memory before any unsafe construction (null with nonzero
//! length rejected; a null AAD must not silently become an empty AAD),
//! invalid input yields `STATUS_ENCODING` rather than a trap, and the
//! `catch_unwind` at each export is belt-and-braces for a hypothetical
//! unwind build — wasm32-wasip1 aborts on panic. Statuses are the only
//! detail leaked.
//!
//! Wasm modules are single-threaded; the host must serialize calls into one
//! instance.

use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};

use futures::executor::block_on;
use stack_encrypt::StackCipher;
use stack_kms::{ClientOpts, StackKms};
use vitaminc_aead_value::transport as codec;
use zeroize::Zeroize;

use crate::buffers;
use crate::config::parse_config;
use crate::host::{HostTokenStrategy, WasiHostConnection};
use crate::ops;
use crate::sessions::Sessions;
use crate::status::{STATUS_BAD_HANDLE, STATUS_ENCODING, STATUS_INTERNAL, STATUS_KMS_TRANSPORT};

/// The cipher a handle names: `stack-encrypt` over the host-transport
/// ZeroKMS client with host-supplied tokens.
type GuestCipher = StackCipher<StackKms<HostTokenStrategy, WasiHostConnection>>;

thread_local! {
    // Wasm is single-threaded, so a thread-local `RefCell` is a plain owner
    // of the session table — no `Send`/`Sync` bounds required.
    static SESSIONS: RefCell<Sessions<GuestCipher>> = RefCell::new(Sessions::new());
}

/// Allocate `len` bytes of guest memory for the host to write into. Returns
/// null if the allocation fails (recoverable host-side; never a trap).
#[no_mangle]
pub extern "C" fn se_alloc(len: u32) -> *mut u8 {
    buffers::alloc(len as usize)
}

/// Zeroize and free a buffer previously handed out by [`se_alloc`] or
/// packed into a result. See [`crate::buffers::dealloc`] for the registry
/// discipline (unknown pointer: no-op; length mismatch: refused).
///
/// # Safety
///
/// `ptr` should be a pointer this module handed out; the registry makes
/// anything else a no-op rather than undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn se_dealloc(ptr: *mut u8, len: u32) {
    unsafe { buffers::dealloc(ptr, len as usize) }
}

/// Pack a buffer result: `ptr << 32 | len`. The buffer is registered so the
/// host's eventual [`se_dealloc`] wipes and frees exactly what was
/// allocated.
fn ok_buffer(out: Vec<u8>) -> u64 {
    let len = out.len() as u64;
    let ptr = buffers::register(out) as usize as u64;
    (ptr << 32) | len
}

/// Pack a handle result: `handle << 32`. Handles start at 1, so the high 32
/// bits are non-zero; the low bits are unused.
fn ok_handle(handle: u32) -> u64 {
    (handle as u64) << 32
}

/// Pack an error: the status in the low 32 bits, high bits zero.
fn err_status(status: u32) -> u64 {
    status as u64
}

/// Current linear-memory size in bytes. `u64` because a full 4 GiB memory
/// (65536 pages) overflows a 32-bit `usize`.
fn linear_memory_bytes() -> u64 {
    core::arch::wasm32::memory_size::<0>() as u64 * 65536
}

/// Borrow a host-supplied `(ptr, len)` pair, validating before any slice
/// exists: null-with-nonzero-length is rejected (treating it as empty would
/// silently drop an AAD context binding), the length must be under
/// `isize::MAX`, and the whole range must lie inside the current linear
/// memory. A pair that fails validation yields `STATUS_ENCODING`; a pair
/// that passes can still name the wrong bytes — the host owns its pointers
/// — but can never fault or over-read past linear memory.
fn input<'a>(ptr: *const u8, len: u32) -> Result<&'a [u8], u32> {
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
unsafe fn wipe_input(ptr: *mut u8, len: u32) {
    if ptr.is_null() || len == 0 {
        return;
    }
    unsafe { std::slice::from_raw_parts_mut(ptr, len as usize) }.zeroize();
}

/// Run `f` with the cipher bound to `handle`, or report `STATUS_BAD_HANDLE`.
fn with_cipher<R>(handle: u32, f: impl FnOnce(&GuestCipher) -> Result<R, u32>) -> Result<R, u32> {
    SESSIONS.with(|s| {
        let s = s.borrow();
        let cipher = s.get(handle).ok_or(STATUS_BAD_HANDLE)?;
        f(cipher)
    })
}

/// Initialise a cipher from an FFI-codec-encoded config object (see
/// [`crate::config`]), returning a handle. Performs one `load-keyset`
/// round trip through the host transport; the raw config buffer — which
/// carries the client-key hex — is wiped in place before any network
/// traffic, whatever the outcome.
///
/// # Safety
///
/// `cfg_ptr`/`cfg_len` should name the buffer the host wrote the config
/// into. The guest bounds-checks the range against linear memory — a bad
/// pair returns `STATUS_ENCODING` instead of faulting — but cannot verify
/// the bytes are the ones the host intended.
#[no_mangle]
pub unsafe extern "C" fn se_cipher_init(cfg_ptr: *mut u8, cfg_len: u32) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        let decoded = codec::decode_value(&mut codec::Reader::new(input(cfg_ptr, cfg_len)?))
            .map_err(|_| STATUS_ENCODING);
        // The borrow of the raw buffer ends with `decoded` owned; wipe the
        // buffer now — it holds the client-key hex — before parsing (and
        // before the init round trip), whatever the decode outcome.
        unsafe { wipe_input(cfg_ptr, cfg_len) };
        cipher_init(decoded?)
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_handle)
}

fn cipher_init(decoded: vitaminc_aead_value::FfiValue) -> Result<u32, u32> {
    let config = parse_config(decoded).map_err(|_| STATUS_ENCODING)?;

    // One request at a time: the host import is synchronous, so concurrency
    // would only interleave nothing; keep the executor honest about it.
    let opts = ClientOpts::new(config.endpoint)
        .with_max_concurrent_reqs(1)
        .map_err(|_| STATUS_INTERNAL)?;
    let kms = StackKms::<HostTokenStrategy, WasiHostConnection>::connect(
        opts,
        HostTokenStrategy,
        config.client_key,
    )
    .map_err(|_| STATUS_KMS_TRANSPORT)?;

    let mut builder = StackCipher::builder().kms(kms);
    if let Some(keyset) = config.keyset {
        builder = builder.keyset(keyset);
    }
    let cipher = block_on(builder.init()).map_err(|e| crate::status::status_for_error(&e))?;
    SESSIONS.with(|s| s.borrow_mut().insert(cipher))
}

/// Drop a cipher handle. The client key and the keyset's index key are
/// wiped by their own `ZeroizeOnDrop`. Freeing an unknown handle is a
/// no-op.
#[no_mangle]
pub extern "C" fn se_cipher_free(handle: u32) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        SESSIONS.with(|s| {
            s.borrow_mut().remove(handle);
        });
    }));
}

/// Encrypt an FFI-codec-encoded value tree under the handle's cipher,
/// binding `aad`; one batched `generate-data-key` call however many leaves.
/// Output: packed pointer to a codec-encoded ciphertext tree whose leaves
/// are the frozen `SealedValue` byte encoding.
///
/// # Safety
///
/// Pointer/length pairs should name buffers the host wrote via
/// [`se_alloc`]; each range is bounds-checked against linear memory (a bad
/// pair returns `STATUS_ENCODING` instead of faulting).
#[no_mangle]
pub unsafe extern "C" fn se_encrypt(
    handle: u32,
    val_ptr: *const u8,
    val_len: u32,
    aad_ptr: *const u8,
    aad_len: u32,
) -> u64 {
    run_encrypt(handle, val_ptr, val_len, aad_ptr, aad_len, false)
}

/// Like [`se_encrypt`], but seals the value as a *sequence element* — rows
/// written through this export interchange with rows written by encrypting
/// a whole sequence under the same AAD.
///
/// # Safety
///
/// As for [`se_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn se_encrypt_element(
    handle: u32,
    val_ptr: *const u8,
    val_len: u32,
    aad_ptr: *const u8,
    aad_len: u32,
) -> u64 {
    run_encrypt(handle, val_ptr, val_len, aad_ptr, aad_len, true)
}

/// Decrypt a codec-encoded ciphertext tree back into a codec-encoded value
/// tree; one batched `retrieve-data-key` call. The output buffer contains
/// **plaintext** — the host must copy it out and immediately release it
/// with [`se_dealloc`] (which wipes it).
///
/// # Safety
///
/// As for [`se_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn se_decrypt(
    handle: u32,
    ct_ptr: *const u8,
    ct_len: u32,
    aad_ptr: *const u8,
    aad_len: u32,
) -> u64 {
    run_decrypt(handle, ct_ptr, ct_len, aad_ptr, aad_len, false)
}

/// Like [`se_decrypt`], but opens the ciphertext as a *sequence element* —
/// the read-side counterpart of [`se_encrypt_element`], for one row of a
/// batch-encrypted sequence under the batch's AAD.
///
/// # Safety
///
/// As for [`se_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn se_decrypt_element(
    handle: u32,
    ct_ptr: *const u8,
    ct_len: u32,
    aad_ptr: *const u8,
    aad_len: u32,
) -> u64 {
    run_decrypt(handle, ct_ptr, ct_len, aad_ptr, aad_len, true)
}

/// [`se_encrypt`] / [`se_encrypt_element`]'s shared drive: validate, look
/// up the handle, block on the op.
fn run_encrypt(
    handle: u32,
    val_ptr: *const u8,
    val_len: u32,
    aad_ptr: *const u8,
    aad_len: u32,
    as_element: bool,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        let value = input(val_ptr, val_len)?;
        let aad = input(aad_ptr, aad_len)?;
        with_cipher(handle, |cipher| {
            block_on(ops::encrypt_value(cipher, value, aad, as_element))
        })
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

/// [`se_decrypt`] / [`se_decrypt_element`]'s shared drive.
fn run_decrypt(
    handle: u32,
    ct_ptr: *const u8,
    ct_len: u32,
    aad_ptr: *const u8,
    aad_len: u32,
    as_element: bool,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        let ciphertext = input(ct_ptr, ct_len)?;
        let aad = input(aad_ptr, aad_len)?;
        with_cipher(handle, |cipher| {
            block_on(ops::decrypt_value(cipher, ciphertext, aad, as_element))
        })
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

/// Derive one index term: a codec-encoded scalar plus a context string and
/// a term kind ([`ops::TERM_EQUALITY`] etc.); the output is the term's
/// frozen byte encoding. Local PRF/CLLW only — never touches ZeroKMS.
///
/// # Safety
///
/// As for [`se_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn se_term(
    handle: u32,
    val_ptr: *const u8,
    val_len: u32,
    ctx_ptr: *const u8,
    ctx_len: u32,
    kind: u32,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        let value = input(val_ptr, val_len)?;
        let context = input(ctx_ptr, ctx_len)?;
        with_cipher(handle, |cipher| {
            block_on(ops::term(cipher, value, context, kind))
        })
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

/// Encrypt a record (or a batch) per a plan — the runtime form of
/// `#[derive(EncryptFrom)]`; see [`ops::encrypt_record`] for the source,
/// plan, and result encodings. One `generate-data-key` call per invocation
/// regardless of row count; terms derive locally.
///
/// # Safety
///
/// As for [`se_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn se_encrypt_record(
    handle: u32,
    src_ptr: *const u8,
    src_len: u32,
    plan_ptr: *const u8,
    plan_len: u32,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        let source = input(src_ptr, src_len)?;
        let plan = input(plan_ptr, plan_len)?;
        with_cipher(handle, |cipher| {
            block_on(ops::encrypt_record(cipher, source, plan))
        })
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

/// Decrypt a record (or a batch) produced by [`se_encrypt_record`] under
/// the same plan; only the `"c"` outputs participate. One
/// `retrieve-data-key` call per invocation. The output buffer contains
/// **plaintext** — same host obligations as [`se_decrypt`].
///
/// # Safety
///
/// As for [`se_encrypt`].
#[no_mangle]
pub unsafe extern "C" fn se_decrypt_record(
    handle: u32,
    rec_ptr: *const u8,
    rec_len: u32,
    plan_ptr: *const u8,
    plan_len: u32,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        let record = input(rec_ptr, rec_len)?;
        let plan = input(plan_ptr, plan_len)?;
        with_cipher(handle, |cipher| {
            block_on(ops::decrypt_record(cipher, record, plan))
        })
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}
