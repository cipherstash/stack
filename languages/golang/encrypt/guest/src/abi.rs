//! This guest's wasm export surface: the cipher exports, over the
//! conventions every guest shares (`stack_guest_abi::abi`: `se_alloc` /
//! `se_dealloc`, the buffer registry, the packed `u64` result encoding, the
//! hostile-input validation of every `(ptr, len)` pair). What is specific
//! to this guest:
//!
//! - **Every export handed plaintext wipes that buffer in place before it
//!   returns**, rather than leaving it for `se_dealloc`: [`se_cipher_init`]
//!   (the config carries the client key), and [`se_term`] and
//!   [`se_encrypt_record`] (their value/source buffers). The host's plaintext therefore lives no longer
//!   than the call, instead of until the host gets round to releasing it.
//!   **A host must not read a plaintext input buffer back after the call, or
//!   pass the same buffer to two calls** — it will be zeros. Option, context,
//!   AAD and plan buffers are not secret and are left untouched.
//! - Output buffers from the decrypt exports contain plaintext; the host must
//!   copy them out and immediately `se_dealloc` (which zeroizes).
//! - **One instance is one client.** [`se_cipher_init`] runs once per
//!   instance: it builds the
//!   `StackCipher<StackKms<HostTokenStrategy, WasiHostConnection>>` (one
//!   `load-keyset` round trip through the host transport for the default
//!   keyset) and returns that keyset's id. There is no cipher handle: the
//!   keysets a client uses are selected per call through the options object
//!   ([`crate::options`]), loaded on first use through the cipher's own
//!   cache. Nothing crosses the boundary that the host could allocate,
//!   alias or free.
//! - [`se_shutdown`] is the one lifetime call: it drops the cipher (client
//!   key and every loaded index key wiped by `ZeroizeOnDrop`) and wipes
//!   every buffer the registry still holds. It exists because closing a
//!   wasm instance frees linear memory without running Rust destructors —
//!   without it, key material would sit in freed host memory. After it, a
//!   well-formed cipher operation is `STATUS_STATE`, as one before
//!   [`se_cipher_init`] is, and so is a re-`se_cipher_init`. That is the
//!   whole of the claim: `se_alloc` and `se_dealloc` return no status
//!   and go on working — the host still has buffers to free — a second
//!   [`se_shutdown`] is a no-op, and a *malformed* call is
//!   `STATUS_ENCODING` in any state, because validation runs first (see
//!   below).
//! - During an entry-point call the host's imported functions may re-enter
//!   the guest **only** through `se_alloc` (to place the transport response
//!   / token); calling any other export from inside a host import is
//!   undefined behaviour of the embedding, not of this module.
//!
//! There are no whole-value exports: every value crosses as a record under
//! a declaration (ADR-0007, amended). The record and term exports bind
//! fields, so their contexts must be non-empty (`STATUS_ENCODING`
//! otherwise): each is a [`stack_encrypt::NonEmpty`] from the moment it is
//! parsed, and the sealing and opening sides bind that one value.
//! [`se_plan_check`] and [`se_targets`] answer the Go generator's questions
//! and need no cipher.
//!
//! Every export decodes and validates *all* of its inputs — the operation
//! payload, the plan or context, the term kind, the value against the
//! plan or kind, and the options object — before it consults the cipher
//! ([`ops::validate`] runs the operation's own parsers), so
//! malformed input reads as `STATUS_ENCODING` whether or not
//! `se_cipher_init` has run, and never costs a keyset load; only a
//! well-formed call with no cipher is `STATUS_STATE`. Keyset *resolution*
//! (a name or id the cipher has not loaded) is a round trip and so happens
//! inside the call, after every check.
//!
//! Wasm modules are single-threaded; the host must serialize calls into one
//! instance.

use std::cell::{Cell, RefCell};
use std::panic::{catch_unwind, AssertUnwindSafe};

use futures::executor::block_on;
use stack_encrypt::{KeysetCipher, StackCipher};
use stack_guest_abi::abi::{err_status, input, ok_buffer, take_plaintext, wipe_input};
use stack_guest_abi::buffers;
use vitaminc_aead_value::transport as codec;
use vitaminc_aead_value::FfiValue;

use crate::ops;
use crate::options::{parse_options, parse_selector, scope_for, KeysetSelector, Side};
use crate::status::{STATUS_ENCODING, STATUS_INTERNAL, STATUS_STATE};
use stack_encrypt::dynamic::Scope;

/// The key source the instance's cipher runs over: the host-transport
/// ZeroKMS client with host-supplied tokens — or, in the `deterministic-kms`
/// test build, the seeded source the record fixture was sealed under.
#[cfg(not(feature = "deterministic-kms"))]
type GuestKms =
    stack_kms::StackKms<crate::host::HostTokenStrategy, crate::host::WasiHostConnection>;
#[cfg(feature = "deterministic-kms")]
type GuestKms = crate::deterministic::DeterministicSource;

/// The instance's cipher: `stack-encrypt` over [`GuestKms`].
type GuestCipher = StackCipher<GuestKms>;

thread_local! {
    // Wasm is single-threaded, so a thread-local `RefCell` is a plain owner
    // of the cipher — no `Send`/`Sync` bounds required.
    static CIPHER: RefCell<Option<GuestCipher>> = const { RefCell::new(None) };
    /// Set by `se_shutdown`: after it, `se_cipher_init` is refused too, so
    /// an instance the host has torn down cannot be quietly revived with
    /// stale buffers around.
    static SHUT_DOWN: Cell<bool> = const { Cell::new(false) };
}

/// Decode one codec-encoded input.
fn decode(bytes: &[u8]) -> Result<FfiValue, u32> {
    codec::decode_value(&mut codec::Reader::new(bytes)).map_err(|_| STATUS_ENCODING)
}

/// Run `f` with the instance's cipher, or report `STATUS_STATE` when there
/// is none (never initialised, or shut down).
fn with_cipher<R>(f: impl FnOnce(&GuestCipher) -> Result<R, u32>) -> Result<R, u32> {
    CIPHER.with(|c| {
        let c = c.borrow();
        let cipher = c.as_ref().ok_or(STATUS_STATE)?;
        f(cipher)
    })
}

/// Run `f` with the keyset the mint-side options in `opts` select,
/// resolving it through the cipher (a first use is one `load-keyset` round
/// trip). The options are decoded and validated before the cipher is
/// consulted.
fn with_keyset<R>(
    opts: &[u8],
    f: impl FnOnce(&KeysetCipher<'_, GuestKms>) -> Result<R, u32>,
) -> Result<R, u32> {
    let options = parse_options(decode(opts)?, Side::Mint)?;
    with_cipher(|cipher| {
        let keyset = block_on(options.keyset.resolve(cipher))?;
        f(&keyset)
    })
}

/// Run `f` with the scope the open-side options in `opts` select: the
/// client for `{"any"}`, one keyset's cipher otherwise.
fn with_scope<R>(
    opts: &[u8],
    f: impl FnOnce(Scope<'_, GuestKms>) -> Result<R, u32>,
) -> Result<R, u32> {
    let options = parse_options(decode(opts)?, Side::Open)?;
    with_cipher(|cipher| {
        let scope = block_on(scope_for(cipher, &options.keyset))?;
        f(scope)
    })
}

/// Initialise the instance's cipher from an FFI-codec-encoded config object
/// (see [`crate::config`]). Performs one `load-keyset` round trip through
/// the host transport for the default keyset, and returns that keyset's id
/// (16 raw UUID bytes) as the output buffer. The raw config buffer — which
/// carries the client-key hex — is wiped in place before any network
/// traffic, whatever the outcome.
///
/// Once per instance: a second call, or a call after [`se_shutdown`], is
/// `STATUS_STATE` once the config parses — a config that does not parse is
/// `STATUS_ENCODING` first, like any malformed input. Either way the config
/// buffer is wiped.
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
        // The pointer/length pair is validated first and on its own: a pair
        // that fails here returns before anything touches the range, which
        // is `wipe_input`'s precondition. Only a validated buffer is decoded
        // and, whatever the decode outcome, wiped.
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before it returns and before any wipe of an overlapping range.
        let bytes = unsafe { input(cfg_ptr, cfg_len)? };
        let decoded = decode(bytes);
        // The borrow of the raw buffer ends with `decoded` owned; wipe the
        // buffer now — it holds the client-key hex — before parsing (and
        // before the init round trip), whatever the decode outcome.
        unsafe { wipe_input(cfg_ptr, cfg_len) };
        cipher_init(decoded?)
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

#[cfg(not(feature = "deterministic-kms"))]
fn cipher_init(decoded: FfiValue) -> Result<Vec<u8>, u32> {
    use crate::host::{HostTokenStrategy, WasiHostConnection};
    use crate::status::STATUS_KMS_TRANSPORT;
    use stack_kms::{ClientOpts, StackKms};

    let config = crate::config::parse_config(decoded).map_err(|_| STATUS_ENCODING)?;
    if SHUT_DOWN.with(Cell::get) || CIPHER.with(|c| c.borrow().is_some()) {
        return Err(STATUS_STATE);
    }

    // One request at a time: the host import is synchronous, so concurrency
    // would only interleave nothing; keep the executor honest about it.
    //
    // `max_keys_per_req` stays at the client default (500). That is what
    // bounds "one ZeroKMS call": a batch is assembled once, then
    // `Client::send_chunked` splits it into sequential requests of at most
    // that many keys — so a 1200-leaf record batch is three calls, not one.
    // Raising it here would trade a documented, server-friendly request size
    // for a claim the server need not honour, so the bound is kept and the
    // docs say 500 rather than "one".
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
    if let Some(size) = config.keyset_cache_size {
        builder = builder.keyset_cache_size(size);
    }
    install(block_on(builder.init()).map_err(|e| crate::status::status_for_error(&e))?)
}

/// The `deterministic-kms` build's init: the config buffer is the
/// deterministic source's 32-byte seed and nothing else — no client key, no
/// endpoint, no token, no network. A test artefact, never shipped; see
/// [`crate::deterministic`].
#[cfg(feature = "deterministic-kms")]
fn cipher_init(decoded: FfiValue) -> Result<Vec<u8>, u32> {
    use vitaminc_protected::Controlled;

    let FfiValue::Bytes(seed) = decoded else {
        return Err(STATUS_ENCODING);
    };
    let seed: [u8; 32] = seed
        .risky_ref()
        .as_slice()
        .try_into()
        .map_err(|_| STATUS_ENCODING)?;
    if SHUT_DOWN.with(Cell::get) || CIPHER.with(|c| c.borrow().is_some()) {
        return Err(STATUS_STATE);
    }
    let builder = StackCipher::builder().kms(crate::deterministic::DeterministicSource::new(seed));
    install(block_on(builder.init()).map_err(|e| crate::status::status_for_error(&e))?)
}

/// Install the built cipher as the instance's and return its default
/// keyset's id.
fn install(cipher: GuestCipher) -> Result<Vec<u8>, u32> {
    let default = cipher.default_keyset().keyset_id().as_bytes().to_vec();
    CIPHER.with(|c| *c.borrow_mut() = Some(cipher));
    Ok(default)
}

/// Tear the instance down: drop the cipher — the client key and every
/// loaded keyset's index key are wiped by `ZeroizeOnDrop` — and wipe every
/// buffer the registry still holds, so nothing the host forgot to
/// `se_dealloc` survives in freed memory. Idempotent — a second call is a
/// no-op, and `se_alloc`/`se_dealloc` keep working so the host can
/// still free what it holds. Afterwards every well-formed cipher operation
/// is `STATUS_STATE`, [`se_cipher_init`] included; a malformed one is
/// `STATUS_ENCODING` first, as in any other state.
///
/// The index keys' wipe holds because each `HmacSha256Prf` clone a
/// derivation takes is created and dropped inside one `block_on`'d call,
/// and the guest is single-threaded, so no clone is alive when the host
/// calls this. That is the precondition, not a property of the drop:
/// anything that later parks a PRF clone beyond an ABI call turns this
/// wipe into a no-op for that key.
#[no_mangle]
pub extern "C" fn se_shutdown() {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        SHUT_DOWN.with(|s| s.set(true));
        CIPHER.with(|c| {
            let _ = c.borrow_mut().take();
        });
        buffers::wipe_all();
    }));
}

/// Resolve a keyset selector (a codec-encoded tagged object — see
/// [`crate::options`]; `{"any"}` is not a keyset and is `STATUS_ENCODING`
/// here, before the cipher is consulted) through the cipher's cache and return the keyset's id (16 raw UUID
/// bytes). A first use of a keyset is one `load-keyset` round trip; a host
/// can call this at boot to validate a tenant's keyset and learn its id.
///
/// # Safety
///
/// As for [`se_term`].
#[no_mangle]
pub unsafe extern "C" fn se_keyset(sel_ptr: *const u8, sel_len: u32) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before it returns and before any wipe of an overlapping range.
        let selector = parse_selector(decode(unsafe { input(sel_ptr, sel_len)? })?)?;
        if selector == KeysetSelector::Any {
            return Err(STATUS_ENCODING);
        }
        with_cipher(|cipher| {
            let keyset = block_on(selector.resolve(cipher))?;
            Ok(keyset.keyset_id().as_bytes().to_vec())
        })
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

/// Derive one index term under the keyset `opts` selects: a codec-encoded
/// scalar, a codec-encoded context and a term kind ([`ops::TERM_EQUALITY`]
/// etc.); the output is the term's frozen byte encoding. Under the local
/// HMAC backend this is one PRF/CLLW derivation with no ZeroKMS I/O; that
/// is the backend's property, not this export's contract.
///
/// The context is one part — a string, bytes, or an `i32`/`i64`/`u32`/`u64`
/// — or an array of parts, which may nest as deep as the transport codec
/// allows (`vitaminc_aead_value::transport::MAX_DEPTH` levels, counted from
/// the root of the encoded value; deeper is refused as `STATUS_ENCODING`
/// before the context is parsed). [`stack_encrypt::dynamic::context`] is the one home of
/// that grammar and of which Rust context each shape spells.
/// A part and the one-element array holding it are *different* contexts
/// (`[x]` is PAE-framed, `x` is not), so a probe must pass the context in
/// exactly the shape the field was sealed under: a plan field's context
/// verbatim, a bare part for a Rust leaf sealed under that part.
///
/// # Safety
///
/// Pointer/length pairs should name buffers the host wrote via
/// `se_alloc`; each range is bounds-checked against linear memory (a bad
/// pair returns `STATUS_ENCODING` instead of faulting).
#[no_mangle]
pub unsafe extern "C" fn se_term(
    val_ptr: *mut u8,
    val_len: u32,
    ctx_ptr: *const u8,
    ctx_len: u32,
    kind: u32,
    opt_ptr: *const u8,
    opt_len: u32,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        let value = unsafe { take_plaintext(val_ptr, val_len)? };
        let value = value.as_slice();
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before it returns and before any wipe of an overlapping range.
        let context = unsafe { input(ctx_ptr, ctx_len)? };
        let opts = unsafe { input(opt_ptr, opt_len)? };
        ops::validate::term(value, context, kind)?;
        with_keyset(opts, |keyset| {
            block_on(ops::term(keyset, value, context, kind))
        })
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

/// Encrypt a record (or a batch) per a plan under the keyset `opts` selects
/// — the runtime form of `#[derive(EncryptFrom)]`; see
/// [`ops::encrypt_record`] for the source, plan, and result encodings. All
/// rows and fields seal from **one** batched key request regardless of row
/// count — dispatched as one `generate-data-key` call per 500 keyed leaves,
/// sequentially — and terms derive under the same keyset's index key.
///
/// # Safety
///
/// As for [`se_term`].
#[no_mangle]
pub unsafe extern "C" fn se_encrypt_record(
    src_ptr: *mut u8,
    src_len: u32,
    plan_ptr: *const u8,
    plan_len: u32,
    opt_ptr: *const u8,
    opt_len: u32,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        let source = unsafe { take_plaintext(src_ptr, src_len)? };
        let source = source.as_slice();
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before it returns and before any wipe of an overlapping range.
        let plan = unsafe { input(plan_ptr, plan_len)? };
        let opts = unsafe { input(opt_ptr, opt_len)? };
        ops::validate::record(source, plan)?;
        with_keyset(opts, |keyset| {
            block_on(ops::encrypt_record(keyset, source, plan))
        })
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

/// Decrypt a record (or a batch) produced by [`se_encrypt_record`] under
/// the same plan; only the `"c"` outputs participate. One batched key
/// request per keyset the leaves were sealed under, dispatched as one
/// `retrieve-data-key` call per 500 keyed leaves. `opts` constrains the
/// keyset: `{"any"}` opens leaves from whichever keyset each was sealed
/// under; `{"name"}`, `{"id"}` and `{"default"}` refuse a leaf from any
/// other keyset as `STATUS_FOREIGN_KEYSET`, before any key is retrieved.
/// `opts` may also carry `context`, the context the host expects each
/// record's context field to hold ([`crate::options`]); a record storing
/// another is `STATUS_CONTEXT_MISMATCH`, before any key is retrieved.
/// The output buffer contains **plaintext**: the host copies it out and
/// immediately `se_dealloc`s it (which wipes it).
///
/// # Safety
///
/// As for [`se_term`].
#[no_mangle]
pub unsafe extern "C" fn se_decrypt_record(
    rec_ptr: *const u8,
    rec_len: u32,
    plan_ptr: *const u8,
    plan_len: u32,
    opt_ptr: *const u8,
    opt_len: u32,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before it returns and before any wipe of an overlapping range.
        let record = unsafe { input(rec_ptr, rec_len)? };
        let plan = unsafe { input(plan_ptr, plan_len)? };
        let opts = unsafe { input(opt_ptr, opt_len)? };
        let expected = parse_options(decode(opts)?, Side::Open)?.context;
        ops::validate::record_tree(record, plan, expected.as_ref())?;
        with_scope(opts, |scope| {
            block_on(ops::decrypt_record(scope, record, plan, expected))
        })
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

/// Check a codec-encoded plan without a cipher: `STATUS_ENCODING` for a
/// declaration the engine would refuse ([`ops::plan_check`]), an empty
/// output buffer for one it accepts. Works in every instance state, before
/// [`se_cipher_init`] and after [`se_shutdown`] alike: the generator that
/// asks has no credentials and makes no request.
///
/// # Safety
///
/// As for [`se_term`].
#[no_mangle]
pub unsafe extern "C" fn se_plan_check(plan_ptr: *const u8, plan_len: u32) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: a host-owned range the export was handed; the borrow ends
        // before it returns.
        let plan = unsafe { input(plan_ptr, plan_len)? };
        ops::plan_check(plan).map(|()| Vec::new())
    }))
    .unwrap_or(Err(STATUS_INTERNAL))
    .map_or_else(err_status, ok_buffer)
}

/// The EQL types this build produces, as a codec-encoded
/// `{"targets": [...]}` ([`ops::targets`]). Needs no cipher.
#[no_mangle]
pub extern "C" fn se_targets() -> u64 {
    catch_unwind(AssertUnwindSafe(ops::targets))
        .unwrap_or(Err(STATUS_INTERNAL))
        .map_or_else(err_status, ok_buffer)
}
