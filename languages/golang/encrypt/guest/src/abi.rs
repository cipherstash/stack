//! This guest's wasm export surface: the cipher exports, over the
//! conventions every guest shares (`stack_guest_abi::abi`: `se_alloc` /
//! `se_dealloc`, the buffer registry, the packed `u64` result encoding, the
//! hostile-input validation of every `(ptr, len)` pair). What is specific
//! to this guest:
//!
//! - **Every export handed plaintext wipes that buffer in place before it
//!   returns**, rather than leaving it for `se_dealloc`: [`se_cipher_init`]
//!   (the config carries the client key), and [`se_term`],
//!   [`se_query_term`], [`se_verify`] and [`se_encrypt_record`] (their
//!   value, source and input buffers, and [`se_verify`]'s page of decrypted
//!   values). The host's plaintext therefore lives no longer
//!   than the call, instead of until the host gets round to releasing it.
//!   **A host must not read a plaintext input buffer back after the call, or
//!   pass the same buffer to two calls** — it will be zeros. Option, context,
//!   AAD and plan buffers are not secret and are left untouched.
//! - Output buffers from the decrypt exports contain plaintext; the host must
//!   copy them out and immediately `se_dealloc` (which zeroizes).
//! - **The guest never waits on the network: it steps.** An export that can
//!   reach ZeroKMS ([`se_cipher_init`], [`se_keyset`], [`se_term`],
//!   [`se_encrypt_record`], [`se_decrypt_record`], [`se_query_term`]) runs
//!   its work as a future, polled once. Done, it returns its output as
//!   always. Waiting on a request, it returns `STATUS_NEEDS_IO` instead: the
//!   host takes the paused operation's handle and requests with [`se_io`],
//!   performs them, and hands the responses to [`se_resume`], which returns
//!   the same three ways; or it gives up with [`se_abort`]
//!   (`stack_guest_abi::step`, and [`crate::io`] for the wire form). Several
//!   operations may be paused at once, each under its own handle. A paused
//!   operation owns its inputs — the plaintext among them, wiped when it
//!   ends or is aborted — so a host's input buffers are free once the
//!   export returns, paused or not. A host reads a step's requests (and a
//!   failure's `se_last_error`) before it steps another operation.
//! - **One instance is one client.** [`se_cipher_init`] runs once per
//!   instance: it builds the
//!   `StackCipher<StackKms<HostTokenStrategy, WasiHostConnection>>` (one
//!   `load-keyset` round trip, through the step loop, for the default
//!   keyset) and returns that keyset's id. There is no cipher handle: the
//!   keysets a client uses are selected per call through the options object
//!   ([`crate::options`]), loaded on first use through the cipher's own
//!   cache. Nothing crosses the boundary that the host could allocate,
//!   alias or free.
//! - [`se_shutdown`] is the one lifetime call: it drops every paused
//!   operation, then the cipher (client
//!   key and every loaded index key wiped by `ZeroizeOnDrop`), and wipes
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
//! - During an entry-point call the host's imported function may re-enter
//!   the guest **only** through `se_alloc` (to place the token); calling any
//!   other export from inside a host import is undefined behaviour of the
//!   embedding, not of this module.
//! - **Every export runs through `stack_guest_abi::abi::export`**, so a
//!   failure leaves its full error for `se_last_error`: the code, message,
//!   help and fields of the `stack_encrypt`, `stack_kms` or `stack_auth`
//!   error behind the status, recorded where the status is decided
//!   ([`crate::status::fail_error`] and [`crate::status::fail_dynamic`]),
//!   or a `GuestError` naming what this boundary refused. [`se_shutdown`]
//!   wipes it with every other buffer.
//!
//! There are no whole-value exports: every value crosses as a record under
//! a declaration (ADR-0007, amended). The record and term exports bind
//! fields, so their contexts must be non-empty (`STATUS_ENCODING`
//! otherwise): each is a [`stack_encrypt::NonEmpty`] from the moment it is
//! parsed, and the sealing and opening sides bind that one value.
//! [`se_plan_check`], [`se_targets`] and [`se_operators`] answer the Go
//! generator's questions and need no cipher; nor do [`se_verify`] and [`se_target_limit`], a
//! probabilistic query's two questions, which use no key.
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
//! instance. Between calls it may interleave steps of different operations.

use std::cell::{Cell, RefCell};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::rc::Rc;

use stack_encrypt::StackCipher;
use stack_guest_abi::abi::{export, input, take_plaintext, wipe_input};
use stack_guest_abi::buffers;
use stack_guest_abi::call;
use stack_guest_abi::last_error::{self, malformed, out_of_order};
use stack_guest_abi::status::STATUS_NEEDS_IO;
use stack_guest_abi::step::{self, Operation, Step};

use crate::io;
use crate::ops;
use crate::options::{parse_options, parse_selector, scope_for, KeysetSelector, Side};
#[cfg(not(feature = "deterministic-kms"))]
use crate::status::STATUS_INTERNAL;
#[cfg(not(feature = "deterministic-kms"))]
use stack_encrypt::ErrorPayload;

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
    // of the cipher — no `Send`/`Sync` bounds required. Paused operations
    // share it through the `Rc`, so their handles are dropped before it at
    // shutdown, and the last owner wipes it.
    static CIPHER: RefCell<Option<Rc<GuestCipher>>> = const { RefCell::new(None) };
    /// Set by `se_shutdown`: after it, `se_cipher_init` is refused too, so
    /// an instance the host has torn down cannot be quietly revived with
    /// stale buffers around.
    static SHUT_DOWN: Cell<bool> = const { Cell::new(false) };
    /// Set while an `se_cipher_init` is paused, so a second one is refused
    /// before the first has installed its cipher.
    static INITIALISING: Cell<bool> = const { Cell::new(false) };
}

/// The instance's cipher, or `STATUS_STATE` when there is none (never
/// initialised, still initialising, or shut down).
fn cipher() -> Result<Rc<GuestCipher>, u32> {
    CIPHER.with(|c| c.borrow().clone()).ok_or_else(|| {
        out_of_order("there is no cipher: call se_cipher_init first, and none after se_shutdown")
    })
}

/// Turn what came of an operation's step into an export's result: the
/// output when done, `STATUS_NEEDS_IO` with the step registered for
/// [`se_io`] when paused, the status when failed.
fn deliver(step: Result<Step, u32>) -> Result<Vec<u8>, u32> {
    match step? {
        Step::Done(out) => Ok(out),
        Step::NeedsIo { handle, requests } => {
            let encoded = io::encode_step(handle, &requests);
            drop(requests);
            let encoded = encoded.inspect_err(|_| {
                let _ = step::abort(handle);
            })?;
            step::set_pending(encoded);
            Err(STATUS_NEEDS_IO)
        }
    }
}

/// [`deliver`] an operation's first step.
fn run(work: Operation) -> Result<Vec<u8>, u32> {
    deliver(step::start(work))
}

/// Initialise the instance's cipher from a config frame
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
    export(|| {
        // The pointer/length pair is validated first and on its own: a pair
        // that fails here returns before anything touches the range, which
        // is `wipe_input`'s precondition. Only a validated buffer is parsed
        // and, whatever the outcome, wiped.
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before it returns and before any wipe of an overlapping range.
        let bytes = unsafe { input(cfg_ptr, cfg_len)? };
        // The parser borrows the buffer's strings and owns only what it
        // builds from them, so the borrow ends here; wipe the buffer now —
        // it holds the client key — before the init round trip, whatever
        // the parse outcome.
        let config = parse_init(bytes);
        unsafe { wipe_input(cfg_ptr, cfg_len) };
        cipher_init(config?)
    })
}

#[cfg(not(feature = "deterministic-kms"))]
use crate::config::{parse_config as parse_init, CipherConfig as InitConfig};
#[cfg(feature = "deterministic-kms")]
use crate::deterministic::Seed as InitConfig;
#[cfg(feature = "deterministic-kms")]
fn parse_init(bytes: &[u8]) -> Result<InitConfig, u32> {
    InitConfig::parse(bytes)
}

#[cfg(not(feature = "deterministic-kms"))]
fn cipher_init(config: InitConfig) -> Result<Vec<u8>, u32> {
    use crate::host::{HostTokenStrategy, WasiHostConnection};
    use crate::status::STATUS_KMS_TRANSPORT;
    use stack_kms::{ClientOpts, StackKms};

    if init_refused() {
        return Err(init_out_of_order());
    }

    // One request at a time: a step hands the host one request, and the
    // first version of the step loop keeps it that way. Raising it later
    // changes no ABI: a step's request list can hold several.
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
        .map_err(|e| last_error::record(&e, e.payload(), STATUS_INTERNAL))?;
    let kms = StackKms::<HostTokenStrategy, WasiHostConnection>::connect(
        opts,
        HostTokenStrategy,
        config.client_key,
    )
    .map_err(|e| {
        last_error::record_with(
            &e,
            e.payload(),
            &crate::status::describe,
            STATUS_KMS_TRANSPORT,
        )
    })?;

    let mut builder = StackCipher::builder().kms(kms);
    if let Some(size) = config.keyset_cache_size {
        builder = builder.keyset_cache_size(size);
    }
    let initialising = Initialising::begin();
    run(Box::pin(async move {
        let _initialising = initialising;
        install(
            builder
                .init()
                .await
                .map_err(|e| crate::status::fail_error(&e))?,
        )
    }))
}

/// The `deterministic-kms` build's init: the config buffer is the
/// deterministic source's 32-byte seed and nothing else — no client key, no
/// endpoint, no token, no network. A test artefact, never shipped; see
/// [`crate::deterministic`].
#[cfg(feature = "deterministic-kms")]
fn cipher_init(seed: InitConfig) -> Result<Vec<u8>, u32> {
    if init_refused() {
        return Err(init_out_of_order());
    }
    let builder = StackCipher::builder().kms(seed.source());
    let initialising = Initialising::begin();
    run(Box::pin(async move {
        let _initialising = initialising;
        install(
            builder
                .init()
                .await
                .map_err(|e| crate::status::fail_error(&e))?,
        )
    }))
}

/// Whether an `se_cipher_init` must be refused: after shutdown, with a
/// cipher installed, or with another init paused.
fn init_refused() -> bool {
    SHUT_DOWN.with(Cell::get)
        || INITIALISING.with(Cell::get)
        || CIPHER.with(|c| c.borrow().is_some())
}

/// Marks an init in flight from the moment it starts until its work ends:
/// done, failed or aborted.
struct Initialising;

impl Initialising {
    fn begin() -> Self {
        INITIALISING.with(|i| i.set(true));
        Initialising
    }
}

impl Drop for Initialising {
    fn drop(&mut self) {
        INITIALISING.with(|i| i.set(false));
    }
}

/// `se_cipher_init` called a second time, while one is paused, or after
/// `se_shutdown`.
fn init_out_of_order() -> u32 {
    out_of_order("the cipher is already initialised or initialising, or the instance is shut down")
}

/// Install the built cipher as the instance's and return its default
/// keyset's id.
fn install(cipher: GuestCipher) -> Result<Vec<u8>, u32> {
    // A shutdown that overtook a paused init installs nothing.
    if SHUT_DOWN.with(Cell::get) {
        return Err(init_out_of_order());
    }
    let default = cipher.default_keyset().keyset_id().as_bytes().to_vec();
    CIPHER.with(|c| *c.borrow_mut() = Some(Rc::new(cipher)));
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
/// Every paused operation is dropped first: each holds the cipher, and may
/// hold a PRF clone a derivation took, plaintext, or keys it was handed.
/// Dropping them before the cipher is what makes the cipher's drop the last
/// owner's, and so its wipe real.
#[no_mangle]
pub extern "C" fn se_shutdown() {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        SHUT_DOWN.with(|s| s.set(true));
        step::drop_all();
        CIPHER.with(|c| {
            let _ = c.borrow_mut().take();
        });
        last_error::clear();
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
    export(|| {
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before it returns and before any wipe of an overlapping range.
        let selector = parse_selector(unsafe { input(sel_ptr, sel_len)? })?;
        if selector == KeysetSelector::Any {
            return Err(malformed(r#"{"any"} is not a keyset"#));
        }
        let cipher = cipher()?;
        run(Box::pin(async move {
            let keyset = selector.resolve(&cipher).await?;
            Ok(keyset.keyset_id().as_bytes().to_vec())
        }))
    })
}

/// Derive one index term under the keyset `opts` selects: a codec-encoded
/// scalar, a codec-encoded context and a term kind ([`ops::TERM_EQUALITY`]
/// etc.); the output is the term's frozen byte encoding. Under the local
/// HMAC backend this is one PRF/CLLW derivation with no ZeroKMS I/O; that
/// is the backend's property, not this export's contract.
///
/// The context is one part — a string, bytes, or an `i32`/`i64`/`u32`/`u64`
/// — or an array of parts, which may nest as deep as the transport codec
/// allows (`stack_encrypt::dynamic::frame::MAX_DEPTH` levels, counted from
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
    export(|| {
        let value = unsafe { take_plaintext(val_ptr, val_len)? };
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before it returns and before any wipe of an overlapping range.
        let context = unsafe { input(ctx_ptr, ctx_len)? }.to_vec();
        let opts = unsafe { input(opt_ptr, opt_len)? };
        ops::validate::term(&value, &context, kind)?;
        let options = parse_options(opts, Side::Mint)?;
        let cipher = cipher()?;
        run(Box::pin(async move {
            let keyset = options.keyset.resolve(&cipher).await?;
            ops::term(&keyset, &value, &context, kind).await
        }))
    })
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
    export(|| {
        let source = unsafe { take_plaintext(src_ptr, src_len)? };
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before it returns and before any wipe of an overlapping range.
        let plan = unsafe { input(plan_ptr, plan_len)? }.to_vec();
        let opts = unsafe { input(opt_ptr, opt_len)? };
        ops::validate::record(&source, &plan)?;
        let options = parse_options(opts, Side::Mint)?;
        let cipher = cipher()?;
        run(Box::pin(async move {
            let keyset = options.keyset.resolve(&cipher).await?;
            ops::encrypt_record(&keyset, &source, &plan).await
        }))
    })
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
    export(|| {
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before it returns and before any wipe of an overlapping range.
        let record = unsafe { input(rec_ptr, rec_len)? }.to_vec();
        let plan = unsafe { input(plan_ptr, plan_len)? }.to_vec();
        let opts = unsafe { input(opt_ptr, opt_len)? };
        let options = parse_options(opts, Side::Open)?;
        ops::validate::record_tree(&record, &plan, options.context.as_ref())?;
        let cipher = cipher()?;
        run(Box::pin(async move {
            let scope = scope_for(&cipher, &options.keyset).await?;
            ops::decrypt_record(scope, &record, &plan, options.context).await
        }))
    })
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
    export(|| {
        // SAFETY: a host-owned range the export was handed; the borrow ends
        // before it returns.
        let plan = unsafe { input(plan_ptr, plan_len)? };
        ops::plan_check(plan).map(|()| Vec::new())
    })
}

/// Derive the query term for one plan field, an operator and its input
/// under the keyset `opts` selects ([`ops::query_term`]): a codec-encoded
/// input (one value, or for `between` a list of two), the codec-encoded
/// plan, and the field's and the operator's names (UTF-8 bytes) in; the
/// term's codec-encoded object out. An operator the field does not answer
/// is `STATUS_ENCODING` naming the field, as a mistyped value is, before
/// the cipher is consulted; the refusals the typed path makes before a term
/// exists (match text that cuts no token or does not normalize) are
/// `STATUS_TERM`, also before the cipher. A range the wrong way round is
/// not refused: it matches no row, as SQL's `BETWEEN` does. The input
/// buffer is wiped in place.
///
/// # Safety
///
/// As for [`se_term`].
#[no_mangle]
pub unsafe extern "C" fn se_query_term(
    val_ptr: *mut u8,
    val_len: u32,
    plan_ptr: *const u8,
    plan_len: u32,
    field_ptr: *const u8,
    field_len: u32,
    op_ptr: *const u8,
    op_len: u32,
    opt_ptr: *const u8,
    opt_len: u32,
) -> u64 {
    export(|| {
        let value = unsafe { take_plaintext(val_ptr, val_len)? };
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before it returns and before any wipe of an overlapping range.
        let plan = unsafe { input(plan_ptr, plan_len)? }.to_vec();
        let field = unsafe { input(field_ptr, field_len)? }.to_vec();
        let operator = unsafe { input(op_ptr, op_len)? }.to_vec();
        let opts = unsafe { input(opt_ptr, opt_len)? };
        ops::validate::query_term(&value, &plan, &field, &operator)?;
        let options = parse_options(opts, Side::Mint)?;
        let cipher = cipher()?;
        run(Box::pin(async move {
            let keyset = options.keyset.resolve(&cipher).await?;
            ops::query_term(&keyset, &value, &plan, &field, &operator).await
        }))
    })
}

/// Open the rows a read of a document field returned ([`ops::json_open`]):
/// the codec-encoded rows (a list per database row of entries), the
/// codec-encoded plan, the field's name (UTF-8 bytes) and the codec-encoded
/// read request in, under the keyset `opts` selects (the keyset the read
/// was prepared under); a codec-encoded list per row of JSON texts out. The
/// output buffer contains **plaintext**: the host copies it out and
/// immediately `se_dealloc`s it (which wipes it). The rows and the request
/// hold no plaintext and are left untouched.
///
/// # Safety
///
/// As for [`se_term`].
#[no_mangle]
pub unsafe extern "C" fn se_json_open(
    rows_ptr: *const u8,
    rows_len: u32,
    plan_ptr: *const u8,
    plan_len: u32,
    field_ptr: *const u8,
    field_len: u32,
    req_ptr: *const u8,
    req_len: u32,
    opt_ptr: *const u8,
    opt_len: u32,
) -> u64 {
    export(|| {
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before it returns.
        let rows = unsafe { input(rows_ptr, rows_len)? }.to_vec();
        let plan = unsafe { input(plan_ptr, plan_len)? }.to_vec();
        let field = unsafe { input(field_ptr, field_len)? }.to_vec();
        let request = unsafe { input(req_ptr, req_len)? }.to_vec();
        let opts = unsafe { input(opt_ptr, opt_len)? };
        ops::validate::json_open(&rows, &plan, &field, &request)?;
        let options = parse_options(opts, Side::Mint)?;
        let cipher = cipher()?;
        run(Box::pin(async move {
            let keyset = options.keyset.resolve(&cipher).await?;
            ops::json_open(&keyset, &rows, &plan, &field, &request).await
        }))
    })
}

/// Verify a page of decrypted values against a probabilistic query
/// ([`ops::verify`]): the query's codec-encoded input and a codec-encoded
/// list of values, the codec-encoded plan, and the field's and the
/// operator's names in; a codec-encoded list of booleans out, one per value.
/// Both plaintext buffers, the input and the values, are wiped in place. An
/// exact operator has nothing to verify and is `STATUS_ENCODING`. Needs no
/// cipher: it works in every instance state, as [`se_plan_check`] does.
///
/// # Safety
///
/// As for [`se_term`].
#[no_mangle]
pub unsafe extern "C" fn se_verify(
    in_ptr: *mut u8,
    in_len: u32,
    vals_ptr: *mut u8,
    vals_len: u32,
    plan_ptr: *const u8,
    plan_len: u32,
    field_ptr: *const u8,
    field_len: u32,
    op_ptr: *const u8,
    op_len: u32,
) -> u64 {
    export(|| {
        // Both buffers are taken, and so wiped, before either result is
        // acted on: a bad query pointer must not leave the page of
        // decrypted values unwiped behind an early return.
        let query = unsafe { take_plaintext(in_ptr, in_len) };
        let values = unsafe { take_plaintext(vals_ptr, vals_len) };
        let (query, values) = (query?, values?);
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before it returns.
        let plan = unsafe { input(plan_ptr, plan_len)? };
        let field = unsafe { input(field_ptr, field_len)? };
        let operator = unsafe { input(op_ptr, op_len)? };
        ops::verify(query.as_slice(), values.as_slice(), plan, field, operator)
    })
}

/// How many rows a probabilistic query should fetch for `want` of them to
/// verify ([`ops::target_limit`]): the term's bytes as [`se_query_term`]
/// returned them, the codec-encoded statistics, the codec-encoded plan,
/// and the field's and the operator's names in, with `want`; the
/// codec-encoded limit out, an unsigned integer or null. An exact operator
/// has no fetch to size and is `STATUS_ENCODING`. Needs no cipher.
///
/// # Safety
///
/// As for [`se_term`].
#[no_mangle]
pub unsafe extern "C" fn se_target_limit(
    term_ptr: *const u8,
    term_len: u32,
    stats_ptr: *const u8,
    stats_len: u32,
    plan_ptr: *const u8,
    plan_len: u32,
    field_ptr: *const u8,
    field_len: u32,
    op_ptr: *const u8,
    op_len: u32,
    want: u64,
) -> u64 {
    export(|| {
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before it returns.
        let term = unsafe { input(term_ptr, term_len)? };
        let stats = unsafe { input(stats_ptr, stats_len)? };
        let plan = unsafe { input(plan_ptr, plan_len)? };
        let field = unsafe { input(field_ptr, field_len)? };
        let operator = unsafe { input(op_ptr, op_len)? };
        ops::target_limit(term, stats, plan, field, operator, want)
    })
}

/// The EQL types this build knows, as a codec-encoded
/// `{"targets": [...]}` ([`ops::targets`]): the catalog in the `eql` build,
/// nothing in the other. Needs no cipher.
#[no_mangle]
pub extern "C" fn se_targets() -> u64 {
    export(ops::targets)
}

/// The operators one plan field answers ([`ops::operators`]): the
/// codec-encoded plan and the field's name (UTF-8 bytes) in, a codec-encoded
/// list of operator objects out. A field the plan does not have is
/// `STATUS_ENCODING`. Needs no cipher: it works in every instance state, as
/// [`se_plan_check`] does.
///
/// # Safety
///
/// As for [`se_term`].
#[no_mangle]
pub unsafe extern "C" fn se_operators(
    plan_ptr: *const u8,
    plan_len: u32,
    field_ptr: *const u8,
    field_len: u32,
) -> u64 {
    export(|| {
        // SAFETY: host-owned ranges the export was handed; the borrows end
        // before they return.
        let plan = unsafe { input(plan_ptr, plan_len)? };
        let field = unsafe { input(field_ptr, field_len)? };
        ops::operators(plan, field)
    })
}

/// The step a paused export left: its handle and the requests it waits on,
/// as a packed buffer ([`crate::io`]), handed over once — the slot is
/// emptied, so a second call returns zero, as does a call with no step
/// waiting. The host calls it after `STATUS_NEEDS_IO`, before it runs any
/// other export, copies the buffer out and releases it with `se_dealloc`
/// (which wipes it: it carries the bearer token).
#[no_mangle]
pub extern "C" fn se_io() -> u64 {
    match step::take_pending() {
        Some((ptr, len)) => call::pack_buffer(ptr as usize as u32, len as u32),
        None => 0,
    }
}

/// Hand a paused operation the responses to the requests its last step
/// asked for ([`crate::io`] has the frame), and run its next step. Returns
/// as the export that started it does: the output when done,
/// `STATUS_NEEDS_IO` when paused again (under the same handle), or the
/// status of its failure. The responses buffer can carry wrapped keys and
/// is wiped in place. A handle that names no paused operation is
/// `STATUS_STATE`; responses that do not decode, or are not one per
/// request, are `STATUS_ENCODING`, and the operation is dropped.
///
/// # Safety
///
/// As for [`se_term`].
#[no_mangle]
pub unsafe extern "C" fn se_resume(handle: u64, resp_ptr: *mut u8, resp_len: u32) -> u64 {
    export(|| {
        let bytes = unsafe { take_plaintext(resp_ptr, resp_len) };
        let responses = bytes.and_then(|bytes| io::decode_responses(&bytes));
        let responses = responses.inspect_err(|_| {
            let _ = step::abort(handle);
        })?;
        deliver(step::resume(handle, responses))
    })
}

/// Give up on a paused operation: drop it, wiping everything it held. An
/// empty output; `STATUS_STATE` for a handle that names no paused
/// operation (one that finished, failed or was aborted).
#[no_mangle]
pub extern "C" fn se_abort(handle: u64) -> u64 {
    export(|| step::abort(handle).map(|()| Vec::new()))
}
