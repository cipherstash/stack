//! No heap block the dynamic paths and the JSON index free still holds
//! plaintext, or (for the JSON index) the data key a document is sealed
//! under.
//!
//! The JSON index's tests ([`json_index`]) cover sealing under either root
//! option, opening a document whole, a subtree read, an extraction and the
//! containment and equality needles. One thing they leave out: the path a
//! caller hands `AtPath` as an owned `String` is cloned by the query
//! builder and dropped by the plan chain unwiped, since the chain only knows
//! `P: AsRef<str>`; the test passes a `&'static str`.
//!
//! This binary installs its own global allocator: a spy that, while a test
//! watches its own thread, scans every block freed on that thread for a
//! marker the test's plaintext carries. A block freed with the marker still
//! in it is plaintext a later allocation can read back, and fails the test.
//! It is the guard for heap residue: the Go SDK's residency test reads the
//! guest's linear memory after the fact, where allocator metadata and reuse
//! have already overwritten most freed chunks, so it cannot see one.
//!
//! One free is excluded by name: vitaminc-encrypt 0.6.0's aws-lc backend
//! (`backend::aws_lc::CipherKey::seal`, native builds only) frees an unwiped
//! plaintext buffer on every seal. That is vitaminc's to fix, not this
//! crate's; the spy reports how many it skipped, and recognises them by
//! their backtrace, so a build without symbols fails rather than passes.
//!
//! The stack is not watched, and is kept out of the picture: a future the
//! operation boxes (`Pending`'s `IntoFuture`) is built on the stack and
//! copied into its box with every byte it does not initialise, so a watch
//! first zeroes the stack below it ([`scrub_stack`]); otherwise residue from
//! earlier work (a hash's block buffer after a PRF over a marked key name)
//! would reach a heap block and be blamed on the operation that boxed it.
//! For the same reason the spy never copies what it looks for onto the
//! stack: it runs on every free, from inside the watched operation, and a
//! copy left in its dead frame would be picked up the same way by a future
//! built later at that depth (see [`holds_key`]).
//!
//! A free is what the spy sees, so a block that is never freed (a
//! `mem::forget`, a `Box::leak`) passes [`watched`]. [`watched_for_leaks`]
//! closes that for the tests that use it: it also records every block
//! allocated during the watch, and fails if one still live when the watch
//! ends holds the marker. It is opt-in because a watch that returns
//! plaintext to its caller keeps that plaintext live on purpose.
//!
//! Unix only: the spy scans a freed block with libc's `memmem`, not as a
//! Rust slice (see [`holds_mark`]).
#![cfg(all(feature = "dynamic", unix))]

mod common;

use stack_encrypt::AsProtectedRef as _;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use common::frames::{frame, object};
use stack_encrypt::dynamic::{query_term, record, verify, NoTargets, Op, ValueFrame};
use stack_encrypt::nonempty;
use vitaminc_aead::plaintext::{Physical, Raw};
use vitaminc_aead::Frame;

/// What every plaintext under test carries.
const MARK: &[u8] = b"zq-heap-marker-7f3a9c";

thread_local! {
    static WATCHING: Cell<bool> = const { Cell::new(false) };
    static BUSY: Cell<bool> = const { Cell::new(false) };
}

/// Held for the whole of a watch: the test harness runs tests on several
/// threads, and the findings below are one set.
static GATE: Mutex<()> = Mutex::new(());

/// The marked frees seen, as backtraces; and how many were vitaminc's.
static FOUND: Mutex<Vec<String>> = Mutex::new(Vec::new());
static UPSTREAM: Mutex<usize> = Mutex::new(0);

/// The data key the JSON tests' key source last handed out, which a freed
/// block must not hold either (see [`json_index`]). Set outside any
/// allocation: a fixed array behind a lock.
static KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

/// How many blocks [`watched_for_leaks`] can track at once. A watch that
/// outgrows it fails rather than passing on a partial record.
const LIVE_SLOTS: usize = 16 * 1024;

/// The blocks allocated on the watched thread during a
/// [`watched_for_leaks`] watch and not yet freed, as `(address, size)`. A
/// fixed array behind a lock: recording one must not allocate.
struct Live {
    blocks: [(usize, usize); LIVE_SLOTS],
    len: usize,
    overflowed: bool,
}

static LIVE: Mutex<Live> = Mutex::new(Live {
    blocks: [(0, 0); LIVE_SLOTS],
    len: 0,
    overflowed: false,
});

/// Whether [`LIVE`] is recording. Read on every allocation and free, on
/// every thread, so a block the watched thread allocated is forgotten
/// wherever it is freed.
static TRACKING: AtomicBool = AtomicBool::new(false);

/// The vitaminc frame whose free is excluded (see the module docs).
const UPSTREAM_SEAL: &str = "vitaminc_encrypt::backend::aws_lc::CipherKey::seal";

/// Whether the `len` bytes at `ptr` hold [`MARK`]. A freed block can hold
/// bytes Rust never initialised (a `Vec`'s spare capacity, a struct's
/// padding), and reading those through a `&[u8]` is undefined behaviour, so
/// the scan is libc's `memmem`, which reads the block as plain memory.
///
/// # Safety
///
/// `ptr` must point to `len` allocated bytes.
unsafe fn holds_mark(ptr: *const u8, len: usize) -> bool {
    extern "C" {
        fn memmem(
            haystack: *const c_void,
            haystack_len: usize,
            needle: *const c_void,
            needle_len: usize,
        ) -> *mut c_void;
    }
    !memmem(ptr.cast(), len, MARK.as_ptr().cast(), MARK.len()).is_null()
}

/// Whether the `len` bytes at `ptr` hold the data key in [`KEY`], read as
/// [`holds_mark`] reads.
///
/// The key is searched for where [`KEY`] holds it, under the lock, and never
/// copied out. This runs on every free during a watch, at whatever depth
/// the operation freed from; a copy in this frame would stay on the dead
/// stack, and a future the operation builds there next (a `JoinAll` whose
/// unused variant space the build leaves as it found it) would carry the
/// key into its box, which the spy would then report as the operation's.
///
/// # Safety
///
/// `ptr` must point to `len` allocated bytes.
unsafe fn holds_key(ptr: *const u8, len: usize) -> bool {
    BUSY.with(|busy| busy.set(true));
    let found = KEY
        .lock()
        .is_ok_and(|key| key.as_ref().is_some_and(|key| find(ptr, len, key)));
    BUSY.with(|busy| busy.set(false));
    found
}

/// [`holds_mark`] for any `needle`.
///
/// # Safety
///
/// `ptr` must point to `len` allocated bytes.
unsafe fn find(ptr: *const u8, len: usize, needle: &[u8]) -> bool {
    extern "C" {
        fn memmem(
            haystack: *const c_void,
            haystack_len: usize,
            needle: *const c_void,
            needle_len: usize,
        ) -> *mut c_void;
    }
    !memmem(ptr.cast(), len, needle.as_ptr().cast(), needle.len()).is_null()
}

struct Spy;

unsafe impl GlobalAlloc for Spy {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Zeroed, so a block holds only what was written into it during its
        // own lifetime: the system allocator hands memory out as its last
        // owner left it, and a block that is only partly written (a boxed
        // future's state, a `Vec`'s spare capacity) would otherwise show
        // what an earlier, excluded free left there and be blamed for it.
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null()
            && TRACKING.load(Ordering::SeqCst)
            && WATCHING.with(Cell::get)
            && !BUSY.with(Cell::get)
        {
            if let Ok(mut live) = LIVE.lock() {
                if live.len < LIVE_SLOTS {
                    let at = live.len;
                    live.blocks[at] = (ptr as usize, layout.size());
                    live.len += 1;
                } else {
                    live.overflowed = true;
                }
            }
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let watching = WATCHING.with(Cell::get) && !BUSY.with(Cell::get);
        if watching {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes until
            // the `System.dealloc` below.
            if holds_mark(ptr, layout.size()) || holds_key(ptr, layout.size()) {
                BUSY.with(|busy| busy.set(true));
                let trace = std::backtrace::Backtrace::force_capture().to_string();
                // Symbol demangling differs by platform: Linux writes
                // `<…::CipherKey>::seal`, macOS `…::CipherKey::seal`. Match
                // with the angle brackets dropped.
                if trace.replace(['<', '>'], "").contains(UPSTREAM_SEAL) {
                    *UPSTREAM.lock().unwrap() += 1;
                } else {
                    FOUND
                        .lock()
                        .unwrap()
                        .push(format!("{} bytes freed unwiped:\n{trace}", layout.size()));
                }
                BUSY.with(|busy| busy.set(false));
            }
        }
        if TRACKING.load(Ordering::SeqCst) {
            if let Ok(mut live) = LIVE.lock() {
                let len = live.len;
                if let Some(at) = live.blocks[..len].iter().position(|b| b.0 == ptr as usize) {
                    live.blocks[at] = live.blocks[len - 1];
                    live.len -= 1;
                }
            }
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static SPY: Spy = Spy;

/// Zero the stack below the caller's frame, so that a future `f` boxes
/// copies zeros rather than what earlier work left there (see the module
/// docs). Deep enough to cover every frame an operation and its runtime
/// nest beneath [`watched`].
#[inline(never)]
fn scrub_stack() {
    let mut pad = [0u8; 256 * 1024];
    for byte in pad.iter_mut() {
        // SAFETY: a volatile write to a live local, so the zeroing is not
        // elided as a dead store.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::hint::black_box(&pad);
}

/// Run `f` with this thread watched, and fail if any block it freed held
/// the marker.
fn watched<T>(what: &str, f: impl FnOnce() -> T) -> T {
    let _gate = gate();
    watched_in_gate(what, f)
}

/// Take [`GATE`], which serializes every watch: the thread-local flags
/// keep other threads' allocations out of a watch, but [`FOUND`],
/// [`UPSTREAM`], [`LIVE`] and [`TRACKING`] are shared, and a test running
/// alongside on another thread (plain `cargo test`) would otherwise reset
/// or switch them off mid-watch. A test that panicked holding it (a
/// `should_panic` control) poisons it; the state it guards is reset on
/// entry, so the poison is ignored.
fn gate() -> std::sync::MutexGuard<'static, ()> {
    GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// [`watched`], for a caller already holding [`GATE`].
fn watched_in_gate<T>(what: &str, f: impl FnOnce() -> T) -> T {
    FOUND.lock().unwrap().clear();
    *UPSTREAM.lock().unwrap() = 0;
    scrub_stack();
    WATCHING.with(|on| on.set(true));
    let out = f();
    WATCHING.with(|on| on.set(false));
    let found = std::mem::take(&mut *FOUND.lock().unwrap());
    let upstream = std::mem::take(&mut *UPSTREAM.lock().unwrap());
    if upstream > 0 {
        eprintln!("{what}: skipped {upstream} unwiped frees in vitaminc's aws-lc seal");
    }
    assert!(
        found.is_empty(),
        "{what}: {} heap blocks were freed with plaintext in them:\n{}",
        found.len(),
        found.join("\n---\n")
    );
    out
}

/// [`watched`], and also fail if a block allocated during the watch is
/// still live when it ends and holds the marker: plaintext leaked rather
/// than freed, which the free-time scan cannot see. `f` returns nothing,
/// so nothing it built is meant to outlive it.
fn watched_for_leaks(what: &str, f: impl FnOnce()) {
    // Held from the reset of `LIVE` to the last read of it, so no other
    // watch can clear this one's records or turn `TRACKING` off under it.
    let _gate = gate();
    {
        let mut live = LIVE.lock().unwrap();
        live.len = 0;
        live.overflowed = false;
    }
    TRACKING.store(true, Ordering::SeqCst);
    // Stop recording whether `watched` returns or panics.
    struct Stop;
    impl Drop for Stop {
        fn drop(&mut self) {
            TRACKING.store(false, Ordering::SeqCst);
        }
    }
    let stop = Stop;
    watched_in_gate(what, f);
    drop(stop);
    // Read under the lock and released before asserting, so a failing
    // assertion (the negative control's, by design) does not poison
    // `LIVE` for the watches that follow in the same process.
    let (overflowed, leaked) = {
        let live = LIVE.lock().unwrap();
        let leaked: Vec<usize> = live.blocks[..live.len]
            .iter()
            // SAFETY: every recorded block is still allocated: a free
            // removes its record while `TRACKING` is on, and it was on
            // until `stop`.
            .filter(|(ptr, size)| unsafe { holds_mark(*ptr as *const u8, *size) })
            .map(|(_, size)| *size)
            .collect();
        (live.overflowed, leaked)
    };
    assert!(
        !overflowed,
        "{what}: more than {LIVE_SLOTS} blocks were live at once; raise LIVE_SLOTS"
    );
    assert!(
        leaked.is_empty(),
        "{what}: {} heap blocks allocated during the watch are still live with plaintext in them (sizes {leaked:?})",
        leaked.len()
    );
}

fn marked(tail: &str) -> String {
    format!("{}-{tail}", std::str::from_utf8(MARK).unwrap())
}

fn null() -> ValueFrame {
    frame(Raw(None, Physical::Null))
}

fn spec<'a>(field: &'a str, outputs: &[&str], ty: Option<&str>) -> (&'a str, ValueFrame) {
    let mut entries = vec![
        ("context", frame(vec!["users", field])),
        ("outputs", frame(outputs.to_vec())),
    ];
    if let Some(ty) = ty {
        entries.push(("type", frame(ty)));
    }
    (field, object(entries))
}

fn plan() -> record::Plan {
    record::plan(
        object(vec![
            spec("email", &["c", "eq", "match", "ore"], Some("string")),
            spec("doc", &["c"], None),
            spec("id", &["passthrough"], None),
        ])
        .as_protected_ref(),
    )
    .unwrap()
}

/// A row with a marked scalar field, a marked nested object field, and a
/// passthrough, as its frame. The strings it is built from are dropped
/// before anything is watched: they are the test's input, not the engine's.
///
/// The nested object ends with a value of several KiB after its marked
/// children, so the buffer its frame is joined into grows while it already
/// holds plaintext.
fn row() -> ValueFrame {
    object(vec![
        ("email", frame(marked("email"))),
        (
            "doc",
            object(vec![
                ("k", frame(marked("doc"))),
                ("n", frame(vec![frame(marked("nested")), null()])),
                ("big", frame("x".repeat(8 * 1024))),
            ]),
        ),
        ("id", frame(7u64)),
    ])
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

#[test]
fn a_record_encrypted_from_a_value_frame_leaves_no_plaintext_on_the_heap() {
    let rt = runtime();
    let cipher = rt.block_on(common::stack_cipher());
    let keyset = cipher.default_keyset();
    let plan = plan();
    let source = row();
    watched("record::encrypt (ValueFrame)", || {
        rt.block_on(async {
            record::encrypt(&keyset, &source, &plan)
                .unwrap()
                .await
                .unwrap()
        });
        drop(source);
    });
}

#[test]
fn a_record_encrypted_from_a_raw_frame_leaves_no_plaintext_on_the_heap() {
    let rt = runtime();
    let cipher = rt.block_on(common::stack_cipher());
    let keyset = cipher.default_keyset();
    let plan = plan();
    let source = row();
    watched("record::encrypt (Frame)", || {
        let frame = Frame::parse(source.risky_ref()).unwrap();
        rt.block_on(async {
            record::encrypt(&keyset, frame, &plan)
                .unwrap()
                .await
                .unwrap()
        });
        drop(source);
    });
}

#[test]
fn a_record_decrypted_with_a_nested_field_leaves_no_plaintext_on_the_heap() {
    let rt = runtime();
    let cipher = rt.block_on(common::stack_cipher());
    let keyset = cipher.default_keyset();
    let plan = plan();
    let sealed = rt.block_on(async {
        record::encrypt(&keyset, row(), &plan)
            .unwrap()
            .await
            .unwrap()
    });
    watched("record::decrypt", || {
        let opened = rt.block_on(async {
            record::decrypt(&cipher, sealed, &plan, None)
                .unwrap()
                .await
                .unwrap()
        });
        // The opened record holds the plaintext until here, in `Protected`.
        assert!(opened
            .risky_ref()
            .windows(MARK.len())
            .any(|window| window == MARK));
        drop(opened);
    });
}

/// A valid first row is followed by an authenticated value of the wrong type.
/// The failed batch returns no output and releases its decoded prefix cleanly.
#[test]
fn a_late_read_type_failure_leaves_no_plaintext_on_the_heap() {
    let rt = runtime();
    let cipher = rt.block_on(common::stack_cipher());
    let keyset = cipher.default_keyset();
    let writer =
        record::plan(object(vec![spec("value", &["c"], None)]).as_protected_ref()).unwrap();
    let reader =
        record::plan(object(vec![spec("value", &["c"], Some("string"))]).as_protected_ref())
            .unwrap();
    let source = frame(vec![
        object(vec![("value", frame(marked("first-row")))]),
        object(vec![("value", frame(true))]),
    ]);
    let sealed = rt.block_on(async { record::encrypt(&keyset, source, &writer).unwrap().await });
    let sealed = sealed.unwrap();
    watched("late authenticated read type failure", || {
        let result = rt.block_on(async {
            record::decrypt(&cipher, sealed, &reader, None)
                .unwrap()
                .await
        });
        assert!(matches!(
            result,
            Err(stack_encrypt::Error::Plan(
                stack_encrypt::plan::PlanError::FieldType { .. }
            ))
        ));
    });
}

/// The owned collection conversion: a column of owned strings is held by
/// the conversion's guard, handed to each element's declaration by
/// reference, and wiped before the pending is returned. Nothing it frees
/// may still hold a value.
#[test]
fn an_owned_column_encrypted_leaves_no_plaintext_on_the_heap() {
    use stack_encrypt::{Ciphertext, EncryptInto};
    let rt = runtime();
    let cipher = rt.block_on(common::stack_cipher());
    let keyset = cipher.default_keyset();
    let column = vec![marked("first"), marked("second"), marked("third")];
    watched("Vec<String> -> Vec<Ciphertext>", || {
        let sealed: Vec<Ciphertext> = rt
            .block_on(async { column.encrypt_into(&keyset).await })
            .unwrap();
        assert_eq!(sealed.len(), 3);
    });
}

/// A column whose later element fails after its key arrived, here with a
/// type the destination does not accept: the element recovered before it is
/// wiped rather than dropped as it is.
#[test]
fn a_late_type_failure_in_an_owned_column_leaves_no_plaintext_on_the_heap() {
    use stack_encrypt::DecryptFrom;
    let rt = runtime();
    let cipher = rt.block_on(common::stack_cipher());
    let keyset = cipher.default_keyset();
    let column = rt.block_on(async {
        vec![
            keyset.encrypt(marked("first-row")).await.unwrap(),
            keyset.encrypt(true).await.unwrap(),
        ]
    });
    watched(
        "late type failure in Vec<Ciphertext> -> Vec<String>",
        || {
            let result = rt.block_on(async { Vec::<String>::decrypt_from(column, &keyset).await });
            assert!(matches!(
                result,
                Err(stack_encrypt::Error::OpenedType { .. })
            ));
        },
    );
}

#[test]
fn a_query_term_leaves_no_plaintext_on_the_heap() {
    let rt = runtime();
    let cipher = rt.block_on(common::stack_cipher());
    let keyset = cipher.default_keyset();
    let plan = plan();
    // The order operators answer over integers alone, which carry no
    // marker; equality and match read text.
    for operator in [Op::Eq, Op::Matches] {
        let query = frame(marked("query"));
        watched(&format!("query_term ({operator:?})"), || {
            rt.block_on(async {
                query_term(&keyset, &plan, "email", operator, &query, &NoTargets)
                    .unwrap()
                    .await
                    .unwrap()
            });
            drop(query);
        });
    }
}

/// The typed chain prepares an equality query before any key is requested
/// by normalizing a copy of the value (`Supports<Eq, S>` is `S: Clone`).
/// The copy is wiped as it is read, so nothing of the query reaches freed
/// memory. A typed `Matches` query is not watched here: `matching` views
/// its owned text and drops it unwiped, which #1593 tracks.
#[test]
fn a_typed_query_leaves_no_plaintext_on_the_heap() {
    use stack_encrypt::{op, Equality, Plan};
    let rt = runtime();
    let cipher = rt.block_on(common::stack_cipher());
    let plan = Plan::context("users/email")
        .with::<String, _>(Equality)
        .build()
        .unwrap();
    // The caller's own value stays alive across the watch: the chain works
    // on its copy, and what the test owns is the test's residue, not the
    // engine's.
    let query = marked("query");
    watched("typed query (Eq)", || {
        rt.block_on(async { cipher.query(op::Eq, &query).on(&plan).await.unwrap() });
    });
    drop(query);
}

/// An order term takes its plaintext by value, so the engine owns the
/// `String` or `Vec<u8>` it is handed (a clone of the caller's, on the
/// target path) and must wipe it. Both paths hand a bare one; the engine
/// wraps it in `Zeroizing` on receipt, before anything can fail.
#[test]
fn an_order_term_of_owned_text_or_bytes_leaves_no_plaintext_on_the_heap() {
    let rt = runtime();
    let cipher = rt.block_on(common::stack_cipher());
    let keyset = cipher.default_keyset();
    // Each plaintext is built before its watch: building one can free a
    // partly written copy, which is the test's own residue, not the term's.
    let text = marked("order");
    watched("ore_term (String)", || {
        rt.block_on(async { keyset.ore_term(text, nonempty!("users/surname")).await })
            .unwrap();
    });
    let text = marked("order");
    watched("ope_term (String)", || {
        rt.block_on(async { keyset.ope_term(text, nonempty!("users/surname")).await })
            .unwrap();
    });
    let bytes = marked("order").into_bytes();
    watched("ore_term (Vec<u8>)", || {
        rt.block_on(async { keyset.ore_term(bytes, nonempty!("users/blob")).await })
            .unwrap();
    });
    let bytes = marked("order").into_bytes();
    watched("ope_term (Vec<u8>)", || {
        rt.block_on(async { keyset.ope_term(bytes, nonempty!("users/blob")).await })
            .unwrap();
    });
}

#[test]
fn verify_leaves_no_plaintext_on_the_heap() {
    let plan = plan();
    let query = frame(marked("query"));
    let page = frame(vec![frame(marked("page")), null()]);
    watched("verify", || {
        let values = page.elements().unwrap();
        let matched = verify(&plan, "email", Op::Matches, &query, values, &NoTargets).unwrap();
        assert_eq!(matched.len(), 2);
        drop(page);
        drop(query);
    });
}

/// A resolver holding `JsonSearch` alone, for checking a document
/// field's operators: a check derives nothing, so nothing here runs.
struct Documents;

impl stack_encrypt::dynamic::TargetResolver for Documents {
    fn targets(&self) -> Vec<stack_encrypt::dynamic::TargetDescriptor> {
        vec![stack_encrypt::dynamic::TargetDescriptor::new(
            "JsonSearch",
            "json",
            "",
            Some(stack_encrypt::dynamic::ValueKind::Json),
            "public.eql_v4_json_search",
            vec!["json".to_string()],
            Some("JsonSearchQuery".to_string()),
            Some("eql_v4.query_json".to_string()),
            true,
            None,
        )
        .with_leaf_query_sql_domain("eql_v4.query_json_leaf")
        .with_elements_query_sql_domain("eql_v4.query_json_elements")
        .with_predicate_query_sql_domain("eql_v4.query_json_predicate")]
    }
    fn encrypt<'a, K: 'static>(
        &self,
        _: &str,
        _: Option<&stack_encrypt::dynamic::TargetOptions>,
        _: &'a stack_encrypt::KeysetCipher<'_, K>,
        _: &stack_encrypt::Label,
        _: ValueFrame,
    ) -> Result<stack_encrypt::Pending<'a, Vec<u8>, K>, stack_encrypt::dynamic::TargetError> {
        unreachable!("a check seals nothing")
    }
    fn decrypt<'a, K: 'static>(
        &self,
        _: &str,
        _: &'a stack_encrypt::StackCipher<K>,
        _: &stack_encrypt::Label,
        _: &[u8],
    ) -> Result<stack_encrypt::Pending<'a, ValueFrame, K>, stack_encrypt::dynamic::TargetError>
    {
        unreachable!("a check opens nothing")
    }
    fn query<'a, K: 'static>(
        &self,
        _: &str,
        _: &stack_encrypt::target::IndexSpec,
        _: &'a stack_encrypt::KeysetCipher<'_, K>,
        _: &stack_encrypt::Label,
        _: ValueFrame,
    ) -> Result<stack_encrypt::Pending<'a, Vec<u8>, K>, stack_encrypt::dynamic::TargetError> {
        unreachable!("a document's operators are the engine's")
    }
}

/// A document operator's JSON input is parsed and checked, and the parsed
/// needle wiped when the check drops it: a check derives nothing, so what
/// it frees is the input's alone.
#[test]
fn a_json_operators_input_leaves_no_plaintext_on_the_heap() {
    let wire = serde_json::json!({
        "profile": {"context": ["users", "profile"], "type": "json", "null": "sql",
                    "target": {"name": "JsonSearch", "options": {"ordered": ["$.age"]}}}
    });
    let plan = record::plan_with(
        stack_encrypt::dynamic::frame::serde::to_vec(&wire)
            .unwrap()
            .as_protected_ref(),
        &Documents,
    )
    .unwrap();
    let mark = marked("needle");
    let pad = "x".repeat(160);
    let needle = joined(&[r#"{""#, &mark, r#"": [""#, &mark, r"\n", &pad, r#""]}"#]);
    let at = joined(&[r#"""#, &mark, r#"\n""#]);
    // Framed by the test's own writer, which leaves no copy behind, so a
    // block the watch sees is the engine's.
    let inputs = [
        (Op::Contains, object(vec![("json", frame(needle.as_str()))])),
        (
            Op::EqAt,
            object(vec![
                ("path", frame("$.name")),
                ("json", frame(at.as_str())),
            ]),
        ),
        (
            Op::GtAt,
            object(vec![("path", frame("$.age")), ("json", frame(at.as_str()))]),
        ),
    ];
    for (operator, input) in &inputs {
        watched(&format!("check_query ({operator:?})"), || {
            stack_encrypt::dynamic::check_query(&plan, "profile", *operator, input, &Documents)
                .expect("a document operator's input");
        });
    }
}

/// A JSON document a binding hands over is parsed by the engine's own
/// parser and held in a `JsonPlaintext`, which wipes it when it drops: the
/// marker in a key, in a string with an escape (decoded, not borrowed) and
/// past 128 bytes leaves no freed block. A refused document wipes what was
/// built.
#[test]
fn a_json_document_read_from_a_frame_leaves_no_plaintext_on_the_heap() {
    let mark = marked("doc");
    let pad = "x".repeat(160);
    let document = joined(&[
        r#"{""#,
        &mark,
        r#"": [""#,
        &mark,
        r"\n",
        &pad,
        r#"", 1.5], "n": ""#,
        &mark,
        r#""}"#,
    ]);
    let refused = joined(&[
        r#"{""#,
        &mark,
        r#"": ""#,
        &mark,
        r#"\n", ""#,
        &mark,
        r#"": 1}"#,
    ]);
    let (document, refused) = (frame(document.as_str()), frame(refused.as_str()));
    watched("read_json", || {
        let parsed = stack_encrypt::dynamic::read_json(&document).expect("a document");
        drop(parsed);
        assert!(stack_encrypt::dynamic::read_json(&refused).is_err());
    });
}

/// A match index folds its text to lower case, and `İ` is longer folded
/// than it is: three bytes for two. The marker comes first, so a buffer
/// sized to the text and grown while it is folded would be freed with the
/// marker in it. The fold's buffers are sized for the folded text.
#[test]
fn a_word_that_lengthens_when_folded_leaves_no_plaintext_on_the_heap() {
    let rt = runtime();
    let cipher = rt.block_on(common::stack_cipher());
    let keyset = cipher.default_keyset();
    let plan = plan();
    let dotted = "İ".repeat(64);
    let text = joined(&[&marked("folded"), " ", &dotted]);
    assert!(
        text.to_lowercase().len() > text.len(),
        "the text lengthens when it is folded"
    );
    let source = object(vec![
        ("email", frame(text.as_str())),
        ("doc", frame(1u64)),
        ("id", frame(7u64)),
    ]);
    watched("record::encrypt (a word that lengthens)", || {
        rt.block_on(async {
            record::encrypt(&keyset, &source, &plan)
                .unwrap()
                .await
                .unwrap()
        });
    });
    let query = frame(text.as_str());
    watched("query_term (a word that lengthens)", || {
        rt.block_on(async {
            query_term(&keyset, &plan, "email", Op::Matches, &query, &NoTargets)
                .unwrap()
                .await
                .unwrap()
        });
    });
    let page = frame(vec![frame(text.as_str())]);
    watched("verify (a word that lengthens)", || {
        let values = page.elements().unwrap();
        let matched = verify(&plan, "email", Op::Matches, &query, values, &NoTargets).unwrap();
        assert_eq!(matched, [true]);
    });
    drop((source, query, page, text));
}

/// The keys of a map in a record are not held to this suite's rule, and
/// this is why: a sealed record stores them in the clear, beside the
/// values it seals (and binds each into its value's associated data). So
/// the copies of a key made while a record is sealed or opened hold nothing
/// the stored record does not, and the engine does not wipe them. A value
/// under a marked key is sealed, and is watched by every test above. The
/// keys of a JSON index document are sealed, and [`json_index`] holds them
/// to the rule.
#[test]
fn a_map_key_is_stored_in_the_clear() {
    use stack_encrypt::{CipherText, StackCipherText};

    /// Every map key in `tree`, at any depth.
    fn keys(tree: &StackCipherText, found: &mut Vec<String>) {
        match tree {
            CipherText::Map(entries) => {
                for (key, child) in entries {
                    found.push(key.clone());
                    keys(child, found);
                }
            }
            CipherText::Sequence(children) => children.iter().for_each(|child| keys(child, found)),
            _ => {}
        }
    }

    let rt = runtime();
    let cipher = rt.block_on(common::stack_cipher());
    let keyset = cipher.default_keyset();
    let key = marked("key");
    let source = object(vec![
        ("email", frame(marked("email"))),
        ("doc", object(vec![(key.as_str(), frame(marked("value")))])),
        ("id", frame(7u64)),
    ]);
    let sealed = rt.block_on(async {
        record::encrypt(&keyset, &source, &plan())
            .unwrap()
            .await
            .unwrap()
    });
    let mut found = Vec::new();
    keys(&sealed, &mut found);
    assert!(
        found.contains(&key),
        "the stored record names the key: {found:?}"
    );
    assert!(
        !found.iter().any(|name| name.contains("value")),
        "and not the value under it: {found:?}"
    );
}

/// A predicate's string literal and quoted key are decoded when either has
/// an escape, not borrowed. Each is decoded into a buffer sized for it,
/// which is wiped; a decoder that grew a scratch buffer would free the
/// marker written before the escape.
#[test]
fn an_escaped_literal_in_a_predicate_leaves_no_plaintext_on_the_heap() {
    let wire = serde_json::json!({
        "profile": {"context": ["users", "profile"], "type": "json", "null": "sql",
                    "target": {"name": "JsonSearch", "options": {"ordered": ["$.age"]}}}
    });
    let plan = record::plan_with(
        stack_encrypt::dynamic::frame::serde::to_vec(&wire)
            .unwrap()
            .as_protected_ref(),
        &Documents,
    )
    .unwrap();
    let mark = marked("literal");
    let pad = "x".repeat(160);
    let predicates = [
        joined(&[r#"$.name == ""#, &mark, r"\n", &pad, r#"""#]),
        joined(&[r#"$.""#, &mark, r"\n", &pad, r#"" == 1"#]),
        // Refused: the escape names no character.
        joined(&[r#"$.name == ""#, &mark, r"\x", &pad, r#"""#]),
        // Refused after a quoted key, and after a plain one, was read into
        // the path: the step that follows is not supported.
        joined(&[r#"$.""#, &mark, r"\n", &pad, r#"".** == 1"#]),
        joined(&["$.", &mark, ".** == 1"]),
    ];
    let inputs = predicates
        .iter()
        .map(|predicate| object(vec![("predicate", frame(predicate.as_str()))]));
    for (input, accepted) in inputs.zip([true, true, false, false, false]) {
        watched("check_query (an escaped literal)", || {
            let checked = stack_encrypt::dynamic::check_query(
                &plan,
                "profile",
                Op::Match,
                &input,
                &Documents,
            );
            assert_eq!(checked.is_ok(), accepted, "{checked:?}");
        });
    }
}

/// A document operator's input names keys in its path and its members, and
/// a predicate names them in its paths and its variables. Each is held in
/// a wiping buffer, whether the input is accepted or refused.
#[test]
fn a_key_in_an_operators_input_leaves_no_plaintext_on_the_heap() {
    let wire = serde_json::json!({
        "profile": {"context": ["users", "profile"], "type": "json", "null": "sql",
                    "target": {"name": "JsonSearch", "options": {"ordered": ["$.age"]}}}
    });
    let plan = record::plan_with(
        stack_encrypt::dynamic::frame::serde::to_vec(&wire)
            .unwrap()
            .as_protected_ref(),
        &Documents,
    )
    .unwrap();
    let mark = marked("key");
    let path = joined(&["$.", &mark]);
    let elements = joined(&["$.", &mark, "[*]"]);
    let predicate = |text: &[&str]| object(vec![("predicate", frame(joined(text).as_str()))]);
    let inputs = [
        (
            Op::EqAt,
            object(vec![("path", frame(path.as_str())), ("json", frame("1"))]),
        ),
        (
            Op::GtAt,
            object(vec![("path", frame(path.as_str())), ("json", frame("1"))]),
        ),
        (
            Op::BetweenAt,
            object(vec![
                ("path", frame(path.as_str())),
                ("low", frame("1")),
                ("high", frame("2")),
            ]),
        ),
        (Op::Selector, object(vec![("path", frame(path.as_str()))])),
        (Op::Children, object(vec![("path", frame(path.as_str()))])),
        (Op::ChildCount, object(vec![("path", frame(path.as_str()))])),
        (Op::Subtree, object(vec![("path", frame(path.as_str()))])),
        (
            Op::ElementMatch,
            object(vec![
                ("path", frame(elements.as_str())),
                (
                    "predicates",
                    frame(vec![object(vec![
                        ("member", frame(mark.as_str())),
                        ("op", frame("eq")),
                        ("json", frame("1")),
                    ])]),
                ),
            ]),
        ),
        // An ordering at a wildcard, with no member after it.
        (Op::Match, predicate(&[r#"$.""#, &mark, r#""[*] < 5"#])),
        (Op::Match, predicate(&["$.", &mark, "[*] < 5"])),
        // A variable, named plainly and in quotes with an escape.
        (Op::Match, predicate(&["$.a == $", &mark])),
        (Op::Match, predicate(&[r#"$.a == $""#, &mark, r#"\n""#])),
    ];
    for (operator, input) in &inputs {
        watched(&format!("check_query ({operator:?}, a marked key)"), || {
            // Accepted or refused, by the operator: either way the input's
            // keys are wiped.
            drop(stack_encrypt::dynamic::check_query(
                &plan, "profile", *operator, input, &Documents,
            ));
        });
    }
}

/// A path's quoted key is decoded when it has an escape, into a buffer
/// sized for it, and the path wipes its keys when it is dropped. A path
/// refused after a key was read wipes that key too.
#[test]
fn a_quoted_key_in_a_path_leaves_no_plaintext_on_the_heap() {
    use stack_encrypt::json::JsonPath;
    let mark = marked("path-key");
    let pad = "x".repeat(160);
    let path = joined(&[r#"$[""#, &mark, r"\n", &pad, r#""].inner"#]);
    let plain = joined(&["$.", &mark, r#"["inner"]"#]);
    let refused = [
        // The escape names no character.
        joined(&[r#"$[""#, &mark, r"\x", &pad, r#""]"#]),
        // Refused after its first two keys were read.
        joined(&["$.", &mark, r#"[""#, &mark, r"\n", &pad, r#""]!"#]),
        // Refused with a quoted key decoded and not yet a step: no `]`.
        joined(&[r#"$[""#, &mark, r"\n", &pad, r#""x"#]),
    ];
    watched("JsonPath::parse", || {
        for text in [&path, &plain] {
            let parsed = JsonPath::parse(text).expect("a path");
            assert_eq!(parsed.segments().len(), 2);
            drop(parsed);
        }
        for text in &refused {
            assert!(JsonPath::parse(text).is_err(), "{text:?}");
        }
    });
}

/// Pending work dropped before it has run, and dropped while its key
/// request is in flight: the plaintext it planned is wiped as it is on
/// success, though no key ever arrives. `lifecycle_conformance` shows the
/// same drops release what the work owns; these show what is released is
/// wiped.
mod cancellation {
    use super::*;

    use std::borrow::Cow;
    use std::future::IntoFuture;
    use std::task::{Context, Waker};

    use stack_encrypt::json::JsonPlaintext;
    use stack_encrypt::target::{json_document, Borrowed};
    use stack_encrypt::{Ciphertext, EncryptInto, OpaqueBlob, Pending, StackCipher};
    use stack_kms::{
        DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyPayload,
        IdentifiedBy, IndexKey, IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
    };
    use uuid::Uuid;

    /// A key source that can stop answering: a request made while `block`
    /// is set never completes.
    struct Stalling {
        inner: FakeDataKeySource,
        block: Arc<AtomicBool>,
        requests: Arc<AtomicUsize>,
    }

    impl Stalling {
        async fn requested(&self) {
            self.requests.fetch_add(1, Ordering::SeqCst);
            if self.block.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
        }
    }

    impl DataKeySource for Stalling {
        async fn generate_keys(
            &self,
            payloads: Vec<GenerateKeyPayload<'_>>,
            keyset: Option<Uuid>,
            context: Option<Cow<'_, UnverifiedContext>>,
        ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
            self.requested().await;
            self.inner.generate_keys(payloads, keyset, context).await
        }

        async fn retrieve_keys(
            &self,
            payloads: Vec<RetrieveKeyPayload<'_>>,
            keyset: Option<Uuid>,
            context: Option<&UnverifiedContext>,
        ) -> Result<Vec<DataKey>, stack_kms::Error> {
            self.requested().await;
            self.inner.retrieve_keys(payloads, keyset, context).await
        }
    }

    impl IndexKeySource for Stalling {
        async fn load_index_key(
            &self,
            keyset: Option<IdentifiedBy>,
        ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
            self.inner.load_index_key(keyset).await
        }
    }

    /// A cipher over a [`Stalling`] source, the switch that stalls it, and
    /// the count of key requests it has been sent.
    fn cipher(
        rt: &tokio::runtime::Runtime,
    ) -> (StackCipher<Stalling>, Arc<AtomicBool>, Arc<AtomicUsize>) {
        let (block, requests) = (Arc::default(), Arc::default());
        let source = Stalling {
            inner: FakeDataKeySource::new(),
            block: Arc::clone(&block),
            requests: Arc::clone(&requests),
        };
        let cipher = rt
            .block_on(StackCipher::builder().kms(source).init())
            .unwrap();
        (cipher, block, requests)
    }

    /// Drop `pending` without running it: no key is requested.
    fn drop_unpolled<T>(pending: Pending<'_, T, Stalling>, requests: &AtomicUsize) {
        drop(pending);
        assert_eq!(requests.load(Ordering::SeqCst), 0, "no key was requested");
    }

    /// Run `pending` until its key request is in flight, then drop it.
    fn drop_in_flight<T>(pending: Pending<'_, T, Stalling>, requests: &AtomicUsize) {
        let mut future = pending.into_future();
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "the key request does not complete"
        );
        assert_eq!(requests.load(Ordering::SeqCst), 1, "one request in flight");
        drop(future);
    }

    #[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize)]
    struct Note {
        title: String,
        /// Written after the marked field, so the blob's buffer regrows
        /// while it holds it.
        body: String,
    }

    fn note() -> OpaqueBlob<Note> {
        OpaqueBlob::new(Note {
            title: marked("note"),
            body: "x".repeat(8 * 1024),
        })
    }

    #[test]
    fn work_dropped_before_it_runs_leaves_no_plaintext_on_the_heap() {
        let rt = runtime();
        let (cipher, _, requests) = cipher(&rt);
        let keyset = cipher.default_keyset();
        let plan = plan();
        let source = row();
        watched("record::encrypt, dropped unpolled", || {
            drop_unpolled(record::encrypt(&keyset, &source, &plan).unwrap(), &requests);
        });
        drop(source);
        let column = vec![marked("first"), marked("second")];
        watched("Vec<String> -> Vec<Ciphertext>, dropped unpolled", || {
            drop_unpolled::<Vec<Ciphertext>>(column.encrypt_into(&keyset), &requests);
        });
        let text = marked("scalar");
        watched("String -> Ciphertext, dropped unpolled", || {
            drop_unpolled(keyset.encrypt(text), &requests);
        });
        let blob = note();
        watched_for_leaks("OpaqueBlob -> Ciphertext, dropped unpolled", || {
            drop_unpolled(keyset.encrypt_with_context(blob, "docs/body"), &requests);
        });
        let query = frame(marked("query"));
        watched("query_term, dropped unpolled", || {
            drop_unpolled(
                query_term(&keyset, &plan, "email", Op::Matches, &query, &NoTargets).unwrap(),
                &requests,
            );
        });
        let value = json_index::document();
        for sealed_root in [true, false] {
            let options = json_index::options(sealed_root);
            watched(
                &format!("JSON index document (sealed_root: {sealed_root}), dropped unpolled"),
                || {
                    drop_unpolled(
                        keyset.run(
                            json_document::<_, Borrowed>(options),
                            &value,
                            json_index::context(),
                        ),
                        &requests,
                    );
                },
            );
        }
        drop(value);
        let document = JsonPlaintext::from(json_plaintext::document());
        watched_for_leaks("JsonPlaintext -> Ciphertext, dropped unpolled", || {
            drop_unpolled(
                keyset.encrypt_with_context(document, "docs/body"),
                &requests,
            );
        });
    }

    #[test]
    fn work_dropped_with_its_key_request_in_flight_leaves_no_plaintext_on_the_heap() {
        let rt = runtime();
        let (cipher, block, requests) = cipher(&rt);
        let keyset = cipher.default_keyset();
        let plan = plan();
        let stored = rt.block_on(async {
            record::encrypt(&keyset, row(), &plan)
                .unwrap()
                .await
                .unwrap()
        });
        block.store(true, Ordering::SeqCst);
        let in_flight = |what: &str, start: &mut dyn FnMut()| {
            requests.store(0, Ordering::SeqCst);
            watched(what, start);
        };

        let source = row();
        in_flight("record::encrypt, dropped in flight", &mut || {
            drop_in_flight(record::encrypt(&keyset, &source, &plan).unwrap(), &requests);
        });
        drop(source);
        let mut column = Some(vec![marked("first"), marked("second")]);
        in_flight(
            "Vec<String> -> Vec<Ciphertext>, dropped in flight",
            &mut || {
                let column = column.take().unwrap();
                drop_in_flight::<Vec<Ciphertext>>(column.encrypt_into(&keyset), &requests);
            },
        );
        let mut text = Some(marked("scalar"));
        in_flight("String -> Ciphertext, dropped in flight", &mut || {
            drop_in_flight(keyset.encrypt(text.take().unwrap()), &requests);
        });
        let mut blob = Some(note());
        in_flight("OpaqueBlob -> Ciphertext, dropped in flight", &mut || {
            let blob = blob.take().unwrap();
            drop_in_flight(keyset.encrypt_with_context(blob, "docs/body"), &requests);
        });
        // An opening holds no plaintext until its key arrives; dropping it
        // in flight frees only what is stored.
        let mut stored = Some(stored);
        in_flight("record::decrypt, dropped in flight", &mut || {
            let stored = stored.take().unwrap();
            drop_in_flight(
                record::decrypt(&cipher, stored, &plan, None).unwrap(),
                &requests,
            );
        });

        // A JSON index document, under either root option: the walked
        // nodes, and with a sealed root the document's text, wait on the
        // key. And a document sealed as one ciphertext.
        let value = json_index::document();
        for sealed_root in [true, false] {
            let options = json_index::options(sealed_root);
            in_flight(
                &format!("JSON index document (sealed_root: {sealed_root}), dropped in flight"),
                &mut || {
                    drop_in_flight(
                        keyset.run(
                            json_document::<_, Borrowed>(options.clone()),
                            &value,
                            json_index::context(),
                        ),
                        &requests,
                    );
                },
            );
        }
        drop(value);
        let mut document = Some(JsonPlaintext::from(json_plaintext::document()));
        in_flight(
            "JsonPlaintext -> Ciphertext, dropped in flight",
            &mut || {
                let document = document.take().unwrap();
                drop_in_flight(
                    keyset.encrypt_with_context(document, "docs/body"),
                    &requests,
                );
            },
        );

        // The cipher is not poisoned: the same work runs once keys arrive.
        block.store(false, Ordering::SeqCst);
        let sealed: Ciphertext = rt.block_on(async { keyset.encrypt(7u64).await }).unwrap();
        assert_eq!(
            rt.block_on(async { keyset.decrypt::<u64>(sealed).await })
                .unwrap(),
            7
        );
    }
}

/// `parts` joined into a string sized for them before it is written, so
/// building a marked input frees no marked block that a later allocation
/// could reuse and a watch then find.
fn joined(parts: &[&str]) -> String {
    let mut out = String::with_capacity(parts.iter().map(|p| p.len()).sum());
    for part in parts {
        out.push_str(part);
    }
    out
}

/// The spy itself: a plain `String` holding the marker, freed while
/// watched, fails the watch. Without this a spy that saw nothing would pass
/// every test above.
#[test]
#[should_panic(expected = "freed with plaintext in them")]
fn the_spy_sees_an_unwiped_free() {
    let text = marked("control");
    watched("control", || drop(text));
}

/// The leak half's negative control: a marked block allocated during the
/// watch and never freed is seen by [`watched_for_leaks`], though the
/// free-time scan alone passes it.
#[test]
#[should_panic(expected = "still live with plaintext in them")]
fn the_spy_sees_a_leaked_block() {
    let text = marked("control");
    watched("control (leak, free-time scan only)", || {
        std::mem::forget(text.clone())
    });
    watched_for_leaks("control (leak)", || std::mem::forget(text.clone()));
}

/// `OpaqueBlob<T>`: the owned source, the storage blob it is encoded into
/// (which grows past its first allocation while it already holds the
/// marker), the planned leaf, and on decrypt the opened buffer the blob
/// is read from, all freed wiped, and none of them leaked rather than
/// freed. The opened value is the caller's and is wiped by hand before the
/// watch ends; a refusal of another shape, found before any field is
/// built, leaves nothing to wipe.
mod opaque_blob {
    use super::*;

    use serde::{Deserialize, Serialize};
    use stack_encrypt::{Error, OpaqueBlob};
    use zeroize::Zeroize;

    #[derive(Serialize, Deserialize, Zeroize)]
    struct Doc {
        title: String,
        notes: Vec<String>,
        /// Written after the marked fields, so the blob's buffer regrows
        /// while it holds them.
        body: String,
        n: u32,
    }

    fn doc() -> OpaqueBlob<Doc> {
        OpaqueBlob::new(Doc {
            title: marked("title"),
            notes: vec![marked("note-1"), marked("note-2")],
            body: "x".repeat(8 * 1024),
            n: 7,
        })
    }

    #[test]
    fn an_opaque_blob_encrypted_leaves_no_plaintext_on_the_heap() {
        let rt = runtime();
        let cipher = rt.block_on(common::stack_cipher());
        let keyset = cipher.default_keyset();
        let source = doc();
        watched_for_leaks("OpaqueBlob encrypt", || {
            rt.block_on(async {
                keyset
                    .encrypt_with_context(source, "docs/body")
                    .await
                    .unwrap()
            });
        });
    }

    #[test]
    fn an_opaque_blob_decrypted_leaves_no_plaintext_on_the_heap() {
        let rt = runtime();
        let cipher = rt.block_on(common::stack_cipher());
        let keyset = cipher.default_keyset();
        let sealed = rt.block_on(async {
            keyset
                .encrypt_with_context(doc(), "docs/body")
                .await
                .unwrap()
        });
        watched_for_leaks("OpaqueBlob decrypt", || {
            let opened = rt.block_on(async {
                keyset
                    .decrypt_with_context::<OpaqueBlob<Doc>>(sealed, "docs/body")
                    .await
                    .unwrap()
            });
            // The opened blob holds the plaintext in its `Zeroizing` guard
            // until it is dropped. Dropping it, with no explicit wipe, must
            // leave no plaintext on the heap.
            assert!(opened
                .get()
                .title
                .as_bytes()
                .windows(MARK.len())
                .any(|w| w == MARK));
            drop(opened);
        });
    }

    /// Refused before `Deserialize` builds a field: the first field of the
    /// target does not read the blob's text, so nothing of the marked value
    /// is built, and the opened buffer is wiped with the refusal.
    #[test]
    fn an_opaque_blob_of_another_shape_leaves_no_plaintext_on_the_heap() {
        let rt = runtime();
        let cipher = rt.block_on(common::stack_cipher());
        let keyset = cipher.default_keyset();
        let sealed = rt.block_on(async {
            keyset
                .encrypt_with_context(doc(), "docs/body")
                .await
                .unwrap()
        });
        #[derive(Deserialize, Zeroize)]
        #[allow(dead_code)]
        struct Other {
            title: u32,
        }
        watched_for_leaks("OpaqueBlob decrypt (mismatch)", || {
            let result = rt.block_on(async {
                keyset
                    .decrypt_with_context::<OpaqueBlob<Other>>(sealed, "docs/body")
                    .await
            });
            assert!(matches!(
                result,
                Err(Error::Blob(stack_encrypt::BlobError::Mismatch(_)))
            ));
        });
    }

    /// The limit the blob docs state, held as a negative control: a derived
    /// `Deserialize` that built a `String` field and then refuses a later
    /// field drops that `String` as an ordinary value, unwiped, because no
    /// `T` was ever constructed to wipe. The opened buffer itself is wiped;
    /// what leaks is serde's partial value. A type whose fields wipe on drop
    /// closes it; this test documents that the library does not.
    #[test]
    #[should_panic(expected = "freed with plaintext in them")]
    fn a_partial_decode_drops_the_fields_it_built_unwiped() {
        let rt = runtime();
        let cipher = rt.block_on(common::stack_cipher());
        let keyset = cipher.default_keyset();
        let sealed = rt.block_on(async {
            keyset
                .encrypt_with_context(doc(), "docs/body")
                .await
                .unwrap()
        });
        #[derive(Deserialize, Zeroize)]
        #[allow(dead_code)]
        struct Later {
            title: String,
            notes: Vec<String>,
            body: u32,
        }
        watched("OpaqueBlob decrypt (partial)", || {
            let result = rt.block_on(async {
                keyset
                    .decrypt_with_context::<OpaqueBlob<Later>>(sealed, "docs/body")
                    .await
            });
            assert!(matches!(
                result,
                Err(Error::Blob(stack_encrypt::BlobError::Mismatch(_)))
            ));
        });
    }
}

/// `JsonPlaintext`: the owned document, the JSON text it is written as to
/// be sealed, the planned leaf, and on decrypt the opened text the document
/// is parsed from, all freed wiped, and none of them leaked rather than
/// freed. The marker sits in a key, in a string with an escape (so the
/// writer and the parser each handle it, rather than copy it through) and
/// beside a string long enough to make a short buffer regrow.
mod json_plaintext {
    use super::*;

    use serde_json::{json, Value};
    use stack_encrypt::json::JsonPlaintext;
    use stack_encrypt::Error;

    pub(super) fn document() -> Value {
        let mut members = serde_json::Map::new();
        members.insert(marked("key"), json!([marked("in-array"), 1.5, null]));
        members.insert(
            "escaped".to_owned(),
            Value::String(format!("{}\n\"", marked("escaped"))),
        );
        members.insert("pad".to_owned(), Value::String("x".repeat(8 * 1024)));
        Value::Object(members)
    }

    #[test]
    fn a_json_plaintext_encrypted_leaves_no_plaintext_on_the_heap() {
        let rt = runtime();
        let cipher = rt.block_on(common::stack_cipher());
        let keyset = cipher.default_keyset();
        let source = JsonPlaintext::from(document());
        watched_for_leaks("JsonPlaintext encrypt", || {
            rt.block_on(async {
                keyset
                    .encrypt_with_context(source, "docs/body")
                    .await
                    .unwrap()
            });
        });
    }

    #[test]
    fn a_json_plaintext_decrypted_leaves_no_plaintext_on_the_heap() {
        let rt = runtime();
        let cipher = rt.block_on(common::stack_cipher());
        let keyset = cipher.default_keyset();
        let sealed = rt.block_on(async {
            keyset
                .encrypt_with_context(JsonPlaintext::from(document()), "docs/body")
                .await
                .unwrap()
        });
        watched_for_leaks("JsonPlaintext decrypt", || {
            let opened = rt.block_on(async {
                keyset
                    .decrypt_with_context::<JsonPlaintext>(sealed, "docs/body")
                    .await
                    .unwrap()
            });
            // The opened document holds the plaintext until it is dropped.
            // Dropping it, with no explicit wipe, must leave none on the
            // heap.
            assert!(opened.value()["escaped"]
                .as_str()
                .unwrap()
                .as_bytes()
                .windows(MARK.len())
                .any(|w| w == MARK));
            drop(opened);
        });
    }

    /// Text that is not a document is refused after the leaf opens. The
    /// part of the document the parser built, and the opened text, are
    /// wiped with the refusal.
    #[test]
    fn text_that_is_not_a_document_leaves_no_plaintext_on_the_heap() {
        let rt = runtime();
        let cipher = rt.block_on(common::stack_cipher());
        let keyset = cipher.default_keyset();
        // A marked member, then the same key again: refused at the repeat,
        // after the first member was built.
        let text = joined(&[
            r#"{""#,
            &marked("key"),
            r#"": ""#,
            &marked("value"),
            r#"\n", ""#,
            &marked("key"),
            r#"": 1}"#,
        ]);
        let sealed = rt.block_on(async {
            keyset
                .encrypt_with_context(text, "docs/body")
                .await
                .unwrap()
        });
        watched_for_leaks(
            "JsonPlaintext decrypt of text that is not a document",
            || {
                let refused = rt.block_on(async {
                    keyset
                        .decrypt_with_context::<JsonPlaintext>(sealed, "docs/body")
                        .await
                });
                assert!(matches!(refused, Err(Error::OpenedType { .. })));
            },
        );
    }
}

/// The JSON index: sealing a document under either root option, opening it
/// whole (from the sealed root, and by walking its chain with the root
/// open), opening a subtree read's rows and an extracted entry, and
/// building a containment needle. Every freed block is checked for the
/// marker, which sits in key names and in string values (one past 128
/// bytes), and for the data key the document is sealed under, which the key
/// source below records as it hands it out.
///
/// The input document is built before each watch and the opened values are
/// dropped after it: they are the caller's, not the engine's.
mod json_index {
    use super::*;

    use std::borrow::Cow;

    use serde_json::{json, Value};
    use stack_encrypt::json::{
        JsonDocument, JsonNode, JsonOptions, JsonPath, JsonQuery, JsonSubtree,
    };
    use stack_encrypt::target::legacy::DecryptFrom;
    use stack_encrypt::target::{json_document, AeadContext, Borrowed, CallerContext};
    use stack_encrypt::{op, Plan, StackCipher};
    use stack_kms::{
        DataKey, DataKeySource, DataKeyWithTag, DeterministicSource, GenerateKeyPayload,
        IdentifiedBy, IndexKey, IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
    };
    use uuid::Uuid;

    /// The deterministic source, recording every data key it hands out in
    /// [`KEY`] so the spy can look for it.
    struct Recorded(DeterministicSource);

    /// Written into [`KEY`] in place, not built on the stack and moved in,
    /// for the reason [`holds_key`] reads it in place.
    fn record(key: &DataKey) {
        KEY.lock()
            .unwrap()
            .get_or_insert([0; 32])
            .copy_from_slice(key.key());
    }

    impl DataKeySource for Recorded {
        async fn generate_keys(
            &self,
            payloads: Vec<GenerateKeyPayload<'_>>,
            keyset_id: Option<Uuid>,
            unverified_context: Option<Cow<'_, UnverifiedContext>>,
        ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
            let keys = self
                .0
                .generate_keys(payloads, keyset_id, unverified_context)
                .await?;
            keys.iter().for_each(|key| record(&key.key));
            Ok(keys)
        }

        async fn retrieve_keys(
            &self,
            payloads: Vec<RetrieveKeyPayload<'_>>,
            keyset_id: Option<Uuid>,
            unverified_context: Option<&UnverifiedContext>,
        ) -> Result<Vec<DataKey>, stack_kms::Error> {
            let keys = self
                .0
                .retrieve_keys(payloads, keyset_id, unverified_context)
                .await?;
            keys.iter().for_each(record);
            Ok(keys)
        }
    }

    impl IndexKeySource for Recorded {
        async fn load_index_key(
            &self,
            keyset_id: Option<IdentifiedBy>,
        ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
            self.0.load_index_key(keyset_id).await
        }
    }

    async fn cipher() -> StackCipher<Recorded> {
        StackCipher::builder()
            .kms(Recorded(DeterministicSource::new([9; 32])))
            .init()
            .await
            .unwrap()
    }

    /// The root option, with the long string and the marked key's `inner`
    /// ordered, so the ordering terms over marked text are derived too.
    pub(super) fn options(sealed_root: bool) -> JsonOptions {
        let inner = format!("$[\"{}\"].inner", marked("key"));
        JsonOptions {
            sealed_root,
            ..JsonOptions::new()
        }
        .ordering(["$.long", inner.as_str()])
        .unwrap()
    }

    pub(super) fn context() -> CallerContext {
        CallerContext::from(nonempty!("users").with("profile"))
    }

    fn aead() -> AeadContext {
        AeadContext::from(nonempty!("users").with("profile"))
    }

    /// A document with the marker in a key name, in a short string, in a
    /// string past 128 bytes, and in an array element under an object.
    pub(super) fn document() -> Value {
        let mut long = marked("long");
        long.push_str(&"x".repeat(160));
        json!({
            marked("key"): {"inner": marked("short"), "list": [marked("element"), 1, null]},
            "long": long,
            "escaped": format!("{}\n\"", marked("escaped")),
            "n": 7,
        })
    }

    /// The key a read of the marked key's `inner` member sends, by path.
    fn inner_path() -> JsonPath {
        JsonPath::parse(&format!("$[\"{}\"].inner", marked("key"))).unwrap()
    }

    /// Seal `value` with this thread watched.
    fn sealed(
        rt: &tokio::runtime::Runtime,
        cipher: &StackCipher<Recorded>,
        value: &Value,
        sealed_root: bool,
    ) -> JsonDocument {
        // Built before the watch: the ordered paths are the test's input.
        let options = options(sealed_root);
        watched(&format!("seal (sealed_root: {sealed_root})"), || {
            rt.block_on(async {
                cipher
                    .default_keyset()
                    .run(json_document::<_, Borrowed>(options), value, context())
                    .await
                    .unwrap()
            })
        })
    }

    #[test]
    fn sealing_and_opening_a_document_leaves_no_plaintext_or_key_on_the_heap() {
        let rt = runtime();
        let cipher = rt.block_on(cipher());
        let value = document();
        for sealed_root in [true, false] {
            let doc = sealed(&rt, &cipher, &value, sealed_root);
            let opened: Value = watched(&format!("open (sealed_root: {sealed_root})"), || {
                rt.block_on(async { doc.clone().decrypt_into(&cipher, aead()).await.unwrap() })
            });
            assert_eq!(opened, value);
        }
        *KEY.lock().unwrap() = None;
    }

    #[test]
    fn a_read_and_an_extraction_leave_no_plaintext_or_key_on_the_heap() {
        let rt = runtime();
        let cipher = rt.block_on(cipher());
        let value = document();
        for sealed_root in [true, false] {
            let doc = sealed(&rt, &cipher, &value, sealed_root);
            let keyset = cipher.default_keyset();
            let path = inner_path();
            let key = rt
                .block_on(async {
                    keyset
                        .json_subtree_key(
                            &path,
                            &options(sealed_root),
                            nonempty!("users").with("profile"),
                        )
                        .await
                })
                .unwrap();
            // The rows as the SQL returns them, built before the watch.
            let rows: Vec<JsonNode> = doc
                .subtree(&key.token_bytes())
                .iter()
                .map(|(j, _, d)| {
                    let mut wire = serde_json::to_value(doc.node(*j).unwrap()).unwrap();
                    wire["d"] = json!(d);
                    serde_json::from_value(wire).unwrap()
                })
                .collect();
            let read = key.open(rows);
            let opened: Value = watched(
                &format!("subtree read (sealed_root: {sealed_root})"),
                || {
                    rt.block_on(async {
                        cipher
                            .decrypt_as::<Value, JsonSubtree>(read, aead())
                            .await
                            .unwrap()
                    })
                },
            );
            assert_eq!(opened, json!(marked("short")));
            let selector = rt
                .block_on(async {
                    keyset
                        .json_selector(&path, nonempty!("users").with("profile"))
                        .await
                })
                .unwrap();
            let (j, _) = doc.find(&key.token_bytes()[0]).unwrap();
            let node = selector.open(doc.node(j).unwrap());
            let opened: Value = watched(&format!("-> (sealed_root: {sealed_root})"), || {
                rt.block_on(async {
                    cipher
                        .decrypt_as::<Value, stack_encrypt::json::JsonExtracted>(node, aead())
                        .await
                        .unwrap()
                })
            });
            assert_eq!(opened, json!(marked("short")));
        }
        *KEY.lock().unwrap() = None;
    }

    #[test]
    fn a_containment_needle_leaves_no_plaintext_on_the_heap() {
        let rt = runtime();
        let cipher = rt.block_on(cipher());
        let plan = Plan::value::<Value>()
            .context("users/profile")
            .encrypt_into::<JsonDocument>()
            .build()
            .unwrap();
        let needle = document();
        let query: JsonQuery = watched("Contains needle", || {
            rt.block_on(async { cipher.query(op::Contains, &needle).on(&plan).await.unwrap() })
        });
        drop(query);
        // The path is a `&'static str`: an owned path `String` is cloned by
        // the query builder and dropped by the plan chain, and the chain's
        // `P: AsRef<str>` cannot wipe it (see the module's JSON notes).
        let path: &'static str =
            Box::leak(format!("$[\"{}\"].inner", marked("key")).into_boxed_str());
        let at = (path, marked("short"));
        let query: JsonQuery = watched("AtPath(Eq) needle", || {
            rt.block_on(async {
                cipher
                    .query(op::AtPath(op::Eq), &at)
                    .on(&plan)
                    .await
                    .unwrap()
            })
        });
        drop(query);
    }

    /// A document field's operators through the data plan
    /// (`dynamic::query_term`) and its reads opened against their request
    /// (`dynamic::json_open`) free no block holding plaintext or a data
    /// key: the operator's parsed input and the document built from it,
    /// and each opened value once its text is written.
    #[test]
    fn a_document_fields_operators_and_reads_leave_no_plaintext_or_key_on_the_heap() {
        use base64ct::{Base64, Encoding};
        use stack_encrypt::dynamic::json_open;

        let rt = runtime();
        let cipher = rt.block_on(cipher());
        let keyset = cipher.default_keyset();
        let wire = json!({
            "profile": {"context": ["users", "profile"], "type": "json", "null": "sql",
                        "target": {"name": "JsonSearch", "options": {"ordered": ["$.age", "$.visits[*].at"]}}}
        });
        let plan = record::plan_with(
            stack_encrypt::dynamic::frame::serde::to_vec(&wire)
                .unwrap()
                .as_protected_ref(),
            &Documents,
        )
        .unwrap();

        let mark = marked("operand");
        let quoted = format!("{mark:?}");
        let document = format!(r#"{{{quoted}: [{quoted}], "name": {quoted}}}"#);
        // Every leaf kind, with a literal and a variable carrying the mark.
        let predicate = format!(
            "$.name == {quoted} && $.name != $v && $.age > {quoted} && \
             exists($.visits[*] ? (@.at == $v && @.at < {quoted})) && $.visits[*].at >= $v"
        );
        let vars = format!(r#"{{"v": {quoted}}}"#);
        let inputs = [
            (
                Op::Contains,
                object(vec![("json", frame(document.as_str()))]),
            ),
            (
                Op::EqAt,
                object(vec![
                    ("path", frame("$.name")),
                    ("json", frame(quoted.as_str())),
                ]),
            ),
            (
                Op::GtAt,
                object(vec![
                    ("path", frame("$.age")),
                    ("json", frame(quoted.as_str())),
                ]),
            ),
            (
                Op::BetweenAt,
                object(vec![
                    ("path", frame("$.age")),
                    ("low", frame(quoted.as_str())),
                    ("high", frame(quoted.as_str())),
                ]),
            ),
            (
                Op::ElementMatch,
                object(vec![
                    ("path", frame("$.visits[*]")),
                    (
                        "predicates",
                        frame(vec![
                            object(vec![
                                ("member", frame("at")),
                                ("op", frame("eq")),
                                ("json", frame(quoted.as_str())),
                            ]),
                            object(vec![
                                ("member", frame("at")),
                                ("op", frame("between")),
                                ("low", frame(quoted.as_str())),
                                ("high", frame(quoted.as_str())),
                            ]),
                        ]),
                    ),
                ]),
            ),
            (
                Op::Match,
                object(vec![
                    ("predicate", frame(predicate.as_str())),
                    ("vars", frame(vars.as_str())),
                ]),
            ),
        ];
        for (operator, input) in &inputs {
            let term = watched(&format!("query_term ({operator:?})"), || {
                rt.block_on(async {
                    query_term(&keyset, &plan, "profile", *operator, input, &Documents)
                        .expect("a document operator")
                        .await
                        .expect("its operand")
                })
            });
            drop(term);
        }

        // A stored document, sealed and laid out as the SQL returns its
        // rows, before the watch.
        let value = json!({
            "name": marked("name"),
            "age": 34,
            "visits": [{"at": 3, "place": marked("place")}, {"at": 1}],
        });
        let doc = rt
            .block_on(async {
                keyset
                    .run(
                        json_document::<_, Borrowed>(
                            JsonOptions::new().ordering(["$.age"]).unwrap(),
                        ),
                        &value,
                        context(),
                    )
                    .await
            })
            .unwrap();
        let operand = |operator: Op, path: &str| {
            rt.block_on(async {
                query_term(
                    &keyset,
                    &plan,
                    "profile",
                    operator,
                    object(vec![("path", frame(path))]),
                    &Documents,
                )
                .unwrap()
                .await
                .unwrap()
            })
        };
        let tag =
            |text: &str| -> [u8; 16] { Base64::decode_vec(text).unwrap().try_into().unwrap() };
        let row = |j: usize, d: Option<u64>| {
            let mut wire = serde_json::to_value(doc.node(j).unwrap()).unwrap();
            if let Some(d) = d {
                wire["d"] = json!(d);
            }
            wire.to_string()
        };
        let stack_encrypt::dynamic::Operand::Text(name) =
            operand(Op::Selector, "$.name").operand().clone()
        else {
            panic!("a selector is text")
        };
        let at = doc
            .entries()
            .iter()
            .position(|entry| entry.selector() == &tag(&name))
            .unwrap();
        let selected = vec![vec![row(at, None)]];
        let stack_encrypt::dynamic::Operand::TextList(tokens) =
            operand(Op::Subtree, "$.visits").operand().clone()
        else {
            panic!("a subtree read's tokens are a text array")
        };
        let tokens: Vec<[u8; 16]> = tokens.iter().map(|t| tag(t)).collect();
        let read = vec![doc
            .subtree(&tokens)
            .into_iter()
            .map(|(j, _, d)| row(j, Some(u64::from(d))))
            .collect::<Vec<_>>()];
        for (what, request, rows) in [
            (
                "json_open (selector)",
                object(vec![
                    ("operation", frame("selector")),
                    ("path", frame("$.name")),
                ]),
                selected,
            ),
            (
                "json_open (subtree)",
                object(vec![
                    ("operation", frame("subtree")),
                    ("path", frame("$.visits")),
                ]),
                read,
            ),
        ] {
            let rows = frame(rows);
            let opened = watched(what, || {
                rt.block_on(async {
                    json_open(&keyset, &plan, "profile", &request, &rows, &Documents)
                        .expect("a read")
                        .await
                        .expect("its values")
                })
            });
            assert!(opened
                .risky_ref()
                .windows(MARK.len())
                .any(|window| window == MARK));
        }
        *KEY.lock().unwrap() = None;
    }

    /// The spy sees the data key too: a copy of the key a seal was handed,
    /// freed while watched, fails the watch.
    #[test]
    #[should_panic(expected = "freed with plaintext in them")]
    fn the_spy_sees_a_freed_data_key() {
        let rt = runtime();
        let cipher = rt.block_on(cipher());
        let value = document();
        let _ = sealed(&rt, &cipher, &value, true);
        let key = KEY.lock().unwrap().expect("the seal recorded its key");
        let copy = key.to_vec();
        watched("control (key)", || drop(copy));
    }
}
