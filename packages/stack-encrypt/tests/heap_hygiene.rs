//! No heap block the dynamic paths free still holds plaintext.
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
//! Unix only: the spy scans a freed block with libc's `memmem`, not as a
//! Rust slice (see [`holds_mark`]).
#![cfg(all(feature = "dynamic", unix))]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::Mutex;

use common::frames::{frame, object};
use stack_encrypt::dynamic::{query_term, record, verify, NoTargets, OpSpec, Scope, ValueFrame};
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

struct Spy;

unsafe impl GlobalAlloc for Spy {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let watching = WATCHING.with(Cell::get) && !BUSY.with(Cell::get);
        if watching {
            // SAFETY: `ptr` is a live block of `layout.size()` bytes until
            // the `System.dealloc` below.
            if holds_mark(ptr, layout.size()) {
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
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static SPY: Spy = Spy;

/// Run `f` with this thread watched, and fail if any block it freed held
/// the marker.
fn watched<T>(what: &str, f: impl FnOnce() -> T) -> T {
    let _gate = GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    FOUND.lock().unwrap().clear();
    *UPSTREAM.lock().unwrap() = 0;
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
        .risky_ref(),
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
            record::decrypt(Scope::Client(&cipher), sealed, &plan, None)
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

#[test]
fn a_query_term_leaves_no_plaintext_on_the_heap() {
    let rt = runtime();
    let cipher = rt.block_on(common::stack_cipher());
    let keyset = cipher.default_keyset();
    let plan = plan();
    // The order operators answer over integers alone, which carry no
    // marker; equality and match read text.
    for operator in [OpSpec::Eq, OpSpec::Matches] {
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
        let matched = verify(&plan, "email", OpSpec::Matches, &query, values, &NoTargets).unwrap();
        assert_eq!(matched.len(), 2);
        drop(page);
        drop(query);
    });
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
