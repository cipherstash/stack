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
#![cfg(feature = "dynamic")]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Mutex;

use stack_encrypt::dynamic::{
    query_term, record, verify, FfiValue, NoTargets, OpSpec, Scope, ValueFrame,
};
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
            let block = std::slice::from_raw_parts(ptr, layout.size());
            if block.windows(MARK.len()).any(|window| window == MARK) {
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

fn s(value: &str) -> FfiValue {
    FfiValue::String(value.into())
}

fn strings(values: &[&str]) -> FfiValue {
    FfiValue::Array(values.iter().map(|value| s(value)).collect())
}

fn spec(field: &str, outputs: &[&str], ty: Option<&str>) -> (String, FfiValue) {
    let mut entries = vec![
        ("context".to_string(), strings(&["users", field])),
        ("outputs".to_string(), strings(outputs)),
    ];
    if let Some(ty) = ty {
        entries.push(("type".to_string(), s(ty)));
    }
    (field.to_string(), FfiValue::Object(entries))
}

fn plan() -> record::Plan {
    record::plan(FfiValue::Object(vec![
        spec("email", &["c", "eq", "match", "ore"], Some("string")),
        spec("doc", &["c"], None),
        spec("id", &["passthrough"], None),
    ]))
    .unwrap()
}

/// A row with a marked scalar field, a marked nested object field, and a
/// passthrough, as its frame. The `FfiValue` it is built from is dropped
/// before anything is watched: it is the test's input, not the engine's.
fn row() -> ValueFrame {
    let row = FfiValue::Object(vec![
        ("email".into(), s(&marked("email"))),
        (
            "doc".into(),
            FfiValue::Object(vec![
                ("k".into(), s(&marked("doc"))),
                (
                    "n".into(),
                    FfiValue::Array(vec![s(&marked("nested")), FfiValue::Null]),
                ),
            ]),
        ),
        ("id".into(), FfiValue::UInt64(7)),
    ]);
    ValueFrame::of(&row).unwrap()
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
        let query = ValueFrame::of(s(&marked("query"))).unwrap();
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

#[test]
fn verify_leaves_no_plaintext_on_the_heap() {
    let plan = plan();
    let query = ValueFrame::of(s(&marked("query"))).unwrap();
    let page = ValueFrame::of(FfiValue::Array(vec![s(&marked("page")), FfiValue::Null])).unwrap();
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
