//! No heap block an EQL target's encrypt, decrypt or query frees still
//! holds plaintext.
//!
//! This binary installs its own global allocator: a spy that, while a test
//! watches its own thread, scans every block freed on that thread for a
//! marker the test's plaintext carries, and fails the test on one. It is the
//! regression test for the opened `String` an EQL decrypt used to free
//! unwiped (`Plaintext::into_frame`), and holds every text target's three
//! paths to the same rule. stack-encrypt's `tests/heap_hygiene.rs` holds
//! its dynamic paths the same way.
//!
//! One free is excluded by name: vitaminc-encrypt 0.6.0's aws-lc backend
//! (`backend::aws_lc::CipherKey::seal`, native builds only) frees an unwiped
//! plaintext buffer on every seal. That is vitaminc's to fix; the spy
//! recognises those frees by their backtrace, so a build without symbols
//! fails rather than passes.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Mutex;

use eql_bindings::encryption::targets;
use stack_encrypt::dynamic::{FfiValue, ValueFrame};
use stack_encrypt::{Label, StackCipher};
use stack_kms::FakeDataKeySource;

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

fn text(value: &str) -> ValueFrame {
    ValueFrame::of(FfiValue::String(value.into())).unwrap()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

/// The producible EQL types over text, each with whether it has a query.
const TEXT_TARGETS: [(&str, bool); 3] = [("Text", false), ("TextEq", true), ("TextMatch", true)];

#[test]
fn a_text_target_leaves_no_plaintext_on_the_heap() {
    let rt = runtime();
    let cipher = rt.block_on(async {
        StackCipher::builder()
            .kms(FakeDataKeySource::new())
            .init()
            .await
            .unwrap()
    });
    let keyset = cipher.default_keyset();
    let label = Label::new(["users", "email"]).unwrap();
    for (name, has_query) in TEXT_TARGETS {
        let plaintext = text(&marked("stored"));
        let stored = watched(&format!("{name} encrypt"), || {
            rt.block_on(async {
                targets::encrypt(name, &keyset, &label, plaintext)
                    .unwrap()
                    .await
                    .unwrap()
            })
        });
        watched(&format!("{name} decrypt"), || {
            let opened = rt.block_on(async {
                targets::decrypt(name, &cipher, &label, &stored)
                    .unwrap()
                    .await
                    .unwrap()
            });
            assert!(opened
                .risky_ref()
                .windows(MARK.len())
                .any(|window| window == MARK));
            drop(opened);
        });
        watched(&format!("{name} decrypt (keyset)"), || {
            let opened = rt.block_on(async {
                targets::decrypt(name, &keyset, &label, &stored)
                    .unwrap()
                    .await
                    .unwrap()
            });
            drop(opened);
        });
        if has_query {
            let query = text(&marked("query"));
            watched(&format!("{name} query"), || {
                rt.block_on(async {
                    targets::query(name, &keyset, &label, query)
                        .unwrap()
                        .await
                        .unwrap()
                })
            });
        }
    }
}

/// The spy itself: a plain `String` holding the marker, freed while
/// watched, fails the watch.
#[test]
#[should_panic(expected = "freed with plaintext in them")]
fn the_spy_sees_an_unwiped_free() {
    let text = marked("control");
    watched("control", || drop(text));
}
