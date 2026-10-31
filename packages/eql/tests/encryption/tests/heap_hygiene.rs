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
//! plaintext buffer on every seal; that is vitaminc's to fix. It is counted
//! and printed, never silent, and every other free on those paths is still
//! watched. The spy recognises these frees by their backtrace, so a build
//! without symbols fails rather than passes.

//!
//! Unix only: the spy scans a freed block with libc's `memmem`, not as a
//! Rust slice (see [`holds_mark`]).
#![cfg(unix)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::Mutex;

use eql_bindings::encryption::targets;
use stack_encrypt::dynamic::ValueFrame;
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

/// The marked frees seen, as backtraces; and how many each exclusion took.
static FOUND: Mutex<Vec<String>> = Mutex::new(Vec::new());
static EXCLUDED: Mutex<[usize; 1]> = Mutex::new([0; 1]);

/// The frames whose frees are excluded, each with what it is (see the module
/// docs): vitaminc's aws-lc seal.
const EXCLUSIONS: [(&str, &str); 1] = [(
    "vitaminc_encrypt::backend::aws_lc::CipherKey::seal",
    "vitaminc's aws-lc seal",
)];

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
                let plain = trace.replace(['<', '>'], "");
                if let Some(at) = EXCLUSIONS
                    .iter()
                    .position(|(frame, _)| plain.contains(frame))
                {
                    EXCLUDED.lock().unwrap()[at] += 1;
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
    *EXCLUDED.lock().unwrap() = [0; 1];
    WATCHING.with(|on| on.set(true));
    let out = f();
    WATCHING.with(|on| on.set(false));
    let found = std::mem::take(&mut *FOUND.lock().unwrap());
    let excluded = std::mem::take(&mut *EXCLUDED.lock().unwrap());
    for ((_, name), skipped) in EXCLUSIONS.iter().zip(excluded) {
        if skipped > 0 {
            eprintln!("{what}: skipped {skipped} unwiped frees in {name}");
        }
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
    ValueFrame::of(value).unwrap()
}

/// Every index the target carries, each of which a query may be asked
/// through. A type whose query is built per index (`TextSearch`) runs a
/// different projection, and its conversion into the query twin, for each.
fn indexes_of(target: &targets::Target) -> Vec<stack_encrypt::target::IndexSpec> {
    target
        .indexes
        .iter()
        .map(|key| stack_encrypt::target::IndexSpec::parse(key).expect("an engine index key"))
        .collect()
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

/// The producible EQL types over text, read from the target table so a type
/// that becomes producible is watched without an edit here.
fn text_targets() -> Vec<&'static targets::Target> {
    let found: Vec<_> = targets::targets()
        .iter()
        .filter(|target| target.family == "text" && target.producible)
        .collect();
    assert!(
        found.iter().any(|target| target.query.is_none())
            && found.iter().any(|target| target.query.is_some()),
        "the table lists a storage-only and a queried text type"
    );
    found
}

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
    for target in text_targets() {
        let name = target.name;
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
        if target.query.is_none() {
            continue;
        }
        for index in indexes_of(target) {
            let query = text(&marked("query"));
            watched(&format!("{name} query through {}", index.key()), || {
                rt.block_on(async {
                    targets::query(name, &index, &keyset, &label, query)
                        .unwrap()
                        .await
                        .unwrap()
                })
            });
        }
    }
}

/// A JSON document at the engine's boundary: the parser a binding's text
/// goes through (`json::parse_text`), with the marker in a string that has
/// escapes (decoded into its own buffer, not borrowed) and past 128 bytes;
/// a refused string, whose buffer is wiped; and the text an opened document
/// goes back as (`dynamic::json_frame`), written into a buffer that never
/// reallocates.
///
/// The documents are strings: this binary's tests share one process, and a
/// container's buffer (a `Vec` or a `BTreeMap` node) has unused slots that
/// can hold another test's freed bytes. stack-encrypt's `heap_hygiene`,
/// run one test to a process, holds containers to the same rule.
///
/// The seal and open themselves are the JSON index's
/// (`stack_encrypt::json`), which is not held to this rule yet: its path
/// derivation frees key and leaf plaintext unwiped, so they are not
/// watched here.
#[test]
fn a_document_leaves_no_plaintext_on_the_heap_at_the_boundary() {
    let mark = marked("doc");
    let pad = "x".repeat(160);
    let document = joined(&[r#"""#, &mark, r#"\n\"quoted\" "#, &pad, r#"""#]);
    let value = watched("parse_text", || {
        stack_encrypt::json::parse_text(document.as_bytes()).unwrap()
    });
    watched("json_frame", || {
        let frame = stack_encrypt::dynamic::json_frame(&value).unwrap();
        drop(frame);
    });
    watched("wipe_value", || {
        let mut value = value;
        stack_encrypt::json::wipe_value(&mut value);
    });
    for refused in [
        joined(&[r#"""#, &mark, r#"\n\x""#]),
        joined(&[r#"""#, &mark, r#"\n"#, &pad]),
    ] {
        watched("parse_text refusal", || {
            assert!(stack_encrypt::json::parse_text(refused.as_bytes()).is_err());
        });
    }
    drop(document);
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
/// watched, fails the watch.
#[test]
#[should_panic(expected = "freed with plaintext in them")]
fn the_spy_sees_an_unwiped_free() {
    let text = marked("control");
    watched("control", || drop(text));
}
