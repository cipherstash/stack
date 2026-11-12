//! No heap block the extension frees during `encrypt`, `query`, `verify` or
//! `decrypt` still contains the plaintext.
//!
//! The scope is the extension's own copies: what this crate and the engine
//! allocate in Rust while they read a Python value, write the input frame,
//! seal it, derive a query term, open a row, and turn an opened value into a
//! Python object. Text and decimals are watched: the text by a marker it
//! contains, a decimal by its digits, as text and as the digit values a
//! `Decimal`'s tuple holds, and by its mantissa as the engine's `i128`. Python's own objects are not watched.
//! CPython allocates them with its own allocator, and the caller owns them, so
//! the SDK makes no promise about them. This includes the `bytes` object that
//! pyo3 makes on its way to a `str`'s UTF-8 under `abi3-py39`.
//!
//! The test binary installs a spy as its global allocator, as stack-encrypt's
//! `tests/heap_hygiene.rs` does. While a test watches its own thread, the spy
//! scans every block freed on that thread for a marker that the plaintext
//! contains. A block freed with the marker still in it is plaintext that a
//! later allocation can read back, and fails the test. The Go SDK's test reads
//! the guest's memory after the call instead, which allocator reuse has
//! mostly overwritten by then. This one sees each free as it happens.
//!
//! One free is excluded by name, as in stack-encrypt's test: vitaminc's
//! aws-lc backend frees an unwiped plaintext buffer on every seal, which is
//! vitaminc's to fix. The spy counts those, and recognises them by their
//! backtrace, so a build without symbols fails rather than passes.
//!
//! Unix only: the spy scans a freed block with libc's `memmem`. CI runs it on
//! Linux.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ffi::c_void;
use std::sync::Mutex;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyString, PyType};
use stack_encrypt::StackCipher;
use stack_kms::FakeDataKeySource;

use stackencrypt_core::decrypt::{decrypt_with, Row, Rows};
use stackencrypt_core::encrypt::{encrypt_with, Column};
use stackencrypt_core::query::{query_with, OpSpec};

use crate::encrypt::{build_plan, field_value, input_frame, Plan};
use crate::values::to_python;

/// What every text plaintext under test contains.
const MARK: &[u8] = b"zq-heap-marker-7f3a9c";

/// The decimal under test, and its digits as the extension handles them:
/// as text, and as the digit values of `Decimal.as_tuple()`.
const DECIMAL: &str = "86753091415926.5358979";
const DIGITS: &[u8] = b"867530914159265358979";
const DIGIT_VALUES: &[u8] = &[
    8, 6, 7, 5, 3, 0, 9, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9,
];

/// The decimal's mantissa as the engine holds it: an `i128`, little-endian,
/// to its last byte that is not zero.
const MANTISSA: [u8; 9] = {
    let bytes = 867_530_914_159_265_358_979_i128.to_le_bytes();
    [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
    ]
};

/// Every needle a freed block must not contain.
const NEEDLES: [&[u8]; 4] = [MARK, DIGITS, DIGIT_VALUES, &MANTISSA];

thread_local! {
    static WATCHING: Cell<bool> = const { Cell::new(false) };
    static BUSY: Cell<bool> = const { Cell::new(false) };
}

/// Held for the whole of a watch: the harness runs tests on several threads,
/// and the findings below are one set.
static GATE: Mutex<()> = Mutex::new(());

/// Held for the whole of each test, taken before the test attaches to
/// Python. Without it, one test can hold [`GATE`] and wait for the GIL while
/// another holds the GIL and waits for [`GATE`].
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The marked frees seen, as backtraces; and how many were vitaminc's.
static FOUND: Mutex<Vec<String>> = Mutex::new(Vec::new());
static UPSTREAM: Mutex<usize> = Mutex::new(0);

/// The vitaminc frame whose free is excluded (see the module docs).
const UPSTREAM_SEAL: &str = "vitaminc_encrypt::backend::aws_lc::CipherKey::seal";

/// Whether the `len` bytes at `ptr` contain one of [`NEEDLES`]. A freed
/// block can hold bytes Rust never initialised, and reading those through a
/// `&[u8]` is undefined behaviour, so the scan is libc's `memmem`.
///
/// # Safety
///
/// `ptr` must point to `len` allocated bytes.
unsafe fn has_mark(ptr: *const u8, len: usize) -> bool {
    extern "C" {
        fn memmem(
            haystack: *const c_void,
            haystack_len: usize,
            needle: *const c_void,
            needle_len: usize,
        ) -> *mut c_void;
    }
    NEEDLES
        .iter()
        .any(|needle| !memmem(ptr.cast(), len, needle.as_ptr().cast(), needle.len()).is_null())
}

struct Spy;

unsafe impl GlobalAlloc for Spy {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Zeroed, so a block holds only what was written into it during its
        // own lifetime, not what an earlier free left there.
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let watching = WATCHING.with(Cell::get) && !BUSY.with(Cell::get);
        // SAFETY: `ptr` is a live block of `layout.size()` bytes until the
        // `System.dealloc` below.
        if watching && has_mark(ptr, layout.size()) {
            BUSY.with(|busy| busy.set(true));
            let trace = std::backtrace::Backtrace::force_capture().to_string();
            // Linux writes `<…::CipherKey>::seal`, macOS `…::CipherKey::seal`.
            if trace.replace(['<', '>'], "").contains(UPSTREAM_SEAL) {
                // A panic here, inside the allocator, would abort the whole
                // test binary with no message, so a poisoned lock is used
                // as it is, as GATE is.
                *UPSTREAM
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) += 1;
            } else {
                FOUND
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(format!("{} bytes freed unwiped:\n{trace}", layout.size()));
            }
            BUSY.with(|busy| busy.set(false));
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static SPY: Spy = Spy;

/// Zero the stack below the caller's frame, so that a future the engine
/// boxes copies zeros, not what earlier work left on the stack.
#[inline(never)]
fn scrub_stack() {
    let mut pad = [0u8; 256 * 1024];
    for byte in pad.iter_mut() {
        // SAFETY: a volatile write to a live local, so it is not elided.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::hint::black_box(&pad);
}

/// Run `f` with this thread watched, and fail if any block it freed still
/// contained the marker.
fn watched<T>(what: &str, f: impl FnOnce() -> T) -> T {
    let _gate = GATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
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

fn marked(tail: &str) -> String {
    format!("{}-{tail}", std::str::from_utf8(MARK).unwrap())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
}

/// A plan for `users`: a text field with an equality index, one with none,
/// and a decimal with an equality index.
fn plan(py: Python<'_>) -> Plan {
    let text = || py.get_type::<PyString>();
    let decimal = decimal_type(py).cast_into::<PyType>().unwrap();
    build_plan(
        py,
        "users",
        vec![
            (
                "email".into(),
                Some("TextEq".into()),
                Some("string".into()),
                text(),
                false,
            ),
            (
                "note".into(),
                Some("Text".into()),
                Some("string".into()),
                text(),
                false,
            ),
            (
                "amount".into(),
                Some("NumericEq".into()),
                Some("decimal".into()),
                decimal,
                false,
            ),
        ],
    )
    .unwrap()
}

fn decimal_type(py: Python<'_>) -> Bound<'_, PyAny> {
    py.import("decimal").unwrap().getattr("Decimal").unwrap()
}

/// A model as `encrypt` reads it: an object with one attribute per field.
fn model<'py>(py: Python<'py>, email: &str, note: &str) -> Bound<'py, PyAny> {
    let fields = PyDict::new(py);
    fields.set_item("email", email).unwrap();
    fields.set_item("note", note).unwrap();
    fields
        .set_item("amount", decimal_type(py).call1((DECIMAL,)).unwrap())
        .unwrap();
    py.import("types")
        .unwrap()
        .getattr("SimpleNamespace")
        .unwrap()
        .call((), Some(&fields))
        .unwrap()
}

fn cipher(runtime: &tokio::runtime::Runtime) -> StackCipher<FakeDataKeySource> {
    runtime
        .block_on(StackCipher::builder().kms(FakeDataKeySource::new()).init())
        .unwrap()
}

/// Two marked models, encrypted outside any watch.
fn stored(
    py: Python<'_>,
    runtime: &tokio::runtime::Runtime,
    cipher: &StackCipher<FakeDataKeySource>,
    plan: &Plan,
) -> Vec<Vec<Column>> {
    let models = vec![
        model(py, &marked("a@example.com"), &marked("a note")),
        model(py, &marked("b@example.com"), &marked("another note")),
    ];
    let frame = input_frame(py, plan, &models).unwrap();
    runtime
        .block_on(encrypt_with(
            &cipher.default_keyset(),
            &plan.plan,
            frame,
            models.len(),
        ))
        .unwrap()
}

#[test]
fn encrypt_frees_no_copy_of_the_plaintext_unwiped() {
    let _serial = serial();
    Python::initialize();
    let runtime = runtime();
    let cipher = cipher(&runtime);
    Python::attach(|py| {
        let plan = plan(py);
        // The Python objects are made before the watch: they are the
        // caller's, not the extension's.
        let models = vec![
            model(py, &marked("a@example.com"), &marked("a note")),
            model(py, &marked("b@example.com"), &marked("another note")),
        ];

        let rows = watched("encrypt", || {
            let frame = input_frame(py, &plan, &models).unwrap();
            runtime
                .block_on(encrypt_with(
                    &cipher.default_keyset(),
                    &plan.plan,
                    frame,
                    models.len(),
                ))
                .unwrap()
        });

        assert_eq!(rows.len(), 2);
    });
}

#[test]
fn query_frees_no_copy_of_the_plaintext_unwiped() {
    let _serial = serial();
    Python::initialize();
    let runtime = runtime();
    let cipher = cipher(&runtime);
    Python::attach(|py| {
        let plan = plan(py);
        let text = PyString::new(py, &marked("a@example.com")).into_any();
        let decimal = decimal_type(py).call1((DECIMAL,)).unwrap();

        for (at, value) in [(0, &text), (2, &decimal)] {
            let (field, kind) = (&plan.plan.fields()[at], plan.kinds[at]);
            let Some((_, engine_kind)) = field.eql else {
                panic!("{} is sealed", field.name);
            };
            let term = watched("query", || {
                let read = field_value(value, field, kind).unwrap().unwrap();
                runtime
                    .block_on(query_with(
                        &cipher.default_keyset(),
                        &plan.plan,
                        &field.name,
                        OpSpec::Eq,
                        engine_kind,
                        read.value(),
                    ))
                    .unwrap()
            });
            assert!(!term.as_bytes().windows(MARK.len()).any(|w| w == MARK));
        }
    });
}

#[test]
fn decrypt_frees_no_copy_of_the_plaintext_unwiped() {
    let _serial = serial();
    Python::initialize();
    let runtime = runtime();
    let cipher = cipher(&runtime);
    Python::attach(|py| {
        let plan = plan(py);
        let stored = stored(py, &runtime, &cipher, &plan);

        let opened = watched("decrypt", || {
            let mut rows = Rows::with_capacity(stored.len());
            for columns in &stored {
                let mut row = Row::new();
                for (field, column) in plan.plan.fields().iter().zip(columns) {
                    let Column::Eql(json) = column else {
                        panic!("{} is sealed", field.name);
                    };
                    row.eql(&plan.plan, field, json.as_bytes()).unwrap();
                }
                rows.push(row);
            }
            let opened = runtime
                .block_on(decrypt_with(&cipher, &plan.plan, rows))
                .unwrap();
            // Each value as the Python object `decrypt` builds the instance
            // from. The objects are the caller's once returned.
            let objects = opened
                .iter()
                .flatten()
                .map(|scalar| to_python(py, scalar).unwrap().unwrap())
                .collect::<Vec<_>>();
            drop(opened);
            objects
        });

        assert_eq!(opened.len(), 6);
        assert_eq!(
            opened[0].bind(py).extract::<String>().unwrap(),
            marked("a@example.com")
        );
    });
}

#[test]
fn verify_frees_no_copy_of_the_plaintext_unwiped() {
    let _serial = serial();
    Python::initialize();
    Python::attach(|py| {
        let plan = build_plan(
            py,
            "notes",
            vec![(
                "body".into(),
                Some("TextMatch".into()),
                Some("string".into()),
                py.get_type::<PyString>(),
                false,
            )],
        )
        .unwrap();
        // The Python objects are made before the watch: they are the
        // caller's, not the extension's.
        let text = PyString::new(py, &marked("a note")).into_any();
        let values =
            PyList::new(py, [marked("a note in full"), "nothing here".to_owned()]).unwrap();

        // The binding `Cipher.verify` calls, as Python calls it.
        let kept = watched("verify", || {
            crate::query::verify(py, &plan, "body", &text, &values).unwrap()
        });

        assert_eq!(kept, [true, false]);
    });
}

/// The spy is not blind: a copy of each needle freed unwiped fails the
/// watch. If frees went unseen (another thread, an exclusion matching too
/// much), the three tests above would pass whatever the extension did.
#[test]
fn the_spy_fails_a_copy_freed_unwiped() {
    let _serial = serial();
    for needle in NEEDLES {
        let leaked = std::panic::catch_unwind(|| {
            watched("a leak", || drop(std::hint::black_box(needle.to_vec())));
        });
        assert!(leaked.is_err(), "the spy missed {needle:?}");
    }
}
