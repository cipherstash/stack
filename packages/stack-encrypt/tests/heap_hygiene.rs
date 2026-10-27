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

/// The data key the JSON tests' key source last handed out, which a freed
/// block must not hold either (see [`json_index`]). Set outside any
/// allocation: a fixed array behind a lock.
static KEY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

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
/// # Safety
///
/// `ptr` must point to `len` allocated bytes.
unsafe fn holds_key(ptr: *const u8, len: usize) -> bool {
    BUSY.with(|busy| busy.set(true));
    let key = KEY.lock().map(|key| *key).unwrap_or(None);
    BUSY.with(|busy| busy.set(false));
    key.is_some_and(|key| find(ptr, len, &key))
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
        System.alloc_zeroed(layout)
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
        .with_leaf_query_sql_domain("eql_v4.query_json_leaf")]
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
        &stack_encrypt::dynamic::frame::serde::to_vec(&wire).unwrap(),
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
        (
            OpSpec::Contains,
            object(vec![("json", frame(needle.as_str()))]),
        ),
        (
            OpSpec::EqAt,
            object(vec![
                ("path", frame("$.name")),
                ("json", frame(at.as_str())),
            ]),
        ),
        (
            OpSpec::GtAt,
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
    use stack_encrypt::target::{json_document, AeadContext, Borrowed, CallerContext};
    use stack_encrypt::{op, DecryptFrom, Plan, StackCipher};
    use stack_kms::{
        DataKey, DataKeySource, DataKeyWithTag, DeterministicSource, GenerateKeyPayload,
        IdentifiedBy, IndexKey, IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
    };
    use uuid::Uuid;

    /// The deterministic source, recording every data key it hands out in
    /// [`KEY`] so the spy can look for it.
    struct Recorded(DeterministicSource);

    fn record(key: &DataKey) {
        *KEY.lock().unwrap() = Some(*key.key());
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
    fn options(sealed_root: bool) -> JsonOptions {
        let inner = format!("$[\"{}\"].inner", marked("key"));
        JsonOptions {
            sealed_root,
            ..JsonOptions::new()
        }
        .ordering(["$.long", inner.as_str()])
        .unwrap()
    }

    fn context() -> CallerContext {
        CallerContext::from(nonempty!("users").with("profile"))
    }

    fn aead() -> AeadContext {
        AeadContext::from(nonempty!("users").with("profile"))
    }

    /// A document with the marker in a key name, in a short string, in a
    /// string past 128 bytes, and in an array element under an object.
    fn document() -> Value {
        let mut long = marked("long");
        long.push_str(&"x".repeat(160));
        json!({
            marked("key"): {"inner": marked("short"), "list": [marked("element"), 1, null]},
            "long": long,
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
                        "target": {"name": "JsonSearch", "options": {"ordered": ["$.age"]}}}
        });
        let plan = record::plan_with(
            &stack_encrypt::dynamic::frame::serde::to_vec(&wire).unwrap(),
            &Documents,
        )
        .unwrap();

        let mark = marked("operand");
        let quoted = format!("{mark:?}");
        let document = format!(r#"{{{quoted}: [{quoted}], "name": {quoted}}}"#);
        let inputs = [
            (
                OpSpec::Contains,
                object(vec![("json", frame(document.as_str()))]),
            ),
            (
                OpSpec::EqAt,
                object(vec![
                    ("path", frame("$.name")),
                    ("json", frame(quoted.as_str())),
                ]),
            ),
            (
                OpSpec::GtAt,
                object(vec![
                    ("path", frame("$.age")),
                    ("json", frame(quoted.as_str())),
                ]),
            ),
            (
                OpSpec::BetweenAt,
                object(vec![
                    ("path", frame("$.age")),
                    ("low", frame(quoted.as_str())),
                    ("high", frame(quoted.as_str())),
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
        let operand = |operator: OpSpec, path: &str| {
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
            operand(OpSpec::Selector, "$.name").operand().clone()
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
            operand(OpSpec::Subtree, "$.visits").operand().clone()
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
