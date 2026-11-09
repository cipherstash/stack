//! The shared raw-frame profile: stored records supplied as transport
//! bytes, so both runners feed the decoder what no map-based tree encoder
//! can write, and each refusal is placed in its class. See
//! conformance/stack-encrypt/raw-frames-contract.md.
#![cfg(feature = "dynamic")]
mod common;

use common::{
    conformance::{value, Input},
    frames::{frame, object},
    unhex, CountingSource, DeterministicSource,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use stack_encrypt::dynamic::{record, Scope};
use stack_encrypt::{
    AsProtectedRef as _, CipherText, Controlled as _, ErrorPayload, Node, PassthroughFrame,
    SealedValue, StackCipher, StackCipherText,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;
use vitaminc_aead_frame::{decode_ciphertext, Frame};

type Row = BTreeMap<String, Input>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    version: u32,
    profile: String,
    seed: String,
    required_capabilities: Vec<String>,
    /// What a WASI boundary reports for bytes that are not a ciphertext
    /// tree. The native codec reports no code of its own.
    boundary_error: Refusal,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    kind: String,
    null: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    read: Declaration,
    frame_hex: String,
    class: Class,
    retrievals: usize,
    expected: Option<Refusal>,
    rows: Option<Vec<Row>>,
    /// For a frame the codec refuses: what the engine refuses when the same
    /// bytes are read by a decoder that admits what the codec does not. A
    /// native observation; a binding never reaches the engine with it.
    native_tree: Option<Refusal>,
}

#[derive(Deserialize, Debug, PartialEq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Class {
    /// The bytes are not a ciphertext tree in the transport codec.
    Transport,
    /// The tree decodes, and a sealed leaf is not in the leaf byte format.
    Leaf,
    /// Leaves are well formed, and the tree does not fit the plan.
    Shape,
    /// The tree fits, the leaf authenticates, and what it holds is not what
    /// the plan reads.
    Authenticated,
    Success,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Refusal {
    code: String,
    fields: Map<String, Value>,
}

fn refusal(error: &impl ErrorPayload, want: &Refusal) -> Result<(), String> {
    let code = error
        .code()
        .map(|code| code.to_string())
        .unwrap_or_default();
    let fields = error.payload();
    if code != want.code || fields != want.fields {
        return Err(format!(
            "{code} {fields:?}, expected {} {:?}",
            want.code, want.fields
        ));
    }
    Ok(())
}

/// The transport codec, read as the guest reads a stored record: the tree,
/// then every leaf in the frozen leaf byte format.
fn decode(bytes: &[u8]) -> Result<Result<StackCipherText, stack_encrypt::LeafBytesError>, ()> {
    let tree: Node<Vec<u8>> = decode_ciphertext(bytes).map_err(drop)?;
    Ok(leaves(tree))
}

fn leaves(tree: Node<Vec<u8>>) -> Result<StackCipherText, stack_encrypt::LeafBytesError> {
    Ok(match tree {
        CipherText::Single(leaf) => CipherText::Single(SealedValue::from_bytes(&leaf)?),
        CipherText::EmptySequence(leaf) => {
            CipherText::EmptySequence(SealedValue::from_bytes(&leaf)?)
        }
        CipherText::EmptyMap(leaf) => CipherText::EmptyMap(SealedValue::from_bytes(&leaf)?),
        CipherText::Sequence(items) => {
            CipherText::Sequence(items.into_iter().map(leaves).collect::<Result<_, _>>()?)
        }
        CipherText::Map(entries) => CipherText::Map(
            entries
                .into_iter()
                .map(|(key, value)| Ok((key, leaves(value)?)))
                .collect::<Result<_, _>>()?,
        ),
        CipherText::Passthrough(payload) => CipherText::Passthrough(payload),
    })
}

/// The transport codec's grammar, read without its duplicate-key rule, so
/// the engine can be asked what it makes of a tree the codec refuses. Every
/// other rule (tags, bounds, one frame per passthrough, no trailing bytes)
/// is kept, so a frame this reads and the codec refuses differs in that
/// one respect.
fn lenient(bytes: &[u8]) -> Option<Node<Vec<u8>>> {
    const MAX_DEPTH: usize = 32;
    fn count(bytes: &[u8], at: &mut usize) -> Option<usize> {
        let len = u32::from_le_bytes(bytes.get(*at..*at + 4)?.try_into().ok()?) as usize;
        *at += 4;
        (len <= bytes.len() - *at).then_some(len)
    }
    fn take<'a>(bytes: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
        let len = count(bytes, at)?;
        let taken = &bytes[*at..*at + len];
        *at += len;
        Some(taken)
    }
    fn node(bytes: &[u8], at: &mut usize, depth: usize) -> Option<Node<Vec<u8>>> {
        if depth > MAX_DEPTH {
            return None;
        }
        let tag = *bytes.get(*at)?;
        *at += 1;
        Some(match tag {
            0x01 => CipherText::Single(take(bytes, at)?.to_vec()),
            0x06 => CipherText::EmptySequence(take(bytes, at)?.to_vec()),
            0x07 => CipherText::EmptyMap(take(bytes, at)?.to_vec()),
            0x03 => {
                let n = count(bytes, at)?;
                CipherText::Sequence(
                    (0..n)
                        .map(|_| node(bytes, at, depth + 1))
                        .collect::<Option<_>>()?,
                )
            }
            0x04 => {
                let n = count(bytes, at)?;
                let mut entries = Vec::new();
                for _ in 0..n {
                    let key = String::from_utf8(take(bytes, at)?.to_vec()).ok()?;
                    entries.push((key, node(bytes, at, depth + 1)?));
                }
                CipherText::Map(entries)
            }
            0x05 => {
                let (frame, _) = Frame::parse_nested(&bytes[*at..], depth + 1).ok()?;
                let len = frame.as_bytes().len();
                *at += len;
                CipherText::Passthrough(PassthroughFrame(bytes[*at - len..*at].to_vec()))
            }
            _ => return None,
        })
    }
    let mut at = 0;
    let tree = node(bytes, &mut at, 0)?;
    (at == bytes.len()).then_some(tree)
}

fn plan(read: &Declaration) -> record::Plan {
    assert!(["", "sql", "sealed"].contains(&read.null.as_str()));
    let mut spec =
        json!({"context": ["conformance", "value"], "outputs": ["c", "eq"], "type": read.kind});
    if !read.null.is_empty() {
        spec["null"] = json!(read.null);
    }
    record::plan(
        vitaminc_aead_frame::serde::to_vec(&json!({"value": spec}))
            .unwrap()
            .as_protected_ref(),
    )
    .unwrap()
}

#[tokio::test]
async fn shared_raw_frame_profile() {
    let corpus: Corpus = serde_json::from_str(include_str!(
        "../../../conformance/stack-encrypt/v1/record-raw-frames-v1.cases.json"
    ))
    .unwrap();
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.profile, "record-raw-frames-v1");
    assert_eq!(
        corpus.required_capabilities,
        [
            "records",
            "raw-frames",
            "read-shapes",
            "authenticated-types"
        ]
    );
    assert_eq!(
        corpus.boundary_error.code,
        "stack_guest_abi::malformed_input"
    );
    assert!(corpus.boundary_error.fields.is_empty());
    assert!(!corpus.cases.is_empty());
    // The deterministic source with ZeroKMS call counters, so a frozen leaf
    // opens and the stage of a refusal is observed.
    let source = CountingSource::over(DeterministicSource::new(
        unhex(&corpus.seed).try_into().expect("32-byte seed"),
    ));
    let (generates, retrieves) = source.counters();
    let cipher = StackCipher::builder()
        .kms(source)
        .init()
        .await
        .expect("build cipher");
    let keyset = cipher.default_keyset();
    let mut ids = BTreeSet::new();
    let mut failures = Vec::new();
    for case in &corpus.cases {
        assert!(!case.id.is_empty() && ids.insert(case.id.clone()));
        eprintln!("raw frame conformance: {}", case.id);
        let mut fail = |message: String| failures.push(format!("{}: {message}", case.id));
        // A case says exactly what its class needs: a refusal for every
        // class but success and transport (whose refusal is the corpus-wide
        // boundary error), rows for success alone, retrieval only once the
        // shape has passed, and a native tree only for a frame the codec
        // refuses.
        assert_eq!(
            case.expected.is_none(),
            matches!(case.class, Class::Success | Class::Transport)
        );
        assert_eq!(case.rows.is_some(), case.class == Class::Success);
        assert_eq!(
            case.retrievals,
            usize::from(matches!(case.class, Class::Authenticated | Class::Success))
        );
        assert!(case.native_tree.is_none() || case.class == Class::Transport);
        let bytes = unhex(&case.frame_hex);
        let plan = plan(&case.read);
        generates.store(0, Ordering::SeqCst);
        retrieves.store(0, Ordering::SeqCst);
        let tree = match decode(&bytes) {
            Err(()) => {
                if case.class != Class::Transport {
                    fail("the codec refused the frame".into());
                }
                if let Some(want) = &case.native_tree {
                    match lenient(&bytes).map(leaves) {
                        Some(Ok(tree)) => match record::check_record(tree, &plan, None) {
                            Ok(()) => fail("the engine accepted the lenient tree".into()),
                            Err(error) => {
                                if let Err(message) = refusal(&error, want) {
                                    fail(format!("native tree: {message}"));
                                }
                            }
                        },
                        _ => fail("the lenient reader refused the frame too".into()),
                    }
                } else if lenient(&bytes).is_some() {
                    // The lenient reader is the codec without the
                    // repeated-key rule. If it reads the frame, that rule
                    // is the only reason the codec refused it.
                    fail(
                        "only the repeated-key rule refuses this frame; give it a native_tree"
                            .into(),
                    );
                }
                continue;
            }
            Ok(Err(error)) => {
                if case.class != Class::Leaf {
                    fail(format!("a leaf is malformed: {error:?}"));
                } else if let Err(message) = refusal(&error, case.expected.as_ref().unwrap()) {
                    fail(message);
                }
                continue;
            }
            Ok(Ok(tree)) => tree,
        };
        if matches!(case.class, Class::Transport | Class::Leaf) {
            fail("the frame decoded with well-formed leaves".into());
            continue;
        }
        let want = case.expected.as_ref();
        // The key-free preflight judges the shape alone: it refuses a shape
        // case as decrypt does, and passes every tree that fits the plan.
        let Ok(Ok(preflight)) = decode(&bytes) else {
            unreachable!("decoded once already")
        };
        match (case.class, record::check_record(preflight, &plan, None)) {
            (Class::Shape, Err(error)) => {
                if let Err(message) = refusal(&error, want.unwrap()) {
                    fail(format!("check_record: {message}"));
                }
            }
            (Class::Shape, Ok(())) => fail("check_record accepted the shape".into()),
            (_, Err(error)) => fail(format!("check_record refused a fitting tree: {error:?}")),
            (_, Ok(())) => {}
        }
        let result = record::decrypt(Scope::Keyset(keyset.clone()), tree, &plan, None);
        match (case.class, result) {
            (Class::Shape, Err(error)) => {
                if let Err(message) = refusal(&error, want.unwrap()) {
                    fail(message);
                }
            }
            (Class::Shape, Ok(_)) => fail("the shape was accepted".into()),
            (_, Err(error)) => fail(format!("refused before any pending operation: {error:?}")),
            (Class::Authenticated, Ok(pending)) => match pending.await {
                Ok(_) => fail("opened".into()),
                Err(error) => {
                    if let Err(message) = refusal(&error, want.unwrap()) {
                        fail(message);
                    }
                }
            },
            (Class::Success, Ok(pending)) => match pending.await {
                Err(error) => fail(format!("did not open: {error:?}")),
                Ok(opened) => {
                    let rows: Vec<_> = case
                        .rows
                        .as_ref()
                        .unwrap()
                        .iter()
                        .map(|row| object(row.iter().map(|(k, v)| (k, value(v))).collect()))
                        .collect();
                    if opened.risky_ref() != frame(rows).risky_ref() {
                        fail("typed rows differ".into());
                    }
                }
            },
            (Class::Transport | Class::Leaf, Ok(_)) => unreachable!(),
        }
        if generates.load(Ordering::SeqCst) != 0 {
            fail("a read generated a data key".into());
        }
        let retrieved = retrieves.load(Ordering::SeqCst);
        if retrieved != case.retrievals {
            fail(format!(
                "{retrieved} retrievals, expected {}",
                case.retrievals
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The lenient reader differs from the codec in the duplicate-key rule
/// alone: it reads every frame the codec reads, to the same tree.
#[test]
fn the_lenient_reader_agrees_with_the_codec_on_what_the_codec_accepts() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../conformance/stack-encrypt/v1/record-raw-frames-v1.cases.json"
    ))
    .unwrap();
    let mut compared = 0;
    for case in corpus["cases"].as_array().unwrap() {
        let bytes = unhex(case["frame_hex"].as_str().unwrap());
        if let Ok(codec) = decode_ciphertext::<Vec<u8>>(&bytes) {
            let ours = lenient(&bytes).expect("the lenient reader reads what the codec reads");
            assert_eq!(
                vitaminc_aead_frame::serde::to_vec(&json!(encoded(&ours)))
                    .unwrap()
                    .risky_ref(),
                vitaminc_aead_frame::serde::to_vec(&json!(encoded(&codec)))
                    .unwrap()
                    .risky_ref(),
                "{}",
                case["id"]
            );
            compared += 1;
        }
    }
    assert!(compared > 0);
}

/// A tree as JSON, for comparison only.
fn encoded(tree: &Node<Vec<u8>>) -> Value {
    match tree {
        CipherText::Single(leaf) => json!({"single": common::hex(leaf)}),
        CipherText::EmptySequence(leaf) => json!({"empty_sequence": common::hex(leaf)}),
        CipherText::EmptyMap(leaf) => json!({"empty_map": common::hex(leaf)}),
        CipherText::Sequence(items) => json!(items.iter().map(encoded).collect::<Vec<_>>()),
        CipherText::Map(entries) => json!(entries
            .iter()
            .map(|(k, v)| json!([k, encoded(v)]))
            .collect::<Vec<_>>()),
        CipherText::Passthrough(payload) => json!({"passthrough": common::hex(&payload.0)}),
    }
}
