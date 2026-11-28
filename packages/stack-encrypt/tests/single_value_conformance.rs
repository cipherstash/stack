//! The shared single-value profile: one value as one ciphertext through the
//! run-time interface, with what it seals held to the typed interface and
//! to frozen artifacts. See conformance/stack-encrypt/single-value-contract.md.
// The typed `Uuid` reference needs the `uuid` feature, which `dynamic` does
// not turn on.
#![cfg(all(feature = "dynamic", feature = "uuid"))]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use common::conformance::{value, Input};
use common::frames::{frame, object, owned};
use common::leaves::{kept_cipher, parts};
use common::{hex, unhex, CountingSource, DeterministicSource};
use miette::Diagnostic as _;
use serde::{Deserialize, Serialize};
use stack_encrypt::dynamic::{self, frame::OwnedFrame, value as single, ValueKind};
use stack_encrypt::json::JsonPlaintext;
use stack_encrypt::kms::{DataKeySource, IndexKeySource};
use stack_encrypt::value::{Date, Decimal, Timestamp, Uuid};
use stack_encrypt::{
    AsProtectedRef as _, CipherRef, Ciphertext, ContextPiece, Decrypt as _, Encrypt as _, Error,
    IntoContext, KeysetCipher, Pending, StackCipher,
};
use vitaminc_aead::frame::{Frame, PASSTHROUGH};
use vitaminc_aead::plaintext::{FixedType, Width};

const PROFILE: &str = "single-value-v1";

/// The values an input of type `shape` names: what `{type, text}` cannot
/// spell. A name outside this list is a corpus error.
const SHAPES: [&str; 5] = [
    "array",
    "empty_array",
    "object",
    "passthrough",
    "typed_null",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    version: u32,
    profile: String,
    seed: String,
    required_capabilities: Vec<String>,
    cases: Vec<Case>,
    batches: Vec<Batch>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    /// The declared kind's name, or empty for none.
    kind: String,
    /// The context's parts, or empty for the empty context.
    context: Vec<String>,
    input: Input,
    /// The value the ciphertext holds, where it is not the input: a number
    /// converted to the declared kind, or a document's compact JSON text.
    stored: Option<Input>,
    /// Kinds the ciphertext must refuse to open as.
    refused_as: Option<Vec<String>>,
    expected_error: Option<ExpectedError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    id: String,
    kind: String,
    context: Vec<String>,
    inputs: Vec<Input>,
    /// The values the ciphertexts hold, where they are not the inputs.
    stored: Option<Vec<Input>>,
    expected_error: Option<ExpectedError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedError {
    code: String,
    reason: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifacts {
    version: u32,
    profile: String,
    producer: String,
    cases: BTreeMap<String, Artifact>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    /// The input's transport frame.
    frame: String,
    /// The plaintext the leaf is sealed with: its tag and payload. Absent
    /// for a refused case.
    #[serde(skip_serializing_if = "Option::is_none")]
    leaf: Option<String>,
    /// A ciphertext of the value, frozen. Absent for a refused case.
    #[serde(skip_serializing_if = "Option::is_none")]
    ciphertext: Option<String>,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/stack-encrypt/v1")
}

/// The value an input of type `shape` names.
fn shape(name: &str) -> OwnedFrame {
    assert!(
        SHAPES.contains(&name),
        "{name}: not a shape the profile names"
    );
    match name {
        "array" => frame(vec!["a", "b"]),
        "empty_array" => frame(Vec::<String>::new()),
        "object" => object(vec![("a", frame(1u32))]),
        "passthrough" => {
            let mut bytes = vec![PASSTHROUGH];
            bytes.extend_from_slice(frame("clear").frame().as_bytes());
            owned(&bytes)
        }
        _ => OwnedFrame::typed_null(FixedType::plain(Width::I64).expect("a fixed type")),
    }
}

/// The frame an input names: a shape, or a value in the corpus's
/// `{type, text}` form.
fn input(input: &Input) -> OwnedFrame {
    match input.kind.as_str() {
        "shape" => shape(&input.text),
        _ => value(input),
    }
}

fn declared(kind: &str) -> Option<ValueKind> {
    (!kind.is_empty()).then(|| kind.parse().expect("a kind's name"))
}

/// A case's context, as a binding hands one over: a frame of its parts.
fn piece(parts: &[String]) -> ContextPiece<'static> {
    let frame = recipher_frame::serde::to_vec(&parts).expect("a context frames");
    dynamic::context(frame.as_protected_ref())
        .expect("a context of two text parts")
        .into_inner()
}

/// The run-time encrypt: the form with no context for an empty context,
/// and the form with one otherwise.
fn seal<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    value: Frame<'_>,
    kind: Option<ValueKind>,
    context: &[String],
) -> Result<Pending<'a, Ciphertext, K>, dynamic::Error> {
    if context.is_empty() {
        single::encrypt(keyset, value, kind)
    } else {
        single::encrypt_with_context(keyset, value, kind, piece(context))
    }
}

fn seal_all<'a, K: 'static>(
    keyset: &'a KeysetCipher<'_, K>,
    values: &[OwnedFrame],
    kind: Option<ValueKind>,
    context: &[String],
) -> Result<Pending<'a, Vec<Ciphertext>, K>, dynamic::Error> {
    let frames = values.iter().map(OwnedFrame::frame);
    if context.is_empty() {
        single::encrypt_all(keyset, frames, kind)
    } else {
        single::encrypt_all_with_context(keyset, frames, kind, piece(context))
    }
}

fn open<'a, K: 'static>(
    cipher: impl Into<CipherRef<'a, K>>,
    ciphertext: Ciphertext,
    kind: Option<ValueKind>,
    context: &[String],
) -> Pending<'a, OwnedFrame, K> {
    if context.is_empty() {
        single::decrypt(cipher, ciphertext, kind)
    } else {
        single::decrypt_with_context(cipher, ciphertext, kind, piece(context))
    }
}

fn open_all<'a, K: 'static>(
    cipher: impl Into<CipherRef<'a, K>>,
    ciphertexts: Vec<Ciphertext>,
    kind: Option<ValueKind>,
    context: &[String],
) -> Pending<'a, Vec<OwnedFrame>, K> {
    if context.is_empty() {
        single::decrypt_all(cipher, ciphertexts, kind)
    } else {
        single::decrypt_all_with_context(cipher, ciphertexts, kind, piece(context))
    }
}

/// The context `ciphertext`'s leaf is sealed under, for opening the leaf
/// with a kept key.
fn sealed_under(context: &[String]) -> ContextPiece<'static> {
    if context.is_empty() {
        ().into_context()
    } else {
        piece(context)
    }
}

/// The Rust types the typed interface spells a kind with. `$run` is handed
/// the type for `name`, or the match is `None` for a kind no Rust type
/// spells: a lone 8-bit unsigned integer, and JavaScript's `undefined`.
macro_rules! with_rust_type {
    ($name:expr, $run:ident) => {
        match $name {
            "bool" => Some($run!(bool)),
            "int8" => Some($run!(i8)),
            "int16" => Some($run!(i16)),
            "int32" => Some($run!(i32)),
            "int64" => Some($run!(i64)),
            "int128" => Some($run!(i128)),
            "uint16" => Some($run!(u16)),
            "uint32" => Some($run!(u32)),
            "uint64" => Some($run!(u64)),
            "uint128" => Some($run!(u128)),
            "float32" => Some($run!(f32)),
            "float64" => Some($run!(f64)),
            "string" => Some($run!(String)),
            "bytes" => Some($run!(Vec<u8>)),
            "date" => Some($run!(Date)),
            "timestamp" => Some($run!(Timestamp)),
            "decimal" => Some($run!(Decimal)),
            "uuid" => Some($run!(Uuid)),
            "json" => Some($run!(JsonPlaintext)),
            "uint8" | "undefined" => None,
            other => panic!("{other}: no typed form is listed for this kind"),
        }
    };
}

/// The typed call's ciphertext of the value `stored` holds, as the Rust
/// type `name` names.
async fn typed_seal<K>(
    keyset: &KeysetCipher<'_, K>,
    name: &str,
    stored: &OwnedFrame,
    context: &[String],
) -> Option<Ciphertext>
where
    K: DataKeySource + IndexKeySource + Sync + 'static,
{
    macro_rules! seal_as {
        ($ty:ty) => {{
            let value: $ty = stored
                .visit(<$ty>::sink())
                .expect("the stored value as its Rust type");
            if context.is_empty() {
                keyset.encrypt(value).await
            } else {
                keyset.encrypt_with_context(value, piece(context)).await
            }
            .expect("the typed call seals")
        }};
    }
    with_rust_type!(name, seal_as)
}

/// The value the typed call opens `ciphertext` to, as the Rust type `name`
/// names, written as a frame.
async fn typed_open<K>(
    keyset: &KeysetCipher<'_, K>,
    name: &str,
    ciphertext: Ciphertext,
    context: &[String],
) -> Option<OwnedFrame>
where
    K: DataKeySource + IndexKeySource + Sync + 'static,
{
    macro_rules! open_as {
        ($ty:ty) => {{
            let value: $ty = if context.is_empty() {
                keyset.decrypt(ciphertext).await
            } else {
                keyset
                    .decrypt_with_context(ciphertext, piece(context))
                    .await
            }
            .expect("the typed call opens");
            frame(&value)
        }};
    }
    with_rust_type!(name, open_as)
}

/// A cipher over the seeded source, with its `(generate, retrieve)` call
/// counters.
async fn counting(
    seed: [u8; 32],
) -> (
    StackCipher<CountingSource<DeterministicSource>>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let source = CountingSource::over(DeterministicSource::new(seed));
    let (generates, retrieves) = source.counters();
    let cipher = StackCipher::builder()
        .kms(source)
        .init()
        .await
        .expect("build cipher");
    (cipher, generates, retrieves)
}

fn assert_refusal(id: &str, error: &dynamic::Error, expected: &ExpectedError) {
    assert_eq!(
        error.code().map(|code| code.to_string()).as_deref(),
        Some(expected.code.as_str()),
        "{id}: the diagnostic code"
    );
    assert_eq!(
        error.reason().map(|reason| reason.as_str()),
        Some(expected.reason.as_str()),
        "{id}: the reason"
    );
    assert_eq!(error.field(), None, "{id}: a single value names no field");
}

fn is_forbidden<T>(result: &Result<T, Error>) -> bool {
    matches!(
        result,
        Err(Error::Kms(stack_kms::Error::RetrieveKey(
            stack_kms::RetrieveKeyError::RequestFailed(error)
        ))) if matches!(error.kind, zerokms_protocol::ViturRequestErrorKind::Forbidden)
    )
}

/// One accepted case: what the run-time call seals is what the typed call
/// seals and what the artifact froze, and every reader opens it.
async fn accepted(
    seed: [u8; 32],
    case: &Case,
    value: &OwnedFrame,
    artifact: &mut Artifact,
    baseline: Option<&Artifact>,
) {
    let id = &case.id;
    let kind = declared(&case.kind);
    let stored_input = case.stored.as_ref().unwrap_or(&case.input);
    let stored = input(stored_input);
    let context = &case.context;

    let (cipher, keys) = kept_cipher(seed).await;
    let keyset = cipher.default_keyset();
    let fresh = seal(&keyset, value.frame(), kind, context)
        .unwrap_or_else(|error| panic!("{id}: the value is refused: {error}"))
        .await
        .unwrap_or_else(|error| panic!("{id}: the value does not seal: {error}"));
    let fresh_parts = parts(&keys, fresh.clone(), sealed_under(context));

    // The typed call, over a fresh source of the same seed, so that its
    // data key is the one the run-time call was given.
    let typed_name = if case.kind == "json" {
        "json"
    } else {
        stored_input.kind.as_str()
    };
    let (typed_cipher, typed_keys) = kept_cipher(seed).await;
    let typed = typed_seal(&typed_cipher.default_keyset(), typed_name, &stored, context).await;
    if let Some(typed) = &typed {
        assert_eq!(
            fresh_parts,
            parts(&typed_keys, typed.clone(), sealed_under(context)),
            "{id}: the run-time ciphertext differs from the typed one in a part that is not the nonce"
        );
    }

    artifact.leaf = Some(fresh_parts.leaf.clone());
    artifact.ciphertext = Some(hex(&typed.unwrap_or_else(|| fresh.clone()).to_bytes()));
    let reference: &Artifact = baseline.unwrap_or(artifact);
    assert_eq!(
        artifact.leaf, reference.leaf,
        "{id}: the plaintext the leaf is sealed with"
    );
    let frozen = Ciphertext::from_bytes(&unhex(
        reference
            .ciphertext
            .as_deref()
            .unwrap_or_else(|| panic!("{id}: an accepted case has a frozen ciphertext")),
    ))
    .unwrap_or_else(|error| panic!("{id}: the frozen ciphertext does not parse: {error}"));
    assert_eq!(
        parts(&keys, frozen.clone(), sealed_under(context)),
        fresh_parts,
        "{id}: the frozen ciphertext differs from a fresh one in a part that is not the nonce"
    );

    // Under the `json` kind a document opens as its text in a bytes leaf.
    let opened_as_declared = if case.kind == "json" {
        frame(stored_input.text.as_bytes().to_vec())
    } else {
        input(stored_input)
    };
    // No case seals under this context.
    let wrong = ["conformance".to_owned(), "wrong".to_owned()];
    assert_ne!(
        context[..],
        wrong[..],
        "{id}: a case uses the wrong context"
    );
    for (origin, ciphertext) in [("fresh", fresh), ("frozen", frozen)] {
        let opened = open(&keyset, ciphertext.clone(), None, context)
            .await
            .unwrap_or_else(|error| panic!("{id}: the {origin} ciphertext does not open: {error}"));
        assert_eq!(
            opened.frame(),
            stored.frame(),
            "{id}: the {origin} ciphertext opens to another value"
        );
        if let Some(kind) = kind {
            let opened = open(&keyset, ciphertext.clone(), Some(kind), context)
                .await
                .unwrap_or_else(|error| {
                    panic!("{id}: the {origin} ciphertext does not open as {kind}: {error}")
                });
            assert_eq!(
                opened.frame(),
                opened_as_declared.frame(),
                "{id}: the {origin} ciphertext opens as {kind} to another value"
            );
        }
        if let Some(opened) = typed_open(&keyset, typed_name, ciphertext.clone(), context).await {
            assert_eq!(
                opened.frame(),
                stored.frame(),
                "{id}: the typed call reads another value from the {origin} ciphertext"
            );
        }
        for name in case.refused_as.iter().flatten() {
            let other = declared(name);
            let refused = open(&keyset, ciphertext.clone(), other, context).await;
            assert!(
                matches!(&refused, Err(Error::OpenedType { expected }) if expected == name),
                "{id}: the {origin} ciphertext must not open as {name}, got: {refused:?}"
            );
        }
        let refused = open(&keyset, ciphertext, None, &wrong).await;
        assert!(
            is_forbidden(&refused),
            "{id}: the {origin} ciphertext must not open under another context, got: {refused:?}"
        );
    }
}

#[tokio::test]
async fn shared_single_value_profile() {
    let update = common::fixture_updates_requested_or_panic();
    let corpus: Corpus = serde_json::from_str(include_str!(
        "../../../conformance/stack-encrypt/v1/single-value-v1.cases.json"
    ))
    .expect("the cases file");
    assert_eq!(corpus.version, 1, "the corpus format version");
    assert_eq!(corpus.profile, PROFILE, "the profile");
    assert_eq!(
        corpus.required_capabilities,
        ["single-value", "value-kinds", "context-binding", "refusals"],
        "the capabilities a runner needs"
    );
    let seed: [u8; 32] = unhex(&corpus.seed).try_into().expect("a 32-byte seed");
    assert!(!corpus.cases.is_empty(), "the profile has cases");
    let ids: BTreeSet<&str> = corpus
        .cases
        .iter()
        .map(|case| case.id.as_str())
        .chain(corpus.batches.iter().map(|batch| batch.id.as_str()))
        .collect();
    assert_eq!(
        ids.len(),
        corpus.cases.len() + corpus.batches.len(),
        "case IDs are distinct"
    );
    assert!(!ids.contains(""), "no case ID is empty");

    let path = root().join("single-value-v1.expected.rust-native.json");
    let baseline: Option<Artifacts> = (!update).then(|| {
        let artifacts: Artifacts =
            serde_json::from_slice(&std::fs::read(&path).expect("the expected file"))
                .expect("the expected file parses");
        assert_eq!(artifacts.version, 1, "the artifacts' format version");
        assert_eq!(artifacts.profile, PROFILE, "the artifacts' profile");
        assert!(
            artifacts.producer.starts_with("rust-native"),
            "the artifacts' producer: {}",
            artifacts.producer
        );
        assert_eq!(
            artifacts
                .cases
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            corpus
                .cases
                .iter()
                .map(|case| case.id.as_str())
                .collect::<BTreeSet<_>>(),
            "the artifacts hold exactly the cases"
        );
        artifacts
    });

    let mut output = BTreeMap::new();
    for case in &corpus.cases {
        eprintln!("single value: {}", case.id);
        let value = input(&case.input);
        let mut artifact = Artifact {
            frame: hex(value.frame().as_bytes()),
            leaf: None,
            ciphertext: None,
        };
        let reference = baseline
            .as_ref()
            .map(|artifacts| &artifacts.cases[&case.id]);
        if let Some(reference) = reference {
            assert_eq!(
                artifact.frame, reference.frame,
                "{}: the input's frame",
                case.id
            );
        }
        match &case.expected_error {
            Some(expected) => {
                assert!(
                    case.stored.is_none() && case.refused_as.is_none(),
                    "{}: a refused case stores nothing",
                    case.id
                );
                let (cipher, generates, retrieves) = counting(seed).await;
                let keyset = cipher.default_keyset();
                let error = match seal(&keyset, value.frame(), declared(&case.kind), &case.context)
                {
                    Err(error) => error,
                    Ok(_) => panic!(
                        "{}: the value is taken where a refusal is expected",
                        case.id
                    ),
                };
                assert_refusal(&case.id, &error, expected);
                assert_eq!(
                    (
                        generates.load(Ordering::SeqCst),
                        retrieves.load(Ordering::SeqCst)
                    ),
                    (0, 0),
                    "{}: a refused value makes no key request",
                    case.id
                );
                if let Some(reference) = reference {
                    assert!(
                        reference.leaf.is_none() && reference.ciphertext.is_none(),
                        "{}: a refused case has no frozen ciphertext",
                        case.id
                    );
                }
            }
            None => accepted(seed, case, &value, &mut artifact, reference).await,
        }
        let _ = output.insert(case.id.clone(), artifact);
    }

    for batch in &corpus.batches {
        eprintln!("single value: {}", batch.id);
        let id = &batch.id;
        let kind = declared(&batch.kind);
        let values: Vec<OwnedFrame> = batch.inputs.iter().map(input).collect();
        let (cipher, generates, retrieves) = counting(seed).await;
        let keyset = cipher.default_keyset();
        let sealed = match (
            seal_all(&keyset, &values, kind, &batch.context),
            &batch.expected_error,
        ) {
            (Err(error), Some(expected)) => {
                assert_refusal(id, &error, expected);
                assert_eq!(
                    generates.load(Ordering::SeqCst),
                    0,
                    "{id}: a refused batch makes no key request"
                );
                continue;
            }
            (Err(error), None) => panic!("{id}: the batch is refused: {error}"),
            (Ok(_), Some(_)) => panic!("{id}: the batch is taken where a refusal is expected"),
            (Ok(pending), None) => pending
                .await
                .unwrap_or_else(|error| panic!("{id}: the batch does not seal: {error}")),
        };
        let requests = usize::from(!values.is_empty());
        assert_eq!(
            sealed.len(),
            values.len(),
            "{id}: one ciphertext for each value"
        );
        assert_eq!(
            generates.load(Ordering::SeqCst),
            requests,
            "{id}: the batch seals in one key request"
        );
        let opened = open_all(&keyset, sealed, kind, &batch.context)
            .await
            .unwrap_or_else(|error| panic!("{id}: the batch does not open: {error}"));
        assert_eq!(
            retrieves.load(Ordering::SeqCst),
            requests,
            "{id}: the batch opens in one key request"
        );
        let stored = batch.stored.as_ref().unwrap_or(&batch.inputs);
        assert_eq!(
            opened.len(),
            stored.len(),
            "{id}: one value for each ciphertext"
        );
        for (position, (opened, expected)) in opened.iter().zip(stored).enumerate() {
            assert_eq!(
                opened.frame(),
                input(expected).frame(),
                "{id}: the value at position {position}"
            );
        }
    }

    if update {
        let artifacts = Artifacts {
            version: 1,
            profile: PROFILE.into(),
            producer: format!("rust-native/stack-encrypt-{}", env!("CARGO_PKG_VERSION")),
            cases: output,
        };
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&artifacts).expect("the artifacts as JSON") + "\n",
        )
        .expect("write the expected file");
    }
}
