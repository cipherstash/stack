//! The language-neutral record-scalars-v1 profile. See conformance/stack-encrypt.
#![cfg(feature = "dynamic")]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::Ordering;

use common::conformance::{refusal, stored_outputs, value, Input};
use common::frames::{frame, object};
use common::{hex, unhex};
use serde::{Deserialize, Serialize};
use serde_json::json;
use stack_encrypt::dynamic::{
    self, record, Fidelity, NoTargets, OpSpec, Operand, Scope, ValueFrame,
};
use stack_encrypt::target::IndexSpec;
use stack_encrypt::{
    CipherText, Ciphertext, Error, KeysetCipher, Label, SealedValue, StackCipherText,
};

const PROFILE: &str = "record-scalars-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    version: u32,
    profile: String,
    seed: String,
    context: Vec<String>,
    field: String,
    required_capabilities: Vec<String>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    kind: String,
    input: Input,
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
    frame: String,
    ciphertext: String,
    equality: String,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/stack-encrypt/v1")
}

fn plan(corpus: &Corpus, case: &Case) -> record::Plan {
    let mut context = corpus.context.clone();
    context.push(corpus.field.clone());
    let declaration = json!({corpus.field.clone(): {
        "context": context, "outputs": ["c", "eq"], "type": case.kind,
    }});
    record::plan(&vitaminc_aead_frame::serde::to_vec(&declaration).unwrap()).unwrap()
}

fn stored(corpus: &Corpus, artifact: &Artifact) -> StackCipherText {
    CipherText::Map(vec![(
        corpus.field.clone(),
        CipherText::Map(vec![
            (
                "c".into(),
                CipherText::Single(SealedValue::from_bytes(&unhex(&artifact.ciphertext)).unwrap()),
            ),
            (
                "eq".into(),
                CipherText::Passthrough(common::passthrough(unhex(&artifact.equality))),
            ),
        ]),
    )])
}

// Exercise the owned scalar API independently of dynamic record lowering.
async fn scalar(
    keyset: &KeysetCipher<'_, common::DeterministicSource>,
    input: &Input,
    context: &Label,
) -> Ciphertext {
    macro_rules! seal {
        ($value:expr) => {
            keyset
                .encrypt_with_context($value, context.clone())
                .await
                .unwrap()
        };
    }
    match input.kind.as_str() {
        "int32" => seal!(input.text.parse::<i32>().unwrap()),
        "int64" => seal!(input.text.parse::<i64>().unwrap()),
        "uint64" => seal!(input.text.parse::<u64>().unwrap()),
        "bool" => seal!(input.text.parse::<bool>().unwrap()),
        "string" => seal!(input.text.clone()),
        other => panic!("unsupported scalar {other}"),
    }
}

async fn open_scalar(
    keyset: &KeysetCipher<'_, common::DeterministicSource>,
    bytes: &[u8],
    kind: &str,
    context: &Label,
) -> ValueFrame {
    let ct = Ciphertext::from_bytes(bytes).unwrap();
    macro_rules! open {
        ($ty:ty) => {
            frame(
                keyset
                    .decrypt_with_context::<$ty>(ct, context.clone())
                    .await
                    .unwrap(),
            )
        };
    }
    match kind {
        "int32" => open!(i32),
        "int64" => open!(i64),
        "uint64" => open!(u64),
        "bool" => open!(bool),
        "string" => open!(String),
        other => panic!("unsupported scalar {other}"),
    }
}

#[tokio::test]
async fn shared_record_scalar_profile() {
    let corpus: Corpus =
        serde_json::from_slice(&std::fs::read(root().join("cases.json")).unwrap()).unwrap();
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.profile, PROFILE);
    assert_eq!(
        corpus.required_capabilities,
        ["records", "equality", "context-binding", "query-errors"]
    );
    assert!(!corpus.cases.is_empty());
    let ids: BTreeSet<_> = corpus.cases.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids.len(), corpus.cases.len(), "duplicate case IDs");
    assert!(!ids.contains(""));
    let positive_ids: BTreeSet<_> = corpus
        .cases
        .iter()
        .filter(|c| c.expected_error.is_none())
        .map(|c| c.id.as_str())
        .collect();
    assert!(!positive_ids.is_empty());

    let update = std::env::var("STACK_CONFORMANCE_UPDATE").as_deref() == Ok("1");
    let imported = std::env::var_os("STACK_CONFORMANCE_INPUT");
    assert!(
        !(update && imported.is_some()),
        "cannot update from external artifacts"
    );
    let baseline: Option<Artifacts> = if update {
        None
    } else {
        let file = imported
            .map(PathBuf::from)
            .unwrap_or_else(|| root().join("native.json"));
        let artifacts: Artifacts = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
        assert_eq!(artifacts.version, 1);
        assert_eq!(artifacts.profile, PROFILE);
        assert!(!artifacts.producer.is_empty());
        assert_eq!(
            artifacts
                .cases
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            positive_ids
        );
        Some(artifacts)
    };

    let cipher =
        common::deterministic_cipher(unhex(&corpus.seed).try_into().expect("32-byte seed")).await;
    let keyset = cipher.default_keyset();
    let context = Label::new(corpus.context.iter().chain(std::iter::once(&corpus.field))).unwrap();
    let (counting, generates, retrieves) = common::counting_cipher().await;
    let mut output = Artifacts {
        version: 1,
        profile: PROFILE.into(),
        producer: format!("rust-native/stack-encrypt-{}", env!("CARGO_PKG_VERSION")),
        cases: BTreeMap::new(),
    };

    for case in &corpus.cases {
        eprintln!("conformance: {}", case.id);
        let plan = plan(&corpus, case);
        if let Some(expected) = &case.expected_error {
            let scope = counting.default_keyset();
            let error = match dynamic::query_term(
                &scope,
                &plan,
                &corpus.field,
                OpSpec::Eq,
                value(&case.input),
                &NoTargets,
            ) {
                Err(error) => error,
                Ok(_) => panic!("{}: expected preflight rejection", case.id),
            };
            refusal(&error, &expected.code, &expected.reason, &corpus.field);
            assert_eq!(generates.load(Ordering::SeqCst), 0);
            assert_eq!(retrieves.load(Ordering::SeqCst), 0);
            continue;
        }
        assert_eq!(case.kind, case.input.kind);
        let input = value(&case.input);
        let expected_row = object(vec![(corpus.field.clone(), input.clone())]);
        let fresh = record::encrypt(&keyset, expected_row.clone(), &plan)
            .unwrap()
            .await
            .unwrap();
        let stored_term = stored_outputs(&fresh, &corpus.field).unwrap().0;
        let opened = record::decrypt(Scope::Keyset(keyset.clone()), fresh, &plan, None)
            .unwrap()
            .await
            .unwrap();
        assert_eq!(
            opened.risky_ref(),
            expected_row.risky_ref(),
            "{}: record roundtrip",
            case.id
        );

        let term = dynamic::query_term(
            &keyset,
            &plan,
            &corpus.field,
            OpSpec::Eq,
            input.clone(),
            &NoTargets,
        )
        .unwrap()
        .await
        .unwrap();
        assert_eq!(term.operator(), OpSpec::Eq);
        assert_eq!(term.index(), &IndexSpec::Equality);
        assert_eq!(term.fidelity(), Fidelity::Exact);
        assert_eq!(term.encoding(), "bytes");
        assert_eq!(term.domain(), None);
        let Operand::One(term) = term.operand() else {
            panic!("expected one equality term")
        };
        assert_eq!(&stored_term, term, "{}: stored equality", case.id);
        let ct = scalar(&keyset, &case.input, &context).await;
        let artifact = Artifact {
            frame: hex(input.risky_ref()),
            ciphertext: hex(&ct.to_bytes()),
            equality: hex(term),
        };
        let reference = baseline.as_ref().map_or(&artifact, |a| &a.cases[&case.id]);
        assert_eq!(artifact.frame, reference.frame, "{}: typed frame", case.id);
        assert_eq!(
            artifact.equality, reference.equality,
            "{}: equality bytes",
            case.id
        );
        for (origin, candidate) in [("fresh", &artifact), ("reference", reference)] {
            let opened =
                open_scalar(&keyset, &unhex(&candidate.ciphertext), &case.kind, &context).await;
            assert_eq!(
                opened.risky_ref(),
                input.risky_ref(),
                "{}: {origin} scalar cross-open",
                case.id
            );
            let opened = record::decrypt(
                Scope::Keyset(keyset.clone()),
                stored(&corpus, candidate),
                &plan,
                None,
            )
            .unwrap()
            .await
            .unwrap();
            assert_eq!(
                opened.risky_ref(),
                expected_row.risky_ref(),
                "{}: {origin} record cross-open",
                case.id
            );
        }

        let mut wrong = corpus.context.clone();
        wrong.push("wrong".into());
        wrong.push(corpus.field.clone());
        let wrong = Label::new(wrong).unwrap();
        let result = keyset
            .decrypt_tree::<ValueFrame, _>(
                CipherText::Single(SealedValue::from_bytes(&unhex(&reference.ciphertext)).unwrap()),
                wrong,
            )
            .await;
        assert!(
            matches!(result, Err(Error::Kms(stack_kms::Error::RetrieveKey(
            stack_kms::RetrieveKeyError::RequestFailed(ref error)
        ))) if matches!(error.kind, zerokms_protocol::ViturRequestErrorKind::Forbidden)),
            "{}: wrong context: {result:?}",
            case.id
        );
        output.cases.insert(case.id.clone(), artifact);
    }
    if update {
        std::fs::write(
            root().join("native.json"),
            serde_json::to_string_pretty(&output).unwrap() + "\n",
        )
        .unwrap();
    }
    if let Some(path) = std::env::var_os("STACK_CONFORMANCE_OUTPUT") {
        std::fs::write(path, serde_json::to_string_pretty(&output).unwrap() + "\n").unwrap();
    }
}
