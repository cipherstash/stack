//! The fresh cross-language artifact exchange profile: this runner writes
//! every value kind at its edges, structural records with passthrough and
//! index terms, and whole-value opaque blobs, as artifacts another runner
//! opens; and it opens the artifacts another runner wrote. Decrypted values
//! and derived query terms are compared, never ciphertext bytes. See
//! conformance/stack-encrypt/exchange-contract.md.
#![cfg(feature = "dynamic")]
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use common::conformance::{value, Input};
use common::frames::{frame, object};
use common::{hex, unhex};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use serde_json::json;
use stack_encrypt::dynamic::{self, record, NoTargets, OpSpec, Operand, Scope, ValueFrame};
use stack_encrypt::{
    CipherText, Ciphertext, KeysetCipher, Label, OpaqueBlob, PassthroughFrame, SealedValue,
    StackCipherText,
};
use zeroize::Zeroize;

const PROFILE: &str = "artifact-exchange-v1";
const LANGUAGE: &str = "rust";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    version: u32,
    profile: String,
    seed: String,
    required_capabilities: Vec<String>,
    values: ValuesRef,
    record: RecordSpec,
    blob: BlobSpec,
    eql: EqlRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValuesRef {
    corpus: String,
    profile: String,
    context: Vec<String>,
    field: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordSpec {
    context: Vec<String>,
    fields: Vec<FieldSpec>,
    rows: Vec<RowSpec>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldSpec {
    name: String,
    kind: String,
    #[serde(default)]
    passthrough: bool,
    #[serde(default)]
    outputs: Vec<String>,
    #[serde(default)]
    null: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RowSpec {
    id: String,
    values: BTreeMap<String, Input>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobSpec {
    context: Vec<String>,
    field: String,
    cases: Vec<BlobCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobCase {
    id: String,
    value: Profile,
}

/// The blob's shape. The Go runner's struct carries the same field names
/// as `vc` tags; a nil `tags` there reads back as an empty `Vec` here.
#[derive(Serialize, Deserialize, Zeroize, Clone, PartialEq, Debug)]
#[serde(deny_unknown_fields)]
struct Profile {
    name: String,
    age: u32,
    tags: Vec<String>,
    nickname: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EqlRef {
    table: String,
    fixture: String,
    schema: String,
}

/// The value-boundary corpus, read in full so an unknown field fails here
/// as it does in its own runner.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValuesCorpus {
    version: u32,
    profile: String,
    required_capabilities: Vec<String>,
    cases: Vec<ValueCase>,
    host_conversions: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValueCase {
    id: String,
    kind: String,
    null: String,
    outputs: Vec<String>,
    input: Input,
    frame: Option<String>,
    companion: Option<Input>,
    equal_query: Option<Input>,
    #[serde(default)]
    unanswered: Vec<String>,
    expected_error: Option<serde_json::Value>,
}

// ---- the artifact file -------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifacts {
    version: u32,
    profile: String,
    producer: Producer,
    values: BTreeMap<String, Stored>,
    record: BTreeMap<String, StoredRecord>,
    blobs: BTreeMap<String, String>,
}

/// Who wrote the artifacts and with what: the SDK, the engine it ran, the
/// backend it ran it through, the (fake) key source, and the profiles and
/// capabilities the artifacts claim.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Producer {
    language: String,
    sdk: String,
    sdk_version: String,
    backend: String,
    engine: Engine,
    key_source: KeySource,
    profiles: Vec<String>,
    capabilities: Vec<String>,
    toolchain: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Engine {
    name: String,
    version: Option<String>,
    guest_sha256: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeySource {
    kind: String,
    seed: String,
}

/// One stored field: the sealed leaf, or none for a SQL null, and each
/// index term's bytes.
#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Stored {
    c: Option<String>,
    terms: BTreeMap<String, String>,
}

/// One stored record: the passthrough fields as the typed inputs they
/// carry in the clear, and each sealed field that was stored.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    passthrough: BTreeMap<String, Input>,
    fields: BTreeMap<String, Stored>,
}

// ---- plans ---------------------------------------------------------------

/// A declaration whose fields keep the order they are given in: `json!`
/// maps sort their keys, and the record's opened frame follows plan order.
struct Declaration<'a>(&'a [(String, serde_json::Value)]);

impl Serialize for Declaration<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, spec) in self.0 {
            map.serialize_entry(name, spec)?;
        }
        map.end()
    }
}

fn plan_of(fields: &[(String, serde_json::Value)]) -> record::Plan {
    record::plan(&vitaminc_aead_frame::serde::to_vec(&Declaration(fields)).unwrap()).unwrap()
}

fn field_context(context: &[String], name: &str) -> Vec<String> {
    let mut label = context.to_vec();
    label.push(name.to_owned());
    label
}

fn value_plan(values: &ValuesRef, case: &ValueCase) -> record::Plan {
    let mut spec = json!({
        "context": field_context(&values.context, &values.field),
        "outputs": case.outputs,
        "type": case.kind,
    });
    if !case.null.is_empty() {
        spec["null"] = json!(case.null);
    }
    plan_of(&[(values.field.clone(), spec)])
}

fn record_plan(record: &RecordSpec) -> record::Plan {
    let fields: Vec<_> = record
        .fields
        .iter()
        .map(|field| {
            let context = field_context(&record.context, &field.name);
            let spec = if field.passthrough {
                assert!(
                    field.outputs.is_empty() && field.null.is_empty(),
                    "{}",
                    field.name
                );
                json!({"context": context, "outputs": ["passthrough"], "type": field.kind})
            } else {
                assert_eq!(
                    field.outputs.first().map(String::as_str),
                    Some("c"),
                    "{}",
                    field.name
                );
                let mut spec =
                    json!({"context": context, "outputs": field.outputs, "type": field.kind});
                if !field.null.is_empty() {
                    spec["null"] = json!(field.null);
                }
                spec
            };
            (field.name.clone(), spec)
        })
        .collect();
    plan_of(&fields)
}

fn blob_label(blob: &BlobSpec) -> Label {
    Label::new(field_context(&blob.context, &blob.field)).unwrap()
}

fn is_null(input: &Input) -> bool {
    input.kind == "null"
}

// ---- stored trees <-> artifacts -------------------------------------------

/// A sealed field's outputs from a stored record, or `None` when the
/// record holds no entry for it (a SQL null). Passthrough outputs are not
/// read here.
fn stored_of(tree: &StackCipherText, field: &str) -> Option<Stored> {
    let CipherText::Map(fields) = tree else {
        panic!("a record is a map of fields")
    };
    let (_, node) = fields.iter().find(|(name, _)| name == field)?;
    let CipherText::Map(outputs) = node else {
        panic!("{field}: a field is a map of outputs")
    };
    let mut stored = Stored::default();
    for (key, output) in outputs {
        match (key.as_str(), output) {
            ("c", CipherText::Single(leaf)) => stored.c = Some(hex(&leaf.to_bytes())),
            ("c", _) => panic!("{field}: the ciphertext is not one leaf"),
            ("passthrough", _) => panic!("{field}: a passthrough is not a sealed field"),
            (index, CipherText::Passthrough(term)) => {
                let bytes: &[u8] = vitaminc_aead_frame::serde::from_slice(&term.0).unwrap();
                stored.terms.insert(index.to_owned(), hex(bytes));
            }
            (key, _) => panic!("{field}: {key} is not a term"),
        }
    }
    assert!(
        stored.c.is_some(),
        "{field}: a stored field has a ciphertext"
    );
    Some(stored)
}

/// The passthrough payload a stored record carries for `field`.
fn passthrough_of(tree: &StackCipherText, field: &str) -> Vec<u8> {
    let CipherText::Map(fields) = tree else {
        panic!("a record is a map of fields")
    };
    let (_, node) = fields.iter().find(|(name, _)| name == field).expect(field);
    let CipherText::Map(outputs) = node else {
        panic!("{field}: a field is a map of outputs")
    };
    assert_eq!(
        outputs.len(),
        1,
        "{field}: a passthrough is the sole output"
    );
    let (key, CipherText::Passthrough(payload)) = &outputs[0] else {
        panic!("{field}: not a passthrough")
    };
    assert_eq!(key, "passthrough");
    payload.0.clone()
}

/// The stored node of a sealed field, rebuilt from an artifact.
fn sealed_node(stored: &Stored, field: &str) -> StackCipherText {
    let c = stored
        .c
        .as_deref()
        .unwrap_or_else(|| panic!("{field}: no ciphertext"));
    let mut outputs = vec![(
        "c".to_owned(),
        CipherText::Single(SealedValue::from_bytes(&unhex(c)).unwrap()),
    )];
    for (index, term) in &stored.terms {
        outputs.push((
            index.clone(),
            CipherText::Passthrough(common::passthrough(unhex(term))),
        ));
    }
    CipherText::Map(outputs)
}

/// The stored node of a passthrough field: the input's frame, in the clear.
fn passthrough_node(input: &Input) -> StackCipherText {
    use vitaminc_protected::Controlled;
    CipherText::Map(vec![(
        "passthrough".to_owned(),
        CipherText::Passthrough(PassthroughFrame(value(input).into_inner().risky_unwrap())),
    )])
}

fn operator_for(index: &str) -> OpSpec {
    match index {
        "eq" => OpSpec::Eq,
        "ore" | "ope" => OpSpec::Lt,
        other => panic!("{other}: not an index this profile exchanges"),
    }
}

/// One field's declared indexes and the value they were derived from, for
/// [`check_terms`].
struct Terms<'a> {
    plan: &'a record::Plan,
    field: &'a str,
    /// The field's declared outputs, `c` first.
    declared: &'a [String],
    /// Stored indexes no operator answers: present, and not queried.
    unanswered: &'a [String],
    input: &'a Input,
    /// Another spelling whose equality query derives the same term.
    equal_query: Option<&'a Input>,
}

/// Every stored term is the term this runner's own query of the same value
/// derives: the query semantics of the artifact, independent of who wrote
/// it. An index the corpus lists as unanswered has no operator to compare
/// with, so only its presence is checked.
async fn check_terms(
    keyset: &KeysetCipher<'_, common::DeterministicSource>,
    terms: Terms<'_>,
    stored: &Stored,
    what: &str,
) {
    let declared: BTreeSet<_> = terms.declared.iter().skip(1).map(String::as_str).collect();
    let present: BTreeSet<_> = stored.terms.keys().map(String::as_str).collect();
    assert_eq!(present, declared, "{what}: stores every declared index");
    for (index, term) in &stored.terms {
        if terms.unanswered.contains(index) {
            continue;
        }
        let mut probes = vec![terms.input];
        if index == "eq" {
            probes.extend(terms.equal_query);
        }
        for probe in probes {
            let derived = dynamic::query_term(
                keyset,
                terms.plan,
                terms.field,
                operator_for(index),
                value(probe),
                &NoTargets,
            )
            .unwrap()
            .await
            .unwrap();
            let Operand::One(bytes) = derived.operand() else {
                panic!("{what}: {index}: one term")
            };
            assert_eq!(
                &hex(bytes),
                term,
                "{what}: {index}: stored term is the query term"
            );
        }
    }
}

// ---- producing -----------------------------------------------------------

fn positive_cases(values: &ValuesCorpus) -> Vec<&ValueCase> {
    values
        .cases
        .iter()
        .filter(|case| case.expected_error.is_none())
        .collect()
}

async fn produce(
    corpus: &Corpus,
    values: &ValuesCorpus,
    keyset: &KeysetCipher<'_, common::DeterministicSource>,
) -> Artifacts {
    let mut artifacts = Artifacts {
        version: 1,
        profile: PROFILE.into(),
        producer: Producer {
            language: LANGUAGE.into(),
            sdk: env!("CARGO_PKG_NAME").into(),
            sdk_version: env!("CARGO_PKG_VERSION").into(),
            backend: "native".into(),
            engine: Engine {
                name: "stack-encrypt".into(),
                version: Some(env!("CARGO_PKG_VERSION").into()),
                guest_sha256: None,
            },
            key_source: KeySource {
                kind: "deterministic".into(),
                seed: corpus.seed.clone(),
            },
            profiles: vec![PROFILE.into(), corpus.values.profile.clone()],
            capabilities: corpus.required_capabilities.clone(),
            toolchain: None,
        },
        values: BTreeMap::new(),
        record: BTreeMap::new(),
        blobs: BTreeMap::new(),
    };

    for case in positive_cases(values) {
        let plan = value_plan(&corpus.values, case);
        let row = object(vec![(corpus.values.field.as_str(), value(&case.input))]);
        let sealed = record::encrypt(keyset, row, &plan).unwrap().await.unwrap();
        let stored = stored_of(&sealed, &corpus.values.field).unwrap_or_default();
        assert_eq!(
            stored.c.is_none(),
            is_null(&case.input) && case.null == "sql",
            "{}: storage",
            case.id
        );
        artifacts.values.insert(case.id.clone(), stored);
    }

    let plan = record_plan(&corpus.record);
    for row in &corpus.record.rows {
        let source = object(
            corpus
                .record
                .fields
                .iter()
                .map(|field| (field.name.as_str(), value(&row.values[&field.name])))
                .collect(),
        );
        let sealed = record::encrypt(keyset, source, &plan)
            .unwrap()
            .await
            .unwrap();
        let mut stored = StoredRecord {
            passthrough: BTreeMap::new(),
            fields: BTreeMap::new(),
        };
        for field in &corpus.record.fields {
            let input = &row.values[&field.name];
            if field.passthrough {
                assert_eq!(
                    passthrough_of(&sealed, &field.name),
                    value(input).risky_ref(),
                    "{}: {}: the passthrough is the input's frame",
                    row.id,
                    field.name
                );
                stored.passthrough.insert(field.name.clone(), input.clone());
            } else if let Some(outputs) = stored_of(&sealed, &field.name) {
                stored.fields.insert(field.name.clone(), outputs);
            } else {
                assert!(
                    is_null(input) && field.null == "sql",
                    "{}: {}: only a SQL null stores nothing",
                    row.id,
                    field.name
                );
            }
        }
        artifacts.record.insert(row.id.clone(), stored);
    }

    let label = blob_label(&corpus.blob);
    for case in &corpus.blob.cases {
        let ct: Ciphertext = keyset
            .encrypt_with_context(OpaqueBlob::new(case.value.clone()), label.clone())
            .await
            .unwrap();
        artifacts.blobs.insert(case.id.clone(), hex(&ct.to_bytes()));
    }
    artifacts
}

// ---- consuming -----------------------------------------------------------

fn ids<'a>(items: impl IntoIterator<Item = &'a String>) -> BTreeSet<&'a str> {
    items.into_iter().map(String::as_str).collect()
}

async fn consume(
    corpus: &Corpus,
    values: &ValuesCorpus,
    keyset: &KeysetCipher<'_, common::DeterministicSource>,
    artifacts: &Artifacts,
    origin: &str,
) {
    assert_eq!(artifacts.version, 1, "{origin}: artifact version");
    assert_eq!(artifacts.profile, PROFILE, "{origin}: artifact profile");
    let producer = &artifacts.producer;
    assert!(
        ["rust", "go", "python", "typescript"].contains(&producer.language.as_str()),
        "{origin}: unknown producer language {}",
        producer.language
    );
    if origin != "self" {
        assert_ne!(
            producer.language, LANGUAGE,
            "{origin}: another runner's artifacts"
        );
    }
    assert!(
        !producer.sdk.is_empty() && !producer.sdk_version.is_empty(),
        "{origin}: the producer names its SDK and version"
    );
    assert!(
        ["native", "wasi"].contains(&producer.backend.as_str()),
        "{origin}: unknown backend {}",
        producer.backend
    );
    assert_eq!(producer.engine.name, "stack-encrypt", "{origin}: engine");
    assert!(
        producer.engine.version.is_some() || producer.engine.guest_sha256.is_some(),
        "{origin}: the engine is identified by version or guest hash"
    );
    assert_eq!(
        producer.key_source.kind, "deterministic",
        "{origin}: key source"
    );
    assert_eq!(
        producer.key_source.seed, corpus.seed,
        "{origin}: the shared seed"
    );
    assert!(
        producer.profiles.contains(&PROFILE.to_owned())
            && producer.profiles.contains(&corpus.values.profile),
        "{origin}: the artifacts claim both profiles"
    );
    assert_eq!(
        producer.capabilities, corpus.required_capabilities,
        "{origin}: capabilities"
    );

    // Every artifact set is nonempty and holds exactly the corpus's cases.
    let positive = positive_cases(values);
    assert!(
        !positive.is_empty() && !corpus.record.rows.is_empty() && !corpus.blob.cases.is_empty()
    );
    assert_eq!(
        ids(artifacts.values.keys()),
        positive.iter().map(|case| case.id.as_str()).collect(),
        "{origin}: value artifacts"
    );
    assert_eq!(
        ids(artifacts.record.keys()),
        corpus
            .record
            .rows
            .iter()
            .map(|row| row.id.as_str())
            .collect(),
        "{origin}: record artifacts"
    );
    assert_eq!(
        ids(artifacts.blobs.keys()),
        corpus
            .blob
            .cases
            .iter()
            .map(|case| case.id.as_str())
            .collect(),
        "{origin}: blob artifacts"
    );

    for case in positive {
        let what = format!("{origin}: values: {}", case.id);
        let plan = value_plan(&corpus.values, case);
        let stored = &artifacts.values[&case.id];
        let omitted = is_null(&case.input) && case.null == "sql";
        assert_eq!(stored.c.is_none(), omitted, "{what}: storage");
        let tree = if omitted {
            assert!(stored.terms.is_empty(), "{what}: a SQL null stores no term");
            CipherText::Map(vec![])
        } else {
            check_terms(
                keyset,
                Terms {
                    plan: &plan,
                    field: &corpus.values.field,
                    declared: &case.outputs,
                    unanswered: &case.unanswered,
                    input: &case.input,
                    equal_query: case.equal_query.as_ref(),
                },
                stored,
                &what,
            )
            .await;
            CipherText::Map(vec![(
                corpus.values.field.clone(),
                sealed_node(stored, &corpus.values.field),
            )])
        };
        let opened = record::decrypt(Scope::Keyset(keyset.clone()), tree, &plan, None)
            .unwrap()
            .await
            .unwrap();
        let expected = object(vec![(corpus.values.field.as_str(), value(&case.input))]);
        assert_eq!(
            opened.risky_ref(),
            expected.risky_ref(),
            "{what}: opened value"
        );
    }

    let plan = record_plan(&corpus.record);
    for row in &corpus.record.rows {
        let what = format!("{origin}: record: {}", row.id);
        let stored = &artifacts.record[&row.id];
        let mut tree = Vec::new();
        let mut expected = Vec::new();
        for field in &corpus.record.fields {
            let input = &row.values[&field.name];
            expected.push((field.name.as_str(), value(input)));
            if field.passthrough {
                let carried = &stored.passthrough[&field.name];
                assert_eq!(carried, input, "{what}: {}: passthrough", field.name);
                tree.push((field.name.clone(), passthrough_node(carried)));
            } else if let Some(outputs) = stored.fields.get(&field.name) {
                check_terms(
                    keyset,
                    Terms {
                        plan: &plan,
                        field: &field.name,
                        declared: &field.outputs,
                        unanswered: &[],
                        input,
                        equal_query: None,
                    },
                    outputs,
                    &format!("{what}: {}", field.name),
                )
                .await;
                tree.push((field.name.clone(), sealed_node(outputs, &field.name)));
            } else {
                assert!(
                    is_null(input) && field.null == "sql",
                    "{what}: {}: only a SQL null is absent",
                    field.name
                );
            }
        }
        assert_eq!(
            ids(stored.passthrough.keys()),
            corpus
                .record
                .fields
                .iter()
                .filter(|field| field.passthrough)
                .map(|field| field.name.as_str())
                .collect(),
            "{what}: passthrough fields"
        );
        // Every stored sealed field is a declared one: an undeclared field
        // would otherwise be dropped before decryption and never checked.
        assert_eq!(
            ids(stored.fields.keys()),
            corpus
                .record
                .fields
                .iter()
                .filter(|field| !field.passthrough)
                // A SQL null stores nothing.
                .filter(|field| !(is_null(&row.values[&field.name]) && field.null == "sql"))
                .map(|field| field.name.as_str())
                .collect(),
            "{what}: sealed fields"
        );
        let opened = record::decrypt(
            Scope::Keyset(keyset.clone()),
            CipherText::Map(tree),
            &plan,
            None,
        )
        .unwrap()
        .await
        .unwrap();
        assert_eq!(
            opened.risky_ref(),
            object(expected).risky_ref(),
            "{what}: opened record"
        );
    }

    let label = blob_label(&corpus.blob);
    for case in &corpus.blob.cases {
        let what = format!("{origin}: blob: {}", case.id);
        let ct = Ciphertext::from_bytes(&unhex(&artifacts.blobs[&case.id])).expect(&what);
        let opened: OpaqueBlob<Profile> = keyset
            .decrypt_with_context(ct, label.clone())
            .await
            .unwrap_or_else(|error| panic!("{what}: {error}"));
        assert_eq!(opened.into_inner(), case.value, "{what}: opened blob");
    }
}

// ---- the test -------------------------------------------------------------

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/stack-encrypt/v1")
}

fn read<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> T {
    serde_json::from_slice(
        &std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())),
    )
    .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Fresh artifacts of every kind this runner writes open here, and the
/// artifacts `STACK_EXCHANGE_INPUT` names, written by another runner, open
/// here too. `STACK_EXCHANGE_OUTPUT` receives this runner's artifacts for
/// the other runner. Nothing frozen is read or written.
#[tokio::test]
async fn fresh_artifact_exchange() {
    let (corpus, values) = corpora();
    let seed: [u8; 32] = unhex(&corpus.seed).try_into().expect("a 32-byte seed");
    let cipher = common::deterministic_cipher(seed).await;
    let keyset = cipher.default_keyset();

    let fresh = produce(&corpus, &values, &keyset).await;
    consume(&corpus, &values, &keyset, &fresh, "self").await;

    if let Some(path) = std::env::var_os("STACK_EXCHANGE_OUTPUT") {
        std::fs::write(path, serde_json::to_string_pretty(&fresh).unwrap() + "\n").unwrap();
    }
    if let Some(path) = std::env::var_os("STACK_EXCHANGE_INPUT") {
        let path = PathBuf::from(path);
        let foreign: Artifacts = read(&path);
        let origin = format!("{} artifacts", foreign.producer.language);
        eprintln!(
            "exchange: opening {origin} from {} {} over {} ({})",
            foreign.producer.sdk,
            foreign.producer.sdk_version,
            foreign.producer.backend,
            path.display()
        );
        consume(&corpus, &values, &keyset, &foreign, &origin).await;
    }
}

/// A record artifact carrying a sealed field the corpus does not declare is
/// refused, though every declared field still opens.
#[tokio::test]
#[should_panic(expected = "sealed fields")]
async fn an_undeclared_record_field_is_refused() {
    let (corpus, values) = corpora();
    let seed: [u8; 32] = unhex(&corpus.seed).try_into().expect("a 32-byte seed");
    let cipher = common::deterministic_cipher(seed).await;
    let keyset = cipher.default_keyset();

    let fresh = produce(&corpus, &values, &keyset).await;
    let mut tampered = serde_json::to_value(&fresh).unwrap();
    let row = &corpus.record.rows[0].id;
    let fields = tampered["record"][row]["fields"]
        .as_object_mut()
        .expect("a record's sealed fields");
    let copy = fields.values().next().expect("a sealed field").clone();
    assert!(fields.insert("undeclared".into(), copy).is_none());
    let tampered: Artifacts = serde_json::from_value(tampered).unwrap();
    consume(&corpus, &values, &keyset, &tampered, "self").await;
}

/// The exchange corpus and the value corpus it draws on, checked for shape.
fn corpora() -> (Corpus, ValuesCorpus) {
    let corpus: Corpus = read(&root().join("exchange.json"));
    assert_eq!(corpus.version, 1);
    assert_eq!(corpus.profile, PROFILE);
    assert_eq!(corpus.values.corpus, "values.json");
    assert_eq!(corpus.eql.table, "profiles");
    assert_eq!(corpus.eql.schema, "eql_v4");
    assert!(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(&corpus.eql.fixture)
            .is_file(),
        "the EQL lane's fixture exists"
    );
    let values: ValuesCorpus = read(&root().join(&corpus.values.corpus));
    assert_eq!(values.version, 1);
    assert_eq!(values.profile, corpus.values.profile);
    assert!(!values.required_capabilities.is_empty() && !values.host_conversions.is_empty());
    for case in &values.cases {
        assert_eq!(
            case.frame.is_none(),
            is_null(&case.input),
            "{}: frame",
            case.id
        );
        let _ = &case.companion;
    }
    let field_names: BTreeSet<_> = corpus
        .record
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert_eq!(
        field_names.len(),
        corpus.record.fields.len(),
        "unique record fields"
    );
    assert!(corpus.record.fields.iter().any(|f| f.passthrough));
    for row in &corpus.record.rows {
        assert_eq!(
            ids(row.values.keys()),
            field_names,
            "{}: every field has a value",
            row.id
        );
    }
    (corpus, values)
}

/// A frame of a null, for the record rows that carry one: pinned so the
/// expected opened row's spelling cannot drift from the runtime profile's.
#[test]
fn a_null_input_is_the_runtime_profile_null() {
    let null = Input {
        kind: "null".into(),
        text: String::new(),
    };
    let expected: ValueFrame = frame(vitaminc_aead::plaintext::Raw(
        None,
        vitaminc_aead::plaintext::Physical::Null,
    ));
    assert_eq!(value(&null).risky_ref(), expected.risky_ref());
}
