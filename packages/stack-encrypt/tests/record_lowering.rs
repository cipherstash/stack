//! The record fixture is the proof of the lowering (ADR-0007, amended
//! 2026-10-06): a Rust chain and the data-plan lowering each open the
//! records the other sealed, and both derive the same bytes for each term.
//! The chain's fields are `dynamic::Value`s, the plaintext type a binding's
//! values have, so the two authors write one declaration over one type; a
//! chain over bare `u32`/`String` fields shares the terms and not the leaves
//! (see `dynamic::record`). `tests/fixtures/record_lowering.json` holds one
//! record from each author, sealed under a deterministic key source so the
//! bytes open in any process, and its README gives the schema a Go test
//! reads later.
//!
//! Regenerate the fixture with `STACK_ENCRYPT_UPDATE_FIXTURES=1 cargo test
//! --test record_lowering --all-features`; every other run reads it.
#![cfg(feature = "dynamic")]

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use common::{deterministic_cipher, DeterministicSource};
use serde_json::{json, Map, Value as Json};
use stack_encrypt::dynamic::record::{self, Plan as DataPlan};
use stack_encrypt::dynamic::{FfiValue, Scope, TermBytes, Value};
use stack_encrypt::plan::{pick, FieldValues};
use stack_encrypt::sem::MatchOptions;
use stack_encrypt::target::{Encrypted, IndexSpec};
use stack_encrypt::{CipherText, Plan, SealedValue, StackCipher, StackCipherText};
use vitaminc_protected::Controlled;

const SEED: [u8; 32] = *b"stack-encrypt record fixture v1 ";

struct User {
    age: Value,
    email: Value,
    notes: Value,
    id: u32,
}

fn user() -> User {
    User {
        age: Value::new(FfiValue::UInt32(34)),
        email: Value::new(FfiValue::String("bob@example.com".into())),
        notes: Value::new(FfiValue::String("likes cats".into())),
        id: 42,
    }
}

/// The one declaration, as the Rust chain writes it over `Value` fields.
fn typed_plan() -> Plan<User, DeterministicSource> {
    Plan::context("users")
        .fields()
        .encrypt_index(
            pick("age", |u: &User| &u.age),
            (IndexSpec::Equality, IndexSpec::Ore),
        )
        .encrypt_index(
            pick("email", |u: &User| &u.email),
            (
                IndexSpec::Equality,
                IndexSpec::Match(MatchOptions::default()),
            ),
        )
        .encrypt(pick("notes", |u: &User| &u.notes))
        .passthrough(pick("id", |u: &User| &u.id))
        .build()
        .expect("the typed plan builds")
}

/// The same declaration as a binding sends it: the fixture's `plan`.
fn data_plan_json() -> Json {
    json!({
        "age":   { "context": ["users", "age"],   "outputs": ["c", "eq", "ore"],   "type": "uint32" },
        "email": { "context": ["users", "email"], "outputs": ["c", "eq", "match"], "type": "string" },
        "notes": { "context": ["users", "notes"], "outputs": ["c"],                "type": "string" },
        "id":    { "context": ["users", "id"],    "outputs": ["passthrough"],      "type": "uint32" },
    })
}

fn plaintext_json() -> Json {
    json!({ "age": 34, "email": "bob@example.com", "notes": "likes cats", "id": 42 })
}

// ---- JSON <-> FfiValue, for the subset the fixture uses --------------------

fn ffi_of_json(value: &Json) -> FfiValue {
    match value {
        Json::String(s) => FfiValue::String(s.as_str().into()),
        Json::Array(items) => FfiValue::Array(items.iter().map(ffi_of_json).collect()),
        Json::Object(entries) => FfiValue::Object(
            entries
                .iter()
                .map(|(k, v)| (k.clone(), ffi_of_json(v)))
                .collect(),
        ),
        Json::Number(n) => FfiValue::UInt64(n.as_u64().expect("a non-negative integer")),
        other => panic!("the fixture does not use {other}"),
    }
}

/// The plaintext as the binding sends it: each field at the kind the plan
/// declares for it.
fn source_of(plaintext: &Json, plan: &DataPlan) -> FfiValue {
    let fields = plaintext.as_object().expect("an object");
    FfiValue::Object(
        plan.fields()
            .iter()
            .map(|field| {
                let value = &fields[field.name()];
                let value = match field.field_type().expect("every fixture field is typed") {
                    stack_encrypt::dynamic::ValueKind::UInt32 => FfiValue::UInt32(
                        u32::try_from(value.as_u64().expect("an integer")).expect("fits a u32"),
                    ),
                    stack_encrypt::dynamic::ValueKind::String => {
                        FfiValue::String(value.as_str().expect("text").into())
                    }
                    other => panic!("the fixture does not use {other}"),
                };
                (field.name().to_string(), value)
            })
            .collect(),
    )
}

fn json_of_opened(value: FfiValue) -> Json {
    match value {
        FfiValue::Object(entries) => Json::Object(
            entries
                .into_iter()
                .map(|(k, v)| (k, json_of_opened(v)))
                .collect(),
        ),
        FfiValue::UInt32(v) => json!(v),
        FfiValue::String(s) => {
            Json::String(String::from_utf8(s.risky_ref().to_vec()).expect("utf8"))
        }
        _ => panic!("the fixture does not use this kind"),
    }
}

// ---- hex ----------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

// ---- the stored record <-> JSON ---------------------------------------------

/// A stored record (the wire tree the lowering writes) as JSON: `"c"` is the
/// `SealedValue` leaf's frozen bytes, a term is its bytes, a passthrough is
/// the value.
fn json_of_record(tree: StackCipherText) -> Json {
    let CipherText::Map(fields) = tree else {
        panic!("a record is a map of fields");
    };
    let mut out = Map::new();
    for (name, node) in fields {
        let CipherText::Map(outputs) = node else {
            panic!("a field is a map of outputs");
        };
        let mut field = Map::new();
        for (key, node) in outputs {
            let value = match (key.as_str(), node) {
                ("c", CipherText::Single(leaf)) => json!(hex(&leaf.to_bytes())),
                ("passthrough", CipherText::Passthrough(payload)) => {
                    match *payload.downcast::<FfiValue>().expect("a value") {
                        FfiValue::UInt32(v) => json!(v),
                        _ => panic!("the fixture's passthrough is a u32"),
                    }
                }
                (_, CipherText::Passthrough(payload)) => {
                    match *payload.downcast::<FfiValue>().expect("a value") {
                        FfiValue::Bytes(bytes) => json!(hex(bytes.risky_ref())),
                        _ => panic!("a term is bytes"),
                    }
                }
                (key, _) => panic!("unexpected output {key}"),
            };
            let _ = field.insert(key, value);
        }
        let _ = out.insert(name, Json::Object(field));
    }
    Json::Object(out)
}

fn record_of_json(record: &Json) -> StackCipherText {
    let fields = record.as_object().expect("an object");
    CipherText::Map(
        fields
            .iter()
            .map(|(name, outputs)| {
                let outputs = outputs.as_object().expect("an object");
                let nodes = outputs
                    .iter()
                    .map(|(key, value)| {
                        let node = match key.as_str() {
                            "c" => CipherText::Single(
                                SealedValue::from_bytes(&unhex(value.as_str().expect("hex")))
                                    .expect("a frozen leaf"),
                            ),
                            "passthrough" => CipherText::Passthrough(Box::new(FfiValue::UInt32(
                                u32::try_from(value.as_u64().expect("an integer")).expect("u32"),
                            ))
                                as stack_encrypt::BoxedPassthrough),
                            _ => CipherText::Passthrough(Box::new(FfiValue::Bytes(
                                vitaminc_protected::Protected::new(unhex(
                                    value.as_str().expect("hex"),
                                )),
                            ))
                                as stack_encrypt::BoxedPassthrough),
                        };
                        (key.clone(), node)
                    })
                    .collect();
                (name.clone(), CipherText::Map(nodes))
            })
            .collect(),
    )
}

/// The typed chain's record, shaped as the stored tree, by hand: what a Go
/// program assembles from the engine's standard outputs.
fn record_of_typed(mut values: FieldValues) -> StackCipherText {
    let age: Encrypted<(TermBytes, TermBytes)> = values.take("age").expect("age");
    let email: Encrypted<(TermBytes, TermBytes)> = values.take("email").expect("email");
    let notes: StackCipherText = values.take("notes").expect("notes");
    let id: u32 = values.take("id").expect("id");
    let term = |bytes: Vec<u8>| -> StackCipherText {
        CipherText::Passthrough(
            Box::new(FfiValue::Bytes(vitaminc_protected::Protected::new(bytes)))
                as stack_encrypt::BoxedPassthrough,
        )
    };
    CipherText::Map(vec![
        (
            "age".into(),
            CipherText::Map(vec![
                ("c".into(), age.ciphertext),
                ("eq".into(), term(age.terms.0.into_bytes())),
                ("ore".into(), term(age.terms.1.into_bytes())),
            ]),
        ),
        (
            "email".into(),
            CipherText::Map(vec![
                ("c".into(), email.ciphertext),
                ("eq".into(), term(email.terms.0.into_bytes())),
                ("match".into(), term(email.terms.1.into_bytes())),
            ]),
        ),
        ("notes".into(), CipherText::Map(vec![("c".into(), notes)])),
        (
            "id".into(),
            CipherText::Map(vec![(
                "passthrough".into(),
                CipherText::Passthrough(
                    Box::new(FfiValue::UInt32(id)) as stack_encrypt::BoxedPassthrough
                ),
            )]),
        ),
    ])
}

/// A stored tree as the typed chain's record, for `open`: each sealed field
/// as its bare ciphertext, the passthrough as its value.
fn typed_of_record(tree: StackCipherText) -> FieldValues {
    let CipherText::Map(fields) = tree else {
        panic!("a record is a map");
    };
    let mut values = FieldValues::new();
    for (name, node) in fields {
        let CipherText::Map(outputs) = node else {
            panic!("a field is a map of outputs");
        };
        for (key, node) in outputs {
            match key.as_str() {
                "c" => {
                    let _ = values.insert(&name, node);
                }
                "passthrough" => {
                    let CipherText::Passthrough(payload) = node else {
                        panic!("a passthrough node");
                    };
                    let FfiValue::UInt32(id) = *payload.downcast::<FfiValue>().expect("a value")
                    else {
                        panic!("a u32");
                    };
                    let _ = values.insert(&name, id);
                }
                _ => {}
            }
        }
    }
    values
}

/// Every term of a record, by `field/key`, so two records' terms compare
/// whatever else differs.
fn terms_of(record: &Json) -> BTreeMap<String, String> {
    let mut terms = BTreeMap::new();
    for (name, outputs) in record.as_object().expect("an object") {
        for (key, value) in outputs.as_object().expect("an object") {
            if key != "c" && key != "passthrough" {
                let _ = terms.insert(
                    format!("{name}/{key}"),
                    value.as_str().expect("hex").to_owned(),
                );
            }
        }
    }
    terms
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/record_lowering.json")
}

async fn seal_typed(cipher: &StackCipher<DeterministicSource>) -> StackCipherText {
    let values = cipher
        .encrypt(&user())
        .using(&typed_plan())
        .await
        .expect("the typed chain seals");
    record_of_typed(values)
}

async fn seal_lowered(
    cipher: &StackCipher<DeterministicSource>,
    plan: &DataPlan,
) -> StackCipherText {
    record::encrypt(
        &cipher.default_keyset(),
        source_of(&plaintext_json(), plan),
        plan,
    )
    .expect("the source fits")
    .await
    .expect("the lowering seals")
}

async fn open_typed(cipher: &StackCipher<DeterministicSource>, tree: StackCipherText) -> Json {
    let mut opened = cipher
        .open(typed_of_record(tree))
        .using(&typed_plan())
        .await
        .expect("the typed chain opens it");
    let mut value =
        |name: &str| json_of_opened(opened.take::<Value>(name).expect(name).into_inner());
    let (age, email, notes) = (value("age"), value("email"), value("notes"));
    json!({
        "age": age,
        "email": email,
        "notes": notes,
        "id": opened.take::<u32>("id").expect("id"),
    })
}

async fn open_lowered(
    cipher: &StackCipher<DeterministicSource>,
    tree: StackCipherText,
    plan: &DataPlan,
) -> Json {
    json_of_opened(
        record::decrypt(Scope::Client(cipher), tree, plan)
            .expect("the record fits")
            .await
            .expect("the lowering opens it"),
    )
}

/// The typed chain and the lowering, run now under the same declaration:
/// the same terms, and each opens the other's record.
#[tokio::test]
async fn the_chain_and_the_lowering_are_one_engine_today() {
    let cipher = deterministic_cipher(SEED).await;
    let plan = record::plan(ffi_of_json(&data_plan_json())).expect("the data plan parses");

    let typed = json_of_record(seal_typed(&cipher).await);
    let lowered = json_of_record(seal_lowered(&cipher, &plan).await);
    assert_eq!(terms_of(&typed), terms_of(&lowered), "the same terms");
    assert_eq!(
        terms_of(&typed).len(),
        4,
        "eq, ore, eq, match: every index derived"
    );

    assert_eq!(
        open_lowered(&cipher, record_of_json(&typed), &plan).await,
        plaintext_json(),
        "the lowering opens the chain's record"
    );
    assert_eq!(
        open_typed(&cipher, record_of_json(&lowered)).await,
        plaintext_json(),
        "the chain opens the lowering's record"
    );
}

/// The committed fixture: records each author sealed in an earlier run,
/// opened by the other now, their terms the ones derived now. With
/// `STACK_ENCRYPT_UPDATE_FIXTURES=1` the records are sealed afresh and
/// written; the terms and the plaintext never change.
#[tokio::test]
async fn the_committed_fixture_opens_both_ways() {
    let cipher = deterministic_cipher(SEED).await;
    let plan = record::plan(ffi_of_json(&data_plan_json())).expect("the data plan parses");
    let path = fixture_path();

    if std::env::var_os("STACK_ENCRYPT_UPDATE_FIXTURES").is_some() {
        let fixture = json!({
            "_comment": "Records sealed by the typed Rust chain and by the data-plan lowering under one declaration (ADR-0007). Read by tests/record_lowering.rs; the schema is in README.md beside this file. Regenerate with STACK_ENCRYPT_UPDATE_FIXTURES=1; do not edit by hand.",
            "key_source": { "kind": "deterministic-sha256", "seed": hex(&SEED) },
            "keyset_id": cipher.default_keyset().keyset_id().to_string(),
            "plan": data_plan_json(),
            "plaintext": plaintext_json(),
            "records": {
                "typed_chain": json_of_record(seal_typed(&cipher).await),
                "lowering": json_of_record(seal_lowered(&cipher, &plan).await),
            },
        });
        let mut text = serde_json::to_string_pretty(&fixture).expect("serialise");
        text.push('\n');
        std::fs::write(&path, text).expect("write the fixture");
    }

    let fixture: Json =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the fixture is committed"))
            .expect("the fixture is JSON");
    assert_eq!(fixture["key_source"]["seed"], json!(hex(&SEED)));
    assert_eq!(
        fixture["keyset_id"],
        json!(cipher.default_keyset().keyset_id().to_string())
    );
    assert_eq!(
        fixture["plan"],
        data_plan_json(),
        "the fixture's declaration is this one"
    );
    assert_eq!(fixture["plaintext"], plaintext_json());

    let typed = &fixture["records"]["typed_chain"];
    let lowered = &fixture["records"]["lowering"];
    let now = json_of_record(seal_lowered(&cipher, &plan).await);
    assert_eq!(
        terms_of(typed),
        terms_of(&now),
        "the chain's fixture terms are today's"
    );
    assert_eq!(
        terms_of(lowered),
        terms_of(&now),
        "the lowering's fixture terms are today's"
    );

    assert_eq!(
        open_lowered(&cipher, record_of_json(typed), &plan).await,
        plaintext_json(),
        "the lowering opens the chain's committed record"
    );
    assert_eq!(
        open_typed(&cipher, record_of_json(lowered)).await,
        plaintext_json(),
        "the chain opens the lowering's committed record"
    );
    assert_eq!(
        open_typed(&cipher, record_of_json(typed)).await,
        plaintext_json(),
        "and each opens its own"
    );
    assert_eq!(
        open_lowered(&cipher, record_of_json(lowered), &plan).await,
        plaintext_json()
    );
}

/// The deterministic source refuses a leaf opened under another descriptor,
/// as ZeroKMS does, so the fixture's records are bound to their labels and
/// not merely decodable.
#[tokio::test]
async fn the_fixture_records_are_bound_to_their_labels() {
    let cipher = deterministic_cipher(SEED).await;
    let plan = record::plan(ffi_of_json(&data_plan_json())).expect("plan");
    let sealed = seal_lowered(&cipher, &plan).await;
    let CipherText::Map(mut fields) = sealed else {
        panic!("a map");
    };
    // `email` and `notes` are both `string` fields, so the per-field type
    // check cannot refuse the swap: only the key source's label binding can.
    for (name, _) in &mut fields {
        *name = match name.as_str() {
            "email" => "notes".into(),
            "notes" => "email".into(),
            other => other.into(),
        };
    }
    let result = record::decrypt(Scope::Client(&cipher), CipherText::Map(fields), &plan)
        .expect("the shape fits")
        .await;
    match result {
        Err(stack_encrypt::Error::Kms(_)) => {}
        Err(other) => {
            panic!("a leaf under another field's label is refused by the key source, got {other:?}")
        }
        Ok(_) => panic!("a leaf under another field's label opened"),
    }
}
