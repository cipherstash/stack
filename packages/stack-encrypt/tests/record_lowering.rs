//! The record fixture is the proof of the lowering (ADR-0007, amended
//! 2026-10-06): the combinators of `stack_encrypt::target`, composed by
//! hand, and the data-plan lowering each open the records the other sealed,
//! and both derive the same bytes for each term. The combinators run over
//! `dynamic::ValueFrame` fields, the plaintext type a binding's values have,
//! so the two authors write one declaration over one type; combinators over
//! bare `u32`/`String` fields seal the same tagged leaves (see
//! `dynamic::record`). `tests/fixtures/record_lowering.json` holds one
//! record from each author, sealed under a deterministic key source so the
//! bytes open in any process, and its README gives the schema a Go test
//! reads later.
//!
//! The fixture names the first author `typed_chain`, and the tests here
//! say "the chain". The committed records of that author were sealed by the
//! plan builder's chain, which is removed. The chain added no operation of
//! its own: `encrypt_index` was `indexed(..).under(label)`, `encrypt` was
//! `ciphertext().under(label)`, `passthrough` was `passthrough()`, and an
//! open was `open` for each field. Those combinators remain, so they seal
//! and open in the chain's place. The fixture and the test names keep the
//! old word, because the Go module reads the file and the fixture
//! enrollment index lists the tests by name.
//!
//! The fixture holds a second case under its `context_field` key: the same
//! proof for a plan that takes its context from a field of the record (the
//! data grammar's `"context_field"`). The combinators read the context from
//! the record and run the sealed field under it. Each author seals the
//! record, and the other opens it under the context the record stores. A
//! reader that names another context opens neither author's record.
//!
//! Regenerate the fixture with `STACK_ENCRYPT_UPDATE_FIXTURES=1 cargo test
//! --test record_lowering --all-features`; every other run reads it. Each
//! test rewrites only the entries it owns, so a filter on one test name
//! regenerates one case and leaves the rest as committed.
#![cfg(feature = "dynamic")]

mod common;

use stack_encrypt::{AsProtectedRef as _, Protected};
use std::collections::BTreeMap;
use std::path::PathBuf;

use common::frames::{frame, object, payload};
use common::{deterministic_cipher, DeterministicSource};
use serde_json::{json, Map, Value as Json};
use stack_encrypt::dynamic::record::{self, Plan as DataPlan};
use stack_encrypt::dynamic::{TermBytes, ValueFrame, ValueKind};
use stack_encrypt::plan::IntoLabel;
use stack_encrypt::sem::MatchOptions;
use stack_encrypt::target::{
    ciphertext, indexed, open, passthrough as carried, Borrowed, DeclaredContext, Encrypted,
    Encryption, IndexSpec,
};
use stack_encrypt::{
    nonempty, CipherText, Error, Label, NonEmpty, SealedValue, StackCipher, StackCipherText,
};
use vitaminc_aead_frame::serde::from_slice;

const SEED: [u8; 32] = *b"stack-encrypt record fixture v1 ";

struct User {
    age: ValueFrame,
    email: ValueFrame,
    notes: ValueFrame,
    id: u32,
}

fn user() -> User {
    User {
        age: frame(34u32),
        email: frame("bob@example.com"),
        notes: frame("likes cats"),
        id: 42,
    }
}

/// What the combinators write for a user: `age` and `email` each sealed
/// with two terms beside it, `notes` sealed alone, and `id` as it is.
type TypedUser = (
    (
        (
            Encrypted<(TermBytes, TermBytes)>,
            Encrypted<(TermBytes, TermBytes)>,
        ),
        StackCipherText,
    ),
    u32,
);

/// The one declaration, as the combinators write it over `ValueFrame`
/// fields: each sealed field under `users/<field>`.
fn typed_declaration<'s>() -> Encryption<'s, User, TypedUser, DeterministicSource, DeclaredContext>
{
    indexed::<ValueFrame, _, Borrowed, _>((IndexSpec::Equality, IndexSpec::Ore))
        .under(nonempty!("users").with("age"))
        .project(|u: &User| &u.age)
        .zip(
            indexed::<ValueFrame, _, Borrowed, _>((
                IndexSpec::Equality,
                IndexSpec::Match(MatchOptions::default()),
            ))
            .under(nonempty!("users").with("email"))
            .project(|u: &User| &u.email),
        )
        .zip(
            ciphertext::<ValueFrame, _, Borrowed>()
                .under(nonempty!("users").with("notes"))
                .project(|u: &User| &u.notes),
        )
        .zip(carried::<u32, _, Borrowed, DeclaredContext>().project(|u: &User| &u.id))
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

// ---- JSON <-> frames, for the subset the fixture uses ---------------------

/// A plan written as JSON, as frame bytes: what a binding sends.
fn frame_of_json(value: &Json) -> vitaminc_protected::Buffer {
    vitaminc_aead_frame::serde::to_vec(value).expect("frames")
}

/// The plaintext as the binding sends it: each field at the kind the plan
/// declares for it.
fn source_of(plaintext: &Json, plan: &DataPlan) -> ValueFrame {
    let fields = plaintext.as_object().expect("an object");
    object(
        plan.fields()
            .iter()
            .map(|field| {
                let value = &fields[field.name()];
                let value = match field.field_type().expect("every fixture field is typed") {
                    stack_encrypt::dynamic::ValueKind::UInt32 => frame(
                        u32::try_from(value.as_u64().expect("an integer")).expect("fits a u32"),
                    ),
                    stack_encrypt::dynamic::ValueKind::String => {
                        frame(value.as_str().expect("text"))
                    }
                    other => panic!("the fixture does not use {other}"),
                };
                (field.name(), value)
            })
            .collect(),
    )
}

/// An opened value, read back from its frame as JSON.
fn json_of_opened(value: ValueFrame) -> Json {
    exact(value.risky_ref())
}

/// A frame read as JSON, holding the fixture's kinds and nothing else: an
/// object, a `u32` or text. Another kind, a `u64` or a `u8` included, fails
/// the test, so both authors are held to the width the plan declares.
fn exact(frame: &[u8]) -> Json {
    from_slice::<Exact>(frame)
        .expect("an object, a u32 or text")
        .0
}

struct Exact(Json);

impl<'de> serde::Deserialize<'de> for Exact {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Exact;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object, a u32 or text")
            }
            fn visit_u32<E>(self, v: u32) -> Result<Exact, E> {
                Ok(Exact(json!(v)))
            }
            fn visit_str<E>(self, v: &str) -> Result<Exact, E> {
                Ok(Exact(json!(v)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Exact, A::Error> {
                let mut out = Map::new();
                while let Some((key, Exact(value))) = map.next_entry::<String, Exact>()? {
                    let _ = out.insert(key, value);
                }
                Ok(Exact(Json::Object(out)))
            }
        }
        d.deserialize_any(V)
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
                    // The fixture's passthroughs are a u32 and text.
                    exact(&payload.0)
                }
                (_, CipherText::Passthrough(payload)) => {
                    json!(hex(
                        from_slice::<&[u8]>(&payload.0).expect("a term is bytes")
                    ))
                }
                (key, _) => panic!("unexpected output {key}"),
            };
            let _ = field.insert(key, value);
        }
        let _ = out.insert(name, Json::Object(field));
    }
    Json::Object(out)
}

/// A value as a passthrough node: its frame, in the clear.
fn passthrough<T: stack_encrypt::Encrypt>(value: T) -> StackCipherText {
    CipherText::Passthrough(stack_encrypt::PassthroughFrame(payload(value)))
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
                            "passthrough" => passthrough(match value {
                                Json::String(text) => frame(text.as_str()),
                                _ => frame(
                                    u32::try_from(value.as_u64().expect("an integer"))
                                        .expect("u32"),
                                ),
                            }),
                            _ => passthrough(unhex(value.as_str().expect("hex"))),
                        };
                        (key.clone(), node)
                    })
                    .collect();
                (name.clone(), CipherText::Map(nodes))
            })
            .collect(),
    )
}

/// The combinators' record, shaped as the stored tree, by hand: what a Go
/// program assembles from the engine's standard outputs.
fn record_of_typed((((age, email), notes), id): TypedUser) -> StackCipherText {
    let term = |bytes: Vec<u8>| -> StackCipherText { passthrough(bytes) };
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
            CipherText::Map(vec![("passthrough".into(), passthrough(id))]),
        ),
    ])
}

/// What the combinators read of a stored tree: each sealed field's bare
/// ciphertext by name, and each passthrough's payload by name. The terms
/// are not read: a term opens nothing.
struct StoredFields {
    sealed: BTreeMap<String, StackCipherText>,
    carried: BTreeMap<String, Vec<u8>>,
}

impl StoredFields {
    fn of(tree: StackCipherText) -> Self {
        let CipherText::Map(fields) = tree else {
            panic!("a record is a map");
        };
        let mut stored = Self {
            sealed: BTreeMap::new(),
            carried: BTreeMap::new(),
        };
        for (name, node) in fields {
            let CipherText::Map(outputs) = node else {
                panic!("a field is a map of outputs");
            };
            for (key, node) in outputs {
                match key.as_str() {
                    "c" => {
                        let _ = stored.sealed.insert(name.clone(), node);
                    }
                    "passthrough" => {
                        let CipherText::Passthrough(payload) = node else {
                            panic!("a passthrough node");
                        };
                        let _ = stored.carried.insert(name.clone(), payload.0);
                    }
                    _ => {}
                }
            }
        }
        stored
    }

    /// The ciphertext of the sealed field `name`.
    fn sealed(&mut self, name: &str) -> StackCipherText {
        self.sealed.remove(name).expect(name)
    }

    /// The passthrough field `name`, which must be a `u32` in its frame.
    fn id(&mut self, name: &str) -> u32 {
        let payload = self.carried.remove(name).expect(name);
        let id: u32 = from_slice(&payload).expect("a u32");
        assert_eq!(payload, common::frames::payload(id), "the id is a u32");
        id
    }

    /// The passthrough field `name`, which must be text in its frame.
    fn text(&mut self, name: &str) -> ValueFrame {
        let payload = self.carried.remove(name).expect(name);
        let text = ValueFrame::from_bytes(Protected::new(payload).as_protected_ref().as_deref())
            .expect("a value");
        assert_eq!(text.kind(), Some(ValueKind::String), "{name} is text");
        text
    }
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
    let sealed = cipher
        .default_keyset()
        .run(typed_declaration(), &user(), DeclaredContext::default())
        .await
        .expect("the combinators seal");
    record_of_typed(sealed)
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

/// Open through the combinators: `open` for each sealed field under the
/// label the declaration seals it under, all in one request.
async fn open_typed(cipher: &StackCipher<DeterministicSource>, tree: StackCipherText) -> Json {
    let mut stored = StoredFields::of(tree);
    let opening = open::<ValueFrame, _>(stored.sealed("age"), nonempty!("users").with("age"))
        .zip(open::<ValueFrame, _>(
            stored.sealed("email"),
            nonempty!("users").with("email"),
        ))
        .zip(open::<ValueFrame, _>(
            stored.sealed("notes"),
            nonempty!("users").with("notes"),
        ));
    let ((age, email), notes) = cipher
        .run_decryption(opening)
        .await
        .expect("the combinators open it");
    json!({
        "age": json_of_opened(age),
        "email": json_of_opened(email),
        "notes": json_of_opened(notes),
        "id": stored.id("id"),
    })
}

async fn open_lowered(
    cipher: &StackCipher<DeterministicSource>,
    tree: StackCipherText,
    plan: &DataPlan,
) -> Json {
    json_of_opened(
        record::decrypt(cipher, tree, plan, None)
            .expect("the record fits")
            .await
            .expect("the lowering opens it"),
    )
}

/// The combinators and the lowering, run now under the same declaration:
/// the same terms, and each opens the other's record.
#[tokio::test]
async fn the_chain_and_the_lowering_are_one_engine_today() {
    let cipher = deterministic_cipher(SEED).await;
    let plan = record::plan(frame_of_json(&data_plan_json()).as_protected_ref())
        .expect("the data plan parses");

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
        "the lowering opens the combinators' record"
    );
    assert_eq!(
        open_typed(&cipher, record_of_json(&lowered)).await,
        plaintext_json(),
        "the combinators open the lowering's record"
    );
}

/// The committed fixture: records each author sealed in an earlier run,
/// opened by the other now, their terms the ones derived now. The
/// `typed_chain` record was sealed by the chain, and the combinators open
/// it; an update seals that record with the combinators. With
/// `STACK_ENCRYPT_UPDATE_FIXTURES=1` the records are sealed afresh and
/// written; the terms and the plaintext never change. Updates panic when
/// `STACK_CONFORMANCE_REQUIRED=1`.
#[tokio::test]
async fn the_committed_fixture_opens_both_ways() {
    let update = common::fixture_updates_requested_or_panic();
    let cipher = deterministic_cipher(SEED).await;
    let plan = record::plan(frame_of_json(&data_plan_json()).as_protected_ref())
        .expect("the data plan parses");
    let path = fixture_path();

    if update {
        let mut fixture = committed_fixture(&path);
        let entries = fixture.as_object_mut().expect("an object");
        // The comment and the `typed_chain` key are written as they are
        // committed, so that an update changes the sealed bytes and nothing
        // else in the file the Go module reads.
        let _ = entries.insert("_comment".into(), json!("Records sealed by typed Rust code and by the data-plan lowering under one declaration (ADR-0007). The typed_chain record was written by the plan chain until that chain was removed; since then, an update writes it with the engine's target combinators (seal_typed in tests/record_lowering.rs), and the key keeps its name for the Go reader. Read by tests/record_lowering.rs; the schema is in README.md beside this file. Regenerate with STACK_ENCRYPT_UPDATE_FIXTURES=1; do not edit by hand."));
        let _ = entries.insert(
            "key_source".into(),
            json!({ "kind": "deterministic-sha256", "seed": hex(&SEED) }),
        );
        let _ = entries.insert(
            "keyset_id".into(),
            json!(cipher
                .default_keyset()
                .keyset_id()
                .await
                .unwrap()
                .to_string()),
        );
        let _ = entries.insert("plan".into(), data_plan_json());
        let _ = entries.insert("plaintext".into(), plaintext_json());
        let _ = entries.insert(
            "records".into(),
            json!({
                "typed_chain": json_of_record(seal_typed(&cipher).await),
                "lowering": json_of_record(seal_lowered(&cipher, &plan).await),
            }),
        );
        write_fixture(&path, &fixture);
    }

    let fixture: Json =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the fixture is committed"))
            .expect("the fixture is JSON");
    assert_eq!(fixture["key_source"]["seed"], json!(hex(&SEED)));
    assert_eq!(
        fixture["keyset_id"],
        json!(cipher
            .default_keyset()
            .keyset_id()
            .await
            .unwrap()
            .to_string())
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
        "the combinators open the lowering's committed record"
    );
    assert_eq!(
        open_typed(&cipher, record_of_json(typed)).await,
        plaintext_json(),
        "and each opens its own author's"
    );
    assert_eq!(
        open_lowered(&cipher, record_of_json(lowered), &plan).await,
        plaintext_json()
    );
}

/// The committed fixture, or an empty object before the first run that
/// writes it. Each test's update path rewrites the entries it owns and
/// leaves the others as committed.
fn committed_fixture(path: &PathBuf) -> Json {
    match std::fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).expect("the fixture is JSON"),
        Err(_) => json!({}),
    }
}

fn write_fixture(path: &PathBuf, fixture: &Json) {
    let mut text = serde_json::to_string_pretty(fixture).expect("serialise");
    text.push('\n');
    std::fs::write(path, text).expect("write the fixture");
}

// ---- The context-field case ---------------------------------------------------

/// A record whose context is one of its own fields: `tenant` names the
/// context, `text` is sealed and indexed under `<tenant>/text`, `id` is
/// carried through.
struct Note {
    tenant: ValueFrame,
    text: ValueFrame,
    id: u32,
}

fn note() -> Note {
    Note {
        tenant: frame("tenants/acme"),
        text: frame("hello"),
        id: 42,
    }
}

/// What the combinators write for a note: the tenant as it is, `text`
/// sealed with its equality term beside it, and `id` as it is.
type TypedNote = ((ValueFrame, Encrypted<TermBytes>), u32);

/// The label a note's `text` is sealed under: the context the note names,
/// then the field.
fn text_label(tenant: &ValueFrame) -> Label {
    let context = tenant.into_label().expect("the tenant is a label");
    Label::new(context.segments().chain(["text"])).expect("a label")
}

/// The declaration as the combinators write it for one note: the tenant
/// is carried as it is, and `text` runs under the label read from it. The
/// label is in the record, so the description is composed for each record.
fn note_declaration<'s>(
    note: &Note,
) -> Encryption<'s, Note, TypedNote, DeterministicSource, DeclaredContext> {
    carried::<ValueFrame, _, Borrowed, DeclaredContext>()
        .project(|n: &Note| &n.tenant)
        .zip(
            indexed::<ValueFrame, _, Borrowed, _>(IndexSpec::Equality)
                .under(NonEmpty::from(text_label(&note.tenant)))
                .project(|n: &Note| &n.text),
        )
        .zip(carried::<u32, _, Borrowed, DeclaredContext>().project(|n: &Note| &n.id))
}

/// The same declaration as a binding sends it: the plan-level
/// `"context_field"` key, and each field's context its identity alone.
fn note_plan_json() -> Json {
    json!({
        "context_field": "tenant",
        "tenant": { "context": ["tenant"], "outputs": ["passthrough"], "type": "string" },
        "text":   { "context": ["text"],   "outputs": ["c", "eq"],      "type": "string" },
        "id":     { "context": ["id"],     "outputs": ["passthrough"],  "type": "uint32" },
    })
}

fn note_json() -> Json {
    json!({ "tenant": "tenants/acme", "text": "hello", "id": 42 })
}

fn acme() -> Label {
    Label::parse("tenants/acme").expect("a label")
}

fn globex() -> Label {
    Label::parse("tenants/globex").expect("a label")
}

/// The combinators' note record, shaped as the stored tree.
fn record_of_note(((tenant, text), id): TypedNote) -> StackCipherText {
    CipherText::Map(vec![
        (
            "tenant".into(),
            CipherText::Map(vec![("passthrough".into(), passthrough(tenant))]),
        ),
        (
            "text".into(),
            CipherText::Map(vec![
                ("c".into(), text.ciphertext),
                ("eq".into(), passthrough(text.terms.into_bytes())),
            ]),
        ),
        (
            "id".into(),
            CipherText::Map(vec![("passthrough".into(), passthrough(id))]),
        ),
    ])
}

async fn seal_note_typed(cipher: &StackCipher<DeterministicSource>) -> StackCipherText {
    let note = note();
    record_of_note(
        cipher
            .default_keyset()
            .run(note_declaration(&note), &note, DeclaredContext::default())
            .await
            .expect("the combinators seal the note"),
    )
}

async fn seal_note_lowered(
    cipher: &StackCipher<DeterministicSource>,
    plan: &DataPlan,
) -> StackCipherText {
    record::encrypt(
        &cipher.default_keyset(),
        source_of(&note_json(), plan),
        plan,
    )
    .expect("the source fits")
    .await
    .expect("the lowering seals the note")
}

/// Open through the combinators: `open` for `text`, under the context
/// `named` if given, or else under the context the record stores. The
/// combinators compare no stored context with an expected one, as a plan
/// does. A reader that names a context opens the field under it, and the
/// key source refuses a leaf that was sealed under another.
async fn open_note_typed(
    cipher: &StackCipher<DeterministicSource>,
    tree: StackCipherText,
    named: Option<Label>,
) -> Result<Json, Error> {
    let mut stored = StoredFields::of(tree);
    let tenant = stored.text("tenant");
    let label = match named {
        Some(context) => Label::new(context.segments().chain(["text"])).expect("a label"),
        None => text_label(&tenant),
    };
    let text = cipher
        .run_decryption(open::<ValueFrame, _>(
            stored.sealed("text"),
            NonEmpty::from(label),
        ))
        .await?;
    Ok(json!({
        "tenant": json_of_opened(tenant),
        "text": json_of_opened(text),
        "id": stored.id("id"),
    }))
}

async fn open_note_lowered(
    cipher: &StackCipher<DeterministicSource>,
    tree: StackCipherText,
    plan: &DataPlan,
    expected: Option<Label>,
) -> Result<Json, Error> {
    Ok(json_of_opened(
        record::decrypt(cipher, tree, plan, expected)
            .expect("the record fits")
            .await?,
    ))
}

/// The two authors under a context field, run now: the same term, and each
/// opens the other's record under the context it stores. Neither opens the
/// other's record under another context. The lowering compares the stored
/// context with the expected one and refuses before any key is requested.
/// The combinators ask for the key under the context the reader names, and
/// the key source refuses.
#[tokio::test]
async fn the_chain_and_the_lowering_agree_on_a_context_field_today() {
    let cipher = deterministic_cipher(SEED).await;
    let plan = record::plan(frame_of_json(&note_plan_json()).as_protected_ref())
        .expect("the data plan parses");
    assert_eq!(plan.context_field(), Some("tenant"));

    let typed = json_of_record(seal_note_typed(&cipher).await);
    let lowered = json_of_record(seal_note_lowered(&cipher, &plan).await);
    assert_eq!(
        terms_of(&typed),
        terms_of(&lowered),
        "the same term under tenants/acme/text"
    );
    assert_eq!(
        typed["tenant"]["passthrough"],
        json!("tenants/acme"),
        "the record stores its context"
    );

    for expected in [None, Some(acme())] {
        assert_eq!(
            open_note_lowered(&cipher, record_of_json(&typed), &plan, expected.clone())
                .await
                .expect("the lowering opens the combinators' note"),
            note_json()
        );
        assert_eq!(
            open_note_typed(&cipher, record_of_json(&lowered), expected)
                .await
                .expect("the combinators open the lowering's note"),
            note_json()
        );
    }
    assert!(matches!(
        open_note_lowered(&cipher, record_of_json(&typed), &plan, Some(globex())).await,
        Err(Error::ContextMismatch { .. })
    ));
    assert!(matches!(
        open_note_typed(&cipher, record_of_json(&lowered), Some(globex())).await,
        Err(Error::Kms(_))
    ));
}

/// The committed context-field case, under the fixture's `context_field`
/// key: sealed by each author in an earlier run, opened by the other now.
/// The `typed_chain` note was sealed by the chain, and an update seals it
/// with the combinators.
/// With `STACK_ENCRYPT_UPDATE_FIXTURES=1` this test rewrites that key and
/// nothing else in the file. Updates panic when `STACK_CONFORMANCE_REQUIRED=1`.
#[tokio::test]
async fn the_committed_context_field_case_opens_both_ways() {
    let update = common::fixture_updates_requested_or_panic();
    let cipher = deterministic_cipher(SEED).await;
    let plan = record::plan(frame_of_json(&note_plan_json()).as_protected_ref())
        .expect("the data plan parses");
    let path = fixture_path();

    if update {
        let mut fixture = committed_fixture(&path);
        let _ = fixture.as_object_mut().expect("an object").insert(
            "context_field".into(),
            json!({
                "_comment": "The same proof for a plan that takes its context from a field of the record: the plan-level context_field key, the context stored as a passthrough, and the term under <tenant>/text.",
                "plan": note_plan_json(),
                "plaintext": note_json(),
                "records": {
                    "typed_chain": json_of_record(seal_note_typed(&cipher).await),
                    "lowering": json_of_record(seal_note_lowered(&cipher, &plan).await),
                },
            }),
        );
        write_fixture(&path, &fixture);
    }

    let fixture = committed_fixture(&path);
    let case = &fixture["context_field"];
    assert_eq!(
        case["plan"],
        note_plan_json(),
        "the case's declaration is this one"
    );
    assert_eq!(case["plaintext"], note_json());

    let typed = &case["records"]["typed_chain"];
    let lowered = &case["records"]["lowering"];
    let now = json_of_record(seal_note_lowered(&cipher, &plan).await);
    assert_eq!(
        terms_of(typed),
        terms_of(&now),
        "the chain's fixture term is today's"
    );
    assert_eq!(
        terms_of(lowered),
        terms_of(&now),
        "the lowering's fixture term is today's"
    );
    assert_eq!(typed["tenant"]["passthrough"], json!("tenants/acme"));

    assert_eq!(
        open_note_lowered(&cipher, record_of_json(typed), &plan, Some(acme()))
            .await
            .expect("the lowering opens the chain's committed note"),
        note_json()
    );
    assert_eq!(
        open_note_typed(&cipher, record_of_json(lowered), Some(acme()))
            .await
            .expect("the combinators open the lowering's committed note"),
        note_json()
    );
    assert!(matches!(
        open_note_lowered(&cipher, record_of_json(typed), &plan, Some(globex())).await,
        Err(Error::ContextMismatch { .. })
    ));
    assert!(matches!(
        open_note_typed(&cipher, record_of_json(lowered), Some(globex())).await,
        Err(Error::Kms(_))
    ));
}

/// The deterministic source refuses a leaf opened under another descriptor,
/// as ZeroKMS does, so the fixture's records are bound to their labels and
/// not merely decodable.
#[tokio::test]
async fn the_fixture_records_are_bound_to_their_labels() {
    let cipher = deterministic_cipher(SEED).await;
    let plan = record::plan(frame_of_json(&data_plan_json()).as_protected_ref()).expect("plan");
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
    let result = record::decrypt(&cipher, CipherText::Map(fields), &plan, None)
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

#[test]
fn enrolled_fixture_tests_are_registered() {
    common::assert_fixture_tests_registered("record_lowering");
}
