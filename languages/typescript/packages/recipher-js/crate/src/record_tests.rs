//! Tests of records through the crate against the engine. The tests cover
//! the plan built from a declaration, and rows encrypted to stored rows and
//! back. The tests also cover what the engine's typed Rust API reads from
//! stored rows.

use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::json;
use stack_encrypt::dynamic::frame::OwnedFrame;
use stack_encrypt::kms::{
    DataKey, DataKeySource, DataKeyWithTag, DeterministicSource, Error, GenerateKeyPayload,
    IdentifiedBy, IndexKey, IndexKeySource, KeySourceKind, OwnIdentity, RetrieveKeyPayload,
    UnverifiedContext,
};
use stack_encrypt::StackCipher;
use uuid::Uuid;

use crate::cipher::{open_rows_in, Confined, Engine};
use crate::frames::{bytes_of, entries, Entry, Map};
use crate::outcome::Outcome;
use crate::record::{conform_row, field_value, one_field_row, open_rows, seal_rows, RecordPlan};

const SEED: [u8; 32] = [3; 32];

fn plan(declaration: serde_json::Value) -> Outcome<Arc<RecordPlan>> {
    let bytes = stack_encrypt::dynamic::frame::serde::to_vec(&declaration).unwrap();
    RecordPlan::of(&OwnedFrame::from_buffer(bytes).unwrap())
}

fn users() -> Arc<RecordPlan> {
    plan(json!({
        "type": "record",
        "name": "users",
        "fields": {
            "id": { "type": "passthrough" },
            "email": { "type": "sealed", "kind": { "name": "string" }, "index": ["equality"] },
            "name": { "type": "sealed", "kind": { "name": "string" }, "index": ["match"] },
            "age": { "type": "sealed", "kind": { "name": "int32" }, "index": ["equality"], "null": "sealed" },
            "notes": { "type": "sealed", "kind": { "name": "string" }, "null": "sql" },
        },
    }))
    .unwrap()
}

/// A row in the form JavaScript passes it, with an integer at its narrowest
/// width.
fn row(age: Option<i8>, notes: Option<&str>) -> OwnedFrame {
    let id = OwnedFrame::of(7u64).unwrap();
    let email = OwnedFrame::of("ada@example.com").unwrap();
    let name = OwnedFrame::of("Ada Lovelace").unwrap();
    let age = age.map(|age| OwnedFrame::of(age).unwrap());
    let notes = notes.map(|notes| OwnedFrame::of(notes).unwrap());
    let frame = OwnedFrame::of(&Map(vec![
        ("id", Entry::Value(&id)),
        ("email", Entry::Value(&email)),
        ("name", Entry::Value(&name)),
        ("age", or_null(age.as_ref())),
        ("notes", or_null(notes.as_ref())),
    ]))
    .unwrap();
    conform_row(&users(), &frame).unwrap()
}

/// A value, or a null where there is none.
fn or_null(value: Option<&OwnedFrame>) -> Entry<'_> {
    value.map_or(Entry::Null, Entry::Value)
}

async fn engine() -> StackCipher<DeterministicSource> {
    StackCipher::builder()
        .kms(DeterministicSource::new(SEED))
        .init()
        .await
        .unwrap()
}

/// The `ciphertext` bytes of the field `name` of a stored row.
fn ciphertext_of(stored: &OwnedFrame, name: &str) -> Vec<u8> {
    let field = field_value(stored, name).unwrap();
    let (_, ciphertext) = entries(&field)
        .unwrap()
        .into_iter()
        .find(|(key, _)| key == "ciphertext")
        .unwrap();
    bytes_of(&ciphertext).unwrap()
}

fn keys(frame: &OwnedFrame) -> Vec<String> {
    entries(frame)
        .unwrap()
        .into_iter()
        .map(|(key, _)| key)
        .collect()
}

#[tokio::test]
async fn a_row_round_trips_and_its_absent_field_opens_as_null() {
    let cipher = engine().await;
    let stored = seal_rows(&cipher.default_keyset(), users(), vec![row(Some(36), None)])
        .await
        .unwrap();
    let opened = open_rows(&cipher, users(), stored).await.unwrap().remove(0);
    assert_eq!(
        field_value(&opened, "age").unwrap().frame(),
        OwnedFrame::of(36i32).unwrap().frame(),
        "the integer opens at the field's width"
    );
    assert_eq!(field_value(&opened, "notes").unwrap().frame().kind(), None);
    assert_eq!(
        field_value(&opened, "id").unwrap().frame(),
        OwnedFrame::of(7u64).unwrap().frame()
    );
}

#[tokio::test]
async fn the_stored_row_has_a_ciphertext_and_the_declared_terms() {
    let cipher = engine().await;
    let stored = seal_rows(
        &cipher.default_keyset(),
        users(),
        vec![row(Some(36), Some("hi"))],
    )
    .await
    .unwrap()
    .remove(0);
    let email = field_value(&stored, "email").unwrap();
    assert_eq!(keys(&email), ["ciphertext", "equality"]);
    let name = field_value(&stored, "name").unwrap();
    assert_eq!(keys(&name), ["ciphertext", "match"]);
    let notes = field_value(&stored, "notes").unwrap();
    assert_eq!(keys(&notes), ["ciphertext"]);
}

#[tokio::test]
async fn a_fields_ciphertext_is_sealed_under_its_field_path() {
    let cipher = engine().await;
    let stored = seal_rows(&cipher.default_keyset(), users(), vec![row(Some(36), None)])
        .await
        .unwrap()
        .remove(0);
    let bytes = ciphertext_of(&stored, "email");
    let keyset = cipher.default_keyset();
    let email: String = keyset
        .decrypt_with_context(
            stack_encrypt::Ciphertext::from_bytes(&bytes).unwrap(),
            ("users", "email"),
        )
        .await
        .unwrap();
    assert_eq!(email, "ada@example.com");
    let elsewhere: Result<String, _> = keyset
        .decrypt_with_context(
            stack_encrypt::Ciphertext::from_bytes(&bytes).unwrap(),
            ("users", "name"),
        )
        .await;
    assert!(elsewhere.is_err());
}

#[tokio::test]
async fn one_field_opens_alone_and_a_field_alone_opens_through_the_engine() {
    let cipher = engine().await;
    let email = users().field("email").unwrap();

    // A field of a whole row decrypts through the field's own plan.
    let stored = seal_rows(&cipher.default_keyset(), users(), vec![row(Some(36), None)])
        .await
        .unwrap()
        .remove(0);
    let alone = one_field_row("email", &field_value(&stored, "email").unwrap()).unwrap();
    let opened = open_rows(&cipher, Arc::clone(&email), vec![alone])
        .await
        .unwrap()
        .remove(0);
    assert_eq!(
        field_value(&opened, "email").unwrap().frame(),
        OwnedFrame::of("ada@example.com").unwrap().frame()
    );

    // A field encrypted on its own decrypts through the engine's typed API,
    // under its field path.
    let value = OwnedFrame::of("grace@example.com").unwrap();
    let row = conform_row(&email, &one_field_row("email", &value).unwrap()).unwrap();
    let sealed = seal_rows(&cipher.default_keyset(), email, vec![row])
        .await
        .unwrap()
        .remove(0);
    let opened: String = cipher
        .default_keyset()
        .decrypt_with_context(
            stack_encrypt::Ciphertext::from_bytes(&ciphertext_of(&sealed, "email")).unwrap(),
            ("users", "email"),
        )
        .await
        .unwrap();
    assert_eq!(opened, "grace@example.com");
}

#[test]
fn an_integer_is_read_at_its_fields_width_and_refused_outside_it() {
    let small = plan(json!({
        "type": "record",
        "name": "t",
        "fields": { "n": { "type": "sealed", "kind": { "name": "int8" } } },
    }))
    .unwrap();
    let fits = OwnedFrame::of(&Map(vec![(
        "n",
        Entry::Value(&OwnedFrame::of(5u64).unwrap()),
    )]))
    .unwrap();
    let read = conform_row(&small, &fits).unwrap();
    assert_eq!(
        field_value(&read, "n").unwrap().frame(),
        OwnedFrame::of(5i8).unwrap().frame()
    );
    let too_big = OwnedFrame::of(&Map(vec![(
        "n",
        Entry::Value(&OwnedFrame::of(300i16).unwrap()),
    )]))
    .unwrap();
    let refused = conform_row(&small, &too_big).unwrap_err();
    assert_eq!(refused.code, "recipher_js::field_type");
    assert_eq!(refused.field.as_deref(), Some("n"));
    assert_eq!(refused.record.as_deref(), Some("t"));
}

#[test]
fn the_engine_refuses_a_declaration_naming_the_record_and_the_field() {
    let refused = plan(json!({
        "type": "record",
        "name": "t",
        "fields": { "n": { "type": "sealed", "kind": { "name": "int32" }, "index": ["match"] } },
    }))
    .unwrap_err();
    assert_eq!(refused.code, "stack_encrypt::dynamic_plan");
    assert_eq!(refused.field.as_deref(), Some("n"));
    assert_eq!(refused.record.as_deref(), Some("t"));

    let unknown = plan(json!({
        "type": "record",
        "name": "t",
        "fields": { "n": { "type": "sealed", "kind": { "name": "int31" } } },
    }))
    .unwrap_err();
    assert_eq!(unknown.code, "recipher_js::kind");
}

fn devices() -> Arc<RecordPlan> {
    plan(json!({
        "type": "record",
        "name": "devices",
        "fields": {
            "id": { "type": "sealed", "kind": { "name": "uuid" }, "index": ["equality"] },
        },
    }))
    .unwrap()
}

fn device_row(id: Uuid) -> OwnedFrame {
    let id = OwnedFrame::of(stack_encrypt::value::Uuid::new(id)).unwrap();
    let frame = OwnedFrame::of(&Map(vec![("id", Entry::Value(&id))])).unwrap();
    conform_row(&devices(), &frame).unwrap()
}

/// The `equality` term of the field `name` of a stored row.
fn equality_of(stored: &OwnedFrame, name: &str) -> Vec<u8> {
    let field = field_value(stored, name).unwrap();
    let (_, term) = entries(&field)
        .unwrap()
        .into_iter()
        .find(|(key, _)| key == "equality")
        .unwrap();
    term.frame().as_bytes().to_vec()
}

#[tokio::test]
async fn a_uuid_field_is_stored_found_by_equality_and_read_back() {
    let cipher = engine().await;
    let keyset = cipher.default_keyset();
    let id = Uuid::from_u128(0x123e_4567_e89b_12d3_a456_4266_1417_4000);
    let other = Uuid::from_u128(0x123e_4567_e89b_12d3_a456_4266_1417_4001);
    let stored = seal_rows(&keyset, devices(), vec![device_row(id)])
        .await
        .unwrap()
        .remove(0);
    assert_eq!(
        keys(&field_value(&stored, "id").unwrap()),
        ["ciphertext", "equality"]
    );

    // A query for the same UUID derives the stored term, and another UUID
    // does not.
    let field = devices().field("id").unwrap();
    let query = |id: Uuid| {
        let value = OwnedFrame::of(stack_encrypt::value::Uuid::new(id)).unwrap();
        conform_row(&field, &one_field_row("id", &value).unwrap()).unwrap()
    };
    let found = seal_rows(&keyset, Arc::clone(&field), vec![query(id), query(other)])
        .await
        .unwrap();
    assert_eq!(equality_of(&found[0], "id"), equality_of(&stored, "id"));
    assert_ne!(equality_of(&found[1], "id"), equality_of(&stored, "id"));

    let opened = open_rows(&cipher, devices(), vec![stored])
        .await
        .unwrap()
        .remove(0);
    let expected = OwnedFrame::of(stack_encrypt::value::Uuid::new(id)).unwrap();
    assert_eq!(
        field_value(&opened, "id").unwrap().frame(),
        expected.frame()
    );
}

#[test]
fn an_order_index_on_a_uuid_field_is_refused_when_the_plan_is_built() {
    for index in ["ore", "ope"] {
        let refused = plan(json!({
            "type": "record",
            "name": "t",
            "fields": { "id": { "type": "sealed", "kind": { "name": "uuid" }, "index": [index] } },
        }))
        .unwrap_err();
        assert_eq!(refused.code, "stack_encrypt::dynamic_plan", "{index}");
        assert_eq!(refused.reason(), Some("index_not_admitted"), "{index}");
        assert_eq!(refused.field.as_deref(), Some("id"), "{index}");
    }
}

#[test]
fn a_json_field_needs_the_eql_extension() {
    let refused = plan(json!({
        "type": "record",
        "name": "t",
        "fields": { "doc": { "type": "sealed", "kind": { "name": "json" } } },
    }))
    .unwrap_err();
    assert_eq!(refused.code, "stack_encrypt::dynamic_plan");
    assert_eq!(refused.reason(), Some("json_needs_target"));
}

#[test]
fn a_bad_record_name_is_the_records_fault_and_a_bad_field_name_the_fields() {
    let bad_record = plan(json!({
        "type": "record",
        "name": "a/b",
        "fields": { "x": { "type": "sealed", "kind": { "name": "string" } } },
    }))
    .unwrap_err();
    assert_eq!(bad_record.code, "recipher_js::record_name");
    assert_eq!(bad_record.record.as_deref(), Some("a/b"));
    assert_eq!(bad_record.field, None);

    let bad_field = plan(json!({
        "type": "record",
        "name": "users",
        "fields": { "a/b": { "type": "sealed", "kind": { "name": "string" } } },
    }))
    .unwrap_err();
    assert_eq!(bad_field.reason(), Some("context_not_label"));
    assert_eq!(bad_field.field.as_deref(), Some("a/b"));
    assert_eq!(bad_field.record.as_deref(), Some("users"));
}

/// A deterministic key source that counts the key requests it receives.
struct Counting {
    inner: DeterministicSource,
    generates: AtomicUsize,
    retrieves: AtomicUsize,
}

impl KeySourceKind for Counting {
    type Kind = OwnIdentity;
}

impl DataKeySource for Counting {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, Error> {
        let _ = self.generates.fetch_add(1, Ordering::SeqCst);
        self.inner
            .generate_keys(payloads, keyset_id, unverified_context)
            .await
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, Error> {
        let _ = self.retrieves.fetch_add(1, Ordering::SeqCst);
        self.inner
            .retrieve_keys(payloads, keyset_id, unverified_context)
            .await
    }
}

impl IndexKeySource for Counting {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), Error> {
        self.inner.load_index_key(keyset_id).await
    }
}

#[tokio::test]
async fn many_rows_and_many_fields_alone_are_one_key_request_each_way() {
    let cipher = StackCipher::builder()
        .kms(Counting {
            inner: DeterministicSource::new(SEED),
            generates: AtomicUsize::new(0),
            retrieves: AtomicUsize::new(0),
        })
        .init()
        .await
        .unwrap();
    let rows = vec![row(Some(1), None), row(Some(2), None), row(None, Some("x"))];
    let stored = seal_rows(&cipher.default_keyset(), users(), rows)
        .await
        .unwrap();
    assert_eq!(cipher.kms().generates.load(Ordering::SeqCst), 1);
    let _ = open_rows(&cipher, users(), stored).await.unwrap();
    assert_eq!(cipher.kms().retrieves.load(Ordering::SeqCst), 1);

    // Three values of one field, as `encryptField` encrypts an array of
    // them.
    let email = users().field("email").unwrap();
    let rows = ["a", "b", "c"]
        .into_iter()
        .map(|text| {
            let value = OwnedFrame::of(text).unwrap();
            conform_row(&email, &one_field_row("email", &value).unwrap()).unwrap()
        })
        .collect();
    let stored = seal_rows(&cipher.default_keyset(), Arc::clone(&email), rows)
        .await
        .unwrap();
    assert_eq!(cipher.kms().generates.load(Ordering::SeqCst), 2);
    let _ = open_rows(&cipher, email, stored).await.unwrap();
    assert_eq!(cipher.kms().retrieves.load(Ordering::SeqCst), 2);
}

#[test]
fn a_plan_is_built_once_for_a_declaration() {
    assert!(Arc::ptr_eq(&users(), &users()));
    let plan = users();
    assert!(Arc::ptr_eq(
        &plan.field("email").unwrap(),
        &plan.field("email").unwrap()
    ));
}

/// `keyset.decrypt` of a stored row is confined to its keyset and
/// `cipher.decrypt` is not, as for a ciphertext. The two differ only in the
/// `Confined` they pass to `open_rows_in`.
#[tokio::test]
async fn a_keyset_refuses_another_keysets_row_and_the_cipher_opens_it() {
    let cipher = engine().await;
    let other = cipher.keyset(IdentifiedBy::Name("another-keyset".to_owned().into()));
    let refused_row = seal_rows(&other, users(), vec![row(Some(36), None)])
        .await
        .unwrap();
    let stored = seal_rows(&other, users(), vec![row(Some(36), None)])
        .await
        .unwrap();
    let engine = Engine::Testing(Box::new(cipher));

    let refused = open_rows_in(&engine, users(), refused_row, Confined::ToDefault)
        .await
        .unwrap_err();
    assert_eq!(refused.code, "stack_encrypt::foreign_keyset");

    let opened = open_rows_in(&engine, users(), stored, Confined::No)
        .await
        .unwrap()
        .remove(0);
    assert_eq!(
        field_value(&opened, "email").unwrap().frame(),
        OwnedFrame::of("ada@example.com").unwrap().frame()
    );
}
