//! EQL types as fields of a derived `struct = ..` record.
//!
//! A record gives each field its scope and the field's name, such as
//! `("members", "email")`. An EQL field stores that pair as its column, `i`.
//! So the field must write what the same type writes on its own under
//! `Identifier::for_column("members", "email")`, and what a data plan writes
//! for a field that names the type. A data plan is the path the Go module
//! takes. Here:
//!
//! - a record with EQL fields encrypts and decrypts through the new API;
//! - each field writes the terms the type writes on its own, and each value
//!   opens through the other path;
//! - a query from the field's marker gives the stored term;
//! - the derive and a data plan write the same terms for a field of each
//!   kind (equality, storage only, order, JSON document), and each opens
//!   the other's value;
//! - a record that lists a caller scope or a binding cannot store an EQL
//!   field, nor can a record nested in another, and each is refused before
//!   any key is requested;
//! - a field that stores another column is refused before any key is
//!   requested;
//! - a JSON document, `JsonTreeDocument`, encrypts from a `JsonPlaintext`
//!   through the new API, writes the search terms the old path writes, and
//!   is a record field too.

mod common;

use eql_bindings::encryption::EqlTargets;
use eql_bindings::v4::integer::IntegerOrd;
use eql_bindings::v4::json_tree::{JsonTree, JsonTreeDocument};
use eql_bindings::v4::text::{Text, TextEq};
use eql_bindings::Identifier;
use serde::Serialize;
use serde_json::{json, Value};
use stack_encrypt::dynamic::{self, record, ValueFrame};
use stack_encrypt::json::JsonPlaintext;
use stack_encrypt::target::{Bind, Layout, Scope};
use stack_encrypt::{
    AsProtectedRef as _, CipherText, Controlled as _, DecryptFrom, DecryptSource, EncryptInto,
    EncryptTarget, Error, NonEmpty, PlanError, StackCipherText,
};
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Zeroize)]
struct Member {
    id: u64,
    email: String,
    age: i32,
}

/// The plan's example "Store a field as an EQL type".
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Member, scope = "members")]
struct EncryptedMember {
    #[stash(passthrough)]
    id: u64,
    email: TextEq,
    age: IntegerOrd,
}

fn ada() -> Member {
    Member {
        id: 7,
        email: "ada@example.com".into(),
        age: 36,
    }
}

fn column(name: &str) -> NonEmpty<Identifier> {
    Identifier::for_column("members", name).unwrap()
}

/// A stored payload without its ciphertext: the envelope and every term.
/// `c` is sealed under a new nonce each time, so its bytes differ.
fn terms_of<T: Serialize>(stored: &T) -> serde_json::Value {
    let mut json = serde_json::to_value(stored).unwrap();
    let object = json.as_object_mut().unwrap();
    assert!(object.remove("c").is_some(), "a stored value carries `c`");
    json
}

#[tokio::test]
async fn a_record_with_eql_fields_round_trips() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let stored: EncryptedMember = ada().encrypt_into(&keyset).await.unwrap();
    assert_eq!(stored.id, 7, "the passthrough field is carried as it is");
    assert_eq!(stored.email.i, *column("email").get());
    assert_eq!(stored.age.i, *column("age").get());
    assert_eq!(
        calls.lock().unwrap().generate.len(),
        1,
        "both fields' keys in one request"
    );

    let opened = Member::decrypt_from(stored, &keyset).await.unwrap();
    assert_eq!(opened, ada());
}

#[tokio::test]
async fn an_eql_field_writes_what_the_type_writes_on_its_own() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let member = ada();
    let stored: EncryptedMember = member.clone().encrypt_into(&keyset).await.unwrap();
    let email: TextEq = member
        .email
        .clone()
        .encrypt_into_with_context(&keyset, column("email"))
        .await
        .unwrap();
    let age: IntegerOrd = member
        .age
        .encrypt_into_with_context(&keyset, column("age"))
        .await
        .unwrap();
    assert_eq!(
        terms_of(&stored.email),
        terms_of(&email),
        "the same email terms"
    );
    assert_eq!(terms_of(&stored.age), terms_of(&age), "the same age terms");

    // The record's fields open on their own, under the column.
    let opened = String::decrypt_from_with_context(stored.email, &keyset, column("email"))
        .await
        .unwrap();
    assert_eq!(opened, member.email);
    let opened = i32::decrypt_from_with_context(stored.age, &keyset, column("age"))
        .await
        .unwrap();
    assert_eq!(opened, member.age);

    // And the values written on their own open as the record's fields.
    let record = EncryptedMember {
        id: member.id,
        email,
        age,
    };
    assert_eq!(Member::decrypt_from(record, &keyset).await.unwrap(), member);
}

#[tokio::test]
async fn a_query_from_the_field_marker_gives_the_stored_term() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let stored: EncryptedMember = ada().encrypt_into(&keyset).await.unwrap();

    let query = EncryptedMember::EMAIL
        .eq("ada@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(
        query.i, stored.email.i,
        "the query names the field's column"
    );
    assert_eq!(query.hm, stored.email.hm, "and carries the stored term");

    let other = EncryptedMember::EMAIL
        .eq("bob@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_ne!(other.hm, stored.email.hm);
}

#[derive(Clone, Zeroize)]
struct Contact {
    email: String,
    name: String,
    age: i32,
    profile: JsonPlaintext,
}

fn contact() -> Contact {
    Contact {
        email: "ada@example.com".into(),
        name: "Ada".into(),
        age: 36,
        profile: profile().into(),
    }
}

/// A field of each kind: equality, storage only, order, and a JSON
/// document.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Contact, scope = "contacts")]
struct EncryptedContact {
    email: TextEq,
    name: Text,
    age: IntegerOrd,
    profile: JsonTreeDocument,
}

/// The data plan that declares the record's fields with EQL targets, as a
/// binding writes it.
fn contact_plan() -> record::Plan {
    let wire = serde_json::json!({
        "email": {"context": ["contacts", "email"], "target": "TextEq"},
        "name": {"context": ["contacts", "name"], "target": "Text"},
        "age": {"context": ["contacts", "age"], "target": "IntegerOrd"},
        "profile": {"context": ["contacts", "profile"], "target": "JsonSearch"},
    });
    record::plan_with(
        dynamic::frame::serde::to_vec(&wire)
            .unwrap()
            .as_protected_ref(),
        &EqlTargets,
    )
    .unwrap()
}

/// A contact as a binding sends it to a data plan: the JSON document as
/// its text.
#[derive(Serialize)]
struct ContactRow {
    email: String,
    name: String,
    age: i32,
    profile: String,
}

/// A contact as a data plan opens it: the JSON document as the bytes of
/// its text.
#[derive(serde::Deserialize)]
struct OpenedContact {
    email: String,
    name: String,
    age: i32,
    profile: Bytes,
}

/// The EQL value of `field`, in a row a data plan sealed.
fn eql_payload<'a>(row: &'a mut StackCipherText, field: &str) -> &'a mut Vec<u8> {
    let CipherText::Map(fields) = row else {
        panic!("a row is a map")
    };
    let Some((_, CipherText::Map(outputs))) = fields.iter_mut().find(|(name, _)| name == field)
    else {
        panic!("{field} is a map of outputs");
    };
    let Some((_, CipherText::Passthrough(payload))) =
        outputs.iter_mut().find(|(key, _)| key == "eql")
    else {
        panic!("{field}'s EQL value is a passthrough");
    };
    &mut payload.0
}

/// An EQL value in a row: its JSON text, framed as bytes.
struct Bytes(Vec<u8>);
impl Serialize for Bytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}
impl<'de> serde::Deserialize<'de> for Bytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Bytes;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("bytes")
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Bytes, E> {
                Ok(Bytes(v.to_vec()))
            }
            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Bytes, E> {
                Ok(Bytes(v))
            }
        }
        d.deserialize_bytes(V)
    }
}

fn read_eql<T: serde::de::DeserializeOwned>(row: &mut StackCipherText, field: &str) -> T {
    let bytes: Bytes = dynamic::frame::serde::from_slice(eql_payload(row, field)).unwrap();
    serde_json::from_slice(&bytes.0).unwrap()
}

fn write_eql<T: Serialize>(row: &mut StackCipherText, field: &str, value: &T) {
    let json = serde_json::to_vec(value).unwrap();
    *eql_payload(row, field) = dynamic::frame::serde::to_vec(&Bytes(json))
        .unwrap()
        .risky_unwrap();
}

#[tokio::test]
async fn the_derive_and_a_data_plan_write_the_same_row() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let plan = contact_plan();
    let derived: EncryptedContact = contact().encrypt_into(&keyset).await.unwrap();
    let source = ContactRow {
        email: "ada@example.com".into(),
        name: "Ada".into(),
        age: 36,
        profile: profile().to_string(),
    };
    let source = ValueFrame::from_bytes(
        dynamic::frame::serde::to_vec(&source)
            .unwrap()
            .as_protected_ref(),
    )
    .unwrap();
    let mut row = record::encrypt_with(&keyset, source, &plan, &EqlTargets)
        .unwrap()
        .await
        .unwrap();

    let planned_email: TextEq = read_eql(&mut row, "email");
    let planned_name: Text = read_eql(&mut row, "name");
    let planned_age: IntegerOrd = read_eql(&mut row, "age");
    let planned_profile: JsonTreeDocument = read_eql(&mut row, "profile");
    assert_eq!(terms_of(&derived.email), terms_of(&planned_email));
    assert_eq!(terms_of(&derived.name), terms_of(&planned_name));
    assert_eq!(terms_of(&derived.age), terms_of(&planned_age));
    assert_eq!(
        document_terms(&derived.profile),
        document_terms(&planned_profile)
    );

    // The data plan's values open as the record's fields.
    let record = EncryptedContact {
        email: planned_email,
        name: planned_name,
        age: planned_age,
        profile: planned_profile,
    };
    let opened = Contact::decrypt_from(record, &keyset).await.unwrap();
    assert_eq!(opened.email, "ada@example.com");
    assert_eq!(opened.name, "Ada");
    assert_eq!(opened.age, 36);
    assert_eq!(opened.profile.value(), &profile());

    // The record's values, in the data plan's row, open through the plan.
    write_eql(&mut row, "email", &derived.email);
    write_eql(&mut row, "name", &derived.name);
    write_eql(&mut row, "age", &derived.age);
    write_eql(&mut row, "profile", &derived.profile);
    let opened = record::decrypt_with(&cipher, row, &plan, None, &EqlTargets)
        .unwrap()
        .await
        .unwrap();
    let opened: OpenedContact = dynamic::frame::serde::from_slice(opened.risky_ref()).unwrap();
    assert_eq!(opened.email, "ada@example.com");
    assert_eq!(opened.name, "Ada");
    assert_eq!(opened.age, 36);
    assert_eq!(
        serde_json::from_slice::<Value>(&opened.profile.0).unwrap(),
        profile()
    );
}

#[derive(Clone, Zeroize)]
struct Tenanted {
    email: String,
}

/// A record whose caller supplies a tenant scope. An EQL payload has
/// nowhere to store the tenant.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Tenanted, scope = "members", scope(tenant: u64))]
struct EncryptedTenanted {
    email: TextEq,
}

/// A record whose caller supplies a row binding.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Tenanted, scope = "members", bind(row: u128))]
struct EncryptedBound {
    email: TextEq,
}

/// The refusal names the field by the record's scope and its name.
fn assert_not_storable<T>(result: Result<T, Error>) {
    match result {
        Err(Error::Plan(PlanError::ContextNotStorable { field })) => {
            assert_eq!(field, "members/email");
        }
        Err(other) => panic!("expected ContextNotStorable, got {other:?}"),
        Ok(_) => panic!("expected ContextNotStorable, got a value"),
    }
}

#[tokio::test]
async fn a_record_with_a_caller_scope_or_binding_cannot_store_an_eql_field() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let tenanted = || Tenanted {
        email: "ada@example.com".into(),
    };

    let scoped: Result<EncryptedTenanted, _> = tenanted()
        .encrypt_into_with_context(&keyset, Scope::new(42u64))
        .await;
    assert_not_storable(scoped);
    let bound: Result<EncryptedBound, _> = tenanted()
        .encrypt_into_with_context(&keyset, Bind::new(9u128))
        .await;
    assert_not_storable(bound);
    assert!(
        calls.lock().unwrap().generate.is_empty(),
        "refused before any key is requested"
    );

    // A value written on its own under the column does not open in such a
    // record either.
    let email: TextEq = "ada@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, column("email"))
        .await
        .unwrap();
    let record = EncryptedTenanted {
        email: email.clone(),
    };
    let opened = Tenanted::decrypt_from_with_context(record, &keyset, Scope::new(42u64)).await;
    assert_not_storable(opened);
    let record = EncryptedBound { email };
    let opened = Tenanted::decrypt_from_with_context(record, &keyset, Bind::new(9u128)).await;
    assert_not_storable(opened);
    assert!(
        calls.lock().unwrap().retrieve.is_empty(),
        "refused before any key is requested"
    );
}

/// A record with an EQL field and nothing the caller supplies.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Tenanted, scope = "members")]
struct EncryptedPlain {
    email: TextEq,
}

#[derive(Clone, Zeroize)]
struct Holder {
    member: Tenanted,
}

/// That record as a field of another. Its EQL field's context is then its
/// own pair, extended by the outer record's.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Holder, scope = "holders")]
struct EncryptedHolder {
    member: EncryptedPlain,
}

#[tokio::test]
async fn an_eql_field_of_a_nested_record_is_refused() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let holder = Holder {
        member: Tenanted {
            email: "ada@example.com".into(),
        },
    };
    let nested: Result<EncryptedHolder, _> = holder.encrypt_into(&keyset).await;
    assert_not_storable(nested);
    assert!(
        calls.lock().unwrap().generate.is_empty(),
        "refused before any key is requested"
    );
}

#[tokio::test]
async fn a_field_that_stores_another_column_is_refused() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let mut stored: EncryptedMember = ada().encrypt_into(&keyset).await.unwrap();
    stored.email = "ada@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, column("other"))
        .await
        .unwrap();

    match Member::decrypt_from(stored, &keyset).await {
        Err(Error::ContextMismatch { .. }) => {}
        Err(other) => panic!("expected ContextMismatch, got {other:?}"),
        Ok(_) => panic!("expected ContextMismatch, got a value"),
    }
    assert!(
        calls.lock().unwrap().retrieve.is_empty(),
        "refused before any key is requested"
    );
}

fn profile() -> Value {
    json!({"name": "Ada", "age": 36, "tags": ["maths", "engines"]})
}

/// What each stored entry shows a query, as a sorted list: its selector,
/// its ordering term and whether it carries a parent tag. Entries are
/// stored in a random order, so two seals of one document compare as
/// multisets.
fn search_terms(document: &JsonTreeDocument) -> Vec<(String, String, bool)> {
    let mut terms: Vec<_> = document
        .sv
        .iter()
        .map(|entry| {
            (
                serde_json::to_string(&entry.s).unwrap(),
                serde_json::to_string(&entry.op).unwrap(),
                entry.p.is_some(),
            )
        })
        .collect();
    terms.sort();
    terms
}

/// A stored document without what differs between two seals of it: the
/// key header `h`, sealed under a new key each time, and the entries' own
/// ciphertexts. The search terms of every entry and the query group are
/// kept, sorted, since both are stored in a random order.
fn document_terms(document: &JsonTreeDocument) -> (Value, Vec<(String, String, bool)>) {
    let mut json = serde_json::to_value(document).unwrap();
    let object = json.as_object_mut().unwrap();
    assert!(object.remove("h").is_some(), "a document carries `h`");
    assert!(object.remove("sv").is_some(), "a document carries `sv`");
    let group = object["q"].as_object_mut().unwrap();
    for list in group.values_mut() {
        list.as_array_mut()
            .unwrap()
            .sort_by_key(|entry| entry.to_string());
    }
    (json, search_terms(document))
}

#[tokio::test]
async fn a_json_document_encrypts_from_a_json_plaintext() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let column = || Identifier::for_column("customers", "profile").unwrap();

    let stored: JsonTreeDocument = JsonPlaintext::from(profile())
        .encrypt_into_with_context(&keyset, column())
        .await
        .unwrap();
    let old: JsonTreeDocument = keyset
        .run(JsonTree::default().encryption(), &profile(), column())
        .await
        .unwrap();
    assert_eq!(
        document_terms(&stored),
        document_terms(&old),
        "the same envelope and search terms"
    );

    // Each path opens what the other sealed.
    let opened = JsonPlaintext::decrypt_from_with_context(old, &keyset, column())
        .await
        .unwrap();
    assert_eq!(opened.value(), &profile());
    let opened: Value = cipher
        .decrypt_as(stored.clone(), column().into())
        .await
        .unwrap();
    assert_eq!(opened, profile());

    // Without a column, the document opens under the one it stores.
    let opened = JsonPlaintext::decrypt_from(stored.clone(), &keyset)
        .await
        .unwrap();
    assert_eq!(opened.value(), &profile());

    // Under another column, it is refused before any key is requested.
    let before = calls.lock().unwrap().retrieve.len();
    let other = Identifier::for_column("customers", "bio").unwrap();
    match JsonPlaintext::decrypt_from_with_context(stored, &keyset, other).await {
        Err(Error::ContextMismatch { .. }) => {}
        Err(other) => panic!("expected ContextMismatch, got {other:?}"),
        Ok(_) => panic!("expected ContextMismatch, got a value"),
    }
    assert_eq!(calls.lock().unwrap().retrieve.len(), before);
}

#[derive(Clone, Zeroize)]
struct Customer {
    id: u64,
    profile: JsonPlaintext,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Customer, scope = "customers")]
struct EncryptedCustomer {
    #[stash(passthrough)]
    id: u64,
    profile: JsonTreeDocument,
}

#[tokio::test]
async fn a_json_document_is_a_record_field() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let customer = Customer {
        id: 3,
        profile: profile().into(),
    };
    let stored: EncryptedCustomer = customer.encrypt_into(&keyset).await.unwrap();
    assert_eq!(
        stored.profile.i,
        Identifier {
            t: "customers".into(),
            c: "profile".into()
        },
        "the field's column is the record's scope and the field's name"
    );
    let old: JsonTreeDocument = keyset
        .run(
            JsonTree::default().encryption(),
            &profile(),
            Identifier::for_column("customers", "profile").unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(document_terms(&stored.profile), document_terms(&old));

    let opened = Customer::decrypt_from(stored, &keyset).await.unwrap();
    assert_eq!(opened.id, 3);
    assert_eq!(opened.profile.value(), &profile());
}
