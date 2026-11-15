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
//! - a scope or a binding that the record lists, supplied by the caller or
//!   stored in the row, comes after the column in the field's context. The
//!   terms derive under the column and the scope. The ciphertext is sealed
//!   under the binding too. `i` stores neither. The reader supplies both
//!   again, and a query supplies the scope;
//! - under a scope and a binding, the derive and a data plan still write
//!   the same terms, and each opens the other's values;
//! - an EQL field of a record nested in another stores its own column too;
//! - a field that stores another column is refused before any key is
//!   requested;
//! - a renamed field keeps its column with `identity`, and reads the rows
//!   written under its old name. With no `identity` they are refused;
//! - a JSON document, `JsonTreeDocument`, encrypts from a `JsonPlaintext`
//!   through the new API, writes the search terms the old path writes, and
//!   is a record field too.

mod common;

use eql_bindings::encryption::{EqlTargets, NativeCiphertextVisitor as NativeLeaf};
use eql_bindings::v4::integer::IntegerOrd;
use eql_bindings::v4::json_tree::{JsonTree, JsonTreeDocument};
use eql_bindings::v4::text::{Text, TextEq, TextEqQuery};
use eql_bindings::Identifier;
use serde::Serialize;
use serde_json::{json, Value};
use stack_encrypt::dynamic::{self, record, Op, Operand, Planned, QueryTerm, ValueFrame};
use stack_encrypt::json::JsonPlaintext;
use stack_encrypt::target::transcode::Reader as _;
use stack_encrypt::target::{AeadContext, Bind, Layout, Parts, Scope};
use stack_encrypt::testing::{bind, scope, Expect};
use stack_encrypt::{
    assert_context, nonempty, AsProtectedRef as _, CipherText, Controlled as _, DecryptFrom,
    DecryptSource, EncryptInto, EncryptTarget, Error, NonEmpty, StackCipherText,
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

#[derive(Clone, Debug, PartialEq, Zeroize)]
struct Tenanted {
    email: String,
}

fn tenanted() -> Tenanted {
    Tenanted {
        email: "ada@example.com".into(),
    }
}

/// A record whose caller supplies a tenant scope and a row binding. An EQL
/// field stores its column in `i`, and neither the tenant nor the row.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Tenanted, scope = "members", scope(tenant: u64), bind(row: u128))]
struct EncryptedTenanted {
    email: TextEq,
}

/// The tenant and the row the tests seal under.
fn tenant_and_row() -> Parts<Scope<u64>, Bind<u128>> {
    Scope::new(42u64).bind(9u128)
}

/// The record shows the contexts of an EQL field's ciphertext and term
/// before any key is requested: the column, the tenant, then the row.
#[test]
fn a_record_shows_the_scope_and_the_binding_of_an_eql_field() {
    assert_context!(
        EncryptedTenanted::contexts(),
        "email.c" = {
            query = [["members", "email"], scope::<u64>("tenant")],
            stored = [
                [
                    Expect::from(["members", "email"]),
                    Expect::from(scope::<u64>("tenant")),
                ],
                bind::<u128>("row"),
            ],
        },
        "email.hm" = {
            query = [["members", "email"], scope::<u64>("tenant")],
            stored = [
                [
                    Expect::from(["members", "email"]),
                    Expect::from(scope::<u64>("tenant")),
                ],
                bind::<u128>("row"),
            ],
        },
    );
}

#[tokio::test]
async fn an_eql_field_stores_its_column_and_not_the_scope_or_the_binding() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let stored: EncryptedTenanted = tenanted()
        .encrypt_into_with_context(&keyset, tenant_and_row())
        .await
        .unwrap();
    assert_eq!(
        stored.email.i,
        *column("email").get(),
        "`i` holds the declared names alone"
    );

    // The ciphertext is sealed under the column, then the tenant, then the
    // row: it opens as a Stack Encrypt leaf under exactly that context.
    let leaf = stored.email.c.clone().read(NativeLeaf).unwrap();
    let context = AeadContext::from(tenant_and_row()).extend(nonempty!("members").with("email"));
    let opened: String = cipher.decrypt_as(leaf, context).await.unwrap();
    assert_eq!(opened, "ada@example.com");

    // The term is derived under the column, then the tenant. A query from
    // the field's marker under the same tenant gives the stored term, and
    // names the column alone.
    let query = EncryptedTenanted::EMAIL
        .eq("ada@example.com")
        .scope(Scope::new(42u64))
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(query.i, stored.email.i);
    assert_eq!(query.hm, stored.email.hm);
    let other_tenant = EncryptedTenanted::EMAIL
        .eq("ada@example.com")
        .scope(Scope::new(43u64))
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_ne!(other_tenant.hm, stored.email.hm);

    // So it is not the term of the column alone.
    let alone: TextEq = "ada@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, column("email"))
        .await
        .unwrap();
    assert_ne!(alone.hm, stored.email.hm);

    // A binding is in no query context: another row has the same term.
    let other_row: EncryptedTenanted = tenanted()
        .encrypt_into_with_context(&keyset, Scope::new(42u64).bind(10u128))
        .await
        .unwrap();
    assert_eq!(other_row.email.hm, stored.email.hm);

    // The reader supplies the tenant and the row again.
    let opened = Tenanted::decrypt_from_with_context(stored, &keyset, tenant_and_row())
        .await
        .unwrap();
    assert_eq!(opened, tenanted());
}

#[tokio::test]
async fn an_eql_field_opens_only_under_the_scope_and_the_binding_it_was_sealed_under() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let stored: EncryptedTenanted = tenanted()
        .encrypt_into_with_context(&keyset, tenant_and_row())
        .await
        .unwrap();
    let again = || EncryptedTenanted {
        email: stored.email.clone(),
    };

    let other_tenant =
        Tenanted::decrypt_from_with_context(again(), &keyset, Scope::new(43u64).bind(9u128));
    assert!(other_tenant.await.is_err(), "another tenant");
    let other_row =
        Tenanted::decrypt_from_with_context(again(), &keyset, Scope::new(42u64).bind(10u128));
    assert!(other_row.await.is_err(), "another row");

    // On its own, the field's value stores the same column. It was sealed
    // under the tenant and the row too, so the column alone does not open
    // it.
    let alone =
        String::decrypt_from_with_context(stored.email.clone(), &keyset, column("email")).await;
    assert!(alone.is_err(), "the column alone");

    // And a value sealed under the column alone does not open as the
    // record's field.
    let email: TextEq = "ada@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, column("email"))
        .await
        .unwrap();
    let record = EncryptedTenanted { email };
    let opened = Tenanted::decrypt_from_with_context(record, &keyset, tenant_and_row()).await;
    assert!(opened.is_err(), "sealed without the tenant and the row");

    // The stored column is checked first, before any key is requested.
    let email: TextEq = "ada@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, column("other"))
        .await
        .unwrap();
    let record = EncryptedTenanted { email };
    let before = calls.lock().unwrap().retrieve.len();
    match Tenanted::decrypt_from_with_context(record, &keyset, tenant_and_row()).await {
        Err(Error::ContextMismatch { .. }) => {}
        Err(other) => panic!("expected ContextMismatch, got {other:?}"),
        Ok(_) => panic!("expected ContextMismatch, got a value"),
    }
    assert_eq!(calls.lock().unwrap().retrieve.len(), before);
}

#[derive(Clone, Zeroize)]
struct Lead {
    email: String,
    profile: JsonPlaintext,
}

/// A record with a scalar field and a document field, under a tenant scope
/// and a row binding that the caller supplies.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Lead, scope = "leads", scope(tenant: u64), bind(row: u128))]
struct EncryptedLead {
    email: TextEq,
    profile: JsonTreeDocument,
}

/// The data plan that declares the same two fields with EQL targets. It
/// lists no scope and no binding: the call supplies them, as it does for
/// the record.
fn lead_plan() -> record::Plan {
    let wire = serde_json::json!({
        "email": {"context": ["leads", "email"], "target": "TextEq"},
        "profile": {"context": ["leads", "profile"], "target": "JsonSearch"},
    });
    record::plan_with(
        dynamic::frame::serde::to_vec(&wire)
            .unwrap()
            .as_protected_ref(),
        &EqlTargets,
    )
    .unwrap()
}

/// A lead as a binding sends it to a data plan.
fn lead_row() -> ValueFrame {
    #[derive(Serialize)]
    struct Row {
        email: String,
        profile: String,
    }
    let row = Row {
        email: "ada@example.com".into(),
        profile: profile().to_string(),
    };
    ValueFrame::from_bytes(
        dynamic::frame::serde::to_vec(&row)
            .unwrap()
            .as_protected_ref(),
    )
    .unwrap()
}

/// A scope and a binding reach an EQL type through a data plan as they
/// reach it through the derive. So the two paths write the same terms
/// under the same tenant and row, each stores the column alone, and each
/// opens what the other sealed. A data plan is the path Go takes.
#[tokio::test]
async fn the_derive_and_a_data_plan_write_the_same_row_under_a_scope_and_a_binding() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let plan = lead_plan();
    let derived: EncryptedLead = Lead {
        email: "ada@example.com".into(),
        profile: profile().into(),
    }
    .encrypt_into_with_context(&keyset, tenant_and_row())
    .await
    .unwrap();
    let seal = || async {
        let row: StackCipherText = Planned::with_resolver(&plan, lead_row(), EqlTargets)
            .encrypt_into_with_context(&keyset, tenant_and_row())
            .await
            .unwrap();
        row
    };

    let mut row = seal().await;
    let planned_email: TextEq = read_eql(&mut row, "email");
    let planned_profile: JsonTreeDocument = read_eql(&mut row, "profile");
    let leads = |name: &str| Identifier::for_column("leads", name).unwrap().into_inner();
    assert_eq!(planned_email.i, leads("email"), "the column alone");
    assert_eq!(planned_profile.i, leads("profile"), "the column alone");
    assert_eq!(terms_of(&planned_email), terms_of(&derived.email));
    assert_eq!(
        document_terms(&planned_profile),
        document_terms(&derived.profile)
    );
    // The terms are the tenant's, and not the column's alone.
    let alone: TextEq = "ada@example.com"
        .to_owned()
        .encrypt_into_with_context(&keyset, Identifier::for_column("leads", "email").unwrap())
        .await
        .unwrap();
    assert_ne!(alone.hm, planned_email.hm);

    // The data plan's values open as the record's fields.
    let record = EncryptedLead {
        email: planned_email,
        profile: planned_profile,
    };
    let opened = Lead::decrypt_from_with_context(record, &keyset, tenant_and_row())
        .await
        .unwrap();
    assert_eq!(opened.email, "ada@example.com");
    assert_eq!(opened.profile.value(), &profile());

    // The record's values, in the data plan's row, open through the plan.
    write_eql(&mut row, "email", &derived.email);
    write_eql(&mut row, "profile", &derived.profile);
    let opened = ValueFrame::decrypt_from_with_context(
        Planned::with_resolver(&plan, row, EqlTargets),
        &keyset,
        tenant_and_row(),
    )
    .await
    .unwrap();
    #[derive(serde::Deserialize)]
    struct Opened {
        email: String,
        profile: Bytes,
    }
    let opened: Opened = dynamic::frame::serde::from_slice(opened.risky_ref()).unwrap();
    assert_eq!(opened.email, "ada@example.com");
    assert_eq!(
        serde_json::from_slice::<Value>(&opened.profile.0).unwrap(),
        profile()
    );

    // The plan opens its row only under the same tenant and row.
    for parts in [
        Scope::new(43u64).bind(9u128),
        Scope::new(42u64).bind(10u128),
    ] {
        let refused = ValueFrame::decrypt_from_with_context(
            Planned::with_resolver(&plan, seal().await, EqlTargets),
            &keyset,
            parts,
        )
        .await;
        assert!(refused.is_err());
    }
    let refused = ValueFrame::decrypt_from(
        Planned::with_resolver(&plan, seal().await, EqlTargets),
        &keyset,
    )
    .await;
    assert!(refused.is_err(), "with no tenant and no row");

    // A query through the plan, under the tenant, is the stored term. It
    // names the column alone.
    let by_email = plan.query_with("email", Op::Eq, &EqlTargets).unwrap();
    let term = |tenant: u64| {
        let (by_email, keyset) = (&by_email, &keyset);
        async move {
            let value = ValueFrame::of("ada@example.com").unwrap();
            let term: QueryTerm = Planned::with_resolver(by_email, value, EqlTargets)
                .encrypt_into_with_context(keyset, Scope::new(tenant))
                .await
                .unwrap();
            let Operand::One(json) = term.operand() else {
                panic!("an equality query has one operand");
            };
            serde_json::from_slice::<TextEqQuery>(json).unwrap()
        }
    };
    let query = term(42).await;
    assert_eq!(query.i, derived.email.i);
    assert_eq!(query.hm, derived.email.hm);
    assert_ne!(term(43).await.hm, derived.email.hm);
}

#[derive(Clone, Zeroize)]
struct Note {
    id: u128,
    tenant: u64,
    title: String,
    body: JsonPlaintext,
}

/// A record that stores its scope and its binding in the row, in fields of
/// its own. Its EQL fields still store their columns alone.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Note, scope = "notes", scope(field = "tenant"), bind(field = "id"))]
struct EncryptedNote {
    #[stash(passthrough)]
    id: u128,
    #[stash(passthrough)]
    tenant: u64,
    title: TextEq,
    body: JsonTreeDocument,
}

#[tokio::test]
async fn an_eql_field_of_a_record_that_stores_its_scope_and_binding() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let note = Note {
        id: 9,
        tenant: 42,
        title: "Renewal".into(),
        body: profile().into(),
    };
    let stored: EncryptedNote = note.encrypt_into(&keyset).await.unwrap();
    let notes = |name: &str| Identifier::for_column("notes", name).unwrap().into_inner();
    assert_eq!(stored.title.i, notes("title"));
    assert_eq!(stored.body.i, notes("body"));

    // A query supplies the tenant, since it cannot read a row.
    let query = EncryptedNote::TITLE
        .eq("Renewal")
        .scope(Scope::new(42u64))
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(query.i, stored.title.i);
    assert_eq!(query.hm, stored.title.hm);

    // The fields of this row do not open in another row.
    let moved = EncryptedNote {
        id: 10,
        tenant: stored.tenant,
        title: stored.title.clone(),
        body: stored.body.clone(),
    };
    assert!(Note::decrypt_from(moved, &keyset).await.is_err());

    // The row supplies its tenant and its ID, so the reader passes none.
    let opened = Note::decrypt_from(stored, &keyset).await.unwrap();
    assert_eq!(opened.id, 9);
    assert_eq!(opened.tenant, 42);
    assert_eq!(opened.title, "Renewal");
    assert_eq!(opened.body.value(), &profile());
}

/// A record with an EQL field and nothing the caller supplies.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Tenanted, scope = "members")]
struct EncryptedPlain {
    email: TextEq,
}

#[derive(Clone, Debug, PartialEq, Zeroize)]
struct Holder {
    member: Tenanted,
}

/// That record as a field of another. Its EQL field's context is then its
/// own pair, followed by the outer field's pair.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Holder, scope = "holders")]
struct EncryptedHolder {
    member: EncryptedPlain,
}

#[tokio::test]
async fn an_eql_field_of_a_nested_record_stores_its_own_column() {
    let (cipher, _) = common::cipher().await;
    let keyset = cipher.default_keyset();
    let holder = Holder { member: tenanted() };
    let stored: EncryptedHolder = holder.clone().encrypt_into(&keyset).await.unwrap();

    // The inner record's scope and the field's name. The outer record's
    // names come after them in the context, and are not stored.
    assert_eq!(stored.member.email.i, *column("email").get());

    // A query from the nested field's marker gives the stored term.
    let query = EncryptedHolder::MEMBER
        .field(EncryptedPlain::EMAIL)
        .eq("ada@example.com")
        .encrypt(&keyset)
        .await
        .unwrap();
    assert_eq!(query.i, stored.member.email.i);
    assert_eq!(query.hm, stored.member.email.hm);

    // The inner record on its own writes another term: its field has no
    // outer names in its context.
    let plain: EncryptedPlain = tenanted().encrypt_into(&keyset).await.unwrap();
    assert_eq!(plain.email.i, stored.member.email.i);
    assert_ne!(plain.email.hm, stored.member.email.hm);

    assert_eq!(Holder::decrypt_from(stored, &keyset).await.unwrap(), holder);
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

/// `Member`, after its `email` field was renamed to `email_address`.
#[derive(Clone, Debug, PartialEq, Zeroize)]
struct RenamedMember {
    id: u64,
    email_address: String,
    age: i32,
}

/// The renamed field keeps its old name as its column, with `identity`.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = RenamedMember, scope = "members")]
struct EncryptedRenamedMember {
    #[stash(passthrough)]
    id: u64,
    #[stash(identity = "email")]
    email_address: TextEq,
    age: IntegerOrd,
}

/// The renamed field with no `identity`: its column is its new name.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = RenamedMember, scope = "members")]
struct EncryptedUnpinnedMember {
    #[stash(passthrough)]
    id: u64,
    email_address: TextEq,
    age: IntegerOrd,
}

/// A field's name is part of its context, so a renamed field does not open
/// the rows written under its old name. `identity` keeps the old name: the
/// field then stores, and expects, the column the rows already hold.
#[tokio::test]
async fn a_renamed_eql_field_keeps_its_column_with_identity() {
    let (cipher, calls) = common::cipher().await;
    let keyset = cipher.default_keyset();
    // A row written before the rename.
    let before: EncryptedMember = ada().encrypt_into(&keyset).await.unwrap();
    assert_eq!(before.email.i, *column("email").get());

    // The renamed record reads it, with the old name kept.
    let row = EncryptedRenamedMember {
        id: before.id,
        email_address: before.email.clone(),
        age: before.age.clone(),
    };
    let opened = RenamedMember::decrypt_from(row, &keyset).await.unwrap();
    assert_eq!(opened.email_address, "ada@example.com");

    // It writes the column and the terms the record wrote before.
    let after: EncryptedRenamedMember = opened.encrypt_into(&keyset).await.unwrap();
    assert_eq!(after.email_address.i, *column("email").get());
    assert_eq!(terms_of(&after.email_address), terms_of(&before.email));

    // With no `identity`, the field's column is `email_address`. The row
    // stores `email`, so it is refused before any key is requested.
    let retrieved = calls.lock().unwrap().retrieve.len();
    let row = EncryptedUnpinnedMember {
        id: before.id,
        email_address: before.email,
        age: before.age,
    };
    match RenamedMember::decrypt_from(row, &keyset).await {
        Err(Error::ContextMismatch { .. }) => {}
        Err(other) => panic!("expected ContextMismatch, got {other:?}"),
        Ok(_) => panic!("expected ContextMismatch, got a value"),
    }
    assert_eq!(
        calls.lock().unwrap().retrieve.len(),
        retrieved,
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
