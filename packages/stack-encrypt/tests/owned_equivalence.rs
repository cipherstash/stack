//! One record, sealed three ways, by one engine. A hand-written
//! `EncryptTarget` (typed), `#[derive(EncryptTarget, DecryptSource)]`
//! (generated), and the data-plan lowering that a binding sends (dynamic) each
//! seal the same mixed, searchable record. All three use the same in-memory
//! provider. The tests check three things:
//!
//! - The descriptors sent to the key provider are the same.
//! - The equality terms are the same, byte for byte.
//! - Each way decrypts what the others sealed, so the associated data is the
//!   same too.
//!
//! Ciphertext bytes are random, so the tests do not compare them.
#![cfg(feature = "dynamic")]

mod common;

use common::frames::{frame, object, payload};
use serde::Deserialize;
use stack_encrypt::dynamic::record::{self, Plan as DataPlan};
use stack_encrypt::dynamic::{Scope, ValueFrame};
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{
    passthrough, Borrowed, ContextExtension, DeclaredContext, DecryptSource, Decryption,
    EncryptTarget, Encryption,
};
use stack_encrypt::{
    nonempty, AsProtectedRef, CipherText, Ciphertext, DecryptFrom, EncryptInto, PassthroughFrame,
    SealedValue, StackCipher, StackCipherText,
};
use vitaminc_aead_frame::serde::from_slice;
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Zeroize)]
struct User {
    id: u32,
    name: String,
    email: String,
}
fn alice() -> User {
    User {
        id: 42,
        name: "Alice".to_owned(),
        email: "alice@example.com".to_owned(),
    }
}

// --- Typed: the operations composed by hand -------------------------------

struct TypedUser {
    id: u32,
    name: Ciphertext,
    email: Ciphertext,
    email_eq: EqualityTerm,
}
impl EncryptTarget<User> for TypedUser {
    type ContextInput = ContextExtension<DeclaredContext>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, User, Self, K, Self::ContextInput> {
        passthrough::<u32, K, Borrowed, DeclaredContext>()
            .project(|user: &User| &user.id)
            .zip(
                <Ciphertext as EncryptTarget<String>>::encryption::<K>()
                    .project(|user: &User| &user.name)
                    .under(nonempty!("users").with("name")),
            )
            .zip(
                <Ciphertext as EncryptTarget<String>>::encryption::<K>()
                    .project(|user: &User| &user.email)
                    .under(nonempty!("users").with("email")),
            )
            .zip(
                <EqualityTerm as EncryptTarget<String>>::encryption::<K>()
                    .project(|user: &User| &user.email)
                    .under(nonempty!("users").with("email")),
            )
            .map(|(((id, name), email), email_eq)| Self {
                id,
                name,
                email,
                email_eq,
            })
            .accepting()
    }
}
impl DecryptSource<User> for TypedUser {
    type ContextInput = ContextExtension<DeclaredContext>;
    fn decryption<K: 'static>(self, context: Self::ContextInput) -> Decryption<User, K> {
        let extension: DeclaredContext = context.into();
        let name = <Ciphertext as DecryptSource<String>>::decryption::<K>(
            self.name,
            extension
                .clone()
                .under(nonempty!("users").with("name"))
                .into(),
        );
        let email = <Ciphertext as DecryptSource<String>>::decryption::<K>(
            self.email,
            extension.under(nonempty!("users").with("email")).into(),
        );
        let id = self.id;
        name.zip(email)
            .map(move |(name, email)| User { id, name, email })
    }
}

// --- Generated: the same declaration, derived -----------------------------

#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct SearchableEmail {
    ciphertext: Ciphertext,
    equality: EqualityTerm,
}
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, context = "users")]
struct GeneratedUser {
    #[stash(passthrough)]
    id: u32,
    name: Ciphertext,
    email: SearchableEmail,
}

// --- Dynamic: the declaration as a binding sends it -----------------------

fn data_plan() -> DataPlan {
    let json = serde_json::json!({
        "id":    { "context": ["users", "id"],    "outputs": ["passthrough"], "type": "uint32" },
        "name":  { "context": ["users", "name"],  "outputs": ["c"],           "type": "string" },
        "email": { "context": ["users", "email"], "outputs": ["c", "eq"],     "type": "string" },
    });
    let declaration = vitaminc_aead_frame::serde::to_vec(&json).expect("frames");
    record::plan(declaration.as_protected_ref()).expect("a plan")
}
fn dynamic_source(user: &User) -> ValueFrame {
    object(vec![
        ("id", frame(user.id)),
        ("name", frame(user.name.as_str())),
        ("email", frame(user.email.as_str())),
    ])
}

/// The three outputs, in one shape: the stored tree that the dynamic path
/// writes and reads. So one comparison and one decryption serve all three.
struct Stored {
    id: u32,
    name: SealedValue,
    email: SealedValue,
    email_eq: Vec<u8>,
}
impl Stored {
    fn of_typed(typed: TypedUser) -> Self {
        Self {
            id: typed.id,
            name: leaf(typed.name),
            email: leaf(typed.email),
            email_eq: typed.email_eq.into_bytes().to_vec(),
        }
    }
    fn of_generated(generated: GeneratedUser) -> Self {
        Self {
            id: generated.id,
            name: leaf(generated.name),
            email: leaf(generated.email.ciphertext),
            email_eq: generated.email.equality.into_bytes().to_vec(),
        }
    }
    fn of_tree(tree: StackCipherText) -> Self {
        let CipherText::Map(fields) = tree else {
            panic!("a record is a map of fields");
        };
        let (mut id, mut name, mut email, mut email_eq) = (None, None, None, None);
        for (field, node) in fields {
            let CipherText::Map(outputs) = node else {
                panic!("a field is a map of outputs");
            };
            for (key, node) in outputs {
                match (field.as_str(), key.as_str(), node) {
                    ("id", "passthrough", CipherText::Passthrough(payload)) => {
                        id = Some(from_slice::<u32>(&payload.0).expect("a u32"));
                    }
                    ("name", "c", CipherText::Single(leaf)) => name = Some(leaf),
                    ("email", "c", CipherText::Single(leaf)) => email = Some(leaf),
                    ("email", "eq", CipherText::Passthrough(payload)) => {
                        email_eq = Some(from_slice::<&[u8]>(&payload.0).expect("bytes").to_vec());
                    }
                    (field, key, _) => panic!("unexpected output {field}/{key}"),
                }
            }
        }
        Self {
            id: id.expect("id"),
            name: name.expect("name"),
            email: email.expect("email"),
            email_eq: email_eq.expect("email/eq"),
        }
    }
    fn tree(&self) -> StackCipherText {
        let passthrough =
            |value: &dyn Fn() -> Vec<u8>| CipherText::Passthrough(PassthroughFrame(value()));
        CipherText::Map(vec![
            (
                "id".into(),
                CipherText::Map(vec![(
                    "passthrough".into(),
                    passthrough(&|| payload(self.id)),
                )]),
            ),
            (
                "name".into(),
                CipherText::Map(vec![("c".into(), CipherText::Single(self.name.clone()))]),
            ),
            (
                "email".into(),
                CipherText::Map(vec![
                    ("c".into(), CipherText::Single(self.email.clone())),
                    (
                        "eq".into(),
                        passthrough(&|| payload(self.email_eq.as_slice())),
                    ),
                ]),
            ),
        ])
    }
    fn typed(&self) -> TypedUser {
        TypedUser {
            id: self.id,
            name: ciphertext(&self.name),
            email: ciphertext(&self.email),
            email_eq: EqualityTerm::from_bytes(self.email_eq.as_slice().try_into().expect("32")),
        }
    }
    fn generated(&self) -> GeneratedUser {
        GeneratedUser {
            id: self.id,
            name: ciphertext(&self.name),
            email: SearchableEmail {
                ciphertext: ciphertext(&self.email),
                equality: EqualityTerm::from_bytes(
                    self.email_eq.as_slice().try_into().expect("32"),
                ),
            },
        }
    }
}
fn leaf(ciphertext: Ciphertext) -> SealedValue {
    SealedValue::from_bytes(&ciphertext.to_bytes()).expect("a leaf")
}
fn ciphertext(leaf: &SealedValue) -> Ciphertext {
    Ciphertext::from_bytes(&leaf.to_bytes()).expect("a ciphertext")
}

#[derive(Deserialize, PartialEq, Debug)]
struct Opened {
    id: u32,
    name: String,
    email: String,
}
async fn open_dynamic(cipher: &StackCipher<common::RecordingSource>, stored: &Stored) -> User {
    let opened = record::decrypt(Scope::Client(cipher), stored.tree(), &data_plan(), None)
        .expect("the record fits the plan")
        .await
        .expect("the lowering opens it");
    let opened: Opened = from_slice(opened.risky_ref()).expect("an object of the three fields");
    User {
        id: opened.id,
        name: opened.name,
        email: opened.email,
    }
}

#[tokio::test]
async fn typed_generated_and_dynamic_declarations_are_one_engine() {
    let user = alice();
    let (cipher, sent) = common::recording_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = data_plan();

    // Each way seals the record. The passthrough field requests no key. The
    // two sealed fields request one key each, under the field's context. The
    // equality term is derived locally.
    let typed: TypedUser = user.clone().encrypt_into(&keyset).await.unwrap();
    let generated: GeneratedUser = user.clone().encrypt_into(&keyset).await.unwrap();
    let dynamic = record::encrypt(&keyset, dynamic_source(&user), &plan)
        .expect("the source fits the plan")
        .await
        .unwrap();
    // Within a call, the fields are in the declaration's order. The data plan
    // uses the key order of the frame instead. So the test compares each call
    // as a set.
    let sorted = |call: &Vec<String>| {
        let mut call = call.clone();
        call.sort();
        call
    };
    let generated_descriptors: Vec<_> = sent.lock().unwrap().generate.iter().map(sorted).collect();
    assert_eq!(
        generated_descriptors,
        vec![
            vec!["users/email", "users/name"],
            vec!["users/email", "users/name"],
            vec!["users/email", "users/name"],
        ],
        "one batched request per author, the same descriptors"
    );

    let typed = Stored::of_typed(typed);
    let generated = Stored::of_generated(generated);
    let dynamic = Stored::of_tree(dynamic);
    // The terms are the same bytes. So a query term built any of the three
    // ways finds the rows that each way stored.
    assert_eq!(typed.email_eq, generated.email_eq);
    assert_eq!(generated.email_eq, dynamic.email_eq);
    assert_eq!(typed.id, 42);
    assert_eq!(generated.id, 42);
    assert_eq!(dynamic.id, 42);

    // Each way decrypts the records of every way: the same context gives the
    // same associated data.
    for stored in [&typed, &generated, &dynamic] {
        assert_eq!(
            User::decrypt_from(stored.typed(), &cipher).await.unwrap(),
            user
        );
        assert_eq!(
            User::decrypt_from(stored.generated(), &cipher)
                .await
                .unwrap(),
            user
        );
        assert_eq!(open_dynamic(&cipher, stored).await, user);
    }
    // Every decryption also retrieved its keys under the same descriptors.
    let retrieved: Vec<_> = sent.lock().unwrap().retrieve.iter().map(sorted).collect();
    assert_eq!(retrieved.len(), 9);
    assert!(retrieved
        .iter()
        .all(|call| call == &["users/email", "users/name"]));
}
