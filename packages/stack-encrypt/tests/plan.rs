//! The plan builder (`stack_encrypt::plan`): the chain lowers to the
//! combinators and produces the same bytes they do, a saved plan is the same
//! chain run later, queries derive under the write's labels, and every way a
//! plan can be refused is refused before any key is requested.
mod common;

use std::sync::atomic::Ordering;

use common::{counting_cipher, loads_counting_cipher, recording_cipher, stack_cipher};
use stack_encrypt::kms::{FakeDataKeySource, IdentifiedBy};
use stack_encrypt::plan::{
    Field, FieldKind, FieldSchema, FieldValues, Fields, Operation, PlanError,
};
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OreTerm};
use stack_encrypt::target::{
    self, indexed, passthrough, Borrowed, DeclaredContext, Encrypted, Encryption, IndexSpec,
};
use stack_encrypt::{
    nonempty, CipherText, Equality, Error, Label, Match, NonEmpty, Ope, Ore, Plan, StackCipher,
    StackCipherText,
};

/// The record every test encrypts: two indexed fields, one sealed alone,
/// one carried through.
#[derive(Clone, Debug, PartialEq)]
struct User {
    email: String,
    age: u32,
    notes: String,
    id: u64,
}

fn user() -> User {
    User {
        email: "bob@example.com".into(),
        age: 34,
        notes: "likes cheese".into(),
        id: 42,
    }
}

impl Fields for User {
    fn field_names(&self) -> Vec<&str> {
        vec!["email", "age", "notes", "id"]
    }
    fn schema() -> Option<Vec<FieldSchema>> {
        Some(vec![
            FieldSchema::of::<String>("email"),
            FieldSchema::of::<u32>("age"),
            FieldSchema::of::<String>("notes"),
            FieldSchema::of::<u64>("id"),
        ])
    }
}
impl Field<String> for User {
    fn field(&self, name: &str) -> Option<&String> {
        match name {
            "email" => Some(&self.email),
            "notes" => Some(&self.notes),
            _ => None,
        }
    }
}
impl Field<u32> for User {
    fn field(&self, name: &str) -> Option<&u32> {
        (name == "age").then_some(&self.age)
    }
}
impl Field<u64> for User {
    fn field(&self, name: &str) -> Option<&u64> {
        (name == "id").then_some(&self.id)
    }
}

/// The same record shape with no schema, and whose field names can be
/// set: a value whose fields only it knows, as a binding's is.
struct Loose {
    names: Vec<&'static str>,
    email: String,
    age: u32,
}
impl Fields for Loose {
    fn field_names(&self) -> Vec<&str> {
        self.names.clone()
    }
}
impl Field<String> for Loose {
    fn field(&self, name: &str) -> Option<&String> {
        (name == "email").then_some(&self.email)
    }
}
impl Field<u32> for Loose {
    fn field(&self, name: &str) -> Option<&u32> {
        (name == "age").then_some(&self.age)
    }
}

type EmailTerms = (EqualityTerm, MatchTerms);
type AgeTerms = (EqualityTerm, OreTerm<u32>);

fn users_plan<K: 'static>() -> Plan<User, K> {
    Plan::context("users")
        .fields()
        .encrypt_index::<String>("email", (Equality, Match::default()))
        .encrypt_index::<u32>("age", (Equality, Ore))
        .encrypt::<String>("notes")
        .passthrough::<u64>("id")
        .build()
        .expect("a valid plan")
}

fn plan_error<T: std::fmt::Debug>(result: Result<T, Error>) -> PlanError {
    match result {
        Err(Error::Plan(error)) => error,
        other => panic!("expected a plan error, got {other:?}"),
    }
}

fn leaf_keyset(ciphertext: &StackCipherText) -> uuid::Uuid {
    match ciphertext {
        CipherText::Single(leaf) => leaf.keyset_id(),
        other => panic!("expected a single leaf, got {other:?}"),
    }
}

/// The hand-composed combinator spelling of the four-field record, each
/// field under the derive's spelling of its context.
type HandOut = (
    (
        (Encrypted<EmailTerms>, Encrypted<AgeTerms>),
        StackCipherText,
    ),
    u64,
);
fn hand_composed<'s, K: 'static>() -> Encryption<'s, User, HandOut, K, DeclaredContext> {
    indexed::<String, _, Borrowed, _>((Equality, Match::default()))
        .under(nonempty!("users").with("email"))
        .project(|u: &User| &u.email)
        .zip(
            indexed::<u32, _, Borrowed, _>((Equality, Ore))
                .under(nonempty!("users").with("age"))
                .project(|u: &User| &u.age),
        )
        .zip(
            target::ciphertext::<String, _, Borrowed>()
                .under(nonempty!("users").with("notes"))
                .project(|u: &User| &u.notes),
        )
        .zip(passthrough::<u64, _, Borrowed, DeclaredContext>().project(|u: &User| &u.id))
}

#[tokio::test]
async fn the_chain_is_the_hand_composed_combinators_field_for_field() {
    let (cipher, sent) = recording_cipher().await;
    let user = user();

    let mut row = cipher
        .encrypt(&user)
        .context("users")
        .fields()
        .encrypt_index::<String>("email", (Equality, Match::default()))
        .encrypt_index::<u32>("age", (Equality, Ore))
        .encrypt::<String>("notes")
        .passthrough::<u64>("id")
        .await
        .unwrap();
    let chain_sent = sent.lock().unwrap().generated();
    sent.lock().unwrap().generate.clear();

    let keyset = cipher.default_keyset();
    let (((email, age), notes), id) = keyset
        .run(hand_composed(), &user, DeclaredContext::default())
        .await
        .unwrap();
    let hand_sent = sent.lock().unwrap().generated();

    assert_eq!(
        row.names().collect::<Vec<_>>(),
        ["email", "age", "notes", "id"],
        "the record has the plan's fields, in order"
    );
    assert_eq!(
        chain_sent, hand_sent,
        "every data key under the same descriptor"
    );
    assert_eq!(
        chain_sent,
        ["users/email", "users/age", "users/notes"],
        "one key per sealed field, under <context>/<field>"
    );

    let chain_email: Encrypted<EmailTerms> = row.take("email").unwrap();
    let chain_age: Encrypted<AgeTerms> = row.take("age").unwrap();
    let chain_notes: StackCipherText = row.take("notes").unwrap();
    assert_eq!(
        row.take::<u64>("id").unwrap(),
        id,
        "passthrough is the value"
    );
    assert_eq!(chain_email.terms.0, email.terms.0, "email equality term");
    assert_eq!(
        chain_email.terms.1.to_bytes(),
        email.terms.1.to_bytes(),
        "email match terms"
    );
    assert_eq!(chain_age.terms.0, age.terms.0, "age equality term");
    assert_eq!(
        chain_age.terms.1.to_bytes(),
        age.terms.1.to_bytes(),
        "age ORE term"
    );

    // Ciphertexts are randomised, so they are compared by opening each
    // spelling's under the other's context.
    let cipher = &cipher;
    let open = |ct: StackCipherText, field: &str| {
        let context = nonempty!("users").with(field.to_owned());
        async move { cipher.decrypt::<String, _>(ct, context).await }
    };
    assert_eq!(
        open(chain_email.ciphertext, "email").await.unwrap(),
        user.email
    );
    assert_eq!(open(chain_notes, "notes").await.unwrap(), user.notes);
    let chain_age_plain: u32 = cipher
        .decrypt(chain_age.ciphertext, nonempty!("users").with("age"))
        .await
        .unwrap();
    assert_eq!(chain_age_plain, user.age);

    let mut hand_row = FieldValues::new();
    hand_row
        .insert("email", email)
        .insert("age", age)
        .insert("notes", notes)
        .insert("id", id);
    let users_plan = users_plan();
    let mut back = cipher.open(hand_row).using(&users_plan).await.unwrap();
    assert_eq!(back.take::<String>("email").unwrap(), user.email);
    assert_eq!(back.take::<u32>("age").unwrap(), user.age);
    assert_eq!(back.take::<String>("notes").unwrap(), user.notes);
    assert_eq!(back.take::<u64>("id").unwrap(), user.id);
    assert!(back.is_empty());
}

#[tokio::test]
async fn a_saved_plan_is_the_same_chain_and_decrypts_back() {
    let cipher = stack_cipher().await;
    let user = user();
    let users_plan = users_plan();

    let mut saved = cipher.encrypt(&user).using(&users_plan).await.unwrap();
    let mut chained = cipher
        .encrypt(&user)
        .context("users")
        .fields()
        .encrypt_index::<String>("email", (Equality, Match::default()))
        .encrypt_index::<u32>("age", (Equality, Ore))
        .encrypt::<String>("notes")
        .passthrough::<u64>("id")
        .await
        .unwrap();
    let a: Encrypted<EmailTerms> = saved.take("email").unwrap();
    let b: Encrypted<EmailTerms> = chained.take("email").unwrap();
    assert_eq!(a.terms.0, b.terms.0);
    saved.insert("email", a);

    let mut back = cipher.open(saved).using(&users_plan).await.unwrap();
    assert_eq!(back.take::<String>("email").unwrap(), user.email);
    assert_eq!(back.take::<u32>("age").unwrap(), user.age);
    assert_eq!(back.take::<String>("notes").unwrap(), user.notes);
    assert_eq!(back.take::<u64>("id").unwrap(), user.id);

    // A plan is reusable: every run lowers it afresh.
    let again = cipher.encrypt(&user).using(&users_plan).await.unwrap();
    assert_eq!(again.len(), 4);
    let cloned = users_plan.clone();
    assert!(cipher.encrypt(&user).using(&cloned).await.is_ok());
}

#[tokio::test]
async fn a_query_derives_under_the_label_the_write_used() {
    let cipher = stack_cipher().await;
    let users_plan = users_plan();
    let mut row = cipher.encrypt(&user()).using(&users_plan).await.unwrap();
    let email: Encrypted<EmailTerms> = row.take("email").unwrap();
    let age: Encrypted<AgeTerms> = row.take("age").unwrap();

    let email_plan = users_plan.field("email").unwrap();
    let age_plan = users_plan.field("age").unwrap();
    let eq: EqualityTerm = cipher
        .query("bob@example.com")
        .using(&email_plan)
        .equality()
        .await
        .unwrap();
    assert_eq!(
        eq, email.terms.0,
        "equality query bytes equal the stored term"
    );
    let matching: MatchTerms = cipher
        .query("bob@example.com")
        .using(&email_plan)
        .index(Match::default())
        .await
        .unwrap();
    assert_eq!(matching.to_bytes(), email.terms.1.to_bytes());
    let ore: OreTerm<u32> = cipher
        .query(&34u32)
        .using(&age_plan)
        .index(Ore)
        .await
        .unwrap();
    assert_eq!(ore.to_bytes(), age.terms.1.to_bytes());

    // A different value is a different term: the query is not a constant.
    let other = cipher
        .query("eve@example.com")
        .using(&email_plan)
        .equality()
        .await
        .unwrap();
    assert_ne!(other, email.terms.0);
}

#[tokio::test]
async fn a_query_extended_like_the_write_matches_it() {
    let cipher = stack_cipher().await;
    let users_plan = users_plan();
    let mut row = cipher
        .encrypt(&user())
        .using(&users_plan)
        .extend(7u64)
        .await
        .unwrap();
    let email: Encrypted<EmailTerms> = row.take("email").unwrap();
    let email_plan = users_plan.field("email").unwrap();
    let query = |extend: Option<u64>| {
        let chain = cipher.query("bob@example.com").using(&email_plan);
        let chain = match extend {
            Some(parts) => chain.extend(parts),
            None => chain,
        };
        chain.equality()
    };
    assert_eq!(query(Some(7)).await.unwrap(), email.terms.0);
    assert_ne!(query(None).await.unwrap(), email.terms.0);
    assert_ne!(query(Some(8)).await.unwrap(), email.terms.0);
}

#[tokio::test]
async fn a_query_against_an_undeclared_index_or_type_is_refused() {
    let cipher = stack_cipher().await;
    let users_plan: Plan<User, FakeDataKeySource> = users_plan();
    let age_plan = users_plan.field("age").unwrap();
    let notes_plan = users_plan.field("notes").unwrap();

    assert_eq!(
        plan_error(cipher.query(&34u32).using(&age_plan).index(Ope).await),
        PlanError::IndexNotDeclared {
            field: "age".into(),
            index: "ope"
        }
    );
    assert_eq!(
        plan_error(cipher.query("x").using(&notes_plan).equality().await),
        PlanError::IndexNotDeclared {
            field: "notes".into(),
            index: "eq"
        }
    );
    assert_eq!(
        plan_error(cipher.query(&34u64).using(&age_plan).equality().await),
        PlanError::FieldType {
            field: "age".into(),
            expected: "u32"
        }
    );
    assert_eq!(
        plan_error(users_plan.field("nope")),
        PlanError::NoSuchField {
            field: "nope".into()
        }
    );
}

#[tokio::test]
async fn a_one_value_plan_writes_queries_by_type_and_reads_back() {
    let cipher = stack_cipher().await;
    let age_plan = Plan::context("users/age")
        .with((Equality, Ore))
        .build()
        .unwrap();
    let out: Encrypted<AgeTerms> = cipher.encrypt(&34u32).using(&age_plan).await.unwrap();

    let chained = cipher
        .encrypt(&34u32)
        .context("users/age")
        .with((Equality, Ore))
        .await
        .unwrap();
    assert_eq!(chained.terms.0, out.terms.0);
    assert_eq!(chained.terms.1.to_bytes(), out.terms.1.to_bytes());

    let eq = cipher
        .query(&34u32)
        .using(&age_plan)
        .equality()
        .await
        .unwrap();
    assert_eq!(eq, out.terms.0);
    let ore = cipher
        .query(&34u32)
        .using(&age_plan)
        .index::<Ore, _>()
        .await
        .unwrap();
    assert_eq!(ore.to_bytes(), out.terms.1.to_bytes());

    // Byte-identical to the combinator, under the same label.
    let hand = cipher
        .default_keyset()
        .run(
            indexed::<u32, _, Borrowed, _>((Equality, Ore)),
            &34u32,
            target::CallerContext::from(NonEmpty::from(Label::parse("users/age").unwrap())),
        )
        .await
        .unwrap();
    assert_eq!(hand.terms.0, out.terms.0);

    let age: u32 = cipher.open(out).using(&age_plan).await.unwrap();
    assert_eq!(age, 34);
    let age: u32 = cipher.open(hand.ciphertext).using(&age_plan).await.unwrap();
    assert_eq!(age, 34, "a bare ciphertext opens too");
    assert_eq!(age_plan.label().to_string(), "users/age");
    assert_eq!(age_plan.indexes(), &(Equality, Ore));
}

#[tokio::test]
async fn the_one_tree_chain_is_the_cipher_directed_call_under_the_label() {
    let (cipher, sent) = recording_cipher().await;
    let body = String::from("the document");
    let ct = cipher
        .encrypt(&body)
        .context("documents/v2/body")
        .await
        .unwrap();
    assert_eq!(sent.lock().unwrap().generated(), ["documents/v2/body"]);
    let label = Label::parse("documents/v2/body").unwrap();
    let back: String = cipher.decrypt(ct, label.clone()).await.unwrap();
    assert_eq!(back, body);

    let refused = cipher.encrypt(&body).context("not//plain").await;
    assert!(matches!(plan_error(refused), PlanError::ContextLabel(_)));
}

#[tokio::test]
async fn extend_extends_every_field_and_reading_back_needs_it() {
    let (cipher, sent) = recording_cipher().await;
    let users_plan = users_plan();
    let row = cipher
        .encrypt(&user())
        .using(&users_plan)
        .extend(7u64)
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        [
            "(users/email)/7u64",
            "(users/age)/7u64",
            "(users/notes)/7u64"
        ]
    );
    let back = cipher
        .open(row)
        .using(&users_plan)
        .extend(7u64)
        .await
        .unwrap();
    assert_eq!(back.get::<String>("email").unwrap(), "bob@example.com");

    let row = cipher
        .encrypt(&user())
        .using(&users_plan)
        .extend(7u64)
        .await
        .unwrap();
    assert!(
        matches!(cipher.open(row).using(&users_plan).await, Err(Error::Aead)),
        "the fake key source ignores descriptors, so a missing extension reaches the AEAD"
    );
}

#[tokio::test]
async fn decrypt_returns_what_can_come_back_and_refuses_a_mismatched_row() {
    let cipher = stack_cipher().await;
    let tokens_plan: Plan<User, _> = Plan::context("users")
        .fields()
        .index::<String>("email", Equality)
        .encrypt_index::<u32>("age", Ore)
        .encrypt::<String>("notes")
        .passthrough::<u64>("id")
        .build()
        .unwrap();
    let row = cipher.encrypt(&user()).using(&tokens_plan).await.unwrap();
    assert!(
        row.get::<EqualityTerm>("email").is_some(),
        "index alone: the term"
    );

    let back = cipher.open(row).using(&tokens_plan).await.unwrap();
    assert_eq!(
        back.names().collect::<Vec<_>>(),
        ["age", "notes", "id"],
        "an index-only field does not come back"
    );

    // A row with an encrypt_index field stored as its bare ciphertext.
    let mut row = cipher.encrypt(&user()).using(&tokens_plan).await.unwrap();
    let age: Encrypted<OreTerm<u32>> = row.take("age").unwrap();
    row.insert("age", age.ciphertext);
    let back = cipher.open(row).using(&tokens_plan).await.unwrap();
    assert_eq!(back.get::<u32>("age"), Some(&34));

    // An index-only field may be absent from a stored row.
    let mut row = cipher.encrypt(&user()).using(&tokens_plan).await.unwrap();
    let _ = row.take::<EqualityTerm>("email").unwrap();
    assert!(cipher.open(row).using(&tokens_plan).await.is_ok());

    let fresh = || async { cipher.encrypt(&user()).using(&tokens_plan).await.unwrap() };

    let mut extra = fresh().await;
    extra.insert("rogue", 1u8);
    assert_eq!(
        plan_error(cipher.open(extra).using(&tokens_plan).await),
        PlanError::NotInPlan {
            field: "rogue".into()
        }
    );
    for missing in ["notes", "id"] {
        let mut row = fresh().await;
        assert!(row.remove(missing));
        assert_eq!(
            plan_error(cipher.open(row).using(&tokens_plan).await),
            PlanError::NotInValue {
                field: missing.into()
            }
        );
    }
    for (field, expected) in [
        ("notes", std::any::type_name::<StackCipherText>()),
        ("age", std::any::type_name::<StackCipherText>()),
        ("id", "u64"),
    ] {
        let mut row = fresh().await;
        row.insert(field, "wrong".to_string());
        assert_eq!(
            plan_error(cipher.open(row).using(&tokens_plan).await),
            PlanError::FieldType {
                field: field.into(),
                expected
            }
        );
    }
}

#[tokio::test]
async fn a_value_that_does_not_match_the_plan_is_refused_without_a_key_request() {
    let (cipher, generates, _) = counting_cipher().await;
    let loose_plan: Plan<Loose, _> = Plan::context("users")
        .fields()
        .encrypt_index::<String>("email", Equality)
        .encrypt::<u32>("age")
        .build()
        .unwrap();
    let loose = |names: Vec<&'static str>| Loose {
        names,
        email: "bob@example.com".into(),
        age: 34,
    };

    assert!(cipher
        .encrypt(&loose(vec!["email", "age"]))
        .using(&loose_plan)
        .await
        .is_ok());
    generates.store(0, Ordering::SeqCst);

    assert_eq!(
        plan_error(
            cipher
                .encrypt(&loose(vec!["email", "age", "rogue"]))
                .using(&loose_plan)
                .await
        ),
        PlanError::NotInPlan {
            field: "rogue".into()
        }
    );
    assert_eq!(
        plan_error(
            cipher
                .encrypt(&loose(vec!["email"]))
                .using(&loose_plan)
                .await
        ),
        PlanError::NotInValue {
            field: "age".into()
        }
    );
    assert_eq!(generates.load(Ordering::SeqCst), 0, "no key requested");

    // A field the value names but cannot produce at the plan's type.
    let wrong_type: Plan<Loose, _> = Plan::context("users")
        .fields()
        .encrypt::<String>("email")
        .encrypt::<String>("age")
        .build()
        .unwrap();
    assert_eq!(
        plan_error(
            cipher
                .encrypt(&loose(vec!["email", "age"]))
                .using(&wrong_type)
                .await
        ),
        PlanError::FieldType {
            field: "age".into(),
            expected: "alloc::string::String"
        }
    );
    // A field the plan names that the value neither names nor produces.
    let ghost: Plan<Loose, _> = Plan::context("users")
        .fields()
        .encrypt::<String>("email")
        .encrypt::<u32>("age")
        .encrypt::<String>("ghost")
        .build()
        .unwrap();
    assert_eq!(
        plan_error(
            cipher
                .encrypt(&loose(vec!["email", "age"]))
                .using(&ghost)
                .await
        ),
        PlanError::NotInValue {
            field: "ghost".into()
        }
    );
    // A field the value names but cannot produce at all.
    assert_eq!(
        plan_error(
            cipher
                .encrypt(&loose(vec!["email", "age", "ghost"]))
                .using(&ghost)
                .await
        ),
        PlanError::FieldType {
            field: "ghost".into(),
            expected: "alloc::string::String"
        }
    );
    assert_eq!(generates.load(Ordering::SeqCst), 0, "no key requested");
}

/// A chain naming a keyset is checked before the keyset is loaded: a plan
/// that does not hold up asks ZeroKMS nothing, the keyset lookup included,
/// and its own refusal is what comes back.
#[tokio::test]
async fn a_refused_chain_never_loads_the_keyset_it_names() {
    let (cipher, loads) = loads_counting_cipher().await;
    let users_plan: Plan<User, _> = users_plan();
    let age_plan = users_plan.field("age").unwrap();
    let doc = String::from("doc");
    let loose_plan: Plan<Loose, _> = Plan::context("users")
        .fields()
        .encrypt::<String>("email")
        .encrypt::<String>("age")
        .build()
        .unwrap();
    let loose = |names: Vec<&'static str>| Loose {
        names,
        email: "bob@example.com".into(),
        age: 34,
    };
    let row = || async { cipher.encrypt(&user()).using(&users_plan).await.unwrap() };
    let mut rogue = row().await;
    rogue.insert("rogue", 1u8);
    let mut retyped = row().await;
    retyped.insert("id", "wrong".to_string());
    assert_eq!(
        loads.load(Ordering::SeqCst),
        0,
        "the default keyset is in hand"
    );

    assert!(matches!(
        plan_error(
            cipher
                .encrypt(&doc)
                .context("docs//x")
                .keyset("tenant")
                .await
        ),
        PlanError::ContextLabel(_)
    ));
    assert!(matches!(
        plan_error(
            cipher
                .encrypt(&34u32)
                .context("users/age")
                .with((Equality, Equality))
                .keyset("tenant")
                .await
        ),
        PlanError::DuplicateIndex { .. }
    ));
    assert!(matches!(
        plan_error(
            cipher
                .encrypt(&user())
                .context("users")
                .fields()
                .encrypt::<String>("email")
                .encrypt::<String>("email")
                .keyset("tenant")
                .await
        ),
        PlanError::DuplicateField { .. }
    ));
    assert!(matches!(
        plan_error(
            cipher
                .encrypt(&loose(vec!["email", "age", "rogue"]))
                .using(&loose_plan)
                .keyset("tenant")
                .await
        ),
        PlanError::NotInPlan { field } if field == "rogue"
    ));
    assert!(matches!(
        plan_error(
            cipher
                .encrypt(&vec![loose(vec!["email", "age"])])
                .using(&loose_plan)
                .keyset("tenant")
                .await
        ),
        PlanError::FieldType { field, .. } if field == "age"
    ));
    assert!(matches!(
        plan_error(
            cipher
                .query(&34u32)
                .using(&age_plan)
                .index(Ope)
                .keyset("tenant")
                .await
        ),
        PlanError::IndexNotDeclared { .. }
    ));
    assert!(matches!(
        plan_error(cipher.open(rogue).using(&users_plan).keyset("tenant").await),
        PlanError::NotInPlan { field } if field == "rogue"
    ));
    assert!(matches!(
        plan_error(
            cipher
                .open(vec![retyped])
                .using(&users_plan)
                .keyset("tenant")
                .await
        ),
        PlanError::FieldType { field, expected: "u64" } if field == "id"
    ));
    assert_eq!(loads.load(Ordering::SeqCst), 0, "no keyset was loaded");

    let refused = stack_encrypt::all((
        cipher.encrypt(&doc).context("docs").keyset("tenant"),
        cipher.encrypt(&doc).context("docs//x"),
    ))
    .await;
    assert!(matches!(plan_error(refused), PlanError::ContextLabel(_)));
    assert_eq!(loads.load(Ordering::SeqCst), 0, "nor in a batch");

    assert!(cipher
        .encrypt(&doc)
        .context("docs")
        .keyset("tenant")
        .await
        .is_ok());
    assert_eq!(loads.load(Ordering::SeqCst), 1, "a valid chain loads it");
}

/// A record whose stored column names are not label segments: a digit
/// first, a reserved character.
struct Odd {
    user_id: String,
    two_factor: u64,
    created: u64,
    id: u64,
}
impl Fields for Odd {
    fn field_names(&self) -> Vec<&str> {
        vec!["user_id", "2fa_enabled", "created(utc)", "id"]
    }
}
impl Field<String> for Odd {
    fn field(&self, name: &str) -> Option<&String> {
        (name == "user_id").then_some(&self.user_id)
    }
}
impl Field<u64> for Odd {
    fn field(&self, name: &str) -> Option<&u64> {
        match name {
            "2fa_enabled" => Some(&self.two_factor),
            "created(utc)" => Some(&self.created),
            "id" => Some(&self.id),
            _ => None,
        }
    }
}

/// A passthrough field is under no label, so its name is only the record
/// key: any text builds, round-trips, and shares no identity with a sealed
/// field. A sealed or indexed field's name is still a label segment.
#[tokio::test]
async fn a_passthrough_name_need_not_be_a_label_segment() {
    let cipher = stack_cipher().await;
    let odd_plan: Plan<Odd, _> = Plan::context("users")
        .fields()
        .encrypt::<String>("user_id")
        .identity("id")
        .passthrough::<u64>("2fa_enabled")
        .passthrough::<u64>("created(utc)")
        .passthrough::<u64>("id")
        .build()
        .unwrap();
    assert_eq!(odd_plan.field("2fa_enabled").unwrap().label(), None);

    let value = Odd {
        user_id: "u-1".into(),
        two_factor: 1,
        created: 1_700_000_000,
        id: 42,
    };
    let row = cipher.encrypt(&value).using(&odd_plan).await.unwrap();
    assert_eq!(row.get::<u64>("created(utc)"), Some(&1_700_000_000));
    let back = cipher.open(row).using(&odd_plan).await.unwrap();
    assert_eq!(back.get::<String>("user_id").unwrap(), "u-1");
    assert_eq!(back.get::<u64>("2fa_enabled"), Some(&1));
    assert_eq!(back.get::<u64>("id"), Some(&42));

    let passthrough_plan = odd_plan.field("2fa_enabled").unwrap();
    assert_eq!(
        plan_error(
            cipher
                .query(&1u64)
                .using(&passthrough_plan)
                .equality()
                .await
        ),
        PlanError::IndexNotDeclared {
            field: "2fa_enabled".into(),
            index: "eq"
        },
        "a passthrough field answers no query"
    );

    let sealed = Plan::context("users")
        .fields::<Odd, FakeDataKeySource>()
        .encrypt::<String>("2fa_enabled")
        .build();
    assert!(matches!(
        plan_error(sealed),
        PlanError::FieldLabel { field, .. } if field == "2fa_enabled"
    ));
    let indexed = Plan::context("users")
        .fields::<Odd, FakeDataKeySource>()
        .index::<u64>("created(utc)", Equality)
        .build();
    assert!(matches!(
        plan_error(indexed),
        PlanError::FieldLabel { field, .. } if field == "created(utc)"
    ));
}

#[tokio::test]
async fn every_build_error_is_its_own() {
    fn fields() -> stack_encrypt::plan::FieldsBuilder<User, FakeDataKeySource> {
        Plan::context("users").fields()
    }
    let build =
        |b: stack_encrypt::plan::FieldsBuilder<User, FakeDataKeySource>| plan_error(b.build());

    assert!(matches!(
        plan_error(
            Plan::context("users//x")
                .fields::<User, FakeDataKeySource>()
                .build()
        ),
        PlanError::ContextLabel(_)
    ));
    assert_eq!(
        build(fields().identity("email")),
        PlanError::IdentityWithoutField
    );
    assert!(matches!(
        build(fields().encrypt::<String>("e/mail")),
        PlanError::FieldLabel { field, .. } if field == "e/mail"
    ));
    assert!(matches!(
        build(fields().encrypt::<String>("email").identity("1email")),
        PlanError::FieldLabel { field, .. } if field == "email"
    ));
    assert_eq!(
        build(fields().encrypt_index::<u32>("age", (Equality, Equality))),
        PlanError::DuplicateIndex {
            at: "age".into(),
            index: "eq"
        }
    );
    assert_eq!(
        build(fields().encrypt_index::<u32>("age", (Ore, Equality, Ore))),
        PlanError::DuplicateIndex {
            at: "age".into(),
            index: "ore"
        }
    );
    assert_eq!(
        build(
            fields()
                .encrypt_index::<String>("email", Equality)
                .passthrough::<String>("email")
        ),
        PlanError::PassthroughIndexed {
            field: "email".into()
        }
    );
    assert_eq!(
        build(
            fields()
                .passthrough::<String>("email")
                .index::<String>("email", Equality)
        ),
        PlanError::PassthroughIndexed {
            field: "email".into()
        }
    );
    assert_eq!(
        build(
            fields()
                .passthrough::<String>("email")
                .encrypt::<String>("email")
        ),
        PlanError::DuplicateField {
            field: "email".into()
        },
        "passthrough beside a sealed field with no index is a field named twice"
    );
    assert_eq!(
        build(
            fields()
                .encrypt_index::<String>("email", Equality)
                .encrypt::<String>("email")
        ),
        PlanError::DuplicateField {
            field: "email".into()
        },
        "an indexed field named again without passthrough is a field named twice"
    );
    assert_eq!(
        build(
            fields()
                .passthrough::<String>("email")
                .passthrough::<String>("email")
        ),
        PlanError::DuplicateField {
            field: "email".into()
        },
        "passthrough twice, with no index, is a field named twice"
    );
    assert_eq!(
        build(
            fields()
                .encrypt::<String>("notes")
                .encrypt::<String>("notes")
        ),
        PlanError::DuplicateField {
            field: "notes".into()
        }
    );
    assert_eq!(
        build(
            fields()
                .encrypt::<String>("email")
                .encrypt::<String>("notes")
                .identity("email")
        ),
        PlanError::SharedIdentity {
            identity: "email".into(),
            first: "email".into(),
            second: "notes".into()
        }
    );
    assert_eq!(
        build(
            fields()
                .encrypt::<String>("email")
                .identity("contact")
                .encrypt::<String>("notes")
                .identity("contact")
        ),
        PlanError::SharedIdentity {
            identity: "contact".into(),
            first: "email".into(),
            second: "notes".into()
        }
    );
    // The schema checks: a field the type lacks, one at the wrong type, and
    // one of the type's the plan leaves unnamed.
    let complete = |b: stack_encrypt::plan::FieldsBuilder<User, FakeDataKeySource>| {
        b.encrypt_index::<String>("email", Equality)
            .encrypt::<u32>("age")
            .encrypt::<String>("notes")
            .passthrough::<u64>("id")
    };
    assert!(complete(fields()).build().is_ok());
    assert_eq!(
        build(complete(fields()).encrypt::<String>("ghost")),
        PlanError::NotInValue {
            field: "ghost".into()
        }
    );
    assert_eq!(
        build(
            fields()
                .encrypt::<String>("email")
                .encrypt::<String>("age")
                .encrypt::<String>("notes")
                .passthrough::<u64>("id")
        ),
        PlanError::FieldType {
            field: "age".into(),
            expected: "alloc::string::String"
        }
    );
    assert_eq!(
        build(
            fields()
                .encrypt::<String>("email")
                .encrypt::<u32>("age")
                .encrypt::<String>("notes")
        ),
        PlanError::NotInPlan { field: "id".into() }
    );

    // The one-value plan's own two.
    assert!(matches!(
        plan_error(Plan::context("a b/").with::<u32, _>(Equality).build()),
        PlanError::ContextLabel(_)
    ));
    assert_eq!(
        plan_error(
            Plan::context("users/age")
                .with::<u32, _>((Ore, Ore))
                .build()
        ),
        PlanError::DuplicateIndex {
            at: "users/age".into(),
            index: "ore"
        }
    );
    // The chain reports the same errors when awaited.
    let cipher = stack_cipher().await;
    assert_eq!(
        plan_error(
            cipher
                .encrypt(&34u32)
                .context("users/age")
                .with((Equality, Equality))
                .await
        ),
        PlanError::DuplicateIndex {
            at: "users/age".into(),
            index: "eq"
        }
    );
    assert_eq!(
        plan_error(
            cipher
                .encrypt(&user())
                .context("users")
                .fields()
                .encrypt::<String>("email")
                .await
        ),
        PlanError::NotInPlan {
            field: "age".into()
        }
    );
}

#[tokio::test]
async fn match_options_must_agree_for_a_query_to_be_declared() {
    #![allow(clippy::needless_update)]
    struct Shingles;
    impl stack_encrypt::sem::MatchConfig for Shingles {
        fn options() -> stack_encrypt::sem::MatchOptions {
            stack_encrypt::sem::MatchOptions {
                downcase: false,
                ..Default::default()
            }
        }
    }
    let cipher = stack_cipher().await;
    let users_plan: Plan<User, FakeDataKeySource> = users_plan();
    let email_plan = users_plan.field("email").unwrap();
    assert_eq!(
        plan_error(
            cipher
                .query("bob")
                .using(&email_plan)
                .index(Match::<Shingles>::new())
                .await
        ),
        PlanError::IndexNotDeclared {
            field: "email".into(),
            index: "match"
        }
    );
}

#[tokio::test]
async fn all_settles_several_chains_in_one_request() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let users_plan: Plan<User, _> = users_plan();
    let email_plan = users_plan.field("email").unwrap();
    let user = user();

    let (row, probe) = stack_encrypt::all((
        cipher.encrypt(&user).using(&users_plan),
        cipher
            .query("bob@example.com")
            .using(&email_plan)
            .equality(),
    ))
    .await
    .unwrap();
    assert_eq!(generates.load(Ordering::SeqCst), 1, "one generate call");
    let email: &Encrypted<EmailTerms> = row.get("email").unwrap();
    assert_eq!(email.terms.0, probe);

    let doc = String::from("doc");
    let (a, b, c) = stack_encrypt::all((
        cipher.encrypt(&doc).context("docs"),
        cipher.encrypt(&user).using(&users_plan),
        cipher.open(row).using(&users_plan),
    ))
    .await
    .unwrap();
    assert_eq!(
        generates.load(Ordering::SeqCst),
        2,
        "one more generate call"
    );
    assert_eq!(retrieves.load(Ordering::SeqCst), 1, "one retrieve call");
    assert_eq!(c.get::<String>("notes").unwrap(), "likes cheese");
    let (_, _, _, d) = stack_encrypt::all((
        cipher.encrypt(&doc).context("docs"),
        cipher.encrypt(&doc).context("docs"),
        cipher.open(a).using(
            &Plan::context("docs")
                .with::<String, _>(Equality)
                .build()
                .unwrap(),
        ),
        cipher.encrypt(&user).using(&users_plan),
    ))
    .await
    .unwrap();
    assert_eq!(generates.load(Ordering::SeqCst), 3);
    assert_eq!(retrieves.load(Ordering::SeqCst), 2);
    assert_eq!(d.len(), 4);
    let _ = b;
}

#[tokio::test]
async fn all_runs_under_one_named_keyset_and_refuses_two() {
    let (cipher, generates, _) = counting_cipher().await;
    let tenant = cipher
        .keyset(IdentifiedBy::Name("tenant".to_string().into()))
        .await
        .unwrap();
    let doc = String::from("doc");

    let (a, b) = stack_encrypt::all((
        cipher.encrypt(&doc).context("docs").keyset("tenant"),
        cipher.encrypt(&doc).context("docs").keyset(&tenant),
    ))
    .await
    .unwrap();
    assert_eq!(leaf_keyset(&a), tenant.keyset_id());
    assert_eq!(leaf_keyset(&b), tenant.keyset_id());
    let (a, _) = stack_encrypt::all((
        cipher.encrypt(&doc).context("docs"),
        cipher.encrypt(&doc).context("docs").keyset(&tenant),
    ))
    .await
    .unwrap();
    assert_eq!(
        leaf_keyset(&a),
        tenant.keyset_id(),
        "one chain names it for all"
    );
    generates.store(0, Ordering::SeqCst);

    let refused = stack_encrypt::all((
        cipher.encrypt(&doc).context("docs").keyset("tenant"),
        cipher.encrypt(&doc).context("docs").keyset("other"),
    ))
    .await;
    assert!(matches!(refused, Err(Error::KeysetMismatch { .. })));
    assert_eq!(
        generates.load(Ordering::SeqCst),
        0,
        "refused before any request"
    );
}

/// A batch settles through one client and resolves every keyset it names
/// there, so chains started on two ciphers are refused, before any keyset
/// is loaded or key requested on either.
#[tokio::test]
async fn all_refuses_chains_from_two_ciphers() {
    let (one, one_loads) = loads_counting_cipher().await;
    let (two, two_loads) = loads_counting_cipher().await;
    let doc = String::from("doc");

    for refused in [
        stack_encrypt::all((
            one.encrypt(&doc).context("docs"),
            two.encrypt(&doc).context("docs").keyset("tenant"),
        ))
        .await,
        stack_encrypt::all((
            one.encrypt(&doc).context("docs").keyset("tenant"),
            two.encrypt(&doc).context("docs"),
        ))
        .await,
    ] {
        assert_eq!(plan_error(refused), PlanError::MixedCiphers);
    }
    let refused = stack_encrypt::all((
        one.encrypt(&doc).context("docs"),
        one.encrypt(&doc).context("docs"),
        two.encrypt(&doc).context("docs"),
    ))
    .await;
    assert_eq!(plan_error(refused), PlanError::MixedCiphers, "any position");
    assert_eq!(one_loads.load(Ordering::SeqCst), 0);
    assert_eq!(two_loads.load(Ordering::SeqCst), 0);

    let (a, b, c, d) = stack_encrypt::all((
        one.encrypt(&doc).context("docs"),
        one.encrypt(&doc).context("docs"),
        one.encrypt(&doc).context("docs"),
        one.encrypt(&doc).context("docs").keyset("tenant"),
    ))
    .await
    .unwrap();
    assert_eq!(leaf_keyset(&a), leaf_keyset(&d), "one cipher is one batch");
    assert_eq!(leaf_keyset(&b), leaf_keyset(&c));
    assert_eq!(
        one_loads.load(Ordering::SeqCst),
        1,
        "the named keyset, once"
    );
}

/// An opening that names no keyset reads a leaf from any keyset inside a
/// batch, as it does alone: it is not confined to the keyset the batch's
/// other chains mint under.
#[tokio::test]
async fn all_lets_an_unnamed_opening_read_any_keyset() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let tenant = cipher
        .keyset(IdentifiedBy::Name("tenant".to_string().into()))
        .await
        .unwrap();
    let default = cipher.default_keyset().keyset_id();
    let docs_plan = Plan::context("docs")
        .with::<String, _>(Equality)
        .build()
        .unwrap();
    let doc = String::from("doc");
    let tenant_row = || async {
        cipher
            .encrypt(&doc)
            .using(&docs_plan)
            .keyset("tenant")
            .await
            .unwrap()
    };
    let (first, second, third) = (tenant_row().await, tenant_row().await, tenant_row().await);
    let default_row = cipher.encrypt(&doc).using(&docs_plan).await.unwrap();
    generates.store(0, Ordering::SeqCst);

    let (written, opened) = stack_encrypt::all((
        cipher.encrypt(&doc).context("docs"),
        cipher.open(first).using(&docs_plan),
    ))
    .await
    .unwrap();
    assert_eq!(leaf_keyset(&written), default, "minted under the default");
    assert_eq!(opened, "doc", "a tenant row opens beside a default write");
    assert_eq!(generates.load(Ordering::SeqCst), 1);
    assert_eq!(retrieves.load(Ordering::SeqCst), 1);

    let (written, opened, also) = stack_encrypt::all((
        cipher.encrypt(&doc).context("docs").keyset("tenant"),
        cipher.open(default_row).using(&docs_plan),
        cipher.open(second).using(&docs_plan),
    ))
    .await
    .unwrap();
    assert_eq!(leaf_keyset(&written), tenant.keyset_id());
    assert_eq!(opened, "doc", "a default row opens beside a tenant write");
    assert_eq!(also, "doc");
    assert_eq!(
        retrieves.load(Ordering::SeqCst),
        3,
        "the unnamed openings: one retrieve per keyset they read"
    );

    // A named opening is confined to the keyset it names, and an unnamed
    // write beside it mints there too.
    let (written, opened) = stack_encrypt::all((
        cipher.encrypt(&doc).context("docs"),
        cipher.open(third).using(&docs_plan).keyset(&tenant),
    ))
    .await
    .unwrap();
    assert_eq!(leaf_keyset(&written), tenant.keyset_id());
    assert_eq!(opened, "doc");
    let other_default = cipher.encrypt(&doc).using(&docs_plan).await.unwrap();
    let refused = stack_encrypt::all((
        cipher.encrypt(&doc).context("docs"),
        cipher.open(other_default).using(&docs_plan).keyset(&tenant),
    ))
    .await;
    assert!(
        matches!(refused, Err(Error::ForeignKeyset { .. })),
        "{refused:?}"
    );
}

/// One chain whose plan does not hold up fails the whole batch before any
/// key is requested, however valid its siblings are.
#[tokio::test]
async fn all_refuses_a_bad_chain_beside_a_good_one_before_any_request() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let users_plan: Plan<User, _> = users_plan();
    let row = cipher.encrypt(&user()).using(&users_plan).await.unwrap();
    generates.store(0, Ordering::SeqCst);
    let document = String::from("doc");
    let result = stack_encrypt::all((
        cipher.encrypt(&document).context("docs"),
        cipher.open(row).using(&users_plan),
        cipher
            .encrypt(&user())
            .context("users")
            .fields()
            .encrypt::<String>("email"),
    ))
    .await;
    assert!(matches!(
        plan_error(result),
        PlanError::NotInPlan { field } if field == "age"
    ));
    assert_eq!(generates.load(Ordering::SeqCst), 0);
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn keyset_selects_the_minting_keyset_and_scopes_an_opening() {
    let cipher = stack_cipher().await;
    let tenant = cipher
        .keyset(IdentifiedBy::Name("tenant".to_string().into()))
        .await
        .unwrap();
    let default = cipher.default_keyset().keyset_id();
    let doc = String::from("doc");

    let plain = cipher.encrypt(&doc).context("docs").await.unwrap();
    assert_eq!(leaf_keyset(&plain), default);
    let by_name = cipher
        .encrypt(&doc)
        .context("docs")
        .keyset("tenant")
        .await
        .unwrap();
    assert_eq!(leaf_keyset(&by_name), tenant.keyset_id());
    let by_id = cipher
        .encrypt(&doc)
        .context("docs")
        .keyset(tenant.keyset_id())
        .await
        .unwrap();
    assert_eq!(leaf_keyset(&by_id), tenant.keyset_id());
    let by_handle = cipher
        .encrypt(&doc)
        .context("docs")
        .keyset(tenant.clone())
        .await
        .unwrap();
    assert_eq!(leaf_keyset(&by_handle), tenant.keyset_id());
    let by_string = cipher
        .encrypt(&doc)
        .context("docs")
        .keyset("tenant".to_string())
        .await
        .unwrap();
    assert_eq!(leaf_keyset(&by_string), tenant.keyset_id());

    let docs_plan = Plan::context("docs")
        .with::<String, _>(Equality)
        .build()
        .unwrap();
    let opened: String = cipher.open(by_name).using(&docs_plan).await.unwrap();
    assert_eq!(opened, "doc", "unscoped, a leaf from any keyset opens");
    let refused = cipher.open(plain).using(&docs_plan).keyset(&tenant).await;
    assert!(
        matches!(refused, Err(Error::ForeignKeyset { .. })),
        "scoped to a keyset, a leaf from another is refused: {refused:?}"
    );
}

#[tokio::test]
async fn a_collection_runs_in_one_request() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let users_plan: Plan<User, _> = users_plan();
    let users = vec![user(), user(), user()];

    let rows = cipher.encrypt(&users).using(&users_plan).await.unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(
        generates.load(Ordering::SeqCst),
        1,
        "one generate for every row"
    );
    let rows = cipher
        .encrypt(&users[..2])
        .using(&users_plan)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(generates.load(Ordering::SeqCst), 2);

    let back = cipher.open(rows).using(&users_plan).await.unwrap();
    assert_eq!(back.len(), 2);
    assert_eq!(
        retrieves.load(Ordering::SeqCst),
        1,
        "one retrieve for every row"
    );
    assert_eq!(back[1].get::<u32>("age"), Some(&34));

    let ages = vec![1u32, 2, 3];
    let age_plan = Plan::context("users/age")
        .with::<u32, _>(Equality)
        .build()
        .unwrap();
    let out = cipher.encrypt(&ages).using(&age_plan).await.unwrap();
    assert_eq!(out.len(), 3);
    let out = cipher.encrypt(&ages[1..]).using(&age_plan).await.unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(generates.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn nothing_touches_a_key_before_the_await() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let users_plan: Plan<User, _> = users_plan();
    let user = user();

    let chain = cipher.encrypt(&user).using(&users_plan).keyset("tenant");
    drop(chain);
    assert_eq!(generates.load(Ordering::SeqCst), 0);

    // A chain yields its Pending synchronously: terms derived, key requests
    // queued, nothing sent until it is awaited.
    let keyset = cipher.default_keyset();
    let pending = cipher
        .encrypt(&user)
        .using(&users_plan)
        .prepare(&keyset, false);
    assert_eq!(generates.load(Ordering::SeqCst), 0, "prepared, not sent");
    let row = pending.await.unwrap();
    assert_eq!(generates.load(Ordering::SeqCst), 1);
    let pending = cipher.open(row).using(&users_plan).prepare(&keyset, true);
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
    assert!(pending.await.is_ok());
    assert_eq!(retrieves.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_plan_lowers_to_an_encryption_and_a_decryption_held_by_value() {
    let cipher = stack_cipher().await;
    let users_plan: Plan<User, _> = users_plan();
    let keyset = cipher.default_keyset();
    let row = keyset
        .run(users_plan.encryption(), &user(), DeclaredContext::default())
        .await
        .unwrap();
    let back = keyset
        .run_decryption(users_plan.decryption(row, DeclaredContext::default()))
        .await
        .unwrap();
    assert_eq!(back.get::<u64>("id"), Some(&42));

    // A record built at run time is a value a plan takes apart too.
    let mut dynamic = FieldValues::new();
    dynamic
        .insert("email", "a@b.c".to_string())
        .insert("age", 7u32);
    let dynamic_plan: Plan<FieldValues, _> = Plan::context("rows")
        .fields()
        .encrypt_index::<String>("email", Equality)
        .encrypt::<u32>("age")
        .build()
        .unwrap();
    let row = keyset
        .run(
            dynamic_plan.encryption(),
            &dynamic,
            DeclaredContext::default(),
        )
        .await
        .unwrap();
    let back = keyset
        .run_decryption(dynamic_plan.decryption(row, DeclaredContext::default()))
        .await
        .unwrap();
    assert_eq!(back.get::<u32>("age"), Some(&7));
}

#[test]
fn a_plan_is_data_its_fields_say_what_they_declare() {
    let users_plan: Plan<User, FakeDataKeySource> = users_plan();
    assert_eq!(users_plan.label().to_string(), "users");
    let fields: Vec<_> = users_plan.fields().collect();
    assert_eq!(fields.len(), 4);
    assert_eq!(fields[0].name(), "email");
    assert_eq!(fields[0].label().unwrap().to_string(), "users/email");
    assert_eq!(fields[0].kind(), FieldKind::EncryptIndex);
    assert_eq!(fields[0].indexes()[0], IndexSpec::Equality);
    assert_eq!(fields[0].indexes()[1].key(), "match");
    assert_eq!(fields[0].type_name(), "alloc::string::String");
    assert_eq!(fields[1].indexes(), [IndexSpec::Equality, IndexSpec::Ore]);
    assert_eq!(fields[2].kind(), FieldKind::Encrypt);
    assert!(fields[2].indexes().is_empty());
    assert_eq!(fields[3].kind(), FieldKind::Passthrough);
    assert_eq!(fields[3].label(), None, "a passthrough field has no label");

    let renamed: Plan<User, FakeDataKeySource> = Plan::context("users")
        .fields()
        .encrypt::<String>("email")
        .identity("contact")
        .encrypt::<u32>("age")
        .encrypt::<String>("notes")
        .passthrough::<u64>("id")
        .build()
        .unwrap();
    assert_eq!(
        renamed.field("email").unwrap().label().unwrap().to_string(),
        "users/contact",
        "a pinned identity keys the field, not its name"
    );
    let index_only: Plan<User, FakeDataKeySource> = Plan::context("users")
        .fields()
        .index::<String>("email", Equality)
        .encrypt::<u32>("age")
        .encrypt::<String>("notes")
        .passthrough::<u64>("id")
        .build()
        .unwrap();
    assert_eq!(index_only.field("email").unwrap().kind(), FieldKind::Index);

    let shown = format!("{users_plan:?}");
    assert!(shown.starts_with(r#"Plan { context: "users", fields: [FieldPlan { name: "email""#));
    let builder = Plan::context("users")
        .fields::<User, FakeDataKeySource>()
        .encrypt::<u32>("age");
    assert_eq!(
        format!("{builder:?}"),
        r#"FieldsBuilder { context: Ok(Label(["users"])), fields: [("age", Encrypt, [])] }"#
    );
    let value_plan = Plan::context("a").with::<u32, _>(Equality);
    assert_eq!(
        format!("{value_plan:?}"),
        r#"ValuePlanBuilder { context: Ok(Label(["a"])), indexes: Equality }"#
    );
    let built = value_plan.build().unwrap();
    assert_eq!(
        format!("{:?}", built.clone()),
        r#"ValuePlan { context: "a", indexes: Equality }"#
    );
    assert_eq!(
        format!("{:?}", Plan::context("x")),
        r#"PlanContext { context: Ok(Label(["x"])) }"#
    );
}

#[tokio::test]
async fn a_chain_shows_no_value() {
    let cipher = stack_cipher().await;
    let secret = String::from("hunter2");
    let users_plan: Plan<User, _> = users_plan();
    let email_plan = users_plan.field("email").unwrap();
    let shown = [
        format!("{:?}", cipher.encrypt(&secret)),
        format!("{:?}", cipher.encrypt(&secret).context("x")),
        format!("{:?}", cipher.encrypt(&secret).context("x").with(Equality)),
        format!("{:?}", cipher.encrypt(&user()).context("x").fields()),
        format!("{:?}", cipher.encrypt(&user()).using(&users_plan)),
        format!("{:?}", cipher.query(&secret)),
        format!("{:?}", cipher.query(&secret).using(&email_plan)),
        format!("{:?}", cipher.query(&secret).using(&email_plan).equality()),
        format!("{:?}", cipher.open(secret.clone())),
        format!("{:?}", cipher.open(FieldValues::new()).using(&users_plan)),
        format!(
            "{:?}",
            stack_encrypt::all((
                cipher.encrypt(&secret).context("x"),
                cipher.encrypt(&secret).context("y")
            ))
        ),
    ];
    for chain in shown {
        assert!(!chain.contains("hunter2"), "{chain}");
        assert!(chain.ends_with(" { .. }"), "{chain}");
    }
}

#[tokio::test]
async fn a_keyset_choice_names_what_it_holds() {
    let cipher = stack_cipher().await;
    let handle: stack_encrypt::plan::KeysetChoice<'_, _> = (&cipher.default_keyset()).into();
    assert!(format!("{handle:?}").starts_with("Handle(KeysetCipher"));
    let named: stack_encrypt::plan::KeysetChoice<'_, FakeDataKeySource> = "tenant".into();
    assert_eq!(
        format!("{named:?}"),
        r#"Named(Name(Name { inner: "tenant" }))"#
    );
}

#[tokio::test]
async fn every_chain_honours_its_named_keyset() {
    let cipher = stack_cipher().await;
    let tenant = cipher
        .keyset(IdentifiedBy::Name("tenant".to_string().into()))
        .await
        .unwrap();
    let id = tenant.keyset_id();
    assert_ne!(id, cipher.default_keyset().keyset_id());
    let user = user();

    let indexed = cipher
        .encrypt(&34u32)
        .context("users/age")
        .with(Equality)
        .keyset("tenant")
        .await
        .unwrap();
    assert_eq!(leaf_keyset(&indexed.ciphertext), id);

    let mut fields = cipher
        .encrypt(&user)
        .context("users")
        .fields()
        .encrypt::<String>("email")
        .encrypt::<u32>("age")
        .encrypt::<String>("notes")
        .passthrough::<u64>("id")
        .keyset("tenant")
        .await
        .unwrap();
    assert_eq!(
        leaf_keyset(&fields.take::<StackCipherText>("notes").unwrap()),
        id
    );

    let users_plan: Plan<User, _> = users_plan();
    let mut row = cipher
        .encrypt(&user)
        .using(&users_plan)
        .keyset("tenant")
        .await
        .unwrap();
    assert_eq!(
        leaf_keyset(&row.take::<StackCipherText>("notes").unwrap()),
        id
    );

    // A term is keyed by the keyset's index key: a query under the tenant
    // matches the tenant's term, not the default keyset's.
    let email: Encrypted<EmailTerms> = row.take("email").unwrap();
    let email_plan = users_plan.field("email").unwrap();
    let under_tenant = cipher
        .query("bob@example.com")
        .using(&email_plan)
        .equality()
        .keyset("tenant")
        .await
        .unwrap();
    let under_default = cipher
        .query("bob@example.com")
        .using(&email_plan)
        .equality()
        .await
        .unwrap();
    assert_eq!(under_tenant, email.terms.0);
    assert_ne!(under_default, email.terms.0);
}

// `StackCipher` must stay nameable in this binary's imports.
#[allow(dead_code)]
fn _cipher_type(_: &StackCipher<FakeDataKeySource>) {}
