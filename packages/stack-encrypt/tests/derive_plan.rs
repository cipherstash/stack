//! The derive emits the plan: what `#[derive(EncryptFrom)]` generates now
//! runs `Record::plan()`, and it must write exactly what the combinator
//! chain it used to generate wrote. Each `Legacy*` type below is that old
//! generated code, written out by hand; each test runs it beside the derived
//! record and compares what ZeroKMS is sent, the terms, and that each
//! record's ciphertext opens through the other.

mod common;

use std::sync::atomic::Ordering as AtomicOrdering;

use common::{counting_cipher, recording_cipher, stack_cipher};
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::plan::pick;
use stack_encrypt::sem::{EqualityTerm, OpeTerm, OreTerm};
use stack_encrypt::target::{
    AeadContext, CallerContext, DeclaredContext, DecryptFrom, EncryptInto, Encrypted, Encryption,
    ExpectedContext, IndexSpec,
};
use stack_encrypt::{
    nonempty, DecryptInto, EncryptFrom, Error, NonEmpty, Plan, PlanError, StackCipherText,
};

// --- A `plaintext = T` record ------------------------------------------------

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String)]
struct Email {
    c: StackCipherText,
    hm: EqualityTerm,
}

/// What the derive generated for `Email` before it emitted the plan.
struct LegacyEmail {
    c: StackCipherText,
    hm: EqualityTerm,
}

impl EncryptFrom<String> for LegacyEmail {
    type Context = CallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::Context>
    where
        String: 's,
    {
        <StackCipherText as EncryptFrom<String>>::encryption::<K>()
            .accepting::<CallerContext>()
            .zip(
                <EqualityTerm as EncryptFrom<String>>::encryption::<K>()
                    .accepting::<CallerContext>(),
            )
            .accepting::<Self::Context>()
            .map(move |(c, hm)| Self { c, hm })
    }
}

#[tokio::test]
async fn a_plaintext_record_writes_what_the_old_chain_wrote() {
    // A context of one escaped part, a two-part one and an integer: the
    // caller's context must reach the outputs as given, never as a label.
    for (n, context) in [
        CallerContext::from(nonempty!("users/email")),
        CallerContext::from(nonempty!("users").with("email")),
        CallerContext::from(7u64),
    ]
    .into_iter()
    .enumerate()
    {
        let (cipher, sent) = recording_cipher().await;
        let keyset = cipher.default_keyset();
        let value = format!("alice{n}@example.com");

        let derived: Email = keyset.encrypt_as(&value, context.clone()).await.unwrap();
        let legacy: LegacyEmail = keyset.encrypt_as(&value, context.clone()).await.unwrap();
        assert_eq!(derived.hm, legacy.hm, "the same term");
        {
            let sent = sent.lock().unwrap();
            let generated = sent.generated();
            assert_eq!(generated.len(), 2);
            assert_eq!(generated[0], generated[1], "the same descriptor");
        }

        // Each record opens through the other's reader.
        let crossed = Email {
            c: legacy.c,
            hm: legacy.hm,
        };
        let opened: String = crossed
            .decrypt_into(&cipher, context.clone())
            .await
            .unwrap();
        assert_eq!(opened, value);
        let opened: String = keyset
            .decrypt_as(derived.c, AeadContext::from(context))
            .await
            .unwrap();
        assert_eq!(opened, value);
    }
}

#[test]
fn a_plaintext_record_plan_is_a_one_value_plan_over_its_outputs() {
    let plan = Email::plan::<String>().unwrap();
    // No context of its own: every output shares the caller's.
    assert_eq!(plan.label(), None);
    // The record answers the queries its terms answer.
    assert_eq!(
        <Email as EncryptFrom<String>>::indexes(),
        vec![IndexSpec::Equality]
    );
}

/// A derived record used as a plan field answers its terms' queries, through
/// the `indexes()` the derive now emits.
#[tokio::test]
async fn a_derived_record_as_a_typed_field_answers_its_queries() {
    struct User {
        email: String,
    }
    let cipher = stack_cipher().await;
    let users_plan: Plan<User, FakeDataKeySource> = Plan::context("users")
        .fields()
        .encrypt_into::<Email, _>(pick("email", |u: &User| &u.email))
        .build()
        .unwrap();
    let user = User {
        email: "bob@example.com".into(),
    };
    let mut record = cipher.encrypt(&user).using(&users_plan).await.unwrap();
    let email: Email = record.take("email").unwrap();
    let query_value = cipher
        .query("bob@example.com")
        .using(&users_plan.field("email").unwrap())
        .equality()
        .await
        .unwrap();
    assert_eq!(query_value, email.hm);
}

// --- A record with more outputs than one tuple holds -------------------------

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct Wide {
    #[stash(decrypt)]
    c: StackCipherText,
    hm: EqualityTerm,
    ob: OreTerm<u32>,
    op: OpeTerm<u32>,
    shadow: StackCipherText,
}

#[tokio::test]
async fn five_outputs_nest_and_each_is_derived_under_the_one_context() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let context = || nonempty!("readings");

    let wide: Wide = 9u32
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    let hm: EqualityTerm = 9u32
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    let ob: OreTerm<u32> = 9u32
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    assert_eq!(wide.hm, hm);
    assert_eq!(wide.ob, ob);
    let op: OpeTerm<u32> = 9u32
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    assert_eq!(wide.op, op);
    assert_eq!(
        <Wide as EncryptFrom<u32>>::indexes().len(),
        3,
        "equality, ORE and OPE"
    );
    let shadow: u32 = wide.shadow.decrypt_into(&cipher, context()).await.unwrap();
    assert_eq!(shadow, 9);
    let wide: Wide = 9u32
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    let opened: u32 = wide.decrypt_into(&cipher, context()).await.unwrap();
    assert_eq!(opened, 9);
}

// --- Two outputs that declare the same index ---------------------------------

#[allow(dead_code)] // never built: refusing it is the point
#[derive(EncryptFrom)]
#[stash(plaintext = String)]
struct TwoEqualities {
    hm: EqualityTerm,
    again: EqualityTerm,
}

/// The one plan refusal the derive cannot know at compile time: it sees the
/// outputs' type names, not the indexes they declare. Refused when run,
/// before any key is requested.
#[tokio::test]
async fn two_outputs_declaring_one_index_are_refused_before_any_request() {
    let (cipher, generates, _) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let result: Result<TwoEqualities, _> = "x"
        .to_string()
        .encrypt_into_with_context(&keyset, nonempty!("x"))
        .await;
    assert!(
        matches!(result, Err(Error::Plan(PlanError::DuplicateIndex { .. }))),
        "{:?}",
        result.err()
    );
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 0);
}

// --- A record that stores its context -----------------------------------------

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String)]
struct Scoped {
    #[stash(context_field)]
    i: String,
    c: StackCipherText,
    hm: EqualityTerm,
    #[stash(default = 3)]
    v: u8,
}

/// What the derive generated for `Scoped` before it emitted the plan.
struct LegacyScoped {
    i: String,
    c: StackCipherText,
    hm: EqualityTerm,
}

impl EncryptFrom<String> for LegacyScoped {
    type Context = NonEmpty<String>;
    fn encryption<'s, K: 'static>() -> Encryption<'s, String, Self, K, Self::Context>
    where
        String: 's,
    {
        <StackCipherText as EncryptFrom<String>>::encryption::<K>()
            .accepting::<CallerContext>()
            .zip(
                <EqualityTerm as EncryptFrom<String>>::encryption::<K>()
                    .accepting::<CallerContext>(),
            )
            .accepting::<Self::Context>()
            .map_with_context(move |(c, hm), context| Self {
                i: context.clone().into_inner(),
                c,
                hm,
            })
    }
}

fn tenant() -> NonEmpty<String> {
    NonEmpty::new("tenants/acme/email".to_string()).unwrap()
}

#[tokio::test]
async fn a_context_field_record_writes_what_the_old_chain_wrote() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let value = "bob@example.com".to_string();

    let derived: Scoped = keyset.encrypt_as(&value, tenant()).await.unwrap();
    let legacy: LegacyScoped = keyset.encrypt_as(&value, tenant()).await.unwrap();
    assert_eq!(derived.i, legacy.i);
    assert_eq!(derived.i, "tenants/acme/email");
    assert_eq!(derived.v, 3);
    assert_eq!(derived.hm, legacy.hm);
    {
        let sent = sent.lock().unwrap();
        let generated = sent.generated();
        assert_eq!(generated.len(), 2);
        assert_eq!(generated[0], generated[1]);
    }

    let crossed = Scoped {
        i: legacy.i,
        c: legacy.c,
        hm: legacy.hm,
        v: 3,
    };
    let opened: String = cipher.decrypt_as(crossed, tenant().into()).await.unwrap();
    assert_eq!(opened, value);
}

#[tokio::test]
async fn a_context_field_plan_carries_and_checks_the_context() {
    let (cipher, _, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let value = "bob@example.com".to_string();
    let plan = Scoped::plan::<String>().unwrap();

    let seal = || keyset.run(plan.encryption_with_context(), &value, tenant());

    let (stored, (_, hm)) = seal().await.unwrap();
    assert_eq!(stored, "tenants/acme/email");
    let derived: Scoped = keyset.encrypt_as(&value, tenant()).await.unwrap();
    assert_eq!(hm, derived.hm, "the plan's term is the record's");

    // Another destination is refused before any key is retrieved.
    let other = NonEmpty::new("tenants/globex/email".to_string()).unwrap();
    let record = seal().await.unwrap();
    let refused = keyset
        .run_decryption(plan.decryption_with_context(record, other.into()))
        .await;
    assert!(
        matches!(refused, Err(Error::ContextMismatch { .. })),
        "{:?}",
        refused.err()
    );
    assert_eq!(retrieves.load(AtomicOrdering::SeqCst), 0);

    // The expected one, and an unchecked one, open it.
    let record = seal().await.unwrap();
    let opened = keyset
        .run_decryption(plan.decryption_with_context(record, tenant().into()))
        .await
        .unwrap();
    assert_eq!(opened, value);
    let record = seal().await.unwrap();
    let opened = keyset
        .run_decryption(plan.decryption_with_context(record, ExpectedContext::default()))
        .await
        .unwrap();
    assert_eq!(opened, value);
}

#[test]
fn a_context_field_plan_has_one_context_source() {
    let refused = Plan::value::<String>()
        .context("users/email")
        .context_field::<String>()
        .encrypt_into::<(StackCipherText, EqualityTerm)>()
        .build();
    assert!(matches!(
        refused,
        Err(Error::Plan(PlanError::TwoContextSources { .. }))
    ));
    let refused = Plan::value::<String>()
        .context_field::<String>()
        .encrypt_into::<(EqualityTerm, EqualityTerm)>()
        .build();
    assert!(matches!(
        refused,
        Err(Error::Plan(PlanError::DuplicateIndex { .. }))
    ));
}

#[tokio::test]
async fn a_one_value_plan_with_its_own_context_refuses_the_callers() {
    let (cipher, generates, _) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<(StackCipherText, EqualityTerm)>()
        .build()
        .unwrap();
    let refused = keyset
        .run(
            plan.encryption_with_context::<_, CallerContext>(),
            &"x".to_string(),
            nonempty!("users/email").into(),
        )
        .await;
    assert!(
        matches!(
            refused,
            Err(Error::Plan(PlanError::TwoContextSources { .. }))
        ),
        "{:?}",
        refused.err()
    );
    assert_eq!(generates.load(AtomicOrdering::SeqCst), 0);
}

// --- A record of ciphertexts alone takes an AEAD-only context -----------------

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String, context_type = AeadContext)]
struct Shadowed {
    #[stash(decrypt)]
    c: StackCipherText,
    shadow: StackCipherText,
}

#[tokio::test]
async fn a_tuple_of_ciphertexts_takes_an_aead_context() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let value = "x".to_string();
    let context = || AeadContext::from(nonempty!("names"));

    let record: Shadowed = keyset.encrypt_as(&value, context()).await.unwrap();
    let pair: (StackCipherText, StackCipherText) =
        keyset.encrypt_as(&value, context()).await.unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["names", "names", "names", "names"]
    );
    let opened: String = keyset.decrypt_as(record.shadow, context()).await.unwrap();
    assert_eq!(opened, value);
    let opened: String = keyset.decrypt_as(pair.1, context()).await.unwrap();
    assert_eq!(opened, value);
    let opened: String = cipher.decrypt_as(record.c, context()).await.unwrap();
    assert_eq!(opened, value);
}

// --- A `struct` record ---------------------------------------------------------

#[derive(Debug, PartialEq, Clone)]
struct User {
    email: String,
    name: String,
    age: u32,
}

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = u32)]
struct Age {
    c: StackCipherText,
    ob: OreTerm<u32>,
}

#[derive(EncryptFrom, DecryptInto)]
#[stash(struct = User, context = "users")]
struct EncryptedUser {
    email: Encrypted<EqualityTerm>,
    #[stash(identity = "nickname")]
    name: StackCipherText,
    age: Age,
    #[stash(default = 3)]
    v: u8,
}

/// What the derive generated for `EncryptedUser` before it emitted the plan.
struct LegacyUser {
    email: Encrypted<EqualityTerm>,
    name: StackCipherText,
    age: Age,
}

impl EncryptFrom<User> for LegacyUser {
    type Context = DeclaredContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, User, Self, K, Self::Context>
    where
        User: 's,
    {
        <Encrypted<EqualityTerm> as EncryptFrom<String>>::encryption::<K>()
            .project(|u: &User| &u.email)
            .under(nonempty!("users").with("email"))
            .zip(
                <StackCipherText as EncryptFrom<String>>::encryption::<K>()
                    .project(|u: &User| &u.name)
                    .under(nonempty!("users").with("nickname")),
            )
            .zip(
                <Age as EncryptFrom<u32>>::encryption::<K>()
                    .project(|u: &User| &u.age)
                    .under(nonempty!("users").with("age")),
            )
            .accepting::<Self::Context>()
            .map(move |((email, name), age)| Self { email, name, age })
    }
}

fn user() -> User {
    User {
        email: "alice@example.com".into(),
        name: "Alice".into(),
        age: 34,
    }
}

#[tokio::test]
async fn a_struct_record_writes_what_the_old_chain_wrote() {
    for extend in [DeclaredContext::from(()), DeclaredContext::from(7u64)] {
        let (cipher, sent) = recording_cipher().await;
        let keyset = cipher.default_keyset();

        let derived: EncryptedUser = keyset.encrypt_as(&user(), extend.clone()).await.unwrap();
        let legacy: LegacyUser = keyset.encrypt_as(&user(), extend.clone()).await.unwrap();
        assert_eq!(derived.v, 3);
        assert_eq!(derived.email.terms, legacy.email.terms);
        assert_eq!(derived.age.ob, legacy.age.ob);
        {
            let sent = sent.lock().unwrap();
            let generated = sent.generated();
            let (new, old) = generated.split_at(generated.len() / 2);
            assert_eq!(new, old, "the same descriptors, in the same order");
        }

        let crossed = EncryptedUser {
            email: legacy.email,
            name: legacy.name,
            age: legacy.age,
            v: 3,
        };
        let opened = User::decrypt_from_with_context(crossed, &cipher, extend)
            .await
            .unwrap();
        assert_eq!(opened, user());
    }
}

#[test]
fn a_struct_record_plan_is_the_hand_written_chain() {
    let derived = EncryptedUser::plan::<FakeDataKeySource>().unwrap();
    let by_hand: Plan<User, FakeDataKeySource> = Plan::context("users")
        .fields()
        .encrypt_into::<Encrypted<EqualityTerm>, _>(pick("email", |u: &User| &u.email))
        .encrypt_into::<StackCipherText, _>(pick("name", |u: &User| &u.name))
        .identity("nickname")
        .encrypt_into::<Age, _>(pick("age", |u: &User| &u.age))
        .build()
        .unwrap();
    assert_eq!(format!("{derived:?}"), format!("{by_hand:?}"));
    let labels: Vec<_> = derived
        .field_plans()
        .map(|field| field.label().map(ToString::to_string))
        .collect();
    assert_eq!(
        labels,
        [
            Some("users/email".to_string()),
            Some("users/nickname".to_string()),
            Some("users/age".to_string())
        ]
    );
    // A typed field answers what its type declares: `Age` names ORE.
    assert_eq!(derived.field("age").unwrap().indexes(), [IndexSpec::Ore]);
}

/// Every plan the derive emits builds: the run-time refusal is unreachable
/// for these inputs, because the derive refused the rest at compile time.
#[test]
fn every_derived_plan_builds() {
    assert!(EncryptedUser::plan::<FakeDataKeySource>().is_ok());
    assert!(Email::plan::<String>().is_ok());
    assert!(Age::plan::<u32>().is_ok());
    assert!(Wide::plan::<u32>().is_ok());
    assert!(Scoped::plan::<String>().is_ok());
    assert!(Shadowed::plan::<String>().is_ok());
    assert!(
        TwoEqualities::plan::<String>().is_err(),
        "the one exception"
    );
}

#[test]
fn a_context_field_plan_debugs_its_stored_context_and_target() {
    let start = Plan::value::<String>().context_field::<String>();
    let start = format!("{start:?}");
    assert!(start.contains("ContextFieldStart"), "{start}");
    assert!(start.contains("String"), "{start}");
    let plan = Scoped::plan::<String>().unwrap();
    let plan = format!("{plan:?}");
    assert!(plan.contains("Stored<alloc::string::String, "), "{plan}");
    assert!(plan.contains("EqualityTerm"), "{plan}");
}
