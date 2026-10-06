//! The derive emits the plan: what `#[derive(EncryptFrom)]` generates now
//! runs `Record::plan()`, and it must write exactly what the combinator
//! chain it used to generate wrote. Each `Legacy*` type below is that old
//! generated code, written out by hand; each test runs it beside the derived
//! record and compares what ZeroKMS is sent, the terms, and that each
//! record's ciphertext opens through the other.

mod common;

use common::{counting_cipher, recording_cipher, stack_cipher};
use stack_encrypt::plan::{pick, FieldValues};
use stack_encrypt::registry::fake::FakeKeysetRegistry;
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OpeTerm, OreTerm};
use stack_encrypt::target::{
    AeadContext, CallerContext, DeclaredContext, DecryptField, DecryptFrom, Decryptable,
    Decryption, EncryptInto, Encrypted, Encryption, ExpectedContext, IndexSpec,
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
    fn encryption<'s, K: stack_encrypt::KeysetRegistry + 'static>(
    ) -> Encryption<'s, String, Self, K, Self::Context>
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
            let sent = sent.calls();
            assert_eq!(sent.generate.len(), 2, "one request per record");
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
    let users_plan: Plan<User, FakeKeysetRegistry> = Plan::context("users")
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
    let (cipher, provider) = counting_cipher().await;
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
    assert_eq!(provider.call_counts().0, 0);
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
    fn encryption<'s, K: stack_encrypt::KeysetRegistry + 'static>(
    ) -> Encryption<'s, String, Self, K, Self::Context>
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
        let sent = sent.calls();
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
    let (cipher, provider) = counting_cipher().await;
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
    assert_eq!(provider.call_counts().1, 0);

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
    let (cipher, provider) = counting_cipher().await;
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
    assert_eq!(provider.call_counts().0, 0);
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
        sent.calls().generated(),
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
    fn encryption<'s, K: stack_encrypt::KeysetRegistry + 'static>(
    ) -> Encryption<'s, User, Self, K, Self::Context>
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
            let sent = sent.calls();
            assert_eq!(sent.generate.len(), 2, "one request per record");
            assert_eq!(
                sent.generate[0], sent.generate[1],
                "the same descriptors, in the same order"
            );
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

/// `EncryptedUser`'s plan, written by hand.
fn users_plan_by_hand<K: stack_encrypt::KeysetRegistry + 'static>() -> Plan<User, K> {
    Plan::context("users")
        .fields()
        .encrypt_into::<Encrypted<EqualityTerm>, _>(pick("email", |u: &User| &u.email))
        .encrypt_into::<StackCipherText, _>(pick("name", |u: &User| &u.name))
        .identity("nickname")
        .encrypt_into::<Age, _>(pick("age", |u: &User| &u.age))
        .build()
        .unwrap()
}

#[test]
fn a_struct_record_plan_is_the_hand_written_chain() {
    let derived = EncryptedUser::plan::<FakeKeysetRegistry>().unwrap();
    let by_hand: Plan<User, FakeKeysetRegistry> = users_plan_by_hand();
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

/// A `struct` record whose field type declares one index twice: the other
/// plan refusal the derive cannot see at compile time.
#[allow(dead_code)] // never built: refusing it is the point
#[derive(EncryptFrom)]
#[stash(struct = User, context = "users")]
struct TwoEqualitiesInAField {
    email: Encrypted<(EqualityTerm, EqualityTerm)>,
}

#[tokio::test]
async fn a_field_declaring_one_index_twice_is_refused_before_any_request() {
    let refused = TwoEqualitiesInAField::plan::<FakeKeysetRegistry>();
    assert!(
        matches!(
            &refused,
            Err(Error::Plan(PlanError::DuplicateIndex { at, index: "eq" })) if at == "email"
        ),
        "{:?}",
        refused.err()
    );
    let (cipher, provider) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let result = keyset
        .encrypt_as::<_, TwoEqualitiesInAField>(&user(), DeclaredContext::default())
        .await;
    assert!(
        matches!(result, Err(Error::Plan(PlanError::DuplicateIndex { .. }))),
        "{:?}",
        result.err()
    );
    assert_eq!(provider.call_counts().0, 0);
}

/// Every plan the derive emits builds, except where an output's type
/// declares an index another declares too: the derive sees types, not the
/// indexes they declare, and refused every other input at compile time.
#[test]
fn every_derived_plan_builds() {
    assert!(EncryptedUser::plan::<FakeKeysetRegistry>().is_ok());
    assert!(Email::plan::<String>().is_ok());
    assert!(Age::plan::<u32>().is_ok());
    assert!(Wide::plan::<u32>().is_ok());
    assert!(Scoped::plan::<String>().is_ok());
    assert!(Shadowed::plan::<String>().is_ok());
    assert!(
        TwoEqualities::plan::<String>().is_err(),
        "two outputs of one index"
    );
    assert!(
        TwoEqualitiesInAField::plan::<FakeKeysetRegistry>().is_err(),
        "a field type of one index twice"
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

// --- The derived `struct` record and the same plan written by hand -----------

/// The derive's `struct` opener (written out by the derive) and the plan's
/// opening (`Plan::decryption`) each encode `<context>/<identity>` extended
/// by the caller's context. Each opens what the other wrote, for every field
/// kind the record has (an index field, an identity-pinned field, a nested
/// record) and with and without an extension; and the derived record sends
/// ZeroKMS exactly what the hand-written plan sends, in one request each.
#[tokio::test]
async fn a_struct_record_and_its_plan_written_by_hand_open_each_other() {
    for extend in [DeclaredContext::from(()), DeclaredContext::from(7u64)] {
        let (cipher, sent) = recording_cipher().await;
        let keyset = cipher.default_keyset();
        let by_hand = users_plan_by_hand();

        let derived: EncryptedUser = keyset.encrypt_as(&user(), extend.clone()).await.unwrap();
        let mut written = cipher
            .encrypt(&user())
            .using(&by_hand)
            .extend(extend.clone())
            .await
            .unwrap();
        {
            let sent = sent.calls();
            assert_eq!(sent.generate.len(), 2, "one request per record");
            assert_eq!(sent.generate[0], sent.generate[1], "the same descriptors");
        }

        // The plan's output, opened through the derived record.
        let email: Encrypted<EqualityTerm> = written.take("email").unwrap();
        assert_eq!(email.terms, derived.email.terms, "the same term");
        let crossed = EncryptedUser {
            email,
            name: written.take("name").unwrap(),
            age: written.take("age").unwrap(),
            v: 3,
        };
        let opened = User::decrypt_from_with_context(crossed, &cipher, extend.clone())
            .await
            .unwrap();
        assert_eq!(opened, user());

        // The derived record, opened through the plan.
        let mut values = FieldValues::new();
        values
            .insert("email", derived.email)
            .insert("name", derived.name)
            .insert("age", derived.age);
        let opened = cipher
            .open(values)
            .using(&by_hand)
            .extend(extend)
            .await
            .unwrap();
        assert_eq!(opened.get::<String>("email"), Some(&user().email));
        assert_eq!(opened.get::<String>("name"), Some(&user().name));
        assert_eq!(opened.get::<u32>("age"), Some(&user().age));
    }
}

// --- A record whose ciphertext is last -----------------------------------------

/// Five outputs, its one ciphertext last: a tuple of targets holds up to
/// five, so the plan's target nests the tail, `(A, B, C, (D, E))`, and the
/// ciphertext sits in the nested tuple.
#[allow(dead_code)] // only `hm` and the opening are read
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String)]
struct CiphertextLast {
    hm: EqualityTerm,
    m: MatchTerms,
    ob: OreTerm<String>,
    op: OpeTerm<String>,
    c: StackCipherText,
}

#[tokio::test]
async fn the_one_decryptable_output_opens_from_the_nested_tail() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let context = || nonempty!("names");
    let value = "alice".to_string();

    // Through the derived record.
    let record: CiphertextLast = value
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    let hm: EqualityTerm = value
        .encrypt_into_with_context(&keyset, context())
        .await
        .unwrap();
    assert_eq!(record.hm, hm);
    let opened: String = record.decrypt_into(&cipher, context()).await.unwrap();
    assert_eq!(opened, value);

    // Through the plan, whose output is the nested tuple and which opens it
    // through the tuple's own `DecryptInto`.
    let plan = CiphertextLast::plan::<String>().unwrap();
    let outputs = cipher
        .encrypt(&value)
        .context("names")
        .using(&plan)
        .await
        .unwrap();
    let (plan_hm, _, _, (_, _)) = &outputs;
    assert_eq!(*plan_hm, hm);
    let opened = cipher
        .open(outputs)
        .context("names")
        .using(&plan)
        .await
        .unwrap();
    assert_eq!(opened, value);
}

// --- A record's context field, through its plan ----------------------------------

#[tokio::test]
async fn a_context_field_plan_refuses_an_empty_stored_context_before_any_request() {
    let (cipher, provider) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let value = "bob@example.com".to_string();
    let plan = Scoped::plan::<String>().unwrap();
    let (_, sealed) = keyset
        .run(plan.encryption_with_context(), &value, tenant())
        .await
        .unwrap();

    // The stored context is not authenticated: a row can hold an empty one.
    let refused = keyset
        .run_decryption(
            plan.decryption_with_context((String::new(), sealed), ExpectedContext::default()),
        )
        .await;
    assert!(refused.is_err(), "{:?}", refused.ok());
    assert_eq!(provider.call_counts().1, 0);
}

/// The derived `context_field` record's opener (written out by the derive)
/// and `ValuePlan::decryption_with_context` each check the stored context
/// and open under it: each opens what the other wrote.
#[tokio::test]
async fn a_context_field_record_and_its_plan_open_each_other() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let value = "bob@example.com".to_string();
    let plan = Scoped::plan::<String>().unwrap();

    // The derived record, opened through the plan.
    let derived: Scoped = keyset.encrypt_as(&value, tenant()).await.unwrap();
    let opened = keyset
        .run_decryption(
            plan.decryption_with_context((derived.i, (derived.c, derived.hm)), tenant().into()),
        )
        .await
        .unwrap();
    assert_eq!(opened, value);

    // The plan's output, opened through the derived record.
    let (i, (c, hm)) = keyset
        .run(plan.encryption_with_context(), &value, tenant())
        .await
        .unwrap();
    let crossed = Scoped { i, c, hm, v: 3 };
    let opened: String = cipher.decrypt_as(crossed, tenant().into()).await.unwrap();
    assert_eq!(opened, value);
}

// --- A record that declares its context type ----------------------------------

#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String, context_type = NonEmpty<u64>)]
struct Tenanted {
    c: StackCipherText,
}

/// A term whose context is a `NonEmpty<u64>`, not a `CallerContext`.
#[derive(Debug, PartialEq)]
struct TenantTag(EqualityTerm);
impl EncryptFrom<String> for TenantTag {
    type Context = NonEmpty<u64>;
    fn encryption<'s, K: stack_encrypt::KeysetRegistry + 'static>(
    ) -> Encryption<'s, String, Self, K, Self::Context> {
        <EqualityTerm as EncryptFrom<String>>::encryption()
            .accepting::<NonEmpty<u64>>()
            .map(TenantTag)
    }
    fn indexes() -> Vec<IndexSpec> {
        vec![IndexSpec::Equality]
    }
}
impl Decryptable for TenantTag {
    const DECRYPTABLE: bool = false;
}
impl<P, Ctx> DecryptField<P, Ctx> for TenantTag {
    fn decryption_field<K: stack_encrypt::KeysetRegistry + 'static>(
        self,
        _: Ctx,
    ) -> Option<Decryption<P, K>> {
        None
    }
}

/// One output, whose context is the record's `NonEmpty<u64>`.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String, context_type = NonEmpty<u64>)]
struct WrappedTenanted {
    inner: Tenanted,
}

/// Two outputs sharing the record's `NonEmpty<u64>`, one of them decryptable.
#[derive(EncryptFrom, DecryptInto)]
#[stash(plaintext = String, context_type = NonEmpty<u64>)]
struct TenantedPair {
    inner: Tenanted,
    tag: TenantTag,
}

/// A record declaring `context_type = NonEmpty<u64>` is sealed and opened
/// under that context, never a `CallerContext` it could not take, and
/// writes what its outputs write alone.
#[tokio::test]
async fn a_record_keeps_its_declared_context_type() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let value = "bob@example.com".to_string();
    let tenant = || NonEmpty::from(7u64);

    let wrapped: WrappedTenanted = keyset.encrypt_as(&value, tenant()).await.unwrap();
    let opened: String = cipher.decrypt_as(wrapped, tenant()).await.unwrap();
    assert_eq!(opened, value);

    let pair: TenantedPair = keyset.encrypt_as(&value, tenant()).await.unwrap();
    let tag: TenantTag = keyset.encrypt_as(&value, tenant()).await.unwrap();
    assert_eq!(pair.tag, tag, "the record's term is the target's");
    let opened: String = cipher.decrypt_as(pair, tenant()).await.unwrap();
    assert_eq!(opened, value);
    assert!(TenantedPair::plan::<String>().is_ok());
}
