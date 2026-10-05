//! The widened plan grammar: two starts, three context sources (exactly
//! one), the typed verb `encrypt_into` in both positions, and the picker.
//!
//! The load-bearing claim is again byte identity: a typed field lowers to
//! the same bytes as the data verbs it replaces, for every index set
//! `Encrypted<Terms>` names, and a one-value typed plan is the `plaintext =
//! T` derive's record.
mod common;

use std::fmt::Debug;
use std::sync::atomic::Ordering;

use common::{counting_cipher, recording_cipher, stack_cipher};
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::plan::{pick, Field, FieldKind, FieldValues, Fields, PlanError};
use stack_encrypt::sem::{
    EqualityTerm, MatchConfig, MatchOptions, MatchTerms, OpeTerm, OreTerm, Tokenizer,
};
use stack_encrypt::target::{
    CallerContext, DecryptField, DecryptInto, Decryptable, Decryption, EncryptFrom, Encrypted,
    Encryption, IndexSpec, Indexes, TermSet,
};
use stack_encrypt::{
    nonempty, Decrypt, Encrypt, Equality, Error, Label, Match, Ope, Ore, Plan, StackCipherText,
};

fn plan_error<T: Debug>(result: Result<T, Error>) -> PlanError {
    match result {
        Err(Error::Plan(error)) => error,
        other => panic!("expected a plan error, got {other:?}"),
    }
}

fn two(first: &'static str, second: &'static str) -> PlanError {
    PlanError::TwoContextSources { first, second }
}

/// A value with no `Fields` impl at all: only pickers can read it.
#[derive(Clone, Debug, PartialEq)]
struct User {
    email: String,
    age: u32,
}

fn user() -> User {
    User {
        email: "bob@example.com".into(),
        age: 34,
    }
}

fn email(u: &User) -> &String {
    &u.email
}
fn age(u: &User) -> &u32 {
    &u.age
}

/// The picker fields plan every context-source test runs, without a
/// context of its own.
fn contextless_plan<K: 'static>() -> Plan<User, K> {
    Plan::fields()
        .encrypt_index(("email", email), Equality)
        .encrypt(("age", age))
        .build()
        .unwrap()
}

// --- Two starts --------------------------------------------------------------

#[tokio::test]
async fn both_starts_build_the_plan_the_context_start_builds() {
    let (cipher, sent) = recording_cipher().await;
    let fields_first = Plan::fields()
        .context("users")
        .encrypt_index(("email", email), Equality)
        .encrypt(("age", age))
        .build()
        .unwrap();
    let context_first = Plan::context("users")
        .fields()
        .encrypt_index(("email", email), Equality)
        .encrypt(("age", age))
        .build()
        .unwrap();
    assert_eq!(fields_first.label(), context_first.label());
    assert_eq!(
        fields_first.field_plans().collect::<Vec<_>>(),
        context_first.field_plans().collect::<Vec<_>>()
    );

    let mut a = cipher.encrypt(&user()).using(&fields_first).await.unwrap();
    let mut b = cipher.encrypt(&user()).using(&context_first).await.unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["users/email", "users/age", "users/email", "users/age"]
    );
    let a: Encrypted<EqualityTerm> = a.take("email").unwrap();
    let b: Encrypted<EqualityTerm> = b.take("email").unwrap();
    assert_eq!(a.terms, b.terms);

    let value_first = Plan::value::<u32>()
        .context("users/age")
        .with((Equality, Ore))
        .build()
        .unwrap();
    let context_first = Plan::context("users/age")
        .with::<u32, _>((Equality, Ore))
        .build()
        .unwrap();
    assert_eq!(value_first.label(), context_first.label());
    let a = cipher.encrypt(&34u32).using(&value_first).await.unwrap();
    let b = cipher.encrypt(&34u32).using(&context_first).await.unwrap();
    assert_eq!(a.terms, b.terms);
}

// --- The context, from the call ------------------------------------------------

#[tokio::test]
async fn a_plan_built_without_a_context_takes_the_calls() {
    let (cipher, sent) = recording_cipher().await;
    let users_plan = contextless_plan();
    assert_eq!(users_plan.label(), None);
    assert_eq!(users_plan.context_field(), None);
    let email_plan = users_plan.field("email").unwrap();
    assert_eq!(email_plan.label(), None, "the label is known only per call");
    assert_eq!(email_plan.identity(), "email");

    let mut record = cipher
        .encrypt(&user())
        .context("tenants/acme")
        .using(&users_plan)
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["tenants/acme/email", "tenants/acme/age"],
        "every field under <call context>/<identity>"
    );
    let stored: Encrypted<EqualityTerm> = record.take("email").unwrap();

    let query_value = cipher
        .query("bob@example.com")
        .context("tenants/acme")
        .using(&email_plan)
        .equality()
        .await
        .unwrap();
    assert_eq!(
        query_value, stored.terms,
        "a query naming the same context matches"
    );
    let elsewhere = cipher
        .query("bob@example.com")
        .context("tenants/globex")
        .using(&email_plan)
        .equality()
        .await
        .unwrap();
    assert_ne!(elsewhere, stored.terms);

    record.insert("email", stored);
    let back = cipher
        .open(record)
        .context("tenants/acme")
        .using(&users_plan)
        .await
        .unwrap();
    assert_eq!(back.get::<String>("email"), Some(&user().email));
    assert_eq!(back.get::<u32>("age"), Some(&34));
}

#[tokio::test]
async fn a_plan_run_with_no_context_is_refused_before_any_key_request() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let users_plan = Plan::fields()
        .encrypt_index(("email", email), Equality)
        .build()
        .unwrap();
    assert_eq!(
        plan_error(cipher.encrypt(&user()).using(&users_plan).await),
        PlanError::NoContext
    );
    assert_eq!(
        plan_error(
            cipher
                .query("bob@example.com")
                .using(&users_plan.field("email").unwrap())
                .equality()
                .await
        ),
        PlanError::NoContext
    );
    let record = cipher
        .encrypt(&user())
        .context("users")
        .using(&users_plan)
        .await
        .unwrap();
    assert_eq!(
        plan_error(cipher.open(record).using(&users_plan).await),
        PlanError::NoContext
    );

    let age_plan = Plan::value::<u32>().with(Equality).build().unwrap();
    assert_eq!(age_plan.label(), None);
    assert_eq!(
        plan_error(cipher.encrypt(&34u32).using(&age_plan).await),
        PlanError::NoContext
    );
    assert_eq!(
        plan_error(cipher.query(&34u32).using(&age_plan).equality().await),
        PlanError::NoContext
    );
    let age = cipher
        .encrypt(&34u32)
        .context("users/age")
        .using(&age_plan)
        .await
        .unwrap();
    assert_eq!(
        plan_error(cipher.open(age).using(&age_plan).await),
        PlanError::NoContext
    );
    assert_eq!(
        generates.load(Ordering::SeqCst),
        2,
        "only the two good writes"
    );
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
    assert!(PlanError::NoContext
        .to_string()
        .starts_with("the plan has no context"));
}

#[tokio::test]
async fn a_context_given_twice_is_refused_at_build() {
    let both = Plan::context("users")
        .fields::<User, FakeDataKeySource>()
        .context("people")
        .encrypt(("age", age))
        .build();
    assert_eq!(plan_error(both), two("the plan", "the plan"));

    let with_field = Plan::context("users")
        .fields::<TenantRecord, FakeDataKeySource>()
        .context_field(("tenant", tenant))
        .build();
    assert_eq!(plan_error(with_field), two("the plan", "a context field"));

    let field_first = Plan::fields::<TenantRecord, FakeDataKeySource>()
        .context_field(("tenant", tenant))
        .context("users")
        .build();
    assert_eq!(plan_error(field_first), two("a context field", "the plan"));

    let value = Plan::value::<u32>()
        .context("a")
        .context("b")
        .with(Equality)
        .build();
    assert_eq!(plan_error(value), two("the plan", "the plan"));

    assert_eq!(
        two("the plan", "the call").to_string(),
        "the plan's context is given twice: by the plan and by the call"
    );
}

#[tokio::test]
async fn a_context_given_twice_is_refused_at_the_call_before_any_key_request() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let users_plan: Plan<User, _> = Plan::context("users")
        .fields()
        .encrypt_index(("email", email), Equality)
        .build()
        .unwrap();
    assert_eq!(
        plan_error(
            cipher
                .encrypt(&user())
                .context("users")
                .using(&users_plan)
                .await
        ),
        two("the plan", "the call")
    );
    assert_eq!(
        plan_error(
            cipher
                .query("bob@example.com")
                .context("users")
                .using(&users_plan.field("email").unwrap())
                .equality()
                .await
        ),
        two("the plan", "the call")
    );
    let record = cipher.encrypt(&user()).using(&users_plan).await.unwrap();
    assert_eq!(
        plan_error(
            cipher
                .open(record)
                .context("users")
                .using(&users_plan)
                .await
        ),
        two("the plan", "the call")
    );

    let records_plan = records_plan();
    assert_eq!(
        plan_error(
            cipher
                .encrypt(&tenant_record())
                .context("x")
                .using(&records_plan)
                .await
        ),
        two("a context field", "the call")
    );

    let age_plan = Plan::value::<u32>()
        .context("users/age")
        .with(Equality)
        .build()
        .unwrap();
    assert_eq!(
        plan_error(
            cipher
                .encrypt(&34u32)
                .context("users/age")
                .using(&age_plan)
                .await
        ),
        two("the plan", "the call")
    );
    assert_eq!(
        plan_error(
            cipher
                .query(&34u32)
                .context("users/age")
                .using(&age_plan)
                .equality()
                .await
        ),
        two("the plan", "the call")
    );
    assert_eq!(generates.load(Ordering::SeqCst), 1, "only the good write");
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_call_context_that_is_not_a_label_is_refused() {
    let cipher = stack_cipher().await;
    let users_plan = contextless_plan();
    let bad = |error: PlanError| matches!(error, PlanError::ContextLabel(_));
    assert!(bad(plan_error(
        cipher
            .encrypt(&user())
            .context("a//b")
            .using(&users_plan)
            .await
    )));
    assert!(bad(plan_error(
        cipher
            .query("bob@example.com")
            .context("a//b")
            .using(&users_plan.field("email").unwrap())
            .equality()
            .await
    )));
    assert!(bad(plan_error(
        cipher
            .open(FieldValues::new())
            .context("a//b")
            .using(&users_plan)
            .await
    )));
}

// --- The context, from a field of the value -----------------------------------

#[derive(Clone, Debug, PartialEq)]
struct TenantRecord {
    tenant: String,
    email: String,
}

fn tenant_record() -> TenantRecord {
    TenantRecord {
        tenant: "tenants/acme".into(),
        email: "bob@example.com".into(),
    }
}

fn tenant(r: &TenantRecord) -> &String {
    &r.tenant
}
fn record_email(r: &TenantRecord) -> &String {
    &r.email
}

fn records_plan<K: 'static>() -> Plan<TenantRecord, K> {
    Plan::fields()
        .context_field(("tenant", tenant))
        .encrypt_index(("email", record_email), Equality)
        .build()
        .unwrap()
}

/// `.extend(parts)` reaches every field of a plan whose context is read
/// from the value, and the same parts are needed to open it.
#[tokio::test]
async fn an_extension_reaches_every_field_of_a_context_field_plan() {
    let (cipher, sent) = recording_cipher().await;
    let records_plan = records_plan();
    let record = cipher
        .encrypt(&tenant_record())
        .using(&records_plan)
        .extend(7u64)
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["(tenants/acme/email)/7u64"]
    );
    let back = cipher
        .open(record)
        .using(&records_plan)
        .extend(7u64)
        .await
        .unwrap();
    assert_eq!(back.get::<String>("email"), Some(&tenant_record().email));

    let record = cipher
        .encrypt(&tenant_record())
        .using(&records_plan)
        .extend(7u64)
        .await
        .unwrap();
    assert!(matches!(
        cipher.open(record).using(&records_plan).await,
        Err(Error::Aead)
    ));
}

/// A `Vec` through a context-field plan seals each record under its own
/// tenant, and a context the caller expects is checked against every
/// record of it.
#[tokio::test]
async fn a_vec_through_a_context_field_plan_seals_each_record_under_its_own_tenant() {
    let (cipher, sent) = recording_cipher().await;
    let records_plan = records_plan();
    let globex = TenantRecord {
        tenant: "tenants/globex".into(),
        ..tenant_record()
    };
    let records = vec![tenant_record(), globex];
    let written = cipher.encrypt(&records).using(&records_plan).await.unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["tenants/acme/email", "tenants/globex/email"],
    );
    let back = cipher.open(written).using(&records_plan).await.unwrap();
    assert_eq!(
        back[0].get::<String>("tenant").map(String::as_str),
        Some("tenants/acme")
    );
    assert_eq!(
        back[1].get::<String>("tenant").map(String::as_str),
        Some("tenants/globex")
    );
    assert_eq!(back[1].get::<String>("email"), Some(&tenant_record().email));

    let written = cipher.encrypt(&records).using(&records_plan).await.unwrap();
    let refused = cipher
        .open(written)
        .context("tenants/acme")
        .using(&records_plan)
        .await;
    assert!(
        matches!(refused, Err(Error::ContextMismatch { .. })),
        "{refused:?}"
    );
}

#[tokio::test]
async fn a_context_field_is_the_context_of_every_other_field() {
    let (cipher, sent) = recording_cipher().await;
    let records_plan: Plan<TenantRecord, _> = Plan::fields()
        .context_field(("tenant", tenant))
        .encrypt_index(("email", record_email), Equality)
        .build()
        .unwrap();
    assert_eq!(records_plan.context_field(), Some("tenant"));
    assert_eq!(records_plan.label(), None);
    assert_eq!(
        records_plan.field("tenant").unwrap().kind(),
        FieldKind::ContextField
    );

    let mut record = cipher
        .encrypt(&tenant_record())
        .using(&records_plan)
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["tenants/acme/email"],
        "the field is sealed under <context field>/<identity>"
    );
    assert_eq!(
        record.get::<String>("tenant"),
        Some(&tenant_record().tenant),
        "the context field is carried as it is"
    );

    // The same bytes as a plan given that context when it is built.
    let fixed: Plan<TenantRecord, _> = Plan::context("tenants/acme")
        .fields()
        .passthrough(("tenant", tenant))
        .encrypt_index(("email", record_email), Equality)
        .build()
        .unwrap();
    let mut fixed_record = cipher
        .encrypt(&tenant_record())
        .using(&fixed)
        .await
        .unwrap();
    let stored: Encrypted<EqualityTerm> = record.take("email").unwrap();
    let fixed_email: Encrypted<EqualityTerm> = fixed_record.take("email").unwrap();
    assert_eq!(stored.terms, fixed_email.terms);

    // A query names the context field's value.
    let query_value = cipher
        .query("bob@example.com")
        .context("tenants/acme")
        .using(&records_plan.field("email").unwrap())
        .equality()
        .await
        .unwrap();
    assert_eq!(query_value, stored.terms);

    // Opens with no expectation, under the stored context.
    record.insert("email", stored);
    let back = cipher.open(record).using(&records_plan).await.unwrap();
    assert_eq!(back.get::<String>("email"), Some(&tenant_record().email));
    assert_eq!(back.get::<String>("tenant"), Some(&tenant_record().tenant));
}

#[tokio::test]
async fn opening_checks_the_context_field_against_the_expected_context() {
    let (cipher, _, retrieves) = counting_cipher().await;
    let records_plan = records_plan();

    let record = cipher
        .encrypt(&tenant_record())
        .using(&records_plan)
        .await
        .unwrap();
    let back = cipher
        .open(record)
        .context("tenants/acme")
        .using(&records_plan)
        .await
        .unwrap();
    assert_eq!(back.get::<String>("email"), Some(&tenant_record().email));
    let before = retrieves.load(Ordering::SeqCst);

    let record = cipher
        .encrypt(&tenant_record())
        .using(&records_plan)
        .await
        .unwrap();
    let refused = cipher
        .open(record)
        .context("tenants/globex")
        .using(&records_plan)
        .await;
    assert!(
        matches!(refused, Err(Error::ContextMismatch { .. })),
        "{refused:?}"
    );
    assert_eq!(
        retrieves.load(Ordering::SeqCst),
        before,
        "refused before any key request"
    );

    // A context field changed in storage opens nothing: every field was
    // sealed under the original.
    let mut moved = cipher
        .encrypt(&tenant_record())
        .using(&records_plan)
        .await
        .unwrap();
    moved.insert("tenant", String::from("tenants/globex"));
    let refused = cipher.open(moved).using(&records_plan).await;
    assert!(matches!(refused, Err(Error::Aead)), "{refused:?}");
}

#[tokio::test]
async fn a_context_field_that_is_not_a_label_or_missing_is_refused() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let records_plan = records_plan();
    let bad = TenantRecord {
        tenant: "acme corp/(x)".into(),
        email: "bob@example.com".into(),
    };
    assert!(matches!(
        plan_error(cipher.encrypt(&bad).using(&records_plan).await),
        PlanError::ContextLabel(_)
    ));

    let mut record = cipher
        .encrypt(&tenant_record())
        .using(&records_plan)
        .await
        .unwrap();
    record.insert("tenant", 7u32);
    assert_eq!(
        plan_error(cipher.open(record).using(&records_plan).await),
        PlanError::FieldType {
            field: "tenant".into(),
            expected: "alloc::string::String"
        }
    );
    let mut record = cipher
        .encrypt(&tenant_record())
        .using(&records_plan)
        .await
        .unwrap();
    record.insert("tenant", String::from("a//b"));
    assert!(matches!(
        plan_error(cipher.open(record).using(&records_plan).await),
        PlanError::ContextLabel(_)
    ));
    let mut record = cipher
        .encrypt(&tenant_record())
        .using(&records_plan)
        .await
        .unwrap();
    assert!(record.remove("tenant"));
    assert_eq!(
        plan_error(cipher.open(record).using(&records_plan).await),
        PlanError::NotInValue {
            field: "tenant".into()
        }
    );
    assert_eq!(generates.load(Ordering::SeqCst), 3, "the three good writes");
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
}

// --- encrypt_into: a typed field is the data verbs' bytes ----------------------

/// A record of one field, read by a picker.
struct One<F> {
    v: F,
}

/// `encrypt_into::<Encrypted<Terms>>` beside `encrypt_index(indexes)`: the
/// same descriptors, the same terms, and each record opens through the
/// other plan.
async fn same_field_bytes<F, Terms, X>(value: F, indexes: X)
where
    F: Encrypt + Decrypt<'static> + Clone + Send + Sync + PartialEq + Debug + 'static,
    Terms: TermSet<F> + PartialEq + Debug + Send,
    X: Indexes<F, Terms = Terms> + Clone + Send + Sync + 'static,
{
    let (cipher, sent) = recording_cipher().await;
    let typed: Plan<One<F>, _> = Plan::context("t")
        .fields()
        .encrypt_into::<Encrypted<Terms>, _>(pick("v", |o: &One<F>| &o.v))
        .build()
        .unwrap();
    let data: Plan<One<F>, _> = Plan::context("t")
        .fields()
        .encrypt_index(pick("v", |o: &One<F>| &o.v), indexes.clone())
        .build()
        .unwrap();
    let field = typed.field("v").unwrap();
    assert_eq!(field.kind(), FieldKind::EncryptInto);
    assert_eq!(
        field.indexes(),
        data.field("v").unwrap().indexes(),
        "the target declares the indexes the data verb names"
    );
    assert_eq!(field.indexes(), indexes.specs());

    let one = One { v: value.clone() };
    let mut typed_record = cipher.encrypt(&one).using(&typed).await.unwrap();
    let mut data_record = cipher.encrypt(&one).using(&data).await.unwrap();
    assert_eq!(sent.lock().unwrap().generated(), ["t/v", "t/v"]);

    let typed_out: Encrypted<Terms> = typed_record.take("v").unwrap();
    let data_out: Encrypted<Terms> = data_record.take("v").unwrap();
    assert_eq!(typed_out.terms, data_out.terms, "the same terms");

    typed_record.insert("v", typed_out);
    data_record.insert("v", data_out);
    let back = cipher.open(typed_record).using(&data).await.unwrap();
    assert_eq!(
        back.get::<F>("v"),
        Some(&value),
        "the data plan opens the typed record"
    );
    let back = cipher.open(data_record).using(&typed).await.unwrap();
    assert_eq!(
        back.get::<F>("v"),
        Some(&value),
        "the typed plan opens the data record"
    );
}

/// A configuration other than the default.
struct Words;
impl MatchConfig for Words {
    fn options() -> MatchOptions {
        MatchOptions {
            tokenizer: Tokenizer::Standard,
            downcase: false,
            k: 4,
            m: 512,
        }
    }
}

type M = MatchTerms;
type W = MatchTerms<Words>;

#[tokio::test]
async fn a_typed_text_field_is_the_data_verbs_bytes_for_every_index_set() {
    let text = || String::from("Hello World");
    let ore = Ore;
    let ope = Ope;
    let eq = Equality;
    let m = Match::default;
    same_field_bytes::<_, EqualityTerm, _>(text(), eq).await;
    same_field_bytes::<_, M, _>(text(), m()).await;
    same_field_bytes::<_, W, _>(text(), Match::<Words>::new()).await;
    same_field_bytes::<_, OreTerm<String>, _>(text(), ore).await;
    same_field_bytes::<_, OpeTerm<String>, _>(text(), ope).await;
    same_field_bytes::<_, (EqualityTerm, M), _>(text(), (eq, m())).await;
    same_field_bytes::<_, (EqualityTerm, OreTerm<String>), _>(text(), (eq, ore)).await;
    same_field_bytes::<_, (EqualityTerm, OpeTerm<String>), _>(text(), (eq, ope)).await;
    same_field_bytes::<_, (M, OreTerm<String>), _>(text(), (m(), ore)).await;
    same_field_bytes::<_, (M, OpeTerm<String>), _>(text(), (m(), ope)).await;
    same_field_bytes::<_, (OreTerm<String>, OpeTerm<String>), _>(text(), (ore, ope)).await;
    same_field_bytes::<_, (EqualityTerm, M, OreTerm<String>), _>(text(), (eq, m(), ore)).await;
    same_field_bytes::<_, (EqualityTerm, M, OpeTerm<String>), _>(text(), (eq, m(), ope)).await;
    same_field_bytes::<_, (EqualityTerm, OreTerm<String>, OpeTerm<String>), _>(
        text(),
        (eq, ore, ope),
    )
    .await;
    same_field_bytes::<_, (M, OreTerm<String>, OpeTerm<String>), _>(text(), (m(), ore, ope)).await;
    same_field_bytes::<_, (EqualityTerm, M, OreTerm<String>, OpeTerm<String>), _>(
        text(),
        (eq, m(), ore, ope),
    )
    .await;
    same_field_bytes::<_, (W, OpeTerm<String>, OreTerm<String>, EqualityTerm), _>(
        text(),
        (Match::<Words>::new(), ope, ore, eq),
    )
    .await;
}

/// Five indexes compile (there are four index kinds, so the fifth is a
/// second match index under other options), but a field holds one term per
/// kind, so both spellings refuse the set when the plan is built.
#[test]
fn a_five_index_field_is_refused_by_both_spellings() {
    let refused = || PlanError::DuplicateIndex {
        at: "v".into(),
        index: "match",
    };
    let typed = Plan::context("t")
        .fields::<One<String>, FakeDataKeySource>()
        .encrypt_into::<Encrypted<(EqualityTerm, M, OreTerm<String>, OpeTerm<String>, W)>, _>(pick(
            "v",
            |o: &One<String>| &o.v,
        ))
        .build();
    assert_eq!(plan_error(typed), refused());
    let data = Plan::context("t")
        .fields::<One<String>, FakeDataKeySource>()
        .encrypt_index(
            pick("v", |o: &One<String>| &o.v),
            (Equality, Match::default(), Ore, Ope, Match::<Words>::new()),
        )
        .build();
    assert_eq!(plan_error(data), refused());
}

#[tokio::test]
async fn a_typed_integer_field_is_the_data_verbs_bytes_for_every_index_set() {
    same_field_bytes::<_, EqualityTerm, _>(7u32, Equality).await;
    same_field_bytes::<_, OreTerm<u32>, _>(7u32, Ore).await;
    same_field_bytes::<_, OpeTerm<u32>, _>(7u32, Ope).await;
    same_field_bytes::<_, (EqualityTerm, OreTerm<u32>), _>(7u32, (Equality, Ore)).await;
    same_field_bytes::<_, (EqualityTerm, OpeTerm<u32>), _>(7u32, (Equality, Ope)).await;
    same_field_bytes::<_, (OreTerm<u32>, OpeTerm<u32>), _>(7u32, (Ore, Ope)).await;
    same_field_bytes::<_, (OreTerm<u32>, EqualityTerm), _>(7u32, (Ore, Equality)).await;
    same_field_bytes::<_, (EqualityTerm, OreTerm<u32>, OpeTerm<u32>), _>(
        7u32,
        (Equality, Ore, Ope),
    )
    .await;
}

type EmailOut = Encrypted<(EqualityTerm, MatchTerms)>;

#[tokio::test]
async fn a_typed_field_answers_the_queries_its_target_declares_and_no_other() {
    let cipher = stack_cipher().await;
    let users_plan: Plan<User, _> = Plan::context("users")
        .fields()
        .encrypt_into::<EmailOut, _>(("email", email))
        .encrypt_into::<Encrypted<OreTerm<u32>>, _>(("age", age))
        .build()
        .unwrap();
    let mut record = cipher.encrypt(&user()).using(&users_plan).await.unwrap();
    let stored: EmailOut = record.take("email").unwrap();

    let email_plan = users_plan.field("email").unwrap();
    let query_value = cipher
        .query("bob@example.com")
        .using(&email_plan)
        .equality()
        .await
        .unwrap();
    assert_eq!(query_value, stored.terms.0);
    let matched = cipher
        .query("bob@example.com")
        .using(&email_plan)
        .index(Match::default())
        .await
        .unwrap();
    assert_eq!(matched, stored.terms.1);
    assert_eq!(
        plan_error(
            cipher
                .query("bob@example.com")
                .using(&email_plan)
                .index(Ore)
                .await
        ),
        PlanError::IndexNotDeclared {
            field: "email".into(),
            index: "ore"
        }
    );
    assert_eq!(
        plan_error(
            cipher
                .query(&34u32)
                .using(&users_plan.field("age").unwrap())
                .equality()
                .await
        ),
        PlanError::IndexNotDeclared {
            field: "age".into(),
            index: "eq"
        }
    );
}

/// A target that opens nothing: its field does not come back from `open`,
/// like an index-only field, and the stored record need not carry it.
#[tokio::test]
async fn a_typed_field_of_terms_alone_does_not_come_back() {
    let cipher = stack_cipher().await;
    let users_plan: Plan<User, _> = Plan::context("users")
        .fields()
        .encrypt_into::<EqualityTerm, _>(("email", email))
        .encrypt_into::<StackCipherText, _>(("age", age))
        .build()
        .unwrap();
    let mut record = cipher.encrypt(&user()).using(&users_plan).await.unwrap();
    let term: EqualityTerm = record.take("email").unwrap();
    let query_value = cipher
        .query("bob@example.com")
        .using(&users_plan.field("email").unwrap())
        .equality()
        .await
        .unwrap();
    assert_eq!(query_value, term);
    let back = cipher.open(record).using(&users_plan).await.unwrap();
    assert_eq!(back.names().collect::<Vec<_>>(), ["age"]);
    assert_eq!(back.get::<u32>("age"), Some(&34));
}

/// A target that says it holds ciphertext and then opens nothing.
#[allow(dead_code)] // never read: it only says it holds ciphertext
struct Lying(StackCipherText);
impl EncryptFrom<u32> for Lying {
    type Context = stack_encrypt::target::AeadContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, u32, Self, K, Self::Context> {
        <StackCipherText as EncryptFrom<u32>>::encryption().map(Lying)
    }
}
impl Decryptable for Lying {
    const DECRYPTABLE: bool = true;
}
impl<P, Ctx> DecryptField<P, Ctx> for Lying {
    fn decryption_field<K: 'static>(self, _: Ctx) -> Option<Decryption<P, K>> {
        None
    }
}

#[tokio::test]
async fn a_typed_field_that_opens_nothing_is_not_opened() {
    let cipher = stack_cipher().await;
    let plan: Plan<User, _> = Plan::context("users")
        .fields()
        .encrypt_into::<Lying, _>(("age", age))
        .build()
        .unwrap();
    let record = cipher.encrypt(&user()).using(&plan).await.unwrap();
    let result = cipher.open(record).using(&plan).await;
    assert!(matches!(result, Err(Error::NotOpened)), "{result:?}");
}

#[tokio::test]
async fn a_field_is_a_target_or_data_verbs_never_both() {
    let target_first = Plan::context("users")
        .fields::<User, FakeDataKeySource>()
        .encrypt_into::<EmailOut, _>(("email", email))
        .encrypt(("email", email))
        .build();
    let verbs_first = Plan::context("users")
        .fields::<User, FakeDataKeySource>()
        .passthrough(("email", email))
        .encrypt_into::<EmailOut, _>(("email", email))
        .build();
    for refused in [target_first, verbs_first] {
        assert_eq!(
            plan_error(refused),
            PlanError::TargetWithVerbs {
                field: "email".into()
            }
        );
    }
    let twice = Plan::context("users")
        .fields::<User, FakeDataKeySource>()
        .encrypt_into::<EmailOut, _>(("email", email))
        .encrypt_into::<EmailOut, _>(("email", email))
        .build();
    assert_eq!(
        plan_error(twice),
        PlanError::DuplicateField {
            field: "email".into()
        },
        "two targets on one field is a field named twice"
    );
    let index_twice = Plan::context("users")
        .fields::<User, FakeDataKeySource>()
        .encrypt_into::<Encrypted<(EqualityTerm, EqualityTerm)>, _>(("email", email))
        .build();
    assert_eq!(
        plan_error(index_twice),
        PlanError::DuplicateIndex {
            at: "email".into(),
            index: "eq"
        }
    );
}

// --- encrypt_into, one value: the `plaintext = T` record -----------------------

#[derive(stack_encrypt::EncryptFrom, stack_encrypt::DecryptInto)]
#[stash(plaintext = String)]
struct DerivedEmail {
    c: StackCipherText,
    hm: EqualityTerm,
}

#[tokio::test]
async fn a_one_value_typed_plan_is_the_plaintext_records_bytes() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let email_plan = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<(StackCipherText, EqualityTerm)>()
        .build()
        .unwrap();
    let email = String::from("bob@example.com");

    let (c, hm) = cipher.encrypt(&email).using(&email_plan).await.unwrap();
    let derived: DerivedEmail = keyset
        .encrypt_as(
            &email,
            CallerContext::from(nonempty!("users").with("email")),
        )
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["users/email", "users/email"]
    );
    assert_eq!(hm, derived.hm, "the same equality term");

    // Each ciphertext opens through the other's reader.
    let opened: String = stack_encrypt::target::DecryptFrom::decrypt_from_with_context(
        DerivedEmail { c, hm: hm.clone() },
        &cipher,
        CallerContext::from(nonempty!("users").with("email")),
    )
    .await
    .unwrap();
    assert_eq!(opened, email);
    let back = cipher
        .open((derived.c, derived.hm))
        .using(&email_plan)
        .await
        .unwrap();
    assert_eq!(back, email);
}

#[tokio::test]
async fn a_one_value_typed_plan_answers_its_targets_queries_and_no_other() {
    let cipher = stack_cipher().await;
    let email_plan = Plan::value::<String>()
        .context("users/email")
        .encrypt_into::<(StackCipherText, EqualityTerm)>()
        .build()
        .unwrap();
    let email = String::from("bob@example.com");
    let (_, hm) = cipher.encrypt(&email).using(&email_plan).await.unwrap();
    let query_value = cipher
        .query("bob@example.com")
        .using(&email_plan)
        .equality()
        .await
        .unwrap();
    assert_eq!(query_value, hm);
    assert_eq!(
        plan_error(
            cipher
                .query("bob@example.com")
                .using(&email_plan)
                .index(Ore)
                .await
        ),
        PlanError::IndexNotDeclared {
            field: "users/email".into(),
            index: "ore"
        }
    );
}

#[tokio::test]
async fn a_one_value_plan_without_a_context_names_the_value_in_its_errors() {
    let refused = Plan::value::<u32>().with((Equality, Equality)).build();
    assert_eq!(
        plan_error(refused),
        PlanError::DuplicateIndex {
            at: "the value".into(),
            index: "eq"
        }
    );
    let refused = Plan::value::<u32>()
        .context("a")
        .with((Equality, Equality))
        .build();
    assert_eq!(
        plan_error(refused),
        PlanError::DuplicateIndex {
            at: "a".into(),
            index: "eq"
        }
    );
}

// --- Collections through a one-value plan -------------------------------------

#[tokio::test]
async fn a_vec_written_through_a_one_value_plan_opens_through_it_in_one_request() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let ages = vec![30u32, 31, 32];

    let age_plan = Plan::context("users/age")
        .with::<u32, _>(Equality)
        .build()
        .unwrap();
    let written = cipher.encrypt(&ages).using(&age_plan).await.unwrap();
    let back: Vec<u32> = cipher.open(written).using(&age_plan).await.unwrap();
    assert_eq!(back, ages);
    assert_eq!(generates.load(Ordering::SeqCst), 1);
    assert_eq!(
        retrieves.load(Ordering::SeqCst),
        1,
        "one retrieve for the Vec"
    );

    let written = cipher.encrypt(&ages).using(&age_plan).await.unwrap();
    let ciphertexts: Vec<StackCipherText> = written.into_iter().map(|e| e.ciphertext).collect();
    let back: Vec<u32> = cipher.open(ciphertexts).using(&age_plan).await.unwrap();
    assert_eq!(back, ages, "a Vec of bare ciphertexts opens too");
    let one = cipher.encrypt(&30u32).using(&age_plan).await.unwrap();
    let back: u32 = cipher.open(one.ciphertext).using(&age_plan).await.unwrap();
    assert_eq!(back, 30);

    let typed_plan = Plan::value::<u32>()
        .context("users/age")
        .encrypt_into::<(StackCipherText, EqualityTerm)>()
        .build()
        .unwrap();
    let before = retrieves.load(Ordering::SeqCst);
    let written = cipher.encrypt(&ages).using(&typed_plan).await.unwrap();
    let back: Vec<u32> = cipher.open(written).using(&typed_plan).await.unwrap();
    assert_eq!(back, ages);
    assert_eq!(retrieves.load(Ordering::SeqCst), before + 1);
}

// --- Pickers -----------------------------------------------------------------

#[tokio::test]
async fn a_picker_plan_needs_no_fields_impl_and_is_the_by_name_plans_bytes() {
    /// The same record, readable by name.
    #[derive(Clone)]
    struct Named(User);
    impl Fields for Named {
        fn field_names(&self) -> Vec<&str> {
            vec!["email", "age"]
        }
    }
    impl Field<String> for Named {
        fn field(&self, name: &str) -> Option<&String> {
            (name == "email").then_some(&self.0.email)
        }
    }
    impl Field<u32> for Named {
        fn field(&self, name: &str) -> Option<&u32> {
            (name == "age").then_some(&self.0.age)
        }
    }

    let (cipher, sent) = recording_cipher().await;
    let picked: Plan<User, _> = Plan::context("users")
        .fields()
        .encrypt_index(pick("email", |u: &User| &u.email), (Equality, Ore))
        .encrypt(pick("age", |u: &User| &u.age))
        .build()
        .unwrap();
    let named: Plan<Named, _> = Plan::context("users")
        .fields()
        .encrypt_index::<String>("email", (Equality, Ore))
        .encrypt::<u32>("age")
        .build()
        .unwrap();
    let mut a = cipher.encrypt(&user()).using(&picked).await.unwrap();
    let mut b = cipher.encrypt(&Named(user())).using(&named).await.unwrap();
    let sent = sent.lock().unwrap().generated();
    assert_eq!(
        sent,
        ["users/email", "users/age", "users/email", "users/age"]
    );
    let a_email: Encrypted<(EqualityTerm, OreTerm<String>)> = a.take("email").unwrap();
    let b_email: Encrypted<(EqualityTerm, OreTerm<String>)> = b.take("email").unwrap();
    assert_eq!(a_email.terms, b_email.terms);
    b.insert("email", a_email);
    let back = cipher.open(b).using(&picked).await.unwrap();
    assert_eq!(back.get::<String>("email"), Some(&user().email));
}

#[tokio::test]
async fn a_plan_naming_any_field_by_name_checks_the_value_and_one_of_pickers_does_not() {
    /// A value naming a field no plan declares.
    struct Extra(User);
    impl Fields for Extra {
        fn field_names(&self) -> Vec<&str> {
            vec!["email", "age", "extra"]
        }
    }
    impl Field<String> for Extra {
        fn field(&self, name: &str) -> Option<&String> {
            (name == "email").then_some(&self.0.email)
        }
    }

    let cipher = stack_cipher().await;
    let mixed: Plan<Extra, _> = Plan::context("users")
        .fields()
        .encrypt::<String>("email")
        .encrypt(pick("age", |e: &Extra| &e.0.age))
        .build()
        .unwrap();
    assert_eq!(
        plan_error(cipher.encrypt(&Extra(user())).using(&mixed).await),
        PlanError::NotInPlan {
            field: "extra".into()
        }
    );
    let picked: Plan<Extra, _> = Plan::context("users")
        .fields()
        .encrypt(pick("email", |e: &Extra| &e.0.email))
        .build()
        .unwrap();
    let record = cipher.encrypt(&Extra(user())).using(&picked).await.unwrap();
    assert_eq!(record.names().collect::<Vec<_>>(), ["email"]);
}

// --- identity rescues a name that is not a plain segment -----------------------

#[tokio::test]
async fn a_pinned_identity_rescues_a_field_name_that_is_not_plain() {
    #[derive(Clone)]
    struct Secret {
        totp: String,
    }
    #[derive(Clone)]
    struct Reading(u32, String);

    let (cipher, sent) = recording_cipher().await;
    let users_plan: Plan<Secret, _> = Plan::context("users")
        .fields()
        .encrypt(pick("2fa_secret", |s: &Secret| &s.totp))
        .identity("totp_secret")
        .build()
        .unwrap();
    assert_eq!(
        users_plan
            .field("2fa_secret")
            .unwrap()
            .label()
            .unwrap()
            .to_string(),
        "users/totp_secret"
    );
    let record = cipher
        .encrypt(&Secret { totp: "s".into() })
        .using(&users_plan)
        .await
        .unwrap();
    assert_eq!(record.names().collect::<Vec<_>>(), ["2fa_secret"]);

    // A tuple record: fields named by index, keyed by their identities.
    let readings_plan: Plan<Reading, _> = Plan::context("reading")
        .fields()
        .encrypt_index(pick("0", |r: &Reading| &r.0), Equality)
        .identity("value")
        .encrypt(pick("1", |r: &Reading| &r.1))
        .identity("unit")
        .build()
        .unwrap();
    let mut record = cipher
        .encrypt(&Reading(21, "celsius".into()))
        .using(&readings_plan)
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["users/totp_secret", "reading/value", "reading/unit"]
    );
    let value: Encrypted<EqualityTerm> = record.take("0").unwrap();
    let query_value = cipher
        .query(&21u32)
        .using(&readings_plan.field("0").unwrap())
        .equality()
        .await
        .unwrap();
    assert_eq!(query_value, value.terms);
    let opened: u32 = cipher
        .decrypt(value.ciphertext, nonempty!("reading").with("value"))
        .await
        .unwrap();
    assert_eq!(opened, 21);

    // Without an identity the name is the identity, and must be plain.
    let refused = Plan::context("users")
        .fields::<Secret, FakeDataKeySource>()
        .encrypt(pick("2fa_secret", |s: &Secret| &s.totp))
        .build();
    assert!(matches!(
        plan_error(refused),
        PlanError::FieldLabel { field, .. } if field == "2fa_secret"
    ));
    // And in a plan whose context comes later, likewise.
    let refused = Plan::fields::<Secret, FakeDataKeySource>()
        .encrypt(pick("2fa_secret", |s: &Secret| &s.totp))
        .build();
    assert!(matches!(
        plan_error(refused),
        PlanError::FieldLabel { field, .. } if field == "2fa_secret"
    ));
}

/// In a plan built without a context, a pinned identity still keys the
/// field: the write, the query and the open all use `<call>/<identity>`,
/// never the field's name.
#[tokio::test]
async fn a_pinned_identity_keys_a_call_context_plan_for_query_and_open() {
    #[derive(Clone)]
    struct Reading(u32);
    let (cipher, sent) = recording_cipher().await;
    let readings_plan: Plan<Reading, _> = Plan::fields()
        .encrypt_index(pick("0", |r: &Reading| &r.0), Equality)
        .identity("value")
        .build()
        .unwrap();
    let mut record = cipher
        .encrypt(&Reading(21))
        .context("reading")
        .using(&readings_plan)
        .await
        .unwrap();
    assert_eq!(sent.lock().unwrap().generated(), ["reading/value"]);
    let stored: Encrypted<EqualityTerm> = record.take("0").unwrap();
    let query_value = cipher
        .query(&21u32)
        .context("reading")
        .using(&readings_plan.field("0").unwrap())
        .equality()
        .await
        .unwrap();
    assert_eq!(query_value, stored.terms);
    record.insert("0", stored);
    let back = cipher
        .open(record)
        .context("reading")
        .using(&readings_plan)
        .await
        .unwrap();
    assert_eq!(back.get::<u32>("0"), Some(&21));
}

// --- Targets declare their indexes --------------------------------------------

#[test]
fn every_target_declares_the_indexes_its_terms_answer() {
    assert_eq!(
        <EqualityTerm as EncryptFrom<String>>::indexes(),
        [IndexSpec::Equality]
    );
    assert_eq!(
        <MatchTerms<Words> as EncryptFrom<String>>::indexes(),
        [IndexSpec::Match(Words::options())]
    );
    assert_eq!(
        <OreTerm<u32> as EncryptFrom<u32>>::indexes(),
        [IndexSpec::Ore]
    );
    assert_eq!(
        <OpeTerm<u32> as EncryptFrom<u32>>::indexes(),
        [IndexSpec::Ope]
    );
    assert!(<StackCipherText as EncryptFrom<u32>>::indexes().is_empty());
    assert_eq!(
        <Encrypted<(OreTerm<u32>, EqualityTerm)> as EncryptFrom<u32>>::indexes(),
        [IndexSpec::Ore, IndexSpec::Equality]
    );
    assert_eq!(
        <(StackCipherText, EqualityTerm, OreTerm<u32>, OpeTerm<u32>) as EncryptFrom<u32>>::indexes(
        ),
        [IndexSpec::Equality, IndexSpec::Ore, IndexSpec::Ope]
    );
    assert_eq!(
        <(OreTerm<u32>, StackCipherText, EqualityTerm) as EncryptFrom<u32>>::indexes(),
        [IndexSpec::Ore, IndexSpec::Equality]
    );
    assert_eq!(
        <(
            EqualityTerm,
            OreTerm<u32>,
            StackCipherText,
            OpeTerm<u32>,
            EqualityTerm,
        ) as EncryptFrom<u32>>::indexes(),
        [
            IndexSpec::Equality,
            IndexSpec::Ore,
            IndexSpec::Ope,
            IndexSpec::Equality
        ]
    );
}

#[test]
#[allow(clippy::assertions_on_constants)] // evaluated at run time, so a mutant fails a test
fn a_tuple_is_decryptable_when_one_element_is() {
    assert!(<(StackCipherText, EqualityTerm) as Decryptable>::DECRYPTABLE);
    assert!(<(EqualityTerm, StackCipherText) as Decryptable>::DECRYPTABLE);
    assert!(!<(EqualityTerm, OreTerm<u32>) as Decryptable>::DECRYPTABLE);
    assert!(<(EqualityTerm, OreTerm<u32>, StackCipherText) as Decryptable>::DECRYPTABLE);
    assert!(
        !<(EqualityTerm, OreTerm<u32>, OpeTerm<u32>, EqualityTerm) as Decryptable>::DECRYPTABLE
    );
    assert!(
        <(
            EqualityTerm,
            OreTerm<u32>,
            OpeTerm<u32>,
            EqualityTerm,
            StackCipherText
        ) as Decryptable>::DECRYPTABLE
    );
    assert!(
        !<(
            EqualityTerm,
            OreTerm<u32>,
            OpeTerm<u32>,
            EqualityTerm,
            OreTerm<u32>
        ) as Decryptable>::DECRYPTABLE
    );
}

#[tokio::test]
async fn a_tuple_opens_through_its_ciphertext_wherever_it_sits() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let context = || CallerContext::from(nonempty!("t"));
    let terms_first: (EqualityTerm, OreTerm<u32>, StackCipherText) =
        keyset.encrypt_as(&7u32, context()).await.unwrap();
    let opened: u32 = cipher.decrypt_as(terms_first, context()).await.unwrap();
    assert_eq!(opened, 7);

    let terms_alone: (EqualityTerm, OreTerm<u32>) =
        keyset.encrypt_as(&7u32, context()).await.unwrap();
    let result: Result<u32, _> = cipher.decrypt_as(terms_alone, context()).await;
    assert!(matches!(result, Err(Error::NotOpened)), "{result:?}");

    // Five elements, the ciphertext last.
    let five: (
        EqualityTerm,
        OreTerm<u32>,
        OpeTerm<u32>,
        EqualityTerm,
        StackCipherText,
    ) = keyset.encrypt_as(&7u32, context()).await.unwrap();
    let opened: u32 = cipher.decrypt_as(five, context()).await.unwrap();
    assert_eq!(opened, 7);

    // As a field of a derived record, through `DecryptField`.
    let pair: (StackCipherText, EqualityTerm) = keyset.encrypt_as(&7u32, context()).await.unwrap();
    let opening: Option<Decryption<u32, FakeDataKeySource>> = pair.decryption_field(context());
    let opened = cipher.run_decryption(opening.unwrap()).await.unwrap();
    assert_eq!(opened, 7);
    let _ = <(StackCipherText, EqualityTerm) as DecryptInto<u32>>::decryption::<FakeDataKeySource>;
}

/// A record whose terms-only tuple comes before its ciphertext.
#[derive(stack_encrypt::EncryptFrom, stack_encrypt::DecryptInto)]
#[stash(plaintext = u32)]
struct TermsFirst {
    terms: (EqualityTerm, OreTerm<u32>),
    c: StackCipherText,
}

/// A tuple of terms alone is no field to open a record through: it yields
/// to the ciphertext beside it, nested in a tuple or in a derived record,
/// rather than stopping the search with `NotOpened`.
#[tokio::test]
async fn a_terms_only_tuple_yields_to_the_ciphertext_beside_it() {
    let cipher = stack_cipher().await;
    let keyset = cipher.default_keyset();
    let context = || CallerContext::from(nonempty!("t"));

    let terms_alone: (EqualityTerm, OreTerm<u32>) =
        keyset.encrypt_as(&7u32, context()).await.unwrap();
    let opening: Option<Decryption<u32, FakeDataKeySource>> =
        terms_alone.decryption_field(context());
    assert!(opening.is_none(), "a tuple of terms alone opens nothing");

    let nested: ((EqualityTerm, OreTerm<u32>), StackCipherText) =
        keyset.encrypt_as(&7u32, context()).await.unwrap();
    let opened: u32 = cipher.decrypt_as(nested, context()).await.unwrap();
    assert_eq!(opened, 7);

    let record: TermsFirst = keyset.encrypt_as(&7u32, context()).await.unwrap();
    let opened: u32 = cipher.decrypt_as(record, context()).await.unwrap();
    assert_eq!(opened, 7);
}

#[test]
fn a_plan_says_where_its_context_comes_from() {
    let records_plan = records_plan::<FakeDataKeySource>();
    assert!(format!("{records_plan:?}").starts_with(r#"Plan { context: "<from field \"tenant\">""#));
    let users_plan = contextless_plan::<FakeDataKeySource>();
    assert!(format!("{users_plan:?}").starts_with(r#"Plan { context: "<from the call>""#));
    let builder =
        Plan::fields::<TenantRecord, FakeDataKeySource>().context_field(("tenant", tenant));
    assert!(format!("{builder:?}").starts_with(r#"FieldsBuilder { context: [Field("tenant")]"#));
    let start = Plan::value::<u32>().context("a");
    assert_eq!(
        format!("{start:?}"),
        r#"ValueStart { context: [Ok(Label(["a"]))] }"#
    );
    let typed = Plan::value::<u32>()
        .encrypt_into::<StackCipherText>()
        .build()
        .unwrap();
    assert!(format!("{typed:?}").contains("Typed<"));
    let _ = Label::parse("a").unwrap();
}
