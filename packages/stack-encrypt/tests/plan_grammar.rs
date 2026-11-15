//! Where a plan that is data gets its context, and what it refuses before
//! any key is requested.
//!
//! A plan (`dynamic::record::Plan`) takes the context of its fields from
//! one of two places: the declaration, where each field names its label, or
//! a field of each record (`context_field`), which holds the label the
//! record's other fields run under. A caller adds a scope to either with
//! `Planned`. A reader of a plan with a context field can name the context
//! it expects each record to store.
//!
//! These tests hold the rules that follow from that, through the public
//! entry points, with a key source that counts its calls:
//!
//! - a query on a plan that reads its context from the record names the
//!   context, and is refused when it names none;
//! - a context given by two sources is refused;
//! - a context that is not a plain label is refused;
//! - a query under the context or the scope the caller names derives the
//!   stored term, and another derives another term;
//! - an empty batch has the scope of its call checked, as a batch of
//!   records has.
//!
//! Each refusal is made before any key is requested. A caller holds its
//! keyset before it runs a plan, so no test here observes a keyset load.
#![cfg(feature = "dynamic")]
mod common;

use std::fmt::Debug;
use std::sync::atomic::Ordering;

use common::frames::{frame, object};
use common::{counting_cipher, recording_cipher};
use stack_encrypt::dynamic::{self, record, NoTargets, Op, Operand, Planned, ValueFrame};
use stack_encrypt::plan::IntoLabel;
use stack_encrypt::target::Scope;
use stack_encrypt::{
    AsProtectedRef as _, CipherText, DecryptFrom, EncryptInto, Error, Label, PlanError,
    StackCipherText,
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

/// One field's declaration: its label, its outputs and its type.
fn field(context: &[&str], outputs: &[&str], kind: &str) -> ValueFrame {
    object(vec![
        ("context", frame(context.to_vec())),
        ("outputs", frame(outputs.to_vec())),
        ("type", frame(kind)),
    ])
}

fn plan_of(declaration: Vec<(&str, ValueFrame)>) -> Result<record::Plan, dynamic::Error> {
    record::plan(object(declaration).as_protected_ref())
}

/// A plan whose context is in the declaration: `email` sealed and indexed
/// under `users/email`, `age` sealed under `users/age`.
fn users_plan() -> record::Plan {
    plan_of(vec![
        ("email", field(&["users", "email"], &["c", "eq"], "string")),
        ("age", field(&["users", "age"], &["c"], "uint32")),
    ])
    .expect("the users plan parses")
}

fn user() -> ValueFrame {
    object(vec![
        ("email", frame("bob@example.com")),
        ("age", frame(34u32)),
    ])
}

/// A plan that reads its context from the record: `tenant` holds the
/// label, and `email` is sealed and indexed under `<tenant>/email`.
fn records_plan() -> record::Plan {
    plan_of(vec![
        ("context_field", frame("tenant")),
        ("tenant", field(&["tenant"], &["passthrough"], "string")),
        ("email", field(&["email"], &["c", "eq"], "string")),
    ])
    .expect("the records plan parses")
}

fn tenant_record(tenant: &str) -> ValueFrame {
    object(vec![
        ("tenant", frame(tenant)),
        ("email", frame("bob@example.com")),
    ])
}

/// The records plan under the context a call names: `email` under
/// `<context>/email`, with no context field. A binding sends this plan for
/// a query, because a query has no record to read the context from.
fn under(context: &str) -> Result<record::Plan, dynamic::Error> {
    let mut label = context.split('/').collect::<Vec<_>>();
    label.push("email");
    plan_of(vec![("email", field(&label, &["c", "eq"], "string"))])
}

fn label(text: &str) -> Label {
    Label::parse(text).expect("a label")
}

/// The outputs of the field `name` of one stored record.
fn outputs<'t>(record: &'t StackCipherText, name: &str) -> &'t [(String, StackCipherText)] {
    let CipherText::Map(fields) = record else {
        panic!("a record is a map of fields")
    };
    let (_, CipherText::Map(outputs)) = fields
        .iter()
        .find(|(key, _)| key == name)
        .expect("the field")
    else {
        panic!("a field is a map of outputs")
    };
    outputs
}

/// The equality term a stored record holds for `email`.
fn stored_term(record: &StackCipherText) -> Vec<u8> {
    let (_, CipherText::Passthrough(term)) = outputs(record, "email")
        .iter()
        .find(|(key, _)| key == "eq")
        .expect("the term")
    else {
        panic!("a term is a passthrough")
    };
    vitaminc_aead_frame::serde::from_slice::<&[u8]>(&term.0)
        .expect("a term is bytes")
        .to_vec()
}

/// A stored record with its `tenant` replaced, or removed for `None`, as
/// someone with write access to the row would leave it.
fn with_stored_tenant(record: StackCipherText, tenant: Option<&str>) -> StackCipherText {
    let CipherText::Map(mut fields) = record else {
        panic!("a record is a map of fields")
    };
    fields.retain(|(key, _)| key != "tenant");
    if let Some(tenant) = tenant {
        fields.push((
            "tenant".into(),
            CipherText::Map(vec![(
                "passthrough".into(),
                CipherText::Passthrough(common::passthrough(tenant)),
            )]),
        ));
    }
    CipherText::Map(fields)
}

/// The equality term a query for `bob@example.com` derives under `plan`.
async fn query<K>(keyset: &stack_encrypt::KeysetCipher<'_, K>, plan: &record::Plan) -> Vec<u8>
where
    K: stack_encrypt::kms::DataKeySource + stack_encrypt::kms::IndexKeySource + Sync + 'static,
{
    let term = dynamic::query_term(keyset, plan, "email", Op::Eq, "bob@example.com", &NoTargets)
        .expect("the plan answers the query")
        .await
        .expect("the term");
    match term.operand() {
        Operand::One(bytes) => bytes.clone(),
        other => panic!("one term, got {other:?}"),
    }
}

// --- The context, from a field of the record -----------------------------------

#[tokio::test]
async fn a_context_field_is_the_context_of_every_other_field() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = records_plan();
    assert_eq!(plan.context_field(), Some("tenant"));
    assert_eq!(plan.label(), None, "the plan has no context of its own");

    let record = record::encrypt(&keyset, tenant_record("tenants/acme"), &plan)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["tenants/acme/email"],
        "the field is sealed under <context field>/<identity>"
    );
    let (_, CipherText::Passthrough(tenant)) = &outputs(&record, "tenant")[0] else {
        panic!("the context field is a passthrough")
    };
    assert_eq!(
        tenant.0,
        common::passthrough("tenants/acme").0,
        "the context field is carried as it is"
    );

    // The same bytes as a plan given that context in its declaration.
    let fixed = under("tenants/acme").unwrap();
    let fixed_record = record::encrypt(
        &keyset,
        object(vec![("email", frame("bob@example.com"))]),
        &fixed,
    )
    .unwrap()
    .await
    .unwrap();
    assert_eq!(stored_term(&record), stored_term(&fixed_record));

    // A query names the context field's value.
    assert_eq!(query(&keyset, &fixed).await, stored_term(&record));

    // Opens with no expectation, under the stored context.
    let back = record::decrypt(&cipher, record, &plan, None)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(back, tenant_record("tenants/acme"));
}

/// A batch through a plan with a context field seals each record under its
/// own tenant, and a context the reader expects is checked against every
/// record of it.
#[tokio::test]
async fn a_batch_through_a_context_field_plan_seals_each_record_under_its_own_tenant() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = records_plan();
    let records = || {
        frame(vec![
            tenant_record("tenants/acme"),
            tenant_record("tenants/globex"),
        ])
    };
    let written = record::encrypt(&keyset, records(), &plan)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["tenants/acme/email", "tenants/globex/email"],
    );
    let back = record::decrypt(&cipher, written, &plan, None)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(back, records());

    let written = record::encrypt(&keyset, records(), &plan)
        .unwrap()
        .await
        .unwrap();
    let refused = record::decrypt(&cipher, written, &plan, Some(label("tenants/acme")))
        .unwrap()
        .await;
    assert!(
        matches!(refused, Err(Error::ContextMismatch { .. })),
        "{refused:?}"
    );
}

#[tokio::test]
async fn opening_checks_the_context_field_against_the_expected_context() {
    let (cipher, _, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = records_plan();
    let sealed = || async {
        record::encrypt(&keyset, tenant_record("tenants/acme"), &plan)
            .unwrap()
            .await
            .unwrap()
    };

    let back = record::decrypt(&cipher, sealed().await, &plan, Some(label("tenants/acme")))
        .unwrap()
        .await
        .unwrap();
    assert_eq!(back, tenant_record("tenants/acme"));
    let before = retrieves.load(Ordering::SeqCst);

    let refused = record::decrypt(
        &cipher,
        sealed().await,
        &plan,
        Some(label("tenants/globex")),
    )
    .unwrap()
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
    let moved = with_stored_tenant(sealed().await, Some("tenants/globex"));
    let refused = record::decrypt(&cipher, moved, &plan, None).unwrap().await;
    assert!(matches!(refused, Err(Error::Aead)), "{refused:?}");
}

// --- A context that is missing -----------------------------------------------

/// A plan that reads its context from the record has none for a query: a
/// query holds no record. The query is refused until the call names the
/// context, by the check that needs no key and by the derivation alike.
#[tokio::test]
async fn a_query_that_names_no_context_is_refused_before_any_key_request() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = records_plan();

    let checked = dynamic::check_query(&plan, "email", Op::Eq, "bob@example.com", &NoTargets);
    assert!(
        matches!(checked, Err(dynamic::Error::Plan { .. })),
        "{checked:?}"
    );
    let derived = dynamic::query_term(
        &keyset,
        &plan,
        "email",
        Op::Eq,
        "bob@example.com",
        &NoTargets,
    );
    assert!(
        matches!(derived.as_ref().err(), Some(dynamic::Error::Plan { .. })),
        "a query on a context field plan names its context"
    );
    assert_eq!(generates.load(Ordering::SeqCst), 0);
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
}

/// A scope the caller passes empty names nothing. The write, the query and
/// the read each refuse it before any key is requested.
#[tokio::test]
async fn an_empty_scope_is_refused_before_any_key_request() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = users_plan();
    let stored: StackCipherText = Planned::new(&plan, user())
        .encrypt_into_with_context(&keyset, Scope::new("acme"))
        .await
        .unwrap();
    generates.store(0, Ordering::SeqCst);

    let written = Planned::new(&plan, user())
        .encrypt_into_with_context::<StackCipherText, _>(&keyset, Scope::new(""))
        .await;
    assert_eq!(plan_error(written), PlanError::EmptyPart);
    let queried = plan
        .field("email")
        .unwrap()
        .eq(frame("bob@example.com"))
        .unwrap()
        .scope(Scope::new(""))
        .encrypt(&keyset)
        .await;
    assert!(queried.is_err(), "{queried:?}");
    let opened =
        ValueFrame::decrypt_from_with_context(Planned::new(&plan, stored), &keyset, Scope::new(""))
            .await;
    assert_eq!(plan_error(opened), PlanError::EmptyPart);
    assert_eq!(generates.load(Ordering::SeqCst), 0);
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
}

// --- A context given twice -----------------------------------------------------

/// A plan names one source for its context. A declaration that names a
/// context field and gives a field a label of its own is refused when it
/// is parsed.
#[test]
fn a_context_given_twice_is_refused_when_the_plan_is_parsed() {
    let refused = [
        (
            "a field under a label of its own beside the context field",
            vec![
                ("context_field", frame("tenant")),
                ("tenant", field(&["tenant"], &["passthrough"], "string")),
                ("email", field(&["users", "email"], &["c", "eq"], "string")),
            ],
        ),
        (
            "the context field itself under a label",
            vec![
                ("context_field", frame("tenant")),
                (
                    "tenant",
                    field(&["users", "tenant"], &["passthrough"], "string"),
                ),
                ("email", field(&["email"], &["c", "eq"], "string")),
            ],
        ),
    ];
    for (what, declaration) in refused {
        let result = plan_of(declaration);
        assert!(
            matches!(result, Err(dynamic::Error::Plan { .. })),
            "{what}: {result:?}"
        );
    }
}

/// A context the reader expects is for a plan that reads its context from
/// the record. A plan with a context of its own already has one, so the
/// reader's is a second source.
#[tokio::test]
async fn a_context_given_twice_is_refused_at_the_call_before_any_key_request() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = users_plan();
    let sealed = || async {
        record::encrypt(&keyset, user(), &plan)
            .unwrap()
            .await
            .unwrap()
    };

    let checked = record::check_record(sealed().await, &plan, Some(&label("users")));
    assert!(
        matches!(checked, Err(dynamic::Error::Record { .. })),
        "{checked:?}"
    );
    let refused = record::decrypt(&cipher, sealed().await, &plan, Some(label("users")))
        .unwrap()
        .await;
    assert_eq!(plan_error(refused), two("the plan", "the call"));

    // A batch of them is refused the same way.
    let batch = record::encrypt(&keyset, frame(vec![user(), user()]), &plan)
        .unwrap()
        .await
        .unwrap();
    let refused = record::decrypt(&cipher, batch, &plan, Some(label("users")))
        .unwrap()
        .await;
    assert_eq!(plan_error(refused), two("the plan", "the call"));

    assert_eq!(generates.load(Ordering::SeqCst), 3, "only the good writes");
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
    assert_eq!(
        two("the plan", "the call").to_string(),
        "the plan's context is given twice: by the plan and by the call"
    );
}

// --- A context that is not a label ---------------------------------------------

/// The value of a context field is read as a label when the plan runs.
/// Text that is not a plain label is refused, in the record a caller
/// writes and in the record a store returns, before any key is requested.
#[tokio::test]
async fn a_context_field_that_is_not_a_label_or_missing_is_refused() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = records_plan();
    for not_a_label in ["acme corp/(x)", "tenants//acme", ""] {
        let refused = record::encrypt(&keyset, tenant_record(not_a_label), &plan)
            .expect("the record has the plan's shape")
            .await;
        assert!(
            matches!(plan_error(refused), PlanError::ContextLabel(_)),
            "{not_a_label:?}"
        );
    }
    assert_eq!(generates.load(Ordering::SeqCst), 0, "nothing was sealed");

    let sealed = || async {
        record::encrypt(&keyset, tenant_record("tenants/acme"), &plan)
            .unwrap()
            .await
            .unwrap()
    };
    let relabelled = with_stored_tenant(sealed().await, Some("a//b"));
    let refused = record::decrypt(&cipher, relabelled, &plan, None)
        .expect("the record has the plan's shape")
        .await;
    assert!(matches!(plan_error(refused), PlanError::ContextLabel(_)));
    // A stored context that is not text is not the plan's shape.
    let CipherText::Map(mut fields) = with_stored_tenant(sealed().await, None) else {
        panic!("a record is a map of fields")
    };
    fields.push((
        "tenant".into(),
        CipherText::Map(vec![(
            "passthrough".into(),
            CipherText::Passthrough(common::passthrough(7u32)),
        )]),
    ));
    let refused = record::decrypt(&cipher, CipherText::Map(fields), &plan, None);
    assert!(
        matches!(
            refused.as_ref().err(),
            Some(dynamic::Error::Record { field: Some(field), .. }) if field == "tenant"
        ),
        "a context field of another type does not fit the plan"
    );
    let missing = with_stored_tenant(sealed().await, None);
    let refused = record::decrypt(&cipher, missing, &plan, None);
    assert!(
        matches!(refused.as_ref().err(), Some(dynamic::Error::Record { .. })),
        "a record with no context field does not fit the plan"
    );
    assert_eq!(generates.load(Ordering::SeqCst), 3, "the three good writes");
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
}

/// The context a query names is a label too: one that is not plain makes
/// no plan, so no term is derived under it.
#[test]
fn a_query_context_that_is_not_a_label_is_refused() {
    for not_a_label in ["a//b", "tenants/(acme)", "tenants/2fa"] {
        let result = under(not_a_label);
        assert!(
            matches!(result, Err(dynamic::Error::Plan { .. })),
            "{not_a_label:?}: {result:?}"
        );
    }
    assert!(under("tenants/acme").is_ok());
}

// --- Queries under the context the caller names ----------------------------------

/// A query on a plan with a context field derives under the context the
/// call names: the stored term for the record's own tenant, and another
/// term for another tenant. No key is requested for either.
#[tokio::test]
async fn a_query_under_the_context_the_call_names_matches_the_stored_term() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = records_plan();
    let record = record::encrypt(&keyset, tenant_record("tenants/acme"), &plan)
        .unwrap()
        .await
        .unwrap();
    generates.store(0, Ordering::SeqCst);

    let acme = query(&keyset, &under("tenants/acme").unwrap()).await;
    assert_eq!(
        acme,
        stored_term(&record),
        "a query naming the same context matches"
    );
    let globex = query(&keyset, &under("tenants/globex").unwrap()).await;
    assert_ne!(globex, stored_term(&record));
    assert_eq!(generates.load(Ordering::SeqCst), 0);
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
}

/// A scope the caller passes extends every field of a plan whose context
/// is in its declaration. A query that names the same scope derives the
/// stored term, and the record opens only under that scope.
#[tokio::test]
async fn a_callers_scope_extends_every_field_and_a_query_names_it() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = users_plan();
    let write = || {
        Planned::new(&plan, user())
            .encrypt_into_with_context::<StackCipherText, _>(&keyset, Scope::new("acme"))
    };
    let record = write().await.unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["(users/email)/acme", "(users/age)/acme"],
        "every field under its own label, then the scope"
    );

    let by_email = |scope: &'static str| {
        plan.field("email")
            .unwrap()
            .eq(frame("bob@example.com"))
            .unwrap()
            .scope(Scope::new(scope))
            .encrypt(&keyset)
    };
    let named = by_email("acme").await.unwrap();
    assert_eq!(
        named.operand(),
        &Operand::One(stored_term(&record)),
        "a query naming the same scope matches"
    );
    let elsewhere = by_email("globex").await.unwrap();
    assert_ne!(elsewhere.operand(), &Operand::One(stored_term(&record)));
    assert_ne!(
        query(&keyset, &plan).await,
        stored_term(&record),
        "and so does a query that names none"
    );

    let back = ValueFrame::decrypt_from_with_context(
        Planned::new(&plan, record),
        &keyset,
        Scope::new("acme"),
    )
    .await
    .unwrap();
    assert_eq!(back, user());
    let unscoped =
        ValueFrame::decrypt_from(Planned::new(&plan, write().await.unwrap()), &keyset).await;
    assert!(
        matches!(unscoped, Err(Error::Aead)),
        "the fake key source ignores descriptors, so a missing scope reaches the AEAD"
    );
}

/// A scope reaches every field of a plan whose context is read from the
/// record, and the same scope is needed to open it.
#[tokio::test]
async fn a_scope_reaches_every_field_of_a_context_field_plan() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = records_plan();
    let write = || {
        Planned::new(&plan, tenant_record("tenants/acme"))
            .encrypt_into_with_context::<StackCipherText, _>(&keyset, Scope::new(7u64))
    };
    let record = write().await.unwrap();
    assert_eq!(
        sent.lock().unwrap().generated(),
        ["(tenants/acme/email)/7u64"]
    );
    let back = ValueFrame::decrypt_from_with_context(
        Planned::new(&plan, record),
        &keyset,
        Scope::new(7u64),
    )
    .await
    .unwrap();
    assert_eq!(back, tenant_record("tenants/acme"));

    let unscoped =
        ValueFrame::decrypt_from(Planned::new(&plan, write().await.unwrap()), &keyset).await;
    assert!(matches!(unscoped, Err(Error::Aead)), "{unscoped:?}");
}

/// A field whose label ends in another segment than its name is keyed
/// under that segment: the write, the query and the read all use the
/// label, never the field's name. So a name that is not a plain segment,
/// such as a column that starts with a digit, is still a field.
#[tokio::test]
async fn a_pinned_identity_keys_the_field_for_the_write_the_query_and_the_read() {
    let (cipher, sent) = recording_cipher().await;
    let keyset = cipher.default_keyset();
    let plan = plan_of(vec![(
        "2fa_secret",
        field(&["users", "totp_secret"], &["c", "eq"], "string"),
    )])
    .unwrap();
    assert_eq!(plan.fields()[0].identity(), "totp_secret");
    let source = || object(vec![("2fa_secret", frame("s3cret"))]);
    let record = record::encrypt(&keyset, source(), &plan)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(sent.lock().unwrap().generated(), ["users/totp_secret"]);

    let term = dynamic::query_term(&keyset, &plan, "2fa_secret", Op::Eq, "s3cret", &NoTargets)
        .unwrap()
        .await
        .unwrap();
    let (_, CipherText::Passthrough(stored)) = &outputs(&record, "2fa_secret")[1] else {
        panic!("the term follows the ciphertext")
    };
    assert_eq!(
        term.operand(),
        &Operand::One(
            vitaminc_aead_frame::serde::from_slice::<&[u8]>(&stored.0)
                .unwrap()
                .to_vec()
        )
    );
    let back = record::decrypt(&cipher, record, &plan, None)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(back, source());

    // Under a context field the identity is the whole of the field's
    // label, and the record's context comes before it.
    let readings = plan_of(vec![
        ("context_field", frame("tenant")),
        ("tenant", field(&["tenant"], &["passthrough"], "string")),
        ("0", field(&["value"], &["c", "eq"], "uint32")),
    ])
    .unwrap();
    sent.lock().unwrap().generate.clear();
    let reading = || object(vec![("tenant", frame("reading")), ("0", frame(21u32))]);
    let record = record::encrypt(&keyset, reading(), &readings)
        .unwrap()
        .await
        .unwrap();
    assert_eq!(sent.lock().unwrap().generated(), ["reading/value"]);
    // A query names the context, and the field's label under it ends in
    // the identity.
    let named = plan_of(vec![(
        "0",
        field(&["reading", "value"], &["c", "eq"], "uint32"),
    )])
    .unwrap();
    let term = dynamic::query_term(&keyset, &named, "0", Op::Eq, 21u32, &NoTargets)
        .unwrap()
        .await
        .unwrap();
    let (_, CipherText::Passthrough(stored)) = &outputs(&record, "0")[1] else {
        panic!("the term follows the ciphertext")
    };
    assert_eq!(
        term.operand(),
        &Operand::One(
            vitaminc_aead_frame::serde::from_slice::<&[u8]>(&stored.0)
                .unwrap()
                .to_vec()
        )
    );
    let back = record::decrypt(&cipher, record, &readings, Some(label("reading")))
        .unwrap()
        .await
        .unwrap();
    assert_eq!(back, reading());
}

/// A context is written as a label, or as text that parses as one: a
/// literal, a `String`, or a borrowed `String` such as a configuration
/// value. Text that is not a plain label is refused.
#[test]
fn a_context_is_a_label_or_text_that_parses_as_one() {
    let users_age = label("users/age");
    let held = String::from("users/age");
    assert_eq!("users/age".into_label().unwrap(), users_age);
    assert_eq!(held.clone().into_label().unwrap(), users_age);
    assert_eq!((&held).into_label().unwrap(), users_age);
    assert_eq!((&users_age).into_label().unwrap(), users_age);
    assert_eq!(users_age.clone().into_label().unwrap(), users_age);
    let not_plain = String::from("users//age");
    assert!((&not_plain).into_label().is_err());
    assert!("a b/".into_label().is_err());
}

// --- An empty batch ------------------------------------------------------------

/// An empty batch runs no record. The scope its call names is checked
/// once for the call, apart from the records, so a scope passed empty is
/// refused for an empty batch too, before any key is requested. A context
/// the reader expects is compared with each record, so an empty batch of a
/// plan with a context field has none to refuse.
#[tokio::test]
async fn an_empty_batch_has_its_context_checked_before_any_key_request() {
    let (cipher, generates, retrieves) = counting_cipher().await;
    let keyset = cipher.default_keyset();
    let users = users_plan();
    let records = records_plan();
    let none = || frame(Vec::<ValueFrame>::new());
    let stored_none = || CipherText::Sequence(Vec::new());

    let refused = Planned::new(&users, none())
        .encrypt_into_with_context::<StackCipherText, _>(&keyset, Scope::new(""))
        .await;
    assert_eq!(plan_error(refused), PlanError::EmptyPart);
    let refused = ValueFrame::decrypt_from_with_context(
        Planned::new(&users, stored_none()),
        &keyset,
        Scope::new(""),
    )
    .await;
    assert_eq!(plan_error(refused), PlanError::EmptyPart);

    let opened = record::decrypt(
        &cipher,
        stored_none(),
        &records,
        Some(label("tenants/acme")),
    )
    .unwrap()
    .await
    .unwrap();
    assert_eq!(opened, none());
    let sealed: StackCipherText = Planned::new(&users, none())
        .encrypt_into_with_context(&keyset, Scope::new("acme"))
        .await
        .unwrap();
    assert!(matches!(sealed, CipherText::Sequence(rows) if rows.is_empty()));
    assert_eq!(generates.load(Ordering::SeqCst), 0);
    assert_eq!(retrieves.load(Ordering::SeqCst), 0);
}

/// The declaration says where the context comes from, before any value is
/// in hand.
#[test]
fn a_plan_says_where_its_context_comes_from() {
    let users = users_plan();
    assert_eq!(
        users.label().map(ToString::to_string).as_deref(),
        Some("users")
    );
    assert_eq!(users.context_field(), None);
    let records = records_plan();
    assert_eq!(records.label(), None);
    assert_eq!(records.context_field(), Some("tenant"));
    let shown = records.contexts().unwrap().to_string();
    assert!(shown.contains("tenant"), "{shown}");
}
