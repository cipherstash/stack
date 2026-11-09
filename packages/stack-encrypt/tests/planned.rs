//! A value under a plan that is data (#1486): `Planned` is a target, so
//! the owned entry points encrypt a record under a `Plan`, decrypt a stored
//! row, and derive a query term under a `QueryPlan`, each with the caller's
//! context as the one context argument. The dynamic field handle checks
//! each operator against the plan where it is called. A query from a plan
//! that is data derives the same term a typed query from a field marker
//! does, under the same scope.
#![cfg(all(feature = "dynamic", feature = "testing"))]

mod common;

use std::sync::atomic::Ordering;

use common::frames::{frame, object};
use miette::Diagnostic as _;
use stack_encrypt::dynamic::{
    self, record, Op, Operand, Planned, QueryTerm, TargetDescriptor, TargetError, TargetResolver,
    ValueFrame, ValueKind,
};
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DeclaredContext, DecryptSource, EncryptTarget, IndexSpec, Scope};
use stack_encrypt::{
    nonempty, AsProtectedRef, DecryptFrom, EncryptInto, Encrypted, Error, KeysetCipher, Label,
    Pending, PlanError, StackCipher, StackCipherText,
};
use zeroize::Zeroize;

/// The plaintext row, as a decrypted frame reads back. Plan order is the
/// field names' order, so the frame is compared by value, not by bytes.
#[derive(Debug, PartialEq, serde::Deserialize)]
struct Row {
    email: String,
    age: u32,
}

fn row_of(frame: &ValueFrame) -> Row {
    vitaminc_aead_frame::serde::from_slice(frame.risky_ref()).expect("an object of the two fields")
}

fn ada_row() -> Row {
    Row {
        email: "ada@example.com".into(),
        age: 36,
    }
}

async fn cipher() -> StackCipher<FakeDataKeySource> {
    StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await
        .unwrap()
}

/// A data plan read from its JSON declaration, with no EQL types.
fn plan_of(declaration: serde_json::Value) -> record::Plan {
    let declaration = vitaminc_aead_frame::serde::to_vec(&declaration).unwrap();
    record::plan(declaration.as_protected_ref()).unwrap()
}

/// The data plan of a record with a searchable email and an ordered age,
/// each field under its own context.
fn plan() -> record::Plan {
    plan_of(serde_json::json!({
        "email": { "context": ["users", "email"], "outputs": ["c", "eq"], "type": "string" },
        "age": { "context": ["users", "age"], "outputs": ["c", "ore"], "type": "uint32" },
    }))
}

/// A resolver holding one EQL type, `Some`, that answers `eq`, whose query
/// is a fixed JSON value: what a target field's query term carries.
struct OneType;

impl TargetResolver for OneType {
    fn targets(&self) -> Vec<TargetDescriptor> {
        vec![TargetDescriptor::new(
            "Some",
            "some",
            "",
            Some(ValueKind::String),
            "public.some",
            vec!["eq".to_owned()],
            Some("SomeQuery".to_owned()),
            Some("eql_v3.query_some".to_owned()),
            true,
            None,
        )]
    }
    fn encrypt<'a, K: 'static>(
        &self,
        _: &str,
        _: Option<&dynamic::TargetOptions>,
        _: &'a KeysetCipher<'_, K>,
        _: &Label,
        _: ValueFrame,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        unreachable!("these tests query, and encrypt nothing")
    }
    fn decrypt<'a, K: 'static>(
        &self,
        _: &str,
        _: &'a StackCipher<K>,
        _: &Label,
        _: &[u8],
    ) -> Result<Pending<'a, ValueFrame, K>, TargetError> {
        unreachable!("these tests query, and decrypt nothing")
    }
    fn query<'a, K: 'static>(
        &self,
        _: &str,
        _: &IndexSpec,
        keyset: &'a KeysetCipher<'_, K>,
        _: &Label,
        _: ValueFrame,
    ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
        Ok(Pending::ready(keyset, Ok(br#"{"hm":"00"}"#.to_vec())))
    }
}

/// The data plan of a record whose email names the EQL type `Some`.
fn target_plan() -> record::Plan {
    let declaration = vitaminc_aead_frame::serde::to_vec(&serde_json::json!({
        "email": { "context": ["users", "email"], "target": "Some" },
    }))
    .unwrap();
    record::plan_with(declaration.as_protected_ref(), &OneType).unwrap()
}

fn ada() -> ValueFrame {
    object(vec![
        ("email", frame("ada@example.com")),
        ("age", frame(36u32)),
    ])
}

/// The dynamic error inside an owned-path failure.
fn dynamic_error(error: &Error) -> &dynamic::Error {
    match error {
        Error::Other(inner) => inner
            .downcast_ref::<dynamic::Error>()
            .unwrap_or_else(|| panic!("not a dynamic error: {inner}")),
        other => panic!("not an owned-path failure: {other}"),
    }
}

// The typed record the data plan above describes, for the equivalence
// checks: the derive seals `email` under `("users", "email")` extended by
// the caller's tenant, as the plan's field is extended by the caller's
// scope.
#[derive(Clone, Zeroize)]
struct User {
    email: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users", scope(tenant: u64))]
struct EncryptedUser {
    email: Encrypted<EqualityTerm>,
}

mod a_record_under_a_plan {
    use super::*;

    #[tokio::test]
    async fn round_trips_with_no_caller_context() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = plan();
        let row: StackCipherText = Planned::new(&plan, ada())
            .encrypt_into(&keyset)
            .await
            .unwrap();
        let back = ValueFrame::decrypt_from(Planned::new(&plan, row), &keyset)
            .await
            .unwrap();
        assert_eq!(row_of(&back), ada_row());
    }

    /// A row written under the tenant and bound to its row ID.
    async fn bound_row(
        keyset: &stack_encrypt::KeysetCipher<'_, FakeDataKeySource>,
    ) -> StackCipherText {
        Planned::new(&plan(), ada())
            .encrypt_into_with_context(keyset, Scope::new(42u64).bind(9u128))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn round_trips_under_a_scope_and_a_binding() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = plan();
        let row = bound_row(&keyset).await;
        let back = ValueFrame::decrypt_from_with_context(
            Planned::new(&plan, row),
            &keyset,
            Scope::new(42u64).bind(9u128),
        )
        .await
        .unwrap();
        assert_eq!(row_of(&back), ada_row());
    }

    #[tokio::test]
    async fn does_not_open_under_another_context() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = plan();
        // Another row's binding, another tenant, or no context: the row
        // does not open.
        for wrong in [
            Scope::new(42u64).bind(10u128),
            Scope::new(43u64).bind(9u128),
        ] {
            let row = bound_row(&keyset).await;
            let refused =
                ValueFrame::decrypt_from_with_context(Planned::new(&plan, row), &keyset, wrong)
                    .await;
            assert!(refused.is_err());
        }
        let row = bound_row(&keyset).await;
        assert!(ValueFrame::decrypt_from(Planned::new(&plan, row), &keyset)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn takes_a_binding_alone() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = plan();
        let row: StackCipherText = Planned::new(&plan, ada())
            .encrypt_into_with_context(&keyset, stack_encrypt::target::Bind::new(9u128))
            .await
            .unwrap();
        let back = ValueFrame::decrypt_from_with_context(
            Planned::new(&plan, row),
            &keyset,
            stack_encrypt::target::Bind::new(9u128),
        )
        .await
        .unwrap();
        assert_eq!(row_of(&back), ada_row());
    }

    #[tokio::test]
    async fn refuses_an_empty_part_before_any_key_is_requested() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = plan();
        let refused = Planned::new(&plan, ada())
            .encrypt_into_with_context::<StackCipherText, _>(&keyset, Scope::new(""))
            .await;
        assert!(refused.is_err(), "{refused:?}");
    }

    #[test]
    fn shows_every_fields_context_with_the_callers_placeholder() {
        let plan = plan();
        let contexts = Planned::new(&plan, ada()).contexts().unwrap();
        assert_eq!(
            contexts.to_string(),
            "age\n  query context:  (users / age) / {scope?: CallerContext}\n  \
             stored context: ((users / age) / {scope?: CallerContext}) / {bind?: CallerContext}\n\
             email\n  query context:  (users / email) / {scope?: CallerContext}\n  \
             stored context: ((users / email) / {scope?: CallerContext}) / {bind?: CallerContext}\n"
        );
    }

    #[test]
    fn shows_the_plans_own_parts_before_the_callers() {
        let plan = plan_of(serde_json::json!({
            "email": { "context": [["users", "email"], 5], "outputs": ["c", "eq"], "type": "string" },
            "bind": [7],
        }));
        let contexts = Planned::new(&plan, ada()).contexts().unwrap();
        assert_eq!(
            contexts.to_string(),
            "email\n  query context:  ((users / email) / 5u64) / {scope?: CallerContext}\n  \
             stored context: ((((users / email) / 5u64) / {scope?: CallerContext}) / 7u64) / {bind?: CallerContext}\n"
        );
    }

    #[tokio::test]
    async fn runs_the_plans_own_scope_before_the_callers() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = plan_of(serde_json::json!({
            "email": { "context": [["users", "email"], 5], "outputs": ["c", "eq"], "type": "string" },
        }));
        let by_email = plan.query("email", Op::Eq).unwrap();
        let term: QueryTerm = Planned::new(&by_email, frame("ada@example.com"))
            .encrypt_into_with_context(&keyset, Scope::new(42u64))
            .await
            .unwrap();
        // The plan's part, then the caller's: `users/email/5/42`.
        let direct: Encrypted<EqualityTerm> = String::from("ada@example.com")
            .encrypt_into_with_context(
                &keyset,
                nonempty!("users").with("email").with(5u64).with(42u64),
            )
            .await
            .unwrap();
        assert_eq!(
            term.operand(),
            &Operand::One(direct.terms.as_bytes().to_vec())
        );
        // And a row written with the caller's scope opens under a plan
        // that spells both parts.
        let row: StackCipherText =
            Planned::new(&plan, object(vec![("email", frame("ada@example.com"))]))
                .encrypt_into_with_context(&keyset, Scope::new(42u64))
                .await
                .unwrap();
        let spelled = plan_of(serde_json::json!({
            "email": { "context": [[["users", "email"], 5], 42], "outputs": ["c", "eq"], "type": "string" },
        }));
        let back = ValueFrame::decrypt_from(Planned::new(&spelled, row), &keyset)
            .await
            .unwrap();
        assert_eq!(
            vitaminc_aead_frame::serde::from_slice::<serde_json::Value>(back.risky_ref()).unwrap(),
            serde_json::json!({"email": "ada@example.com"})
        );
    }

    #[tokio::test]
    async fn runs_the_plans_own_binding_before_the_callers() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = plan_of(serde_json::json!({
            "email": { "context": ["users", "email"], "outputs": ["c", "eq"], "type": "string" },
            "bind": [7],
        }));
        let row = || async {
            let row: StackCipherText =
                Planned::new(&plan, object(vec![("email", frame("ada@example.com"))]))
                    .encrypt_into_with_context(&keyset, Scope::new(42u64).bind(9u64))
                    .await
                    .unwrap();
            row
        };
        // The row opens under a plan whose bindings are the plan's, then
        // the caller's, and not the other way round.
        let in_order = plan_of(serde_json::json!({
            "email": { "context": [["users", "email"], 42], "outputs": ["c", "eq"], "type": "string" },
            "bind": [7, 9],
        }));
        assert!(
            ValueFrame::decrypt_from(Planned::new(&in_order, row().await), &keyset)
                .await
                .is_ok()
        );
        let reversed = plan_of(serde_json::json!({
            "email": { "context": [["users", "email"], 42], "outputs": ["c", "eq"], "type": "string" },
            "bind": [9, 7],
        }));
        assert!(
            ValueFrame::decrypt_from(Planned::new(&reversed, row().await), &keyset)
                .await
                .is_err()
        );
    }

    #[test]
    fn prints_neither_the_value_nor_the_plan() {
        let plan = plan();
        let shown = format!("{:?}", Planned::new(&plan, frame("a secret")));
        assert!(!shown.contains("secret"), "{shown}");
        assert!(!shown.contains("users"), "{shown}");
    }

    #[test]
    fn wipes_its_value() {
        // A frame wipes to no bytes; a `Planned` wipes its frame the same
        // way, and the owned entry points consume or read the frame in
        // place, so its buffer is wiped as it is dropped.
        let mut value = frame("a secret");
        value.zeroize();
        assert!(value.risky_ref().is_empty());
        let plan = plan();
        let mut planned = Planned::new(&plan, frame("a secret"));
        planned.zeroize();
        let shown = format!("{planned:?}");
        assert!(!shown.contains("secret"), "{shown}");
    }
}

mod a_query_plan {
    use super::*;

    #[test]
    fn is_refused_where_no_index_answers_the_operator() {
        let plan = plan();
        assert!(plan.query("email", Op::Eq).is_ok());
        assert!(plan.query("age", Op::Between).is_ok());
        let refused = plan.query("email", Op::Gt).unwrap_err();
        assert!(
            matches!(
                &refused,
                dynamic::Error::Source { field: Some(field), reason: dynamic::Reason::OperatorNotAnswered } if field == "email"
            ),
            "{refused}"
        );
        let missing = plan.query("name", Op::Eq).unwrap_err();
        assert!(
            matches!(
                &missing,
                dynamic::Error::Plan {
                    reason: dynamic::Reason::NoSuchField,
                    ..
                }
            ),
            "{missing}"
        );
    }

    #[test]
    fn names_its_field_and_operator_and_shows_the_fields_context() {
        let plan = plan();
        let by_email = plan.query("email", Op::Eq).unwrap();
        assert_eq!(by_email.field(), "email");
        assert_eq!(by_email.operator(), Op::Eq);
        assert_eq!(by_email.plan().fields().len(), 2);
        assert_eq!(
            by_email.contexts().unwrap().to_string(),
            "context: (users / email) / {scope?: CallerContext}\n"
        );
        assert_eq!(
            Planned::new(&by_email, frame("x")).contexts().unwrap(),
            by_email.contexts().unwrap()
        );
    }

    #[tokio::test]
    async fn derives_the_term_a_typed_marker_query_derives() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = plan();

        // The typed record, written under the tenant.
        let stored: EncryptedUser = User {
            email: "ada@example.com".into(),
        }
        .encrypt_into_with_context(&keyset, Scope::new(42u64))
        .await
        .unwrap();
        let typed = EncryptedUser::EMAIL
            .eq("ada@example.com")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(typed, stored.email.terms);

        // The query value under the query plan, by the same scope.
        let by_email = plan.query("email", Op::Eq).unwrap();
        let term: QueryTerm = Planned::new(&by_email, frame("ada@example.com"))
            .encrypt_into_with_context(&keyset, Scope::new(42u64))
            .await
            .unwrap();
        assert_eq!(term.operator(), Op::Eq);
        assert_eq!(term.operand(), &Operand::One(typed.as_bytes().to_vec()));

        // And through the field handle.
        let same: QueryTerm = plan
            .field("email")
            .unwrap()
            .eq(frame("ada@example.com"))
            .unwrap()
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(same, term);

        // Another tenant is another term.
        let other: QueryTerm = Planned::new(&by_email, frame("ada@example.com"))
            .encrypt_into_with_context(&keyset, Scope::new(43u64))
            .await
            .unwrap();
        assert_ne!(other, term);
    }

    #[tokio::test]
    async fn derives_a_range_with_one_term_per_bound() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = plan();
        let range: QueryTerm = plan
            .field("age")
            .unwrap()
            .between(frame(vec![18u32, 65]))
            .unwrap()
            .encrypt(&keyset)
            .await
            .unwrap();
        let lo: QueryTerm = Planned::new(&plan.query("age", Op::Gte).unwrap(), frame(18u32))
            .encrypt_into(&keyset)
            .await
            .unwrap();
        match (range.operand(), lo.operand()) {
            (Operand::Range { lo: low, .. }, Operand::One(bound)) => assert_eq!(low, bound),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn refuses_a_binding_before_any_key_is_requested() {
        let (cipher, generates, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let plan = plan();
        let by_email = plan.query("email", Op::Eq).unwrap();
        let refused = Planned::new(&by_email, frame("ada@example.com"))
            .encrypt_into_with_context::<QueryTerm, _>(&keyset, Scope::new(42u64).bind(9u128))
            .await
            .unwrap_err();
        // The crate's own refusal, with its code, as the typed query
        // reports it.
        assert!(
            matches!(refused, Error::Plan(PlanError::BindInQuery)),
            "{refused}"
        );
        assert_eq!(
            refused.code().unwrap().to_string(),
            "stack_encrypt::plan_bind_in_query"
        );

        // The handle has no `bind` method; a binding smuggled in through a
        // declared context is refused the same way.
        let bound = DeclaredContext::default().with(Scope::new(42u64).bind(9u128));
        let refused = plan
            .field("email")
            .unwrap()
            .eq(frame("ada@example.com"))
            .unwrap()
            .scope(bound)
            .encrypt(&keyset)
            .await
            .unwrap_err();
        assert!(
            matches!(refused, Error::Plan(PlanError::BindInQuery)),
            "{refused}"
        );
        assert_eq!(generates.load(Ordering::SeqCst), 0);
        assert_eq!(retrieves.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn keeps_a_refused_terms_kind_and_requests_no_key() {
        let (cipher, generates, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let plan = plan();
        let by_email = plan.query("email", Op::Eq).unwrap();
        let refused = Planned::new(&by_email, frame("ada\u{0378}@example.com"))
            .encrypt_into::<QueryTerm, _>(&keyset)
            .await
            .unwrap_err();
        assert!(matches!(refused, Error::Term(_)), "{refused}");
        let refused = plan
            .field("email")
            .unwrap()
            .eq(frame("ada\u{0378}@example.com"))
            .unwrap()
            .encrypt(&keyset)
            .await
            .unwrap_err();
        assert!(matches!(refused, Error::Term(_)), "{refused}");
        // An empty scope is refused as the typed path refuses it.
        let refused = Planned::new(&by_email, frame("ada@example.com"))
            .encrypt_into_with_context::<QueryTerm, _>(&keyset, Scope::new(""))
            .await
            .unwrap_err();
        assert!(matches!(refused, Error::Other(_)), "{refused}");
        assert_eq!(generates.load(Ordering::SeqCst), 0);
        assert_eq!(retrieves.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn derives_a_match_query_the_typed_path_derives() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = plan_of(serde_json::json!({
            "bio": { "context": ["users", "bio"], "outputs": ["c", "match"], "type": "string" },
        }));
        let term: QueryTerm = plan
            .field("bio")
            .unwrap()
            .matches(frame("engines"))
            .unwrap()
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        let typed: Encrypted<stack_encrypt::sem::MatchTerms> = String::from("engines")
            .encrypt_into_with_context(&keyset, nonempty!("users").with("bio").with(42u64))
            .await
            .unwrap();
        // A match query term is the filter of the query text under the
        // same context, which is what is stored for that text.
        assert_eq!(term.operator(), Op::Matches);
        assert_eq!(term.operand(), &Operand::One(typed.terms.to_bytes()));
    }
}

mod a_target_field {
    use super::*;

    #[tokio::test]
    async fn queries_through_the_handle_and_through_planned_with_its_resolver() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = target_plan();
        let through_handle: QueryTerm = plan
            .field_with("email", &OneType)
            .unwrap()
            .eq(frame("a"))
            .unwrap()
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(
            through_handle.operand(),
            &Operand::One(br#"{"hm":"00"}"#.to_vec())
        );
        assert_eq!(through_handle.domain(), Some("eql_v3.query_some"));
        let by_email = plan.query_with("email", Op::Eq, &OneType).unwrap();
        let through_planned: QueryTerm = Planned::with_resolver(&by_email, frame("a"), OneType)
            .encrypt_into(&keyset)
            .await
            .unwrap();
        assert_eq!(through_planned, through_handle);
    }

    #[test]
    fn is_refused_without_its_resolver() {
        let plan = target_plan();
        let refused = plan.field("email").unwrap().eq(frame("a")).unwrap_err();
        assert!(matches!(refused, dynamic::Error::Target(_)), "{refused}");
        assert!(matches!(
            plan.query("email", Op::Eq).unwrap_err(),
            dynamic::Error::Target(_)
        ));
    }

    #[tokio::test]
    async fn refuses_a_scope_it_cannot_be_stored_under() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = target_plan();
        let by_email = plan.query_with("email", Op::Eq, &OneType).unwrap();
        let refused = Planned::with_resolver(&by_email, frame("a"), OneType)
            .encrypt_into_with_context::<QueryTerm, _>(&keyset, Scope::new(1u64))
            .await
            .unwrap_err();
        assert!(
            matches!(
                dynamic_error(&refused),
                dynamic::Error::Target(TargetError::Extended { name, .. }) if name == "email"
            ),
            "{refused}"
        );
    }
}

mod a_field_handle {
    use super::*;

    #[test]
    fn is_refused_for_a_field_the_plan_does_not_have() {
        let plan = plan();
        let missing = plan.field("name").unwrap_err();
        assert!(
            matches!(
                &missing,
                dynamic::Error::Plan {
                    reason: dynamic::Reason::NoSuchField,
                    ..
                }
            ),
            "{missing}"
        );
        assert_eq!(plan.field("email").unwrap().name(), "email");
    }

    #[test]
    fn checks_each_operator_where_it_is_called() {
        let plan = plan();
        let email = plan.field("email").unwrap();
        assert!(email.clone().eq(frame("x")).is_ok());
        let refused = email.gt(frame("x")).unwrap_err();
        assert!(
            matches!(
                &refused,
                dynamic::Error::Source {
                    reason: dynamic::Reason::OperatorNotAnswered,
                    ..
                }
            ),
            "{refused}"
        );
        let age = plan.field("age").unwrap();
        assert!(age.clone().lt(frame(1u32)).is_ok());
        assert!(age.matches(frame("x")).is_err());
    }

    #[test]
    fn prints_the_field_and_operator_and_not_the_value() {
        let plan = plan();
        let query = plan.field("email").unwrap().eq(frame("a secret")).unwrap();
        let shown = format!("{query:?}");
        assert!(shown.contains("email") && shown.contains("Eq"), "{shown}");
        assert!(!shown.contains("secret"), "{shown}");
    }
}
