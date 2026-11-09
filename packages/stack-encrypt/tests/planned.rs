//! A value under a plan that is data (#1486): `Planned` is a target, so
//! the owned entry points encrypt a record under a `Plan`, decrypt a stored
//! row, and derive a query term under a `QueryPlan`, each with the caller's
//! context as the one context argument. The dynamic field handle checks
//! each operator against the plan where it is called. A query from a plan
//! that is data derives the same term a typed query from a field marker
//! does, under the same scope.
#![cfg(all(feature = "dynamic", feature = "testing"))]

mod common;

use common::frames::{frame, object};
use stack_encrypt::dynamic::{self, record, Op, Operand, Planned, QueryTerm, ValueFrame};
use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DeclaredContext, DecryptSource, EncryptTarget, Scope};
use stack_encrypt::{
    AsProtectedRef, DecryptFrom, EncryptInto, Encrypted, Error, StackCipher, StackCipherText,
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

/// The data plan of a record with a searchable email and an ordered age,
/// each field under its own context.
fn plan() -> record::Plan {
    let declaration = vitaminc_aead_frame::serde::to_vec(&serde_json::json!({
        "email": { "context": ["users", "email"], "outputs": ["c", "eq"], "type": "string" },
        "age": { "context": ["users", "age"], "outputs": ["c", "ore"], "type": "uint32" },
    }))
    .unwrap();
    record::plan(declaration.as_protected_ref()).unwrap()
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
            "age\n  context: (users / age) / {context?: CallerContext}\n\
             email\n  context: (users / email) / {context?: CallerContext}\n"
        );
    }

    #[test]
    fn shows_the_plans_own_parts_before_the_callers() {
        let declaration = vitaminc_aead_frame::serde::to_vec(&serde_json::json!({
            "email": { "context": ["users", "email"], "outputs": ["c", "eq"], "type": "string" },
            "bind": [7],
        }))
        .unwrap();
        let plan = record::plan(declaration.as_protected_ref()).unwrap();
        let contexts = Planned::new(&plan, ada()).contexts().unwrap();
        assert_eq!(
            contexts.to_string(),
            "email\n  query context:  (users / email) / {context?: CallerContext}\n  \
             stored context: ((users / email) / {context?: CallerContext}) / 7u64\n"
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
        let mut value = frame("a secret");
        value.zeroize();
        assert!(value.risky_ref().is_empty());
        let plan = plan();
        let mut planned = Planned::new(&plan, frame("a secret"));
        planned.zeroize();
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
            "context: users / email\n"
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
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let plan = plan();
        let by_email = plan.query("email", Op::Eq).unwrap();
        let refused = Planned::new(&by_email, frame("ada@example.com"))
            .encrypt_into_with_context::<QueryTerm, _>(&keyset, Scope::new(42u64).bind(9u128))
            .await
            .unwrap_err();
        assert!(
            matches!(
                dynamic_error(&refused),
                dynamic::Error::Plan {
                    reason: dynamic::Reason::BindInQuery,
                    ..
                }
            ),
            "{refused}"
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
            matches!(
                dynamic_error(&refused),
                dynamic::Error::Plan {
                    reason: dynamic::Reason::BindInQuery,
                    ..
                }
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
