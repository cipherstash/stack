//! The contexts a declaration or a call uses, shown before any key is
//! requested (#1568).
//!
//! Each test pins the output of `contexts()` for one shape of declaration,
//! and states the same context with `assert_context!`. The shapes are the
//! context scenarios of the Stack Encrypt API plan that exist on `next`:
//! a static context (scenario 1), a context stored in the row, a nested
//! record, a target that takes the caller's context, a collection, and a
//! plan with each of its three context sources. The scenarios that need the
//! `scope(..)` and `bind(..)` attributes land with #1487.
#![cfg(feature = "testing")]

use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::plan::{Field, Fields, Operation as _};
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{DecryptSource, EncryptTarget, Encryption, RequiredContext};
use stack_encrypt::testing::{extension, from_plaintext, required, Expect};
use stack_encrypt::{
    assert_context, nonempty, ContextTree, DecryptFrom, EncryptInto, Encrypted, Equality, NonEmpty,
    Ore, Plan, StackCipher, StackCipherText,
};
use zeroize::Zeroize;

async fn cipher() -> StackCipher<FakeDataKeySource> {
    StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await
        .unwrap()
}

// Scenario 1: a static context only. Every field's context is the record's
// name and the field's name. The caller passes nothing.
#[derive(Clone, Zeroize)]
struct Settings {
    theme: String,
    notes: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Settings, scope = "settings")]
struct EncryptedSettings {
    theme: Encrypted<EqualityTerm>,
    notes: StackCipherText,
}

mod a_record_with_a_static_context {
    use super::*;

    #[test]
    fn shows_each_field_under_the_record_name_and_the_field_name() {
        assert_eq!(
            EncryptedSettings::contexts().to_string(),
            "theme\n  context: settings / theme\nnotes\n  context: settings / notes\n"
        );
    }

    #[test]
    fn is_pinned_with_assert_context() {
        assert_context!(
            EncryptedSettings::contexts(),
            theme = ["settings", "theme"],
            notes = ["settings", "notes"],
        );
    }

    #[test]
    #[should_panic(
        expected = "field `theme`: the context differs at part 2: expected `name`, found `theme`"
    )]
    fn names_the_first_part_that_differs() {
        assert_context!(EncryptedSettings::contexts(), theme = ["settings", "name"]);
    }

    #[test]
    #[should_panic(expected = "the declaration has no field `colour`")]
    fn refuses_a_field_the_record_does_not_have() {
        assert_context!(
            EncryptedSettings::contexts(),
            colour = ["settings", "colour"]
        );
    }

    #[tokio::test]
    async fn a_call_uses_the_contexts_the_declaration_shows() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let settings = Settings {
            theme: "dark".into(),
            notes: "none".into(),
        };
        let call = settings.encrypt_into::<EncryptedSettings, _>(&keyset);
        assert_eq!(
            call.context().to_string(),
            "context: settings / theme\ncontext: settings / notes\n"
        );
        let contexts = EncryptedSettings::contexts();
        let shown: Vec<&ContextTree> = contexts.fields().iter().map(|f| f.context()).collect();
        assert_eq!(call.context().contexts().iter().collect::<Vec<_>>(), shown);
        let stored = call.await.unwrap();

        // The read uses the same contexts, with no caller value either.
        let open = Settings::decrypt_from(stored, &keyset);
        assert_eq!(
            open.context().to_string(),
            "context: settings / theme\ncontext: settings / notes\n"
        );
        let back = open.await.unwrap();
        assert_eq!(back.theme, "dark");
    }
}

// A context stored in the row: the caller passes a `NonEmpty<String>`, the
// record stores it in `column`, and every other field is sealed or indexed
// under it.
#[derive(EncryptTarget, DecryptSource)]
#[stash(plaintext = String)]
struct Stored {
    #[stash(context_field)]
    column: String,
    hm: EqualityTerm,
    c: StackCipherText,
}

mod a_record_that_stores_its_context {
    use super::*;

    #[test]
    fn shows_the_caller_part_as_a_typed_placeholder() {
        assert_eq!(
            Stored::contexts().to_string(),
            "hm\n  context: {context: NonEmpty<String>}\nc\n  context: {context: NonEmpty<String>}\n"
        );
        assert_context!(
            Stored::contexts(),
            hm = [required::<NonEmpty<String>>()],
            c = [required::<NonEmpty<String>>()],
        );
    }

    #[tokio::test]
    async fn a_call_fills_the_placeholder_in() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let call = String::from("ada").encrypt_into_with_context::<Stored, _>(
            &keyset,
            NonEmpty::new("users/email".to_owned()).unwrap(),
        );
        // One context for both leaves: the text is not plain, so it is quoted.
        assert_eq!(call.context().to_string(), "context: \"users/email\"\n");
        assert_context!(call.context(), ["users/email"]);
        let _stored = call.await.unwrap();
    }
}

// A nested record: the inner record's fields are sealed under their own
// context, extended by the outer field's. The field names are joined.
#[derive(Clone, Zeroize)]
struct Account {
    owner: Settings,
    label: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Account, scope = "accounts")]
struct EncryptedAccount {
    owner: EncryptedSettings,
    label: StackCipherText,
}

mod a_nested_record {
    use super::*;

    #[test]
    fn extends_each_inner_context_by_the_outer_field() {
        assert_eq!(
            EncryptedAccount::contexts().to_string(),
            "owner.theme\n  context: (settings / theme) / (accounts / owner)\n\
             owner.notes\n  context: (settings / notes) / (accounts / owner)\n\
             label\n  context: accounts / label\n"
        );
    }

    #[tokio::test]
    async fn the_call_agrees() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let account = Account {
            owner: Settings {
                theme: "dark".into(),
                notes: "none".into(),
            },
            label: "main".into(),
        };
        let call = account.encrypt_into::<EncryptedAccount, _>(&keyset);
        assert_eq!(
            call.context().to_string(),
            "context: (settings / theme) / (accounts / owner)\n\
             context: (settings / notes) / (accounts / owner)\n\
             context: accounts / label\n"
        );
        let _stored = call.await.unwrap();
    }
}

mod a_target_that_takes_the_callers_context {
    use super::*;

    #[test]
    fn shows_the_whole_context_as_the_callers() {
        let contexts =
            <Encrypted<EqualityTerm> as EncryptTarget<String>>::encryption::<()>().contexts();
        assert_eq!(contexts.to_string(), "context: {context: CallerContext}\n");
        assert_context!(
            contexts,
            [required::<stack_encrypt::target::CallerContext>()]
        );
    }

    #[tokio::test]
    async fn a_call_shows_the_value_with_its_types() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let column = nonempty!("users").with("email").with(7u64);
        let call = String::from("ada")
            .encrypt_into_with_context::<Encrypted<EqualityTerm>, _>(&keyset, column);
        assert_eq!(
            call.context().to_string(),
            "context: (users / email) / 7u64\n"
        );
        assert_context!(call.context(), [["users", "email"], 7u64]);
        let _ = call.await.unwrap();
    }

    #[tokio::test]
    #[allow(
        clippy::needless_borrows_for_generic_args,
        reason = "passing the context by reference is what this test checks"
    )]
    async fn a_borrowed_context_is_the_same_context() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let column = nonempty!("users").with("email");
        // By reference: `column` is still usable after the call.
        let by_ref: Encrypted<EqualityTerm> = String::from("ada")
            .encrypt_into_with_context(&keyset, &column)
            .await
            .unwrap();
        let by_value: Encrypted<EqualityTerm> = String::from("ada")
            .encrypt_into_with_context(&keyset, column)
            .await
            .unwrap();
        assert_eq!(by_ref.terms, by_value.terms);
    }
}

mod a_collection {
    use super::*;

    #[test]
    fn has_the_contexts_of_its_element() {
        assert_eq!(
            <Vec<EncryptedSettings> as EncryptTarget<Vec<Settings>>>::encryption::<()>().contexts(),
            EncryptedSettings::contexts()
        );
        assert_eq!(
            <Option<EncryptedSettings> as EncryptTarget<Option<Settings>>>::encryption::<()>()
                .contexts(),
            EncryptedSettings::contexts()
        );
    }

    #[test]
    fn a_passthrough_alone_seals_nothing() {
        let contexts = stack_encrypt::target::passthrough::<
            String,
            (),
            stack_encrypt::target::Borrowed,
            RequiredContext<stack_encrypt::target::CallerContext>,
        >()
        .contexts();
        assert!(contexts.is_empty());
        assert_eq!(contexts.to_string(), "no field is sealed or indexed\n");
    }
}

struct User {
    email: String,
    age: u32,
    id: u64,
    tenant: String,
}
impl Fields for User {
    fn field_names(&self) -> Vec<&str> {
        vec!["email", "age", "id", "tenant"]
    }
}
impl Field<String> for User {
    fn field(&self, name: &str) -> Option<&String> {
        match name {
            "email" => Some(&self.email),
            "tenant" => Some(&self.tenant),
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

mod a_plan {
    use super::*;

    #[test]
    fn with_its_own_context_shows_the_extension_a_run_may_add() {
        let plan: Plan<User, FakeDataKeySource> = Plan::context("users")
            .fields()
            .encrypt_index::<String>("email", Equality)
            .encrypt_index::<u32>("age", (Equality, Ore))
            .passthrough::<u64>("id")
            .build()
            .unwrap();
        assert_eq!(
            plan.contexts().to_string(),
            "email\n  context: (users / email) / {extension?: CallerContext}\n\
             age\n  context: (users / age) / {extension?: CallerContext}\n"
        );
        assert_context!(
            plan.contexts(),
            email = [["users", "email"], extension()],
            age = [["users", "age"], extension()],
        );
    }

    #[test]
    fn built_without_a_context_shows_the_label_the_call_names() {
        let plan: Plan<User, FakeDataKeySource> = Plan::fields()
            .encrypt_index::<String>("email", Equality)
            .build()
            .unwrap();
        assert_eq!(
            plan.contexts().to_string(),
            "email\n  context: ({context: Label} / email) / {extension?: CallerContext}\n"
        );
    }

    #[test]
    fn with_a_context_field_shows_where_the_context_is_read_from() {
        let plan: Plan<User, FakeDataKeySource> = Plan::fields()
            .context_field::<String>("tenant")
            .encrypt_index::<String>("email", Equality)
            .build()
            .unwrap();
        assert_eq!(
            plan.contexts().to_string(),
            "email\n  context: ({tenant: Label, from the plaintext} / email) / {extension?: CallerContext}\n"
        );
        assert_context!(
            plan.contexts(),
            email = [
                [
                    Expect::from(from_plaintext::<stack_encrypt::Label>("tenant")),
                    Expect::from("email"),
                ],
                extension(),
            ],
        );
    }

    #[tokio::test]
    async fn a_run_fills_the_extension_in() {
        let cipher = cipher().await;
        let plan: Plan<User, FakeDataKeySource> = Plan::context("users")
            .fields()
            .encrypt_index::<String>("email", Equality)
            .passthrough::<u32>("age")
            .passthrough::<u64>("id")
            .passthrough::<String>("tenant")
            .build()
            .unwrap();
        let user = User {
            email: "ada@example.com".into(),
            age: 36,
            id: 7,
            tenant: "acme".into(),
        };
        let keyset = cipher.default_keyset();
        let call = cipher
            .encrypt(&user)
            .using(&plan)
            .extend(nonempty!("acme"))
            .prepare(&keyset, false);
        let shown = call.context();
        let record = call.await;
        assert!(record.is_ok(), "{record:?}");
        assert_eq!(shown.to_string(), "context: (users / email) / acme\n");
    }
}

#[cfg(feature = "dynamic")]
mod a_data_plan {
    use super::*;
    use stack_encrypt::dynamic::record::{FieldPlan, Output, Plan as DataPlan};
    use stack_encrypt::dynamic::ValueKind;
    use stack_encrypt::target::IndexSpec;
    use stack_encrypt::{Describe as _, Label};

    #[test]
    fn shows_the_same_contexts_as_the_typed_plan_it_lowers_to() {
        let label = NonEmpty::new(Label::parse("users/email").unwrap().to_context()).unwrap();
        let email = FieldPlan::new(
            "email",
            label,
            vec![Output::Ciphertext, Output::Term(IndexSpec::Equality)],
        )
        .unwrap()
        .with_type(ValueKind::String)
        .unwrap();
        let plan = DataPlan::new(vec![email]).unwrap();
        assert_eq!(
            plan.contexts().unwrap().to_string(),
            "email\n  context: users / email\n"
        );
    }
}

/// A description built by hand shows its leaf under the caller's context,
/// and a description that is mapped keeps its contexts.
#[test]
fn a_mapped_description_keeps_its_contexts() {
    let description: Encryption<'_, String, usize, (), _> =
        <Encrypted<EqualityTerm> as EncryptTarget<String>>::encryption::<()>()
            .map(|encrypted| encrypted.terms.to_bytes().len());
    assert_eq!(
        description.contexts().to_string(),
        "context: {context: CallerContext}\n"
    );
}
