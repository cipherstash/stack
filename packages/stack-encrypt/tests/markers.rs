//! Field markers (#1486): the value a typed query of a derived record's
//! field starts from. `#[derive(EncryptTarget)]` on a `struct = ..` record
//! emits `EncryptedUser::EMAIL` for a field `email`. A query from the
//! marker derives under the context the derive sealed the field under, so
//! the query term is the stored term; the marker's operator methods exist
//! only where the field's indexes answer the operator; and a record that
//! lists a caller scope gives its markers that scope's type, so the query
//! cannot run without it.
#![cfg(feature = "testing")]

mod common;

use std::sync::atomic::Ordering;

use stack_encrypt::kms::FakeDataKeySource;
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OreTerm};
use stack_encrypt::target::{DecryptSource, EncryptTarget, NoScope, Scope};
use stack_encrypt::testing::{scope, stored_scope};
use stack_encrypt::{
    assert_context, nonempty, DecryptFrom, EncryptInto, Encrypted, Error, Marker, StackCipher,
    StackCipherText,
};
use zeroize::Zeroize;

async fn cipher() -> StackCipher<FakeDataKeySource> {
    StackCipher::builder()
        .kms(FakeDataKeySource::new())
        .init()
        .await
        .unwrap()
}

#[derive(Clone, Zeroize)]
struct User {
    email: String,
    age: u32,
    bio: String,
}

fn ada() -> User {
    User {
        email: "ada@example.com".into(),
        age: 36,
        bio: "Analytical engines and their programs".into(),
    }
}

/// A record whose caller supplies a tenant scope on every call.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "users", scope(tenant: u64))]
struct EncryptedUser {
    email: Encrypted<EqualityTerm>,
    age: Encrypted<OreTerm<u32>>,
    bio: Encrypted<MatchTerms>,
}

/// A record with no caller part, a field keyed under another identity,
/// and a field that is a ciphertext alone.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = User, scope = "people")]
struct Renamed {
    #[stash(identity = "mail")]
    email: Encrypted<EqualityTerm>,
    age: Encrypted<OreTerm<u32>>,
    bio: StackCipherText,
}

/// A record whose scope is stored in the row: the plaintext carries it,
/// and a query supplies it.
#[derive(Clone, Zeroize)]
struct TenantUser {
    tenant: u64,
    email: String,
}

#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = TenantUser, scope = "users", scope(field = "tenant"))]
struct StoredTenant {
    #[stash(passthrough)]
    tenant: u64,
    email: Encrypted<EqualityTerm>,
}

/// A record with a raw-identifier field and a field that is a record.
#[derive(Clone, Zeroize)]
struct Address {
    street: String,
}

#[derive(Clone, Zeroize)]
struct Account {
    r#type: String,
    address: Address,
}

#[derive(EncryptTarget)]
#[stash(struct = Address, scope = "addresses")]
#[allow(dead_code)]
struct EncryptedAddress {
    street: Encrypted<EqualityTerm>,
}

#[derive(EncryptTarget)]
#[stash(struct = Account, scope = "accounts")]
#[allow(dead_code)]
struct EncryptedAccount {
    r#type: Encrypted<EqualityTerm>,
    address: EncryptedAddress,
}

mod a_marker {
    use super::*;

    #[test]
    fn names_its_field_and_the_context_the_derive_sealed_it_under() {
        assert_eq!(EncryptedUser::EMAIL.name(), "email");
        assert_eq!(EncryptedUser::EMAIL.label().to_string(), "users/email");
        assert_eq!(EncryptedUser::AGE.label().to_string(), "users/age");
        // An identity replaces the segment, and the name stays the field's.
        assert_eq!(Renamed::EMAIL.name(), "email");
        assert_eq!(Renamed::EMAIL.label().to_string(), "people/mail");
    }

    #[test]
    fn shows_the_fields_context_with_the_callers_placeholder() {
        assert_context!(
            EncryptedUser::EMAIL,
            [["users", "email"], scope::<u64>("tenant")]
        );
        assert_context!(Renamed::EMAIL, ["people", "mail"]);
        assert_context!(
            StoredTenant::EMAIL,
            [["users", "email"], stored_scope::<u64>("tenant")]
        );
        assert_eq!(
            EncryptedUser::AGE.contexts().to_string(),
            "context: (users / age) / {tenant: u64}\n"
        );
        // The marker's context is the record's entry for the field.
        assert_eq!(
            EncryptedUser::contexts().get("email"),
            EncryptedUser::EMAIL.contexts().single()
        );
    }

    #[test]
    #[should_panic(expected = "the context differs at part 1: expected `members`, found `people`")]
    fn is_pinned_with_assert_context() {
        assert_context!(Renamed::EMAIL, ["members", "mail"]);
    }

    #[test]
    fn carries_the_type_of_the_scope_its_caller_supplies() {
        let scoped: Marker<Encrypted<EqualityTerm>, Scope<u64>> = EncryptedUser::EMAIL;
        let stored: Marker<Encrypted<EqualityTerm>, Scope<u64>> = StoredTenant::EMAIL;
        let unscoped: Marker<Encrypted<EqualityTerm>, NoScope> = Renamed::EMAIL;
        assert_eq!(scoped.name(), stored.name());
        assert_eq!(unscoped.name(), "email");
    }

    #[test]
    fn keeps_a_raw_identifiers_name() {
        // The constant drops the `r#`; the name and the context keep it,
        // as `contexts()` and the label spell the field.
        assert_eq!(EncryptedAccount::TYPE.name(), "r#type");
        assert_eq!(
            EncryptedAccount::TYPE.label().to_string(),
            "accounts/r#type"
        );
        assert_context!(EncryptedAccount::TYPE, ["accounts", "r#type"]);
    }

    #[test]
    fn on_a_record_field_lists_the_inner_fields() {
        let address = EncryptedAccount::ADDRESS;
        assert_eq!(address.label().to_string(), "accounts/address");
        assert_eq!(
            address.contexts().to_string(),
            "street\n  context: (addresses / street) / (accounts / address)\n"
        );
        assert_eq!(address.contexts().fields().len(), 1);
        assert!(address.contexts().single().is_none());
    }

    #[test]
    fn is_a_plain_value() {
        let marker = EncryptedUser::EMAIL;
        let copy = marker;
        assert_eq!(copy.name(), marker.name());
        let shown = format!("{marker:?}");
        assert!(
            shown.contains("\"email\"") && shown.contains("\"users\""),
            "{shown}"
        );
    }
}

mod a_marker_query {
    use super::*;

    #[tokio::test]
    async fn derives_the_stored_equality_term_under_the_scope() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedUser = ada()
            .encrypt_into_with_context(&keyset, Scope::new(42u64))
            .await
            .unwrap();

        let term = EncryptedUser::EMAIL
            .eq("ada@example.com")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.email.terms);

        // Another tenant, or another value, is another term.
        let other_tenant = EncryptedUser::EMAIL
            .eq("ada@example.com")
            .scope(Scope::new(43u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_ne!(other_tenant, stored.email.terms);
        let other_value = EncryptedUser::EMAIL
            .eq("bob@example.com")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_ne!(other_value, stored.email.terms);
    }

    #[tokio::test]
    async fn derives_the_stored_order_term_at_each_bound() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedUser = ada()
            .encrypt_into_with_context(&keyset, Scope::new(42u64))
            .await
            .unwrap();

        // A bound equal to the stored value derives the stored term.
        let at_36 = EncryptedUser::AGE
            .gte(36u32)
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(at_36, stored.age.terms);

        // A range carries one term per bound, each as the stored term of
        // that value would be.
        let adults = EncryptedUser::AGE
            .between(18u32, 36u32)
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(adults.hi(), &stored.age.terms);
        let at_18: Encrypted<OreTerm<u32>> = 18u32
            .encrypt_into_with_context(&keyset, nonempty!("users").with("age").with(42u64))
            .await
            .unwrap();
        assert_eq!(adults.lo(), &at_18.terms);
    }

    #[tokio::test]
    async fn matches_the_stored_text_under_the_scope() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedUser = ada()
            .encrypt_into_with_context(&keyset, Scope::new(42u64))
            .await
            .unwrap();
        let query = EncryptedUser::BIO
            .matches("engines")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert!(stored.bio.terms.matches(&query));
        let elsewhere = EncryptedUser::BIO
            .matches("engines")
            .scope(Scope::new(43u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert!(!stored.bio.terms.matches(&elsewhere));
    }

    #[tokio::test]
    async fn takes_no_scope_for_a_record_with_no_caller_part() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: Renamed = ada().encrypt_into(&keyset).await.unwrap();
        let term = Renamed::EMAIL
            .eq("ada@example.com")
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.email.terms);
        let direct: Encrypted<EqualityTerm> = String::from("ada@example.com")
            .encrypt_into_with_context(&keyset, nonempty!("people").with("mail"))
            .await
            .unwrap();
        assert_eq!(term, direct.terms);
    }

    #[tokio::test]
    async fn supplies_a_scope_the_record_stores_in_the_row() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: StoredTenant = TenantUser {
            tenant: 42,
            email: "ada@example.com".into(),
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        assert_eq!(stored.tenant, 42);
        let term = StoredTenant::EMAIL
            .eq("ada@example.com")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.email.terms);
    }

    #[tokio::test]
    async fn refuses_text_with_no_normal_form_and_requests_no_key() {
        let (cipher, generates, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let refused = EncryptedUser::EMAIL
            .eq("ada\u{0378}@example.com")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await;
        assert!(matches!(refused, Err(Error::Term(_))), "{refused:?}");
        assert_eq!(generates.load(Ordering::SeqCst), 0);
        assert_eq!(retrieves.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn refuses_an_empty_scope_and_requests_no_key() {
        let (cipher, generates, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let refused = EncryptedUser::EMAIL
            .eq("ada@example.com")
            .scope(Scope::new(0u64))
            .encrypt(&keyset)
            .await;
        assert!(refused.is_ok(), "zero is a value, not an empty part");
        assert_eq!(generates.load(Ordering::SeqCst), 0);
        assert_eq!(retrieves.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn is_the_query_the_record_opens_for() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedUser = ada()
            .encrypt_into_with_context(&keyset, Scope::new(42u64))
            .await
            .unwrap();
        let term = EncryptedUser::EMAIL
            .eq("ada@example.com")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.email.terms);
        let back = User::decrypt_from_with_context(stored, &keyset, Scope::new(42u64))
            .await
            .unwrap();
        assert_eq!(back.email, "ada@example.com");
    }

    #[test]
    fn prints_its_label_and_not_the_value() {
        let query = EncryptedUser::EMAIL.eq("a secret");
        let shown = format!("{query:?}");
        assert!(
            shown.contains("users") && shown.contains("email"),
            "{shown}"
        );
        assert!(!shown.contains("secret"), "{shown}");
        // Dropped before it is encrypted: the copy is wiped, not leaked.
        drop(query);
    }
}
