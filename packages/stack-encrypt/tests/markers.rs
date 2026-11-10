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
use stack_encrypt::marker::{Nested, Root, Takes, TakesAny};
use stack_encrypt::sem::{EqualityTerm, MatchTerms, OreBlockTerm, OreTerm};
use stack_encrypt::target::{DecryptSource, EncryptTarget, NoScope, Scope};
use stack_encrypt::testing::{scope, stored_scope};
use stack_encrypt::{
    assert_context, nonempty, DecryptFrom, EncryptInto, Encrypted, Error, KeysetCipher, Marker,
    PlanError, StackCipher, StackCipherText,
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
struct EncryptedAddress {
    street: Encrypted<EqualityTerm>,
}

#[derive(EncryptTarget)]
#[stash(struct = Account, scope = "accounts")]
struct EncryptedAccount {
    r#type: Encrypted<EqualityTerm>,
    address: EncryptedAddress,
}

/// A record whose fields are of several indexes, nullable, and of a
/// stated query type.
#[derive(Clone, Zeroize)]
struct Person {
    email: String,
    nick: Option<String>,
    age: u32,
}

#[derive(EncryptTarget)]
#[stash(struct = Person, scope = "people", scope(tenant: u64))]
struct EncryptedPerson {
    #[stash(query = String)]
    email: Encrypted<(EqualityTerm, MatchTerms, OreTerm<String>)>,
    #[stash(query = String)]
    nick: Option<Encrypted<EqualityTerm>>,
    age: Encrypted<(EqualityTerm, OreTerm<u32>)>,
}

fn person(nick: Option<&str>) -> Person {
    Person {
        email: "ada@example.com".into(),
        nick: nick.map(str::to_owned),
        age: 36,
    }
}

/// A record field under a record with a caller scope.
#[derive(Clone, Zeroize)]
struct Branch {
    name: String,
    address: Address,
}

#[derive(EncryptTarget)]
#[stash(struct = Branch, scope = "branches", scope(tenant: u64))]
struct EncryptedBranch {
    name: Encrypted<EqualityTerm>,
    address: EncryptedAddress,
}

/// A record three deep, under a caller scope.
#[derive(Clone, Zeroize)]
struct Holder {
    account: Account,
}

#[derive(EncryptTarget)]
#[stash(struct = Holder, scope = "holders", scope(tenant: u64))]
struct EncryptedHolder {
    account: EncryptedAccount,
}

/// A record field under a record that stores its scope in the row.
#[derive(Clone, Zeroize)]
struct Office {
    tenant: u64,
    address: Address,
}

#[derive(EncryptTarget)]
#[stash(struct = Office, scope = "offices", scope(field = "tenant"))]
struct EncryptedOffice {
    #[stash(passthrough)]
    tenant: u64,
    address: EncryptedAddress,
}

/// A record field under a caller scope and a caller binding.
#[derive(EncryptTarget)]
#[stash(struct = Branch, scope = "bound", scope(tenant: u64), bind(row: u128))]
struct BoundBranch {
    name: Encrypted<EqualityTerm>,
    address: EncryptedAddress,
}

/// A record whose fields bind to the row it stores: an inner record with
/// a stored binding, an outer field under another identity, and a
/// nullable field of two indexes, under a caller scope.
#[derive(Clone, Zeroize)]
struct Tag {
    id: u128,
    label: String,
}

#[derive(EncryptTarget)]
#[stash(struct = Tag, scope = "tags", bind(field = "id"))]
struct EncryptedTag {
    #[stash(passthrough)]
    id: u128,
    label: Encrypted<EqualityTerm>,
}

#[derive(Clone, Zeroize)]
struct Shelf {
    id: u128,
    address: Address,
    tag: Tag,
    score: Option<u32>,
}

#[derive(EncryptTarget)]
#[stash(struct = Shelf, scope = "shelves", scope(tenant: u64), bind(field = "id"))]
struct EncryptedShelf {
    #[stash(passthrough)]
    id: u128,
    #[stash(identity = "place")]
    address: EncryptedAddress,
    tag: EncryptedTag,
    #[stash(query = u32)]
    score: Option<Encrypted<(EqualityTerm, OreTerm<u32>)>>,
}

fn shelf() -> Shelf {
    Shelf {
        id: 9,
        address: account().address,
        tag: Tag {
            id: 7,
            label: "fiction".into(),
        },
        score: Some(4),
    }
}

/// A record that stores its scope in the row, as a field of other records.
#[derive(Clone, Zeroize)]
struct Desk {
    tenant: u64,
    label: String,
}

#[derive(EncryptTarget)]
#[stash(struct = Desk, scope = "desks", scope(field = "tenant"))]
#[allow(dead_code)]
struct EncryptedDesk {
    #[stash(passthrough)]
    tenant: u64,
    label: Encrypted<EqualityTerm>,
}

/// A record with no scope that holds a record with one, a nullable record
/// with one, and a nullable record with none.
#[derive(Clone, Zeroize)]
struct Floor {
    desk: Desk,
    hot: Option<Desk>,
    lobby: Option<Address>,
}

#[derive(EncryptTarget)]
#[stash(struct = Floor, scope = "floors")]
struct EncryptedFloor {
    desk: EncryptedDesk,
    hot: Option<EncryptedDesk>,
    lobby: Option<EncryptedAddress>,
}

/// A record with a caller scope that holds a record with a stored one.
#[derive(Clone, Zeroize)]
struct Tower {
    desk: Desk,
}

#[derive(EncryptTarget)]
#[stash(struct = Tower, scope = "towers", scope(region: String))]
struct EncryptedTower {
    desk: EncryptedDesk,
}

/// A record that stores its scope, and holds a record with none that
/// holds a record with one: two scopes, with a record between them.
#[derive(Clone, Zeroize)]
struct Campus {
    owner: u32,
    floor: Floor,
}

#[derive(EncryptTarget)]
#[stash(struct = Campus, scope = "campuses", scope(field = "owner"))]
#[allow(dead_code)]
struct EncryptedCampus {
    #[stash(passthrough)]
    owner: u32,
    floor: EncryptedFloor,
}

/// Three records deep, each with a scope of its own.
#[derive(Clone, Zeroize)]
struct Wing {
    owner: u32,
    desk: Desk,
}

#[derive(EncryptTarget)]
#[stash(struct = Wing, scope = "wings", scope(field = "owner"))]
#[allow(dead_code)]
struct EncryptedWing {
    #[stash(passthrough)]
    owner: u32,
    desk: EncryptedDesk,
}

#[derive(Clone, Zeroize)]
struct Park {
    wing: Wing,
}

#[derive(EncryptTarget)]
#[stash(struct = Park, scope = "parks", scope(region: String))]
struct EncryptedPark {
    wing: EncryptedWing,
}

fn desk(tenant: u64) -> Desk {
    Desk {
        tenant,
        label: "D-7".into(),
    }
}

fn floor() -> Floor {
    Floor {
        desk: desk(42),
        hot: Some(desk(43)),
        lobby: Some(account().address),
    }
}

/// A record that stores a scope and a binding in the row.
#[derive(Clone, Zeroize)]
struct Locker {
    tenant: u64,
    id: u128,
    code: String,
}

#[derive(EncryptTarget)]
#[stash(struct = Locker, scope = "lockers", scope(field = "tenant"), bind(field = "id"))]
#[allow(dead_code)]
struct EncryptedLocker {
    #[stash(passthrough)]
    tenant: u64,
    #[stash(passthrough)]
    id: u128,
    code: Encrypted<EqualityTerm>,
}

/// A record with a caller scope and a caller binding. It holds a record
/// with a stored scope and binding, a nullable one, and a nullable record
/// with a stored binding and no scope.
#[derive(Clone, Zeroize)]
struct Gym {
    locker: Locker,
    spare: Option<Locker>,
    tag: Option<Tag>,
}

#[derive(EncryptTarget)]
#[stash(struct = Gym, scope = "gyms", scope(region: String), bind(row: u128))]
struct EncryptedGym {
    locker: EncryptedLocker,
    spare: Option<EncryptedLocker>,
    tag: Option<EncryptedTag>,
}

fn locker(tenant: u64) -> Locker {
    Locker {
        tenant,
        id: 99,
        code: "1234".into(),
    }
}

/// A record with no scope that holds a nullable record with a scope,
/// which holds a record with none, which holds a nullable record with one.
#[derive(Clone, Zeroize)]
struct Plaza {
    campus: Option<Campus>,
}

#[derive(EncryptTarget)]
#[stash(struct = Plaza, scope = "plazas")]
struct EncryptedPlaza {
    campus: Option<EncryptedCampus>,
}

/// A record with block ORE fields, alone and beside an equality index.
#[derive(Clone, Zeroize)]
struct Reading {
    level: u32,
    depth: u32,
}

#[derive(EncryptTarget)]
#[stash(struct = Reading, scope = "readings")]
struct EncryptedReading {
    level: Encrypted<OreBlockTerm<u32>>,
    depth: Encrypted<(EqualityTerm, OreBlockTerm<u32>)>,
}

fn account() -> Account {
    Account {
        r#type: "savings".into(),
        address: Address {
            street: "1 Main St".into(),
        },
    }
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
        let scoped: Marker<Root<EncryptedUser>, Encrypted<EqualityTerm>, Scope<u64>> =
            EncryptedUser::EMAIL;
        let stored: Marker<Root<StoredTenant>, Encrypted<EqualityTerm>, Scope<u64>> =
            StoredTenant::EMAIL;
        let unscoped: Marker<Root<Renamed>, Encrypted<EqualityTerm>, NoScope> = Renamed::EMAIL;
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
        assert!(shown.contains("within: []"), "{shown}");
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

mod a_marker_of_several_indexes {
    use super::*;

    #[tokio::test]
    async fn answers_each_operator_through_the_index_that_answers_it() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedPerson = person(None)
            .encrypt_into_with_context(&keyset, Scope::new(42u64))
            .await
            .unwrap();
        let (equality, matching, order) = &stored.email.terms;

        let eq = EncryptedPerson::EMAIL
            .eq("ada@example.com")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(&eq, equality);
        let text = EncryptedPerson::EMAIL
            .matches("example")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert!(matching.matches(&text));
        let at = EncryptedPerson::EMAIL
            .gte("ada@example.com")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(&at, order);
    }

    #[tokio::test]
    async fn answers_an_index_at_any_position() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedPerson = person(None)
            .encrypt_into_with_context(&keyset, Scope::new(42u64))
            .await
            .unwrap();
        let (equality, order) = &stored.age.terms;
        let eq = EncryptedPerson::AGE
            .eq(36u32)
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(&eq, equality);
        let range = EncryptedPerson::AGE
            .between(18u32, 36u32)
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(range.hi(), order);
    }
}

mod a_nullable_marker {
    use super::*;

    #[tokio::test]
    async fn derives_a_present_values_term_as_a_bare_value_is_derived() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedPerson = person(Some("ada"))
            .encrypt_into_with_context(&keyset, Scope::new(42u64))
            .await
            .unwrap();
        let present = stored.nick.as_ref().expect("a present nick");

        let term = EncryptedPerson::NICK
            .eq("ada")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, present.terms);
        let bare: Encrypted<EqualityTerm> = String::from("ada")
            .encrypt_into_with_context(&keyset, nonempty!("people").with("nick").with(42u64))
            .await
            .unwrap();
        assert_eq!(bare.terms, present.terms);
    }

    #[tokio::test]
    async fn queries_a_field_whose_stored_value_is_absent() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedPerson = person(None)
            .encrypt_into_with_context(&keyset, Scope::new(42u64))
            .await
            .unwrap();
        assert!(stored.nick.is_none(), "a NULL holds no term to match");
        let term = EncryptedPerson::NICK
            .eq("ada")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await;
        assert!(term.is_ok(), "{term:?}");
    }
}

mod a_typed_marker {
    use super::*;

    type Email = Encrypted<(EqualityTerm, MatchTerms, OreTerm<String>)>;
    type Age = Encrypted<(EqualityTerm, OreTerm<u32>)>;

    #[test]
    fn carries_the_type_its_record_states() {
        let email: Marker<Root<EncryptedPerson>, Email, Scope<u64>, Takes<String>> =
            EncryptedPerson::EMAIL;
        let nick: Marker<
            Root<EncryptedPerson>,
            Option<Encrypted<EqualityTerm>>,
            Scope<u64>,
            Takes<String>,
        > = EncryptedPerson::NICK;
        let age: Marker<Root<EncryptedPerson>, Age, Scope<u64>, TakesAny> = EncryptedPerson::AGE;
        assert_eq!(
            [email.name(), nick.name(), age.name()],
            ["email", "nick", "age"]
        );
    }
}

mod a_record_field_marker {
    use super::*;

    #[test]
    fn reaches_the_inner_field_under_the_outer_fields_context() {
        let street: Marker<Nested<Root<EncryptedAccount>>, Encrypted<EqualityTerm>> =
            EncryptedAccount::ADDRESS.field(EncryptedAddress::STREET);
        assert_eq!(street.name(), "street");
        assert_eq!(street.label().to_string(), "addresses/street");
        assert_eq!(
            street.contexts().to_string(),
            "context: (addresses / street) / (accounts / address)\n"
        );
        assert_eq!(
            EncryptedAccount::contexts().get("address.street"),
            street.contexts().single()
        );
    }

    #[test]
    fn shows_the_outer_records_scope_in_its_context() {
        let street = EncryptedBranch::ADDRESS.field(EncryptedAddress::STREET);
        assert_eq!(
            street.contexts().to_string(),
            "context: (addresses / street) / ((branches / address) / {tenant: u64})\n"
        );
        let deep = EncryptedHolder::ACCOUNT
            .field(EncryptedAccount::ADDRESS)
            .field(EncryptedAddress::STREET);
        assert_eq!(
            deep.contexts().to_string(),
            "context: (addresses / street) / ((accounts / address) / ((holders / account) / {tenant: u64}))\n"
        );
        // A step that lands on a record field lists that record's fields.
        let address = EncryptedHolder::ACCOUNT.field(EncryptedAccount::ADDRESS);
        assert_eq!(address.contexts().fields().len(), 1);
        assert_eq!(address.contexts().fields()[0].name(), Some("street"));
    }

    #[test]
    fn is_a_plain_value_that_names_the_fields_holding_it() {
        let street = EncryptedBranch::ADDRESS.field(EncryptedAddress::STREET);
        let copy = street;
        assert_eq!(copy.name(), street.name());
        let shown = format!("{street:?}");
        assert!(
            shown.contains("\"street\"") && shown.contains("[\"branches\", \"address\"]"),
            "{shown}"
        );
        let query = street.eq("a secret");
        let shown = format!("{query:?}");
        assert!(
            shown.contains("addresses") && shown.contains("[\"branches\", \"address\"]"),
            "{shown}"
        );
        assert!(!shown.contains("secret"), "{shown}");
    }

    #[tokio::test]
    async fn derives_the_stored_term_of_the_inner_field() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedAccount = account().encrypt_into(&keyset).await.unwrap();
        let term = EncryptedAccount::ADDRESS
            .field(EncryptedAddress::STREET)
            .eq("1 Main St")
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.address.street.terms);
        // The inner record's own marker is the inner record alone, under
        // its own context: another term.
        let alone = EncryptedAddress::STREET
            .eq("1 Main St")
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_ne!(alone, stored.address.street.terms);
    }

    #[tokio::test]
    async fn takes_the_outer_records_scope() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedBranch = Branch {
            name: "central".into(),
            address: account().address,
        }
        .encrypt_into_with_context(&keyset, Scope::new(42u64))
        .await
        .unwrap();
        let street = EncryptedBranch::ADDRESS.field(EncryptedAddress::STREET);
        let term = street
            .eq("1 Main St")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.address.street.terms);
        let name = EncryptedBranch::NAME
            .eq("central")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(name, stored.name.terms);
        let elsewhere = street
            .eq("1 Main St")
            .scope(Scope::new(43u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_ne!(elsewhere, stored.address.street.terms);
    }

    #[tokio::test]
    async fn reaches_a_record_three_deep() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedHolder = Holder { account: account() }
            .encrypt_into_with_context(&keyset, Scope::new(42u64))
            .await
            .unwrap();
        let street = EncryptedHolder::ACCOUNT
            .field(EncryptedAccount::ADDRESS)
            .field(EncryptedAddress::STREET)
            .eq("1 Main St")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(street, stored.account.address.street.terms);
        let kind = EncryptedHolder::ACCOUNT
            .field(EncryptedAccount::TYPE)
            .eq("savings")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(kind, stored.account.r#type.terms);
    }

    #[tokio::test]
    async fn takes_a_scope_the_outer_record_stores_in_the_row() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedOffice = Office {
            tenant: 42,
            address: account().address,
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        assert_eq!(stored.tenant, 42);
        let term = EncryptedOffice::ADDRESS
            .field(EncryptedAddress::STREET)
            .eq("1 Main St")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.address.street.terms);
    }
}

mod a_record_field_marker_beside_bindings {
    use super::*;

    #[tokio::test]
    async fn derives_the_stored_term_under_a_caller_binding() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: BoundBranch = Branch {
            name: "central".into(),
            address: account().address,
        }
        .encrypt_into_with_context(&keyset, Scope::new(42u64).bind(9u128))
        .await
        .unwrap();
        // A binding is in the stored context and in no query context.
        let term = BoundBranch::ADDRESS
            .field(EncryptedAddress::STREET)
            .eq("1 Main St")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.address.street.terms);
        let name = BoundBranch::NAME
            .eq("central")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(name, stored.name.terms);
    }

    #[tokio::test]
    async fn derives_the_stored_terms_under_stored_bindings_and_an_identity() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedShelf = shelf()
            .encrypt_into_with_context(&keyset, Scope::new(42u64))
            .await
            .unwrap();
        assert_eq!((stored.id, stored.tag.id), (9, 7));

        // The outer field is keyed under its identity, `shelves/place`.
        let street = EncryptedShelf::ADDRESS.field(EncryptedAddress::STREET);
        assert_eq!(
            street.contexts().single().map(ToString::to_string),
            Some(
                "query context:  (addresses / street) / ((shelves / place) / {tenant: u64})\n\
                 stored context: ((addresses / street) / ((shelves / place) / {tenant: u64})) / {id: u128, from the plaintext}\n"
                    .into()
            )
        );
        let term = street
            .eq("1 Main St")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.address.street.terms);

        // The inner record binds to its own row id; the query does not.
        let label = EncryptedShelf::TAG
            .field(EncryptedTag::LABEL)
            .eq("fiction")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(label, stored.tag.label.terms);
    }

    #[tokio::test]
    async fn answers_each_index_of_a_nullable_field() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedShelf = shelf()
            .encrypt_into_with_context(&keyset, Scope::new(42u64))
            .await
            .unwrap();
        let (equality, order) = &stored.score.as_ref().expect("a score").terms;
        let eq = EncryptedShelf::SCORE
            .eq(4u32)
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(&eq, equality);
        let at = EncryptedShelf::SCORE
            .gte(4u32)
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(&at, order);
    }

    #[tokio::test]
    async fn refuses_an_empty_scope_and_requests_no_key() {
        let (cipher, generates, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let refused = UnderText::ADDRESS
            .field(EncryptedAddress::STREET)
            .eq("1 Main St")
            .scope(Scope::new(String::new()))
            .encrypt(&keyset)
            .await;
        assert!(refused.is_err(), "an empty scope is refused");
        assert_eq!(generates.load(Ordering::SeqCst), 0);
        assert_eq!(retrieves.load(Ordering::SeqCst), 0);
    }
}

/// A record field under a text scope, which can be empty. Only its
/// markers are used.
#[derive(Clone, Zeroize)]
struct Site {
    address: Address,
}

#[derive(EncryptTarget)]
#[stash(struct = Site, scope = "sites", scope(region: String))]
#[allow(dead_code)]
struct UnderText {
    address: EncryptedAddress,
}

mod a_block_ore_marker {
    use super::*;

    #[tokio::test]
    async fn derives_the_stored_order_term_alone_and_beside_equality() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedReading = Reading { level: 7, depth: 3 }
            .encrypt_into(&keyset)
            .await
            .unwrap();
        let level = EncryptedReading::LEVEL
            .gte(7u32)
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(level, stored.level.terms);
        let (equality, order) = &stored.depth.terms;
        let eq = EncryptedReading::DEPTH
            .eq(3u32)
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(&eq, equality);
        let lt = EncryptedReading::DEPTH
            .lt(3u32)
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(&lt, order);
    }
}

mod a_marker_of_a_record_with_its_own_scope {
    use super::*;

    #[test]
    fn takes_the_inner_records_scope_alone_under_a_record_with_none() {
        let label: Marker<Nested<Root<EncryptedFloor>>, Encrypted<EqualityTerm>, Scope<u64>> =
            EncryptedFloor::DESK.field(EncryptedDesk::LABEL);
        assert_eq!(label.label().to_string(), "desks/label");
        assert_eq!(
            EncryptedFloor::contexts().get("desk.label"),
            label.contexts().single()
        );
    }

    /// An equality field's marker that takes the scopes `C`.
    type Scoped<W, C> = Marker<W, Encrypted<EqualityTerm>, C>;

    #[test]
    fn takes_both_scopes_outermost_first() {
        let label: Scoped<_, (Scope<String>, Scope<u64>)> =
            EncryptedTower::DESK.field(EncryptedDesk::LABEL);
        assert_eq!(
            EncryptedTower::contexts().get("desk.label"),
            label.contexts().single()
        );
        // A record between the two that lists none adds no scope.
        let _: Scoped<_, (Scope<u32>, Scope<u64>)> = EncryptedCampus::FLOOR
            .field(EncryptedFloor::DESK)
            .field(EncryptedDesk::LABEL);
        // Three records with a scope each.
        let three: Scoped<_, (Scope<String>, Scope<u32>, Scope<u64>)> = EncryptedPark::WING
            .field(EncryptedWing::DESK)
            .field(EncryptedDesk::LABEL);
        assert_eq!(
            EncryptedPark::contexts().get("wing.desk.label"),
            three.contexts().single()
        );
    }

    #[tokio::test]
    async fn derives_the_stored_term_under_the_inner_scope_alone() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedFloor = floor().encrypt_into(&keyset).await.unwrap();
        let label = EncryptedFloor::DESK.field(EncryptedDesk::LABEL);
        let term = label
            .eq("D-7")
            .scope(Scope::new(42u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.desk.label.terms);
        let elsewhere = label
            .eq("D-7")
            .scope(Scope::new(43u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_ne!(elsewhere, stored.desk.label.terms);
    }

    #[tokio::test]
    async fn derives_the_stored_term_under_both_scopes() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedTower = Tower { desk: desk(42) }
            .encrypt_into_with_context(&keyset, Scope::new(String::from("eu")))
            .await
            .unwrap();
        let label = EncryptedTower::DESK.field(EncryptedDesk::LABEL);
        let term = label
            .eq("D-7")
            .scope((Scope::new(String::from("eu")), Scope::new(42u64)))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.desk.label.terms);
        // Each scope is its own record's: another value of either is
        // another term.
        for (region, tenant) in [("us", 42u64), ("eu", 43)] {
            let other = label
                .eq("D-7")
                .scope((Scope::new(String::from(region)), Scope::new(tenant)))
                .encrypt(&keyset)
                .await
                .unwrap();
            assert_ne!(other, stored.desk.label.terms, "{region} {tenant}");
        }
    }

    /// Two scopes of one type, so that the order they are given in is not
    /// checked by the compiler: the first is the outer record's.
    #[tokio::test]
    async fn gives_the_first_scope_to_the_outer_record() {
        #[derive(Clone, Zeroize)]
        struct Room {
            tenant: u64,
            desk: Desk,
        }
        #[derive(EncryptTarget)]
        #[stash(struct = Room, scope = "rooms", scope(field = "tenant"))]
        #[allow(dead_code)]
        struct EncryptedRoom {
            #[stash(passthrough)]
            tenant: u64,
            desk: EncryptedDesk,
        }
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedRoom = Room {
            tenant: 1,
            desk: desk(2),
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        let label = EncryptedRoom::DESK.field(EncryptedDesk::LABEL);
        let term = label
            .eq("D-7")
            .scope((Scope::new(1u64), Scope::new(2u64)))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.desk.label.terms);
        let swapped = label
            .eq("D-7")
            .scope((Scope::new(2u64), Scope::new(1u64)))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_ne!(swapped, stored.desk.label.terms);
    }

    #[tokio::test]
    async fn derives_the_stored_term_past_a_record_with_no_scope() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedCampus = Campus {
            owner: 7,
            floor: floor(),
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        let term = EncryptedCampus::FLOOR
            .field(EncryptedFloor::DESK)
            .field(EncryptedDesk::LABEL)
            .eq("D-7")
            .scope((Scope::new(7u32), Scope::new(42u64)))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.floor.desk.label.terms);
    }

    #[tokio::test]
    async fn derives_the_stored_term_under_three_scopes() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedPark = Park {
            wing: Wing {
                owner: 7,
                desk: desk(42),
            },
        }
        .encrypt_into_with_context(&keyset, Scope::new(String::from("eu")))
        .await
        .unwrap();
        let term = EncryptedPark::WING
            .field(EncryptedWing::DESK)
            .field(EncryptedDesk::LABEL)
            .eq("D-7")
            .scope((
                Scope::new(String::from("eu")),
                Scope::new(7u32),
                Scope::new(42u64),
            ))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.wing.desk.label.terms);
    }

    #[tokio::test]
    async fn refuses_an_empty_scope_of_either_record_and_requests_no_key() {
        let (cipher, generates, retrieves) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let label = EncryptedTower::DESK.field(EncryptedDesk::LABEL);
        let refused = label
            .eq("D-7")
            .scope((Scope::new(String::new()), Scope::new(42u64)))
            .encrypt(&keyset)
            .await;
        assert!(
            matches!(refused, Err(Error::Plan(PlanError::EmptyPart))),
            "an empty outer scope is refused: {refused:?}"
        );
        // The inner record's scope, where it is the one that can be empty.
        #[derive(Clone, Zeroize)]
        struct Stall {
            region: String,
            name: String,
        }
        #[derive(EncryptTarget)]
        #[stash(struct = Stall, scope = "stalls", scope(field = "region"))]
        #[allow(dead_code)]
        struct EncryptedStall {
            #[stash(passthrough)]
            region: String,
            name: Encrypted<EqualityTerm>,
        }
        #[derive(Clone, Zeroize)]
        struct Market {
            stall: Stall,
        }
        #[derive(EncryptTarget)]
        #[stash(struct = Market, scope = "markets", scope(tenant: u64))]
        #[allow(dead_code)]
        struct EncryptedMarket {
            stall: EncryptedStall,
        }
        let refused = EncryptedMarket::STALL
            .field(EncryptedStall::NAME)
            .eq("fruit")
            .scope((Scope::new(42u64), Scope::new(String::new())))
            .encrypt(&keyset)
            .await;
        assert!(
            matches!(refused, Err(Error::Plan(PlanError::EmptyPart))),
            "an empty inner scope is refused: {refused:?}"
        );
        assert_eq!(generates.load(Ordering::SeqCst), 0);
        assert_eq!(retrieves.load(Ordering::SeqCst), 0);
    }
}

mod a_marker_of_a_nullable_record {
    use super::*;

    #[test]
    fn reaches_the_inner_field_as_a_present_record_does() {
        let street: Marker<Nested<Root<EncryptedFloor>>, Encrypted<EqualityTerm>> =
            EncryptedFloor::LOBBY.field(EncryptedAddress::STREET);
        assert_eq!(street.label().to_string(), "addresses/street");
        assert_eq!(
            EncryptedFloor::contexts().get("lobby.street"),
            street.contexts().single()
        );
        let hot: Marker<_, Encrypted<EqualityTerm>, Scope<u64>> =
            EncryptedFloor::HOT.field(EncryptedDesk::LABEL);
        assert_eq!(
            EncryptedFloor::contexts().get("hot.label"),
            hot.contexts().single()
        );
    }

    #[tokio::test]
    async fn derives_the_stored_term_of_a_present_record() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedFloor = floor().encrypt_into(&keyset).await.unwrap();
        let term = EncryptedFloor::LOBBY
            .field(EncryptedAddress::STREET)
            .eq("1 Main St")
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.lobby.as_ref().unwrap().street.terms);
        // A nullable record with a scope of its own takes that scope.
        let hot = EncryptedFloor::HOT
            .field(EncryptedDesk::LABEL)
            .eq("D-7")
            .scope(Scope::new(43u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(hot, stored.hot.as_ref().unwrap().label.terms);
    }

    #[tokio::test]
    async fn queries_a_field_whose_stored_record_is_absent() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedFloor = Floor {
            hot: None,
            lobby: None,
            ..floor()
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        assert!(stored.hot.is_none() && stored.lobby.is_none());
        // The query derives the term a present record stores: it does not
        // depend on the row. This row stores nothing for it to match.
        let present: EncryptedFloor = floor().encrypt_into(&keyset).await.unwrap();
        let term = EncryptedFloor::LOBBY
            .field(EncryptedAddress::STREET)
            .eq("1 Main St")
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, present.lobby.as_ref().unwrap().street.terms);
    }

    #[tokio::test]
    async fn reaches_a_nullable_record_inside_a_nullable_record() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedPlaza = Plaza {
            campus: Some(Campus {
                owner: 7,
                floor: floor(),
            }),
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        // The campus's scope, then the desk's; the floor between lists none.
        let label: Marker<_, Encrypted<EqualityTerm>, (Scope<u32>, Scope<u64>)> =
            EncryptedPlaza::CAMPUS
                .field(EncryptedCampus::FLOOR)
                .field(EncryptedFloor::HOT)
                .field(EncryptedDesk::LABEL);
        assert_eq!(
            EncryptedPlaza::contexts().get("campus.floor.hot.label"),
            label.contexts().single()
        );
        let term = label
            .eq("D-7")
            .scope((Scope::new(7u32), Scope::new(43u64)))
            .encrypt(&keyset)
            .await
            .unwrap();
        let Some(campus) = &stored.campus else {
            panic!("the campus is stored")
        };
        let Some(hot) = &campus.floor.hot else {
            panic!("the desk is stored")
        };
        assert_eq!(term, hot.label.terms);
    }
}

/// A binding is in no query context. Where a record stores or takes a
/// binding beside a scope, at either level, a query takes the scopes alone
/// and still derives the stored term.
mod a_nested_marker_beside_a_binding {
    use super::*;

    async fn stored_gym(keyset: &KeysetCipher<'_, FakeDataKeySource>) -> EncryptedGym {
        Gym {
            locker: locker(5),
            spare: Some(locker(6)),
            tag: Some(Tag {
                id: 3,
                label: "fiction".into(),
            }),
        }
        .encrypt_into_with_context(keyset, Scope::new(String::from("eu")).bind(77u128))
        .await
        .unwrap()
    }

    #[test]
    fn takes_the_scopes_alone_and_shows_the_record_contexts() {
        let code: Marker<_, Encrypted<EqualityTerm>, (Scope<String>, Scope<u64>)> =
            EncryptedGym::LOCKER.field(EncryptedLocker::CODE);
        assert_eq!(
            EncryptedGym::contexts().get("locker.code"),
            code.contexts().single()
        );
        let spare: Marker<_, Encrypted<EqualityTerm>, (Scope<String>, Scope<u64>)> =
            EncryptedGym::SPARE.field(EncryptedLocker::CODE);
        assert_eq!(
            EncryptedGym::contexts().get("spare.code"),
            spare.contexts().single()
        );
        // A record that stores a binding and no scope adds no scope.
        let tag: Marker<_, Encrypted<EqualityTerm>, Scope<String>> =
            EncryptedGym::TAG.field(EncryptedTag::LABEL);
        assert_eq!(
            EncryptedGym::contexts().get("tag.label"),
            tag.contexts().single()
        );
    }

    #[tokio::test]
    async fn derives_the_stored_term_of_a_record_with_a_stored_binding() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored = stored_gym(&keyset).await;
        let term = EncryptedGym::LOCKER
            .field(EncryptedLocker::CODE)
            .eq("1234")
            .scope((Scope::new(String::from("eu")), Scope::new(5u64)))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, stored.locker.code.terms);
    }

    #[tokio::test]
    async fn derives_the_stored_term_of_a_nullable_record_with_a_stored_binding() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored = stored_gym(&keyset).await;
        let Some(spare) = &stored.spare else {
            panic!("the spare locker is stored")
        };
        let term = EncryptedGym::SPARE
            .field(EncryptedLocker::CODE)
            .eq("1234")
            .scope((Scope::new(String::from("eu")), Scope::new(6u64)))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, spare.code.terms);
        let Some(tag) = &stored.tag else {
            panic!("the tag is stored")
        };
        let term = EncryptedGym::TAG
            .field(EncryptedTag::LABEL)
            .eq("fiction")
            .scope(Scope::new(String::from("eu")))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(term, tag.label.terms);
    }
}
