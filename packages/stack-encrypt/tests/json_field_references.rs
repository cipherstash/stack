//! The JSON queries of a field reference: a record field that stores a JSON
//! document, sealed under the options its `#[stash(json(..))]` names, and
//! queried from its field reference under the same column and options.
//!
//! Each query is checked against a document the record sealed, and, with
//! the `dynamic` feature, against the operand a data plan derives for the
//! same declaration, which is what the Go SDK sends: the field reference and the
//! data plan read one definition of each input, so they derive the same
//! operand.

mod common;

#[cfg(feature = "dynamic")]
use std::num::NonZeroU32;
use std::sync::atomic::Ordering;

use serde_json::{json, Value};
use stack_encrypt::json::{JsonDocument, JsonLeafQuery, JsonPlaintext, JsonQuery};
use stack_encrypt::refusal::Reason;
use stack_encrypt::sem::TermError;
use stack_encrypt::target::{DecryptSource, EncryptTarget, Scope};
use stack_encrypt::{DecryptFrom, EncryptInto, Error, KeysetCipher, StackCipher};
use stack_kms::FakeDataKeySource;
use zeroize::Zeroize;

/// A customer and the profile document the record stores.
#[derive(Zeroize)]
struct Customer {
    name: String,
    profile: JsonPlaintext,
}

/// The profile is stored under `customers/profile`, ordering the age and
/// each visit's time and place.
#[derive(EncryptTarget, DecryptSource)]
#[stash(struct = Customer, scope = "customers")]
struct EncryptedCustomer {
    name: stack_encrypt::StackCipherText,
    #[stash(json(ordered = { "$.age": u32, "$.visits[*].at": u64, "$.visits[*].place": String }))]
    profile: JsonDocument,
}

/// The same record with the default options, which order no path.
#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
#[allow(dead_code)] // only queried
struct UnorderedCustomer {
    name: stack_encrypt::StackCipherText,
    profile: JsonDocument,
}

fn profile() -> Value {
    json!({
        "name": "Ada",
        "age": 35,
        "visits": [{"place": "home", "at": 15}, {"place": "work", "at": 9}],
        "tags": ["a", "b"]
    })
}

fn customer() -> Customer {
    Customer {
        name: "Ada".into(),
        profile: profile().into(),
    }
}

async fn cipher() -> StackCipher<FakeDataKeySource> {
    common::stack_cipher().await
}

async fn stored(keyset: &KeysetCipher<'_, FakeDataKeySource>) -> EncryptedCustomer {
    customer().encrypt_into(keyset).await.expect("seals")
}

mod given_a_document_field {
    use super::*;

    #[tokio::test]
    async fn it_round_trips_under_its_options() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let encrypted = stored(&keyset).await;
        let opened = Customer::decrypt_from(encrypted, &keyset)
            .await
            .expect("opens");
        assert_eq!(opened.profile.value(), &profile());
        assert_eq!(opened.name, "Ada");
    }

    #[tokio::test]
    async fn contains_finds_the_documents_that_hold_its_needle() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let doc = stored(&keyset).await.profile;
        let ada: JsonQuery = EncryptedCustomer::PROFILE
            .contains(json!({"name": "Ada", "visits": [{"place": "home"}]}))
            .encrypt(&keyset)
            .await
            .expect("derives");
        assert!(ada.matches(doc.selector_set()), "the document holds it");
        let bob = EncryptedCustomer::PROFILE
            .contains(json!({"name": "Bob"}))
            .encrypt(&keyset)
            .await
            .expect("derives");
        assert!(!bob.matches(doc.selector_set()), "the document does not");
    }

    #[tokio::test]
    async fn contained_by_sends_the_needle_contains_sends() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let needle = json!({"name": "Ada"});
        let contains = EncryptedCustomer::PROFILE
            .contains(needle.clone())
            .encrypt(&keyset)
            .await
            .unwrap();
        let contained_by = EncryptedCustomer::PROFILE
            .contained_by(JsonPlaintext::from(needle))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(
            contains, contained_by,
            "one operand; the SQL says which way"
        );
    }

    #[tokio::test]
    async fn at_eq_finds_a_scalar_at_a_path_and_at_any_element() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let doc = stored(&keyset).await.profile;
        for (path, value, holds) in [
            ("$.age", json!(35), true),
            ("$.age", json!(36), false),
            ("$.visits[*].place", json!("home"), true),
            ("$.visits[*].place", json!("gym"), false),
        ] {
            let query = match value {
                Value::Number(n) => EncryptedCustomer::PROFILE
                    .at_text_path(path)
                    .eq(n.as_i64().unwrap()),
                Value::String(s) => {
                    let borrowed = EncryptedCustomer::PROFILE
                        .at_text_path(path)
                        .eq(&s)
                        .encrypt(&keyset)
                        .await
                        .expect("derives");
                    assert_eq!(
                        borrowed.matches(doc.selector_set()),
                        holds,
                        "{path}, a `&String`"
                    );
                    EncryptedCustomer::PROFILE.at_text_path(path).eq(s)
                }
                _ => unreachable!(),
            }
            .encrypt(&keyset)
            .await
            .expect("derives");
            assert_eq!(query.matches(doc.selector_set()), holds, "{path}");
        }
    }

    #[tokio::test]
    async fn an_ordering_carries_the_paths_selector() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let older: JsonLeafQuery = EncryptedCustomer::PROFILE
            .at_text_path("$.age")
            .gt(30)
            .encrypt(&keyset)
            .await
            .expect("derives");
        let selector = EncryptedCustomer::PROFILE
            .at_text_path("$.age")
            .selector()
            .encrypt(&keyset)
            .await
            .expect("derives");
        assert_eq!(older.selector(), selector);
        let (low, high) = EncryptedCustomer::PROFILE
            .at_text_path("$.age")
            .between(18, 65)
            .encrypt(&keyset)
            .await
            .expect("derives");
        assert_eq!((low.selector(), high.selector()), (selector, selector));
        assert_ne!(low.ordering_term(), high.ordering_term());
    }

    #[tokio::test]
    async fn an_element_predicate_holds_one_member_per_condition() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let visit = EncryptedCustomer::PROFILE
            .elements_text_path("$.visits[*]")
            .eq("place", "home")
            .encrypt(&keyset)
            .await
            .expect("derives");
        assert_eq!(visit.len(), 1);
        assert!(!visit.is_empty());
    }

    #[test]
    fn a_query_prints_its_field_and_not_its_values() {
        let shown = format!(
            "{:?}",
            EncryptedCustomer::PROFILE.contains(json!({"name": "Ada"}))
        );
        assert!(shown.starts_with("JsonFieldQuery("), "{shown}");
        assert!(shown.contains("profile"), "{shown}");
        assert!(!shown.contains("Ada"), "{shown}");
    }
}

/// The options a field names reach the stored document, and its field reference
/// derives under the same ones: an ordered path's entry carries an
/// ordering term at the selector the field reference derives, and the token the
/// field reference derives names an entry of the document.
mod the_fields_options {
    use super::*;
    use stack_encrypt::json::JsonSubtreeKey;

    /// The entry the token in `key` names, as the server finds it.
    fn entry<'d>(
        doc: &'d JsonDocument,
        key: &JsonSubtreeKey,
    ) -> Option<&'d stack_encrypt::json::JsonEntry> {
        doc.find(&key.token_bytes()[0]).map(|(_, entry)| entry)
    }

    #[tokio::test]
    async fn an_ordered_paths_entry_carries_an_ordering_term_at_the_field_references_selector() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let doc = stored(&keyset).await.profile;
        let key = EncryptedCustomer::PROFILE
            .children("$.age")
            .encrypt(&keyset)
            .await
            .unwrap();
        let selector = EncryptedCustomer::PROFILE
            .at_text_path("$.age")
            .selector()
            .encrypt(&keyset)
            .await
            .unwrap();
        let age = entry(&doc, &key).expect("the token names the entry");
        assert_eq!(age.selector(), selector.as_bytes());
        assert!(age.ordering_term().is_some(), "an ordered path's leaf");
        let key = EncryptedCustomer::PROFILE
            .children("$.name")
            .encrypt(&keyset)
            .await
            .unwrap();
        let name = entry(&doc, &key).expect("the token names the entry");
        assert!(name.ordering_term().is_none(), "an unordered path's leaf");
    }

    /// `sealed_root = false` reaches the stored document's header, and the
    /// field reference derives the root's token under the same options.
    #[derive(EncryptTarget)]
    #[stash(struct = Customer, scope = "customers")]
    #[allow(dead_code)] // only the profile is read
    struct OpenCustomer {
        name: stack_encrypt::StackCipherText,
        #[stash(json(ordered = { "$.age": u32 }, sealed_root = false))]
        profile: JsonDocument,
    }

    #[tokio::test]
    async fn an_open_root_is_sealed_and_queried_open() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let open: OpenCustomer = customer().encrypt_into(&keyset).await.unwrap();
        assert!(!open.profile.header().sealed_root());
        let root = OpenCustomer::PROFILE
            .children("$")
            .encrypt(&keyset)
            .await
            .unwrap();
        assert!(entry(&open.profile, &root).is_some(), "the root's token");
        assert!(
            stored(&keyset).await.profile.header().sealed_root(),
            "the default seals it"
        );
    }

    #[derive(EncryptTarget)]
    #[stash(struct = Customer, scope = "customers", scope(tenant: u64))]
    #[allow(dead_code)] // only the profile is read
    struct TenantCustomer {
        name: stack_encrypt::StackCipherText,
        #[stash(json(ordered = { "$.age": u32 }))]
        profile: JsonDocument,
    }

    #[tokio::test]
    async fn under_a_scope_the_tokens_and_selectors_are_the_scopes() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let seven: TenantCustomer = customer()
            .encrypt_into_with_context(&keyset, Scope::new(7u64))
            .await
            .unwrap();
        for (tenant, found) in [(7u64, true), (8, false)] {
            let key = TenantCustomer::PROFILE
                .children("$.age")
                .scope(Scope::new(tenant))
                .encrypt(&keyset)
                .await
                .unwrap();
            let age = entry(&seven.profile, &key);
            assert_eq!(age.is_some(), found, "tenant {tenant}");
            let selector = TenantCustomer::PROFILE
                .at_text_path("$.age")
                .selector()
                .scope(Scope::new(tenant))
                .encrypt(&keyset)
                .await
                .unwrap();
            if let Some(age) = age {
                assert_eq!(age.selector(), selector.as_bytes());
                assert!(age.ordering_term().is_some());
            }
        }
    }

    #[derive(Zeroize)]
    struct Account {
        customer: Customer,
    }

    #[derive(EncryptTarget)]
    #[stash(struct = Account, scope = "accounts")]
    struct EncryptedAccount {
        customer: EncryptedCustomer,
    }

    #[tokio::test]
    async fn through_an_outer_field_the_tokens_and_selectors_are_the_inner_fields() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let account: EncryptedAccount = Account {
            customer: customer(),
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        let reference = EncryptedAccount::CUSTOMER.field(EncryptedCustomer::PROFILE);
        let key = reference.children("$.age").encrypt(&keyset).await.unwrap();
        let age = entry(&account.customer.profile, &key).expect("the inner field's token");
        let selector = reference
            .at_text_path("$.age")
            .selector()
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(age.selector(), selector.as_bytes());
        assert!(age.ordering_term().is_some());
    }

    /// A document type that seals under options of its own when its field
    /// names none: its field queries under the same options.
    struct AgeOrdered(JsonDocument);

    fn age_ordered() -> stack_encrypt::json::JsonOptions {
        stack_encrypt::json::JsonOptions::new()
            .ordering(["$.age"])
            .unwrap()
    }

    impl EncryptTarget<JsonPlaintext> for AgeOrdered {
        type ContextInput =
            stack_encrypt::target::RequiredContext<stack_encrypt::target::CallerContext>;
        fn encryption<'s, K: 'static>(
        ) -> stack_encrypt::Encryption<'s, JsonPlaintext, Self, K, Self::ContextInput>
        where
            JsonPlaintext: 's,
        {
            stack_encrypt::target::json_document(age_ordered())
                .project(JsonPlaintext::value)
                .accepting()
                .map(AgeOrdered)
        }
    }

    impl stack_encrypt::target::Decryptable for AgeOrdered {
        const DECRYPTABLE: bool = true;
    }

    impl stack_encrypt::json::JsonQueries for AgeOrdered {
        type Query = <JsonDocument as stack_encrypt::json::JsonQueries>::Query;
        type LeafQuery = JsonLeafQuery;
        type ElementsQuery = stack_encrypt::json::JsonElementsQuery;
        type PredicateQuery = stack_encrypt::json::JsonPredicateQuery;
        type Selector = stack_encrypt::json::JsonSelector;
        type Token = JsonSubtreeKey;
        fn default_options() -> stack_encrypt::json::JsonOptions {
            age_ordered()
        }
        fn query(query: JsonQuery) -> Result<JsonQuery, Error> {
            Ok(query)
        }
        fn leaf_query(query: JsonLeafQuery) -> Result<JsonLeafQuery, Error> {
            Ok(query)
        }
        fn elements_query(
            query: stack_encrypt::json::JsonElementsQuery,
        ) -> Result<stack_encrypt::json::JsonElementsQuery, Error> {
            Ok(query)
        }
        fn predicate_query(
            query: stack_encrypt::json::JsonPredicateQuery,
        ) -> Result<stack_encrypt::json::JsonPredicateQuery, Error> {
            Ok(query)
        }
        fn selector(
            selector: stack_encrypt::json::JsonSelector,
        ) -> Result<stack_encrypt::json::JsonSelector, Error> {
            Ok(selector)
        }
        fn token(key: JsonSubtreeKey) -> Result<JsonSubtreeKey, Error> {
            Ok(key)
        }
    }

    #[derive(EncryptTarget)]
    #[stash(struct = Customer, scope = "customers")]
    #[allow(dead_code)] // only the profile is read
    struct OwnOptionsCustomer {
        name: stack_encrypt::StackCipherText,
        profile: AgeOrdered,
    }

    #[tokio::test]
    async fn a_field_that_names_no_options_queries_under_its_types_own() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: OwnOptionsCustomer = customer().encrypt_into(&keyset).await.unwrap();
        let older = OwnOptionsCustomer::PROFILE
            .at_text_path("$.age")
            .gt(30)
            .encrypt(&keyset)
            .await;
        assert!(older.is_ok(), "the type orders `$.age`: {older:?}");
        let key = OwnOptionsCustomer::PROFILE
            .children("$.age")
            .encrypt(&keyset)
            .await
            .unwrap();
        let age = entry(&stored.profile.0, &key).expect("the token names the entry");
        assert!(age.ordering_term().is_some());
    }

    #[derive(Zeroize)]
    struct Lead {
        profile: Option<JsonPlaintext>,
    }

    #[derive(EncryptTarget)]
    #[stash(struct = Lead, scope = "leads")]
    #[allow(dead_code)] // only queried
    struct OwnOptionsLead {
        profile: Option<AgeOrdered>,
    }

    #[tokio::test]
    async fn a_nullable_field_queries_under_its_types_own_options() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let older = OwnOptionsLead::PROFILE
            .at_text_path("$.age")
            .gt(30)
            .encrypt(&keyset)
            .await;
        assert!(older.is_ok(), "the type orders `$.age`: {older:?}");
    }
}

/// A declared path's typed accessor derives the operand the text form
/// derives for the same path and value, byte for byte: both build the same
/// input, through the same code. The data plan's operands are held to the
/// typed form in `as_the_data_plan_derives`.
mod typed_paths {
    use super::*;
    use std::num::NonZeroU32;

    fn json<T: serde::Serialize>(value: &T) -> Value {
        serde_json::to_value(value).unwrap()
    }

    #[tokio::test]
    async fn equality_at_a_path_is_the_text_forms() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let doc = stored(&keyset).await.profile;
        let typed = EncryptedCustomer::PROFILE
            .at()
            .age()
            .eq(35)
            .encrypt(&keyset)
            .await
            .unwrap();
        let text = EncryptedCustomer::PROFILE
            .at_text_path("$.age")
            .eq(35)
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(typed, text, "one needle, compared as sets");
        assert!(typed.matches(doc.selector_set()));
        for place in ["home", "gym"] {
            let owned = String::from(place);
            let typed = [
                EncryptedCustomer::PROFILE
                    .at()
                    .visits_place()
                    .eq(place)
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
                EncryptedCustomer::PROFILE
                    .at()
                    .visits_place()
                    .eq(&owned)
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
                EncryptedCustomer::PROFILE
                    .at()
                    .visits_place()
                    .eq(owned.clone())
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
            ];
            let text = EncryptedCustomer::PROFILE
                .at_text_path("$.visits[*].place")
                .eq(place)
                .encrypt(&keyset)
                .await
                .unwrap();
            for typed in typed {
                assert_eq!(typed, text, "{place}");
                assert_eq!(typed.matches(doc.selector_set()), place == "home");
            }
        }
        let typed = EncryptedCustomer::PROFILE
            .at()
            .age()
            .is_null()
            .encrypt(&keyset)
            .await
            .unwrap();
        let text = EncryptedCustomer::PROFILE
            .at_text_path("$.age")
            .is_null()
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(typed, text);
    }

    #[tokio::test]
    async fn the_orderings_and_the_selector_are_the_text_forms() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let reference = || EncryptedCustomer::PROFILE.at().age();
        let text = || EncryptedCustomer::PROFILE.at_text_path("$.age");
        let pairs = [
            (
                json(&reference().lt(30).encrypt(&keyset).await.unwrap()),
                json(&text().lt(30).encrypt(&keyset).await.unwrap()),
            ),
            (
                json(&reference().lte(30).encrypt(&keyset).await.unwrap()),
                json(&text().lte(30).encrypt(&keyset).await.unwrap()),
            ),
            (
                json(&reference().gt(30).encrypt(&keyset).await.unwrap()),
                json(&text().gt(30).encrypt(&keyset).await.unwrap()),
            ),
            (
                json(&reference().gte(30).encrypt(&keyset).await.unwrap()),
                json(&text().gte(30).encrypt(&keyset).await.unwrap()),
            ),
            (
                json(&reference().between(18, 65).encrypt(&keyset).await.unwrap()),
                json(&text().between(18, 65).encrypt(&keyset).await.unwrap()),
            ),
        ];
        for (typed, text) in &pairs {
            assert_eq!(typed, text);
        }
        assert_ne!(
            pairs[0].0,
            json(&reference().lt(31).encrypt(&keyset).await.unwrap()),
            "the operand carries the value"
        );
        assert_eq!(
            reference().selector().encrypt(&keyset).await.unwrap(),
            text().selector().encrypt(&keyset).await.unwrap()
        );
        // A path through an array, and a string.
        let typed = EncryptedCustomer::PROFILE
            .at()
            .visits_place()
            .gte("h")
            .encrypt(&keyset)
            .await
            .unwrap();
        let text = EncryptedCustomer::PROFILE
            .at_text_path("$.visits[*].place")
            .gte("h")
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(json(&typed), json(&text));
        let typed = EncryptedCustomer::PROFILE
            .at()
            .visits_at()
            .between(10, 20)
            .encrypt(&keyset)
            .await
            .unwrap();
        let text = EncryptedCustomer::PROFILE
            .at_text_path("$.visits[*].at")
            .between(10, 20)
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(json(&typed), json(&text));
    }

    #[tokio::test]
    async fn an_element_predicate_is_the_text_forms() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let bound = NonZeroU32::new(8).unwrap();
        let typed = EncryptedCustomer::PROFILE
            .elements()
            .visits()
            .place()
            .eq("home")
            .and()
            .at()
            .between(10, 20)
            .and()
            .at()
            .lt(30)
            .and()
            .at()
            .lte(30)
            .and()
            .at()
            .gt(1)
            .and()
            .place()
            .gte("a")
            .wildcard_bound(bound)
            .encrypt(&keyset)
            .await
            .unwrap();
        let text = EncryptedCustomer::PROFILE
            .elements_text_path("$.visits[*]")
            .eq("place", "home")
            .between("at", 10, 20)
            .lt("at", 30)
            .lte("at", 30)
            .gt("at", 1)
            .gte("place", "a")
            .wildcard_bound(bound)
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(typed.len(), 6);
        assert_eq!(json(&typed), json(&text));
        // Each first condition starts the predicate the text form starts.
        for (typed, text) in [
            (
                EncryptedCustomer::PROFILE
                    .elements()
                    .visits()
                    .at()
                    .lt(9)
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
                EncryptedCustomer::PROFILE
                    .elements_text_path("$.visits[*]")
                    .lt("at", 9)
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
            ),
            (
                EncryptedCustomer::PROFILE
                    .elements()
                    .visits()
                    .at()
                    .lte(9)
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
                EncryptedCustomer::PROFILE
                    .elements_text_path("$.visits[*]")
                    .lte("at", 9)
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
            ),
            (
                EncryptedCustomer::PROFILE
                    .elements()
                    .visits()
                    .at()
                    .gt(9)
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
                EncryptedCustomer::PROFILE
                    .elements_text_path("$.visits[*]")
                    .gt("at", 9)
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
            ),
            (
                EncryptedCustomer::PROFILE
                    .elements()
                    .visits()
                    .at()
                    .gte(9)
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
                EncryptedCustomer::PROFILE
                    .elements_text_path("$.visits[*]")
                    .gte("at", 9)
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
            ),
            (
                EncryptedCustomer::PROFILE
                    .elements()
                    .visits()
                    .at()
                    .between(1, 9)
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
                EncryptedCustomer::PROFILE
                    .elements_text_path("$.visits[*]")
                    .between("at", 1, 9)
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
            ),
            (
                EncryptedCustomer::PROFILE
                    .elements()
                    .visits()
                    .place()
                    .eq("work")
                    .and()
                    .place()
                    .lte("x")
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
                EncryptedCustomer::PROFILE
                    .elements_text_path("$.visits[*]")
                    .eq("place", "work")
                    .lte("place", "x")
                    .encrypt(&keyset)
                    .await
                    .unwrap(),
            ),
        ] {
            assert_eq!(json(&typed), json(&text));
        }
    }

    /// A record whose keys are not all Rust identifiers: a camel-case key,
    /// a keyword, a key named in `names`, quoted keys, and a nested array.
    #[derive(Zeroize)]
    struct Order {
        doc: JsonPlaintext,
    }

    #[derive(EncryptTarget)]
    #[stash(struct = Order, scope = "orders")]
    struct EncryptedOrder {
        #[stash(json(
            ordered = {
                "$.firstName": String,
                "$.type": String,
                "$[\"ship to\"].zip": String,
                "$.lines[*][\"unit price\"]": f64,
                "$.lines[*].qty": u32,
                "$.lines[*].parts[*].sku": String,
                "$[*]": i64,
            },
            names = { "ship to": ship_to, "unit price": unit_price },
        ))]
        doc: JsonDocument,
    }

    fn order() -> Value {
        json!({
            "firstName": "Ada",
            "type": "retail",
            "ship to": {"zip": "3000"},
            "lines": [{"unit price": 2.5, "qty": 3, "parts": [{"sku": "a-1"}]}]
        })
    }

    #[tokio::test]
    async fn an_accessor_is_named_by_the_rule_and_reaches_its_path() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let stored: EncryptedOrder = Order {
            doc: order().into(),
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        let typed = [
            EncryptedOrder::DOC
                .at()
                .first_name()
                .eq("Ada")
                .encrypt(&keyset)
                .await
                .unwrap(),
            EncryptedOrder::DOC
                .at()
                .r#type()
                .eq("retail")
                .encrypt(&keyset)
                .await
                .unwrap(),
            EncryptedOrder::DOC
                .at()
                .ship_to_zip()
                .eq("3000")
                .encrypt(&keyset)
                .await
                .unwrap(),
            EncryptedOrder::DOC
                .at()
                .lines_unit_price()
                .eq(2.5)
                .encrypt(&keyset)
                .await
                .unwrap(),
            EncryptedOrder::DOC
                .at()
                .lines_parts_sku()
                .eq("a-1")
                .encrypt(&keyset)
                .await
                .unwrap(),
        ];
        let text = [
            ("$.firstName", json!("Ada")),
            ("$.type", json!("retail")),
            (r#"$["ship to"].zip"#, json!("3000")),
            (r#"$.lines[*]["unit price"]"#, json!(2.5)),
            ("$.lines[*].parts[*].sku", json!("a-1")),
        ];
        for (typed, (path, value)) in typed.into_iter().zip(text) {
            let text = match &value {
                Value::String(s) => EncryptedOrder::DOC.at_text_path(path).eq(s.as_str()),
                Value::Number(n) => EncryptedOrder::DOC
                    .at_text_path(path)
                    .eq(n.as_f64().unwrap()),
                _ => unreachable!(),
            }
            .encrypt(&keyset)
            .await
            .unwrap();
            assert_eq!(typed, text, "{path}");
            assert!(typed.matches(stored.doc.selector_set()), "{path}");
        }
        // A quoted member, and an array inside an array.
        let typed = EncryptedOrder::DOC
            .elements()
            .lines()
            .unit_price()
            .gt(1.0)
            .and()
            .qty()
            .eq(3)
            .encrypt(&keyset)
            .await
            .unwrap();
        let text = EncryptedOrder::DOC
            .elements_text_path("$.lines[*]")
            .gt(r#"["unit price"]"#, 1.0)
            .eq("qty", 3)
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(json(&typed), json(&text));
        let typed = EncryptedOrder::DOC
            .elements()
            .lines_parts()
            .sku()
            .eq("a-1")
            .encrypt(&keyset)
            .await
            .unwrap();
        let text = EncryptedOrder::DOC
            .elements_text_path("$.lines[*].parts[*]")
            .eq("sku", "a-1")
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(json(&typed), json(&text));
        // A path with no keys is `root`.
        let typed = EncryptedOrder::DOC
            .at()
            .root()
            .gt(1)
            .encrypt(&keyset)
            .await
            .unwrap();
        let text = EncryptedOrder::DOC
            .at_text_path("$[*]")
            .gt(1)
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(json(&typed), json(&text));
    }

    #[derive(EncryptTarget)]
    #[stash(struct = Customer, scope = "customers", scope(tenant: u64))]
    #[allow(dead_code)] // only queried
    struct TenantCustomer {
        name: stack_encrypt::StackCipherText,
        #[stash(json(ordered = { "$.age": u32, "$.visits[*].at": u64 }))]
        profile: JsonDocument,
    }

    #[tokio::test]
    async fn under_a_scope_a_typed_query_is_the_text_forms() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let typed = TenantCustomer::PROFILE
            .at()
            .age()
            .gt(30)
            .scope(Scope::new(7u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        let text = TenantCustomer::PROFILE
            .at_text_path("$.age")
            .gt(30)
            .scope(Scope::new(7u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        let other = TenantCustomer::PROFILE
            .at()
            .age()
            .gt(30)
            .scope(Scope::new(8u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(json(&typed), json(&text));
        assert_ne!(json(&typed), json(&other), "the scope is in the operand");
        let typed = TenantCustomer::PROFILE
            .elements()
            .visits()
            .at()
            .gt(1)
            .scope(Scope::new(7u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        let text = TenantCustomer::PROFILE
            .elements_text_path("$.visits[*]")
            .gt("at", 1)
            .scope(Scope::new(7u64))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(json(&typed), json(&text));
    }

    #[derive(Zeroize)]
    struct Account {
        customer: Customer,
    }

    #[derive(EncryptTarget)]
    #[stash(struct = Account, scope = "accounts")]
    struct EncryptedAccount {
        customer: EncryptedCustomer,
    }

    #[tokio::test]
    async fn through_an_outer_field_a_typed_query_is_the_text_forms() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let account: EncryptedAccount = Account {
            customer: customer(),
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        let reference = EncryptedAccount::CUSTOMER.field(EncryptedCustomer::PROFILE);
        let typed = reference.at().age().eq(35).encrypt(&keyset).await.unwrap();
        let text = reference
            .at_text_path("$.age")
            .eq(35)
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(typed, text);
        assert!(typed.matches(account.customer.profile.selector_set()));
        let flat = EncryptedCustomer::PROFILE
            .at()
            .age()
            .eq(35)
            .encrypt(&keyset)
            .await
            .unwrap();
        assert!(!flat.matches(account.customer.profile.selector_set()));
        let typed = reference
            .elements()
            .visits()
            .place()
            .eq("home")
            .encrypt(&keyset)
            .await
            .unwrap();
        let text = reference
            .elements_text_path("$.visits[*]")
            .eq("place", "home")
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(json(&typed), json(&text));
    }

    #[tokio::test]
    async fn a_number_json_cannot_hold_is_refused_before_any_key() {
        let (cipher, generates, _) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let refused = [
            EncryptedOrder::DOC
                .at()
                .lines_unit_price()
                .eq(f64::NAN)
                .encrypt(&keyset)
                .await
                .map(drop),
            EncryptedOrder::DOC
                .at()
                .lines_unit_price()
                .lt(f64::INFINITY)
                .encrypt(&keyset)
                .await
                .map(drop),
            EncryptedOrder::DOC
                .at()
                .lines_unit_price()
                .between(0.0, f64::NAN)
                .encrypt(&keyset)
                .await
                .map(drop),
            EncryptedOrder::DOC
                .elements()
                .lines()
                .unit_price()
                .gte(f64::NAN)
                .encrypt(&keyset)
                .await
                .map(drop),
            EncryptedOrder::DOC
                .elements()
                .lines()
                .qty()
                .eq(1)
                .and()
                .unit_price()
                .between(f64::NEG_INFINITY, 1.0)
                .encrypt(&keyset)
                .await
                .map(drop),
        ];
        for refused in refused {
            assert!(
                matches!(refused, Err(Error::Term(TermError::JsonNumberNotFinite))),
                "{refused:?}"
            );
        }
        assert_eq!(generates.load(Ordering::SeqCst), 0, "no key requested");
    }
}

/// Values a query takes: a number JSON can hold, as a document writes it,
/// and a JSON `null` by name.
mod values {
    use super::*;

    #[derive(Zeroize)]
    struct Reading {
        doc: JsonPlaintext,
    }

    #[derive(EncryptTarget)]
    #[stash(struct = Reading, scope = "readings")]
    struct EncryptedReading {
        #[stash(json(ordered = { "$.score": f64 }))]
        doc: JsonDocument,
    }

    async fn reading(keyset: &KeysetCipher<'_, FakeDataKeySource>, doc: Value) -> JsonDocument {
        let stored: EncryptedReading = Reading { doc: doc.into() }
            .encrypt_into(keyset)
            .await
            .unwrap();
        stored.doc
    }

    #[tokio::test]
    async fn a_nan_or_an_infinity_is_refused_before_any_key_and_never_matches_null() {
        let (cipher, generates, _) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let refused = [
            EncryptedReading::DOC
                .at_text_path("$.score")
                .eq(f64::NAN)
                .encrypt(&keyset)
                .await
                .map(drop),
            EncryptedReading::DOC
                .at_text_path("$.score")
                .eq(f64::INFINITY)
                .encrypt(&keyset)
                .await
                .map(drop),
            EncryptedReading::DOC
                .at_text_path("$.score")
                .gt(f64::NEG_INFINITY)
                .encrypt(&keyset)
                .await
                .map(drop),
            EncryptedReading::DOC
                .at_text_path("$.score")
                .between(0.0, f64::NAN)
                .encrypt(&keyset)
                .await
                .map(drop),
        ];
        for refused in refused {
            assert!(
                matches!(refused, Err(Error::Term(TermError::JsonNumberNotFinite))),
                "{refused:?}"
            );
        }
        assert_eq!(generates.load(Ordering::SeqCst), 0, "no key requested");
    }

    /// A query takes no `f32` (the UI case `field_reference_json_value_types`):
    /// serde_json widens one when it builds a document, so the caller
    /// passes the `f64` the document holds. `f64::from(x)` is that `f64`
    /// for a document built from `x` through serde_json, and a decimal
    /// `0.1` finds a document holding `0.1`.
    #[tokio::test]
    async fn an_f32_is_queried_as_the_f64_the_document_holds() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let widened = reading(&keyset, json!({"score": 0.1f32})).await;
        let decimal = reading(&keyset, json!({"score": 0.1})).await;
        let from_f32 = EncryptedReading::DOC
            .at_text_path("$.score")
            .eq(f64::from(0.1f32))
            .encrypt(&keyset)
            .await
            .unwrap();
        let tenth = EncryptedReading::DOC
            .at_text_path("$.score")
            .eq(0.1f64)
            .encrypt(&keyset)
            .await
            .unwrap();
        assert!(from_f32.matches(widened.selector_set()));
        assert!(!from_f32.matches(decimal.selector_set()));
        assert!(tenth.matches(decimal.selector_set()));
        assert!(!tenth.matches(widened.selector_set()));
    }

    #[tokio::test]
    async fn is_null_finds_a_json_null_and_not_an_absent_path() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let null = reading(&keyset, json!({"score": null})).await;
        let absent = reading(&keyset, json!({"other": 1})).await;
        let number = reading(&keyset, json!({"score": 1})).await;
        let query = EncryptedReading::DOC
            .at_text_path("$.score")
            .is_null()
            .encrypt(&keyset)
            .await
            .unwrap();
        assert!(query.matches(null.selector_set()));
        assert!(!query.matches(absent.selector_set()));
        assert!(!query.matches(number.selector_set()));
    }
}

mod refusals {
    use super::*;

    /// A containment document nested deeper than the index reads is
    /// refused as the walk refuses it, before any key is requested.
    #[tokio::test]
    async fn a_document_nested_too_deep_is_refused_before_any_key() {
        let (cipher, generates, _) = common::counting_cipher().await;
        let keyset = cipher.default_keyset();
        let mut deep = json!(1);
        for _ in 0..200 {
            deep = json!([deep]);
        }
        let refused = EncryptedCustomer::PROFILE
            .contains(json!({ "visits": deep }))
            .encrypt(&keyset)
            .await
            .map(drop);
        assert!(
            matches!(refused, Err(Error::Term(TermError::JsonTooDeep))),
            "{refused:?}"
        );
        assert_eq!(generates.load(Ordering::SeqCst), 0, "no key requested");
    }

    /// A counting cipher: what each refusal is checked to request.
    async fn counting() -> (
        StackCipher<common::CountingSource>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let (cipher, generates, _) = common::counting_cipher().await;
        (cipher, generates)
    }

    #[tokio::test]
    async fn an_ordering_at_a_path_the_field_does_not_order_is_refused_before_any_key() {
        let (cipher, generates) = counting().await;
        let keyset = cipher.default_keyset();
        let refused = EncryptedCustomer::PROFILE
            .at_text_path("$.name")
            .gt("A")
            .encrypt(&keyset)
            .await;
        assert!(
            matches!(refused, Err(Error::Term(TermError::JsonPathNotOrdered))),
            "{refused:?}"
        );
        let unordered = UnorderedCustomer::PROFILE
            .at_text_path("$.age")
            .gt(30)
            .encrypt(&keyset)
            .await;
        assert!(
            matches!(unordered, Err(Error::Term(TermError::JsonPathNotOrdered))),
            "a field with no options orders no path: {unordered:?}"
        );
        assert_eq!(generates.load(Ordering::SeqCst), 0, "no key requested");
    }

    /// The reason an input refusal names, or a panic naming what came
    /// back instead.
    fn reason_of<T: std::fmt::Debug>(what: &str, refused: Result<T, Error>) -> Reason {
        match refused {
            Err(Error::Input(refusal)) => refusal
                .reason()
                .unwrap_or_else(|| panic!("{what}: no reason in {refusal:?}")),
            other => panic!("{what}: not an input refusal: {other:?}"),
        }
    }

    #[tokio::test]
    async fn equality_at_a_position_is_refused() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let refused = EncryptedCustomer::PROFILE
            .at_text_path("$.tags[1]")
            .eq("b")
            .encrypt(&keyset)
            .await;
        assert_eq!(
            reason_of("eq at a position", refused),
            Reason::JsonPathPosition
        );
    }

    #[tokio::test]
    async fn the_input_shapes_a_field_reference_cannot_build_are_refused_with_their_reason() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let no_wildcard = EncryptedCustomer::PROFILE
            .elements_text_path("$.visits")
            .eq("place", "home")
            .encrypt(&keyset)
            .await
            .map(drop);
        let wildcard_node = EncryptedCustomer::PROFILE
            .children("$.visits[*]")
            .encrypt(&keyset)
            .await
            .map(drop);
        let syntax = EncryptedCustomer::PROFILE
            .predicate("$.age >")
            .encrypt(&keyset)
            .await
            .map(drop);
        let vars = EncryptedCustomer::PROFILE
            .predicate("$.age >= $min")
            .vars(json!([30]))
            .encrypt(&keyset)
            .await
            .map(drop);
        for (what, refused, reason) in [
            (
                "an elements path with no wildcard",
                no_wildcard,
                Reason::JsonPathNoWildcard,
            ),
            (
                "children of a wildcard",
                wildcard_node,
                Reason::JsonPathWildcard,
            ),
            (
                "a predicate that does not parse",
                syntax,
                Reason::JsonPredicateSyntax,
            ),
            ("variables that are not an object", vars, Reason::JsonInput),
        ] {
            assert_eq!(reason_of(what, refused), reason, "{what}");
        }
    }

    /// An input refusal reports the code and the payload the dynamic
    /// interface reports for the same input, so a caller that maps codes to
    /// its own statuses sees the input at fault, not the engine.
    #[tokio::test]
    async fn an_input_refusal_has_the_dynamic_interfaces_code_and_payload() {
        use miette::Diagnostic as _;
        use stack_encrypt::ErrorPayload as _;
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let Err(refusal) = EncryptedCustomer::PROFILE
            .elements_text_path("$.visits")
            .eq("place", "home")
            .encrypt(&keyset)
            .await
        else {
            panic!("refused")
        };
        assert_eq!(
            refusal.code().map(|code| code.to_string()).as_deref(),
            Some("stack_encrypt::dynamic_source"),
            "{refusal:?}"
        );
        assert_eq!(
            refusal.payload().get("reason"),
            Some(&json!("json_path_no_wildcard")),
            "{refusal:?}"
        );
        let Err(refusal) = EncryptedCustomer::PROFILE
            .predicate("$.age >")
            .encrypt(&keyset)
            .await
        else {
            panic!("refused")
        };
        assert_eq!(
            refusal.code().map(|code| code.to_string()).as_deref(),
            Some("stack_encrypt::dynamic_predicate"),
            "{refusal:?}"
        );
        let payload = refusal.payload();
        assert_eq!(payload.get("reason"), Some(&json!("json_predicate_syntax")));
        assert!(
            payload.contains_key("at") && payload.contains_key("construct"),
            "{payload:?}"
        );
    }
}

mod under_a_scope {
    use super::*;

    #[derive(EncryptTarget)]
    #[stash(struct = Customer, scope = "customers", scope(tenant: u64))]
    #[allow(dead_code)] // only the profile is read
    struct TenantCustomer {
        name: stack_encrypt::StackCipherText,
        #[stash(json(ordered = { "$.age": u32 }))]
        profile: JsonDocument,
    }

    #[tokio::test]
    async fn a_query_matches_the_documents_sealed_under_its_scope() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let seven: TenantCustomer = customer()
            .encrypt_into_with_context(&keyset, Scope::new(7u64))
            .await
            .unwrap();
        let query = |tenant: u64| {
            TenantCustomer::PROFILE
                .contains(json!({"name": "Ada"}))
                .scope(Scope::new(tenant))
                .encrypt(&keyset)
        };
        assert!(query(7)
            .await
            .unwrap()
            .matches(seven.profile.selector_set()));
        assert!(!query(8)
            .await
            .unwrap()
            .matches(seven.profile.selector_set()));
    }
}

mod in_a_nested_record {
    use super::*;

    #[derive(Zeroize)]
    struct Account {
        customer: Customer,
    }

    #[derive(EncryptTarget)]
    #[stash(struct = Account, scope = "accounts")]
    struct EncryptedAccount {
        customer: EncryptedCustomer,
    }

    #[tokio::test]
    async fn the_inner_fields_field_reference_queries_under_the_outer_fields_context() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let account: EncryptedAccount = Account {
            customer: customer(),
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        let reference = EncryptedAccount::CUSTOMER.field(EncryptedCustomer::PROFILE);
        let older = reference
            .at_text_path("$.age")
            .gt(30)
            .encrypt(&keyset)
            .await;
        assert!(older.is_ok(), "the inner field's options travel: {older:?}");
        let needle = reference
            .contains(json!({"name": "Ada"}))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert!(needle.matches(account.customer.profile.selector_set()));
        let flat = EncryptedCustomer::PROFILE
            .contains(json!({"name": "Ada"}))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert!(
            !flat.matches(account.customer.profile.selector_set()),
            "the outer field's context is part of the inner field's"
        );
    }
}

mod a_nullable_field {
    use super::*;

    #[derive(Zeroize)]
    struct Lead {
        profile: Option<JsonPlaintext>,
    }

    #[derive(EncryptTarget, DecryptSource)]
    #[stash(struct = Lead, scope = "leads")]
    struct EncryptedLead {
        #[stash(json(ordered = { "$.age": u32 }))]
        profile: Option<JsonDocument>,
    }

    #[tokio::test]
    async fn stores_nothing_for_none_and_is_queried_as_a_present_one() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let none: EncryptedLead = Lead { profile: None }.encrypt_into(&keyset).await.unwrap();
        assert!(none.profile.is_none());
        let some: EncryptedLead = Lead {
            profile: Some(profile().into()),
        }
        .encrypt_into(&keyset)
        .await
        .unwrap();
        let doc = some.profile.as_ref().expect("stored");
        let needle = EncryptedLead::PROFILE
            .contains(json!({"age": 35}))
            .encrypt(&keyset)
            .await
            .unwrap();
        assert!(needle.matches(doc.selector_set()));
        let older = EncryptedLead::PROFILE
            .at_text_path("$.age")
            .gt(30)
            .encrypt(&keyset)
            .await;
        assert!(older.is_ok(), "{older:?}");
        let opened = Lead::decrypt_from(some, &keyset).await.unwrap();
        assert_eq!(opened.profile.map(|p| p.value().clone()), Some(profile()));
    }
}

/// The field reference and a data plan of the same declaration derive the same
/// operands: the plan's field is the column `customers/profile`, sealed
/// under the record's options.
#[cfg(feature = "dynamic")]
mod as_the_data_plan_derives {
    use super::*;
    use stack_encrypt::dynamic::{
        self, record, Op, Operand, TargetDescriptor, TargetError, TargetOptions, TargetResolver,
        ValueFrame, ValueKind,
    };
    use stack_encrypt::target::{DeclaredContext, IndexSpec};
    use stack_encrypt::{AsProtectedRef as _, Label, Pending};

    /// A resolver holding `JsonSearch`, a document. The engine derives the
    /// JSON operators itself, so it is asked for the description alone.
    struct Documents;

    impl TargetResolver for Documents {
        fn targets(&self) -> Vec<TargetDescriptor> {
            vec![TargetDescriptor::new(
                "JsonSearch",
                "json",
                "",
                Some(ValueKind::Json),
                "public.eql_v4_json_search",
                vec!["json".to_string()],
                Some("JsonSearchQuery".to_string()),
                Some("eql_v4.query_json".to_string()),
                true,
                None,
            )
            .with_leaf_query_sql_domain("eql_v4.query_json_leaf")
            .with_elements_query_sql_domain("eql_v4.query_json_elements")
            .with_predicate_query_sql_domain("eql_v4.query_json_predicate")]
        }

        fn encrypt<'a, K: 'static>(
            &self,
            _: &str,
            _: Option<&TargetOptions>,
            _: &'a KeysetCipher<'_, K>,
            _: &Label,
            _: &DeclaredContext,
            _: ValueFrame,
        ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
            unreachable!("only queried")
        }

        fn decrypt<'a, K: 'static>(
            &self,
            _: &str,
            _: &'a StackCipher<K>,
            _: &Label,
            _: &DeclaredContext,
            _: &[u8],
        ) -> Result<Pending<'a, ValueFrame, K>, TargetError> {
            unreachable!("only queried")
        }

        fn query<'a, K: 'static>(
            &self,
            _: &str,
            _: &IndexSpec,
            _: &'a KeysetCipher<'_, K>,
            _: &Label,
            _: &DeclaredContext,
            _: ValueFrame,
        ) -> Result<Pending<'a, Vec<u8>, K>, TargetError> {
            unreachable!("the JSON operators are the engine's")
        }
    }

    /// The record's field as a data plan.
    fn plan() -> record::Plan {
        let wire = json!({
            "profile": {
                "context": ["customers", "profile"],
                "type": "json",
                "null": "sql",
                "target": {
                    "name": "JsonSearch",
                    "options": {
                        "sealed_root": true,
                        "ordered": ["$.age", "$.visits[*].at", "$.visits[*].place"]
                    }
                }
            }
        });
        record::plan_with(
            dynamic::frame::serde::to_vec(&wire)
                .unwrap()
                .as_protected_ref(),
            &Documents,
        )
        .unwrap()
    }

    /// The operand the data plan derives for `input`.
    async fn operand(
        keyset: &KeysetCipher<'_, FakeDataKeySource>,
        op: Op,
        input: Value,
    ) -> Operand {
        let frame = ValueFrame::from_bytes(
            dynamic::frame::serde::to_vec(&input)
                .unwrap()
                .as_protected_ref(),
        )
        .unwrap();
        dynamic::query_term(keyset, &plan(), "profile", op, frame, &Documents)
            .unwrap()
            .await
            .unwrap()
            .operand()
            .clone()
    }

    fn one(operand: Operand) -> Value {
        match operand {
            Operand::One(bytes) => serde_json::from_slice(&bytes).unwrap(),
            other => panic!("one operand: {other:?}"),
        }
    }

    fn text(operand: Operand) -> String {
        match operand {
            Operand::Text(text) => text,
            other => panic!("text: {other:?}"),
        }
    }

    #[tokio::test]
    async fn containment_and_equality_at_a_path() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let needle = json!({"visits": [{"place": "home"}]});
        let typed = EncryptedCustomer::PROFILE
            .contains(needle.clone())
            .encrypt(&keyset)
            .await
            .unwrap();
        let data: JsonQuery = serde_json::from_value(one(operand(
            &keyset,
            Op::Contains,
            json!({"json": needle.to_string()}),
        )
        .await))
        .unwrap();
        assert_eq!(typed, data, "one needle, compared as sets");
        let typed = EncryptedCustomer::PROFILE
            .at_text_path("$.visits[*].place")
            .eq("home")
            .encrypt(&keyset)
            .await
            .unwrap();
        let data: JsonQuery = serde_json::from_value(one(operand(
            &keyset,
            Op::EqAt,
            json!({"path": "$.visits[*].place", "json": "\"home\""}),
        )
        .await))
        .unwrap();
        assert_eq!(typed, data);
        let declared = EncryptedCustomer::PROFILE
            .at()
            .visits_place()
            .eq("home")
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(declared, data, "the declared path's needle");
    }

    #[tokio::test]
    async fn orderings_and_the_selector() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let typed = EncryptedCustomer::PROFILE
            .at_text_path("$.age")
            .gte(18)
            .encrypt(&keyset)
            .await
            .unwrap();
        let data = one(operand(&keyset, Op::GteAt, json!({"path": "$.age", "json": "18"})).await);
        assert_eq!(serde_json::to_value(&typed).unwrap(), data);
        let declared = EncryptedCustomer::PROFILE
            .at()
            .age()
            .gte(18)
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(serde_json::to_value(&declared).unwrap(), data);
        let (low, high) = EncryptedCustomer::PROFILE
            .at_text_path("$.visits[*].at")
            .between(10, 20)
            .encrypt(&keyset)
            .await
            .unwrap();
        let Operand::Range { lo, hi } = operand(
            &keyset,
            Op::BetweenAt,
            json!({"path": "$.visits[*].at", "low": "10", "high": "20"}),
        )
        .await
        else {
            panic!("a range")
        };
        assert_eq!(
            serde_json::to_value(&low).unwrap(),
            serde_json::from_slice::<Value>(&lo).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&high).unwrap(),
            serde_json::from_slice::<Value>(&hi).unwrap()
        );
        let (low, high) = EncryptedCustomer::PROFILE
            .at()
            .visits_at()
            .between(10, 20)
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(
            (
                serde_json::to_value(&low).unwrap(),
                serde_json::to_value(&high).unwrap()
            ),
            (
                serde_json::from_slice::<Value>(&lo).unwrap(),
                serde_json::from_slice::<Value>(&hi).unwrap()
            ),
            "the declared path's range"
        );
        let selector = EncryptedCustomer::PROFILE
            .at_text_path("$.age")
            .selector()
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(
            selector.to_string(),
            text(operand(&keyset, Op::Selector, json!({"path": "$.age"})).await)
        );
        let declared = EncryptedCustomer::PROFILE
            .at()
            .age()
            .selector()
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(declared, selector);
    }

    #[tokio::test]
    async fn element_match_predicates_and_children() {
        let cipher = cipher().await;
        let keyset = cipher.default_keyset();
        let typed = EncryptedCustomer::PROFILE
            .elements_text_path("$.visits[*]")
            .eq("place", "home")
            .between("at", 10, 20)
            .wildcard_bound(NonZeroU32::new(8).unwrap())
            .encrypt(&keyset)
            .await
            .unwrap();
        let data = one(operand(
            &keyset,
            Op::ElementMatch,
            json!({"path": "$.visits[*]", "wildcard_bound": 8, "predicates": [
                {"member": "place", "op": "eq", "json": "\"home\""},
                {"member": "at", "op": "between", "low": "10", "high": "20"}
            ]}),
        )
        .await);
        assert_eq!(serde_json::to_value(&typed).unwrap(), data);
        assert_eq!(typed.len(), 2);
        let declared = EncryptedCustomer::PROFILE
            .elements()
            .visits()
            .place()
            .eq("home")
            .and()
            .at()
            .between(10, 20)
            .wildcard_bound(NonZeroU32::new(8).unwrap())
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(&declared).unwrap(),
            data,
            "the declared array's predicate"
        );

        // Selectors and orderings: deterministic leaves, so the trees
        // compare as written.
        let typed = EncryptedCustomer::PROFILE
            .predicate("$.age >= $min && exists($.name)")
            .vars(json!({"min": 30}))
            .encrypt(&keyset)
            .await
            .unwrap();
        let data = one(operand(
            &keyset,
            Op::Match,
            json!({"predicate": "$.age >= $min && exists($.name)", "vars": "{\"min\": 30}"}),
        )
        .await);
        assert_eq!(serde_json::to_value(&typed).unwrap(), data);

        let token = EncryptedCustomer::PROFILE
            .children("$.visits")
            .encrypt(&keyset)
            .await
            .unwrap();
        assert_eq!(
            token.tokens(),
            vec![text(
                operand(&keyset, Op::Children, json!({"path": "$.visits"})).await
            )]
        );
    }
}
