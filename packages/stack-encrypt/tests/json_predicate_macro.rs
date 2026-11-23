//! `predicate!`: a SQL/JSON path predicate on a document field, checked when
//! the program compiles and sent as written when it runs.
//!
//! Each test holds the macro's query to the one `predicate(text)` builds with
//! the same variables, byte for byte under one seed of the deterministic key
//! source (with the crate's `test-support` feature, which seeds the JSON
//! index's permutations), and as sets of selectors without it. With the
//! `dynamic` feature, it is also held to the operand the data plan's `match`
//! operator derives for the same text and variables. The compile-time
//! refusals are the `tests/ui/predicate_*.rs` cases.

mod common;

use std::cell::Cell;
use std::num::NonZeroU32;

use serde_json::Value;
use stack_encrypt::field_reference::json::{JsonFieldQuery, Predicate};
use stack_encrypt::json::{JsonDocument, JsonPlaintext};
use stack_encrypt::target::{EncryptTarget, Scope};
use stack_encrypt::{predicate, Ready};
use zeroize::Zeroize;

#[derive(Zeroize)]
struct Customer {
    profile: JsonPlaintext,
}

/// A profile with every kind of declared path: ordered numbers and strings,
/// paths for equality alone (a string, a boolean, a keyword key, quoted keys
/// named with `names`, an array's elements, an array's member), and members
/// of two arrays and of a nested array.
#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers")]
#[allow(dead_code)] // only queried
struct EncryptedCustomer {
    #[stash(json(
        ordered = {
            "$.age": u32,
            "$.score": f64,
            "$.visits[*].at": u64,
            "$.visits[*].place": String,
            "$.contacts[*].relationship": String,
            "$.contacts[*].calls": u32,
            "$.orders[*].lines[*].qty": u32,
        },
        paths = {
            "$.name": String,
            "$.note": String,
            "$.vip": bool,
            "$.type": String,
            "$[\"first name\"]": String,
            "$[\"ship to\"].zip": String,
            "$.tags[*]": String,
            "$.visits[*].kind": String,
        },
        names = { "first name": given_name, "ship to": shipping },
    ))]
    profile: JsonDocument,
}

/// The same profile under a record that lists a scope.
#[derive(EncryptTarget)]
#[stash(struct = Customer, scope = "customers", scope(tenant: u64))]
#[allow(dead_code)] // only queried
struct TenantCustomer {
    #[stash(json(ordered = { "$.age": u32 }, paths = { "$.name": String }))]
    profile: JsonDocument,
}

#[derive(Zeroize)]
struct Account {
    customer: Customer,
}

/// The profile reached through an outer record.
#[derive(EncryptTarget)]
#[stash(struct = Account, scope = "accounts")]
#[allow(dead_code)] // only queried
struct EncryptedAccount {
    customer: EncryptedCustomer,
}

type Query = JsonFieldQuery<JsonDocument, Predicate, Ready>;

/// The seed every comparison derives under: both sides start from a fresh
/// cipher at the same seed, so they draw the same permutations.
const SEED: [u8; 32] = [5; 32];

/// The operand `query` derives, from a fresh cipher at [`SEED`].
async fn operand(query: Query) -> Value {
    let cipher = common::deterministic_cipher(SEED).await;
    let keyset = cipher.default_keyset();
    serde_json::to_value(query.encrypt(&keyset).await.expect("derives")).unwrap()
}

/// `value` with every selector set (`sv`) sorted, so two needles compare as
/// sets whatever order each was sent in.
fn sets(mut value: Value) -> Value {
    fn sort(value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, inner) in map.iter_mut() {
                    if let (true, Value::Array(items)) = (key == "sv", &mut *inner) {
                        items.sort_by_key(|item| item.to_string());
                    }
                    sort(inner);
                }
            }
            Value::Array(items) => items.iter_mut().for_each(sort),
            _ => {}
        }
    }
    sort(&mut value);
    value
}

/// The macro's query and the text form's derive the same operand.
async fn assert_same(text: &str, from_macro: Query, from_text: Query) {
    let (from_macro, from_text) = (operand(from_macro).await, operand(from_text).await);
    #[cfg(feature = "test-support")]
    assert_eq!(from_macro, from_text, "byte for byte: {text}");
    assert_eq!(sets(from_macro), sets(from_text), "{text}");
}

/// The macro and `predicate(text)` with the same variables, through a
/// declarative macro, as a caller's own macro would reach it.
macro_rules! same_as_text {
    ($text:literal $(, $name:ident = $value:expr)* $(,)?) => {
        assert_same(
            $text,
            predicate!(EncryptedCustomer::PROFILE, $text $(, $name = $value)*),
            EncryptedCustomer::PROFILE.predicate($text) $(.var(stringify!($name), $value))*,
        )
        .await
    };
}

mod given_each_construct_of_the_grammar {
    use super::*;

    #[tokio::test]
    async fn each_comparison_at_one_node() {
        same_as_text!("$.age >= $min", min = 30u32);
        same_as_text!("$.age < 18");
        same_as_text!("$.age <= 18");
        same_as_text!("$.age > 18");
        same_as_text!("$.age == 35");
        same_as_text!("$.age != 35");
        same_as_text!("$.age <> 35");
        same_as_text!("18 < $.age");
        same_as_text!("$.score > 1.5");
        same_as_text!("$.score >= 2");
        same_as_text!("$.score < $s", s = 2.5);
        same_as_text!(r#"$.name == "Ada""#);
        same_as_text!("$.name == $name", name = "Ada");
        same_as_text!("$.name == null");
        same_as_text!("$.name != null");
        same_as_text!("$.vip == true");
        same_as_text!("$.vip == $vip", vip = false);
    }

    #[tokio::test]
    async fn keys_that_are_not_rust_names() {
        same_as_text!(r#"$.type == "retail""#);
        same_as_text!(r#"$."type" == "retail""#);
        same_as_text!(r#"$."first name" == $first"#, first = "Ada");
        same_as_text!(r#"$."ship to".zip == "3000""#);
        same_as_text!(r#"$ . "ship to" . zip == "3000""#);
    }

    #[tokio::test]
    async fn wildcards_presence_and_filters() {
        same_as_text!(r#"$.tags[*] == "a""#);
        same_as_text!("$.visits[*].at > 10");
        same_as_text!("exists($.age)");
        same_as_text!("exists($.visits[*].place)");
        same_as_text!("!exists($.name)");
        same_as_text!(r#"exists($.visits[*] ? (@.place == "home"))"#);
        same_as_text!(r#"exists($.visits[*] ? (@.kind == "walk-in"))"#);
        same_as_text!(
            "exists($.visits[*] ? (@.place == $p && @.at > $after))",
            p = "home",
            after = 10u64,
        );
        same_as_text!(
            "exists($.contacts[*] ? (@.relationship == $r && @.calls > 5))",
            r = "Sibling",
        );
        same_as_text!("exists($.contacts[*] ? ((@.calls >= 1) && (@.calls < 9)))");
        same_as_text!("$.orders[*].lines[*].qty > 2");
        same_as_text!("exists($.orders[*].lines[*] ? (@.qty >= 1 && @.qty < 9))");
    }

    #[tokio::test]
    async fn the_boolean_structure_and_the_text_around_it() {
        same_as_text!(r#"$.age > 1 && ($.name == "Ada" || !($.score < 2))"#);
        same_as_text!(
            "$.age >= $min && $.name == $name && $.vip == $vip && $.note == null",
            min = 30u32,
            name = "Ada",
            vip = true,
        );
        same_as_text!("  $.age /* why */ >= $min  ", min = 30u32);
        same_as_text!("EXISTS($.age) && Exists($.name)");
    }
}

mod given_how_a_caller_writes_it {
    use super::*;

    /// A local variable's name alone gives it, and moves it; a
    /// quoted variable is given by its name as a string; a value is any
    /// expression, and a trailing comma is read.
    #[tokio::test]
    async fn variables_by_name_by_string_and_by_expression() {
        let min: u32 = 30;
        let name = "Ada".to_owned();
        let name = &name;
        assert_same(
            "shorthand",
            predicate!(
                EncryptedCustomer::PROFILE,
                "$.age >= $min && $.name == $name",
                min,
                name
            ),
            EncryptedCustomer::PROFILE
                .predicate("$.age >= $min && $.name == $name")
                .var("min", min)
                .var("name", name),
        )
        .await;
        assert_same(
            "a quoted variable",
            predicate!(
                EncryptedCustomer::PROFILE,
                r#"$.age >= $"min age""#,
                "min age" = min + 1,
            ),
            EncryptedCustomer::PROFILE
                .predicate(r#"$.age >= $"min age""#)
                .var("min age", 31u32),
        )
        .await;
        let r#type = "retail";
        assert_same(
            "a keyword variable",
            predicate!(EncryptedCustomer::PROFILE, "$.type == $type", r#type),
            EncryptedCustomer::PROFILE
                .predicate("$.type == $type")
                .var("type", "retail"),
        )
        .await;
    }

    /// Each variable's expression runs once, in the order given, and the
    /// field reference's first.
    #[tokio::test]
    async fn each_expression_is_evaluated_once_in_order() {
        let order = Cell::new(Vec::new());
        let note = |what: &'static str| {
            let mut seen = order.take();
            seen.push(what);
            order.set(seen);
        };
        let query = predicate!(
            {
                note("reference");
                EncryptedCustomer::PROFILE
            },
            "$.age >= $min && $.name == $name",
            name = {
                note("name");
                "Ada"
            },
            min = {
                note("min");
                30u32
            },
        );
        assert_eq!(order.take(), ["reference", "name", "min"]);
        assert_same(
            "evaluated once",
            query,
            EncryptedCustomer::PROFILE
                .predicate("$.age >= $min && $.name == $name")
                .var("name", "Ada")
                .var("min", 30u32),
        )
        .await;
    }

    /// The query takes `wildcard_bound`, as the text form's does.
    #[tokio::test]
    async fn a_wildcard_bound_is_kept() {
        let bound = NonZeroU32::new(8).unwrap();
        let text = "exists($.visits[*] ? (@.place == \"home\" && @.at > 10))";
        assert_same(
            text,
            predicate!(
                EncryptedCustomer::PROFILE,
                "exists($.visits[*] ? (@.place == \"home\" && @.at > 10))"
            )
            .wildcard_bound(bound),
            EncryptedCustomer::PROFILE
                .predicate(text)
                .wildcard_bound(bound),
        )
        .await;
    }

    /// A record that lists a scope takes it after the macro.
    #[tokio::test]
    async fn a_scope_is_given_after_the_macro() {
        assert_same(
            "scoped",
            predicate!(
                TenantCustomer::PROFILE,
                r#"$.age > $min && $.name == "Ada""#,
                min = 3u32
            )
            .scope(Scope::new(7u64)),
            TenantCustomer::PROFILE
                .predicate(r#"$.age > $min && $.name == "Ada""#)
                .var("min", 3u32)
                .scope(Scope::new(7u64)),
        )
        .await;
    }

    /// A field reached through an outer record checks its paths as its own,
    /// and derives under the outer field's context.
    #[tokio::test]
    async fn a_field_through_an_outer_record() {
        let reference = EncryptedAccount::CUSTOMER.field(EncryptedCustomer::PROFILE);
        assert_same(
            "through an outer field",
            predicate!(
                EncryptedAccount::CUSTOMER.field(EncryptedCustomer::PROFILE),
                "$.age >= $min && exists($.visits[*] ? (@.place == $p && @.at > 3))",
                min = 30u32,
                p = "home",
            ),
            reference
                .predicate("$.age >= $min && exists($.visits[*] ? (@.place == $p && @.at > 3))")
                .var("min", 30u32)
                .var("p", "home"),
        )
        .await;
    }

    /// What only a run-time value can make wrong is refused when the query
    /// is encrypted, as the text form refuses it.
    #[tokio::test]
    async fn the_query_is_refused_at_run_time_as_the_text_form_is() {
        let cipher = common::deterministic_cipher(SEED).await;
        let keyset = cipher.default_keyset();
        // A NaN is no JSON number: refused when the query is encrypted,
        // before any key is requested, on both paths.
        let from_macro = predicate!(EncryptedCustomer::PROFILE, "$.score > $s", s = f64::NAN)
            .encrypt(&keyset)
            .await
            .unwrap_err();
        let from_text = EncryptedCustomer::PROFILE
            .predicate("$.score > $s")
            .var("s", f64::NAN)
            .encrypt(&keyset)
            .await
            .unwrap_err();
        assert_eq!(from_macro.to_string(), from_text.to_string());
    }
}

#[cfg(feature = "dynamic")]
mod as_the_data_plan_derives {
    use super::*;
    use serde_json::json;
    use stack_encrypt::dynamic::{
        self, record, Op, Operand, TargetDescriptor, TargetError, TargetOptions, TargetResolver,
        ValueFrame, ValueKind,
    };
    use stack_encrypt::target::{DeclaredContext, IndexSpec};
    use stack_encrypt::{AsProtectedRef as _, KeysetCipher, Label, Pending, StackCipher};

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

    /// The record's field as a data plan: its ordered paths, and none of
    /// its `paths`, which add nothing to its options.
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
                        "ordered": [
                            "$.age", "$.score", "$.visits[*].at", "$.visits[*].place",
                            "$.contacts[*].relationship", "$.contacts[*].calls",
                            "$.orders[*].lines[*].qty"
                        ]
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

    /// The operand the data plan's `match` derives for `text` and `vars`,
    /// from a fresh cipher at [`SEED`].
    async fn matched(text: &str, vars: Value) -> Value {
        let cipher = common::deterministic_cipher(SEED).await;
        let keyset = cipher.default_keyset();
        let input = json!({"predicate": text, "vars": vars.to_string()});
        let frame = ValueFrame::from_bytes(
            dynamic::frame::serde::to_vec(&input)
                .unwrap()
                .as_protected_ref(),
        )
        .unwrap();
        let operand =
            dynamic::query_term(&keyset, &plan(), "profile", Op::Match, frame, &Documents)
                .unwrap()
                .await
                .unwrap()
                .operand()
                .clone();
        match operand {
            Operand::One(bytes) => serde_json::from_slice(&bytes).unwrap(),
            other => panic!("one operand: {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_macro_derives_the_match_operand() {
        let text = "$.age >= $min && $.name == $name && $.vip == $vip && $.note == null \
                    && exists($.contacts[*] ? (@.relationship == $r && @.calls > 5)) \
                    && $.\"first name\" == \"Ada\"";
        let from_macro = operand(predicate!(
            EncryptedCustomer::PROFILE,
            "$.age >= $min && $.name == $name && $.vip == $vip && $.note == null \
             && exists($.contacts[*] ? (@.relationship == $r && @.calls > 5)) \
             && $.\"first name\" == \"Ada\"",
            min = 30u32,
            name = "Ada",
            vip = true,
            r = "Sibling",
        ))
        .await;
        let data = matched(
            text,
            json!({"min": 30, "name": "Ada", "vip": true, "r": "Sibling"}),
        )
        .await;
        #[cfg(feature = "test-support")]
        assert_eq!(from_macro, data, "byte for byte");
        assert_eq!(sets(from_macro), sets(data));
    }
}
