//! EQL types as plan field targets, reached by name: the dispatch in
//! `eql_bindings::encryption::targets` must run the same plan the typed
//! `encrypt_as::<TextEq>` call runs, refuse what the table says it cannot
//! produce, and the table must be the catalog.

mod common;

use eql_bindings::encryption::targets::{self as targets, Opener, Target, TargetError};
use eql_bindings::v3::text::{TextEq, TextEqQuery};
use eql_bindings::{v3, Identifier};
use eql_domains::{Shape, Term, CATALOG};
use stack_encrypt::Label;
use vitaminc_aead_value::{FfiValue, ValueKind};

fn email() -> Label {
    Label::new(["users", "email"]).unwrap()
}

fn column() -> stack_encrypt::NonEmpty<Identifier> {
    Identifier::for_column("users", "email").unwrap()
}

fn text(value: &str) -> FfiValue {
    FfiValue::String(value.into())
}

fn opened(value: FfiValue) -> String {
    match value {
        FfiValue::String(s) => std::str::from_utf8(s.risky_ref()).unwrap().to_owned(),
        other => panic!("a text target opens to a string, not {:?}", other.kind()),
    }
}

/// The refusal a dispatch returned. `Pending` has no `Debug`, so this stands
/// in for `unwrap_err`; an accepted call is the test's failure.
fn refused<T>(result: Result<T, TargetError>) -> TargetError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("the dispatch accepted what it should have refused"),
    }
}

mod given_text_eq {
    use super::*;

    /// The dispatch and the typed call are the same plan: same identifier,
    /// same equality term, and each side's value opens through the other.
    /// The ciphertexts differ because every write seals under a fresh key,
    /// so byte identity is asserted on everything but `c`.
    #[tokio::test]
    async fn produces_what_encrypt_as_produces() {
        let (cipher, calls) = common::cipher().await;
        let keyset = cipher.default_keyset();
        for value in ["alice@example.com", "", "雪☃", "cafe\u{301}"] {
            let by_name = targets::encrypt("TextEq", &keyset, &email(), text(value))
                .unwrap()
                .await
                .unwrap();
            let by_name: TextEq = serde_json::from_slice(&by_name).unwrap();
            let typed: TextEq = keyset
                .encrypt_as(&value.to_owned(), column())
                .await
                .unwrap();
            assert_eq!(by_name.v, typed.v, "{value:?}: same envelope version");
            assert_eq!(
                by_name.i, typed.i,
                "{value:?}: the label is the stored identifier"
            );
            assert_eq!(by_name.hm, typed.hm, "{value:?}: same equality term");
            assert_ne!(
                by_name.c, typed.c,
                "{value:?}: each write seals under a fresh key"
            );

            let typed_opened: String = cipher
                .decrypt_as(by_name.clone(), column().into())
                .await
                .unwrap();
            assert_eq!(
                typed_opened, value,
                "{value:?}: the typed path opens the named value"
            );
            let named_opened = targets::decrypt(
                "TextEq",
                &cipher,
                &email(),
                &serde_json::to_vec(&typed).unwrap(),
            )
            .unwrap()
            .await
            .unwrap();
            assert_eq!(
                opened(named_opened),
                value,
                "{value:?}: the named path opens the typed value"
            );
        }
        let calls = calls.lock().unwrap();
        assert!(
            calls.generate.iter().flatten().all(|d| d == "users/email"),
            "both paths mint under the column's descriptor: {:?}",
            calls.generate
        );
        assert!(
            calls.retrieve.iter().flatten().all(|d| d == "users/email"),
            "both paths retrieve under the column's descriptor: {:?}",
            calls.retrieve
        );
    }

    #[tokio::test]
    async fn round_trips_through_both_openers() {
        let (cipher, _) = common::cipher().await;
        let keyset = cipher.default_keyset();
        let stored = targets::encrypt("TextEq", &keyset, &email(), text("secret"))
            .unwrap()
            .await
            .unwrap();
        let through_client = targets::decrypt("TextEq", Opener::Client(&cipher), &email(), &stored)
            .unwrap()
            .await
            .unwrap();
        assert_eq!(
            opened(through_client),
            "secret",
            "the client opens its keyset's value"
        );
        let through_keyset = targets::decrypt("TextEq", &keyset, &email(), &stored)
            .unwrap()
            .await
            .unwrap();
        assert_eq!(
            opened(through_keyset),
            "secret",
            "the keyset opens its own value"
        );
    }

    #[tokio::test]
    async fn query_bytes_are_the_typed_query_twin() {
        let (cipher, calls) = common::cipher().await;
        let keyset = cipher.default_keyset();
        let by_name = targets::query("TextEq", &keyset, &email(), text("alice@example.com"))
            .unwrap()
            .await
            .unwrap();
        let typed: TextEqQuery = keyset
            .encrypt_as(&"alice@example.com".to_owned(), column())
            .await
            .unwrap();
        assert_eq!(
            by_name,
            serde_json::to_vec(&typed).unwrap(),
            "a query has no fresh key in it, so the bytes are identical"
        );
        let stored = targets::encrypt("TextEq", &keyset, &email(), text("alice@example.com"))
            .unwrap()
            .await
            .unwrap();
        let stored: TextEq = serde_json::from_slice(&stored).unwrap();
        assert_eq!(typed.hm, stored.hm, "the query matches the stored value");
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.generate.len(),
            1,
            "only the stored value minted a key"
        );
        assert!(calls.retrieve.is_empty(), "a query retrieves nothing");
    }

    #[tokio::test]
    async fn opens_under_the_expected_column_only() {
        let (cipher, calls) = common::cipher().await;
        let keyset = cipher.default_keyset();
        let stored = targets::encrypt("TextEq", &keyset, &email(), text("secret"))
            .unwrap()
            .await
            .unwrap();
        let other = Label::new(["users", "name"]).unwrap();
        let result = targets::decrypt("TextEq", &cipher, &other, &stored)
            .unwrap()
            .await;
        match result {
            Err(error) => assert!(
                matches!(error, stack_encrypt::Error::ContextMismatch { .. }),
                "a different expected column is refused before any key is retrieved: {error}"
            ),
            Ok(_) => panic!("a value stored under another column opened"),
        }
        assert!(
            calls.lock().unwrap().retrieve.is_empty(),
            "nothing was retrieved"
        );
    }

    #[tokio::test]
    async fn refuses_a_value_of_another_kind_before_minting() {
        let (cipher, calls) = common::cipher().await;
        let keyset = cipher.default_keyset();
        let error = refused(targets::encrypt(
            "TextEq",
            &keyset,
            &email(),
            FfiValue::UInt64(34),
        ));
        assert!(
            matches!(
                error,
                TargetError::Plaintext {
                    target: "TextEq",
                    expected: ValueKind::String,
                    found: Some(ValueKind::UInt64)
                }
            ),
            "{error}"
        );
        let error = refused(targets::query("TextEq", &keyset, &email(), FfiValue::Null));
        assert!(
            matches!(error, TargetError::Plaintext { found: None, .. }),
            "{error}"
        );
        assert!(
            calls.lock().unwrap().generate.is_empty(),
            "nothing was minted"
        );
    }

    #[tokio::test]
    async fn refuses_bytes_that_are_not_the_type() {
        let (cipher, _) = common::cipher().await;
        for bytes in [
            &b"not json"[..],
            br#"{"v":3,"i":{"t":"users","c":"email"},"hm":"00"}"#,
        ] {
            let error = refused(targets::decrypt("TextEq", &cipher, &email(), bytes));
            assert!(
                matches!(
                    error,
                    TargetError::Stored {
                        target: "TextEq",
                        ..
                    }
                ),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn refuses_a_label_that_is_not_a_column() {
        let (cipher, _) = common::cipher().await;
        let keyset = cipher.default_keyset();
        let tenant = Label::new(["tenant", "users", "email"]).unwrap();
        let error = refused(targets::encrypt("TextEq", &keyset, &tenant, text("x")));
        assert!(
            matches!(&error, TargetError::Context { label } if label == "tenant/users/email"),
            "{error}"
        );
    }
}

mod given_a_name_the_engine_cannot_produce {
    use super::*;

    #[tokio::test]
    async fn every_entry_point_refuses_it_with_the_table_reason() {
        let (cipher, calls) = common::cipher().await;
        let keyset = cipher.default_keyset();
        let unproducible = |error: TargetError, name: &str| {
            let reason = targets::target(name).unwrap().reason.unwrap();
            assert!(
                matches!(&error, TargetError::Unproducible { name: n, reason: r } if *n == name && *r == reason),
                "{name}: {error}"
            );
        };
        for target in targets::targets().iter().filter(|t| !t.producible) {
            let name = target.name;
            unproducible(
                refused(targets::encrypt(name, &keyset, &email(), text("x"))),
                name,
            );
            unproducible(
                refused(targets::query(name, &keyset, &email(), text("x"))),
                name,
            );
            unproducible(
                refused(targets::decrypt(name, &cipher, &email(), b"{}")),
                name,
            );
        }
        let error = refused(targets::encrypt("TextOrdOre", &keyset, &email(), text("x")));
        assert_eq!(
            error.to_string(),
            "the engine cannot produce TextOrdOre yet: EQL stores a block ORE term and the engine \
             derives a CLLW ORE term; the two are different algorithms"
        );
        // Refused by name before the label or the value is looked at.
        let error = refused(targets::encrypt(
            "TextOrdOre",
            &keyset,
            &Label::new(["one"]).unwrap(),
            FfiValue::Null,
        ));
        assert!(matches!(error, TargetError::Unproducible { .. }), "{error}");
        let calls = calls.lock().unwrap();
        assert!(
            calls.generate.is_empty() && calls.retrieve.is_empty(),
            "no key was touched"
        );
    }
}

mod given_an_unknown_name {
    use super::*;

    #[tokio::test]
    async fn every_entry_point_says_no_such_type() {
        let (cipher, _) = common::cipher().await;
        let keyset = cipher.default_keyset();
        for name in ["Nope", "texteq", "text_eq", "TextEqQuery", ""] {
            let unknown = |error: TargetError| {
                assert!(
                    matches!(&error, TargetError::Unknown { name: n } if n == name),
                    "{name:?}: {error}"
                );
            };
            unknown(refused(targets::encrypt(
                name,
                &keyset,
                &email(),
                text("x"),
            )));
            unknown(refused(targets::query(name, &keyset, &email(), text("x"))));
            unknown(refused(targets::decrypt(name, &cipher, &email(), b"{}")));
        }
        assert_eq!(
            refused(targets::encrypt("Nope", &keyset, &email(), text("x"))).to_string(),
            "no such EQL type: Nope"
        );
    }
}

mod the_table {
    use super::*;

    /// The stored domains of the catalog, in catalog order: every scalar
    /// domain plus the SteVec document — the rows the table must have.
    fn stored_domains() -> Vec<(
        &'static eql_domains::DomainFamily,
        &'static eql_domains::Domain,
    )> {
        CATALOG
            .iter()
            .flat_map(|f| f.domains.iter().map(move |d| (f, d)))
            .filter(|(f, d)| d.is_scalar() || d.full_name(f.name) == "json_search")
            .collect()
    }

    fn index_key(term: Term) -> &'static str {
        match term {
            Term::Hm => "eq",
            Term::Bloom => "match",
            Term::Ore => "ore",
            Term::Ope => "ope",
        }
    }

    #[test]
    fn names_every_stored_catalog_domain_in_order() {
        let table = targets::targets();
        let expected = stored_domains();
        assert_eq!(
            table.iter().map(|t| t.name).collect::<Vec<_>>(),
            expected
                .iter()
                .map(|(f, d)| d.rust_struct_name(f.name))
                .collect::<Vec<_>>(),
            "one row per stored domain, named as its struct, in catalog order"
        );
        for (row, (family, domain)) in table.iter().zip(&expected) {
            let name = row.name;
            assert_eq!(row.family, family.name, "{name}: family");
            assert_eq!(
                row.sql_domain,
                format!("public.{}", domain.sql_typname(family.name)),
                "{name}: stored domain"
            );
            let indexes: Vec<&str> = if matches!(domain.shape, Shape::SteVec) {
                vec!["json"]
            } else {
                Term::payload_terms(domain.terms)
                    .into_iter()
                    .map(index_key)
                    .collect()
            };
            assert_eq!(row.indexes, indexes.as_slice(), "{name}: indexes");
            let suffix: String = domain
                .name
                .split('_')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    let mut c = s.chars();
                    c.next().unwrap().to_uppercase().collect::<String>() + c.as_str()
                })
                .collect();
            assert_eq!(row.suffix, suffix, "{name}: suffix");
            assert_eq!(
                row.plaintext,
                (family.name == "text").then_some("string"),
                "{name}: only text's plaintext encoding is specified"
            );
            assert_eq!(
                row.plaintext_kind(),
                (family.name == "text").then_some(ValueKind::String),
                "{name}: the plaintext name is a vitaminc kind"
            );
            if matches!(domain.shape, Shape::SteVec) {
                assert_eq!(
                    row.query,
                    Some("SteVecQuery"),
                    "{name}: the containment needle"
                );
                assert_eq!(row.query_sql_domain, Some("eql_v3.query_json"), "{name}");
            } else if domain.terms.is_empty() {
                assert_eq!(
                    (row.query, row.query_sql_domain),
                    (None, None),
                    "{name}: storage-only"
                );
            } else {
                assert_eq!(
                    row.query.map(str::to_owned),
                    Some(format!("{}Query", domain.struct_ident(family.name))),
                    "{name}: query twin"
                );
                assert_eq!(
                    row.query_sql_domain.map(str::to_owned),
                    Some(format!("eql_v3.{}", domain.query_name(family.name))),
                    "{name}: query domain"
                );
            }
        }
    }

    #[test]
    fn every_row_is_a_compiled_domain_type_and_so_is_its_query() {
        let stored: Vec<&str> = v3::all().iter().map(|d| d.sql_domain()).collect();
        let queries: Vec<&str> = v3::all_query().iter().map(|d| d.sql_domain()).collect();
        for row in targets::targets() {
            assert!(
                stored.contains(&row.sql_domain),
                "{}: {} is in all()",
                row.name,
                row.sql_domain
            );
            if let Some(query) = row.query_sql_domain {
                // The SteVec needle is in `all()`, not `all_query()`: it is
                // a hand-written document shape, not a scalar twin.
                assert!(
                    queries.contains(&query) || stored.contains(&query),
                    "{}: {query} is a compiled domain type",
                    row.name
                );
            }
        }
    }

    #[test]
    fn text_eq_is_the_one_producible_type_today() {
        let producible: Vec<&str> = targets::targets()
            .iter()
            .filter(|t| t.producible)
            .map(|t| t.name)
            .collect();
        assert_eq!(
            producible,
            ["TextEq"],
            "the plan's list: the engine produces TextEq only"
        );
        for row in targets::targets().iter().filter(|t| !t.producible) {
            let reason = row.reason.expect("an unproducible type has a reason");
            let expected = match (row.family, row.suffix) {
                ("json", "Search") => "JSON index",
                (family, _) if family != "text" => "encodes a plaintext",
                (_, "OrdOre" | "SearchOre") => "CLLW",
                (_, "Match" | "Ord" | "OrdOpe" | "Search") => "no EQL type is built",
                (_, "") => "storage-only",
                (_, suffix) => panic!("{}: unexpected text suffix {suffix}", row.name),
            };
            assert!(reason.contains(expected), "{}: {reason}", row.name);
        }
    }

    /// The `se_targets` wire format, pinned on one row: a field renamed or
    /// dropped here is a change every reader of the export sees.
    #[test]
    fn serializes_as_the_documented_wire_format() {
        let row: &Target = targets::target("TextEq").unwrap();
        assert_eq!(
            serde_json::to_value(row).unwrap(),
            serde_json::json!({
                "name": "TextEq",
                "family": "text",
                "suffix": "Eq",
                "plaintext": "string",
                "sql_domain": "public.eql_v3_text_eq",
                "indexes": ["eq"],
                "query": "TextEqQuery",
                "query_sql_domain": "eql_v3.query_text_eq",
                "producible": true,
                "reason": null
            })
        );
        let row = targets::target("Integer").unwrap();
        let json = serde_json::to_value(row).unwrap();
        assert_eq!(
            json["plaintext"],
            serde_json::Value::Null,
            "an unspecified plaintext is null, not absent"
        );
        assert_eq!(json["query"], serde_json::Value::Null);
        assert_eq!(json["producible"], false);
        assert!(json["reason"].is_string());
        // The whole table serializes as a list, the shape of the export.
        let all = serde_json::to_value(targets::targets()).unwrap();
        assert_eq!(all.as_array().unwrap().len(), targets::targets().len());
    }
}

mod the_cross_language_fixture {
    use super::*;
    use std::path::PathBuf;

    /// `fixtures/text_eq_query.json`: the `TextEqQuery` for one plaintext
    /// under the key source every test in the repository derives terms
    /// under (`FakeDataKeySource`'s index key, keyset nil), as the Rust
    /// dispatch produces it. The Go SDK's hermetic test seals the same
    /// plaintext through generated code over the deterministic guest build
    /// — whose index key is the same — and asserts its `Fields.Email.Query`
    /// bytes equal these, which is the cross-language half of the proof
    /// that a Go `encrypt_into=TextEq` field runs this plan and no other.
    /// Regenerate with `EQL_UPDATE_FIXTURES=1`; the bytes must not change
    /// otherwise.
    fn fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/text_eq_query.json")
    }

    const PLAINTEXT: &str = "bob@example.com";

    #[tokio::test]
    async fn the_text_eq_query_fixture_is_what_the_dispatch_derives() {
        let (cipher, calls) = common::cipher().await;
        let keyset = cipher.default_keyset();
        let query = targets::query("TextEq", &keyset, &email(), text(PLAINTEXT))
            .unwrap()
            .await
            .unwrap();
        assert!(
            calls.lock().unwrap().generate.is_empty(),
            "a query mints nothing"
        );
        let fixture = serde_json::json!({
            "_comment": "The TextEqQuery eql-bindings derives for the plaintext under FakeDataKeySource's index key (keyset nil), read by the Go SDK's hermetic test; regenerate with EQL_UPDATE_FIXTURES=1, do not edit.",
            "table": "users",
            "column": "email",
            "plaintext": PLAINTEXT,
            "query": String::from_utf8(query.clone()).unwrap(),
        });
        let rendered = serde_json::to_string_pretty(&fixture).unwrap() + "\n";
        if std::env::var_os("EQL_UPDATE_FIXTURES").is_some() {
            std::fs::write(fixture_path(), &rendered).unwrap();
        }
        let committed = std::fs::read_to_string(fixture_path())
            .expect("fixtures/text_eq_query.json is committed; EQL_UPDATE_FIXTURES=1 writes it");
        assert_eq!(
            committed, rendered,
            "the committed fixture is what the dispatch derives today"
        );
        let typed: TextEqQuery = keyset
            .encrypt_as(&PLAINTEXT.to_owned(), column())
            .await
            .unwrap();
        assert_eq!(
            query,
            serde_json::to_vec(&typed).unwrap(),
            "and what the typed path derives"
        );
    }
}
