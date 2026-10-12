//! The v4 counterpart of `catalog_parity.rs`: every v4 inventory entry must be
//! the catalog domain it claims, under the `eql_v4` names, and the version
//! boundary between the two generations must hold in both directions. A v3
//! payload that a v4 type accepted would let a cipherstash-client value be
//! read as a Stack Encrypt one (ADR-0002), so these are pinned with literals
//! rather than through the helpers they check.

use eql_bindings::{v3, v4};
use eql_domains::{Term, CATALOG};
use serde_json::{json, Value};

/// The catalog's scalar domains under their v4 names, in catalog order. v4 has
/// no SteVec bindings, so only scalar domains appear.
fn expected_v4_domains() -> Vec<String> {
    CATALOG
        .iter()
        .flat_map(|spec| {
            spec.domains
                .iter()
                .filter(|d| d.is_scalar())
                .map(move |d| spec.domain_name(d))
        })
        .map(|name| {
            let bare = name
                .strip_prefix(eql_domains::PUBLIC_TYPNAME_PREFIX)
                .unwrap_or_else(|| panic!("{name} does not carry the v3 typname prefix"));
            format!("{}{bare}", v4::PUBLIC_TYPNAME_PREFIX)
        })
        .collect()
}

#[test]
fn inventory_covers_the_scalar_catalog_in_order() {
    let actual: Vec<String> = v4::all().iter().map(|e| e.domain().to_string()).collect();
    assert_eq!(
        actual,
        expected_v4_domains(),
        "v4::all() must list the catalog's scalar domains, as eql_v4_*, in catalog \
         order — regenerate with `mise run types:generate`"
    );
}

#[test]
fn stored_entries_name_public_v4_domains_and_v4_schema_ids() {
    for entry in v4::all() {
        let name = entry.domain();
        assert_eq!(entry.sql_domain(), format!("public.{name}"));
        assert!(name.starts_with("eql_v4_"), "{name}");
        assert_eq!(
            entry.schema_id(),
            format!("https://schemas.cipherstash.com/eql/v4/{name}.json")
        );
    }
}

#[test]
fn query_entries_live_in_the_eql_v4_schema() {
    let v3_queries: Vec<String> = v3::all_query()
        .iter()
        .filter(|e| e.term_json_keys().is_some())
        .map(|e| e.domain().to_string())
        .collect();
    let v4_queries: Vec<String> = v4::all_query()
        .iter()
        .map(|e| {
            let sql = e.sql_domain();
            assert!(sql.starts_with("eql_v4.query_"), "{sql}");
            e.domain().to_string()
        })
        .collect();
    assert_eq!(
        v4_queries, v3_queries,
        "each scalar query twin exists in v4 under the same name"
    );
}

#[test]
fn term_keys_match_the_catalog() {
    let entries = v4::all();
    for spec in CATALOG {
        for domain in spec.domains.iter().filter(|d| d.is_scalar()) {
            let v3_name = spec.domain_name(domain);
            let name = v3_name.replacen("eql_v3_", "eql_v4_", 1);
            let entry = entries
                .iter()
                .find(|e| e.domain() == name)
                .unwrap_or_else(|| panic!("no v4 inventory entry for {name}"));
            assert_eq!(
                entry.term_json_keys().map(<[&str]>::to_vec),
                Some(Term::term_json_keys(domain.terms)),
                "{name}"
            );
        }
    }
}

fn text_eq(version: u8) -> Value {
    json!({
        "v": version,
        "i": { "t": "users", "c": "email" },
        "c": "stack-encrypt:1:ciphertext",
        "hm": "a".repeat(64),
    })
}

/// The boundary the move to v4 relies on: the payloads are otherwise
/// well-formed, so only the version can be what refuses them.
#[test]
fn each_generation_refuses_the_other_version() {
    assert!(serde_json::from_value::<v4::text::TextEq>(text_eq(4)).is_ok());
    assert!(serde_json::from_value::<v3::text::TextEq>(text_eq(3)).is_ok());

    let err = serde_json::from_value::<v4::text::TextEq>(text_eq(3)).unwrap_err();
    assert!(err.to_string().contains("version 3"), "{err}");
    let err = serde_json::from_value::<v3::text::TextEq>(text_eq(4)).unwrap_err();
    assert!(err.to_string().contains("version 4"), "{err}");

    // And through the inventory, which is how a caller holding only a name
    // validates a payload.
    let v4_entry = v4::all()
        .into_iter()
        .find(|e| e.domain() == "eql_v4_text_eq")
        .expect("eql_v4_text_eq in v4::all()");
    assert!(v4_entry.parse_value(&text_eq(4)).is_ok());
    assert!(v4_entry.parse_value(&text_eq(3)).is_err());
}
