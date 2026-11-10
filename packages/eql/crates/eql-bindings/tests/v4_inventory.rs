//! Every v4 inventory entry is the eql-domains catalog domain it claims,
//! under its `eql_v4` name and schema id, and a v4 type admits only `"v": 4`.
//! The expected names and ids are written as literals rather than through the
//! helpers they check.

// `eql_bindings::v4` exists only with the `stack-encrypt` feature.
#![cfg(feature = "stack-encrypt")]

use eql_bindings::v4;
use eql_domains::{Term, CATALOG};
use serde_json::{json, Value};

/// The catalog's scalar domains under their v4 names, in catalog order, then
/// each document family's stored document. v4 has no SteVec bindings, so
/// only scalar domains appear from `CATALOG`. The catalog spells each name
/// with the `eql_v3_` prefix, which is swapped for v4's; a document family
/// is v4 only and spells its own.
fn expected_v4_domains() -> Vec<String> {
    let documents = eql_domains::DOCUMENT_FAMILIES.iter().flat_map(|f| {
        f.domains
            .iter()
            .filter(|d| d.role == eql_domains::DocumentRole::Stored)
            .map(|d| d.sql_domain.trim_start_matches("public.").to_owned())
    });
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
                .unwrap_or_else(|| panic!("{name} does not carry the catalog typname prefix"));
            format!("{}{bare}", v4::PUBLIC_TYPNAME_PREFIX)
        })
        .chain(documents)
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
    for entry in v4::all_query() {
        let sql = entry.sql_domain();
        assert!(sql.starts_with("eql_v4.query_"), "{sql}");
    }
}

#[test]
fn term_keys_match_the_catalog() {
    let entries = v4::all();
    for spec in CATALOG {
        for domain in spec.domains.iter().filter(|d| d.is_scalar()) {
            let catalog_name = spec.domain_name(domain);
            let name = catalog_name.replacen("eql_v3_", "eql_v4_", 1);
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

fn text_eq(version: u16) -> Value {
    json!({
        "v": version,
        "i": { "t": "users", "c": "email" },
        "c": "stack-encrypt:1:ciphertext",
        "hm": "a".repeat(64),
    })
}

/// The payload is otherwise well-formed, so only the version can be what
/// refuses it.
#[test]
fn a_v4_type_admits_only_version_4() {
    assert!(serde_json::from_value::<v4::text::TextEq>(text_eq(4)).is_ok());
    for version in [0, 3, 5] {
        let err = serde_json::from_value::<v4::text::TextEq>(text_eq(version)).unwrap_err();
        assert!(
            err.to_string().contains(&format!(
                "unsupported EQL schema version {version} (expected 4)"
            )),
            "{err}"
        );
    }

    // And through the inventory, which is how a caller holding only a name
    // validates a payload.
    let entry = v4::all()
        .into_iter()
        .find(|e| e.domain() == "eql_v4_text_eq")
        .expect("eql_v4_text_eq in v4::all()");
    assert!(entry.parse_value(&text_eq(4)).is_ok());
    assert!(entry.parse_value(&text_eq(3)).is_err());
}
