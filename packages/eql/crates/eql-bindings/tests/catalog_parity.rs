//! The drift gate: every v3 domain's wire contract — pinned through the
//! published JSON Schema — must match `eql-domains::CATALOG`, the same catalog
//! that GENERATES both the SQL surface and these payload structs. schemars
//! output reflects the real serde contract, so per domain this catches a
//! wrong/dropped required key, a struct that lost
//! `#[serde(deny_unknown_fields)]` (`additionalProperties: false`), and a `v`
//! field that is not [`eql_bindings::SchemaVersion`] (the `$ref` and its
//! `const: 2`). The inventory set/order IS policed here by
//! `inventory_exactly_covers_catalog_in_order()`, which asserts `v3::all()`
//! lists exactly the `CATALOG` domains in catalog order (the generated
//! `inventory.rs` byte-parity gate lives in eql-codegen; this covers the
//! compiled `all()`). The emitted `.ts` property order is pinned by
//! `tests/ts_property_order.rs`. Behavioural spot checks live in
//! `tests/v3_conformance.rs`.

use std::collections::BTreeSet;

use eql_bindings::{v3, EQL_SCHEMA_VERSION};
use eql_domains::{Term, CATALOG, ENVELOPE_KEYS};
use serde_json::{json, Value};

/// The *published* JSON Schemas must agree with the catalog: each domain's
/// schema `required` list is exactly envelope + catalog term keys — the
/// artifact schema consumers validate against cannot drift from the SQL
/// surface's CHECK constraints.
#[test]
fn schema_required_keys_match_catalog_terms() {
    let entries = v3::all();
    // `scalar_families()` is the DRY filter for scalar-only consumers — the
    // SteVec jsonb domains' required keys are not envelope+terms and are pinned
    // separately by `jsonb_schema_required_keys_match_the_sql_check_contract`.
    for spec in eql_domains::scalar_families() {
        for domain in spec.domains {
            let name = spec.domain_name(domain);
            let entry = entries
                .iter()
                .find(|e| e.domain() == name)
                .unwrap_or_else(|| panic!("no domain inventory entry for {name}"));

            let schema: Value = serde_json::to_value(entry.schema())
                .unwrap_or_else(|e| panic!("{name}: schema does not serialize: {e}"));
            let required: BTreeSet<&str> = schema["required"]
                .as_array()
                .unwrap_or_else(|| panic!("{name}: schema has no required array"))
                .iter()
                .map(|v| v.as_str().expect("required entry is a string"))
                .collect();

            let expected: BTreeSet<&str> = ENVELOPE_KEYS
                .iter()
                .copied()
                .chain(Term::term_json_keys(domain.terms))
                .collect();

            assert_eq!(
                required, expected,
                "{name}: schema required keys must be envelope + catalog terms"
            );
        }
    }
}

/// `v3::all()` must list exactly the catalog domains, in catalog order. The
/// generated `inventory.rs` makes this structurally true, but the only cargo-
/// level guard was `schema_required_keys_match_catalog_terms`, which iterates
/// CATALOG and *finds* each entry — it catches a missing entry but neither an
/// extra entry nor a wrong order. (The byte-parity gate in eql-codegen covers
/// the generated `inventory.rs` source; this covers the actually-compiled
/// `all()` at the eql-bindings level.) A direct ordered `assert_eq!` restores
/// both directions, the regression dropped when `inventory_exactly_covers_catalog`
/// was removed (commit 27c200c4).
#[test]
fn inventory_exactly_covers_catalog_in_order() {
    // `domain_name` is correct for every shape (including the jsonb family's
    // one documented exception, the `public.eql_v3_json_search` document domain — see
    // `Domain::full_name`), so no per-shape branch is needed here.
    let expected: Vec<String> = CATALOG
        .iter()
        .flat_map(|spec| spec.domains.iter().map(move |d| spec.domain_name(d)))
        .collect();
    let actual: Vec<String> = v3::all().iter().map(|e| e.domain().to_string()).collect();
    assert_eq!(
        actual, expected,
        "v3::all() must list exactly the catalog domains in catalog order \
         (extra/missing entry or reordering) — regenerate with \
         `mise run types:generate` and commit inventory.rs"
    );
}

/// The trait-level term-key surface must agree with the catalog: for every
/// scalar domain, `DomainType::term_json_keys` (threaded through the generated
/// impls so `from_v2::TargetDomain::parse` can resolve required keys without a
/// runtime eql-domains dependency) is exactly `Term::term_json_keys` over the
/// catalog terms; for the SteVec (jsonb) shapes it is `None` — their index
/// terms live per sv leaf, not as flat payload keys.
#[test]
fn term_json_keys_match_catalog_terms() {
    let entries = v3::all();
    for spec in CATALOG {
        for domain in spec.domains {
            let name = spec.domain_name(domain);
            let entry = entries
                .iter()
                .find(|e| e.domain() == name)
                .unwrap_or_else(|| panic!("no domain inventory entry for {name}"));
            if domain.is_scalar() {
                let expected = Term::term_json_keys(domain.terms);
                assert_eq!(
                    entry.term_json_keys().map(<[&str]>::to_vec),
                    Some(expected),
                    "{name}: term_json_keys must be the catalog term keys"
                );
            } else {
                assert_eq!(
                    entry.term_json_keys(),
                    None,
                    "{name}: non-scalar (SteVec) shapes carry no flat term keys"
                );
            }
        }
    }
}

/// `DomainType::parse_value` must be the strict serde parse of the concrete
/// payload struct, reachable through the trait object — the mechanism
/// `from_v2` uses for final validation of converted payloads. One positive
/// and one negative per capability shape suffices; the per-struct strictness
/// itself is covered by `v3_conformance.rs`.
#[test]
fn parse_value_validates_through_the_inventory() {
    let entries = v3::all();
    let entry = |name: &str| {
        entries
            .iter()
            .find(|e| e.domain() == name)
            .unwrap_or_else(|| panic!("no domain inventory entry for {name}"))
    };

    let eq_payload = json!({
        "v": 3,
        "i": { "t": "users", "c": "age" },
        "c": "mp_base85_ciphertext",
        "hm": "deadbeef"
    });
    assert!(entry("eql_v3_integer_eq").parse_value(&eq_payload).is_ok());
    // Missing term key fails.
    assert!(entry("eql_v3_integer_ord")
        .parse_value(&eq_payload)
        .is_err());
    // Unknown key fails (deny_unknown_fields is live through the trait).
    assert!(entry("eql_v3_integer").parse_value(&eq_payload).is_err());

    let doc = json!({
        "v": 3,
        "k": "sv",
        "i": { "t": "users", "c": "profile" },
        "h": "mp_base85_key_header",
        "sv": [ { "s": "sel", "c": "ct" }, { "s": "sel_ord", "c": "ct", "op": "cllw" } ]
    });
    assert!(entry("eql_v3_json_search").parse_value(&doc).is_ok());
    assert!(entry("query_json").parse_value(&doc).is_err());
    assert!(entry("query_json")
        .parse_value(&json!({ "sv": [ { "s": "sel" }, { "s": "sel_ord", "op": "cllw" } ] }))
        .is_ok());
}

/// The published `$id` is the schema's identity URL — `tests/export.rs`
/// injects [`v3::DomainType::schema_id`] into every written file. Pin its
/// shape with independent literals (NOT the helper, which would only test
/// itself): a regressed host, a dropped `v3/`, or a wrong domain segment must
/// turn a test red, not merely shift the freshness diff.
#[test]
fn schema_id_is_canonical() {
    let entries = v3::all();
    let id_of = |domain: &str| {
        entries
            .iter()
            .find(|e| e.domain() == domain)
            .unwrap_or_else(|| panic!("no domain inventory entry for {domain}"))
            .schema_id()
    };

    // Fully-literal anchors — no interpolation, so a typo in the helper's base
    // URL or path cannot match.
    assert_eq!(
        id_of("eql_v3_integer_eq"),
        "https://schemas.cipherstash.com/eql/v3/eql_v3_integer_eq.json"
    );
    assert_eq!(
        id_of("eql_v3_text_search"),
        "https://schemas.cipherstash.com/eql/v3/eql_v3_text_search.json"
    );

    // Every domain follows the same canonical pattern.
    for entry in &entries {
        let id = entry.schema_id();
        let name = entry.domain();
        assert_eq!(
            id,
            format!("https://schemas.cipherstash.com/eql/v3/{name}.json"),
            "{name}: $id must be the canonical eql/v3 URL"
        );
    }
}

/// Every published schema must be *strict*, not just complete: unknown keys
/// rejected at the root and inside the nested `Identifier`, and the `v`
/// property pinned to the `SchemaVersion` definition whose `const` is the
/// wire version. `required` alone (the test above) would stay green if a
/// struct lost `#[serde(deny_unknown_fields)]` or swapped `SchemaVersion`
/// for a bare integer — both regenerate a permissive schema that
/// `types:check` would happily commit as the new baseline.
#[test]
fn schemas_are_strict() {
    let entries = v3::all();
    // Iterate the scalar families directly (via the DRY `scalar_families()`
    // helper) and resolve each to its inventory entry — rather than iterating
    // every entry and reverse-looking-up its Shape with a fail-open default.
    // SteVec strictness (Document/Query only) is asserted in `v3_conformance.rs`.
    for spec in eql_domains::scalar_families() {
        for domain in spec.domains {
            let name = spec.domain_name(domain);
            let entry = entries
                .iter()
                .find(|e| e.domain() == name)
                .unwrap_or_else(|| panic!("no domain inventory entry for {name}"));
            let schema: Value = serde_json::to_value(entry.schema())
                .unwrap_or_else(|e| panic!("{name}: schema does not serialize: {e}"));

            assert_eq!(
                schema.pointer("/additionalProperties"),
                Some(&json!(false)),
                "{name}: schema must set additionalProperties: false \
                 (struct lost #[serde(deny_unknown_fields)]?)"
            );
            assert_eq!(
                schema.pointer("/$defs/Identifier/additionalProperties"),
                Some(&json!(false)),
                "{name}: Identifier definition must set additionalProperties: false"
            );
            assert_eq!(
                schema.pointer("/properties/v/$ref"),
                Some(&json!("#/$defs/SchemaVersion")),
                "{name}: the v property must $ref the SchemaVersion definition \
                 (field declared as a bare integer instead of SchemaVersion?)"
            );
            assert_eq!(
                schema.pointer("/$defs/SchemaVersion/const"),
                Some(&json!(EQL_SCHEMA_VERSION)),
                "{name}: SchemaVersion must pin const: {EQL_SCHEMA_VERSION}"
            );
        }
    }
}

/// The jsonb (SteVec) drift gate: the SteVec families' `terms` are empty (their
/// index capability is structural, not a flat `Term` list), so the scalar gate
/// `schema_required_keys_match_catalog_terms` cannot cover them and skips the
/// family. This pins the published jsonb schemas' `required` sets against the
/// SteVec wire contract — the one link (wire ↔ published JSON Schema) that
/// otherwise has no structural test.
///
/// KEEP IN SYNC with the canonical `SteVecPayload`
/// (`eql-payload-v2.3.schema.json`) and `is_valid_ste_vec_{document,entry,query}_payload`:
/// - `public.eql_v3_json_search`      requires `v` `k` `i` `sv`           (document; `k` = "sv"
///   form discriminator, required by the canonical SteVecPayload and carried on
///   every real payload — the SQL CHECK is laxer and only mandates `v`/`i`/`sv`,
///   but the binding models the real wire, which always carries `k`)
/// - `public.eql_v3_json_entry` requires `s` `c`; `op` and extracted metadata are optional
/// - `eql_v3.query_json` requires `sv`; each element requires `s`, with optional `op`
#[test]
fn jsonb_schema_required_keys_match_the_sql_check_contract() {
    let entries = v3::all();
    let schema_of = |domain: &str| -> Value {
        let entry = entries
            .iter()
            .find(|e| e.domain() == domain)
            .unwrap_or_else(|| panic!("no inventory entry for {domain}"));
        serde_json::to_value(entry.schema())
            .unwrap_or_else(|e| panic!("{domain}: schema does not serialize: {e}"))
    };
    let required = |schema: &Value, ptr: &str, ctx: &str| -> BTreeSet<String> {
        schema
            .pointer(ptr)
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("{ctx}: no required array at {ptr}"))
            .iter()
            .map(|v| v.as_str().expect("required entry is a string").to_string())
            .collect()
    };
    let set = |keys: &[&str]| -> BTreeSet<String> { keys.iter().map(|s| s.to_string()).collect() };

    // Document: {v, k, i, h, sv}. No root `c` (a document is not itself a
    // ciphertext); `k` is the "sv" form discriminator (SteVecForm-pinned);
    // `h` is the envelope key header, stored once per document.
    let doc = schema_of("eql_v3_json_search");
    assert_eq!(
        required(&doc, "/required", "eql_v3_json_search"),
        set(&["v", "k", "i", "h", "sv"]),
        "public.eql_v3_json_search required keys must match the SteVec document wire contract"
    );

    // Entry: {s, c} + an optional op ordering term and optional extracted
    // metadata. Unknown fields are rejected; `hm` must not appear anywhere.
    let entry = schema_of("eql_v3_json_entry");
    assert_eq!(
        required(&entry, "/required", "eql_v3_json_entry"),
        set(&["s", "c"]),
        "public.eql_v3_json_entry base required keys must be s + c"
    );
    assert_eq!(entry.pointer("/additionalProperties"), Some(&json!(false)));
    assert!(entry.pointer("/properties/op").is_some());
    assert!(entry.pointer("/properties/hm").is_none());

    // Query: {sv}. The element (SteVecQueryEntry) requires `s` plus an
    // OPTIONAL op ordering term, and carries NO ciphertext `c` — the
    // "queries never carry ciphertext" rule.
    let query = schema_of("query_json");
    assert_eq!(
        required(&query, "/required", "query_json"),
        set(&["sv"]),
        "eql_v3.query_json required keys must be sv"
    );
    let elem_required = required(
        &query,
        "/$defs/SteVecQueryEntry/required",
        "query_json element",
    );
    assert!(
        elem_required.contains("s"),
        "query_json element must require a selector s, got {elem_required:?}"
    );
    assert!(
        !elem_required.contains("c"),
        "query_json element must NOT require a ciphertext c \
         (is_valid_ste_vec_query_payload forbids it), got {elem_required:?}"
    );
    assert_eq!(
        query.pointer("/$defs/SteVecQueryEntry/additionalProperties"),
        Some(&json!(false))
    );
    assert!(query
        .pointer("/$defs/SteVecQueryEntry/properties/op")
        .is_some());
    assert!(query
        .pointer("/$defs/SteVecQueryEntry/properties/c")
        .is_none());
    assert!(query
        .pointer("/$defs/SteVecQueryEntry/properties/hm")
        .is_none());
}
