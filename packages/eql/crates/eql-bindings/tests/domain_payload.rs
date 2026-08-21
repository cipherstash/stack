//! Tests for the catalog-generated [`DomainPayload`] enum and the typed
//! conversion path [`from_v2_typed`].
//!
//! The load-bearing contract is the byte-identical serialization pin: for
//! every conversion target, `serde_json::to_value(&from_v2_typed(..))` must
//! equal the `Value` the wire-oriented `from_v2` returns — the enum is
//! `#[serde(untagged)]`, so typing a payload can never change the wire.
//! Construction is always from a KNOWN target domain ([`DomainPayload::parse`]
//! / [`from_v2_typed`]) — never inferred from bytes, per the "Why there is no
//! discriminated enum" note in the v3 module docs (cross-token payloads are
//! byte-identical on the wire).

use eql_bindings::from_v2::{from_v2, from_v2_typed, is_v3_payload, FromV2Error, TargetDomain};
use eql_bindings::v3::{DomainPayload, DomainType};
use serde_json::{json, Value};

const CIPHERTEXT: &str = "mBbL@V^%dN?0W$;g)1-JP*cmqX%JhW0ZKZ^G?lNn$CfXJH";
const HEX: &str = "8067db44a848ab32c3056a3dbe4edf16";
const HEX_LONG: &str = "fbc7a11fc81f2a321553bc06a91f240bb7d8f3a9c6aec445a5ba6793";
const SELECTOR: &str = "9493d6010fe7845d52149b697729c745";

fn ident() -> Value {
    json!({ "t": "users", "c": "email" })
}

/// A fully-populated v2.3 scalar (`k: "ct"`) payload — every index term, so
/// any scalar target converts (mirrors `tests/from_v2.rs`).
fn v2_ct_full() -> Value {
    json!({
        "v": 2,
        "k": "ct",
        "c": CIPHERTEXT,
        "i": ident(),
        "hm": HEX,
        "bf": [12, 47, 91, 188],
        "ob": [HEX, HEX_LONG],
        "op": HEX
    })
}

/// A v2.3 SteVec (`k: "sv"`) payload (mirrors `tests/from_v2.rs`).
fn v2_sv() -> Value {
    json!({
        "v": 2,
        "k": "sv",
        "i": ident(),
        "sv": [
            { "s": SELECTOR, "c": CIPHERTEXT, "hm": HEX },
            { "s": SELECTOR, "a": true, "c": CIPHERTEXT, "op": HEX_LONG }
        ]
    })
}

fn target(name: &str) -> TargetDomain {
    TargetDomain::parse(name).unwrap_or_else(|e| panic!("target {name} must parse: {e}"))
}

/// The serialization pin for one conversion: the typed payload must
/// serialize to exactly the `Value` the untyped `from_v2` returns — as a
/// `Value` and as a canonical JSON string — and the direct string form must
/// parse back to the same `Value`.
fn assert_serialization_pin(v2: &Value, t: TargetDomain) -> DomainPayload {
    let typed = from_v2_typed(v2, t).expect("typed conversion succeeds");
    let untyped = from_v2(v2, t).expect("untyped conversion succeeds");

    let typed_value = serde_json::to_value(&typed).expect("typed payload serializes");
    assert_eq!(typed_value, untyped, "to_value must match from_v2 exactly");

    // String form: canonical (through Value) is byte-identical; the direct
    // struct string form differs only in JSON object key order (semantically
    // irrelevant, and normalized by jsonb) — pin that it parses back equal.
    assert_eq!(
        serde_json::to_string(&typed_value).unwrap(),
        serde_json::to_string(&untyped).unwrap(),
        "canonical string form must be byte-identical"
    );
    let direct: Value =
        serde_json::from_str(&serde_json::to_string(&typed).unwrap()).expect("direct form parses");
    assert_eq!(direct, untyped, "direct string form must round-trip equal");

    assert!(is_v3_payload(&typed_value));
    typed
}

// ---------------------------------------------------------------------------
// from_v2_typed — happy paths per payload shape
// ---------------------------------------------------------------------------

#[test]
fn typed_scalar_single_term_yields_the_matching_variant() {
    let typed = assert_serialization_pin(&v2_ct_full(), target("eql_v3_integer_eq"));
    assert_eq!(typed.domain(), "eql_v3_integer_eq");
    assert_eq!(typed.sql_domain(), "public.eql_v3_integer_eq");
    match &typed {
        DomainPayload::IntegerEq(p) => {
            assert_eq!(p.sql_domain(), "public.eql_v3_integer_eq");
        }
        other => panic!("expected IntegerEq, got {other:?}"),
    }
}

#[test]
fn typed_scalar_multi_term_yields_text_search() {
    let typed = assert_serialization_pin(&v2_ct_full(), target("eql_v3_text_search"));
    assert_eq!(typed.domain(), "eql_v3_text_search");
    match &typed {
        DomainPayload::TextSearch(p) => {
            // All three terms present — the capability is the type. `_search` is
            // OPE-backed, so the ordering term is `op`; the block-ORE `ob` shape
            // lives on `text_search_ore` below.
            assert_eq!(
                serde_json::to_value(p).unwrap(),
                json!({
                    "v": 3,
                    "i": ident(),
                    "c": CIPHERTEXT,
                    "hm": HEX,
                    "op": HEX,
                    "bf": [12, 47, 91, 188]
                })
            );
        }
        other => panic!("expected TextSearch, got {other:?}"),
    }
}

#[test]
fn typed_scalar_multi_term_yields_text_search_ore() {
    let typed = assert_serialization_pin(&v2_ct_full(), target("eql_v3_text_search_ore"));
    assert_eq!(typed.domain(), "eql_v3_text_search_ore");
    match &typed {
        DomainPayload::TextSearchOre(p) => {
            // The by-name block-ORE sibling keeps the `ob` array.
            assert_eq!(
                serde_json::to_value(p).unwrap(),
                json!({
                    "v": 3,
                    "i": ident(),
                    "c": CIPHERTEXT,
                    "hm": HEX,
                    "ob": [HEX, HEX_LONG],
                    "bf": [12, 47, 91, 188]
                })
            );
        }
        other => panic!("expected TextSearchOre, got {other:?}"),
    }
}

#[test]
fn typed_ste_vec_document_is_unconvertible() {
    // The v3 envelope wire format (per-document key header `h` +
    // selector-derived entry nonces) cannot be derived from a v2 payload by
    // JSON transformation — both entry points fail closed. The
    // SteVecDocument DomainPayload variant is reachable only via
    // DomainPayload::parse over a real v3 wire payload.
    assert!(matches!(
        from_v2(&v2_sv(), TargetDomain::Json).unwrap_err(),
        FromV2Error::UnconvertibleSteVecDocument
    ));
    assert!(matches!(
        from_v2_typed(&v2_sv(), TargetDomain::Json).unwrap_err(),
        FromV2Error::UnconvertibleSteVecDocument
    ));
}

#[test]
fn typed_conversion_pins_serialization_for_every_scalar_domain() {
    // Exhaustive over the catalog: every scalar conversion target's typed
    // payload serializes to exactly the untyped from_v2 output, so the pin
    // cannot drift when the catalog grows.
    for family in eql_domains::scalar_families() {
        for domain in family.domains {
            let name = family.domain_name(domain);
            let typed = assert_serialization_pin(&v2_ct_full(), target(&name));
            assert_eq!(typed.domain(), name, "variant reports its domain");
        }
    }
}

// ---------------------------------------------------------------------------
// from_v2_typed — failure parity with from_v2
// ---------------------------------------------------------------------------

#[test]
fn typed_missing_term_fails_closed_exactly_like_from_v2() {
    let minimal = json!({ "v": 2, "k": "ct", "c": CIPHERTEXT, "i": ident() });
    let typed_err = from_v2_typed(&minimal, target("eql_v3_text_eq")).unwrap_err();
    let untyped_err = from_v2(&minimal, target("eql_v3_text_eq")).unwrap_err();
    for err in [&typed_err, &untyped_err] {
        match err {
            FromV2Error::MissingTerm { domain, key, entry } => {
                assert_eq!(domain, "eql_v3_text_eq");
                assert_eq!(key, "hm");
                assert_eq!(entry, &None);
            }
            other => panic!("expected MissingTerm, got {other:?}"),
        }
    }
}

#[test]
fn typed_rejects_the_same_inputs_as_from_v2() {
    // Version, kind, and kind-mismatch failures are shared with from_v2 (one
    // conversion path); spot-check each class.
    let v3 = json!({ "v": 3, "i": ident(), "c": CIPHERTEXT, "hm": HEX });
    assert!(matches!(
        from_v2_typed(&v3, target("eql_v3_text_eq")).unwrap_err(),
        FromV2Error::UnsupportedVersion { found: Some(3) }
    ));
    assert!(matches!(
        from_v2_typed(&v2_sv(), target("eql_v3_integer_eq")).unwrap_err(),
        FromV2Error::KindMismatch { .. }
    ));
    // A v2 QUERY payload (no `c`) fails the strict parse — Invalid, exactly
    // like from_v2's validate_as.
    let query = json!({ "v": 2, "k": "ct", "i": ident(), "hm": HEX });
    assert!(matches!(
        from_v2_typed(&query, target("eql_v3_text_eq")).unwrap_err(),
        FromV2Error::Invalid(_)
    ));
}

// ---------------------------------------------------------------------------
// DomainPayload::parse — construct-from-known-domain
// ---------------------------------------------------------------------------

#[test]
fn parse_constructs_every_stored_payload_domain() {
    // Every scalar domain plus the SteVec document is parseable by name; the
    // constructed variant reports the same domain back.
    for family in eql_domains::CATALOG {
        for domain in family.domains {
            let name = family.domain_name(domain);
            let stored = domain.is_scalar() || name == "eql_v3_json_search";
            let value = if name == "eql_v3_json_search" {
                // A v3 document cannot come from from_v2 (the envelope wire
                // format is unconvertible) — construct the wire shape
                // directly.
                json!({
                    "v": 3,
                    "k": "sv",
                    "i": ident(),
                    "h": "mp_base85_key_header",
                    "sv": [
                        { "s": SELECTOR, "c": CIPHERTEXT },
                        { "s": SELECTOR, "c": CIPHERTEXT, "a": true, "op": HEX_LONG }
                    ]
                })
            } else if stored {
                from_v2(&v2_ct_full(), target(&name)).unwrap()
            } else {
                // jsonb_entry / query_json: inventory members but not stored
                // payloads — no DomainPayload variant, parse returns None.
                assert!(
                    DomainPayload::parse(&name, &json!({})).is_none(),
                    "{name} must not be a DomainPayload domain"
                );
                continue;
            };
            let parsed = DomainPayload::parse(&name, &value)
                .unwrap_or_else(|| panic!("{name} must be a DomainPayload domain"))
                .unwrap_or_else(|e| panic!("{name} strict parse must succeed: {e}"));
            assert_eq!(parsed.domain(), name);
            assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
        }
    }
}

#[test]
fn parse_returns_none_for_unknown_domains() {
    for name in [
        "int5",
        "public.eql_v3_integer_eq",
        "",
        "jsonb",
        "eql_v3_json_entry",
        "query_json",
    ] {
        assert!(
            DomainPayload::parse(name, &json!({})).is_none(),
            "{name:?} must not resolve to a DomainPayload variant"
        );
    }
}

#[test]
fn parse_is_strict_exactly_like_the_binding_struct() {
    // Unknown keys and wrong envelope versions fail — DomainPayload::parse is
    // the binding struct's strict Deserialize, kept instead of discarded.
    let mut good = from_v2(&v2_ct_full(), target("eql_v3_integer_eq")).unwrap();
    assert!(DomainPayload::parse("eql_v3_integer_eq", &good)
        .unwrap()
        .is_ok());

    good["extra"] = json!(1);
    assert!(
        DomainPayload::parse("eql_v3_integer_eq", &good)
            .unwrap()
            .is_err(),
        "deny_unknown_fields must reject a stray key"
    );

    let wrong_version = json!({ "v": 2, "i": ident(), "c": CIPHERTEXT, "hm": HEX });
    assert!(
        DomainPayload::parse("eql_v3_integer_eq", &wrong_version)
            .unwrap()
            .is_err(),
        "SchemaVersion must reject v: 2"
    );
}

#[test]
fn as_domain_type_exposes_the_inner_trait_object() {
    let typed = from_v2_typed(&v2_ct_full(), target("eql_v3_bigint_ord_ope")).unwrap();
    let dt: &dyn DomainType = typed.as_domain_type();
    assert_eq!(dt.sql_domain(), "public.eql_v3_bigint_ord_ope");
    assert_eq!(dt.domain(), "eql_v3_bigint_ord_ope");
}
