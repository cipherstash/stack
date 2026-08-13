//! Tests for the generated [`QueryPayload`] enum and the typed query
//! conversion path [`from_v2_query_typed`].
//!
//! The load-bearing contract mirrors `tests/domain_payload.rs`: the
//! byte-identical serialization pin — `serde_json::to_value(&from_v2_query_typed(..))`
//! must equal the `Value` the wire-oriented `from_v2_query` returns (the enum
//! is `#[serde(untagged)]`, so typing a query payload can never change the
//! wire) — plus failure parity: both entry points reject the same inputs with
//! the same errors, including [`FromV2Error::UnsupportedQueryTarget`] for
//! STORAGE-ONLY scalar targets (term-bearing scalars hoist to their
//! `query_<name>` operand).

use eql_bindings::from_v2::{from_v2_query, from_v2_query_typed, FromV2Error, TargetDomain};
use eql_bindings::v3::QueryPayload;
use serde_json::{json, Value};

const CIPHERTEXT: &str = "mBbL@V^%dN?0W$;g)1-JP*cmqX%JhW0ZKZ^G?lNn$CfXJH";
const HEX: &str = "8067db44a848ab32c3056a3dbe4edf16";
const HEX_LONG: &str = "fbc7a11fc81f2a321553bc06a91f240bb7d8f3a9c6aec445a5ba6793";
const SELECTOR: &str = "9493d6010fe7845d52149b697729c745";

fn ident() -> Value {
    json!({ "t": "users", "c": "email" })
}

fn target(name: &str) -> TargetDomain {
    TargetDomain::parse(name).unwrap_or_else(|e| panic!("target {name} must parse: {e}"))
}

// ---------------------------------------------------------------------------
// from_v2_query_typed — failure parity with from_v2_query
// ---------------------------------------------------------------------------

/// A v2 `k:"ct"` scalar payload carrying representative values for `term_keys`
/// PLUS a stray `c` (which a query hoist must drop). Empty `term_keys` → just
/// the `{v,k,i,c}` envelope.
fn v2_scalar_query(term_keys: &[&str]) -> Value {
    let mut obj = json!({ "v": 2, "k": "ct", "i": ident(), "c": CIPHERTEXT });
    let map = obj.as_object_mut().unwrap();
    for &k in term_keys {
        let term = match k {
            "hm" | "op" => json!(HEX),
            "ob" => json!([HEX, HEX]),
            "bf" => json!([1, 2, 3]),
            other => panic!("unhandled term key {other}"),
        };
        map.insert(k.into(), term);
    }
    obj
}

#[test]
fn scalar_query_hoist_and_storage_only_unsupported() {
    // A term-bearing scalar target hoists the v2 payload's required
    // terms into the enveloped term-only operand `{v:3, i, <terms>}` for its
    // `query_<name>` domain (dropping `c`/`k`); a storage-only scalar target
    // (no operators) still fails closed with UnsupportedQueryTarget. Exhaustive
    // over the catalog, both entry points, with the typed==untyped pin.
    for family in eql_domains::scalar_families() {
        for domain in family.domains {
            let name = family.domain_name(domain);
            let t = target(&name);
            let term_keys: Vec<&str> = eql_domains::Term::term_json_keys(domain.terms);
            let v2 = v2_scalar_query(&term_keys);

            if term_keys.is_empty() {
                for err in [
                    from_v2_query_typed(&v2, t).unwrap_err(),
                    from_v2_query(&v2, t).unwrap_err(),
                ] {
                    match err {
                        FromV2Error::UnsupportedQueryTarget { domain } => assert_eq!(domain, name),
                        other => {
                            panic!("expected UnsupportedQueryTarget for {name}, got {other:?}")
                        }
                    }
                }
                continue;
            }

            let out =
                from_v2_query(&v2, t).unwrap_or_else(|e| panic!("{name} hoist failed: {e:?}"));
            let obj = out.as_object().unwrap();
            assert_eq!(obj.get("v").and_then(Value::as_u64), Some(3), "{name} v:3");
            assert!(obj.contains_key("i"), "{name} keeps i");
            assert!(!obj.contains_key("c"), "{name} query drops c");
            assert!(!obj.contains_key("k"), "{name} query drops k");
            for k in &term_keys {
                assert!(obj.contains_key(*k), "{name} keeps term {k}");
            }
            assert_eq!(
                obj.len(),
                2 + term_keys.len(),
                "{name} is exactly v+i+terms"
            );

            let typed =
                from_v2_query_typed(&v2, t).unwrap_or_else(|e| panic!("{name} typed hoist: {e:?}"));
            // The query twin joins `query_` to the BARE name: the stored
            // domain's `eql_v3_` version prefix never applies to
            // query operands (the `eql_v3` schema already versions them).
            let query_name = domain.query_name(family.name);
            assert_eq!(typed.domain(), query_name, "{name} domain");
            assert_eq!(typed.sql_domain(), format!("eql_v3.{query_name}"));
            assert_eq!(
                serde_json::to_value(&typed).unwrap(),
                out,
                "{name}: typed to_value must equal from_v2_query"
            );
        }
    }
}

#[test]
fn typed_ste_vec_queries_fail_closed() {
    for input in [
        json!({ "sv": [ { "s": SELECTOR, "hm": HEX, "op": HEX_LONG } ] }),
        json!({ "sv": [ { "s": SELECTOR } ] }),
        json!({ "v": 3, "sv": [ { "s": SELECTOR, "op": HEX_LONG } ] }),
        json!({ "k": "ct", "sv": [ { "s": SELECTOR, "op": HEX_LONG } ] }),
    ] {
        for err in [
            from_v2_query_typed(&input, TargetDomain::Json).unwrap_err(),
            from_v2_query(&input, TargetDomain::Json).unwrap_err(),
        ] {
            assert!(matches!(err, FromV2Error::UnconvertibleSteVecQuery));
        }
    }
}

// ---------------------------------------------------------------------------
// QueryPayload::parse — construct-from-known-domain
// ---------------------------------------------------------------------------

#[test]
fn parse_constructs_the_needle_from_its_domain_name() {
    let needle = json!({ "sv": [ { "s": SELECTOR }, { "s": SELECTOR, "op": HEX_LONG } ] });
    let parsed = QueryPayload::parse("query_json", &needle)
        .expect("query_json must be a QueryPayload domain")
        .expect("strict parse must succeed");
    assert_eq!(parsed.domain(), "query_json");
    assert_eq!(serde_json::to_value(&parsed).unwrap(), needle);
}

#[test]
fn parse_is_strict_exactly_like_the_binding_struct() {
    // SteVecQuery is `deny_unknown_fields` at the root — a stray root key
    // fails, exactly as the untyped path's validate_as does.
    let stray = json!({ "sv": [ { "s": SELECTOR, "op": HEX_LONG } ], "extra": 1 });
    assert!(
        QueryPayload::parse("query_json", &stray).unwrap().is_err(),
        "deny_unknown_fields must reject a stray root key"
    );
}

#[test]
fn parse_returns_none_for_non_query_domains() {
    // Stored-payload domains (DomainPayload territory), the entry shape, and
    // unknown names are not query payloads.
    for name in [
        "eql_v3_json_search",
        "eql_v3_json_entry",
        "eql_v3_integer_eq",
        "eql_v3.query_json",
        "",
    ] {
        assert!(
            QueryPayload::parse(name, &json!({})).is_none(),
            "{name:?} must not resolve to a QueryPayload variant"
        );
    }
}
