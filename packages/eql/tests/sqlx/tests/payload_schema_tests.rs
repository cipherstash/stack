//! JSON Schema validation tests for the EQL v2.2 baseline and v2.3 target
//! payload formats. These do not touch the database.
//!
//! Goals:
//! - Lock the on-the-wire payload contracts as code so format drift is caught
//!   in CI rather than discovered at integration time.
//! - Document the v2.2 -> v2.3 delta as executable assertions: payloads that
//!   are valid in 2.2 (e.g. `b3` everywhere, `opf`/`opv` and `ocf`/`ocv`
//!   splits) must fail under 2.3, and vice versa.

use std::path::PathBuf;
use std::sync::OnceLock;

use jsonschema::Validator;
use serde_json::{json, Value};

// ---------- helpers ----------

fn load_schema(filename: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/reference/schema")
        .join(filename);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("schema is not valid JSON: {e}"))
}

fn compile(schema: &Value) -> Validator {
    // `validator_for` auto-detects the draft from the schema's `$schema`
    // keyword. Both files declare draft 2020-12, which is supported natively
    // by jsonschema >= 0.18.
    jsonschema::validator_for(schema).expect("schema fails to compile")
}

fn schema_v2_2() -> &'static Validator {
    static S: OnceLock<Validator> = OnceLock::new();
    S.get_or_init(|| compile(&load_schema("eql-payload-v2.2.schema.json")))
}

fn schema_v2_3() -> &'static Validator {
    static S: OnceLock<Validator> = OnceLock::new();
    S.get_or_init(|| compile(&load_schema("eql-payload-v2.3.schema.json")))
}

#[track_caller]
fn assert_valid(schema: &Validator, instance: &Value, label: &str) {
    if !schema.is_valid(instance) {
        let msgs: Vec<String> = schema
            .iter_errors(instance)
            .map(|e| format!("  - {} (at {})", e, e.instance_path()))
            .collect();
        panic!(
            "expected `{label}` to validate, but got:\n{}\ninstance:\n{}",
            msgs.join("\n"),
            serde_json::to_string_pretty(instance).unwrap()
        );
    }
}

#[track_caller]
fn assert_invalid(schema: &Validator, instance: &Value, label: &str) {
    if schema.is_valid(instance) {
        panic!(
            "expected `{label}` to fail validation, but it passed:\n{}",
            serde_json::to_string_pretty(instance).unwrap()
        );
    }
}

const CIPHERTEXT: &str = "mBbL@V^%dN?0W$;g)1-JP*cmqX%JhW0ZKZ^G?lNn$CfXJH";
const HEX: &str = "8067db44a848ab32c3056a3dbe4edf16";
const HEX_LONG: &str = "fbc7a11fc81f2a321553bc06a91f240bb7d8f3a9c6aec445a5ba6793";
const SELECTOR: &str = "9493d6010fe7845d52149b697729c745";

fn ident() -> Value {
    json!({ "t": "users", "c": "email" })
}

// ===========================================================================
// v2.2 schema
// ===========================================================================

#[test]
fn v2_2_minimal_encrypted_payload_is_valid() {
    let p = json!({ "v": 2, "c": CIPHERTEXT, "i": ident() });
    assert_valid(schema_v2_2(), &p, "minimal encrypted payload");
}

#[test]
fn v2_2_full_encrypted_payload_with_all_index_terms_is_valid() {
    // v2.2 still has b3, opf and opv as separate fields.
    let p = json!({
        "v": 2,
        "k": "ct",
        "c": CIPHERTEXT,
        "i": ident(),
        "hm": HEX,
        "b3": HEX,
        "bf": [12, 47, 91, 188],
        "ob": [HEX, HEX_LONG],
        "ocf": HEX,
        "ocv": HEX_LONG,
        "opf": HEX,
        "opv": HEX_LONG
    });
    assert_valid(schema_v2_2(), &p, "fully populated encrypted payload");
}

#[test]
fn v2_2_ste_vec_payload_is_valid() {
    let p = json!({
        "v": 2,
        "k": "sv",
        "i": ident(),
        "sv": [
            { "s": SELECTOR, "a": false, "c": CIPHERTEXT, "b3": HEX },
            { "s": SELECTOR, "a": false, "c": CIPHERTEXT, "ocv": HEX_LONG },
            { "s": SELECTOR, "a": true,  "c": CIPHERTEXT, "ocf": HEX, "opv": HEX }
        ]
    });
    assert_valid(schema_v2_2(), &p, "ste_vec payload");
}

#[test]
fn v2_2_encrypted_missing_required_fields_fails() {
    let cases = [
        ("missing v", json!({ "c": CIPHERTEXT, "i": ident() })),
        ("missing c", json!({ "v": 2, "i": ident() })),
        ("missing i", json!({ "v": 2, "c": CIPHERTEXT })),
        (
            "ident missing t",
            json!({ "v": 2, "c": CIPHERTEXT, "i": { "c": "email" } }),
        ),
        (
            "ident missing c",
            json!({ "v": 2, "c": CIPHERTEXT, "i": { "t": "users" } }),
        ),
    ];
    for (label, p) in cases {
        assert_invalid(schema_v2_2(), &p, label);
    }
}

#[test]
fn v2_2_encrypted_with_wrong_version_fails() {
    let p = json!({ "v": 1, "c": CIPHERTEXT, "i": ident() });
    assert_invalid(schema_v2_2(), &p, "wrong version");
}

#[test]
fn v2_2_encrypted_payload_with_sv_fails() {
    // EncryptedPayload is mutually exclusive with SteVecPayload.
    let p = json!({
        "v": 2, "k": "ct", "c": CIPHERTEXT, "i": ident(),
        "sv": [{ "s": SELECTOR, "c": CIPHERTEXT, "b3": HEX }]
    });
    assert_invalid(schema_v2_2(), &p, "encrypted payload carrying sv");
}

#[test]
fn v2_2_ste_vec_payload_with_top_level_ciphertext_fails() {
    // SteVecPayload is metadata + sv only — no top-level c.
    let p = json!({
        "v": 2, "k": "sv", "i": ident(),
        "c": CIPHERTEXT,
        "sv": [{ "s": SELECTOR, "c": CIPHERTEXT, "b3": HEX }]
    });
    assert_invalid(schema_v2_2(), &p, "ste_vec payload with top-level c");
}

#[test]
fn v2_2_ste_vec_element_with_hm_fails() {
    // v2.2 forbids hm at the sv-element level (root-only term).
    let p = json!({
        "v": 2, "k": "sv", "i": ident(),
        "sv": [{ "s": SELECTOR, "c": CIPHERTEXT, "hm": HEX }]
    });
    assert_invalid(schema_v2_2(), &p, "sv element carrying hm");
}

#[test]
fn v2_2_ste_vec_element_with_root_only_fields_fails() {
    let cases = [
        (
            "element with i",
            json!({
                "v": 2, "k": "sv", "i": ident(),
                "sv": [{ "s": SELECTOR, "c": CIPHERTEXT, "b3": HEX, "i": ident() }]
            }),
        ),
        (
            "element with v",
            json!({
                "v": 2, "k": "sv", "i": ident(),
                "sv": [{ "s": SELECTOR, "c": CIPHERTEXT, "b3": HEX, "v": 2 }]
            }),
        ),
        (
            "element with nested sv",
            json!({
                "v": 2, "k": "sv", "i": ident(),
                "sv": [{
                    "s": SELECTOR, "c": CIPHERTEXT, "b3": HEX,
                    "sv": [{ "s": SELECTOR, "c": CIPHERTEXT, "b3": HEX }]
                }]
            }),
        ),
    ];
    for (label, p) in cases {
        assert_invalid(schema_v2_2(), &p, label);
    }
}

#[test]
fn v2_2_unknown_top_level_field_fails() {
    // additionalProperties: false at the root.
    let p = json!({
        "v": 2, "c": CIPHERTEXT, "i": ident(),
        "x": "not a known field"
    });
    assert_invalid(schema_v2_2(), &p, "unknown top-level field");
}

// ===========================================================================
// v2.3 schema
// ===========================================================================

#[test]
fn v2_3_minimal_encrypted_payload_is_valid() {
    let p = json!({ "v": 2, "c": CIPHERTEXT, "i": ident() });
    assert_valid(schema_v2_3(), &p, "minimal encrypted payload");
}

#[test]
fn v2_3_encrypted_payload_with_ob_only_is_valid() {
    // Root-only Block ORE. `oc` is sv-element only by convention, but the
    // schema doesn't restrict it to that level today — covered separately.
    let p = json!({
        "v": 2, "k": "ct", "c": CIPHERTEXT, "i": ident(),
        "hm": HEX, "ob": [HEX, HEX_LONG]
    });
    assert_valid(schema_v2_3(), &p, "encrypted with Block ORE only");
}

#[test]
fn v2_3_sv_element_with_oc_is_valid() {
    // `oc` covers string and number leaves. `hm` is NOT present on the
    // same element — the two are mutually exclusive per v2.3.
    let p = json!({
        "v": 2, "k": "sv", "i": ident(),
        "sv": [
            { "s": SELECTOR, "a": false, "c": CIPHERTEXT, "oc": HEX_LONG }
        ]
    });
    assert_valid(schema_v2_3(), &p, "sv element with single oc term");
}

#[test]
fn v2_3_ste_vec_payload_with_mixed_hm_and_oc_elements_is_valid() {
    // v2.3 promotes element equality from b3 -> hm for boolean leaves and
    // for the placeholder entries that represent array / object roots.
    // String / number leaves carry `oc` instead. Every sv element has
    // exactly one — the two are mutually exclusive — and a single payload
    // can mix the two kinds of elements freely.
    let p = json!({
        "v": 2, "k": "sv", "i": ident(),
        "sv": [
            { "s": SELECTOR, "a": false, "c": CIPHERTEXT, "hm": HEX },
            { "s": SELECTOR, "a": true,  "c": CIPHERTEXT, "oc": HEX_LONG }
        ]
    });
    assert_valid(
        schema_v2_3(),
        &p,
        "ste_vec payload with hm-bearing + oc-bearing elements",
    );
}

#[test]
fn v2_3_sv_element_with_both_hm_and_oc_is_rejected() {
    // hm and oc are mutually exclusive: hm covers boolean leaves and the
    // placeholders for array / object roots; oc covers string / number
    // leaves. cipherstash-suite never emits both on the same entry.
    let p = json!({
        "v": 2, "k": "sv", "i": ident(),
        "sv": [
            { "s": SELECTOR, "a": false, "c": CIPHERTEXT, "hm": HEX, "oc": HEX_LONG }
        ]
    });
    assert_invalid(schema_v2_3(), &p, "sv element carrying both hm and oc");
}

#[test]
fn v2_3_sv_element_with_neither_hm_nor_oc_is_rejected() {
    // Every sv element carries exactly one of hm or oc — neither is also
    // malformed.
    let p = json!({
        "v": 2, "k": "sv", "i": ident(),
        "sv": [
            { "s": SELECTOR, "a": false, "c": CIPHERTEXT }
        ]
    });
    assert_invalid(schema_v2_3(), &p, "sv element with neither hm nor oc");
}

#[test]
fn v2_3_b3_field_is_rejected_everywhere() {
    let root = json!({
        "v": 2, "c": CIPHERTEXT, "i": ident(),
        "b3": HEX
    });
    assert_invalid(schema_v2_3(), &root, "encrypted payload carrying b3");

    let element = json!({
        "v": 2, "k": "sv", "i": ident(),
        "sv": [{ "s": SELECTOR, "c": CIPHERTEXT, "b3": HEX }]
    });
    assert_invalid(schema_v2_3(), &element, "sv element carrying b3");
}

#[test]
fn v2_3_legacy_split_ore_fields_are_rejected() {
    // v2.2 had `ocf` (ORE CLLW fixed) and `ocv` (ORE CLLW var) as separate
    // ordered fields. v2.3 collapses them into a single `oc` field. Width
    // information that was implied by the field name is now carried in a
    // leading domain-tag byte on the ciphertext.
    //
    // The OPE-side legacy fields (`opf` / `opv`) are also rejected — v2.3
    // doesn't support OPE (deferred to a future separate type).
    let cases = [
        (
            "encrypted payload with legacy ocf",
            json!({ "v": 2, "c": CIPHERTEXT, "i": ident(), "ocf": HEX }),
        ),
        (
            "encrypted payload with legacy ocv",
            json!({ "v": 2, "c": CIPHERTEXT, "i": ident(), "ocv": HEX_LONG }),
        ),
        (
            "encrypted payload with legacy opf",
            json!({ "v": 2, "c": CIPHERTEXT, "i": ident(), "opf": HEX }),
        ),
        (
            "encrypted payload with legacy opv",
            json!({ "v": 2, "c": CIPHERTEXT, "i": ident(), "opv": HEX_LONG }),
        ),
        (
            "sv element with legacy ocv",
            json!({
                "v": 2, "k": "sv", "i": ident(),
                "sv": [{ "s": SELECTOR, "c": CIPHERTEXT, "hm": HEX, "ocv": HEX_LONG }]
            }),
        ),
        (
            "sv element with `op` (OPE not supported in v2.3)",
            json!({
                "v": 2, "k": "sv", "i": ident(),
                "sv": [{ "s": SELECTOR, "c": CIPHERTEXT, "hm": HEX, "op": HEX }]
            }),
        ),
    ];
    for (label, p) in cases {
        assert_invalid(schema_v2_3(), &p, label);
    }
}

#[test]
fn v2_3_ob_and_oc_are_mutually_exclusive_at_root() {
    let p = json!({
        "v": 2, "c": CIPHERTEXT, "i": ident(),
        "oc": HEX_LONG, "ob": [HEX, HEX_LONG]
    });
    assert_invalid(schema_v2_3(), &p, "ob + oc");
}

#[test]
fn v2_3_oc_at_root_is_rejected() {
    // `oc` is sv-element-scope only. It must never appear at the root
    // of an EncryptedPayload, regardless of whether `ob` is also present
    // — the scope-disjoint rule (U-006) is independent of the mutual-
    // exclusion check between the two ordered terms.
    let p = json!({
        "v": 2, "c": CIPHERTEXT, "i": ident(),
        "oc": HEX_LONG
    });
    assert_invalid(schema_v2_3(), &p, "root payload with oc");
}

#[test]
fn v2_3_ob_and_oc_are_mutually_exclusive_in_sv_element() {
    let p = json!({
        "v": 2, "k": "sv", "i": ident(),
        "sv": [{
            "s": SELECTOR, "c": CIPHERTEXT,
            "hm": HEX, "ob": [HEX, HEX_LONG], "oc": HEX_LONG
        }]
    });
    assert_invalid(schema_v2_3(), &p, "sv element with both ob and oc");
}

#[test]
fn v2_3_encrypted_payload_with_sv_is_rejected() {
    let p = json!({
        "v": 2, "k": "ct", "c": CIPHERTEXT, "i": ident(),
        "sv": [{ "s": SELECTOR, "c": CIPHERTEXT, "hm": HEX }]
    });
    assert_invalid(schema_v2_3(), &p, "encrypted payload with sv");
}

// ---- SteVecQueryPayload (containment needle) ----

fn compile_query_schema() -> jsonschema::Validator {
    let mut schema = load_schema("eql-payload-v2.3.schema.json");
    // The top-level schema gates SteVecQueryPayload behind a separate
    // path; validate via the embedded definition.
    let defs = schema["$defs"]["SteVecQueryPayload"].clone();
    // Carry the surrounding $defs so $ref resolution still works.
    schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": schema["$defs"].clone(),
        "$ref": "#/$defs/SteVecQueryPayload"
    });
    let _ = defs;
    compile(&schema)
}

#[test]
fn v2_3_stevec_query_payload_with_hm_only_is_valid() {
    let schema = compile_query_schema();
    let payload = json!({
        "sv": [{ "s": SELECTOR, "hm": HEX }]
    });
    assert_valid(&schema, &payload, "stevec_query with hm-only element");
}

#[test]
fn v2_3_stevec_query_payload_with_oc_only_is_valid() {
    let schema = compile_query_schema();
    let payload = json!({
        "sv": [{ "s": SELECTOR, "oc": HEX_LONG }]
    });
    assert_valid(&schema, &payload, "stevec_query with oc-only element");
}

#[test]
fn v2_3_stevec_query_payload_with_c_field_is_rejected() {
    let schema = compile_query_schema();
    let payload = json!({
        "sv": [{ "s": SELECTOR, "c": CIPHERTEXT, "hm": HEX }]
    });
    assert_invalid(&schema, &payload, "stevec_query with c on element");
}

#[test]
fn v2_3_stevec_query_payload_without_sv_is_rejected() {
    let schema = compile_query_schema();
    let payload = json!({ "x": 1 });
    assert_invalid(&schema, &payload, "stevec_query without sv");
}

#[test]
fn v2_3_stevec_query_element_without_hm_or_oc_is_rejected() {
    let schema = compile_query_schema();
    let payload = json!({
        "sv": [{ "s": SELECTOR }]
    });
    assert_invalid(&schema, &payload, "stevec_query element with neither term");
}

#[test]
fn v2_3_minimum_required_fields_enforced() {
    let cases = [
        ("missing v", json!({ "c": CIPHERTEXT, "i": ident() })),
        ("missing c (encrypted)", json!({ "v": 2, "i": ident() })),
        ("missing i (encrypted)", json!({ "v": 2, "c": CIPHERTEXT })),
        (
            "ste_vec missing sv",
            json!({ "v": 2, "k": "sv", "i": ident() }),
        ),
        (
            "ste_vec missing k",
            json!({ "v": 2, "i": ident(), "sv": [{ "s": SELECTOR, "c": CIPHERTEXT, "hm": HEX }] }),
        ),
        (
            "sv element missing s",
            json!({
                "v": 2, "k": "sv", "i": ident(),
                "sv": [{ "c": CIPHERTEXT, "hm": HEX }]
            }),
        ),
        (
            "sv element missing c",
            json!({
                "v": 2, "k": "sv", "i": ident(),
                "sv": [{ "s": SELECTOR, "hm": HEX }]
            }),
        ),
    ];
    for (label, p) in cases {
        assert_invalid(schema_v2_3(), &p, label);
    }
}

// ===========================================================================
// from_v2 conversion outputs against the published v3 JSON Schemas
// ===========================================================================
//
// `eql_bindings::from_v2` already validates every converted payload through
// the target's binding struct; these tests close the remaining gap by
// validating the SAME outputs against the committed schema ARTIFACTS in
// `crates/eql-bindings/schema/v3/` — the files external consumers validate
// with — using the identical jsonschema machinery as the v2 sections above.

fn load_v3_schema(domain: &str) -> Validator {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/eql-bindings/schema/v3")
        .join(format!("{domain}.json"));
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    let schema: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("schema is not valid JSON: {e}"));
    compile(&schema)
}

/// Convert `v2` for `domain` via `from_v2` and validate against the
/// domain's committed schema file.
#[track_caller]
fn assert_converts_to_valid_v3(v2: &Value, domain: &str) -> Value {
    use eql_bindings::from_v2::{from_v2, TargetDomain};
    let target =
        TargetDomain::parse(domain).unwrap_or_else(|e| panic!("target {domain} must parse: {e}"));
    let out =
        from_v2(v2, target).unwrap_or_else(|e| panic!("conversion to {domain} must succeed: {e}"));
    assert_valid(
        &load_v3_schema(domain),
        &out,
        &format!("from_v2 output for {domain}"),
    );
    out
}

/// The fully-populated v2.3 scalar payload used by the conversion tests
/// (`op` included: cipherstash-client emits it for OPE-ordered columns ahead
/// of the v3 envelope).
fn v2_ct_full() -> Value {
    json!({
        "v": 2,
        "k": "ct",
        "c": CIPHERTEXT,
        "i": ident(),
        "hm": HEX,
        "bf": [12, 47, 91, 40000],
        "ob": [HEX, HEX_LONG],
        "op": HEX
    })
}

#[test]
fn from_v2_scalar_outputs_validate_against_published_v3_schemas() {
    // One target per capability shape: storage-only, hm, ob, hm+op+bf,
    // hm+ob+bf, op, hm+op. The bf fixture includes an upper-half position
    // (40000) so the schema's signed int16 bounds are exercised on the
    // converted value.
    let v2 = v2_ct_full();
    for domain in [
        "eql_v3_integer",
        "eql_v3_text_eq",
        "eql_v3_integer_ord_ore",
        "eql_v3_text_search",
        "eql_v3_text_search_ore",
        "eql_v3_integer_ord_ope",
        "eql_v3_text_ord_ope",
    ] {
        assert_converts_to_valid_v3(&v2, domain);
    }
}

#[test]
fn native_v3_ste_vec_document_validates_against_published_v3_schema() {
    // A v2 SteVec DOCUMENT is no longer convertible to v3 (the envelope wire
    // format — key header + selector-derived nonces — is re-encryption, not
    // a JSON transform), so this validates a NATIVE v3 envelope document
    // (the shape encrypt_eql_v3 emits) against the committed schema.
    let doc = json!({
        "v": 3,
        "k": "sv",
        "i": ident(),
        "h": "mp_base85_key_header",
        "sv": [
            { "s": SELECTOR, "c": CIPHERTEXT },
            { "s": SELECTOR, "a": true, "c": CIPHERTEXT, "op": HEX_LONG }
        ]
    });
    assert_valid(
        &load_v3_schema("eql_v3_json_search"),
        &doc,
        "native v3 SteVec document",
    );
}

#[test]
fn from_v2_ste_vec_query_fails_closed() {
    use eql_bindings::from_v2::{from_v2_query, TargetDomain};
    // Legacy selectors do not include the plaintext value, so no legacy
    // SteVec query can be transformed into a v3 exact-match query.
    let v2 = json!({
        "sv": [
            { "s": SELECTOR },
            { "s": SELECTOR, "op": HEX_LONG }
        ]
    });
    assert!(matches!(
        from_v2_query(&v2, TargetDomain::Json).unwrap_err(),
        eql_bindings::from_v2::FromV2Error::UnconvertibleSteVecQuery
    ));
}

#[test]
fn published_v3_schemas_reject_the_unconverted_v2_payloads() {
    // The discriminating half: the same machinery must FAIL the raw v2 inputs
    // (v: 2 envelope, stray k/terms), proving the schema validation above is
    // not vacuously green.
    assert_invalid(
        &load_v3_schema("eql_v3_text_eq"),
        &v2_ct_full(),
        "raw v2 ct payload",
    );
    assert_invalid(
        &load_v3_schema("eql_v3_json_search"),
        &json!({
            "v": 2, "k": "sv", "i": ident(),
            "sv": [{ "s": SELECTOR, "c": CIPHERTEXT, "hm": HEX }]
        }),
        "raw v2 sv payload",
    );
}
