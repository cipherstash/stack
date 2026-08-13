//! Conformance for the v3 tier: explicit, readable tests for the reference
//! token (`integer`) plus the term shapes it doesn't carry. The exhaustive
//! catalog-driven sweep (every domain, every required key) lives in
//! `catalog_parity.rs`.

use eql_bindings::v3::integer::{Integer, IntegerEq, IntegerOrd, IntegerOrdOpe, IntegerOrdOre};
use eql_bindings::v3::text::TextMatch;
use eql_bindings::v3::DomainType;
use serde_json::json;

#[test]
fn integer_storage_round_trips() {
    let wire = json!({
        "v": 3,
        "i": { "t": "users", "c": "age" },
        "c": "mp_base85_ciphertext"
    });
    let parsed: Integer = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
    assert_eq!(Integer::sql_domain_static(), "public.eql_v3_integer");
}

#[test]
fn integer_eq_round_trips() {
    let wire = json!({
        "v": 3,
        "i": { "t": "users", "c": "age" },
        "c": "mp_base85_ciphertext",
        "hm": "deadbeef"
    });
    let parsed: IntegerEq = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
    assert_eq!(IntegerEq::sql_domain_static(), "public.eql_v3_integer_eq");
}

#[test]
fn integer_ord_ore_round_trips() {
    // `_ord_ore` carries the block-ORE term: `ob` is an array of hex blocks.
    let wire = json!({
        "v": 3,
        "i": { "t": "users", "c": "age" },
        "c": "mp_base85_ciphertext",
        "ob": ["ore_block_0", "ore_block_1"]
    });
    let parsed: IntegerOrdOre = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
    assert_eq!(
        IntegerOrdOre::sql_domain_static(),
        "public.eql_v3_integer_ord_ore"
    );
}

#[test]
fn integer_ord_round_trips() {
    // `_ord` (the default) carries the CLLW-OPE term: `op` is a single hex
    // string (not an array like `ob`), natively bytea-sortable after hex-decode.
    let wire = json!({
        "v": 3,
        "i": { "t": "users", "c": "age" },
        "c": "mp_base85_ciphertext",
        "op": "00ffab"
    });
    let parsed: IntegerOrd = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
    assert_eq!(IntegerOrd::sql_domain_static(), "public.eql_v3_integer_ord");
    // `_ord_ope` is the same shape under the scheme-explicit domain name.
    let parsed: IntegerOrdOpe = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
    assert_eq!(
        IntegerOrdOpe::sql_domain_static(),
        "public.eql_v3_integer_ord_ope"
    );
}

#[test]
fn integer_ord_ope_rejects_missing_ope_term() {
    // Only the base fields, so the sole cause of failure is the absent `op`.
    // `_ord` carries the same term, so it must reject the same payload.
    let no_op = json!({
        "v": 3,
        "i": { "t": "users", "c": "age" },
        "c": "mp_base85_ciphertext"
    });
    let result: Result<IntegerOrdOpe, _> = serde_json::from_value(no_op.clone());
    assert!(
        result.is_err(),
        "IntegerOrdOpe must reject a payload with no op"
    );
    let result: Result<IntegerOrd, _> = serde_json::from_value(no_op);
    assert!(
        result.is_err(),
        "IntegerOrd must reject a payload with no op"
    );
}

#[test]
fn integer_eq_rejects_missing_hmac() {
    // The capability is type-enforced: an `integer_eq` payload with no `hm` is
    // not representable. This is the bug class — a search term missing its
    // index term — closed at the type boundary, before any consumer runs.
    let no_hm = json!({
        "v": 3,
        "i": { "t": "users", "c": "age" },
        "c": "mp_base85_ciphertext"
    });
    let result: Result<IntegerEq, _> = serde_json::from_value(no_hm);
    assert!(
        result.is_err(),
        "IntegerEq must reject a payload with no hm"
    );
}

#[test]
fn rejects_missing_envelope_keys() {
    // v/i/c are the shared envelope contract every domain CHECK asserts. The
    // missing-term negatives cover hm/ob/bf; these cover the envelope itself —
    // dropping the version, identifier, or ciphertext fails at the type
    // boundary, the Rust analogue of the CHECK's NOT NULL envelope columns.
    let base = json!({
        "v": 3,
        "i": { "t": "users", "c": "age" },
        "c": "mp_base85_ciphertext",
        "hm": "deadbeef"
    });
    for key in ["v", "i", "c"] {
        let mut wire = base.clone();
        wire.as_object_mut().unwrap().remove(key);
        let result: Result<IntegerEq, _> = serde_json::from_value(wire);
        assert!(
            result.is_err(),
            "IntegerEq must reject a payload with no {key}"
        );
    }
}

#[test]
fn rejects_wrong_envelope_version() {
    // The SchemaVersion field is the Rust analogue of the domain CHECK's
    // `VALUE->>'v' = '3'`: any other version — the legacy 2, and a string
    // "3", which the CHECK's `->>` coercion would accept — fails at the type
    // boundary instead of at INSERT.
    for v in [json!(1), json!(2), json!("3")] {
        let wire = json!({
            "v": v,
            "i": { "t": "users", "c": "age" },
            "c": "mp_base85_ciphertext",
            "hm": "deadbeef"
        });
        let result: Result<IntegerEq, _> = serde_json::from_value(wire);
        assert!(result.is_err(), "IntegerEq must reject v = {v}");
    }
}

#[test]
fn rejects_unknown_keys() {
    // deny_unknown_fields: a payload carrying keys outside the domain's set
    // is not silently accepted-and-stripped — a pass-through consumer must
    // not lose data it didn't know about.
    let wire = json!({
        "v": 3,
        "i": { "t": "users", "c": "age" },
        "c": "mp_base85_ciphertext",
        "hm": "deadbeef",
        "ob": ["ore_block_0"]
    });
    let result: Result<IntegerEq, _> = serde_json::from_value(wire);
    assert!(
        result.is_err(),
        "IntegerEq must reject a payload carrying keys beyond its domain (here: ob)"
    );
}

#[test]
fn integer_ord_ore_rejects_missing_ore_term() {
    // Omit `hm`: it is not an IntegerOrdOre field, so leaving it in would trip
    // deny_unknown_fields and the rejection could pass for the wrong reason.
    // This payload carries only the base fields, so the sole cause of failure
    // is the absent `ob`.
    let no_ob = json!({
        "v": 3,
        "i": { "t": "users", "c": "age" },
        "c": "mp_base85_ciphertext"
    });
    let result: Result<IntegerOrdOre, _> = serde_json::from_value(no_ob);
    assert!(
        result.is_err(),
        "IntegerOrdOre must reject a payload with no ob"
    );
}

#[test]
fn text_match_round_trips_signed_bloom_filter() {
    // `bf` is signed i16 (smallint[]): filters sized above 32768 emit
    // upper-half bit positions as negative values.
    let wire = json!({
        "v": 3,
        "i": { "t": "users", "c": "email" },
        "c": "mp_base85_ciphertext",
        "bf": [-1, -32768, 32767, 0]
    });
    let parsed: TextMatch = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);

    let no_bf = json!({
        "v": 3,
        "i": { "t": "users", "c": "email" },
        "c": "mp_base85_ciphertext"
    });
    let result: Result<TextMatch, _> = serde_json::from_value(no_bf);
    assert!(
        result.is_err(),
        "TextMatch must reject a payload with no bf"
    );
}

#[test]
fn non_integer_tokens_round_trip_every_domain() {
    // integer is exercised exhaustively above; the other ordered tokens carry the
    // *same* wire field names but were serialized by no test, so a copy-paste
    // field typo (e.g. `hm` -> `hmm` in `bigint.rs`) would ship green —
    // `catalog_parity.rs` checks domain *names* only, never the wire shape.
    // This sweep roundtrips every non-integer domain and pins its catalog name,
    // failing the instant a token drifts from the shared envelope/term contract.
    use eql_bindings::v3::{
        bigint::*, boolean::*, date::*, double::*, numeric::*, real::*, smallint::*, text::*,
    };

    // Wire builders for the shapes the ordered tokens share.
    let storage = |t: &str| json!({ "v": 3, "i": { "t": t, "c": "x" }, "c": "ct" });
    let eq = |t: &str| json!({ "v": 3, "i": { "t": t, "c": "x" }, "c": "ct", "hm": "deadbeef" });
    // `_ord_ore` carries the block-ORE term `ob` (an array of hex blocks).
    let ore = |t: &str| json!({ "v": 3, "i": { "t": t, "c": "x" }, "c": "ct", "ob": ["b0", "b1"] });
    // `_ord` (the default) and `_ord_ope` carry the CLLW-OPE hex string `op`
    // (a single string, not an array).
    let ope = |t: &str| json!({ "v": 3, "i": { "t": t, "c": "x" }, "c": "ct", "op": "00ffab" });
    // Text routes equality through `hm`, so its ordered domains carry both `hm`
    // and the ordering term (`[Hm, Ore]` / `[Hm, Ope]`); `text_search` adds the
    // Bloom-filter match term and is OPE-ordered, while `text_search_ore` is its
    // block-ORE sibling.
    let text_ore = |t: &str| json!({ "v": 3, "i": { "t": t, "c": "x" }, "c": "ct", "hm": "deadbeef", "ob": ["b0", "b1"] });
    let text_ope = |t: &str| json!({ "v": 3, "i": { "t": t, "c": "x" }, "c": "ct", "hm": "deadbeef", "op": "00ffab" });
    let text_search = |t: &str| json!({ "v": 3, "i": { "t": t, "c": "x" }, "c": "ct", "hm": "deadbeef", "op": "00ffab", "bf": [1, 2, 3] });
    let text_search_ore = |t: &str| json!({ "v": 3, "i": { "t": t, "c": "x" }, "c": "ct", "hm": "deadbeef", "ob": ["b0", "b1"], "bf": [1, 2, 3] });

    // Roundtrip a payload byte-for-byte, then confirm the catalog domain name.
    macro_rules! round_trip {
        ($ty:ty, $wire:expr, $domain:expr) => {{
            let wire = $wire;
            let parsed: $ty = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
            assert_eq!(<$ty>::sql_domain_static(), $domain);
        }};
    }

    round_trip!(Smallint, storage("a"), "public.eql_v3_smallint");
    round_trip!(SmallintEq, eq("a"), "public.eql_v3_smallint_eq");
    round_trip!(SmallintOrd, ope("a"), "public.eql_v3_smallint_ord");
    round_trip!(SmallintOrdOre, ore("a"), "public.eql_v3_smallint_ord_ore");
    round_trip!(SmallintOrdOpe, ope("a"), "public.eql_v3_smallint_ord_ope");

    round_trip!(Bigint, storage("a"), "public.eql_v3_bigint");
    round_trip!(BigintEq, eq("a"), "public.eql_v3_bigint_eq");
    round_trip!(BigintOrd, ope("a"), "public.eql_v3_bigint_ord");
    round_trip!(BigintOrdOre, ore("a"), "public.eql_v3_bigint_ord_ore");
    round_trip!(BigintOrdOpe, ope("a"), "public.eql_v3_bigint_ord_ope");

    round_trip!(Date, storage("a"), "public.eql_v3_date");
    round_trip!(DateEq, eq("a"), "public.eql_v3_date_eq");
    round_trip!(DateOrd, ope("a"), "public.eql_v3_date_ord");
    round_trip!(DateOrdOre, ore("a"), "public.eql_v3_date_ord_ore");
    round_trip!(DateOrdOpe, ope("a"), "public.eql_v3_date_ord_ope");

    // numeric is the first scalar whose native ORE term exceeds 8 blocks (14);
    // the wire shape is identical, so the same `ord` builder applies.
    round_trip!(Numeric, storage("a"), "public.eql_v3_numeric");
    round_trip!(NumericEq, eq("a"), "public.eql_v3_numeric_eq");
    round_trip!(NumericOrd, ope("a"), "public.eql_v3_numeric_ord");
    round_trip!(NumericOrdOre, ore("a"), "public.eql_v3_numeric_ord_ore");
    round_trip!(NumericOrdOpe, ope("a"), "public.eql_v3_numeric_ord_ope");

    // real/double are the float scalars (renamed from float4/float8); they carry
    // the same ordered-token wire shape as the int scalars (`hm` eq, `ob` ord).
    round_trip!(Real, storage("a"), "public.eql_v3_real");
    round_trip!(RealEq, eq("a"), "public.eql_v3_real_eq");
    round_trip!(RealOrd, ope("a"), "public.eql_v3_real_ord");
    round_trip!(RealOrdOre, ore("a"), "public.eql_v3_real_ord_ore");

    round_trip!(Double, storage("a"), "public.eql_v3_double");
    round_trip!(DoubleEq, eq("a"), "public.eql_v3_double_eq");
    round_trip!(DoubleOrd, ope("a"), "public.eql_v3_double_ord");
    round_trip!(DoubleOrdOre, ore("a"), "public.eql_v3_double_ord_ore");

    // boolean is storage-only (no eq/ord term) — just the shared envelope.
    round_trip!(Boolean, storage("a"), "public.eql_v3_boolean");

    // text_match is covered by `text_match_round_trips_signed_bloom_filter`.
    round_trip!(Text, storage("a"), "public.eql_v3_text");
    round_trip!(TextEq, eq("a"), "public.eql_v3_text_eq");
    round_trip!(TextOrd, text_ope("a"), "public.eql_v3_text_ord");
    round_trip!(TextOrdOre, text_ore("a"), "public.eql_v3_text_ord_ore");
    round_trip!(TextOrdOpe, text_ope("a"), "public.eql_v3_text_ord_ope");
    round_trip!(TextSearch, text_search("a"), "public.eql_v3_text_search");
    round_trip!(
        TextSearchOre,
        text_search_ore("a"),
        "public.eql_v3_text_search_ore"
    );
}

#[test]
fn timestamp_round_trips_and_enforces_term_capabilities() {
    // timestamp is an ordered token — it carries the full
    // storage/`_eq`/`_ord_ore`/`_ord`/`_ord_ope` shape, the same as the int
    // scalars. The integer template was copy-pasted to produce it, so a dropped
    // `hm`/`ob`/`op` or a field typo would pass `catalog_parity` (domain names
    // only) but is caught here. (Was equality-only while the ORE comparator was
    // hardcoded to 8 blocks; promoted once `eql_v3.ore_block_256` generalized to
    // any width — that 12-block ORE width is what `_ord_ore` still carries.)
    use eql_bindings::v3::timestamp::{
        Timestamp, TimestampEq, TimestampOrd, TimestampOrdOpe, TimestampOrdOre,
    };

    // Storage-only: envelope, no term.
    let storage = json!({
        "v": 3,
        "i": { "t": "events", "c": "occurred_at" },
        "c": "mp_base85_ciphertext"
    });
    let parsed: Timestamp = serde_json::from_value(storage.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), storage);
    assert_eq!(Timestamp::sql_domain_static(), "public.eql_v3_timestamp");

    // Equality: envelope + hm.
    let with_hm = json!({
        "v": 3,
        "i": { "t": "events", "c": "occurred_at" },
        "c": "mp_base85_ciphertext",
        "hm": "deadbeef"
    });
    let parsed: TimestampEq = serde_json::from_value(with_hm.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), with_hm);
    assert_eq!(
        TimestampEq::sql_domain_static(),
        "public.eql_v3_timestamp_eq"
    );

    // ORE ordered: envelope + ob (a 12-block array on the wire; shape is the same).
    let with_ob = json!({
        "v": 3,
        "i": { "t": "events", "c": "occurred_at" },
        "c": "mp_base85_ciphertext",
        "ob": ["b0", "b1"]
    });
    let parsed: TimestampOrdOre = serde_json::from_value(with_ob.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), with_ob);
    assert_eq!(
        TimestampOrdOre::sql_domain_static(),
        "public.eql_v3_timestamp_ord_ore"
    );

    // OPE ordered: envelope + op (a single CLLW-OPE hex string). `_ord` (the
    // default) and `_ord_ope` share this shape.
    let with_op = json!({
        "v": 3,
        "i": { "t": "events", "c": "occurred_at" },
        "c": "mp_base85_ciphertext",
        "op": "00ffab"
    });
    let parsed: TimestampOrd = serde_json::from_value(with_op.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), with_op);
    assert_eq!(
        TimestampOrd::sql_domain_static(),
        "public.eql_v3_timestamp_ord"
    );
    let parsed: TimestampOrdOpe = serde_json::from_value(with_op.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), with_op);
    assert_eq!(
        TimestampOrdOpe::sql_domain_static(),
        "public.eql_v3_timestamp_ord_ope"
    );

    // The searchable domains cannot let their term silently become optional.
    let no_hm = json!({
        "v": 3,
        "i": { "t": "events", "c": "occurred_at" },
        "c": "mp_base85_ciphertext"
    });
    let result: Result<TimestampEq, _> = serde_json::from_value(no_hm.clone());
    assert!(
        result.is_err(),
        "TimestampEq must reject a payload with no hm"
    );
    let result: Result<TimestampOrdOre, _> = serde_json::from_value(no_hm.clone());
    assert!(
        result.is_err(),
        "TimestampOrdOre must reject a payload with no ob"
    );
    let result: Result<TimestampOrd, _> = serde_json::from_value(no_hm);
    assert!(
        result.is_err(),
        "TimestampOrd must reject a payload with no op"
    );
}

#[test]
fn stevec_document_round_trips_and_enforces_envelope() {
    use eql_bindings::v3::json::SteVecDocument;
    use eql_bindings::v3::DomainType;
    // The real cipherstash SteVec document envelope carries the `k` form
    // discriminator (`"sv"`), required by the canonical eql-payload-v2.3
    // `SteVecPayload` (`required: [v,k,i,sv]`) and emitted on every real payload.
    // The document struct is strict, so it must MODEL `k` — omitting it would
    // reject the real wire (the bug this test's real-crypto sibling caught).
    let wire = json!({
        "v": 3,
        "k": "sv",
        "i": { "t": "users", "c": "profile" },
        "h": "mp_base85_key_header",
        "sv": [
            { "s": "sel_root", "c": "ct_root" },
            { "s": "sel_age", "c": "ct_age", "a": true, "op": "cllw_ope" }
        ]
    });
    let parsed: SteVecDocument = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
    assert_eq!(
        SteVecDocument::sql_domain_static(),
        "public.eql_v3_json_search"
    );

    // Envelope negatives (parity with the scalar integer tests) — including
    // `k` and the envelope key header `h`.
    for missing in ["v", "k", "i", "h", "sv"] {
        let mut w = wire.clone();
        w.as_object_mut().unwrap().remove(missing);
        assert!(
            serde_json::from_value::<SteVecDocument>(w).is_err(),
            "missing {missing} must fail"
        );
    }
    // Wrong version (the legacy 2 is rejected now the tier carries v: 3).
    let mut wrong_v = wire.clone();
    wrong_v["v"] = json!(2);
    assert!(serde_json::from_value::<SteVecDocument>(wrong_v).is_err());
    // Wrong form discriminator: `k` is pinned to "sv" (like `v` is pinned to 3),
    // so a scalar-ciphertext (`k:"ct"`) payload can't be read back as a document.
    let mut wrong_k = wire.clone();
    wrong_k["k"] = json!("ct");
    assert!(
        serde_json::from_value::<SteVecDocument>(wrong_k).is_err(),
        "k other than \"sv\" must fail"
    );
    // Unknown top-level key (deny_unknown_fields; no flatten on the document).
    let mut extra = wire.clone();
    extra
        .as_object_mut()
        .unwrap()
        .insert("bogus".into(), json!(1));
    assert!(serde_json::from_value::<SteVecDocument>(extra).is_err());
}

#[test]
fn stevec_entry_term_is_optional_and_op_only() {
    use eql_bindings::v3::json::SteVecEntry;
    // Term-less entries — value entries and non-orderable path entries — are
    // the common case: exact matching is selector presence, not a term.
    let termless: SteVecEntry = serde_json::from_value(json!({ "s": "sel", "c": "ct" })).unwrap();
    assert!(termless.op.is_none(), "term-less entries have no op");
    // op arm (ordered number/string path entries).
    let op: SteVecEntry =
        serde_json::from_value(json!({ "s": "sel", "c": "ct", "op": "cllw" })).unwrap();
    assert!(op.op.is_some());
    // Explicit optional fields preserve root i/v/h merged in by `->`.
    let merged: SteVecEntry = serde_json::from_value(
        json!({ "s": "sel", "c": "ct", "op": "cllw", "i": {"t":"a","c":"b"}, "v": 3, "h": "kh" }),
    )
    .unwrap();
    assert!(merged.op.is_some());
    assert!(merged.i.is_some() && merged.v.is_some() && merged.h.is_some());
    // Retired and unknown keys fail at the binding boundary, matching SQL.
    assert!(serde_json::from_value::<SteVecEntry>(
        json!({ "s": "sel", "c": "ct", "hm": "deadbeef" })
    )
    .is_err());
    assert!(
        serde_json::from_value::<SteVecEntry>(json!({ "s": "sel", "c": "ct", "bogus": true }))
            .is_err()
    );
}

#[test]
fn stevec_query_round_trips() {
    use eql_bindings::v3::json::SteVecQuery;
    use eql_bindings::v3::DomainType;
    // A needle mixes selector-only elements (value selectors / structural
    // nodes — matched on presence) with op-bearing ordered path elements.
    let wire = json!({ "sv": [ { "s": "sel" }, { "s": "sel_ord", "op": "cllw" } ] });
    let parsed: SteVecQuery = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
    assert_eq!(SteVecQuery::sql_domain_static(), "eql_v3.query_json");
    // Unknown top-level key rejected (SteVecQuery has no flatten field).
    assert!(serde_json::from_value::<SteVecQuery>(json!({ "sv": [], "bogus": 1 })).is_err());
    assert!(serde_json::from_value::<SteVecQuery>(
        json!({ "sv": [{ "s": "sel", "c": "ciphertext" }] })
    )
    .is_err());
    assert!(serde_json::from_value::<SteVecQuery>(
        json!({ "sv": [{ "s": "sel", "hm": "deadbeef" }] })
    )
    .is_err());
}

#[test]
fn stevec_document_and_query_schemas_are_strict() {
    use eql_bindings::v3::json::{SteVecDocument, SteVecForm, SteVecQuery};
    use eql_bindings::v3::DomainType;
    use eql_bindings::{Identifier, SchemaVersion};
    let doc = SteVecDocument {
        v: SchemaVersion::CURRENT,
        k: SteVecForm::SV,
        i: Identifier {
            t: "x".into(),
            c: "y".into(),
        },
        h: "kh".to_string().into(),
        sv: vec![],
    };
    let sdoc = serde_json::to_value(doc.schema()).unwrap();
    assert_eq!(sdoc.pointer("/additionalProperties"), Some(&json!(false)));
    assert_eq!(
        sdoc.pointer("/properties/v/$ref"),
        Some(&json!("#/$defs/SchemaVersion"))
    );
    assert_eq!(
        sdoc.pointer("/$defs/SchemaVersion/const"),
        Some(&json!(eql_bindings::EQL_SCHEMA_VERSION))
    );
    // `k` is pinned to the const "sv" via SteVecForm, exactly like `v`/SchemaVersion.
    assert_eq!(
        sdoc.pointer("/properties/k/$ref"),
        Some(&json!("#/$defs/SteVecForm"))
    );
    assert_eq!(sdoc.pointer("/$defs/SteVecForm/const"), Some(&json!("sv")));
    let q = SteVecQuery { sv: vec![] };
    let sq = serde_json::to_value(q.schema()).unwrap();
    assert_eq!(sq.pointer("/additionalProperties"), Some(&json!(false)));
    // SteVecDocument/Query domain names.
    assert_eq!(
        SteVecDocument::sql_domain_static(),
        "public.eql_v3_json_search"
    );
    assert_eq!(SteVecQuery::sql_domain_static(), "eql_v3.query_json");
}

#[test]
fn stevec_ts_exports_have_expected_shape() {
    // Pin the emitted .ts STRUCTURALLY so a
    // regression is a test failure, not a human-inspection miss. Assertions match
    // against the `export type <Name> = ...;` BODY LINE — never loose single-char
    // `contains` over the whole file, which the generated header / imports / doc
    // comment satisfy trivially (a dropped field would still pass). During
    // `types:check`, read the freshly exported TS_RS_EXPORT_DIR output; plain
    // `cargo test` falls back to committed bindings next to the crate manifest.
    let base = match std::env::var("TS_RS_EXPORT_DIR") {
        Ok(dir) if !dir.is_empty() => format!("{dir}/v3"),
        _ => format!("{}/bindings/v3", env!("CARGO_MANIFEST_DIR")),
    };

    // Isolate and normalize the generated type body. Field-level Rustdoc makes
    // ts-rs split the declaration over several lines, so remove generated block
    // comments before collapsing whitespace.
    let export_body = |file: &str, name: &str| -> String {
        let text = std::fs::read_to_string(format!("{base}/{file}")).unwrap();
        let start = text
            .find(&format!("export type {name} "))
            .unwrap_or_else(|| panic!("{file}: no `export type {name}` declaration"));
        let declaration = &text[start..];
        let mut without_comments = String::new();
        let mut rest = declaration;
        while let Some(comment_start) = rest.find("/**") {
            without_comments.push_str(&rest[..comment_start]);
            let comment_end = rest[comment_start + 3..]
                .find("*/")
                .unwrap_or_else(|| panic!("{file}: unterminated generated comment"));
            rest = &rest[comment_start + 3 + comment_end + 2..];
        }
        without_comments.push_str(rest);
        without_comments
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };

    // SteVecEntry: direct fields s/c, optional op and extracted metadata, and
    // the OPTIONAL nullable array marker `a`. `a?: boolean | null` (not `a: boolean |
    // null`) pins ts-rs optionality so the TS binding agrees with the JSON Schema,
    // which excludes `a` from `required` — the drift a bare `Option<bool>` without
    // `#[ts(optional = nullable)]` silently reintroduces.
    let entry = export_body("SteVecEntry.ts", "SteVecEntry");
    for needle in [
        "s: Selector",
        "c: EntryCiphertext",
        "a?: boolean | null",
        "op?: OpeCllw",
        "i?: Identifier",
        "v?: SchemaVersion",
        "h?: KeyHeader",
    ] {
        assert!(
            entry.contains(needle),
            "SteVecEntry.ts body must contain `{needle}`, got: {entry}"
        );
    }
    // Property ORDER pin. The generic `ts_property_order.rs` guard structurally
    // skips non-scalar (jsonb) domains, so the SteVec property order has no other
    // regression guard. Assert the exact ordered field prefix so a field reorder
    // in `json.rs` (which changes the wire/consumer contract) fails here rather
    // than escaping to a manual diff.
    assert!(
        entry.contains("{ s: Selector, c: EntryCiphertext, a?: boolean | null, op?: OpeCllw, i?: Identifier, v?: SchemaVersion, h?: KeyHeader, }"),
        "SteVecEntry.ts field order must be s, c, a, op, i, v, h; got: {entry}"
    );
    let document = export_body("SteVecDocument.ts", "SteVecDocument");
    assert!(
        document.contains(
            "{ v: SchemaVersion, k: SteVecForm, i: Identifier, h: KeyHeader, sv: Array<SteVecEntry>, }"
        ),
        "SteVecDocument.ts field order must be v, k, i, h, sv, got: {document}"
    );
}
