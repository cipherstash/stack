//! Stored rows, frozen: records the `next` build wrote, which every later
//! build must still open, and whose terms every later build must still
//! derive.
//!
//! The other record fixtures (`record_lowering.json`, `value_kinds.json`,
//! `query_operators.json`) prove that two authors of one record agree
//! *today*, and are regenerated when the encoding moves. This one is the
//! opposite: `tests/fixtures/stored_rows_v1.json` is written once and never
//! regenerated, so a change that alters the bytes of a stored row (the leaf
//! encoding, the AAD, a term derivation, the stored tree's shape) fails
//! here instead of being regenerated away. Nothing in this file writes it
//! except [`write_stored_rows_v1`], which is ignored, and refuses to run when
//! the file exists. `STACK_ENCRYPT_UPDATE_FIXTURES` does not touch it.
//!
//! A deliberate change to the stored format adds `stored_rows_v2.json`
//! beside this one. It never edits v1, and it says how v1 rows migrate.
//! Order terms are the one exception, for as long as the README says: a
//! deliberate change to how one is derived re-freezes only the `ore` and
//! `ope` terms that moved, by running the check with
//! `STACK_ENCRYPT_REFREEZE_ORDER_TERMS=1`. That run asserts nothing else
//! moved before it rewrites anything.
//!
//! The schema and the rules are in `tests/fixtures/README.md`.
#![cfg(feature = "dynamic")]

mod common;

use std::path::PathBuf;

use common::{deterministic_cipher, DeterministicSource};
use serde_json::{json, Map, Value as Json};
use stack_encrypt::dynamic::record::{self, Plan as DataPlan};
use stack_encrypt::dynamic::{admits, Scope, ValueFrame, ValueKind};
use stack_encrypt::target::IndexSpec;
use stack_encrypt::StackCipherText as Node;
use stack_encrypt::{
    CipherText, Label, PassthroughFrame, SealedValue, StackCipher, StackCipherText,
};
use vitaminc_aead::plaintext::{Float, Int, Logical, MapSink, Physical, SeqSink, Sink};
use vitaminc_aead::FrameWriter;

/// The seed of the deterministic key source the rows were sealed under. Part
/// of the frozen contract, as is `stack_kms::DeterministicSource` itself.
const SEED: [u8; 32] = *b"stack-encrypt stored rows v1    ";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/stored_rows_v1.json")
}

// ---- hex ----------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "hex of odd length");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

// ---- a stored tree <-> JSON -------------------------------------------------

/// A stored tree as JSON, one object per node, so every shape round-trips:
/// `{"leaf": hex}` (a `SealedValue`'s frozen bytes), `{"seq": [..]}`,
/// `{"empty_seq": hex}`, `{"map": [[key, node], ..]}` (in stored order),
/// `{"empty_map": hex}` and `{"passthrough": hex}` (the payload's frame).
fn json_of_node(node: Node) -> Json {
    match node {
        CipherText::Single(leaf) => json!({ "leaf": hex(&leaf.to_bytes()) }),
        CipherText::Sequence(items) => {
            json!({ "seq": items.into_iter().map(json_of_node).collect::<Vec<_>>() })
        }
        CipherText::EmptySequence(leaf) => json!({ "empty_seq": hex(&leaf.to_bytes()) }),
        CipherText::Map(entries) => json!({
            "map": entries
                .into_iter()
                .map(|(key, node)| json!([key, json_of_node(node)]))
                .collect::<Vec<_>>()
        }),
        CipherText::EmptyMap(leaf) => json!({ "empty_map": hex(&leaf.to_bytes()) }),
        CipherText::Passthrough(payload) => json!({ "passthrough": hex(&payload.0) }),
    }
}

fn leaf_of(value: &Json) -> SealedValue {
    SealedValue::from_bytes(&unhex(value.as_str().expect("hex"))).expect("a frozen leaf")
}

fn node_of_json(json: &Json) -> Node {
    let object = json.as_object().expect("a node is an object");
    assert_eq!(object.len(), 1, "a node has one key: {json}");
    let (kind, value) = object.iter().next().expect("one entry");
    match kind.as_str() {
        "leaf" => CipherText::Single(leaf_of(value)),
        "seq" => CipherText::Sequence(
            value
                .as_array()
                .expect("a list")
                .iter()
                .map(node_of_json)
                .collect(),
        ),
        "empty_seq" => CipherText::EmptySequence(leaf_of(value)),
        "map" => CipherText::Map(
            value
                .as_array()
                .expect("a list")
                .iter()
                .map(|entry| {
                    let pair = entry.as_array().expect("a [key, node] pair");
                    (
                        pair[0].as_str().expect("a key").to_string(),
                        node_of_json(&pair[1]),
                    )
                })
                .collect(),
        ),
        "empty_map" => CipherText::EmptyMap(leaf_of(value)),
        "passthrough" => {
            CipherText::Passthrough(PassthroughFrame(unhex(value.as_str().expect("hex"))))
        }
        other => panic!("not a node kind: {other}"),
    }
}

/// What a stored tree must keep when it is sealed again: everything but the
/// sealed leaves, which carry a fresh nonce each time. Its shape, its map
/// keys in order, its terms and its passthroughs.
fn skeleton(json: &Json) -> Json {
    let object = json.as_object().expect("a node");
    let (kind, value) = object.iter().next().expect("one entry");
    match kind.as_str() {
        "leaf" | "empty_seq" | "empty_map" => json!(kind),
        "seq" => {
            json!({ "seq": value.as_array().expect("a list").iter().map(skeleton).collect::<Vec<_>>() })
        }
        "map" => json!({
            "map": value
                .as_array()
                .expect("a list")
                .iter()
                .map(|pair| json!([pair[0], skeleton(&pair[1])]))
                .collect::<Vec<_>>()
        }),
        _ => json.clone(),
    }
}

/// Whether a stored map entry is an order term: `["ore", {"passthrough": ..}]`
/// or the same under `"ope"`.
fn is_order_term(pair: &Json) -> bool {
    matches!(pair[0].as_str(), Some("ore" | "ope"))
        && pair[1]
            .as_object()
            .is_some_and(|node| node.contains_key("passthrough"))
}

/// [`skeleton`] with every order term's bytes masked: what must stay
/// exactly as written when order terms are re-frozen.
fn without_order_terms(json: &Json) -> Json {
    let object = json.as_object().expect("a node");
    let (kind, value) = object.iter().next().expect("one entry");
    match kind.as_str() {
        "leaf" | "empty_seq" | "empty_map" => json!(kind),
        "seq" => json!({
            "seq": value.as_array().expect("a list").iter().map(without_order_terms).collect::<Vec<_>>()
        }),
        "map" => json!({
            "map": value
                .as_array()
                .expect("a list")
                .iter()
                .map(|pair| {
                    if is_order_term(pair) {
                        json!([pair[0], "order term"])
                    } else {
                        json!([pair[0], without_order_terms(&pair[1])])
                    }
                })
                .collect::<Vec<_>>()
        }),
        _ => json.clone(),
    }
}

/// Copy every order term of `resealed` over the one in the same place in
/// `stored`. The two have the same shape, which the caller has asserted.
fn refreeze_order_terms(stored: &mut Json, resealed: &Json) {
    let Some(object) = stored.as_object_mut() else {
        return;
    };
    let (kind, value) = object.iter_mut().next().expect("one entry");
    let key = kind.clone();
    let theirs = &resealed[key.as_str()];
    match key.as_str() {
        "seq" => {
            for (index, node) in value.as_array_mut().expect("a list").iter_mut().enumerate() {
                refreeze_order_terms(node, &theirs[index]);
            }
        }
        "map" => {
            for (index, pair) in value.as_array_mut().expect("a list").iter_mut().enumerate() {
                if is_order_term(pair) {
                    pair[1] = theirs[index][1].clone();
                } else {
                    refreeze_order_terms(&mut pair[1], &theirs[index][1]);
                }
            }
        }
        _ => {}
    }
}

// ---- a plan as JSON ---------------------------------------------------------

/// A plan written as JSON, as frame bytes: what a binding sends.
fn frame_of_json(value: &Json) -> Vec<u8> {
    vitaminc_aead_frame::serde::to_vec(value).expect("frames")
}

fn plan_of(json: &Json) -> DataPlan {
    record::plan(&frame_of_json(json)).expect("the frozen plan parses")
}

// ---- sealing and opening ----------------------------------------------------

async fn seal(
    cipher: &StackCipher<DeterministicSource>,
    source: &[u8],
    plan: &DataPlan,
) -> StackCipherText {
    let source = ValueFrame::from_bytes(source).expect("the source is a value");
    record::encrypt(&cipher.default_keyset(), source, plan)
        .expect("the source fits the plan")
        .await
        .expect("the record seals")
}

async fn open(
    cipher: &StackCipher<DeterministicSource>,
    stored: StackCipherText,
    plan: &DataPlan,
    expected: Option<Label>,
) -> Vec<u8> {
    record::decrypt(Scope::Client(cipher), stored, plan, expected)
        .expect("the stored record fits the plan")
        .await
        .expect("the stored record opens")
        .risky_ref()
        .to_vec()
}

fn expected_of(case: &Json) -> Option<Label> {
    case["expected_context"]
        .as_str()
        .map(|text| Label::parse(text).expect("a label"))
}

// ---- the check --------------------------------------------------------------

/// Every frozen row opens to exactly the frame it opened to when it was
/// written, and sealing its source again today gives the same tree: the
/// same shape and keys, the same terms, the same passthroughs.
///
/// With `STACK_ENCRYPT_REFREEZE_ORDER_TERMS=1` it instead re-freezes the
/// `ore` and `ope` terms that moved, the one edit the README allows, after
/// asserting that nothing else did: every row still opens as it did, and
/// the resealed tree matches the stored one in everything but its order
/// terms' bytes.
#[tokio::test]
async fn every_frozen_row_opens_and_seals_as_it_did() {
    let refreeze = std::env::var("STACK_ENCRYPT_REFREEZE_ORDER_TERMS").is_ok_and(|v| v == "1");
    let text = std::fs::read_to_string(fixture_path()).expect("stored_rows_v1.json is committed");
    let mut fixture: Json = serde_json::from_str(&text).expect("the fixture is JSON");
    assert_eq!(fixture["key_source"]["kind"], json!("deterministic-sha256"));
    assert_eq!(fixture["key_source"]["seed"], json!(hex(&SEED)));
    let cipher = deterministic_cipher(SEED).await;
    assert_eq!(
        fixture["keyset_id"],
        json!(cipher.default_keyset().keyset_id().to_string()),
        "the deterministic source names the keyset it named"
    );

    let cases = fixture["cases"].as_array_mut().expect("a list of cases");
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().expect("a name");
        let plan = plan_of(&case["plan"]);
        let source = unhex(case["source"].as_str().expect("hex"));
        let stored = &case["stored"];

        let opened = open(&cipher, node_of_json(stored), &plan, expected_of(case)).await;
        assert_eq!(
            hex(&opened),
            case["opened"].as_str().expect("hex"),
            "{name}: the frozen row opens to what it opened to"
        );

        let resealed = json_of_node(seal(&cipher, &source, &plan).await);
        assert_eq!(
            without_order_terms(&resealed),
            without_order_terms(stored),
            "{name}: sealing the source today stores the same shape, terms and passthroughs"
        );
        if refreeze {
            refreeze_order_terms(&mut case["stored"], &resealed);
        } else {
            assert_eq!(
                skeleton(&resealed),
                skeleton(stored),
                "{name}: only ORE or OPE terms moved. If that is deliberate, re-freeze them \
                 with STACK_ENCRYPT_REFREEZE_ORDER_TERMS=1 and say so in the CHANGELOG \
                 (tests/fixtures/README.md)"
            );
        }
    }
    if refreeze {
        let mut text = serde_json::to_string_pretty(&fixture).expect("serialise");
        text.push('\n');
        std::fs::write(fixture_path(), text).expect("write the fixture");
    }
}

// ---- writing the fixture, once ----------------------------------------------

/// One frozen case: a plan, its source, and the context `decrypt` is told
/// to expect.
struct Case {
    name: &'static str,
    about: &'static str,
    plan: Json,
    source: Vec<u8>,
    expected_context: Option<&'static str>,
}

/// Write one value into `sink`.
#[derive(Clone)]
enum Value {
    Scalar(Option<Logical>, Scalar),
    Seq(Vec<Value>),
    Map(Vec<(&'static str, Value)>),
}

#[derive(Clone)]
enum Scalar {
    Null,
    Bool(bool),
    Int(Int),
    Float(Float),
    Text(&'static str),
    Bytes(&'static [u8]),
}

impl Value {
    fn write<S: Sink>(&self, sink: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Scalar(ty, scalar) => {
                let physical = match scalar {
                    Scalar::Null => Physical::Null,
                    Scalar::Bool(b) => Physical::Bool(*b),
                    Scalar::Int(i) => Physical::Int(*i),
                    Scalar::Float(f) => Physical::Float(*f),
                    Scalar::Text(t) => Physical::Text(t),
                    Scalar::Bytes(b) => Physical::Bytes(b),
                };
                sink.scalar(*ty, physical)
            }
            Value::Seq(items) => {
                let mut seq = sink.seq(Some(items.len()))?;
                for item in items {
                    item.write(seq.element()?)?;
                }
                seq.end()
            }
            Value::Map(entries) => {
                let mut map = sink.map(Some(entries.len()))?;
                for (key, value) in entries {
                    value.write(map.entry(key)?)?;
                }
                map.end()
            }
        }
    }

    fn frame(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.write(FrameWriter::new(&mut bytes)).expect("frames");
        bytes
    }
}

fn int(i: Int) -> Value {
    Value::Scalar(None, Scalar::Int(i))
}

fn text(t: &'static str) -> Value {
    Value::Scalar(None, Scalar::Text(t))
}

/// 2026-10-17T01:02:03.123456789Z, in nanoseconds since the epoch.
const AT: i128 = 1_792_198_923_123_456_789;

/// One field per value kind, with every index its kind admits today (each
/// kind that admits OPE has a twin field holding only that term), a
/// composite field of each shape, an untyped field, a field whose key is not
/// its label's last segment, and a passthrough.
fn every_kind() -> (Json, Value) {
    use vitaminc_aead::plaintext::TimeUnit;
    let ts = Logical::Timestamp(TimeUnit::Nanos);
    #[rustfmt::skip]
    let fields: Vec<(&'static str, &'static str, &'static [&'static str], Value)> = vec![
        ("flag",    "bool",      &["c", "eq", "ore"],        Value::Scalar(None, Scalar::Bool(true))),
        ("i8",      "int8",      &["c", "eq", "ore"],        int(Int::I8(-8))),
        ("i16",     "int16",     &["c", "eq", "ore"],        int(Int::I16(-300))),
        ("i32",     "int32",     &["c", "eq", "ore"],        int(Int::I32(-70_000))),
        ("i64",     "int64",     &["c", "eq", "ore"],        int(Int::I64(-5_000_000_000))),
        ("i128",    "int128",    &["c", "eq", "ore"],        int(Int::I128(i128::MIN))),
        ("u8",      "uint8",     &["c", "eq", "ore"],        int(Int::U8(200))),
        ("u16",     "uint16",    &["c", "eq", "ore"],        int(Int::U16(60_000))),
        ("u32",     "uint32",    &["c", "eq", "ore"],        int(Int::U32(4_000_000_000))),
        ("u64",     "uint64",    &["c", "eq", "ore"],        int(Int::U64(u64::MAX))),
        ("u128",    "uint128",   &["c", "eq", "ore"],        int(Int::U128(u128::MAX))),
        ("f32",     "float32",   &["c", "eq", "ore"],        Value::Scalar(None, Scalar::Float(Float::F32(-0.0)))),
        ("f64",     "float64",   &["c", "eq", "ore"],        Value::Scalar(None, Scalar::Float(Float::F64(2.25)))),
        ("amount",  "decimal",   &["c", "eq", "ore"],               Value::Scalar(Some(Logical::Decimal { scale: 4 }), Scalar::Int(Int::I128(-12_345_600)))),
        ("day",     "date",      &["c", "eq", "ore"],               Value::Scalar(Some(Logical::Date), Scalar::Int(Int::I32(19_782)))),
        ("at",      "timestamp", &["c", "eq", "ore"],               Value::Scalar(Some(ts), Scalar::Int(Int::I128(AT)))),
        ("email",   "string",    &["c", "eq", "match", "ore"], text("Alice.Smith@example.com")),
        ("bio",     "string",    &["c", "match_custom"],     text("Encrypted search over short notes")),
        ("blob",    "bytes",     &["c", "eq", "match", "ore"],               Value::Scalar(None, Scalar::Bytes(&[0x00, 0x01, 0xfe, 0xff]))),
        ("tags",    "array",     &["c"],                     Value::Seq(vec![text("a"), int(Int::I32(1)), Value::Seq(vec![])])),
        ("prefs",   "object",    &["c"],                     Value::Map(vec![("dark", Value::Scalar(None, Scalar::Bool(true))), ("none", Value::Scalar(None, Scalar::Null)), ("empty", Value::Map(vec![]))])),
        ("loose",   "",          &["c"],                     text("a field with no type")),
        ("mail",    "string",    &["c", "eq"],               text("bob@example.com")),
        ("id",      "uint32",    &["passthrough"],           int(Int::U32(42))),
    ];
    // A field offered ORE whose kind admits OPE gets a twin field holding
    // only its OPE term: ORE and OPE are stored on separate fields.
    let fields = fields.into_iter().flat_map(|(field, ty, outputs, value)| {
        let ope = outputs.contains(&"ore")
            && admits(ty.parse::<ValueKind>().expect("a kind"), &IndexSpec::Ope);
        let twin = ope.then(|| {
            let name: &'static str = Box::leak(format!("{field}_ope").into_boxed_str());
            (name, ty, &["ope"][..], value.clone())
        });
        std::iter::once((field, ty, outputs, value)).chain(twin)
    });
    let mut plan = Map::new();
    let mut source = Vec::new();
    for (field, ty, outputs, value) in fields {
        // "mail" is stored under the column "email_address": a field's key
        // need not be its label's last segment.
        let column = if field == "mail" {
            "email_address"
        } else {
            field
        };
        // Keep only what the kind admits today, so the table can offer every
        // index to every kind.
        let kind = (!ty.is_empty()).then(|| ty.parse::<ValueKind>().expect("a kind"));
        let admitted = |index: &IndexSpec| kind.is_none_or(|kind| admits(kind, index));
        let outputs: Vec<Json> = outputs
            .iter()
            .filter(|output| match **output {
                "eq" => admitted(&IndexSpec::Equality),
                "ore" => admitted(&IndexSpec::Ore),
                "ope" => admitted(&IndexSpec::Ope),
                "match" | "match_custom" => admitted(&IndexSpec::Match(Default::default())),
                _ => true,
            })
            .map(|output| match *output {
                "match_custom" => json!({ "match": { "tokenizer": "standard", "downcase": false, "k": 6, "m": 1024 } }),
                other => json!(other),
            })
            .collect();
        if outputs.is_empty() {
            continue;
        }
        let mut spec = Map::new();
        let _ = spec.insert("context".into(), json!(["kinds", column]));
        let _ = spec.insert("outputs".into(), Json::Array(outputs));
        if !ty.is_empty() {
            let _ = spec.insert("type".into(), json!(ty));
        }
        let _ = plan.insert(field.into(), Json::Object(spec));
        source.push((field, value));
    }
    (Json::Object(plan), Value::Map(source))
}

fn cases() -> Vec<Case> {
    let (kinds_plan, kinds_source) = every_kind();
    let user = |age: u32, email: &'static str| {
        Value::Map(vec![("age", int(Int::U32(age))), ("email", text(email))])
    };
    let user_plan = |age: Json, email: Json| {
        json!({
            "age":   { "context": age,   "outputs": ["c", "eq", "ore"], "type": "uint32" },
            "email": { "context": email, "outputs": ["c", "eq", "match"], "type": "string" },
        })
    };
    vec![
        Case {
            name: "every_kind",
            about: "one field per value kind with every index it admits, composites, an untyped field, a renamed field and a passthrough",
            plan: kinds_plan,
            source: kinds_source.frame(),
            expected_context: None,
        },
        Case {
            name: "three_segment_label",
            about: "labels of three segments: the plan's context is the first two",
            plan: json!({
                "title": { "context": ["documents", "v2", "title"], "outputs": ["c", "eq"], "type": "string" },
                "body":  { "context": ["documents", "v2", "body"],  "outputs": ["c", "match"], "type": "string" },
            }),
            source: Value::Map(vec![
                ("title", text("Quarterly report")),
                ("body", text("Revenue grew in every region")),
            ])
            .frame(),
            expected_context: None,
        },
        Case {
            name: "one_extension_part",
            about: "every label extended by one integer part, as a tenant id",
            plan: user_plan(json!([["users", "age"], 7]), json!([["users", "email"], 7])),
            source: user(34, "carol@example.com").frame(),
            expected_context: None,
        },
        Case {
            name: "two_extension_parts",
            about: "every label extended by an integer part and then a text part",
            plan: user_plan(
                json!([[["users", "age"], 7], "eu"]),
                json!([[["users", "email"], 7], "eu"]),
            ),
            source: user(35, "dave@example.com").frame(),
            expected_context: None,
        },
        Case {
            name: "context_field",
            about: "a plan whose context is the record's tenant field, opened expecting that tenant",
            plan: json!({
                "context_field": "tenant",
                "tenant": { "context": ["tenant"], "outputs": ["passthrough"], "type": "string" },
                "email":  { "context": ["email"],  "outputs": ["c", "eq"], "type": "string" },
                "age":    { "context": ["age"],    "outputs": ["c", "ore"], "type": "uint32" },
            }),
            source: Value::Map(vec![
                ("tenant", text("tenants/acme")),
                ("email", text("erin@acme.example")),
                ("age", int(Int::U32(41))),
            ])
            .frame(),
            expected_context: Some("tenants/acme"),
        },
        Case {
            name: "batch",
            about: "a batch of two records under one plan",
            plan: user_plan(json!(["users", "age"]), json!(["users", "email"])),
            source: Value::Seq(vec![user(29, "frank@example.com"), user(52, "grace@example.com")])
                .frame(),
            expected_context: None,
        },
    ]
}

/// Write `stored_rows_v1.json`, once. Ignored, so no test run writes it,
/// and refusing when the file exists, so no run rewrites it. Run with
/// `cargo test -p stack-encrypt --all-features --test stored_rows -- --ignored`
/// only to create the file for the first time.
#[tokio::test]
#[ignore = "writes stored_rows_v1.json once; the file is frozen and never regenerated"]
async fn write_stored_rows_v1() {
    let path = fixture_path();
    assert!(
        !path.exists(),
        "{} is frozen: it records rows an earlier build stored, and is never regenerated. \
         A change to the stored format adds stored_rows_v2.json beside it; order terms are \
         re-frozen by the check itself (tests/fixtures/README.md).",
        path.display()
    );
    let cipher = deterministic_cipher(SEED).await;
    let mut written = Vec::new();
    for case in cases() {
        let plan = plan_of(&case.plan);
        let stored = seal(&cipher, &case.source, &plan).await;
        let stored_json = json_of_node(stored);
        let expected = case
            .expected_context
            .map(|text| Label::parse(text).expect("a label"));
        let opened = open(&cipher, node_of_json(&stored_json), &plan, expected).await;
        written.push(json!({
            "name": case.name,
            "about": case.about,
            "plan": case.plan,
            "source": hex(&case.source),
            "expected_context": case.expected_context,
            "stored": stored_json,
            "opened": hex(&opened),
        }));
    }
    let fixture = json!({
        "_comment": "FROZEN. Records the next build stored, under a deterministic key source. Every later build must open each one to `opened` and seal its `source` to the same shape, terms and passthroughs. Read by tests/stored_rows.rs; the schema is in README.md beside this file. Never regenerate this file, and edit it only as README.md allows for order terms: a change to the stored format adds stored_rows_v2.json beside it.",
        "key_source": { "kind": "deterministic-sha256", "seed": hex(&SEED) },
        "keyset_id": cipher.default_keyset().keyset_id().to_string(),
        "cases": written,
    });
    let mut text = serde_json::to_string_pretty(&fixture).expect("serialise");
    text.push('\n');
    std::fs::write(&path, text).expect("write the fixture");
}
