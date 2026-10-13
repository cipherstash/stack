//! The Rust side of the byte-parity test (`tests/test_bytes.py`).
//!
//! Python never encrypts. Both sides of that test run ONE engine; what
//! differs is everything in front of it. This binary is "the engine with
//! nothing in front of it": the same data plan the Python test declares,
//! written here as an `FfiValue` literal, through the same
//! `dynamic::record` entry points and the same [`tree`] walk the lib uses.
//! If the shell drifts from the engine's grammar — a value tagged the wrong
//! width, a plan missing its `"type"`, a tree rebuilt wrongly — this is what
//! the shell's output stops agreeing with.
//!
//! It runs AT TEST TIME, under the same credentials as the Python side, so
//! nothing keyed to a workspace keyset is ever committed.
//!
//! Two modes, JSON on stdout:
//!
//! - `seal`  → `{"plan", "plaintext", "record", "term"}`; the record's EQL
//!   bytes and the term are base64.
//! - `open`  ← a record in that shape on stdin → the plaintext.

use std::io::Read;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::{json, Value};
use stack_encrypt::dynamic::record::{self, Plan};
use stack_encrypt::dynamic::{FfiValue, Scope};
use stack_encrypt::{CipherText, StackCipher};
use vitaminc_protected::Controlled;

// `#[path]` includes the lib's files verbatim, so the one resolver and the
// one tree walk serve both sides. `targets.rs` also carries `select` and
// `named` for the lib's plan resolution, which this bin never calls; that
// is the whole of the dead code allowed here.
#[allow(dead_code)]
#[path = "../targets.rs"]
mod targets;
#[path = "../tree.rs"]
mod tree;

// `targets.rs` carries the pyo3 `PlanError` conversions for the lib; the
// bin only needs the resolver, so the pyo3 surface is stubbed here rather
// than linking the interpreter into a command-line tool.
mod errors {
    pyo3::create_exception!(_parity, PlanError, pyo3::exceptions::PyException);
}

const EMAIL: &str = "parity@example.com";
const AGE: i64 = 41;

/// The plan, as the Python test's `_declare` writes it after `build()` has
/// resolved the target: `"target": "TextEq"` and `"type"` on both fields.
fn plan_value() -> FfiValue {
    let s = |v: &str| FfiValue::String(v.to_owned().into());
    FfiValue::Object(vec![
        (
            "email".into(),
            FfiValue::Object(vec![
                (
                    "context".into(),
                    FfiValue::Array(vec![s("users"), s("email")]),
                ),
                ("target".into(), s("TextEq")),
                ("type".into(), s("string")),
            ]),
        ),
        (
            "age".into(),
            FfiValue::Object(vec![
                (
                    "context".into(),
                    FfiValue::Array(vec![s("users"), s("age")]),
                ),
                ("outputs".into(), FfiValue::Array(vec![s("passthrough")])),
                ("type".into(), s("int64")),
            ]),
        ),
    ])
}

/// The same plan as the Python dict `PlanSpec.fields` holds, for the test's
/// "both sides build the same plan" assertion.
fn plan_json() -> Value {
    json!({
        "email": {"context": ["users", "email"], "target": "TextEq", "type": "string"},
        "age": {"context": ["users", "age"], "outputs": ["passthrough"], "type": "int64"},
    })
}

fn plan() -> Plan {
    record::plan_with(plan_value(), &targets::Resolver).expect("the parity plan parses")
}

#[tokio::main]
async fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let cipher = StackCipher::new().await.expect("credentials resolve");
    let plan = plan();
    match mode.as_str() {
        "seal" => seal(&cipher, &plan).await,
        "open" => open(&cipher, &plan).await,
        other => {
            eprintln!("parity: unknown mode {other:?}; use seal or open");
            std::process::exit(2);
        }
    }
}

async fn seal<K>(cipher: &StackCipher<K>, plan: &Plan)
where
    K: stack_encrypt::kms::DataKeySource + Send + Sync + 'static,
{
    let row = FfiValue::Object(vec![
        ("email".into(), FfiValue::String(EMAIL.to_owned().into())),
        ("age".into(), FfiValue::Int64(AGE)),
    ]);
    let keyset = cipher.default_keyset();
    let sealed = record::encrypt_with(
        &keyset,
        FfiValue::Array(vec![row]),
        plan,
        &targets::Resolver,
    )
    .expect("the row fits the plan")
    .await
    .expect("seal");
    let mut rows = tree::rows_of(sealed).expect("a batch of one");
    let columns = tree::stored_row(rows.remove(0), plan).expect("column values");

    let term = record::query(
        &keyset,
        plan,
        "email",
        FfiValue::String(EMAIL.to_owned().into()),
        &targets::Resolver,
    )
    .expect("a query for email")
    .await
    .expect("term");

    let mut record = serde_json::Map::new();
    for (name, value) in columns {
        record.insert(name, column_json(value));
    }
    println!(
        "{}",
        json!({
            "plan": plan_json(),
            "plaintext": {"email": EMAIL, "age": AGE},
            "record": Value::Object(record),
            "term": BASE64.encode(term),
        })
    );
}

async fn open<K>(cipher: &StackCipher<K>, plan: &Plan)
where
    K: stack_encrypt::kms::DataKeySource + Send + Sync + 'static,
{
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("a record on stdin");
    let wire: serde_json::Map<String, Value> = serde_json::from_str(&input).expect("a JSON object");
    let values = wire
        .into_iter()
        .map(|(name, value)| {
            let value = match value {
                Value::String(b64) => FfiValue::Bytes(BASE64.decode(b64).expect("base64").into()),
                Value::Number(n) => FfiValue::Int64(n.as_i64().expect("an int64")),
                other => panic!("{name}: unexpected column value {other}"),
            };
            (name, value)
        })
        .collect();
    let tree = tree::record_tree(values, plan).expect("the record fits the plan");
    let opened = record::decrypt_with(
        Scope::Keyset(cipher.default_keyset()),
        CipherText::Sequence(vec![tree]),
        plan,
        None,
        &targets::Resolver,
    )
    .expect("the tree fits the plan")
    .await
    .expect("open");
    let FfiValue::Array(mut rows) = opened else {
        panic!("a batch opens to a list")
    };
    let FfiValue::Object(fields) = rows.remove(0) else {
        panic!("a row opens to an object")
    };
    let mut out = serde_json::Map::new();
    for (name, value) in fields {
        out.insert(name, column_json(value));
    }
    println!("{}", Value::Object(out));
}

/// A column value as the JSON the test exchanges: bytes as base64, an
/// integer as a number, text as a string.
fn column_json(value: FfiValue) -> Value {
    match value {
        FfiValue::Bytes(b) => Value::String(BASE64.encode(b.risky_ref())),
        FfiValue::Int64(i) => json!(i),
        FfiValue::String(s) => {
            Value::String(String::from_utf8(s.risky_ref().to_vec()).expect("utf-8"))
        }
        other => panic!("unexpected column value kind {:?}", other.kind()),
    }
}
