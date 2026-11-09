//! A stdin/stdout EQL v4 codec over live ZeroKMS, for migration tests in other
//! languages.
//!
//! TypeScript cannot produce EQL v4 yet: the only v4 producer is Stack
//! Encrypt, reached from Rust and Go. The live migration suite in
//! `languages/typescript/packages/protect-ffi/integration-tests` (EQL v2 and
//! v3 to v4) decrypts legacy rows with protect-ffi and hands the plaintexts
//! here to re-encrypt them as v4. Every value goes through
//! `eql_bindings::encryption::targets`, the by-name dispatch the Go guest
//! uses, so the payloads are the ones a v4 SDK writes.
//!
//! Run from `packages/eql`:
//!
//! ```sh
//! cargo build --locked -p eql-encryption-tests --example v4_codec
//! echo '{"encrypt":[{"type":"TextEq","table":"users","column":"email","value":"a@b.c"}]}' \
//!   | target/debug/examples/v4_codec
//! ```
//!
//! Credentials come from the environment (`CS_CLIENT_ACCESS_KEY`,
//! `CS_WORKSPACE_CRN`, `CS_CLIENT_ID`, `CS_CLIENT_KEY`) or the CLI profile, the
//! same way `StackCipher::new()` finds them everywhere else.
//!
//! The request is one JSON object with three optional lists:
//!
//! ```json
//! {
//!   "encrypt": [{ "type": "TextEq", "table": "t", "column": "c", "value": "x" }],
//!   "query":   [{ "type": "IntegerOrd", "table": "t", "column": "c", "value": 7 },
//!               { "type": "TextSearch", "table": "t", "column": "c", "value": "x", "index": "match" }],
//!   "decrypt": [{ "type": "TextEq", "table": "t", "column": "c", "payload": { … } }]
//! }
//! ```
//!
//! The response has the same three keys, each a list in request order:
//! stored payloads, query operands (bind as the target's `query_sql_domain`)
//! and decrypted plaintexts. `type` is a target name from
//! `eql_bindings::encryption::targets::targets()`. A query goes through one of
//! the target's indexes. A target with one index uses it. A target with several
//! (`TextOrdOre`, `TextOrd`, `TextOrdOpe`, `TextSearchOre`, `TextSearch`) needs
//! `index`, one of its `Target::indexes` keys, because `TextSearch` and
//! `TextSearchOre` operands carry that index's term alone: the codec does not
//! guess, and a request naming none is refused with the valid keys.
//! Plaintexts are JSON strings, booleans and numbers; the target's
//! `plaintext` kind decides how a number is read. The `float32` kind (`Real*`)
//! is refused: no caller needs it, and narrowing a JSON number would seal an
//! out-of-range value as infinity without an error.

use std::io::{Read, Write};

use eql_bindings::encryption::targets::{self, Opener};
use serde::Deserialize;
use serde_json::{json, Value};
use stack_encrypt::dynamic::ValueFrame;
use stack_encrypt::target::{IndexSpec, Pending};
use stack_encrypt::{Decrypt, Encrypt, KeysetCipher, Label, StackCipher};
use stack_kms::{DataKeySource, IndexKeySource};

type Error = Box<dyn std::error::Error>;

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(default)]
    encrypt: Vec<Item>,
    #[serde(default)]
    query: Vec<Item>,
    #[serde(default)]
    decrypt: Vec<Stored>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Item {
    r#type: String,
    table: String,
    column: String,
    value: Value,
    /// The index a query goes through, by key. Read for `query` items only.
    #[serde(default)]
    index: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    r#type: String,
    table: String,
    column: String,
    payload: Value,
}

/// The target's plaintext kind, e.g. `"int32"`, or an error naming the type.
fn plaintext_kind(name: &str) -> Result<&'static str, Error> {
    let target = targets::target(name).ok_or_else(|| format!("no EQL v4 target named {name}"))?;
    target
        .plaintext
        .ok_or_else(|| format!("{name} has no scalar plaintext kind").into())
}

fn label(table: &str, column: &str) -> Result<Label, Error> {
    Ok(Label::new([table, column])?)
}

/// A JSON value's type, for an error that must not repeat the value.
fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// A JSON plaintext as the engine's runtime frame, read as `name`'s kind.
fn frame(name: &str, value: &Value) -> Result<ValueFrame, Error> {
    let kind = plaintext_kind(name)?;
    let wrong = || {
        format!(
            "{name} takes a {kind} plaintext, not a JSON {}",
            json_type(value)
        )
    };
    let frame = match kind {
        "string" => ValueFrame::of(value.as_str().ok_or_else(wrong)?.to_owned()),
        "boolean" | "bool" => ValueFrame::of(value.as_bool().ok_or_else(wrong)?),
        "int16" => ValueFrame::of(i16::try_from(value.as_i64().ok_or_else(wrong)?)?),
        "int32" => ValueFrame::of(i32::try_from(value.as_i64().ok_or_else(wrong)?)?),
        "int64" => ValueFrame::of(value.as_i64().ok_or_else(wrong)?),
        "float64" => ValueFrame::of(value.as_f64().ok_or_else(wrong)?),
        other => {
            return Err(format!("{name}: plaintext kind {other} is not supported here").into())
        }
    };
    Ok(frame?)
}

/// An opened frame as JSON, read as `name`'s kind.
fn plaintext(name: &str, opened: ValueFrame) -> Result<Value, Error> {
    let kind = plaintext_kind(name)?;
    let value = match kind {
        "string" => json!(opened.visit(String::sink())?),
        "boolean" | "bool" => json!(opened.visit(bool::sink())?),
        "int16" => json!(opened.visit(i16::sink())?),
        "int32" => json!(opened.visit(i32::sink())?),
        "int64" => json!(opened.visit(i64::sink())?),
        "float64" => json!(opened.visit(f64::sink())?),
        other => {
            return Err(format!("{name}: plaintext kind {other} is not supported here").into())
        }
    };
    Ok(value)
}

/// The index a query on `name` goes through: the one `requested` names, or
/// the target's only index. Refuses, naming the valid keys, rather than pick
/// one of several.
fn query_index(name: &str, requested: Option<&str>) -> Result<IndexSpec, Error> {
    let target = targets::target(name).ok_or_else(|| format!("no EQL v4 target named {name}"))?;
    let valid = target.indexes.join(", ");
    let key = match (requested, target.indexes) {
        (_, []) => return Err(format!("{name} is storage-only and answers no query").into()),
        (Some(key), indexes) if indexes.contains(&key) => key,
        (Some(key), _) => {
            return Err(format!("{name} carries no {key} index; its indexes are: {valid}").into())
        }
        (None, [only]) => *only,
        (None, _) => return Err(format!("{name} has several indexes; name one of: {valid}").into()),
    };
    IndexSpec::parse(key).ok_or_else(|| format!("{name}: index {key} is not recognised").into())
}

/// The stored payload for each item, in order. One ZeroKMS call for the
/// whole list; one bad item fails it.
async fn encrypt_all<K>(keyset: &KeysetCipher<'_, K>, items: &[Item]) -> Result<Vec<Value>, Error>
where
    K: DataKeySource + IndexKeySource + Sync + 'static,
{
    let pending = items
        .iter()
        .map(|item| {
            Ok(targets::encrypt(
                &item.r#type,
                keyset,
                &label(&item.table, &item.column)?,
                frame(&item.r#type, &item.value)?,
            )?)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Pending::all(keyset, pending)
        .await?
        .iter()
        .map(|bytes| Ok(serde_json::from_slice::<Value>(bytes)?))
        .collect()
}

/// The plaintext of each stored item, in order. One ZeroKMS call for the
/// whole list; one bad item fails it.
async fn decrypt_all<K>(cipher: &StackCipher<K>, items: &[Stored]) -> Result<Vec<Value>, Error>
where
    K: DataKeySource + IndexKeySource + Sync + 'static,
{
    let pending = items
        .iter()
        .map(|item| {
            let stored = serde_json::to_vec(&item.payload)?;
            Ok(targets::decrypt(
                &item.r#type,
                Opener::Client(cipher),
                &label(&item.table, &item.column)?,
                &stored,
            )?)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Pending::all(cipher, pending)
        .await?
        .into_iter()
        .zip(items)
        .map(|(opened, item)| plaintext(&item.r#type, opened))
        .collect()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let request: Request = serde_json::from_str(&input)?;

    let cipher = StackCipher::new().await?;
    let keyset = cipher.default_keyset();

    let encrypted = encrypt_all(&keyset, &request.encrypt).await?;

    let mut queries = Vec::with_capacity(request.query.len());
    for item in &request.query {
        let bytes = targets::query(
            &item.r#type,
            &query_index(&item.r#type, item.index.as_deref())?,
            &keyset,
            &label(&item.table, &item.column)?,
            frame(&item.r#type, &item.value)?,
        )?
        .await?;
        queries.push(serde_json::from_slice::<Value>(&bytes)?);
    }

    let decrypted = decrypt_all(&cipher, &request.decrypt).await?;

    let response = json!({ "encrypt": encrypted, "query": queries, "decrypt": decrypted });
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

// The call-counting fake KMS the integration tests use.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../tests/common/mod.rs"]
mod common;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn multi_index_targets() -> Vec<&'static targets::Target> {
        targets::targets()
            .iter()
            .filter(|target| target.indexes.len() > 1)
            .collect()
    }

    mod given_a_plaintext_of_the_wrong_kind {
        use super::*;

        fn refusal(name: &str, value: &Value) -> String {
            match frame(name, value) {
                Ok(_) => panic!("{name} should refuse a plaintext of the wrong kind"),
                Err(error) => error.to_string(),
            }
        }

        #[test]
        fn reports_the_json_type_and_never_the_value() {
            let cases = [
                ("TextEq", json!(12345), "12345", "number"),
                ("IntegerEq", json!("alice@b.c"), "alice@b.c", "string"),
                ("IntegerEq", json!(1.5), "1.5", "number"),
                ("Boolean", json!("secret-flag"), "secret-flag", "string"),
                ("TextEq", json!({ "ssn": "078-05" }), "078-05", "object"),
            ];
            for (name, value, plaintext, json_type) in cases {
                let message = refusal(name, &value);
                assert!(
                    !message.contains(plaintext),
                    "{name}'s refusal should not repeat the plaintext, got: {message}"
                );
                assert!(
                    message.contains(json_type),
                    "{name}'s refusal should name the JSON type {json_type}, got: {message}"
                );
            }
        }
    }

    mod given_a_target_with_several_indexes {
        use super::*;

        mod and_no_index_named {
            use super::*;

            #[test]
            fn refuses_and_lists_the_valid_keys() {
                let targets = multi_index_targets();
                assert!(!targets.is_empty(), "the table should have such targets");
                for target in targets {
                    match query_index(target.name, None) {
                        Ok(spec) => panic!(
                            "{} should not guess among {:?}, chose {spec:?}",
                            target.name, target.indexes
                        ),
                        Err(error) => {
                            let message = error.to_string();
                            for key in target.indexes {
                                assert!(
                                    message.contains(key),
                                    "{}'s refusal should name {key}, got: {message}",
                                    target.name
                                );
                            }
                        }
                    }
                }
            }
        }

        mod and_an_index_named {
            use super::*;

            #[test]
            fn selects_that_index_on_every_target_that_carries_it() {
                for target in multi_index_targets() {
                    for key in target.indexes {
                        let selected = query_index(target.name, Some(key)).unwrap();
                        assert_eq!(
                            selected,
                            IndexSpec::parse(key).unwrap(),
                            "{} queried through {key}",
                            target.name
                        );
                    }
                }
            }
        }
    }

    mod given_an_index_the_target_does_not_carry {
        use super::*;

        #[test]
        fn refuses_and_lists_the_valid_keys() {
            match query_index("TextEq", Some("ore_block")) {
                Ok(spec) => panic!("TextEq carries no ore_block index, chose {spec:?}"),
                Err(error) => {
                    let message = error.to_string();
                    assert!(
                        message.contains("ore_block") && message.contains("eq"),
                        "the refusal should name the key and the valid keys, got: {message}"
                    );
                }
            }
        }
    }

    // The requests `integration-tests/tests/v4-codec.ts` sends today name no
    // index, so a target with one index must not start needing it.
    mod given_a_target_with_one_index_and_no_index_named {
        use super::*;

        #[test]
        fn uses_that_index() {
            for target in targets::targets().iter().filter(|t| t.indexes.len() == 1) {
                let selected = query_index(target.name, None).unwrap();
                assert_eq!(
                    selected,
                    IndexSpec::parse(target.indexes[0]).unwrap(),
                    "{}'s only index",
                    target.name
                );
            }
        }
    }

    mod given_a_request_of_many_items {
        use super::*;

        #[tokio::test]
        async fn batches_each_direction_into_one_kms_call_and_keeps_the_order() {
            let (cipher, calls) = common::cipher().await;
            let keyset = cipher.default_keyset();
            let plaintexts: Vec<String> = (0..25).map(|n| format!("value-{n}")).collect();
            let items: Vec<Item> = plaintexts
                .iter()
                .enumerate()
                .map(|(n, value)| Item {
                    r#type: "TextEq".to_string(),
                    table: "t".to_string(),
                    column: format!("c{}", n % 5),
                    value: json!(value),
                    index: None,
                })
                .collect();

            let encrypted = encrypt_all(&keyset, &items).await.unwrap();
            let generate_calls = calls.lock().unwrap().generate.len();
            assert_eq!(generate_calls, 1, "25 values should be one generate call");

            let stored: Vec<Stored> = encrypted
                .into_iter()
                .zip(&items)
                .map(|(payload, item)| Stored {
                    r#type: item.r#type.clone(),
                    table: item.table.clone(),
                    column: item.column.clone(),
                    payload,
                })
                .collect();
            let decrypted = decrypt_all(&cipher, &stored).await.unwrap();
            let retrieve_calls = calls.lock().unwrap().retrieve.len();
            assert_eq!(retrieve_calls, 1, "25 values should be one retrieve call");

            let expected: Vec<Value> = plaintexts.iter().map(|value| json!(value)).collect();
            assert_eq!(decrypted, expected, "output order should be request order");
        }
    }

    mod given_a_real_target {
        use super::*;

        const REAL_TARGETS: [&str; 5] = ["Real", "RealEq", "RealOrdOre", "RealOrd", "RealOrdOpe"];

        fn assert_refused_without_the_value(name: &str, message: &str) {
            assert!(
                message.contains("float32 is not supported"),
                "{name} should be refused as unsupported, got: {message}"
            );
            assert!(
                !message.contains("1.5"),
                "{name}'s refusal should not repeat the plaintext, got: {message}"
            );
        }

        #[test]
        fn refuses_a_plaintext_without_repeating_it() {
            for name in REAL_TARGETS {
                match frame(name, &json!(1.5)) {
                    Ok(_) => panic!("{name} should refuse a float32 plaintext"),
                    Err(error) => assert_refused_without_the_value(name, &error.to_string()),
                }
            }
        }

        #[test]
        fn refuses_an_opened_value_without_repeating_it() {
            for name in REAL_TARGETS {
                let opened = ValueFrame::of(1.5_f32).unwrap();
                match plaintext(name, opened) {
                    Ok(value) => panic!("{name} should refuse a float32 value, got: {value}"),
                    Err(error) => assert_refused_without_the_value(name, &error.to_string()),
                }
            }
        }
    }
}
