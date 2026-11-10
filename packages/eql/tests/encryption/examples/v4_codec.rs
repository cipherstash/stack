//! A stdin/stdout EQL v4 codec over live ZeroKMS, for migration tests in other
//! languages.
//!
//! TypeScript cannot produce EQL v4 yet: the only v4 producer is Stack
//! Encrypt, reached from Rust and Go. The live migration suites in
//! `languages/typescript/packages/protect-ffi/integration-tests` (EQL v2 and
//! v3 to v4) decrypt legacy rows with protect-ffi and hand the plaintexts here
//! to re-encrypt them as v4.
//!
//! Every value goes through Stack Encrypt's typed API, the one a Rust
//! application migrating its own data uses: a legacy value decrypts with the
//! column it was stored in, and [`Shim`] encrypts it as an EQL v4 type under
//! that column, through `Encryption::context_from`. The request names each
//! item's type as a string, and serde reads it into an enum variant, which
//! also types the plaintext. So a plaintext of the wrong kind and an unknown
//! type are both refused while the request is read, before any key is
//! requested.
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
//!   "query":   [{ "type": "IntegerOrdOre", "table": "t", "column": "c", "value": 7 }],
//!   "decrypt": [{ "type": "TextEq", "table": "t", "column": "c", "payload": { … } }]
//! }
//! ```
//!
//! The response has the same three keys, each a list in request order:
//! stored payloads, query operands (bind as the type's query domain, e.g.
//! `eql_v4.query_text_eq`) and decrypted plaintexts. Each list is one ZeroKMS
//! request, whatever mix of types it holds. `type` is one of the variants of
//! [`Encrypt`] (for `encrypt` and `decrypt`) or [`Query`] (for `query`): the
//! types the migration suites use, and no others. Adding one is a variant on
//! each enum.

use std::io::{Read, Write};

use eql_bindings::v4::boolean::Boolean;
use eql_bindings::v4::double::{DoubleOrdOre, DoubleOrdOreQuery};
use eql_bindings::v4::integer::{
    IntegerOrdOpe, IntegerOrdOpeQuery, IntegerOrdOre, IntegerOrdOreQuery,
};
use eql_bindings::v4::text::{
    TextEq, TextEqQuery, TextMatch, TextMatchQuery, TextOrdOre, TextOrdOreQuery,
};
use eql_bindings::Identifier;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use stack_encrypt::target::{
    AcceptsContext, DecryptSource, EncryptTarget, Encryption, NoCallerContext, Pending,
    RequiredContext, Zeroize,
};
use stack_encrypt::{DecryptFrom, EncryptInto, KeysetCipher, NonEmpty, StackCipher};
use stack_kms::{DataKeySource, IndexKeySource};

type Error = Box<dyn std::error::Error>;

/// A value decrypted from EQL v2 or v3, with the column it was stored in.
///
/// On the wire it is `{ "table", "column", "value" }`.
#[derive(Deserialize)]
#[serde(from = "Wire<P>", bound(deserialize = "P: Deserialize<'de>"))]
struct Legacy<P> {
    i: Identifier,
    p: P,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire<P> {
    table: String,
    column: String,
    value: P,
}

impl<P> From<Wire<P>> for Legacy<P> {
    fn from(wire: Wire<P>) -> Self {
        Legacy {
            i: Identifier {
                t: wire.table,
                c: wire.column,
            },
            p: wire.value,
        }
    }
}

impl<P: Zeroize> Zeroize for Legacy<P> {
    // The column is not secret: it is stored in the clear in `i`.
    fn zeroize(&mut self) {
        self.p.zeroize();
    }
}

/// An EQL v4 type, encrypted from a [`Legacy`] value under the column in the
/// value. One impl covers every v4 type whose context is its column, stored
/// types and query types alike. To rename a column, edit `i` before the call.
struct Shim<T>(T);

impl<P, T> EncryptTarget<Legacy<P>> for Shim<T>
where
    P: Zeroize,
    T: EncryptTarget<P, ContextInput = RequiredContext<NonEmpty<Identifier>>>,
{
    type ContextInput = NoCallerContext;
    fn encryption<'s, K: 'static>() -> Encryption<'s, Legacy<P>, Self, K, NoCallerContext>
    where
        Legacy<P>: 's,
    {
        T::encryption()
            .project(|source: &Legacy<P>| &source.p)
            .context_from(|source: &Legacy<P>| &source.i)
            .map(Shim)
    }
}

/// A stored EQL v4 payload to open, with the column it is read from.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored<T> {
    table: String,
    column: String,
    payload: T,
}

/// An item of `encrypt` or of `decrypt`, by EQL v4 type. Under `encrypt` the
/// variant types the plaintext; under `decrypt`, the stored payload, whose
/// shape the type then checks.
#[derive(Deserialize)]
#[serde(tag = "type")]
enum Encrypt {
    TextEq(Legacy<String>),
    TextMatch(Legacy<String>),
    TextOrdOre(Legacy<String>),
    IntegerOrdOre(Legacy<i32>),
    IntegerOrdOpe(Legacy<i32>),
    DoubleOrdOre(Legacy<f64>),
    Boolean(Legacy<bool>),
}

#[derive(Deserialize)]
#[serde(tag = "type")]
enum Decrypt {
    TextEq(Stored<TextEq>),
    TextMatch(Stored<TextMatch>),
    TextOrdOre(Stored<TextOrdOre>),
    IntegerOrdOre(Stored<IntegerOrdOre>),
    IntegerOrdOpe(Stored<IntegerOrdOpe>),
    DoubleOrdOre(Stored<DoubleOrdOre>),
    Boolean(Stored<Boolean>),
}

/// An item of `query`, by the EQL v4 type of the column it queries. A type
/// that answers no query, such as `Boolean`, has no variant.
#[derive(Deserialize)]
#[serde(tag = "type")]
enum Query {
    TextEq(Legacy<String>),
    TextMatch(Legacy<String>),
    TextOrdOre(Legacy<String>),
    IntegerOrdOre(Legacy<i32>),
    IntegerOrdOpe(Legacy<i32>),
    DoubleOrdOre(Legacy<f64>),
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Request {
    #[serde(default)]
    encrypt: Vec<Value>,
    #[serde(default)]
    query: Vec<Value>,
    #[serde(default)]
    decrypt: Vec<Value>,
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

/// Read one item of `list` into its enum. serde's message for a value of the
/// wrong kind quotes the value, and the value is a plaintext, so only the
/// messages that name nothing but fields and types (an unknown type, a
/// missing or unknown field) are passed on. Any other refusal names the
/// item's type and the JSON type of its value or payload.
fn item<T: DeserializeOwned>(list: &str, n: usize, value: Value) -> Result<T, Error> {
    let r#type = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("(no type)")
        .to_owned();
    let content = value
        .get("value")
        .or_else(|| value.get("payload"))
        .map_or("nothing", json_type);
    serde_json::from_value(value).map_err(|error| {
        let message = error.to_string();
        let names_only = ["unknown variant", "missing field", "unknown field"]
            .iter()
            .any(|safe| message.starts_with(safe));
        if names_only {
            format!("{list}[{n}]: {message}").into()
        } else {
            format!("{list}[{n}]: {type} cannot be read from a JSON {content}").into()
        }
    })
}

fn items<T: DeserializeOwned>(list: &str, values: Vec<Value>) -> Result<Vec<T>, Error> {
    values
        .into_iter()
        .enumerate()
        .map(|(n, value)| item(list, n, value))
        .collect()
}

fn to_json(value: &impl Serialize) -> Result<Value, stack_encrypt::Error> {
    serde_json::to_value(value).map_err(|error| stack_encrypt::Error::Other(error.into()))
}

/// Encrypt a legacy value as `T`, which is a stored type or a query type,
/// under the column the value carries.
fn seal<'a, P, T, K>(source: Legacy<P>, keyset: &'a KeysetCipher<'_, K>) -> Pending<'a, Value, K>
where
    P: Zeroize,
    T: EncryptTarget<P, ContextInput = RequiredContext<NonEmpty<Identifier>>> + Serialize,
    K: 'static,
{
    source
        .encrypt_into::<Shim<T>, _>(keyset)
        .try_map(|Shim(sealed)| to_json(&sealed))
}

/// Open a stored `T` as its plaintext `P`, under the column it is read from.
/// A payload stored under any other column is refused before any key is
/// requested.
fn open<'a, P, T, K>(
    stored: Stored<T>,
    keyset: &'a KeysetCipher<'_, K>,
) -> Result<Pending<'a, Value, K>, Error>
where
    P: Zeroize + Serialize + 'static,
    T: DecryptSource<P>,
    T::ContextInput: AcceptsContext,
    NonEmpty<Identifier>: Into<<T::ContextInput as AcceptsContext>::Value>,
    K: 'static,
{
    let column = Identifier::for_column(stored.table, stored.column)?;
    Ok(P::decrypt_from_with_context(stored.payload, keyset, column)
        .try_map(|opened| to_json(&opened)))
}

fn encrypt_one<'a, K: 'static>(
    item: Encrypt,
    keyset: &'a KeysetCipher<'_, K>,
) -> Pending<'a, Value, K> {
    match item {
        Encrypt::TextEq(v) => seal::<_, TextEq, _>(v, keyset),
        Encrypt::TextMatch(v) => seal::<_, TextMatch, _>(v, keyset),
        Encrypt::TextOrdOre(v) => seal::<_, TextOrdOre, _>(v, keyset),
        Encrypt::IntegerOrdOre(v) => seal::<_, IntegerOrdOre, _>(v, keyset),
        Encrypt::IntegerOrdOpe(v) => seal::<_, IntegerOrdOpe, _>(v, keyset),
        Encrypt::DoubleOrdOre(v) => seal::<_, DoubleOrdOre, _>(v, keyset),
        Encrypt::Boolean(v) => seal::<_, Boolean, _>(v, keyset),
    }
}

fn query_one<'a, K: 'static>(
    item: Query,
    keyset: &'a KeysetCipher<'_, K>,
) -> Pending<'a, Value, K> {
    match item {
        Query::TextEq(v) => seal::<_, TextEqQuery, _>(v, keyset),
        Query::TextMatch(v) => seal::<_, TextMatchQuery, _>(v, keyset),
        Query::TextOrdOre(v) => seal::<_, TextOrdOreQuery, _>(v, keyset),
        Query::IntegerOrdOre(v) => seal::<_, IntegerOrdOreQuery, _>(v, keyset),
        Query::IntegerOrdOpe(v) => seal::<_, IntegerOrdOpeQuery, _>(v, keyset),
        Query::DoubleOrdOre(v) => seal::<_, DoubleOrdOreQuery, _>(v, keyset),
    }
}

fn decrypt_one<'a, K: 'static>(
    item: Decrypt,
    keyset: &'a KeysetCipher<'_, K>,
) -> Result<Pending<'a, Value, K>, Error> {
    match item {
        Decrypt::TextEq(s) => open::<String, _, _>(s, keyset),
        Decrypt::TextMatch(s) => open::<String, _, _>(s, keyset),
        Decrypt::TextOrdOre(s) => open::<String, _, _>(s, keyset),
        Decrypt::IntegerOrdOre(s) => open::<i32, _, _>(s, keyset),
        Decrypt::IntegerOrdOpe(s) => open::<i32, _, _>(s, keyset),
        Decrypt::DoubleOrdOre(s) => open::<f64, _, _>(s, keyset),
        Decrypt::Boolean(s) => open::<bool, _, _>(s, keyset),
    }
}

/// Answer a request: each list is read whole, then sent as one ZeroKMS
/// request whose results keep request order. One bad item fails its list.
async fn answer<K>(keyset: &KeysetCipher<'_, K>, request: Request) -> Result<Value, Error>
where
    K: DataKeySource + IndexKeySource + Sync + 'static,
{
    let encrypt: Vec<Encrypt> = items("encrypt", request.encrypt)?;
    let query: Vec<Query> = items("query", request.query)?;
    let decrypt: Vec<Decrypt> = items("decrypt", request.decrypt)?;

    let encrypted = Pending::all(
        keyset,
        encrypt
            .into_iter()
            .map(|item| encrypt_one(item, keyset))
            .collect(),
    )
    .await?;
    let queries = Pending::all(
        keyset,
        query
            .into_iter()
            .map(|item| query_one(item, keyset))
            .collect(),
    )
    .await?;
    let decrypted = Pending::all(
        keyset,
        decrypt
            .into_iter()
            .map(|item| decrypt_one(item, keyset))
            .collect::<Result<_, _>>()?,
    )
    .await?;

    Ok(json!({ "encrypt": encrypted, "query": queries, "decrypt": decrypted }))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let request: Request = serde_json::from_str(&input)?;

    let cipher = StackCipher::new().await?;
    let response = answer(&cipher.default_keyset(), request).await?;

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

    fn request(value: Value) -> Request {
        serde_json::from_value(value).unwrap()
    }

    async fn refusal(value: Value) -> String {
        let (cipher, calls) = common::cipher().await;
        match answer(&cipher.default_keyset(), request(value)).await {
            Ok(response) => panic!("the request should be refused, got: {response}"),
            Err(error) => {
                let calls = calls.lock().unwrap();
                assert!(
                    calls.generate.is_empty() && calls.retrieve.is_empty(),
                    "a request refused while it is read should request no key"
                );
                error.to_string()
            }
        }
    }

    mod given_a_plaintext_of_the_wrong_kind {
        use super::*;

        #[tokio::test]
        async fn refuses_naming_the_json_type_and_never_the_value() {
            let cases = [
                ("TextEq", json!(12345), "12345", "number"),
                ("IntegerOrdOre", json!("alice@b.c"), "alice@b.c", "string"),
                ("IntegerOrdOre", json!(1.5), "1.5", "number"),
                (
                    "IntegerOrdOpe",
                    json!(9_999_999_999_i64),
                    "9999999999",
                    "number",
                ),
                ("Boolean", json!("secret-flag"), "secret-flag", "string"),
                ("TextEq", json!({ "ssn": "078-05" }), "078-05", "object"),
            ];
            for (name, value, plaintext, json_type) in cases {
                let message = refusal(json!({
                    "encrypt": [{ "type": name, "table": "t", "column": "c", "value": value }]
                }))
                .await;
                assert!(
                    !message.contains(plaintext),
                    "{name}'s refusal should not repeat the plaintext, got: {message}"
                );
                assert!(
                    message.contains(name) && message.contains(json_type),
                    "{name}'s refusal should name the type and the JSON type {json_type}, got: {message}"
                );
            }
        }
    }

    mod given_an_unknown_type {
        use super::*;

        #[tokio::test]
        async fn refuses_naming_it() {
            let message = refusal(json!({
                "encrypt": [{ "type": "TextOrdOpe", "table": "t", "column": "c", "value": "x" }]
            }))
            .await;
            assert!(
                message.contains("unknown variant") && message.contains("TextOrdOpe"),
                "got: {message}"
            );
        }

        #[tokio::test]
        async fn refuses_a_query_on_a_type_that_answers_none() {
            let message = refusal(json!({
                "query": [{ "type": "Boolean", "table": "t", "column": "c", "value": true }]
            }))
            .await;
            assert!(message.contains("Boolean"), "got: {message}");
        }
    }

    mod given_an_empty_column {
        use super::*;

        #[tokio::test]
        async fn refuses_before_any_key_is_requested() {
            let (cipher, calls) = common::cipher().await;
            let result = answer(
                &cipher.default_keyset(),
                request(json!({
                    "encrypt": [{ "type": "TextEq", "table": "t", "column": "", "value": "x" }]
                })),
            )
            .await;
            assert!(result.is_err(), "an empty column should be refused");
            assert!(
                calls.lock().unwrap().generate.is_empty(),
                "no key was requested"
            );
        }
    }

    mod given_a_request_of_many_items {
        use super::*;

        fn mixed() -> Vec<(&'static str, Value)> {
            (0..25)
                .map(|n| match n % 7 {
                    0 => ("TextEq", json!(format!("value-{n}"))),
                    1 => ("TextMatch", json!(format!("some words {n}"))),
                    2 => ("IntegerOrdOre", json!(n)),
                    3 => ("IntegerOrdOpe", json!(-n)),
                    // A JSON integer reads as a double, as protect-ffi hands
                    // an integral number back.
                    4 => ("DoubleOrdOre", json!(n)),
                    5 => ("Boolean", json!(n % 2 == 0)),
                    _ => ("TextOrdOre", json!(format!("name-{n}"))),
                })
                .collect()
        }

        #[tokio::test]
        async fn sends_each_list_as_one_kms_call_and_keeps_the_order() {
            let (cipher, calls) = common::cipher().await;
            let keyset = cipher.default_keyset();
            let items = mixed();

            let encrypt: Vec<Value> = items
                .iter()
                .enumerate()
                .map(|(n, (name, value))| {
                    json!({ "type": name, "table": "t", "column": format!("c{}", n % 5), "value": value })
                })
                .collect();
            let response = answer(&keyset, request(json!({ "encrypt": encrypt })))
                .await
                .unwrap();
            assert_eq!(
                calls.lock().unwrap().generate.len(),
                1,
                "25 values of seven types should be one generate call"
            );

            let decrypt: Vec<Value> = response["encrypt"]
                .as_array()
                .unwrap()
                .iter()
                .zip(&items)
                .enumerate()
                .map(|(n, (payload, (name, _)))| {
                    json!({ "type": name, "table": "t", "column": format!("c{}", n % 5), "payload": payload })
                })
                .collect();
            let response = answer(&keyset, request(json!({ "decrypt": decrypt })))
                .await
                .unwrap();
            assert_eq!(
                calls.lock().unwrap().retrieve.len(),
                1,
                "25 values of seven types should be one retrieve call"
            );

            let decrypted = response["decrypt"].as_array().unwrap();
            for ((name, expected), opened) in items.iter().zip(decrypted) {
                let matches = match expected {
                    Value::Number(n) if *name == "DoubleOrdOre" => opened.as_f64() == n.as_f64(),
                    _ => opened == expected,
                };
                assert!(matches, "{name}: expected {expected}, opened {opened}");
            }
        }
    }

    mod given_a_query {
        use super::*;

        #[tokio::test]
        async fn its_operand_matches_the_stored_value_of_the_same_column() {
            let (cipher, _) = common::cipher().await;
            let keyset = cipher.default_keyset();
            let item = json!({
                "type": "TextEq", "table": "customers", "column": "email", "value": "alan@example.com"
            });
            let response = answer(
                &keyset,
                request(json!({ "encrypt": [item.clone()], "query": [item] })),
            )
            .await
            .unwrap();
            let stored = &response["encrypt"][0];
            let operand = &response["query"][0];
            assert!(stored["hm"].is_string(), "the stored value carries hm");
            assert_eq!(
                stored["hm"], operand["hm"],
                "the query finds the stored value"
            );
        }
    }

    // The migration suites relabel a legacy payload as v4 and expect it
    // refused by name: the refusal must come from the ciphertext's producer,
    // not from a decode error, or the suite cannot tell the two apart.
    mod given_a_payload_another_producer_wrote {
        use super::*;

        #[tokio::test]
        async fn refuses_it_by_name() {
            let (cipher, _) = common::cipher().await;
            let keyset = cipher.default_keyset();
            let response = answer(
                &keyset,
                request(json!({
                    "encrypt": [{ "type": "TextEq", "table": "t", "column": "email", "value": "x" }]
                })),
            )
            .await
            .unwrap();
            let mut legacy = response["encrypt"][0].clone();
            legacy["c"] = json!("legacy-ciphertext");
            let error = answer(
                &keyset,
                request(json!({
                    "decrypt": [{ "type": "TextEq", "table": "t", "column": "email", "payload": legacy }]
                })),
            )
            .await
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("unsupported EQL ciphertext producer or version"),
                "got: {error}"
            );
        }
    }

    mod given_a_payload_read_from_another_column {
        use super::*;

        #[tokio::test]
        async fn refuses_to_open_it() {
            let (cipher, _) = common::cipher().await;
            let keyset = cipher.default_keyset();
            let response = answer(
                &keyset,
                request(json!({
                    "encrypt": [{ "type": "TextEq", "table": "t", "column": "email", "value": "x" }]
                })),
            )
            .await
            .unwrap();
            let result = answer(
                &keyset,
                request(json!({
                    "decrypt": [{
                        "type": "TextEq", "table": "t", "column": "other",
                        "payload": response["encrypt"][0]
                    }]
                })),
            )
            .await;
            assert!(
                result.is_err(),
                "a payload stored under email should not open as other"
            );
        }
    }
}
