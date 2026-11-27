//! Byte pins for how a plaintext value is written: its transport frame, the
//! plaintext its sealed leaf holds, and the leaf of a sealed null, for every
//! scalar kind the engine takes, on the typed Rust path and on the dynamic
//! record path a language binding calls.
//!
//! The conformance corpus pins frames and terms, and opens stored rows, but a
//! sealed leaf carries a random AES-GCM nonce, so no other test compares the
//! plaintext a leaf was sealed with. Here every leaf is sealed under
//! [`DeterministicSource`], whose data keys this file records, and opened
//! again with those keys and the engine's leaf AAD. The plaintext that comes
//! out is compared byte for byte with `tests/fixtures/value_bytes_v1.json`.
//!
//! What the file holds is today's behaviour, including rules a reader may
//! expect to change: a host's typed null reads as a plain null, a timestamp
//! in another unit keeps its unit in the frame and is sealed in
//! nanoseconds, and opaque JSON is a text leaf on the typed path and a bytes
//! frame when it opens. A change to any of these is a change to a
//! pinned value, and shows in the fixture's diff.
//!
//! Regenerate with `STACK_ENCRYPT_UPDATE_FIXTURES=1 cargo test -p
//! stack-encrypt --all-features --test value_bytes`, then run `pnpm run
//! code:fix` to format it. Nothing in it depends on a nonce, so a run that
//! changes it
//! changed what is written. The schema is in the README beside the fixture.
// The typed `Uuid` cases need the `uuid` feature, which `dynamic` does not
// turn on.
#![cfg(all(feature = "dynamic", feature = "uuid"))]

mod common;

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use common::conformance::{value, Input};
use common::frames::{frame, object};
use common::{hex, DeterministicSource};
use serde_json::{json, Map, Value as Json};
use stack_encrypt::dynamic::{self, frame::OwnedFrame, record};
use stack_encrypt::json::JsonPlaintext;
use stack_encrypt::sem::EqualityTerm;
use stack_encrypt::target::{equality, Borrowed, CallerContext};
use stack_encrypt::value::{Date, Decimal, Timestamp, Uuid as UuidValue};
use stack_encrypt::{AsProtectedRef as _, CipherText, SealedValue, StackCipher, StackCipherText};
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, GenerateKeyPayload, IdentifiedBy, IndexKey,
    IndexKeySource, RetrieveKeyPayload, UnverifiedContext,
};
use uuid::Uuid;
use vitaminc_aead::plaintext::{FixedType, Float, Int, Logical, Physical, Raw, TimeUnit, Width};
use vitaminc_aead::seal::Cipher;
use vitaminc_aead::{
    Context, Encrypt, Frame, FrameWriter, IntoContext, LocalCipherText, Unspecified,
};
use vitaminc_encrypt::{Aes256Cipher, Key as AesKey};
use vitaminc_protected::{Buffer, Controlled as _, Protected};

const SEED: [u8; 32] = *b"stack-encrypt value bytes v1    ";

/// The context every value here is sealed under.
const CONTEXT: [&str; 2] = ["conformance", "value"];

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/value_bytes_v1.json")
}

// =============================================================================
// Opening a sealed leaf to the plaintext sealed in it
// =============================================================================

/// [`DeterministicSource`], keeping each data key it generates by its IV,
/// so a test can open the leaves sealed under them without the engine.
struct KeptKeys {
    inner: DeterministicSource,
    keys: Arc<Mutex<HashMap<Vec<u8>, [u8; 32]>>>,
}

impl stack_kms::KeySourceKind for KeptKeys {
    type Kind = stack_kms::OwnIdentity;
}

impl DataKeySource for KeptKeys {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
        let keys = self
            .inner
            .generate_keys(payloads, keyset_id, unverified_context)
            .await?;
        let mut kept = self.keys.lock().unwrap();
        for key in &keys {
            let _ = kept.insert(key.key.iv.to_vec(), *key.key.key());
        }
        Ok(keys)
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_kms::Error> {
        self.inner
            .retrieve_keys(payloads, keyset_id, unverified_context)
            .await
    }
}

impl IndexKeySource for KeptKeys {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, IndexKey), stack_kms::Error> {
        self.inner.load_index_key(keyset_id).await
    }
}

/// A cipher over the kept keys, and the keys.
async fn cipher() -> (
    StackCipher<KeptKeys>,
    Arc<Mutex<HashMap<Vec<u8>, [u8; 32]>>>,
) {
    let keys = Arc::default();
    let cipher = StackCipher::builder()
        .kms(KeptKeys {
            inner: DeterministicSource::new(SEED),
            keys: Arc::clone(&keys),
        })
        .init()
        .await
        .expect("build cipher");
    (cipher, keys)
}

/// A vitaminc cipher that opens a stored leaf with its kept key, under the
/// AAD the engine binds a leaf to (`stack-encrypt/leaf`, the format version,
/// the keyset, the AAD of the leaf's place and the key tag, as a PAE), and
/// keeps each plaintext it opened, in walk order.
struct Reveal<'k> {
    keys: &'k HashMap<Vec<u8>, [u8; 32]>,
    opened: RefCell<Vec<String>>,
}

impl Cipher for Reveal<'_> {
    type Leaf = SealedValue;
    type Error = Unspecified;

    fn seal(&self, _: Protected<Vec<u8>>, _: &Context<'_>) -> Result<SealedValue, Unspecified> {
        Err(Unspecified)
    }

    fn open(
        &self,
        leaf: SealedValue,
        aad: &Context<'_>,
    ) -> Result<Protected<Vec<u8>>, Unspecified> {
        let (keyset_id, iv, tag, ciphertext) = leaf.into_parts();
        let key = self.keys.get(iv.as_slice()).ok_or(Unspecified)?;
        let aad = Context::pae(&[
            b"stack-encrypt/leaf",
            &[SealedValue::FORMAT_VERSION],
            keyset_id.as_bytes(),
            aad.as_bytes(),
            &tag,
        ]);
        let cipher = Aes256Cipher::new(&AesKey::from(*key))?;
        let plaintext = cipher.open(LocalCipherText::from(ciphertext), &aad)?;
        self.opened.borrow_mut().push(hex(plaintext.risky_ref()));
        Ok(plaintext)
    }
}

/// The plaintext of every leaf of `tree`, sealed under `context`, in walk
/// order: a scalar's tagged bytes, a typed null's padded bytes, and an empty
/// container's marker as the empty string.
fn reveal<'c>(
    keys: &Mutex<HashMap<Vec<u8>, [u8; 32]>>,
    tree: StackCipherText,
    context: impl IntoContext<'c>,
) -> Vec<String> {
    let keys = keys.lock().unwrap();
    let reveal = Reveal {
        keys: &keys,
        opened: RefCell::default(),
    };
    let mut out = Buffer::default();
    vitaminc_aead::decrypt_into(
        &reveal,
        tree,
        context.into_context(),
        FrameWriter::new(&mut out),
    )
    .unwrap_or_else(|_| {
        panic!(
            "the leaves open under their kept keys: if every case fails here, \
             the AAD `Reveal` builds no longer mirrors `leaf_aad` in src/cipher.rs"
        )
    });
    reveal.opened.into_inner()
}

fn context_label() -> String {
    CONTEXT.join("/")
}

// =============================================================================
// The typed Rust path
// =============================================================================

/// One typed value: its frame as vitaminc writes it, and the plaintext of
/// the leaf `encrypt_tree` seals it as.
async fn typed<T: Encrypt>(
    cipher: &StackCipher<KeptKeys>,
    keys: &Mutex<HashMap<Vec<u8>, [u8; 32]>>,
    frame_of: T,
    sealed: T,
) -> Json {
    let frame = vitaminc_aead::to_frame(frame_of).expect("a typed value frames");
    let tree = cipher
        .default_keyset()
        .encrypt_tree(sealed, context_label().as_str())
        .await
        .expect("a typed value seals");
    let leaves = reveal(keys, tree, context_label().as_str());
    json!({ "frame": hex(frame.risky_ref()), "leaf": one(leaves) })
}

fn one(mut leaves: Vec<String>) -> String {
    assert_eq!(leaves.len(), 1, "one leaf");
    leaves.remove(0)
}

fn date(text: &str) -> Date {
    Date::new(text.parse::<jiff::civil::Date>().expect("a date"))
}

fn timestamp(text: &str) -> Timestamp {
    Timestamp::new(text.parse::<jiff::Timestamp>().expect("an instant")).expect("in range")
}

fn decimal(text: &str) -> Decimal {
    Decimal::new(text.parse::<rust_decimal::Decimal>().expect("a decimal"))
}

/// The UUID the typed path seals.
const UUID: u128 = 0x123e_4567_e89b_12d3_a456_4266_1417_4000;

fn uuid_value() -> UuidValue {
    UuidValue::new(Uuid::from_u128(UUID))
}

/// A UUID's equality term on the typed path, beside the term of the same
/// sixteen bytes as a byte string: the UUID's is derived under its own
/// domain, so the two differ.
async fn uuid_equality(cipher: &StackCipher<KeptKeys>) -> Json {
    let keyset = cipher.default_keyset();
    let ctx = || {
        CallerContext::from(
            dynamic::context(
                recipher_frame::serde::to_vec(&CONTEXT)
                    .unwrap()
                    .as_protected_ref(),
            )
            .expect("a context"),
        )
    };
    let uuid: EqualityTerm = keyset
        .run(equality::<_, _, Borrowed>(), &uuid_value(), ctx())
        .await
        .expect("a uuid has an equality term");
    let bytes: EqualityTerm = keyset
        .run(
            equality::<_, _, Borrowed>(),
            &Uuid::from_u128(UUID).as_bytes().to_vec(),
            ctx(),
        )
        .await
        .expect("bytes have an equality term");
    let (uuid, bytes) = (hex(&uuid.into_bytes()[..]), hex(&bytes.into_bytes()[..]));
    assert_ne!(uuid, bytes, "a uuid is not its bytes");
    json!({ "Uuid": uuid, "Vec<u8>": bytes })
}

fn document() -> JsonPlaintext {
    JsonPlaintext::from(json!({"a": [1, "x"], "b": null}))
}

async fn typed_section(
    cipher: &StackCipher<KeptKeys>,
    keys: &Mutex<HashMap<Vec<u8>, [u8; 32]>>,
) -> Json {
    let mut out = Map::new();
    macro_rules! pin {
        ($name:literal, $value:expr) => {
            let _ = out.insert($name.into(), typed(cipher, keys, $value, $value).await);
        };
    }
    // A lone `u8` is not a typed plaintext: vitaminc writes a `Vec<u8>` as
    // one byte string, so `u8` has no `Encrypt`. The dynamic path below
    // pins `uint8`.
    pin!("bool", true);
    pin!("i8", -8i8);
    pin!("i16", -300i16);
    pin!("u16", 60_000u16);
    pin!("i32", -2i32);
    pin!("u32", 4_000_000_000u32);
    pin!("i64", -9_007_199_254_740_993i64);
    pin!("u64", u64::MAX);
    pin!("i128", i128::MIN);
    pin!("u128", u128::MAX);
    pin!("f32", 1.5f32);
    pin!("f64", -0.0f64);
    pin!("String", String::from("café"));
    pin!("Vec<u8>", vec![0u8, 255, 16]);
    pin!("Date", date("2024-02-29"));
    pin!("Timestamp", timestamp("2026-10-17T01:02:03.123456789Z"));
    pin!("Decimal", decimal("-1234.5600"));
    pin!("JsonPlaintext", document());
    pin!("Uuid", uuid_value());
    // `None` of a fixed-width type seals as a typed null of that type, as
    // long as a value of it. A `bool` is the exception: its leaf is one byte,
    // as long as the plain null, so its `None` seals as the plain null `00`.
    // A `None` of a type with no fixed width seals as the plain null too.
    pin!("Option<bool>::None", None::<bool>);
    pin!("Option<i8>::None", None::<i8>);
    pin!("Option<i16>::None", None::<i16>);
    pin!("Option<u16>::None", None::<u16>);
    pin!("Option<i32>::None", None::<i32>);
    pin!("Option<u32>::None", None::<u32>);
    pin!("Option<i64>::None", None::<i64>);
    pin!("Option<u64>::None", None::<u64>);
    pin!("Option<i128>::None", None::<i128>);
    pin!("Option<u128>::None", None::<u128>);
    pin!("Option<f32>::None", None::<f32>);
    pin!("Option<f64>::None", None::<f64>);
    pin!("Option<Date>::None", None::<Date>);
    pin!("Option<Timestamp>::None", None::<Timestamp>);
    pin!("Option<Decimal>::None", None::<Decimal>);
    pin!("Option<String>::None", None::<String>);
    pin!("Option<Vec<u8>>::None", None::<Vec<u8>>);
    pin!("Option<JsonPlaintext>::None", None::<JsonPlaintext>);
    pin!("Option<Uuid>::None", None::<UuidValue>);
    Json::Object(out)
}

// =============================================================================
// The dynamic record path
// =============================================================================

/// A data plan of one field, `value`, under [`CONTEXT`], or its refusal.
fn plan(spec: &Json) -> Result<record::Plan, dynamic::Error> {
    let mut spec = spec.clone();
    spec["context"] = json!(CONTEXT);
    record::plan(
        recipher_frame::serde::to_vec(&json!({ "value": spec }))
            .unwrap()
            .as_protected_ref(),
    )
}

/// What the record path does with one row: the plaintext of each leaf of
/// the field's ciphertext, that the field is stored as SQL `NULL`, or the
/// refusal's code and reason.
async fn seal_row(
    cipher: &StackCipher<KeptKeys>,
    keys: &Mutex<HashMap<Vec<u8>, [u8; 32]>>,
    spec: Json,
    row: impl Encrypt,
) -> Json {
    let plan = match plan(&spec) {
        Ok(plan) => plan,
        Err(error) => return json!({ "plan_refused": diagnostic(&error) }),
    };
    let keyset = cipher.default_keyset();
    let pending = match record::encrypt(&keyset, row, &plan) {
        Ok(pending) => pending,
        Err(error) => return json!({ "refused": diagnostic(&error) }),
    };
    let stored = pending.await.expect("the record seals");
    let CipherText::Map(fields) = stored else {
        panic!("a record")
    };
    let Some((_, outputs)) = fields.into_iter().find(|(name, _)| name == "value") else {
        return json!({ "stored": "sql_null" });
    };
    let CipherText::Map(outputs) = outputs else {
        panic!("the field's outputs")
    };
    let (_, c) = outputs
        .into_iter()
        .find(|(key, _)| key == "c")
        .expect("a ciphertext");
    let context = plan.fields()[0].context().clone();
    json!({ "leaves": reveal(keys, c, context) })
}

fn diagnostic(error: &dynamic::Error) -> String {
    use miette::Diagnostic as _;
    let code = error
        .code()
        .map(|code| code.to_string())
        .unwrap_or_default();
    match error.reason() {
        Some(reason) => format!("{code}/{}", reason.as_str()),
        None => code,
    }
}

fn input(kind: &str, text: &str) -> Input {
    Input {
        kind: kind.into(),
        text: text.into(),
    }
}

/// One value per kind a data plan declares, in the corpus's text forms.
const KINDS: &[(&str, &str)] = &[
    ("bool", "true"),
    ("int8", "-8"),
    ("int16", "-300"),
    ("int32", "-2"),
    ("int64", "-9007199254740993"),
    ("int128", "-170141183460469231731687303715884105728"),
    ("uint8", "200"),
    ("uint16", "60000"),
    ("uint32", "4000000000"),
    ("uint64", "18446744073709551615"),
    ("uint128", "340282366920938463463374607431768211455"),
    ("float32", "1.5"),
    ("float64", "-0"),
    ("decimal", "-1234.5600"),
    ("date", "2024-02-29"),
    ("timestamp", "2026-10-17T01:02:03.123456789Z"),
    ("string", "café"),
    ("bytes", "00ff10"),
];

async fn dynamic_section(
    cipher: &StackCipher<KeptKeys>,
    keys: &Mutex<HashMap<Vec<u8>, [u8; 32]>>,
) -> Json {
    let mut out = Map::new();
    for (kind, text) in KINDS {
        let value = value(&input(kind, text));
        let frame = hex(value.risky_ref());
        let row = |value: OwnedFrame| object(vec![("value", value)]);
        let mut entry = Map::new();
        let _ = entry.insert("text".into(), json!(text));
        let _ = entry.insert("frame".into(), json!(frame));
        let _ = entry.insert(
            "value".into(),
            seal_row(
                cipher,
                keys,
                json!({"outputs": ["c"], "type": kind}),
                row(value),
            )
            .await,
        );
        let _ = entry.insert(
            "null_sealed".into(),
            seal_row(
                cipher,
                keys,
                json!({"outputs": ["c"], "type": kind, "null": "sealed"}),
                row(value_of_null()),
            )
            .await,
        );
        let _ = entry.insert(
            "null_sql".into(),
            seal_row(
                cipher,
                keys,
                json!({"outputs": ["c"], "type": kind, "null": "sql"}),
                row(value_of_null()),
            )
            .await,
        );
        let _ = out.insert((*kind).into(), Json::Object(entry));
    }
    // An untyped field takes any value in the model; a container's every
    // scalar is a leaf, and an empty container a marker.
    let untyped = json!({"outputs": ["c"]});
    let nested = object(vec![
        ("list", frame(vec![frame(1i32), frame(String::from("x"))])),
        ("empty_list", frame(Vec::<OwnedFrame>::new())),
        ("empty_map", object(Vec::<(&str, OwnedFrame)>::new())),
    ]);
    let _ = out.insert(
        "untyped_object".into(),
        json!({
            "frame": hex(nested.risky_ref()),
            "value": seal_row(cipher, keys, untyped.clone(), object(vec![("value", nested)])).await,
        }),
    );
    let _ = out.insert(
        "untyped_null".into(),
        json!({
            "value": seal_row(cipher, keys, untyped, object(vec![("value", value_of_null())])).await,
        }),
    );
    Json::Object(out)
}

fn value_of_null() -> OwnedFrame {
    value(&input("null", ""))
}

// =============================================================================
// Frames a host writes that no Rust value in this file writes
// =============================================================================

/// Frame bytes as a host writes them, read the way the Go guest reads a
/// record: checked with [`Frame::parse`] and walked in place.
fn host_row(field_frame: &[u8]) -> Vec<u8> {
    // An object of one entry, `value`, whose frame is spliced in after the
    // key: the frame writer would drop a typed null, so the bytes are built
    // around a placeholder instead.
    let placeholder = object(vec![("value", frame(true))]);
    let bytes = placeholder.risky_ref();
    assert_eq!(bytes.last(), Some(&vitaminc_aead::tags::BOOL_TRUE));
    let mut row = bytes[..bytes.len() - 1].to_vec();
    row.extend_from_slice(field_frame);
    row
}

/// The bytes a host sends for a typed null of `ty`: the same encoding a
/// sealed leaf uses, the tag and the padding.
fn typed_null(ty: FixedType) -> Vec<u8> {
    let mut out = Vec::new();
    vitaminc_aead::leaf::write_typed_null(ty, &mut out);
    out
}

async fn host_row_outcome(
    cipher: &StackCipher<KeptKeys>,
    keys: &Mutex<HashMap<Vec<u8>, [u8; 32]>>,
    spec: Json,
    field_frame: &[u8],
) -> Json {
    let row = host_row(field_frame);
    let row = protected(&row);
    match Frame::parse(row.risky_ref()) {
        Ok(checked) => seal_row(cipher, keys, spec, checked).await,
        Err(_) => json!({ "frame_refused": true }),
    }
}

/// Bytes in the protected buffer a binding hands the engine.
fn protected(bytes: &[u8]) -> Buffer {
    let mut buffer = Buffer::with_capacity(bytes.len());
    buffer.extend_from_slice(bytes);
    buffer
}

/// A host frame read on its own: what [`OwnedFrame::from_bytes`] keeps of it,
/// or that it refuses it.
fn engine_frame(host: &[u8]) -> Json {
    let host = protected(host);
    match OwnedFrame::from_bytes(host.as_protected_ref()) {
        Ok(value) => json!(hex(value.risky_ref())),
        Err(_) => json!({ "refused": true }),
    }
}

/// A logical value in the envelope a host may write for any logical type:
/// `0xF3`, the logical type's id, its parameter, then an `i64` (tag `0x05`).
/// vitaminc's own frame writer uses the shorter tag a date or a nanosecond
/// timestamp has, so a Rust value cannot produce these bytes.
fn envelope(logical: u8, parameter: u8, int64: &[u8; 8]) -> Vec<u8> {
    let mut out = vec![0xF3, logical, parameter, vitaminc_aead::tags::INT64];
    out.extend_from_slice(int64);
    out
}

async fn host_section(
    cipher: &StackCipher<KeptKeys>,
    keys: &Mutex<HashMap<Vec<u8>, [u8; 32]>>,
) -> Json {
    let to = |raw: Raw<'_>| {
        vitaminc_aead::to_frame(raw)
            .expect("a host frame")
            .risky_ref()
            .to_vec()
    };
    let ts =
        |unit: TimeUnit, count: Int| to(Raw(Some(Logical::Timestamp(unit)), Physical::Int(count)));
    let uuid = to(Raw(
        Some(Logical::Uuid),
        Physical::Bytes(&[
            0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17,
            0x40, 0x00,
        ]),
    ));
    let undefined = to(Raw(Some(Logical::Undefined), Physical::Null));
    // A timestamp in a unit other than nanoseconds, as a host may write one
    // (a JavaScript `Date` is milliseconds over an `i64`).
    let hosts: Vec<(&str, &str, Vec<u8>)> = vec![
        (
            "timestamp_seconds",
            "timestamp",
            ts(TimeUnit::Seconds, Int::I64(1)),
        ),
        (
            "timestamp_millis",
            "timestamp",
            ts(TimeUnit::Millis, Int::I64(123)),
        ),
        (
            "timestamp_millis_negative",
            "timestamp",
            ts(TimeUnit::Millis, Int::I64(-1)),
        ),
        (
            "timestamp_micros",
            "timestamp",
            ts(TimeUnit::Micros, Int::I64(1)),
        ),
        (
            "timestamp_nanos_i64",
            "timestamp",
            envelope(3, 3, &1i64.to_le_bytes()),
        ),
        ("uuid", "", uuid),
        ("undefined", "", undefined.clone()),
        ("undefined_for_string", "string", undefined),
        (
            "date_over_i64",
            "date",
            // 2024-02-29: 19,782 days after 1970-01-01.
            envelope(2, 0, &19_782i64.to_le_bytes()),
        ),
        (
            "float64_for_float32",
            "float32",
            to(Raw(None, Physical::Float(Float::F64(1.5)))),
        ),
    ];
    // These reach the engine as the 0xF3 envelope a host writes, not the
    // shorthand a Rust frame writer would turn them into.
    let envelopes = [
        "timestamp_seconds",
        "timestamp_millis",
        "timestamp_millis_negative",
        "timestamp_micros",
        "timestamp_nanos_i64",
        "date_over_i64",
    ];
    let mut out = Map::new();
    for (name, kind, host) in hosts {
        if envelopes.contains(&name) {
            assert_eq!(host[0], 0xF3, "{name}: the host's envelope");
        }
        let spec = if kind.is_empty() {
            json!({"outputs": ["c"]})
        } else {
            json!({"outputs": ["c"], "type": kind})
        };
        let _ = out.insert(
            name.into(),
            json!({
                "type": kind,
                "host_frame": hex(&host),
                "frame": engine_frame(&host),
                "value": host_row_outcome(cipher, keys, spec, &host).await,
            }),
        );
    }
    Json::Object(out)
}

/// A typed null a host sends (Go's `vcvalue.TypedNull`, or a nil pointer to
/// a fixed-width type), against each null policy of a typed field, an
/// untyped field, and inside an untyped value.
async fn typed_null_section(
    cipher: &StackCipher<KeptKeys>,
    keys: &Mutex<HashMap<Vec<u8>, [u8; 32]>>,
) -> Json {
    let int32 = typed_null(FixedType::new(None, Width::I32).expect("a fixed type"));
    let int64 = typed_null(FixedType::new(None, Width::I64).expect("a fixed type"));
    let mut out = Map::new();
    let _ = out.insert(
        "frames".into(),
        json!({
            "int32": { "host_frame": hex(&int32), "frame": engine_frame(&int32) },
            "int64": { "host_frame": hex(&int64), "frame": engine_frame(&int64) },
        }),
    );
    let cases: Vec<(&str, Json, &[u8])> = vec![
        (
            "int32_field_int32_null",
            json!({"outputs": ["c"], "type": "int32"}),
            &int32,
        ),
        (
            "int32_field_int32_null_sql",
            json!({"outputs": ["c"], "type": "int32", "null": "sql"}),
            &int32,
        ),
        (
            "int32_field_int32_null_sealed",
            json!({"outputs": ["c"], "type": "int32", "null": "sealed"}),
            &int32,
        ),
        (
            "int32_field_int64_null_sealed",
            json!({"outputs": ["c"], "type": "int32", "null": "sealed"}),
            &int64,
        ),
        (
            "untyped_field_int32_null",
            json!({"outputs": ["c"]}),
            &int32,
        ),
    ];
    for (name, spec, host) in cases {
        let _ = out.insert(
            name.into(),
            host_row_outcome(cipher, keys, spec, host).await,
        );
    }
    // Inside an untyped value: an array of one typed null.
    let mut array = vec![0xF0, 1, 0, 0, 0];
    array.extend_from_slice(&int32);
    let _ = out.insert(
        "untyped_field_array_of_int32_null".into(),
        json!({
            "host_frame": hex(&array),
            "frame": engine_frame(&array),
            "value": host_row_outcome(cipher, keys, json!({"outputs": ["c"]}), &array).await,
        }),
    );
    Json::Object(out)
}

// =============================================================================
// A JSON document
// =============================================================================

async fn json_section(
    cipher: &StackCipher<KeptKeys>,
    keys: &Mutex<HashMap<Vec<u8>, [u8; 32]>>,
) -> Json {
    let text = r#"{"a":[1,"x"],"b":null}"#;
    let opened = dynamic::json_frame(&json!({"a": [1, "x"], "b": null})).expect("a document");
    let as_text = frame(String::from(text));
    let as_bytes = frame(text.as_bytes().to_vec());
    // A `json` field reads a text frame and a bytes frame as one document.
    for value in [&as_text, &as_bytes, &opened] {
        let document = dynamic::read_json(value).expect("a document");
        assert_eq!(document.value(), document_value(), "one document");
    }
    json!({
        "typed_leaf": typed(cipher, keys, document(), document()).await,
        "opened_frame": hex(opened.risky_ref()),
        "record_without_target": seal_row(
            cipher,
            keys,
            json!({"outputs": ["c"], "type": "json"}),
            object(vec![("value", as_text)]),
        )
        .await,
        "untyped_text": seal_row(
            cipher,
            keys,
            json!({"outputs": ["c"]}),
            object(vec![("value", frame(String::from(text)))]),
        )
        .await,
    })
}

fn document_value() -> &'static Json {
    static DOCUMENT: std::sync::OnceLock<Json> = std::sync::OnceLock::new();
    DOCUMENT.get_or_init(|| json!({"a": [1, "x"], "b": null}))
}

// =============================================================================
// The fixture
// =============================================================================

/// Every difference between `actual` and `expected`, by path.
fn differences(path: &str, actual: &Json, expected: &Json, out: &mut Vec<String>) {
    match (actual, expected) {
        (Json::Object(a), Json::Object(e)) => {
            for key in a
                .keys()
                .chain(e.keys())
                .collect::<std::collections::BTreeSet<_>>()
            {
                let here = format!("{path}.{key}");
                match (a.get(key), e.get(key)) {
                    (Some(a), Some(e)) => differences(&here, a, e, out),
                    (Some(a), None) => out.push(format!("{here}: {a}, not in the fixture")),
                    (None, Some(e)) => out.push(format!("{here}: missing, the fixture has {e}")),
                    (None, None) => unreachable!(),
                }
            }
        }
        _ if actual == expected => {}
        _ => out.push(format!("{path}: {actual}, the fixture has {expected}")),
    }
}

#[tokio::test]
async fn value_bytes_are_the_pinned_bytes() {
    let update = common::fixture_updates_requested_or_panic();
    let (cipher, keys) = cipher().await;
    let actual = json!({
        "typed": typed_section(&cipher, &keys).await,
        "dynamic": dynamic_section(&cipher, &keys).await,
        "host": host_section(&cipher, &keys).await,
        "host_typed_null": typed_null_section(&cipher, &keys).await,
        "json": json_section(&cipher, &keys).await,
        "uuid_equality": uuid_equality(&cipher).await,
    });
    let mut document = json!({
        "_comment": "Pinned bytes of every way a plaintext value is written: its transport frame, the plaintext its sealed leaf holds, and a sealed null's leaf, for the typed Rust path and the dynamic record path. Read by tests/value_bytes.rs; the schema is in README.md beside this file. Regenerate with STACK_ENCRYPT_UPDATE_FIXTURES=1, then run pnpm run code:fix; never edit by hand.",
        "key_source": { "kind": "deterministic-sha256", "seed": hex(&SEED) },
        "context": CONTEXT,
    });
    for (key, section) in actual.as_object().unwrap() {
        document[key] = section.clone();
    }
    let path = fixture_path();
    if update {
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&document).unwrap() + "\n",
        )
        .expect("write the fixture");
        return;
    }
    let committed: Json =
        serde_json::from_slice(&std::fs::read(&path).expect("the fixture")).expect("JSON");
    // The whole document: a key the test no longer writes is a failure too.
    let mut failures = Vec::new();
    differences("", &document, &committed, &mut failures);
    assert!(
        failures.is_empty(),
        "written bytes moved:\n{}",
        failures.join("\n")
    );
}

// =============================================================================
// Timestamps: sealed in nanoseconds, passed through as written
// =============================================================================

/// A timestamp in seconds, milliseconds or microseconds, as a host writes
/// it, seals through the record path to the leaf of the same instant in
/// nanoseconds.
#[tokio::test]
async fn a_timestamp_in_any_unit_seals_to_the_nanosecond_leaf() {
    let (cipher, keys) = cipher().await;
    let spec = || json!({"outputs": ["c"], "type": "timestamp"});
    let leaves = |field: OwnedFrame| {
        let row = object(vec![("value", field)]);
        seal_row(&cipher, &keys, spec(), row)
    };
    for (unit, count, nanos) in [
        (TimeUnit::Seconds, -2i64, -2_000_000_000i128),
        (TimeUnit::Millis, 123, 123_000_000),
        (TimeUnit::Millis, -1, -1_000_000),
        (TimeUnit::Micros, 1, 1_000),
    ] {
        let host = frame(Raw(
            Some(Logical::Timestamp(unit)),
            Physical::Int(Int::I64(count)),
        ));
        assert_eq!(
            host.risky_ref()[0],
            vitaminc_aead::tags::LOGICAL,
            "{unit:?}: the host's unit is kept in the frame"
        );
        let expected = frame(Raw(
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I128(nanos)),
        ));
        let sealed = leaves(host).await;
        assert_eq!(sealed, json!({ "leaves": [hex(expected.risky_ref())] }));
        assert_eq!(sealed, leaves(expected).await, "{unit:?}");
    }
}

/// A passthrough timestamp field in a unit other than nanoseconds stores
/// the bytes the host sent, and opens to them.
#[tokio::test]
async fn a_passthrough_timestamp_keeps_the_hosts_bytes() {
    let (cipher, _) = cipher().await;
    let plan = record::plan(
        recipher_frame::serde::to_vec(&json!({
            "sealed": { "context": ["conformance", "sealed"], "outputs": ["c"], "type": "int32" },
            "value": { "context": ["conformance", "value"], "outputs": ["passthrough"], "type": "timestamp" },
        }))
        .unwrap()
        .as_protected_ref(),
    )
    .expect("a plan");
    for (unit, count) in [
        (TimeUnit::Seconds, 1i64),
        (TimeUnit::Millis, 123),
        (TimeUnit::Millis, -1),
        (TimeUnit::Micros, 1),
    ] {
        let host = vitaminc_aead::to_frame(Raw(
            Some(Logical::Timestamp(unit)),
            Physical::Int(Int::I64(count)),
        ))
        .expect("a host frame")
        .risky_ref()
        .to_vec();
        assert_eq!(host[0], vitaminc_aead::tags::LOGICAL, "{unit:?}");
        let row = object(vec![
            ("sealed", frame(7i32)),
            (
                "value",
                OwnedFrame::from_bytes(protected(&host).as_protected_ref()).expect("in the model"),
            ),
        ]);
        let sent = row.risky_ref().to_vec();
        assert!(
            sent.ends_with(&host),
            "{unit:?}: the row carries the host's bytes"
        );
        let keyset = cipher.default_keyset();
        let stored = record::encrypt(&keyset, row, &plan)
            .expect("plans")
            .await
            .expect("seals");
        let CipherText::Map(fields) = &stored else {
            panic!("a record")
        };
        let (_, outputs) = fields
            .iter()
            .find(|(name, _)| name == "value")
            .expect("the passthrough field");
        let CipherText::Map(outputs) = outputs else {
            panic!("the field's outputs")
        };
        let (_, passthrough) = outputs
            .iter()
            .find(|(key, _)| key == "passthrough")
            .expect("a passthrough");
        let CipherText::Passthrough(payload) = passthrough else {
            panic!("a passthrough node")
        };
        assert_eq!(payload.0, host, "{unit:?}: stored as the host sent it");
        let opened = record::decrypt(&keyset, stored, &plan, None)
            .expect("plans")
            .await
            .expect("opens");
        assert_eq!(
            opened.risky_ref(),
            sent,
            "{unit:?}: opens to the host's bytes"
        );
    }
}
