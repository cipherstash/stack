//! Native tests of the guest's operations over `FakeDataKeySource` — the
//! same functions the wasm ABI drives, minus linear memory. What they pin:
//!
//! * value trees round-trip through the FFI codec + the guest ops
//!   (including element mode and passthrough subtrees);
//! * a leaf inside a guest ciphertext tree **is** the frozen `SealedValue`
//!   storage encoding — a native cipher decrypts it;
//! * terms derived through the guest dispatch are byte-identical to the
//!   native `sem` calls (the cross-language contract);
//! * record encryption follows its plan, keeps to **one** ZeroKMS call per
//!   invocation however many rows, and round-trips;
//! * hostile/malformed inputs and wrong-AAD decrypts map to the documented
//!   statuses.

use std::borrow::Cow;
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::executor::block_on;
use stack_encrypt::sem::DefaultMatch;
use stack_encrypt::{Aad, CipherText, Decrypt, SealedValue, StackCipher};
use stack_encrypt_guest::ops::{self, TERM_EQUALITY, TERM_MATCH, TERM_OPE, TERM_ORE};
use stack_encrypt_guest::status::{STATUS_AUTH, STATUS_ENCODING};
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyPayload, IndexKeySource,
    RetrieveKeyPayload,
};
use uuid::Uuid;
use vitaminc_aead_value::{transport as codec, FfiValue};
use vitaminc_protected::{Controlled, Protected};
use zerokms_protocol::{IdentifiedBy, UnverifiedContext};

// =============================================================================
// Harness
// =============================================================================

/// `FakeDataKeySource` with call counters, so the tests can assert the
/// batching contract ("one `generate_keys` per invocation") instead of
/// trusting it.
#[derive(Default)]
struct Counting {
    inner: FakeDataKeySource,
    generate_calls: AtomicUsize,
    retrieve_calls: AtomicUsize,
}

impl DataKeySource for Counting {
    async fn generate_keys(
        &self,
        payloads: Vec<GenerateKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<Cow<'_, UnverifiedContext>>,
    ) -> Result<Vec<DataKeyWithTag>, stack_kms::Error> {
        self.generate_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .generate_keys(payloads, keyset_id, unverified_context)
            .await
    }

    async fn retrieve_keys(
        &self,
        payloads: Vec<RetrieveKeyPayload<'_>>,
        keyset_id: Option<Uuid>,
        unverified_context: Option<&UnverifiedContext>,
    ) -> Result<Vec<DataKey>, stack_kms::Error> {
        self.retrieve_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .retrieve_keys(payloads, keyset_id, unverified_context)
            .await
    }
}

impl IndexKeySource for Counting {
    async fn load_index_key(
        &self,
        keyset_id: Option<IdentifiedBy>,
    ) -> Result<(Uuid, stack_kms::IndexKey), stack_kms::Error> {
        self.inner.load_index_key(keyset_id).await
    }
}

fn cipher() -> StackCipher<Counting> {
    block_on(StackCipher::builder().kms(Counting::default()).init()).expect("build cipher")
}

fn encode(value: FfiValue) -> Vec<u8> {
    let mut out = Vec::new();
    codec::encode_value(value, &mut out).expect("encode value");
    out
}

fn decode(bytes: &[u8]) -> FfiValue {
    codec::decode_value(&mut codec::Reader::new(bytes)).expect("decode value")
}

/// Decode a guest ciphertext buffer with the passthrough payload kept as a
/// plain [`FfiValue`], so tests can inspect term nodes directly.
fn decode_tree(bytes: &[u8]) -> CipherText<Vec<u8>, FfiValue> {
    codec::decode_ciphertext(&mut codec::Reader::new(bytes)).expect("decode ciphertext tree")
}

fn text(value: &FfiValue) -> &str {
    match value {
        FfiValue::String(s) => std::str::from_utf8(s.risky_ref()).expect("utf8"),
        other => panic!("expected a string, got {}", kind(other)),
    }
}

fn kind(value: &FfiValue) -> &'static str {
    match value {
        FfiValue::Null => "null",
        FfiValue::Undefined => "undefined",
        FfiValue::Bool(_) => "bool",
        FfiValue::Int32(_) => "i32",
        FfiValue::Int64(_) => "i64",
        FfiValue::UInt32(_) => "u32",
        FfiValue::UInt64(_) => "u64",
        FfiValue::Float32(_) => "f32",
        FfiValue::Float64(_) => "f64",
        FfiValue::String(_) => "string",
        FfiValue::Bytes(_) => "bytes",
        FfiValue::Array(_) => "array",
        FfiValue::Object(_) => "object",
        FfiValue::Passthrough(_) => "passthrough",
    }
}

fn obj(entries: Vec<(&str, FfiValue)>) -> FfiValue {
    FfiValue::Object(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

fn s(value: &str) -> FfiValue {
    FfiValue::String(value.into())
}

/// The plan used by the record tests: an ORE-indexed integer and a
/// match-indexed string, both stored.
fn plan() -> Vec<u8> {
    encode(obj(vec![
        (
            "age",
            obj(vec![
                ("context", s("users/age")),
                ("outputs", FfiValue::Array(vec![s("c"), s("eq"), s("ore")])),
            ]),
        ),
        (
            "name",
            obj(vec![
                ("context", s("users/name")),
                ("outputs", FfiValue::Array(vec![s("c"), s("match")])),
            ]),
        ),
    ]))
}

fn row(age: u32, name: &str) -> FfiValue {
    obj(vec![("age", FfiValue::UInt32(age)), ("name", s(name))])
}

// =============================================================================
// Values
// =============================================================================

#[test]
fn value_round_trips_through_the_guest_ops() {
    let cipher = cipher();
    let value = obj(vec![
        ("email", s("alice@example.com")),
        ("age", FfiValue::UInt32(34)),
        ("id", FfiValue::Passthrough(Box::new(FfiValue::Int64(7)))),
    ]);

    let ct = block_on(ops::encrypt_value(
        &cipher,
        &encode(value),
        b"users/42",
        false,
    ))
    .expect("encrypt");
    let pt = block_on(ops::decrypt_value(&cipher, &ct, b"users/42", false)).expect("decrypt");

    let FfiValue::Object(entries) = decode(&pt) else {
        panic!("expected an object back");
    };
    assert_eq!(entries.len(), 3);
    assert_eq!(text(&entries[0].1), "alice@example.com");
    assert!(matches!(entries[1].1, FfiValue::UInt32(34)));
    assert!(
        matches!(&entries[2].1, FfiValue::Passthrough(inner) if matches!(**inner, FfiValue::Int64(7)))
    );

    assert_eq!(cipher.kms().generate_calls.load(Ordering::SeqCst), 1);
    assert_eq!(cipher.kms().retrieve_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn element_mode_round_trips() {
    let cipher = cipher();
    let ct = block_on(ops::encrypt_value(
        &cipher,
        &encode(s("row-0")),
        b"users",
        true,
    ))
    .expect("encrypt element");
    let pt = block_on(ops::decrypt_value(&cipher, &ct, b"users", true)).expect("decrypt element");
    assert_eq!(text(&decode(&pt)), "row-0");

    // An element is not a plain value: opening it without the element
    // derivation must fail authentication.
    assert_eq!(
        block_on(ops::decrypt_value(&cipher, &ct, b"users", false)),
        Err(STATUS_AUTH)
    );
}

#[test]
fn guest_leaves_are_the_frozen_storage_encoding() {
    // A leaf lifted out of the guest's codec framing is exactly the
    // `SealedValue::from_bytes` storage format — a native cipher opens it.
    let cipher = cipher();
    let ct = block_on(ops::encrypt_value(
        &cipher,
        &encode(s("durable")),
        b"ctx",
        false,
    ))
    .expect("encrypt");

    let CipherText::Single(leaf_bytes) = decode_tree(&ct) else {
        panic!("expected a single leaf");
    };
    let leaf = SealedValue::from_bytes(&leaf_bytes).expect("frozen leaf encoding");
    // A guest leaf seals the *value model's* typed payload (`[tag] ++
    // payload`, the vitaminc sealed-leaf format), so the native open goes
    // through `FfiValue`'s own `Decrypt` — not a bare `String`.
    let decipher =
        block_on(cipher.decipher(CipherText::Single(leaf))).expect("retrieve the data key");
    let value = FfiValue::decrypt_with_aad(decipher, Aad::from_slice(b"ctx"))
        .expect("native decrypt of a guest leaf");
    assert_eq!(text(&value), "durable");
}

#[test]
fn wrong_aad_and_malformed_inputs_map_to_statuses() {
    let cipher = cipher();
    let ct =
        block_on(ops::encrypt_value(&cipher, &encode(s("x")), b"ctx", false)).expect("encrypt");

    // Wrong AAD: authentication, not encoding.
    assert_eq!(
        block_on(ops::decrypt_value(&cipher, &ct, b"other", false)),
        Err(STATUS_AUTH)
    );
    // Garbage transport bytes on either path: encoding.
    assert_eq!(
        block_on(ops::encrypt_value(&cipher, b"\xffgarbage", b"ctx", false)),
        Err(STATUS_ENCODING)
    );
    assert_eq!(
        block_on(ops::decrypt_value(&cipher, b"\xffgarbage", b"ctx", false)),
        Err(STATUS_ENCODING)
    );
    // A truncated leaf inside a well-formed tree: encoding (structural),
    // never a parse of the wrong layout.
    let CipherText::Single(leaf_bytes) = decode_tree(&ct) else {
        panic!("expected a single leaf");
    };
    let mut out = Vec::new();
    codec::encode_ciphertext::<Vec<u8>, FfiValue>(
        &CipherText::Single(leaf_bytes[..10].to_vec()),
        &mut out,
    )
    .expect("encode truncated");
    assert_eq!(
        block_on(ops::decrypt_value(&cipher, &out, b"ctx", false)),
        Err(STATUS_ENCODING)
    );
}

/// The AAD is what makes a ciphertext belong to a field. Sealing under
/// nothing would make ciphertexts transplantable between fields, so the value
/// paths refuse it exactly as the record and term paths do — and refuse it
/// *before* minting a key, so a caller that omitted the AAD cannot spend a
/// ZeroKMS call discovering it.
#[test]
fn an_empty_or_degenerate_aad_is_refused_on_the_value_paths() {
    let cipher = cipher();
    let value = encode(s("x"));

    // A real ciphertext to try to open with a missing AAD.
    let ct = block_on(ops::encrypt_value(&cipher, &value, b"ctx", false)).expect("encrypt");
    let before = cipher.kms().generate_calls.load(Ordering::SeqCst);

    // `pae([])` — eight zero bytes — is not byte-empty but carries nothing,
    // and is what `None` and `0u64` encode to. Both forms must be refused.
    for (label, aad) in [
        ("empty", b"".as_slice()),
        ("pae of an empty list", &[0u8; 8][..]),
    ] {
        for as_element in [false, true] {
            assert_eq!(
                block_on(ops::encrypt_value(&cipher, &value, aad, as_element)),
                Err(STATUS_ENCODING),
                "encrypt with a {label} aad (element: {as_element})"
            );
            assert_eq!(
                block_on(ops::decrypt_value(&cipher, &ct, aad, as_element)),
                Err(STATUS_ENCODING),
                "decrypt with a {label} aad (element: {as_element})"
            );
        }
    }

    assert_eq!(
        cipher.kms().generate_calls.load(Ordering::SeqCst),
        before,
        "no data key may be minted for a rejected call"
    );
}

// =============================================================================
// Terms
// =============================================================================

#[test]
fn guest_terms_match_the_native_sem_derivations() {
    let cipher = cipher();
    let ctx = b"users/age".as_slice();

    let eq = block_on(ops::term(
        &cipher,
        &encode(FfiValue::UInt32(42)),
        ctx,
        TERM_EQUALITY,
    ))
    .expect("eq term");
    let native = block_on(cipher.equality_term(42u32, "users/age")).expect("native eq");
    assert_eq!(eq, native.as_bytes());

    let ore = block_on(ops::term(
        &cipher,
        &encode(FfiValue::UInt32(42)),
        ctx,
        TERM_ORE,
    ))
    .expect("ore term");
    let native = block_on(cipher.ore_term(42u32, "users/age")).expect("native ore");
    assert_eq!(ore, native.as_ref());

    let ope = block_on(ops::term(
        &cipher,
        &encode(FfiValue::UInt32(42)),
        ctx,
        TERM_OPE,
    ))
    .expect("ope term");
    let native = block_on(cipher.ope_term(42u32, "users/age")).expect("native ope");
    assert_eq!(ope, native.as_ref());

    let m = block_on(ops::term(
        &cipher,
        &encode(s("alice smith")),
        b"users/name",
        TERM_MATCH,
    ))
    .expect("match term");
    let native =
        block_on(cipher.match_terms::<DefaultMatch>("alice smith", "users/name")).expect("native");
    assert_eq!(m, native.to_bytes());

    // Strings and bytes have distinct PRF encodings — the guest must keep
    // them apart even when their raw bytes are equal.
    let eq_text =
        block_on(ops::term(&cipher, &encode(s("ab")), b"f", TERM_EQUALITY)).expect("text term");
    let eq_bytes = block_on(ops::term(
        &cipher,
        &encode(FfiValue::Bytes(Protected::new(b"ab".to_vec()))),
        b"f",
        TERM_EQUALITY,
    ))
    .expect("bytes term");
    assert_ne!(eq_text, eq_bytes);
    let native_text = block_on(cipher.equality_term("ab".to_string(), "f")).expect("native");
    assert_eq!(eq_text, native_text.as_bytes());
    let native_bytes =
        block_on(cipher.equality_term(Protected::new(b"ab".to_vec()), "f")).expect("native");
    assert_eq!(eq_bytes, native_bytes.as_bytes());

    // Variable-width CLLW output for strings.
    let ore_s = block_on(ops::term(
        &cipher,
        &encode(s("alice")),
        b"users/name",
        TERM_ORE,
    ))
    .expect("string ore");
    assert_eq!(ore_s.len(), 5 * 8);

    // No ZeroKMS traffic for any of it.
    assert_eq!(cipher.kms().generate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(cipher.kms().retrieve_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn unsupported_term_inputs_are_encoding_errors() {
    let cipher = cipher();
    let ctx = b"f".as_slice();

    // Floats and bools have no equality encoding; match is text-only;
    // containers have no term semantics; kinds outside the table and empty
    // contexts are rejected.
    for (value, kind) in [
        (FfiValue::Float64(1.5), TERM_EQUALITY),
        (FfiValue::Bool(true), TERM_EQUALITY),
        (FfiValue::UInt32(1), TERM_MATCH),
        (FfiValue::Array(vec![]), TERM_ORE),
        (FfiValue::Null, TERM_EQUALITY),
        (FfiValue::UInt32(1), 99),
    ] {
        assert_eq!(
            block_on(ops::term(&cipher, &encode(value), ctx, kind)),
            Err(STATUS_ENCODING),
            "kind {kind}"
        );
    }
    assert_eq!(
        block_on(ops::term(
            &cipher,
            &encode(FfiValue::UInt32(1)),
            b"",
            TERM_EQUALITY
        )),
        Err(STATUS_ENCODING),
        "empty context"
    );
}

// =============================================================================
// Records
// =============================================================================

#[test]
fn a_record_batch_encrypts_in_one_call_and_round_trips() {
    let cipher = cipher();
    let source = encode(FfiValue::Array(vec![
        row(29, "alice smith"),
        row(34, "bob jones"),
        row(41, "carol park"),
    ]));

    let record = block_on(ops::encrypt_record(&cipher, &source, &plan())).expect("encrypt records");
    // Three rows, two ciphertext fields each: still exactly one call.
    assert_eq!(cipher.kms().generate_calls.load(Ordering::SeqCst), 1);

    let pt = block_on(ops::decrypt_record(&cipher, &record, &plan())).expect("decrypt records");
    assert_eq!(cipher.kms().retrieve_calls.load(Ordering::SeqCst), 1);

    let FfiValue::Array(rows) = decode(&pt) else {
        panic!("expected an array of rows back");
    };
    assert_eq!(rows.len(), 3);
    let FfiValue::Object(fields) = &rows[1] else {
        panic!("expected an object row");
    };
    assert_eq!(fields[0].0, "age");
    assert!(matches!(fields[0].1, FfiValue::UInt32(34)));
    assert_eq!(fields[1].0, "name");
    assert_eq!(text(&fields[1].1), "bob jones");
}

#[test]
fn record_terms_equal_the_native_derivations_and_probe_them() {
    let cipher = cipher();
    let record = block_on(ops::encrypt_record(
        &cipher,
        &encode(row(34, "alice smith")),
        &plan(),
    ))
    .expect("encrypt record");

    let CipherText::Map(fields) = decode_tree(&record) else {
        panic!("expected a field map");
    };
    assert_eq!(fields.len(), 2);
    let (age_name, CipherText::Map(age_outputs)) = &fields[0] else {
        panic!("expected an output map for the first field");
    };
    assert_eq!(age_name, "age");
    assert_eq!(
        age_outputs
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>(),
        vec!["c", "eq", "ore"],
        "output order is the plan's"
    );

    let term_bytes = |node: &CipherText<Vec<u8>, FfiValue>| -> Vec<u8> {
        let CipherText::Passthrough(FfiValue::Bytes(b)) = node else {
            panic!("expected a passthrough bytes term node");
        };
        b.risky_ref().to_vec()
    };

    // The stored terms are byte-identical to query-time probes built the
    // native way — the property that makes the index searchable.
    let eq_probe = block_on(cipher.equality_term(34u32, "users/age")).expect("probe");
    assert_eq!(term_bytes(&age_outputs[1].1), eq_probe.as_bytes());
    let ore_probe = block_on(cipher.ore_term(34u32, "users/age")).expect("probe");
    assert_eq!(term_bytes(&age_outputs[2].1), ore_probe.as_ref());

    let (_, CipherText::Map(name_outputs)) = &fields[1] else {
        panic!("expected an output map for the second field");
    };
    let match_probe =
        block_on(cipher.match_terms::<DefaultMatch>("alice smith", "users/name")).expect("probe");
    assert_eq!(term_bytes(&name_outputs[1].1), match_probe.to_bytes());

    // And the "c" node is an ordinary value-model ciphertext bound to the
    // field's context.
    let CipherText::Single(leaf) = &age_outputs[0].1 else {
        panic!("expected a single leaf for a scalar field");
    };
    let leaf = SealedValue::from_bytes(leaf).expect("frozen leaf");
    let decipher =
        block_on(cipher.decipher(CipherText::Single(leaf))).expect("retrieve the data key");
    let value = FfiValue::decrypt_with_aad(decipher, "users/age")
        .expect("native decrypt of a record field");
    assert!(matches!(value, FfiValue::UInt32(34)));
}

#[test]
fn record_shape_violations_are_encoding_errors() {
    let cipher = cipher();

    // A field missing from the row, an extra field, a non-scalar term
    // source, and malformed plans.
    let missing = encode(obj(vec![("age", FfiValue::UInt32(1))]));
    assert_eq!(
        block_on(ops::encrypt_record(&cipher, &missing, &plan())),
        Err(STATUS_ENCODING)
    );

    let extra = encode(obj(vec![
        ("age", FfiValue::UInt32(1)),
        ("name", s("a")),
        ("stray", s("b")),
    ]));
    assert_eq!(
        block_on(ops::encrypt_record(&cipher, &extra, &plan())),
        Err(STATUS_ENCODING)
    );

    let nested = encode(obj(vec![
        ("age", FfiValue::Array(vec![FfiValue::UInt32(1)])),
        ("name", s("a")),
    ]));
    assert_eq!(
        block_on(ops::encrypt_record(&cipher, &nested, &plan())),
        Err(STATUS_ENCODING),
        "a term-indexed field must be a scalar"
    );

    for bad_plan in [
        obj(vec![]),                                      // empty
        obj(vec![("f", obj(vec![("context", s("c"))]))]), // no outputs
        obj(vec![(
            "f",
            obj(vec![
                ("context", s("")),
                ("outputs", FfiValue::Array(vec![s("c")])),
            ]),
        )]), // empty context
        obj(vec![(
            "f",
            obj(vec![
                ("context", s("c")),
                ("outputs", FfiValue::Array(vec![s("nope")])),
            ]),
        )]), // unknown output
        obj(vec![(
            "f",
            obj(vec![
                ("context", s("c")),
                ("outputs", FfiValue::Array(vec![s("eq"), s("eq")])),
            ]),
        )]), // duplicate output
    ] {
        assert_eq!(
            block_on(ops::encrypt_record(
                &cipher,
                &encode(obj(vec![("f", FfiValue::UInt32(1))])),
                &encode(bad_plan),
            )),
            Err(STATUS_ENCODING)
        );
    }

    // No data keys were minted for any rejected call.
    assert_eq!(cipher.kms().generate_calls.load(Ordering::SeqCst), 0);
}

/// A context that is not byte-empty but still carries nothing — the PAE of an
/// empty list, i.e. eight zero bytes, which is what `None` and `0u64` encode
/// to — must be rejected at plan-parse time.
///
/// Without the check the two record paths disagree: `encrypt_record` seals
/// through the cipher-directed path, which does not run stack-encrypt's
/// context predicate, while `decrypt_record` opens through `decrypt_into`,
/// which does. The row would encrypt and then never decrypt.
#[test]
fn a_degenerate_plan_context_is_refused_before_anything_is_sealed() {
    let cipher = cipher();
    let degenerate = String::from_utf8(vec![0u8; 8]).expect("nul bytes are valid utf-8");
    let bad_plan = encode(obj(vec![(
        "f",
        obj(vec![
            ("context", s(&degenerate)),
            ("outputs", FfiValue::Array(vec![s("c")])),
        ]),
    )]));
    let source = encode(obj(vec![("f", FfiValue::UInt32(1))]));

    assert_eq!(
        block_on(ops::encrypt_record(&cipher, &source, &bad_plan)),
        Err(STATUS_ENCODING)
    );
    assert_eq!(
        cipher.kms().generate_calls.load(Ordering::SeqCst),
        0,
        "a context that could never be decrypted under must not seal"
    );

    // And the decrypt side agrees, so neither half can drift into accepting
    // what the other refuses.
    assert_eq!(
        block_on(ops::decrypt_record(&cipher, &source, &bad_plan)),
        Err(STATUS_ENCODING)
    );
}
