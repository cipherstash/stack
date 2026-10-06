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

use std::future::IntoFuture;

use stack_encrypt::dynamic::Scope;
use stack_encrypt::sem::DefaultMatch;
use stack_encrypt::{nonempty, CipherText, Encrypt, Label, SealedValue, StackCipher};
use stack_encrypt_guest::ops::{self, TERM_EQUALITY, TERM_MATCH, TERM_OPE, TERM_ORE};
use stack_encrypt_guest::status::{
    STATUS_AUTH, STATUS_CONTEXT_MISMATCH, STATUS_ENCODING, STATUS_FOREIGN_KEYSET,
};
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyPayload, IndexKeySource,
    RetrieveKeyPayload,
};
use uuid::Uuid;
use vitaminc_aead_value::{transport as codec, FfiValue};
use vitaminc_protected::{Controlled, Protected};
use zerokms_protocol::{IdentifiedBy, UnverifiedContext};

/// `futures::executor::block_on` over anything awaitable: the term API
/// returns a `Pending`, which is `IntoFuture` rather than `Future`.
fn block_on<F: IntoFuture>(f: F) -> F::Output {
    futures::executor::block_on(f.into_future())
}

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

/// The label `users/<field>` as a plan field spells its context: a list of
/// plain segments, what a Go `label=users/<field>` tag sends.
fn label(field: &str) -> FfiValue {
    FfiValue::Array(vec![s("users"), s(field)])
}

/// The plan shape the record tests share — an ORE-indexed integer and a
/// match-indexed string, both stored — under whatever context `ctx` gives
/// each field. Output order is fixed here, and the tests index into it.
fn plan_under(ctx: impl Fn(&str) -> FfiValue) -> Vec<u8> {
    encode(obj(vec![
        (
            "age",
            obj(vec![
                ("context", ctx("age")),
                ("outputs", FfiValue::Array(vec![s("c"), s("eq"), s("ore")])),
            ]),
        ),
        (
            "name",
            obj(vec![
                ("context", ctx("name")),
                ("outputs", FfiValue::Array(vec![s("c"), s("match")])),
            ]),
        ),
    ]))
}

/// The plan used by the record tests: `plan_under` with each field's label.
fn plan() -> Vec<u8> {
    plan_under(label)
}

/// A one-field plan storing only the ciphertext, under `context`.
fn single_field_plan(field: &str, context: FfiValue) -> Vec<u8> {
    encode(obj(vec![(
        field,
        obj(vec![
            ("context", context),
            ("outputs", FfiValue::Array(vec![s("c")])),
        ]),
    )]))
}

/// The bytes of a term node in a decoded record tree.
fn term_bytes(node: &CipherText<Vec<u8>, FfiValue>) -> Vec<u8> {
    let CipherText::Passthrough(FfiValue::Bytes(b)) = node else {
        panic!("expected a passthrough bytes term node");
    };
    b.risky_ref().to_vec()
}

fn row(age: u32, name: &str) -> FfiValue {
    obj(vec![("age", FfiValue::UInt32(age)), ("name", s(name))])
}

// =============================================================================
// Values
// =============================================================================

// =============================================================================
// Terms
// =============================================================================

#[test]
fn guest_terms_match_the_native_sem_derivations() {
    let cipher = cipher();
    let ctx = encode(s("users/age"));

    let eq = block_on(ops::term(
        &cipher.default_keyset(),
        &encode(FfiValue::UInt32(42)),
        &ctx,
        TERM_EQUALITY,
    ))
    .expect("eq term");
    let native = block_on(
        cipher
            .default_keyset()
            .equality_term(42u32, nonempty!("users/age")),
    )
    .expect("native eq");
    assert_eq!(eq, native.as_bytes());

    let ore = block_on(ops::term(
        &cipher.default_keyset(),
        &encode(FfiValue::UInt32(42)),
        &ctx,
        TERM_ORE,
    ))
    .expect("ore term");
    let native = block_on(
        cipher
            .default_keyset()
            .ore_term(42u32, nonempty!("users/age")),
    )
    .expect("native ore");
    assert_eq!(ore, native.as_ref());

    let ope = block_on(ops::term(
        &cipher.default_keyset(),
        &encode(FfiValue::UInt32(42)),
        &ctx,
        TERM_OPE,
    ))
    .expect("ope term");
    let native = block_on(
        cipher
            .default_keyset()
            .ope_term(42u32, nonempty!("users/age")),
    )
    .expect("native ope");
    assert_eq!(ope, native.as_ref());

    let m = block_on(ops::term(
        &cipher.default_keyset(),
        &encode(s("alice smith")),
        &encode(s("users/name")),
        TERM_MATCH,
    ))
    .expect("match term");
    let native = block_on(
        cipher
            .default_keyset()
            .match_terms::<DefaultMatch>("alice smith", nonempty!("users/name")),
    )
    .expect("native");
    assert_eq!(m, native.to_bytes());

    // Strings and bytes have distinct PRF encodings — the guest must keep
    // them apart even when their raw bytes are equal.
    let eq_text = block_on(ops::term(
        &cipher.default_keyset(),
        &encode(s("ab")),
        &encode(s("f")),
        TERM_EQUALITY,
    ))
    .expect("text term");
    let eq_bytes = block_on(ops::term(
        &cipher.default_keyset(),
        &encode(FfiValue::Bytes(Protected::new(b"ab".to_vec()))),
        &encode(s("f")),
        TERM_EQUALITY,
    ))
    .expect("bytes term");
    assert_ne!(eq_text, eq_bytes);
    let native_text = block_on(
        cipher
            .default_keyset()
            .equality_term("ab".to_string(), nonempty!("f")),
    )
    .expect("native");
    assert_eq!(eq_text, native_text.as_bytes());
    let native_bytes = block_on(
        cipher
            .default_keyset()
            .equality_term(Protected::new(b"ab".to_vec()), nonempty!("f")),
    )
    .expect("native");
    assert_eq!(eq_bytes, native_bytes.as_bytes());

    // Variable-width CLLW output for strings.
    let ore_s = block_on(ops::term(
        &cipher.default_keyset(),
        &encode(s("alice")),
        &encode(s("users/name")),
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
    let ctx = encode(s("f"));

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
            block_on(ops::term(
                &cipher.default_keyset(),
                &encode(value),
                &ctx,
                kind
            )),
            Err(STATUS_ENCODING),
            "kind {kind}"
        );
    }
    assert_eq!(
        block_on(ops::term(
            &cipher.default_keyset(),
            &encode(FfiValue::UInt32(1)),
            &encode(s("")),
            TERM_EQUALITY
        )),
        Err(STATUS_ENCODING),
        "empty context"
    );

    // The context is codec-encoded, not raw text: the pre-structured form
    // must be refused at the boundary, not read as a flat context; and a
    // codec value that is not a context must be refused too.
    for (label, context) in [
        ("raw utf-8 bytes", b"f".to_vec()),
        ("a boolean", encode(FfiValue::Bool(true))),
        ("an object", encode(obj(vec![("k", s("v"))]))),
    ] {
        assert_eq!(
            block_on(ops::term(
                &cipher.default_keyset(),
                &encode(FfiValue::UInt32(1)),
                &context,
                TERM_EQUALITY
            )),
            Err(STATUS_ENCODING),
            "a term context of {label} must be refused"
        );
    }
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

    let record = block_on(ops::encrypt_record(
        &cipher.default_keyset(),
        &source,
        &plan(),
    ))
    .expect("encrypt records");
    // Three rows, two ciphertext fields each: still exactly one call.
    assert_eq!(cipher.kms().generate_calls.load(Ordering::SeqCst), 1);

    let pt = block_on(ops::decrypt_record(
        Scope::Client(&cipher),
        &record,
        &plan(),
        None,
    ))
    .expect("decrypt records");
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

/// The forgery that motivates `reject_passthrough_tree`: an attacker with
/// write access to the stored tree swaps a field's `"c"` subtree for a
/// passthrough carrying chosen plaintext. `decrypt_into` opens no AEAD for a
/// passthrough, so without the rejection this would come back as a
/// *successful* decrypt of attacker-chosen bytes.
#[test]
fn a_forged_passthrough_ciphertext_slot_is_rejected_not_decrypted() {
    let cipher = cipher();
    let source = encode(row(29, "alice smith"));
    let record = block_on(ops::encrypt_record(
        &cipher.default_keyset(),
        &source,
        &plan(),
    ))
    .expect("encrypt record");

    let CipherText::Map(mut fields) = decode_tree(&record) else {
        panic!("expected a field map");
    };
    for (field, node) in &mut fields {
        if field != "age" {
            continue;
        }
        let CipherText::Map(outputs) = node else {
            panic!("expected an output map");
        };
        for (key, slot) in outputs.iter_mut() {
            if key == "c" {
                *slot = CipherText::Passthrough(FfiValue::UInt32(99));
            }
        }
    }
    let mut forged = Vec::new();
    codec::encode_ciphertext(&CipherText::Map(fields), &mut forged).expect("re-encode");

    assert_eq!(
        block_on(ops::decrypt_record(
            Scope::Client(&cipher),
            &forged,
            &plan(),
            None
        )),
        Err(STATUS_ENCODING),
        "a passthrough in a ciphertext slot must be a hard error, never plaintext"
    );
}

/// The encrypt-side half of the same invariant: a source value containing a
/// passthrough must not reach a `"c"` slot (it would seal nothing for those
/// bytes), even nested inside a container.
#[test]
fn a_passthrough_source_value_is_refused_a_ciphertext_slot() {
    let cipher = cipher();
    for age in [
        FfiValue::Passthrough(Box::new(FfiValue::UInt32(29))),
        FfiValue::Array(vec![FfiValue::Passthrough(Box::new(FfiValue::UInt32(29)))]),
    ] {
        // A ciphertext-only plan, so the term path's own scalar rejection
        // cannot mask the one under test.
        let plan = encode(obj(vec![(
            "age",
            obj(vec![
                ("context", label("age")),
                ("outputs", FfiValue::Array(vec![s("c")])),
            ]),
        )]));
        let source = encode(obj(vec![("age", age)]));
        assert_eq!(
            block_on(ops::encrypt_record(
                &cipher.default_keyset(),
                &source,
                &plan
            )),
            Err(STATUS_ENCODING)
        );
    }
}

#[test]
fn record_terms_equal_the_native_derivations_and_probe_them() {
    let cipher = cipher();
    let record = block_on(ops::encrypt_record(
        &cipher.default_keyset(),
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

    // The stored terms are byte-identical to query-time probes built the
    // native way — the property that makes the index searchable.
    let eq_probe = block_on(
        cipher
            .default_keyset()
            .equality_term(34u32, nonempty!("users").with("age")),
    )
    .expect("probe");
    assert_eq!(term_bytes(&age_outputs[1].1), eq_probe.as_bytes());
    let ore_probe = block_on(
        cipher
            .default_keyset()
            .ore_term(34u32, nonempty!("users").with("age")),
    )
    .expect("probe");
    assert_eq!(term_bytes(&age_outputs[2].1), ore_probe.as_ref());

    let (_, CipherText::Map(name_outputs)) = &fields[1] else {
        panic!("expected an output map for the second field");
    };
    let match_probe = block_on(
        cipher
            .default_keyset()
            .match_terms::<DefaultMatch>("alice smith", nonempty!("users").with("name")),
    )
    .expect("probe");
    assert_eq!(term_bytes(&name_outputs[1].1), match_probe.to_bytes());

    // And the "c" node is an ordinary value-model ciphertext bound to the
    // field's label.
    let CipherText::Single(leaf) = &age_outputs[0].1 else {
        panic!("expected a single leaf for a scalar field");
    };
    let leaf = SealedValue::from_bytes(leaf).expect("frozen leaf");
    let value: FfiValue =
        block_on(cipher.decrypt(CipherText::Single(leaf), nonempty!("users").with("age")))
            .expect("native decrypt of a record field");
    assert!(matches!(value, FfiValue::UInt32(34)));
}

// =============================================================================
// Structured contexts
// =============================================================================

/// The caller extension a Rust row gets from the chain's `.extend(7u64)`:
/// every field's label becomes `(users/<field>)/7u64`. A plan spells it as a
/// list, the label nested inside.
fn extended(field: &str) -> FfiValue {
    FfiValue::Array(vec![label(field), FfiValue::UInt64(7)])
}

/// `plan()` under the extension.
fn extended_plan() -> Vec<u8> {
    plan_under(extended)
}

/// A plan whose context is a list seals exactly what the Rust derive seals
/// under a caller-extended context: the stored terms are the native probes
/// under `nonempty!("users").with("age").with(7u64)`, the guest's own probe
/// under the list is the same bytes, and the `"c"` leaf opens natively under
/// the tuple. The flat label is a different domain, as it must be.
#[test]
fn a_structured_plan_context_seals_what_the_native_extended_context_does() {
    let cipher = cipher();
    let record = block_on(ops::encrypt_record(
        &cipher.default_keyset(),
        &encode(row(34, "alice smith")),
        &extended_plan(),
    ))
    .expect("encrypt record");

    let CipherText::Map(fields) = decode_tree(&record) else {
        panic!("expected a field map");
    };
    let (_, CipherText::Map(age_outputs)) = &fields[0] else {
        panic!("expected an output map for the first field");
    };

    let native = nonempty!("users").with("age").with(7u64);
    let eq_probe = block_on(cipher.default_keyset().equality_term(34u32, native)).expect("probe");
    assert_eq!(term_bytes(&age_outputs[1].1), eq_probe.as_bytes());
    let ore_probe = block_on(cipher.default_keyset().ore_term(34u32, native)).expect("probe");
    assert_eq!(term_bytes(&age_outputs[2].1), ore_probe.as_ref());
    let flat_probe = block_on(
        cipher
            .default_keyset()
            .equality_term(34u32, nonempty!("users").with("age")),
    )
    .expect("probe");
    assert_ne!(
        term_bytes(&age_outputs[1].1),
        flat_probe.as_bytes(),
        "the extension domain-separates from the flat context"
    );

    let guest_probe = block_on(ops::term(
        &cipher.default_keyset(),
        &encode(FfiValue::UInt32(34)),
        &encode(extended("age")),
        TERM_EQUALITY,
    ))
    .expect("guest probe");
    assert_eq!(term_bytes(&age_outputs[1].1), guest_probe);

    let (_, CipherText::Map(name_outputs)) = &fields[1] else {
        panic!("expected an output map for the second field");
    };
    let match_probe = block_on(
        cipher
            .default_keyset()
            .match_terms::<DefaultMatch>("alice smith", nonempty!("users").with("name").with(7u64)),
    )
    .expect("probe");
    assert_eq!(term_bytes(&name_outputs[1].1), match_probe.to_bytes());

    let CipherText::Single(leaf) = &age_outputs[0].1 else {
        panic!("expected a single leaf for a scalar field");
    };
    let leaf = SealedValue::from_bytes(leaf).expect("frozen leaf");
    let value: FfiValue = block_on(cipher.decrypt(CipherText::Single(leaf), native))
        .expect("native decrypt under the tuple");
    assert!(matches!(value, FfiValue::UInt32(34)));
}

/// The reverse direction: a field sealed natively under the tuple — as a
/// Rust row sealed with a caller context is — opens through a plan whose
/// context is the same list, and not through the flat plan.
#[test]
fn a_natively_sealed_field_under_an_extended_context_opens_through_a_plan() {
    let cipher = cipher();
    let keyset = cipher.default_keyset();
    let native = nonempty!("users").with("age").with(7u64);
    let sealed = block_on(
        FfiValue::UInt32(34)
            .encrypt_with_aad(&keyset, native)
            .expect("encrypt")
            .seal(&keyset, native),
    )
    .expect("seal");
    let CipherText::Single(leaf) = sealed else {
        panic!("a scalar seals to a single leaf");
    };

    // Shape the tree the way `encrypt_record` writes it: field → { c: leaf }.
    let tree: CipherText<Vec<u8>, FfiValue> = CipherText::Map(vec![(
        "age".to_string(),
        CipherText::Map(vec![("c".to_string(), CipherText::Single(leaf.to_bytes()))]),
    )]);
    let mut record = Vec::new();
    codec::encode_ciphertext(&tree, &mut record).expect("encode tree");

    let plan_with = |context: FfiValue| single_field_plan("age", context);

    let opened = block_on(ops::decrypt_record(
        Scope::Client(&cipher),
        &record,
        &plan_with(extended("age")),
        None,
    ))
    .expect("open through the plan");
    let FfiValue::Object(fields) = decode(&opened) else {
        panic!("a record decrypts to an object");
    };
    assert!(matches!(fields.as_slice(), [(name, FfiValue::UInt32(34))] if name == "age"));

    assert_eq!(
        block_on(ops::decrypt_record(
            Scope::Client(&cipher),
            &record,
            &plan_with(label("age")),
            None
        )),
        Err(STATUS_AUTH),
        "the flat label is not the one it was sealed under"
    );
}

/// A plan context that is not a context — the wrong value kind, or empty
/// by the tuple rule — or that is a context but not a field's label is
/// refused at parse, before anything is sealed.
#[test]
fn a_structured_plan_context_is_validated_at_parse() {
    let cipher = cipher();
    let plan_with = |context: FfiValue| single_field_plan("f", context);
    let source = encode(obj(vec![("f", FfiValue::UInt32(1))]));

    for (label, bad) in [
        ("a boolean", FfiValue::Bool(true)),
        ("a float", FfiValue::Float64(7.0)),
        ("an object", FfiValue::Object(vec![])),
        ("an empty list", FfiValue::Array(vec![])),
        ("a list of one empty string", FfiValue::Array(vec![s("")])),
        (
            "a list with a float in it",
            FfiValue::Array(vec![label("age"), FfiValue::Float64(7.0)]),
        ),
        ("one text part, not a label", s("users/age")),
        ("a one-segment label", FfiValue::Array(vec![s("users")])),
        ("an integer", FfiValue::UInt64(7)),
    ] {
        assert_eq!(
            block_on(ops::encrypt_record(
                &cipher.default_keyset(),
                &source,
                &plan_with(bad)
            )),
            Err(STATUS_ENCODING),
            "a plan context of {label} must be refused at parse"
        );
    }
    assert_eq!(
        cipher.kms().generate_calls.load(Ordering::SeqCst),
        0,
        "nothing seals under a context that is not one"
    );

    // An extension part may be empty: the label carries the context, as a
    // Go `Context.With("")` extends one.
    let sealed = block_on(ops::encrypt_record(
        &cipher.default_keyset(),
        &source,
        &plan_with(FfiValue::Array(vec![label("f"), s("")])),
    ))
    .expect("a label extended by an empty part is never empty");
    assert!(block_on(ops::decrypt_record(
        Scope::Client(&cipher),
        &sealed,
        &plan_with(FfiValue::Array(vec![label("f"), s("")])),
        None
    ))
    .is_ok());
}

#[test]
fn record_shape_violations_are_encoding_errors() {
    let cipher = cipher();

    // A field missing from the row, an extra field, a non-scalar term
    // source, and malformed plans.
    let missing = encode(obj(vec![("age", FfiValue::UInt32(1))]));
    assert_eq!(
        block_on(ops::encrypt_record(
            &cipher.default_keyset(),
            &missing,
            &plan()
        )),
        Err(STATUS_ENCODING)
    );

    let extra = encode(obj(vec![
        ("age", FfiValue::UInt32(1)),
        ("name", s("a")),
        ("stray", s("b")),
    ]));
    assert_eq!(
        block_on(ops::encrypt_record(
            &cipher.default_keyset(),
            &extra,
            &plan()
        )),
        Err(STATUS_ENCODING)
    );

    let nested = encode(obj(vec![
        ("age", FfiValue::Array(vec![FfiValue::UInt32(1)])),
        ("name", s("a")),
    ]));
    assert_eq!(
        block_on(ops::encrypt_record(
            &cipher.default_keyset(),
            &nested,
            &plan()
        )),
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
                &cipher.default_keyset(),
                &encode(obj(vec![("f", FfiValue::UInt32(1))])),
                &encode(bad_plan),
            )),
            Err(STATUS_ENCODING)
        );
    }

    // No data keys were minted for any rejected call.
    assert_eq!(cipher.kms().generate_calls.load(Ordering::SeqCst), 0);
}

/// An empty plan context is refused at plan-parse time, before anything is
/// sealed — and on both record paths, so neither half can drift into
/// accepting what the other refuses. (`encrypt_record` seals through the
/// cipher-directed path, which accepts any AAD; `decrypt_record` opens
/// through `decrypt_into`, which takes a `NonEmpty<_>`: proving the context
/// once, at parse, is what keeps a row from encrypting and then never
/// decrypting.)
#[test]
fn an_empty_plan_context_is_refused_before_anything_is_sealed() {
    let cipher = cipher();
    let bad_plan = encode(obj(vec![(
        "f",
        obj(vec![
            ("context", s("")),
            ("outputs", FfiValue::Array(vec![s("c")])),
        ]),
    )]));
    let source = encode(obj(vec![("f", FfiValue::UInt32(1))]));

    assert_eq!(
        block_on(ops::encrypt_record(
            &cipher.default_keyset(),
            &source,
            &bad_plan
        )),
        Err(STATUS_ENCODING)
    );
    assert_eq!(
        cipher.kms().generate_calls.load(Ordering::SeqCst),
        0,
        "a context that could never be decrypted under must not seal"
    );
    assert_eq!(
        block_on(ops::decrypt_record(
            Scope::Client(&cipher),
            &source,
            &bad_plan,
            None
        )),
        Err(STATUS_ENCODING)
    );

    // A label of unusual but plain text is still a label: it seals, and
    // opens. (Control characters are not plain, so a NUL is refused at
    // parse as any non-label is.)
    let odd_plan = encode(obj(vec![(
        "f",
        obj(vec![
            ("context", FfiValue::Array(vec![s("naïve users"), s("f")])),
            ("outputs", FfiValue::Array(vec![s("c")])),
        ]),
    )]));
    let sealed = block_on(ops::encrypt_record(
        &cipher.default_keyset(),
        &source,
        &odd_plan,
    ))
    .expect("encrypt");
    let opened = block_on(ops::decrypt_record(
        Scope::Client(&cipher),
        &sealed,
        &odd_plan,
        None,
    ))
    .expect("decrypt");
    let FfiValue::Object(fields) = decode(&opened) else {
        panic!("a record decrypts to an object");
    };
    assert!(matches!(fields.as_slice(), [(name, FfiValue::UInt32(1))] if name == "f"));
}

// =============================================================================
// Keysets: the scope a call selects
// =============================================================================

fn keyset_named<'c>(
    cipher: &'c StackCipher<Counting>,
    name: &str,
) -> stack_encrypt::KeysetCipher<'c, Counting> {
    block_on(cipher.keyset(IdentifiedBy::Name(name.to_string().into()))).expect("select keyset")
}

/// A record batch whose rows were sealed under different keysets opens
/// through `{"any"}` in one call per keyset, and not through one keyset.
#[test]
fn a_mixed_keyset_record_batch_opens_through_any_one_call_per_keyset() {
    let cipher = cipher();
    let acme = keyset_named(&cipher, "acme");
    let globex = keyset_named(&cipher, "globex");

    // One row per tenant, sealed separately; a host stores them side by
    // side and reads them back as one batch.
    let acme_rows = block_on(ops::encrypt_record(
        &acme,
        &encode(row(29, "alice smith")),
        &plan(),
    ))
    .expect("encrypt acme row");
    let globex_rows = block_on(ops::encrypt_record(
        &globex,
        &encode(row(34, "bob jones")),
        &plan(),
    ))
    .expect("encrypt globex row");
    let batch = {
        let (CipherText::Map(a), CipherText::Map(g)) = (
            codec::decode_ciphertext_boxed::<Vec<u8>>(&mut codec::Reader::new(&acme_rows))
                .expect("decode"),
            codec::decode_ciphertext_boxed::<Vec<u8>>(&mut codec::Reader::new(&globex_rows))
                .expect("decode"),
        ) else {
            panic!("a single record is a map");
        };
        let mut out = Vec::new();
        codec::encode_ciphertext_boxed(
            CipherText::Sequence(vec![CipherText::Map(a), CipherText::Map(g)]),
            &mut out,
        )
        .expect("encode batch");
        out
    };

    let before = cipher.kms().retrieve_calls.load(Ordering::SeqCst);
    let pt = block_on(ops::decrypt_record(
        Scope::Client(&cipher),
        &batch,
        &plan(),
        None,
    ))
    .expect("any opens the mixed batch");
    assert_eq!(
        cipher.kms().retrieve_calls.load(Ordering::SeqCst) - before,
        2,
        "one retrieve per keyset"
    );
    let FfiValue::Array(rows) = decode(&pt) else {
        panic!("expected an array of rows back");
    };
    assert_eq!(rows.len(), 2);

    let before = cipher.kms().retrieve_calls.load(Ordering::SeqCst);
    assert_eq!(
        block_on(ops::decrypt_record(
            Scope::Keyset(acme),
            &batch,
            &plan(),
            None
        )),
        Err(STATUS_FOREIGN_KEYSET)
    );
    assert_eq!(cipher.kms().retrieve_calls.load(Ordering::SeqCst), before);
}

/// Terms derive under the selected keyset's index key: the same probe
/// under two keysets differs, and matches the native derivation for each.
#[test]
fn terms_derive_under_the_selected_keyset() {
    let cipher = cipher();
    let acme = keyset_named(&cipher, "acme");
    let globex = keyset_named(&cipher, "globex");
    let ctx = encode(s("users/age"));

    let acme_term = block_on(ops::term(
        &acme,
        &encode(FfiValue::UInt32(42)),
        &ctx,
        TERM_EQUALITY,
    ))
    .expect("acme term");
    let globex_term = block_on(ops::term(
        &globex,
        &encode(FfiValue::UInt32(42)),
        &ctx,
        TERM_EQUALITY,
    ))
    .expect("globex term");
    assert_ne!(acme_term, globex_term);

    let native = block_on(acme.equality_term(42u32, nonempty!("users/age"))).expect("native");
    assert_eq!(acme_term, native.into_bytes().to_vec());
}

// =============================================================================
// Validation precedence
// =============================================================================

/// The ABI runs `ops::validate` on every input before it consults the
/// cipher, so a malformed call must be refused there — not by the operation
/// after a keyset has been resolved. These pin that the validators reject
/// exactly the inputs the operations reject as `STATUS_ENCODING`, on a
/// static path that needs no cipher at all, and accept what the operations
/// accept.
#[test]
fn term_validation_refuses_what_the_term_op_refuses() {
    let cipher = cipher();
    let ctx = encode(s("f"));

    for (label, value, kind) in [
        (
            "a float under equality",
            FfiValue::Float64(1.5),
            TERM_EQUALITY,
        ),
        ("a bool under equality", FfiValue::Bool(true), TERM_EQUALITY),
        ("an integer under match", FfiValue::UInt32(1), TERM_MATCH),
        ("a container", FfiValue::Array(vec![]), TERM_ORE),
        ("an object", obj(vec![("k", s("v"))]), TERM_EQUALITY),
        ("null", FfiValue::Null, TERM_OPE),
        ("an unknown kind", FfiValue::UInt32(1), 99),
    ] {
        let value = encode(value);
        assert_eq!(
            ops::validate::term(&value, &ctx, kind),
            Err(STATUS_ENCODING),
            "{label} must be refused by validation"
        );
        assert_eq!(
            block_on(ops::term(&cipher.default_keyset(), &value, &ctx, kind)),
            Err(STATUS_ENCODING),
            "{label} must be refused by the op too"
        );
    }
    for (label, context) in [
        ("an empty context", encode(s(""))),
        (
            "a context that is not a context",
            encode(FfiValue::Bool(true)),
        ),
        ("raw bytes for a context", b"f".to_vec()),
    ] {
        assert_eq!(
            ops::validate::term(&encode(FfiValue::UInt32(1)), &context, TERM_EQUALITY),
            Err(STATUS_ENCODING),
            "{label} must be refused by validation"
        );
    }

    // Every pair the scheme defines passes.
    for (value, kind) in [
        (FfiValue::UInt32(1), TERM_EQUALITY),
        (FfiValue::Int64(-1), TERM_EQUALITY),
        (s("x"), TERM_EQUALITY),
        (FfiValue::Bytes(Protected::new(vec![1])), TERM_EQUALITY),
        (s("x y"), TERM_MATCH),
        (FfiValue::Float64(1.5), TERM_ORE),
        (FfiValue::Bool(true), TERM_OPE),
        (s("x"), TERM_ORE),
    ] {
        assert_eq!(ops::validate::term(&encode(value), &ctx, kind), Ok(()));
    }
}

#[test]
fn record_validation_refuses_what_encrypt_record_refuses() {
    let cipher = cipher();
    let plan = plan();

    for (label, source) in [
        ("a missing field", obj(vec![("age", FfiValue::UInt32(1))])),
        (
            "an extra field",
            obj(vec![
                ("age", FfiValue::UInt32(1)),
                ("name", s("a")),
                ("stray", s("b")),
            ]),
        ),
        (
            "a container under a term output",
            obj(vec![
                ("age", FfiValue::Array(vec![FfiValue::UInt32(1)])),
                ("name", s("a")),
            ]),
        ),
        (
            "a float under equality",
            obj(vec![("age", FfiValue::Float64(1.0)), ("name", s("a"))]),
        ),
        (
            "an integer under match",
            obj(vec![
                ("age", FfiValue::UInt32(1)),
                ("name", FfiValue::UInt32(2)),
            ]),
        ),
        ("a scalar, not a record", FfiValue::UInt32(1)),
        (
            "a batch holding a non-record",
            FfiValue::Array(vec![row(1, "a"), FfiValue::Null]),
        ),
    ] {
        let source = encode(source);
        assert_eq!(
            ops::validate::record(&source, &plan),
            Err(STATUS_ENCODING),
            "{label} must be refused by validation"
        );
        assert_eq!(
            block_on(ops::encrypt_record(
                &cipher.default_keyset(),
                &source,
                &plan
            )),
            Err(STATUS_ENCODING),
            "{label} must be refused by the op too"
        );
    }

    // A passthrough under a ciphertext output, with no term output to mask
    // it (the invariant `a_passthrough_source_value_is_refused_a_ciphertext_slot` pins).
    let ct_only = single_field_plan("age", label("age"));
    let passthrough = encode(obj(vec![(
        "age",
        FfiValue::Passthrough(Box::new(FfiValue::UInt32(29))),
    )]));
    assert_eq!(
        ops::validate::record(&passthrough, &ct_only),
        Err(STATUS_ENCODING)
    );

    // A malformed plan is refused with a well-formed source.
    assert_eq!(
        ops::validate::record(&encode(row(1, "a")), &encode(obj(vec![]))),
        Err(STATUS_ENCODING)
    );

    assert_eq!(ops::validate::record(&encode(row(1, "a")), &plan), Ok(()));
    assert_eq!(
        ops::validate::record(
            &encode(FfiValue::Array(vec![row(1, "a"), row(2, "b")])),
            &plan
        ),
        Ok(())
    );
    assert_eq!(cipher.kms().generate_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn record_tree_validation_refuses_what_decrypt_record_refuses() {
    let cipher = cipher();
    let plan = plan();
    let record = block_on(ops::encrypt_record(
        &cipher.default_keyset(),
        &encode(row(29, "alice")),
        &plan,
    ))
    .expect("encrypt record");
    assert_eq!(ops::validate::record_tree(&record, &plan, None), Ok(()));

    type Node = CipherText<Vec<u8>, FfiValue>;
    // The tree is not `Clone`; every variant decodes the record afresh.
    let fields = || {
        let CipherText::Map(fields) = decode_tree(&record) else {
            panic!("expected a field map");
        };
        fields
    };
    let re_encode = |tree: Node| {
        let mut out = Vec::new();
        codec::encode_ciphertext(&tree, &mut out).expect("re-encode");
        out
    };
    let with_age = |edit: &dyn Fn(&mut Node)| {
        let mut fields = fields();
        for (field, node) in &mut fields {
            if field == "age" {
                edit(node);
            }
        }
        CipherText::Map(fields)
    };

    let forged_c = with_age(&|node| {
        let CipherText::Map(outputs) = node else {
            panic!("expected an output map");
        };
        for (key, slot) in outputs.iter_mut() {
            if key == "c" {
                *slot = CipherText::Passthrough(FfiValue::UInt32(99));
            }
        }
    });
    let no_c = with_age(&|node| {
        let CipherText::Map(outputs) = node else {
            panic!("expected an output map");
        };
        outputs.retain(|(key, _)| key != "c");
    });
    let not_a_map = with_age(&|node| *node = CipherText::Passthrough(FfiValue::Null));
    let missing_field = {
        let mut fields = fields();
        fields.retain(|(field, _)| field != "age");
        CipherText::Map(fields)
    };
    let batch_of_non_records = CipherText::Sequence(vec![
        CipherText::Map(fields()),
        CipherText::Passthrough(FfiValue::Null),
    ]);

    for (label, tree) in [
        ("a forged passthrough under c", forged_c),
        ("a field without c", no_c),
        ("a field that is not an output map", not_a_map),
        ("a missing field", missing_field),
        ("a batch holding a non-record", batch_of_non_records),
    ] {
        let tree = re_encode(tree);
        assert_eq!(
            ops::validate::record_tree(&tree, &plan, None),
            Err(STATUS_ENCODING),
            "{label} must be refused by validation"
        );
        assert_eq!(
            block_on(ops::decrypt_record(
                Scope::Client(&cipher),
                &tree,
                &plan,
                None
            )),
            Err(STATUS_ENCODING),
            "{label} must be refused by the op too"
        );
    }
    assert_eq!(cipher.kms().retrieve_calls.load(Ordering::SeqCst), 0);
}

// =============================================================================
// The generator's questions
// =============================================================================

/// `plan_check` accepts what `encrypt_record` would run and refuses what it
/// would refuse, with no cipher in hand: the Go generator asks this for every
/// declaration it writes.
#[test]
fn plan_check_answers_without_a_cipher() {
    assert_eq!(ops::plan_check(&plan()), Ok(()));
    assert_eq!(ops::plan_check(&extended_plan()), Ok(()));

    // match over an integer: a type that does not admit one of its indexes.
    let bad_index = encode(obj(vec![(
        "age",
        obj(vec![
            ("context", label("age")),
            ("outputs", FfiValue::Array(vec![s("c"), s("match")])),
            ("type", s("uint32")),
        ]),
    )]));
    assert_eq!(ops::plan_check(&bad_index), Err(STATUS_ENCODING));

    // a one-segment context is not a label a fields plan can seal under.
    let one_segment = encode(obj(vec![(
        "age",
        obj(vec![
            ("context", FfiValue::Array(vec![s("users")])),
            ("outputs", FfiValue::Array(vec![s("c")])),
        ]),
    )]));
    assert_eq!(ops::plan_check(&one_segment), Err(STATUS_ENCODING));

    // not a plan at all.
    assert_eq!(ops::plan_check(&encode(s("users"))), Err(STATUS_ENCODING));
    assert_eq!(ops::plan_check(b"\xff\xff"), Err(STATUS_ENCODING));
}

/// `targets` is the fixed wire shape: `{"targets": [...]}`. The build
/// without EQL types lists none, which the Go generator reads as "no
/// `encrypt_into` type is available"; the `eql` build lists the catalog,
/// `TextEq` producible and every other type with its reason.
#[test]
fn targets_lists_what_the_build_holds() {
    let out = ops::targets().expect("targets encode");
    let FfiValue::Object(entries) = decode(&out) else {
        panic!("targets is an object");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "targets");
    let FfiValue::Array(items) = &entries[0].1 else {
        panic!("targets is a list");
    };
    if !stack_encrypt_guest::targets::HOLDS_EQL {
        assert!(items.is_empty(), "the build without EQL types lists none");
        return;
    }
    let name_of = |item: &FfiValue| match item {
        FfiValue::Object(fields) => fields.iter().find_map(|(k, v)| match (k.as_str(), v) {
            ("name", FfiValue::String(s)) => {
                std::str::from_utf8(s.risky_ref()).ok().map(str::to_owned)
            }
            _ => None,
        }),
        _ => None,
    };
    let producible = |item: &FfiValue| match item {
        FfiValue::Object(fields) => fields
            .iter()
            .any(|(k, v)| k == "producible" && matches!(v, FfiValue::Bool(true))),
        _ => false,
    };
    let names: Vec<String> = items.iter().filter_map(name_of).collect();
    assert_eq!(names.len(), items.len(), "every entry is named");
    assert!(names.iter().any(|n| n == "TextEq"));
    let producible: Vec<String> = items
        .iter()
        .filter(|i| producible(i))
        .filter_map(name_of)
        .collect();
    assert_eq!(producible, ["TextEq"], "the engine produces TextEq only");
}

// =============================================================================
// A plan whose context is a field of the record
// =============================================================================

/// The plan-level `"context_field"` key: `tenant` names each record's
/// context, `age` is sealed under `<tenant>/age`.
fn context_field_plan() -> Vec<u8> {
    let identity = |field: &str| FfiValue::Array(vec![s(field)]);
    encode(obj(vec![
        ("context_field", s("tenant")),
        (
            "tenant",
            obj(vec![
                ("context", identity("tenant")),
                ("outputs", FfiValue::Array(vec![s("passthrough")])),
                ("type", s("string")),
            ]),
        ),
        (
            "age",
            obj(vec![
                ("context", identity("age")),
                ("outputs", FfiValue::Array(vec![s("c"), s("eq")])),
                ("type", s("uint32")),
            ]),
        ),
    ]))
}

fn tenant_row(tenant: &str, age: u32) -> FfiValue {
    obj(vec![("tenant", s(tenant)), ("age", FfiValue::UInt32(age))])
}

/// Two tenants in one batch seal under their own contexts and open back
/// with no context named; the expected context the host passes through
/// `se_decrypt_record`'s options refuses a record stored under another,
/// as `STATUS_CONTEXT_MISMATCH`, before any key is retrieved — and the
/// boundary validation says the same.
#[test]
fn a_context_field_record_opens_under_the_context_it_stores() {
    let cipher = cipher();
    let plan = context_field_plan();
    let batch = encode(FfiValue::Array(vec![
        tenant_row("tenants/acme", 34),
        tenant_row("tenants/globex", 34),
    ]));
    let record = block_on(ops::encrypt_record(&cipher.default_keyset(), &batch, &plan))
        .expect("encrypt a batch of two tenants");
    assert_eq!(cipher.kms().generate_calls.load(Ordering::SeqCst), 1);

    // The same age under two tenants is two terms.
    let CipherText::Sequence(rows) = decode_tree(&record) else {
        panic!("a batch is a sequence");
    };
    let eq_of = |row: &CipherText<Vec<u8>, FfiValue>| {
        let CipherText::Map(fields) = row else {
            panic!("a row is a map");
        };
        let CipherText::Map(age) = &fields[1].1 else {
            panic!("age is a map of outputs");
        };
        term_bytes(&age[1].1)
    };
    assert_ne!(eq_of(&rows[0]), eq_of(&rows[1]));

    let opened = block_on(ops::decrypt_record(
        Scope::Client(&cipher),
        &record,
        &plan,
        None,
    ))
    .expect("each record opens under the context it stores");
    let FfiValue::Array(opened) = decode(&opened) else {
        panic!("an array of rows");
    };
    let FfiValue::Object(globex) = &opened[1] else {
        panic!("an object row");
    };
    assert_eq!(
        text(&globex[0].1),
        "tenants/globex",
        "the context field comes back"
    );
    assert!(matches!(globex[1].1, FfiValue::UInt32(34)));

    let acme = Label::parse("tenants/acme").expect("a label");
    let before = cipher.kms().retrieve_calls.load(Ordering::SeqCst);
    assert_eq!(
        block_on(ops::decrypt_record(
            Scope::Client(&cipher),
            &record,
            &plan,
            Some(acme.clone()),
        )),
        Err(STATUS_CONTEXT_MISMATCH),
        "the globex record is not the acme one"
    );
    assert_eq!(
        cipher.kms().retrieve_calls.load(Ordering::SeqCst),
        before,
        "refused before any key is retrieved"
    );
    assert_eq!(
        ops::validate::record_tree(&record, &plan, Some(&acme)),
        Err(STATUS_CONTEXT_MISMATCH),
        "and the boundary validation refuses it the same way"
    );
    assert_eq!(ops::validate::record_tree(&record, &plan, None), Ok(()));

    // One record stored under the expected context opens under it.
    let one = encode(tenant_row("tenants/acme", 35));
    let record =
        block_on(ops::encrypt_record(&cipher.default_keyset(), &one, &plan)).expect("encrypt one");
    assert_eq!(
        ops::validate::record_tree(&record, &plan, Some(&acme)),
        Ok(())
    );
    let opened = block_on(ops::decrypt_record(
        Scope::Client(&cipher),
        &record,
        &plan,
        Some(acme),
    ))
    .expect("the expected context opens it");
    let FfiValue::Object(fields) = decode(&opened) else {
        panic!("an object row");
    };
    assert!(matches!(fields[1].1, FfiValue::UInt32(35)));
}
