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

use stack_encrypt::dynamic::FfiValue;
use stack_encrypt::dynamic::Scope;
use stack_encrypt::sem::DefaultMatch;
use stack_encrypt::{
    nonempty, CipherText, Label, Node, PassthroughFrame, PendingStackCipherText, SealedValue,
    StackCipher,
};
use stack_encrypt_guest::ops::{self, TERM_EQUALITY, TERM_MATCH, TERM_OPE, TERM_ORE};
use stack_encrypt_guest::status::{
    STATUS_AUTH, STATUS_CONTEXT_MISMATCH, STATUS_ENCODING, STATUS_FOREIGN_KEYSET, STATUS_TERM,
};
use stack_kms::{
    DataKey, DataKeySource, DataKeyWithTag, FakeDataKeySource, GenerateKeyPayload, IndexKeySource,
    RetrieveKeyPayload,
};
use uuid::Uuid;
use vitaminc_aead_frame::{decode_ciphertext, encode_ciphertext};
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
    value.to_frame().expect("encode value").risky_unwrap()
}

fn decode(bytes: &[u8]) -> FfiValue {
    FfiValue::from_frame(bytes).expect("decode value")
}

/// Decode a guest ciphertext buffer with its leaves as bytes, so tests can
/// inspect the nodes directly.
fn decode_tree(bytes: &[u8]) -> Node<Vec<u8>> {
    decode_ciphertext(bytes).expect("decode ciphertext tree")
}

/// Encode a ciphertext tree as the guest reads it.
fn encode_tree(tree: &Node<Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    encode_ciphertext(tree, &mut out).expect("encode ciphertext tree");
    out
}

/// A value as a passthrough node: its frame, in the clear.
fn clear(value: FfiValue) -> Node<Vec<u8>> {
    CipherText::Passthrough(PassthroughFrame(encode(value)))
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
                ("type", s("uint32")),
            ]),
        ),
        (
            "name",
            obj(vec![
                ("context", ctx("name")),
                ("outputs", FfiValue::Array(vec![s("c"), s("match")])),
                ("type", s("string")),
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
fn term_bytes(node: &Node<Vec<u8>>) -> Vec<u8> {
    let CipherText::Passthrough(frame) = node else {
        panic!("expected a passthrough term node");
    };
    let FfiValue::Bytes(b) = decode(&frame.0) else {
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

    // Bools have no equality domain and no order term; match is text-only;
    // containers have no term semantics; kinds outside the table and empty
    // contexts are rejected.
    for (value, kind) in [
        (FfiValue::Bool(true), TERM_EQUALITY),
        (FfiValue::Bool(true), TERM_ORE),
        (FfiValue::Bool(false), TERM_OPE),
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
                *slot = clear(FfiValue::UInt32(99));
            }
        }
    }
    let forged = encode_tree(&CipherText::Map(fields));

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
        PendingStackCipherText::plan(FfiValue::UInt32(34), native)
            .expect("plan")
            .seal(&keyset, native),
    )
    .expect("seal");
    let CipherText::Single(leaf) = sealed else {
        panic!("a scalar seals to a single leaf");
    };

    // Shape the tree the way `encrypt_record` writes it: field → { c: leaf }.
    let tree: Node<Vec<u8>> = CipherText::Map(vec![(
        "age".to_string(),
        CipherText::Map(vec![("c".to_string(), CipherText::Single(leaf.to_bytes()))]),
    )]);
    let record = encode_tree(&tree);

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
        let (CipherText::Map(a), CipherText::Map(g)) =
            (decode_tree(&acme_rows), decode_tree(&globex_rows))
        else {
            panic!("a single record is a map");
        };
        encode_tree(&CipherText::Sequence(vec![
            CipherText::Map(a),
            CipherText::Map(g),
        ]))
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
        ("a bool under equality", FfiValue::Bool(true), TERM_EQUALITY),
        ("a bool under ore", FfiValue::Bool(true), TERM_ORE),
        ("a bool under ope", FfiValue::Bool(true), TERM_OPE),
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
        (FfiValue::Float64(1.5), TERM_EQUALITY),
        (FfiValue::Float64(1.5), TERM_ORE),
        (FfiValue::Int32(-1), TERM_OPE),
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

    type Node = stack_encrypt::Node<Vec<u8>>;
    // The tree is not `Clone`; every variant decodes the record afresh.
    let fields = || {
        let CipherText::Map(fields) = decode_tree(&record) else {
            panic!("expected a field map");
        };
        fields
    };
    let re_encode = |tree: Node| encode_tree(&tree);
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
                *slot = clear(FfiValue::UInt32(99));
            }
        }
    });
    let no_c = with_age(&|node| {
        let CipherText::Map(outputs) = node else {
            panic!("expected an output map");
        };
        outputs.retain(|(key, _)| key != "c");
    });
    let not_a_map = with_age(&|node| *node = clear(FfiValue::Null));
    let missing_field = {
        let mut fields = fields();
        fields.retain(|(field, _)| field != "age");
        CipherText::Map(fields)
    };
    let batch_of_non_records =
        CipherText::Sequence(vec![CipherText::Map(fields()), clear(FfiValue::Null)]);

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

    // an indexed field with no declared type: every term derives from one
    // declared kind, so the plan is refused before any value arrives.
    let untyped_index = encode(obj(vec![(
        "age",
        obj(vec![
            ("context", label("age")),
            ("outputs", FfiValue::Array(vec![s("c"), s("eq")])),
        ]),
    )]));
    assert_eq!(ops::plan_check(&untyped_index), Err(STATUS_ENCODING));

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
    assert_eq!(
        producible,
        [
            "Integer",
            "IntegerEq",
            "Bigint",
            "BigintEq",
            "Text",
            "TextEq",
            "TextMatch",
            "Boolean",
            "Real",
            "RealEq",
            "Double",
            "DoubleEq"
        ],
        "the engine's producible types, in catalog order"
    );
}

// =============================================================================
// Queries by operator
// =============================================================================

/// The entries of a query term's object, by key.
fn query_term_entries(out: &[u8]) -> Vec<(String, FfiValue)> {
    let FfiValue::Object(entries) = decode(out) else {
        panic!("a query term is an object");
    };
    entries
}

fn entry<'a>(entries: &'a [(String, FfiValue)], key: &str) -> &'a FfiValue {
    &entries
        .iter()
        .find(|(k, _)| k == key)
        .unwrap_or_else(|| panic!("no {key}"))
        .1
}

fn bytes_of(value: &FfiValue) -> Vec<u8> {
    match value {
        FfiValue::Bytes(b) => b.risky_ref().to_vec(),
        other => panic!("expected bytes, got {}", kind(other)),
    }
}

/// A query by operator derives, through the guest, the bytes the term
/// export derives for the index that answers it, under the field's
/// context: the plan picks the index, and the derivation is the one a
/// stored term came from.
#[test]
fn a_query_term_is_the_term_of_the_index_that_answers_its_operator() {
    let cipher = cipher();
    let keyset = cipher.default_keyset();
    let term_of = |value: FfiValue, field: &str, kind: u32| {
        block_on(ops::term(
            &keyset,
            &encode(value),
            &encode(label(field)),
            kind,
        ))
        .expect("term")
    };
    let query = |input: FfiValue, field: &str, operator: &str| {
        let input = encode(input);
        assert_eq!(
            ops::validate::query_term(&input, &plan(), field.as_bytes(), operator.as_bytes()),
            Ok(()),
            "{operator} on {field} validates"
        );
        query_term_entries(
            &block_on(ops::query_term(
                &keyset,
                &input,
                &plan(),
                field.as_bytes(),
                operator.as_bytes(),
            ))
            .expect("query term"),
        )
    };

    let eq = query(FfiValue::UInt32(34), "age", "eq");
    assert_eq!(text(entry(&eq, "operator")), "eq");
    assert_eq!(text(entry(&eq, "fidelity")), "exact");
    assert_eq!(text(entry(&eq, "index")), "eq");
    assert!(matches!(entry(&eq, "domain"), FfiValue::Null));
    assert_eq!(
        bytes_of(entry(&eq, "term")),
        term_of(FfiValue::UInt32(34), "age", TERM_EQUALITY)
    );

    // A host's float reads as the field's integer.
    let lt = query(FfiValue::Float64(40.0), "age", "lt");
    assert_eq!(text(entry(&lt, "index")), "ore");
    assert_eq!(
        bytes_of(entry(&lt, "term")),
        term_of(FfiValue::UInt32(40), "age", TERM_ORE)
    );

    let range = query(
        FfiValue::Array(vec![FfiValue::UInt32(18), FfiValue::UInt32(65)]),
        "age",
        "between",
    );
    let FfiValue::Array(bounds) = entry(&range, "term") else {
        panic!("a range is a list of two terms");
    };
    assert_eq!(bounds.len(), 2);
    assert_eq!(
        bytes_of(&bounds[0]),
        term_of(FfiValue::UInt32(18), "age", TERM_ORE)
    );
    assert_eq!(
        bytes_of(&bounds[1]),
        term_of(FfiValue::UInt32(65), "age", TERM_ORE)
    );

    let matches = query(s("alice"), "name", "matches");
    assert_eq!(text(entry(&matches, "fidelity")), "probabilistic");
    assert_eq!(
        bytes_of(entry(&matches, "term")),
        term_of(s("alice"), "name", TERM_MATCH)
    );
}

/// The validator refuses what the operation refuses, with the same status,
/// before a keyset is resolved: an operator the field does not answer, or
/// one the engine does not know, as a mistyped value is refused; the typed
/// path's own query refusals as `STATUS_TERM`.
/// Equality text that does not normalize (a code point unassigned in
/// Unicode 16) is refused by the cipher-free check as a term failure, as
/// derivation would refuse it, so a guest with no cipher reports
/// STATUS_TERM rather than STATUS_STATE, and the query op agrees.
#[test]
fn equality_text_that_does_not_normalize_is_a_term_failure_before_any_cipher() {
    let plan = encode(obj(vec![(
        "email",
        obj(vec![
            ("context", label("email")),
            ("outputs", FfiValue::Array(vec![s("c"), s("eq")])),
            ("type", s("string")),
        ]),
    )]));
    let input = encode(s("a\u{0378}bc"));
    assert_eq!(
        ops::validate::query_term(&input, &plan, b"email", b"eq"),
        Err(STATUS_TERM),
        "validation"
    );
    let cipher = cipher();
    let keyset = cipher.default_keyset();
    assert_eq!(
        block_on(ops::query_term(&keyset, &input, &plan, b"email", b"eq")).map(|_| ()),
        Err(STATUS_TERM),
        "the op"
    );
}

#[test]
fn query_term_validation_refuses_what_the_query_op_refuses() {
    let cipher = cipher();
    let keyset = cipher.default_keyset();
    for (what, input, field, operator, status) in [
        (
            "unknown operator",
            FfiValue::UInt32(1),
            "age",
            "like",
            STATUS_ENCODING,
        ),
        ("not answered", s("ali"), "age", "matches", STATUS_ENCODING),
        (
            "not answered by a match index",
            s("ali"),
            "name",
            "eq",
            STATUS_ENCODING,
        ),
        (
            "no such field",
            FfiValue::UInt32(1),
            "height",
            "eq",
            STATUS_ENCODING,
        ),
        ("mistyped input", s("34"), "age", "eq", STATUS_ENCODING),
        (
            "not a range",
            FfiValue::UInt32(1),
            "age",
            "between",
            STATUS_ENCODING,
        ),
        (
            "inverted range",
            FfiValue::Array(vec![FfiValue::UInt32(65), FfiValue::UInt32(18)]),
            "age",
            "between",
            STATUS_TERM,
        ),
        ("no token", s("al"), "name", "matches", STATUS_TERM),
    ] {
        let input = encode(input);
        assert_eq!(
            ops::validate::query_term(&input, &plan(), field.as_bytes(), operator.as_bytes()),
            Err(status),
            "{what}: validation"
        );
        assert_eq!(
            block_on(ops::query_term(
                &keyset,
                &input,
                &plan(),
                field.as_bytes(),
                operator.as_bytes()
            )),
            Err(status),
            "{what}: the op"
        );
    }
    assert_eq!(
        ops::validate::query_term(&encode(FfiValue::UInt32(1)), &plan(), b"\xff", b"eq"),
        Err(STATUS_ENCODING),
        "a field name that is not UTF-8"
    );
}

/// `verify` answers one boolean per value, in order, with no cipher; an
/// exact operator has nothing to verify.
#[test]
fn verify_answers_a_page_in_one_call() {
    let values = encode(FfiValue::Array(vec![
        s("Alice Smith"),
        s("Bob"),
        FfiValue::Null,
        s("malice"),
    ]));
    let out =
        ops::verify(&encode(s("alice")), &values, &plan(), b"name", b"matches").expect("verify");
    let FfiValue::Array(verified) = decode(&out) else {
        panic!("a list");
    };
    let verified: Vec<bool> = verified
        .iter()
        .map(|v| match v {
            FfiValue::Bool(b) => *b,
            other => panic!("a boolean, not {}", kind(other)),
        })
        .collect();
    assert_eq!(
        verified,
        [true, false, false, true],
        "malice holds every 3-gram of alice"
    );

    for (what, input, values, field, operator) in [
        (
            "an exact operator",
            FfiValue::UInt32(1),
            FfiValue::Array(vec![]),
            "age",
            "eq",
        ),
        (
            "values not a list",
            s("alice"),
            s("Alice"),
            "name",
            "matches",
        ),
        (
            "a value of another type",
            s("alice"),
            FfiValue::Array(vec![FfiValue::UInt32(1)]),
            "name",
            "matches",
        ),
        (
            "an unknown operator",
            s("alice"),
            FfiValue::Array(vec![]),
            "name",
            "match",
        ),
    ] {
        assert_eq!(
            ops::verify(
                &encode(input),
                &encode(values),
                &plan(),
                field.as_bytes(),
                operator.as_bytes()
            ),
            Err(STATUS_ENCODING),
            "{what}"
        );
    }
    assert_eq!(
        ops::verify(
            &encode(s("al")),
            &encode(FfiValue::Array(vec![])),
            &plan(),
            b"name",
            b"matches"
        ),
        Err(STATUS_TERM),
        "a query that cuts no token verifies nothing"
    );
}

/// `target_limit` reads the term's bytes and the statistics, with no
/// cipher: a measured histogram sizes a fetch, the declared prior a data
/// plan has none of answers null.
#[test]
fn target_limit_sizes_a_fetch_from_the_terms_bytes() {
    let cipher = cipher();
    let keyset = cipher.default_keyset();
    let out = block_on(ops::query_term(
        &keyset,
        &encode(s("ali")),
        &plan(),
        b"name",
        b"matches",
    ))
    .expect("query term");
    let term = bytes_of(entry(&query_term_entries(&out), "term"));
    let pair = |bits: u32, rows: u64| {
        FfiValue::Array(vec![FfiValue::UInt32(bits), FfiValue::UInt64(rows)])
    };
    let measured = encode(obj(vec![
        ("rows", FfiValue::UInt64(1_000_000)),
        (
            "histogram",
            FfiValue::Array(vec![pair(40, 500_000), pair(120, 500_000)]),
        ),
    ]));
    let limit = |stats: &[u8], term: &[u8], field: &str, operator: &str| {
        ops::target_limit(
            term,
            stats,
            &plan(),
            field.as_bytes(),
            operator.as_bytes(),
            10,
        )
    };
    let rows = decode(&limit(&measured, &term, "name", "matches").expect("a limit"));
    assert!(
        matches!(rows, FfiValue::UInt64(n) if n > 10),
        "{}",
        kind(&rows)
    );
    let declared = encode(obj(vec![("rows", FfiValue::UInt64(1_000_000))]));
    assert!(matches!(
        decode(&limit(&declared, &term, "name", "matches").expect("a limit")),
        FfiValue::Null
    ));

    assert_eq!(
        limit(&measured, &[1], "name", "matches"),
        Err(STATUS_ENCODING),
        "half a position"
    );
    assert_eq!(
        limit(&encode(s("x")), &term, "name", "matches"),
        Err(STATUS_ENCODING),
        "not stats"
    );
    assert_eq!(
        limit(&measured, &term, "age", "eq"),
        Err(STATUS_ENCODING),
        "an exact operator"
    );
}

/// The `eql` build's catalog lists, per type, the operators the engine
/// answers: `TextEq` answers `eq`, exactly, and a type the engine does not
/// produce answers nothing.
#[test]
fn the_catalog_lists_each_types_operators() {
    if !stack_encrypt_guest::targets::HOLDS_EQL {
        return;
    }
    let FfiValue::Object(entries) = decode(&ops::targets().expect("targets")) else {
        panic!("an object");
    };
    let FfiValue::Array(items) = &entries[0].1 else {
        panic!("a list");
    };
    for item in items {
        let FfiValue::Object(fields) = item else {
            panic!("an object");
        };
        let name = text(entry(fields, "name")).to_owned();
        let FfiValue::Array(operators) = entry(fields, "operators") else {
            panic!("{name}: operators is a list");
        };
        let producible = matches!(entry(fields, "producible"), FfiValue::Bool(true));
        let only = |want: [(&str, &str); 4]| {
            assert_eq!(operators.len(), 1, "{name} answers one operator");
            let FfiValue::Object(op) = &operators[0] else {
                panic!("an object");
            };
            let op: Vec<(&str, &str)> = op.iter().map(|(k, v)| (k.as_str(), text(v))).collect();
            assert_eq!(op, want, "{name}");
        };
        match name.as_str() {
            "TextEq" | "IntegerEq" | "BigintEq" | "RealEq" | "DoubleEq" => only([
                ("operator", "eq"),
                ("fidelity", "exact"),
                ("arity", "one"),
                ("index", "eq"),
            ]),
            "TextMatch" => only([
                ("operator", "matches"),
                ("fidelity", "probabilistic"),
                ("arity", "one"),
                ("index", "match"),
            ]),
            _ => {
                // A type the engine does not produce answers nothing, and
                // the other produced types are storage-only: no twin.
                let why = if producible {
                    "is storage-only, so answers nothing"
                } else {
                    "is not produced, so answers nothing"
                };
                assert!(operators.is_empty(), "{name} {why}");
            }
        }
    }
}

/// `TextMatch` answers `matches` through its query twin and nothing else:
/// the term is a `TextMatchQuery` under `eql_v4.query_text_match`, and
/// `verify` and `target_limit` run under EQL's match options, reading the
/// twin's `bf`. `eq` is refused as not answered.
#[test]
fn a_text_match_field_answers_matches_through_its_twin() {
    if !stack_encrypt_guest::targets::HOLDS_EQL {
        return;
    }
    let cipher = cipher();
    let keyset = cipher.default_keyset();
    let plan = encode(obj(vec![(
        "name",
        obj(vec![("context", label("name")), ("target", s("TextMatch"))]),
    )]));
    let term = block_on(ops::query_term(
        &keyset,
        &encode(s("Alice")),
        &plan,
        b"name",
        b"matches",
    ))
    .expect("matches on a TextMatch field");
    let FfiValue::Object(term) = decode(&term) else {
        panic!("a term is an object");
    };
    let field = |key: &str| &term.iter().find(|(k, _)| k == key).expect(key).1;
    assert_eq!(text(field("fidelity")), "probabilistic");
    assert_eq!(text(field("index")), "match");
    assert_eq!(text(field("domain")), "eql_v4.query_text_match");
    let FfiValue::Bytes(twin) = field("term") else {
        panic!("the term is bytes");
    };
    let twin: serde_json::Value = serde_json::from_slice(twin.risky_ref()).expect("JSON");
    let bits = twin["bf"].as_array().expect("a bf").len();
    assert!(
        bits > 0 && bits <= 3 * 6,
        "3 trigrams of k = 6 bits: {bits}"
    );

    let verified = ops::verify(
        &encode(s("ALICE")),
        &encode(FfiValue::Array(vec![
            s("say alice"),
            s("alison"),
            FfiValue::Null,
        ])),
        &plan,
        b"name",
        b"matches",
    )
    .expect("verify");
    let FfiValue::Array(verified) = decode(&verified) else {
        panic!("a list");
    };
    let verified: Vec<bool> = verified
        .iter()
        .map(|v| matches!(v, FfiValue::Bool(true)))
        .collect();
    assert_eq!(verified, [true, false, false]);
    let FfiValue::Bytes(twin_bytes) = field("term") else {
        unreachable!()
    };
    let limit = ops::target_limit(
        twin_bytes.risky_ref(),
        &encode(obj(vec![("rows", FfiValue::UInt64(1000))])),
        &plan,
        b"name",
        b"matches",
        10,
    )
    .expect("target_limit reads the twin's bf");
    assert!(
        matches!(decode(&limit), FfiValue::Null),
        "a declared count and no measured histogram give no finite fetch"
    );

    assert_eq!(
        block_on(ops::query_term(
            &keyset,
            &encode(s("alice")),
            &plan,
            b"name",
            b"eq",
        ))
        .map(|_| ()),
        Err(STATUS_ENCODING),
        "eq on a TextMatch field"
    );
}

/// The operators of one field, each as `(operator, fidelity, arity, index)`.
fn operators_of(plan: &[u8], field: &str) -> Vec<[String; 4]> {
    let FfiValue::Array(items) =
        decode(&ops::operators(plan, field.as_bytes()).expect("operators"))
    else {
        panic!("operators are a list");
    };
    items
        .iter()
        .map(|item| {
            let FfiValue::Object(entries) = item else {
                panic!("an operator is an object");
            };
            let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
            assert_eq!(keys, ["operator", "fidelity", "arity", "index"]);
            [0, 1, 2, 3].map(|i| text(&entries[i].1).to_owned())
        })
        .collect()
}

/// A field's operators are the queries the engine answers on it, with
/// their fidelity, arity and index: what the generator writes one method
/// for. Every operator listed derives a term, and every other is refused.
#[test]
fn a_fields_operators_are_the_queries_it_answers() {
    let row = |op: &str, fidelity: &str, arity: &str, index: &str| {
        [op, fidelity, arity, index].map(str::to_owned)
    };
    assert_eq!(
        operators_of(&plan(), "age"),
        [
            row("eq", "exact", "one", "eq"),
            row("lt", "exact", "one", "ore"),
            row("lte", "exact", "one", "ore"),
            row("gt", "exact", "one", "ore"),
            row("gte", "exact", "one", "ore"),
            row("between", "exact", "pair", "ore"),
        ]
    );
    assert_eq!(
        operators_of(&plan(), "name"),
        [row("matches", "probabilistic", "one", "match")]
    );
    for (field, input) in [("age", FfiValue::UInt32(7)), ("name", s("alice smith"))] {
        let listed: Vec<String> = operators_of(&plan(), field)
            .into_iter()
            .map(|[op, ..]| op)
            .collect();
        for op in ["eq", "lt", "lte", "gt", "gte", "between", "matches"] {
            let input = if op == "between" {
                FfiValue::Array(vec![input.clone(), input.clone()])
            } else {
                input.clone()
            };
            let checked =
                ops::validate::query_term(&encode(input), &plan(), field.as_bytes(), op.as_bytes());
            if listed.iter().any(|l| l == op) {
                assert_eq!(checked, Ok(()), "{field} {op} is listed and answered");
            } else {
                assert_eq!(checked, Err(STATUS_ENCODING), "{field} {op} is not listed");
            }
        }
    }
    assert_eq!(
        ops::operators(&plan(), b"phone"),
        Err(STATUS_ENCODING),
        "a field the plan lacks"
    );
    assert_eq!(ops::operators(b"\xff", b"age"), Err(STATUS_ENCODING));
}

/// In the `eql` build a field that names an EQL type answers what the
/// catalog lists for the type: `TextEq` answers `eq`.
#[test]
fn a_target_fields_operators_are_its_types() {
    if !stack_encrypt_guest::targets::HOLDS_EQL {
        return;
    }
    let plan = encode(obj(vec![(
        "email",
        obj(vec![("context", label("email")), ("target", s("TextEq"))]),
    )]));
    assert_eq!(
        operators_of(&plan, "email"),
        [["eq", "exact", "one", "eq"].map(str::to_owned)]
    );
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
    let eq_of = |row: &Node<Vec<u8>>| {
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
