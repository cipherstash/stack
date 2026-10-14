//! The plaintext model against today's `Value` path, with real AES-256-GCM.
//!
//! A frame sealed through `EncryptSink` and a `Cipher` opens on the `Value`
//! path, and a `Value` sealed on today's path opens through `walk` into a
//! frame, across the conformance corpus. So the leaf format, the AAD
//! derivations and the container rules are byte-identical.

use std::any::Any;

use vitaminc_aead::seal::Cipher;
use vitaminc_aead::{
    decrypt_to_frame, encrypt, to_frame, CipherText, Context, Decipher, DecipherVisitor,
    DecryptError, EncryptError, Frame, LocalCipherText, Node, PassthroughFrame, Plaintext, Sink,
    Unspecified,
};
use vitaminc_aead::{Cipher as _, Encrypt as _};
use vitaminc_aead_value::transport::{decode_value, encode_value, Reader};
use vitaminc_aead_value::Value;
use vitaminc_encrypt::{Aes256Cipher, AesCipherText, Key};
use vitaminc_protected::{Controlled, Protected};

const AAD: &[u8] = b"\x01\x00\x00\x00interop";

fn cipher() -> Aes256Cipher {
    Aes256Cipher::new(&Key::from([7u8; 32])).expect("cipher")
}

/// `Aes256Cipher` as a leaf cipher, through today's public API so the
/// leaves are byte-compatible with today's. The real `impl Cipher for
/// Aes256Cipher` lands in `vitaminc-encrypt`.
struct Aes(Aes256Cipher);

impl Cipher for Aes {
    type Leaf = LocalCipherText;
    type Error = Unspecified;

    fn seal(
        &self,
        plaintext: Protected<Vec<u8>>,
        aad: &Context<'_>,
    ) -> Result<LocalCipherText, Unspecified> {
        match self
            .0
            .encrypt_bytes_vec(plaintext, Context::from_encoded(aad.as_bytes()))?
        {
            AesCipherText::Single(leaf) => Ok(leaf),
            _ => Err(Unspecified),
        }
    }

    fn open(
        &self,
        leaf: LocalCipherText,
        aad: &Context<'_>,
    ) -> Result<Protected<Vec<u8>>, Unspecified> {
        struct Raw;
        impl DecipherVisitor<'_> for Raw {
            type Value = Protected<Vec<u8>>;
            fn visit_bytes_vec(self, data: Protected<Vec<u8>>) -> Result<Self::Value, Unspecified> {
                Ok(data)
            }
        }
        self.0
            .decipher(AesCipherText::Single(leaf))
            .decrypt_bytes(Raw, Context::from_encoded(aad.as_bytes()))
    }
}

struct Vector {
    name: String,
    bytes: Vec<u8>,
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Valid today, but with no physical-plus-logical form: a leap second has
/// no count of nanoseconds, and a decimal negative zero reads as zero.
const CHANGED: [&str; 2] = ["timestamp-leap", "decimal-negative-zero"];

fn corpus() -> Vec<Vector> {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../../testdata/value-conformance.json"))
            .expect("corpus");
    let mut all: Vec<Vector> = corpus["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .map(|v| Vector {
            name: v["name"].as_str().expect("name").to_owned(),
            bytes: hex(v["transport"].as_str().expect("transport")),
        })
        .filter(|v| !CHANGED.contains(&v.name.as_str()))
        .collect();
    all.push(Vector {
        name: "nested-sample".into(),
        bytes: encode(sample()),
    });
    all
}

fn encode(value: Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_value(value, &mut out).expect("encodes");
    out
}

fn sample() -> Value {
    Value::Object(vec![
        ("name".into(), Value::String("Ada".into())),
        ("age".into(), Value::UInt32(34)),
        (
            "scores".into(),
            Value::Array(vec![Value::Int8(-1), Value::Float64(2.5), Value::Null]),
        ),
        (
            "joined".into(),
            Value::Date(chrono::NaiveDate::from_ymd_opt(2024, 2, 29).expect("date")),
        ),
        (
            "note".into(),
            Value::Passthrough(Box::new(Value::String("public".into()))),
        ),
        ("blob".into(), Value::Bytes(Protected::new(vec![1, 2, 3]))),
        (
            "seen".into(),
            Value::Timestamp(
                chrono::DateTime::from_timestamp(1_700_000_000, 123_456_789).expect("timestamp"),
            ),
        ),
        ("active".into(), Value::Bool(true)),
    ])
}

/// Today's path: a frame in, a `Value` tree sealed by `Encrypt`.
fn today_encrypt(cipher: &Aes256Cipher, frame: &[u8]) -> AesCipherText {
    let value = decode_value(&mut Reader::new(frame)).expect("decodes");
    value
        .encrypt_with_aad(cipher, Context::from_encoded(AAD))
        .expect("encrypts")
}

/// Today's path: a `Value` tree opened by `Decrypt`, out as a frame.
fn today_decrypt(cipher: &Aes256Cipher, ct: AesCipherText) -> Result<Vec<u8>, Unspecified> {
    let value: Value = cipher.decrypt_with_aad(ct, Context::from_encoded(AAD))?;
    Ok(encode(value))
}

/// Re-home a passthrough payload between the two paths. Today's is a
/// boxed `Value`; the model's is a frame.
fn to_today(node: Node<LocalCipherText>) -> AesCipherText {
    node.map_passthrough(
        &mut |f: PassthroughFrame| -> Result<Box<dyn Any + Send>, Unspecified> {
            Ok(Box::new(
                decode_value(&mut Reader::new(&f.0)).map_err(|_| Unspecified)?,
            ))
        },
    )
    .expect("re-homes")
}

fn to_model(ct: AesCipherText) -> Node<LocalCipherText> {
    ct.map_passthrough(
        &mut |b: Box<dyn Any + Send>| -> Result<PassthroughFrame, Unspecified> {
            let value = *b.downcast::<Value>().map_err(|_| Unspecified)?;
            Ok(PassthroughFrame(encode(value)))
        },
    )
    .expect("re-homes")
}

#[test]
fn the_model_interoperates_with_today_both_ways() {
    let aes = Aes(cipher());
    for v in corpus() {
        let frame = Frame::parse(&v.bytes).expect(&v.name);
        let new_ct = encrypt(frame, &aes, Context::from_encoded(AAD)).expect(&v.name);
        let old_ct = today_encrypt(&aes.0, &v.bytes);

        assert_eq!(
            today_decrypt(&aes.0, to_today(new_ct)).expect(&v.name),
            v.bytes,
            "new to old: {}",
            v.name
        );
        assert_eq!(
            decrypt_to_frame(&aes, to_model(old_ct), Context::from_encoded(AAD)).expect(&v.name),
            v.bytes,
            "old to new: {}",
            v.name
        );
        let new_ct = encrypt(frame, &aes, Context::from_encoded(AAD)).expect(&v.name);
        assert_eq!(
            decrypt_to_frame(&aes, new_ct, Context::from_encoded(AAD)).expect(&v.name),
            v.bytes,
            "new to new: {}",
            v.name
        );
    }
}

#[test]
fn a_wrong_aad_is_an_auth_failure() {
    let aes = Aes(cipher());
    for v in corpus() {
        let ct = encrypt(
            Frame::parse(&v.bytes).expect(&v.name),
            &aes,
            Context::from_encoded(AAD),
        )
        .expect(&v.name);
        let wrong = decrypt_to_frame(&aes, ct, Context::from_encoded(b"other"));
        // A passthrough-only value authenticates nothing, by design.
        if v.bytes.first() == Some(&vitaminc_aead::frame::PASSTHROUGH) {
            assert!(wrong.is_ok(), "{}", v.name);
        } else {
            assert!(matches!(wrong, Err(DecryptError::Auth)), "{}", v.name);
        }
    }
}

#[test]
fn a_rust_value_seals_to_the_same_leaf_as_its_frame() {
    // Go's uint32(34): version byte + 12-byte nonce + 5-byte tagged
    // plaintext + 16-byte tag. A Rust `u32` is the same leaf.
    let aes = Aes(cipher());
    let leaf_len = |ct: Node<LocalCipherText>| match ct {
        CipherText::Single(leaf) => leaf.as_ref().len(),
        _ => panic!("expected a single leaf"),
    };
    assert_eq!(leaf_len(encrypt(34u32, &aes, ()).expect("encrypts")), 34);
    assert_eq!(leaf_len(encrypt(34i8, &aes, ()).expect("encrypts")), 31);

    // And a Rust source reads back on today's path as the frame it writes.
    struct Pair(Option<f64>, Vec<u8>);
    impl Plaintext for Pair {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            use vitaminc_aead::SeqSink;
            let mut seq = sink.seq(Some(2))?;
            self.0.visit(seq.element()?)?;
            self.1.visit(seq.element()?)?;
            seq.end()
        }
    }
    let ct = encrypt(
        Pair(Some(2.5), vec![1, 2]),
        &aes,
        Context::from_encoded(AAD),
    )
    .expect("encrypts");
    let frame = today_decrypt(&aes.0, to_today(ct)).expect("decrypts");
    assert_eq!(
        &frame,
        to_frame(Pair(Some(2.5), vec![1, 2]))
            .expect("frames")
            .risky_ref()
    );
}

#[test]
fn a_failing_source_stops_the_walk_with_its_own_error() {
    struct Failing;
    impl Plaintext for Failing {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            use vitaminc_aead::plaintext::{Error, SourceError};
            let _ = sink.seq(None)?;
            Err(S::Error::source(SourceError::msg("getter threw")))
        }
    }
    match encrypt(Failing, &Aes(cipher()), ()) {
        Err(EncryptError::Source(e)) => assert_eq!(e.to_string(), "getter threw"),
        other => panic!("{other:?}"),
    }
}
