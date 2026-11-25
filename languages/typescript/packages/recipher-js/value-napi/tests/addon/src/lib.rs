//! The addon the Node suites load: the binding's walk and build, the
//! ciphertext projection, and real AES-256-GCM through the sink-based
//! `Cipher`, so every row of the ADR 0001 section 6 mapping encrypts and
//! decrypts inside a live Node.

use napi::bindgen_prelude::{AsyncTask, Buffer, JsObjectValue, Object, Unknown};
use napi::{Env, Error, Result, Status, Task};
use napi_derive::napi;
use recipher_value_napi::{JsBuilder, JsCipherText, JsFault, JsRef, Wrappers};
use vitaminc_aead::seal::Cipher;
use vitaminc_aead::{
    decrypt, decrypt_into, encrypt, to_frame, CipherText, Context, DecryptError, Encrypt,
    EncryptError, Float, Frame, Int, Logical, MapSink, Node, PassthroughFrame, Physical, SeqSink,
    Sink, TimeUnit,
};
use vitaminc_encrypt::{Aes256Cipher, Key, LocalCipherText};
use vitaminc_protected::{Controlled, Protected};

/// The wrapper classes, exported so JavaScript can construct them.
#[napi(module_exports)]
fn init(mut exports: Object<'_>, env: Env) -> Result<()> {
    let wrappers = Wrappers::exports(&env)?;
    for name in ["VcDate", "VcTimestamp", "VcDecimal", "VcUuid"] {
        exports.set_named_property(name, wrappers.get_named_property::<Unknown>(name)?)?;
    }
    Ok(())
}

/// Take the environment's instance data for the addon itself, as an addon
/// author may: the binding must not depend on that slot.
#[napi]
pub fn claim_instance_data(env: Env) -> Result<()> {
    struct Mine;
    env.set_instance_data(Mine, (), |_| {})
}

fn fixed_cipher() -> Result<Aes256Cipher> {
    // Test data, not a secret.
    Aes256Cipher::new(&Key::from([42u8; 32]))
        .map_err(|_| Error::new(Status::GenericFailure, "cipher"))
}

/// An encryption failure as the error JavaScript sees. A failure reading
/// the value (a getter threw) is handed back as that error.
fn encrypt_error<E>(error: EncryptError<E>) -> Error {
    match error {
        EncryptError::Source(source) => JsFault::from_source(&source),
        EncryptError::Shape(shape) => Error::new(Status::InvalidArg, format!("encrypt: {shape}")),
        EncryptError::Cipher(_) => Error::new(Status::GenericFailure, "encrypt: cipher failed"),
        EncryptError::Count(count) => {
            Error::new(Status::GenericFailure, format!("encrypt: {count}"))
        }
    }
}

fn decrypt_error<E: std::fmt::Display, C>(error: DecryptError<E, C>) -> Error {
    match error {
        DecryptError::Cipher(_) => Error::new(Status::GenericFailure, "decrypt: cipher failed"),
        DecryptError::Auth => Error::new(Status::GenericFailure, "decrypt: authentication failed"),
        DecryptError::Malformed => {
            Error::new(Status::GenericFailure, "decrypt: malformed ciphertext")
        }
        DecryptError::Sink(sink) => Error::new(Status::InvalidArg, format!("decrypt: {sink}")),
    }
}

type Ct = JsCipherText<LocalCipherText, PassthroughFrame>;

/// Walk a JavaScript value into a frame.
#[napi]
pub fn encode(value: Unknown<'_>) -> Result<Buffer> {
    let frame = JsRef::new(value).to_frame()?;
    Ok(Buffer::from(frame.risky_ref().to_vec()))
}

/// Walk a JavaScript value and drop the frame, to test the walk alone.
#[napi]
pub fn convert(value: Unknown<'_>) -> Result<()> {
    Ok(JsRef::new(value).to_frame().map(drop)?)
}

/// Build a JavaScript value from a frame.
#[napi]
pub fn decode<'e>(env: &'e Env, bytes: Buffer) -> Result<Unknown<'e>> {
    let frame = Frame::parse(&bytes).map_err(|_| Error::from_reason("frame decode failed"))?;
    Ok(JsBuilder::build(env, frame)?)
}

/// Parse a frame and write it again from its own walk.
#[napi]
pub fn codec_round_trip(bytes: Buffer) -> Result<Buffer> {
    let frame = Frame::parse(&bytes).map_err(|_| Error::from_reason("frame decode failed"))?;
    let written = to_frame(frame).map_err(|_| Error::from_reason("frame encode failed"))?;
    Ok(Buffer::from(written.risky_ref().to_vec()))
}

/// Encrypt a JavaScript value, walked in place, under `aad`.
#[napi(ts_return_type = "unknown")]
pub fn encrypt_value(value: Unknown<'_>, aad: String) -> Result<Ct> {
    let cipher = fixed_cipher()?;
    let node = encrypt(JsRef::new(value), &cipher, aad.as_str()).map_err(encrypt_error)?;
    Ok(JsCipherText(node))
}

/// Decrypt a ciphertext into a JavaScript value, built by the sink.
#[napi]
pub fn decrypt_value<'e>(
    env: &'e Env,
    #[napi(ts_arg_type = "unknown")] ct: Ct,
    aad: String,
) -> Result<Unknown<'e>> {
    let cipher = fixed_cipher()?;
    decrypt_into(&cipher, ct.0, aad.as_str(), JsBuilder::new(env)).map_err(decrypt_error)
}

/// Decrypt a ciphertext as a Rust `Option<String>` and report whether it
/// is `None`: a JavaScript `null` sealed by the binding reads as `None`.
#[napi]
pub fn decrypts_as_none(#[napi(ts_arg_type = "unknown")] ct: Ct, aad: String) -> Result<bool> {
    let cipher = fixed_cipher()?;
    let value: Option<String> = decrypt(&cipher, ct.0, aad.as_str()).map_err(decrypt_error)?;
    Ok(value.is_none())
}

/// Encrypt off the JavaScript thread: the value is snapshotted as a frame
/// here, on the JavaScript thread, and the worker seals the frame with no
/// JavaScript access at all.
pub struct EncryptFrame {
    frame: Option<vitaminc_protected::Buffer>,
    aad: String,
}

impl Task for EncryptFrame {
    type Output = Node<LocalCipherText>;
    type JsValue = Ct;

    fn compute(&mut self) -> Result<Self::Output> {
        let frame = self
            .frame
            .take()
            .ok_or_else(|| Error::from_reason("frame already sealed"))?;
        let cipher = fixed_cipher()?;
        let parsed = Frame::parse(frame.risky_ref())
            .map_err(|_| Error::from_reason("snapshot is not a frame"))?;
        encrypt(parsed, &cipher, self.aad.as_str()).map_err(encrypt_error)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(JsCipherText(output))
    }
}

#[napi(ts_return_type = "Promise<unknown>")]
pub fn encrypt_value_async(value: Unknown<'_>, aad: String) -> Result<AsyncTask<EncryptFrame>> {
    let frame = JsRef::new(value).to_frame()?;
    Ok(AsyncTask::new(EncryptFrame {
        frame: Some(frame),
        aad,
    }))
}

/// A leaf sealed under the given AAD, for ciphertext nodes built here.
fn sealed_leaf(aad: &str) -> Result<LocalCipherText> {
    fixed_cipher()?
        .seal(
            Protected::new(vec![0x03]),
            &Context::from_encoded(aad.as_bytes()),
        )
        .map_err(|_| Error::from_reason("seal"))
}

/// Read a ciphertext node tree into Rust and project it back to JS.
#[napi(ts_return_type = "unknown")]
pub fn ciphertext_round_trip(#[napi(ts_arg_type = "unknown")] ct: Ct) -> Ct {
    ct
}

/// `levels` containers of one `wrap` kind ("array", "object" or
/// "passthrough") around `true`, written as a frame in Rust and built from
/// it, so the build's own depth limit is what applies.
#[napi]
pub fn nested_value<'e>(env: &'e Env, levels: u32, wrap: String) -> Result<Unknown<'e>> {
    let frame = to_frame(Nest {
        levels: levels as usize,
        wrap,
    })
    .map_err(|e| Error::from_reason(format!("frame: {e}")))?;
    let frame = Frame::parse(frame.risky_ref()).map_err(|_| Error::from_reason("frame"))?;
    Ok(JsBuilder::build(env, frame)?)
}

#[derive(Clone)]
struct Nest {
    levels: usize,
    wrap: String,
}

/// Passthrough lends its value, so the nested source walks by reference too.
impl Encrypt for &Nest {
    fn visit<S: Sink>(self, sink: S) -> std::result::Result<S::Ok, S::Error> {
        self.clone().visit(sink)
    }
}

impl Encrypt for Nest {
    fn visit<S: Sink>(self, sink: S) -> std::result::Result<S::Ok, S::Error> {
        if self.levels == 0 {
            return sink.scalar(None, Physical::Bool(true));
        }
        let inner = Nest {
            levels: self.levels - 1,
            wrap: self.wrap.clone(),
        };
        match self.wrap.as_str() {
            "array" => {
                let mut seq = sink.seq(Some(1))?;
                inner.visit(seq.element()?)?;
                seq.end()
            }
            "object" => {
                let mut map = sink.map(Some(1))?;
                inner.visit(map.entry("k")?)?;
                map.end()
            }
            _ => sink.passthrough(&inner),
        }
    }
}

/// `levels` ciphertext containers of one `wrap` kind ("seq" or "map")
/// around one sealed leaf.
#[napi(ts_return_type = "unknown")]
pub fn nested_ciphertext(levels: u32, wrap: String) -> Result<Ct> {
    let mut node = CipherText::Single(sealed_leaf("nested")?);
    for _ in 0..levels {
        node = match wrap.as_str() {
            "seq" => CipherText::Sequence(vec![node]),
            _ => CipherText::Map(vec![("k".into(), node)]),
        };
    }
    Ok(JsCipherText(node))
}

/// `ct_levels` ciphertext sequences around a passthrough node whose payload
/// is `value_levels` arrays around `true`: one tree whose depth spans both.
#[napi(ts_return_type = "unknown")]
pub fn ciphertext_with_payload(ct_levels: u32, value_levels: u32) -> Result<Ct> {
    // Written at the payload's depth, as the encrypt sink writes it, so a
    // payload too deep for the frame's own limit is still a frame here and
    // the projection's limit is what refuses it.
    let payload = vitaminc_aead::to_frame(Nest {
        levels: value_levels as usize,
        wrap: "array".into(),
    });
    let payload = match payload {
        Ok(frame) => frame.risky_ref().to_vec(),
        // Past the frame writer's bound: hand-write the frame bytes.
        Err(_) => {
            let mut bytes = Vec::new();
            for _ in 0..value_levels {
                bytes.extend_from_slice(&[0xF0, 1, 0, 0, 0]);
            }
            bytes.push(0x03);
            bytes
        }
    };
    let mut node = CipherText::Passthrough(PassthroughFrame(payload));
    for _ in 0..ct_levels {
        node = CipherText::Sequence(vec![node]);
    }
    Ok(JsCipherText(node))
}

/// Read a ciphertext node tree into Rust and drop it, to test reading alone.
#[napi]
pub fn read_ciphertext(#[napi(ts_arg_type = "unknown")] ct: Ct) {
    drop(ct);
}

/// As `read_ciphertext`, for a cipher with no passthrough payload.
#[napi]
pub fn read_unit_ciphertext(#[napi(ts_arg_type = "unknown")] ct: JsCipherText<Vec<u8>, ()>) {
    drop(ct);
}

/// `levels` ciphertext sequences around a passthrough node with no payload.
#[napi(ts_return_type = "unknown")]
pub fn unit_ciphertext(levels: u32) -> JsCipherText<Vec<u8>, ()> {
    let mut node = CipherText::Passthrough(());
    for _ in 0..levels {
        node = CipherText::Sequence(vec![node]);
    }
    JsCipherText(node)
}

/// Every scalar kind the binding can build, each from one `Sink::scalar`
/// call, keyed by name: the inventory `tests/kind_inventory.cjs` checks.
#[napi]
pub fn kind_inventory<'e>(env: &'e Env) -> Result<Object<'e>> {
    let samples: Vec<(&str, Option<Logical>, Physical<'_>)> = vec![
        ("null", None, Physical::Null),
        ("undefined", Some(Logical::Undefined), Physical::Null),
        ("bool", None, Physical::Bool(true)),
        ("int8", None, Physical::Int(Int::I8(i8::MIN))),
        ("uint8", None, Physical::Int(Int::U8(u8::MAX))),
        ("int16", None, Physical::Int(Int::I16(i16::MIN))),
        ("uint16", None, Physical::Int(Int::U16(u16::MAX))),
        ("int32", None, Physical::Int(Int::I32(-32))),
        ("uint32", None, Physical::Int(Int::U32(u32::MAX))),
        ("int64", None, Physical::Int(Int::I64(i64::MIN))),
        ("uint64", None, Physical::Int(Int::U64(u64::MAX))),
        ("int128", None, Physical::Int(Int::I128(i128::MIN))),
        ("uint128", None, Physical::Int(Int::U128(u128::MAX))),
        ("float32", None, Physical::Float(Float::F32(1.5))),
        ("float64", None, Physical::Float(Float::F64(2.5))),
        ("string", None, Physical::Text("hello")),
        ("bytes", None, Physical::Bytes(&[0, 255])),
        ("date", Some(Logical::Date), Physical::Int(Int::I32(19782))),
        (
            "timestamp",
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I64(0)),
        ),
        (
            "timestampMillis",
            Some(Logical::Timestamp(TimeUnit::Millis)),
            Physical::Int(Int::I64(-1)),
        ),
        (
            "timestampMicros",
            Some(Logical::Timestamp(TimeUnit::Micros)),
            Physical::Int(Int::I64(1)),
        ),
        (
            "timestampNanos",
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I64(-1)),
        ),
        (
            "decimal",
            Some(Logical::Decimal { scale: 2 }),
            Physical::Int(Int::I128(150)),
        ),
        (
            "uuid",
            Some(Logical::Uuid),
            Physical::Bytes(&[
                0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17,
                0x40, 0x00,
            ]),
        ),
    ];
    let mut exports = Object::new(env)?;
    for (name, ty, value) in samples {
        let built = JsBuilder::new(env).scalar(ty, value)?;
        exports.set_named_property(name, built)?;
    }
    // Containers and passthrough, built through the whole walk.
    let frame = to_frame(Nest {
        levels: 1,
        wrap: "array".into(),
    })
    .map_err(|_| Error::from_reason("frame"))?;
    let array = JsBuilder::build(
        env,
        Frame::parse(frame.risky_ref()).map_err(|_| Error::from_reason("frame"))?,
    )?;
    exports.set_named_property("array", array)?;
    let frame = to_frame(Nest {
        levels: 1,
        wrap: "object".into(),
    })
    .map_err(|_| Error::from_reason("frame"))?;
    let object = JsBuilder::build(
        env,
        Frame::parse(frame.risky_ref()).map_err(|_| Error::from_reason("frame"))?,
    )?;
    exports.set_named_property("object", object)?;
    let frame = to_frame(Nest {
        levels: 1,
        wrap: "passthrough".into(),
    })
    .map_err(|_| Error::from_reason("frame"))?;
    let passthrough = JsBuilder::build(
        env,
        Frame::parse(frame.risky_ref()).map_err(|_| Error::from_reason("frame"))?,
    )?;
    exports.set_named_property("passthrough", passthrough)?;
    Ok(exports)
}

/// A known logical type over a value it does not admit, sent straight to
/// the build, which must refuse it rather than show the physical value. A
/// frame never gets this far: `Frame::parse` checks what each type admits.
#[napi]
pub fn build_mismatched<'e>(env: &'e Env, case: String) -> Result<Unknown<'e>> {
    let (ty, value) = match case.as_str() {
        "date-over-text" => (Logical::Date, Physical::Text("2024-02-29")),
        "date-out-of-range" => (Logical::Date, Physical::Int(Int::I128(i128::MAX))),
        "timestamp-out-of-range" => (
            Logical::Timestamp(TimeUnit::Nanos),
            Physical::Int(Int::I128(i128::MAX)),
        ),
        "uuid-short" => (Logical::Uuid, Physical::Bytes(&[0; 15])),
        "decimal-scale" => (Logical::Decimal { scale: 29 }, Physical::Int(Int::I128(1))),
        other => return Err(Error::from_reason(format!("no such case: {other}"))),
    };
    Ok(JsBuilder::new(env).scalar(Some(ty), value)?)
}

/// A frame carrying a logical type this binding does not know, to pin that
/// the build refuses it rather than dropping the type.
#[napi]
pub fn unknown_logical_frame() -> Buffer {
    // The `0xF3` envelope: id 200, parameter 0, over an int8 of 7.
    Buffer::from(vec![0xF3, 200, 0, 0x0C, 7])
}
