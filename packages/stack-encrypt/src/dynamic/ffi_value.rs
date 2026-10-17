//! The value tree a binding's control data decodes into: [`FfiValue`], and
//! the kinds a plan field declares ([`ValueKind`]).
//!
//! **`FfiValue` is not plaintext's type.** It carries what a binding sends to
//! describe an operation and set the engine up: a plan, a context, an
//! options object, a query's statistics, a binding's configuration, and what
//! the engine answers (a query term's wire object, a catalog). That is not
//! all public: a configuration carries credentials (the Go guest's
//! `cipher_init` config holds the client key, and a deterministic test
//! build's seed arrives as [`FfiValue::Bytes`]), so the [`Protected`] text
//! and bytes leaves are what keeps those wiped, not a courtesy. vitaminc 0.6 has no shared value
//! type (vitaminc ADR 0001): a value describes itself once, and sinks
//! consume it. So a plaintext the engine holds is a
//! [`ValueFrame`](super::ValueFrame), one value as its transport frame in a
//! wiped buffer, and every plaintext path (a record's source and what it
//! opens to, a query's input, a page to verify, an EQL target's plaintext)
//! walks frames into sinks with no tree in between.
//!
//! `FfiValue` still describes itself to vitaminc ([`Encrypt`]) and can be
//! read back from a walk ([`Decrypt`]), because that is how control data
//! crosses a binding's boundary as a transport frame
//! ([`to_frame`](FfiValue::to_frame), [`from_frame`](FfiValue::from_frame)).
//! The same impls let a Rust test spell a value as a tree and hand it to an
//! entry point that takes any source; the engine walks it and keeps none of
//! it. Do not seal through an `FfiValue` in code a binding runs: decode a
//! host's plaintext into a [`ValueFrame`](super::ValueFrame) instead.

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use vitaminc_aead::frame::{FrameError, FrameWriteError};
use vitaminc_aead::plaintext::{
    visit_map, visit_seq, Error as _, Float, Int, Logical, MapSink, Physical, SeqSink, Sink,
    SourceError,
};
use vitaminc_aead::{to_frame, DecodeError, Decrypt, Encrypt, Frame};
use vitaminc_protected::{Controlled, Protected};
use zeroize::Zeroize;

use crate::plan::IntoLabel;
use crate::{Label, LabelError};

/// An owned, `Send`, language-neutral tree of a binding's control data: a
/// plan, a context, options, statistics, configuration, and the engine's
/// answers. Not plaintext: a binding's plaintext is a
/// [`ValueFrame`](super::ValueFrame) (vitaminc ADR 0001 removed the shared
/// value type). Text and bytes leaves are held in [`Protected`] and wiped
/// on drop, and must stay so: control data includes credentials (a client
/// key in a configuration, a seed as bytes).
///
/// Each variant is one of vitaminc's scalars or containers: `Null` is a
/// null, `Undefined` a null under the `Undefined` logical type, the
/// numeric variants are ints and floats of their width, `String` is text,
/// `Bytes` bytes, `Array` a sequence, `Object` a map, and `Passthrough` a
/// subtree that travels in the clear. So a value seals as the leaves a
/// typed Rust value of the same kind seals as: `UInt32(34)` and `34u32`
/// are the same ciphertext under the same context.
#[derive(Zeroize)]
pub enum FfiValue {
    /// Null (JS `null`, Python `None`, Go `nil`).
    Null,
    /// JavaScript `undefined`. Languages without an analog decode this to
    /// their null value and never encode it.
    Undefined,
    /// Boolean.
    Bool(bool),
    /// 32-bit signed integer.
    Int32(i32),
    /// 64-bit signed integer.
    Int64(i64),
    /// 32-bit unsigned integer.
    UInt32(u32),
    /// 64-bit unsigned integer.
    UInt64(u64),
    /// 32-bit floating-point number. Round-trips by IEEE-754 bit pattern.
    Float32(f32),
    /// 64-bit floating-point number. Round-trips by IEEE-754 bit pattern.
    Float64(f64),
    /// String as UTF-8 bytes, validated at construction ([`Utf8String`]).
    String(Utf8String),
    /// Binary data.
    Bytes(Protected<Vec<u8>>),
    /// Array: a sequence.
    Array(Vec<FfiValue>),
    /// String-keyed object: a map. Keys travel in the clear, bound into
    /// each value's AAD.
    Object(Vec<(String, FfiValue)>),
    /// A subtree that travels alongside the ciphertext **unencrypted and
    /// unauthenticated**. Non-sensitive fields only: anyone holding the
    /// ciphertext can read and alter it.
    // Skipped by `Zeroize`: the payload is non-sensitive by contract (it is
    // sent in the clear), and `Box<T>` is not `Zeroize` anyway.
    #[zeroize(skip)]
    Passthrough(Box<FfiValue>),
}

/// UTF-8 string payload for [`FfiValue::String`], validated at construction.
///
/// Wraps `Protected<Vec<u8>>` with the invariant that the bytes are valid
/// UTF-8, so a `String` leaf can never seal bytes that would not read back
/// as text.
#[derive(Zeroize)]
pub struct Utf8String(Protected<Vec<u8>>);

impl Utf8String {
    /// The validated UTF-8 bytes. Same chain-of-custody caveats as
    /// [`Protected::risky_ref`]: the reference must not outlive its use.
    pub fn risky_ref(&self) -> &[u8] {
        self.0.risky_ref()
    }

    /// Unwrap to the protected byte payload (still valid UTF-8; the
    /// invariant is dropped with the type).
    pub fn into_inner(self) -> Protected<Vec<u8>> {
        self.0
    }

    /// The text. `None` cannot happen while the invariant holds; it is
    /// checked rather than assumed because this is boundary code.
    fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.0.risky_ref()).ok()
    }
}

impl From<String> for Utf8String {
    fn from(s: String) -> Self {
        Self(Protected::new(s.into_bytes()))
    }
}

impl From<&str> for Utf8String {
    fn from(s: &str) -> Self {
        Self(Protected::new(s.as_bytes().to_vec()))
    }
}

impl TryFrom<Protected<Vec<u8>>> for Utf8String {
    type Error = vitaminc_aead::Unspecified;

    /// Validates the bytes; on failure the rejected payload is dropped (and
    /// wiped) here.
    fn try_from(bytes: Protected<Vec<u8>>) -> Result<Self, Self::Error> {
        let _ = std::str::from_utf8(bytes.risky_ref()).map_err(|_| vitaminc_aead::Unspecified)?;
        Ok(Self(bytes))
    }
}

/// A deep copy, each text and bytes leaf into a fresh [`Protected`], which
/// wipes on drop as the original does, so a copy is under the same custody
/// as the value it was made from.
///
/// The engine hands a borrowed field to every operation that consumes it and
/// clones it on the way in, as it does a `String` field of a derived record,
/// so a field's plaintext type is `Clone`; this is what lets an `FfiValue`
/// be that type for every field lowered from data. A record of a few fields
/// clones each once per operation that consumes it, as the derive's does.
impl Clone for FfiValue {
    fn clone(&self) -> Self {
        // Exhaustive, so a variant added later has to say how it is copied.
        match self {
            FfiValue::Null => FfiValue::Null,
            FfiValue::Undefined => FfiValue::Undefined,
            FfiValue::Bool(v) => FfiValue::Bool(*v),
            FfiValue::Int32(v) => FfiValue::Int32(*v),
            FfiValue::Int64(v) => FfiValue::Int64(*v),
            FfiValue::UInt32(v) => FfiValue::UInt32(*v),
            FfiValue::UInt64(v) => FfiValue::UInt64(*v),
            FfiValue::Float32(v) => FfiValue::Float32(*v),
            FfiValue::Float64(v) => FfiValue::Float64(*v),
            FfiValue::String(s) => FfiValue::String(s.clone()),
            FfiValue::Bytes(b) => FfiValue::Bytes(Protected::new(b.risky_ref().to_vec())),
            FfiValue::Array(items) => FfiValue::Array(items.clone()),
            FfiValue::Object(entries) => FfiValue::Object(entries.clone()),
            FfiValue::Passthrough(inner) => FfiValue::Passthrough(inner.clone()),
        }
    }
}

/// A copy of the text in a fresh [`Protected`]: valid UTF-8 because the
/// original is.
impl Clone for Utf8String {
    fn clone(&self) -> Self {
        Self(Protected::new(self.0.risky_ref().to_vec()))
    }
}

/// A string value read as a plan's context: what a data plan's
/// `"context_field"` holds (`"tenants/acme"`), parsed as a Rust chain's
/// `String` context field is ([`Label::parse`]). Any other variant is
/// [`LabelError::NotText`], which the plan reports as
/// `PlanError::ContextLabel` before any key is requested.
impl IntoLabel for FfiValue {
    fn into_label(self) -> Result<Label, LabelError> {
        match &self {
            FfiValue::String(s) => match s.as_str() {
                Some(text) => Label::parse(text),
                None => Err(LabelError::NotText),
            },
            _ => Err(LabelError::NotText),
        }
    }
}

impl FfiValue {
    /// This value as a transport frame: what a binding hands its host.
    ///
    /// # Errors
    ///
    /// [`FrameWriteError`] for a value nested deeper than the frame
    /// carries, or an object with a repeated key.
    pub fn to_frame(&self) -> Result<Protected<Vec<u8>>, FrameWriteError> {
        to_frame(self)
    }

    /// Read one value from a transport frame: what a host hands a binding.
    ///
    /// # Errors
    ///
    /// [`FromFrameError`] when the bytes are not exactly one frame, or the
    /// frame holds a scalar no variant holds (an 8-bit integer, a date).
    pub fn from_frame(bytes: &[u8]) -> Result<Self, FromFrameError> {
        let frame = Frame::parse(bytes).map_err(FromFrameError::Frame)?;
        frame.visit(Self::sink()).map_err(FromFrameError::Value)
    }
}

/// Why [`FfiValue::from_frame`] refused its bytes.
#[derive(Debug, thiserror::Error)]
pub enum FromFrameError {
    /// The bytes are not exactly one well-formed frame.
    #[error(transparent)]
    Frame(FrameError),
    /// The frame holds a value no [`FfiValue`] variant holds.
    #[error(transparent)]
    Value(DecodeError),
}

/// Walks the value, leaving it where it is. Text and bytes are handed to
/// the sink as borrows of the `Protected` payloads.
impl Encrypt for &FfiValue {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        match self {
            FfiValue::Null => sink.scalar(None, Physical::Null),
            FfiValue::Undefined => sink.scalar(Some(Logical::Undefined), Physical::Null),
            FfiValue::Bool(b) => sink.scalar(None, Physical::Bool(*b)),
            FfiValue::Int32(i) => sink.scalar(None, Physical::Int(Int::I32(*i))),
            FfiValue::Int64(i) => sink.scalar(None, Physical::Int(Int::I64(*i))),
            FfiValue::UInt32(u) => sink.scalar(None, Physical::Int(Int::U32(*u))),
            FfiValue::UInt64(u) => sink.scalar(None, Physical::Int(Int::U64(*u))),
            FfiValue::Float32(f) => sink.scalar(None, Physical::Float(Float::F32(*f))),
            FfiValue::Float64(f) => sink.scalar(None, Physical::Float(Float::F64(*f))),
            FfiValue::String(s) => match s.as_str() {
                Some(text) => sink.scalar(None, Physical::Text(text)),
                None => Err(S::Error::source(SourceError::msg("a string is not UTF-8"))),
            },
            FfiValue::Bytes(b) => sink.scalar(None, Physical::Bytes(b.risky_ref())),
            FfiValue::Array(items) => visit_seq(sink, Some(items.len()), items),
            FfiValue::Object(entries) => visit_map(
                sink,
                Some(entries.len()),
                entries.iter().map(|(key, value)| (key.as_str(), value)),
            ),
            FfiValue::Passthrough(inner) => sink.passthrough(&**inner),
        }
    }
}

/// Walks the value by reference, then drops it, which wipes its text and
/// bytes.
impl Encrypt for FfiValue {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (&self).visit(sink)
    }
}

impl Decrypt for FfiValue {
    type Sink = ValueSink<Root>;
    fn sink() -> Self::Sink {
        ValueSink(Root)
    }
}

/// Where a finished value goes: back to the caller, or into its parent.
pub trait Put {
    /// What putting a value produces.
    type Ok;
    /// Put `value` in place.
    fn put(self, value: FfiValue) -> Self::Ok;
}

/// The top of a walk: the value is the result.
pub struct Root;

impl Put for Root {
    type Ok = FfiValue;
    fn put(self, value: FfiValue) -> FfiValue {
        value
    }
}

/// The next element of an array under construction.
pub struct Element<'s>(&'s mut Vec<FfiValue>);

impl Put for Element<'_> {
    type Ok = ();
    fn put(self, value: FfiValue) {
        self.0.push(value);
    }
}

/// One entry of an object under construction.
pub struct Entry<'s>(&'s mut Vec<(String, FfiValue)>, String);

impl Put for Entry<'_> {
    type Ok = ();
    fn put(self, value: FfiValue) {
        self.0.push((self.1, value));
    }
}

/// The [`Decrypt`] sink of an [`FfiValue`]: builds the value a walk
/// describes. An 8- or 16-bit integer reads as the 32-bit variant of its
/// sign, which holds it exactly: a host with narrower integers (Go's `int8`,
/// say) sends them at their own width, and the value model has no variant
/// for them. A scalar no variant holds (a 128-bit integer, or a logical
/// type other than `Undefined`) is refused.
pub struct ValueSink<O>(O);

impl<O: Put> ValueSink<O> {
    /// A sink that puts the value it builds into `out`.
    pub fn new(out: O) -> Self {
        Self(out)
    }
}

/// What [`ValueSink`] refuses a scalar with.
const EXPECTED: &str = "a null, bool, int of at most 64 bits, float, string or bytes";

impl<O: Put> Sink for ValueSink<O> {
    type Ok = O::Ok;
    type Error = DecodeError;
    type Seq = ValueSeq<O>;
    type Map = ValueMap<O>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<O::Ok, DecodeError> {
        let value = match (ty, value) {
            (None, Physical::Null) => FfiValue::Null,
            (Some(Logical::Undefined), Physical::Null) => FfiValue::Undefined,
            (None, Physical::Bool(b)) => FfiValue::Bool(b),
            (None, Physical::Int(Int::I8(i))) => FfiValue::Int32(i.into()),
            (None, Physical::Int(Int::I16(i))) => FfiValue::Int32(i.into()),
            (None, Physical::Int(Int::I32(i))) => FfiValue::Int32(i),
            (None, Physical::Int(Int::I64(i))) => FfiValue::Int64(i),
            (None, Physical::Int(Int::U8(u))) => FfiValue::UInt32(u.into()),
            (None, Physical::Int(Int::U16(u))) => FfiValue::UInt32(u.into()),
            (None, Physical::Int(Int::U32(u))) => FfiValue::UInt32(u),
            (None, Physical::Int(Int::U64(u))) => FfiValue::UInt64(u),
            (None, Physical::Float(Float::F32(f))) => FfiValue::Float32(f),
            (None, Physical::Float(Float::F64(f))) => FfiValue::Float64(f),
            (None, Physical::Text(text)) => FfiValue::String(text.into()),
            (None, Physical::Bytes(bytes)) => FfiValue::Bytes(Protected::new(bytes.to_vec())),
            _ => return Err(DecodeError::Expected(EXPECTED)),
        };
        Ok(self.0.put(value))
    }

    fn seq(self, _: Option<usize>) -> Result<ValueSeq<O>, DecodeError> {
        Ok(ValueSeq {
            out: self.0,
            items: Vec::new(),
        })
    }

    fn map(self, _: Option<usize>) -> Result<ValueMap<O>, DecodeError> {
        Ok(ValueMap {
            out: self.0,
            entries: Vec::new(),
            keys: BTreeSet::new(),
        })
    }

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<O::Ok, DecodeError> {
        let inner = value.visit(ValueSink(Root))?;
        Ok(self.0.put(FfiValue::Passthrough(Box::new(inner))))
    }
}

/// The sequence sink of [`ValueSink`].
pub struct ValueSeq<O> {
    out: O,
    items: Vec<FfiValue>,
}

impl<O: Put> SeqSink for ValueSeq<O> {
    type Ok = O::Ok;
    type Error = DecodeError;
    type Element<'s>
        = ValueSink<Element<'s>>
    where
        Self: 's;

    fn element(&mut self) -> Result<ValueSink<Element<'_>>, DecodeError> {
        Ok(ValueSink(Element(&mut self.items)))
    }

    fn end(self) -> Result<O::Ok, DecodeError> {
        Ok(self.out.put(FfiValue::Array(self.items)))
    }
}

/// The map sink of [`ValueSink`]. A repeated key is refused, as an object
/// holds each key once.
pub struct ValueMap<O> {
    out: O,
    entries: Vec<(String, FfiValue)>,
    /// The keys seen so far, so the repeated-key check is a lookup rather
    /// than a scan of `entries`: a frame is host input, and a scan made an
    /// object of `n` keys cost `n²` comparisons. Ordered rather than hashed,
    /// so no key can be chosen to collide.
    keys: BTreeSet<String>,
}

impl<O: Put> MapSink for ValueMap<O> {
    type Ok = O::Ok;
    type Error = DecodeError;
    type Entry<'s>
        = ValueSink<Entry<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<ValueSink<Entry<'_>>, DecodeError> {
        if !self.keys.insert(key.to_owned()) {
            return Err(DecodeError::duplicate_key(key));
        }
        Ok(ValueSink(Entry(&mut self.entries, key.to_owned())))
    }

    fn end(self) -> Result<O::Ok, DecodeError> {
        Ok(self.out.put(FfiValue::Object(self.entries)))
    }
}

#[cfg(test)]
impl PartialEq for FfiValue {
    /// Structural equality for tests only. Variable-time, which is why
    /// this is `cfg(test)`. Floats compare by raw bit pattern so `-0.0` and
    /// `NaN` payloads compare as they seal.
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (FfiValue::Null, FfiValue::Null) => true,
            (FfiValue::Undefined, FfiValue::Undefined) => true,
            (FfiValue::Bool(a), FfiValue::Bool(b)) => a == b,
            (FfiValue::Int32(a), FfiValue::Int32(b)) => a == b,
            (FfiValue::Int64(a), FfiValue::Int64(b)) => a == b,
            (FfiValue::UInt32(a), FfiValue::UInt32(b)) => a == b,
            (FfiValue::UInt64(a), FfiValue::UInt64(b)) => a == b,
            (FfiValue::Float32(a), FfiValue::Float32(b)) => a.to_bits() == b.to_bits(),
            (FfiValue::Float64(a), FfiValue::Float64(b)) => a.to_bits() == b.to_bits(),
            (FfiValue::String(a), FfiValue::String(b)) => a.risky_ref() == b.risky_ref(),
            (FfiValue::Bytes(a), FfiValue::Bytes(b)) => a.risky_ref() == b.risky_ref(),
            (FfiValue::Array(a), FfiValue::Array(b)) => a == b,
            (FfiValue::Object(a), FfiValue::Object(b)) => a == b,
            (FfiValue::Passthrough(a), FfiValue::Passthrough(b)) => a == b,
            _ => false,
        }
    }
}

/// Names the variant and nothing more of a string or bytes: the value is
/// plaintext.
impl fmt::Debug for FfiValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FfiValue::Null => f.write_str("Null"),
            FfiValue::Undefined => f.write_str("Undefined"),
            FfiValue::Bool(b) => write!(f, "Bool({b})"),
            FfiValue::Int32(i) => write!(f, "Int32({i})"),
            FfiValue::Int64(i) => write!(f, "Int64({i})"),
            FfiValue::UInt32(u) => write!(f, "UInt32({u})"),
            FfiValue::UInt64(u) => write!(f, "UInt64({u})"),
            FfiValue::Float32(n) => write!(f, "Float32({n})"),
            FfiValue::Float64(n) => write!(f, "Float64({n})"),
            FfiValue::String(_) => f.write_str("String(<redacted>)"),
            FfiValue::Bytes(_) => f.write_str("Bytes(<redacted>)"),
            FfiValue::Array(items) => f.debug_tuple("Array").field(items).finish(),
            FfiValue::Object(entries) => f.debug_tuple("Object").field(entries).finish(),
            FfiValue::Passthrough(inner) => f.debug_tuple("Passthrough").field(inner).finish(),
        }
    }
}

/// The kind of an [`FfiValue`]: its variant, without a payload. This is the
/// type vocabulary a plan field declares in its `"type"` key.
///
/// `Null`, `Undefined` and `Passthrough` have no kind: each null is a type
/// with one value, so declaring a field as one says nothing, and a
/// passthrough is a transport choice, not a type.
///
/// # Names are wire format
///
/// [`name`](Self::name) (also its [`Display`](fmt::Display) and [`FromStr`]
/// form) is how a binding spells a kind. The names are frozen: matched
/// exactly, case-sensitively, and never renamed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ValueKind {
    /// `"bool"`.
    Bool,
    /// `"int8"`.
    Int8,
    /// `"int16"`.
    Int16,
    /// `"int32"`.
    Int32,
    /// `"int64"`.
    Int64,
    /// `"int128"`.
    Int128,
    /// `"uint8"`.
    UInt8,
    /// `"uint16"`.
    UInt16,
    /// `"uint32"`.
    UInt32,
    /// `"uint64"`.
    UInt64,
    /// `"uint128"`.
    UInt128,
    /// `"float32"`.
    Float32,
    /// `"float64"`.
    Float64,
    /// `"decimal"`: vitaminc's `Decimal` logical type, a mantissa and a
    /// scale.
    Decimal,
    /// `"date"`: vitaminc's `Date` logical type, a calendar date with no
    /// time or zone.
    Date,
    /// `"timestamp"`: vitaminc's `Timestamp` logical type, an instant in
    /// UTC, to the nanosecond.
    Timestamp,
    /// `"string"`.
    String,
    /// `"bytes"`.
    Bytes,
    /// `"array"`. Says nothing about the elements' kinds.
    Array,
    /// `"object"`. Says nothing about the entries' kinds.
    Object,
}

impl ValueKind {
    /// Every kind, in declaration order.
    pub const ALL: [ValueKind; 20] = [
        ValueKind::Bool,
        ValueKind::Int8,
        ValueKind::Int16,
        ValueKind::Int32,
        ValueKind::Int64,
        ValueKind::Int128,
        ValueKind::UInt8,
        ValueKind::UInt16,
        ValueKind::UInt32,
        ValueKind::UInt64,
        ValueKind::UInt128,
        ValueKind::Float32,
        ValueKind::Float64,
        ValueKind::Decimal,
        ValueKind::Date,
        ValueKind::Timestamp,
        ValueKind::String,
        ValueKind::Bytes,
        ValueKind::Array,
        ValueKind::Object,
    ];

    /// How a declaration spells this kind: `"bool"`, `"int8"`, `"int16"`,
    /// `"int32"`, `"int64"`, `"int128"`, `"uint8"`, `"uint16"`, `"uint32"`,
    /// `"uint64"`, `"uint128"`, `"float32"`, `"float64"`, `"decimal"`,
    /// `"date"`, `"timestamp"`, `"string"`, `"bytes"`, `"array"` or
    /// `"object"`. Frozen wire format.
    pub const fn name(self) -> &'static str {
        match self {
            ValueKind::Bool => "bool",
            ValueKind::Int8 => "int8",
            ValueKind::Int16 => "int16",
            ValueKind::Int32 => "int32",
            ValueKind::Int64 => "int64",
            ValueKind::Int128 => "int128",
            ValueKind::UInt8 => "uint8",
            ValueKind::UInt16 => "uint16",
            ValueKind::UInt32 => "uint32",
            ValueKind::UInt64 => "uint64",
            ValueKind::UInt128 => "uint128",
            ValueKind::Float32 => "float32",
            ValueKind::Float64 => "float64",
            ValueKind::Decimal => "decimal",
            ValueKind::Date => "date",
            ValueKind::Timestamp => "timestamp",
            ValueKind::String => "string",
            ValueKind::Bytes => "bytes",
            ValueKind::Array => "array",
            ValueKind::Object => "object",
        }
    }

    /// Whether `value` is of this kind. Exact: an `Int64` is not held by
    /// [`UInt64`](Self::UInt64), and a [`FfiValue::Passthrough`] is held by
    /// no kind, whatever it wraps. A control-data tree has no 8-, 16- or
    /// 128-bit integer, decimal, date or timestamp, so no `FfiValue` is of
    /// those kinds; a [`ValueFrame`](super::ValueFrame) can be
    /// ([`ValueFrame::kind`](super::ValueFrame::kind)).
    pub fn holds(self, value: &FfiValue) -> bool {
        value.kind() == Some(self)
    }
}

impl fmt::Display for ValueKind {
    /// Writes [`name`](Self::name).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for ValueKind {
    type Err = ParseValueKindError;

    /// Parses a [`name`](Self::name), exactly: `"uint64"`, not `"UInt64"`,
    /// `"u64"` or `" uint64"`. `"null"` and `"undefined"` are not kinds.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        ValueKind::ALL
            .into_iter()
            .find(|kind| kind.name() == name)
            .ok_or(ParseValueKindError)
    }
}

/// The error from parsing a string that is not a [`ValueKind::name`].
/// Carries no detail: the caller holds the string it tried to parse.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("not a value kind")]
pub struct ParseValueKindError;

impl FfiValue {
    /// This value's [`ValueKind`], or `None` for [`Null`](FfiValue::Null),
    /// [`Undefined`](FfiValue::Undefined) and
    /// [`Passthrough`](FfiValue::Passthrough).
    pub fn kind(&self) -> Option<ValueKind> {
        // Exhaustive on purpose: a new variant must decide its kind here.
        match self {
            FfiValue::Bool(_) => Some(ValueKind::Bool),
            FfiValue::Int32(_) => Some(ValueKind::Int32),
            FfiValue::Int64(_) => Some(ValueKind::Int64),
            FfiValue::UInt32(_) => Some(ValueKind::UInt32),
            FfiValue::UInt64(_) => Some(ValueKind::UInt64),
            FfiValue::Float32(_) => Some(ValueKind::Float32),
            FfiValue::Float64(_) => Some(ValueKind::Float64),
            FfiValue::String(_) => Some(ValueKind::String),
            FfiValue::Bytes(_) => Some(ValueKind::Bytes),
            FfiValue::Array(_) => Some(ValueKind::Array),
            FfiValue::Object(_) => Some(ValueKind::Object),
            FfiValue::Null | FfiValue::Undefined | FfiValue::Passthrough(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(value: &str) -> FfiValue {
        FfiValue::String(value.into())
    }

    fn every_variant() -> FfiValue {
        FfiValue::Object(vec![
            ("n".to_string(), FfiValue::Null),
            ("u".to_string(), FfiValue::Undefined),
            ("b".to_string(), FfiValue::Bool(true)),
            ("i32".to_string(), FfiValue::Int32(-3)),
            ("i64".to_string(), FfiValue::Int64(-4)),
            ("u32".to_string(), FfiValue::UInt32(34)),
            ("u64".to_string(), FfiValue::UInt64(u64::MAX)),
            ("f32".to_string(), FfiValue::Float32(-0.0)),
            ("f64".to_string(), FfiValue::Float64(f64::NAN)),
            ("s".to_string(), s("alice")),
            (
                "bytes".to_string(),
                FfiValue::Bytes(Protected::new(vec![1, 2, 3])),
            ),
            (
                "list".to_string(),
                FfiValue::Array(vec![s("a"), FfiValue::Passthrough(Box::new(s("p")))]),
            ),
            ("empty".to_string(), FfiValue::Array(vec![])),
        ])
    }

    /// A clone is the same value, leaf for leaf, at every depth and for
    /// every variant, and shares no payload with its original.
    #[test]
    fn a_clone_is_the_same_value_in_fresh_payloads() {
        let original = every_variant();
        let copy = original.clone();
        assert_eq!(copy, original, "the same value");
        let (FfiValue::Object(a), FfiValue::Object(b)) = (&original, &copy) else {
            panic!("objects");
        };
        let (FfiValue::String(x), FfiValue::String(y)) = (&a[9].1, &b[9].1) else {
            panic!("strings");
        };
        assert_ne!(
            x.risky_ref().as_ptr(),
            y.risky_ref().as_ptr(),
            "the text was copied, not shared"
        );
        let (FfiValue::Bytes(x), FfiValue::Bytes(y)) = (&a[10].1, &b[10].1) else {
            panic!("bytes");
        };
        assert_ne!(
            x.risky_ref().as_ptr(),
            y.risky_ref().as_ptr(),
            "the bytes were copied, not shared"
        );
    }

    #[test]
    fn a_string_reads_as_a_label_and_nothing_else_does() {
        assert_eq!(
            s("tenants/acme").into_label().expect("a label"),
            Label::parse("tenants/acme").expect("a label")
        );
        assert!(matches!(
            FfiValue::UInt32(7).into_label(),
            Err(LabelError::NotText)
        ));
    }

    /// Reading an object refuses a key it has already read, wherever the
    /// repeat falls.
    #[test]
    fn reading_a_repeated_key_is_refused() {
        let keys: Vec<String> = (0..1000).map(|i| format!("k{i}")).collect();
        let entries = |repeat: &str| {
            let mut entries: Vec<(String, FfiValue)> =
                keys.iter().map(|k| (k.clone(), FfiValue::Null)).collect();
            entries.push((repeat.to_string(), FfiValue::Null));
            FfiValue::Object(entries)
        };
        for repeat in ["k0", "k500", "k999"] {
            let refused = entries(repeat).visit(FfiValue::sink());
            assert!(refused.is_err(), "{repeat} read twice is refused");
        }
        let read = entries("k1000")
            .visit(FfiValue::sink())
            .expect("all distinct");
        assert!(matches!(read, FfiValue::Object(e) if e.len() == 1001));
    }

    #[test]
    fn every_variant_survives_a_frame_round_trip() {
        let frame = every_variant().to_frame().expect("frames");
        let back = FfiValue::from_frame(frame.risky_ref()).expect("reads back");
        assert_eq!(back, every_variant(), "the same value, variant for variant");
    }

    /// The width of an integer is part of the value: an `Int32` frames as a
    /// 32-bit int and reads back as one, not as the 64-bit variant.
    #[test]
    fn integer_widths_are_kept_apart() {
        for value in [
            FfiValue::Int32(7),
            FfiValue::Int64(7),
            FfiValue::UInt32(7),
            FfiValue::UInt64(7),
        ] {
            let frame = value.to_frame().expect("frames");
            let back = FfiValue::from_frame(frame.risky_ref()).expect("reads back");
            assert_eq!(back.kind(), value.kind(), "{value:?} kept its width");
        }
    }

    /// A narrower integer reads as the 32-bit variant of its sign, which
    /// holds it exactly.
    #[test]
    fn a_narrower_integer_reads_as_the_32_bit_variant_of_its_sign() {
        let read = |frame: Protected<Vec<u8>>| {
            FfiValue::from_frame(frame.risky_ref()).expect("reads back")
        };
        assert_eq!(
            read(vitaminc_aead::to_frame(-8i8).expect("frames")),
            FfiValue::Int32(-8)
        );
        assert_eq!(
            read(vitaminc_aead::to_frame(i16::MIN).expect("frames")),
            FfiValue::Int32(i16::MIN.into())
        );
        assert_eq!(
            read(vitaminc_aead::to_frame(u16::MAX).expect("frames")),
            FfiValue::UInt32(u16::MAX.into())
        );
        // No Rust source walks a `u8` as an int (`Vec<u8>` is bytes), but a
        // host's frame can carry one: the `UINT8` tag and its byte.
        assert_eq!(
            FfiValue::from_frame(&[vitaminc_aead::tags::UINT8, 200]).expect("reads back"),
            FfiValue::UInt32(200)
        );
    }

    /// A frame holding a scalar no variant holds is refused, not read as
    /// the nearest variant.
    #[test]
    fn a_scalar_no_variant_holds_is_refused() {
        for frame in [
            vitaminc_aead::to_frame(7u128).expect("frames"),
            vitaminc_aead::to_frame(-7i128).expect("frames"),
        ] {
            assert!(matches!(
                FfiValue::from_frame(frame.risky_ref()),
                Err(FromFrameError::Value(DecodeError::Expected(_)))
            ));
        }
    }

    #[test]
    fn bytes_that_are_not_one_frame_are_refused() {
        assert!(matches!(
            FfiValue::from_frame(&[]),
            Err(FromFrameError::Frame(_))
        ));
        let mut frame = FfiValue::Null.to_frame().expect("frames").risky_unwrap();
        frame.push(0);
        assert!(matches!(
            FfiValue::from_frame(&frame),
            Err(FromFrameError::Frame(_))
        ));
    }

    #[test]
    fn debug_redacts_text_and_bytes() {
        assert_eq!(format!("{:?}", s("secret")), "String(<redacted>)");
        assert_eq!(
            format!("{:?}", FfiValue::Bytes(Protected::new(vec![1]))),
            "Bytes(<redacted>)"
        );
        assert_eq!(format!("{:?}", FfiValue::UInt32(34)), "UInt32(34)");
    }

    /// Every variant's `Debug` form: numbers and booleans print, text and
    /// bytes are redacted at any depth, so a container or a passthrough
    /// holding a secret prints none of it.
    #[test]
    fn debug_prints_every_variant_and_redacts_at_any_depth() {
        let cases = [
            (FfiValue::Null, "Null"),
            (FfiValue::Undefined, "Undefined"),
            (FfiValue::Bool(true), "Bool(true)"),
            (FfiValue::Int32(-1), "Int32(-1)"),
            (FfiValue::Int64(-2), "Int64(-2)"),
            (FfiValue::UInt64(3), "UInt64(3)"),
            (FfiValue::Float32(1.5), "Float32(1.5)"),
            (FfiValue::Float64(2.5), "Float64(2.5)"),
            (
                FfiValue::Array(vec![s("secret"), FfiValue::UInt32(1)]),
                "Array([String(<redacted>), UInt32(1)])",
            ),
            (
                FfiValue::Object(vec![("k".into(), s("secret"))]),
                "Object([(\"k\", String(<redacted>))])",
            ),
            (
                FfiValue::Passthrough(Box::new(FfiValue::Bytes(Protected::new(vec![1])))),
                "Passthrough(Bytes(<redacted>))",
            ),
        ];
        for (value, printed) in cases {
            assert_eq!(format!("{value:?}"), printed);
        }
    }

    #[test]
    fn kind_names_parse_back_exactly() {
        let names: Vec<&str> = ValueKind::ALL.iter().map(|kind| kind.name()).collect();
        assert_eq!(
            names,
            [
                "bool",
                "int8",
                "int16",
                "int32",
                "int64",
                "int128",
                "uint8",
                "uint16",
                "uint32",
                "uint64",
                "uint128",
                "float32",
                "float64",
                "decimal",
                "date",
                "timestamp",
                "string",
                "bytes",
                "array",
                "object"
            ],
            "the frozen names"
        );
        for kind in ValueKind::ALL {
            assert_eq!(kind.name().parse::<ValueKind>(), Ok(kind));
            assert_eq!(kind.to_string(), kind.name());
        }
        assert_eq!("UInt64".parse::<ValueKind>(), Err(ParseValueKindError));
        assert_eq!("null".parse::<ValueKind>(), Err(ParseValueKindError));
        assert!(ValueKind::UInt64.holds(&FfiValue::UInt64(34)));
        assert!(!ValueKind::UInt64.holds(&FfiValue::Int64(34)));
        assert_eq!(FfiValue::Passthrough(Box::new(s("p"))).kind(), None);
    }
}
