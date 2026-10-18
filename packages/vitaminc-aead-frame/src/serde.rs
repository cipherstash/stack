//! serde over the transport frame: [`from_slice`] reads frame bytes into
//! any `Deserialize` type, and [`to_vec`] writes any `Serialize` type as
//! frame bytes.
//!
//! This is a serde data format, as `serde_json` is for JSON. It is for data
//! a host exchanges with Rust that is not plaintext to seal: a call's
//! options, a plan, statistics, a result. Plaintext crosses as a frame
//! walked into a [`Sink`], never through
//! serde.
//!
//! # The mapping
//!
//! | Frame | serde |
//! | --- | --- |
//! | object | map, struct |
//! | array | sequence, tuple |
//! | text | `&str`, borrowed from the input |
//! | bytes | `&[u8]`, borrowed from the input |
//! | an integer | that exact width: `i8` … `i128`, `u8` … `u128` |
//! | `f32`, `f64` | that width |
//! | bool | bool |
//! | null | unit, and `None` |
//!
//! A frame keeps an integer's width, and so does this format: a type that
//! reads through `deserialize_any` sees `visit_u32` for a `u32`, never a
//! wider or narrower call. serde's own integer types accept any integer
//! that fits, as they do in every format.
//!
//! An enum is externally tagged. A unit variant is written as its name, a
//! string. Any other variant is an object of one entry, the variant's name
//! mapped to its payload: `{"name": "acme"}`, or `{"default": {}}` for a
//! struct variant with no fields. Reading accepts the same two forms, and
//! treats a missing payload and a null one alike: a bare name reads as a
//! newtype variant whose payload is null (so `Match(Option<Options>)`
//! reads `"match"` as `Match(None)`), and `{"name": null}` reads as a unit
//! variant.
//!
//! serde's `untagged` and `flatten` read through a buffer of their own,
//! which has no 128-bit integers, so a type using either cannot hold an
//! `i128` or `u128`.
//!
//! The format is not human readable ([`is_human_readable`] is `false`), so
//! a type with a compact binary form uses it: a `uuid::Uuid` crosses as its
//! 16 bytes.
//!
//! Not supported, and refused: a passthrough node, and a scalar with a
//! logical type (a date, a timestamp, a decimal), which serde has no data
//! model for.
//!
//! [`is_human_readable`]: ::serde::Deserializer::is_human_readable
//!
//! # Errors never echo a value
//!
//! serde's default messages print the value that did not fit ("invalid
//! type: string \"…\""). This format's [`Error`] names only the kind of
//! value it found, and does not repeat an unknown key, so a message never
//! carries data a host sent: a credential in a configuration, say. Each
//! error records the path of keys and indexes from the root to where it
//! happened ([`Error::path`]), so a caller can say which field was wrong.
//!
//! ```
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! #[serde(deny_unknown_fields)]
//! struct Options {
//!     keyset: Keyset,
//!     #[serde(default, skip_serializing_if = "Option::is_none")]
//!     context: Option<String>,
//! }
//!
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! #[serde(rename_all = "lowercase", deny_unknown_fields)]
//! enum Keyset {
//!     Default {},
//!     Name(String),
//! }
//!
//! let options = Options { keyset: Keyset::Name("acme".into()), context: None };
//! let bytes = vitaminc_aead_frame::serde::to_vec(&options)?;
//! let back: Options = vitaminc_aead_frame::serde::from_slice(&bytes)?;
//! assert_eq!(back, options);
//! # Ok::<(), vitaminc_aead_frame::serde::Error>(())
//! ```

use std::fmt;

use ::serde::de::value::{BorrowedStrDeserializer, UnitDeserializer};
use ::serde::de::{
    self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, Unexpected, VariantAccess, Visitor,
};
use ::serde::ser::{self, Serialize};
use ::serde::Deserialize;
use vitaminc_aead::frame::{ARRAY, OBJECT, PASSTHROUGH};
use vitaminc_aead::leaf::{self, Form};
use vitaminc_aead::plaintext::{Float, Int, Logical, MapSink, Physical, SeqSink, Sink};
use vitaminc_aead::{Encrypt, Frame, FrameWriter};
use zeroize::Zeroize;

// =============================================================================
// Errors
// =============================================================================

/// Why a value could not be read from, or written as, a frame.
///
/// The message names what was wrong and never the value itself. [`path`]
/// is where it happened.
///
/// [`path`]: Error::path
#[derive(Clone, PartialEq, Eq)]
pub struct Error {
    message: String,
    path: Vec<PathSegment>,
}

/// One step from the root of a frame towards a node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathSegment {
    /// An object's entry, by key.
    Key(String),
    /// An array's element, by position.
    Index(usize),
}

impl Error {
    fn new(message: impl fmt::Display) -> Self {
        Self {
            message: message.to_string(),
            path: Vec::new(),
        }
    }

    /// The message, without the path.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The keys and indexes from the root to the node the error is about,
    /// outermost first. Empty for an error about the root.
    pub fn path(&self) -> &[PathSegment] {
        &self.path
    }

    /// The first key on the path: for a struct read from the root, the
    /// field the error is about.
    pub fn field(&self) -> Option<&str> {
        self.path.iter().find_map(|segment| match segment {
            PathSegment::Key(key) => Some(key.as_str()),
            PathSegment::Index(_) => None,
        })
    }

    fn at(mut self, segment: PathSegment) -> Self {
        self.path.insert(0, segment);
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            return f.write_str(&self.message);
        }
        for (i, segment) in self.path.iter().enumerate() {
            match segment {
                PathSegment::Key(key) if i == 0 => write!(f, "{key}")?,
                PathSegment::Key(key) => write!(f, ".{key}")?,
                PathSegment::Index(index) => write!(f, "[{index}]")?,
            }
        }
        write!(f, ": {}", self.message)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error({self})")
    }
}

impl std::error::Error for Error {}

/// The kind of an unexpected value, without the value.
fn kind(unexpected: &Unexpected<'_>) -> &'static str {
    match unexpected {
        Unexpected::Bool(_) => "a boolean",
        Unexpected::Unsigned(_) | Unexpected::Signed(_) => "an integer",
        Unexpected::Float(_) => "a float",
        Unexpected::Char(_) | Unexpected::Str(_) => "a string",
        Unexpected::Bytes(_) => "bytes",
        Unexpected::Unit => "null",
        Unexpected::Option => "an optional value",
        Unexpected::NewtypeStruct => "a newtype struct",
        Unexpected::Seq => "an array",
        Unexpected::Map => "an object",
        Unexpected::Enum => "an enum",
        Unexpected::UnitVariant => "a unit variant",
        Unexpected::NewtypeVariant => "a newtype variant",
        Unexpected::TupleVariant => "a tuple variant",
        Unexpected::StructVariant => "a struct variant",
        Unexpected::Other(_) => "a value of another kind",
    }
}

impl de::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self::new(msg)
    }

    fn invalid_type(unexpected: Unexpected<'_>, expected: &dyn de::Expected) -> Self {
        Self::new(format_args!(
            "expected {expected}, found {}",
            kind(&unexpected)
        ))
    }

    fn invalid_value(unexpected: Unexpected<'_>, expected: &dyn de::Expected) -> Self {
        Self::new(format_args!("{} that is not {expected}", kind(&unexpected)))
    }

    fn unknown_variant(_variant: &str, expected: &'static [&'static str]) -> Self {
        Self::new(format_args!("an unknown variant, {}", one_of(expected)))
    }

    fn unknown_field(_field: &str, expected: &'static [&'static str]) -> Self {
        Self::new(format_args!("an unknown key, {}", one_of(expected)))
    }
}

/// What an unknown name could have been. A struct with no fields expects
/// none, and says so rather than listing nothing.
fn one_of(expected: &[&str]) -> String {
    if expected.is_empty() {
        "expected none".to_owned()
    } else {
        format!("expected one of {}", expected.join(", "))
    }
}

impl ser::Error for Error {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        Self::new(msg)
    }
}

// =============================================================================
// Reading
// =============================================================================

/// Read `T` from frame bytes.
///
/// The bytes must be exactly one frame: [`Frame::parse`] checks them first,
/// so a malformed frame, a repeated key or a frame nested too deep is
/// refused before `T` sees anything.
///
/// # Errors
///
/// A malformed frame, or a value `T` does not accept.
pub fn from_slice<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, Error> {
    let frame = Frame::parse(bytes).map_err(|_| Error::new("malformed frame"))?;
    from_frame(frame)
}

/// Read `T` from a frame that has already been parsed.
///
/// # Errors
///
/// A value `T` does not accept.
pub fn from_frame<'de, T: Deserialize<'de>>(frame: Frame<'de>) -> Result<T, Error> {
    let mut de = Deserializer {
        buf: frame.as_bytes(),
        pos: 0,
    };
    let value = T::deserialize(&mut de)?;
    // The frame is one node, and `T` must have read all of it: a
    // `Deserialize` that stopped early (a unit variant that left its payload
    // unread, say) would otherwise pass with data ignored.
    if de.pos != de.buf.len() {
        return Err(Error::new("the value did not read the whole frame"));
    }
    Ok(value)
}

/// Reads one validated frame. Every read below runs on bytes
/// [`Frame::parse`] accepted, so a read failing is a bug, and is reported
/// as a malformed frame rather than a panic.
struct Deserializer<'de> {
    buf: &'de [u8],
    pos: usize,
}

fn malformed() -> Error {
    Error::new("malformed frame")
}

impl<'de> Deserializer<'de> {
    fn peek(&self) -> Result<u8, Error> {
        self.buf.get(self.pos).copied().ok_or_else(malformed)
    }

    fn take(&mut self, n: usize) -> Result<&'de [u8], Error> {
        let end = self.pos.checked_add(n).ok_or_else(malformed)?;
        let bytes = self.buf.get(self.pos..end).ok_or_else(malformed)?;
        self.pos = end;
        Ok(bytes)
    }

    fn count(&mut self) -> Result<usize, Error> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| malformed())?;
        Ok(u32::from_le_bytes(bytes) as usize)
    }

    fn key(&mut self) -> Result<&'de str, Error> {
        let len = self.count()?;
        core::str::from_utf8(self.take(len)?).map_err(|_| malformed())
    }

    fn scalar(&mut self) -> Result<(Option<Logical>, Physical<'de>), Error> {
        let rest = self.buf.get(self.pos..).ok_or_else(malformed)?;
        let (scalar, used) = leaf::read(rest, Form::Frame).map_err(|_| malformed())?;
        self.pos += used;
        Ok(scalar)
    }

    /// Step over one node.
    fn skip(&mut self) -> Result<(), Error> {
        match self.peek()? {
            ARRAY => {
                self.pos += 1;
                for _ in 0..self.count()? {
                    self.skip()?;
                }
            }
            OBJECT => {
                self.pos += 1;
                for _ in 0..self.count()? {
                    self.key()?;
                    self.skip()?;
                }
            }
            PASSTHROUGH => {
                self.pos += 1;
                self.skip()?;
            }
            _ => {
                self.scalar()?;
            }
        }
        Ok(())
    }

    /// Whether the next node is a null scalar.
    fn next_is_null(&self) -> Result<bool, Error> {
        if matches!(self.peek()?, ARRAY | OBJECT | PASSTHROUGH) {
            return Ok(false);
        }
        let rest = self.buf.get(self.pos..).ok_or_else(malformed)?;
        let ((ty, value), _) = leaf::read(rest, Form::Frame).map_err(|_| malformed())?;
        Ok(ty.is_none() && matches!(value, Physical::Null))
    }
}

impl<'de> de::Deserializer<'de> for &mut Deserializer<'de> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.peek()? {
            ARRAY => {
                self.pos += 1;
                let len = self.count()?;
                visitor.visit_seq(Seq {
                    de: self,
                    left: len,
                    index: 0,
                })
            }
            OBJECT => {
                self.pos += 1;
                let len = self.count()?;
                visitor.visit_map(Map {
                    de: self,
                    left: len,
                    key: None,
                })
            }
            PASSTHROUGH => Err(Error::new("a passthrough is not supported")),
            _ => match self.scalar()? {
                (None, Physical::Null) => visitor.visit_unit(),
                (None, Physical::Bool(b)) => visitor.visit_bool(b),
                (None, Physical::Int(int)) => match int {
                    Int::I8(v) => visitor.visit_i8(v),
                    Int::I16(v) => visitor.visit_i16(v),
                    Int::I32(v) => visitor.visit_i32(v),
                    Int::I64(v) => visitor.visit_i64(v),
                    Int::I128(v) => visitor.visit_i128(v),
                    Int::U8(v) => visitor.visit_u8(v),
                    Int::U16(v) => visitor.visit_u16(v),
                    Int::U32(v) => visitor.visit_u32(v),
                    Int::U64(v) => visitor.visit_u64(v),
                    Int::U128(v) => visitor.visit_u128(v),
                },
                (None, Physical::Float(Float::F32(v))) => visitor.visit_f32(v),
                (None, Physical::Float(Float::F64(v))) => visitor.visit_f64(v),
                (None, Physical::Text(text)) => visitor.visit_borrowed_str(text),
                (None, Physical::Bytes(bytes)) => visitor.visit_borrowed_bytes(bytes),
                (Some(_), _) => Err(Error::new(
                    "a value with a logical type (a date, a timestamp, a decimal) is not supported",
                )),
            },
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if self.next_is_null()? {
            self.scalar()?;
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.peek()? {
            OBJECT => {
                self.pos += 1;
                if self.count()? != 1 {
                    return Err(Error::new(
                        "expected an enum: a variant name, or an object of one entry",
                    ));
                }
                let variant = self.key()?;
                visitor.visit_enum(Enum { de: self, variant })
            }
            ARRAY | PASSTHROUGH => Err(Error::new(
                "expected an enum: a variant name, or an object of one entry",
            )),
            _ => match self.scalar()? {
                (None, Physical::Text(variant)) => visitor.visit_enum(BareVariant { variant }),
                _ => Err(Error::new(
                    "expected an enum: a variant name, or an object of one entry",
                )),
            },
        }
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.skip()?;
        visitor.visit_unit()
    }

    fn is_human_readable(&self) -> bool {
        false
    }

    ::serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple tuple_struct map struct
        identifier
    }
}

struct Seq<'a, 'de> {
    de: &'a mut Deserializer<'de>,
    left: usize,
    index: usize,
}

impl<'de> SeqAccess<'de> for Seq<'_, 'de> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        if self.left == 0 {
            return Ok(None);
        }
        self.left -= 1;
        let index = self.index;
        self.index += 1;
        seed.deserialize(&mut *self.de)
            .map(Some)
            .map_err(|e| e.at(PathSegment::Index(index)))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.left)
    }
}

struct Map<'a, 'de> {
    de: &'a mut Deserializer<'de>,
    left: usize,
    /// The key of the entry whose value is next.
    key: Option<&'de str>,
}

impl<'de> MapAccess<'de> for Map<'_, 'de> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        if self.left == 0 {
            return Ok(None);
        }
        self.left -= 1;
        let key = self.de.key()?;
        self.key = Some(key);
        // An error about the key itself (an unknown key) stays at the
        // object's path: putting the key on the path would print it, and a
        // message never repeats what a host sent.
        seed.deserialize(BorrowedStrDeserializer::<Error>::new(key))
            .map(Some)
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        let key = self.key.take().unwrap_or_default();
        seed.deserialize(&mut *self.de)
            .map_err(|e| e.at(PathSegment::Key(key.to_owned())))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.left)
    }
}

struct Enum<'a, 'de> {
    de: &'a mut Deserializer<'de>,
    variant: &'de str,
}

impl<'a, 'de> EnumAccess<'de> for Enum<'a, 'de> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self), Error> {
        let variant = seed.deserialize(BorrowedStrDeserializer::<Error>::new(self.variant))?;
        Ok((variant, self))
    }
}

impl<'de> VariantAccess<'de> for Enum<'_, 'de> {
    type Error = Error;

    /// `{"variant": null}` reads as a unit variant, so a host may give one a
    /// null payload as well as writing its bare name.
    fn unit_variant(self) -> Result<(), Error> {
        let at = self.at();
        de::Deserialize::deserialize(&mut *self.de).map_err(|e: Error| e.at(at))
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        let at = self.at();
        seed.deserialize(&mut *self.de).map_err(|e| e.at(at))
    }

    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value, Error> {
        let at = self.at();
        de::Deserializer::deserialize_seq(&mut *self.de, visitor).map_err(|e| e.at(at))
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        let at = self.at();
        de::Deserializer::deserialize_map(&mut *self.de, visitor).map_err(|e| e.at(at))
    }
}

impl Enum<'_, '_> {
    /// The path segment for an error inside the payload. It is added only
    /// once the variant is known, so an unknown variant's name is never
    /// printed.
    fn at(&self) -> PathSegment {
        PathSegment::Key(self.variant.to_owned())
    }
}

/// A variant written as its bare name. Its payload is null: a unit variant
/// reads nothing, a newtype variant reads its payload from null (so an
/// `Option<T>` payload is `None`), and a tuple or struct variant is refused.
struct BareVariant<'de> {
    variant: &'de str,
}

impl<'de> EnumAccess<'de> for BareVariant<'de> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<V: DeserializeSeed<'de>>(self, seed: V) -> Result<(V::Value, Self), Error> {
        let variant = seed.deserialize(BorrowedStrDeserializer::<Error>::new(self.variant))?;
        Ok((variant, self))
    }
}

impl<'de> VariantAccess<'de> for BareVariant<'de> {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        Ok(())
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        seed.deserialize(UnitDeserializer::<Error>::new())
            .map_err(|e| e.at(PathSegment::Key(self.variant.to_owned())))
    }

    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, _visitor: V) -> Result<V::Value, Error> {
        Err(de::Error::invalid_type(
            Unexpected::UnitVariant,
            &"a tuple variant",
        ))
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Error> {
        Err(de::Error::invalid_type(
            Unexpected::UnitVariant,
            &"a struct variant",
        ))
    }
}

// =============================================================================
// Writing
// =============================================================================

/// Write `value` as frame bytes.
///
/// The buffer grows without leaving copies of what it held behind, as every
/// frame vitaminc writes does.
///
/// # Errors
///
/// A value nested deeper than a frame allows, text or bytes too long for
/// one, a map with a key that is not a string, or a repeated key.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    value.serialize(Serializer(FrameWriter::new(&mut out)))?;
    Ok(out)
}

fn written(error: vitaminc_aead::frame::FrameWriteError) -> Error {
    Error::new(error)
}

/// Writes one node into a [`FrameWriter`].
struct Serializer<'o>(FrameWriter<'o>);

impl<'o> Serializer<'o> {
    fn scalar(self, value: Physical<'_>) -> Result<(), Error> {
        self.0.scalar(None, value).map_err(written)
    }

    fn int(self, value: Int) -> Result<(), Error> {
        self.scalar(Physical::Int(value))
    }

    /// An object of one entry: an enum variant with a payload.
    fn variant<T: Serialize + ?Sized>(self, variant: &str, payload: &T) -> Result<(), Error> {
        let mut map = self.0.map(Some(1)).map_err(written)?;
        payload
            .serialize(Serializer(map.entry(variant).map_err(written)?))
            .map_err(|e| e.at(PathSegment::Key(variant.to_owned())))?;
        map.end().map_err(written)
    }
}

impl<'o> ser::Serializer for Serializer<'o> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = SerSeq<'o>;
    type SerializeTuple = SerSeq<'o>;
    type SerializeTupleStruct = SerSeq<'o>;
    type SerializeTupleVariant = SerVariant<'o>;
    type SerializeMap = SerMap<'o>;
    type SerializeStruct = SerMap<'o>;
    type SerializeStructVariant = SerVariant<'o>;

    fn serialize_bool(self, v: bool) -> Result<(), Error> {
        self.scalar(Physical::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<(), Error> {
        self.int(Int::I8(v))
    }
    fn serialize_i16(self, v: i16) -> Result<(), Error> {
        self.int(Int::I16(v))
    }
    fn serialize_i32(self, v: i32) -> Result<(), Error> {
        self.int(Int::I32(v))
    }
    fn serialize_i64(self, v: i64) -> Result<(), Error> {
        self.int(Int::I64(v))
    }
    fn serialize_i128(self, v: i128) -> Result<(), Error> {
        self.int(Int::I128(v))
    }
    fn serialize_u8(self, v: u8) -> Result<(), Error> {
        self.int(Int::U8(v))
    }
    fn serialize_u16(self, v: u16) -> Result<(), Error> {
        self.int(Int::U16(v))
    }
    fn serialize_u32(self, v: u32) -> Result<(), Error> {
        self.int(Int::U32(v))
    }
    fn serialize_u64(self, v: u64) -> Result<(), Error> {
        self.int(Int::U64(v))
    }
    fn serialize_u128(self, v: u128) -> Result<(), Error> {
        self.int(Int::U128(v))
    }
    fn serialize_f32(self, v: f32) -> Result<(), Error> {
        self.scalar(Physical::Float(Float::F32(v)))
    }
    fn serialize_f64(self, v: f64) -> Result<(), Error> {
        self.scalar(Physical::Float(Float::F64(v)))
    }
    fn serialize_char(self, v: char) -> Result<(), Error> {
        let mut buf = [0u8; 4];
        self.scalar(Physical::Text(v.encode_utf8(&mut buf)))
    }
    fn serialize_str(self, v: &str) -> Result<(), Error> {
        self.scalar(Physical::Text(v))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<(), Error> {
        self.scalar(Physical::Bytes(v))
    }
    fn serialize_none(self) -> Result<(), Error> {
        self.scalar(Physical::Null)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), Error> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), Error> {
        self.scalar(Physical::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), Error> {
        self.scalar(Physical::Null)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<(), Error> {
        self.scalar(Physical::Text(variant))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.variant(variant, value)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<SerSeq<'o>, Error> {
        Ok(SerSeq {
            seq: self.0.seq(len).map_err(written)?,
            index: 0,
        })
    }
    fn serialize_tuple(self, len: usize) -> Result<SerSeq<'o>, Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(self, _name: &'static str, len: usize) -> Result<SerSeq<'o>, Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<SerVariant<'o>, Error> {
        Ok(SerVariant::new(self.0, variant, len))
    }
    fn serialize_map(self, len: Option<usize>) -> Result<SerMap<'o>, Error> {
        Ok(SerMap {
            map: self.0.map(len).map_err(written)?,
            key: None,
        })
    }
    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<SerMap<'o>, Error> {
        self.serialize_map(Some(len))
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<SerVariant<'o>, Error> {
        Ok(SerVariant::new(self.0, variant, len))
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

struct SerSeq<'o> {
    seq: vitaminc_aead::frame::FrameSeq<'o>,
    index: usize,
}

impl SerSeq<'_> {
    fn element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        let index = self.index;
        self.index += 1;
        value
            .serialize(Serializer(self.seq.element().map_err(written)?))
            .map_err(|e| e.at(PathSegment::Index(index)))
    }
}

impl ser::SerializeSeq for SerSeq<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        self.seq.end().map_err(written)
    }
}

impl ser::SerializeTuple for SerSeq<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        self.seq.end().map_err(written)
    }
}

impl ser::SerializeTupleStruct for SerSeq<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        self.seq.end().map_err(written)
    }
}

struct SerMap<'o> {
    map: vitaminc_aead::frame::FrameMap<'o>,
    /// The key of the entry whose value is next.
    key: Option<String>,
}

impl SerMap<'_> {
    fn entry<T: Serialize + ?Sized>(&mut self, key: &str, value: &T) -> Result<(), Error> {
        value
            .serialize(Serializer(self.map.entry(key).map_err(written)?))
            .map_err(|e| e.at(PathSegment::Key(key.to_owned())))
    }
}

impl ser::SerializeMap for SerMap<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Error> {
        self.key = Some(key.serialize(KeySerializer)?);
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        let key = self
            .key
            .take()
            .ok_or_else(|| Error::new("a map value was written before its key"))?;
        self.entry(&key, value)
    }
    fn end(self) -> Result<(), Error> {
        self.map.end().map_err(written)
    }
}

impl ser::SerializeStruct for SerMap<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.entry(key, value)
    }
    fn end(self) -> Result<(), Error> {
        self.map.end().map_err(written)
    }
}

/// A tuple or struct variant: an object of one entry, the variant's name
/// mapped to an array (a tuple variant) or an object (a struct variant).
///
/// The outer object's entry borrows the outer object, so the payload cannot
/// be written in place while both are held. Each part is written to its own
/// buffer instead, and copied into the outer object at [`end`], by walking
/// its frame. The buffers are wiped when they are copied.
///
/// [`end`]: ser::SerializeStructVariant::end
struct SerVariant<'o> {
    writer: FrameWriter<'o>,
    variant: &'static str,
    /// Each part's key (a struct variant's field; `None` in a tuple
    /// variant) and frame.
    parts: Vec<(Option<&'static str>, Vec<u8>)>,
}

impl<'o> SerVariant<'o> {
    fn new(writer: FrameWriter<'o>, variant: &'static str, len: usize) -> Self {
        Self {
            writer,
            variant,
            parts: Vec::with_capacity(len),
        }
    }

    fn part<T: Serialize + ?Sized>(
        &mut self,
        key: Option<&'static str>,
        value: &T,
    ) -> Result<(), Error> {
        let at = match key {
            Some(key) => PathSegment::Key(key.to_owned()),
            None => PathSegment::Index(self.parts.len()),
        };
        let frame =
            to_vec(value).map_err(|e| e.at(at).at(PathSegment::Key(self.variant.to_owned())))?;
        self.parts.push((key, frame));
        Ok(())
    }

    fn end(self, is_struct: bool) -> Result<(), Error> {
        let Self {
            writer,
            variant,
            mut parts,
        } = self;
        let result = write_variant(writer, variant, &parts, is_struct);
        for (_, frame) in &mut parts {
            frame.zeroize();
        }
        result
    }
}

fn write_variant(
    writer: FrameWriter<'_>,
    variant: &str,
    parts: &[(Option<&'static str>, Vec<u8>)],
    is_struct: bool,
) -> Result<(), Error> {
    let mut outer = writer.map(Some(1)).map_err(written)?;
    let entry = outer.entry(variant).map_err(written)?;
    if is_struct {
        let mut map = entry.map(Some(parts.len())).map_err(written)?;
        for (key, frame) in parts {
            let frame = Frame::parse(frame).map_err(|_| malformed())?;
            frame
                .visit(map.entry(key.unwrap_or_default()).map_err(written)?)
                .map_err(written)?;
        }
        map.end().map_err(written)?;
    } else {
        let mut seq = entry.seq(Some(parts.len())).map_err(written)?;
        for (_, frame) in parts {
            let frame = Frame::parse(frame).map_err(|_| malformed())?;
            frame
                .visit(seq.element().map_err(written)?)
                .map_err(written)?;
        }
        seq.end().map_err(written)?;
    }
    outer.end().map_err(written)
}

impl ser::SerializeTupleVariant for SerVariant<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.part(None, value)
    }
    fn end(self) -> Result<(), Error> {
        SerVariant::end(self, false)
    }
}

impl ser::SerializeStructVariant for SerVariant<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.part(Some(key), value)
    }
    fn end(self) -> Result<(), Error> {
        SerVariant::end(self, true)
    }
}

/// Serializes a map key, which a frame holds as text.
struct KeySerializer;

fn key_not_text() -> Error {
    Error::new("a map key must be a string")
}

impl ser::Serializer for KeySerializer {
    type Ok = String;
    type Error = Error;
    type SerializeSeq = ser::Impossible<String, Error>;
    type SerializeTuple = ser::Impossible<String, Error>;
    type SerializeTupleStruct = ser::Impossible<String, Error>;
    type SerializeTupleVariant = ser::Impossible<String, Error>;
    type SerializeMap = ser::Impossible<String, Error>;
    type SerializeStruct = ser::Impossible<String, Error>;
    type SerializeStructVariant = ser::Impossible<String, Error>;

    fn serialize_str(self, v: &str) -> Result<String, Error> {
        Ok(v.to_owned())
    }
    fn serialize_char(self, v: char) -> Result<String, Error> {
        Ok(v.to_string())
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<String, Error> {
        Ok(variant.to_owned())
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<String, Error> {
        value.serialize(self)
    }
    fn serialize_bool(self, _v: bool) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_i8(self, _v: i8) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_i16(self, _v: i16) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_i32(self, _v: i32) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_i64(self, _v: i64) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_u8(self, _v: u8) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_u16(self, _v: u16) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_u32(self, _v: u32) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_u64(self, _v: u64) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_f32(self, _v: f32) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_f64(self, _v: f64) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_bytes(self, _v: &[u8]) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_none(self) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_some<T: Serialize + ?Sized>(self, _value: &T) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_unit(self) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<String, Error> {
        Err(key_not_text())
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Err(key_not_text())
    }
    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Error> {
        Err(key_not_text())
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Err(key_not_text())
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        Err(key_not_text())
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(key_not_text())
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Error> {
        Err(key_not_text())
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        Err(key_not_text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every kind of unexpected value is named by its kind, and none prints
    /// the value it carries.
    #[test]
    fn every_unexpected_value_is_named_by_kind_only() {
        let cases = [
            (Unexpected::Bool(true), "a boolean"),
            (Unexpected::Unsigned(41), "an integer"),
            (Unexpected::Signed(-41), "an integer"),
            (Unexpected::Float(4.1), "a float"),
            (Unexpected::Char('Z'), "a string"),
            (Unexpected::Str("s3cr3t"), "a string"),
            (Unexpected::Bytes(b"s3cr3t"), "bytes"),
            (Unexpected::Unit, "null"),
            (Unexpected::Option, "an optional value"),
            (Unexpected::NewtypeStruct, "a newtype struct"),
            (Unexpected::Seq, "an array"),
            (Unexpected::Map, "an object"),
            (Unexpected::Enum, "an enum"),
            (Unexpected::UnitVariant, "a unit variant"),
            (Unexpected::NewtypeVariant, "a newtype variant"),
            (Unexpected::TupleVariant, "a tuple variant"),
            (Unexpected::StructVariant, "a struct variant"),
            (Unexpected::Other("s3cr3t"), "a value of another kind"),
        ];
        for (unexpected, expected) in cases {
            assert_eq!(kind(&unexpected), expected);
            let message = <Error as de::Error>::invalid_value(unexpected, &"x").to_string();
            assert!(
                !message.contains("s3cr3t") && !message.contains("41"),
                "{message}"
            );
        }
    }
}
