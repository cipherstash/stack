//! serde over the transport frame: [`from_slice`] reads frame bytes into
//! any `Deserialize` type, and [`to_vec`] writes any `Serialize` type as
//! frame bytes.
//!
//! This is a serde data format, as `serde_json` is for JSON. It is for data
//! a host exchanges with Rust that is not plaintext to seal: a call's
//! options, a plan, statistics, a result. Plaintext crosses as a frame
//! walked into a [`Sink`](vitaminc_aead::plaintext::Sink), never through
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
//! | null, and JavaScript's `undefined` | unit, and `None` |
//!
//! A typed null ([`tags::TYPED_NULL`]) is
//! refused as malformed. It is how plaintext marks an absent fixed-width
//! value so its sealed length matches a present one, which is no concern of
//! data that is not sealed, and this format never writes one.
//!
//! Each kind reads only as itself: a struct or a map reads an object, never
//! an array by position, and a string reads text, never bytes that happen
//! to be UTF-8, nor bytes text.
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
//! serde's `untagged`, internally tagged (`tag = "…"`) and `flatten` read
//! through a buffer of their own. It has no 128-bit integers, so a type
//! using any of them cannot hold an `i128` or `u128`, and an error found
//! while reading back from it has no path below the buffered value.
//!
//! The format is not human readable ([`is_human_readable`] is `false`), so
//! a type with a compact binary form uses it: a `uuid::Uuid` crosses as its
//! 16 bytes. A map's key is text, so a `Uuid` used as a key crosses in its
//! text form.
//!
//! Not supported, and refused: a passthrough node, and a scalar with a
//! logical type (a date, a timestamp, a decimal), which serde has no data
//! model for. JavaScript's `undefined`, which always sits over null, reads
//! as null.
//!
//! [`is_human_readable`]: ::serde::Deserializer::is_human_readable
//!
//! # Errors never echo a value
//!
//! serde's default messages print the value that did not fit ("invalid
//! type: string \"…\""). This format's [`Error`] names only the kind of
//! value it found, and does not repeat an unknown key, so a message never
//! carries data a host sent: a credential in a configuration, say. A type's
//! own message (from a `try_from` or `deserialize_with` check, through
//! `Error::custom`) is dropped for the same reason, since it may print the
//! value it refused. serde's messages for a value of the wrong type, value
//! or length are kept, and they print what the type expected: its
//! `Visitor::expecting`, or an `Expected` impl. A derived type's text is
//! fixed, but a hand-written `expecting` is printed as written, so it must
//! describe the type and never include a value. Each error records the path from the root to where it
//! happened ([`Error::path`]), so a caller can say which field was wrong.
//! The path names a struct's fields and an enum's variants, which the type
//! declares. Any other key (a map's, a flattened entry's) is data, so its
//! entry is placed by position instead ([`PathSegment::Entry`]), and
//! printed as `{1}`.
//!
//! # One reader and one writer for both formats
//!
//! This format and the [storage profile](crate::storage) share their serde
//! reader and their serde writer. Each is one body of code with a switch
//! for the profile, and the profiles differ in only a few places. Writing,
//! a storage blob starts with a header, marks an `Option`'s `Some`, and
//! writes a map's keys as values of any key kind, where this format writes
//! no header, no marker, and a map as an object whose keys are text.
//! Reading, the storage profile reads its map keys in their compact form.
//! Everything else is the same code. The derive
//! path's writer, [`FrameWriter`](crate::FrameWriter), is separate: serde
//! does not go through it.
//!
//! ```
//! use serde::{Deserialize, Serialize};
//! use vitaminc_protected::Controlled;
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
//! let back: Options = vitaminc_aead_frame::serde::from_slice(bytes.risky_ref())?;
//! assert_eq!(back, options);
//! # Ok::<(), vitaminc_aead_frame::serde::Error>(())
//! ```
//!
//! # Memory
//!
//! What a host sends may be secret even when it is not plaintext to seal,
//! so the writer leaves no copy of a value on the heap. Its buffer grows
//! into a fresh allocation and wipes the old one. A `Display` value, a
//! map's key included, is formatted straight into the frame. A map's keys
//! are checked for a repeat where they lie in the frame, rather than
//! copied. The frame is returned in a [`Buffer`], whose bytes are read
//! through `risky_ref`.
//! `tests/transport_wipe.rs` checks this. Copies on the stack and in
//! registers are not wiped, as for the storage profile (STORAGE.md,
//! *Memory and timing*). The reader borrows text and bytes from its input.

use std::fmt;

use ::serde::de::value::{BorrowedStrDeserializer, UnitDeserializer};
use ::serde::de::{
    self, DeserializeSeed, EnumAccess, MapAccess, SeqAccess, Unexpected, VariantAccess, Visitor,
};
use ::serde::ser::{self, Serialize};
use ::serde::Deserialize;
use vitaminc_aead::frame::{ARRAY, OBJECT, PASSTHROUGH};
use vitaminc_aead::leaf::{self, Form};
use vitaminc_aead::plaintext::{Float, Int, Logical, Physical};
use vitaminc_aead::{tags, Frame};
use vitaminc_protected::Buffer;

use crate::write::{write, AsTransport};

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
    /// An object's entry, by key: a field or variant name the type itself
    /// declares, never a key only a host chose.
    Key(String),
    /// An array's element, by position.
    Index(usize),
    /// An object's entry, by position, where its key is data rather than a
    /// name the type declares: a map's key, a flattened entry, a variant
    /// read through `#[serde(other)]`. The key is not kept, since it is
    /// what a host sent (or, writing, what the caller's map held).
    Entry(usize),
}

impl Error {
    pub(crate) fn new(message: impl fmt::Display) -> Self {
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
    /// field the error is about. A key is always a name the type declares.
    pub fn field(&self) -> Option<&str> {
        self.path.iter().find_map(|segment| match segment {
            PathSegment::Key(key) => Some(key.as_str()),
            PathSegment::Index(_) | PathSegment::Entry(_) => None,
        })
    }

    pub(crate) fn at(mut self, segment: impl Into<PathSegment>) -> Self {
        self.path.insert(0, segment.into());
        self
    }
}

/// Where an entry sits on the path, held while its value is read or
/// written. It names a key by the type's own `&'static str`, and becomes a
/// [`PathSegment`] only when an error is placed at it, so an entry read or
/// written without one allocates nothing for its path.
#[derive(Clone, Copy)]
pub(crate) enum At {
    Key(&'static str),
    Index(usize),
    Entry(usize),
}

impl From<At> for PathSegment {
    fn from(at: At) -> Self {
        match at {
            At::Key(key) => PathSegment::Key(key.to_owned()),
            At::Index(index) => PathSegment::Index(index),
            At::Entry(index) => PathSegment::Entry(index),
        }
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
                PathSegment::Entry(index) => write!(f, "{{{index}}}")?,
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

/// A type's own message is dropped: `custom` takes any `Display`, and a
/// `try_from` or `deserialize_with` check may well print the value it
/// refused. serde's messages that are known to name no value (a missing or
/// repeated field, a length) are kept, by overriding the methods that build
/// them. `invalid_type`, `invalid_value` and `invalid_length` print the
/// type's `expected` text, which is the type's to keep free of values.
impl de::Error for Error {
    fn custom<T: fmt::Display>(_msg: T) -> Self {
        Self::new("a value its type does not accept")
    }

    fn missing_field(field: &'static str) -> Self {
        Self::new(format_args!("missing field `{field}`"))
    }

    fn duplicate_field(field: &'static str) -> Self {
        Self::new(format_args!("duplicate field `{field}`"))
    }

    fn invalid_length(len: usize, expected: &dyn de::Expected) -> Self {
        Self::new(format_args!("expected {expected}, found a length of {len}"))
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

/// As in reading, a type's own message is dropped, since it may print the
/// value being written.
impl ser::Error for Error {
    fn custom<T: fmt::Display>(_msg: T) -> Self {
        Self::new("a value its type could not write")
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
    let frame = Frame::parse(bytes).map_err(|_| Error::new(MALFORMED))?;
    from_frame(frame)
}

/// Read `T` from a frame that has already been parsed.
///
/// # Errors
///
/// A value `T` does not accept.
pub fn from_frame<'de, T: Deserialize<'de>>(frame: Frame<'de>) -> Result<T, Error> {
    from_validated(frame.as_bytes(), Profile::Transport)
}

/// Which format a node is read or written for.
///
/// They read alike, but for the mode a text key is read in: the transport's
/// key writer is human readable, so a key type reads its text form, and the
/// storage profile's is not, so a key type reads the compact form it was
/// written in.
///
/// They write alike, but for an `Option`'s `Some`, which only the storage
/// profile marks, and a map, which the storage profile writes as a map of
/// key nodes and the transport as an object of text keys. A storage blob's
/// header is written by [`storage::to_vec`](crate::storage::to_vec), not by
/// the writer.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Profile {
    Transport,
    Storage,
}

/// Read `T` from one node that has already been validated: a frame
/// [`Frame::parse`] accepted, or the body of a storage blob its own
/// validator accepted.
pub(crate) fn from_validated<'de, T: Deserialize<'de>>(
    bytes: &'de [u8],
    profile: Profile,
) -> Result<T, Error> {
    let mut de = Deserializer {
        buf: bytes,
        pos: 0,
        profile,
    };
    let value = T::deserialize(&mut de)?;
    // The frame is one node, and `T` must have read all of it: a
    // `Deserialize` that stopped early (a unit variant that left its payload
    // unread, say) would otherwise pass with data ignored.
    if de.pos != de.buf.len() {
        return Err(Error::new(UNREAD_REST));
    }
    Ok(value)
}

/// The message of a read that found bytes no validator should have passed.
/// The storage profile gives it its own words.
pub(crate) const MALFORMED: &str = "malformed frame";

/// The message of a value that left part of its node unread. The storage
/// profile gives it its own words.
pub(crate) const UNREAD_REST: &str = "the value did not read the whole frame";

/// The storage profile's presence marker: `SOME`, then the node an
/// `Option`'s `Some` holds. It is not in the transport frame's grammar, so
/// [`Frame::parse`] refuses it, and the reader below meets it only in a
/// storage blob, whose own validator admits it. See
/// [`storage`](crate::storage).
pub(crate) const SOME: u8 = tags::STORAGE_SOME;

/// The storage profile's map: `MAP`, a `u32` count, then a key node and a
/// value node for each entry. Like [`SOME`], only a storage blob holds one.
pub(crate) const MAP: u8 = tags::STORAGE_MAP;

/// Reads one validated node. Every read below runs on bytes a validator
/// accepted ([`Frame::parse`], or the storage profile's), so a read failing
/// is a bug, and is reported as a malformed frame rather than a panic.
struct Deserializer<'de> {
    buf: &'de [u8],
    pos: usize,
    profile: Profile,
}

fn malformed() -> Error {
    Error::new(MALFORMED)
}

/// Every read that takes anything from a node takes all of it, so a child
/// whose read left the position where it was was not read at all: a seed or
/// a visitor returned without touching the deserializer it was handed.
/// Counting it as read would leave its bytes for the next read.
fn unread() -> Error {
    Error::new("a value its type did not read")
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
            MAP => {
                self.pos += 1;
                for _ in 0..self.count()? {
                    self.skip()?;
                    self.skip()?;
                }
            }
            PASSTHROUGH | SOME => {
                self.pos += 1;
                self.skip()?;
            }
            _ => {
                self.scalar()?;
            }
        }
        Ok(())
    }

    /// Whether the next node is a null scalar: plain null, or `undefined`,
    /// which reads as null ([`is_plain`]). Told from the tag alone, so a
    /// node that is not null is not decoded here and then again by the
    /// read that follows.
    fn next_is_null(&self) -> Result<bool, Error> {
        Ok(matches!(self.peek()?, tags::NULL | tags::UNDEFINED))
    }

    /// A storage map's next key, consumed, if it is text; otherwise
    /// nothing, with the key left where it is. A map's key is always a
    /// scalar: the storage validator admits nothing else.
    fn text_node(&mut self) -> Result<Option<&'de str>, Error> {
        let rest = self.buf.get(self.pos..).ok_or_else(malformed)?;
        match leaf::read(rest, Form::Frame).map_err(|_| malformed())? {
            ((None, Physical::Text(text)), used) => {
                self.pos += used;
                Ok(Some(text))
            }
            _ => Ok(None),
        }
    }

    /// The kind of the next node, for a refusal. It carries no value, so a
    /// message built from it cannot repeat one. The kind is told from the
    /// tag alone: a scalar is not decoded here and then again by the read
    /// that follows, and a tag the validator would not have passed is
    /// reported as malformed, as that read would report it.
    fn found(&self) -> Result<Unexpected<'static>, Error> {
        Ok(match self.peek()? {
            ARRAY => Unexpected::Seq,
            OBJECT | MAP => Unexpected::Map,
            PASSTHROUGH => Unexpected::Other("a passthrough"),
            SOME => Unexpected::Option,
            tags::NULL => Unexpected::Unit,
            tags::BOOL_FALSE | tags::BOOL_TRUE => Unexpected::Bool(false),
            tags::INT8
            | tags::INT16
            | tags::INT32
            | tags::INT64
            | tags::INT128
            | tags::UINT8
            | tags::UINT16
            | tags::UINT32
            | tags::UINT64
            | tags::UINT128 => Unexpected::Unsigned(0),
            tags::FLOAT32 | tags::FLOAT64 => Unexpected::Float(0.0),
            tags::STRING => Unexpected::Str(""),
            tags::BYTES => Unexpected::Bytes(&[]),
            tags::UNDEFINED | tags::DATE | tags::TIMESTAMP | tags::DECIMAL | tags::LOGICAL => {
                Unexpected::Other("a value with a logical type")
            }
            _ => return Err(malformed()),
        })
    }

    /// Read the next node only if it is of the kind `expected` names, so a
    /// type reads exactly the kind it asked for: a struct or map an object
    /// and never an array, a string a text leaf and never bytes, bytes a
    /// bytes leaf and never text.
    fn only<V: Visitor<'de>>(
        &mut self,
        expected: fn(&Unexpected<'_>) -> bool,
        visitor: V,
    ) -> Result<V::Value, Error> {
        let found = self.found()?;
        // A passthrough or a logical scalar is refused by deserialize_any,
        // which says which it was.
        if expected(&found) || matches!(found, Unexpected::Other(_)) {
            de::Deserializer::deserialize_any(self, visitor)
        } else {
            Err(de::Error::invalid_type(found, &visitor))
        }
    }
}

impl<'de> Deserializer<'de> {
    /// Visit the array whose tag is next. A visitor that stopped early (a
    /// tuple shorter than the array) would leave elements for the
    /// enclosing container to read as its own next key or value, so the
    /// array must be read to its end.
    fn array<V: Visitor<'de>>(&mut self, visitor: V) -> Result<V::Value, Error> {
        self.pos += 1;
        let len = self.count()?;
        let mut seq = Seq {
            de: self,
            left: len,
            index: 0,
        };
        let value = visitor.visit_seq(&mut seq)?;
        if seq.left != 0 {
            return Err(Error::new("an array longer than expected"));
        }
        Ok(value)
    }

    /// Visit the object or map whose tag is next, which must be read to its
    /// end, as an array must. `names` are the fields the type declares, if
    /// it is a struct: only those keys are put on an error's path. `keys`
    /// says how its keys are held, and which a struct reads.
    fn entries<V: Visitor<'de>>(
        &mut self,
        names: &'static [&'static str],
        keys: Keys,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.pos += 1;
        let len = self.count()?;
        let mut map = Map {
            de: self,
            names,
            keys,
            left: len,
            index: 0,
            at: None,
        };
        let value = visitor.visit_map(&mut map)?;
        if map.left != 0 || map.at.is_some() {
            return Err(Error::new("an object with entries left unread"));
        }
        Ok(value)
    }
}

/// Hand a scalar to a visitor at its exact type. A scalar with a logical
/// type is refused, since serde has no data model for one.
fn visit_scalar<'de, V: Visitor<'de>>(
    ty: Option<Logical>,
    value: Physical<'de>,
    visitor: V,
) -> Result<V::Value, Error> {
    if !is_plain(ty) {
        return Err(Error::new(
            "a value with a logical type (a date, a timestamp, a decimal) is not supported",
        ));
    }
    match value {
        Physical::Null => visitor.visit_unit(),
        Physical::Bool(b) => visitor.visit_bool(b),
        Physical::Int(int) => visit_int(int, visitor),
        Physical::Float(Float::F32(v)) => visitor.visit_f32(v),
        Physical::Float(Float::F64(v)) => visitor.visit_f64(v),
        Physical::Text(text) => visitor.visit_borrowed_str(text),
        Physical::Bytes(bytes) => visitor.visit_borrowed_bytes(bytes),
    }
}

/// Whether a scalar reads as its physical value. JavaScript's `undefined`
/// is the one logical type that does: it always sits over null, and a host
/// that models a missing field as `undefined` means null by it.
fn is_plain(ty: Option<Logical>) -> bool {
    matches!(ty, None | Some(Logical::Undefined))
}

/// The path segment for an object's entry: its key when that is one of the
/// names the type declares, and otherwise only its position, so a key a
/// host chose is never printed.
fn entry_at(names: &'static [&'static str], key: &str, index: usize) -> At {
    match names.iter().find(|name| **name == key) {
        Some(name) => At::Key(name),
        None => At::Entry(index),
    }
}

/// Hand an integer to a visitor at its exact width.
fn visit_int<'de, V: Visitor<'de>>(int: Int, visitor: V) -> Result<V::Value, Error> {
    match int {
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
    }
}

impl<'de> de::Deserializer<'de> for &mut Deserializer<'de> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.peek()? {
            ARRAY => self.array(visitor),
            OBJECT => self.entries(&[], Keys::Text, visitor),
            MAP => self.entries(&[], Keys::Nodes, visitor),
            PASSTHROUGH => Err(Error::new("a passthrough is not supported")),
            SOME => {
                self.pos += 1;
                visitor.visit_some(self)
            }
            _ => {
                let (ty, value) = self.scalar()?;
                visit_scalar(ty, value, visitor)
            }
        }
    }

    /// Null is `None`. A storage blob marks a `Some` with [`SOME`], so a
    /// `Some(())` or a `Some(None)` is not read as `None`. Any other node is
    /// a `Some` holding it: the transport has no marker, and a storage blob
    /// written before a field became optional has none either.
    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        if self.peek()? == SOME {
            self.pos += 1;
            return visitor.visit_some(self);
        }
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

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.peek()? {
            OBJECT => self.entries(fields, Keys::Text, visitor),
            MAP => self.entries(fields, Keys::Names, visitor),
            _ => self.only(|found| matches!(found, Unexpected::Map), visitor),
        }
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        variants: &'static [&'static str],
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
                let payload = self.pos;
                let value = visitor.visit_enum(Enum {
                    de: self,
                    variants,
                    variant,
                })?;
                if self.pos == payload {
                    return Err(unread());
                }
                Ok(value)
            }
            ARRAY | MAP | PASSTHROUGH | SOME => Err(Error::new(
                "expected an enum: a variant name, or an object of one entry",
            )),
            _ => match self.scalar()? {
                (None, Physical::Text(variant)) => {
                    visitor.visit_enum(BareVariant { variants, variant })
                }
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

    /// A map is an object, as a struct is (above), never an array: serde's
    /// derived struct visitor would read one by position.
    fn deserialize_map<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.only(|found| matches!(found, Unexpected::Map), visitor)
    }

    /// A string is text. serde's string visitors would also take bytes that
    /// happen to be UTF-8, which the format keeps apart.
    fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.only(|found| matches!(found, Unexpected::Str(_)), visitor)
    }

    fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_str(self, visitor)
    }

    /// Bytes are bytes. serde's byte visitors would also take text.
    fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        self.only(|found| matches!(found, Unexpected::Bytes(_)), visitor)
    }

    fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_bytes(self, visitor)
    }

    ::serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char
        unit unit_struct seq tuple tuple_struct identifier
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
        let start = self.de.pos;
        let value = seed
            .deserialize(&mut *self.de)
            .map_err(|e| e.at(PathSegment::Index(index)))?;
        if self.de.pos == start {
            return Err(unread().at(PathSegment::Index(index)));
        }
        Ok(Some(value))
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.left)
    }
}

/// How an object's or a map's keys are held, and read.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Keys {
    /// An object's: a length and UTF-8, read as a string.
    Text,
    /// A storage map's: each a node, read as the key type reads a value.
    Nodes,
    /// A storage map's, read by a struct, which names its fields in text:
    /// a key that is not text is refused.
    Names,
}

struct Map<'a, 'de> {
    de: &'a mut Deserializer<'de>,
    /// The fields the type declares, if it is a struct.
    names: &'static [&'static str],
    keys: Keys,
    left: usize,
    /// The position of the next entry.
    index: usize,
    /// Where the entry whose value is next sits on the path.
    at: Option<At>,
}

impl<'de> MapAccess<'de> for Map<'_, 'de> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        // A key asked for while a value is pending would read the value's
        // own bytes.
        if self.at.is_some() {
            return Err(Error::new("a map key was read before the previous value"));
        }
        if self.left == 0 {
            return Ok(None);
        }
        self.left -= 1;
        let index = self.index;
        self.index += 1;
        // An error about the key itself (an unknown key) stays at the
        // object's path: putting the key on the path would print it, and a
        // message never repeats what a host sent.
        let text = match self.keys {
            Keys::Text => Some(self.de.key()?),
            Keys::Nodes | Keys::Names => self.de.text_node()?,
        };
        if let Some(key) = text {
            self.at = Some(entry_at(self.names, key, index));
            return seed
                .deserialize(KeyDeserializer(key, self.de.profile))
                .map(Some);
        }
        if self.keys == Keys::Names {
            return Err(de::Error::invalid_type(self.de.found()?, &"a field name"));
        }
        self.at = Some(At::Entry(index));
        let start = self.de.pos;
        let key = seed.deserialize(&mut *self.de)?;
        if self.de.pos == start {
            return Err(unread());
        }
        Ok(Some(key))
    }

    fn next_value_seed<V: DeserializeSeed<'de>>(&mut self, seed: V) -> Result<V::Value, Error> {
        // A value asked for before its key would read the key's own bytes.
        let at = self
            .at
            .take()
            .ok_or_else(|| Error::new("a map value was read before its key"))?;
        let start = self.de.pos;
        let value = seed.deserialize(&mut *self.de).map_err(|e| e.at(at))?;
        if self.de.pos == start {
            return Err(unread().at(at));
        }
        Ok(value)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.left)
    }
}

/// Reads an object's key, which is text, into the key type. A key written
/// from a newtype struct around a string reads back into it, as serde's
/// own string deserializer would refuse; everything else is that
/// deserializer's. It is human readable in the transport and not in the
/// storage profile, as each profile's key writer is.
struct KeyDeserializer<'de>(&'de str, Profile);

impl<'de> de::Deserializer<'de> for KeyDeserializer<'de> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.visit_borrowed_str(self.0)
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
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        BorrowedStrDeserializer::<Error>::new(self.0).deserialize_enum(name, variants, visitor)
    }

    fn is_human_readable(&self) -> bool {
        self.1 == Profile::Transport
    }

    ::serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct seq tuple tuple_struct map
        struct identifier ignored_any
    }
}

struct Enum<'a, 'de> {
    de: &'a mut Deserializer<'de>,
    /// The variants the type declares.
    variants: &'static [&'static str],
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
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        let at = self.at();
        de::Deserializer::deserialize_struct(&mut *self.de, "", fields, visitor)
            .map_err(|e| e.at(at))
    }
}

impl Enum<'_, '_> {
    /// The path segment for an error inside the payload. It is added only
    /// once the variant is accepted, and names it only if it is one the
    /// type declares: a variant read through `#[serde(other)]` accepts a
    /// name the type does not know, which is never printed.
    fn at(&self) -> At {
        entry_at(self.variants, self.variant, 0)
    }
}

/// A variant written as its bare name. Its payload is null: a unit variant
/// reads nothing, a newtype variant reads its payload from null (so an
/// `Option<T>` payload is `None`), and a tuple or struct variant is refused.
struct BareVariant<'de> {
    /// The variants the type declares.
    variants: &'static [&'static str],
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
            .map_err(|e| e.at(entry_at(self.variants, self.variant, 0)))
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
/// What a host and Rust exchange this way is not plaintext to seal, but may
/// still be secret (a credential in a configuration, say). So the frame is
/// returned as a [`Buffer`], and wiped when it is dropped. The buffer
/// grows without leaving copies of what it held behind, as every frame
/// vitaminc writes does, and is wiped if writing fails part way. A value
/// written through `Display` (`collect_str`), a map's key included, is
/// formatted straight into the frame.
///
/// # Errors
///
/// A value nested deeper than a frame allows, text or bytes too long for
/// one, a map with a key that is not a string, a repeated key, a map key
/// written without its value (or a value without its key), or a value its
/// own `Serialize` refused.
///
/// A container's length is checked, not taken as a hint: if a `Serialize`
/// gives `serialize_seq`, `serialize_map` or `serialize_struct` a length
/// that is not the number of children it then writes, the container is
/// refused ("container length does not match its children"). `serde_json`
/// ignores a wrong length, so a hand-written impl that works there can fail
/// here. Pass `None` when the count is not known up front.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Buffer, Error> {
    let mut out = Buffer::new();
    write::<AsTransport, T>(value, &mut out)?;
    Ok(out)
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

    /// A typed null is plaintext's, not this format's: refused wherever it
    /// appears, an option included, rather than read as a null.
    #[test]
    fn a_typed_null_is_refused() {
        let null_u32 = [
            vitaminc_aead::tags::TYPED_NULL,
            vitaminc_aead::tags::UINT32,
            0,
            0,
            0,
        ];
        assert!(from_slice::<Option<u32>>(&null_u32).is_err());
        assert!(from_slice::<()>(&null_u32).is_err());
        assert!(from_slice::<u32>(&null_u32).is_err());
    }
}
