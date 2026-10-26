//! The storage profile: a value as one versioned blob, for bytes that are
//! kept. [`to_vec`] writes any `Serialize` type as a blob and [`from_slice`]
//! reads one back into any `Deserialize` type.
//!
//! Unlike the rest of this crate, which is transport and ships in lockstep
//! with its peer, the bytes these two functions write and read are a
//! compatibility commitment. The specification below defines their format
//! and compatibility rules.
//!
//! ```
//! use serde::{Deserialize, Serialize};
//! use vitaminc_aead_frame::storage::{self, ErrorKind, HEADER};
//! use vitaminc_protected::Controlled;
//!
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct Note {
//!     title: String,
//!     pinned: Option<()>,
//! }
//!
//! let note = Note { title: "hi".into(), pinned: Some(()) };
//! // The blob is plaintext, so it comes back `Protected`, and is wiped
//! // when it is dropped.
//! let blob = storage::to_vec(&note)?;
//! assert_eq!(blob.risky_ref()[..4], HEADER);
//! let back: Note = storage::from_slice(blob.risky_ref())?;
//! assert_eq!(back, note);
//!
//! // A reader that needs upgrading is told apart from a corrupt blob.
//! let newer = [b'V', b'C', b'S', 2, 0];
//! let error = storage::from_slice::<Note>(&newer).unwrap_err();
//! assert_eq!(error.kind(), ErrorKind::UnsupportedVersion);
//! # Ok::<(), storage::Error>(())
//! ```
//!
#![doc = include_str!("../STORAGE.md")]

use std::collections::HashSet;
use std::fmt;

use ::serde::ser::{self, Serialize};
use ::serde::Deserialize;
use vitaminc_aead::frame::{FrameWriteError, ARRAY, MAX_DEPTH, OBJECT};
use vitaminc_aead::leaf::{self, Form, ScalarError};
use vitaminc_aead::plaintext::{Float, Int, Physical};
use vitaminc_aead::tags;
use vitaminc_protected::Protected;
use zeroize::{Zeroize, Zeroizing};

use crate::serde::{self as transport, from_validated, written, PathSegment, Profile};

/// The first three bytes of every blob: `"VCS"`.
pub const MAGIC: [u8; 3] = *b"VCS";

/// The version this release writes, and the only one it reads.
pub const VERSION: u8 = 1;

/// The four bytes every blob [`to_vec`] writes starts with: [`MAGIC`],
/// then [`VERSION`].
pub const HEADER: [u8; 4] = [MAGIC[0], MAGIC[1], MAGIC[2], VERSION];

/// The presence marker: `SOME`, then the node an `Option`'s `Some` holds,
/// so `Some(())` and `Some(None)` are not `None`.
pub const SOME: u8 = transport::SOME;

/// A serde map: `MAP`, a `u32` count, then a key node and a value node for
/// each entry. A struct and an enum variant's payload are objects.
pub const MAP: u8 = transport::MAP;

/// The scalar tags a version 1 node may start with. A tag the leaf codec
/// gains later is not admitted here until a new version says so.
const SCALARS: [u8; 17] = [
    tags::NULL,
    tags::BOOL_FALSE,
    tags::BOOL_TRUE,
    tags::INT8,
    tags::INT16,
    tags::INT32,
    tags::INT64,
    tags::INT128,
    tags::UINT8,
    tags::UINT16,
    tags::UINT32,
    tags::UINT64,
    tags::UINT128,
    tags::FLOAT32,
    tags::FLOAT64,
    tags::STRING,
    tags::BYTES,
];

/// The scalar tags a map's key may start with: an integer of any width,
/// text, or bytes.
const KEYS: [u8; 12] = [
    tags::INT8,
    tags::INT16,
    tags::INT32,
    tags::INT64,
    tags::INT128,
    tags::UINT8,
    tags::UINT16,
    tags::UINT32,
    tags::UINT64,
    tags::UINT128,
    tags::STRING,
    tags::BYTES,
];

// =============================================================================
// Errors
// =============================================================================

/// Why a blob could not be read, or a value written.
///
/// [`kind`](Error::kind) is the class of the refusal, and is stable. The
/// message is fixed text that names what was wrong and never a value or a
/// key, but its wording is not part of the format.
#[derive(Clone, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    inner: transport::Error,
}

/// The class of an [`Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The bytes are not a blob: shorter than its header, or not starting
    /// with [`MAGIC`].
    NotABlob,
    /// A blob of a version this release does not read. A later release
    /// may: the reader needs upgrading, and the blob is not corrupt.
    UnsupportedVersion,
    /// A blob of a version this release reads, whose body breaks a rule of
    /// that version: truncated, trailing bytes, an unknown tag, a repeated
    /// key, nested too deep.
    Malformed,
    /// A well-formed blob whose value the type does not read: a missing
    /// field, a string where a number was expected, an unknown variant.
    Mismatch,
    /// A value that cannot be written as a blob: nested too deep, a map key
    /// that is not an integer, text or bytes, a repeated key, or a value
    /// its own `Serialize` refused.
    Unwritable,
}

impl Error {
    fn of(kind: ErrorKind, message: &str) -> Self {
        Self {
            kind,
            inner: transport::Error::new(message),
        }
    }

    /// The class of the refusal.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The message, without the path.
    pub fn message(&self) -> &str {
        self.inner.message()
    }

    /// The keys and indexes from the root to the node the error is about,
    /// outermost first. Empty for an error about the whole blob.
    pub fn path(&self) -> &[PathSegment] {
        self.inner.path()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error({:?}, {self})", self.kind)
    }
}

impl std::error::Error for Error {}

fn not_a_blob() -> Error {
    Error::of(ErrorKind::NotABlob, "not a storage blob")
}

fn unsupported_version() -> Error {
    Error::of(
        ErrorKind::UnsupportedVersion,
        "an unsupported storage version",
    )
}

fn malformed() -> Error {
    Error::of(ErrorKind::Malformed, "malformed storage blob")
}

/// A refusal from the reader the transport shares, in this profile's words.
fn mismatch(error: transport::Error) -> Error {
    match error.message() {
        // The validator passed every byte the reader reads, so the reader
        // finding one it cannot is a bug in one or the other.
        transport::MALFORMED => malformed(),
        transport::UNREAD_REST => {
            Error::of(ErrorKind::Mismatch, "the value did not read the whole blob")
        }
        _ => Error {
            kind: ErrorKind::Mismatch,
            inner: error,
        },
    }
}

fn unwritable(error: transport::Error) -> Error {
    Error {
        kind: ErrorKind::Unwritable,
        inner: error,
    }
}

// =============================================================================
// Reading
// =============================================================================

/// Read `T` from a blob.
///
/// The header is checked first, then the whole body, so a blob of another
/// version, a malformed body, a repeated key or a value nested too deep is
/// refused before `T` sees anything.
///
/// # Errors
///
/// Bytes that are not a blob, a blob of a version this release does not
/// read, a malformed body, or a value `T` does not accept, each its own
/// [`ErrorKind`].
pub fn from_slice<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, Error> {
    let body = body(bytes)?;
    validate(body).map_err(|_| malformed())?;
    from_validated(body, Profile::Storage).map_err(mismatch)
}

/// The body after a version 1 header.
fn body(bytes: &[u8]) -> Result<&[u8], Error> {
    let (magic, rest) = bytes.split_first_chunk::<3>().ok_or_else(not_a_blob)?;
    if *magic != MAGIC {
        return Err(not_a_blob());
    }
    let (&version, body) = rest.split_first().ok_or_else(not_a_blob)?;
    if version != VERSION {
        return Err(unsupported_version());
    }
    Ok(body)
}

/// Why a body is not one version 1 node. A reader refuses either as
/// malformed; a writer that wrote a repeated key says so.
#[derive(Debug, PartialEq, Eq)]
enum Invalid {
    Malformed,
    DuplicateKey,
}

/// Check that `body` is exactly one version 1 node.
fn validate(body: &[u8]) -> Result<(), Invalid> {
    let mut cursor = Cursor { buf: body, pos: 0 };
    node(&mut cursor, 0)?;
    if cursor.pos != body.len() {
        return Err(Invalid::Malformed);
    }
    Ok(())
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Result<u8, Invalid> {
        self.buf.get(self.pos).copied().ok_or(Invalid::Malformed)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Invalid> {
        let end = self.pos.checked_add(n).ok_or(Invalid::Malformed)?;
        let bytes = self.buf.get(self.pos..end).ok_or(Invalid::Malformed)?;
        self.pos = end;
        Ok(bytes)
    }

    /// A count of nodes or a length of bytes. Every node takes at least one
    /// byte, so either is at most the bytes left, and a larger one is
    /// refused before anything loops over it.
    fn count(&mut self) -> Result<usize, Invalid> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| Invalid::Malformed)?;
        let n = usize::try_from(u32::from_le_bytes(bytes)).map_err(|_| Invalid::Malformed)?;
        if n > self.buf.get(self.pos..).map_or(0, <[u8]>::len) {
            return Err(Invalid::Malformed);
        }
        Ok(n)
    }

    /// An object's key: a length, then UTF-8.
    fn key(&mut self) -> Result<&'a str, Invalid> {
        let len = self.count()?;
        core::str::from_utf8(self.take(len)?).map_err(|_| Invalid::Malformed)
    }

    /// One scalar, whatever its tag; the caller has checked the tag.
    fn scalar(&mut self) -> Result<&'a [u8], Invalid> {
        let rest = self.buf.get(self.pos..).ok_or(Invalid::Malformed)?;
        let (_, used) = leaf::read(rest, Form::Frame).map_err(|_| Invalid::Malformed)?;
        self.take(used)
    }

    /// A map's key: an integer, text or bytes scalar.
    fn map_key(&mut self) -> Result<MapKey<'a>, Invalid> {
        if !KEYS.contains(&self.peek()?) {
            return Err(Invalid::Malformed);
        }
        self.scalar().map(MapKey)
    }
}

/// Step over one node at `depth`, validating it.
fn node(c: &mut Cursor<'_>, depth: usize) -> Result<(), Invalid> {
    if depth > MAX_DEPTH {
        return Err(Invalid::Malformed);
    }
    match c.peek()? {
        ARRAY => {
            c.pos += 1;
            for _ in 0..c.count()? {
                node(c, depth + 1)?;
            }
        }
        OBJECT => {
            c.pos += 1;
            let count = c.count()?;
            let mut seen = HashSet::new();
            for _ in 0..count {
                if !seen.insert(c.key()?) {
                    return Err(Invalid::DuplicateKey);
                }
                node(c, depth + 1)?;
            }
        }
        MAP => {
            c.pos += 1;
            let count = c.count()?;
            let mut keys = Vec::new();
            for _ in 0..count {
                keys.push(c.map_key()?);
                node(c, depth + 1)?;
            }
            distinct(keys)?;
        }
        SOME => {
            c.pos += 1;
            node(c, depth + 1)?;
        }
        tag if SCALARS.contains(&tag) => {
            c.scalar()?;
        }
        _ => return Err(Invalid::Malformed),
    }
    Ok(())
}

/// A map's key node, borrowed from the blob, so the keys gathered to find a
/// repeat hold no copy of a key's value, only where it is. It is compared
/// by its [`Identity`].
#[derive(Clone, Copy)]
struct MapKey<'a>(&'a [u8]);

/// What makes two map keys the same: integers of equal value, whatever
/// their widths, so `1u8` and `1u64` are one key; and otherwise equal
/// nodes, tag and all, so text and bytes with the same bytes are two.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Identity<'a> {
    Int(bool, u128),
    Node(&'a [u8]),
}

impl<'a> MapKey<'a> {
    fn identity(self) -> Identity<'a> {
        match leaf::read(self.0, Form::Frame) {
            Ok(((_, Physical::Int(int)), _)) => {
                let (negative, word) = int.sign_and_word();
                Identity::Int(negative, word)
            }
            _ => Identity::Node(self.0),
        }
    }
}

/// Refuse a map whose keys repeat one.
///
/// Each key's identity is worked out once, not at every comparison of a
/// sort. An integer's identity is its value, a copy of the key, so those
/// are kept in a buffer sized up front, which never regrows and is wiped
/// when dropped. Any other key is compared where it lies in the blob.
fn distinct(keys: Vec<MapKey<'_>>) -> Result<(), Invalid> {
    let mut integers: Zeroizing<Vec<[u8; 17]>> = Zeroizing::new(Vec::with_capacity(keys.len()));
    let mut nodes = Vec::new();
    for key in keys {
        match key.identity() {
            Identity::Int(negative, word) => {
                let mut value = [0; 17];
                value[0] = u8::from(negative);
                value[1..].copy_from_slice(&word.to_le_bytes());
                integers.push(value);
            }
            Identity::Node(node) => nodes.push(node),
        }
    }
    integers.sort_unstable();
    nodes.sort_unstable();
    if integers.windows(2).any(|pair| pair[0] == pair[1])
        || nodes.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(Invalid::DuplicateKey);
    }
    Ok(())
}

// =============================================================================
// Writing
// =============================================================================

/// Write `value` as a blob: [`HEADER`], then its node.
///
/// The blob is the value's plaintext, so it is returned [`Protected`], and
/// wiped when it is dropped. The buffer grows without leaving copies of what
/// it held behind, and is wiped if writing fails part way. What is written
/// is validated as a reader would before it is returned, so a blob this
/// returns always reads.
///
/// # Errors
///
/// An [`ErrorKind::Unwritable`]: a value nested deeper than 128 levels, text
/// or bytes too long for a `u32` length, a map key that is not an integer,
/// text or bytes, a repeated key, a container whose `Serialize` gave a
/// length other than the number of children it wrote, a map key written
/// without its value (or a value without its key), or a value its own
/// `Serialize` refused.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Protected<Vec<u8>>, Error> {
    let mut out = Zeroizing::new(Vec::new());
    reserve(&mut out, HEADER.len());
    out.extend_from_slice(&HEADER);
    value
        .serialize(Writer {
            out: &mut out,
            depth: 0,
        })
        .map_err(unwritable)?;
    // The writer checks depth, lengths and counts as it goes. A repeated
    // key is found here, as a reader would find it, so the writer keeps no
    // copy of the keys it wrote.
    validate(&out[HEADER.len()..]).map_err(refused_own)?;
    Ok(Protected::new(core::mem::take(&mut *out)))
}

/// What [`to_vec`] says of a blob it wrote but would not read.
fn refused_own(invalid: Invalid) -> Error {
    match invalid {
        Invalid::DuplicateKey => unwritable(written(FrameWriteError::DuplicateKey)),
        // The writer checks everything else as it writes, so this is a bug
        // in it, reported rather than returned as a blob no reader reads.
        Invalid::Malformed => Error::of(
            ErrorKind::Unwritable,
            "the writer wrote a malformed storage blob",
        ),
    }
}

/// Make room for `additional` more bytes. A `Vec` that regrows frees its
/// old allocation without wiping it, so grow into a fresh allocation and
/// wipe the old one instead.
///
/// The same as `reserve` in `vitaminc_aead::frame`, which the frame writer
/// uses; that one is private to its crate. A fix to either belongs in both.
fn reserve(out: &mut Vec<u8>, additional: usize) {
    if out.capacity() - out.len() >= additional {
        return;
    }
    let capacity = out
        .len()
        .saturating_add(additional)
        .max(out.len().saturating_mul(2))
        .max(64);
    let mut grown = Vec::with_capacity(capacity);
    grown.extend_from_slice(out);
    out.zeroize();
    *out = grown;
}

fn write_len(out: &mut Vec<u8>, len: usize) -> Result<(), transport::Error> {
    let len = u32::try_from(len).map_err(|_| written(FrameWriteError::TooLong))?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

/// An object's key: a length, then UTF-8.
fn write_key(out: &mut Vec<u8>, key: &str) -> Result<(), transport::Error> {
    reserve(out, key.len().saturating_add(4));
    write_len(out, key.len())?;
    out.extend_from_slice(key.as_bytes());
    Ok(())
}

fn write_scalar(out: &mut Vec<u8>, value: Physical<'_>) -> Result<(), transport::Error> {
    reserve(out, leaf::max_len(&value));
    leaf::write(None, value, Form::Frame, out).map_err(|e| {
        written(match e {
            ScalarError::Invalid => FrameWriteError::Invalid,
            // Text or bytes too long for a `u32` length: a plain scalar
            // has nothing else to refuse.
            _ => FrameWriteError::TooLong,
        })
    })
}

/// Write `value`'s `Display` as a text scalar. It is formatted straight
/// into the blob, as serde's default would format it into a `String` of its
/// own and free it unwiped.
fn write_display<T: fmt::Display + ?Sized>(
    out: &mut Vec<u8>,
    value: &T,
) -> Result<(), transport::Error> {
    reserve(out, 5);
    out.push(tags::STRING);
    let at = out.len();
    out.extend_from_slice(&[0; 4]);
    fmt::write(&mut Appender(out), format_args!("{value}"))
        .map_err(|_| <transport::Error as ser::Error>::custom(""))?;
    let len = out.len() - at - 4;
    let len = u32::try_from(len).map_err(|_| written(FrameWriteError::TooLong))?;
    out[at..at + 4].copy_from_slice(&len.to_le_bytes());
    Ok(())
}

/// Appends formatted text to a blob, growing it as [`reserve`] does.
struct Appender<'o>(&'o mut Vec<u8>);

impl fmt::Write for Appender<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        reserve(self.0, s.len());
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// Writes one node onto the end of a blob, `depth` levels below its root.
struct Writer<'o> {
    out: &'o mut Vec<u8>,
    depth: usize,
}

impl<'o> Writer<'o> {
    fn check_depth(&self) -> Result<(), transport::Error> {
        if self.depth > MAX_DEPTH {
            return Err(written(FrameWriteError::TooDeep));
        }
        Ok(())
    }

    fn scalar(self, value: Physical<'_>) -> Result<(), transport::Error> {
        self.check_depth()?;
        write_scalar(self.out, value)
    }

    fn int(self, value: Int) -> Result<(), transport::Error> {
        self.scalar(Physical::Int(value))
    }

    /// Open an array, an object or a map whose count is patched in at its
    /// end. `variant` is the enum variant whose payload it is, if any, so
    /// an error inside it is placed under the variant's name.
    fn container(
        self,
        tag: u8,
        expected: Option<usize>,
        variant: Option<&'static str>,
    ) -> Result<Container<'o>, transport::Error> {
        self.check_depth()?;
        reserve(self.out, 5);
        self.out.push(tag);
        let at = self.out.len();
        self.out.extend_from_slice(&[0; 4]);
        Ok(Container {
            out: self.out,
            depth: self.depth,
            at,
            n: 0,
            expected,
            variant,
        })
    }

    /// The object of one entry that holds a tuple or struct variant: its
    /// count and key are known, so they are written now, and the payload
    /// container is returned open, one level down.
    fn variant(
        self,
        variant: &'static str,
        tag: u8,
        len: usize,
    ) -> Result<Container<'o>, transport::Error> {
        self.check_depth()?;
        reserve(self.out, 5);
        self.out.push(OBJECT);
        self.out.extend_from_slice(&1u32.to_le_bytes());
        write_key(self.out, variant)?;
        Writer {
            out: self.out,
            depth: self.depth + 1,
        }
        .container(tag, Some(len), Some(variant))
    }
}

/// An array, an object or a map being written.
struct Container<'o> {
    out: &'o mut Vec<u8>,
    depth: usize,
    /// Where the count goes.
    at: usize,
    n: usize,
    expected: Option<usize>,
    variant: Option<&'static str>,
}

impl Container<'_> {
    fn child<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
        at: impl FnOnce() -> PathSegment,
    ) -> Result<(), transport::Error> {
        self.n += 1;
        value
            .serialize(Writer {
                out: &mut *self.out,
                depth: self.depth + 1,
            })
            .map_err(|e| {
                let e = e.at(at());
                match self.variant {
                    Some(variant) => e.at(PathSegment::Key(variant.to_owned())),
                    None => e,
                }
            })
    }

    fn element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), transport::Error> {
        let index = self.n;
        self.child(value, || PathSegment::Index(index))
    }

    /// An object's entry: a field or variant name the type declares, then
    /// its value.
    fn field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), transport::Error> {
        write_key(self.out, key)?;
        self.child(value, || PathSegment::Key(key.to_owned()))
    }

    fn end(self) -> Result<(), transport::Error> {
        if self.expected.is_some_and(|e| e != self.n) {
            return Err(written(FrameWriteError::CountMismatch));
        }
        let n = u32::try_from(self.n).map_err(|_| written(FrameWriteError::TooLong))?;
        self.out[self.at..self.at + 4].copy_from_slice(&n.to_le_bytes());
        Ok(())
    }
}

/// A map being written. Each key is written as a node the moment it is
/// given, so no copy of it is kept.
struct MapWriter<'o> {
    c: Container<'o>,
    /// Whether a key has been written whose value is next.
    pending: bool,
}

impl<'o> ser::Serializer for Writer<'o> {
    type Ok = ();
    type Error = transport::Error;
    type SerializeSeq = Container<'o>;
    type SerializeTuple = Container<'o>;
    type SerializeTupleStruct = Container<'o>;
    type SerializeTupleVariant = Container<'o>;
    type SerializeMap = MapWriter<'o>;
    type SerializeStruct = Container<'o>;
    type SerializeStructVariant = Container<'o>;

    fn serialize_bool(self, v: bool) -> Result<(), transport::Error> {
        self.scalar(Physical::Bool(v))
    }
    fn serialize_i8(self, v: i8) -> Result<(), transport::Error> {
        self.int(Int::I8(v))
    }
    fn serialize_i16(self, v: i16) -> Result<(), transport::Error> {
        self.int(Int::I16(v))
    }
    fn serialize_i32(self, v: i32) -> Result<(), transport::Error> {
        self.int(Int::I32(v))
    }
    fn serialize_i64(self, v: i64) -> Result<(), transport::Error> {
        self.int(Int::I64(v))
    }
    fn serialize_i128(self, v: i128) -> Result<(), transport::Error> {
        self.int(Int::I128(v))
    }
    fn serialize_u8(self, v: u8) -> Result<(), transport::Error> {
        self.int(Int::U8(v))
    }
    fn serialize_u16(self, v: u16) -> Result<(), transport::Error> {
        self.int(Int::U16(v))
    }
    fn serialize_u32(self, v: u32) -> Result<(), transport::Error> {
        self.int(Int::U32(v))
    }
    fn serialize_u64(self, v: u64) -> Result<(), transport::Error> {
        self.int(Int::U64(v))
    }
    fn serialize_u128(self, v: u128) -> Result<(), transport::Error> {
        self.int(Int::U128(v))
    }
    fn serialize_f32(self, v: f32) -> Result<(), transport::Error> {
        self.scalar(Physical::Float(Float::F32(v)))
    }
    fn serialize_f64(self, v: f64) -> Result<(), transport::Error> {
        self.scalar(Physical::Float(Float::F64(v)))
    }
    fn serialize_char(self, v: char) -> Result<(), transport::Error> {
        let mut buf = [0u8; 4];
        self.scalar(Physical::Text(v.encode_utf8(&mut buf)))
    }
    fn serialize_str(self, v: &str) -> Result<(), transport::Error> {
        self.scalar(Physical::Text(v))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<(), transport::Error> {
        self.scalar(Physical::Bytes(v))
    }
    fn serialize_none(self) -> Result<(), transport::Error> {
        self.scalar(Physical::Null)
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), transport::Error> {
        self.check_depth()?;
        reserve(self.out, 1);
        self.out.push(SOME);
        value.serialize(Writer {
            out: self.out,
            depth: self.depth + 1,
        })
    }
    fn serialize_unit(self) -> Result<(), transport::Error> {
        self.scalar(Physical::Null)
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), transport::Error> {
        self.scalar(Physical::Null)
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<(), transport::Error> {
        self.scalar(Physical::Text(variant))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), transport::Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), transport::Error> {
        let mut object = self.container(OBJECT, Some(1), None)?;
        object.field(variant, value)?;
        object.end()
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Container<'o>, transport::Error> {
        self.container(ARRAY, len, None)
    }
    fn serialize_tuple(self, len: usize) -> Result<Container<'o>, transport::Error> {
        self.container(ARRAY, Some(len), None)
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Container<'o>, transport::Error> {
        self.container(ARRAY, Some(len), None)
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Container<'o>, transport::Error> {
        self.variant(variant, ARRAY, len)
    }
    fn serialize_map(self, len: Option<usize>) -> Result<MapWriter<'o>, transport::Error> {
        Ok(MapWriter {
            c: self.container(MAP, len, None)?,
            pending: false,
        })
    }
    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Container<'o>, transport::Error> {
        self.container(OBJECT, Some(len), None)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Container<'o>, transport::Error> {
        self.variant(variant, OBJECT, len)
    }

    fn collect_str<T: fmt::Display + ?Sized>(self, value: &T) -> Result<(), transport::Error> {
        self.check_depth()?;
        write_display(self.out, value)
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

impl ser::SerializeSeq for Container<'_> {
    type Ok = ();
    type Error = transport::Error;
    fn serialize_element<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), transport::Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), transport::Error> {
        Container::end(self)
    }
}

impl ser::SerializeTuple for Container<'_> {
    type Ok = ();
    type Error = transport::Error;
    fn serialize_element<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), transport::Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), transport::Error> {
        Container::end(self)
    }
}

impl ser::SerializeTupleStruct for Container<'_> {
    type Ok = ();
    type Error = transport::Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), transport::Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), transport::Error> {
        Container::end(self)
    }
}

impl ser::SerializeTupleVariant for Container<'_> {
    type Ok = ();
    type Error = transport::Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), transport::Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), transport::Error> {
        Container::end(self)
    }
}

impl ser::SerializeStruct for Container<'_> {
    type Ok = ();
    type Error = transport::Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), transport::Error> {
        self.field(key, value)
    }
    fn end(self) -> Result<(), transport::Error> {
        Container::end(self)
    }
}

impl ser::SerializeStructVariant for Container<'_> {
    type Ok = ();
    type Error = transport::Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), transport::Error> {
        self.field(key, value)
    }
    fn end(self) -> Result<(), transport::Error> {
        Container::end(self)
    }
}

impl ser::SerializeMap for MapWriter<'_> {
    type Ok = ();
    type Error = transport::Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), transport::Error> {
        // A second key would leave the first without a value.
        if self.pending {
            return Err(transport::Error::new(
                "a map key was written before the previous value",
            ));
        }
        let index = self.c.n;
        key.serialize(KeyWriter(&mut *self.c.out))
            .map_err(|e| e.at(PathSegment::Entry(index)))?;
        self.pending = true;
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), transport::Error> {
        if !self.pending {
            return Err(transport::Error::new(
                "a map value was written before its key",
            ));
        }
        self.pending = false;
        let index = self.c.n;
        self.c.child(value, || PathSegment::Entry(index))
    }
    fn end(self) -> Result<(), transport::Error> {
        if self.pending {
            return Err(transport::Error::new(
                "a map key was written without its value",
            ));
        }
        self.c.end()
    }
}

fn key_refused() -> transport::Error {
    transport::Error::new("a map key must be an integer, text or bytes")
}

/// Writes a map's key node: an integer, text or bytes. A `char` and a unit
/// variant's name are text, and a newtype struct is what it holds.
struct KeyWriter<'o>(&'o mut Vec<u8>);

type NoKey = ser::Impossible<(), transport::Error>;

impl ser::Serializer for KeyWriter<'_> {
    type Ok = ();
    type Error = transport::Error;
    type SerializeSeq = NoKey;
    type SerializeTuple = NoKey;
    type SerializeTupleStruct = NoKey;
    type SerializeTupleVariant = NoKey;
    type SerializeMap = NoKey;
    type SerializeStruct = NoKey;
    type SerializeStructVariant = NoKey;

    fn serialize_i8(self, v: i8) -> Result<(), transport::Error> {
        write_scalar(self.0, Physical::Int(Int::I8(v)))
    }
    fn serialize_i16(self, v: i16) -> Result<(), transport::Error> {
        write_scalar(self.0, Physical::Int(Int::I16(v)))
    }
    fn serialize_i32(self, v: i32) -> Result<(), transport::Error> {
        write_scalar(self.0, Physical::Int(Int::I32(v)))
    }
    fn serialize_i64(self, v: i64) -> Result<(), transport::Error> {
        write_scalar(self.0, Physical::Int(Int::I64(v)))
    }
    fn serialize_i128(self, v: i128) -> Result<(), transport::Error> {
        write_scalar(self.0, Physical::Int(Int::I128(v)))
    }
    fn serialize_u8(self, v: u8) -> Result<(), transport::Error> {
        write_scalar(self.0, Physical::Int(Int::U8(v)))
    }
    fn serialize_u16(self, v: u16) -> Result<(), transport::Error> {
        write_scalar(self.0, Physical::Int(Int::U16(v)))
    }
    fn serialize_u32(self, v: u32) -> Result<(), transport::Error> {
        write_scalar(self.0, Physical::Int(Int::U32(v)))
    }
    fn serialize_u64(self, v: u64) -> Result<(), transport::Error> {
        write_scalar(self.0, Physical::Int(Int::U64(v)))
    }
    fn serialize_u128(self, v: u128) -> Result<(), transport::Error> {
        write_scalar(self.0, Physical::Int(Int::U128(v)))
    }
    fn serialize_char(self, v: char) -> Result<(), transport::Error> {
        let mut buf = [0u8; 4];
        write_scalar(self.0, Physical::Text(v.encode_utf8(&mut buf)))
    }
    fn serialize_str(self, v: &str) -> Result<(), transport::Error> {
        write_scalar(self.0, Physical::Text(v))
    }
    fn serialize_bytes(self, v: &[u8]) -> Result<(), transport::Error> {
        write_scalar(self.0, Physical::Bytes(v))
    }
    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<(), transport::Error> {
        write_scalar(self.0, Physical::Text(variant))
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), transport::Error> {
        value.serialize(self)
    }
    fn collect_str<T: fmt::Display + ?Sized>(self, value: &T) -> Result<(), transport::Error> {
        write_display(self.0, value)
    }
    fn is_human_readable(&self) -> bool {
        false
    }

    fn serialize_bool(self, _v: bool) -> Result<(), transport::Error> {
        Err(key_refused())
    }
    fn serialize_f32(self, _v: f32) -> Result<(), transport::Error> {
        Err(key_refused())
    }
    fn serialize_f64(self, _v: f64) -> Result<(), transport::Error> {
        Err(key_refused())
    }
    fn serialize_none(self) -> Result<(), transport::Error> {
        Err(key_refused())
    }
    fn serialize_some<T: Serialize + ?Sized>(self, _value: &T) -> Result<(), transport::Error> {
        Err(key_refused())
    }
    fn serialize_unit(self) -> Result<(), transport::Error> {
        Err(key_refused())
    }
    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), transport::Error> {
        Err(key_refused())
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<(), transport::Error> {
        Err(key_refused())
    }
    fn serialize_seq(self, _len: Option<usize>) -> Result<NoKey, transport::Error> {
        Err(key_refused())
    }
    fn serialize_tuple(self, _len: usize) -> Result<NoKey, transport::Error> {
        Err(key_refused())
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<NoKey, transport::Error> {
        Err(key_refused())
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<NoKey, transport::Error> {
        Err(key_refused())
    }
    fn serialize_map(self, _len: Option<usize>) -> Result<NoKey, transport::Error> {
        Err(key_refused())
    }
    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<NoKey, transport::Error> {
        Err(key_refused())
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<NoKey, transport::Error> {
        Err(key_refused())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_spells_vcs_and_the_version() {
        assert_eq!(HEADER, [0x56, 0x43, 0x53, 0x01]);
        assert_eq!(SOME, 0xF5);
        assert_eq!(MAP, 0xF6);
    }

    /// No byte that starts a version 1 node is also a header byte, so a
    /// transport frame is never read as a blob, nor a blob as a frame.
    #[test]
    fn the_magic_is_no_node_tag() {
        for byte in MAGIC {
            assert!(!SCALARS.contains(&byte) && ![ARRAY, OBJECT, MAP, SOME].contains(&byte));
        }
    }

    #[test]
    fn reserve_keeps_the_bytes_and_makes_room() {
        let mut out = vec![1, 2, 3];
        out.shrink_to_fit();
        reserve(&mut out, 100);
        assert_eq!(out, [1, 2, 3]);
        assert!(out.capacity() >= 103);
        let capacity = out.capacity();
        reserve(&mut out, 1);
        assert_eq!(out.capacity(), capacity, "a buffer with room is left alone");
        // A full buffer grows for even a little more than its length.
        let mut full = vec![1, 2, 3];
        full.shrink_to_fit();
        reserve(&mut full, 4);
        assert!(full.capacity() >= 7);
    }

    /// The two refusals no blob can reach: they mean the reader and the
    /// validator, or the writer and the validator, disagree.
    #[test]
    fn a_bug_is_reported_as_one() {
        let error = mismatch(transport::Error::new(transport::MALFORMED));
        assert_eq!(error, malformed());
        let error = refused_own(Invalid::Malformed);
        assert_eq!(error.kind(), ErrorKind::Unwritable);
        assert_eq!(error.message(), "the writer wrote a malformed storage blob");
        let error = refused_own(Invalid::DuplicateKey);
        assert_eq!(error.kind(), ErrorKind::Unwritable);
        assert_eq!(error.message(), "duplicate key");
    }

    /// Map keys are compared by value across integer widths, and by node
    /// otherwise.
    #[test]
    fn map_keys_compare_by_identity() {
        let key = |bytes: &'static [u8]| MapKey(bytes).identity();
        assert!(key(&[tags::UINT8, 1]) == key(&[tags::INT64, 1, 0, 0, 0, 0, 0, 0, 0]));
        assert!(key(&[tags::INT8, 0xFF]) != key(&[tags::UINT8, 0xFF]));
        assert!(key(&[tags::STRING, 1, 0, 0, 0, b'a']) != key(&[tags::BYTES, 1, 0, 0, 0, b'a']));
        assert!(distinct(vec![MapKey(&[tags::UINT8, 2]), MapKey(&[tags::UINT8, 1])]).is_ok());
        assert_eq!(
            distinct(vec![
                MapKey(&[tags::UINT8, 1]),
                MapKey(&[tags::UINT8, 2]),
                MapKey(&[tags::UINT16, 1, 0])
            ]),
            Err(Invalid::DuplicateKey)
        );
    }
}
