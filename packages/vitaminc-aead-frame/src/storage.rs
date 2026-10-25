//! The storage profile: a value as one versioned blob, for bytes that are
//! kept. [`to_vec`] writes any `Serialize` type as a blob and [`from_slice`]
//! reads one back into any `Deserialize` type.
//!
//! Unlike the rest of this crate, which is transport and ships in lockstep
//! with its peer, the bytes these two functions write and read are a
//! compatibility commitment. The specification below is normative, and the
//! golden corpus in `testdata/storage-v1.json` pins it.
//!
//! ```
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize, PartialEq, Debug)]
//! struct Note {
//!     title: String,
//!     pinned: Option<()>,
//! }
//!
//! let note = Note { title: "hi".into(), pinned: Some(()) };
//! let blob = vitaminc_aead_frame::storage::to_vec(&note)?;
//! assert_eq!(blob[..4], vitaminc_aead_frame::storage::HEADER);
//! let back: Note = vitaminc_aead_frame::storage::from_slice(&blob)?;
//! assert_eq!(back, note);
//! # Ok::<(), vitaminc_aead_frame::serde::Error>(())
//! ```
//!
#![doc = include_str!("../STORAGE.md")]

use std::collections::HashSet;

use ::serde::ser::{self, Serialize};
use ::serde::Deserialize;
use vitaminc_aead::frame::{FrameWriteError, ARRAY, MAX_DEPTH, OBJECT};
use vitaminc_aead::leaf::{self, Form, ScalarError};
use vitaminc_aead::plaintext::{Float, Int, Physical};
use vitaminc_aead::tags;
use zeroize::{Zeroize, Zeroizing};

use crate::serde::{from_validated, written, Error, KeySerializer, PathSegment};

/// The first three bytes of every blob: `"VCS"`.
pub const MAGIC: [u8; 3] = *b"VCS";

/// The version this release writes, and the only one it reads.
pub const VERSION: u8 = 1;

/// The four bytes every blob [`to_vec`] writes starts with: [`MAGIC`],
/// then [`VERSION`].
pub const HEADER: [u8; 4] = [MAGIC[0], MAGIC[1], MAGIC[2], VERSION];

/// The presence marker: `SOME`, then the node an `Option`'s `Some` holds,
/// so `Some(())` and `Some(None)` are not `None`.
pub const SOME: u8 = crate::serde::SOME;

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

// =============================================================================
// Reading
// =============================================================================

fn not_a_blob() -> Error {
    Error::new("not a storage blob")
}

fn unsupported_version() -> Error {
    Error::new("an unsupported storage version")
}

fn malformed() -> Error {
    Error::new("malformed storage blob")
}

/// Read `T` from a blob.
///
/// The header is checked first, then the whole body, so a blob of another
/// version, a malformed body, a repeated key or a value nested too deep is
/// refused before `T` sees anything.
///
/// # Errors
///
/// Bytes that are not a blob, a blob of a version this release does not
/// read, a malformed body, or a value `T` does not accept. Each has a
/// fixed message, so a caller can tell an old reader from a corrupt blob.
pub fn from_slice<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, Error> {
    let body = body(bytes)?;
    validate(body)?;
    from_validated(body)
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

/// Check that `body` is exactly one version 1 node.
fn validate(body: &[u8]) -> Result<(), Error> {
    let mut cursor = Cursor { buf: body, pos: 0 };
    node(&mut cursor, 0)?;
    if cursor.pos != body.len() {
        return Err(malformed());
    }
    Ok(())
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Result<u8, Error> {
        self.buf.get(self.pos).copied().ok_or_else(malformed)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or_else(malformed)?;
        let bytes = self.buf.get(self.pos..end).ok_or_else(malformed)?;
        self.pos = end;
        Ok(bytes)
    }

    /// A count of nodes or a length of bytes. Every node takes at least one
    /// byte, so either is at most the bytes left, and a larger one is
    /// refused before anything loops over it.
    fn count(&mut self) -> Result<usize, Error> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| malformed())?;
        let n = usize::try_from(u32::from_le_bytes(bytes)).map_err(|_| malformed())?;
        if n > self.buf.get(self.pos..).map_or(0, <[u8]>::len) {
            return Err(malformed());
        }
        Ok(n)
    }

    fn key(&mut self) -> Result<&'a str, Error> {
        let len = self.count()?;
        core::str::from_utf8(self.take(len)?).map_err(|_| malformed())
    }
}

/// Step over one node at `depth`, validating it.
fn node(c: &mut Cursor<'_>, depth: usize) -> Result<(), Error> {
    if depth > MAX_DEPTH {
        return Err(malformed());
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
                    return Err(malformed());
                }
                node(c, depth + 1)?;
            }
        }
        SOME => {
            c.pos += 1;
            node(c, depth + 1)?;
        }
        tag if SCALARS.contains(&tag) => {
            let rest = c.buf.get(c.pos..).ok_or_else(malformed)?;
            let (_, used) = leaf::read(rest, Form::Frame).map_err(|_| malformed())?;
            c.pos += used;
        }
        _ => return Err(malformed()),
    }
    Ok(())
}

// =============================================================================
// Writing
// =============================================================================

/// Write `value` as a blob: [`HEADER`], then its node.
///
/// The buffer grows without leaving copies of what it held behind, and is
/// wiped if writing fails part way. What is written is validated as a
/// reader would before it is returned, so a blob this returns always reads.
///
/// # Errors
///
/// A value nested deeper than 128 levels, text or bytes too long for a
/// `u32` length, a map with a key that is not a string, a repeated key, a
/// container whose `Serialize` gave a length other than the number of
/// children it wrote, a map key written without its value (or a value
/// without its key), or a value its own `Serialize` refused.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    let mut out = Zeroizing::new(Vec::new());
    reserve(&mut out, HEADER.len());
    out.extend_from_slice(&HEADER);
    value.serialize(Writer {
        out: &mut out,
        depth: 0,
    })?;
    validate(body(&out)?)?;
    Ok(core::mem::take(&mut *out))
}

/// Make room for `additional` more bytes. A `Vec` that regrows frees its
/// old allocation without wiping it, so grow into a fresh allocation and
/// wipe the old one instead, as `FrameWriter` does.
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

fn write_len(out: &mut Vec<u8>, len: usize) -> Result<(), Error> {
    let len = u32::try_from(len).map_err(|_| written(FrameWriteError::TooLong))?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

fn write_key(out: &mut Vec<u8>, key: &str) -> Result<(), Error> {
    reserve(out, key.len().saturating_add(4));
    write_len(out, key.len())?;
    out.extend_from_slice(key.as_bytes());
    Ok(())
}

/// Writes one node onto the end of a blob, `depth` levels below its root.
struct Writer<'o> {
    out: &'o mut Vec<u8>,
    depth: usize,
}

impl<'o> Writer<'o> {
    fn check_depth(&self) -> Result<(), Error> {
        if self.depth > MAX_DEPTH {
            return Err(written(FrameWriteError::TooDeep));
        }
        Ok(())
    }

    fn scalar(self, value: Physical<'_>) -> Result<(), Error> {
        self.check_depth()?;
        reserve(self.out, leaf::max_len(&value));
        leaf::write(None, value, Form::Frame, self.out).map_err(|e| {
            written(match e {
                ScalarError::Invalid => FrameWriteError::Invalid,
                // Text or bytes too long for a `u32` length: a plain
                // scalar has nothing else to refuse.
                _ => FrameWriteError::TooLong,
            })
        })
    }

    fn int(self, value: Int) -> Result<(), Error> {
        self.scalar(Physical::Int(value))
    }

    /// Open an array or an object whose count is patched in at its end.
    /// `variant` is the enum variant whose payload it is, if any, so an
    /// error inside it is placed under the variant's name.
    fn container(
        self,
        tag: u8,
        expected: Option<usize>,
        variant: Option<&'static str>,
    ) -> Result<Container<'o>, Error> {
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

    fn object(
        self,
        expected: Option<usize>,
        variant: Option<&'static str>,
    ) -> Result<Obj<'o>, Error> {
        Ok(Obj {
            c: self.container(OBJECT, expected, variant)?,
            seen: HashSet::new(),
            key: None,
        })
    }

    /// The object of one entry that holds a tuple or struct variant: its
    /// count and key are known, so they are written now, and the payload
    /// container is returned open, one level down.
    fn variant(self, variant: &'static str, tag: u8, len: usize) -> Result<Container<'o>, Error> {
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

/// An array or an object being written.
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
    ) -> Result<(), Error> {
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

    fn element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        let index = self.n;
        self.child(value, || PathSegment::Index(index))
    }

    fn end(self) -> Result<(), Error> {
        if self.expected.is_some_and(|e| e != self.n) {
            return Err(written(FrameWriteError::CountMismatch));
        }
        let n = u32::try_from(self.n).map_err(|_| written(FrameWriteError::TooLong))?;
        self.out[self.at..self.at + 4].copy_from_slice(&n.to_le_bytes());
        Ok(())
    }
}

/// A key already written, kept to refuse it a second time. Map keys can be
/// data, so the copy is wiped when it is dropped.
#[derive(PartialEq, Eq, Hash)]
struct SeenKey(String);

impl Drop for SeenKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// An object being written: a map, a struct, or a struct variant's payload.
struct Obj<'o> {
    c: Container<'o>,
    seen: HashSet<SeenKey>,
    /// The key of the entry whose value is next, from the caller's map.
    key: Option<Zeroizing<String>>,
}

impl Obj<'_> {
    fn entry<T: Serialize + ?Sized>(
        &mut self,
        key: &str,
        at: impl FnOnce() -> PathSegment,
        value: &T,
    ) -> Result<(), Error> {
        if !self.seen.insert(SeenKey(key.to_owned())) {
            return Err(written(FrameWriteError::DuplicateKey));
        }
        write_key(self.c.out, key)?;
        self.c.child(value, at)
    }

    fn field<T: Serialize + ?Sized>(&mut self, key: &'static str, value: &T) -> Result<(), Error> {
        self.entry(key, || PathSegment::Key(key.to_owned()), value)
    }
}

impl<'o> ser::Serializer for Writer<'o> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Container<'o>;
    type SerializeTuple = Container<'o>;
    type SerializeTupleStruct = Container<'o>;
    type SerializeTupleVariant = Container<'o>;
    type SerializeMap = Obj<'o>;
    type SerializeStruct = Obj<'o>;
    type SerializeStructVariant = Obj<'o>;

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
        self.check_depth()?;
        reserve(self.out, 1);
        self.out.push(SOME);
        value.serialize(Writer {
            out: self.out,
            depth: self.depth + 1,
        })
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
        let mut obj = self.object(Some(1), None)?;
        obj.field(variant, value)?;
        obj.c.end()
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Container<'o>, Error> {
        self.container(ARRAY, len, None)
    }
    fn serialize_tuple(self, len: usize) -> Result<Container<'o>, Error> {
        self.container(ARRAY, Some(len), None)
    }
    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Container<'o>, Error> {
        self.container(ARRAY, Some(len), None)
    }
    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Container<'o>, Error> {
        self.variant(variant, ARRAY, len)
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Obj<'o>, Error> {
        self.object(len, None)
    }
    fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Obj<'o>, Error> {
        self.object(Some(len), None)
    }
    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Obj<'o>, Error> {
        Ok(Obj {
            c: self.variant(variant, OBJECT, len)?,
            seen: HashSet::new(),
            key: None,
        })
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

impl ser::SerializeSeq for Container<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        Container::end(self)
    }
}

impl ser::SerializeTuple for Container<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        Container::end(self)
    }
}

impl ser::SerializeTupleStruct for Container<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        Container::end(self)
    }
}

impl ser::SerializeTupleVariant for Container<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        Container::end(self)
    }
}

impl ser::SerializeMap for Obj<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Error> {
        // A second key would silently replace the first, losing its entry.
        if self.key.is_some() {
            return Err(Error::new(
                "a map key was written before the previous value",
            ));
        }
        self.key = Some(Zeroizing::new(key.serialize(KeySerializer)?));
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        let key = self
            .key
            .take()
            .ok_or_else(|| Error::new("a map value was written before its key"))?;
        let index = self.c.n;
        self.entry(&key, || PathSegment::Entry(index), value)
    }
    fn end(self) -> Result<(), Error> {
        if self.key.is_some() {
            return Err(Error::new("a map key was written without its value"));
        }
        self.c.end()
    }
}

impl ser::SerializeStruct for Obj<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.field(key, value)
    }
    fn end(self) -> Result<(), Error> {
        self.c.end()
    }
}

impl ser::SerializeStructVariant for Obj<'_> {
    type Ok = ();
    type Error = Error;
    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.field(key, value)
    }
    fn end(self) -> Result<(), Error> {
        self.c.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_spells_vcs_and_the_version() {
        assert_eq!(HEADER, [0x56, 0x43, 0x53, 0x01]);
        assert_eq!(SOME, 0xF5);
    }

    /// No byte that starts a version 1 node is also a header byte, so a
    /// transport frame is never read as a blob, nor a blob as a frame.
    #[test]
    fn the_magic_is_no_node_tag() {
        for byte in MAGIC {
            assert!(!SCALARS.contains(&byte) && ![ARRAY, OBJECT, SOME].contains(&byte));
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
}
