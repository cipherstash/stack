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
//! // The blob is plaintext, so it comes back in a `Buffer`: read through
//! // `risky_ref`, and wiped when it is dropped.
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

use std::fmt;

use ::serde::ser::Serialize;
use ::serde::Deserialize;
use vitaminc_aead::frame::__private::SeenKeys;
use vitaminc_aead::frame::{ARRAY, MAX_DEPTH, OBJECT};
use vitaminc_aead::leaf::{self, Form};
use vitaminc_aead::plaintext::Physical;
use vitaminc_aead::tags;
use vitaminc_protected::{Buffer, Controlled};

use crate::serde::{self as transport, from_validated, PathSegment, Profile};
use crate::write::{write, AsStorage};

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
pub(crate) enum Invalid {
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
            let mut seen = SeenKeys::default();
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
            distinct(keys.into_iter())?;
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
pub(crate) struct MapKey<'a>(pub(crate) &'a [u8]);

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

/// The bytes an integer key's identity takes in [`distinct`]'s scratch:
/// its sign, then its magnitude as a little-endian `u128`.
const INT_IDENTITY: usize = 1 + 16;

/// Refuse a map whose keys repeat one.
///
/// Each key's identity is worked out once, not at every comparison of a
/// sort. An integer's identity is its value, a copy of the key, so those
/// are kept in a [`Buffer`] sized up front, which never regrows and is
/// wiped when dropped. Any other key is compared where it lies in the blob.
pub(crate) fn distinct<'a>(keys: impl ExactSizeIterator<Item = MapKey<'a>>) -> Result<(), Invalid> {
    let mut integers = Buffer::with_capacity(keys.len().saturating_mul(INT_IDENTITY));
    let mut nodes = Vec::new();
    for key in keys {
        match key.identity() {
            Identity::Int(negative, word) => {
                integers.push(u8::from(negative));
                integers.extend_from_slice(&word.to_le_bytes());
            }
            Identity::Node(node) => nodes.push(node),
        }
    }
    let (integers, rest) = integers.risky_inner_mut().as_chunks_mut::<INT_IDENTITY>();
    debug_assert!(rest.is_empty(), "every identity is whole");
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
/// The node is written by the same serde writer as the transport format's
/// [`to_vec`](crate::serde::to_vec), set to this profile: it marks an
/// `Option`'s `Some` with [`SOME`], and writes a map as a [`MAP`] whose
/// keys keep their kind.
///
/// The blob is the value's plaintext, so it is returned as a [`Buffer`],
/// and wiped when it is dropped. It grows without leaving copies of what
/// it held behind, and is wiped if writing fails part way. The writer
/// checks each rule a reader checks as it writes, so a blob this returns
/// always reads; a debug build reads it back to make sure.
///
/// # Errors
///
/// An [`ErrorKind::Unwritable`]: a value nested deeper than 128 levels, text
/// or bytes too long for a `u32` length, a map key that is not an integer,
/// text or bytes, a repeated key, a container whose `Serialize` gave a
/// length other than the number of children it wrote, a map key written
/// without its value (or a value without its key), or a value its own
/// `Serialize` refused.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Buffer, Error> {
    let mut out = Buffer::new();
    out.extend_from_slice(&HEADER);
    write::<AsStorage, T>(value, &mut out).map_err(unwritable)?;
    // The writer checks depth, lengths, counts and repeated keys as it
    // goes, so reading the blob back finds nothing. A debug build does so
    // anyway, since a blob that disagrees with the reader is a bug.
    debug_assert_eq!(
        validate(&out.risky_ref()[HEADER.len()..]),
        Ok(()),
        "the writer wrote a blob the reader refuses"
    );
    Ok(out)
}

#[cfg(kani)]
mod proofs;

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

    /// The refusal no blob can reach: it means the reader and the
    /// validator disagree.
    #[test]
    fn a_bug_is_reported_as_one() {
        let error = mismatch(transport::Error::new(transport::MALFORMED));
        assert_eq!(error, malformed());
    }

    /// Map keys are compared by value across integer widths, and by node
    /// otherwise.
    #[test]
    fn map_keys_compare_by_identity() {
        let key = |bytes: &'static [u8]| MapKey(bytes).identity();
        assert!(key(&[tags::UINT8, 1]) == key(&[tags::INT64, 1, 0, 0, 0, 0, 0, 0, 0]));
        assert!(key(&[tags::INT8, 0xFF]) != key(&[tags::UINT8, 0xFF]));
        assert!(key(&[tags::STRING, 1, 0, 0, 0, b'a']) != key(&[tags::BYTES, 1, 0, 0, 0, b'a']));
        assert!(
            distinct([MapKey(&[tags::UINT8, 2]), MapKey(&[tags::UINT8, 1])].into_iter()).is_ok()
        );
        assert_eq!(
            distinct(
                [
                    MapKey(&[tags::UINT8, 1]),
                    MapKey(&[tags::UINT8, 2]),
                    MapKey(&[tags::UINT16, 1, 0])
                ]
                .into_iter()
            ),
            Err(Invalid::DuplicateKey)
        );
    }
}
