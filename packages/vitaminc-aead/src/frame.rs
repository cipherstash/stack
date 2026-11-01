//! The transport frame: one value, as bytes, for crossing an FFI boundary
//! and for carrying a passthrough subtree in the clear.
//!
//! A frame is a transport encoding, not a storage format. Scalars use the
//! leaf codec in [`leaf`] in its frame form (text and bytes
//! carry a `u32` length). Containers are framed with the tags here: an
//! [`ARRAY`] or [`OBJECT`] byte, a `u32` little-endian count, then the
//! children; object keys are a `u32` length and UTF-8 bytes. A
//! [`PASSTHROUGH`] byte marks the next node as a subtree that travels in
//! the clear.
//!
//! [`Frame`] is a validated, borrowed frame that implements [`Encrypt`]
//! by walking its own bytes in place, so a host that ships frames (Go) is
//! a source with no intermediate value. [`FrameWriter`] is a [`Sink`] that
//! writes frame bytes, so the same host decrypts straight into a frame.
//! [`PassthroughFrame`] is the owned frame a ciphertext carries for a
//! passthrough subtree.

use std::collections::HashSet;
use std::ops::Range;

use vitaminc_protected::{Controlled, OpaqueDebug, Protected, TimingSafeEq};
use zeroize::Zeroize;

use crate::leaf::{self, Form, Item, ScalarError};
use crate::plaintext::{
    Encrypt, Error, FixedType, Logical, MapSink, Physical, SeqSink, Sink, SourceError,
};

/// Framing tag for a sequence: `ARRAY`, `u32` count, then the elements.
pub const ARRAY: u8 = 0xF0;
/// Framing tag for a map: `OBJECT`, `u32` count, then `u32` key length,
/// key bytes and value for each entry.
pub const OBJECT: u8 = 0xF1;
/// Framing tag for a passthrough subtree: `PASSTHROUGH`, then one node
/// that travels in the clear.
pub const PASSTHROUGH: u8 = 0xF2;

/// Maximum nesting depth of a frame. Bounds recursion so a deeply nested
/// input cannot overflow the stack. The same limit, counted the same way,
/// as the host bindings', so any frame they accept parses here.
pub const MAX_DEPTH: usize = 128;

/// Exactly one validated value node, borrowed.
///
/// A frame of plaintext is plaintext, so `Debug` is redacted and `==` is
/// constant time.
#[derive(Clone, Copy, OpaqueDebug, TimingSafeEq)]
pub struct Frame<'a> {
    bytes: &'a [u8],
}

/// The bytes are not a well-formed frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("malformed frame")]
pub struct FrameError;

impl<'a> Frame<'a> {
    /// Validate `bytes` as exactly one value node.
    ///
    /// The whole frame is checked up front, so [`visit`](Encrypt::visit)
    /// never has to report a malformed frame part way through a walk.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, FrameError> {
        let (frame, rest) = Self::parse_nested(bytes, 0)?;
        if !rest.is_empty() {
            return Err(FrameError);
        }
        Ok(frame)
    }

    /// Validate the value node at the start of `bytes`, and return it with
    /// the bytes after it.
    ///
    /// For a frame embedded in a larger structure, such as the passthrough
    /// payload of a ciphertext node. `depth` is how many levels the carrier
    /// already nests the node, so the [`MAX_DEPTH`] bound counts the whole
    /// structure and not the frame alone.
    pub fn parse_nested(bytes: &'a [u8], depth: usize) -> Result<(Self, &'a [u8]), FrameError> {
        let mut cursor = Cursor { buf: bytes, pos: 0 };
        skip(&mut cursor, depth)?;
        let (frame, rest) = bytes.split_at(cursor.pos);
        Ok((Self { bytes: frame }, rest))
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Result<u8, FrameError> {
        self.buf.get(self.pos).copied().ok_or(FrameError)
    }

    fn byte(&mut self) -> Result<u8, FrameError> {
        let b = self.peek()?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], FrameError> {
        let end = self.pos.checked_add(n).ok_or(FrameError)?;
        let s = self.buf.get(self.pos..end).ok_or(FrameError)?;
        self.pos = end;
        Ok(s)
    }

    fn count(&mut self) -> Result<usize, FrameError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().map_err(|_| FrameError)?) as usize)
    }

    fn key(&mut self) -> Result<&'a str, FrameError> {
        let len = self.count()?;
        core::str::from_utf8(self.take(len)?).map_err(|_| FrameError)
    }

    fn scalar(&mut self) -> Result<Item<'a>, FrameError> {
        let (item, used) =
            leaf::read_item(&self.buf[self.pos..], Form::Frame).map_err(|_| FrameError)?;
        self.pos += used;
        Ok(item)
    }

    /// The next whole value node, as its own frame.
    fn node(&mut self, depth: usize) -> Result<Frame<'a>, FrameError> {
        let start = self.pos;
        skip(self, depth)?;
        Ok(Frame {
            bytes: &self.buf[start..self.pos],
        })
    }
}

/// Step over one value node, validating it.
fn skip(c: &mut Cursor<'_>, depth: usize) -> Result<(), FrameError> {
    if depth > MAX_DEPTH {
        return Err(FrameError);
    }
    match c.peek()? {
        ARRAY => {
            c.byte()?;
            for _ in 0..c.count()? {
                skip(c, depth + 1)?;
            }
        }
        OBJECT => {
            c.byte()?;
            let count = c.count()?;
            let mut seen = HashSet::new();
            for _ in 0..count {
                let key = c.key()?;
                if !seen.insert(key) {
                    return Err(FrameError);
                }
                skip(c, depth + 1)?;
            }
        }
        PASSTHROUGH => {
            c.byte()?;
            skip(c, depth + 1)?;
        }
        _ => {
            c.scalar()?;
        }
    }
    Ok(())
}

// Everything below runs on a frame `parse` accepted, so a read cannot fail.
const VALIDATED: &str = "frame was validated by Frame::parse";

/// A frame walked in place: no scalar leaves the buffer except to go
/// straight to the sink.
impl Encrypt for Frame<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        visit_node(
            &mut Cursor {
                buf: self.bytes,
                pos: 0,
            },
            sink,
        )
    }
}

/// A borrowed frame is the same frame: it is a view, and `Copy`.
impl Encrypt for &Frame<'_> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (*self).visit(sink)
    }
}

/// Walk the node at the cursor into `sink`, leaving the cursor after it.
/// One pass: each byte is read once, except that a passthrough subtree is
/// stepped over to find its end before the sink walks it.
fn visit_node<S: Sink>(c: &mut Cursor<'_>, sink: S) -> Result<S::Ok, S::Error> {
    match c.peek().expect(VALIDATED) {
        ARRAY => {
            c.byte().expect(VALIDATED);
            let count = c.count().expect(VALIDATED);
            let mut seq = sink.seq(Some(count))?;
            for _ in 0..count {
                visit_node(c, seq.element()?)?;
            }
            seq.end()
        }
        OBJECT => {
            c.byte().expect(VALIDATED);
            let count = c.count().expect(VALIDATED);
            let mut map = sink.map(Some(count))?;
            for _ in 0..count {
                let key = c.key().expect(VALIDATED);
                visit_node(c, map.entry(key)?)?;
            }
            map.end()
        }
        PASSTHROUGH => {
            c.byte().expect(VALIDATED);
            sink.passthrough(c.node(0).expect(VALIDATED))
        }
        _ => match c.scalar().expect(VALIDATED) {
            Item::Scalar(ty, v) => sink.scalar(ty, v),
            Item::TypedNull(ty) => sink.typed_null(ty),
        },
    }
}

/// An owned frame: the payload a ciphertext carries for a passthrough
/// subtree. Non-sensitive by contract; neither sealed nor authenticated,
/// and never wiped. `Debug` and `==` match [`Frame`]'s all the same, so a
/// frame prints and compares one way whichever form it is in.
#[derive(Clone, OpaqueDebug, TimingSafeEq)]
pub struct PassthroughFrame(pub Vec<u8>);

impl PassthroughFrame {
    /// The frame, validated.
    pub fn parse(&self) -> Result<Frame<'_>, FrameError> {
        Frame::parse(&self.0)
    }
}

impl Encrypt for PassthroughFrame {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.parse()
            .map_err(|e| S::Error::source(SourceError::new(e)))?
            .visit(sink)
    }
}

impl Encrypt for &PassthroughFrame {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.parse()
            .map_err(|e| S::Error::source(SourceError::new(e)))?
            .visit(sink)
    }
}

/// Why a value could not be written as a frame.
#[derive(Debug, thiserror::Error)]
pub enum FrameWriteError {
    /// Nested deeper than [`MAX_DEPTH`].
    #[error("value nests deeper than {MAX_DEPTH} levels")]
    TooDeep,
    /// Text, bytes, a key or a count longer than a `u32`.
    #[error("text, bytes, a key or a count is too long for a u32")]
    TooLong,
    /// A value that is not valid for its logical type.
    #[error("value is not valid for its logical type")]
    Invalid,
    /// A container's declared length did not match the children written.
    #[error("container length does not match its children")]
    CountMismatch,
    /// A map wrote the same key twice.
    #[error("duplicate key")]
    DuplicateKey,
    /// A child sink was dropped without a value written into it, which
    /// would leave the container's count ahead of its children.
    #[error("a child sink was dropped without a value")]
    Unwritten,
    /// A container was never ended, so its count was never written and
    /// the bytes are not a frame.
    #[error("a container was never ended")]
    Unfinished,
    /// The source stopped the walk.
    #[error("source failed: {0}")]
    Source(#[source] SourceError),
}

impl Error for FrameWriteError {
    fn source(error: SourceError) -> Self {
        Self::Source(error)
    }
}

/// Write any source as a frame. The buffer is `Protected`, since a frame
/// of plaintext is plaintext, and it grows without leaving copies behind.
///
/// The result is checked with [`Frame::parse`] before it is returned, so a
/// source that opens a container and never ends it is refused here, not by
/// every later reader of the frame.
pub fn to_frame<P: Encrypt>(p: P) -> Result<Protected<Vec<u8>>, FrameWriteError> {
    to_frame_at(p, 0)
}

/// [`to_frame`] for a subtree whose root sits `depth` levels below the top
/// of a document, so [`MAX_DEPTH`] counts from the top, as the transport
/// decoder counts it.
pub(crate) fn to_frame_at<P: Encrypt>(
    p: P,
    depth: usize,
) -> Result<Protected<Vec<u8>>, FrameWriteError> {
    let mut out = Protected::new(Vec::new());
    p.visit(FrameWriter {
        out: out.risky_inner_mut(),
        depth,
    })?;
    Frame::parse(out.risky_ref()).map_err(|_| FrameWriteError::Unfinished)?;
    Ok(out)
}

/// A sink that writes one value node onto the end of a buffer. Unknown
/// container lengths are patched in at `end`.
pub struct FrameWriter<'o> {
    out: &'o mut Vec<u8>,
    depth: usize,
}

impl<'o> FrameWriter<'o> {
    pub fn new(out: &'o mut Vec<u8>) -> Self {
        Self { out, depth: 0 }
    }

    /// A writer for a node that sits `depth` levels below the top of a
    /// document, so [`MAX_DEPTH`] counts from the top: for a subtree
    /// written to a buffer of its own and copied into the document later.
    pub fn at_depth(out: &'o mut Vec<u8>, depth: usize) -> Self {
        Self { out, depth }
    }

    /// How many levels below the top of its document this writer's node
    /// sits.
    pub fn depth(&self) -> usize {
        self.depth
    }

    fn node(self, tag: u8) -> Result<&'o mut Vec<u8>, FrameWriteError> {
        if self.depth > MAX_DEPTH {
            return Err(FrameWriteError::TooDeep);
        }
        reserve(self.out, 1);
        self.out.push(tag);
        Ok(self.out)
    }

    fn container(self, tag: u8) -> Result<Count<'o>, FrameWriteError> {
        let depth = self.depth;
        reserve(self.out, 5);
        let out = self.node(tag)?;
        let at = out.len();
        out.extend_from_slice(&[0; 4]);
        Ok(Count {
            out,
            depth,
            at,
            n: 0,
            open: None,
        })
    }
}

/// Make room for `additional` more bytes. A `Vec` that regrows frees its
/// old allocation without wiping it, and a frame is plaintext, so grow into
/// a fresh allocation and wipe the old one instead.
pub(crate) fn reserve(out: &mut Vec<u8>, additional: usize) {
    if out.capacity() - out.len() >= additional {
        return;
    }
    // Doubling the length, not the capacity, still amortises a full
    // buffer's growth, and never balloons a buffer that had room.
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

fn write_len(out: &mut Vec<u8>, len: usize) -> Result<(), FrameWriteError> {
    let len = u32::try_from(len).map_err(|_| FrameWriteError::TooLong)?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

/// A container whose count is written once the children are known.
struct Count<'o> {
    out: &'o mut Vec<u8>,
    depth: usize,
    at: usize,
    n: usize,
    /// Where the last child sink handed out would start writing. Every
    /// node writes at least its tag, so if the buffer has not grown past
    /// it by the next child or the end, that sink was dropped unused.
    open: Option<usize>,
}

impl Count<'_> {
    fn settle(&mut self) -> Result<(), FrameWriteError> {
        match self.open.take() {
            Some(start) if self.out.len() == start => Err(FrameWriteError::Unwritten),
            _ => Ok(()),
        }
    }

    fn child(&mut self) -> FrameWriter<'_> {
        self.n += 1;
        self.open = Some(self.out.len());
        FrameWriter {
            out: &mut *self.out,
            depth: self.depth + 1,
        }
    }

    fn end(mut self, expected: Option<usize>) -> Result<(), FrameWriteError> {
        self.settle()?;
        if expected.is_some_and(|e| e != self.n) {
            return Err(FrameWriteError::CountMismatch);
        }
        let n = u32::try_from(self.n).map_err(|_| FrameWriteError::TooLong)?;
        self.out[self.at..self.at + 4].copy_from_slice(&n.to_le_bytes());
        Ok(())
    }
}

impl<'o> Sink for FrameWriter<'o> {
    type Ok = ();
    type Error = FrameWriteError;
    type Seq = FrameSeq<'o>;
    type Map = FrameMap<'o>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<(), FrameWriteError> {
        if self.depth > MAX_DEPTH {
            return Err(FrameWriteError::TooDeep);
        }
        reserve(self.out, leaf::max_len(&v));
        leaf::write(ty, v, Form::Frame, self.out).map_err(|e| match e {
            ScalarError::Invalid => FrameWriteError::Invalid,
            ScalarError::TooLong | ScalarError::Malformed => FrameWriteError::TooLong,
        })
    }

    /// Written as the plain null. A frame is plaintext, never sealed, so
    /// padding hides nothing in it: what a frame writer produces goes to a
    /// host (the frame [`decrypt_to_frame`](crate::decrypt_to_frame)
    /// returns) or into the clear (a passthrough subtree), where the plain
    /// null is what every reader already knows. A frame a host sends may
    /// still carry a typed null, which [`Frame`] reads, so the host's
    /// absent values are padded when sealed.
    fn typed_null(self, _: FixedType) -> Result<(), FrameWriteError> {
        self.scalar(None, Physical::Null)
    }

    fn seq(self, len: Option<usize>) -> Result<FrameSeq<'o>, FrameWriteError> {
        Ok(FrameSeq {
            count: self.container(ARRAY)?,
            expected: len,
        })
    }

    fn map(self, len: Option<usize>) -> Result<FrameMap<'o>, FrameWriteError> {
        Ok(FrameMap {
            count: self.container(OBJECT)?,
            expected: len,
            keys: Vec::new(),
        })
    }

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<(), FrameWriteError> {
        let depth = self.depth;
        let out = self.node(PASSTHROUGH)?;
        value.visit(FrameWriter {
            out,
            depth: depth + 1,
        })
    }
}

pub struct FrameSeq<'o> {
    count: Count<'o>,
    expected: Option<usize>,
}

impl SeqSink for FrameSeq<'_> {
    type Ok = ();
    type Error = FrameWriteError;
    type Element<'s>
        = FrameWriter<'s>
    where
        Self: 's;

    fn element(&mut self) -> Result<FrameWriter<'_>, FrameWriteError> {
        self.count.settle()?;
        Ok(self.count.child())
    }

    fn end(self) -> Result<(), FrameWriteError> {
        self.count.end(self.expected)
    }
}

pub struct FrameMap<'o> {
    count: Count<'o>,
    expected: Option<usize>,
    /// Where each key's bytes lie in the frame. A repeat is found among
    /// them at the end, so no key is copied out of the frame, where it
    /// would be freed unwiped.
    keys: Vec<Range<usize>>,
}

impl MapSink for FrameMap<'_> {
    type Ok = ();
    type Error = FrameWriteError;
    type Entry<'s>
        = FrameWriter<'s>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<FrameWriter<'_>, FrameWriteError> {
        self.count.settle()?;
        reserve(self.count.out, key.len().saturating_add(4));
        write_len(self.count.out, key.len())?;
        let start = self.count.out.len();
        self.count.out.extend_from_slice(key.as_bytes());
        self.keys.push(start..self.count.out.len());
        Ok(self.count.child())
    }

    fn end(mut self) -> Result<(), FrameWriteError> {
        // The frame only grows while the map is written, so every range
        // still holds its key.
        let out: &[u8] = self.count.out;
        self.keys
            .sort_unstable_by(|a, b| out[a.clone()].cmp(&out[b.clone()]));
        if self
            .keys
            .windows(2)
            .any(|pair| out[pair[0].clone()] == out[pair[1].clone()])
        {
            return Err(FrameWriteError::DuplicateKey);
        }
        self.count.end(self.expected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plaintext::record::{record, Event, Owned};
    use crate::plaintext::{visit_seq, Int};
    use std::collections::BTreeMap;

    fn frame_of<P: Encrypt>(p: P) -> Vec<u8> {
        to_frame(p).expect("frames").risky_ref().clone()
    }

    #[test]
    fn a_frame_round_trips_through_write_and_walk() {
        let mut value = BTreeMap::new();
        value.insert("name", vec![Some("Ada"), None]);
        value.insert("empty", vec![]);
        let bytes = frame_of(value.clone());
        let frame = Frame::parse(&bytes).expect("parses");
        assert_eq!(record(frame).expect("walks"), record(value).expect("walks"));
        // A borrowed frame walks as the frame itself.
        let borrowed: &Frame<'_> = &frame;
        assert_eq!(
            record(borrowed).expect("walks"),
            record(frame).expect("walks")
        );
        // Writing the walk of a frame gives the same frame.
        assert_eq!(frame_of(frame), bytes);
    }

    #[test]
    fn container_framing_is_tag_count_children() {
        assert_eq!(
            frame_of(vec![1u16, 2]),
            [ARRAY, 2, 0, 0, 0, 0x0F, 1, 0, 0x0F, 2, 0]
        );
        let mut map = BTreeMap::new();
        map.insert("k", true);
        assert_eq!(frame_of(map), [OBJECT, 1, 0, 0, 0, 1, 0, 0, 0, b'k', 0x03]);
    }

    /// A source that asks for a child sink and drops it unused.
    #[derive(Clone)]
    struct DropsAChild {
        map: bool,
    }

    impl Encrypt for DropsAChild {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            if self.map {
                let mut map = sink.map(None)?;
                let _ = map.entry("a")?;
                1u16.visit(map.entry("b")?)?;
                map.end()
            } else {
                let mut seq = sink.seq(None)?;
                1u16.visit(seq.element()?)?;
                let _ = seq.element()?;
                seq.end()
            }
        }
    }

    #[test]
    fn a_dropped_child_sink_is_refused_not_framed() {
        for map in [false, true] {
            assert!(matches!(
                to_frame(DropsAChild { map }),
                Err(FrameWriteError::Unwritten)
            ));
        }
        // And so a passthrough that drops one cannot be sealed into a
        // document that would never decrypt.
        struct Doc;
        impl Encrypt for Doc {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut seq = sink.seq(Some(2))?;
                1u16.visit(seq.element()?)?;
                seq.element()?.passthrough(DropsAChild { map: false })?;
                seq.end()
            }
        }
        assert!(matches!(
            crate::plan::<_, (), _>(Doc, "ctx"),
            Err(crate::EncryptError::Shape(_))
        ));
    }

    #[test]
    fn reserve_moves_to_a_bigger_buffer_and_keeps_the_bytes() {
        let mut out = vec![1u8, 2, 3];
        out.shrink_to_fit();
        reserve(&mut out, 10);
        assert_eq!(out, [1, 2, 3]);
        assert!(out.capacity() >= 13);
        let before = out.as_ptr();
        reserve(&mut out, 10);
        assert_eq!(out.as_ptr(), before, "enough room already: no move");

        // A full buffer grows, even by one byte.
        let mut full = vec![7u8; 100];
        full.shrink_to_fit();
        reserve(&mut full, 1);
        assert!(full.capacity() >= 101);
        assert_eq!(full, [7u8; 100]);
    }

    #[test]
    fn a_parsed_frame_is_its_bytes() {
        let bytes = frame_of(vec![1u8, 2]);
        let frame = Frame::parse(&bytes).expect("parses");
        assert_eq!(frame.as_bytes(), &bytes[..]);
        assert_eq!(FrameError.to_string(), "malformed frame");
    }

    #[test]
    fn passthrough_is_framed_in_the_clear() {
        struct Pass;
        impl Encrypt for Pass {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                sink.passthrough("public")
            }
        }
        let bytes = frame_of(Pass);
        assert_eq!(
            bytes,
            [
                PASSTHROUGH,
                0x0A,
                6,
                0,
                0,
                0,
                b'p',
                b'u',
                b'b',
                b'l',
                b'i',
                b'c'
            ]
        );
        assert_eq!(
            record(Frame::parse(&bytes).expect("parses")).expect("walks"),
            [
                Event::Passthrough,
                Event::Scalar(None, Owned::Text("public".into()))
            ]
        );
        let owned = PassthroughFrame(bytes.clone());
        assert_eq!(frame_of(owned.clone()), bytes);
        assert_eq!(frame_of(&owned), bytes);
    }

    #[test]
    fn unknown_lengths_are_patched_in() {
        struct Unsized(Vec<u32>);
        impl Encrypt for Unsized {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                visit_seq(sink, None, self.0)
            }
        }
        assert_eq!(frame_of(Unsized(vec![1, 2, 3])), frame_of(vec![1u32, 2, 3]));
    }

    #[test]
    fn a_wrong_length_hint_is_refused() {
        struct Lies;
        impl Encrypt for Lies {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                visit_seq(sink, Some(5), vec![1u32])
            }
        }
        assert!(matches!(
            to_frame(Lies),
            Err(FrameWriteError::CountMismatch)
        ));
    }

    #[test]
    fn duplicate_keys_are_refused_both_ways() {
        struct Dup;
        impl Encrypt for Dup {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut map = sink.map(None)?;
                1u32.visit(map.entry("k")?)?;
                2u32.visit(map.entry("k")?)?;
                map.end()
            }
        }
        assert!(matches!(to_frame(Dup), Err(FrameWriteError::DuplicateKey)));
        let bytes = [
            OBJECT, 2, 0, 0, 0, 1, 0, 0, 0, b'k', 0x00, 1, 0, 0, 0, b'k', 0x00,
        ];
        assert_eq!(Frame::parse(&bytes), Err(FrameError));
    }

    /// A repeat is found among the keys a map wrote, wherever it falls, and
    /// only in the same map: a key that starts another, or the same key in
    /// a nested map, is not one.
    #[test]
    fn a_repeated_key_is_found_apart_and_only_in_its_own_map() {
        struct Keys(&'static [&'static str]);
        impl Encrypt for Keys {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                let mut map = sink.map(None)?;
                for key in self.0 {
                    let mut inner = map.entry(key)?.map(None)?;
                    1u32.visit(inner.entry(key)?)?;
                    inner.end()?;
                }
                map.end()
            }
        }
        assert!(matches!(
            to_frame(Keys(&["b", "a", "c", "b"])),
            Err(FrameWriteError::DuplicateKey)
        ));
        assert!(to_frame(Keys(&["k", "kk", "", "a"])).is_ok());
        // An empty key is an empty range in the frame, and two are still
        // a repeat.
        assert!(matches!(
            to_frame(Keys(&["", "a", ""])),
            Err(FrameWriteError::DuplicateKey)
        ));
    }

    #[test]
    fn malformed_frames_are_refused() {
        assert_eq!(Frame::parse(&[]), Err(FrameError));
        assert_eq!(Frame::parse(&[0x00, 0x00]), Err(FrameError));
        assert_eq!(Frame::parse(&[ARRAY, 1, 0, 0, 0]), Err(FrameError));
        assert_eq!(
            Frame::parse(&[OBJECT, 1, 0, 0, 0, 1, 0, 0, 0, 0xFF, 0x00]),
            Err(FrameError)
        );
        assert_eq!(Frame::parse(&[PASSTHROUGH]), Err(FrameError));
        assert_eq!(
            Frame::parse(&[0x0A, 2, 0, 0, 0, b'a']).err(),
            Some(FrameError)
        );
    }

    #[derive(Clone, Copy)]
    enum Kind {
        Seq,
        Map,
        Pass,
    }

    /// `n` levels of one kind of container around an empty sequence, so
    /// the innermost value is itself a container at depth `n`.
    #[derive(Clone, Copy)]
    struct Nest(Kind, usize);

    impl Encrypt for Nest {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            let Nest(kind, n) = self;
            if n == 0 {
                return sink.seq(Some(0))?.end();
            }
            let inner = Nest(kind, n - 1);
            match kind {
                Kind::Seq => {
                    let mut seq = sink.seq(Some(1))?;
                    inner.visit(seq.element()?)?;
                    seq.end()
                }
                Kind::Map => {
                    let mut map = sink.map(Some(1))?;
                    inner.visit(map.entry("k")?)?;
                    map.end()
                }
                Kind::Pass => sink.passthrough(inner),
            }
        }
    }

    #[test]
    fn depth_is_bounded_both_ways() {
        for kind in [Kind::Seq, Kind::Map, Kind::Pass] {
            // A container at exactly `MAX_DEPTH` is written and parsed.
            let bytes = frame_of(Nest(kind, MAX_DEPTH));
            assert!(Frame::parse(&bytes).is_ok());

            // One more level is refused by both.
            assert!(matches!(
                to_frame(Nest(kind, MAX_DEPTH + 1)),
                Err(FrameWriteError::TooDeep)
            ));
            let mut deeper = match kind {
                Kind::Seq => vec![ARRAY, 1, 0, 0, 0],
                Kind::Map => vec![OBJECT, 1, 0, 0, 0, 1, 0, 0, 0, b'k'],
                Kind::Pass => vec![PASSTHROUGH],
            };
            deeper.extend_from_slice(&bytes);
            assert_eq!(Frame::parse(&deeper), Err(FrameError));
        }

        struct Deep(usize);
        impl Encrypt for Deep {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                if self.0 == 0 {
                    return sink.scalar(None, Physical::Int(Int::U8(0)));
                }
                let mut seq = sink.seq(Some(1))?;
                Deep(self.0 - 1).visit(seq.element()?)?;
                seq.end()
            }
        }
        assert!(to_frame(Deep(MAX_DEPTH)).is_ok());
        assert!(matches!(
            to_frame(Deep(MAX_DEPTH + 1)),
            Err(FrameWriteError::TooDeep)
        ));
    }

    #[test]
    fn parse_nested_takes_one_node_and_returns_the_rest() {
        let mut bytes = frame_of(vec![1u16, 2]);
        let trailing = frame_of("after");
        bytes.extend_from_slice(&trailing);

        // `parse` wants exactly one node; `parse_nested` hands back the rest.
        assert_eq!(Frame::parse(&bytes), Err(FrameError));
        let (frame, rest) = Frame::parse_nested(&bytes, 0).expect("parses the prefix");
        assert_eq!(frame.as_bytes(), &frame_of(vec![1u16, 2])[..]);
        assert_eq!(rest, &trailing[..]);

        // The rest is itself one node, and after it nothing is left.
        let (frame, rest) = Frame::parse_nested(rest, 0).expect("parses the rest");
        assert_eq!(frame.as_bytes(), &trailing[..]);
        assert!(rest.is_empty());

        // An empty buffer holds no node.
        assert_eq!(Frame::parse_nested(&[], 0), Err(FrameError));
    }

    #[test]
    fn parse_nested_counts_the_carrier_in_the_depth_bound() {
        // A node at exactly `MAX_DEPTH` parses at depth 0, but not when its
        // carrier already nests it one level.
        let bytes = frame_of(Nest(Kind::Seq, MAX_DEPTH));
        assert!(Frame::parse_nested(&bytes, 0).is_ok());
        assert_eq!(Frame::parse_nested(&bytes, 1), Err(FrameError));
        // A scalar sits at the bound too.
        let scalar = frame_of(1u16);
        assert!(Frame::parse_nested(&scalar, MAX_DEPTH).is_ok());
        assert_eq!(Frame::parse_nested(&scalar, MAX_DEPTH + 1), Err(FrameError));
    }

    #[test]
    fn a_writer_at_depth_counts_from_the_top() {
        let mut out = Vec::new();
        let writer = FrameWriter::at_depth(&mut out, 7);
        assert_eq!(writer.depth(), 7);
        let mut seq = writer.seq(Some(1)).expect("seq");
        assert_eq!(seq.element().expect("element").depth(), 8);

        // A scalar fits at the bound, and not below it.
        let mut out = Vec::new();
        assert!(FrameWriter::at_depth(&mut out, MAX_DEPTH)
            .scalar(None, Physical::Bool(true))
            .is_ok());
        assert!(matches!(
            FrameWriter::at_depth(&mut out, MAX_DEPTH + 1).scalar(None, Physical::Bool(true)),
            Err(FrameWriteError::TooDeep)
        ));
    }

    #[test]
    fn a_frame_debugs_redacted_and_compares_by_value() {
        let bytes = frame_of("secret");
        let frame = Frame::parse(&bytes).expect("parses");
        let shown = format!("{frame:?}");
        assert!(
            shown.contains("***") && !shown.contains("secret"),
            "{shown}"
        );
        assert!(!shown.contains(&bytes.len().to_string()), "{shown}");
        let pass = format!("{:?}", PassthroughFrame(bytes.clone()));
        assert!(pass.contains("***") && !pass.contains("secret"), "{pass}");

        let same = bytes.clone();
        let other = frame_of("public");
        assert_eq!(frame, Frame::parse(&same).expect("parses"));
        assert_ne!(frame, Frame::parse(&other).expect("parses"));
        assert_eq!(PassthroughFrame(bytes.clone()), PassthroughFrame(same));
        assert_ne!(PassthroughFrame(bytes), PassthroughFrame(other));
    }

    #[test]
    fn frame_write_errors_say_what_failed() {
        let cases = [
            (
                FrameWriteError::TooDeep,
                "value nests deeper than 128 levels",
            ),
            (
                FrameWriteError::TooLong,
                "text, bytes, a key or a count is too long for a u32",
            ),
            (
                FrameWriteError::Invalid,
                "value is not valid for its logical type",
            ),
            (
                FrameWriteError::CountMismatch,
                "container length does not match its children",
            ),
            (FrameWriteError::DuplicateKey, "duplicate key"),
            (
                FrameWriteError::Unwritten,
                "a child sink was dropped without a value",
            ),
            (FrameWriteError::Unfinished, "a container was never ended"),
            (
                FrameWriteError::Source(SourceError::msg("getter threw")),
                "source failed: getter threw",
            ),
        ];
        for (error, message) in cases {
            assert_eq!(error.to_string(), message);
        }
        fn is_error<E: core::error::Error>(_: &E) {}
        is_error(&FrameWriteError::TooDeep);
        use core::error::Error as _;
        let sourced = FrameWriteError::Source(SourceError::msg("getter threw"));
        assert_eq!(
            sourced.source().map(|cause| cause.to_string()),
            Some("getter threw".into())
        );
        assert!(FrameWriteError::TooDeep.source().is_none());
    }
}
