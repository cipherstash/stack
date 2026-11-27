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
//! [`OwnedFrame`] is a [`Buffer`] that holds exactly one frame: what a
//! ciphertext opens into, and a value kept past the call that made it.
//! [`PassthroughFrame`] is the owned frame a ciphertext carries for a
//! passthrough subtree, which is in the clear.

use std::borrow::BorrowMut;
use std::marker::PhantomData;
use std::ops::Range;

use vitaminc_protected::{Buffer, Controlled, OpaqueDebug, TimingSafeEq};

use __private::SeenKeys;

mod owned;
pub use owned::{OwnedFrame, OwnedFrameContainer, OwnedFrameSink};

use crate::leaf::{self, Form, Item, ScalarError};
use crate::plaintext::{
    Encrypt, EncryptRef, Error, FixedType, Logical, MapSink, Physical, SeqSink, Sink, SourceError,
    ValueKind,
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
    ///
    /// # Errors
    ///
    /// Returns [`FrameError`] for malformed scalar/container encodings, invalid
    /// UTF-8, duplicate map keys, trailing bytes, or nesting beyond [`MAX_DEPTH`].
    /// Validation is structural; it provides no authentication.
    ///
    /// # Examples
    ///
    /// ```
    /// use vitaminc_aead::{to_frame, Frame};
    /// use vitaminc_protected::Controlled;
    /// let encoded = to_frame(42u32)?;
    /// let frame = Frame::parse(encoded.risky_ref())?;
    /// assert_eq!(frame.as_bytes(), encoded.risky_ref().as_slice());
    /// assert!(Frame::parse(&[]).is_err());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
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
    ///
    /// # Errors
    ///
    /// Refuses the same malformed nodes as [`parse`](Self::parse), but allows
    /// trailing bytes and returns them separately. Refuses `depth > MAX_DEPTH`.
    pub fn parse_nested(bytes: &'a [u8], depth: usize) -> Result<(Self, &'a [u8]), FrameError> {
        let mut cursor = Cursor { buf: bytes, pos: 0 };
        skip(&mut cursor, depth)?;
        let (frame, rest) = bytes.split_at(cursor.pos);
        Ok((Self { bytes: frame }, rest))
    }

    /// Borrow the exact validated bytes, without copying or authenticating them.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The value's [`ValueKind`], or `None` for a null, plain or typed,
    /// `undefined`, a passthrough, or a logical type this build does not
    /// know, which have no kind.
    ///
    /// ```
    /// use vitaminc_aead::{Frame, OwnedFrame, ValueKind};
    ///
    /// let owned = OwnedFrame::of("alice")?;
    /// assert_eq!(owned.frame().kind(), Some(ValueKind::String));
    /// assert_eq!(OwnedFrame::null().frame().kind(), None);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn kind(&self) -> Option<ValueKind> {
        match self.tag() {
            ARRAY => Some(ValueKind::Array),
            OBJECT => Some(ValueKind::Object),
            PASSTHROUGH => None,
            _ => match self.scalar() {
                Item::Scalar(ty, value) => ValueKind::of(ty, &value),
                Item::TypedNull(_) => None,
            },
        }
    }

    /// Whether the value is a null, plain or typed. `undefined` is not.
    pub fn is_null(&self) -> bool {
        match self.tag() {
            ARRAY | OBJECT | PASSTHROUGH => false,
            _ => matches!(
                self.scalar(),
                Item::Scalar(None, Physical::Null) | Item::TypedNull(_)
            ),
        }
    }

    /// Whether the value holds a passthrough at any depth.
    pub fn has_passthrough(&self) -> bool {
        holds_passthrough(&mut self.cursor())
    }

    /// The elements of a sequence, each the frame it is inside this one,
    /// in order, with nothing copied; `None` for any other value.
    ///
    /// ```
    /// use vitaminc_aead::{Frame, OwnedFrame};
    ///
    /// let owned = OwnedFrame::of(vec!["a", "b"])?;
    /// let elements = owned.frame().elements().expect("a sequence");
    /// assert_eq!(elements.len(), 2);
    /// assert!(OwnedFrame::of("a")?.frame().elements().is_none());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn elements(&self) -> Option<Elements<'a>> {
        let mut cursor = self.cursor();
        if cursor.byte().expect(VALIDATED) != ARRAY {
            return None;
        }
        let left = cursor.count().expect(VALIDATED);
        Some(Elements { cursor, left })
    }

    fn cursor(&self) -> Cursor<'a> {
        Cursor {
            buf: self.bytes,
            pos: 0,
        }
    }

    /// The first byte: a container's tag, or a scalar's first.
    fn tag(&self) -> u8 {
        self.cursor().peek().expect(VALIDATED)
    }

    /// The value, read as a scalar: for a frame whose tag is no container's.
    fn scalar(&self) -> Item<'a> {
        self.cursor().scalar().expect(VALIDATED)
    }
}

/// The elements of a sequence frame, each a [`Frame`] borrowed from it:
/// what [`Frame::elements`] returns. `Debug` shows nothing of them.
#[derive(Clone, OpaqueDebug)]
pub struct Elements<'a> {
    cursor: Cursor<'a>,
    left: usize,
}

impl<'a> Iterator for Elements<'a> {
    type Item = Frame<'a>;

    fn next(&mut self) -> Option<Frame<'a>> {
        self.left = self.left.checked_sub(1)?;
        Some(self.cursor.node(1).expect(VALIDATED))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.left, Some(self.left))
    }
}

impl ExactSizeIterator for Elements<'_> {}

/// Whether the node at the cursor, which `Frame::parse` accepted, holds a
/// passthrough. Leaves the cursor after the node.
fn holds_passthrough(cursor: &mut Cursor<'_>) -> bool {
    match cursor.peek().expect(VALIDATED) {
        ARRAY => {
            cursor.byte().expect(VALIDATED);
            let count = cursor.count().expect(VALIDATED);
            let mut found = false;
            for _ in 0..count {
                found |= holds_passthrough(cursor);
            }
            found
        }
        OBJECT => {
            cursor.byte().expect(VALIDATED);
            let count = cursor.count().expect(VALIDATED);
            let mut found = false;
            for _ in 0..count {
                cursor.key().expect(VALIDATED);
                found |= holds_passthrough(cursor);
            }
            found
        }
        PASSTHROUGH => {
            cursor.node(0).expect(VALIDATED);
            true
        }
        _ => {
            cursor.scalar().expect(VALIDATED);
            false
        }
    }
}

#[derive(Clone)]
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

/// What `recipher-frame` shares with this crate by path. Not an API:
/// anything here may change in any release.
#[doc(hidden)]
pub mod __private {
    use std::collections::HashSet;

    /// How many keys an object may have before `SeenKeys` hashes them.
    const FEW_KEYS: usize = 16;

    /// The keys an object has given so far, to refuse a repeat.
    ///
    /// The keys are compared one by one while there are few: an object
    /// rarely has more fields than a hash set's allocation and hashing would
    /// pay for. Past sixteen they are hashed, so an object a host sends
    /// with thousands of keys is still checked in linear time. The keys are
    /// borrowed from the frame, so nothing is copied.
    ///
    /// Not an API: it is reachable only so `recipher-frame`'s storage
    /// reader can share this one copy, and it may change in any release.
    #[derive(Default)]
    pub struct SeenKeys<'a> {
        few: [&'a str; FEW_KEYS],
        len: usize,
        many: Option<HashSet<&'a str>>,
    }

    impl<'a> SeenKeys<'a> {
        /// Record `key`; whether it was new.
        pub fn insert(&mut self, key: &'a str) -> bool {
            if let Some(many) = &mut self.many {
                return many.insert(key);
            }
            if self.few[..self.len].contains(&key) {
                return false;
            }
            if self.len < FEW_KEYS {
                self.few[self.len] = key;
                self.len += 1;
            } else {
                let mut many: HashSet<&'a str> = self.few.iter().copied().collect();
                many.insert(key);
                self.many = Some(many);
            }
            true
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn seen_keys_find_a_repeat_before_and_after_they_spill_to_a_set() {
            let names: Vec<String> = (0..40).map(|i| format!("k{i}")).collect();
            let mut seen = SeenKeys::default();
            for (i, name) in names.iter().enumerate() {
                assert!(seen.insert(name), "key {i} is new");
            }
            assert_eq!(seen.len, FEW_KEYS, "the first keys stay inline");
            assert!(seen.many.is_some(), "the rest spilled to a set");
            assert!(!seen.insert(&names[0]), "an inline key repeats");
            assert!(!seen.insert(&names[39]), "a spilled key repeats");
            assert!(seen.insert("new"), "a fresh key is still new");

            let mut few = SeenKeys::default();
            assert!(few.insert("a"));
            assert!(few.insert("b"));
            assert!(!few.insert("a"), "a repeat is found without a set");
            assert!(few.many.is_none());
        }
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
            let mut seen = SeenKeys::default();
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
            sink.passthrough(&c.node(0).expect(VALIDATED))
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

/// Write any source as a frame. The result is a [`Buffer`], since a frame
/// of plaintext is plaintext: it grows without leaving copies behind, and
/// is wiped when it is dropped.
///
/// The result is checked with [`Frame::parse`] before it is returned, so a
/// source that opens a container and never ends it is refused here, not by
/// every later reader of the frame.
pub fn to_frame<P: Encrypt>(p: P) -> Result<Buffer, FrameWriteError> {
    to_frame_at(p, 0)
}

/// [`to_frame`] for a subtree whose root sits `depth` levels below the top
/// of a document, so [`MAX_DEPTH`] counts from the top, as the transport
/// decoder counts it.
pub(crate) fn to_frame_at<P: Encrypt>(p: P, depth: usize) -> Result<Buffer, FrameWriteError> {
    let mut out = Buffer::new();
    p.visit(FrameWriter::at_depth(&mut out, depth))?;
    Frame::parse(out.risky_ref()).map_err(|_| FrameWriteError::Unfinished)?;
    Ok(out)
}

/// A sink that writes one value node onto the end of a buffer. Unknown
/// container lengths are patched in at `end`.
///
/// Writes are immediate: errors or dropping a container before `end` can leave
/// an incomplete suffix in the borrowed buffer. The writer neither rolls back
/// nor wipes that suffix. Prefer [`to_frame`] for an owned protected result
/// returned only after successful writing and validation.
///
/// `E` is the error the writer reports, [`FrameWriteError`] unless a sink
/// that writes through it reports its own: the sink of an [`OwnedFrame`],
/// a decrypt target, reports [`DecodeError`](crate::DecodeError). A frame
/// writer's refusal reaches `E` through `From`.
pub struct FrameWriter<'o, E = FrameWriteError> {
    out: &'o mut Buffer,
    depth: usize,
    error: PhantomData<fn() -> E>,
}

impl<'o> FrameWriter<'o> {
    /// Append a root-level node to `out`, preserving any existing prefix.
    /// The caller owns the buffer, which wipes its bytes when dropped,
    /// including after an error.
    pub fn new(out: &'o mut Buffer) -> Self {
        Self::at_depth(out, 0)
    }

    /// A writer for a node that sits `depth` levels below the top of a
    /// document, so [`MAX_DEPTH`] counts from the top: for a subtree
    /// written to a buffer of its own and copied into the document later.
    pub fn at_depth(out: &'o mut Buffer, depth: usize) -> Self {
        Self::reporting(out, depth)
    }
}

impl<'o, E> FrameWriter<'o, E> {
    /// A writer that reports `E`.
    fn reporting(out: &'o mut Buffer, depth: usize) -> Self {
        Self {
            out,
            depth,
            error: PhantomData,
        }
    }

    /// How many levels below the top of its document this writer's node
    /// sits.
    pub fn depth(&self) -> usize {
        self.depth
    }
}

impl<'o, E: Error + From<FrameWriteError>> FrameWriter<'o, E> {
    fn node(self, tag: u8) -> Result<&'o mut Buffer, E> {
        if self.depth > MAX_DEPTH {
            return Err(FrameWriteError::TooDeep.into());
        }
        self.out.push(tag);
        Ok(self.out)
    }
}

fn write_len(out: &mut Buffer, len: usize) -> Result<(), FrameWriteError> {
    let len = u32::try_from(len).map_err(|_| FrameWriteError::TooLong)?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

/// A container being written: its tag and a count, written once the
/// children are known, into a buffer `B` it borrows (`&mut Buffer`) or owns
/// (`Buffer`). Its children write straight into the same buffer, so a
/// container costs no copy whichever it is.
struct Container<B, E> {
    out: B,
    depth: usize,
    /// Where the count goes.
    at: usize,
    n: usize,
    expected: Option<usize>,
    /// Where the last child sink handed out would start writing. Every
    /// node writes at least its tag, so if the buffer has not grown past
    /// it by the next child or the end, that sink was dropped unused.
    open: Option<usize>,
    /// Where each key of a map lies in the buffer. A repeat is found among
    /// them at the end, so no key is copied out of the frame, where it
    /// would be freed unwiped. Empty for a sequence.
    keys: Vec<Range<usize>>,
    error: PhantomData<fn() -> E>,
}

impl<B: BorrowMut<Buffer>, E: Error + From<FrameWriteError>> Container<B, E> {
    /// Write `tag` and room for the count onto `out`, for a container at
    /// `depth` that says it holds `expected` children.
    fn open(mut out: B, tag: u8, depth: usize, expected: Option<usize>) -> Result<Self, E> {
        if depth > MAX_DEPTH {
            return Err(FrameWriteError::TooDeep.into());
        }
        let buffer = out.borrow_mut();
        buffer.reserve(5);
        buffer.push(tag);
        let at = buffer.len();
        buffer.extend_from_slice(&[0; 4]);
        Ok(Self {
            out,
            depth,
            at,
            n: 0,
            expected,
            open: None,
            keys: Vec::new(),
            error: PhantomData,
        })
    }

    fn settle(&mut self) -> Result<(), E> {
        match self.open.take() {
            Some(start) if self.out.borrow().len() == start => {
                Err(FrameWriteError::Unwritten.into())
            }
            _ => Ok(()),
        }
    }

    fn child(&mut self) -> FrameWriter<'_, E> {
        self.n += 1;
        let out = self.out.borrow_mut();
        self.open = Some(out.len());
        FrameWriter::reporting(out, self.depth + 1)
    }

    fn element(&mut self) -> Result<FrameWriter<'_, E>, E> {
        self.settle()?;
        Ok(self.child())
    }

    fn entry(&mut self, key: &str) -> Result<FrameWriter<'_, E>, E> {
        self.settle()?;
        let out = self.out.borrow_mut();
        out.reserve(key.len().saturating_add(4));
        write_len(out, key.len())?;
        let start = out.len();
        out.extend_from_slice(key.as_bytes());
        self.keys.push(start..out.len());
        Ok(self.child())
    }

    /// Check the children and write the count; the buffer, finished.
    fn end(mut self) -> Result<B, E> {
        self.settle()?;
        // The frame only grows while the container is written, so every
        // range still holds its key.
        let out: &[u8] = self.out.borrow().risky_ref();
        self.keys
            .sort_unstable_by(|a, b| out[a.clone()].cmp(&out[b.clone()]));
        if self
            .keys
            .windows(2)
            .any(|pair| out[pair[0].clone()] == out[pair[1].clone()])
        {
            return Err(FrameWriteError::DuplicateKey.into());
        }
        if self.expected.is_some_and(|e| e != self.n) {
            return Err(FrameWriteError::CountMismatch.into());
        }
        let n = u32::try_from(self.n).map_err(|_| FrameWriteError::TooLong)?;
        self.out.borrow_mut().overwrite(self.at, &n.to_le_bytes());
        Ok(self.out)
    }
}

impl<'o, E: Error + From<FrameWriteError>> Sink for FrameWriter<'o, E> {
    type Ok = ();
    type Error = E;
    type Seq = FrameSeq<'o, E>;
    type Map = FrameMap<'o, E>;

    fn scalar(self, ty: Option<Logical>, v: Physical<'_>) -> Result<(), E> {
        if self.depth > MAX_DEPTH {
            return Err(FrameWriteError::TooDeep.into());
        }
        self.out.reserve(leaf::max_len(&v));
        leaf::write(ty, v, Form::Frame, self.out).map_err(|e| {
            match e {
                ScalarError::Invalid => FrameWriteError::Invalid,
                ScalarError::TooLong | ScalarError::Malformed => FrameWriteError::TooLong,
            }
            .into()
        })
    }

    /// Written as the plain null. A frame is plaintext, never sealed, so
    /// padding hides nothing in it: what a frame writer produces goes to a
    /// host (the frame [`decrypt_to_frame`](crate::decrypt_to_frame)
    /// returns) or into the clear (a passthrough subtree), where the plain
    /// null is what every reader already knows. A frame a host sends may
    /// still carry a typed null, which [`Frame`] reads, so the host's
    /// absent values are padded when sealed; [`OwnedFrame::typed_null`]
    /// writes one.
    fn typed_null(self, _: FixedType) -> Result<(), E> {
        self.scalar(None, Physical::Null)
    }

    fn seq(self, len: Option<usize>) -> Result<FrameSeq<'o, E>, E> {
        Container::open(self.out, ARRAY, self.depth, len).map(FrameSeq)
    }

    fn map(self, len: Option<usize>) -> Result<FrameMap<'o, E>, E> {
        Container::open(self.out, OBJECT, self.depth, len).map(FrameMap)
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, value: &P) -> Result<(), E> {
        let depth = self.depth;
        let out = self.node(PASSTHROUGH)?;
        value.visit_ref(FrameWriter::reporting(out, depth + 1))
    }
}

/// In-progress frame sequence. Each child must write one node, and
/// [`SeqSink::end`] checks the supplied length and completes the count header.
/// Dropping it leaves partial bytes in the writer's buffer.
pub struct FrameSeq<'o, E = FrameWriteError>(Container<&'o mut Buffer, E>);

impl<E: Error + From<FrameWriteError>> SeqSink for FrameSeq<'_, E> {
    type Ok = ();
    type Error = E;
    type Element<'s>
        = FrameWriter<'s, E>
    where
        Self: 's;

    fn element(&mut self) -> Result<FrameWriter<'_, E>, E> {
        self.0.element()
    }

    fn end(self) -> Result<(), E> {
        self.0.end().map(drop)
    }
}

/// In-progress frame map. Rejects duplicate keys and unfinished children;
/// [`MapSink::end`] checks the supplied length and completes the count header.
/// Keys are written as cleartext UTF-8. Errors do not roll back earlier bytes.
pub struct FrameMap<'o, E = FrameWriteError>(Container<&'o mut Buffer, E>);

impl<E: Error + From<FrameWriteError>> MapSink for FrameMap<'_, E> {
    type Ok = ();
    type Error = E;
    type Entry<'s>
        = FrameWriter<'s, E>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<FrameWriter<'_, E>, E> {
        self.0.entry(key)
    }

    fn end(self) -> Result<(), E> {
        self.0.end().map(drop)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plaintext::record::{record, Event, Owned};
    use crate::plaintext::{visit_seq, Int};
    use std::collections::BTreeMap;

    fn frame_of<P: Encrypt>(p: P) -> Vec<u8> {
        to_frame(p).expect("frames").risky_ref().to_vec()
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
    /// Passthrough lends its value, so a test source walks by reference too.
    impl Encrypt for &DropsAChild {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            self.clone().visit(sink)
        }
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
                seq.element()?.passthrough(&DropsAChild { map: false })?;
                seq.end()
            }
        }
        assert!(matches!(
            crate::plan::<_, (), _>(Doc, "ctx"),
            Err(crate::EncryptError::Shape(_))
        ));
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
                sink.passthrough(&"public")
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
    /// Passthrough lends its value, so a test source walks by reference too.
    impl Encrypt for &Nest {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            (*self).visit(sink)
        }
    }

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
                Kind::Pass => sink.passthrough(&inner),
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
        let mut out = Buffer::new();
        let writer = FrameWriter::at_depth(&mut out, 7);
        assert_eq!(writer.depth(), 7);
        let mut seq = writer.seq(Some(1)).expect("seq");
        assert_eq!(seq.element().expect("element").depth(), 8);

        // A scalar fits at the bound, and not below it.
        let mut out = Buffer::new();
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

    fn typed_null(ty: FixedType) -> Vec<u8> {
        let mut out = Vec::new();
        leaf::write_typed_null(ty, &mut out);
        out
    }

    /// A passthrough of a value: a frame with a passthrough at its top.
    struct Pass<T>(T);
    impl<T: EncryptRef> Encrypt for Pass<T> {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            sink.passthrough(&self.0)
        }
    }

    /// A frame names its kind: a container's, a scalar's, or none for a
    /// null, `undefined`, a passthrough or an unknown logical type.
    #[test]
    fn a_frame_names_its_kind() {
        use crate::plaintext::{Raw, Width};
        let date = FixedType::new(Some(Logical::Date), Width::I32).expect("fixed");
        let unknown = Logical::from_wire(200, 0).expect("an unknown logical type");
        let mut map = BTreeMap::new();
        map.insert("k", 1u16);
        let cases = [
            (frame_of(None::<&str>), None),
            (
                frame_of(Raw(Some(Logical::Undefined), Physical::Null)),
                None,
            ),
            (frame_of(true), Some(ValueKind::Bool)),
            (frame_of(1i32), Some(ValueKind::Int32)),
            (frame_of(1u64), Some(ValueKind::UInt64)),
            (frame_of(1.0f64), Some(ValueKind::Float64)),
            (frame_of("a"), Some(ValueKind::String)),
            (frame_of(vec!["a"]), Some(ValueKind::Array)),
            (frame_of(map), Some(ValueKind::Object)),
            (frame_of(Pass("p")), None),
            (
                frame_of(Raw(Some(unknown), Physical::Int(Int::I32(1)))),
                None,
            ),
            (typed_null(date), None),
        ];
        for (bytes, kind) in cases {
            let frame = Frame::parse(&bytes).expect("parses");
            assert_eq!(frame.kind(), kind, "{bytes:?}");
        }
    }

    /// Only a null, plain or typed, is a null; `undefined`, a scalar, a
    /// container and a passthrough of a null are not.
    #[test]
    fn only_a_null_is_a_null() {
        use crate::plaintext::{Raw, Width};
        let parsed = |bytes: &[u8]| Frame::parse(bytes).expect("parses").is_null();
        assert!(parsed(&frame_of(None::<&str>)));
        assert!(parsed(&typed_null(
            FixedType::new(None, Width::I64).expect("fixed")
        )));
        for bytes in [
            frame_of(Raw(Some(Logical::Undefined), Physical::Null)),
            frame_of(false),
            frame_of(0u16),
            frame_of(""),
            frame_of(vec![None::<&str>]),
            frame_of(BTreeMap::<&str, u16>::new()),
            frame_of(Pass(None::<&str>)),
        ] {
            assert!(!parsed(&bytes), "{bytes:?}");
        }
    }

    /// A sequence's elements are borrowed from it, in order and as they
    /// are, a typed null included; any other value has none.
    #[test]
    fn elements_are_the_childrens_frames_in_place() {
        use crate::plaintext::Width;
        let date = FixedType::new(Some(Logical::Date), Width::I32).expect("fixed");
        let mut seq = vec![ARRAY, 3, 0, 0, 0];
        seq.extend(frame_of("a"));
        seq.extend(typed_null(date));
        seq.extend(frame_of(vec![1i32]));
        let frame = Frame::parse(&seq).expect("parses");
        let elements = frame.elements().expect("a sequence");
        assert_eq!(elements.len(), 3);
        assert_eq!(elements.size_hint(), (3, Some(3)));
        let items: Vec<Frame<'_>> = elements.clone().collect();
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].as_bytes(), &frame_of("a")[..]);
        assert_eq!(items[1].as_bytes(), &typed_null(date)[..]);
        assert!(items[1].is_null());
        assert_eq!(items[2].as_bytes(), &frame_of(vec![1i32])[..]);
        // Borrowed from the sequence, not copied.
        assert_eq!(items[0].as_bytes().as_ptr(), seq[5..].as_ptr());

        let mut rest = frame.elements().expect("a sequence");
        assert!(rest.next().is_some());
        assert_eq!(rest.len(), 2);
        assert!(rest.next().is_some());
        assert!(rest.next().is_some());
        assert_eq!(rest.len(), 0);
        assert!(rest.next().is_none());
        assert!(rest.next().is_none(), "stays done");

        let empty = frame_of(Vec::<u16>::new());
        let none = Frame::parse(&empty).expect("parses").elements();
        assert_eq!(none.map(|e| e.len()), Some(0));
        let mut map = BTreeMap::new();
        map.insert("k", "a");
        for other in [
            frame_of("a"),
            frame_of(map),
            frame_of(Pass(Vec::<u16>::new())),
        ] {
            assert!(Frame::parse(&other).expect("parses").elements().is_none());
        }
    }

    #[test]
    fn elements_debug_shows_nothing_of_them() {
        let bytes = frame_of(vec!["secret"]);
        let frame = Frame::parse(&bytes).expect("parses");
        let shown = format!("{:?}", frame.elements().expect("a sequence"));
        assert!(
            shown.contains("***") && !shown.contains("secret"),
            "{shown}"
        );
    }

    /// A passthrough is found at any depth, and nowhere else.
    #[test]
    fn a_passthrough_is_found_at_any_depth() {
        struct Inside(bool);
        impl Encrypt for Inside {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                if self.0 {
                    let mut map = sink.map(Some(2))?;
                    "a".visit(map.entry("a")?)?;
                    Pass("p").visit(map.entry("p")?)?;
                    map.end()
                } else {
                    let mut seq = sink.seq(Some(2))?;
                    None::<&str>.visit(seq.element()?)?;
                    Pass(None::<&str>).visit(seq.element()?)?;
                    seq.end()
                }
            }
        }
        let has = |bytes: Vec<u8>| Frame::parse(&bytes).expect("parses").has_passthrough();
        assert!(has(frame_of(Pass("p"))));
        assert!(has(frame_of(Inside(true))));
        assert!(has(frame_of(Inside(false))));
        let mut map = BTreeMap::new();
        map.insert("k", vec!["a"]);
        assert!(!has(frame_of("a")));
        assert!(!has(frame_of(map)));
        assert!(!has(frame_of(vec![vec![None::<&str>], vec![]])));
    }

    /// A passthrough below the bound is refused before its tag is written;
    /// at the bound, its tag fits and the value inside it does not.
    #[test]
    fn a_passthrough_past_the_bound_writes_nothing() {
        let mut out = Buffer::new();
        assert!(matches!(
            FrameWriter::at_depth(&mut out, MAX_DEPTH + 1).passthrough(&1u16),
            Err(FrameWriteError::TooDeep)
        ));
        assert!(out.is_empty());
        assert!(matches!(
            FrameWriter::at_depth(&mut out, MAX_DEPTH).passthrough(&1u16),
            Err(FrameWriteError::TooDeep)
        ));
        assert_eq!(out.risky_ref().as_slice(), [PASSTHROUGH]);
        let mut out = Buffer::new();
        assert!(FrameWriter::at_depth(&mut out, MAX_DEPTH - 1)
            .passthrough(&1u16)
            .is_ok());
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
