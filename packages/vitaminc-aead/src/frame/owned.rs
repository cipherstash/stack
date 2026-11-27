//! [`OwnedFrame`]: one value in a frame of its own, owned, wiped when it
//! drops, and compared in constant time.

use std::collections::BTreeSet;

use vitaminc_protected::{
    AsProtectedRef, Buffer, Controlled, Equatable, OpaqueDebug, Protected, ProtectedRef,
};
use zeroize::Zeroize;

use super::{
    Cursor, Frame, FrameError, FrameMap, FrameSeq, FrameWriteError, FrameWriter, ARRAY, OBJECT,
    PASSTHROUGH, VALIDATED,
};
use crate::leaf::{self, Form, Item};
use crate::plaintext::{
    Encrypt, EncryptRef, Error as _, FixedType, Logical, MapSink, Physical, SeqSink, Sink,
    SourceError, ValueKind,
};
use crate::typed::{DecodeError, Decrypt};

/// One value as a transport frame, in a buffer of its own: a plaintext a
/// host hands over, a value to seal, or a value a ciphertext opens into.
///
/// The bytes are exactly one well-formed frame ([`Frame::parse`] accepts
/// them), held in a [`Protected`] buffer that is wiped when it drops.
/// `zeroize` wipes them early and leaves no bytes: walking a zeroized frame
/// fails with a source error.
///
/// - Make one from any source with [`of`](Self::of), from a host's bytes
///   with [`from_bytes`](Self::from_bytes), or from a [`Buffer`] a
///   [`FrameWriter`] filled with [`from_buffer`](Self::from_buffer).
/// - It is a source ([`Encrypt`]): walking it into a sink seals, indexes or
///   writes the value, reading the bytes in place.
/// - It is a decrypt target ([`Decrypt`]): a ciphertext opens straight
///   into a frame, with no value tree in between.
/// - [`into_inner`](Self::into_inner) hands the bytes back still protected.
///
/// `Debug` names the type and masks the bytes, which are plaintext. Two
/// frames compare with `==` in constant time; see the [`PartialEq`
/// impl](#impl-PartialEq-for-OwnedFrame) for what equal means.
///
/// ```
/// use vitaminc_aead::frame::OwnedFrame;
/// use vitaminc_aead::ValueKind;
/// use vitaminc_protected::AsProtectedRef;
///
/// let frame = OwnedFrame::of("alice")?;
/// assert_eq!(frame.kind(), Some(ValueKind::String));
///
/// // The same value, as a host would hand it over.
/// let from_host = OwnedFrame::from_bytes(frame.as_protected_ref())?;
/// assert_eq!(from_host, frame);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(OpaqueDebug)]
pub struct OwnedFrame(Equatable<Protected<Vec<u8>>>);

impl OwnedFrame {
    /// The frame of any source.
    ///
    /// A typed null is written as a plain null, as [`FrameWriter`] writes
    /// one.
    ///
    /// # Errors
    ///
    /// - [`DecodeError::Expected`] for a scalar its logical type does not
    ///   admit ([`Logical::admits`]): a date, decimal or timestamp out of
    ///   range, or a UUID that is not sixteen bytes.
    /// - [`DecodeError::DuplicateKey`] for a map inside a passthrough that
    ///   repeats a key. A passthrough is in the clear, so the error names
    ///   the key.
    /// - [`DecodeError::Source`] for a source that fails, for a value deeper
    ///   or longer than a frame allows, and for a map outside a passthrough
    ///   that repeats a key. The last wraps [`FrameWriteError::DuplicateKey`],
    ///   which does not name the key: the key is plaintext, and naming it
    ///   would copy it out of the frame into memory freed without a wipe.
    pub fn of<P: Encrypt>(value: P) -> Result<Self, DecodeError> {
        write(|writer| value.visit(ValueWriter::new(writer)))
    }

    /// Read one value from frame bytes a host handed over.
    ///
    /// The value is written into a buffer of its own, so a typed null in
    /// the bytes reads as a plain null, as [`of`](Self::of) writes one.
    ///
    /// # Errors
    ///
    /// [`FrameError`] when the bytes are not exactly one well-formed frame
    /// ([`Frame::parse`]).
    pub fn from_bytes(bytes: ProtectedRef<'_, [u8]>) -> Result<Self, FrameError> {
        let frame = Frame::parse(bytes.risky_ref())?;
        // `parse` refuses every value the writer refuses, so a refusal here
        // would be a frame the two disagree on: it is the parse's error.
        Self::of(frame).map_err(|_| FrameError)
    }

    /// The frame a [`FrameWriter`] wrote into `buffer`, moved in without a
    /// copy. Unlike [`from_bytes`](Self::from_bytes), the bytes are kept as
    /// they are, a typed null included.
    ///
    /// # Errors
    ///
    /// [`FrameError`] when the buffer does not hold exactly one well-formed
    /// frame, such as one a writer left unfinished after an error. The
    /// buffer is dropped, which wipes it.
    pub fn from_buffer(buffer: Buffer) -> Result<Self, FrameError> {
        Frame::parse(buffer.risky_ref())?;
        Ok(Self::from_written(buffer))
    }

    /// The null.
    pub fn null() -> Self {
        Self(Equatable::new(vec![crate::tags::NULL]))
    }

    /// A typed null of `ty`: a null that says what it stands in for. Walked
    /// into the encrypting sink, it is sealed padded to the length of a
    /// value of `ty` (see [`Sink::typed_null`]); any other sink sees a
    /// null.
    pub fn typed_null(ty: FixedType) -> Self {
        let mut leaf = Equatable::new(Vec::new());
        leaf::write_typed_null(ty, leaf.risky_inner_mut());
        Self(leaf)
    }

    /// The frame's bytes. Same chain-of-custody caveats as
    /// [`Protected::risky_ref`]: the bytes are plaintext, and the reference
    /// must not outlive its use.
    pub fn risky_ref(&self) -> &[u8] {
        self.0.risky_ref()
    }

    /// The frame's bytes, still protected.
    pub fn into_inner(self) -> Protected<Vec<u8>> {
        Protected::new(self.0.risky_unwrap())
    }

    /// The value's [`ValueKind`], or `None` for a null, `undefined`, a
    /// passthrough, or a logical type this build does not know, which have
    /// no kind.
    pub fn kind(&self) -> Option<ValueKind> {
        match self.risky_ref().first().copied()? {
            ARRAY => Some(ValueKind::Array),
            OBJECT => Some(ValueKind::Object),
            // A passthrough's tag is no leaf's, so it reads as no scalar.
            _ => match leaf::read_item(self.risky_ref(), Form::Frame).ok()?.0 {
                Item::Scalar(ty, value) => ValueKind::of(ty, &value),
                Item::TypedNull(_) => None,
            },
        }
    }

    /// Whether the value is a null, plain or typed.
    pub fn is_null(&self) -> bool {
        matches!(
            leaf::read_item(self.risky_ref(), Form::Frame),
            Ok((Item::Scalar(None, Physical::Null) | Item::TypedNull(_), _))
        )
    }

    /// The elements of a sequence, each as a frame of its own, in order;
    /// `None` for any other value. Each element is written as
    /// [`of`](Self::of) writes it.
    pub fn elements(&self) -> Option<Vec<OwnedFrame>> {
        let frame = self.frame().ok()?;
        let mut cursor = Cursor {
            buf: frame.as_bytes(),
            pos: 0,
        };
        if cursor.byte().ok()? != ARRAY {
            return None;
        }
        let count = cursor.count().expect(VALIDATED);
        (0..count)
            .map(|_| Self::of(cursor.node(1).expect(VALIDATED)).ok())
            .collect()
    }

    /// Whether the value holds a passthrough at any depth.
    pub fn has_passthrough(&self) -> bool {
        self.frame().is_ok_and(|frame| {
            holds_passthrough(&mut Cursor {
                buf: frame.as_bytes(),
                pos: 0,
            })
        })
    }

    /// The frame, for walking. Fails only for a zeroized frame.
    fn frame(&self) -> Result<Frame<'_>, FrameError> {
        Frame::parse(self.risky_ref())
    }

    /// The bytes a writer has finished writing, which the caller has
    /// checked are one frame. They move into the frame's [`Protected`]
    /// without a copy. While the writer wrote, the `Buffer` wiped each
    /// allocation it outgrew.
    fn from_written(buffer: Buffer) -> Self {
        Self(Equatable::from(Protected::from(buffer)))
    }
}

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

/// Write one value into a fresh buffer that wipes what it outgrows.
fn write(
    f: impl FnOnce(FrameWriter<'_>) -> Result<(), DecodeError>,
) -> Result<OwnedFrame, DecodeError> {
    let mut buffer = Buffer::new();
    f(FrameWriter::new(&mut buffer))?;
    // A source that opens a container and never ends it leaves bytes that
    // are not a frame.
    OwnedFrame::from_buffer(buffer).map_err(|_| decode_error(FrameWriteError::Unfinished))
}

/// Walks the frame in place: no scalar leaves the buffer except to go
/// straight to the sink.
impl Encrypt for &OwnedFrame {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.frame()
            .map_err(|error| S::Error::source(SourceError::new(error)))?
            .visit(sink)
    }
}

/// Walks the frame, then drops it, which wipes it.
impl Encrypt for OwnedFrame {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (&self).visit(sink)
    }
}

/// What a ciphertext opens into: the opened value written straight into a
/// frame.
impl Decrypt for OwnedFrame {
    type Sink = OwnedFrameSink;
    fn sink() -> OwnedFrameSink {
        OwnedFrameSink(())
    }
}

/// A frame lends its bytes, so a frame reader can take them without the
/// caller reading them through [`risky_ref`](OwnedFrame::risky_ref).
impl<'a> AsProtectedRef<'a, [u8]> for OwnedFrame {
    fn as_protected_ref(&'a self) -> ProtectedRef<'a, [u8]> {
        self.0.as_protected_ref().as_deref()
    }
}

/// Two frames are equal when their bytes are. The bytes are compared in
/// constant time, so the comparison does not reveal where two frames first
/// differ. Frames of different lengths are unequal at once, which reveals
/// only their lengths. A ciphertext's length already shows those.
///
/// This compares frames, not values. A frame records each scalar's width and
/// type, so `34u32` and `34u64` are not equal, and neither are `0.0` and
/// `-0.0`, or a typed null and a plain one. A map is equal to another only
/// when its keys are written in the same order.
///
/// ```
/// use vitaminc_aead::frame::OwnedFrame;
///
/// assert_eq!(OwnedFrame::of(34u64)?, OwnedFrame::of(34u64)?);
/// assert_ne!(OwnedFrame::of(34u64)?, OwnedFrame::of(34u32)?);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
impl PartialEq for OwnedFrame {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// Wipes the bytes and leaves none, so a zeroized frame holds no value:
/// walking it fails rather than reading as a null.
impl Zeroize for OwnedFrame {
    fn zeroize(&mut self) {
        // The buffer that held the bytes wipes them as it drops.
        *self = Self(Equatable::new(Vec::new()));
    }
}

// =============================================================================
// Writing a value: the frame writer, with a decrypt target's errors
// =============================================================================

/// What a scalar its logical type does not admit is refused with.
const EXPECTED: &str = "a scalar its logical type admits";

/// A [`FrameWriter`] whose errors are [`DecodeError`]s, the error a
/// [`Decrypt`] target reports, and which names a repeated key inside a
/// passthrough.
///
/// The writer of each child of an [`OwnedFrameContainer`].
pub struct ValueWriter<'o>(FrameWriter<'o>);

/// The sequence half of [`ValueWriter`].
pub struct ValueSeq<'o>(FrameSeq<'o>);

/// The map half of [`ValueWriter`].
pub struct ValueMap<'o>(FrameMap<'o>);

impl<'o> ValueWriter<'o> {
    fn new(inner: FrameWriter<'o>) -> Self {
        Self(inner)
    }
}

/// Converts a frame writer's refusal into a decode error.
///
/// Inside a passthrough subtree, [`ModelOnly`] can return only the writer's
/// error type, so a repeated key it finds arrives wrapped as the writer's
/// source error. This unwraps it, and the caller gets the same
/// `DuplicateKey` a sealed value gives. A scalar its logical type does not
/// admit is the writer's [`FrameWriteError::Invalid`], which becomes
/// `Expected`.
///
/// Outside a passthrough, the writer finds a repeated key when the map ends
/// and returns its own [`FrameWriteError::DuplicateKey`], which does not
/// name the key: naming it would copy plaintext out of the frame.
fn decode_error(error: FrameWriteError) -> DecodeError {
    match error {
        FrameWriteError::Source(error) => match error.inner().downcast_ref::<DecodeError>() {
            Some(DecodeError::DuplicateKey(key)) => DecodeError::duplicate_key(key),
            _ => DecodeError::Source(error),
        },
        FrameWriteError::Invalid => DecodeError::Expected(EXPECTED),
        other => DecodeError::Source(SourceError::new(other)),
    }
}

impl<'o> Sink for ValueWriter<'o> {
    type Ok = ();
    type Error = DecodeError;
    type Seq = ValueSeq<'o>;
    type Map = ValueMap<'o>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<(), DecodeError> {
        self.0.scalar(ty, value).map_err(decode_error)
    }

    fn typed_null(self, ty: FixedType) -> Result<(), DecodeError> {
        self.0.typed_null(ty).map_err(decode_error)
    }

    fn seq(self, len: Option<usize>) -> Result<ValueSeq<'o>, DecodeError> {
        self.0.seq(len).map(ValueSeq).map_err(decode_error)
    }

    fn map(self, len: Option<usize>) -> Result<ValueMap<'o>, DecodeError> {
        self.0.map(len).map(ValueMap).map_err(decode_error)
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, value: &P) -> Result<(), DecodeError> {
        self.0
            .passthrough(&ModeledSource(value))
            .map_err(decode_error)
    }
}

impl SeqSink for ValueSeq<'_> {
    type Ok = ();
    type Error = DecodeError;
    type Element<'s>
        = ValueWriter<'s>
    where
        Self: 's;

    fn element(&mut self) -> Result<ValueWriter<'_>, DecodeError> {
        self.0.element().map(ValueWriter).map_err(decode_error)
    }

    fn end(self) -> Result<(), DecodeError> {
        self.0.end().map_err(decode_error)
    }
}

impl MapSink for ValueMap<'_> {
    type Ok = ();
    type Error = DecodeError;
    type Entry<'s>
        = ValueWriter<'s>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<ValueWriter<'_>, DecodeError> {
        self.0.entry(key).map(ValueWriter).map_err(decode_error)
    }

    fn end(self) -> Result<(), DecodeError> {
        self.0.end().map_err(decode_error)
    }
}

/// A passthrough subtree, walked through [`ModelOnly`].
struct ModeledSource<'a, P: ?Sized>(&'a P);

impl<P: ?Sized + EncryptRef> Encrypt for &ModeledSource<'_, P> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.0.visit_ref(ModelOnly(sink))
    }
}

/// In front of any sink, keeping that sink's error: a map refuses a
/// repeated key itself, naming it, before the sink can refuse it as a bare
/// frame error. A passthrough is in the clear, so its keys may be named.
struct ModelOnly<S>(S);

/// A map under [`ModelOnly`], with the keys it has been given.
struct ModelOnlyMap<S> {
    inner: S,
    keys: BTreeSet<String>,
}

impl<S: Sink> Sink for ModelOnly<S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type Seq = ModelOnly<S::Seq>;
    type Map = ModelOnlyMap<S::Map>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<S::Ok, S::Error> {
        self.0.scalar(ty, value)
    }

    fn typed_null(self, ty: FixedType) -> Result<S::Ok, S::Error> {
        self.0.typed_null(ty)
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, S::Error> {
        self.0.seq(len).map(ModelOnly)
    }

    fn map(self, len: Option<usize>) -> Result<Self::Map, S::Error> {
        self.0.map(len).map(|inner| ModelOnlyMap {
            inner,
            keys: BTreeSet::new(),
        })
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, value: &P) -> Result<S::Ok, S::Error> {
        self.0.passthrough(&ModeledSource(value))
    }
}

impl<S: SeqSink> SeqSink for ModelOnly<S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type Element<'s>
        = ModelOnly<S::Element<'s>>
    where
        Self: 's;

    fn element(&mut self) -> Result<Self::Element<'_>, S::Error> {
        self.0.element().map(ModelOnly)
    }

    fn end(self) -> Result<S::Ok, S::Error> {
        self.0.end()
    }
}

impl<S: MapSink> MapSink for ModelOnlyMap<S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type Entry<'s>
        = ModelOnly<S::Entry<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, S::Error> {
        if !self.keys.insert(key.to_owned()) {
            return Err(S::Error::source(SourceError::new(
                DecodeError::duplicate_key(key),
            )));
        }
        self.inner.entry(key).map(ModelOnly)
    }

    fn end(self) -> Result<S::Ok, S::Error> {
        self.inner.end()
    }
}

// =============================================================================
// Opening into a frame
// =============================================================================

/// The [`Decrypt`] sink of an [`OwnedFrame`]: writes the opened value into
/// a frame. A scalar or a passthrough is written directly. A container's
/// children are each written into a frame of their own as they are opened,
/// and the container is written around them when it ends.
pub struct OwnedFrameSink(());

/// A container an [`OwnedFrameSink`] is opening: its children, each in a
/// buffer of its own, joined into one frame when it ends. A map refuses a
/// repeated key, naming it.
///
/// Each key is copied out and held unwiped. A map this opens is a stored
/// one, and a stored map's keys are in the clear beside its sealed values,
/// so a copy of one holds nothing the stored value does not.
pub struct OwnedFrameContainer {
    map: bool,
    children: Vec<(Option<String>, Buffer)>,
}

impl Sink for OwnedFrameSink {
    type Ok = OwnedFrame;
    type Error = DecodeError;
    type Seq = OwnedFrameContainer;
    type Map = OwnedFrameContainer;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<OwnedFrame, DecodeError> {
        write(|writer| ValueWriter::new(writer).scalar(ty, value))
    }

    fn typed_null(self, ty: FixedType) -> Result<OwnedFrame, DecodeError> {
        write(|writer| ValueWriter::new(writer).typed_null(ty))
    }

    fn seq(self, _: Option<usize>) -> Result<OwnedFrameContainer, DecodeError> {
        Ok(OwnedFrameContainer::new(false))
    }

    fn map(self, _: Option<usize>) -> Result<OwnedFrameContainer, DecodeError> {
        Ok(OwnedFrameContainer::new(true))
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, value: &P) -> Result<OwnedFrame, DecodeError> {
        write(|writer| ValueWriter::new(writer).passthrough(value))
    }
}

impl OwnedFrameContainer {
    fn new(map: bool) -> Self {
        Self {
            map,
            children: Vec::new(),
        }
    }

    fn next(&mut self, key: Option<&str>) -> ValueWriter<'_> {
        self.children.push((key.map(str::to_owned), Buffer::new()));
        let buffer = match self.children.last_mut() {
            Some((_, buffer)) => buffer,
            // Pushed on the line above.
            None => unreachable!(),
        };
        ValueWriter::new(FrameWriter::new(buffer))
    }

    /// Write the container around its children's frames.
    fn join(self) -> Result<OwnedFrame, DecodeError> {
        let Self { map, children } = self;
        write(|writer| {
            let count = Some(children.len());
            if map {
                let mut entries = ValueWriter::new(writer).map(count)?;
                let mut keys = BTreeSet::new();
                for (key, child) in &children {
                    let key = key.as_deref().unwrap_or_default();
                    if !keys.insert(key) {
                        return Err(DecodeError::duplicate_key(key));
                    }
                    child_frame(child)?.visit(entries.entry(key)?)?;
                }
                entries.end()
            } else {
                let mut elements = ValueWriter::new(writer).seq(count)?;
                for (_, child) in &children {
                    child_frame(child)?.visit(elements.element()?)?;
                }
                elements.end()
            }
        })
    }
}

/// A child's buffer as the frame its writer wrote. A child sink the source
/// dropped unwritten leaves no frame.
fn child_frame(buffer: &Buffer) -> Result<Frame<'_>, DecodeError> {
    Frame::parse(buffer.risky_ref()).map_err(|_| decode_error(FrameWriteError::Unwritten))
}

impl SeqSink for OwnedFrameContainer {
    type Ok = OwnedFrame;
    type Error = DecodeError;
    type Element<'s>
        = ValueWriter<'s>
    where
        Self: 's;

    fn element(&mut self) -> Result<ValueWriter<'_>, DecodeError> {
        Ok(self.next(None))
    }

    fn end(self) -> Result<OwnedFrame, DecodeError> {
        self.join()
    }
}

impl MapSink for OwnedFrameContainer {
    type Ok = OwnedFrame;
    type Error = DecodeError;
    type Entry<'s>
        = ValueWriter<'s>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<ValueWriter<'_>, DecodeError> {
        Ok(self.next(Some(key)))
    }

    fn end(self) -> Result<OwnedFrame, DecodeError> {
        self.join()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plaintext::kinds::{MAX_DATE_DAYS, MAX_TIMESTAMP_NANOS};
    use crate::plaintext::record::{record, Event, Owned};
    use crate::plaintext::{Int, Raw, TimeUnit, Width};
    use crate::tags;

    /// A value of any shape, to walk into the frame's sinks.
    #[derive(Clone)]
    enum V {
        Null,
        Undefined,
        Bool(bool),
        I32(i32),
        U64(u64),
        F64(f64),
        Text(&'static str),
        Bytes(&'static [u8]),
        Raw(Raw<'static>),
        TypedNull(FixedType),
        Seq(Vec<V>),
        Map(Vec<(&'static str, V)>),
        Pass(Box<V>),
        /// A sequence whose second element sink is dropped unwritten.
        DropsAChild,
    }

    impl Encrypt for &V {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            match self {
                V::Null => sink.scalar(None, Physical::Null),
                V::Undefined => sink.scalar(Some(Logical::Undefined), Physical::Null),
                V::Bool(b) => sink.scalar(None, Physical::Bool(*b)),
                V::I32(i) => sink.scalar(None, Physical::Int(Int::I32(*i))),
                V::U64(i) => sink.scalar(None, Physical::Int(Int::U64(*i))),
                V::F64(f) => (*f).visit(sink),
                V::Text(t) => sink.scalar(None, Physical::Text(t)),
                V::Bytes(b) => sink.scalar(None, Physical::Bytes(b)),
                V::Raw(raw) => raw.visit(sink),
                V::TypedNull(ty) => sink.typed_null(*ty),
                V::Seq(items) => {
                    let mut seq = sink.seq(Some(items.len()))?;
                    for item in items {
                        item.visit(seq.element()?)?;
                    }
                    seq.end()
                }
                V::Map(entries) => {
                    let mut map = sink.map(Some(entries.len()))?;
                    for (key, value) in entries {
                        value.visit(map.entry(key)?)?;
                    }
                    map.end()
                }
                V::Pass(inner) => sink.passthrough(&**inner),
                V::DropsAChild => {
                    let mut seq = sink.seq(None)?;
                    1u16.visit(seq.element()?)?;
                    let _ = seq.element()?;
                    seq.end()
                }
            }
        }
    }

    impl Encrypt for V {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            (&self).visit(sink)
        }
    }

    fn frame(value: &V) -> OwnedFrame {
        OwnedFrame::of(value).expect("in the model")
    }

    fn bytes(value: &V) -> Vec<u8> {
        crate::to_frame(value).expect("frames").risky_ref().clone()
    }

    fn protected(bytes: &[u8]) -> Protected<Vec<u8>> {
        Protected::new(bytes.to_vec())
    }

    fn fixed(ty: Option<Logical>, width: Width) -> FixedType {
        FixedType::new(ty, width).expect("a fixed-width type")
    }

    fn every_variant() -> V {
        V::Map(vec![
            ("n", V::Null),
            ("u", V::Undefined),
            ("b", V::Bool(true)),
            ("i32", V::I32(-3)),
            ("u64", V::U64(u64::MAX)),
            ("f64", V::F64(f64::NAN)),
            ("s", V::Text("alice")),
            ("bytes", V::Bytes(&[1, 2, 3])),
            (
                "list",
                V::Seq(vec![V::Text("a"), V::Pass(Box::new(V::Text("p")))]),
            ),
            ("empty", V::Seq(vec![])),
            ("none", V::Map(vec![])),
        ])
    }

    /// A typed null of each kind of fixed type, a logical type this build
    /// does not know among them.
    fn typed_nulls() -> Vec<FixedType> {
        vec![
            fixed(None, Width::I64),
            fixed(None, Width::F32),
            fixed(Some(Logical::Date), Width::I32),
            fixed(Some(Logical::Decimal { scale: 2 }), Width::I128),
            fixed(Some(Logical::Timestamp(TimeUnit::Micros)), Width::I64),
            fixed(Some(Logical::Uuid), Width::Bytes16),
            fixed(
                Some(Logical::from_wire(200, 0).expect("an unknown logical type")),
                Width::I32,
            ),
        ]
    }

    fn typed_null_bytes(ty: FixedType) -> Vec<u8> {
        let mut out = Vec::new();
        leaf::write_typed_null(ty, &mut out);
        out
    }

    mod equality {
        use super::*;

        #[test]
        fn frames_with_the_same_bytes_are_equal() {
            let one = frame(&V::Text("alice"));
            assert_eq!(
                one,
                OwnedFrame::from_bytes(one.as_protected_ref()).expect("reads")
            );
        }

        #[test]
        fn frames_with_different_bytes_of_the_same_length_are_not_equal() {
            let (a, b) = (frame(&V::Text("alice")), frame(&V::Text("alicf")));
            assert_eq!(a.risky_ref().len(), b.risky_ref().len());
            assert_ne!(a, b);
        }

        #[test]
        fn frames_of_different_lengths_are_not_equal() {
            assert_ne!(frame(&V::Text("alice")), frame(&V::Text("alice!")));
        }

        #[test]
        fn the_same_number_at_two_widths_is_not_equal() {
            assert_ne!(
                OwnedFrame::of(34u32).expect("in the model"),
                OwnedFrame::of(34u64).expect("in the model")
            );
        }
    }

    /// A value's frame is the frame `to_frame` writes for it, byte for byte,
    /// walks back as the value, and comes out of `into_inner` unchanged.
    #[test]
    fn a_frame_is_the_values_own_frame() {
        let value = every_variant();
        let owned = frame(&value);
        assert_eq!(owned.risky_ref(), bytes(&value).as_slice());
        assert_eq!(
            record(&owned).expect("walks"),
            record(&value).expect("walks")
        );
        assert_eq!(
            record(frame(&value)).expect("walks by value"),
            record(&value).expect("walks")
        );
        let lent = owned.as_protected_ref();
        assert_eq!(lent.risky_ref(), bytes(&value).as_slice());
        assert_eq!(owned.into_inner().risky_ref(), &bytes(&value));
    }

    /// Every integer keeps its own width, as the host wrote it.
    #[test]
    fn every_integer_keeps_its_width() {
        for (int, tag) in [
            (Int::I8(-8), tags::INT8),
            (Int::I16(-8), tags::INT16),
            (Int::I128(-8), tags::INT128),
            (Int::U8(8), tags::UINT8),
            (Int::U16(8), tags::UINT16),
            (Int::U128(8), tags::UINT128),
        ] {
            let owned = OwnedFrame::of(Raw(None, Physical::Int(int))).expect("in the model");
            assert_eq!(owned.risky_ref()[0], tag);
            let back = OwnedFrame::from_bytes(owned.as_protected_ref()).expect("in the model");
            assert_eq!(back, owned, "read back at its width");
        }
    }

    /// A typed null is a null in a frame: written, read from a host's
    /// bytes, or opened. Its padding belongs to a sealed leaf. `typed_null`
    /// and `from_buffer` keep it as it is.
    #[test]
    fn a_typed_null_is_a_null_in_a_frame_unless_kept() {
        let null = OwnedFrame::null();
        assert_eq!(null.risky_ref(), [tags::NULL]);
        assert!(null.is_null());
        for ty in typed_nulls() {
            assert_eq!(frame(&V::TypedNull(ty)), null, "{ty:?} written");
            let host = typed_null_bytes(ty);
            let read = OwnedFrame::from_bytes(protected(&host).as_protected_ref().as_deref())
                .expect("reads");
            assert_eq!(read, null, "{ty:?} read");
            let opened = V::TypedNull(ty).visit(OwnedFrame::sink()).expect("opens");
            assert_eq!(opened, null, "{ty:?} opened");

            let kept = OwnedFrame::typed_null(ty);
            assert_eq!(kept.risky_ref(), host.as_slice(), "{ty:?} kept");
            assert!(kept.is_null(), "{ty:?} is a null");
            assert_eq!(kept.kind(), None, "{ty:?} has no kind");
            assert_eq!(record(&kept).expect("walks"), [Event::TypedNull(ty)]);
            let mut buffer = Buffer::new();
            buffer.extend_from_slice(&host);
            let moved = OwnedFrame::from_buffer(buffer).expect("a frame");
            assert_eq!(moved, kept, "{ty:?} moved in as it is");

            let hidden = V::Pass(Box::new(V::TypedNull(ty)));
            assert_eq!(
                frame(&hidden),
                frame(&V::Pass(Box::new(V::Null))),
                "{ty:?} in a passthrough"
            );
        }
    }

    /// `from_buffer` takes the buffer's bytes without a copy, and refuses
    /// what is not one frame.
    #[test]
    fn from_buffer_moves_a_frame_and_refuses_anything_else() {
        let mut buffer = Buffer::new();
        FrameWriter::new(&mut buffer)
            .scalar(None, Physical::Text("alice"))
            .expect("writes");
        let at = buffer.risky_ref().as_ptr();
        let moved = OwnedFrame::from_buffer(buffer).expect("a frame");
        assert_eq!(moved.risky_ref().as_ptr(), at, "moved, not copied");
        assert_eq!(moved, frame(&V::Text("alice")));
        for refused in [&[][..], &[ARRAY, 1, 0, 0, 0], &[tags::NULL, tags::NULL]] {
            let mut buffer = Buffer::new();
            buffer.extend_from_slice(refused);
            assert_eq!(OwnedFrame::from_buffer(buffer).err(), Some(FrameError));
            assert_eq!(
                OwnedFrame::from_bytes(protected(refused).as_protected_ref().as_deref()).err(),
                Some(FrameError)
            );
        }
    }

    /// A date, a decimal, a timestamp in any unit and a UUID keep their
    /// logical type and its parameters. A logical type this build does not
    /// know is carried as written, and has no kind.
    #[test]
    fn logical_types_are_kept_as_written() {
        let cases = [
            (
                Raw(Some(Logical::Date), Physical::Int(Int::I32(19_782))),
                Some(ValueKind::Date),
            ),
            (
                Raw(
                    Some(Logical::Decimal { scale: 2 }),
                    Physical::Int(Int::I64(150)),
                ),
                Some(ValueKind::Decimal),
            ),
            (
                Raw(
                    Some(Logical::Timestamp(TimeUnit::Micros)),
                    Physical::Int(Int::I64(-2_000_000)),
                ),
                Some(ValueKind::Timestamp),
            ),
            (
                Raw(Some(Logical::Uuid), Physical::Bytes(&[7; 16])),
                Some(ValueKind::Uuid),
            ),
            (
                Raw(
                    Some(Logical::from_wire(200, 9).expect("an unknown logical type")),
                    Physical::Int(Int::I32(1)),
                ),
                None,
            ),
        ];
        for (raw, kind) in cases {
            let owned = OwnedFrame::of(raw).expect("in the model");
            assert_eq!(owned.kind(), kind, "{raw:?}");
            assert_eq!(owned.risky_ref(), bytes(&V::Raw(raw)).as_slice());
            let opened = raw.visit(OwnedFrame::sink()).expect("opens");
            assert_eq!(opened, owned, "{raw:?} opens as written");
            let back = OwnedFrame::from_bytes(owned.as_protected_ref()).expect("reads");
            assert_eq!(back, owned, "{raw:?} reads as written");
        }
    }

    /// A scalar its logical type does not admit is refused, at the top, in
    /// a container or inside a passthrough.
    #[test]
    fn what_a_logical_type_does_not_admit_is_refused() {
        let refused = [
            Raw(Some(Logical::Uuid), Physical::Bytes(&[7; 15])),
            Raw(Some(Logical::Uuid), Physical::Text("0123456789abcdef")),
            Raw(
                Some(Logical::Date),
                Physical::Int(Int::I64(i64::from(MAX_DATE_DAYS) + 1)),
            ),
            Raw(
                Some(Logical::Timestamp(TimeUnit::Nanos)),
                Physical::Int(Int::I128(MAX_TIMESTAMP_NANOS + 1)),
            ),
            Raw(Some(Logical::Undefined), Physical::Bool(true)),
        ];
        for raw in refused {
            for value in [
                V::Raw(raw),
                V::Seq(vec![V::Raw(raw)]),
                V::Pass(Box::new(V::Raw(raw))),
            ] {
                assert!(
                    matches!(OwnedFrame::of(&value), Err(DecodeError::Expected(EXPECTED))),
                    "{raw:?}"
                );
                assert!(
                    matches!(
                        value.visit(OwnedFrame::sink()),
                        Err(DecodeError::Expected(EXPECTED))
                    ),
                    "{raw:?} opened"
                );
            }
        }
    }

    /// A repeated key outside a passthrough is refused unnamed, as the
    /// writer refuses it; inside one, it is named. Opening a map names it
    /// too: a stored map's keys are in the clear.
    #[test]
    fn a_repeated_key_is_refused_and_named_only_where_it_is_in_the_clear() {
        let repeated = V::Map(vec![("k", V::Null), ("k", V::Null)]);
        assert!(matches!(
            OwnedFrame::of(&repeated),
            Err(DecodeError::Source(ref source))
                if matches!(
                    source.inner().downcast_ref::<FrameWriteError>(),
                    Some(FrameWriteError::DuplicateKey)
                )
        ));
        let hidden = V::Pass(Box::new(V::Seq(vec![repeated.clone()])));
        assert!(matches!(
            OwnedFrame::of(&hidden),
            Err(DecodeError::DuplicateKey(ref key)) if key == "k"
        ));
        assert!(matches!(
            repeated.visit(OwnedFrame::sink()),
            Err(DecodeError::DuplicateKey(ref key)) if key == "k"
        ));
        assert!(matches!(
            hidden.visit(OwnedFrame::sink()),
            Err(DecodeError::DuplicateKey(ref key)) if key == "k"
        ));
        let distinct = V::Pass(Box::new(V::Map(vec![("j", V::Null), ("k", V::Null)])));
        assert!(OwnedFrame::of(&distinct).is_ok());
    }

    /// A source that drops a child sink unwritten, or nests too deep, is
    /// refused rather than kept as bytes that are no frame.
    #[test]
    fn an_unfinished_value_is_refused() {
        assert!(matches!(
            OwnedFrame::of(&V::DropsAChild),
            Err(DecodeError::Source(_))
        ));
        assert!(matches!(
            V::DropsAChild.visit(OwnedFrame::sink()),
            Err(DecodeError::Source(ref source))
                if matches!(
                    source.inner().downcast_ref::<FrameWriteError>(),
                    Some(FrameWriteError::Unwritten)
                )
        ));
        let too_deep = (0..=crate::frame::MAX_DEPTH).fold(V::Null, |inner, _| V::Seq(vec![inner]));
        assert!(matches!(
            OwnedFrame::of(&too_deep),
            Err(DecodeError::Source(ref source))
                if matches!(
                    source.inner().downcast_ref::<FrameWriteError>(),
                    Some(FrameWriteError::TooDeep)
                )
        ));
    }

    /// A source's own failure reaches the caller as the source's error.
    #[test]
    fn a_failing_source_is_refused_with_its_error() {
        struct Fails;
        impl Encrypt for &Fails {
            fn visit<S: Sink>(self, _: S) -> Result<S::Ok, S::Error> {
                Err(S::Error::source(SourceError::msg("getter threw")))
            }
        }
        assert!(matches!(
            OwnedFrame::of(&Fails),
            Err(DecodeError::Source(ref source)) if source.to_string() == "getter threw"
        ));
        struct HidesFails;
        impl Encrypt for &HidesFails {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                sink.passthrough(&Fails)
            }
        }
        assert!(matches!(
            OwnedFrame::of(&HidesFails),
            Err(DecodeError::Source(ref source)) if source.to_string() == "getter threw"
        ));
    }

    /// Every value opens to the frame it was written as.
    #[test]
    fn opening_writes_the_frame_it_reads() {
        let value = every_variant();
        let opened = (&value).visit(OwnedFrame::sink()).expect("opens");
        assert_eq!(opened, frame(&value));
        for scalar in [
            V::Text("x"),
            V::Null,
            V::I32(1),
            V::Pass(Box::new(V::Text("p"))),
        ] {
            let opened = (&scalar).visit(OwnedFrame::sink()).expect("opens");
            assert_eq!(opened, frame(&scalar));
        }
        let nested = V::Seq(vec![V::Map(vec![("a", V::Seq(vec![V::I32(1)]))])]);
        let opened = (&nested).visit(OwnedFrame::sink()).expect("opens");
        assert_eq!(opened, frame(&nested));
    }

    #[test]
    fn a_frame_names_its_kind() {
        let cases = [
            (V::Null, None),
            (V::Undefined, None),
            (V::Bool(true), Some(ValueKind::Bool)),
            (V::I32(1), Some(ValueKind::Int32)),
            (V::U64(1), Some(ValueKind::UInt64)),
            (V::F64(1.0), Some(ValueKind::Float64)),
            (V::Text("a"), Some(ValueKind::String)),
            (V::Bytes(&[1]), Some(ValueKind::Bytes)),
            (V::Seq(vec![V::Text("a")]), Some(ValueKind::Array)),
            (V::Map(vec![("k", V::Text("a"))]), Some(ValueKind::Object)),
            (V::Pass(Box::new(V::Text("p"))), None),
        ];
        for (value, kind) in cases {
            assert_eq!(frame(&value).kind(), kind);
        }
    }

    /// Only a null, plain or typed, is a null; `undefined` is not.
    #[test]
    fn only_a_null_is_a_null() {
        assert!(frame(&V::Null).is_null());
        for value in [
            V::Undefined,
            V::Bool(false),
            V::I32(0),
            V::Text(""),
            V::Seq(vec![V::Null]),
            V::Pass(Box::new(V::Null)),
        ] {
            assert!(!frame(&value).is_null());
        }
    }

    /// A sequence's elements are their own frames, in order, each written
    /// as `of` writes it.
    #[test]
    fn elements_are_the_childrens_frames() {
        let ty = fixed(Some(Logical::Date), Width::I32);
        let mut seq = vec![ARRAY, 3, 0, 0, 0];
        seq.extend(bytes(&V::Text("a")));
        seq.extend(typed_null_bytes(ty));
        seq.extend(bytes(&V::Seq(vec![V::I32(1)])));
        let mut buffer = Buffer::new();
        buffer.extend_from_slice(&seq);
        let items = OwnedFrame::from_buffer(buffer)
            .expect("a frame")
            .elements()
            .expect("a sequence");
        assert_eq!(
            items,
            [
                frame(&V::Text("a")),
                OwnedFrame::null(),
                frame(&V::Seq(vec![V::I32(1)]))
            ]
        );
        assert_eq!(frame(&V::Seq(vec![])).elements(), Some(vec![]));
        for other in [
            V::Text("a"),
            V::Map(vec![("k", V::Text("a"))]),
            V::Pass(Box::new(V::Seq(vec![]))),
        ] {
            assert!(frame(&other).elements().is_none());
        }
    }

    #[test]
    fn a_passthrough_is_found_at_any_depth() {
        assert!(frame(&every_variant()).has_passthrough());
        assert!(frame(&V::Pass(Box::new(V::Text("p")))).has_passthrough());
        assert!(frame(&V::Map(vec![
            ("a", V::Text("a")),
            ("p", V::Pass(Box::new(V::Null)))
        ]))
        .has_passthrough());
        assert!(frame(&V::Seq(vec![V::Null, V::Pass(Box::new(V::Null))])).has_passthrough());
        assert!(!frame(&V::Text("a")).has_passthrough());
        assert!(!frame(&V::Map(vec![("k", V::Seq(vec![V::Text("a")]))])).has_passthrough());
        assert!(!frame(&V::Seq(vec![V::Map(vec![]), V::Null])).has_passthrough());
    }

    /// A zeroized frame holds no bytes, and no value: it walks as an error
    /// and is neither a null nor of any kind.
    #[test]
    fn a_zeroized_frame_holds_nothing() {
        let mut owned = frame(&V::Seq(vec![V::Pass(Box::new(V::Text("p")))]));
        owned.zeroize();
        assert!(owned.risky_ref().is_empty());
        assert!(record(&owned).is_err());
        assert!(!owned.is_null());
        assert_eq!(owned.kind(), None);
        assert!(owned.elements().is_none());
        assert!(!owned.has_passthrough());
    }

    #[test]
    fn debug_redacts_the_frame() {
        let shown = format!("{:?}", frame(&V::Text("secret")));
        assert!(shown.ends_with("OwnedFrame(\"***\")"), "{shown}");
        assert!(!shown.contains("secret"), "{shown}");
    }

    /// The text a frame's scalar holds is what a recording sees.
    #[test]
    fn a_frame_walks_its_scalars_in_place() {
        assert_eq!(
            record(frame(&V::Text("alice"))).expect("walks"),
            [Event::Scalar(None, Owned::Text("alice".into()))]
        );
    }
}
