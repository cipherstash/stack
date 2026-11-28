//! [`OwnedFrame`]: a [`Buffer`] that holds exactly one frame.

use vitaminc_protected::{Buffer, Controlled, OpaqueDebug};
use zeroize::Zeroize;

use super::{to_frame, Container, Frame, FrameError, FrameWriteError, FrameWriter, ARRAY, OBJECT};
use crate::leaf::{self, typed_null_len};
use crate::plaintext::{
    Encrypt, EncryptRef, FixedType, Logical, MapSink, Physical, SeqSink, Sink, SourceError,
};
use crate::tags;
use crate::typed::{DecodeError, Decrypt, ScalarTarget};

/// One value as a transport frame, in a [`Buffer`] of its own: a value
/// kept past the call that wrote it, and what a ciphertext opens into.
///
/// The buffer holds exactly one frame that [`Frame::parse`] accepted, so
/// [`frame`](Self::frame) lends it without a check and without a copy. The
/// buffer is wiped when it drops, and wipes each allocation it outgrows
/// while it is written.
///
/// A value only read within one call does not need one: read it as a
/// [`Frame`] borrowed from wherever its bytes are. Every reader of a frame
/// reads a `Frame`. An `OwnedFrame` is for a value that must outlive its
/// bytes' owner, such as a decrypted field or a value an async call holds.
///
/// - Make one from any source with [`of`](Self::of), from a [`Buffer`] a
///   [`FrameWriter`] filled with [`from_buffer`](Self::from_buffer), or as a
///   [`null`](Self::null) or a [`typed_null`](Self::typed_null).
/// - It is a source ([`Encrypt`]): walking it into a sink seals, indexes or
///   writes the value, reading the bytes in place.
/// - It is a decrypt target ([`Decrypt`]): a ciphertext opens straight
///   into one buffer, with no value tree in between and no copy per child.
/// - [`into_buffer`](Self::into_buffer) hands the bytes back, still in the
///   `Buffer` that wipes them.
///
/// `Debug` names the type and masks the bytes, which are plaintext. It has
/// no `==`: compare two frames with [`Frame`]'s, in constant time.
///
/// ```
/// use vitaminc_aead::{OwnedFrame, ValueKind};
///
/// let frame = OwnedFrame::of("alice")?;
/// assert_eq!(frame.frame().kind(), Some(ValueKind::String));
///
/// // The same value, written into a buffer and moved in without a copy.
/// let moved = OwnedFrame::from_buffer(vitaminc_aead::to_frame("alice")?)?;
/// assert_eq!(moved.frame(), frame.frame());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(OpaqueDebug)]
pub struct OwnedFrame(Buffer);

impl OwnedFrame {
    /// The frame of any source, as [`to_frame`] writes it: a typed null is
    /// written as a plain null.
    ///
    /// # Errors
    ///
    /// As [`to_frame`]: [`FrameWriteError::Invalid`] for a scalar its
    /// logical type does not admit ([`Logical::admits`]), and the other
    /// [`FrameWriteError`]s for a value deeper or longer than a frame allows,
    /// a map that repeats a key, or a source that fails.
    pub fn of<P: Encrypt>(value: P) -> Result<Self, FrameWriteError> {
        to_frame(value).map(Self)
    }

    /// The frame a [`FrameWriter`] wrote into `buffer`, moved in without a
    /// copy. The bytes are kept as they are, a typed null included.
    ///
    /// # Errors
    ///
    /// [`FrameError`] when the buffer does not hold exactly one well-formed
    /// frame ([`Frame::parse`]), such as one a writer left unfinished after
    /// an error. The buffer is dropped, which wipes it.
    pub fn from_buffer(buffer: Buffer) -> Result<Self, FrameError> {
        Frame::parse(buffer.risky_ref())?;
        Ok(Self(buffer))
    }

    /// The plain null.
    pub fn null() -> Self {
        let mut buffer = Buffer::new();
        buffer.push(tags::NULL);
        Self(buffer)
    }

    /// A typed null of `ty`: a null that says what it stands in for. Walked
    /// into the encrypting sink, it is sealed padded to the length of a
    /// value of `ty` (see [`Sink::typed_null`]); any other sink sees a
    /// null. A [`FrameWriter`] writes a plain null for one, so this is how
    /// an owned frame comes to hold one.
    pub fn typed_null(ty: FixedType) -> Self {
        // The bytes are a type's tags and zeros, and no plaintext.
        let mut leaf = Vec::with_capacity(typed_null_len(ty));
        leaf::write_typed_null(ty, &mut leaf);
        let mut buffer = Buffer::new();
        buffer.extend_from_slice(&leaf);
        Self(buffer)
    }

    /// The frame, borrowed: what every reader of a frame takes.
    pub fn frame(&self) -> Frame<'_> {
        Frame {
            bytes: self.0.risky_ref(),
        }
    }

    /// The frame's bytes, in the [`Buffer`] that wipes them.
    pub fn into_buffer(self) -> Buffer {
        self.0
    }
}

/// Walks the frame in place: no scalar leaves the buffer except to go
/// straight to the sink.
impl Encrypt for &OwnedFrame {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.frame().visit(sink)
    }
}

/// Walks the frame, then drops it, which wipes it.
impl Encrypt for OwnedFrame {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.frame().visit(sink)
    }
}

/// What a ciphertext opens into: the opened value written straight into
/// one buffer.
impl Decrypt for OwnedFrame {
    type Sink = OwnedFrameSink;
    fn sink() -> OwnedFrameSink {
        OwnedFrameSink(())
    }
}

/// One leaf always builds a frame: the frame of the one scalar, or of the
/// null, that the leaf holds.
impl ScalarTarget for OwnedFrame {}

/// Wipes the bytes and leaves the plain null, the frame a buffer of no
/// value holds: an `OwnedFrame` always holds one frame, so a zeroized one
/// reads, walks and seals as a null.
impl Zeroize for OwnedFrame {
    fn zeroize(&mut self) {
        self.0.zeroize();
        self.0.push(tags::NULL);
    }
}

/// A frame writer's refusal, as a decrypt target reports it. A scalar its
/// logical type does not admit is [`DecodeError::Expected`]; a source's
/// own failure is that failure; any other refusal is the writer's error,
/// as the source of [`DecodeError::Source`].
impl From<FrameWriteError> for DecodeError {
    fn from(error: FrameWriteError) -> Self {
        match error {
            FrameWriteError::Invalid => DecodeError::Expected("a scalar its logical type admits"),
            FrameWriteError::Source(error) => DecodeError::Source(error),
            other => DecodeError::Source(SourceError::new(other)),
        }
    }
}

// =============================================================================
// Opening into a frame
// =============================================================================

/// The [`Decrypt`] sink of an [`OwnedFrame`]: writes the opened value into
/// one buffer, the frame's. A container's children are written into the
/// same buffer as they are opened, so nothing is copied after it is
/// written.
pub struct OwnedFrameSink(());

/// A container an [`OwnedFrameSink`] is opening: a sequence or a map
/// written in place into the frame's buffer, which it owns until it ends.
/// A map refuses a repeated key, without naming it.
pub struct OwnedFrameContainer(Container<Buffer, DecodeError>);

/// The frame in `buffer`, which a writer has finished writing: checked
/// once more, so a source that opened a container and never ended it is
/// refused rather than kept.
fn finished(buffer: Buffer) -> Result<OwnedFrame, DecodeError> {
    OwnedFrame::from_buffer(buffer).map_err(|_| FrameWriteError::Unfinished.into())
}

/// Write one node into a fresh buffer.
fn node(
    write: impl FnOnce(FrameWriter<'_, DecodeError>) -> Result<(), DecodeError>,
) -> Result<OwnedFrame, DecodeError> {
    let mut buffer = Buffer::new();
    write(FrameWriter::reporting(&mut buffer, 0))?;
    finished(buffer)
}

impl Sink for OwnedFrameSink {
    type Ok = OwnedFrame;
    type Error = DecodeError;
    type Seq = OwnedFrameContainer;
    type Map = OwnedFrameContainer;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<OwnedFrame, DecodeError> {
        node(|writer| writer.scalar(ty, value))
    }

    /// Written as the plain null, as a [`FrameWriter`] writes one.
    fn typed_null(self, ty: FixedType) -> Result<OwnedFrame, DecodeError> {
        node(|writer| writer.typed_null(ty))
    }

    fn seq(self, len: Option<usize>) -> Result<OwnedFrameContainer, DecodeError> {
        Container::open(Buffer::new(), ARRAY, 0, len).map(OwnedFrameContainer)
    }

    fn map(self, len: Option<usize>) -> Result<OwnedFrameContainer, DecodeError> {
        Container::open(Buffer::new(), OBJECT, 0, len).map(OwnedFrameContainer)
    }

    fn passthrough<P: ?Sized + EncryptRef>(self, value: &P) -> Result<OwnedFrame, DecodeError> {
        node(|writer| writer.passthrough(value))
    }
}

impl SeqSink for OwnedFrameContainer {
    type Ok = OwnedFrame;
    type Error = DecodeError;
    type Element<'s>
        = FrameWriter<'s, DecodeError>
    where
        Self: 's;

    fn element(&mut self) -> Result<FrameWriter<'_, DecodeError>, DecodeError> {
        self.0.element()
    }

    fn end(self) -> Result<OwnedFrame, DecodeError> {
        finished(self.0.end()?)
    }
}

impl MapSink for OwnedFrameContainer {
    type Ok = OwnedFrame;
    type Error = DecodeError;
    type Entry<'s>
        = FrameWriter<'s, DecodeError>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<FrameWriter<'_, DecodeError>, DecodeError> {
        self.0.entry(key)
    }

    fn end(self) -> Result<OwnedFrame, DecodeError> {
        finished(self.0.end()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{FrameMap, FrameSeq};
    use crate::plaintext::kinds::{MAX_DATE_DAYS, MAX_TIMESTAMP_NANOS};
    use crate::plaintext::record::{record, Event, Owned};
    use crate::plaintext::{Error as _, Int, Raw, TimeUnit, ValueKind, Width};

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
        /// A sequence holding a sequence with an element that is never
        /// ended, so its count is never written.
        Unended,
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
                V::Unended => {
                    let mut seq = sink.seq(None)?;
                    let mut inner = seq.element()?.seq(None)?;
                    true.visit(inner.element()?)?;
                    drop(inner);
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

    fn buffer(bytes: &[u8]) -> Buffer {
        let mut buffer = Buffer::new();
        buffer.extend_from_slice(bytes);
        buffer
    }

    fn opened(value: &V) -> Result<OwnedFrame, DecodeError> {
        value.visit(OwnedFrame::sink())
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

    /// A value's frame is the frame `to_frame` writes for it, byte for byte,
    /// walks back as the value by reference and by value, and comes out of
    /// `into_buffer` unchanged.
    #[test]
    fn a_frame_is_the_values_own_frame() {
        let value = every_variant();
        let owned = frame(&value);
        assert_eq!(owned.frame().as_bytes(), bytes(&value).as_slice());
        assert_eq!(
            record(&owned).expect("walks"),
            record(&value).expect("walks")
        );
        assert_eq!(
            record(frame(&value)).expect("walks by value"),
            record(&value).expect("walks")
        );
        assert_eq!(owned.into_buffer().risky_ref(), &bytes(&value));
    }

    /// `from_buffer` takes the buffer's bytes without a copy, keeps them
    /// as they are, and refuses what is not one frame.
    #[test]
    fn from_buffer_moves_a_frame_and_refuses_anything_else() {
        let mut written = Buffer::new();
        FrameWriter::new(&mut written)
            .scalar(None, Physical::Text("alice"))
            .expect("writes");
        let at = written.risky_ref().as_ptr();
        let moved = OwnedFrame::from_buffer(written).expect("a frame");
        assert_eq!(moved.frame().as_bytes().as_ptr(), at, "moved, not copied");
        assert_eq!(moved.frame(), frame(&V::Text("alice")).frame());
        assert_eq!(moved.into_buffer().risky_ref().as_ptr(), at, "handed back");
        for refused in [&[][..], &[ARRAY, 1, 0, 0, 0], &[tags::NULL, tags::NULL]] {
            assert_eq!(
                OwnedFrame::from_buffer(buffer(refused)).err(),
                Some(FrameError)
            );
        }
    }

    /// A typed null is a plain null once written or opened: its padding
    /// belongs to a sealed leaf. `typed_null` and `from_buffer` keep it.
    #[test]
    fn a_typed_null_is_kept_only_where_it_is_asked_for() {
        let null = OwnedFrame::null();
        assert_eq!(null.frame().as_bytes(), [tags::NULL]);
        assert!(null.frame().is_null());
        for ty in typed_nulls() {
            assert_eq!(frame(&V::TypedNull(ty)).frame(), null.frame(), "{ty:?}");
            let opened = opened(&V::TypedNull(ty)).expect("opens");
            assert_eq!(opened.frame(), null.frame(), "{ty:?} opened");

            let host = typed_null_bytes(ty);
            let kept = OwnedFrame::typed_null(ty);
            assert_eq!(kept.frame().as_bytes(), host.as_slice(), "{ty:?} kept");
            assert_eq!(record(&kept).expect("walks"), [Event::TypedNull(ty)]);
            let moved = OwnedFrame::from_buffer(buffer(&host)).expect("a frame");
            assert_eq!(moved.frame(), kept.frame(), "{ty:?} moved in as it is");
        }
    }

    /// A date, a decimal, a timestamp and a UUID keep their logical type
    /// and its parameters, written or opened. So does a logical type this
    /// build does not know, which has no kind.
    #[test]
    fn logical_types_are_kept_as_written() {
        let unknown = Logical::from_wire(200, 9).expect("an unknown logical type");
        let cases = [
            Raw(Some(Logical::Date), Physical::Int(Int::I32(19_782))),
            Raw(
                Some(Logical::Decimal { scale: 2 }),
                Physical::Int(Int::I64(150)),
            ),
            Raw(
                Some(Logical::Timestamp(TimeUnit::Micros)),
                Physical::Int(Int::I64(-2_000_000)),
            ),
            Raw(Some(Logical::Uuid), Physical::Bytes(&[7; 16])),
            Raw(Some(unknown), Physical::Int(Int::I32(1))),
        ];
        for raw in cases {
            let owned = OwnedFrame::of(raw).expect("in the model");
            assert_eq!(owned.frame().as_bytes(), bytes(&V::Raw(raw)).as_slice());
            let opened = opened(&V::Raw(raw)).expect("opens");
            assert_eq!(opened.frame(), owned.frame(), "{raw:?} opens as written");
        }
    }

    /// A scalar its logical type does not admit is refused, at the top, in
    /// a container or inside a passthrough: by `of` as the writer refuses
    /// it, and when opened as a decrypt target refuses a value.
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
                V::Map(vec![("k", V::Raw(raw))]),
                V::Pass(Box::new(V::Raw(raw))),
            ] {
                assert!(
                    matches!(OwnedFrame::of(&value), Err(FrameWriteError::Invalid)),
                    "{raw:?}"
                );
                assert!(
                    matches!(
                        opened(&value),
                        Err(DecodeError::Expected("a scalar its logical type admits"))
                    ),
                    "{raw:?} opened"
                );
            }
        }
    }

    /// The writer's refusals, as a decrypt target reports them: each is
    /// the source of a `DecodeError::Source`, and a source's own failure is
    /// that failure.
    #[test]
    fn a_write_refusal_is_a_decode_errors_source() {
        let cause = |error: &DecodeError| match error {
            DecodeError::Source(source) => source
                .inner()
                .downcast_ref::<FrameWriteError>()
                .map(ToString::to_string),
            _ => None,
        };
        for refusal in [
            FrameWriteError::TooDeep,
            FrameWriteError::DuplicateKey,
            FrameWriteError::Unwritten,
        ] {
            let message = refusal.to_string();
            assert_eq!(cause(&DecodeError::from(refusal)), Some(message));
        }
        let failed = DecodeError::from(FrameWriteError::Source(SourceError::msg("threw")));
        assert!(
            matches!(&failed, DecodeError::Source(source) if source.to_string() == "threw"),
            "{failed:?}"
        );
        assert_eq!(cause(&failed), None, "not wrapped twice");
    }

    /// A repeated key is refused, written or opened, and not named: the
    /// writer finds it among the key ranges of the frame.
    #[test]
    fn a_repeated_key_is_refused() {
        let repeated = V::Map(vec![("k", V::Null), ("k", V::Null)]);
        let hidden = V::Pass(Box::new(V::Seq(vec![repeated.clone()])));
        for value in [&repeated, &hidden] {
            assert!(matches!(
                OwnedFrame::of(value),
                Err(FrameWriteError::DuplicateKey)
            ));
            assert!(matches!(
                opened(value),
                Err(DecodeError::Source(ref source))
                    if matches!(
                        source.inner().downcast_ref::<FrameWriteError>(),
                        Some(FrameWriteError::DuplicateKey)
                    )
            ));
        }
        let distinct = V::Map(vec![("j", V::Null), ("k", V::Null)]);
        assert!(OwnedFrame::of(&distinct).is_ok());
        assert!(opened(&distinct).is_ok());
    }

    /// An opened container checks the length it said it had.
    #[test]
    fn an_opened_container_holds_the_children_it_said_it_had() {
        struct Says(usize, bool);
        impl Encrypt for &Says {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                if self.1 {
                    let mut map = sink.map(Some(self.0))?;
                    true.visit(map.entry("k")?)?;
                    map.end()
                } else {
                    let mut seq = sink.seq(Some(self.0))?;
                    true.visit(seq.element()?)?;
                    seq.end()
                }
            }
        }
        for map in [false, true] {
            assert!(Says(1, map).visit(OwnedFrame::sink()).is_ok());
            assert!(matches!(
                Says(2, map).visit(OwnedFrame::sink()),
                Err(DecodeError::Source(ref source))
                    if matches!(
                        source.inner().downcast_ref::<FrameWriteError>(),
                        Some(FrameWriteError::CountMismatch)
                    )
            ));
        }
    }

    /// A source that drops a child sink unwritten, leaves a container
    /// unended, or nests too deep, is refused rather than kept as bytes
    /// that are no frame.
    #[test]
    fn an_unfinished_value_is_refused() {
        let refused = |result: Result<OwnedFrame, DecodeError>, want: FrameWriteError| {
            matches!(
                result,
                Err(DecodeError::Source(ref source))
                    if source.inner().downcast_ref::<FrameWriteError>().map(ToString::to_string)
                        == Some(want.to_string())
            )
        };
        assert!(matches!(
            OwnedFrame::of(&V::DropsAChild),
            Err(FrameWriteError::Unwritten)
        ));
        assert!(refused(opened(&V::DropsAChild), FrameWriteError::Unwritten));
        assert!(matches!(
            OwnedFrame::of(&V::Unended),
            Err(FrameWriteError::Unfinished)
        ));
        assert!(refused(opened(&V::Unended), FrameWriteError::Unfinished));
        let too_deep = (0..=crate::frame::MAX_DEPTH).fold(V::Null, |inner, _| V::Seq(vec![inner]));
        assert!(matches!(
            OwnedFrame::of(&too_deep),
            Err(FrameWriteError::TooDeep)
        ));
        assert!(refused(opened(&too_deep), FrameWriteError::TooDeep));
        let too_deep_map =
            (0..=crate::frame::MAX_DEPTH).fold(V::Null, |inner, _| V::Map(vec![("k", inner)]));
        assert!(refused(opened(&too_deep_map), FrameWriteError::TooDeep));
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
        struct HidesFails;
        impl Encrypt for &HidesFails {
            fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
                sink.passthrough(&Fails)
            }
        }
        assert!(matches!(
            OwnedFrame::of(&Fails),
            Err(FrameWriteError::Source(ref source)) if source.to_string() == "getter threw"
        ));
        assert!(matches!(
            (&HidesFails).visit(OwnedFrame::sink()),
            Err(DecodeError::Source(ref source)) if source.to_string() == "getter threw"
        ));
    }

    /// Every value opens to the frame it was written as, and a container
    /// is written in one buffer: its children are never copied.
    #[test]
    fn opening_writes_the_frame_it_reads() {
        for value in [
            every_variant(),
            V::Text("x"),
            V::Null,
            V::I32(1),
            V::Pass(Box::new(V::Text("p"))),
            V::Seq(vec![V::Map(vec![("a", V::Seq(vec![V::I32(1)]))])]),
        ] {
            let opened = opened(&value).expect("opens");
            assert_eq!(opened.frame(), frame(&value).frame());
        }
    }

    /// The frame an `OwnedFrame` lends is its buffer, not a copy.
    #[test]
    fn the_frame_is_the_buffer() {
        let owned = frame(&V::Seq(vec![V::Text("a")]));
        let lent = owned.frame();
        assert_eq!(
            lent.as_bytes(),
            bytes(&V::Seq(vec![V::Text("a")])).as_slice()
        );
        let again = owned.frame();
        assert_eq!(lent.as_bytes().as_ptr(), again.as_bytes().as_ptr());
        assert_eq!(lent.kind(), Some(ValueKind::Array));
    }

    /// A zeroized frame is wiped and holds the plain null, so it is still
    /// one frame: it reads, walks and seals as a null.
    #[test]
    fn a_zeroized_frame_holds_the_null() {
        let mut owned = frame(&V::Seq(vec![V::Pass(Box::new(V::Text("p")))]));
        owned.zeroize();
        assert_eq!(owned.frame().as_bytes(), [tags::NULL]);
        assert!(owned.frame().is_null());
        assert_eq!(
            record(&owned).expect("walks"),
            [Event::Scalar(None, Owned::Null)]
        );
        assert_eq!(owned.into_buffer().risky_ref(), &[tags::NULL]);
    }

    #[test]
    fn debug_redacts_the_frame() {
        let shown = format!("{:?}", frame(&V::Text("secret")));
        assert!(shown.ends_with("OwnedFrame(\"***\")"), "{shown}");
        assert!(!shown.contains("secret"), "{shown}");
    }

    /// The sinks an opened container hands its children are frame writers
    /// reporting the target's error, at the next depth down.
    #[test]
    fn an_opened_containers_children_write_into_it() {
        let mut seq = OwnedFrame::sink().seq(None).expect("opens");
        assert_eq!(seq.element().expect("a child").depth(), 1);
        let seq = SeqSink::end(seq).err();
        assert!(seq.is_some(), "the child was dropped unwritten");

        let mut map = OwnedFrame::sink().map(None).expect("opens");
        map.entry("k")
            .expect("a child")
            .scalar(None, Physical::Bool(true))
            .expect("writes");
        let opened = MapSink::end(map).expect("ends");
        assert_eq!(
            opened.frame(),
            frame(&V::Map(vec![("k", V::Bool(true))])).frame()
        );
        // The public writer's containers report the writer's own error.
        let mut out = Buffer::new();
        let _: FrameSeq<'_> = FrameWriter::new(&mut out).seq(None).expect("opens");
        let mut out = Buffer::new();
        let _: FrameMap<'_> = FrameWriter::new(&mut out).map(None).expect("opens");
    }
}
