//! [`ValueFrame`]: a plaintext whose type is known only at run time, held as
//! one value in vitaminc's transport frame.
//!
//! A binding hands the engine frame bytes. Read them with
//! [`ValueFrame::from_bytes`], which refuses anything outside the
//! [value model](ValueFrame#the-value-model), or check a record source in
//! place with [`ValueFrame::check`]. A Rust value becomes a frame with
//! [`ValueFrame::of`]. A `ValueFrame` is a source ([`Encrypt`]), so it is
//! sealed, indexed or written into another frame by walking it into that
//! sink. It is also a decrypt target ([`Decrypt`]), so an opened value comes
//! back as a frame. The bytes are kept in a [`Protected`] buffer that is
//! wiped when it drops, and [`ValueFrame::into_inner`] hands them back to the
//! binding still protected.
//!
//! ```
//! use stack_encrypt::dynamic::{ValueFrame, ValueKind};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let frame = ValueFrame::of("alice")?;
//! assert_eq!(frame.kind(), Some(ValueKind::String));
//!
//! // The same value, as a binding would hand it over.
//! let from_host = ValueFrame::from_bytes(frame.risky_ref())?;
//! assert_eq!(from_host.risky_ref(), frame.risky_ref());
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::sync::Arc;

use vitaminc_aead::frame::{Frame, FrameError, FrameMap, FrameSeq, FrameWriteError, FrameWriter};
use vitaminc_aead::plaintext::kinds::timestamp_nanos;
use vitaminc_aead::plaintext::{
    Error as _, FixedType, Float, Int, Logical, MapSink, Physical, SeqSink, Sink, SourceError,
    TimeUnit, Width,
};
use vitaminc_aead::{DecodeError, Decrypt, Encrypt};
use vitaminc_protected::{Controlled, OpaqueDebug, Protected};

use super::ValueKind;
use crate::plan::IntoLabel;
use crate::{Label, LabelError};

/// One value in the engine's [value model](#the-value-model), as a
/// transport frame: the plaintext of a record field, an opened value, a
/// query's input.
///
/// The bytes are exactly one well-formed frame with no repeated map key and
/// no scalar outside the model, held in a [`Protected`] buffer that is
/// wiped when it drops. A `ValueFrame` is a source ([`Encrypt`]) that walks
/// its own bytes in place, and a decrypt target ([`Decrypt`]) that writes
/// what it opens straight into a frame, so a dynamic plaintext passes from
/// a host to the sealing sink, and from an opened leaf back to the host,
/// with no value tree in between.
///
/// `Debug` ([`OpaqueDebug`]) names the type and masks the frame, which is
/// plaintext.
///
/// # The value model
///
/// A frame can carry any of vitaminc's scalars. The engine admits a subset,
/// the *value model*: null, `undefined`, booleans, integers of every width
/// (`i8` to `u128`, each kept at its own width), both floats, text, bytes,
/// and three logical types: a date, a decimal (its scale kept), and a
/// timestamp, read in nanoseconds whatever unit it arrives in, which is the
/// unit vitaminc's `TIMESTAMP` leaf carries; and sequences, maps and
/// passthroughs of them. A uuid, and a logical type this build does not
/// know, are refused, as is a date, decimal or timestamp outside vitaminc's
/// range. Every [`ValueFrame`] is in the model: it is written through the
/// sink adapter that holds these rules, so a frame from a host and a frame
/// opened from a ciphertext are read the same way.
#[derive(OpaqueDebug)]
pub struct ValueFrame(Protected<Vec<u8>>);

/// Why [`ValueFrame::from_bytes`] or [`ValueFrame::check`] refused its bytes.
#[derive(Debug, thiserror::Error)]
pub enum FromFrameError {
    /// The bytes are not exactly one well-formed frame.
    #[error(transparent)]
    Frame(FrameError),
    /// The frame holds a value outside the value model.
    #[error(transparent)]
    Value(DecodeError),
}

impl ValueFrame {
    /// The frame of any source, in the value model.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Expected`] for a scalar outside the model (a uuid, a
    /// logical type this build does not know, a date, decimal or timestamp
    /// outside vitaminc's range), [`DecodeError::DuplicateKey`] for a map with a
    /// repeated key, and [`DecodeError::Source`] for a source that fails or
    /// a value deeper or longer than a frame carries.
    pub fn of<P: Encrypt>(value: P) -> Result<Self, DecodeError> {
        write(|writer| value.visit(Modeled::new(writer)))
    }

    /// Read one value from frame bytes a host handed over.
    ///
    /// A typed null in the bytes reads as a plain null: the value this
    /// returns does not remember the type, so sealing it does not pad it to
    /// the type's length. To store a field's absent values padded, give the
    /// field `"null": "sealed"` in its plan ([`FieldPlan::with_null`]).
    ///
    /// [`FieldPlan::with_null`]: crate::dynamic::FieldPlan::with_null
    ///
    /// # Errors
    ///
    /// [`FromFrameError::Frame`] when the
    /// bytes are not exactly one frame, and
    /// [`FromFrameError::Value`] as
    /// [`of`](Self::of) refuses a value.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FromFrameError> {
        let frame = Frame::parse(bytes).map_err(FromFrameError::Frame)?;
        Self::of(frame).map_err(FromFrameError::Value)
    }

    /// Check frame bytes a host handed over as [`from_bytes`](Self::from_bytes)
    /// does, and return them as a [`Frame`] to walk in place, without
    /// copying the value into a buffer of its own. For a source that is
    /// walked once and dropped, such as a record a binding encrypts: the
    /// split copies each field into its own frame, so a whole-source copy
    /// first would be one copy of the plaintext too many.
    ///
    /// The frame parse refuses a malformed frame and a repeated key; the
    /// walk that follows writes nothing and refuses what the value model does
    /// not hold, inside a passthrough subtree too.
    ///
    /// # Errors
    ///
    /// As [`from_bytes`](Self::from_bytes).
    pub fn check(bytes: &[u8]) -> Result<Frame<'_>, FromFrameError> {
        let frame = Frame::parse(bytes).map_err(FromFrameError::Frame)?;
        frame.visit(Check).map_err(FromFrameError::Value)?;
        Ok(frame)
    }

    /// A frame this module's writers wrote from frames already in the value
    /// model: the record a decrypt assembles. Checked to be one frame.
    pub(super) fn from_written(buffer: Protected<Vec<u8>>) -> Result<Self, crate::Error> {
        let _ = Frame::parse(buffer.risky_ref()).map_err(|_| crate::Error::ResponseShape)?;
        Ok(Self(buffer))
    }

    /// The null, as a frame: what an absent value opens to.
    pub(super) fn null() -> Self {
        Self(Protected::new(vec![vitaminc_aead::tags::NULL]))
    }

    /// A typed null of `ty`, as a frame: the leaf alone. Walked into the
    /// encrypting sink it seals as a typed null, as long as a value of `ty`
    /// (vitaminc 0.8); any other sink sees a null. The value model holds a
    /// typed null of its own types only ([`model_null`]), so `ty` is one of
    /// those a [`ValueKind`] names.
    pub(super) fn typed_null(ty: FixedType) -> Self {
        let mut leaf = Protected::new(Vec::new());
        vitaminc_aead::leaf::write_typed_null(ty, leaf.risky_inner_mut());
        Self(leaf)
    }

    /// Whether the value is a null, plain or typed.
    pub(super) fn is_null(&self) -> bool {
        self.visit(super::term::OneScalar::new(
            |ty: Option<Logical>, value: Physical<'_>| match (ty, value) {
                (None, Physical::Null) => Ok(()),
                _ => Err(None),
            },
        ))
        .is_ok()
    }

    /// The frame bytes. Same chain-of-custody caveats as
    /// [`Protected::risky_ref`]: the bytes are plaintext, and the reference
    /// must not outlive its use.
    pub fn risky_ref(&self) -> &[u8] {
        self.0.risky_ref()
    }

    /// The frame bytes, still protected.
    pub fn into_inner(self) -> Protected<Vec<u8>> {
        self.0
    }

    /// The frame, for walking.
    fn frame(&self) -> Result<Frame<'_>, FrameError> {
        Frame::parse(self.0.risky_ref())
    }

    /// The value's [`ValueKind`], or `None` for a null, an `undefined` or a
    /// passthrough, which have no kind.
    pub fn kind(&self) -> Option<ValueKind> {
        self.visit(KindOf).ok().flatten()
    }

    /// The elements of a sequence, each as its own frame, in order; `None`
    /// for any other value. What a binding hands over as a list of values,
    /// a page to verify, is read this way.
    pub fn elements(&self) -> Option<Vec<ValueFrame>> {
        match self.parts() {
            Ok(Parts::Seq(items)) => Some(items),
            _ => None,
        }
    }

    /// The value's elements, each as its frame, in order, if it is a
    /// sequence; otherwise what it is.
    pub(super) fn parts(&self) -> Result<Parts, DecodeError> {
        self.visit(Split)
    }

    /// Whether the value holds a passthrough at any depth.
    pub(super) fn has_passthrough(&self) -> bool {
        self.visit(Skip::refusing_passthrough()).is_err()
    }
}

/// The value model's check with nothing written: [`ValueFrame::check`]'s
/// walk. A repeated key needs no check here, because the frame parse
/// refuses one.
struct Check;

impl Sink for Check {
    type Ok = ();
    type Error = DecodeError;
    type Seq = Check;
    type Map = Check;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<(), DecodeError> {
        model(ty, value)
            .map(drop)
            .ok_or(DecodeError::Expected(EXPECTED))
    }

    fn typed_null(self, ty: FixedType) -> Result<(), DecodeError> {
        model_null(ty)
            .map(drop)
            .ok_or(DecodeError::Expected(EXPECTED))
    }

    fn seq(self, _: Option<usize>) -> Result<Check, DecodeError> {
        Ok(Check)
    }

    fn map(self, _: Option<usize>) -> Result<Check, DecodeError> {
        Ok(Check)
    }

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<(), DecodeError> {
        value.visit(Check)
    }
}

impl SeqSink for Check {
    type Ok = ();
    type Error = DecodeError;
    type Element<'s> = Check;

    fn element(&mut self) -> Result<Check, DecodeError> {
        Ok(Check)
    }

    fn end(self) -> Result<(), DecodeError> {
        Ok(())
    }
}

impl MapSink for Check {
    type Ok = ();
    type Error = DecodeError;
    type Entry<'s> = Check;

    fn entry(&mut self, _: &str) -> Result<Check, DecodeError> {
        Ok(Check)
    }

    fn end(self) -> Result<(), DecodeError> {
        Ok(())
    }
}

/// Write one value into a fresh protected buffer.
fn write(
    f: impl FnOnce(FrameWriter<'_>) -> Result<(), DecodeError>,
) -> Result<ValueFrame, DecodeError> {
    let mut buffer = Protected::new(Vec::new());
    f(FrameWriter::new(buffer.risky_inner_mut()))?;
    Ok(ValueFrame(buffer))
}

/// Walks the frame in place: no scalar leaves the buffer except to go
/// straight to the sink.
impl Encrypt for &ValueFrame {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        // The bytes are a frame by construction; checked rather than assumed
        // because a walk must not panic.
        self.frame()
            .map_err(|error| S::Error::source(SourceError::new(error)))?
            .visit(sink)
    }
}

/// Walks the frame, then drops it, which wipes it.
impl Encrypt for ValueFrame {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (&self).visit(sink)
    }
}

/// What a frame is opened into: the opened value written straight into a
/// frame, through the value model. A container's children are each written
/// into a frame of their own as they are opened, and joined into one frame
/// when the container ends.
impl Decrypt for ValueFrame {
    type Sink = Opening;
    fn sink() -> Opening {
        Opening
    }
}

/// A deep copy into a fresh [`Protected`] buffer, which wipes on drop as the
/// original does.
impl Clone for ValueFrame {
    fn clone(&self) -> Self {
        Self(Protected::new(self.0.risky_ref().to_vec()))
    }
}

/// A text value read as a plan's context: what a data plan's
/// `"context_field"` holds (`"tenants/acme"`), parsed as a Rust chain's
/// `String` context field is ([`Label::parse`]). Anything else is
/// [`LabelError::NotText`].
impl IntoLabel for ValueFrame {
    fn into_label(self) -> Result<Label, LabelError> {
        self.visit(super::term::OneScalar::new(
            |ty: Option<Logical>, value: Physical<'_>| match (ty, value) {
                (None, Physical::Text(text)) => Ok(Label::parse(text)),
                _ => Err(None),
            },
        ))
        .unwrap_or(Err(LabelError::NotText))
    }
}

// =============================================================================
// The value model, as a sink adapter
// =============================================================================

/// What [`Modeled`] refuses a scalar with.
const EXPECTED: &str =
    "a null, bool, integer, float, string, bytes, date, timestamp or decimal in range";

/// A scalar in the value model: a timestamp as the same instant in
/// nanoseconds, every other scalar of the model as it is, or `None` for one
/// outside the model.
fn model(ty: Option<Logical>, value: Physical<'_>) -> Option<(Option<Logical>, Physical<'_>)> {
    Some(match (ty, value) {
        (None, value) => (None, value),
        (Some(Logical::Timestamp(unit)), Physical::Int(count)) => (
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I128(timestamp_nanos(unit, count)?)),
        ),
        (Some(logical @ (Logical::Undefined | Logical::Date | Logical::Decimal { .. })), value)
            if logical.admits(&value) =>
        {
            (ty, value)
        }
        _ => return None,
    })
}

/// A typed null in the value model: a timestamp's as a nanosecond
/// timestamp's, as [`model`] reads the timestamp it stands in for, every
/// other type of the model as it is, or `None` for a type outside the model
/// (a uuid, or a logical type this crate does not know).
fn model_null(ty: FixedType) -> Option<FixedType> {
    match ty.logical() {
        None | Some(Logical::Date | Logical::Decimal { .. }) => Some(ty),
        Some(Logical::Timestamp(_)) => {
            FixedType::new(Some(Logical::Timestamp(TimeUnit::Nanos)), Width::I128)
        }
        _ => None,
    }
}

/// A frame writer that holds the [value model](ValueFrame#the-value-model):
/// each scalar is read through the model before it is written, and every
/// error is a [`DecodeError`], the error a [`Decrypt`] target reports. A
/// writer for one field of a record names the field in every error it
/// reports, so a value refused while a source is split is refused naming its
/// field.
pub struct Modeled<S> {
    inner: S,
    field: Option<Arc<str>>,
}

impl<S> Modeled<S> {
    pub(super) fn new(inner: S) -> Self {
        Self { inner, field: None }
    }

    fn in_field(inner: S, field: &str) -> Self {
        Self {
            inner,
            field: Some(field.into()),
        }
    }

    fn child<T>(&self, inner: T) -> Modeled<T> {
        Modeled {
            inner,
            field: self.field.clone(),
        }
    }

    /// `error`, naming this writer's field if it has one.
    fn fault(&self, error: DecodeError) -> DecodeError {
        match &self.field {
            Some(field) => DecodeError::Source(SourceError::new(FieldFault {
                field: field.to_string(),
                error,
            })),
            None => error,
        }
    }

    fn written(&self, error: FrameWriteError) -> DecodeError {
        self.fault(decode_error(error))
    }
}

/// A value refused while one field of a record source was written: the
/// field, and why.
#[derive(Debug, thiserror::Error)]
#[error("field {field}: {error}")]
pub(super) struct FieldFault {
    pub(super) field: String,
    pub(super) error: DecodeError,
}

/// A frame writer's refusal as a decode error. A repeated key is reported
/// where the key is known ([`Modeled::entry`]). A value the model does not
/// hold, or a repeated key, inside a passthrough subtree reaches here wrapped
/// as the writer's source error ([`ModelOnly`] can only return the writer's
/// error type), and is unwrapped, so it is refused as the same `Expected` or
/// `DuplicateKey` a sealed value is.
fn decode_error(error: FrameWriteError) -> DecodeError {
    match error {
        FrameWriteError::Source(error) => match error.inner().downcast_ref::<DecodeError>() {
            Some(DecodeError::Expected(expected)) => DecodeError::Expected(expected),
            Some(DecodeError::DuplicateKey(key)) => DecodeError::duplicate_key(key),
            _ => DecodeError::Source(error),
        },
        FrameWriteError::Invalid => DecodeError::Expected(EXPECTED),
        other => DecodeError::Source(SourceError::new(other)),
    }
}

impl<'o> Sink for Modeled<FrameWriter<'o>> {
    type Ok = ();
    type Error = DecodeError;
    type Seq = Modeled<FrameSeq<'o>>;
    type Map = Modeled<FrameMap<'o>>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<(), DecodeError> {
        let Some((ty, value)) = model(ty, value) else {
            return Err(self.fault(DecodeError::Expected(EXPECTED)));
        };
        let Self { inner, field } = self;
        inner
            .scalar(ty, value)
            .map_err(|error| Modeled { inner: (), field }.written(error))
    }

    fn typed_null(self, ty: FixedType) -> Result<(), DecodeError> {
        let Some(ty) = model_null(ty) else {
            return Err(self.fault(DecodeError::Expected(EXPECTED)));
        };
        let Self { inner, field } = self;
        inner
            .typed_null(ty)
            .map_err(|error| Modeled { inner: (), field }.written(error))
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, DecodeError> {
        let Self { inner, field } = self;
        let at = Modeled { inner: (), field };
        match inner.seq(len) {
            Ok(seq) => Ok(at.child(seq)),
            Err(error) => Err(at.written(error)),
        }
    }

    fn map(self, len: Option<usize>) -> Result<Self::Map, DecodeError> {
        let Self { inner, field } = self;
        let at = Modeled { inner: (), field };
        match inner.map(len) {
            Ok(map) => Ok(at.child(map)),
            Err(error) => Err(at.written(error)),
        }
    }

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<(), DecodeError> {
        let Self { inner, field } = self;
        inner
            .passthrough(ModeledSource(value))
            .map_err(|error| Modeled { inner: (), field }.written(error))
    }
}

impl SeqSink for Modeled<FrameSeq<'_>> {
    type Ok = ();
    type Error = DecodeError;
    type Element<'s>
        = Modeled<FrameWriter<'s>>
    where
        Self: 's;

    fn element(&mut self) -> Result<Modeled<FrameWriter<'_>>, DecodeError> {
        let field = self.field.clone();
        match self.inner.element() {
            Ok(writer) => Ok(Modeled {
                inner: writer,
                field,
            }),
            Err(error) => Err(Modeled { inner: (), field }.written(error)),
        }
    }

    fn end(self) -> Result<(), DecodeError> {
        let Self { inner, field } = self;
        inner
            .end()
            .map_err(|error| Modeled { inner: (), field }.written(error))
    }
}

impl MapSink for Modeled<FrameMap<'_>> {
    type Ok = ();
    type Error = DecodeError;
    type Entry<'s>
        = Modeled<FrameWriter<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Modeled<FrameWriter<'_>>, DecodeError> {
        let field = self.field.clone();
        match self.inner.entry(key) {
            Ok(writer) => Ok(Modeled {
                inner: writer,
                field,
            }),
            Err(FrameWriteError::DuplicateKey) => {
                Err(Modeled { inner: (), field }.fault(DecodeError::duplicate_key(key)))
            }
            Err(error) => Err(Modeled { inner: (), field }.written(error)),
        }
    }

    fn end(self) -> Result<(), DecodeError> {
        let Self { inner, field } = self;
        inner
            .end()
            .map_err(|error| Modeled { inner: (), field }.written(error))
    }
}

/// A passthrough subtree, walked through the value model too: what it
/// carries is held to the same rules as what is sealed beside it.
#[derive(Clone)]
struct ModeledSource<P>(P);

impl<P: Encrypt> Encrypt for ModeledSource<P> {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        self.0.visit(ModelOnly(sink))
    }
}

/// [`model`] in front of any sink, keeping that sink's error: the
/// passthrough half of [`Modeled`], whose inner writer reports frame errors.
/// A map refuses a repeated key itself, naming it, before the writer can
/// refuse it as a bare frame error.
struct ModelOnly<S>(S);

/// A map under [`ModelOnly`], with the keys it has been given. A
/// passthrough is not plaintext, so its keys may be kept.
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
        match model(ty, value) {
            Some((ty, value)) => self.0.scalar(ty, value),
            None => Err(S::Error::source(SourceError::new(DecodeError::Expected(
                EXPECTED,
            )))),
        }
    }

    fn typed_null(self, ty: FixedType) -> Result<S::Ok, S::Error> {
        match model_null(ty) {
            Some(ty) => self.0.typed_null(ty),
            None => Err(S::Error::source(SourceError::new(DecodeError::Expected(
                EXPECTED,
            )))),
        }
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

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<S::Ok, S::Error> {
        self.0.passthrough(ModeledSource(value))
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
// One level of a value: its children, each as a frame
// =============================================================================

/// One level of a value: a sequence's elements, each written into a frame of
/// its own, or what the value is when it is not a sequence.
pub(super) enum Parts {
    /// A scalar.
    Scalar,
    /// A passthrough.
    Passthrough,
    /// A map.
    Map,
    /// A sequence's elements, in order.
    Seq(Vec<ValueFrame>),
}

/// The sink of [`ValueFrame::parts`]: at the top, it records what the value
/// is; each child is walked into its own [`Modeled`] frame writer.
struct Split;

impl Sink for Split {
    type Ok = Parts;
    type Error = DecodeError;
    type Seq = Children<Parts>;
    type Map = Skip<Parts>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<Parts, DecodeError> {
        let _ = model(ty, value).ok_or(DecodeError::Expected(EXPECTED))?;
        Ok(Parts::Scalar)
    }

    fn typed_null(self, ty: FixedType) -> Result<Parts, DecodeError> {
        let _ = model_null(ty).ok_or(DecodeError::Expected(EXPECTED))?;
        Ok(Parts::Scalar)
    }

    fn seq(self, _: Option<usize>) -> Result<Children<Parts>, DecodeError> {
        Ok(Children::new(false, parts))
    }

    fn map(self, _: Option<usize>) -> Result<Skip<Parts>, DecodeError> {
        Ok(Skip::ending(Parts::Map, false))
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<Parts, DecodeError> {
        Ok(Parts::Passthrough)
    }
}

fn parts(_: bool, children: Vec<(Option<String>, ValueFrame)>) -> Result<Parts, DecodeError> {
    Ok(Parts::Seq(
        children.into_iter().map(|(_, value)| value).collect(),
    ))
}

/// What a container's children become when it ends: whether it is a map,
/// and each child's key (for a map) and frame.
type Finish<T> = fn(bool, Vec<(Option<String>, ValueFrame)>) -> Result<T, DecodeError>;

/// The children of one container, each written into its own frame as it is
/// walked, and handed to `finish` when the container ends. The map form
/// keeps a repeated key for `finish` to refuse.
pub struct Children<T> {
    map: bool,
    children: Vec<(Option<String>, Protected<Vec<u8>>)>,
    finish: Finish<T>,
}

impl<T> Children<T> {
    fn new(map: bool, finish: Finish<T>) -> Self {
        Self {
            map,
            children: Vec::new(),
            finish,
        }
    }

    fn next(&mut self, key: Option<&str>) -> Modeled<FrameWriter<'_>> {
        self.children
            .push((key.map(str::to_owned), Protected::new(Vec::new())));
        let buffer = match self.children.last_mut() {
            Some((_, buffer)) => buffer,
            // Pushed on the line above.
            None => unreachable!(),
        };
        Modeled::new(FrameWriter::new(buffer.risky_inner_mut()))
    }

    fn finish(self) -> Result<T, DecodeError> {
        let children = self
            .children
            .into_iter()
            .map(|(key, buffer)| (key, ValueFrame(buffer)))
            .collect();
        (self.finish)(self.map, children)
    }
}

impl<T> SeqSink for Children<T> {
    type Ok = T;
    type Error = DecodeError;
    type Element<'s>
        = Modeled<FrameWriter<'s>>
    where
        Self: 's;

    fn element(&mut self) -> Result<Modeled<FrameWriter<'_>>, DecodeError> {
        Ok(self.next(None))
    }

    fn end(self) -> Result<T, DecodeError> {
        self.finish()
    }
}

impl<T> MapSink for Children<T> {
    type Ok = T;
    type Error = DecodeError;
    type Entry<'s>
        = Modeled<FrameWriter<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Modeled<FrameWriter<'_>>, DecodeError> {
        Ok(self.next(Some(key)))
    }

    fn end(self) -> Result<T, DecodeError> {
        self.finish()
    }
}

// =============================================================================
// Opening into a frame
// =============================================================================

/// The [`Decrypt`] sink of a [`ValueFrame`]: writes the opened value into a
/// frame through the value model. A scalar or a passthrough is written
/// directly; a container's children are written into frames of their own as
/// they are opened (the sink owns no buffer for a child writer to borrow
/// until the container exists), and the container is written around them
/// when it ends, by walking each child's frame into vitaminc's
/// [`FrameWriter`].
pub struct Opening;

impl Sink for Opening {
    type Ok = ValueFrame;
    type Error = DecodeError;
    type Seq = Children<ValueFrame>;
    type Map = Children<ValueFrame>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<ValueFrame, DecodeError> {
        write(|writer| Modeled::new(writer).scalar(ty, value))
    }

    fn typed_null(self, ty: FixedType) -> Result<ValueFrame, DecodeError> {
        write(|writer| Modeled::new(writer).typed_null(ty))
    }

    fn seq(self, _: Option<usize>) -> Result<Children<ValueFrame>, DecodeError> {
        Ok(Children::new(false, join))
    }

    fn map(self, _: Option<usize>) -> Result<Children<ValueFrame>, DecodeError> {
        Ok(Children::new(true, join))
    }

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<ValueFrame, DecodeError> {
        write(|writer| Modeled::new(writer).passthrough(value))
    }
}

/// Write a container around its children's frames. A repeated key is
/// refused, as an object holds each key once.
fn join(map: bool, children: Vec<(Option<String>, ValueFrame)>) -> Result<ValueFrame, DecodeError> {
    write(|writer| {
        let count = Some(children.len());
        if map {
            let mut entries = Modeled::new(writer).map(count)?;
            let mut keys = BTreeSet::new();
            for (key, child) in &children {
                let key = key.as_deref().unwrap_or_default();
                if !keys.insert(key) {
                    return Err(DecodeError::duplicate_key(key));
                }
                child.visit(entries.entry(key)?)?;
            }
            entries.end()
        } else {
            let mut elements = Modeled::new(writer).seq(count)?;
            for (_, child) in &children {
                child.visit(elements.element()?)?;
            }
            elements.end()
        }
    })
}

// =============================================================================
// Reading without copying: a value's kind, and its passthroughs
// =============================================================================

/// A sink that reads nothing and accepts everything, or everything but a
/// passthrough: for walking past a value, or checking one holds none.
pub(super) struct Skip<T> {
    refuse_passthrough: bool,
    ok: PhantomData<fn() -> T>,
    value: Option<T>,
}

impl<T> Skip<T> {
    fn ending(value: T, refuse_passthrough: bool) -> Self {
        Self {
            refuse_passthrough,
            ok: PhantomData,
            value: Some(value),
        }
    }
}

impl Skip<()> {
    fn refusing_passthrough() -> Self {
        Self::ending((), true)
    }
}

impl<T> Skip<T> {
    fn done(self) -> Result<T, DecodeError> {
        self.value.ok_or(DecodeError::Expected("a value"))
    }

    fn child(&self) -> Skip<()> {
        Skip::ending((), self.refuse_passthrough)
    }
}

impl<T> Sink for Skip<T> {
    type Ok = T;
    type Error = DecodeError;
    type Seq = Self;
    type Map = Self;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<T, DecodeError> {
        self.done()
    }

    fn typed_null(self, _: FixedType) -> Result<T, DecodeError> {
        self.done()
    }

    fn seq(self, _: Option<usize>) -> Result<Self, DecodeError> {
        Ok(self)
    }

    fn map(self, _: Option<usize>) -> Result<Self, DecodeError> {
        Ok(self)
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<T, DecodeError> {
        if self.refuse_passthrough {
            return Err(DecodeError::Expected("no passthrough"));
        }
        self.done()
    }
}

impl<T> SeqSink for Skip<T> {
    type Ok = T;
    type Error = DecodeError;
    type Element<'s>
        = Skip<()>
    where
        Self: 's;

    fn element(&mut self) -> Result<Skip<()>, DecodeError> {
        Ok(self.child())
    }

    fn end(self) -> Result<T, DecodeError> {
        self.done()
    }
}

impl<T> MapSink for Skip<T> {
    type Ok = T;
    type Error = DecodeError;
    type Entry<'s>
        = Skip<()>
    where
        Self: 's;

    fn entry(&mut self, _: &str) -> Result<Skip<()>, DecodeError> {
        Ok(self.child())
    }

    fn end(self) -> Result<T, DecodeError> {
        self.done()
    }
}

/// The sink of [`ValueFrame::kind`]: a scalar's kind, or a container's,
/// walking past its children.
struct KindOf;

impl Sink for KindOf {
    type Ok = Option<ValueKind>;
    type Error = DecodeError;
    type Seq = Skip<Option<ValueKind>>;
    type Map = Skip<Option<ValueKind>>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<Self::Ok, DecodeError> {
        Ok(scalar_kind(ty, &value))
    }

    /// A typed null is a null, which has no kind.
    fn typed_null(self, _: FixedType) -> Result<Self::Ok, DecodeError> {
        self.scalar(None, Physical::Null)
    }

    fn seq(self, _: Option<usize>) -> Result<Self::Seq, DecodeError> {
        Ok(Skip::ending(Some(ValueKind::Array), false))
    }

    fn map(self, _: Option<usize>) -> Result<Self::Map, DecodeError> {
        Ok(Skip::ending(Some(ValueKind::Object), false))
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<Self::Ok, DecodeError> {
        Ok(None)
    }
}

/// The kind of one scalar in the value model, or `None` for a null, an
/// `undefined`, or a scalar outside the model.
pub(super) fn scalar_kind(ty: Option<Logical>, value: &Physical<'_>) -> Option<ValueKind> {
    let (ty, value) = model(ty, *value)?;
    Some(match (ty, value) {
        (Some(Logical::Date), _) => ValueKind::Date,
        (Some(Logical::Timestamp(_)), _) => ValueKind::Timestamp,
        (Some(Logical::Decimal { .. }), _) => ValueKind::Decimal,
        (Some(_), _) | (None, Physical::Null) => return None,
        (None, Physical::Bool(_)) => ValueKind::Bool,
        (None, Physical::Int(int)) => match int {
            Int::I8(_) => ValueKind::Int8,
            Int::I16(_) => ValueKind::Int16,
            Int::I32(_) => ValueKind::Int32,
            Int::I64(_) => ValueKind::Int64,
            Int::I128(_) => ValueKind::Int128,
            Int::U8(_) => ValueKind::UInt8,
            Int::U16(_) => ValueKind::UInt16,
            Int::U32(_) => ValueKind::UInt32,
            Int::U64(_) => ValueKind::UInt64,
            Int::U128(_) => ValueKind::UInt128,
        },
        (None, Physical::Float(Float::F32(_))) => ValueKind::Float32,
        (None, Physical::Float(Float::F64(_))) => ValueKind::Float64,
        (None, Physical::Text(_)) => ValueKind::String,
        (None, Physical::Bytes(_)) => ValueKind::Bytes,
    })
}

// =============================================================================
// A record source, split into its rows and each row's fields
// =============================================================================

/// One row of a record source: its entries, each value written into its
/// own frame as the source is walked, in source order with a repeated key
/// kept; or `None` for a row that is not a map.
pub(super) type SourceRow = Option<Vec<(String, ValueFrame)>>;

/// A record source split by [`split_rows`]: one row, or a batch.
pub(super) enum SourceRows {
    /// A map: one row.
    One(SourceRow),
    /// A sequence: each element a row.
    Batch(Vec<SourceRow>),
}

/// Walk a record source once, writing each field's value into a frame of its
/// own through the value model. The source is a map (one row) or a sequence
/// of maps (a batch); anything else, at the top or as a batch element, is a
/// row that is not a map. A value the model refuses fails the walk with a
/// [`FieldFault`] naming its field.
pub(super) fn split_rows<P: Encrypt>(source: P) -> Result<SourceRows, DecodeError> {
    source.visit(RowsSink)
}

/// Where a finished row goes: back to the caller, or into a batch.
pub(super) trait PutRow {
    type Ok;
    fn put(self, row: SourceRow) -> Self::Ok;
}

/// The top of a source: the row is the result.
pub(super) struct TopRow;

impl PutRow for TopRow {
    type Ok = SourceRows;
    fn put(self, row: SourceRow) -> SourceRows {
        SourceRows::One(row)
    }
}

/// The next row of a batch.
pub(super) struct BatchRow<'s>(&'s mut Vec<SourceRow>);

impl PutRow for BatchRow<'_> {
    type Ok = ();
    fn put(self, row: SourceRow) {
        self.0.push(row);
    }
}

/// The top of a record source.
struct RowsSink;

impl Sink for RowsSink {
    type Ok = SourceRows;
    type Error = DecodeError;
    type Seq = BatchSink;
    type Map = RowMap<TopRow>;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<SourceRows, DecodeError> {
        Ok(SourceRows::One(None))
    }

    fn typed_null(self, _: FixedType) -> Result<SourceRows, DecodeError> {
        Ok(SourceRows::One(None))
    }

    fn seq(self, _: Option<usize>) -> Result<BatchSink, DecodeError> {
        Ok(BatchSink(Vec::new()))
    }

    fn map(self, _: Option<usize>) -> Result<RowMap<TopRow>, DecodeError> {
        Ok(RowMap::new(TopRow))
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<SourceRows, DecodeError> {
        Ok(SourceRows::One(None))
    }
}

/// A batch: one row per element.
pub(super) struct BatchSink(Vec<SourceRow>);

impl SeqSink for BatchSink {
    type Ok = SourceRows;
    type Error = DecodeError;
    type Element<'s>
        = RowSink<'s>
    where
        Self: 's;

    fn element(&mut self) -> Result<RowSink<'_>, DecodeError> {
        Ok(RowSink(BatchRow(&mut self.0)))
    }

    fn end(self) -> Result<SourceRows, DecodeError> {
        Ok(SourceRows::Batch(self.0))
    }
}

/// One element of a batch: a row if it is a map, a row that is not a map
/// otherwise, whose content is walked past.
pub(super) struct RowSink<'s>(BatchRow<'s>);

impl<'s> Sink for RowSink<'s> {
    type Ok = ();
    type Error = DecodeError;
    type Seq = NotARow<'s>;
    type Map = RowMap<BatchRow<'s>>;

    fn scalar(self, _: Option<Logical>, _: Physical<'_>) -> Result<(), DecodeError> {
        self.0.put(None);
        Ok(())
    }

    fn typed_null(self, _: FixedType) -> Result<(), DecodeError> {
        self.0.put(None);
        Ok(())
    }

    fn seq(self, _: Option<usize>) -> Result<NotARow<'s>, DecodeError> {
        Ok(NotARow(self.0))
    }

    fn map(self, _: Option<usize>) -> Result<RowMap<BatchRow<'s>>, DecodeError> {
        Ok(RowMap::new(self.0))
    }

    fn passthrough<P: Encrypt + Clone>(self, _: P) -> Result<(), DecodeError> {
        self.0.put(None);
        Ok(())
    }
}

/// A batch element that is a sequence: not a row. Its elements are walked
/// past, and it is recorded when it ends.
pub(super) struct NotARow<'s>(BatchRow<'s>);

impl SeqSink for NotARow<'_> {
    type Ok = ();
    type Error = DecodeError;
    type Element<'e>
        = Skip<()>
    where
        Self: 'e;

    fn element(&mut self) -> Result<Skip<()>, DecodeError> {
        Ok(Skip::ending((), false))
    }

    fn end(self) -> Result<(), DecodeError> {
        self.0.put(None);
        Ok(())
    }
}

/// One row's entries, each written into its own frame by a writer that
/// names the entry's key in any refusal.
pub(super) struct RowMap<O> {
    out: O,
    entries: Vec<(String, Protected<Vec<u8>>)>,
}

impl<O> RowMap<O> {
    fn new(out: O) -> Self {
        Self {
            out,
            entries: Vec::new(),
        }
    }
}

impl<O: PutRow> MapSink for RowMap<O> {
    type Ok = O::Ok;
    type Error = DecodeError;
    type Entry<'s>
        = Modeled<FrameWriter<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Modeled<FrameWriter<'_>>, DecodeError> {
        self.entries
            .push((key.to_owned(), Protected::new(Vec::new())));
        let buffer = match self.entries.last_mut() {
            Some((_, buffer)) => buffer,
            // Pushed on the line above.
            None => unreachable!(),
        };
        Ok(Modeled::in_field(
            FrameWriter::new(buffer.risky_inner_mut()),
            key,
        ))
    }

    fn end(self) -> Result<O::Ok, DecodeError> {
        let row = self
            .entries
            .into_iter()
            .map(|(key, buffer)| (key, ValueFrame(buffer)))
            .collect();
        Ok(self.out.put(Some(row)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dynamic::test_frame::Tree;

    fn s(value: &str) -> Tree {
        Tree::String(value.into())
    }

    fn frame_of(value: &Tree) -> ValueFrame {
        ValueFrame::of(value).expect("in the model")
    }

    fn every_variant() -> Tree {
        Tree::Object(vec![
            ("n".to_string(), Tree::Null),
            ("u".to_string(), Tree::Undefined),
            ("b".to_string(), Tree::Bool(true)),
            ("i32".to_string(), Tree::Int32(-3)),
            ("i64".to_string(), Tree::Int64(-4)),
            ("u32".to_string(), Tree::UInt32(34)),
            ("u64".to_string(), Tree::UInt64(u64::MAX)),
            ("f32".to_string(), Tree::Float32(-0.0)),
            ("f64".to_string(), Tree::Float64(f64::NAN)),
            ("s".to_string(), s("alice")),
            ("bytes".to_string(), Tree::Bytes(vec![1, 2, 3])),
            (
                "list".to_string(),
                Tree::Array(vec![s("a"), Tree::Passthrough(Box::new(s("p")))]),
            ),
            ("empty".to_string(), Tree::Array(vec![])),
            ("none".to_string(), Tree::Object(vec![])),
        ])
    }

    /// A null that says what it stands in for, as vitaminc walks a `None`
    /// of a fixed-width type and as a host may send one in a frame.
    #[derive(Clone)]
    struct TypedNull(FixedType);

    impl Encrypt for TypedNull {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            sink.typed_null(self.0)
        }
    }

    fn fixed(ty: Option<Logical>, width: Width) -> FixedType {
        FixedType::new(ty, width).expect("a fixed-width type")
    }

    /// A typed null of each kind of type the value model holds: a plain
    /// int and float, and the three logical types, a timestamp of another
    /// unit than the model's among them.
    fn typed_nulls_in_the_model() -> Vec<FixedType> {
        vec![
            fixed(None, Width::I64),
            fixed(None, Width::F32),
            fixed(Some(Logical::Date), Width::I32),
            fixed(Some(Logical::Decimal { scale: 2 }), Width::I128),
            fixed(Some(Logical::Timestamp(TimeUnit::Micros)), Width::I64),
            fixed(Some(Logical::Timestamp(TimeUnit::Nanos)), Width::I128),
        ]
    }

    /// A uuid has a typed null, and no place in the value model.
    fn uuid_null() -> FixedType {
        fixed(Some(Logical::Uuid), Width::Bytes16)
    }

    /// The frame a host sends for a typed null: the leaf alone.
    fn typed_null_frame(ty: FixedType) -> Vec<u8> {
        let mut out = Vec::new();
        vitaminc_aead::leaf::write_typed_null(ty, &mut out);
        out
    }

    /// A typed null of a type in the model is a null in a frame: written,
    /// read from a host's bytes, or opened. Its padding belongs to a sealed
    /// leaf, not to a frame, and a null has no kind. So a host's typed null
    /// is not padded by this path.
    #[test]
    fn a_typed_null_in_the_model_is_a_null_in_its_frame() {
        let null = frame_of(&Tree::Null);
        for ty in typed_nulls_in_the_model() {
            let written = ValueFrame::of(TypedNull(ty)).expect("in the model");
            assert_eq!(written.risky_ref(), null.risky_ref(), "{ty:?} written");
            let bytes = typed_null_frame(ty);
            assert!(ValueFrame::check(&bytes).is_ok(), "{ty:?} checks");
            let read = ValueFrame::from_bytes(&bytes).expect("reads");
            assert_eq!(read.risky_ref(), null.risky_ref(), "{ty:?} read");
            let opened = TypedNull(ty).visit(Opening).expect("opens");
            assert_eq!(opened.risky_ref(), null.risky_ref(), "{ty:?} opened");
            assert_eq!(read.kind(), None, "{ty:?} has no kind");
        }
    }

    /// A typed null of a type outside the model is refused wherever a
    /// value of that type is.
    #[test]
    fn a_typed_null_outside_the_model_is_refused() {
        let uuid = uuid_null();
        assert!(matches!(
            ValueFrame::of(TypedNull(uuid)),
            Err(DecodeError::Expected(EXPECTED))
        ));
        let bytes = typed_null_frame(uuid);
        for refused in [
            ValueFrame::check(&bytes).map(drop),
            ValueFrame::from_bytes(&bytes).map(drop),
        ] {
            assert!(
                matches!(
                    refused,
                    Err(FromFrameError::Value(DecodeError::Expected(EXPECTED)))
                ),
                "{refused:?}"
            );
        }
        assert!(matches!(
            TypedNull(uuid).visit(Opening),
            Err(DecodeError::Expected(EXPECTED))
        ));
    }

    /// A host's frame of a typed null inside a passthrough.
    fn hidden_typed_null_frame(ty: FixedType) -> Vec<u8> {
        let mut out = vec![vitaminc_aead::frame::PASSTHROUGH];
        out.extend(typed_null_frame(ty));
        out
    }

    /// A passthrough holds a typed null to the same rules: one in the model
    /// is a null, written or read from a host's bytes, and a uuid's is
    /// refused.
    #[test]
    fn a_typed_null_in_a_passthrough_is_held_to_the_model() {
        let null = frame_of(&Tree::Passthrough(Box::new(Tree::Null)));
        for ty in typed_nulls_in_the_model() {
            let written = ValueFrame::of(Hidden(TypedNull(ty))).expect("in the model");
            assert_eq!(written.risky_ref(), null.risky_ref(), "{ty:?} written");
            let bytes = hidden_typed_null_frame(ty);
            assert!(ValueFrame::check(&bytes).is_ok(), "{ty:?} checks");
            let read = ValueFrame::from_bytes(&bytes).expect("reads");
            assert_eq!(read.risky_ref(), null.risky_ref(), "{ty:?} read");
        }
        assert!(matches!(
            ValueFrame::of(Hidden(TypedNull(uuid_null()))),
            Err(DecodeError::Expected(EXPECTED))
        ));
        let bytes = hidden_typed_null_frame(uuid_null());
        for refused in [
            ValueFrame::check(&bytes).map(drop),
            ValueFrame::from_bytes(&bytes).map(drop),
        ] {
            assert!(
                matches!(
                    refused,
                    Err(FromFrameError::Value(DecodeError::Expected(EXPECTED)))
                ),
                "{refused:?}"
            );
        }
    }

    /// A record source that is a typed null, or holds one as a batch
    /// element, is a row that is not a map, as a null is.
    #[test]
    fn a_typed_null_record_source_is_no_row() {
        let ty = fixed(Some(Logical::Date), Width::I32);
        let one = typed_null_frame(ty);
        let one = Frame::parse(&one).expect("a frame");
        assert!(matches!(split_rows(one), Ok(SourceRows::One(None))));
        let mut batch = vec![vitaminc_aead::frame::ARRAY, 2, 0, 0, 0];
        batch.extend(typed_null_frame(ty));
        batch.extend(typed_null_frame(ty));
        let batch = Frame::parse(&batch).expect("a frame");
        assert!(matches!(
            split_rows(batch),
            Ok(SourceRows::Batch(rows)) if rows.len() == 2 && rows.iter().all(Option::is_none)
        ));
    }

    /// A value's frame is the frame vitaminc writes for it, byte for byte,
    /// and reads back as the value.
    #[test]
    fn a_value_frame_is_the_values_own_frame() {
        let value = every_variant();
        let frame = frame_of(&value);
        assert_eq!(
            frame.risky_ref(),
            value.to_frame().expect("frames").risky_ref()
        );
        let back = Tree::from_frame(frame.risky_ref()).expect("reads back");
        assert_eq!(back, value);
        let copy = frame.clone();
        assert_eq!(copy.risky_ref(), frame.risky_ref());
        assert_ne!(copy.risky_ref().as_ptr(), frame.risky_ref().as_ptr());
        let bytes = copy.into_inner();
        assert_eq!(
            bytes.risky_ref(),
            frame.risky_ref(),
            "the frame, still protected"
        );
    }

    /// Every integer keeps its own width, at any depth: an `i8` is the
    /// `INT8` leaf, not the 32-bit one.
    #[test]
    fn every_integer_keeps_its_width() {
        use vitaminc_aead::plaintext::Raw;
        use vitaminc_aead::tags;
        for (int, tag) in [
            (Int::I8(-8), tags::INT8),
            (Int::I16(-8), tags::INT16),
            (Int::I128(-8), tags::INT128),
            (Int::U8(8), tags::UINT8),
            (Int::U16(8), tags::UINT16),
            (Int::U128(8), tags::UINT128),
        ] {
            let frame = ValueFrame::of(Raw(None, Physical::Int(int))).expect("in the model");
            assert_eq!(frame.risky_ref()[0], tag);
            let back = ValueFrame::from_bytes(frame.risky_ref()).expect("in the model");
            assert_eq!(
                back.risky_ref(),
                frame.risky_ref(),
                "read back at its width"
            );
        }
        let nested = ValueFrame::of(vec![vec![300u16]]).expect("in the model");
        let inner = ValueFrame::of(300u16).expect("in the model");
        assert!(nested.risky_ref().ends_with(inner.risky_ref()));
    }

    /// A date, a decimal and a timestamp are in the model; a timestamp in
    /// any unit is the same instant in nanoseconds, under the `TIMESTAMP`
    /// tag; a decimal keeps its scale.
    #[test]
    fn the_logical_types_of_the_model_are_kept() {
        use vitaminc_aead::plaintext::Raw;
        let date = ValueFrame::of(Raw(Some(Logical::Date), Physical::Int(Int::I32(19_782))))
            .expect("a date");
        assert_eq!(date.kind(), Some(ValueKind::Date));
        assert_eq!(date.risky_ref()[0], vitaminc_aead::tags::DATE);
        let decimal = ValueFrame::of(Raw(
            Some(Logical::Decimal { scale: 2 }),
            Physical::Int(Int::I64(150)),
        ))
        .expect("a decimal");
        assert_eq!(decimal.kind(), Some(ValueKind::Decimal));
        let one_point_five = ValueFrame::of(Raw(
            Some(Logical::Decimal { scale: 1 }),
            Physical::Int(Int::I64(15)),
        ))
        .expect("a decimal");
        assert_ne!(
            decimal.risky_ref(),
            one_point_five.risky_ref(),
            "1.50 is not 1.5"
        );
        let nanos = ValueFrame::of(Raw(
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I128(-2_000_000_000)),
        ))
        .expect("an instant");
        assert_eq!(nanos.kind(), Some(ValueKind::Timestamp));
        for (unit, count) in [
            (TimeUnit::Seconds, -2i64),
            (TimeUnit::Millis, -2_000),
            (TimeUnit::Micros, -2_000_000),
        ] {
            let other = ValueFrame::of(Raw(
                Some(Logical::Timestamp(unit)),
                Physical::Int(Int::I64(count)),
            ))
            .expect("an instant");
            assert_eq!(other.risky_ref(), nanos.risky_ref(), "{unit:?}");
        }
    }

    /// A scalar outside the model is refused wherever it is, a passthrough
    /// included, and so is a repeated key.
    /// `check` refuses exactly what `from_bytes` refuses, and hands back the
    /// bytes it was given.
    #[test]
    fn check_refuses_what_from_bytes_refuses_without_a_copy() {
        let good = every_variant();
        let bytes = ValueFrame::of(&good).expect("frames");
        let checked = ValueFrame::check(bytes.risky_ref()).expect("checks");
        assert_eq!(checked.as_bytes().as_ptr(), bytes.risky_ref().as_ptr());
        assert_eq!(checked.as_bytes(), bytes.risky_ref());
        let hidden = vitaminc_aead::to_frame(Hidden(vitaminc_aead::plaintext::Raw(
            Some(Logical::Uuid),
            Physical::Bytes(&[7; 16]),
        )))
        .expect("frames");
        let uuid = vitaminc_aead::to_frame(vitaminc_aead::plaintext::Raw(
            Some(Logical::Uuid),
            Physical::Bytes(&[7; 16]),
        ))
        .expect("frames");
        for refused in [hidden.risky_ref(), uuid.risky_ref()] {
            assert!(matches!(
                ValueFrame::check(refused),
                Err(super::FromFrameError::Value(DecodeError::Expected(_)))
            ));
            assert!(matches!(
                ValueFrame::from_bytes(refused),
                Err(super::FromFrameError::Value(DecodeError::Expected(_)))
            ));
        }
        assert!(matches!(
            ValueFrame::check(&[]),
            Err(super::FromFrameError::Frame(_))
        ));
    }

    /// A value that travels as a passthrough subtree.
    #[derive(Clone)]
    struct Hidden<P>(P);

    impl<P: Encrypt + Clone> Encrypt for Hidden<P> {
        fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
            sink.passthrough(self.0)
        }
    }

    #[test]
    fn what_the_model_does_not_hold_is_refused() {
        use vitaminc_aead::plaintext::kinds::{MAX_DATE_DAYS, MAX_TIMESTAMP_NANOS};
        use vitaminc_aead::plaintext::Raw;
        let refused =
            |value: Raw<'_>| matches!(ValueFrame::of(value), Err(DecodeError::Expected(_)));
        assert!(refused(Raw(Some(Logical::Uuid), Physical::Bytes(&[7; 16]))));
        let unknown = Logical::from_wire(200, 0).expect("an unknown logical type");
        assert!(refused(Raw(Some(unknown), Physical::Int(Int::I32(1)))));
        assert!(refused(Raw(
            Some(Logical::Date),
            Physical::Int(Int::I64(i64::from(MAX_DATE_DAYS) + 1))
        )));
        assert!(refused(Raw(
            Some(Logical::Date),
            Physical::Text("2024-01-01")
        )));
        assert!(refused(Raw(
            Some(Logical::Timestamp(TimeUnit::Nanos)),
            Physical::Int(Int::I128(MAX_TIMESTAMP_NANOS + 1))
        )));
        assert!(refused(Raw(
            Some(Logical::Timestamp(TimeUnit::Seconds)),
            Physical::Int(Int::I128(i128::MAX))
        )));
        assert!(refused(Raw(
            Some(Logical::Decimal { scale: 0 }),
            Physical::Int(Int::I128(1 << 96))
        )));
        assert!(refused(Raw(Some(Logical::Undefined), Physical::Bool(true))));
        assert!(matches!(
            ValueFrame::of(vec![Raw(Some(Logical::Uuid), Physical::Bytes(&[7; 16]))]),
            Err(DecodeError::Expected(_))
        ));
        let hidden = Tree::Passthrough(Box::new(Tree::Null));
        assert!(ValueFrame::of(&hidden).is_ok());
        // Inside a passthrough too, and refused the same way.
        let hidden = Hidden(vitaminc_aead::plaintext::Raw(
            Some(Logical::Uuid),
            Physical::Bytes(&[7; 16]),
        ));
        assert!(matches!(
            ValueFrame::of(hidden),
            Err(DecodeError::Expected(_))
        ));
        let repeated = Tree::Object(vec![("k".into(), Tree::Null), ("k".into(), Tree::Null)]);
        assert!(matches!(
            ValueFrame::of(&repeated),
            Err(DecodeError::DuplicateKey(key)) if key == "k"
        ));
        assert!(matches!(
            ValueFrame::from_bytes(&[]),
            Err(super::FromFrameError::Frame(_))
        ));
        let uuid = vitaminc_aead::to_frame(Raw(Some(Logical::Uuid), Physical::Bytes(&[7; 16])))
            .expect("frames");
        assert!(matches!(
            ValueFrame::from_bytes(uuid.risky_ref()),
            Err(super::FromFrameError::Value(DecodeError::Expected(_)))
        ));
    }

    /// Every value opens to the frame it was written as, through a walk of
    /// any source into the decrypt sink.
    #[test]
    fn opening_writes_the_frame_it_reads() {
        let value = every_variant();
        let opened = (&value).visit(ValueFrame::sink()).expect("opens");
        assert_eq!(opened.risky_ref(), frame_of(&value).risky_ref());
        for scalar in [s("x"), Tree::Null, Tree::Int64(1)] {
            let opened = (&scalar).visit(ValueFrame::sink()).expect("opens");
            assert_eq!(opened.risky_ref(), frame_of(&scalar).risky_ref());
        }
        let passthrough = Tree::Passthrough(Box::new(s("p")));
        let opened = (&passthrough).visit(ValueFrame::sink()).expect("opens");
        assert_eq!(opened.risky_ref(), frame_of(&passthrough).risky_ref());
        let repeated = Tree::Object(vec![("k".into(), Tree::Null), ("k".into(), Tree::Null)]);
        assert!(matches!(
            (&repeated).visit(ValueFrame::sink()),
            Err(DecodeError::DuplicateKey(key)) if key == "k"
        ));
    }

    #[test]
    fn a_frame_names_its_kind() {
        let cases = [
            (Tree::Null, None),
            (Tree::Undefined, None),
            (Tree::Bool(true), Some(ValueKind::Bool)),
            (Tree::Int32(1), Some(ValueKind::Int32)),
            (Tree::Int64(1), Some(ValueKind::Int64)),
            (Tree::UInt32(1), Some(ValueKind::UInt32)),
            (Tree::UInt64(1), Some(ValueKind::UInt64)),
            (Tree::Float32(1.0), Some(ValueKind::Float32)),
            (Tree::Float64(1.0), Some(ValueKind::Float64)),
            (s("a"), Some(ValueKind::String)),
            (Tree::Bytes(vec![1]), Some(ValueKind::Bytes)),
            (Tree::Array(vec![s("a")]), Some(ValueKind::Array)),
            (
                Tree::Object(vec![("k".into(), s("a"))]),
                Some(ValueKind::Object),
            ),
            (Tree::Passthrough(Box::new(s("p"))), None),
        ];
        for (value, kind) in cases {
            assert_eq!(frame_of(&value).kind(), kind, "{value:?}");
            assert_eq!(value.kind(), kind, "the tree agrees: {value:?}");
        }
        use vitaminc_aead::plaintext::Raw;
        for (int, kind) in [
            (Int::I8(1), ValueKind::Int8),
            (Int::I16(1), ValueKind::Int16),
            (Int::I128(1), ValueKind::Int128),
            (Int::U8(1), ValueKind::UInt8),
            (Int::U16(1), ValueKind::UInt16),
            (Int::U128(1), ValueKind::UInt128),
        ] {
            let frame = ValueFrame::of(Raw(None, Physical::Int(int))).expect("in the model");
            assert_eq!(frame.kind(), Some(kind));
        }
        let undefined =
            ValueFrame::of(Raw(Some(Logical::Undefined), Physical::Null)).expect("in the model");
        assert_eq!(undefined.kind(), None);
    }

    /// A sequence's parts are its elements' own frames, in order.
    #[test]
    fn parts_are_the_childrens_frames() {
        let Parts::Seq(items) = frame_of(&Tree::Array(vec![s("a"), Tree::Int32(1)]))
            .parts()
            .expect("parts")
        else {
            panic!("a sequence");
        };
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].risky_ref(), frame_of(&s("a")).risky_ref());
        assert!(matches!(
            frame_of(&Tree::Object(vec![("k".into(), s("a"))])).parts(),
            Ok(Parts::Map)
        ));
        assert!(matches!(frame_of(&s("a")).parts(), Ok(Parts::Scalar)));
        assert_eq!(
            frame_of(&Tree::Array(vec![s("a")]))
                .elements()
                .map(|items| items.len()),
            Some(1)
        );
        assert!(frame_of(&s("a")).elements().is_none());
        assert!(matches!(
            frame_of(&Tree::Passthrough(Box::new(s("p")))).parts(),
            Ok(Parts::Passthrough)
        ));
    }

    #[test]
    fn a_passthrough_is_found_at_any_depth() {
        assert!(frame_of(&every_variant()).kind().is_some());
        assert!(frame_of(&every_variant()).has_passthrough());
        assert!(!frame_of(&s("a")).has_passthrough());
        assert!(frame_of(&Tree::Passthrough(Box::new(s("p")))).has_passthrough());
        assert!(!frame_of(&Tree::Object(vec![("k".into(), s("a"))])).has_passthrough());
    }

    #[test]
    fn text_reads_as_a_label_and_nothing_else_does() {
        assert_eq!(
            frame_of(&s("tenants/acme")).into_label().expect("a label"),
            Label::parse("tenants/acme").expect("a label")
        );
        assert!(matches!(
            frame_of(&Tree::UInt32(7)).into_label(),
            Err(LabelError::NotText)
        ));
        assert!(frame_of(&s("")).into_label().is_err());
    }

    #[test]
    fn debug_redacts_the_frame() {
        let shown = format!("{:?}", frame_of(&s("secret")));
        assert!(shown.ends_with("ValueFrame(\"***\")"), "{shown}");
        assert!(!shown.contains("secret"), "{shown}");
    }
}
