//! The engine's plaintext for a value whose type is known only at run time:
//! [`ValueFrame`], one value as a transport frame.
//!
//! vitaminc ADR 0001 removed the shared value type: a value describes itself
//! once ([`Encrypt`]), and whatever consumes it is a sink. A binding hands the
//! engine a transport frame, and the frame is a source that walks its own
//! bytes in place. So the engine keeps a dynamic plaintext as its frame and
//! nothing else: a record field split out of a source, a value opened from a
//! ciphertext, a query's input. Each is written once, by vitaminc's
//! [`FrameWriter`], into a [`Protected`] buffer that is wiped when it drops,
//! and read by walking it into the next sink: the encrypting sink, a term
//! deriver, another frame writer.
//!
//! [`FfiValue`](super::FfiValue) is not plaintext's type. It is the tree a
//! binding's control data decodes into: plans, contexts, options, query
//! statistics, and configuration, which can carry credentials, so its text
//! and bytes leaves are wiped too.
//!
//! The value model the engine reads every such frame through is on
//! [`ValueFrame`].

use std::collections::BTreeSet;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use vitaminc_aead::frame::{Frame, FrameError, FrameMap, FrameSeq, FrameWriteError, FrameWriter};
use vitaminc_aead::plaintext::{
    Error as _, Float, Int, Logical, MapSink, Physical, SeqSink, Sink, SourceError,
};
use vitaminc_aead::{DecodeError, Decrypt, Encrypt};
use vitaminc_protected::{Controlled, Protected};

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
/// `Debug` names the type and nothing more: the frame is plaintext.
///
/// # The value model
///
/// A frame can carry any of vitaminc's scalars. The engine admits a subset,
/// the *value model*: null, `undefined`, booleans, integers of 32 and 64
/// bits, both floats, text and bytes, and sequences, maps and passthroughs of
/// them. An 8- or 16-bit integer is read as the 32-bit integer of its sign,
/// which holds it exactly, so a host with narrower integers (Go's `int8`)
/// seals the 32-bit leaf a plan field of that width declares. A 128-bit
/// integer and a scalar under a logical type other than `undefined` (a date,
/// a decimal) are refused. Every [`ValueFrame`] is in the model: it is
/// written through the sink adapter that holds these rules, so a frame from
/// a host and a frame opened from a ciphertext are read the same way.
pub struct ValueFrame(Protected<Vec<u8>>);

impl ValueFrame {
    /// The frame of any source, in the value model.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Expected`] for a scalar outside the model (a 128-bit
    /// integer, a date), [`DecodeError::DuplicateKey`] for a map with a
    /// repeated key, and [`DecodeError::Source`] for a source that fails or
    /// a value deeper or longer than a frame carries.
    pub fn of<P: Encrypt>(value: P) -> Result<Self, DecodeError> {
        write(|writer| value.visit(Modeled::new(writer)))
    }

    /// Read one value from frame bytes a host handed over.
    ///
    /// # Errors
    ///
    /// [`FromFrameError::Frame`](super::FromFrameError::Frame) when the
    /// bytes are not exactly one frame, and
    /// [`FromFrameError::Value`](super::FromFrameError::Value) as
    /// [`of`](Self::of) refuses a value.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, super::FromFrameError> {
        let frame = Frame::parse(bytes).map_err(super::FromFrameError::Frame)?;
        Self::of(frame).map_err(super::FromFrameError::Value)
    }

    /// A frame this module's writers wrote from frames already in the value
    /// model: the record a decrypt assembles. Checked to be one frame.
    pub(super) fn from_written(buffer: Protected<Vec<u8>>) -> Result<Self, crate::Error> {
        let _ = Frame::parse(buffer.risky_ref()).map_err(|_| crate::Error::ResponseShape)?;
        Ok(Self(buffer))
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

impl fmt::Debug for ValueFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ValueFrame(<redacted>)")
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
const EXPECTED: &str = "a null, bool, int of at most 64 bits, float, string or bytes";

/// A scalar in the value model: an 8- or 16-bit integer as the 32-bit
/// integer of its sign, every other scalar as it is, or `None` for one
/// outside the model.
fn model(ty: Option<Logical>, value: Physical<'_>) -> Option<(Option<Logical>, Physical<'_>)> {
    Some(match (ty, value) {
        (None, Physical::Int(int)) => (
            None,
            Physical::Int(match int {
                Int::I8(v) => Int::I32(v.into()),
                Int::I16(v) => Int::I32(v.into()),
                Int::U8(v) => Int::U32(v.into()),
                Int::U16(v) => Int::U32(v.into()),
                Int::I128(_) | Int::U128(_) => return None,
                other => other,
            }),
        ),
        (None, value) => (None, value),
        (Some(Logical::Undefined), Physical::Null) => (ty, value),
        _ => return None,
    })
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
/// hold inside a passthrough subtree reaches here wrapped as the writer's
/// source error ([`ModelOnly`] can only return the writer's error type), and
/// is unwrapped, so it is refused as the same `Expected` a sealed value is.
fn decode_error(error: FrameWriteError) -> DecodeError {
    match error {
        FrameWriteError::Source(error) => match error.inner().downcast_ref::<DecodeError>() {
            Some(DecodeError::Expected(expected)) => DecodeError::Expected(expected),
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
struct ModelOnly<S>(S);

impl<S: Sink> Sink for ModelOnly<S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type Seq = ModelOnly<S::Seq>;
    type Map = ModelOnly<S::Map>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<S::Ok, S::Error> {
        match model(ty, value) {
            Some((ty, value)) => self.0.scalar(ty, value),
            None => Err(S::Error::source(SourceError::new(DecodeError::Expected(
                EXPECTED,
            )))),
        }
    }

    fn seq(self, len: Option<usize>) -> Result<Self::Seq, S::Error> {
        self.0.seq(len).map(ModelOnly)
    }

    fn map(self, len: Option<usize>) -> Result<Self::Map, S::Error> {
        self.0.map(len).map(ModelOnly)
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

impl<S: MapSink> MapSink for ModelOnly<S> {
    type Ok = S::Ok;
    type Error = S::Error;
    type Entry<'s>
        = ModelOnly<S::Entry<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<Self::Entry<'_>, S::Error> {
        self.0.entry(key).map(ModelOnly)
    }

    fn end(self) -> Result<S::Ok, S::Error> {
        self.0.end()
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
    if ty.is_some() {
        return None;
    }
    Some(match value {
        Physical::Bool(_) => ValueKind::Bool,
        Physical::Int(Int::I32(_)) => ValueKind::Int32,
        Physical::Int(Int::I64(_)) => ValueKind::Int64,
        Physical::Int(Int::U32(_)) => ValueKind::UInt32,
        Physical::Int(Int::U64(_)) => ValueKind::UInt64,
        Physical::Int(_) => return None,
        Physical::Float(Float::F32(_)) => ValueKind::Float32,
        Physical::Float(Float::F64(_)) => ValueKind::Float64,
        Physical::Text(_) => ValueKind::String,
        Physical::Bytes(_) => ValueKind::Bytes,
        Physical::Null => return None,
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
    use crate::dynamic::FfiValue;

    fn s(value: &str) -> FfiValue {
        FfiValue::String(value.into())
    }

    fn frame_of(value: &FfiValue) -> ValueFrame {
        ValueFrame::of(value).expect("in the model")
    }

    fn every_variant() -> FfiValue {
        FfiValue::Object(vec![
            ("n".to_string(), FfiValue::Null),
            ("u".to_string(), FfiValue::Undefined),
            ("b".to_string(), FfiValue::Bool(true)),
            ("i32".to_string(), FfiValue::Int32(-3)),
            ("i64".to_string(), FfiValue::Int64(-4)),
            ("u32".to_string(), FfiValue::UInt32(34)),
            ("u64".to_string(), FfiValue::UInt64(u64::MAX)),
            ("f32".to_string(), FfiValue::Float32(-0.0)),
            ("f64".to_string(), FfiValue::Float64(f64::NAN)),
            ("s".to_string(), s("alice")),
            (
                "bytes".to_string(),
                FfiValue::Bytes(Protected::new(vec![1, 2, 3])),
            ),
            (
                "list".to_string(),
                FfiValue::Array(vec![s("a"), FfiValue::Passthrough(Box::new(s("p")))]),
            ),
            ("empty".to_string(), FfiValue::Array(vec![])),
            ("none".to_string(), FfiValue::Object(vec![])),
        ])
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
        let back = FfiValue::from_frame(frame.risky_ref()).expect("reads back");
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

    /// An 8- or 16-bit integer is the 32-bit integer of its sign, at any
    /// depth and inside a passthrough, as the value tree read it.
    #[test]
    fn a_narrow_integer_is_written_at_32_bits() {
        use vitaminc_aead::plaintext::Raw;
        let narrow = vec![
            Raw(None, Physical::Int(Int::I8(-8))),
            Raw(None, Physical::Int(Int::U8(200))),
        ];
        let frame = ValueFrame::of(narrow).expect("in the model");
        let wide = FfiValue::Array(vec![FfiValue::Int32(-8), FfiValue::UInt32(200)]);
        assert_eq!(frame.risky_ref(), frame_of(&wide).risky_ref());
        let nested = ValueFrame::of(vec![vec![300u16]]).expect("in the model");
        let wide = FfiValue::Array(vec![FfiValue::Array(vec![FfiValue::UInt32(300)])]);
        assert_eq!(nested.risky_ref(), frame_of(&wide).risky_ref());
        let i16_frame = vitaminc_aead::to_frame(i16::MIN).expect("frames");
        assert_eq!(
            FfiValue::from_frame(
                ValueFrame::from_bytes(i16_frame.risky_ref())
                    .expect("in the model")
                    .risky_ref()
            )
            .expect("reads back"),
            FfiValue::Int32(i16::MIN.into())
        );
    }

    /// A scalar outside the model is refused wherever it is, a passthrough
    /// included, and so is a repeated key.
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
        assert!(matches!(
            ValueFrame::of(7u128),
            Err(DecodeError::Expected(_))
        ));
        assert!(matches!(
            ValueFrame::of(vec![-7i128]),
            Err(DecodeError::Expected(_))
        ));
        let date = vitaminc_aead::plaintext::Raw(Some(Logical::Date), Physical::Int(Int::I32(1)));
        assert!(matches!(
            ValueFrame::of(date),
            Err(DecodeError::Expected(_))
        ));
        let hidden = FfiValue::Passthrough(Box::new(FfiValue::Null));
        assert!(ValueFrame::of(&hidden).is_ok());
        // Inside a passthrough too, and refused the same way.
        let hidden = Hidden(vitaminc_aead::plaintext::Raw(
            None,
            Physical::Int(Int::I128(7)),
        ));
        assert!(matches!(
            ValueFrame::of(hidden),
            Err(DecodeError::Expected(_))
        ));
        let repeated = FfiValue::Object(vec![
            ("k".into(), FfiValue::Null),
            ("k".into(), FfiValue::Null),
        ]);
        assert!(matches!(
            ValueFrame::of(&repeated),
            Err(DecodeError::DuplicateKey(key)) if key == "k"
        ));
        assert!(matches!(
            ValueFrame::from_bytes(&[]),
            Err(super::super::FromFrameError::Frame(_))
        ));
        let uuid = vitaminc_aead::to_frame(vitaminc_aead::plaintext::Raw(
            Some(Logical::Uuid),
            Physical::Bytes(&[7; 16]),
        ))
        .expect("frames");
        assert!(matches!(
            ValueFrame::from_bytes(uuid.risky_ref()),
            Err(super::super::FromFrameError::Value(DecodeError::Expected(
                _
            )))
        ));
    }

    /// Every value opens to the frame it was written as, through a walk of
    /// any source into the decrypt sink.
    #[test]
    fn opening_writes_the_frame_it_reads() {
        let value = every_variant();
        let opened = (&value).visit(ValueFrame::sink()).expect("opens");
        assert_eq!(opened.risky_ref(), frame_of(&value).risky_ref());
        for scalar in [s("x"), FfiValue::Null, FfiValue::Int64(1)] {
            let opened = (&scalar).visit(ValueFrame::sink()).expect("opens");
            assert_eq!(opened.risky_ref(), frame_of(&scalar).risky_ref());
        }
        let passthrough = FfiValue::Passthrough(Box::new(s("p")));
        let opened = (&passthrough).visit(ValueFrame::sink()).expect("opens");
        assert_eq!(opened.risky_ref(), frame_of(&passthrough).risky_ref());
        let repeated = FfiValue::Object(vec![
            ("k".into(), FfiValue::Null),
            ("k".into(), FfiValue::Null),
        ]);
        assert!(matches!(
            (&repeated).visit(ValueFrame::sink()),
            Err(DecodeError::DuplicateKey(key)) if key == "k"
        ));
    }

    #[test]
    fn a_frame_names_its_kind() {
        let cases = [
            (FfiValue::Null, None),
            (FfiValue::Undefined, None),
            (FfiValue::Bool(true), Some(ValueKind::Bool)),
            (FfiValue::Int32(1), Some(ValueKind::Int32)),
            (FfiValue::Int64(1), Some(ValueKind::Int64)),
            (FfiValue::UInt32(1), Some(ValueKind::UInt32)),
            (FfiValue::UInt64(1), Some(ValueKind::UInt64)),
            (FfiValue::Float32(1.0), Some(ValueKind::Float32)),
            (FfiValue::Float64(1.0), Some(ValueKind::Float64)),
            (s("a"), Some(ValueKind::String)),
            (
                FfiValue::Bytes(Protected::new(vec![1])),
                Some(ValueKind::Bytes),
            ),
            (FfiValue::Array(vec![s("a")]), Some(ValueKind::Array)),
            (
                FfiValue::Object(vec![("k".into(), s("a"))]),
                Some(ValueKind::Object),
            ),
            (FfiValue::Passthrough(Box::new(s("p"))), None),
        ];
        for (value, kind) in cases {
            assert_eq!(frame_of(&value).kind(), kind, "{value:?}");
            assert_eq!(value.kind(), kind, "the tree agrees: {value:?}");
        }
    }

    /// A sequence's parts are its elements' own frames, in order.
    #[test]
    fn parts_are_the_childrens_frames() {
        let Parts::Seq(items) = frame_of(&FfiValue::Array(vec![s("a"), FfiValue::Int32(1)]))
            .parts()
            .expect("parts")
        else {
            panic!("a sequence");
        };
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].risky_ref(), frame_of(&s("a")).risky_ref());
        assert!(matches!(
            frame_of(&FfiValue::Object(vec![("k".into(), s("a"))])).parts(),
            Ok(Parts::Map)
        ));
        assert!(matches!(frame_of(&s("a")).parts(), Ok(Parts::Scalar)));
        assert_eq!(
            frame_of(&FfiValue::Array(vec![s("a")]))
                .elements()
                .map(|items| items.len()),
            Some(1)
        );
        assert!(frame_of(&s("a")).elements().is_none());
        assert!(matches!(
            frame_of(&FfiValue::Passthrough(Box::new(s("p")))).parts(),
            Ok(Parts::Passthrough)
        ));
    }

    #[test]
    fn a_passthrough_is_found_at_any_depth() {
        assert!(frame_of(&every_variant()).kind().is_some());
        assert!(frame_of(&every_variant()).has_passthrough());
        assert!(!frame_of(&s("a")).has_passthrough());
        assert!(frame_of(&FfiValue::Passthrough(Box::new(s("p")))).has_passthrough());
        assert!(!frame_of(&FfiValue::Object(vec![("k".into(), s("a"))])).has_passthrough());
    }

    #[test]
    fn text_reads_as_a_label_and_nothing_else_does() {
        assert_eq!(
            frame_of(&s("tenants/acme")).into_label().expect("a label"),
            Label::parse("tenants/acme").expect("a label")
        );
        assert!(matches!(
            frame_of(&FfiValue::UInt32(7)).into_label(),
            Err(LabelError::NotText)
        ));
        assert!(frame_of(&s("")).into_label().is_err());
    }

    #[test]
    fn debug_redacts_the_frame() {
        assert_eq!(
            format!("{:?}", frame_of(&s("secret"))),
            "ValueFrame(<redacted>)"
        );
    }
}
