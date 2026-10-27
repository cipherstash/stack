//! Test inputs and outputs as a binding sends and reads them: a [`Tree`] a
//! test spells, written as frame bytes, and a frame read back as one.
//!
//! The tree is a test's own notation, never a type the engine takes: every
//! entry point reads frames ([`ValueFrame`](super::ValueFrame), or bytes),
//! and a tree reaches one only as its frame or as an [`Encrypt`] source.
//! [`frame_of`] writes objects and arrays by hand, so a test can send a
//! repeated key, which no frame writer would.

use vitaminc_aead::frame::{FrameError, FrameWriteError};
use vitaminc_aead::plaintext::{
    visit_map, visit_seq, Error as _, FixedType, Float, Int, Logical, MapSink, Physical, SeqSink,
    Sink, SourceError,
};
use vitaminc_aead::{to_frame, DecodeError, Decrypt, Encrypt, Frame};
use vitaminc_protected::{Controlled, Protected};

/// A value as a test spells it: each scalar at its own width, a logical
/// scalar under its type. Equality is structural and variable-time, which
/// is why this is test code; floats compare by bit pattern, so `-0.0` and a
/// NaN's payload compare as they seal.
#[derive(Debug, Clone)]
pub(crate) enum Tree {
    Null,
    Undefined,
    Bool(bool),
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Int128(i128),
    UInt8(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    UInt128(u128),
    Float32(f32),
    Float64(f64),
    String(String),
    Bytes(Vec<u8>),
    /// A scalar under a logical type other than `Undefined`.
    Typed(Logical, Box<Tree>),
    Array(Vec<Tree>),
    Object(Vec<(String, Tree)>),
    Passthrough(Box<Tree>),
}

impl PartialEq for Tree {
    fn eq(&self, other: &Self) -> bool {
        use Tree::*;
        match (self, other) {
            (Null, Null) | (Undefined, Undefined) => true,
            (Bool(a), Bool(b)) => a == b,
            (Int8(a), Int8(b)) => a == b,
            (Int16(a), Int16(b)) => a == b,
            (Int32(a), Int32(b)) => a == b,
            (Int64(a), Int64(b)) => a == b,
            (Int128(a), Int128(b)) => a == b,
            (UInt8(a), UInt8(b)) => a == b,
            (UInt16(a), UInt16(b)) => a == b,
            (UInt32(a), UInt32(b)) => a == b,
            (UInt64(a), UInt64(b)) => a == b,
            (UInt128(a), UInt128(b)) => a == b,
            (Float32(a), Float32(b)) => a.to_bits() == b.to_bits(),
            (Float64(a), Float64(b)) => a.to_bits() == b.to_bits(),
            (String(a), String(b)) => a == b,
            (Bytes(a), Bytes(b)) => a == b,
            (Typed(ta, a), Typed(tb, b)) => ta == tb && a == b,
            (Array(a), Array(b)) => a == b,
            (Object(a), Object(b)) => a == b,
            (Passthrough(a), Passthrough(b)) => a == b,
            _ => false,
        }
    }
}

impl Tree {
    /// The tree's frame, written by vitaminc's own frame writer, which
    /// refuses a repeated key.
    pub(crate) fn to_frame(&self) -> Result<Protected<Vec<u8>>, FrameWriteError> {
        to_frame(self)
    }

    /// The tree's [`ValueKind`](super::ValueKind), as the engine reads it
    /// from the tree's frame: `None` for a null, an `undefined`, a
    /// passthrough, or a tree no frame holds.
    pub(crate) fn kind(&self) -> Option<super::ValueKind> {
        super::ValueFrame::of(self).ok()?.kind()
    }

    /// A frame read back as a tree.
    pub(crate) fn from_frame(bytes: &[u8]) -> Result<Self, ReadError> {
        let frame = Frame::parse(bytes).map_err(ReadError::Frame)?;
        frame.visit(TreeSink(Root)).map_err(ReadError::Value)
    }
}

/// Why [`Tree::from_frame`] refused its bytes.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum ReadError {
    Frame(FrameError),
    Value(DecodeError),
}

/// The frame bytes of `value`, written by hand: an object's entries in
/// order, a repeated key included.
pub(crate) fn frame_of(value: &Tree) -> Vec<u8> {
    let mut out = Vec::new();
    write(value, &mut out);
    out
}

fn write(value: &Tree, out: &mut Vec<u8>) {
    let count = |len: usize| u32::try_from(len).expect("short").to_le_bytes();
    match value {
        Tree::Object(entries) => {
            out.push(vitaminc_aead::frame::OBJECT);
            out.extend_from_slice(&count(entries.len()));
            for (key, value) in entries {
                out.extend_from_slice(&count(key.len()));
                out.extend_from_slice(key.as_bytes());
                write(value, out);
            }
        }
        Tree::Array(items) => {
            out.push(vitaminc_aead::frame::ARRAY);
            out.extend_from_slice(&count(items.len()));
            for item in items {
                write(item, out);
            }
        }
        other => out.extend_from_slice(other.to_frame().expect("frames").risky_ref()),
    }
}

/// What a binding reads back from an answer the engine writes: its frame,
/// read back.
pub(crate) fn value_of<T: serde::Serialize>(answer: &T) -> Tree {
    let frame = vitaminc_aead_frame::serde::to_vec(answer).expect("frames");
    Tree::from_frame(&frame).expect("a value")
}

fn scalar<S: Sink>(sink: S, ty: Option<Logical>, value: &Tree) -> Result<S::Ok, S::Error> {
    let physical = match value {
        Tree::Null => Physical::Null,
        Tree::Bool(b) => Physical::Bool(*b),
        Tree::Int8(i) => Physical::Int(Int::I8(*i)),
        Tree::Int16(i) => Physical::Int(Int::I16(*i)),
        Tree::Int32(i) => Physical::Int(Int::I32(*i)),
        Tree::Int64(i) => Physical::Int(Int::I64(*i)),
        Tree::Int128(i) => Physical::Int(Int::I128(*i)),
        Tree::UInt8(u) => Physical::Int(Int::U8(*u)),
        Tree::UInt16(u) => Physical::Int(Int::U16(*u)),
        Tree::UInt32(u) => Physical::Int(Int::U32(*u)),
        Tree::UInt64(u) => Physical::Int(Int::U64(*u)),
        Tree::UInt128(u) => Physical::Int(Int::U128(*u)),
        Tree::Float32(f) => Physical::Float(Float::F32(*f)),
        Tree::Float64(f) => Physical::Float(Float::F64(*f)),
        Tree::String(text) => Physical::Text(text),
        Tree::Bytes(bytes) => Physical::Bytes(bytes),
        _ => {
            return Err(S::Error::source(SourceError::msg(
                "a logical type is over a scalar",
            )))
        }
    };
    sink.scalar(ty, physical)
}

/// Walks the tree, leaving it where it is.
impl Encrypt for &Tree {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        match self {
            Tree::Undefined => sink.scalar(Some(Logical::Undefined), Physical::Null),
            Tree::Typed(ty, inner) => scalar(sink, Some(*ty), inner),
            Tree::Array(items) => visit_seq(sink, Some(items.len()), items),
            Tree::Object(entries) => visit_map(
                sink,
                Some(entries.len()),
                entries.iter().map(|(key, value)| (key.as_str(), value)),
            ),
            Tree::Passthrough(inner) => sink.passthrough(&**inner),
            leaf => scalar(sink, None, leaf),
        }
    }
}

impl Encrypt for Tree {
    fn visit<S: Sink>(self, sink: S) -> Result<S::Ok, S::Error> {
        (&self).visit(sink)
    }
}

/// What a walk opens into, read back as a tree.
impl Decrypt for Tree {
    type Sink = TreeSink<Root>;
    fn sink() -> Self::Sink {
        TreeSink(Root)
    }
}

pub(crate) trait Put {
    type Ok;
    fn put(self, value: Tree) -> Self::Ok;
}

pub(crate) struct Root;

impl Put for Root {
    type Ok = Tree;
    fn put(self, value: Tree) -> Tree {
        value
    }
}

pub(crate) struct Element<'s>(&'s mut Vec<Tree>);

impl Put for Element<'_> {
    type Ok = ();
    fn put(self, value: Tree) {
        self.0.push(value);
    }
}

pub(crate) struct Entry<'s>(&'s mut Vec<(String, Tree)>, String);

impl Put for Entry<'_> {
    type Ok = ();
    fn put(self, value: Tree) {
        self.0.push((self.1, value));
    }
}

/// Reads a walk back as a tree.
pub(crate) struct TreeSink<O>(O);

fn physical(value: Physical<'_>) -> Tree {
    match value {
        Physical::Null => Tree::Null,
        Physical::Bool(b) => Tree::Bool(b),
        Physical::Int(Int::I8(i)) => Tree::Int8(i),
        Physical::Int(Int::I16(i)) => Tree::Int16(i),
        Physical::Int(Int::I32(i)) => Tree::Int32(i),
        Physical::Int(Int::I64(i)) => Tree::Int64(i),
        Physical::Int(Int::I128(i)) => Tree::Int128(i),
        Physical::Int(Int::U8(u)) => Tree::UInt8(u),
        Physical::Int(Int::U16(u)) => Tree::UInt16(u),
        Physical::Int(Int::U32(u)) => Tree::UInt32(u),
        Physical::Int(Int::U64(u)) => Tree::UInt64(u),
        Physical::Int(Int::U128(u)) => Tree::UInt128(u),
        Physical::Float(Float::F32(f)) => Tree::Float32(f),
        Physical::Float(Float::F64(f)) => Tree::Float64(f),
        Physical::Text(text) => Tree::String(text.to_owned()),
        Physical::Bytes(bytes) => Tree::Bytes(bytes.to_vec()),
    }
}

impl<O: Put> Sink for TreeSink<O> {
    type Ok = O::Ok;
    type Error = DecodeError;
    type Seq = TreeSeq<O>;
    type Map = TreeMap<O>;

    fn scalar(self, ty: Option<Logical>, value: Physical<'_>) -> Result<O::Ok, DecodeError> {
        let value = match ty {
            None => physical(value),
            Some(Logical::Undefined) => Tree::Undefined,
            Some(ty) => Tree::Typed(ty, Box::new(physical(value))),
        };
        Ok(self.0.put(value))
    }

    fn typed_null(self, _: FixedType) -> Result<O::Ok, DecodeError> {
        Ok(self.0.put(Tree::Null))
    }

    fn seq(self, _: Option<usize>) -> Result<TreeSeq<O>, DecodeError> {
        Ok(TreeSeq {
            out: self.0,
            items: Vec::new(),
        })
    }

    fn map(self, _: Option<usize>) -> Result<TreeMap<O>, DecodeError> {
        Ok(TreeMap {
            out: self.0,
            entries: Vec::new(),
        })
    }

    fn passthrough<P: Encrypt + Clone>(self, value: P) -> Result<O::Ok, DecodeError> {
        let inner = value.visit(TreeSink(Root))?;
        Ok(self.0.put(Tree::Passthrough(Box::new(inner))))
    }
}

pub(crate) struct TreeSeq<O> {
    out: O,
    items: Vec<Tree>,
}

impl<O: Put> SeqSink for TreeSeq<O> {
    type Ok = O::Ok;
    type Error = DecodeError;
    type Element<'s>
        = TreeSink<Element<'s>>
    where
        Self: 's;

    fn element(&mut self) -> Result<TreeSink<Element<'_>>, DecodeError> {
        Ok(TreeSink(Element(&mut self.items)))
    }

    fn end(self) -> Result<O::Ok, DecodeError> {
        Ok(self.out.put(Tree::Array(self.items)))
    }
}

pub(crate) struct TreeMap<O> {
    out: O,
    entries: Vec<(String, Tree)>,
}

impl<O: Put> MapSink for TreeMap<O> {
    type Ok = O::Ok;
    type Error = DecodeError;
    type Entry<'s>
        = TreeSink<Entry<'s>>
    where
        Self: 's;

    fn entry(&mut self, key: &str) -> Result<TreeSink<Entry<'_>>, DecodeError> {
        Ok(TreeSink(Entry(&mut self.entries, key.to_owned())))
    }

    fn end(self) -> Result<O::Ok, DecodeError> {
        Ok(self.out.put(Tree::Object(self.entries)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vitaminc_aead::plaintext::TimeUnit;

    /// One tree of every variant, nested in each container.
    fn every_variant() -> Vec<Tree> {
        vec![
            Tree::Null,
            Tree::Undefined,
            Tree::Bool(true),
            Tree::Int8(-8),
            Tree::Int16(-16),
            Tree::Int32(-32),
            Tree::Int64(-64),
            Tree::Int128(-128),
            Tree::UInt8(8),
            Tree::UInt16(16),
            Tree::UInt32(32),
            Tree::UInt64(64),
            Tree::UInt128(128),
            Tree::Float32(-0.0),
            Tree::Float64(f64::NAN),
            Tree::String("text".into()),
            Tree::Bytes(vec![1, 2, 3]),
            Tree::Typed(Logical::Date, Box::new(Tree::Int32(19_000))),
            Tree::Typed(
                Logical::Timestamp(TimeUnit::Nanos),
                Box::new(Tree::Int128(1)),
            ),
            Tree::Array(vec![Tree::UInt32(1), Tree::Null]),
            Tree::Object(vec![("k".into(), Tree::String("v".into()))]),
            Tree::Passthrough(Box::new(Tree::Bytes(vec![9]))),
        ]
    }

    /// Every variant writes a frame that reads back as itself, alone and
    /// inside an array and an object, and equals only itself.
    #[test]
    fn every_variant_reads_back_as_itself_and_equals_only_itself() {
        let variants = every_variant();
        for (at, tree) in variants.iter().enumerate() {
            let frame = tree.to_frame().expect("frames");
            assert_eq!(&Tree::from_frame(frame.risky_ref()).expect("reads"), tree);
            assert_eq!(&Tree::from_frame(&frame_of(tree)).expect("reads"), tree);
            for (other_at, other) in variants.iter().enumerate() {
                assert_eq!(tree == other, at == other_at, "{tree:?} vs {other:?}");
            }
        }
        let array = Tree::Array(variants.clone());
        assert_eq!(Tree::from_frame(&frame_of(&array)).expect("reads"), array);
        let object = Tree::Object(
            variants
                .into_iter()
                .enumerate()
                .map(|(at, tree)| (at.to_string(), tree))
                .collect(),
        );
        assert_eq!(Tree::from_frame(&frame_of(&object)).expect("reads"), object);
    }

    /// A logical type over anything but a scalar is not a value, and bytes
    /// that are not one frame do not read back.
    #[test]
    fn a_tree_no_frame_holds_is_refused() {
        let over_a_list = Tree::Typed(Logical::Date, Box::new(Tree::Array(vec![])));
        assert!(over_a_list.to_frame().is_err());
        assert!(matches!(Tree::from_frame(&[]), Err(ReadError::Frame(_))));
        assert_eq!(
            Tree::UInt32(7).kind(),
            Some(super::super::ValueKind::UInt32)
        );
        assert_eq!(Tree::Null.kind(), None);
    }
}
