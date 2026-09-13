//! Consuming readers over native encryption output. Reading moves existing
//! leaves and containers; it does not serialize or build an intermediate tree.
use crate::sem::{EqualityTerm, MatchConfig, MatchTerm, OpeTerm, OreTerm};
use crate::{BoxedPassthrough, CipherText, Error, SealedValue, StackCipherText};

/// An encrypted output that can drive a destination visitor.
pub trait Reader: Sized {
    fn read<V: Visitor>(self, visitor: V) -> Result<V::Value, Error>;
}
/// Destination construction. Unsupported shapes fail explicitly by default.
/// Markers remain sealed: none of these methods authenticates their contents.
pub trait Visitor: Sized {
    type Value;
    fn sealed(self, _: SealedValue) -> Result<Self::Value, Error> {
        Err(shape())
    }
    fn sequence<R: SequenceReader>(self, _: R) -> Result<Self::Value, Error> {
        Err(shape())
    }
    fn map<R: MapReader>(self, _: R) -> Result<Self::Value, Error> {
        Err(shape())
    }
    fn absent(self, _: SealedValue) -> Result<Self::Value, Error> {
        Err(shape())
    }
    fn empty_sequence(self, _: SealedValue) -> Result<Self::Value, Error> {
        Err(shape())
    }
    fn empty_map(self, _: SealedValue) -> Result<Self::Value, Error> {
        Err(shape())
    }
    /// Passthrough metadata is not AEAD-authenticated by the reader.
    fn passthrough(self, _: BoxedPassthrough) -> Result<Self::Value, Error> {
        Err(shape())
    }
    fn equality(self, _: EqualityTerm) -> Result<Self::Value, Error> {
        Err(shape())
    }
    fn matching<O: MatchConfig>(self, _: MatchTerm<O>) -> Result<Self::Value, Error> {
        Err(shape())
    }
    fn ore<T: cllw_ore::CllwOreEncrypt>(self, _: OreTerm<T>) -> Result<Self::Value, Error> {
        Err(shape())
    }
    fn ope<T: cllw_ore::CllwOpeEncrypt>(self, _: OpeTerm<T>) -> Result<Self::Value, Error> {
        Err(shape())
    }
}
/// A destination chooses its visitor without receiving plaintext or a cipher.
pub trait Transcode: Sized {
    type Visitor: Visitor<Value = Self>;
    fn visitor() -> Self::Visitor;
}
/// Streaming access to an existing sequence. The child reader owns its output.
pub trait SequenceReader {
    type Item: Reader;
    fn next(&mut self) -> Option<Self::Item>;
    fn remaining(&self) -> usize;
}
/// Map keys retain their original spelling and order. They must not be renamed
/// when opening: Vitamin C uses them to derive each entry's authenticated context.
pub trait MapReader {
    type Item: Reader;
    fn next(&mut self) -> Option<(String, Self::Item)>;
    fn remaining(&self) -> usize;
}
impl SequenceReader for std::vec::IntoIter<StackCipherText> {
    type Item = StackCipherText;
    fn next(&mut self) -> Option<Self::Item> {
        Iterator::next(self)
    }
    fn remaining(&self) -> usize {
        self.len()
    }
}
impl MapReader for std::vec::IntoIter<(String, StackCipherText)> {
    type Item = StackCipherText;
    fn next(&mut self) -> Option<(String, Self::Item)> {
        Iterator::next(self)
    }
    fn remaining(&self) -> usize {
        self.len()
    }
}
impl Reader for StackCipherText {
    fn read<V: Visitor>(self, visitor: V) -> Result<V::Value, Error> {
        match self {
            CipherText::Single(leaf) => visitor.sealed(leaf),
            CipherText::Sequence(items) => visitor.sequence(items.into_iter()),
            CipherText::Map(entries) => visitor.map(entries.into_iter()),
            CipherText::None(marker) => visitor.absent(marker),
            CipherText::EmptySequence(marker) => visitor.empty_sequence(marker),
            CipherText::EmptyMap(marker) => visitor.empty_map(marker),
            CipherText::Passthrough(value) => visitor.passthrough(value),
        }
    }
}
impl Reader for EqualityTerm {
    fn read<V: Visitor>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.equality(self)
    }
}
impl<O: MatchConfig> Reader for MatchTerm<O> {
    fn read<V: Visitor>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.matching(self)
    }
}
impl<T: cllw_ore::CllwOreEncrypt> Reader for OreTerm<T> {
    fn read<V: Visitor>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.ore(self)
    }
}
impl<T: cllw_ore::CllwOpeEncrypt> Reader for OpeTerm<T> {
    fn read<V: Visitor>(self, visitor: V) -> Result<V::Value, Error> {
        visitor.ope(self)
    }
}
fn shape() -> Error {
    Error::Other("destination does not support this encrypted output shape".into())
}
