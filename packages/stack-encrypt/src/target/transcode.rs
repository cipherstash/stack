//! Consuming readers over native encryption output.
//!
//! A destination that stores encrypted output in its own shape (an EQL
//! envelope, say) implements [`Transcode`] with a [`Visitor`]; the cipher's
//! native output is a [`Reader`] that drives it. Reading moves the existing
//! leaves, markers, and terms into the destination as they are: nothing is
//! serialised, re-encrypted, or gathered into an intermediate tree first.
//!
//! What a reader hands over is what the cipher produced, no more: a sealed
//! leaf or marker is authenticated ciphertext, but passthrough metadata and
//! terms are not, and a visitor must not present them as such.
use crate::sem::{EqualityTerm, MatchConfig, MatchTerm, OpeTerm, OreTerm};
use crate::{BoxedPassthrough, CipherText, Error, SealedValue, StackCipherText};

/// An encrypted output that can drive a destination visitor.
///
/// Implemented by the native [`StackCipherText`] tree and by every term
/// type; [`Encryption::transcode`](super::Encryption::transcode) calls it on
/// an operation's completed output.
pub trait Reader: Sized {
    /// Hand this output to `visitor`, consuming it.
    ///
    /// # Errors
    ///
    /// Whatever the visitor returns; for its default methods, that is
    /// [`Error::UnsupportedShape`].
    fn read<V: Visitor>(self, visitor: V) -> Result<V::Value, Error>;
}
/// How a destination is built from each shape of encrypted output.
///
/// Every method has a default that refuses with [`Error::UnsupportedShape`],
/// so a destination implements only the shapes it stores: a scalar column
/// takes `sealed` and nothing else, and is then refused a sequence rather
/// than handed one flattened. Markers arrive sealed: none of these methods
/// authenticates what it is given.
pub trait Visitor: Sized {
    /// The destination this visitor builds.
    type Value;
    /// One sealed leaf: a scalar's ciphertext.
    ///
    /// # Errors
    ///
    /// Refuses with [`Error::UnsupportedShape`] unless overridden.
    fn sealed(self, _: SealedValue) -> Result<Self::Value, Error> {
        Err(Error::UnsupportedShape)
    }
    /// A non-empty sequence, read one item at a time.
    ///
    /// # Errors
    ///
    /// Refuses with [`Error::UnsupportedShape`] unless overridden.
    fn sequence<R: SequenceReader>(self, _: R) -> Result<Self::Value, Error> {
        Err(Error::UnsupportedShape)
    }
    /// A non-empty map, read one entry at a time.
    ///
    /// # Errors
    ///
    /// Refuses with [`Error::UnsupportedShape`] unless overridden.
    fn map<R: MapReader>(self, _: R) -> Result<Self::Value, Error> {
        Err(Error::UnsupportedShape)
    }
    /// The sealed marker of an absent optional. It is ciphertext, not a
    /// null: opening it under the wrong context fails like any leaf.
    ///
    /// # Errors
    ///
    /// Refuses with [`Error::UnsupportedShape`] unless overridden.
    fn absent(self, _: SealedValue) -> Result<Self::Value, Error> {
        Err(Error::UnsupportedShape)
    }
    /// The sealed marker of an empty sequence.
    ///
    /// # Errors
    ///
    /// Refuses with [`Error::UnsupportedShape`] unless overridden.
    fn empty_sequence(self, _: SealedValue) -> Result<Self::Value, Error> {
        Err(Error::UnsupportedShape)
    }
    /// The sealed marker of an empty map.
    ///
    /// # Errors
    ///
    /// Refuses with [`Error::UnsupportedShape`] unless overridden.
    fn empty_map(self, _: SealedValue) -> Result<Self::Value, Error> {
        Err(Error::UnsupportedShape)
    }
    /// Passthrough metadata the plaintext carried alongside its encrypted
    /// fields. Not authenticated: the reader hands it over as it was given.
    ///
    /// # Errors
    ///
    /// Refuses with [`Error::UnsupportedShape`] unless overridden.
    fn passthrough(self, _: BoxedPassthrough) -> Result<Self::Value, Error> {
        Err(Error::UnsupportedShape)
    }
    /// An equality term. One-way, and not authenticated.
    ///
    /// # Errors
    ///
    /// Refuses with [`Error::UnsupportedShape`] unless overridden.
    fn equality(self, _: EqualityTerm) -> Result<Self::Value, Error> {
        Err(Error::UnsupportedShape)
    }
    /// A match term. One-way, and not authenticated.
    ///
    /// # Errors
    ///
    /// Refuses with [`Error::UnsupportedShape`] unless overridden.
    fn matching<O: MatchConfig>(self, _: MatchTerm<O>) -> Result<Self::Value, Error> {
        Err(Error::UnsupportedShape)
    }
    /// An order-revealing term. One-way, and not authenticated.
    ///
    /// # Errors
    ///
    /// Refuses with [`Error::UnsupportedShape`] unless overridden.
    fn ore<T: cllw_ore::CllwOreEncrypt>(self, _: OreTerm<T>) -> Result<Self::Value, Error> {
        Err(Error::UnsupportedShape)
    }
    /// An order-preserving term. One-way, and not authenticated.
    ///
    /// # Errors
    ///
    /// Refuses with [`Error::UnsupportedShape`] unless overridden.
    fn ope<T: cllw_ore::CllwOpeEncrypt>(self, _: OpeTerm<T>) -> Result<Self::Value, Error> {
        Err(Error::UnsupportedShape)
    }
}
/// A destination that names its visitor, so an
/// [`Encryption`](super::Encryption) can be transcoded into it by type alone.
/// Choosing the visitor sees neither plaintext nor cipher.
pub trait Transcode: Sized {
    /// The visitor that builds this destination.
    type Visitor: Visitor<Value = Self>;
    /// A fresh visitor for one output.
    fn visitor() -> Self::Visitor;
}
/// Streaming access to an existing sequence. Each item is itself a
/// [`Reader`], so nesting is read the same way; the child owns its output.
pub trait SequenceReader {
    /// One item of the sequence.
    type Item: Reader;
    /// The next item, in the sequence's order.
    fn next(&mut self) -> Option<Self::Item>;
    /// How many items remain — a capacity hint, not a promise.
    fn remaining(&self) -> usize;
}
/// Streaming access to an existing map.
///
/// Keys keep their original spelling and order, and a destination must store
/// them exactly: Vitamin C derives each entry's authenticated context from
/// its key, so a renamed key fails to open.
pub trait MapReader {
    /// One entry's value.
    type Item: Reader;
    /// The next entry, in the map's order.
    fn next(&mut self) -> Option<(String, Self::Item)>;
    /// How many entries remain — a capacity hint, not a promise.
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
